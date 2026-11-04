"""Back-test harness: prior FILED returns -> draft-vs-filed accuracy report.

The fastest way a firm trusts the first-pass engine is to point it at returns
it has *already filed* and see how close the draft lands. This module is that
harness: a case is a client's source documents plus the figures the firm
actually filed (:class:`FiledReturn`); for each case it runs the deterministic
:mod:`maverick.tax_prep` pipeline and diffs the draft against the filed
actuals on the lines the v1 scope computes.

The one discipline that makes the number meaningful: a return carrying items
the engine deliberately does NOT compute (Schedule C/D/E income, itemized
deductions, a graduated-state tax, an unsupported filing status) is reported
OUT OF SCOPE and excluded from the accuracy metric. The harness measures
whether the engine's in-scope math is right -- not whether it reproduces work
it intentionally hands to the preparer. So the headline "matched N/M in-scope
returns within $T" is an honest accuracy signal, and the out-of-scope list is
exactly the book of business a firm would still drive through its tax engine.

Pure functions (diff/aggregate/render) are unit-tested with no IO; the thin
``run_backtest_dir`` loader and the ``maverick tax backtest`` command wire them
to a folder of cases.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import tax_prep
from .tax_prep import (
    Draft1040,
    SourceDoc,
    Workpaper,
    compute_first_pass,
    extract,
    normalize_filing_status,
)

# Document types whose income the v1 computation does NOT total (they are
# carried/flagged for the preparer), so a return that includes one cannot be
# expected to match the filed total -- it is an out-of-scope case.
_OUT_OF_SCOPE_DOCS = {
    "1099-NEC", "K-1", "1099-B", "1099-R", "SSA-1099", "1099-G",
}

# Default match tolerance in dollars: the engine rounds to cents, so a real
# in-scope match is exact; $1 absorbs rounding/transcription noise.
DEFAULT_TOLERANCE = 1.0


@dataclass
class FiledReturn:
    """The figures a firm actually filed -- the back-test ground truth.

    Only the lines the v1 engine computes are required; ``itemized`` and
    ``has_schedule_c_d_e`` let a firm mark a return out of scope explicitly
    even when the source docs alone wouldn't reveal it."""
    client: str
    filing_status: str
    total_income: float
    taxable_income: float
    tax_after_credits: float
    federal_withholding: float
    balance: float                   # negative = refund
    itemized: bool = False
    has_schedule_c_d_e: bool = False


@dataclass
class LineDiff:
    line: str
    draft: float
    filed: float

    @property
    def delta(self) -> float:
        return round(self.draft - self.filed, 2)


@dataclass
class ReturnDiff:
    client: str
    in_scope: bool
    out_of_scope_reasons: list[str] = field(default_factory=list)
    lines: list[LineDiff] = field(default_factory=list)

    @property
    def max_abs_delta(self) -> float:
        return max((abs(d.delta) for d in self.lines), default=0.0)

    def matched(self, tolerance: float = DEFAULT_TOLERANCE) -> bool:
        """An in-scope return whose every compared line is within tolerance."""
        return self.in_scope and self.max_abs_delta <= tolerance


@dataclass
class BatchReport:
    diffs: list[ReturnDiff]
    tolerance: float = DEFAULT_TOLERANCE

    @property
    def in_scope(self) -> list[ReturnDiff]:
        return [d for d in self.diffs if d.in_scope]

    @property
    def out_of_scope(self) -> list[ReturnDiff]:
        return [d for d in self.diffs if not d.in_scope]

    @property
    def matched(self) -> list[ReturnDiff]:
        return [d for d in self.in_scope if d.matched(self.tolerance)]

    @property
    def mismatched(self) -> list[ReturnDiff]:
        return [d for d in self.in_scope if not d.matched(self.tolerance)]

    @property
    def accuracy(self) -> float:
        """Share of in-scope returns matched within tolerance (0..1); 1.0 when
        there are no in-scope returns to judge."""
        n = len(self.in_scope)
        return 1.0 if n == 0 else len(self.matched) / n


def _scope_reasons(filed: FiledReturn, wp: Workpaper,
                   draft: Draft1040) -> list[str]:
    """Why a case is out of the v1 computation's scope (empty = in scope)."""
    reasons: list[str] = []
    if normalize_filing_status(filed.filing_status) not in tax_prep.FILING_STATUSES:
        reasons.append(f"filing status {filed.filing_status!r} unsupported")
    if filed.itemized:
        reasons.append("itemized return (v1 computes the standard deduction)")
    if filed.has_schedule_c_d_e:
        reasons.append("Schedule C/D/E income (not totaled by v1)")
    kinds = sorted({d.doc_type for d in wp.docs} & _OUT_OF_SCOPE_DOCS)
    if kinds:
        reasons.append("out-of-scope income document(s): " + ", ".join(kinds))
    return reasons


def diff_return(filed: FiledReturn, draft: Draft1040,
                wp: Workpaper) -> ReturnDiff:
    """Diff one filed return against its first-pass draft.

    Compares the five lines the v1 scope computes. When the case is out of
    scope the lines are still recorded (for the report) but ``in_scope`` is
    False so it never counts against accuracy."""
    lines = [
        LineDiff("Total income", draft.total_income, filed.total_income),
        LineDiff("Taxable income", draft.taxable_income, filed.taxable_income),
        LineDiff("Tax after credits", draft.tax_after_credits,
                 filed.tax_after_credits),
        LineDiff("Federal withholding", draft.federal_withholding,
                 filed.federal_withholding),
        LineDiff("Balance (− = refund)", draft.balance, filed.balance),
    ]
    reasons = _scope_reasons(filed, wp, draft)
    return ReturnDiff(client=filed.client, in_scope=not reasons,
                      out_of_scope_reasons=reasons, lines=lines)


def render_backtest(report: BatchReport) -> str:
    """Human-readable accuracy report: headline metric, per-return deltas."""
    out = [
        "TAX FIRST-PASS BACK-TEST — draft vs. filed",
        "=" * 52,
        f"Cases               : {len(report.diffs)}",
        f"In scope            : {len(report.in_scope)}  "
        f"(matched {len(report.matched)} within ${report.tolerance:,.2f})",
        f"Out of scope        : {len(report.out_of_scope)}",
        f"In-scope accuracy   : {report.accuracy * 100:.1f}%",
    ]
    if report.mismatched:
        out += ["", "IN-SCOPE MISMATCHES (engine math to investigate):",
                "-" * 52]
        for d in report.mismatched:
            out.append(f"  {d.client}  (max Δ ${d.max_abs_delta:,.2f})")
            for ln in d.lines:
                if abs(ln.delta) > report.tolerance:
                    out.append(f"      {ln.line:<22} draft ${ln.draft:,.2f} "
                               f"vs filed ${ln.filed:,.2f}  "
                               f"(Δ ${ln.delta:,.2f})")
    if report.out_of_scope:
        out += ["", "OUT OF SCOPE (expected to differ — drive via tax engine):",
                "-" * 52]
        for d in report.out_of_scope:
            out.append(f"  {d.client}: {'; '.join(d.out_of_scope_reasons)}")
    return "\n".join(out)


def backtest_dict(report: BatchReport) -> dict:
    """The back-test report as a structured dict for a firm's dashboard.

    Headline accuracy plus a per-return record (in/out of scope, max delta,
    and the per-line deltas) so a firm can chart accuracy and drill into any
    mismatch programmatically."""
    return {
        "tolerance": report.tolerance,
        "cases": len(report.diffs),
        "in_scope": len(report.in_scope),
        "matched": len(report.matched),
        "out_of_scope": len(report.out_of_scope),
        "accuracy": round(report.accuracy, 4),
        "returns": [
            {
                "client": d.client,
                "in_scope": d.in_scope,
                "matched": d.matched(report.tolerance),
                "max_abs_delta": d.max_abs_delta,
                "out_of_scope_reasons": list(d.out_of_scope_reasons),
                "lines": [{"line": ln.line, "draft": ln.draft,
                           "filed": ln.filed, "delta": ln.delta}
                          for ln in d.lines],
            }
            for d in report.diffs
        ],
    }


def _filed_from_dict(d: dict) -> FiledReturn:
    f = d.get("filed") or {}
    return FiledReturn(
        client=str(d.get("client") or "?"),
        filing_status=str(d.get("filing_status") or "single"),
        total_income=float(f.get("total_income", 0.0)),
        taxable_income=float(f.get("taxable_income", 0.0)),
        tax_after_credits=float(f.get("tax_after_credits", 0.0)),
        federal_withholding=float(f.get("federal_withholding", 0.0)),
        balance=float(f.get("balance", 0.0)),
        itemized=bool(d.get("itemized", False)),
        has_schedule_c_d_e=bool(d.get("has_schedule_c_d_e", False)),
    )


def run_backtest_dir(cases_dir: Path | str,
                     tolerance: float = DEFAULT_TOLERANCE) -> BatchReport:
    """Run every case subdirectory under ``cases_dir``.

    A case is a folder with the client's source ``*.txt`` documents plus a
    ``filed.json`` carrying ``client``/``filing_status``/``dependents``/
    ``state`` and a ``filed`` block of the actual filed figures."""
    diffs: list[ReturnDiff] = []
    for case in sorted(p for p in Path(cases_dir).iterdir() if p.is_dir()):
        meta_path = case / "filed.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        filed = _filed_from_dict(meta)
        docs: list[SourceDoc] = [
            extract(p.read_text(encoding="utf-8", errors="replace"),
                    label=p.name)
            for p in sorted(case.glob("*.txt"))
        ]
        wp = Workpaper(
            filing_status=filed.filing_status,
            dependents_under_17=int(meta.get("dependents", 0)),
            docs=docs, state=str(meta.get("state", "")),
            estimated_payments=float(meta.get("estimated_payments", 0.0) or 0.0),
            prior_year_overpayment=float(
                meta.get("prior_year_overpayment", 0.0) or 0.0),
            taxpayer_65_or_older=bool(meta.get("taxpayer_65", False)),
            spouse_65_or_older=bool(meta.get("spouse_65", False)),
            taxpayer_blind=bool(meta.get("taxpayer_blind", False)),
            spouse_blind=bool(meta.get("spouse_blind", False)))
        draft = compute_first_pass(wp)
        diffs.append(diff_return(filed, draft, wp))
    return BatchReport(diffs=diffs, tolerance=tolerance)


__all__ = [
    "DEFAULT_TOLERANCE", "FiledReturn", "LineDiff", "ReturnDiff",
    "BatchReport", "diff_return", "render_backtest", "backtest_dict",
    "run_backtest_dir",
]
