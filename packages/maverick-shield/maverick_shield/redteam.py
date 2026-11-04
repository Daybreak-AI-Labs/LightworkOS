"""Red-team CI runner + shield calibration.

Two halves, one scan loop:

* **Red-team CI** — run a labelled adversarial corpus through the shield's
  always-present built-in detector and FAIL (exit 1) when any case labelled
  ``block`` gets through. ``python -m maverick_shield.redteam`` is wired as a
  named CI job so the gate is visible in the checks list, not buried in the
  test suite. The corpus is a grow-by-PR JSONL file
  (``redteam_corpus.jsonl``: ``{id, text, expected, category}``); teams add
  their own cases with ``--corpus extra.jsonl``.

* **Calibration** — the same scan loop swept across every block threshold
  (``low``→``critical``) yields the operating curve (recall vs false-positive
  rate per threshold) plus per-rule hit counts: the data behind the shield
  calibration dashboard, exposed as ``calibration_report()`` and rendered by
  ``--calibrate``.

Deterministic and offline: scans the built-in rules (no SDK, no network).
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import builtin_rules

_THRESHOLDS = ("low", "medium", "high", "critical")
_DEFAULT_CORPUS = Path(__file__).parent / "redteam_corpus.jsonl"


@dataclass(frozen=True)
class Case:
    id: str
    text: str
    expected: str            # "block" | "allow"
    category: str = ""


@dataclass
class CaseResult:
    case: Case
    blocked: bool
    severity: str
    rules: tuple[str, ...] = ()


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    missed: list[str] = field(default_factory=list)        # case ids (expected block, allowed)
    overblocked: list[str] = field(default_factory=list)   # case ids (expected allow, blocked)

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 1.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 1.0

    @property
    def fp_rate(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0


def load_corpus(path: Path | None = None) -> list[Case]:
    """Load the JSONL corpus; malformed lines fail loudly (a silent skip would
    quietly shrink the gate)."""
    p = Path(path) if path else _DEFAULT_CORPUS
    cases: list[Case] = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        row = json.loads(line)
        expected = str(row.get("expected", "")).lower()
        if expected not in ("block", "allow"):
            raise ValueError(f"{p}:{i + 1}: expected must be block|allow, got {expected!r}")
        if not row.get("id") or not row.get("text"):
            raise ValueError(f"{p}:{i + 1}: id and text are required")
        cases.append(Case(
            id=str(row["id"]), text=str(row["text"]),
            expected=expected, category=str(row.get("category", "")),
        ))
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{p}: duplicate case ids")
    return cases


def run_cases(cases: list[Case], *, block_threshold: str = "high") -> list[CaseResult]:
    out: list[CaseResult] = []
    for c in cases:
        blocked, severity, names = builtin_rules.scan(c.text, block_threshold=block_threshold)
        out.append(CaseResult(case=c, blocked=blocked, severity=severity,
                              rules=tuple(names or ())))
    return out


def score(results: list[CaseResult]) -> Score:
    s = Score()
    for r in results:
        if r.case.expected == "block" and r.blocked:
            s.tp += 1
        elif r.case.expected == "block":
            s.fn += 1
            s.missed.append(r.case.id)
        elif r.blocked:
            s.fp += 1
            s.overblocked.append(r.case.id)
        else:
            s.tn += 1
    return s


def calibration_report(cases: list[Case]) -> dict:
    """Threshold sweep + per-rule hits — the calibration dashboard's data.

    For each block threshold, score the corpus; also count which rules fired
    across all cases (at the most permissive threshold) so a noisy rule is
    visible. Returns a plain dict (JSON-renderable).
    """
    sweep = {}
    for thr in _THRESHOLDS:
        s = score(run_cases(cases, block_threshold=thr))
        sweep[thr] = {
            "recall": round(s.recall, 4),
            "precision": round(s.precision, 4),
            "fp_rate": round(s.fp_rate, 4),
            "missed": s.missed,
            "overblocked": s.overblocked,
        }
    rule_hits: dict[str, int] = {}
    for r in run_cases(cases, block_threshold="low"):
        for name in r.rules:
            rule_hits[name] = rule_hits.get(name, 0) + 1
    return {
        "cases": len(cases),
        "thresholds": sweep,
        "rule_hits": dict(sorted(rule_hits.items(), key=lambda kv: -kv[1])),
    }


def main(argv: list[str] | None = None) -> int:
    """CLI: gate on missed attacks (red-team CI) or print the calibration report."""
    args = list(sys.argv[1:] if argv is None else argv)
    calibrate = "--calibrate" in args
    if calibrate:
        args.remove("--calibrate")
    corpus_path: Path | None = None
    if "--corpus" in args:
        i = args.index("--corpus")
        corpus_path = Path(args[i + 1])
        del args[i:i + 2]
    threshold = "high"
    if "--threshold" in args:
        i = args.index("--threshold")
        threshold = args[i + 1]
        del args[i:i + 2]

    cases = load_corpus(corpus_path)
    if calibrate:
        print(json.dumps(calibration_report(cases), indent=2))
        return 0

    s = score(run_cases(cases, block_threshold=threshold))
    print(f"red-team: {len(cases)} cases @ threshold={threshold}")
    print(f"  recall={s.recall:.2f} precision={s.precision:.2f} fp_rate={s.fp_rate:.2f}")
    if s.overblocked:
        print(f"  over-blocked (expected allow): {', '.join(s.overblocked)}")
    if s.missed:
        print(f"  MISSED ATTACKS: {', '.join(s.missed)}")
        print("verdict: FAIL")
        return 1
    print("verdict: PASS")
    return 0


if __name__ == "__main__":  # pragma: no cover -- exercised via main() in tests
    raise SystemExit(main())
