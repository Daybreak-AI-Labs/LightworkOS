"""Predictive approvals.

When an operator has approved "git push to a feature branch" twenty times and
never denied it, the twenty-first prompt is friction with no signal. This learns,
per ``(action, risk_tier)``, the operator's historical approve/deny rate from the
approvals history and **suggests** a default — ``auto-approve-candidate``,
``auto-deny-candidate``, or ``always-ask`` — with a confidence that grows with
sample size.

Safety: this only ever *recommends*. It never decides, never writes to the
consent ledger, never short-circuits :mod:`maverick.safety.consent`. The output
is a suggestion surfaced to a human ("you've approved this 20/20 times — make it
auto?"), and a human (or the integrator's policy UI) acts on it. A low sample, a
mixed record, or anything risky stays ``always-ask``.

Pure and deterministic: the history is injected (a list of records, or any object
exposing the recorded approvals), so suggestions are unit-tested offline with no
world model and no clock.
"""
from __future__ import annotations

from dataclasses import dataclass

_VALID_RISK = ("low", "medium", "high", "critical")

# Below this many decisions for an (action, risk) we never suggest automating —
# the sample is too small to trust regardless of how lopsided it looks.
_MIN_SAMPLE = 5
# A side must hold at least this share of decisions to be a candidate. 0.9 means
# "≥90% approved" before we'd suggest auto-approve (and symmetrically for deny).
_DOMINANCE = 0.9
# Risk tiers we refuse to ever suggest auto-*approve* for: a human should keep
# eyes on high/critical actions no matter how routine they've become. (Auto-DENY
# is still suggestible for these — erring toward blocking is the safe direction.)
_NO_AUTO_APPROVE_RISK = frozenset({"high", "critical"})

SUGGEST_APPROVE = "auto-approve-candidate"
SUGGEST_DENY = "auto-deny-candidate"
SUGGEST_ASK = "always-ask"


@dataclass(frozen=True)
class Suggestion:
    action: str
    risk: str
    suggestion: str          # one of the SUGGEST_* constants
    approve_rate: float      # share of decided records that were approvals
    sample: int              # number of *decided* records (approve+deny)
    confidence: float        # 0..1, grows with sample and one-sidedness
    reason: str


def _norm_risk(risk: str) -> str:
    r = (risk or "").strip().lower()
    return r if r in _VALID_RISK else "medium"


def _decided(record: dict) -> bool | None:
    """Map one history record to True (approved) / False (denied) / None (skip).

    Accepts the shapes the kernel writes: a ``decision`` of approve/deny/grant,
    a ``status`` of approved/denied, or a boolean ``granted``/``approved``.
    Pending / unknown records return ``None`` and don't count toward the sample.
    """
    for key in ("granted", "approved"):
        if key in record and isinstance(record[key], bool):
            return record[key]
    text = str(record.get("decision") or record.get("status") or "").strip().lower()
    if text in ("approve", "approved", "grant", "granted", "allow", "yes"):
        return True
    if text in ("deny", "denied", "reject", "rejected", "block", "no"):
        return False
    return None


def _confidence(approvals: int, denials: int) -> float:
    """A 0..1 confidence that the dominant side is the *real* default.

    Wilson-style: the lower bound of the dominant proportion's 95% interval,
    which rises with both sample size and one-sidedness (10/10 beats 6/6 beats
    3/3). Symmetric for approve- and deny-dominant records.
    """
    import math
    n = approvals + denials
    if n <= 0:
        return 0.0
    p = max(approvals, denials) / n
    z = 1.959963984540054
    denom = 1.0 + (z * z) / n
    centre = p + (z * z) / (2.0 * n)
    margin = z * math.sqrt((p * (1.0 - p) + (z * z) / (4.0 * n)) / n)
    return round(max(0.0, (centre - margin) / denom), 4)


def suggest(
    action: str,
    risk: str,
    records: list[dict],
    *,
    min_sample: int = _MIN_SAMPLE,
    dominance: float = _DOMINANCE,
) -> Suggestion:
    """Suggest a default for one ``(action, risk)`` from its decided records.

    ``records`` are the history rows already filtered to this action+risk (or a
    superset — non-matching/pending rows are ignored). Returns a never-binding
    :class:`Suggestion`.
    """
    risk = _norm_risk(risk)
    approvals = denials = 0
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        d = _decided(rec)
        if d is True:
            approvals += 1
        elif d is False:
            denials += 1
    sample = approvals + denials
    rate = round(approvals / sample, 4) if sample else 0.0
    conf = _confidence(approvals, denials)

    if sample < min_sample:
        return Suggestion(
            action, risk, SUGGEST_ASK, rate, sample, conf,
            f"only {sample} decision(s) on record (need {min_sample}) — keep asking.",
        )
    approve_share = approvals / sample
    deny_share = denials / sample
    if approve_share >= dominance:
        if risk in _NO_AUTO_APPROVE_RISK:
            return Suggestion(
                action, risk, SUGGEST_ASK, rate, sample, conf,
                f"approved {approvals}/{sample} but risk={risk} stays human-gated.",
            )
        return Suggestion(
            action, risk, SUGGEST_APPROVE, rate, sample, conf,
            f"approved {approvals}/{sample} ({approve_share:.0%}) — candidate to auto-approve.",
        )
    if deny_share >= dominance:
        return Suggestion(
            action, risk, SUGGEST_DENY, rate, sample, conf,
            f"denied {denials}/{sample} ({deny_share:.0%}) — candidate to auto-deny.",
        )
    return Suggestion(
        action, risk, SUGGEST_ASK, rate, sample, conf,
        f"mixed record ({approvals} approve / {denials} deny) — keep asking.",
    )


def _key(record: dict) -> tuple[str, str]:
    return (
        str(record.get("action") or "").strip(),
        _norm_risk(str(record.get("risk") or "")),
    )


def suggest_all(
    history,
    *,
    min_sample: int = _MIN_SAMPLE,
    dominance: float = _DOMINANCE,
) -> list[Suggestion]:
    """Group a flat history into ``(action, risk)`` buckets and suggest each.

    ``history`` is a list of records or an object exposing one via
    ``.records()`` / ``.approvals()`` / ``.history()`` (duck-typed so a world
    model or an in-memory log both work). Results are sorted most-confident
    first, then by action, so the strongest automation candidates surface on top.
    """
    rows = _coerce_history(history)
    buckets: dict[tuple[str, str], list[dict]] = {}
    for rec in rows:
        if not isinstance(rec, dict):
            continue
        action, _ = _key(rec)
        if not action:
            continue
        buckets.setdefault(_key(rec), []).append(rec)
    out = [
        suggest(action, risk, recs, min_sample=min_sample, dominance=dominance)
        for (action, risk), recs in buckets.items()
    ]
    out.sort(key=lambda s: (-s.confidence, s.action, s.risk))
    return out


def _coerce_history(history) -> list[dict]:
    if history is None:
        return []
    if isinstance(history, list):
        return history
    for attr in ("records", "approvals", "history"):
        fn = getattr(history, attr, None)
        if callable(fn):
            try:
                return list(fn() or [])
            except Exception:  # pragma: no cover -- a broken source reads empty
                return []
    return []


def render(suggestions: list[Suggestion]) -> str:
    """Render suggestions as a plain text table (advisory only)."""
    if not suggestions:
        return "predictive approvals: no history to learn from yet."
    lines = ["predictive approvals (suggestions only — never auto-applied):"]
    for s in suggestions:
        lines.append(
            f"  [{s.suggestion}] {s.action} (risk={s.risk}) "
            f"approve_rate={s.approve_rate:.0%} n={s.sample} conf={s.confidence:.2f}"
        )
        lines.append(f"      {s.reason}")
    return "\n".join(lines)


__all__ = [
    "Suggestion",
    "suggest",
    "suggest_all",
    "render",
    "SUGGEST_APPROVE",
    "SUGGEST_DENY",
    "SUGGEST_ASK",
]
