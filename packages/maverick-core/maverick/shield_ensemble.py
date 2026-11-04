"""Shield v3 — detector ensemble with explainable reason codes.

The target is a small-model ensemble (injection + jailbreak + exfil + policy)
with explainable reason codes. This ships the **ensemble framework** and the
explainability now, with the existing deterministic detectors as members; a
member is a small pluggable unit, so a trained small-model classifier can be
dropped in later behind the same interface without touching callers.

Each member screens a blob and returns a :class:`DetectorSignal` (a 0–1 score,
whether it fired, and human-readable reasons). The ensemble is **deny-wins**
(any member firing blocks — the union of risks, the same posture as the rest of
Lightwork's safety layer), reports the dominant score as severity, and — the
point of v3 — emits a structured **reason_codes** list explaining *which*
detector objected and *why*, instead of an opaque block.

Deterministic and offline; composes detectors that already ship.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectorSignal:
    detector: str
    score: float            # 0..1
    fired: bool
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EnsembleVerdict:
    allowed: bool
    severity: str           # "none" | "low" | "medium" | "high"
    score: float            # the dominant member score
    reason_codes: list[dict]  # [{detector, score, reasons}] for each fired member


def _severity(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.6:
        return "medium"
    if score >= 0.3:
        return "low"
    return "none"


# -- members (each wraps a shipping detector) -----------------------------

class InjectionMember:
    name = "injection"

    def evaluate(self, text: str) -> DetectorSignal:
        from .safety.jailbreak_heuristics import score_text
        score, matched = score_text(text or "")
        return DetectorSignal(self.name, round(float(score), 3), score >= 0.6,
                              [f"pattern:{m}" for m in matched])


class ExfilMember:
    name = "exfil"

    def evaluate(self, text: str) -> DetectorSignal:
        from .safety.secret_detector import scan
        hits = scan(text or "")
        score = min(1.0, 0.6 + 0.2 * (len(hits) - 1)) if hits else 0.0
        return DetectorSignal(self.name, round(score, 3), bool(hits),
                              [f"secret:{h.name}" for h in hits])


class PiiMember:
    name = "pii"

    def evaluate(self, text: str) -> DetectorSignal:
        from .safety.pii_detector import scan
        hits = scan(text or "")
        score = min(1.0, 0.35 + 0.15 * (len(hits) - 1)) if hits else 0.0
        return DetectorSignal(self.name, round(score, 3), bool(hits),
                              [f"pii:{h.kind}" for h in hits])


def _default_members():
    return [InjectionMember(), ExfilMember(), PiiMember()]


class ShieldEnsemble:
    """Deny-wins ensemble over pluggable detector members."""

    def __init__(self, members=None):
        self.members = list(members) if members is not None else _default_members()

    def evaluate(self, text: str) -> EnsembleVerdict:
        signals = [m.evaluate(text) for m in self.members]
        fired = [s for s in signals if s.fired]
        score = max((s.score for s in signals), default=0.0)
        return EnsembleVerdict(
            allowed=not fired,
            severity=_severity(score),
            score=round(score, 3),
            reason_codes=[{"detector": s.detector, "score": s.score,
                           "reasons": s.reasons} for s in fired],
        )


__all__ = ["DetectorSignal", "EnsembleVerdict", "ShieldEnsemble",
           "InjectionMember", "ExfilMember", "PiiMember"]
