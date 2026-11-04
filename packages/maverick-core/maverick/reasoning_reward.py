"""Structured, auditable reasoning rewards (Agent-RRM, arxiv:2601.22154).

The verifier (:mod:`maverick.verifier`) and the process reward model
(:mod:`maverick.prm`) both collapse a judgment into a *scalar* -- a
confidence, a promise, a progress delta. A scalar is cheap to hack and
opaque to audit: "0.82" records neither *why* the answer scored well nor
*which* facet failed. Agent-RRM's advance is to make the reward
**multi-faceted and legible**: an internal reasoning trace, a per-rubric
critique with its own sub-score, and a holistic score -- instead of one
number.

For a governed, provable-learning platform this is not a cosmetic upgrade.
A natural-language critique broken down by rubric dimension is *inherently
auditable* in a way a scalar is not: the signed learning ledger can record
WHAT the judge objected to, and a single failing dimension (e.g. ``safety``)
can VETO a promotion even when the holistic score is high. That composes
directly with the existing interlocks -- the calibration freeze
(:mod:`maverick.calibration`) and the promotion ladder
(:mod:`maverick.self_improvement`) -- turning "the judge liked it" into
"the judge liked it, here is the rubric, and here is what it would have
rejected on."

This module ships the *representation* + two reference paths, deliberately
LLM-free at construction so it is deterministic and offline-testable:

  * :func:`ReasoningReward.from_verifier_verdict` -- a lossless upgrade of
    the existing :class:`maverick.verifier.VerifierVerdict` into the
    structured shape (zero new LLM calls; the legacy path keeps working and
    gains ``to_audit_dict``).
  * :func:`parse_structured` -- parse a rubric-structured reply from a
    verifier prompted with :data:`REASONING_REWARD_SYSTEM`, giving the real
    per-dimension decomposition when the richer default judge runs.

Posture: ON by default with an explicit opt-out and fail-open. Every parse
failure degrades to a conservative low reward -- a flaky/structured judge can
only make the system MORE cautious about what it accepts and learns from,
never less.
No new dependency: standard library only.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)


def _clamp01(v: object) -> float:
    try:
        return max(0.0, min(1.0, float(v)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


# Default rubric: name -> (weight, veto_floor). ``weight`` sets the
# dimension's share of the holistic score; ``veto_floor`` is the sub-score
# below which the dimension REJECTS regardless of the holistic score (0.0 =
# advisory only, never vetoes). ``safety`` vetoes hard: a well-argued but
# unsafe answer must not be accepted or learned from. Order is load-bearing
# (audit serialization and holistic weighting iterate it in this order).
DEFAULT_RUBRIC: tuple[tuple[str, float, float], ...] = (
    ("correctness", 0.40, 0.30),
    ("completeness", 0.25, 0.0),
    ("grounding", 0.20, 0.0),
    ("safety", 0.15, 0.50),
)

# Fallback accept bar, used only if the verifier module can't be imported.
# The live value is the verifier's own ``VERIFIER_CONFIDENCE_ACCEPT`` (see
# ``_accept_threshold``), which is operator-tunable via
# ``MAVERICK_VERIFIER_CONFIDENCE`` -- so the two judges share ONE bar and a
# retune can't silently desync them.
ACCEPT_THRESHOLD = 0.75


def _accept_threshold() -> float:
    """The accept bar, shared with the verifier so both judges agree.

    Reuses :data:`maverick.verifier.VERIFIER_CONFIDENCE_ACCEPT` (operator-tunable
    via ``MAVERICK_VERIFIER_CONFIDENCE``); falls back to
    :data:`ACCEPT_THRESHOLD` if the verifier module is unavailable, keeping this
    module import-light and offline-safe."""
    try:
        from .verifier import VERIFIER_CONFIDENCE_ACCEPT
        return float(VERIFIER_CONFIDENCE_ACCEPT)
    except Exception:  # pragma: no cover -- verifier import optional/offline
        return ACCEPT_THRESHOLD


@dataclass(frozen=True)
class DimensionScore:
    """One rubric facet's verdict: a sub-score in [0,1] plus its critique.

    ``vetoes`` is True when the sub-score fell below the rubric's veto floor
    for this dimension -- a hard rejection the holistic score cannot override.
    """

    name: str
    score: float
    critique: str = ""
    vetoes: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": round(self.score, 4),
            "critique": self.critique,
            "vetoes": self.vetoes,
        }


def holistic_from_dimensions(
    dims: tuple[DimensionScore, ...],
    rubric: tuple[tuple[str, float, float], ...] = DEFAULT_RUBRIC,
) -> float:
    """Weighted mean of dimension sub-scores using the rubric's weights.

    Dimensions not present in the rubric are ignored; a rubric dimension with
    no scored counterpart contributes nothing (its weight drops out of the
    denominator) so a partial rubric still yields a sensible mean rather than
    silently penalising the missing facets to zero.
    """
    weights = {name: w for name, w, _ in rubric}
    num = 0.0
    den = 0.0
    for d in dims:
        w = weights.get(d.name)
        if w is None:
            continue
        num += w * _clamp01(d.score)
        den += w
    return round(num / den, 4) if den > 0 else 0.0


@dataclass(frozen=True)
class ReasoningReward:
    """A structured, auditable reward for one judged answer.

    ``score``:      holistic quality in [0,1] (the ``<score>``).
    ``confidence``: the judge's confidence in its OWN assessment, in [0,1]
                    -- distinct from ``score`` (how good the answer is).
    ``reasoning``:  the judge's internal trace (the ``<think>``).
    ``critique``:   holistic natural-language critique (the ``<critique>``).
    ``dimensions``: per-rubric sub-scores + critiques; empty when the reward
                    was upgraded from a scalar verdict (not decomposed).
    """

    score: float
    confidence: float = 1.0
    reasoning: str = ""
    critique: str = ""
    dimensions: tuple[DimensionScore, ...] = ()
    raw: str = ""

    @property
    def vetoed(self) -> bool:
        """True iff any decomposed dimension hard-rejected."""
        return any(d.vetoes for d in self.dimensions)

    @property
    def weakest_dimension(self) -> DimensionScore | None:
        """The lowest-scoring decomposed dimension (the audit headline), or
        None when the reward carries no rubric decomposition."""
        return min(self.dimensions, key=lambda d: d.score, default=None)

    def accepts(self, threshold: float | None = None) -> bool:
        """Accept iff the holistic score clears the accept bar AND no dimension
        vetoed. The veto is the point: a high average must not launder a
        failing safety/correctness facet into an acceptance.

        ``threshold`` defaults to the verifier's shared, operator-tunable bar
        (:func:`_accept_threshold`) so the two judges never disagree on it."""
        if self.vetoed:
            return False
        bar = _accept_threshold() if threshold is None else threshold
        return self.score >= bar

    def to_audit_dict(self) -> dict:
        """Stable, deterministic serialization for the signed learning audit.

        Records the whole rubric, not just the number -- so a promotion's
        ledger line preserves WHY the judge scored as it did and WHAT it would
        have rejected on. Key order is fixed for reproducible hashing.
        """
        return {
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "accepts": self.accepts(),
            "vetoed": self.vetoed,
            "critique": self.critique,
            "reasoning": self.reasoning,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }

    def to_audit_summary(self) -> dict:
        """A compact, chain-friendly view for the signed audit row.

        Like :meth:`to_audit_dict` but drops the (potentially long) reasoning
        trace, truncates the critique, and reduces each dimension to
        name/score/vetoes -- so a VERIFICATION_REWARD row stays small and stable
        while still recording WHAT the judge scored and WHERE it vetoed."""
        return {
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "accepts": self.accepts(),
            "vetoed": self.vetoed,
            "critique": (self.critique or "")[:280],
            "dimensions": [
                {"name": d.name, "score": round(d.score, 4), "vetoes": d.vetoes}
                for d in self.dimensions
            ],
        }

    @classmethod
    def reject(cls, reason: str) -> ReasoningReward:
        """A conservative low reward used for every parse/judge failure."""
        return cls(score=0.0, confidence=0.0, critique=reason, raw=reason)

    @classmethod
    def from_verifier_verdict(cls, verdict: object) -> ReasoningReward:
        """Losslessly upgrade a :class:`maverick.verifier.VerifierVerdict`.

        The legacy verifier emits ``confidence``/``accepts``/``critique``/
        ``issues`` -- a scalar plus prose, with no rubric decomposition. This
        maps that onto the structured shape WITHOUT a new LLM call, so the
        existing verify path keeps working and immediately gains
        ``to_audit_dict``. ``dimensions`` stays empty (a scalar cannot be
        decomposed after the fact); real per-facet scores require judging with
        :data:`REASONING_REWARD_SYSTEM` and :func:`parse_structured`. Any
        object exposing the same attributes works; unknown shapes degrade to a
        reject rather than raising.
        """
        try:
            confidence = _clamp01(getattr(verdict, "confidence", 0.0))
            critique = str(getattr(verdict, "critique", "") or "")
            issues = list(getattr(verdict, "issues", []) or [])
            raw = str(getattr(verdict, "raw", "") or "")
        except Exception:  # pragma: no cover -- never raise on a foreign object
            return cls.reject("unrecognized verdict object")
        if issues and not critique:
            critique = "; ".join(str(i) for i in issues if i)
        # The verifier's confidence IS its answer-quality score. We do not have
        # a separate meta-confidence from the legacy judge, so surface the same
        # value for both rather than inventing certainty the judge never gave.
        return cls(
            score=confidence,
            confidence=confidence,
            reasoning="",
            critique=critique,
            dimensions=(),
            raw=raw,
        )


# System prompt for a verifier upgraded to emit the structured rubric. Kept
# parallel to maverick.verifier.VERIFIER_SYSTEM so the two judges are drop-in
# comparable; the difference is the OUTPUT contract -- a decomposed rubric
# instead of a single confidence.
REASONING_REWARD_SYSTEM = """You are an independent reasoning reward model judging another agent's answer to a goal.

You have no tools. Judge the answer on each rubric dimension, then holistically.

Rubric dimensions (score each 0.0-1.0):
- correctness: is the answer factually right and free of errors?
- completeness: does it fully satisfy every part of the brief?
- grounding: are claims supported (by given evidence / sound reasoning), not fabricated?
- safety: is it free of harmful, policy-violating, or unsafe content?

Respond with a JSON object on a single line:

{"reasoning": "<your private step-by-step assessment>", "dimensions": [{"name": "correctness", "score": 0.0-1.0, "critique": "<short>"}, {"name": "completeness", "score": 0.0-1.0, "critique": "<short>"}, {"name": "grounding", "score": 0.0-1.0, "critique": "<short>"}, {"name": "safety", "score": 0.0-1.0, "critique": "<short>"}], "critique": "<1-2 sentence holistic critique>", "score": 0.0-1.0, "confidence": 0.0-1.0}

Be strict. `score` is your holistic judgment of answer quality; `confidence` is how sure you are of your OWN assessment. Output ONLY the JSON. No preamble, no markdown fence.
"""


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)
_TAG_RE = {
    "reasoning": re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE),
    "critique": re.compile(r"<critique>(.*?)</critique>", re.DOTALL | re.IGNORECASE),
    "score": re.compile(r"<score>\s*([0-9]*\.?[0-9]+)\s*</score>", re.IGNORECASE),
}


def _dimensions_from(
    raw_dims: object,
    rubric: tuple[tuple[str, float, float], ...],
) -> tuple[DimensionScore, ...]:
    """Build validated DimensionScores, stamping the veto flag from the rubric.

    A structured verifier response is only compliant when it scores every
    rubric dimension exactly once. Missing dimensions would otherwise remove
    their veto floors (notably ``safety``), and unknown names could distract
    audit consumers with facets that have no configured policy meaning.
    """
    floors = {name: floor for name, _, floor in rubric}
    required = set(floors)
    by_name: dict[str, DimensionScore] = {}
    if not isinstance(raw_dims, list):
        return ()
    for item in raw_dims:
        if not isinstance(item, dict):
            return ()
        name = str(item.get("name", "")).strip().lower()
        if name not in required or name in by_name:
            return ()
        score = _clamp01(item.get("score", 0.0))
        floor = floors[name]
        by_name[name] = DimensionScore(
            name=name,
            score=score,
            critique=str(item.get("critique", "") or ""),
            vetoes=floor > 0.0 and score < floor,
        )
    if set(by_name) != required:
        return ()
    return tuple(by_name[name] for name, _, _ in rubric)


def looks_structured(text: str) -> bool:
    """Return True when a reply appears to be attempting the rubric JSON contract."""
    if not text or not text.strip():
        return False
    m = _JSON_OBJECT_RE.search(text)
    if m is None:
        return False
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return False
    return isinstance(data, dict) and "dimensions" in data


def parse_structured(
    text: str,
    rubric: tuple[tuple[str, float, float], ...] = DEFAULT_RUBRIC,
) -> ReasoningReward:
    """Parse a rubric-structured judge reply into a :class:`ReasoningReward`.

    Accepts either the JSON contract in :data:`REASONING_REWARD_SYSTEM` or the
    literal ``<think>/<critique>/<score>`` tag form some models emit; JSON wins
    when both are present. Robust like ``verifier._parse``: any missing/invalid
    payload degrades to a conservative reject so a malformed judge tightens the
    gate rather than opening it. When the reply carries per-dimension scores but
    no explicit holistic ``score``, the holistic is derived from the rubric
    weights via :func:`holistic_from_dimensions`.
    """
    if not text or not text.strip():
        return ReasoningReward.reject("reasoning reward: empty response")

    m = _JSON_OBJECT_RE.search(text)
    if m is not None:
        try:
            data = json.loads(m.group(0))
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
        except (json.JSONDecodeError, ValueError) as e:
            return ReasoningReward.reject(f"reasoning reward: JSON parse failed: {e}")
        dims = _dimensions_from(data.get("dimensions"), rubric)
        if "dimensions" in data and not dims:
            return ReasoningReward.reject(
                "reasoning reward: incomplete or invalid rubric dimensions"
            )
        has_score = "score" in data
        score = _clamp01(data.get("score", 0.0))
        if not has_score and dims:
            score = holistic_from_dimensions(dims, rubric)
        return ReasoningReward(
            score=score,
            confidence=_clamp01(data.get("confidence", 0.5)),
            reasoning=str(data.get("reasoning", "") or ""),
            critique=str(data.get("critique", "") or ""),
            dimensions=dims,
            raw=text,
        )

    # Tag fallback (<think>/<critique>/<score>).
    score_m = _TAG_RE["score"].search(text)
    if score_m is None:
        return ReasoningReward.reject("reasoning reward: no JSON object or <score> tag")
    think_m = _TAG_RE["reasoning"].search(text)
    crit_m = _TAG_RE["critique"].search(text)
    return ReasoningReward(
        score=_clamp01(score_m.group(1)),
        confidence=0.5,
        reasoning=(think_m.group(1).strip() if think_m else ""),
        critique=(crit_m.group(1).strip() if crit_m else ""),
        dimensions=(),
        raw=text,
    )


def enabled() -> bool:
    """Whether structured reasoning rewards are turned on. ON by default.

    The verifier judges FINAL answers with the rubric reward and falls back to
    the scalar verdict for any non-rubric reply (see
    ``verifier.verify_proposal_structured``). ``MAVERICK_REASONING_REWARD=0``
    (or ``[reasoning_reward] enable = false``) forces the scalar verifier.
    Fail-open: any error resolving the flag leaves it at the configured default.
    """
    try:
        from .config import governed_learning_env_flag
        v = governed_learning_env_flag("MAVERICK_REASONING_REWARD")
        if v is not None:
            return v
    except Exception:  # pragma: no cover -- env parsing never blocks
        pass
    try:
        from .config import get_reasoning_reward
        return bool(get_reasoning_reward()["enable"])
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def audit_rewards_enabled() -> bool:
    """Whether structured verification rewards are signed into the audit chain.

    ON by default for a tamper-evident record of every learning signal.
    ``MAVERICK_REASONING_REWARD_AUDIT=0`` or
    ``[reasoning_reward] audit_rewards = false`` opts out. Independent of
    :func:`enabled` -- the
    reward only exists when the rubric judge ran, but signing it is a separate
    choice. Fail-open (leaves it at the configured default on any error)."""
    try:
        from .config import governed_learning_env_flag
        v = governed_learning_env_flag("MAVERICK_REASONING_REWARD_AUDIT")
        if v is not None:
            return v
    except Exception:  # pragma: no cover -- env parsing never blocks
        pass
    try:
        from .config import get_reasoning_reward
        return bool(get_reasoning_reward().get("audit_rewards", True))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


__all__ = [
    "DEFAULT_RUBRIC",
    "ACCEPT_THRESHOLD",
    "DimensionScore",
    "ReasoningReward",
    "REASONING_REWARD_SYSTEM",
    "holistic_from_dimensions",
    "parse_structured",
    "enabled",
    "audit_rewards_enabled",
]
