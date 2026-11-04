"""Per-rung producers -- every self-improvement rung, one governed gate.

The :mod:`maverick.self_improvement` controller owns the safety spine (beats
baseline, never widens capability, human-gated at high rungs, reversible, frozen
on verifier drift, signed + audited). This module is the set of *producers* that
turn each rung's work into a :class:`~maverick.self_improvement.Candidate` and
push it through that one gate, so no rung re-invents its own safety:

* ``propose_prompt`` / ``propose_policy`` -- strategy (prompts, playbooks,
  routing policies) and a trained policy/adapter, once the caller's RL seam
  has produced one.
* ``propose_tool`` -- a synthesized tool earns promotion only when its
  measured success rate beats the baseline; the :class:`ToolOutcomeTracker`
  supplies that evidence.
* ``propose_verifier`` -- a retrained verifier head is adopted only if it
  discriminates better than the incumbent.
* ``propose_code`` -- a code self-modification must pass an out-of-process
  ``validate`` seam *before* it can even reach the gate, which then forces
  human approval + non-escalation + reversibility.
* ``propose_weights`` -- a fine-tuned checkpoint, human-gated.

The GPU/codegen work (RL training, head training, diff generation, fine-tuning)
is always an injected seam supplied by the caller -- this module never fakes a
trained model; it governs *adoption* of whatever the seam produced.
"""
from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_file,
)
from .promotion_effect import EffectEstimate
from .self_improvement import (
    Candidate,
    GateResult,
    SelfImprovementController,
    Verdict,
    consider,
)

log = logging.getLogger(__name__)


# -- tool evidence: did a synthesized tool actually help? -------------------

@dataclass
class ToolOutcomeTracker:
    """Per-tool use/success tally -- the reward signal for synthesized tools."""

    path: Path | None = None
    _stats: dict[str, list[int]] = field(default_factory=dict)  # name -> [uses, wins]
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.path is not None:
            self._load()

    def record(self, name: str, success: bool) -> None:
        if not name:
            return
        with self._lock:
            if self.path is not None:
                try:
                    path = Path(self.path)
                    # The tally is a read-modify-write.  Serialize the whole
                    # operation so two worker processes cannot both read N and
                    # publish N+1, silently losing one training outcome.
                    with cross_process_lock(path, strict=True):
                        stats = self._read_stats(path)
                        s = stats.setdefault(name, [0, 0])
                        s[0] += 1
                        if success:
                            s[1] += 1
                        atomic_write_text(path, json.dumps(stats, sort_keys=True))
                    self._stats = stats
                    return
                except Exception:  # pragma: no cover -- evidence is best-effort
                    log.debug("tool outcome save failed", exc_info=True)
            s = self._stats.setdefault(name, [0, 0])
            s[0] += 1
            if success:
                s[1] += 1

    def success_rate(self, name: str) -> float:
        with self._lock:
            s = self._stats.get(name)
            return (s[1] / s[0]) if s and s[0] else 0.0

    def samples(self, name: str) -> int:
        with self._lock:
            s = self._stats.get(name)
            return s[0] if s else 0

    def _load(self) -> None:
        try:
            self._stats = self._read_stats(Path(self.path))
        except OSError:
            return

    @staticmethod
    def _read_stats(path: Path) -> dict[str, list[int]]:
        if not path.exists():
            return {}
        path = ensure_private_file(path)
        try:
            raw = json.loads(atomic_read_text(path))
        except ValueError:
            return {}
        if not isinstance(raw, dict):
            return {}
        out: dict[str, list[int]] = {}
        for k, v in (raw or {}).items():
            try:
                out[str(k)] = [int(v[0]), int(v[1])]
            except (TypeError, ValueError, IndexError):
                continue
        return out

    def _save(self) -> None:
        if self.path is None:
            return
        try:
            atomic_write_text(
                Path(self.path), json.dumps(self._stats, sort_keys=True),
            )
        except Exception:  # pragma: no cover -- best-effort
            log.debug("tool outcome save failed", exc_info=True)


# -- producers (each builds a Candidate and runs it through the one gate) ----

def _propose(rung: str, summary: str, baseline: float, candidate: float, samples: int,
             *, controller: SelfImprovementController | None = None,
             capability_widens: bool | None = None, approved: bool = False,
             rollback=None, payload=None, provenance: dict | None = None,
             approve=None) -> Verdict:
    cand = Candidate(
        rung=rung, summary=summary, baseline_score=baseline, candidate_score=candidate,
        samples=samples, capability_widens=capability_widens, approved=approved,
        rollback=rollback, payload=payload, provenance=provenance or {},
    )
    if approve is not None:
        try:
            from .approval_signing import ApprovalRequest

            request = ApprovalRequest.for_candidate(cand)
            signature = approve(request)
            if signature:
                cand.approval_signature = str(signature)
                cand.payload_sha256 = request.payload_sha256
        except Exception:
            log.warning("self-improvement approval request failed", exc_info=True)
    return consider(cand, controller=controller)


def propose_prompt(summary, baseline, candidate, samples, *, rollback,
                   controller=None, **prov) -> Verdict:
    """A new prompt/playbook variant (no capability surface)."""
    return _propose("prompt", summary, baseline, candidate, samples,
                    controller=controller, rollback=rollback, provenance=prov)


def propose_policy(summary, baseline, candidate, samples, *, rollback,
                   capability_widens=False, approved=False, controller=None, **prov) -> Verdict:
    """A trained routing/decision policy or strategy change."""
    return _propose("policy", summary, baseline, candidate, samples,
                    controller=controller, capability_widens=capability_widens,
                    approved=approved, rollback=rollback, provenance=prov)


def propose_tool(name, tracker: ToolOutcomeTracker, baseline_success, *, rollback,
                 capability_widens=None, controller=None, **prov) -> Verdict:
    """Promote a synthesized tool only if its measured success beats baseline.

    ``capability_widens`` defaults to ``None`` (UNPROVEN), not ``False``. A new
    tool is a capability surface by definition, so asserting non-escalation by
    default made the capability gate -- the very control the tool rung exists for
    -- vacuous: any tool sailed through. ``None`` fails closed at the tool rung
    (require_capability_evidence=True); the caller must PROVE non-escalation
    (pass ``capability_widens=False`` from a real ``capability`` delta, or supply
    before/after grants + probe tools on the candidate) for a tool to promote.
    """
    return _propose(
        "tool", f"synthesized tool {name!r}", baseline_success,
        tracker.success_rate(name), tracker.samples(name),
        controller=controller, capability_widens=capability_widens,
        rollback=rollback, payload={"tool": name},
        provenance={"tool": name, **prov},
    )


def propose_with_effect(rung, summary, effect: EffectEstimate, *, rollback,
                        capability_widens=False, approved=False, controller=None,
                        **prov) -> Verdict:
    """Submit a calibrated effect estimate to the promotion gate.

    Observational strata are useful diagnostic evidence, but do not clear this
    gate. A promotion-grade estimate requires prospectively randomized units,
    overlap, and a significant comparison to shuffled assignments. The
    provenance records the design and uncertainty for review.
    """
    provenance = {
        "kind": "randomized_effect" if effect.randomized else "observational_comparison",
        "ci": [round(effect.ci_low, 6), round(effect.ci_high, 6)],
        "naive": round(effect.naive_effect, 6),
        "adjusted_for": list(effect.adjusted_for),
        "n": effect.n_used,
        "overlap": round(effect.overlap, 4),
        "placebo": round(effect.placebo_effect, 6),
        "permutation_p_value": round(effect.permutation_p_value, 6),
        "randomized": effect.randomized,
        "trustworthy": effect.trustworthy,
        **prov,
    }
    cand = Candidate(
        rung=rung, summary=summary, baseline_score=0.0,
        candidate_score=effect.effect, samples=effect.n_used,
        effect_ci_low=effect.ci_low, capability_widens=capability_widens,
        approved=approved, rollback=rollback, provenance=provenance,
    )
    if not effect.trustworthy or not effect.randomized:
        return Verdict(
            cand.id, rung, False,
            (GateResult("effect_calibration", False,
                        "effect needs a controlled comparison with sufficient overlap and clear evidence"),),
            "effect estimate not trustworthy",
        )
    return consider(cand, controller=controller)


def propose_verifier(summary, baseline_discrimination, candidate_discrimination, samples,
                     *, rollback, controller=None, approve=None, **prov) -> Verdict:
    """Adopt a retrained verifier head only if it discriminates better.

    A better *judge* doesn't widen authority, so capability is bounded by
    construction. It uses the dedicated evaluator rung: by default that sits
    above the autonomous policy ceiling and therefore requires human approval;
    deployments must explicitly opt into autonomous evaluator co-evolution or
    provide ``approve(ApprovalRequest) -> signature`` from an external signer.
    """
    provenance = {"kind": "verifier", **prov}
    return _propose("evaluator", f"verifier update: {summary}",
                    baseline_discrimination, candidate_discrimination, samples,
                    controller=controller, capability_widens=False,
                    rollback=rollback,
                    payload={
                        "kind": "verifier", "summary": str(summary),
                        "baseline_discrimination": baseline_discrimination,
                        "candidate_discrimination": candidate_discrimination,
                        "samples": samples, "provenance": provenance,
                    },
                    provenance=provenance, approve=approve)


def propose_code(summary, *, validate: Callable[[], tuple[bool, str]],
                 eval_before: float, eval_after: float, samples: int, rollback,
                 approved: bool = False, capability_widens: bool | None = None,
                 controller=None, **prov) -> Verdict:
    """A code self-modification. Must pass an out-of-process ``validate``
    seam (sandboxed import/shape/safety check) BEFORE the gate; then the
    controller forces human approval + non-escalation + reversibility.
    """
    try:
        ok, reason = validate()
    except Exception:  # pragma: no cover -- a failing validator fails closed
        ok, reason = False, "validate seam raised"
    if not ok:
        cand_id = "code-rejected"
        return Verdict(cand_id, "code", False,
                       (GateResult("validate", False, reason or "validation failed"),),
                       reason or "validation failed")
    return _propose("code", summary, eval_before, eval_after, samples,
                    controller=controller, capability_widens=capability_widens,
                    approved=approved, rollback=rollback, provenance={"kind": "code", **prov})


def propose_weights(summary, *, eval_before: float, eval_after: float, samples: int,
                    rollback, approved: bool = False, controller=None, **prov) -> Verdict:
    """Adopt a fine-tuned checkpoint (human-gated, reversible)."""
    return _propose("weights", summary, eval_before, eval_after, samples,
                    controller=controller, capability_widens=False,
                    approved=approved, rollback=rollback, provenance={"kind": "weights", **prov})


_tracker_shared: dict[Path, ToolOutcomeTracker] = {}
_tracker_lock = threading.Lock()


def shared_tracker() -> ToolOutcomeTracker:
    from .file_lock import ensure_private_directory
    from .paths import data_dir

    path = data_dir("tool_outcomes.json")
    with _tracker_lock:
        t = _tracker_shared.get(path)
        if t is None:
            ensure_private_directory(path.parent)
            t = ToolOutcomeTracker(path=path)
            _tracker_shared[path] = t
        return t


def reset_shared_tracker() -> None:
    with _tracker_lock:
        _tracker_shared.clear()


__all__ = [
    "ToolOutcomeTracker", "shared_tracker", "reset_shared_tracker",
    "propose_prompt", "propose_policy", "propose_tool",
    "propose_verifier", "propose_code", "propose_weights",
    "propose_with_effect",
]
