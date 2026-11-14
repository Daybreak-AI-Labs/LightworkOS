"""Governed self-improvement: the promotion ladder that makes learning *safe*.

Lightwork *learns* in several places (skills, reflexions, dreams, config
evolution). This module is the single governed gate that decides whether a
proposed self-change is allowed to take effect. A system that rewrites
*itself* in production is deployable only with **interlocks**: a
change may take effect only if it (a) measurably beats its own baseline, (b)
never widens the capability envelope, (c) is approved by a human at the rungs
that touch tools/code/weights, (d) is reversible, and (e) is refused outright
while the verifier is mis-calibrated (so the system can't learn from its own
drift). Every promotion is signed into the audit chain.

This module is that controller. It does NOT train models -- the per-rung work
(RL on trajectories, tool synthesis, code self-mod, fine-tuning) is injected as
opaque candidate payloads. It owns the *governance spine* shared by every rung,
so each new self-improvement capability inherits the same provable safety
properties instead of re-litigating them.

Rungs, lowest -> highest risk: ``config`` -> ``prompt`` -> ``tool`` ->
``policy`` -> ``code`` -> ``weights``. Higher rungs require capability evidence
and human approval; the lowest may auto-promote once they beat their baseline.

Posture: ON by default for governed prompt/policy learning, with an explicit
opt-out. The gates fail **closed**: a promotion is a privileged write, so a
broken gate, missing evidence, or any error rejects the change rather than
letting it through. Code/weight authority and DGM execution remain separately
gated. The engine being off is a no-op; the engine deciding will not promote on
doubt.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import stat
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .learning_guard import Halted, check_learning_halt

log = logging.getLogger(__name__)

# Rungs ordered by blast radius. Index == risk rank. ``evaluator`` (swapping the
# learned judge a whole role is scored by -- see maverick.evaluator_evolution)
# sits above ``policy``: it reshapes the entire learning signal so it is more
# consequential than a policy tweak, but an evaluator only *scores* -- it never
# grants a tool or executes code -- so it is strictly less dangerous than a
# ``code``/``weights`` edit and carries no capability-escalation surface.
RUNGS: tuple[str, ...] = (
    "config", "prompt", "tool", "policy", "evaluator", "code", "weights")


def _rung_rank(rung: str) -> int:
    try:
        return RUNGS.index(rung)
    except ValueError:
        # Unknown rung is treated as the most dangerous -- fail closed.
        return len(RUNGS)


def _ceiling_rank(rung: str) -> int:
    """Rank of the autonomous-promotion CEILING (``max_auto_rung``).

    A ceiling must fail closed in the OPPOSITE direction from a candidate rung:
    an unknown/typo ceiling ("polciy") must behave as the MOST restrictive
    ceiling -- below every real rung -- so every promotion still needs human
    approval. Reusing :func:`_rung_rank` here would return ``len(RUNGS)`` (the
    highest possible), which silently DISABLES the ceiling (nothing is ever
    "above" it) -- fail-open, the exact opposite of the intent."""
    try:
        return RUNGS.index(rung)
    except ValueError:
        return -1


# Per-rung gate policy. ``require_capability_evidence`` forces a non-escalation
# proof (a change that can't show it didn't widen authority is refused at and
# above ``tool``). ``require_human`` gates code/weights behind explicit sign-off.
_RUNG_POLICY: dict[str, dict[str, Any]] = {
    "config":  {"min_samples": 3,  "require_capability_evidence": False, "require_human": False},
    "prompt":  {"min_samples": 5,  "require_capability_evidence": False, "require_human": False},
    "tool":    {"min_samples": 5,  "require_capability_evidence": True,  "require_human": False},
    "policy":  {"min_samples": 8,  "require_capability_evidence": True,  "require_human": False},
    # An evaluator scores; it cannot widen the capability envelope, so no
    # non-escalation proof is demanded (it would be vacuous). It needs a high
    # anchor-evidence floor because swapping the judge re-ranks everything it
    # scores. ``require_human`` is False so an operator can opt into autonomous
    # co-evolution by raising ``max_auto_rung`` to ``evaluator``; until then it
    # sits above the default ceiling (``policy``) and a swap needs approval.
    "evaluator": {"min_samples": 12, "require_capability_evidence": False, "require_human": False},
    "code":    {"min_samples": 10, "require_capability_evidence": True,  "require_human": True},
    "weights": {"min_samples": 20, "require_capability_evidence": True,  "require_human": True},
}


def enabled() -> bool:
    """Whether governed prompt/policy learning may promote. ON by default."""
    try:
        from .config import (
            config_source_errors,
            get_self_improvement,
            governed_learning_env_flag,
        )
        if config_source_errors(include_tenant=True):
            # Unreadable configuration may hide ``enable = false``.
            return False
        override = governed_learning_env_flag("MAVERICK_SELF_IMPROVEMENT")
        base = (override if override is not None
                else bool(get_self_improvement().get("enable", True)))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False
    return base


_FROZEN_CONFIG = {"enable": False, "min_improvement": -1.0, "max_auto_rung": "policy"}


def _config() -> dict:
    try:
        from .config import config_source_errors, get_self_improvement
        if config_source_errors(include_tenant=True):
            # ``load_config`` returns defaults for an unreadable file; the
            # operator's margin and ceiling may be lost, so freeze instead.
            return dict(_FROZEN_CONFIG)
        return get_self_improvement()
    except Exception:  # pragma: no cover
        # Invalid margin freezes the controller if a direct caller constructs it
        # despite the disabled master switch. Never turn config loss into the
        # permissive zero-margin policy.
        return dict(_FROZEN_CONFIG)


@dataclass
class Candidate:
    """A proposed self-change awaiting promotion.

    The controller is agnostic to *what* changed -- ``payload`` is opaque (a
    config diff, a new tool's source, a trained adapter ref). It judges only the
    evidence: did it beat baseline, did authority stay bounded, is it reversible.

    Capability non-escalation can be proven two ways: pass ``capability_widens``
    directly (the caller computed it with ``maverick.capability``), or pass
    ``capability_before``/``capability_after`` plus ``probe_tools`` and let the
    gate check that the change permits no tool the prior grant didn't.
    """

    rung: str
    summary: str
    baseline_score: float
    candidate_score: float
    samples: int = 0
    payload: Any = None
    # When set, the evidence gate judges the change on the LOWER confidence bound
    # of its estimated *causal* effect (maverick.promotion_effect) instead of the
    # raw candidate-vs-baseline difference: promote only when we're confident the
    # change actually *caused* the improvement, not merely correlated with it.
    effect_ci_low: float | None = None
    capability_widens: bool | None = None
    capability_before: Any = None
    capability_after: Any = None
    probe_tools: tuple[str, ...] = ()
    approved: bool = False
    # Cryptographic human approval (maverick.approval_signing). When a deployment
    # configures trusted approver keys, the ``approved`` boolean above is
    # IGNORED at human-gated rungs and a valid Ed25519 signature over
    # (id, rung, payload digest) is required instead -- a self-modifying agent
    # cannot forge it. ``payload_sha256`` pins WHAT was approved (defaults to a
    # digest of ``payload``) so an approval can't be replayed onto a swapped
    # payload. Both unused unless signing is enforced (backward compatible).
    approval_signature: str | None = None
    payload_sha256: str | None = None
    # Truthy iff the change can be undone (a snapshot id / revert handle). A
    # change that can't be rolled back is never promoted.
    rollback: Any = None
    provenance: dict = field(default_factory=dict)
    # Event-specific fields for the durable promotion audit receipt.  Artifact
    # owners can attach diagnostic evidence (for example the self-harness line
    # and held-out score) without teaching the generic ledger about that
    # producer.  The controller supplies and pins event identity, decision,
    # candidate, rung, and occurrence time.
    audit_payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass(frozen=True)
class GateResult:
    gate: str
    ok: bool
    reason: str = ""


@dataclass(frozen=True)
class Verdict:
    """Outcome of evaluating a candidate. ``promote`` is the AND of all gates."""

    candidate_id: str
    rung: str
    promote: bool
    gates: tuple[GateResult, ...]
    blocking_reason: str = ""
    # The approver key-id whose signature satisfied the human-approval gate
    # (maverick.approval), or None when human approval was a boolean / not
    # required. Recorded in the signed audit line for a promotion.
    approver_id: str | None = None
    # Exact binding that the Model Risk verifier actually checked.  This is
    # captured during evaluation and carried into PREPARE so mutable candidate
    # state cannot swap the journaled payload after authorization.
    model_risk_payload_sha256: str | None = None
    # How the capability gate judged authority, carried out of evaluation so the
    # promotion receipt can record it. The gate's *decision* is not enough for a
    # third party: it refuses a widening change, but a receipt that omits the
    # grading leaves "proven bounded" and "never checked" indistinguishable.
    capability_evidence: str | None = None
    capability_probe_tools: int | None = None

    @property
    def ok(self) -> bool:
        return self.promote


@dataclass(frozen=True)
class PromotionRecord:
    id: str
    rung: str
    summary: str
    baseline_score: float
    candidate_score: float
    promoted_at: float
    rolled_back: bool = False
    rolled_back_at: float | None = None
    # Signature material so a THIRD PARTY can re-verify the promotion from the
    # ledger file alone. All default to None so
    # a ledger written before this field existed still loads, and a promotion
    # with no cryptographic approval (dev/community path) records them as None --
    # i.e. this is purely additive and backward-compatible.
    #  * approver_id       -- key-id whose Ed25519 signature satisfied the gate
    #  * payload_sha256     -- digest the approver signed (pins WHAT was approved)
    #  * approval_signature -- the hex Ed25519 signature over (id, rung, digest)
    approver_id: str | None = None
    payload_sha256: str | None = None
    approval_signature: str | None = None
    # Exact actual-payload binding, used to re-read Model Risk authority at the
    # artifact-application, COMMIT, and crash-recovery boundaries.  This is
    # separate from ``payload_sha256`` because that legacy field exists only
    # when an Ed25519 human-approval signature is present.
    model_risk_payload_sha256: str | None = None
    # Evidence/provenance is part of the authoritative receipt, not merely a
    # best-effort audit event.  Defaults preserve compatibility with journals
    # written before evidence-bearing external-artifact transactions existed.
    samples: int | None = None
    effect_ci_low: float | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    # Bounded producer-specific evidence copied into the durable audit outbox
    # when the promotion journal commits.  Omitted for legacy receipts.
    audit_payload: dict[str, Any] = field(default_factory=dict)
    # How the capability non-escalation gate judged THIS promotion, so the claim
    # "self-improvement never widened its authority" is checkable from the
    # ledger file rather than taken on the issuer's word. One of
    # ``probed_bounded`` / ``declared_bounded`` / ``unproven``. ``None`` means the
    # receipt predates the field -- which a verifier must read as "unknown", NOT
    # as bounded: a receipt written before anyone recorded the grading cannot
    # retroactively prove anything about it.
    capability_evidence: str | None = None
    capability_probe_tools: int | None = None

    def to_dict(self) -> dict:
        data = {
            "id": self.id, "rung": self.rung, "summary": self.summary,
            "baseline_score": self.baseline_score,
            "candidate_score": self.candidate_score,
            "promoted_at": self.promoted_at,
            "rolled_back": self.rolled_back,
            "rolled_back_at": self.rolled_back_at,
            "approver_id": self.approver_id,
            "payload_sha256": self.payload_sha256,
            "approval_signature": self.approval_signature,
        }
        # Do not rewrite legacy receipts just because a newer reader loaded
        # them.  New evidence-bearing receipts opt in to these fields.
        if self.samples is not None:
            data["samples"] = self.samples
        if self.effect_ci_low is not None:
            data["effect_ci_low"] = self.effect_ci_low
        if self.provenance:
            data["provenance"] = self.provenance
        if self.audit_payload:
            data["audit_payload"] = self.audit_payload
        if self.model_risk_payload_sha256 is not None:
            data["model_risk_payload_sha256"] = self.model_risk_payload_sha256
        if self.capability_evidence is not None:
            data["capability_evidence"] = self.capability_evidence
        if self.capability_probe_tools is not None:
            data["capability_probe_tools"] = self.capability_probe_tools
        return data


@dataclass(frozen=True)
class ArtifactRevision:
    """Content-addressed identity of one deployable runtime artifact.

    ``identity`` names the logical artifact (not merely a temporary file),
    ``sha256`` pins its canonical source-of-truth bytes, and ``version`` is the
    store's independently checked revision/CAS token.  Promotion transactions
    require all three fields to match; a digest without an artifact identity or
    revision is too easy to replay against the wrong deployment generation.
    """

    identity: str
    sha256: str
    version: str

    def __post_init__(self) -> None:
        identity = self.identity.strip() if isinstance(self.identity, str) else ""
        digest = self.sha256.lower() if isinstance(self.sha256, str) else ""
        version = self.version.strip() if isinstance(self.version, str) else ""
        if not identity or len(identity) > 2048 or any(ord(ch) < 32 for ch in identity):
            raise ValueError("artifact identity must be a non-empty printable string")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("artifact sha256 must be 64 lowercase hexadecimal characters")
        if not version or len(version) > 512 or any(ord(ch) < 32 for ch in version):
            raise ValueError("artifact version must be a non-empty printable string")
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "version", version)

    def to_dict(self) -> dict[str, str]:
        return {
            "identity": self.identity,
            "sha256": self.sha256,
            "version": self.version,
        }


@dataclass(frozen=True)
class PromotionTransaction:
    """Durable write-ahead intent bridging governance and runtime state.

    Only ``committed`` transactions appear in the historical promotion-record
    projection.  ``prepared`` transactions are deliberately fail-closed: they
    reserve their artifact identity until recovery proves that the artifact is
    exactly the declared before or after revision.
    """

    id: str
    record: PromotionRecord
    before: ArtifactRevision
    after: ArtifactRevision
    prepared_at: float
    state: str = "prepared"
    resolved_at: float | None = None
    reason: str = ""
    last_observed: ArtifactRevision | None = None
    recovery_attempts: int = 0

    @property
    def in_doubt(self) -> bool:
        return self.state == "prepared"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "record": self.record.to_dict(),
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "prepared_at": self.prepared_at,
            "state": self.state,
            "resolved_at": self.resolved_at,
            "reason": self.reason,
            "last_observed": (
                self.last_observed.to_dict() if self.last_observed is not None else None),
            "recovery_attempts": self.recovery_attempts,
        }


@dataclass(frozen=True)
class PromotionPreparation:
    """Gate verdict plus the durable transaction it authorized, when any."""

    verdict: Verdict
    transaction: PromotionTransaction | None = None

    @property
    def ok(self) -> bool:
        return self.verdict.ok and self.transaction is not None

    @property
    def blocking_reason(self) -> str:
        return self.verdict.blocking_reason

    @property
    def needs_apply(self) -> bool:
        return self.ok and self.transaction is not None and self.transaction.state == "prepared"

    @property
    def committed(self) -> bool:
        return self.ok and self.transaction is not None and self.transaction.state == "committed"

    @property
    def transaction_id(self) -> str | None:
        return self.transaction.id if self.transaction is not None else None


class PromotionLedgerError(RuntimeError):
    """The durable promotion receipt could not be read or committed.

    Promotion is a privileged state transition. Callers must treat this as a
    failed commit rather than as a logging warning: a missing, malformed, or
    mismatched receipt means the system cannot prove what was promoted.
    """


def _canonical_json(value: Any) -> str:
    """Return the one byte representation used by journal hash links."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _receipt_provenance(value: Any) -> dict[str, Any]:
    """Return bounded, canonical JSON provenance for a durable receipt.

    A candidate may be supplied by an extension, so arbitrary Python objects,
    non-finite numbers, integer keys, and unbounded blobs must not reach the
    hash-chained promotion journal.  Invalid provenance fails the privileged
    transition closed instead of silently dropping the evidence lineage.
    """
    if not isinstance(value, dict):
        raise ValueError("promotion provenance must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError("promotion provenance keys must be strings")
    canonical = _canonical_json(value)
    if len(canonical.encode("utf-8")) > 32_768:
        raise ValueError("promotion provenance exceeds 32768 bytes")
    parsed = json.loads(canonical)
    if not isinstance(parsed, dict):  # pragma: no cover - guarded above
        raise ValueError("promotion provenance must be an object")
    return parsed


def _receipt_audit_payload(value: Any) -> dict[str, Any]:
    """Return a bounded canonical JSON object for an audit-outbox receipt."""
    if not isinstance(value, dict):
        raise ValueError("promotion audit payload must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError("promotion audit payload keys must be strings")
    canonical = _canonical_json(value)
    if len(canonical.encode("utf-8")) > 32_768:
        raise ValueError("promotion audit payload exceeds 32768 bytes")
    parsed = json.loads(canonical)
    if not isinstance(parsed, dict):  # pragma: no cover - guarded above
        raise ValueError("promotion audit payload must be an object")
    return parsed


def _capability_assessment(cand: Candidate) -> tuple[bool | None, str, int | None]:
    """Judge authority widening AND record *how* it was judged.

    Returns ``(widens, method, probe_tools)`` where ``widens`` is True=widened /
    False=bounded / None=unknown, ``method`` names the evidence that produced it
    (``"declared"``, ``"probed"``, or ``"none"``), and ``probe_tools`` is the
    size of the probe set when one was actually walked.

    The gate only needs ``widens``, but a promotion *receipt* needs the other
    two: "the caller asserted authority stayed bounded" and "the capability
    algebra was walked over 40 tools and permitted none of them newly" are very
    different grades of proof, and a third party reading the ledger later has no
    way to tell them apart unless we write down which one happened. Collapsing
    them would let a bare assertion be read as a probe — the same laundering the
    evaluator-anchor lock exists to prevent.
    """
    if cand.capability_widens is not None:
        # Strings such as "" or "false" must not masquerade as a proof about
        # authority. Unknown/ill-typed evidence is handled fail-closed by the
        # rung policy below.
        if isinstance(cand.capability_widens, bool):
            return cand.capability_widens, "declared", None
        return None, "none", None
    before, after = cand.capability_before, cand.capability_after
    if before is None or after is None or not cand.probe_tools:
        return None, "none", None
    try:
        for tool in cand.probe_tools:
            if after.permits(tool) and not before.permits(tool):
                return True, "probed", len(cand.probe_tools)
        return False, "probed", len(cand.probe_tools)
    except Exception:  # pragma: no cover -- can't prove -> caller treats as unknown
        return None, "none", None


def _capability_widens(cand: Candidate) -> bool | None:
    """Did the change widen authority? True=widened, False=bounded, None=unknown."""
    return _capability_assessment(cand)[0]


# The three honest capability gradings a *promoted* receipt can carry. A
# widening change never promotes (the gate refuses it), so "widened" is
# deliberately not among them.
CAPABILITY_PROBED_BOUNDED = "probed_bounded"
CAPABILITY_DECLARED_BOUNDED = "declared_bounded"
CAPABILITY_UNPROVEN = "unproven"


def _capability_evidence_label(widens: bool | None, method: str) -> str:
    """The grading written into a promotion receipt."""
    if widens is False and method == "probed":
        return CAPABILITY_PROBED_BOUNDED
    if widens is False and method == "declared":
        return CAPABILITY_DECLARED_BOUNDED
    # widens is None -- the rung did not require capability evidence and none
    # was supplied. Recorded as unproven rather than omitted: silence in a
    # receipt reads as "field predates the schema", which is a different and
    # weaker statement than "we looked and could not prove it".
    return CAPABILITY_UNPROVEN


def _valid_rollback_handle(handle: Any) -> bool:
    """Require an inspectable rollback reference, not a truthy placeholder."""
    if isinstance(handle, str):
        return bool(handle.strip()) and len(handle) <= 4096
    if isinstance(handle, Mapping):
        return bool(handle)
    return callable(handle)


def _default_frozen_fn() -> bool:
    try:
        from .calibration import learning_frozen
        return bool(learning_frozen())
    except Exception:  # pragma: no cover -- if we can't check, fail closed below
        raise


def _default_audit_fn(**payload: Any) -> bool:
    """Deliver one audit receipt while preserving explicit refusal semantics."""
    from .audit import EventKind, audit_event

    event_payload = dict(payload)
    agent = str(event_payload.pop("_audit_agent", "self_improvement"))
    return audit_event(
        EventKind.LEARNING_UPDATE,
        agent=agent,
        **event_payload,
    )


@dataclass
class SelfImprovementController:
    """Decide, record, and reverse self-changes under the safety interlocks."""

    min_improvement: float = 0.0
    max_auto_rung: str = "policy"
    frozen_fn: Callable[[], bool] = _default_frozen_fn
    audit_fn: Callable[..., bool | None] = _default_audit_fn
    ledger: PromotionLedger | None = None
    now: Callable[[], float] = time.time
    # Optional request-scoped verifier for deployments whose approval trust
    # root is tenant-bound.  Keeping this on the controller avoids mutating
    # process-global environment variables while another tenant is evaluating
    # a candidate.  It returns the trusted approver id or ``None``.
    approval_verifier: Callable[[Candidate], str | None] | None = None
    # Optional request-scoped Model Risk verifier. The default verifier reads
    # governed officer policy and the exact current CAS authorization.
    model_risk_verifier: Callable[..., tuple[bool, str]] | None = None
    rung_policy: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {k: dict(v) for k, v in _RUNG_POLICY.items()})

    # -- the gate pipeline (pure; no side effects) ------------------------

    def evaluate(self, cand: Candidate) -> Verdict:
        """Run every gate. Promotion requires ALL to pass; gates fail closed."""
        gates: list[GateResult] = []

        # 0. Known rung.
        if not isinstance(cand.rung, str):
            return self._reject(
                cand, [GateResult("rung", False, "candidate rung must be a string")])
        policy = self.rung_policy.get(cand.rung)
        if policy is None:
            return self._reject(cand, [GateResult("rung", False, f"unknown rung {cand.rung!r}")])

        # 1. Calibration interlock: never learn while the verifier is drifting.
        try:
            frozen = self.frozen_fn()
        except Exception:
            frozen = True  # can't confirm the judge is honest -> fail closed
        gates.append(GateResult("calibration", not frozen,
                                "" if not frozen else "learning frozen: verifier mis-calibrated"))

        # 2. Evidence: must beat its own baseline by the margin, with enough
        #    samples. For a causal candidate (effect_ci_low set) the bar is the
        #    LOWER confidence bound of the estimated effect -- promote only when
        #    we're confident the change *caused* the win, not merely correlated.
        valid_scores = all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)) and 0.0 <= float(value) <= 1.0
            for value in (cand.baseline_score, cand.candidate_score)
        )
        valid_samples = (
            isinstance(cand.samples, int) and not isinstance(cand.samples, bool)
            and 0 <= cand.samples <= 1_000_000_000
        )
        valid_effect = (
            cand.effect_ci_low is None
            or (isinstance(cand.effect_ci_low, (int, float))
                and not isinstance(cand.effect_ci_low, bool)
                and math.isfinite(float(cand.effect_ci_low))
                and -1.0 <= float(cand.effect_ci_low) <= 1.0)
        )
        valid_margin = (
            isinstance(self.min_improvement, (int, float))
            and not isinstance(self.min_improvement, bool)
            and math.isfinite(float(self.min_improvement))
            and 0.0 <= float(self.min_improvement) <= 1.0
        )
        if not (valid_scores and valid_samples and valid_effect and valid_margin):
            gates.append(GateResult(
                "evidence", False,
                "invalid evidence: scores/margin must be finite normalized numbers, "
                "samples a non-negative integer, and effect bound finite in [-1, 1]",
            ))
            # Continue through non-evidence gates without performing unsafe
            # arithmetic/formatting on attacker-controlled numeric objects.
            improvement = 0.0
            enough = False
            beats = False
        else:
            improvement = float(cand.candidate_score) - float(cand.baseline_score)
            enough = cand.samples >= int(policy["min_samples"])
            if cand.effect_ci_low is not None:
                beats = float(cand.effect_ci_low) > float(self.min_improvement)
            else:
                beats = improvement > float(self.min_improvement)
        if valid_effect and valid_margin and cand.effect_ci_low is not None:
            beats_reason = (f"causal effect CI lower bound {cand.effect_ci_low:.4f} <= margin "
                            f"{self.min_improvement:.4f}")
        else:
            beats_reason = (f"no improvement: +{improvement:.4f} <= margin "
                            f"{float(self.min_improvement) if valid_margin else 0.0:.4f}")
        ev_ok = enough and beats
        ev_reason = ""
        if not enough:
            ev_reason = f"insufficient evidence: {cand.samples} < {policy['min_samples']} samples"
        elif not beats:
            ev_reason = beats_reason
        if valid_scores and valid_samples and valid_effect and valid_margin:
            gates.append(GateResult("evidence", ev_ok, ev_reason))

        # 3. Capability non-escalation -- the core safety property of the gate.
        widens, cap_method, cap_probes = _capability_assessment(cand)
        cap_evidence = _capability_evidence_label(widens, cap_method)
        needs_cap = bool(policy["require_capability_evidence"])
        if widens is True:
            gates.append(GateResult("capability", False, "change widens the capability envelope"))
        elif widens is None and needs_cap:
            gates.append(GateResult("capability", False,
                                    "no capability-non-escalation proof for a tool/code/weights change"))
        else:
            gates.append(GateResult("capability", True, ""))

        # 4. Model-risk authority. When enabled, this binds authorization to
        #    the actual candidate payload rather than candidate-supplied metadata.
        model_risk_ok, model_risk_reason, model_risk_binding = (
            self._model_risk_approval(cand)
        )
        gates.append(GateResult(
            "model_risk_assurance",
            model_risk_ok,
            "" if model_risk_ok else model_risk_reason,
        ))

        # 5. Human approval -- required at code/weights, and for any rung above
        #    ``max_auto_rung`` (a deployment-wide ceiling on autonomous promotion).
        needs_human = bool(policy["require_human"]) or (
            _rung_rank(cand.rung) > _ceiling_rank(self.max_auto_rung))
        human_ok, approver, human_reason = self._human_approval(cand, needs_human)
        gates.append(GateResult("human_approval", human_ok, "" if human_ok else human_reason))

        # 6. Reversibility: never promote a change you can't undo.
        rb_ok = _valid_rollback_handle(cand.rollback)
        gates.append(GateResult("rollback", rb_ok,
                                "" if rb_ok else "no rollback handle: change is not reversible"))

        failing = [g for g in gates if not g.ok]
        if failing:
            return Verdict(cand.id, cand.rung, False, tuple(gates), failing[0].reason,
                           approver_id=approver,
                           model_risk_payload_sha256=model_risk_binding,
                           capability_evidence=cap_evidence,
                           capability_probe_tools=cap_probes)
        return Verdict(
            cand.id,
            cand.rung,
            True,
            tuple(gates),
            approver_id=approver,
            model_risk_payload_sha256=model_risk_binding,
            capability_evidence=cap_evidence,
            capability_probe_tools=cap_probes,
        )

    def _model_risk_binding_approval(
        self,
        *,
        candidate_id: str,
        rung: str,
        payload_sha256: str | None,
    ) -> tuple[bool, str]:
        """Re-read Model Risk authority over one persisted exact binding."""

        if payload_sha256 is None:
            # Transactions written before this binding was introduced remain
            # recoverable only while the built-in gate is explicitly disabled.
            # Once assurance is enabled, an unbound PREPARE cannot be promoted.
            if self.model_risk_verifier is not None:
                return False, "prepared promotion lacks an exact model-risk payload binding"
            try:
                from .model_risk_assurance import promotion_gate_enabled

                if not promotion_gate_enabled():
                    return True, ""
            except Exception:
                return False, "model-risk assurance policy is unavailable"
            return False, "prepared promotion lacks an exact model-risk payload binding"
        if (
            not isinstance(payload_sha256, str)
            or len(payload_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in payload_sha256)
        ):
            return False, "prepared promotion has an invalid model-risk payload binding"
        try:
            verifier = self.model_risk_verifier
            if verifier is None:
                from .model_risk_assurance import verify_promotion_candidate

                # The built-in verifier owns an authoritative record-store
                # clock.  A controller/replica clock must never influence an
                # authorization-expiry decision.
                result = verify_promotion_candidate(
                    candidate_id=candidate_id,
                    rung=rung,
                    payload_sha256=payload_sha256,
                )
            else:
                # Preserve the injectable verifier seam for deterministic
                # controller tests and downstream integrations.
                result = verifier(
                    candidate_id=candidate_id,
                    rung=rung,
                    payload_sha256=payload_sha256,
                    now=self.now(),
                )
        except Exception:
            log.warning("model-risk assurance promotion verification failed", exc_info=True)
            return False, "model-risk assurance policy is unavailable"
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not isinstance(result[0], bool)
            or not isinstance(result[1], str)
        ):
            return False, "model-risk assurance verifier returned an invalid result"
        allowed, reason = result
        if allowed:
            return True, ""
        return False, reason or "model-risk assurance authorization denied"

    def _model_risk_approval(self, cand: Candidate) -> tuple[bool, str, str | None]:
        """Verify current Model Risk authority over the exact candidate bytes.

        ``Candidate.payload_sha256`` is agent-controlled metadata, so the
        approval request is rebuilt from the actual payload. Any policy,
        storage, clock, import, or return-shape failure denies promotion.
        """
        try:
            from .approval_signing import ApprovalRequest

            request = ApprovalRequest.for_candidate(cand)
        except Exception:
            log.warning("model-risk candidate binding failed", exc_info=True)
            return False, "model-risk assurance policy is unavailable", None
        allowed, reason = self._model_risk_binding_approval(
            candidate_id=request.candidate_id,
            rung=request.rung,
            payload_sha256=request.payload_sha256,
        )
        # A verifier callback is outside the Candidate trust boundary.  Detect
        # mutation during that callback before returning an approved verdict.
        try:
            current = ApprovalRequest.for_candidate(cand)
        except Exception:
            return False, "candidate changed during model-risk verification", None
        if current != request:
            return False, "candidate changed during model-risk verification", None
        return allowed, reason, request.payload_sha256

    def _model_risk_record_approval(self, record: PromotionRecord) -> tuple[bool, str]:
        return self._model_risk_binding_approval(
            candidate_id=record.id,
            rung=record.rung,
            payload_sha256=record.model_risk_payload_sha256,
        )

    def _human_approval(self, cand: Candidate, needs_human: bool) -> tuple[bool, str | None, str]:
        """Resolve the human-approval gate to ``(ok, approver_id, reason)``.

        A valid Ed25519 signature over the exact candidate is required at
        human-gated rungs. Missing signatures and verifier errors fail closed;
        the self-settable ``approved`` boolean cannot grant authority.
        """
        if not needs_human:
            return True, None, ""
        approver: str | None = None
        try:
            if self.approval_verifier is not None:
                approver = self.approval_verifier(cand)
            else:
                from . import approval_signing
                approval_signing.signing_enforced()  # validates policy availability
                approver = approval_signing.verify_candidate(cand)
        except Exception:
            # Whether signing is configured is itself security policy. If that
            # policy or its trust roots cannot be resolved, we cannot prove that
            # the legacy boolean path is authorized, so refuse the promotion.
            return (False, None,
                    f"{cand.rung} promotion approval policy is unavailable")
        if approver:
            return True, approver, ""
        return (False, None,
                f"{cand.rung} promotion requires a valid approver signature "
                "(none present or signature invalid)")

    def _reject(self, cand: Candidate, gates: list[GateResult]) -> Verdict:
        return Verdict(cand.id, cand.rung, False, tuple(gates),
                       gates[0].reason if gates else "rejected")

    def _audit(self, **payload: Any) -> None:
        """Emit non-authoritative telemetry outside the promotion transaction.

        Successful promotion and rollback decisions do not use this seam: their
        audit receipts are committed atomically in the promotion journal and
        drained by :meth:`_flush_audit_outbox`.
        """
        try:
            self.audit_fn(**payload)
        except Exception:
            log.warning("self-improvement audit sink failed", exc_info=True)

    def _flush_audit_outbox(self) -> None:
        """Attempt bounded delivery without inverting a committed transition."""
        if self.ledger is None:
            return
        try:
            self.ledger.flush_audit_outbox(self.audit_fn)
        except Exception:
            # The receipt remains in the authoritative journal.  Returning an
            # error after the artifact and COMMIT are live would invite an
            # unsafe retry; a later controller touch drains the same event id.
            log.warning(
                "self-improvement durable audit delivery is pending",
                exc_info=True,
            )

    # -- privileged writes (promote / rollback) --------------------------

    @staticmethod
    def _promotion_record(cand: Candidate, verdict: Verdict, *, at: float) -> PromotionRecord:
        from .approval_signing import ApprovalRequest

        signed = bool(cand.approval_signature)
        current_binding = ApprovalRequest.for_candidate(cand)
        if (
            verdict.model_risk_payload_sha256 is None
            or current_binding.candidate_id != verdict.candidate_id
            or current_binding.rung != verdict.rung
            or current_binding.payload_sha256 != verdict.model_risk_payload_sha256
        ):
            raise ValueError("candidate changed after model-risk authorization")
        return PromotionRecord(
            id=cand.id, rung=cand.rung, summary=cand.summary,
            baseline_score=cand.baseline_score, candidate_score=cand.candidate_score,
            promoted_at=at,
            approver_id=verdict.approver_id if signed else None,
            payload_sha256=cand.payload_sha256 if signed else None,
            approval_signature=cand.approval_signature if signed else None,
            model_risk_payload_sha256=verdict.model_risk_payload_sha256,
            samples=cand.samples,
            effect_ci_low=cand.effect_ci_low,
            provenance=_receipt_provenance(cand.provenance),
            audit_payload=_receipt_audit_payload(cand.audit_payload),
            capability_evidence=verdict.capability_evidence,
            capability_probe_tools=verdict.capability_probe_tools,
        )

    @staticmethod
    def _fail_verdict(verdict: Verdict, *, gate: str, reason: str) -> Verdict:
        failure = GateResult(gate, False, reason)
        return Verdict(
            verdict.candidate_id, verdict.rung, False,
            (*verdict.gates, failure), reason,
            approver_id=verdict.approver_id,
            model_risk_payload_sha256=verdict.model_risk_payload_sha256,
            capability_evidence=verdict.capability_evidence,
            capability_probe_tools=verdict.capability_probe_tools)

    @staticmethod
    def _halt_reason(phase: str) -> str | None:
        """Return the active operational-stop reason, if any.

        The controller returns a normal failed gate instead of leaking the
        control-flow exception through its public fail-closed API.  Recovery
        and rollback intentionally bypass this check.
        """
        try:
            check_learning_halt("self_improvement", phase)
        except Halted as exc:
            return str(exc)
        return None

    def prepare_promotion(
        self, cand: Candidate, *, before: ArtifactRevision,
        after: ArtifactRevision, transaction_id: str | None = None,
    ) -> PromotionPreparation:
        """Gate and durably PREPARE, without claiming the artifact is deployed.

        A caller should next hold the artifact's own write/CAS lock, verify
        ``before``, atomically install ``after``, and call
        :meth:`commit_prepared` before releasing that lock.  If the process dies
        between installation and COMMIT, :meth:`recover_promotions` reconciles
        the durable intent against the current artifact revision.
        """
        if not enabled():
            verdict = Verdict(
                cand.id, cand.rung, False,
                (GateResult("enabled", False, "self-improvement disabled"),),
                "self-improvement disabled")
            return PromotionPreparation(verdict)
        halt_reason = self._halt_reason("evaluation")
        if halt_reason is not None:
            verdict = Verdict(
                cand.id, cand.rung, False,
                (GateResult("killswitch", False, halt_reason),), halt_reason)
            return PromotionPreparation(verdict)
        verdict = self.evaluate(cand)
        if not verdict.ok:
            self._audit(
                content="self_improvement_rejected", decision="reject",
                rung=cand.rung, candidate=cand.id, reason=verdict.blocking_reason)
            return PromotionPreparation(verdict)
        try:
            halt_reason = self._halt_reason("promotion")
            if halt_reason is not None:
                failed = self._fail_verdict(
                    verdict, gate="killswitch", reason=halt_reason)
                self._audit(
                    content="self_improvement_rejected", decision="reject",
                    rung=cand.rung, candidate=cand.id, reason=halt_reason)
                return PromotionPreparation(failed)
            if self.ledger is None:
                raise PromotionLedgerError("promotion ledger is required")
            prepared_at = self.now()
            rec = self._promotion_record(cand, verdict, at=prepared_at)
            transaction = self.ledger.prepare(
                rec, before=before, after=after, prepared_at=prepared_at,
                transaction_id=transaction_id)
            if transaction.state == "aborted":
                failed = self._fail_verdict(
                    verdict, gate="transaction",
                    reason="promotion transaction was already aborted")
                return PromotionPreparation(failed, transaction)
        except (PromotionLedgerError, TypeError, ValueError):
            log.warning("self-improvement promotion prepare failed for %s",
                        cand.id, exc_info=True)
            failed = self._fail_verdict(
                verdict, gate="ledger", reason="promotion prepare persistence failed")
            self._audit(
                content="self_improvement_rejected", decision="reject",
                rung=cand.rung, candidate=cand.id, reason=failed.blocking_reason)
            return PromotionPreparation(failed)
        if transaction.state == "committed":
            self._flush_audit_outbox()
            return PromotionPreparation(verdict, transaction)
        self._audit(
            content="self_improvement_prepared", decision="prepare",
            rung=cand.rung, candidate=cand.id, transaction=transaction.id,
            artifact=before.identity, before_sha256=before.sha256,
            after_sha256=after.sha256, samples=transaction.record.samples,
            effect_ci_low=transaction.record.effect_ci_low,
            provenance=transaction.record.provenance)
        return PromotionPreparation(verdict, transaction)

    def authorize_prepared(
        self,
        preparation: PromotionPreparation,
        *,
        artifact: ArtifactRevision,
    ) -> Verdict:
        """Revalidate exact authority under the caller's artifact/CAS lock.

        Artifact owners must call this immediately before installing ``after``.
        A denial safely ABORTs only when the exact prepared ``before`` revision
        is still live; any ambiguous state remains in doubt and blocks reuse.
        """

        if not preparation.ok or preparation.transaction is None:
            return preparation.verdict
        try:
            if self.ledger is None:
                raise PromotionLedgerError("promotion ledger is required")
            current = self.ledger.transaction(preparation.transaction.id)
            if current is None:
                raise PromotionLedgerError("promotion transaction does not exist")
            if (
                current.record.id != preparation.verdict.candidate_id
                or current.record.rung != preparation.verdict.rung
            ):
                raise PromotionLedgerError("promotion preparation identity does not match ledger")
            if current.state == "committed":
                if artifact != current.after:
                    raise PromotionLedgerError(
                        "committed promotion does not match the live artifact"
                    )
                return preparation.verdict
            if current.state == "aborted":
                return self._fail_verdict(
                    preparation.verdict,
                    gate="transaction",
                    reason="promotion transaction was already aborted",
                )
            if artifact != current.before:
                raise PromotionLedgerError(
                    "pre-apply authorization requires the exact original artifact"
                )
            failure = self._prepared_control_failure()
            if failure is None:
                allowed, reason = self._model_risk_record_approval(current.record)
                failure = (self._prepared_control_failure() if allowed else (
                    "model_risk_assurance",
                    f"model-risk authority changed before artifact application: {reason}",
                ))
            if failure is None:
                return preparation.verdict
            gate, denial = failure
            self.ledger.abort(
                current.id,
                artifact=artifact,
                at=self.now(),
                reason=denial,
            )
            failed = self._fail_verdict(
                preparation.verdict,
                gate=gate,
                reason=denial,
            )
            self._audit(
                content="self_improvement_aborted",
                decision="abort",
                rung=current.record.rung,
                candidate=current.record.id,
                transaction=current.id,
                reason=denial,
            )
            return failed
        except (PromotionLedgerError, TypeError, ValueError):
            log.warning(
                "self-improvement pre-apply authorization is in doubt for %s",
                preparation.verdict.candidate_id,
                exc_info=True,
            )
            failed = self._fail_verdict(
                preparation.verdict,
                gate="transaction",
                reason="pre-apply authorization is in doubt; recovery required",
            )
            self._audit(
                content="self_improvement_in_doubt",
                decision="in_doubt",
                rung=preparation.verdict.rung,
                candidate=preparation.verdict.candidate_id,
                transaction=preparation.transaction.id,
            )
            return failed

    def _prepared_control_failure(self) -> tuple[str, str] | None:
        """Current new-effect controls, never a gate on committed originals."""
        if not enabled():
            return "enabled", "self-improvement disabled"
        halt_reason = self._halt_reason("promotion")
        if halt_reason is not None:
            return "killswitch", halt_reason
        try:
            frozen = self.frozen_fn()
        except Exception:
            frozen = True  # Same unavailable-calibration refusal as evaluate.
        if frozen:
            return "calibration", "learning frozen: verifier mis-calibrated"
        return None

    def commit_prepared(
        self, preparation: PromotionPreparation, *, artifact: ArtifactRevision,
    ) -> Verdict:
        """COMMIT a prepared receipt only after exact-after artifact evidence."""
        if not preparation.ok or preparation.transaction is None:
            return preparation.verdict
        transaction = preparation.transaction
        try:
            if self.ledger is None:
                raise PromotionLedgerError("promotion ledger is required")
            current = self.ledger.transaction(transaction.id)
            if current is None:
                raise PromotionLedgerError("promotion transaction does not exist")
            if (
                current.record.id != preparation.verdict.candidate_id
                or current.record.rung != preparation.verdict.rung
            ):
                raise PromotionLedgerError("promotion preparation identity does not match ledger")
            if current.state == "aborted":
                return self._fail_verdict(
                    preparation.verdict, gate="transaction",
                    reason="promotion transaction was already aborted")
            was_committed = current.state == "committed"
            if not was_committed:
                if artifact != current.after:
                    raise PromotionLedgerError(
                        "runtime artifact does not match the prepared promotion revision"
                    )
                allowed, reason = self._model_risk_record_approval(current.record)
                if not allowed:
                    denial = f"model-risk authority changed before commit: {reason}"
                    failed = self._fail_verdict(
                        preparation.verdict,
                        gate="model_risk_assurance",
                        reason=denial,
                    )
                    self._audit(
                        content="self_improvement_in_doubt",
                        decision="in_doubt",
                        rung=current.record.rung,
                        candidate=current.record.id,
                        transaction=current.id,
                        reason=denial,
                    )
                    return failed
            self.ledger.commit(transaction.id, artifact=artifact, at=self.now())
            transaction = current
        except (PromotionLedgerError, TypeError, ValueError):
            # The artifact may already be live.  Never manufacture an abort or
            # claim rejection here; retain PREPARE for deterministic recovery.
            log.warning("self-improvement promotion commit is in doubt for %s",
                        preparation.verdict.candidate_id, exc_info=True)
            failed = self._fail_verdict(
                preparation.verdict, gate="transaction",
                reason="promotion commit is in doubt; recovery required")
            self._audit(
                content="self_improvement_in_doubt", decision="in_doubt",
                rung=preparation.verdict.rung,
                candidate=preparation.verdict.candidate_id,
                transaction=transaction.id)
            return failed
        self._flush_audit_outbox()
        return preparation.verdict

    def abort_prepared(
        self, preparation: PromotionPreparation, *, artifact: ArtifactRevision,
        reason: str,
    ) -> Verdict:
        """ABORT only with proof the declared before-revision remains live."""
        if preparation.transaction is None:
            return preparation.verdict
        try:
            if self.ledger is None:
                raise PromotionLedgerError("promotion ledger is required")
            current = self.ledger.transaction(preparation.transaction.id)
            if current is not None and current.state == "committed":
                if artifact == current.after:
                    return preparation.verdict
                return self._fail_verdict(
                    preparation.verdict, gate="transaction",
                    reason="promotion transaction was already committed")
            if current is not None and current.state == "aborted":
                return self._fail_verdict(
                    preparation.verdict, gate="application",
                    reason=current.reason or reason)
            self.ledger.abort(
                preparation.transaction.id, artifact=artifact,
                at=self.now(), reason=reason)
        except (PromotionLedgerError, TypeError, ValueError):
            log.warning("self-improvement promotion abort is in doubt for %s",
                        preparation.verdict.candidate_id, exc_info=True)
            failed = self._fail_verdict(
                preparation.verdict, gate="transaction",
                reason="promotion transaction is in doubt; recovery required")
            self._audit(
                content="self_improvement_in_doubt", decision="in_doubt",
                rung=preparation.verdict.rung,
                candidate=preparation.verdict.candidate_id,
                transaction=preparation.transaction.id)
            return failed
        failed = self._fail_verdict(
            preparation.verdict, gate="application", reason=reason)
        self._audit(
            content="self_improvement_aborted", decision="abort",
            rung=preparation.verdict.rung,
            candidate=preparation.verdict.candidate_id,
            transaction=preparation.transaction.id, reason=reason)
        return failed

    def recover_promotions(
        self, inspect: Callable[[str], ArtifactRevision], *,
        artifact_identity: str | None = None,
    ) -> list[PromotionTransaction]:
        """Reconcile crash-left PREPAREs; unresolved artifacts stay blocked."""
        if self.ledger is None:
            raise PromotionLedgerError("promotion ledger is required")
        pending = self.ledger.in_doubt(artifact_identity=artifact_identity)
        recovered: list[PromotionTransaction] = []
        for tx in pending:
            try:
                artifact = inspect(tx.before.identity)
                if not isinstance(artifact, ArtifactRevision):
                    raise TypeError("artifact inspector returned the wrong type")
                if artifact == tx.after:
                    allowed, reason = self._model_risk_record_approval(tx.record)
                    if not allowed:
                        self._audit(
                            content="self_improvement_recovery_denied",
                            decision="in_doubt",
                            rung=tx.record.rung,
                            candidate=tx.record.id,
                            transaction=tx.id,
                            reason=(
                                "model-risk authority changed before recovery commit: "
                                f"{reason}"
                            ),
                        )
                        latest = self.ledger.transaction(tx.id)
                        recovered.append(latest if latest is not None else tx)
                        continue
                recovered.append(
                    self.ledger.recover(tx.id, artifact=artifact, at=self.now())
                )
            except Exception:
                log.warning(
                    "promotion transaction recovery failed for %s", tx.id, exc_info=True
                )
                latest = self.ledger.transaction(tx.id)
                recovered.append(latest if latest is not None else tx)
        for tx in recovered:
            if tx.state in {"committed", "aborted"}:
                self._audit(
                    content="self_improvement_recovered", decision=tx.state,
                    rung=tx.record.rung, candidate=tx.record.id,
                    transaction=tx.id, artifact=tx.before.identity,
                    samples=tx.record.samples,
                    effect_ci_low=tx.record.effect_ci_low,
                    provenance=tx.record.provenance)
        self._flush_audit_outbox()
        return recovered

    def promote(self, cand: Candidate) -> Verdict:
        """Evaluate and, if every gate passes, record + sign the promotion.

        A no-op (never promotes) while the engine is disabled. The caller
        applies ``cand.payload`` only when the returned verdict ``ok`` is True.
        This legacy one-phase seam is retained for compatibility with purely
        logical/in-ledger changes.  Owners of an external runtime artifact must
        use ``prepare_promotion`` -> CAS/atomic apply -> ``commit_prepared`` so a
        crash cannot create a receipt/artifact split-brain.
        """
        if not enabled():
            return Verdict(cand.id, cand.rung, False,
                           (GateResult("enabled", False, "self-improvement disabled"),),
                           "self-improvement disabled")
        halt_reason = self._halt_reason("evaluation")
        if halt_reason is not None:
            return Verdict(
                cand.id, cand.rung, False,
                (GateResult("killswitch", False, halt_reason),), halt_reason)
        verdict = self.evaluate(cand)
        if not verdict.promote:
            self._audit(content="self_improvement_rejected", decision="reject",
                        rung=cand.rung, candidate=cand.id, reason=verdict.blocking_reason)
            return verdict
        # Persist the signature material ONLY when the candidate carried a
        # cryptographic approval, so a third party can re-verify the Ed25519
        # signature from the ledger alone. ``verdict.approver_id`` is the key-id
        # that actually satisfied the human-approval gate (reused, not
        # recomputed). No signature (dev/community boolean path) => all None, so
        # the record carries no signature fields.
        try:
            halt_reason = self._halt_reason("promotion")
            if halt_reason is not None:
                failed = self._fail_verdict(
                    verdict, gate="killswitch", reason=halt_reason)
                self._audit(content="self_improvement_rejected", decision="reject",
                            rung=cand.rung, candidate=cand.id, reason=halt_reason)
                return failed
            rec = self._promotion_record(cand, verdict, at=self.now())
            if self.ledger is None:
                raise PromotionLedgerError("promotion ledger is required")
            current, reason = self._model_risk_record_approval(rec)
            if not current:
                failed = self._fail_verdict(
                    verdict,
                    gate="model_risk_assurance",
                    reason=f"model-risk authority changed before commit: {reason}",
                )
                self._audit(
                    content="self_improvement_rejected",
                    decision="reject",
                    rung=cand.rung,
                    candidate=cand.id,
                    reason=failed.blocking_reason,
                )
                return failed
            # A privileged transition is successful only after its receipt
            # commits. A best-effort audit event is not a substitute for the
            # authoritative promotion journal.
            self.ledger.add(rec)
        except (PromotionLedgerError, TypeError, ValueError):
            log.warning("self-improvement promotion receipt commit failed for %s",
                        cand.id, exc_info=True)
            failure = GateResult("ledger", False, "promotion ledger persistence failed")
            failed = self._fail_verdict(verdict, gate="ledger", reason=failure.reason)
            self._audit(content="self_improvement_rejected", decision="reject",
                        rung=cand.rung, candidate=cand.id, reason=failure.reason)
            return failed
        self._flush_audit_outbox()
        return verdict

    def rollback(self, record_id: str, *, undo: Callable[[], None] | None = None) -> bool:
        """Reverse a prior promotion: mark it rolled back, run ``undo``, audit."""
        if self.ledger is None:
            return False
        try:
            rec = self.ledger.get(record_id)
        except PromotionLedgerError:
            log.warning("self-improvement rollback receipt read failed for %s",
                        record_id, exc_info=True)
            return False
        if rec is None or rec.rolled_back:
            return False
        if undo is not None:
            try:
                undo()
            except Exception:
                log.warning("self-improvement rollback undo failed for %s", record_id, exc_info=True)
                return False
        try:
            if not self.ledger.mark_rolled_back(record_id, at=self.now()):
                return False
        except PromotionLedgerError:
            # ``undo`` may already have run, but it is unsafe to report a
            # completed rollback when the durable receipt cannot prove it.
            log.warning("self-improvement rollback receipt commit failed for %s",
                        record_id, exc_info=True)
            return False
        self._flush_audit_outbox()
        return True


_LEDGER_PATH_LOCKS: dict[str, threading.RLock] = {}
_LEDGER_PATH_LOCKS_GUARD = threading.Lock()
_JOURNAL_VERSION = 1


def _path_lock_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _assert_regular_file(path: Path, *, label: str) -> None:
    """Refuse links/devices: a durable receipt must stay inside its store."""
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PromotionLedgerError(f"cannot inspect {label}") from exc
    if not stat.S_ISREG(mode):
        raise PromotionLedgerError(f"{label} must be a regular file")


@contextmanager
def _exclusive_ledger_lock(journal: Path):
    """Strict cross-process serialization for one promotion journal.

    Lock acquisition is part of the privileged transaction and therefore never
    degrades to a best-effort/no-op path.
    """
    lock_path = journal.parent / f"{journal.name}.lock"
    key = _path_lock_key(lock_path)
    with _LEDGER_PATH_LOCKS_GUARD:
        local_lock = _LEDGER_PATH_LOCKS.setdefault(key, threading.RLock())
    with local_lock:
        fd: int | None = None
        kind: str | None = None
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            _assert_regular_file(lock_path, label="promotion ledger lock")
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            created = False
            if os.name == "nt":
                try:
                    fd = os.open(
                        os.fspath(lock_path), flags | os.O_EXCL, 0o600)
                    created = True
                except FileExistsError:
                    fd = os.open(os.fspath(lock_path), flags, 0o600)
            else:
                fd = os.open(os.fspath(lock_path), flags, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise PromotionLedgerError("promotion ledger lock must be a regular file")
            if os.name == "nt":
                import msvcrt

                if created:
                    os.write(fd, b"\0")
                else:
                    # Only the O_EXCL creator initializes the lock byte. The
                    # old check-then-write let two fresh processes both observe
                    # size zero; one could lock the byte before the other wrote,
                    # turning a valid idempotent retry into PermissionError.
                    for _ in range(1_000):
                        if os.fstat(fd).st_size >= 1:
                            break
                        time.sleep(0.001)
                    else:
                        raise PromotionLedgerError(
                            "promotion ledger lock is uninitialized")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                kind = "msvcrt"
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
                kind = "flock"
        except PromotionLedgerError:
            if fd is not None:
                os.close(fd)
            raise
        except (ImportError, OSError) as exc:
            if fd is not None:
                os.close(fd)
            raise PromotionLedgerError("cannot acquire promotion ledger lock") from exc

        try:
            yield
        finally:
            try:
                if kind == "msvcrt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                elif kind == "flock":
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                log.warning("could not explicitly release promotion ledger lock", exc_info=True)
            finally:
                if fd is not None:
                    os.close(fd)


def _sync_file(path: Path) -> None:
    """Flush a completed ledger file before reporting its commit."""
    flags = os.O_RDWR if os.name == "nt" else os.O_RDONLY
    fd = os.open(os.fspath(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_directory(path: Path) -> None:
    """Persist a rename on POSIX; NTFS has no portable directory fsync API."""
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(os.fspath(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _record_from_dict(raw: Any) -> PromotionRecord:
    if not isinstance(raw, dict):
        raise PromotionLedgerError("promotion ledger record is not an object")
    try:
        rolled_back_at = raw.get("rolled_back_at")
        samples = raw.get("samples")
        if (samples is not None
                and (not isinstance(samples, int) or isinstance(samples, bool)
                     or samples < 0 or samples > 1_000_000_000)):
            raise TypeError("samples is not a valid non-negative integer")
        effect_ci_low = raw.get("effect_ci_low")
        if effect_ci_low is not None:
            if (not isinstance(effect_ci_low, (int, float))
                    or isinstance(effect_ci_low, bool)
                    or not math.isfinite(float(effect_ci_low))
                    or not -1.0 <= float(effect_ci_low) <= 1.0):
                raise TypeError("effect_ci_low is not a finite normalized effect")
            effect_ci_low = float(effect_ci_low)
        model_risk_payload_sha256 = raw.get("model_risk_payload_sha256")
        if (
            model_risk_payload_sha256 is not None
            and (
                not isinstance(model_risk_payload_sha256, str)
                or len(model_risk_payload_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in model_risk_payload_sha256)
            )
        ):
            raise TypeError("model_risk_payload_sha256 is not a lowercase SHA-256 digest")
        capability_evidence = raw.get("capability_evidence")
        if capability_evidence is not None and capability_evidence not in (
            CAPABILITY_PROBED_BOUNDED, CAPABILITY_DECLARED_BOUNDED,
            CAPABILITY_UNPROVEN,
        ):
            # An unrecognized grading is rejected rather than downgraded. A
            # verifier that silently mapped an unknown label to "unproven" would
            # let a future writer (or an editor) invent a stronger-sounding one
            # and still be read as a valid, merely-weaker receipt.
            raise TypeError("capability_evidence is not a recognized grading")
        capability_probe_tools = raw.get("capability_probe_tools")
        if (capability_probe_tools is not None
                and (not isinstance(capability_probe_tools, int)
                     or isinstance(capability_probe_tools, bool)
                     or capability_probe_tools < 0
                     or capability_probe_tools > 1_000_000_000)):
            raise TypeError("capability_probe_tools is not a valid non-negative integer")
        if (capability_probe_tools is not None
                and capability_evidence != CAPABILITY_PROBED_BOUNDED):
            # A probe count only means something alongside the grading that says
            # a probe was walked. Accepting one without it would let a receipt
            # imply a probe it never ran.
            raise TypeError("capability_probe_tools requires a probed grading")
        return PromotionRecord(
            id=str(raw["id"]), rung=str(raw["rung"]),
            summary=str(raw.get("summary", "")),
            baseline_score=float(raw.get("baseline_score", 0.0)),
            candidate_score=float(raw.get("candidate_score", 0.0)),
            promoted_at=float(raw.get("promoted_at", 0.0)),
            rolled_back=bool(raw.get("rolled_back", False)),
            rolled_back_at=(None if rolled_back_at is None else float(rolled_back_at)),
            approver_id=raw.get("approver_id"),
            payload_sha256=raw.get("payload_sha256"),
            approval_signature=raw.get("approval_signature"),
            model_risk_payload_sha256=model_risk_payload_sha256,
            samples=samples,
            effect_ci_low=effect_ci_low,
            provenance=_receipt_provenance(raw.get("provenance", {})),
            audit_payload=_receipt_audit_payload(raw.get("audit_payload", {})),
            capability_evidence=capability_evidence,
            capability_probe_tools=capability_probe_tools,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PromotionLedgerError("promotion ledger contains an invalid record") from exc


def _artifact_revision_from_dict(raw: Any) -> ArtifactRevision:
    if not isinstance(raw, dict):
        raise PromotionLedgerError("promotion transaction artifact is not an object")
    try:
        return ArtifactRevision(
            identity=raw["identity"], sha256=raw["sha256"], version=raw["version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PromotionLedgerError("promotion transaction has an invalid artifact revision") from exc


def _event_time(raw: Any, label: str) -> float:
    if isinstance(raw, bool):
        raise PromotionLedgerError(f"promotion ledger has an invalid {label} time")
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise PromotionLedgerError(f"promotion ledger has an invalid {label} time") from exc
    if value < 0 or value != value or value in {float("inf"), float("-inf")}:
        raise PromotionLedgerError(f"promotion ledger has an invalid {label} time")
    return value


def _transaction_from_dict(raw: Any) -> PromotionTransaction:
    if not isinstance(raw, dict):
        raise PromotionLedgerError("promotion transaction is not an object")
    try:
        last_observed = raw.get("last_observed")
        recovery_attempts = raw.get("recovery_attempts", 0)
        if (not isinstance(recovery_attempts, int)
                or isinstance(recovery_attempts, bool)):
            raise TypeError("recovery_attempts is not an integer")
        transaction = PromotionTransaction(
            id=raw["id"],
            record=_record_from_dict(raw["record"]),
            before=_artifact_revision_from_dict(raw["before"]),
            after=_artifact_revision_from_dict(raw["after"]),
            prepared_at=_event_time(raw["prepared_at"], "prepare"),
            state=raw.get("state", "prepared"),
            resolved_at=(None if raw.get("resolved_at") is None
                         else _event_time(raw["resolved_at"], "resolution")),
            reason=raw.get("reason", ""),
            last_observed=(None if last_observed is None
                           else _artifact_revision_from_dict(last_observed)),
            recovery_attempts=recovery_attempts,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PromotionLedgerError("promotion ledger contains an invalid transaction") from exc
    if (not isinstance(transaction.id, str) or not transaction.id
            or len(transaction.id) > 256
            or any(ord(ch) < 32 for ch in transaction.id)
            or not isinstance(transaction.state, str)
            or transaction.state not in {"prepared", "committed", "aborted"}
            or not isinstance(transaction.reason, str)
            or transaction.recovery_attempts < 0
            or transaction.before.identity != transaction.after.identity
            or transaction.before.sha256 == transaction.after.sha256
            or transaction.before.version == transaction.after.version):
        raise PromotionLedgerError("promotion ledger contains an invalid transaction")
    return transaction


def _same_transaction_intent(left: PromotionTransaction,
                             right: PromotionTransaction) -> bool:
    """Compare retry identity while ignoring caller-generated timestamps."""
    left_record = left.record.to_dict()
    right_record = right.record.to_dict()
    left_record.pop("promoted_at", None)
    right_record.pop("promoted_at", None)
    return (
        left.id == right.id
        and left_record == right_record
        and left.before == right.before
        and left.after == right.after
    )


def _records_match(left: Mapping[str, PromotionRecord],
                   right: Mapping[str, PromotionRecord]) -> bool:
    return {key: value.to_dict() for key, value in left.items()} == {
        key: value.to_dict() for key, value in right.items()
    }


def _promotion_audit_envelope(
    record: PromotionRecord,
    *,
    decision: str,
    occurred_at: float,
    transaction_id: str | None = None,
    artifact: ArtifactRevision | None = None,
) -> dict[str, Any]:
    """Build one stable, bounded outbox receipt for a journal transition."""
    at = _event_time(occurred_at, "audit")
    identity = {
        "decision": decision,
        "record": record.to_dict(),
        "transaction": transaction_id,
        "artifact": artifact.to_dict() if artifact is not None else None,
    }
    event_id = "self-improvement-" + hashlib.sha256(
        _canonical_json(identity).encode("utf-8")
    ).hexdigest()
    custom = record.audit_payload if decision == "promote" else {}
    payload = _receipt_audit_payload({
        **custom,
        "event_id": event_id,
        "occurred_at": at,
        "content": (
            "self_improvement_promoted"
            if decision == "promote"
            else "self_improvement_rolled_back"
        ),
        "decision": decision,
        "rung": record.rung,
        "candidate": record.id,
        "transaction": transaction_id,
        "artifact": artifact.identity if artifact is not None else None,
        "artifact_sha256": artifact.sha256 if artifact is not None else None,
        "improvement": round(
            record.candidate_score - record.baseline_score,
            6,
        ),
        "approver": record.approver_id,
        "samples": record.samples,
        "effect_ci_low": record.effect_ci_low,
        "provenance": record.provenance,
    })
    return {"event_id": event_id, "queued_at": at, "payload": payload}


def _audit_envelope_from_dict(raw: Any) -> dict[str, Any]:
    """Validate an audit receipt replayed from the authoritative journal."""
    if not isinstance(raw, dict) or set(raw) != {
        "event_id", "queued_at", "payload",
    }:
        raise PromotionLedgerError(
            "promotion ledger contains an invalid audit outbox receipt"
        )
    event_id = raw.get("event_id")
    if (
        not isinstance(event_id, str)
        or not event_id
        or len(event_id) > 256
        or any(ord(ch) < 32 for ch in event_id)
    ):
        raise PromotionLedgerError(
            "promotion ledger contains an invalid audit event id"
        )
    queued_at = _event_time(raw.get("queued_at"), "audit")
    try:
        payload = _receipt_audit_payload(raw.get("payload"))
    except (TypeError, ValueError) as exc:
        raise PromotionLedgerError(
            "promotion ledger contains an invalid audit payload"
        ) from exc
    if payload.get("event_id") != event_id:
        raise PromotionLedgerError(
            "promotion ledger audit payload is not bound to its event id"
        )
    try:
        payload_at = _event_time(payload.get("occurred_at"), "audit occurrence")
    except PromotionLedgerError as exc:
        raise PromotionLedgerError(
            "promotion ledger audit payload has an invalid occurrence time"
        ) from exc
    if payload_at != queued_at:
        raise PromotionLedgerError(
            "promotion ledger audit payload time does not match its receipt"
        )
    return {"event_id": event_id, "queued_at": queued_at, "payload": payload}


@dataclass
class PromotionLedger:
    """Durable promotion receipts with a JSON compatibility projection.

    ``path`` remains the historical JSON-list view consumed by independent
    auditors. ``<path>.journal`` is the authority: an append-only, hash-chained
    JSONL stream fsynced under a strict cross-process lock. Missing, stale, or
    malformed projections are rebuilt from the journal; journal corruption and
    lock/commit failures fail closed with :class:`PromotionLedgerError`.

    History is retained without a lifetime receipt ceiling by default. An
    explicitly supplied ``max_records`` keeps the legacy bound on committed
    receipts plus unresolved reservations; it never deletes older receipts.
    """

    path: Path | None = None
    max_records: int | None = None
    _records: dict[str, PromotionRecord] = field(default_factory=dict)
    _transactions: dict[str, PromotionTransaction] = field(default_factory=dict)
    _audit_pending: dict[str, dict[str, Any]] = field(
        default_factory=dict,
        repr=False,
    )
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        if self.max_records is not None and (
                isinstance(self.max_records, bool)
                or not isinstance(self.max_records, int)
                or self.max_records < 0):
            raise ValueError("max_records must be None or a nonnegative integer")
        if self.path is not None:
            self.path = Path(self.path)
            self._refresh()

    @property
    def _journal_path(self) -> Path:
        if self.path is None:  # pragma: no cover - guarded by callers
            raise PromotionLedgerError("in-memory ledger has no journal path")
        return Path(f"{self.path}.journal")

    @contextmanager
    def _locked(self):
        with self._lock:
            if self.path is None:
                yield
            else:
                with _exclusive_ledger_lock(self._journal_path):
                    yield

    def add(self, rec: PromotionRecord) -> None:
        """Commit a new immutable promotion receipt or raise on any failure."""
        try:
            with self._locked():
                records, transactions, head, has_journal = self._full_state_locked()
                if (rec.id in records
                        or any(tx.record.id == rec.id for tx in transactions.values())):
                    raise PromotionLedgerError(f"promotion record {rec.id!r} already exists")
                reservations = sum(tx.state == "prepared" for tx in transactions.values())
                if (self.max_records is not None
                        and len(records) + reservations >= self.max_records):
                    raise PromotionLedgerError("promotion ledger retention limit reached")

                if self.path is not None:
                    if not has_journal:
                        head = self._migrate_legacy_locked(records)
                    audit_receipt = _promotion_audit_envelope(
                        rec,
                        decision="promote",
                        occurred_at=rec.promoted_at,
                    )
                    event = self._event(
                        "promote",
                        head,
                        record=rec,
                        audit=audit_receipt,
                    )
                    self._append_events_locked((event,))
                    records[rec.id] = rec
                    self._audit_pending[audit_receipt["event_id"]] = audit_receipt
                    self._sync_projection_after_journal_locked(records)
                else:
                    records[rec.id] = rec
                    audit_receipt = _promotion_audit_envelope(
                        rec,
                        decision="promote",
                        occurred_at=rec.promoted_at,
                    )
                    self._audit_pending[audit_receipt["event_id"]] = audit_receipt
                self._records = records
                self._transactions = transactions
        except PromotionLedgerError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("could not persist promotion receipt") from exc

    def prepare(
        self, rec: PromotionRecord, *, before: ArtifactRevision,
        after: ArtifactRevision, prepared_at: float,
        transaction_id: str | None = None,
    ) -> PromotionTransaction:
        """Durably reserve an artifact and write its immutable deployment intent.

        Retrying the same transaction id with the same record/artifact intent is
        idempotent.  Any mismatched reuse, duplicate candidate, no-op digest, or
        second in-doubt transaction for the same artifact fails closed.
        """
        tx_id = transaction_id or f"promotion:{rec.id}"
        if (not isinstance(tx_id, str) or not tx_id or len(tx_id) > 256
                or any(ord(ch) < 32 for ch in tx_id)):
            raise PromotionLedgerError("promotion transaction id is invalid")
        if rec.rolled_back:
            raise PromotionLedgerError("cannot prepare a rolled-back promotion record")
        if (before.identity != after.identity or before.sha256 == after.sha256
                or before.version == after.version):
            raise PromotionLedgerError("promotion transaction artifact transition is invalid")
        # Reserve a receipt that COMMIT can actually enqueue before the caller
        # is allowed to install the external artifact.  Without this preflight,
        # a combined provenance + producer payload that exceeds the outbox cap
        # would fail only after the runtime artifact was already live.
        try:
            _promotion_audit_envelope(
                rec,
                decision="promote",
                occurred_at=prepared_at,
                transaction_id=tx_id,
                artifact=after,
            )
        except (PromotionLedgerError, TypeError, ValueError) as exc:
            raise PromotionLedgerError(
                "promotion audit receipt cannot be reserved"
            ) from exc
        intent = PromotionTransaction(
            id=tx_id, record=rec, before=before, after=after,
            prepared_at=_event_time(prepared_at, "prepare"),
        )
        try:
            with self._locked():
                records, transactions, head, has_journal = self._full_state_locked()
                existing = transactions.get(tx_id)
                if existing is not None:
                    if not _same_transaction_intent(existing, intent):
                        raise PromotionLedgerError(
                            f"promotion transaction {tx_id!r} was reused with different intent")
                    return existing
                if rec.id in records or any(
                        tx.record.id == rec.id for tx in transactions.values()):
                    raise PromotionLedgerError(f"promotion record {rec.id!r} already exists")
                if any(tx.in_doubt and tx.before.identity == before.identity
                       for tx in transactions.values()):
                    raise PromotionLedgerError(
                        f"artifact {before.identity!r} has an unresolved promotion transaction")
                reservations = sum(tx.in_doubt for tx in transactions.values())
                if (self.max_records is not None
                        and len(records) + reservations >= self.max_records):
                    raise PromotionLedgerError("promotion ledger retention limit reached")

                if self.path is not None:
                    if not has_journal:
                        head = self._migrate_legacy_locked(records)
                    event = self._event("prepare", head, transaction=intent)
                    self._append_events_locked((event,))
                    # Keep the historical projection readable even when the
                    # first journal entry is an intentionally invisible prepare.
                    self._sync_projection_after_journal_locked(records)
                transactions[tx_id] = intent
                self._records = records
                self._transactions = transactions
                return intent
        except PromotionLedgerError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("could not persist promotion prepare") from exc

    def commit(self, transaction_id: str, *, artifact: ArtifactRevision,
               at: float) -> PromotionRecord:
        """Commit a prepared promotion iff the exact intended artifact is live."""
        committed_at = _event_time(at, "commit")
        try:
            with self._locked():
                records, transactions, head, has_journal = self._full_state_locked()
                tx = transactions.get(transaction_id)
                if tx is None:
                    raise PromotionLedgerError(
                        f"promotion transaction {transaction_id!r} does not exist")
                if tx.state == "committed":
                    rec = records.get(tx.record.id)
                    if rec is None:
                        raise PromotionLedgerError("committed transaction has no promotion record")
                    if artifact != tx.after:
                        raise PromotionLedgerError(
                            "idempotent promotion commit used a mismatched artifact")
                    return rec
                if tx.state != "prepared":
                    raise PromotionLedgerError("cannot commit an aborted promotion transaction")
                if artifact != tx.after:
                    raise PromotionLedgerError(
                        "runtime artifact does not match the prepared promotion revision")
                committed = replace(tx.record, promoted_at=committed_at)
                if committed.id in records:
                    raise PromotionLedgerError(
                        f"promotion record {committed.id!r} already exists")

                if self.path is not None:
                    if not has_journal:  # pragma: no cover - prepare always creates it
                        head = self._migrate_legacy_locked(records)
                    audit_receipt = _promotion_audit_envelope(
                        committed,
                        decision="promote",
                        occurred_at=committed_at,
                        transaction_id=transaction_id,
                        artifact=artifact,
                    )
                    event = self._event(
                        "commit", head, transaction_id=transaction_id,
                        artifact=artifact, committed_at=committed_at,
                        audit=audit_receipt)
                    self._append_events_locked((event,))
                    self._audit_pending[audit_receipt["event_id"]] = audit_receipt
                else:
                    audit_receipt = _promotion_audit_envelope(
                        committed,
                        decision="promote",
                        occurred_at=committed_at,
                        transaction_id=transaction_id,
                        artifact=artifact,
                    )
                    self._audit_pending[audit_receipt["event_id"]] = audit_receipt
                records[committed.id] = committed
                transactions[transaction_id] = replace(
                    tx, state="committed", resolved_at=committed_at,
                    reason="", last_observed=artifact)
                if self.path is not None:
                    self._sync_projection_after_journal_locked(records)
                self._records = records
                self._transactions = transactions
                return committed
        except PromotionLedgerError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("could not persist promotion commit") from exc

    def abort(self, transaction_id: str, *, artifact: ArtifactRevision,
              at: float, reason: str) -> PromotionTransaction:
        """Abort only when observation proves the pre-promotion artifact is live."""
        aborted_at = _event_time(at, "abort")
        clean_reason = str(reason).replace("\r", " ").replace("\n", " ")[:500]
        try:
            with self._locked():
                records, transactions, head, has_journal = self._full_state_locked()
                tx = transactions.get(transaction_id)
                if tx is None:
                    raise PromotionLedgerError(
                        f"promotion transaction {transaction_id!r} does not exist")
                if tx.state == "aborted":
                    if artifact != tx.before:
                        raise PromotionLedgerError(
                            "idempotent promotion abort used a mismatched artifact")
                    return tx
                if tx.state != "prepared":
                    raise PromotionLedgerError("cannot abort a committed promotion transaction")
                if artifact != tx.before:
                    raise PromotionLedgerError(
                        "cannot abort while the runtime artifact differs from prepared before state")

                if self.path is not None:
                    if not has_journal:  # pragma: no cover - prepare always creates it
                        head = self._migrate_legacy_locked(records)
                    event = self._event(
                        "abort", head, transaction_id=transaction_id,
                        artifact=artifact, aborted_at=aborted_at, reason=clean_reason)
                    self._append_events_locked((event,))
                aborted = replace(
                    tx, state="aborted", resolved_at=aborted_at,
                    reason=clean_reason, last_observed=artifact)
                transactions[transaction_id] = aborted
                self._records = records
                self._transactions = transactions
                return aborted
        except PromotionLedgerError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("could not persist promotion abort") from exc

    def transaction(self, transaction_id: str) -> PromotionTransaction | None:
        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            return transactions.get(transaction_id)

    def transactions(
        self, *, artifact_identity: str | None = None,
        state: str | None = None,
    ) -> list[PromotionTransaction]:
        """Return the authoritative promotion transactions matching a query.

        Persistent ledgers are re-read from their hash-chained journal while
        holding the cross-process lock; the JSON projection and this instance's
        cache are never treated as authority.  A committed transaction embeds
        the current promotion record so later rollback receipts are visible to
        authorization callers instead of the stale record captured at PREPARE.

        Results are ordered oldest-first by ``(prepared_at, id)``.  Filters are
        deliberately exact and validated before any ledger I/O, preventing a
        misspelled state or malformed artifact identity from becoming an empty,
        and therefore potentially misinterpreted, authority result.
        """
        if artifact_identity is not None:
            if not isinstance(artifact_identity, str):
                raise ValueError("artifact_identity must be a string or None")
            normalized_identity = artifact_identity.strip()
            if (normalized_identity != artifact_identity
                    or not normalized_identity or len(normalized_identity) > 2048
                    or any(ord(ch) < 32 for ch in normalized_identity)):
                raise ValueError(
                    "artifact_identity must be a non-empty printable string")
            artifact_identity = normalized_identity
        if state is not None and (
            not isinstance(state, str)
            or state not in {"prepared", "committed", "aborted"}
        ):
            raise ValueError(
                "state must be one of 'prepared', 'committed', 'aborted', or None")

        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            refreshed: dict[str, PromotionTransaction] = {}
            for transaction_id, transaction in transactions.items():
                current_record = records.get(transaction.record.id)
                if transaction.state == "committed":
                    if current_record is None:
                        raise PromotionLedgerError(
                            "committed promotion transaction has no current record")
                    transaction = replace(transaction, record=current_record)
                elif current_record is not None:
                    raise PromotionLedgerError(
                        "uncommitted promotion transaction has a promotion record")
                refreshed[transaction_id] = transaction

            self._records = records
            self._transactions = refreshed
            return sorted(
                (
                    transaction for transaction in refreshed.values()
                    if (artifact_identity is None
                        or transaction.before.identity == artifact_identity)
                    and (state is None or transaction.state == state)
                ),
                key=lambda transaction: (transaction.prepared_at, transaction.id),
            )

    def in_doubt(self, *, artifact_identity: str | None = None) -> list[PromotionTransaction]:
        """Return durable prepares that still require artifact reconciliation."""
        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            return sorted(
                (tx for tx in transactions.values()
                 if tx.in_doubt and (artifact_identity is None
                                     or tx.before.identity == artifact_identity)),
                key=lambda tx: (tx.prepared_at, tx.id),
            )

    def recover(self, transaction_id: str, *, artifact: ArtifactRevision,
                at: float) -> PromotionTransaction:
        """Resolve one in-doubt prepare from a trusted current observation.

        Exact intended-after commits, exact before aborts, and every third state
        remains visibly in doubt.  The latter is append-audited and continues to
        reserve the artifact, preventing an unknown partial write from being
        papered over by a later promotion.
        """
        tx = self.transaction(transaction_id)
        if tx is None:
            raise PromotionLedgerError(
                f"promotion transaction {transaction_id!r} does not exist")
        if tx.state == "committed":
            return tx
        if tx.state == "aborted":
            return tx
        if artifact == tx.after:
            self.commit(transaction_id, artifact=artifact, at=at)
            resolved = self.transaction(transaction_id)
            if resolved is None:  # pragma: no cover - guarded by commit
                raise PromotionLedgerError("committed promotion transaction disappeared")
            return resolved
        if artifact == tx.before:
            return self.abort(
                transaction_id, artifact=artifact, at=at,
                reason="recovery observed the original artifact revision")
        return self._record_recovery_conflict(
            transaction_id, artifact=artifact, at=at,
            reason="runtime artifact matches neither prepared revision")

    def recover_in_doubt(
        self, inspect: Callable[[str], ArtifactRevision], *,
        artifact_identity: str | None = None, at: float | None = None,
    ) -> list[PromotionTransaction]:
        """Inspect and reconcile every selected in-doubt transaction.

        Inspection failures leave the durable prepare untouched (and therefore
        still blocking).  Callers receive the post-attempt states so a privileged
        writer can refuse to continue unless every selected transaction resolved.
        """
        resolved: list[PromotionTransaction] = []
        for tx in self.in_doubt(artifact_identity=artifact_identity):
            observed_at = time.time() if at is None else at
            try:
                artifact = inspect(tx.before.identity)
                if not isinstance(artifact, ArtifactRevision):
                    raise TypeError("artifact inspector returned the wrong type")
                resolved.append(self.recover(tx.id, artifact=artifact, at=observed_at))
            except Exception:
                log.warning("promotion transaction recovery failed for %s", tx.id, exc_info=True)
                latest = self.transaction(tx.id)
                resolved.append(latest if latest is not None else tx)
        return resolved

    def _record_recovery_conflict(
        self, transaction_id: str, *, artifact: ArtifactRevision,
        at: float, reason: str,
    ) -> PromotionTransaction:
        observed_at = _event_time(at, "recovery conflict")
        clean_reason = str(reason).replace("\r", " ").replace("\n", " ")[:500]
        try:
            with self._locked():
                records, transactions, head, has_journal = self._full_state_locked()
                tx = transactions.get(transaction_id)
                if tx is None:
                    raise PromotionLedgerError(
                        f"promotion transaction {transaction_id!r} does not exist")
                if tx.state != "prepared":
                    return tx
                if (artifact.identity != tx.before.identity
                        or artifact in {tx.before, tx.after}):
                    raise PromotionLedgerError("recovery conflict observation is invalid")
                if tx.last_observed == artifact and tx.reason == clean_reason:
                    return tx
                if self.path is not None:
                    if not has_journal:  # pragma: no cover - prepare always creates it
                        head = self._migrate_legacy_locked(records)
                    event = self._event(
                        "recovery_conflict", head, transaction_id=transaction_id,
                        artifact=artifact, observed_at=observed_at, reason=clean_reason)
                    self._append_events_locked((event,))
                conflicted = replace(
                    tx, reason=clean_reason, last_observed=artifact,
                    recovery_attempts=tx.recovery_attempts + 1)
                transactions[transaction_id] = conflicted
                self._records = records
                self._transactions = transactions
                return conflicted
        except PromotionLedgerError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("could not persist promotion recovery conflict") from exc

    def pending_audit_count(self) -> int:
        """Return durable promotion/rollback events awaiting signed delivery."""
        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            return len(self._audit_pending)

    def flush_audit_outbox(
        self,
        recorder: Callable[..., bool | None],
        *,
        limit: int = 32,
    ) -> int:
        """Deliver a bounded at-least-once window of committed audit receipts.

        The state transition and receipt are one hash-chained journal event.
        Delivery acknowledgement is a later journal event.  A process death
        after the sink accepts a row but before acknowledgement therefore
        retries the same stable ``event_id`` instead of losing the audit.
        """
        if not callable(recorder):
            raise TypeError("audit recorder must be callable")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("audit delivery limit must be between 1 and 500")
        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            pending = sorted(
                self._audit_pending.values(),
                key=lambda item: (item["queued_at"], item["event_id"]),
            )[:limit]

        delivered = 0
        for receipt in pending:
            try:
                accepted = recorder(**dict(receipt["payload"]))
            except Exception as exc:
                log.warning(
                    "self-improvement audit event %s remains pending (%s)",
                    receipt["event_id"],
                    type(exc).__name__,
                )
                break
            if accepted is False:
                log.warning(
                    "self-improvement audit event %s remains pending "
                    "(sink did not accept it)",
                    receipt["event_id"],
                )
                break
            if self._acknowledge_audit(receipt):
                delivered += 1
        return delivered

    def _acknowledge_audit(self, receipt: Mapping[str, Any]) -> bool:
        event_id = str(receipt.get("event_id") or "")
        with self._locked():
            records, transactions, head, has_journal = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            current = self._audit_pending.get(event_id)
            if current is None:
                # A concurrent drainer already acknowledged the same stable id.
                return False
            if current != receipt:
                raise PromotionLedgerError(
                    "audit acknowledgement does not match the pending receipt"
                )
            if self.path is not None:
                if not has_journal:
                    raise PromotionLedgerError(
                        "cannot acknowledge an audit without its authoritative journal"
                    )
                event = self._event(
                    "audit_ack",
                    head,
                    audit_event_id=event_id,
                    delivered_at=time.time(),
                )
                self._append_events_locked((event,))
            self._audit_pending.pop(event_id)
            return True

    def get(self, record_id: str) -> PromotionRecord | None:
        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            return records.get(record_id)

    def mark_rolled_back(self, record_id: str, *, at: float, effect_guard=None,
                         rollback_metadata: Mapping[str, Any] | None = None) -> bool:
        """Append a rollback event; never report success without its receipt."""
        try:
            with self._locked():
                records, transactions, head, has_journal = self._full_state_locked()
                rec = records.get(record_id)
                if rec is None or rec.rolled_back:
                    return False
                provenance = dict(rec.provenance)
                if rollback_metadata is not None:
                    provenance["rollback_receipt"] = _receipt_provenance(rollback_metadata)
                    provenance = _receipt_provenance(provenance)
                updated = PromotionRecord(
                    **{**rec.to_dict(), "rolled_back": True, "rolled_back_at": at,
                       "provenance": provenance})
                if self.path is not None:
                    if not has_journal:
                        head = self._migrate_legacy_locked(records)
                    audit_receipt = _promotion_audit_envelope(
                        updated,
                        decision="rollback",
                        occurred_at=at,
                    )
                    event = self._event("rollback", head, record_id=record_id,
                                        rolled_back_at=at, audit=audit_receipt,
                                        **({"rollback_metadata": provenance["rollback_receipt"]}
                                           if rollback_metadata is not None else {}))
                    if effect_guard is None:
                        self._append_events_locked((event,))
                    else:
                        self._append_events_locked((event,), effect_guard=effect_guard)
                    self._audit_pending[audit_receipt["event_id"]] = audit_receipt
                    records[record_id] = updated
                    self._sync_projection_after_journal_locked(records)
                else:
                    if effect_guard is not None:
                        effect_guard()
                    records[record_id] = updated
                    audit_receipt = _promotion_audit_envelope(
                        updated,
                        decision="rollback",
                        occurred_at=at,
                    )
                    self._audit_pending[audit_receipt["event_id"]] = audit_receipt
                self._records = records
                self._transactions = transactions
                return True
        except PromotionLedgerError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("could not persist rollback receipt") from exc

    def all(self) -> list[PromotionRecord]:
        with self._locked():
            records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions
            return sorted(records.values(), key=lambda rec: (rec.promoted_at, rec.id), reverse=True)

    def _refresh(self) -> None:
        with self._locked():
            records, transactions, _, has_journal = self._full_state_locked()
            if self.path is not None and records and not has_journal:
                self._migrate_legacy_locked(records)
                self._sync_projection_after_journal_locked(records)
                records, transactions, _, _ = self._full_state_locked()
            self._records = records
            self._transactions = transactions

    def _state_locked(self) -> tuple[dict[str, PromotionRecord], str | None, bool]:
        """Compatibility view used by legacy promotion/rollback operations."""
        records, _transactions, head, has_journal = self._full_state_locked()
        return records, head, has_journal

    def _full_state_locked(self) -> tuple[
        dict[str, PromotionRecord], dict[str, PromotionTransaction], str | None, bool,
    ]:
        if self.path is None:
            return dict(self._records), dict(self._transactions), None, False
        projection = Path(self.path)
        journal = self._journal_path
        _assert_regular_file(projection, label="promotion ledger projection")
        _assert_regular_file(journal, label="promotion ledger journal")
        if journal.exists():
            records, transactions, head = self._read_journal_state_locked()
            repair_reason = ""
            try:
                if not projection.exists():
                    repair_reason = "missing"
                else:
                    projected = self._read_projection_locked()
                    if not _records_match(records, projected):
                        repair_reason = "disagrees with authoritative journal"
            except PromotionLedgerError:
                repair_reason = "malformed"
            if repair_reason:
                log.warning("repairing %s promotion ledger projection from journal", repair_reason)
                self._sync_projection_after_journal_locked(records)
            return records, transactions, head, True
        if projection.exists():
            self._audit_pending = {}
            return self._read_projection_locked(), {}, None, False
        self._audit_pending = {}
        return {}, {}, None, False

    def _read_projection_locked(self) -> dict[str, PromotionRecord]:
        projection = Path(self.path)
        try:
            raw = json.loads(projection.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise PromotionLedgerError("cannot read promotion ledger projection") from exc
        if not isinstance(raw, list):
            raise PromotionLedgerError("promotion ledger projection is not a JSON list")
        records: dict[str, PromotionRecord] = {}
        for item in raw:
            rec = _record_from_dict(item)
            if rec.id in records:
                raise PromotionLedgerError(f"duplicate promotion record {rec.id!r}")
            records[rec.id] = rec
        return records

    def _read_journal_locked(self) -> tuple[dict[str, PromotionRecord], str]:
        records, _transactions, head = self._read_journal_state_locked()
        return records, head

    def _read_journal_state_locked(self) -> tuple[
        dict[str, PromotionRecord], dict[str, PromotionTransaction], str,
    ]:
        journal = self._journal_path
        try:
            text = journal.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise PromotionLedgerError("cannot read promotion ledger journal") from exc
        return self._replay_journal_text(text)

    def _replay_journal_text(self, text: str) -> tuple[
        dict[str, PromotionRecord], dict[str, PromotionTransaction], str,
    ]:
        """Verify and replay an already-read journal without repairing files.

        Audit readers may bound their read before using the same native replay
        authority. The caller owns any file permission and read-size checks.
        """
        if not text or not text.endswith("\n"):
            raise PromotionLedgerError("promotion ledger journal is incomplete")

        records: dict[str, PromotionRecord] = {}
        transactions: dict[str, PromotionTransaction] = {}
        pending_audits: dict[str, dict[str, Any]] = {}
        seen_audits: set[str] = set()
        previous: str | None = None
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line:
                raise PromotionLedgerError("promotion ledger journal contains a blank event")
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise PromotionLedgerError(
                    f"promotion ledger journal event {line_number} is invalid JSON") from exc
            if not isinstance(event, dict):
                raise PromotionLedgerError(
                    f"promotion ledger journal event {line_number} is not an object")
            claimed = event.get("sha256")
            unsigned = {key: value for key, value in event.items() if key != "sha256"}
            try:
                expected = hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()
            except (TypeError, ValueError) as exc:
                raise PromotionLedgerError(
                    f"promotion ledger journal event {line_number} is not canonical JSON") from exc
            if not isinstance(claimed, str) or claimed != expected:
                raise PromotionLedgerError(
                    f"promotion ledger journal event {line_number} failed its hash check")
            if event.get("version") != _JOURNAL_VERSION or event.get("prev_sha256") != previous:
                raise PromotionLedgerError(
                    f"promotion ledger journal event {line_number} broke the hash chain")

            event_kind = event.get("event")
            if event_kind == "audit_ack":
                event_id = event.get("audit_event_id")
                _event_time(event.get("delivered_at"), "audit delivery")
                if (
                    not isinstance(event_id, str)
                    or event_id not in pending_audits
                    or "audit" in event
                ):
                    raise PromotionLedgerError(
                        f"promotion ledger journal event {line_number} "
                        "has an invalid audit acknowledgement"
                    )
                pending_audits.pop(event_id)
                previous = claimed
                continue

            handler = {
                "promote": self._replay_promote,
                "prepare": self._replay_prepare,
                "commit": self._replay_commit,
                "abort": self._replay_abort,
                "recovery_conflict": self._replay_recovery_conflict,
                "rollback": self._replay_rollback,
            }.get(event_kind)
            if handler is None:
                raise PromotionLedgerError(
                    f"promotion ledger journal event {line_number} has an unknown type")
            handler(event, records, transactions, line_number)
            raw_audit = event.get("audit")
            if raw_audit is not None:
                audit_receipt = _audit_envelope_from_dict(raw_audit)
                audit_event_id = audit_receipt["event_id"]
                if audit_event_id in seen_audits:
                    raise PromotionLedgerError(
                        f"promotion ledger journal event {line_number} "
                        "reused an audit event id"
                    )
                seen_audits.add(audit_event_id)
                pending_audits[audit_event_id] = audit_receipt
            previous = claimed
        self._audit_pending = pending_audits
        return records, transactions, previous

    @staticmethod
    def _replay_promote(event, records, transactions, line_number) -> None:
        rec = _record_from_dict(event.get("record"))
        if (rec.rolled_back or rec.id in records
                or any(tx.record.id == rec.id for tx in transactions.values())):
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid promotion")
        records[rec.id] = rec

    @staticmethod
    def _replay_prepare(event, records, transactions, line_number) -> None:
        tx = _transaction_from_dict(event.get("transaction"))
        if (tx.state != "prepared" or tx.record.rolled_back
                or tx.resolved_at is not None or tx.reason
                or tx.last_observed is not None or tx.recovery_attempts
                or tx.id in transactions or tx.record.id in records
                or any(existing.record.id == tx.record.id
                       for existing in transactions.values())):
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid prepare")
        transactions[tx.id] = tx

    @staticmethod
    def _replay_commit(event, records, transactions, line_number) -> None:
        tx_id = event.get("transaction_id")
        tx = transactions.get(tx_id)
        observed = _artifact_revision_from_dict(event.get("artifact"))
        committed_at = _event_time(event.get("committed_at"), "commit")
        if (not isinstance(tx_id, str) or tx is None or tx.state != "prepared"
                or observed != tx.after or tx.record.id in records):
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid commit")
        committed = replace(tx.record, promoted_at=committed_at)
        records[committed.id] = committed
        transactions[tx_id] = replace(
            tx, state="committed", resolved_at=committed_at,
            reason="", last_observed=observed)

    @staticmethod
    def _replay_abort(event, _records, transactions, line_number) -> None:
        tx_id = event.get("transaction_id")
        tx = transactions.get(tx_id)
        observed = _artifact_revision_from_dict(event.get("artifact"))
        aborted_at = _event_time(event.get("aborted_at"), "abort")
        reason = event.get("reason", "")
        if (not isinstance(tx_id, str) or tx is None or tx.state != "prepared"
                or observed != tx.before or not isinstance(reason, str)):
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid abort")
        transactions[tx_id] = replace(
            tx, state="aborted", resolved_at=aborted_at,
            reason=reason, last_observed=observed)

    @staticmethod
    def _replay_recovery_conflict(event, _records, transactions, line_number) -> None:
        tx_id = event.get("transaction_id")
        tx = transactions.get(tx_id)
        raw_observed = event.get("artifact")
        observed = (None if raw_observed is None
                    else _artifact_revision_from_dict(raw_observed))
        _event_time(event.get("observed_at"), "recovery conflict")
        reason = event.get("reason", "")
        if (not isinstance(tx_id, str) or tx is None or tx.state != "prepared"
                or not isinstance(reason, str)
                or (observed is not None
                    and (observed.identity != tx.before.identity
                         or observed in {tx.before, tx.after}))):
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid recovery")
        transactions[tx_id] = replace(
            tx, reason=reason, last_observed=observed,
            recovery_attempts=tx.recovery_attempts + 1)

    @staticmethod
    def _replay_rollback(event, records, _transactions, line_number) -> None:
        record_id = event.get("record_id")
        rec = records.get(record_id)
        if not isinstance(record_id, str) or rec is None or rec.rolled_back:
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid rollback")
        rolled_back_at = event.get("rolled_back_at")
        try:
            if rolled_back_at is not None:
                rolled_back_at = float(rolled_back_at)
        except (TypeError, ValueError) as exc:
            raise PromotionLedgerError(
                f"promotion ledger journal event {line_number} has an invalid rollback time") from exc
        provenance = dict(rec.provenance)
        if "rollback_metadata" in event:
            try:
                provenance["rollback_receipt"] = _receipt_provenance(event["rollback_metadata"])
                provenance = _receipt_provenance(provenance)
            except (TypeError, ValueError) as exc:
                raise PromotionLedgerError("invalid rollback receipt metadata") from exc
        records[record_id] = PromotionRecord(
            **{**rec.to_dict(), "rolled_back": True,
               "rolled_back_at": rolled_back_at, "provenance": provenance})

    def _event(self, kind: str, previous: str | None, **payload: Any) -> dict[str, Any]:
        event = {
            "version": _JOURNAL_VERSION,
            "event": kind,
            "prev_sha256": previous,
            **payload,
        }
        if "record" in event:
            record = event["record"]
            event["record"] = record.to_dict() if isinstance(record, PromotionRecord) else record
        if "transaction" in event:
            transaction = event["transaction"]
            event["transaction"] = (
                transaction.to_dict()
                if isinstance(transaction, PromotionTransaction) else transaction)
        if "artifact" in event:
            artifact = event["artifact"]
            event["artifact"] = (
                artifact.to_dict() if isinstance(artifact, ArtifactRevision) else artifact)
        try:
            event["sha256"] = hashlib.sha256(
                _canonical_json(event).encode("utf-8")).hexdigest()
        except (TypeError, ValueError) as exc:
            raise PromotionLedgerError("promotion receipt is not serializable") from exc
        return event

    def _migrate_legacy_locked(self, records: Mapping[str, PromotionRecord]) -> str | None:
        """Seed the journal once from an old JSON list without discarding it."""
        if not records:
            return None
        previous: str | None = None
        events: list[dict[str, Any]] = []
        for rec in sorted(records.values(), key=lambda item: (item.promoted_at, item.id)):
            original = PromotionRecord(
                **{**rec.to_dict(), "rolled_back": False, "rolled_back_at": None})
            event = self._event("promote", previous, record=original)
            events.append(event)
            previous = event["sha256"]
            if rec.rolled_back:
                event = self._event("rollback", previous, record_id=rec.id,
                                    rolled_back_at=rec.rolled_back_at)
                events.append(event)
                previous = event["sha256"]
        return self._append_events_locked(events)

    def _ensure_journal_locked(self) -> None:
        journal = self._journal_path
        if journal.exists():
            _assert_regular_file(journal, label="promotion ledger journal")
            return
        try:
            from .file_lock import atomic_write_text

            atomic_write_text(journal, "", mode=0o600)
            _sync_file(journal)
            _sync_directory(journal.parent)
        except OSError as exc:
            raise PromotionLedgerError("cannot create promotion ledger journal") from exc

    def _append_events_locked(self, events: tuple[dict[str, Any], ...] | list[dict[str, Any]],
                              *, effect_guard=None) -> str:
        if not events:
            raise PromotionLedgerError("cannot commit an empty promotion journal transaction")
        self._ensure_journal_locked()
        journal = self._journal_path
        try:
            payload = "".join(_canonical_json(event) + "\n" for event in events)
            with journal.open("a", encoding="utf-8", newline="\n") as stream:
                if effect_guard is not None:
                    effect_guard()
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _sync_directory(journal.parent)
        except (OSError, UnicodeError, TypeError, ValueError) as exc:
            raise PromotionLedgerError("cannot append promotion ledger journal") from exc
        return str(events[-1]["sha256"])

    def _write_projection_locked(self, records: Mapping[str, PromotionRecord]) -> None:
        projection = Path(self.path)
        try:
            data = [record.to_dict() for record in sorted(
                records.values(), key=lambda item: (item.promoted_at, item.id))]
            from .file_lock import atomic_write_text

            atomic_write_text(projection, _canonical_json(data) + "\n", mode=0o600)
            _sync_file(projection)
            _sync_directory(projection.parent)
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            raise PromotionLedgerError("cannot write promotion ledger audit projection") from exc

    def _sync_projection_after_journal_locked(
            self, records: Mapping[str, PromotionRecord]) -> None:
        """Update the recoverable projection after the journal has committed."""
        try:
            self._write_projection_locked(records)
        except Exception:
            log.warning("promotion ledger journal committed but JSON projection is stale; "
                        "it will be repaired from the journal", exc_info=True)


_shared: dict[Path, SelfImprovementController] = {}
_shared_lock = threading.Lock()


def shared() -> SelfImprovementController:
    from .paths import data_dir

    path = data_dir("self_improvement.json")
    cfg = _config()
    with _shared_lock:
        ctrl = _shared.get(path)
        if ctrl is None:
            ctrl = SelfImprovementController(ledger=PromotionLedger(path=path))
            _shared[path] = ctrl
        # Re-read the margin and ceiling on every call: the controller is
        # process-wide, and an operator who tightens either one must not have
        # to restart long-running processes for it to apply.
        ctrl.min_improvement = float(cfg.get("min_improvement", 0.0))
        ctrl.max_auto_rung = str(cfg.get("max_auto_rung", "policy"))
        return ctrl


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def prepare_promotion(
    cand: Candidate, *, before: ArtifactRevision, after: ArtifactRevision,
    transaction_id: str | None = None,
    controller: SelfImprovementController | None = None,
) -> PromotionPreparation:
    """Public write-ahead promotion seam for runtime artifact owners."""
    try:
        return (controller or shared()).prepare_promotion(
            cand, before=before, after=after, transaction_id=transaction_id)
    except Exception:  # pragma: no cover - a privileged prepare must fail closed
        log.warning("self-improvement promotion prepare errored", exc_info=True)
        reason = "controller error"
        return PromotionPreparation(Verdict(
            cand.id, cand.rung, False, (GateResult("error", False, reason),), reason))


def authorize_prepared(
    preparation: PromotionPreparation,
    *,
    artifact: ArtifactRevision,
    controller: SelfImprovementController | None = None,
) -> Verdict:
    """Re-read exact authority immediately before artifact application."""
    try:
        return (controller or shared()).authorize_prepared(
            preparation,
            artifact=artifact,
        )
    except Exception:  # pragma: no cover - retain PREPARE for recovery
        log.warning("self-improvement pre-apply authorization errored", exc_info=True)
        return SelfImprovementController._fail_verdict(
            preparation.verdict,
            gate="transaction",
            reason="pre-apply authorization is in doubt; recovery required",
        )


def commit_prepared(
    preparation: PromotionPreparation, *, artifact: ArtifactRevision,
    controller: SelfImprovementController | None = None,
) -> Verdict:
    """Public exact-artifact COMMIT seam paired with :func:`prepare_promotion`."""
    try:
        return (controller or shared()).commit_prepared(preparation, artifact=artifact)
    except Exception:  # pragma: no cover - retain PREPARE for recovery
        log.warning("self-improvement promotion commit errored", exc_info=True)
        return SelfImprovementController._fail_verdict(
            preparation.verdict, gate="transaction",
            reason="promotion commit is in doubt; recovery required")


def abort_prepared(
    preparation: PromotionPreparation, *, artifact: ArtifactRevision, reason: str,
    controller: SelfImprovementController | None = None,
) -> Verdict:
    """Public proof-of-before ABORT seam paired with :func:`prepare_promotion`."""
    try:
        return (controller or shared()).abort_prepared(
            preparation, artifact=artifact, reason=reason)
    except Exception:  # pragma: no cover - retain PREPARE for recovery
        log.warning("self-improvement promotion abort errored", exc_info=True)
        return SelfImprovementController._fail_verdict(
            preparation.verdict, gate="transaction",
            reason="promotion transaction is in doubt; recovery required")


def recover_promotions(
    inspect: Callable[[str], ArtifactRevision], *, artifact_identity: str | None = None,
    controller: SelfImprovementController | None = None,
) -> list[PromotionTransaction]:
    """Public recovery seam; unresolved entries remain visible and blocking."""
    return (controller or shared()).recover_promotions(
        inspect, artifact_identity=artifact_identity)


def consider(cand: Candidate, *, controller: SelfImprovementController | None = None) -> Verdict:
    """Governed entry point: judge a candidate self-change for promotion.

    Returns a non-promoting verdict (a safe no-op for the caller) when the
    engine is off or any gate fails. The caller applies the change only on
    ``verdict.ok``.  Runtime artifact owners must use the write-ahead
    :func:`prepare_promotion` protocol instead of this compatibility seam.
    """
    if not enabled():
        return Verdict(cand.id, cand.rung, False,
                       (GateResult("enabled", False, "self-improvement disabled"),),
                       "self-improvement disabled")
    try:
        return (controller or shared()).promote(cand)
    except Exception:  # pragma: no cover -- a privileged write must never crash a run
        log.warning("self-improvement promotion errored; refusing change", exc_info=True)
        return Verdict(cand.id, cand.rung, False,
                       (GateResult("error", False, "controller error"),), "controller error")


__all__ = [
    "RUNGS", "Candidate", "GateResult", "Verdict", "PromotionRecord",
    "ArtifactRevision", "PromotionTransaction", "PromotionPreparation",
    "SelfImprovementController", "PromotionLedger", "PromotionLedgerError",
    "enabled", "shared", "reset_shared", "consider", "prepare_promotion",
    "authorize_prepared", "commit_prepared", "abort_prepared", "recover_promotions",
]
