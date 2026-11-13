"""Opt-in trajectory donation — the Tesla data-engine analog.

Schema v6 has the right shape for episode collection, but no selection
function. The flywheel only works if the upload is:

1. **Opt-in, default OFF.** ``[telemetry] donate_trajectories = true``
   in ``~/.maverick/config.toml`` (also surfaced in the installer
   wizard) is the only way to enable it. No env-var shortcut.
2. **Client-side scrubbed.** Every text field passes through the
   secret-scrubber + a PII-redaction step BEFORE landing in the
   outbox. The user can inspect ``~/.maverick/outbox/`` before
   anything is sent.
3. **Metadata-only by default.** Tuple is
   ``(task_brief_hash, action_sequence, terminal_reward, model_id,
   tool_subset, disagreement_entropy)``. NO raw text unless the user
   ALSO opts into ``donate_text = true``.
4. **Selective.** Only trajectories where
   ``disagreement_high AND outcome == 'success'`` are written -- the
   cases where the swarm learned something the solo agent couldn't.
   Everything else is noise.

The outbox is a local directory that ``maverick dream --donations-dir``
can replay. This module only writes records in the right shape to disk;
it does NOT phone home.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .paths import data_dir
from .secrets import scrub

log = logging.getLogger(__name__)


def _redact_text(text: str) -> str:
    """Secret-scrub AND PII-redact one string before it lands in the outbox.

    The donation contract (see module docstring) promises both passes: the
    regex secret-scrubber (API keys / tokens / URL credentials) PLUS a
    PII-redaction step (emails / phone numbers / SSNs / card numbers) via
    :mod:`maverick.safety.pii_detector`. Run secrets first, then PII; if the
    PII detector is somehow unavailable, the text is still secret-scrubbed
    (never weaker than before)."""
    out = scrub(text)
    try:
        from .safety.pii_detector import redact as _redact_pii
        out, _ = _redact_pii(out)
    except Exception:  # pragma: no cover -- PII pass must never block a write
        log.warning("trajectory donation: PII redaction unavailable; "
                    "text is secret-scrubbed only")
    return out


def _default_outbox() -> Path:
    """The active scope's donation outbox, resolved at CALL time.

    Every peer learning store (reflexion, dreaming, self_harness) resolves its
    tenant-scoped path per call via ``data_dir(..., tenant=...)`` /
    ``_tenant_path`` so a later ``set_tenant`` takes effect. Binding this as a
    module-level constant at import time froze it to whatever tenant (or no
    tenant) was active during import -- so with critique mining on by default,
    ``dreaming._replay_critiques`` could read another tenant's donated outbox
    into THIS tenant's dream cycle. Resolved fresh here, like the rest of the
    learning stores.
    """
    return data_dir("outbox")


@dataclass
class TrajectoryRecord:
    """One donated trajectory.

    The hashed task brief identifies a task family (same prompt → same
    hash) for aggregation across users without exposing user text.
    Action sequence is tool names + JSON-shape only -- no argument
    values, no return values.
    """
    schema_version: int = 1
    record_id: str = field(default_factory=lambda: "trj_" + uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)
    task_brief_hash: str = ""
    task_brief_text: str | None = None  # only when donate_text=true
    # Local world-DB row id for this run. NOT meaningful off this machine; it's
    # the join key `training.ingest` / `training.export_texts` use to pull this
    # goal's `goal_events` back out of the local world DB (to label PRM steps and
    # reconstruct the DPO text sidecar). Without it both lookups hit goal_id=0,
    # fetch nothing, and every trajectory ends up with zero steps / no transcript.
    goal_id: int = 0
    source_ownership: str = "unknown"  # metadata only; never expose a principal
    model_id: str = ""
    tools_used: list[str] = field(default_factory=list)
    action_sequence: list[str] = field(default_factory=list)
    outcome: str = ""              # success / failure / blocked / etc
    reward: float = 0.0             # 1.0 on accept, 0.0 on reject, else verifier confidence
    verifier_confidence: float = 0.0
    verifier_critique: str = ""
    disagreement_entropy: float = 0.0
    # Counterfactual swarm credit (maverick.credit): agent name -> marginal
    # credit, when CSCA ran. Lets the data engine credit-WEIGHT the trajectory
    # (learn more from the sub-agents that actually earned the outcome) instead
    # of treating every contributor equally. Empty when CSCA was off/not run.
    agent_credit: dict = field(default_factory=dict)
    # Per-sub-agent trajectories (role, name, tool-name actions, credit, weight)
    # -- the credit-weighted units to learn from, not just the goal-level record.
    # Populated from ctx.last_subtrajectories when CSCA ran. Action sequences are
    # tool NAMES only, so this carries no argument/result text.
    sub_trajectories: list = field(default_factory=list)
    # Rejected pre-revision drafts: each ``{"text", "confidence", "critique"}``.
    # When the verifier rejects a FINAL and the agent revises, the rejected draft
    # is the "rejected" half of a DPO preference pair (the accepted final is the
    # "chosen"). This is the genuine quality gradient the agent produces -- every
    # shipped answer is driven to "good", so the only clearly-worse examples are
    # the drafts it discards. The ``text`` is raw transcript content, so it is
    # stripped unless ``donate_text`` is also set (same rule as task_brief_text).
    rejected_attempts: list = field(default_factory=list)
    # Best-of-N scored candidates: each ``{"text": patch, "score": float in [0,1],
    # "all_pass": bool}``. When coding-mode best-of-N runs N attempts at one task,
    # each candidate's OBJECTIVE local-test pass-rate is its score -- a passing
    # patch (1.0) vs a failing one (~0.0) is a real DPO preference pair WITHOUT
    # any verifier rejection (the verifier accepts ~everything, spread 0.03-0.10).
    # The ``text`` is the unified-diff patch (the proposer artifact DPO trains on),
    # stripped unless ``donate_text`` is set -- same rule as task_brief_text.
    scored_candidates: list = field(default_factory=list)
    wall_seconds: float = 0.0
    cost_dollars: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0


def _donations_enabled() -> bool:
    """Single source of truth for the opt-in toggle."""
    try:
        from .config import load_config
        cfg = load_config()
        return bool(cfg.get("telemetry", {}).get("donate_trajectories", False))
    except Exception:
        return False


def _text_donations_enabled() -> bool:
    try:
        from .config import load_config
        cfg = load_config()
        tel = cfg.get("telemetry", {})
        return bool(
            tel.get("donate_trajectories", False)
            and tel.get("donate_text", False)
        )
    except Exception:
        return False


def hash_brief(brief: str) -> str:
    """Stable identifier for a task brief without revealing its text."""
    return hashlib.sha256(brief.strip().encode("utf-8")).hexdigest()[:16]


def _scrub_payload(value):
    """Recursively secret-scrub + PII-redact every string in a JSON payload."""
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_scrub_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_payload(item) for item in value)
    if isinstance(value, dict):
        # Keys are field names (no user content), so secret-scrub only.
        return {
            (scrub(key) if isinstance(key, str) else key): _scrub_payload(item)
            for key, item in value.items()
        }
    return value


def _donation_thresholds() -> tuple[float, float]:
    """``(min_entropy, min_confidence)`` from ``[telemetry]``.

    Defaults to the "gold trajectory" bar (0.5 / 0.75). Lower
    ``[telemetry] donate_min_entropy = 0`` to capture EVERY successful,
    high-confidence run -- not only swarm high-disagreement ones -- so the
    learning loop actually has data from normal single-agent use (most goals
    never spawn a disagreeing swarm, so the default bar donates nothing from
    typical usage). Fail-open to the defaults."""
    try:
        from .config import load_config
        tel = load_config().get("telemetry", {}) or {}
        ent = float(tel.get("donate_min_entropy", 0.5))
        conf = float(tel.get("donate_min_confidence", 0.75))
        return max(0.0, ent), max(0.0, min(1.0, conf))
    except Exception:
        return 0.5, 0.75


def should_donate(
    outcome: str,
    verifier_confidence: float,
    disagreement_entropy: float,
    *,
    min_entropy: float | None = None,
    min_confidence: float | None = None,
) -> bool:
    """Selection: only the trajectories the model can learn from.

    Gold rows are: high disagreement (the swarm actually explored
    multiple branches) AND high verifier confidence on the chosen
    branch (we know the right answer was eventually reached) AND
    outcome=success (the trajectory closed cleanly).

    When ``min_entropy``/``min_confidence`` are not passed, they come from
    ``[telemetry] donate_min_entropy`` / ``donate_min_confidence`` (see
    :func:`_donation_thresholds`) -- set ``donate_min_entropy = 0`` to donate
    every successful high-confidence run, not just swarm-disagreement ones.
    """
    if min_entropy is None or min_confidence is None:
        cfg_ent, cfg_conf = _donation_thresholds()
        if min_entropy is None:
            min_entropy = cfg_ent
        if min_confidence is None:
            min_confidence = cfg_conf
    if outcome != "success":
        return False
    if verifier_confidence < min_confidence:
        return False
    if disagreement_entropy < min_entropy:
        return False
    return True


def write_record(
    record: TrajectoryRecord,
    *,
    outbox: Path | None = None,
) -> Path | None:
    """Persist a record to the local outbox, with scrubbing.

    Returns the written path, or None if donations are disabled OR the
    record doesn't pass the selection gate. A failed write is logged and
    returns None. The gates, the text stripping and the scrubbing before the
    write are not guarded, so an error there propagates: the caller must
    contain it (the orchestrator does) so a bug in the donor cannot affect
    the actual goal execution.
    """
    if not _donations_enabled():
        return None
    from .pilot_learning import excluded
    if excluded(record.goal_id):
        return None
    from .memory_ownership import current_owner
    try:
        record.source_ownership = "unowned" if current_owner(goal_id=record.goal_id) == "" else "private"
        if record.source_ownership != "unowned":
            return None  # installation opt-in cannot publish an employee's private work
    except Exception:
        return None
    # Calibration interlock: if the verifier has drifted (no longer
    # discriminates correct from incorrect on the labeled set), freeze learning
    # rather than harvest trajectories labeled by an untrustworthy evaluator.
    # Off by default + fail-open, so this is a no-op until calibration is
    # enforced and an assessment has found the verifier inadequate.
    try:
        from .calibration import learning_frozen
        if learning_frozen():
            log.warning(
                "trajectory donation skipped: verifier calibration inadequate "
                "(learning frozen). Run `maverick calibrate` after re-checking "
                "the verifier against a labeled set."
            )
            return None
    except Exception:  # pragma: no cover -- interlock must never block a run
        pass
    if not should_donate(
        record.outcome, record.verifier_confidence, record.disagreement_entropy,
    ):
        return None

    # Strip text fields unless the user opted into that too.
    if not _text_donations_enabled():
        record.task_brief_text = None
        # verifier_critique is raw model-generated free text (from verdict.critique
        # / test_result.summary()) that can quote proprietary task/answer content
        # and is NOT caught by secret/PII scrubbing. Drop it in metadata-only mode
        # so the "no raw text unless donate_text=true" contract actually holds.
        record.verifier_critique = ""
        # Drop the rejected-draft text (keep confidence/critique metadata) so the
        # default metadata-only contract holds. DPO needs this text, so the
        # self-learning runbook sets donate_text = true.
        record.rejected_attempts = [
            {k: v for k, v in a.items() if k != "text"}
            for a in (record.rejected_attempts or [])
            if isinstance(a, dict)
        ]
        # Same rule for best-of-N candidate patches: keep score/all_pass, drop text.
        record.scored_candidates = [
            {k: v for k, v in c.items() if k != "text"}
            for c in (record.scored_candidates or [])
            if isinstance(c, dict)
        ]

    # Scrub every text field that could carry secrets, including strings nested
    # in dictionaries/lists such as sub_trajectories.
    payload = _scrub_payload(asdict(record))

    try:
        out_dir = outbox or _default_outbox()
        out_dir.mkdir(parents=True, exist_ok=True)
        # Trajectory records carry prompt/result text; keep the outbox and
        # files owner-only (the default umask often leaves them
        # world-readable on servers).
        try:
            out_dir.chmod(0o700)
        except OSError:
            pass
        from .file_lock import atomic_create_text, atomic_read_text, ensure_private_directory
        from .training.identity import record_trajectory_id

        ensure_private_directory(out_dir)
        identity = record_trajectory_id({"record_id": record.record_id})
        payload["record_id"] = identity
        fname = f"{identity}.json"
        path = out_dir / fname
        body = json.dumps(payload, indent=2)
        try:
            atomic_create_text(path, body)
        except FileExistsError:
            if atomic_read_text(path) != body:
                raise ValueError("donation record identity already binds different content") from None
        return path
    except Exception as e:  # pragma: no cover
        log.warning("trajectory donation write failed: %s", e)
        return None


def list_pending(outbox: Path | None = None) -> list[Path]:
    """Return the outbox files awaiting upload, for `maverick donate status`."""
    out_dir = outbox or _default_outbox()
    if not out_dir.exists():
        return []
    return sorted(out_dir.glob("*.json"))


def clear_outbox(outbox: Path | None = None) -> int:
    """Delete every pending record. Returns count removed."""
    out_dir = outbox or _default_outbox()
    if not out_dir.exists():
        return 0
    n = 0
    for p in out_dir.glob("*.json"):
        try:
            p.unlink()
            n += 1
        except OSError:
            pass
    return n
