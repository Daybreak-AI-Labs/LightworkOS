"""Governed trajectory capture -- the data foundation for self-improvement.

Nothing downstream can *learn* without a record of what the agents actually
did. This is that record: a per-tenant, consent-gated, secret-redacted,
append-only store of agent steps (role, tool, outcome, error, verifier
confidence, process-reward signal). It is the raw material the verifier/policy
training rungs consume and the substrate the compounding-metric reads.

Posture: secret-scrubbed local capture is ON by default and can be disabled with
``[self_improvement] capture = false`` or ``MAVERICK_TRAJECTORY_CAPTURE=0``.
Raw-text donation and provider egress remain separate opt-ins. Every text field is run through
``secrets.scrub`` before it touches disk (a trajectory outlives the run and must
not become a credential leak). Writes are atomic-append, 0600, tenant-scoped via
``paths.data_dir``, and bounded (oldest rows roll off). Fail-open: a capture
error is logged and swallowed, never raised into a run.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text_chunks,
    cross_process_lock,
    ensure_private_file,
    open_private_append,
)

log = logging.getLogger(__name__)

_MAX_ROWS = 50_000  # bounded; oldest roll off


def enabled() -> bool:
    """Whether secret-scrubbed trajectory capture is on. ON by default."""
    try:
        from .config import get_self_improvement, governed_learning_env_flag
        override = governed_learning_env_flag("MAVERICK_TRAJECTORY_CAPTURE")
        if override is not None:
            return override
        return bool(get_self_improvement().get("capture", True))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _scrub(text: str | None) -> str:
    if not text:
        return ""
    try:
        from .secrets import scrub
        return scrub(str(text))
    except Exception:  # pragma: no cover -- never block capture on a scrub error
        return ""


@dataclass
class TrajectoryStep:
    ts: float
    goal_id: int
    episode_id: int
    step: int
    role: str
    tool: str = ""
    tool_succeeded: bool | None = None
    # None on legacy rows, True for a call that reached execution. Refused
    # calls are never captured by the agent loop. Keeping this separate from
    # success lets an executed failure remain honest training evidence.
    tool_executed: bool | None = None
    is_final: bool = False
    error: str = ""
    verifier_confidence: float | None = None
    promise: float | None = None
    progress: float | None = None
    domain: str = ""
    # Decision-DAG edge + terminal label, for counterfactual credit
    # (maverick.promotion_effect). ``parent_step`` is the step this one descends
    # from (None at a root); ``outcome`` is the episode's terminal task outcome in
    # [0,1], carried on the final step. Both optional and absent in old rows.
    parent_step: int | None = None
    outcome: float | None = None
    # A terminal outcome is training evidence only when an independent producer
    # records where it came from and when it was verified.  Agent-generated
    # verifier confidence intentionally leaves these fields empty: confidence is
    # not ground truth and must not become a label for the verifier that emitted
    # it.  Examples of trusted sources are ``human``, ``tests``, ``transaction``,
    # and ``ground_truth``.
    outcome_source: str = ""
    outcome_verified_at: float | None = None
    # Optional stable task identity.  ``goal_id`` remains the backwards-
    # compatible fallback; a stable task id lets repeated attempts stay in the
    # same evaluation group instead of leaking across train and test.
    task_id: str = ""

    def redacted(self) -> TrajectoryStep:
        """A copy safe to persist: scrub free-text fields."""
        return TrajectoryStep(
            ts=self.ts, goal_id=self.goal_id, episode_id=self.episode_id,
            step=self.step, role=_scrub(self.role)[:64], tool=_scrub(self.tool)[:64],
            tool_succeeded=self.tool_succeeded, tool_executed=self.tool_executed,
            is_final=self.is_final,
            error=_scrub(self.error)[:500], verifier_confidence=self.verifier_confidence,
            promise=self.promise, progress=self.progress, domain=_scrub(self.domain)[:64],
            parent_step=self.parent_step, outcome=self.outcome,
            outcome_source=_scrub(self.outcome_source)[:120],
            outcome_verified_at=self.outcome_verified_at,
            task_id=_scrub(self.task_id)[:160],
        )


@dataclass
class TrajectoryStore:
    path: Path | None = None
    max_rows: int = _MAX_ROWS
    _lock: threading.Lock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._lock is None:
            self._lock = threading.Lock()
        # Appends since the last rotation check. _maybe_rotate re-reads the whole
        # file, so we amortize that O(file) scan over a batch of appends instead
        # of paying it on EVERY record -- once the file filled to max_rows the
        # old code re-read tens of MB of NDJSON per captured step.
        self._since_check = 0

    def record(self, step: TrajectoryStep) -> bool:
        """Append one redacted step. Returns True on success; never raises."""
        # Enforce the client/operator switch at the persistence boundary; do
        # not rely on every current and future producer remembering to gate.
        if self.path is None or not enabled():
            return False
        try:
            # The gates can raise (a kill-switch checker); a gate that cannot
            # answer refuses the write rather than breaking the agent path.
            from .pilot_learning import excluded
            if excluded(step.goal_id):
                return False
            from .learning_guard import learning_write_allowed
            if not learning_write_allowed("trajectory_capture"):
                return False
            line = json.dumps(asdict(step.redacted()), sort_keys=True)
            with self._lock:
                p = Path(self.path)
                # Rotation is a read-modify-write.  Hold one strict process
                # lock across append + possible rewrite so a second worker
                # cannot append to the inode we are about to replace and lose
                # a trajectory row.
                with cross_process_lock(p, strict=True):
                    fd = open_private_append(p)
                    with os.fdopen(fd, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                        fh.flush()
                        os.fsync(fh.fileno())
                    # Only scan for rotation periodically (worst-case overage is
                    # one batch above max_rows), not on every append.
                    self._since_check += 1
                    if self._since_check >= max(1, self.max_rows // 8):
                        self._since_check = 0
                        self._maybe_rotate(p)
            return True
        except Exception:  # pragma: no cover -- capture is best-effort
            log.debug("trajectory capture failed", exc_info=True)
            return False

    def _maybe_rotate(self, p: Path) -> None:
        # Cheap bound: when the file exceeds the cap, keep the newest max_rows.
        try:
            ensure_private_file(p)
            lines = atomic_read_text(p).splitlines(keepends=True)
            if len(lines) <= self.max_rows:
                return
            kept = lines[-self.max_rows:]
            atomic_write_text_chunks(p, kept)
        except Exception:  # pragma: no cover
            pass

    def iter_steps(self, *, goal_id: int | None = None, limit: int = 10_000):
        """Yield stored steps (optionally for one goal), newest last."""
        if self.path is None or not Path(self.path).exists():
            return
        try:
            path = ensure_private_file(Path(self.path))
            lines = atomic_read_text(path).splitlines()
        except OSError:  # pragma: no cover
            return
        for raw in lines[-limit:]:
            try:
                d = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(d, dict):
                continue
            if goal_id is not None and d.get("goal_id") != goal_id:
                continue
            from .pilot_learning import excluded
            if excluded(d.get("goal_id")):
                continue
            yield TrajectoryStep(**{k: d.get(k) for k in TrajectoryStep.__dataclass_fields__})

    def tools_by_goal(self, *, limit: int = 20_000) -> dict[int, list[str]]:
        """Map ``goal_id`` -> the distinct tools that goal's run used, in first-
        seen order. This is the signal dreaming needs to give a distilled skill
        its ``tools_needed`` (the raw episode row records only a tool *count*).
        Empty when capture is off (nothing was recorded)."""
        out: dict[int, list[str]] = {}
        for s in self.iter_steps(limit=limit):
            tool = (s.tool or "").strip()
            if not tool:
                continue
            seen = out.setdefault(int(s.goal_id), [])
            if tool not in seen:
                seen.append(tool)
        return out

    def count(self) -> int:
        if self.path is None or not Path(self.path).exists():
            return 0
        try:
            path = ensure_private_file(Path(self.path))
            return len(atomic_read_text(path).splitlines())
        except OSError:  # pragma: no cover
            return 0


_shared: dict[Path, TrajectoryStore] = {}
_shared_lock = threading.Lock()


def shared() -> TrajectoryStore:
    from .file_lock import ensure_private_directory
    from .paths import data_dir

    path = data_dir("trajectories.ndjson")
    with _shared_lock:
        store = _shared.get(path)
        if store is None:
            ensure_private_directory(path.parent)
            store = TrajectoryStore(path=path)
            _shared[path] = store
        return store


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()


def capture_step(step: TrajectoryStep, *, store: TrajectoryStore | None = None) -> bool:
    """Default-on capture entry point; returns False when explicitly disabled."""
    if not enabled():
        return False
    try:
        return (store or shared()).record(step)
    except Exception:  # pragma: no cover -- never block a run
        return False


def episode_dag_fields(step_index: int, is_final: bool,
                       verifier_confidence: float | None) -> dict:
    """Decision-DAG fields for a captured step.

    ``parent_step`` is the linear edge to the prior step (None at the root) -- a
    faithful chain for a single agent's episode (cross-agent branching is a later
    refinement). ``outcome`` is the episode's terminal task label, carried only on
    the final step: the verifier's confidence in the final answer, which is what
    ``promotion_effect`` / ``counterfactual_rollout`` read as the leaf reward.
    ``verifier_confidence`` mirrors it for the final step. The estimators are the
    consumers, so populating these makes the captured corpus DAG-complete.
    """
    vconf = None if verifier_confidence is None else float(verifier_confidence)
    return {
        "parent_step": (step_index - 1) if step_index else None,
        "verifier_confidence": vconf if is_final else None,
        "outcome": vconf if (is_final and vconf is not None) else None,
    }


def tools_by_goal(*, store: TrajectoryStore | None = None,
                  limit: int = 20_000) -> dict[int, list[str]]:
    """Distinct tools each captured run used, keyed by goal_id. Empty when
    capture is off (nothing recorded)."""
    return (store or shared()).tools_by_goal(limit=limit)


def tools_for_goal(goal_id: int, *, store: TrajectoryStore | None = None,
                   limit: int = 20_000) -> list[str]:
    """Distinct tools ONE captured run used, in first-seen order. Empty when
    capture is off or that goal called no tool. Cheaper than scanning every goal
    when only one is needed (a flow node grounding its own agent run)."""
    seen: list[str] = []
    for s in (store or shared()).iter_steps(goal_id=goal_id, limit=limit):
        tool = (s.tool or "").strip()
        if tool and tool not in seen:
            seen.append(tool)
    return seen


__all__ = [
    "TrajectoryStep", "TrajectoryStore",
    "enabled", "shared", "reset_shared", "capture_step", "episode_dag_fields",
    "tools_by_goal", "tools_for_goal",
]
