"""Gradual rollout of a changed specialist: a trial version beside the current one.

With ``[agent_tests] canary_percent`` above 0, publishing changed instructions for
an existing specialist makes them a trial candidate instead of replacing the
current version. A new goal for that specialist runs the candidate for that share
of goals, chosen from the goal id, and the current version for the rest. Each goal
that starts during a trial records the version it used. Goals already running, and
resumed goals with no recorded version, keep the current version.

A trial ends by promotion (the candidate becomes current), by a roll back (the
candidate is discarded), or automatically when ``canary_auto_rollback`` is on and
the trial fails clearly more often. That check runs when a new goal starts.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from fractions import Fraction

from . import agent_tests_policy
from .governed_records import GovernedRecordCapacityError, GovernedRecordStore

log = logging.getLogger(__name__)

CURRENT, CANDIDATE = "current", "candidate"
PROMOTED, ROLLED_BACK, ROLLED_BACK_AUTOMATICALLY = "promoted", "rolled_back", "rolled_back_automatically"
MIN_FINISHED_GOALS = 10
MAX_FAILURE_GAP = Fraction(1, 5)  # 20 percentage points
MAX_ROWS = 10_000
AUTO_CHECK_SECONDS = 60  # the automatic check reads every trial goal, so it runs at most this often
SYSTEM_ACTOR = "system:canary"

# One record per specialist (its live trial, if any) and one per goal that ran
# during a trial (the version it used). Both are tenant-scoped governed records.
TRIALS = GovernedRecordStore("specialist-canaries", "SPC", "specialist_canary", archive_when_full=False)
TRIAL_GOALS = GovernedRecordStore("specialist-canary-goals", "SCG", "specialist_canary_goal", archive_when_full=False)


_LAST_AUTO_CHECK: dict[str, tuple[str, float]] = {}  # specialist -> (candidate id, when it was last checked)


def _now() -> float:
    return time.monotonic()


class TrialAlreadyLive(ValueError):
    """A specialist already has a trial version; a second change waits for it."""


class TrialChanged(ValueError):
    """The trial a decision was reviewed for is no longer the live one."""


def _digest(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()[:32]


def _trial_id(name: str) -> str:
    return "SPC-" + _digest("trial", name)


def _goal_record_id(name: str, goal_id: int) -> str:
    return "SCG-" + _digest("goal", name, goal_id)


def bucket(name: str, goal_id: int) -> int:
    """A stable position from 0 to 99, so a goal always lands in the same version."""
    return int(_digest("bucket", name, goal_id)[:8], 16) % 100


def live(name: str) -> dict | None:
    """The live trial for ``name``: its candidate id, share, patch and profile. ``None`` when there is none."""
    row = TRIALS.get(_trial_id(name))
    return row.get("live") if row else None


def start(name: str, *, patch: dict, profile: dict, percent: int, actor: str, title: str = "",
          reason: str = "", effect_guard=None) -> dict:
    """Make ``patch`` a trial for ``name`` on ``percent`` of new goals. Callers hold the specialist's lock."""
    if not 1 <= percent <= agent_tests_policy.MAX_CANARY_PERCENT:
        raise ValueError("A trial share must be a whole number from 1 to 50.")
    trial = {"candidate_id": secrets.token_hex(16), "percent": percent, "patch": patch, "profile": profile,
             "started_at": time.time(), "title": title, "reason": reason, "actor": actor}
    row = TRIALS.get(_trial_id(name))
    if row is None:
        TRIALS.create({"id": _trial_id(name), "name": name, "live": trial, "last": None},
                      action="specialist_canary.started", actor=actor, effect_guard=effect_guard)
    elif row.get("live") is not None:
        raise TrialAlreadyLive("A trial version of this specialist is already live.")
    else:
        TRIALS.update(row["id"], lambda current: current.update(live=trial), expected_revision=row["revision"],
                      action="specialist_canary.started", actor=actor, effect_guard=effect_guard)
    return trial


def finish(name: str, *, candidate_id: str, outcome: str, actor: str, effect_guard=None) -> dict:
    """End the live trial as ``outcome`` (promoted or rolled back). Raises when it is no longer live."""
    row = TRIALS.get(_trial_id(name))
    trial = row.get("live") if row else None
    if not trial or trial["candidate_id"] != candidate_id:
        raise TrialChanged("The trial version changed. Review it again.")
    last = {"candidate_id": candidate_id, "outcome": outcome, "at": time.time(), "actor": actor}
    TRIALS.update(row["id"], lambda current: current.update(live=None, last=last), expected_revision=row["revision"],
                  action=f"specialist_canary.{outcome}", actor=actor, effect_guard=effect_guard)
    return trial


def _tally() -> dict:
    return {"goals": 0, "done": 0, "failed": 0, "other": 0, "thumbs_up": 0, "thumbs_down": 0}


def version_stats(name: str, world, *, candidate_id: str) -> dict[str, dict]:
    """Per version of one trial: goals started, finished (done or failed), failed and feedback counts."""
    from maverick import result_feedback_receipts

    rows = [row for row in TRIAL_GOALS.list(limit=MAX_ROWS + 1)
            if row.get("name") == name and row.get("candidate_id") == candidate_id]
    if len(rows) > MAX_ROWS:
        raise RuntimeError("The trial history exceeds its supported limit.")
    goals = world.get_goals([row["goal_id"] for row in rows]) if rows else {}
    feedback, truncated = result_feedback_receipts.summary_scan(world)
    ratings = {row["goal_id"]: row["rating"] for row in feedback}
    stats = {CURRENT: _tally(), CANDIDATE: _tally()}
    for row in rows:
        tally = stats[row["version"]]
        goal = goals.get(row["goal_id"])
        status = goal.status if goal is not None else ""
        tally["goals"] += 1
        tally["done" if status == "done" else "failed" if status == "failed" else "other"] += 1
        rating = ratings.get(row["goal_id"])
        if rating in {"up", "down"}:
            tally["thumbs_up" if rating == "up" else "thumbs_down"] += 1
    for tally in stats.values():
        # The feedback read is bounded; when it reached its limit the thumbs counts can be too low.
        tally["feedback_complete"] = not truncated
    return stats


def _failure_share(tally: dict) -> Fraction | None:
    finished = tally["done"] + tally["failed"]
    return Fraction(tally["failed"], finished) if finished else None


def auto_rollback_due(name: str, world, trial: dict) -> bool:
    """Whether the trial has enough finished goals and fails clearly more than the current version."""
    stats = version_stats(name, world, candidate_id=trial["candidate_id"])
    candidate, current = stats[CANDIDATE], stats[CURRENT]
    if candidate["done"] + candidate["failed"] < MIN_FINISHED_GOALS:
        return False
    candidate_share, current_share = _failure_share(candidate), _failure_share(current)
    if candidate_share is None or current_share is None:
        return False
    return candidate_share - current_share > MAX_FAILURE_GAP


def _auto_check_due(name: str, trial: dict) -> bool:
    """Whether the automatic check may run now; it is throttled per specialist and trial."""
    now = _now()
    last = _LAST_AUTO_CHECK.get(name)
    if last is not None and last[0] == trial["candidate_id"] and now - last[1] < AUTO_CHECK_SECONDS:
        return False
    _LAST_AUTO_CHECK[name] = (trial["candidate_id"], now)
    return True


def version_for_goal(name: str, goal_id: int, *, world=None, resume: bool = False) -> tuple[str, dict | None]:
    """The version a goal runs with: ``(CANDIDATE, trial)`` or ``(CURRENT, None)``.

    With no live trial nothing is recorded. During a trial the choice is recorded
    once per goal, so the goal keeps it on later checks. A goal that is resumed
    with no recorded choice keeps the current version. If the record cannot be
    written, the current version is used.
    """
    trial = live(name)
    if trial is None:
        return CURRENT, None
    if (world is not None and agent_tests_policy.canary_auto_rollback() and _auto_check_due(name, trial)
            and auto_rollback_due(name, world, trial)):
        from maverick.audit import EventKind, audit_event

        finish(name, candidate_id=trial["candidate_id"], outcome=ROLLED_BACK_AUTOMATICALLY, actor=SYSTEM_ACTOR)
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="system", verb="agent_trial_rolled_back_automatically",
                    actor=SYSTEM_ACTOR, specialist=name, goal_id=goal_id)
        return CURRENT, None
    record_id = _goal_record_id(name, goal_id)
    row = TRIAL_GOALS.get(record_id)
    if row is None:
        if resume:
            return CURRENT, None
        version = CANDIDATE if bucket(name, goal_id) < trial["percent"] else CURRENT
        try:
            row = _record_goal_choice({"id": record_id, "name": name, "goal_id": goal_id,
                                       "candidate_id": trial["candidate_id"], "version": version,
                                       "assigned_at": time.time()}, world)
        except Exception:  # the record is the only proof a goal may use the trial
            row = TRIAL_GOALS.get(record_id)
            if row is None:
                log.warning("specialist trial choice for goal #%s could not be recorded; the current version is used", goal_id)
                return CURRENT, None
    if row["version"] == CANDIDATE and row["candidate_id"] == trial["candidate_id"]:
        return CANDIDATE, trial
    return CURRENT, None


_FINISHED_GOAL_STATUSES = frozenset({"done", "completed", "failed", "cancelled", "error"})
_PRUNE_RETRY_AFTER = 0.0  # monotonic time before which a full store is not listed again


def _prune_finished_trial_goals(world) -> int:
    """Delete goal records of ended trials whose goals have finished; returns how many.

    Only the live trial's records feed its statistics, and a goal keeps its
    recorded choice while it can still run, so only records of an ended trial
    whose goal is finished (or gone) are removed. Without the world model a
    goal's state is unknown and nothing is removed.
    """
    global _PRUNE_RETRY_AFTER
    if world is None or _now() < _PRUNE_RETRY_AFTER:
        return 0
    rows = TRIAL_GOALS.list(limit=MAX_ROWS)
    live_ids: dict[str, str | None] = {}
    ended = []
    for row in rows:
        name = row.get("name")
        if name not in live_ids:
            trial = live(name)
            live_ids[name] = trial["candidate_id"] if trial else None
        if row.get("candidate_id") != live_ids[name] and not row.get("_audit_pending"):
            ended.append(row)
    goals = world.get_goals([row["goal_id"] for row in ended]) if ended else {}
    dead = [row for row in ended
            if row["goal_id"] not in goals
            or getattr(goals[row["goal_id"]], "status", "") in _FINISHED_GOAL_STATUSES]
    if not dead:
        # The store stays full for a while; do not list it on every goal start.
        _PRUNE_RETRY_AFTER = _now() + AUTO_CHECK_SECONDS
        return 0
    from maverick.audit import EventKind, audit_event

    audit_event(EventKind.CONTROL_PLANE_ACTION, agent="system", verb="agent_trial_goal_records_pruned",
                actor=SYSTEM_ACTOR, records=len(dead))
    return sum(1 for row in dead if TRIAL_GOALS.delete(row["id"], expected_revision=row["revision"]))


def _record_goal_choice(record: dict, world) -> dict:
    def create() -> dict:
        return TRIAL_GOALS.create(record, action="specialist_canary.goal_assigned", actor=SYSTEM_ACTOR,
                                  max_records=MAX_ROWS)

    try:
        return create()
    except GovernedRecordCapacityError:
        if not _prune_finished_trial_goals(world):
            raise
        return create()


def profile_for_goal(name: str, profile, goal_id: int, *, world=None, resume: bool = False):
    """``(profile, version)`` for a goal of ``name``. ``profile`` is the current definition."""
    try:
        version, trial = version_for_goal(name, goal_id, world=world, resume=resume)
        if trial is None:
            return profile, CURRENT
        from .domain import _coerce

        return _coerce(name, trial["profile"]), CANDIDATE
    except Exception:
        log.warning("specialist trial version could not be read for goal #%s; the current version is used", goal_id)
        return profile, CURRENT


__all__ = ["CANDIDATE", "CURRENT", "MIN_FINISHED_GOALS", "PROMOTED", "ROLLED_BACK", "ROLLED_BACK_AUTOMATICALLY",
           "TrialAlreadyLive", "TrialChanged", "auto_rollback_due", "finish", "live", "profile_for_goal", "start",
           "version_for_goal", "version_stats"]
