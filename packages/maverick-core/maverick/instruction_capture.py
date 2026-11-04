"""Explicit, owner-bound capture of one successful model instruction dispatch.

Captures are historical local records, never a claim of current deployment or
improvement. User messages, answers and tool results are not retained here.
"""
from __future__ import annotations

import hashlib
import logging
import time
from contextlib import contextmanager
from contextvars import ContextVar

from .governed_records import GovernedRecordStore
from .memory_ownership import current_owner, source_allowed
from .paths import current_tenant_id_strict, data_dir

log = logging.getLogger(__name__)
_RUNTIME = ContextVar("instruction_capture_runtime", default=None)
LIMIT = 128 * 1024
_MAX_RECORDS = 512


def records():
    return GovernedRecordStore("instruction-captures", "ISC", "instruction_capture", required_backend="local")


def enabled():
    from .config import load_global_config
    return load_global_config().get("instruction_capture", {}).get("enable") is True


def _hint(goal_id):
    # Absence is a read-only fast path. Presence never grants capture authority:
    # the current governed record and original sources are checked afterwards.
    return data_dir("instruction-capture-hints", "goal-" + str(goal_id))


def _hint_value(goal_id):
    from .file_lock import atomic_read_text
    path = _hint(goal_id)
    if not path.is_file() or path.stat().st_size > 128:
        return ""
    return atomic_read_text(path, encoding="utf-8")


def result_pending(row):
    return row["state"] == "waiting" and _hint_value(row["goal_id"]) == "consumed:" + row["id"]


def pointer(goal_id):
    return "ISC-goal-" + str(goal_id)


def authorize(world, goal_id, owner, operation):
    from .file_lock import cross_process_lock, prepare_private_directory
    hint = _hint(goal_id)
    prepare_private_directory(hint.parent)
    with cross_process_lock(hint, strict=True):
        return _authorize(world, goal_id, owner, operation)


def _authorize(world, goal_id, owner, operation):
    """Record one exact reviewed capture request; repeating its ID is readback."""
    from .learning_guard import check_learning_halt
    check_learning_halt("instruction_capture", "authorize")
    if not enabled():
        raise ValueError("Turn on instruction recording on this page before requesting a capture.")
    if not current_tenant_id_strict() or not owner.startswith("user:") or not source_allowed(goal_id, owner, world=world):
        raise ValueError("This task is not available for instruction capture under your current account.")
    store = records()
    identity = "ISC-" + operation
    existing = store.get(identity)
    if existing:
        if existing.get("goal_id") != goal_id or existing.get("owner") != owner:
            raise ValueError("This reviewed request belongs to a different task or person.")
        if existing["state"] in {"prepared", "waiting"} and existing["expires_at"] <= time.time():
            raise ValueError("This capture request expired. Authorize a new request instead.")
    selected = store.get(pointer(goal_id))
    if selected:
        previous = store.get(selected["capture"])
        if previous and previous["id"] != identity and previous["state"] == "waiting" and previous["expires_at"] > time.time():
            raise ValueError("This task already has a waiting capture request. Review or withdraw it first.")
    if existing and existing["state"] in {"captured", "withdrawn", "withheld"}:
        return existing
    if existing and existing["state"] == "waiting" and selected and selected["capture"] == identity:
        # Replaying consent never rearms a call that has already returned.
        return existing
    goal = world.get_goal(goal_id)
    row = existing or store.create({"id": identity, "owner": owner, "goal_id": goal_id,
        "title": goal.title, "state": "prepared", "expires_at": time.time() + 86400,
        "instructions": "", "source_bindings": [], "captured_at": None,
        "role": "", "model": "", "instruction_sha256": ""},
        action="instructions.capture.authorize", actor=owner, max_records=_MAX_RECORDS)
    if selected and selected["capture"] != identity:
        store.update(selected["id"], lambda value: value.update(capture=identity),
                     expected_revision=selected["revision"], action="instructions.capture.select", actor=owner)
    elif not selected:
        store.create({"id": pointer(goal_id), "capture": identity},
                     action="instructions.capture.select", actor=owner, max_records=_MAX_RECORDS)
    from .file_lock import atomic_write_text, prepare_private_directory
    hint = _hint(goal_id)
    prepare_private_directory(hint.parent)
    atomic_write_text(hint, "armed:" + identity)
    if row["state"] == "prepared":
        row = store.update(row["id"], lambda value: value.update(state="waiting"), expected_revision=row["revision"],
                           action="instructions.capture.ready", actor=owner)
    return row


def _source_bindings(world, goal_id, sources, capture_owner):
    result = []
    for identity in sorted({goal_id, *sources}):
        if type(identity) is not int or identity < 0:
            raise ValueError("An original learning source is no longer available.")
        owner = current_owner(world=world, goal_id=identity)
        if (owner not in {capture_owner, ""} or identity == goal_id and owner != capture_owner
                or not source_allowed(identity, owner, world=world)):
            raise ValueError("An original learning source is no longer available.")
        result.append({"goal": identity, "owner": owner})
    return result


@contextmanager
def runtime_scope(world, goal_id, role, sources=(), *, verified=True, preferences_owner=""):
    """Native Agent calls alone supply runtime context, never browser payloads."""
    runtime = None
    armed = ""
    try:
        if world and type(goal_id) is int and goal_id > 0 and current_tenant_id_strict() and enabled():
            armed = _hint_value(goal_id)
        if armed.startswith("armed:"):
            store = records()
            selected = store.get(pointer(goal_id))
            row = store.get(selected["capture"]) if selected else None
            if row and row["state"] == "waiting" and row["expires_at"] > time.time() and _hint_value(goal_id) == "armed:" + row["id"]:
                reason = "" if verified else "The exact original learning sources could not be checked."
                if preferences_owner and preferences_owner != row["owner"]:
                    reason = "The completed call includes response preferences belonging to another account."
                try:
                    bindings = _source_bindings(world, goal_id, sources, row["owner"])
                except Exception:
                    bindings = []
                    reason = "The instructions include an original source unavailable to this account."
                runtime = (world, str(role), row, bindings, reason)
    except Exception:
        if armed.startswith("armed:ISC-") and len(armed) == 42:
            # The hint never grants text retention. If authority is unreadable,
            # consume the returned call and offer metadata-only recovery later.
            runtime = (world, str(role), {"id": armed[6:], "goal_id": goal_id, "revision": None}, [],
                       "The capture request could not be checked before this call.")
        log.debug("Optional instruction capture context unavailable", exc_info=True)
    token = _RUNTIME.set(runtime)
    try:
        yield
    finally:
        _RUNTIME.reset(token)


def record_dispatch(model, instructions):
    """Called after a native provider adapter returns, using its actual arguments.

    Exact post-egress-minimization bytes are retained, or none. A secret-bearing
    or oversized prompt is withheld rather than redacted into false provenance.
    """
    runtime = _RUNTIME.get()
    if runtime is None:
        return False
    try:
        from .learning_guard import learning_write_allowed
        from .safety.secret_detector import redact
        world, role, reviewed, bindings, reason = runtime
        from .file_lock import atomic_write_text, cross_process_lock
        with cross_process_lock(_hint(reviewed["goal_id"]), strict=True):
            if _hint_value(reviewed["goal_id"]) != "armed:" + reviewed["id"]:
                return False
            # A returned call consumes the request before optional persistence.
            # A failed receipt cannot cause a later, different call to be kept.
            atomic_write_text(_hint(reviewed["goal_id"]), "consumed:" + reviewed["id"])
        if not learning_write_allowed("instruction_capture"):
            reason = "Learning was stopped before this call completed."
        if not enabled():
            reason = "Instruction recording was turned off before this call completed."
        elif not isinstance(instructions, str) or not instructions.strip():
            reason = "The completed call had no instruction text available to record."
        elif len(instructions.encode("utf-8")) > LIMIT:
            reason = "The instruction text exceeds the recording limit."
        else:
            try:
                _safe, secrets = redact(instructions)
                if secrets or "\x00" in instructions:
                    reason = "The instruction text contains detectable secrets or unsupported characters."
            except Exception:
                reason = "The instruction text could not pass its required privacy check."
        store = records()
        current = store.get(reviewed["id"])
        if (current is None or current["state"] != "waiting" or current["revision"] != reviewed["revision"]
                or current["expires_at"] <= time.time()):
            return False
        if not source_allowed(current["goal_id"], current["owner"], world=world) or any(
            binding["owner"] not in {current["owner"], ""} or not source_allowed(binding["goal"], binding["owner"], world=world) for binding in bindings):
            reason = "Original source permission changed before this call completed."
        def save(value):
            value.update(state="withheld" if reason else "captured", reason=reason, instructions="" if reason else instructions, model=str(model), role=role,
                         source_bindings=bindings, captured_at=time.time(),
                         instruction_sha256="" if reason else hashlib.sha256(instructions.encode("utf-8")).hexdigest())
        store.update(current["id"], save, expected_revision=current["revision"],
                     action="instructions.capture.withheld" if reason else "instructions.capture.completed", actor=current["owner"])
        try:
            from .file_lock import cross_process_lock
            with cross_process_lock(_hint(current["goal_id"]), strict=True):
                selected = store.get(pointer(current["goal_id"]))
                if selected and selected["capture"] == current["id"]:
                    _hint(current["goal_id"]).unlink(missing_ok=True)
        except Exception:
            pass
        return True
    except Exception:
        log.debug("Optional instruction capture withheld", exc_info=True)
        return False


def resolve(identity, owner, revision):
    store = records()
    row = store.get(identity)
    if not row or row.get("owner") != owner or row["revision"] != revision or not result_pending(row):
        raise ValueError("The completed capture changed. Refresh and review its current result.")
    return store.update(identity, lambda value: value.update(state="withheld", instructions="",
        reason="The call completed, but its instruction receipt could not be confirmed. No instruction text is available and no call was repeated."),
        expected_revision=revision, action="instructions.capture.resolve", actor=owner)


def visible(world, identity, owner):
    row = records().get(identity)
    if row is None or row.get("owner") != owner:
        raise ValueError("This instruction record is unavailable to your account.")
    if row["state"] in {"withdrawn", "withheld"}:
        return row
    if not source_allowed(row["goal_id"], owner, world=world):
        raise ValueError("Its original task is unavailable or no longer permits local learning.")
    if any(binding["owner"] not in {owner, ""} or not source_allowed(binding["goal"], binding["owner"], world=world) for binding in row["source_bindings"]):
        raise ValueError("An original learning source no longer permits use of these instructions.")
    return row


def withdraw(identity, owner, revision):
    store = records()
    row = store.get(identity)
    if row is None or row.get("owner") != owner:
        raise ValueError("This instruction record is unavailable to your account.")
    if row["state"] == "withdrawn":
        return row
    return store.update(identity, lambda value: value.update(state="withdrawn", instructions=""),
                        expected_revision=revision, action="instructions.capture.withdraw", actor=owner)
