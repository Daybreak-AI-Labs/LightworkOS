"""Revalidated view projection shared by initial and live conversation answers."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict

from fastapi import HTTPException
from maverick.governed_operations import digest

from .auth import assert_goal_access, caller_principal, has_permission, require_permission
from .draft_api import context_for
from .product_errors import product_error

# While a task is queued or working, the runner keeps rewriting these columns
# (admission flips pending to active, every write advances updated_at). They
# are progress, not the answer or who may see it, so they do not make an open
# page stale. A finished, stopped or failed task compares its whole row.
_RUN_PROGRESS_FIELDS = ("status", "updated_at")
_RUN_OPEN = frozenset({"draft", "pending", "active", "running", "in_progress"})
# A page built while a real change lands is rebuilt; it waits this long
# before each new attempt and gives up (409, retryable) after the last.
SETTLE_ATTEMPTS = 3
SETTLE_PAUSE_SECONDS = 0.2


def _answer_row(goal) -> dict:
    row = asdict(goal)
    if goal.status in _RUN_OPEN:
        for field in _RUN_PROGRESS_FIELDS:
            row.pop(field, None)
    return row


def version_for(goal, contract, signoff, artifacts, handoff_closed=None):
    source = {"goal": _answer_row(goal), "contract": contract, "signoff": signoff, "artifacts": artifacts}
    version = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":"),
                                       default=str).encode()).hexdigest()
    return hashlib.sha256((version + json.dumps(handoff_closed, sort_keys=True)).encode()).hexdigest()


def _policy_removed(goal) -> bool:
    """The task's specialist (and so its result policy) no longer exists.

    The task still opens, read as an ungated result exactly as the page reads
    it, while every export stays withheld (``_chat_answer_download_state``
    fails closed on the missing policy). A catalogue that cannot be read is
    not "removed": it raises and the page is withheld (503) as before.
    """
    if not goal.domain:
        return False
    from maverick.domain import available_domains

    return available_domains().get(goal.domain) is None


def _snapshot(world, goal):
    from .app import _goal_artifacts, _goal_deliverable

    contract, rendered = ((None, None) if goal.status in ("blocked", "failed") or _policy_removed(goal)
                          else _goal_deliverable(goal, strict=True))
    signoff = world.signoff_for(goal.id) if contract and contract.get("gate") else None
    artifacts = _goal_artifacts(world, goal.id, strict=True)
    from maverick.task_handoffs import closure
    closed = closure(world, goal.id)
    version = version_for(goal, contract, signoff, artifacts, closed)
    return {"goal": goal, "deliverable": contract, "rendered": rendered,
            "signoff": signoff, "artifacts": artifacts, "answer_version": version, "handoff_closed": closed}


def validate_current(request, world, context, expected_context):
    """Withhold a page when an edit or access change overtakes its reads."""
    require_permission(request, "view")
    fresh = world.get_goal(context["goal"].id)
    if fresh is None:
        raise product_error(404, "task_unavailable", "This task is no longer available.")
    assert_goal_access(request, fresh)
    try:
        latest = _snapshot(world, fresh)
    except (LookupError, ValueError, TypeError) as exc:
        raise product_error(503, "result_unavailable", "The saved result and its release requirements could not be loaded. Retry to confirm the current version.", retryable=True) from exc
    require_permission(request, "view")
    assert_goal_access(request, fresh)
    again = world.get_goal(fresh.id)
    if again is None:
        raise product_error(404, "task_unavailable", "This task is no longer available.")
    assert_goal_access(request, again)
    if (context["answer_version"] != latest["answer_version"]
            or _answer_row(again) != _answer_row(fresh)
            or expected_context != context_for(request)):
        raise product_error(409, "result_changing", "The saved result or your access changed. Refresh it again in a moment.", retryable=True)


def _still_changing(exc: HTTPException) -> bool:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    return exc.status_code == 409 and detail.get("code") == "result_changing"


def settled(build):
    """Build a task page again when a change overtook it, a few times.

    Only the read is repeated: nothing here writes, so a retry can never start
    or change work. Access is checked again on every attempt by ``build``.
    """
    for attempt in range(1, SETTLE_ATTEMPTS + 1):
        try:
            return build()
        except HTTPException as exc:
            if attempt == SETTLE_ATTEMPTS or not _still_changing(exc):
                raise
        time.sleep(SETTLE_PAUSE_SECONDS * attempt)
    raise AssertionError("unreachable")  # pragma: no cover


def projection(request, world, goal_id: int) -> dict:
    from maverick.attachment_submissions import SubmissionStore

    from .answer_run_details import read as read_run_details
    from .app import _chat_answer_download_state, _chat_answer_text, _voice_only_mode

    require_permission(request, "view")
    original_context = context_for(request)
    goal = world.get_goal(goal_id)
    if goal is None:
        raise product_error(404, "task_unavailable", "This task is no longer available.")
    assert_goal_access(request, goal)
    try:
        context = _snapshot(world, goal)
        fresh = world.get_goal(goal_id)
        if fresh is None:
            raise product_error(404, "task_unavailable", "This task is no longer available.")
        assert_goal_access(request, fresh)
        latest = _snapshot(world, fresh)
        if context["answer_version"] != latest["answer_version"]:
            raise product_error(409, "result_changing", "The saved result is still changing. Refresh it again in a moment.", retryable=True)
        context["submission"] = SubmissionStore(world).for_goal(goal_id)
        context["answer_run_details"] = read_run_details(request, world, goal_id, expected_goal=fresh)
        context["answer_run_details_version"] = digest(context["answer_run_details"])
    except (LookupError, ValueError, TypeError) as exc:
        raise product_error(503, "result_unavailable", "The saved result and its release requirements could not be loaded. Retry to confirm the current version.", retryable=True) from exc
    can_download, download_note = _chat_answer_download_state(world, fresh)
    from maverick.stop_reasons import stop_payload

    from .answer_checks import answer_facts
    from .app import _withheld_event_markers

    stop = stop_payload(fresh.status, fresh.result)
    # Exceptional content grants never become permission to mutate the task.
    context.update(can_operate=not context["handoff_closed"] and has_permission(request, "operate") and
                   (caller_principal(request) or "") == (fresh.owner or ""),
                   conversation_context=context_for(request), voice_only=_voice_only_mode(),
                   stop=stop,
                   can_download_chat_answer=can_download, chat_answer_download_note=download_note,
                   chat_answer_text=_chat_answer_text(fresh),
                   **answer_facts(world, fresh, frozenset(_withheld_event_markers()), request=request))
    validate_current(request, world, context, original_context)
    return context
