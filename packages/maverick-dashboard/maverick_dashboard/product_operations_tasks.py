"""Reviewed conversation operations backed by native task and review services."""
from __future__ import annotations

from dataclasses import replace
from functools import partial
from typing import Literal

from fastapi import BackgroundTasks, HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

TASK_PAGES = ("/chat/goal/*", "/goals/*")


class AnswerInput(StrictInput):
    question: str = Field(pattern=r"^[1-9][0-9]*$")
    answer: str = Field(min_length=1, max_length=12000)


class EditInput(StrictInput):
    text: str = Field(max_length=12000)


class ReviewInput(StrictInput):
    packet: str = Field(pattern=r"^PRP-[0-9a-f]{32}$")
    action: Literal["comment", "approve", "request_changes", "cancel"]
    note: str = Field(min_length=1, max_length=4000)


def _task(request, selection, *, write=False):
    from .app import _world

    auth.require_permission(request, "operate" if write else "view")
    identifier = selection.get("goal_id", selection.get("id"))
    if selection.get("kind") != "goal" or type(identifier) is not int or identifier < 1:
        raise HTTPException(404, "Open a task to use this action.")
    world = _world()
    goal = world.get_goal(identifier)
    if goal is None:
        raise HTTPException(404, "This task is unavailable.")
    auth.assert_goal_access(request, goal)
    if write and (auth.caller_principal(request) or "") != (goal.owner or ""):
        raise HTTPException(403, "Only the current task owner can change this work.")
    return world, goal


def task_snapshot(request, selection):
    from .answer_projection import projection

    world, goal = _task(request, selection)
    state = projection(request, world, goal.id)
    goal = state["goal"]
    return Snapshot(state["answer_version"], "Current saved task, result, artifacts and review state",
                    goal.title, {"title": goal.title, "status": goal.status,
                                 "result": state["goal"].result or "",
                                 "updated_at": state["goal"].updated_at,
                                 "artifacts": [{key: artifact.get(key) for key in ("id", "title", "kind", "version", "content")}
                                               for artifact in state["artifacts"]],
                                 "can_operate": state["can_operate"],
                                 "href": f"/chat/goal/{goal.id}"})


def current_status_snapshot(request, selection):
    from .answer_projection import projection, validate_current
    from .goal_waiting import open_question_ids
    from .plain_labels import datetime_text
    from .run_status import status_label

    world, selected = _task(request, selection)
    source = projection(request, world, selected.id)
    goal = source["goal"]
    questions = open_question_ids(world, goal)
    stop = None if questions else source["stop"]
    run_details = source["answer_run_details"]
    href = f"/chat/goal/{goal.id}"
    details = {"Task": goal.title,
               "Status": "Waiting for your answer" if questions else
                   status_label(goal.status, stop["kind"] if stop else None) or "Status unavailable",
               "Last updated": datetime_text(goal.updated_at) or "Date unavailable"}
    if questions:
        details.update({"Reason": "Lightwork is waiting for an answer before continuing.",
                        "Next action": {"label": "Read and answer the current question",
                                        "href": href + "#question-panel"}})
    elif stop:
        details.update({"Reason": stop["message"], "Next step": stop["action"]})
        if stop["link"] and (auth.has_permission(request, "admin") or
                             not stop["link"].startswith(("/settings", "/mcp"))):
            details["Next action"] = {"label": stop["link_label"], "href": stop["link"]}
    elif goal.status == "cancelled":
        details.update({"Reason": "The task was stopped. Earlier changes are not undone.",
                        "Next step": "Review saved progress and any changes already made before another attempt."})
    else:
        answer = source["chat_answer_text"]
        details["Saved answer"] = (answer if len(answer) <= 12000 else
            "The complete saved answer is too large for this panel. Open the task to read it in full.") or "No saved answer."
    artifacts = source["artifacts"]
    details["Saved output titles"] = ([row.get("title") or "Untitled output" for row in artifacts]
        if len(artifacts) <= 20 else
        f"{len(artifacts)} retained outputs. Open the task to review all names and complete contents.") or "No saved outputs."
    details["Complete answer and files"] = {"label": "Open the complete task and recovery controls", "href": href}
    details["Recorded run"] = ({"Runtime price": run_details["price_text"],
                                "Time": run_details["elapsed_text"], "Scope": run_details["scope"]}
                               if run_details else "No retained run figures match this saved answer.")
    validate_current(request, world, source, source["conversation_context"])
    if questions != open_question_ids(world, goal):
        raise HTTPException(409, "The task question changed. Check its current status again.")
    return Snapshot(digest({"answer": source["answer_version"], "run": run_details, "questions": questions}),
                    "Current saved task, result, artifacts and review state", goal.title, details)


def task_preview(request, selection, args):
    state = current_status_snapshot(request, selection)
    return Preview("Current saved task and recovery information. A saved answer does not prove external delivery. "
                   "Open the task for all retained attachments, complete output contents or a larger answer.", native=state.details)


def answer_snapshot(request, selection):
    from maverick.chat_threads import question_version

    world, goal = _task(request, selection, write=True)
    questions = [{"id": question.id, "question": question.question,
                  "version": question_version(question.id, question.asked_at, question.question)}
                 for question in world.open_questions(goal_id=goal.id)]
    details = {"goal_id": goal.id, "status": goal.status, "questions": questions}
    blocked = "There are no open questions for this task." if not questions else ""
    if goal.status in {"cancelled", "done", "completed", "failed", "error"}:
        blocked = "This task has stopped. Review its progress before restarting."
    return Snapshot(digest(details), "Current unanswered questions on your task",
                    "Answer one question. Use the conversation composer when your answer needs files.", details,
                    [{"name": "question", "label": "Question", "kind": "select", "required": True,
                      "choices": [{"value": str(row["id"]), "label": row["question"]} for row in questions]},
                     {"name": "answer", "label": "Your answer", "kind": "textarea", "required": True,
                      "max_length": 12000}], blocked)


def answer_preview(request, selection, args):
    from .draft_api import context_for

    state = answer_snapshot(request, selection)
    question = next((row for row in state.details["questions"] if str(row["id"]) == args["question"]), None)
    if question is None or not args["answer"].strip():
        raise HTTPException(409, "Choose a current question and enter your answer.")
    restarts = state.details["status"] == "blocked" and len(state.details["questions"]) == 1
    return Preview("Save this answer" + (" and resume the task under its current spending limits." if restarts else "."),
                   [{"label": "Question", "after": question["question"]},
                    {"label": "Answer", "after": args["answer"]},
                    {"label": "Attached files", "after": "None. Use the task composer to select evidence files."}],
                   {"question_id": question["id"], "expected_question": question["version"],
                    "expected_context": context_for(request)})


def _answer_outcome(result, *, background=None):
    message = "Your answer was received."
    if result["admitted"]:
        message += " A restart was admitted; check task progress for execution."
    return Outcome("replayed" if result["replayed"] else "queued" if result["admitted"] else "confirmed",
                   message, result, background=background)


def answer_execute(request, selection, args, native, operation_id):
    from . import api
    from .clarification_submission import submit_text

    world, goal = _task(request, selection, write=True)
    background = BackgroundTasks()
    result = submit_text(request, world, goal.id,
        question_id=native["question_id"], answer=args["answer"],
        expected_question=native["expected_question"], operation_id=operation_id,
        expected_context=native["expected_context"])
    if result["admitted"] and not result["replayed"]:
        api._dispatch_requeued_goal(request, background, goal.id, conversation_id=result["conversation_id"])
    return _answer_outcome(result, background=background)


def answer_recover(request, selection, args, native, operation_id):
    from .clarification_submission import receipt

    world, goal = _task(request, selection, write=True)
    result = receipt(request, world, goal.id, operation_id)
    return _answer_outcome(result) if result.get("received") else None


def edit_snapshot(request, selection):
    _world, goal = _task(request, selection, write=True)
    state = task_snapshot(request, selection)
    blocked = "Wait for the task to finish before editing its saved result." if goal.status != "done" else ""
    if len(goal.result or "") > 12000:
        blocked = "Use Edit in the conversation to revise this larger result. Copilot supports up to 12,000 characters."
    return replace(state, fields=[{"name": "text", "label": "Saved result", "kind": "textarea",
                                   "value": "" if len(goal.result or "") > 12000 else goal.result or "",
                                   "max_length": 12000}], blocked=blocked)


def edit_preview(request, selection, args):
    _world, goal = _task(request, selection, write=True)
    if goal.status != "done":
        raise HTTPException(409, "Wait for the task to finish before editing its saved result.")
    return Preview("Save your revised result as a new version and clear its previous sign-off. No training is completed by this save.",
                   [{"label": "Saved result", "before": goal.result or "", "after": args["text"]}],
                   {"expected_updated_at": float(goal.updated_at)})


def edit_execute(request, selection, args, native, operation_id):
    from .api import edit_deliverable
    from .api_schemas import DeliverableEditIn

    _world, goal = _task(request, selection, write=True)
    result = edit_deliverable(request, goal.id, DeliverableEditIn(
        text=args["text"], expected_updated_at=native["expected_updated_at"], operation_id=operation_id))
    return Outcome("replayed" if result.get("replayed") else "confirmed",
                   "Your revised result was saved. No training has completed.", result)


def edit_recover(request, selection, args, native, operation_id):
    from maverick.goal_mutations import _fingerprint, _receipt, _transaction

    world, goal = _task(request, selection, write=True)
    actor = auth.caller_principal(request) or "local administrator"
    fingerprint = _fingerprint({"text": args["text"], "expected_updated_at": native["expected_updated_at"]})
    with _transaction(world, goal.id) as (execute, _encode, decode, _pg, _tenant):
        result = _receipt(execute, decode, goal.id, "result", operation_id, actor, fingerprint)
    return edit_execute(request, selection, args, native, operation_id) if result is not None else None


def _reviews(request):
    from .project_reviews_api import _service

    auth.require_permission(request, "operate")
    return _service(request)


def _review_call(operation):
    from maverick.privacy_ops import RecordConflict
    from maverick.project_reviews import ProjectReviewDenied

    try:
        return operation()
    except ProjectReviewDenied as exc:
        raise HTTPException(404, "This review is unavailable to your current account.") from exc
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _review_choices(row, actor):
    result = [{"value": "comment", "label": "Add comment"}]
    if row["status"] == "pending":
        if row["owner"] == actor:
            result.append({"value": "cancel", "label": "Withdraw this review packet"})
        if row["reviewer"] == actor and not row["stale"]:
            result.extend([{"value": "approve", "label": "Accept this reviewed version"},
                           {"value": "request_changes", "label": "Request changes"}])
    return result


def review_snapshot(request, selection):
    service = _reviews(request)
    rows = _review_call(service.inbox)
    if len(rows) > 200:
        raise HTTPException(409, "Open the review page to narrow your review inventory before using this action.")
    choices = {row["id"]: _review_choices(row, service.principal) for row in rows}
    # Overdue display changes do not change the reviewed packet or its authority.
    versions = [{key: row.get(key) for key in ("id", "revision", "source_version", "status", "stale")}
                for row in rows]
    return Snapshot(digest(versions), "Current project review packets you may access",
                    "Review one fixed result version. Decisions do not change task ownership or deliver work externally.",
                    {"packets": rows},
                    [{"name": "packet", "label": "Review packet", "kind": "select", "required": True,
                      "choices": [{"value": row["id"], "label": row["title"] + " — " + row["status"].replace("_", " ")} for row in rows]},
                     {"name": "action", "label": "Response", "kind": "select", "required": True,
                      "depends_on": "packet", "choices_by": choices},
                     {"name": "note", "label": "Review comment", "kind": "textarea", "required": True,
                      "max_length": 4000}], "No review packets are available to your account." if not rows else "")


def review_preview(request, selection, args):
    service = _reviews(request)
    packet = _review_call(partial(service.get, args["packet"]))
    if not packet["can_respond"] or args["action"] not in {row["value"] for row in _review_choices(packet, service.principal)}:
        raise HTTPException(403, "This response is unavailable for the current review and your role.")
    return Preview("Record your response to this fixed review packet. This neither changes the live task nor publishes its result.",
                   [{"label": "Reviewed result", "after": packet["snapshot"]["result"]},
                    {"label": "Response", "after": args["action"].replace("_", " ")},
                    {"label": "Comment", "after": args["note"]}],
                   {"expected_revision": packet["revision"], "source_version": packet["source_version"]})


def review_execute(request, selection, args, native, operation_id):
    service = _reviews(request)
    result = _review_call(partial(service.respond, args["packet"], action=args["action"], note=args["note"],
                                  expected_revision=native["expected_revision"], source_version=native["source_version"],
                                  request_id=operation_id))
    return Outcome("confirmed", "Your review response was recorded. Task ownership and external delivery are unchanged.",
                   {"status": result["status"], "revision": result["revision"], "href": "/project-reviews"})


def review_recover(request, selection, args, native, operation_id):
    service = _reviews(request)
    _review_call(partial(service.get, args["packet"]))
    record = service.packets.get(args["packet"])
    if operation_id not in record.get("operations", {}):
        return None
    return replace(review_execute(request, selection, args, native, operation_id), status="replayed")


def entries():
    from .product_operations_bundles import entries as bundle_entries
    from .product_operations_handoffs import entries as handoff_entries
    from .product_operations_resume import entries as resume_entries

    return (
        Adapter("tasks.current_status", "Read this task's status and saved result", "tasks", "/chat", TASK_PAGES,
                EmptyInput, current_status_snapshot, task_preview),
        Adapter("clarifications.answer", "Answer a task question", "clarifications", "/chat", TASK_PAGES,
                AnswerInput, answer_snapshot, answer_preview, answer_execute, answer_recover, read_recovery=answer_recover),
        Adapter("artifacts.edit_saved_result", "Revise the saved result", "artifacts", "/chat", TASK_PAGES,
                EditInput, edit_snapshot, edit_preview, edit_execute, edit_recover),
        Adapter("reviews.respond", "Respond to a project review", "reviews", "/project-reviews",
                ("/project-reviews", "/projects", "/projects/*"),
                ReviewInput, review_snapshot, review_preview, review_execute, review_recover),
    ) + bundle_entries() + handoff_entries() + resume_entries()
