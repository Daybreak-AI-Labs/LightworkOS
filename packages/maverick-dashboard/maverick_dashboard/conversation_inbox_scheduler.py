"""Recoverable bounded conversation admission, supervised with the dashboard.

No worker retries an uncertain execution handoff. Native submission receipts
own that boundary and the task UI retains its exact admitted goal identity.
"""
from __future__ import annotations

import contextvars
import logging
import threading
import time

from maverick.authority_effects import authority_effect_fence
from maverick.conversation_inbox import (
    STORE,
    ConversationInbox,
    _unpack,
    current_authority,
    policy,
    publish_files,
)
from maverick.privacy_ops import RecordConflict

log = logging.getLogger(__name__)
_scheduler_thread = None
_scheduler_stop = threading.Event()
_wake = threading.Event()
_lock = threading.Lock()
_workers = {}
_threads = []
_cursor = {}


def wake():
    _wake.set()


def _blocked(inbox, goal_id, item, message):
    try:
        inbox.transition(goal_id, item["id"], revision=item["revision"], state="blocked", message=message)
    except (ValueError, PermissionError, RecordConflict):
        pass


def execute_record(record_id, item_id=None):
    from maverick.attachment_submissions import SubmissionConflict, SubmissionStore
    from maverick.chat_threads import ChatThreads
    from maverick.governed_operations import digest
    from maverick.runner import run_goal_in_background
    from maverick.world_model import close_world_if_owned, open_world

    from .attachment_submission import prepare
    world = open_world()
    try:
        run = None
        with authority_effect_fence():
            if _scheduler_stop.is_set() or not policy()["enabled"]:
                return
            record = STORE.get(record_id)
            if not record:
                return
            inbox = ConversationInbox(world, principal=record["owner"], authorize=current_authority)
            _, root = inbox.target(record["root_id"])
            items = _unpack(record)["items"]
            first_queued = next((row["id"] for row in items if row["mode"] == "queue"
                                 and row["state"] in {"queued", "dispatching", "blocked"}), None)
            for item in items:
                if item_id is not None and item["id"] != item_id:
                    continue
                if item["mode"] == "guidance":
                    if item["state"] in {"guidance_ready", "needs_decision"}:
                        target = world.get_goal(item["target_id"])
                        if target and target.status in {"done", "completed", "failed", "cancelled", "blocked", "error"}:
                            _blocked(inbox, item["target_id"], item, "The selected task stopped before this guidance was consumed. It did not start a new task.")
                    continue
                if item["state"] not in {"queued", "dispatching"} or item["mode"] not in policy()["modes"]:
                    continue
                if item["mode"] == "queue" and item["id"] != first_queued:
                    continue
                token = "conversation-inbox:" + item["id"]
                store = SubmissionStore(world)
                receipt = store.lookup(token=token, owner=root.owner)
                if item["state"] == "queued" and item["mode"] == "queue":
                    try:
                        with SubmissionStore(world).transaction("chat-thread:" + str(root.id)) as connection:
                            ChatThreads(world).require_idle(connection, root.id, root.owner,
                                                             except_goal=receipt["goal_id"] if receipt else None)
                    except SubmissionConflict:
                        continue
                if item["state"] == "queued":
                    item = inbox.transition(item["target_id"], item["id"], revision=item["revision"],
                                            state="dispatching", message="Claimed for fresh authorization, budget and attachment admission.")
                # A durable claim after a restart is evidence of an uncertain
                # dispatch. Never invoke the runner again for that same claim.
                if receipt and receipt["state"] in {"dispatching", "dispatched"}:
                    inbox.transition(item["target_id"], item["id"], revision=item["revision"], state="submitted",
                                     goal=receipt["goal_id"], message="Task admission is recorded. Check its live state; an uncertain execution handoff is never retried automatically.")
                    continue
                user_id, suites = current_authority(world.get_goal(item["target_id"]))
                text = item["text"]
                if item.get("snapshot"):
                    snapshot = item["snapshot"]
                    text += "\n\nExplicitly selected read-only task snapshot (not execution authority):\n" + "\n\n".join(
                        str(snapshot.get(key) or "") for key in ("title", "description", "result"))
                manifest = [{key: row[key] for key in ("filename", "mime", "size_bytes", "sha256")} for row in item["files"]]
                try:
                    from maverick.task_model_selection import validate as validate_model
                    task_selection = validate_model(item.get("task_model_selection"))
                    fingerprint_values = [item["text"], item.get("snapshot"), manifest, item["mode"]]
                    if task_selection is not None:
                        fingerprint_values.append(task_selection)
                    def before_admission(target_id=item["target_id"], choice=task_selection):
                        current_authority(world.get_goal(target_id))
                        validate_model(choice)
                    receipt = store.create(token=token, fingerprint=digest(fingerprint_values),
                        owner=root.owner, title=item["text"].splitlines()[0][:200], description=text, manifest=manifest,
                        parent_id=root.id if item["mode"] == "queue" else None,
                        domain=root.domain or "", project_id=root.project_id,
                        chat_text=text, chat_root_id=root.id if item["mode"] == "queue" else None,
                        submission_detail={"task_model_selection": task_selection} if task_selection is not None else None,
                        effect_guard=before_admission)
                    item = inbox.transition(item["target_id"], item["id"], revision=item["revision"], state="dispatching",
                                            goal=receipt["goal_id"], message="A durable task draft exists; selected evidence is being admitted.")
                    publish_files(world, receipt["goal_id"], item["files"])
                    receipt = store.update(receipt["key"], state="admitted", message="Conversation message and files admitted; preparing evidence.")
                    binding = ChatThreads(world).binding(receipt["goal_id"])
                    intent = {"channel": "dashboard", "user_id": user_id,
                              "allowed_suites": sorted(suites) if suites is not None else None,
                              "conversation_id": binding.conversation_id if binding else None}
                    store.record_dispatch_intent(receipt["key"], intent)
                    current_authority(world.get_goal(item["target_id"]))
                    if not prepare(world, receipt):
                        _blocked(inbox, item["target_id"], item, "Task preparation did not claim execution. Review the admitted draft and attachments before an explicit retry.")
                        continue
                    inbox.transition(item["target_id"], item["id"], revision=item["revision"], state="submitted",
                                     goal=receipt["goal_id"], message="Admitted once to its governed task. Inspect that task for execution and result receipts.")
                    run = (receipt["goal_id"], {**intent, "allowed_suites": suites})
                    break
                except (ValueError, PermissionError, OSError) as exc:
                    _blocked(inbox, item["target_id"], item, "Admission paused without an automatic retry. Review current task state and attachments before retrying. " + type(exc).__name__)
        if run and not _scheduler_stop.is_set():
            run_goal_in_background(run[0], **run[1])
    finally:
        close_world_if_owned(world)


def _work(key, record_id, item_id):
    try:
        execute_record(record_id, item_id)
    except Exception as exc:
        log.warning("Conversation inbox execution unavailable (%s)", type(exc).__name__)
    finally:
        with _lock:
            _workers.pop(key, None)
        wake()


def cycle():
    from maverick.paths import tenant_scope

    from .personal_notification_scheduler import _tenants
    for tenant in _tenants():
        if _scheduler_stop.is_set():
            return
        with tenant_scope(tenant=tenant):
            if not policy()["enabled"]:
                continue
            page = list(STORE.iter_record_ids(start_after=_cursor.get(tenant, ""), limit=20))
            _cursor[tenant] = page[-1][0] if page else ""
            for _, record_id in page:
                record = STORE.get(record_id)
                if not record or not any(item["state"] in {"queued", "dispatching", "guidance_ready", "needs_decision"}
                                         for item in _unpack(record)["items"]):
                    continue
                for item in _unpack(record)["items"]:
                    if item["state"] not in {"queued", "dispatching", "guidance_ready", "needs_decision"}:
                        continue
                    key = (tenant, record_id, item["id"])
                    with _lock:
                        if key in _workers or len(_workers) >= 4:
                            continue
                        context = contextvars.copy_context()
                        worker = threading.Thread(target=context.run, args=(_work, key, record_id, item["id"]),
                                                  name="conversation-message-dispatch", daemon=True)
                        _workers[key] = worker
                        _threads[:] = [thread for thread in _threads if thread.is_alive()]
                        _threads.append(worker)
                        worker.start()


def _loop():
    while not _scheduler_stop.is_set():
        try:
            cycle()
        except Exception as exc:
            log.warning("Conversation inbox observer unavailable (%s)", type(exc).__name__)
        _wake.wait(3)
        _wake.clear()


def start_conversation_inbox_scheduler():
    global _scheduler_thread
    with _lock:
        if any(thread.is_alive() for thread in _threads):
            return False
        _scheduler_stop.clear()
        _scheduler_thread = threading.Thread(target=_loop, name="conversation-inbox-observer", daemon=True)
        _threads.append(_scheduler_thread)
        _scheduler_thread.start()
        return True


def stop_conversation_inbox_scheduler(*, timeout=20, wait=True):
    _scheduler_stop.set()
    _wake.set()
    deadline = time.monotonic() + max(0, timeout)
    with _lock:
        threads = [*_workers.values(), *([_scheduler_thread] if _scheduler_thread else [])]
    if wait:
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
    return all(not thread.is_alive() for thread in threads)
