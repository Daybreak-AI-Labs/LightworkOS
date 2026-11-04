"""Immutable chat alternatives, admitted through the original submission writer."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
from pathlib import Path

from .attachment_submissions import AttachmentAdmission, SubmissionConflict, SubmissionStore
from .chat_threads import ChatThreads
from .governed_operations import digest

ACTIONS = ("retry", "edit", "branch")
KINDS = ("chat_alternative_answer", "chat_alternative_work")
MAX_TURNS = 100
MAX_TEXT = 120000
_DISPATCH = ContextVar("chat_alternative_dispatch", default=None)


def source(world, goal_id, action, *, owner, authorize, connection=None, at_turn=None):
    """Read complete bounded source, without treating copied history as effects."""
    if action not in ACTIONS:
        raise ValueError("Choose Try again, Edit and resend, or Branch from here.")
    chat = ChatThreads(world)
    binding = chat.binding(goal_id, connection=connection)
    if binding is None or binding.owner != owner:
        raise SubmissionConflict("Open one of your saved conversations first.")
    if action != "branch" and chat.latest(goal_id) != goal_id:
        raise SubmissionConflict("Open the latest message to try again or edit and resend.")
    members = chat.members(binding, connection=connection, limit=MAX_TURNS + 1)
    if len(members) > MAX_TURNS:
        raise SubmissionConflict("This conversation is too long to copy completely. Start a new conversation with the messages and files you choose explicitly.")
    if any(status not in {"done", "completed", "cancelled", "blocked", "failed", "error"}
           for _, status in members):
        raise SubmissionConflict("Wait for the conversation to finish, or stop its current work, before creating an alternative.")
    ids = sorted(int(member) for member, _ in members if int(member) <= goal_id)
    if connection is not None:
        chat._lock(connection, binding.root_id)
        if not chat.store.sqlite:
            scope, values = chat.store.scope()
            for identity in ids:
                chat.store.execute(connection, f"SELECT id FROM goals WHERE id=? AND {scope} FOR UPDATE",
                                   (identity, *values)).fetchone()
    goals, files, questions = _records(world, ids, owner, authorize)
    gs, gv = chat._scope("g")
    rows = chat._rows("SELECT t.id,t.goal_id,t.role,t.content,t.ts FROM turns t "
        "JOIN goals g ON g.id=t.goal_id WHERE t.conversation_id=? AND g.owner=? "
        f"AND g.id<=? AND {gs} AND t.role IN ('user','assistant') ORDER BY t.id LIMIT ?",
        (binding.conversation_id, owner, goal_id, *gv, MAX_TURNS + 1), connection=connection)
    if len(rows) > MAX_TURNS:
        raise SubmissionConflict("This conversation has more messages than can be reviewed completely. Start a new conversation with explicitly selected context.")
    turns = [{"id": int(row[0]), "goal_id": int(row[1]), "role": row[2],
              "content": chat.store.open(row[3]), "at": row[4]} for row in rows]
    selected = [row for row in turns if row["goal_id"] == goal_id and row["role"] == "user"]
    if not selected:
        raise SubmissionConflict("The saved question is unavailable; no alternative was created.")
    last_user = selected[-1]
    if at_turn is not None and action != "branch":
        raise SubmissionConflict("Choose an earlier answer only when branching.")
    pivot = next((row for row in turns if row["id"] == at_turn), None) if at_turn is not None else None
    if at_turn is not None and (pivot is None or pivot["role"] != "assistant"):
        raise SubmissionConflict("This saved answer is no longer available for branching.")
    cutoff = (turns.index(pivot) + 1 if pivot else len(turns)) if action == "branch" else turns.index(last_user)
    if action != "branch" and questions.get(str(goal_id)):
        # Keep the question that these explicit clarifications answered. The
        # new message follows it; the old final answer remains excluded.
        cutoff += 1
    included_ids = {row["goal_id"] for row in turns[:cutoff]}
    if action != "branch":
        included_ids.add(goal_id)  # The resent question keeps its originally reviewed files.
    cutoff_time = float(pivot["at"]) if pivot is not None else float("inf")
    # A later turn's files never enter an earlier branch. The full source still
    # binds every file's provenance, while exact duplicate bytes are admitted once.
    chosen = _files(chat, files, included_ids, cutoff_time)
    prior = _history(turns, cutoff, questions, goals)
    if action == "branch" and pivot is None:
        goal = next(row for row in goals if row["id"] == goal_id)
        if goal["result"]:
            answer = _readable_answer(goal, goal["result"])
            after_question = turns[turns.index(last_user) + 1:]
            if after_question and after_question[-1]["role"] == "assistant":
                prior[-1] = {"role": "assistant", "content": answer, "at": goal["updated_at"]}
            else:
                prior.append({"role": "assistant", "content": answer, "at": goal["updated_at"]})
    if len(prior) > MAX_TURNS or sum(len(row["content"]) for row in prior) > MAX_TEXT:
        raise SubmissionConflict("The complete conversation is too large for this review. Start a new conversation and choose the context explicitly; no hidden messages were copied.")
    _verify_material(world, goals, owner, authorize)
    from .template_connections import for_goal
    return {"goal_id": goal_id, "root_id": binding.root_id, "owner": owner,
            "action": action, "at_turn": at_turn, "goals": goals, "turns": turns, "questions": questions,
            "files": chosen, "file_provenance": files,
            "prior": prior, "question": last_user["content"], "connections": for_goal(world, goal_id)}


def _verify_material(world, goals, owner, authorize):
    # Revalidate the same complete native source after all file/source waits.
    from .knowledge_task_context import require_read
    for material in goals:
        current = world.get_goal(material["id"])
        if current is None or asdict(current) != material:
            raise SubmissionConflict("A message changed while it was read. Review the current conversation again.")
        authorize(current)
        require_read(current, owner)


def _records(world, ids, owner, authorize):
    from .attachments import _verify_stored_attachment
    from .knowledge_task_context import require_read
    goals, files, questions = [], [], {}
    for identity in ids:
        goal = world.get_goal(identity)
        if goal is None or goal.owner != owner:
            raise SubmissionConflict("A conversation message is no longer available to this account.")
        authorize(goal)
        require_read(goal, owner)
        require_runtime_sources(world, identity)
        goals.append(asdict(goal))
        questions[str(identity)] = [asdict(q) for q in world.all_questions(identity) if q.answer is not None]
        for item in world.list_attachments(identity):
            _verify_stored_attachment(Path(item.path), item.sha256)
            files.append({**asdict(item), "source_goal": identity})
    return goals, files, questions


def _files(chat, files, included_ids, cutoff_time):
    for item in files:
        receipt = chat.store.for_goal(item["source_goal"])
        origins = (receipt["detail"].get("alternative") or {}).get("file_sources", []) if receipt else []
        item["available_at"] = next((row["at"] for row in origins if all(row[k] == item[k]
            for k in ("filename", "mime", "size_bytes", "sha256"))), item["created_at"])
    retained_files = [row for row in files if row["source_goal"] in included_ids and row["available_at"] <= cutoff_time]
    chosen = {}
    for item in retained_files:
        chosen.setdefault(tuple(item[k] for k in ("filename", "mime", "size_bytes", "sha256")), item)
    from .attachments import MAX_GOAL_BYTES
    if len(chosen) > 128 or sum(item[2] for item in chosen) > MAX_GOAL_BYTES:
        raise SubmissionConflict("These retained files exceed one conversation's supported limit. Start a new conversation and choose fewer files explicitly; nothing was copied.")
    return list(chosen.values())


def _readable_answer(goal, content):
    from .stop_reasons import stop_payload
    stopped = stop_payload(goal["status"], content) if content == goal["result"] else None
    return f"{stopped['message']}\n\n{stopped['action']}" if stopped else content


def _history(turns, cutoff, questions, goals):
    prior = []
    material = {row["id"]: row for row in goals}
    last_users = {row["goal_id"]: row["id"] for row in turns if row["role"] == "user"}
    for turn in turns[:cutoff]:
        content = _readable_answer(material[turn["goal_id"]], turn["content"]) if turn["role"] == "assistant" else turn["content"]
        prior.append({"role": turn["role"], "content": content, "at": turn["at"]})
        if turn["role"] == "user" and turn["id"] == last_users[turn["goal_id"]]:
            for q in questions.get(str(turn["goal_id"]), []):
                prior.extend(({"role": "assistant", "content": q["question"], "at": q["asked_at"]},
                              {"role": "user", "content": q["answer"], "at": q["answered_at"]}))
    return prior


def create(world, reviewed, *, token, message, answer_only, caps, admission, before_create):
    """One atomic native goal/turn/attachment/receipt admission; never dispatch."""
    store = SubmissionStore(world)
    selected = next(row for row in reviewed["goals"] if row["id"] == reviewed["goal_id"])
    from .task_model_selection import recorded
    task_selection = recorded(world, reviewed["goal_id"])
    fingerprints = [{key: item[key] for key in ("filename", "mime", "size_bytes", "sha256")}
                    for item in reviewed["files"]]
    request = {"source": digest(reviewed), "message": message, "answer_only": answer_only,
               "caps": caps, "admission": admission}
    return store.create(token=token, fingerprint=digest(request), owner=reviewed["owner"],
        title=next(line.strip() for line in message.splitlines() if line.strip())[:200],
        description=message, domain=selected["domain"], project_id=selected["project_id"],
        connection_references=reviewed["connections"],
        manifest=fingerprints, kind=KINDS[0 if answer_only else 1], chat_text=message,
        chat_prior=reviewed["prior"], before_create=before_create,
        attachment_records=[AttachmentAdmission(item["filename"], item["mime"], item["size_bytes"],
            item["sha256"], item["path"]) for item in reviewed["files"]],
        submission_detail={**({"task_model_selection": task_selection} if task_selection is not None else {}),
            "alternative": {"source_goal_ids": [row["id"] for row in reviewed["goals"]],
            "source_goal": reviewed["goal_id"], "action": reviewed["action"],
            "source_sha256": digest(reviewed), "answer_only": answer_only,
            "caps": caps, "admission": admission,
            "file_sources": [{**{k: row[k] for k in ("filename", "mime", "size_bytes", "sha256")},
                              "at": row["available_at"]} for row in reviewed["files"]]}})


def require_copy_sources(world, goal_id, *, alternative=None, authorize=None, defer_errors=False):
    """Historical copied text retains source ACLs, independently of new-work policy.

    ``defer_errors``: a source that cannot be checked (an error other than a
    ``PermissionError`` refusal) is set aside and the walk goes on, so a later
    source that refuses still decides. At the end an error set aside is raised,
    an outage ahead of a ``SourceContextUnavailable`` (which can also be a
    refusal). For a check that must tell "cannot be read" from "refused"."""
    if alternative is None:
        alternative = _alternative(world, goal_id)
        if alternative is None:
            return None
    from .knowledge_task_context import require_read
    goal = world.get_goal(goal_id)
    if goal is None:
        raise PermissionError("The alternative conversation is unavailable.")
    if authorize is not None:
        authorize(goal)
    pending, seen, deferred = list(alternative["source_goal_ids"]), {goal_id}, []
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        seen.add(identity)
        if len(seen) > 1000:
            raise PermissionError("This copied conversation has too many source dependencies to verify completely. Start a new conversation with explicitly chosen context.")
        try:
            _check_copy_source(world, identity, goal, authorize, require_read, pending,
                               deferred if defer_errors else None)
        except PermissionError:
            raise
        except Exception as exc:
            if not defer_errors:
                raise
            deferred.append(exc)
    if deferred:
        from .knowledge_task_context import SourceContextUnavailable

        # An outage outranks an "unavailable source", which can also be a
        # refusal: the answer does not depend on the order sources were walked.
        raise next((exc for exc in deferred if not isinstance(exc, SourceContextUnavailable)), deferred[0])
    from .attachments import _verify_stored_attachment
    for item in world.list_attachments(goal_id):
        _verify_stored_attachment(Path(item.path), item.sha256)
    return alternative


def _check_copy_source(world, identity, goal, authorize, require_read, pending, deferred=None):
    """Check one copied source and queue its own copied sources. With
    ``deferred`` (a list), a step that cannot be checked is set aside there
    while the others still run, and the nested sources are queued first, so
    they are walked even when this source cannot be checked (or read)."""
    def check():
        source_goal = world.get_goal(identity)
        if source_goal is None or source_goal.owner != goal.owner:
            raise PermissionError("A copied source is no longer available to this account.")
        if authorize is not None:
            authorize(source_goal)
        require_read(source_goal, goal.owner)

    def queue_nested():
        nested = SubmissionStore(world).for_goal(identity)
        if nested and nested["detail"].get("kind") in KINDS:
            pending.extend(nested["detail"]["alternative"]["source_goal_ids"])

    if deferred is None:
        check()
        queue_nested()
        return
    for step in (queue_nested, check):
        try:
            step()
        except PermissionError:
            raise
        except Exception as exc:
            deferred.append(exc)


def _alternative(world, goal_id):
    store = SubmissionStore(world)
    receipt = store.for_goal(goal_id)
    if not receipt or receipt["detail"].get("kind") not in KINDS:
        binding = ChatThreads(world).binding(goal_id)
        receipt = store.for_goal(binding.root_id) if binding and binding.root_id != goal_id else None
    return receipt["detail"]["alternative"] if receipt and receipt["detail"].get("kind") in KINDS else None


def require_runtime_sources(world, goal_id, *, alternative=None):
    """Each resumed/model attempt rechecks current execution and copied-source grants."""
    alternative = _alternative(world, goal_id) if alternative is None else alternative
    if alternative is not None:
        from maverick_dashboard.auth import fresh_configuration

        from .config import get_chat_message_actions
        from .conversation_inbox import current_authority
        if not get_chat_message_actions()["enabled"]:
            raise PermissionError("Conversation alternatives are turned off; no new AI work can start.")
        with fresh_configuration():
            require_copy_sources(world, goal_id, alternative=alternative, authorize=current_authority)
    return alternative


def runtime_limits(world, goal, max_dollars, max_wall_seconds, max_depth, capability):
    """A resumed copied conversation cannot widen its original reviewed limits."""
    alternative = require_runtime_sources(world, goal.id)
    if alternative is None:
        return None, max_dollars, max_wall_seconds, max_depth, capability
    caps = alternative["caps"]
    dollars = min(max_dollars, caps["max_dollars"]) if max_dollars is not None else caps["max_dollars"]
    seconds = min(max_wall_seconds, caps["max_wall_seconds"]) if max_wall_seconds is not None else caps["max_wall_seconds"]
    if alternative["answer_only"]:
        from .capability import deny_all_capability
        answer_grant = deny_all_capability(goal.owner or "user:local")
        capability = (capability.intersect(answer_grant, principal=answer_grant.principal)
                      if capability is not None else answer_grant)
    return alternative, dollars, seconds, min(max_depth, caps["max_depth"]), capability


@contextmanager
def runtime_scope(world, goal_id, alternative):
    token = _DISPATCH.set((world, goal_id, alternative) if alternative is not None else None)
    try:
        yield
    finally:
        _DISPATCH.reset(token)


def require_dispatch_sources():
    current = _DISPATCH.get()
    if current is not None:
        require_runtime_sources(current[0], current[1], alternative=current[2])


def answer_only_runtime():
    current = _DISPATCH.get()
    return current is not None and current[2]["answer_only"] is True
