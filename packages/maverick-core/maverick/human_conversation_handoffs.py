"""Explicit same-thread human support, using the existing private inbox journal."""
from __future__ import annotations

import copy
import json
import logging
import re
import time
from contextlib import ExitStack

from . import conversation_inbox as inbox
from .chat_threads import ChatThreads
from .goal_mutations import GoalMutationConflict, _fingerprint, _record, _transaction
from .goal_stop import TERMINAL, stop
from .governed_operations import digest
from .task_execution_guard import lease

HELD = {"stopping", "waiting", "active", "unknown"}
MAX_ROWS, MAX_MESSAGES, MAX_SCOPE = 10000, 200, 100
DUTY_SCHEMA = "lightwork.human-conversation-duty.v1"
log = logging.getLogger(__name__)


def _identifier(root):
    return "CI-" + digest({"root": root.id, "owner": root.owner, "created_at": root.created_at})[:32]


def _check_operation(value):
    return inbox.operation(value)


def _bounded_text(value, maximum, label):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"Enter {label} up to {maximum:,} characters. Nothing was shortened.")
    return value


def _read_record(record):
    if record is None:
        raise GoalMutationConflict("The original human handoff is unavailable. New AI work remains held; no earlier work was repeated.")
    return inbox._unpack(record)


def require_ai_open(world, goal_id, *, execute=None, decode=None):
    """Physical admission reads exact original hold pointers, including moved tasks."""
    from .attachment_submissions import SubmissionStore
    store = SubmissionStore(world)
    query = (lambda sql, args: execute(sql, args).fetchall()) if execute else world.query
    decode = decode or store.open
    current, seen = int(goal_id), set()
    while current is not None:
        if current in seen or len(seen) >= 100:
            raise GoalMutationConflict("The conversation's current human handoff could not be checked.")
        seen.add(current)
        identity = query("SELECT id,owner,created_at FROM goals WHERE id=?", (current,))
        if identity:
            identifier = "CI-" + digest({"root": identity[0][0], "owner": identity[0][1], "created_at": identity[0][2]})[:32]
            native = inbox.STORE.get(identifier)
            if native is not None:
                human = _read_record(native).get("human", {})
                session = human.get("sessions", {}).get(human.get("current"))
                if session and (session.get("state") in HELD or native.get("_audit_pending")):
                    raise GoalMutationConflict("A human handoff holds this conversation. Read its original outcome or separately review hand-back.")
        rows = query("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind='human_conversation_hold'", (current,))
        for (raw,) in rows:
            pointer = json.loads(decode(raw))
            record = inbox.STORE.get(pointer["record"])
            value = _read_record(record)
            session = value.get("human", {}).get("sessions", {}).get(pointer["session"])
            if session is None or session.get("state") in HELD or record.get("_audit_pending"):
                raise GoalMutationConflict("A human handoff holds this conversation. Read its original outcome or separately review hand-back; earlier AI work will not restart automatically.")
        parents = query("SELECT parent_id FROM goals WHERE id=?", (current,))
        current = parents[0][0] if parents else None


class HumanConversations:
    """Callbacks supply current caller/source/duty authority, never a model."""
    def __init__(self, world, *, actor, authorize, store=None, metadata_only=False):
        if not isinstance(actor, str) or not actor.strip():
            raise PermissionError("Sign in with a named account to use human conversations.")
        self.world, self.actor, self.authorize = world, actor, authorize
        self.store = store or inbox.STORE
        self.metadata_only = metadata_only

    def _source(self, goal_id):
        goal = self.world.get_goal(goal_id)
        binding = ChatThreads(self.world).binding(goal_id) if goal else None
        if not goal or not binding:
            raise PermissionError("Choose an existing web conversation.")
        root = self.world.get_goal(binding.root_id)
        if root is None or root.owner != goal.owner:
            raise PermissionError("This conversation's source owner changed.")
        return goal, root, binding

    def _load(self, goal_id):
        goal, root, binding = self._source(goal_id)
        record = self.store.get(_identifier(root))
        if record is None:
            record = {"id": _identifier(root), "owner": root.owner, "root_id": root.id,
                      "revision": 0, "schema": "lightwork.conversation-inbox.v1"}
            value = {"generation": 0, "items": [], "operations": {}}
        else:
            if record.get("owner") != root.owner or record.get("root_id") != root.id:
                raise PermissionError("The original conversation ownership changed.")
            value = inbox._unpack(record)
        human = value.setdefault("human", {"sessions": {}, "current": None, "operations": {}})
        return goal, root, binding, record, value, human

    def _save(self, record, value, *, action, guard):
        if guard:
            guard()
        payload = inbox._pack(value, record)
        if record["revision"] == 0:
            saved = self.store.create({key: val for key, val in {**record, "payload": payload}.items() if key != "revision"},
                                      actor=self.actor, action=action, effect_guard=guard)
        else:
            def change(current):
                if (current.get("owner"), current.get("root_id")) != (record["owner"], record["root_id"]):
                    raise PermissionError("The original conversation ownership changed.")
                current["payload"] = payload
            saved = self.store.update(record["id"], change, expected_revision=record["revision"], actor=self.actor,
                                      action=action, effect_guard=guard)
        if saved is None:
            raise GoalMutationConflict("This conversation changed. Read its current original before reviewing a new decision.")
        return saved

    def _authorized(self, goal, root, human, *, write=False):
        current = human["sessions"].get(human["current"]) if human["current"] else None
        if self.metadata_only and self.actor != root.owner:
            raise PermissionError("Only the original owner can release this recorded hold.")
        if self.actor != root.owner and (not current or current["recipient"] != self.actor):
            raise PermissionError("This human conversation is unavailable to your account.")
        self.authorize(goal, current, write)
        return current

    def scope(self, root):
        rows = self.world.query("WITH RECURSIVE scope(id) AS (SELECT id FROM goals WHERE id=? UNION SELECT g.id FROM goals g JOIN scope s ON g.parent_id=s.id) SELECT id FROM scope LIMIT 101", (root.id,))
        if len(rows) > MAX_SCOPE:
            raise ValueError("This conversation has more than 100 related tasks. Stop its work separately before selecting a smaller conversation.")
        goals = [self.world.get_goal(int(row[0])) for row in rows]
        if any(goal is None or goal.owner != root.owner for goal in goals):
            raise PermissionError("Every task paused with this conversation must retain its original owner.")
        return sorted(goals, key=lambda goal: goal.id)

    def state(self, goal_id):
        goal, root, _binding, record, _value, human = self._load(goal_id)
        session = self._authorized(goal, root, human)
        self.authorize(goal, session, False)
        visible = copy.deepcopy(session)
        if visible and _value.get("erasures") and not any(visible["shared"].values()) and not visible["messages"]:
            visible["erased"] = True
        if visible and self.metadata_only:
            visible.update(shared={"title":"Withheld","brief":"Current source permission is unavailable.","saved_reply":"Withheld"},
                           purpose="",recipient="",duty_label="",messages=[])
        from . import contact_centre
        external = contact_centre.shown_status(human["current"]) if session and not self.metadata_only else None
        return {"goal_id": goal.id, "root_id": root.id, "owner": root.owner, "is_owner": self.actor == root.owner, "revision": record["revision"],
                "session": visible, "held": bool(session and session["state"] in HELD), "contact_centre": external,
                "audit_pending": bool(record.get("_audit_pending")), "source_unavailable": self.metadata_only,
                "title": "Owned human conversation" if self.metadata_only else goal.title}

    def review(self, goal_id, action, *, recipient="", purpose="", expires_at=0, message="", duty=None):
        if self.metadata_only and action != "handback":
            raise PermissionError("This metadata review can only release the original owner's recorded AI hold.")
        goal, root, _binding, record, value, human = self._load(goal_id)
        session = self._authorized(goal, root, human, write=True)
        if len(human["operations"]) >= 1000:
            raise ValueError("This conversation's retained human decision history is full. Earlier originals were not removed.")
        if action == "request":
            if self.actor != root.owner or (session and session["state"] in HELD):
                raise GoalMutationConflict("A human handoff is already held. Read it before separately reviewing a change.")
            if any(item["state"] not in {"cancelled", "consumed", "submitted"} for item in value["items"]):
                raise GoalMutationConflict("Cancel or finish each pending message first. The handoff will not silently send old queued work.")
            if not duty or duty.get("owner") != recipient or duty.get("until", 0) <= time.time():
                raise GoalMutationConflict("Choose a currently on-duty named person.")
            if not time.time() < expires_at <= time.time() + 8 * 3600:
                raise ValueError("Choose human access for up to eight hours.")
            _bounded_text(purpose, 1000, "why you need a person")
            shared = {"title": goal.title, "brief": goal.description, "saved_reply": goal.result or ""}
            if sum(len(text) for text in shared.values()) > 64000:
                raise ValueError("This complete brief and saved reply exceed 64,000 characters. Nothing was shortened or shared.")
            tasks = [[item.id, item.owner, float(item.updated_at), item.status] for item in self.scope(root)]
        else:
            if session is None or session["state"] not in HELD:
                raise GoalMutationConflict("No current human handoff is available for that decision.")
            shared, tasks = session["shared"], session["tasks"]
            recipient, purpose, expires_at = session["recipient"], session["purpose"], session["expires_at"]
            if action == "finish_pause":
                tasks = [[item.id, item.owner, float(item.updated_at), item.status] for item in self.scope(root)]
            if action == "claim" and (self.actor != session["recipient"] or session["state"] != "waiting"):
                raise PermissionError("Only the selected person can claim a settled waiting conversation.")
            if action in {"reply", "message"}:
                expected = session["recipient"] if action == "reply" else root.owner
                if self.actor != expected or session["state"] != "active":
                    raise PermissionError("This person has not claimed the conversation, or it has been handed back.")
                _bounded_text(message, 4000, "your reply")
                if len(session["messages"]) >= MAX_MESSAGES:
                    raise ValueError("This human exchange reached 200 messages. Earlier messages were not discarded.")
            if action in {"handback", "finish_pause"} and self.actor != root.owner:
                raise PermissionError("Only the original customer can release or finish this conversation's AI hold.")
            if action not in {"claim", "reply", "message", "handback", "finish_pause"}:
                raise ValueError("Choose an available human conversation decision.")
        prepared = {"action": action, "goal_id": goal.id, "root_id": root.id, "owner": root.owner, "actor": self.actor,
                    "record": record["id"], "revision": record["revision"], "source": inbox.task_snapshot(goal)["version"],
                    "session": human["current"], "recipient": recipient, "purpose": purpose, "expires_at": expires_at,
                    "message": message, "shared": shared, "tasks": tasks, "duty": copy.deepcopy(duty), "review_expires": time.time() + 300}
        prepared["person_name"] = duty["label"] if duty else session["duty_label"]
        prepared["metadata_only"] = self.metadata_only
        if self.metadata_only:
            prepared.update(shared={"title":"Withheld","brief":"Only the recorded AI hold is released.","saved_reply":"Withheld"},
                            purpose="End the original human sharing permission",recipient="",person_name="Withheld")
        prepared["task_names"] = [self.world.get_goal(row[0]).title if self.actor == root.owner and not self.metadata_only else f"Related task {index}"
                                  for index, row in enumerate(tasks, 1)]
        prepared["binding"] = digest(prepared)
        return prepared

    def _pointer(self, prepared, session_id, guard):
        fingerprint = _fingerprint([prepared["record"], session_id])
        with _transaction(self.world, prepared["root_id"]) as (execute, encode, decode, _pg, _tenant):
            for goal_id, owner, _updated, _status in prepared["tasks"]:
                guard()
                row = execute("SELECT owner FROM goals WHERE id=?", (goal_id,)).fetchone()
                if row is None or row[0] != owner:
                    raise PermissionError("The task's original owner changed before its AI hold.")
                prior = execute("SELECT request_hash FROM goal_mutation_receipts WHERE goal_id=? AND kind='human_conversation_hold' AND operation_id=? AND actor=?", (goal_id, session_id, self.actor)).fetchone()
                if prior is None:
                    _record(execute, encode, goal_id, "human_conversation_hold", session_id, self.actor, fingerprint,
                            {"record": prepared["record"], "session": session_id})
                elif prior[0] != fingerprint:
                    raise GoalMutationConflict("This original AI hold belongs to different work.")
            guard()

    def _pause(self, prepared, operation, guard):
        for goal_id, owner, updated, _status in prepared["tasks"]:
            guard()
            goal = self.world.get_goal(goal_id)
            if goal is None or goal.owner != owner:
                raise PermissionError("A related task's owner changed.")
            if goal.status not in TERMINAL:
                if prepared["action"] == "claim":
                    raise GoalMutationConflict("AI work is not settled. Only the customer can separately review Finish pausing.")
                stop(self.world, goal_id, actor=self.actor, operation_id="human:" + operation + ":" + str(goal_id),
                     expected_updated_at=updated, expected_owner=owner, effect_guard=guard)
        root = self.world.get_goal(prepared["root_id"])
        if [item.id for item in self.scope(root)] != [row[0] for row in prepared["tasks"]]:
            raise GoalMutationConflict("The related task scope changed. The AI hold remains; review its current work separately.")
        with ExitStack() as stack:
            for goal in self.scope(root):
                stack.enter_context(lease(self.world, goal.id))
                guard()
                current = self.world.get_goal(goal.id)
                if current.status not in TERMINAL or self.world.query("SELECT id FROM episodes WHERE goal_id=? AND ended_at IS NULL LIMIT 1", (goal.id,)):
                    raise GoalMutationConflict("AI work has not settled. Its hold is kept; separately review Finish pausing after cleanup.")
            guard()

    def apply(self, prepared, operation, *, guard):
        operation = _check_operation(operation)
        goal, root, _binding, record, value, human = self._load(prepared["goal_id"])
        self._authorized(goal, root, human, write=True)
        prior = human["operations"].get(operation)
        if prior is not None:
            if prior["binding"] != prepared["binding"]:
                raise GoalMutationConflict("This original decision belongs to different entered work.")
            return copy.deepcopy(prior)
        guard()
        if record["revision"] != prepared["revision"]:
            raise GoalMutationConflict("This human conversation changed after review.")
        session_id = operation if prepared["action"] == "request" else human["current"]
        human["operations"][operation] = {"operation": operation, "binding": prepared["binding"], "action": prepared["action"],
                                         "actor": self.actor, "state": "unknown", "recorded_at": time.time(), "session": session_id}
        if prepared["action"] == "request":
            human["sessions"][session_id] = {"id": session_id, "state": "stopping", "recipient": prepared["recipient"],
                "goal_id": prepared["goal_id"],
                "owner": root.owner, "purpose": prepared["purpose"], "expires_at": prepared["expires_at"], "shared": prepared["shared"],
                "source": prepared["source"], "tasks": prepared["tasks"], "messages": [], "duty_label": prepared["duty"]["label"]}
            human["current"] = session_id
        # Reserve before native effects. Unknown original decisions never execute again.
        record = self._save(record, value, action="human_decision_reserved", guard=guard)
        if record.get("_audit_pending"):
            return self.original(prepared["goal_id"], operation)
        session = human["sessions"][session_id]
        action = prepared["action"]
        if action in {"request", "finish_pause"}:
            self._pointer(prepared, session_id, guard)
            self._pause(prepared, operation, guard)
            session["state"] = "waiting"
        elif action == "claim":
            self._pause(prepared, operation, guard)
            session["state"] = "active"
        elif action in {"reply", "message"}:
            session["messages"].append({"actor": self.actor, "from": "person" if action == "reply" else "customer",
                "text": prepared["message"], "at": time.time(), "operation": operation})
        elif action == "handback":
            session["state"] = "returned"
        human["operations"][operation]["state"] = "confirmed"
        self._save(record, value, action="human_decision_confirmed", guard=guard)
        if prepared["action"] == "request":
            self._contact_centre_handoff(prepared, goal, session_id)
        return self.original(prepared["goal_id"], operation)

    def _contact_centre_handoff(self, prepared, goal, session_id):
        """Queue the outside contact-centre handoff. Never raises: the in-app handoff is already confirmed."""
        from . import config, contact_centre
        try:
            policy = config.get_contact_centre()
            if policy["provider"] == "off":
                return
            from .chat_threads import ChatThreads
            turns, _more = ChatThreads(self.world).history(goal.id, limit=policy["max_messages"])
            contact_centre.enqueue_handoff(
                handoff_id=session_id, title=prepared["shared"]["title"], reason=prepared["purpose"],
                requester_name=self.actor, requester_email=self.actor if "@" in self.actor else "",
                messages=[(turn.role, turn.content) for turn in turns], link=contact_centre.conversation_link(goal.id))
        except Exception as exc:
            log.warning("contact centre: handoff %s was not queued (%s)", session_id, type(exc).__name__)

    def original(self, goal_id, operation):
        _goal, _root, _binding, record, _value, _human = self._load(goal_id)
        return self.original_record(record["id"], operation)

    def original_record(self, identifier, operation):
        if not re.fullmatch(r"CI-[a-f0-9]{32}", identifier or ""):
            raise PermissionError("This original decision is unavailable.")
        record = self.store.get(identifier)
        if not record or record.get("schema") != "lightwork.conversation-inbox.v1":
            raise PermissionError("This original decision is unavailable.")
        human = inbox._unpack(record).get("human", {})
        prior = human.get("operations", {}).get(_check_operation(operation))
        if prior is None or prior["actor"] != self.actor:
            raise PermissionError("This original decision is unavailable to your account.")
        value = copy.deepcopy(prior)
        value["confirmed"] = value["state"] == "confirmed" and not record.get("_audit_pending")
        value["message"] = "The original decision is confirmed. Nothing was repeated." if value["confirmed"] else "This original outcome remains unconfirmed. Earlier effects may exist; nothing was repeated. Read the current conversation to check any remaining AI hold."
        return value

    def duty(self):
        identifier = "CI-" + digest(["human-duty", self.actor])[:32]
        record = self.store.get(identifier)
        if record and (record.get("owner") != self.actor or record.get("schema") != DUTY_SCHEMA):
            raise PermissionError("The duty declaration's owner changed.")
        return record, inbox._unpack(record) if record else {"items": [], "operations": {}, "label": "", "until": 0}

    def duty_original(self, operation):
        record, value = self.duty()
        prior = value["operations"].get(_check_operation(operation))
        if not prior or prior["actor"] != self.actor:
            raise PermissionError("This original duty declaration is unavailable.")
        return {"operation": operation, "confirmed": not record.get("_audit_pending"),
                "message": "Your original duty declaration is confirmed. Nothing was repeated." if not record.get("_audit_pending")
                else "This original duty declaration remains unconfirmed. Nothing was repeated."}

    def set_duty(self, *, label, until, operation, expected_revision, guard):
        operation = _check_operation(operation)
        record, value = self.duty()
        binding = digest([label, until, expected_revision])
        if operation in value["operations"]:
            if value["operations"][operation]["binding"] != binding:
                raise GoalMutationConflict("This original duty decision belongs to different work.")
            return record
        if until:
            _bounded_text(label, 120, "the name customers will see")
            if not time.time() < until <= time.time() + 8 * 3600:
                raise ValueError("Choose on-duty availability for up to eight hours.")
        if (record or {}).get("revision", 0) != expected_revision:
            raise GoalMutationConflict("Your duty declaration changed. Review it again.")
        if len(value["operations"]) >= 1000:
            raise ValueError("Your retained duty history reached its limit. Earlier originals were not discarded.")
        record = record or {"id": "CI-" + digest(["human-duty", self.actor])[:32], "owner": self.actor, "root_id": 0,
                            "revision": 0, "schema": DUTY_SCHEMA}
        value.update(label=label, until=until)
        value["operations"][operation] = {"binding": binding, "actor": self.actor, "state": "confirmed", "at": time.time()}
        return self._save(record, value, action="human_duty_declared", guard=guard)

    def roster(self):
        rows = self.store.list(limit=MAX_ROWS + 1)
        if len(rows) > MAX_ROWS:
            raise ValueError("The complete duty inventory exceeds its supported limit. No subset was presented as complete.")
        result = []
        for row in rows:
            if row.get("schema") != DUTY_SCHEMA or row.get("_audit_pending"):
                continue
            value = inbox._unpack(row)
            if value["until"] > time.time():
                result.append({"owner": row["owner"], "revision": row["revision"], "label": value["label"], "until": value["until"]})
        return sorted(result, key=lambda item: (item["label"], item["owner"]))
