"""Explicit accepted continuations, without transferring private chat history.

The world transaction closes the source and creates the successor/receipt
atomically. The governed offer is a recoverable projection of that receipt.
Selected copies become the recipient's task evidence; revoking an offer or
bundle never claims to erase a copy already accepted or downloaded.
"""
from __future__ import annotations

import copy
import json
import math
import time
from contextlib import ExitStack

from .attachment_submissions import SubmissionStore
from .chat_threads import ChatThreads
from .deliverable_bundles import BundleDenied, _operation, _text, decoded_items
from .goal_mutations import GoalMutationConflict, _record
from .governed_operations import digest
from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict
from .task_execution_guard import TaskBusy, lease

STORE = GovernedRecordStore("task_handoffs", "HOF", "task_handoff")
CLOSED = "This work was handed off. Its original history stays private; continue in the accepted recipient-owned task."
TERMINAL = {"done", "completed", "failed", "error", "blocked", "cancelled"}


def _row_receipt(world, goal_id, kind):
    store = SubmissionStore(world)
    rows = world.query("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind=? ORDER BY created_at LIMIT 1", (goal_id, kind))
    return json.loads(store.open(rows[0][0])) if rows else None


def lineage(world, goal_id):
    return _row_receipt(world, goal_id, "handoff_lineage")


def closure(world, goal_id, *, execute=None, decode=None):
    """Return lineage metadata only. Descendants cannot reopen closed work."""
    store = SubmissionStore(world)
    query = (lambda sql, args: execute(sql, args).fetchall()) if execute else world.query
    decode = decode or store.open
    current, seen = goal_id, set()
    while current is not None:
        if current in seen or len(seen) >= 100:
            raise GoalMutationConflict("Task ancestry is unavailable. Review the task map before starting.")
        seen.add(current)
        rows = query("SELECT receipt FROM goal_mutation_receipts WHERE goal_id=? AND kind='handoff_closed' LIMIT 1", (current,))
        if rows:
            return json.loads(decode(rows[0][0]))
        rows = query("SELECT parent_id FROM goals WHERE id=?", (current,))
        current = rows[0][0] if rows else None
    return None


def require_open(world, goal_id, *, execute=None, decode=None):
    if closure(world, goal_id, execute=execute, decode=decode):
        raise GoalMutationConflict(CLOSED)


def apply_ceiling(world, goal_id, budget):
    """Inherited ceilings include recorded descendant spend; never grant dollars."""
    current, seen = goal_id, set()
    while current is not None:
        if current in seen or len(seen) >= 100:
            raise GoalMutationConflict("Task allowance ancestry is unavailable.")
        seen.add(current)
        record = lineage(world, current)
        if record:
            # Some historical parent summaries include child spend. Counting
            # both can conservatively stop early; it cannot expand the cap.
            spent = world.query("WITH RECURSIVE scope(id) AS (SELECT id FROM goals WHERE id=? UNION SELECT g.id FROM goals g JOIN scope s ON g.parent_id=s.id) SELECT COALESCE(SUM(e.cost_dollars),0) FROM episodes e JOIN scope s ON e.goal_id=s.id", (current,))[0][0]
            remaining = max(0.0, float(record["max_dollars"]) - float(spent))
            budget.max_dollars = remaining if budget.max_dollars is None else min(budget.max_dollars, remaining)
        parent = world.get_goal(current)
        current = parent.parent_id if parent else None


class TaskHandoffs:
    def __init__(self, bundles, *, store=None):
        self.bundles, self.world, self.actor = bundles, bundles.world, bundles.actor
        self.store = store or STORE

    def _authorize(self, record, *, write=False):
        if not record or record.get("schema") != "lightwork.task-handoff.v1" or self.actor not in {record["owner"], record["recipient"]}:
            raise BundleDenied("This handoff is unavailable to your account.")
        self.bundles._allowed(self.actor, record["domain"], "operate" if write else "view")
        if self.actor == record["recipient"] and not self._accepted(record):
            if record["state"] != "offered" or record["preview"]["expires_at"] <= self.store.authoritative_time():
                raise BundleDenied("Future access to this offer ended. Copies already received cannot be recalled.")
            self.bundles.get(record["preview"]["bundle_id"])


    def _scope(self, source_id):
        binding = ChatThreads(self.world).binding(source_id)
        root = binding.root_id if binding else source_id
        rows = self.world.query("WITH RECURSIVE scope(id) AS (SELECT id FROM goals WHERE id=? UNION SELECT g.id FROM goals g JOIN scope s ON g.parent_id=s.id) SELECT id FROM scope LIMIT 1001", (root,))
        if len(rows) > 1000:
            raise ValueError("This work contains too many subtasks for one handoff. Close or hand off a smaller independent task.")
        return root, sorted(int(row[0]) for row in rows)

    def _boundary(self, source_id, owner):
        root, ids = self._scope(source_id)
        if not ids:
            raise BundleDenied("The source task is unavailable.")
        for goal_id in ids:
            goal = self.world.get_goal(goal_id)
            if goal is None or goal.owner != owner:
                raise BundleDenied("Every task closed by this handoff must belong to the sender.")
            if goal.status not in TERMINAL:
                raise TaskBusy("Stop or finish this conversation and its subtasks before offering a handoff.")
            if self.world.query("SELECT id FROM episodes WHERE goal_id=? AND ended_at IS NULL LIMIT 1", (goal_id,)):
                raise TaskBusy("An execution episode has not settled. Resolve its recovery before handing off.")
            require_open(self.world, goal_id)
        return root, ids

    @staticmethod
    def _prepared_items(bundle):
        from .attachments import validate_attachment
        result, total = [], 0
        for index, (item, content) in enumerate(decoded_items(bundle), 1):
            filename = item["title"] if item["kind"] == "evidence" else f"selected-{index}.md"
            mime = item["source"]["mime"] if item["kind"] == "evidence" else "text/markdown"
            validate_attachment(filename, mime, content, existing_total=total)
            total += len(content)
            result.append((item, content))
        return result

    def prepare(self, bundle_id, *, title, instruction, commitments, max_dollars):
        bundle = self.bundles.get(bundle_id)
        if bundle["owner"] != self.actor or bundle["status"] != "shared" or bundle["stale"]:
            raise BundleDenied("Only the source owner can offer an unchanged, available selected bundle.")
        payload = bundle["payload"]
        self._prepared_items(bundle)
        if bundle["expires_at"] <= self.store.authoritative_time():
            raise RecordConflict("The selected bundle expired. Share a fresh reviewed bundle first.")
        self.bundles._allowed(payload["recipient"], payload["source"]["domain"], "operate")
        source = self.bundles._source(payload["source"]["goal_id"])
        root, ids = self._boundary(source.id, self.actor)
        if isinstance(max_dollars, bool) or not isinstance(max_dollars, (int, float)) or not math.isfinite(max_dollars) or not 0 < max_dollars <= 1000000:
            raise ValueError("Choose a finite positive continuation ceiling, at most 1,000,000 dollars. Current administrative limits may be lower.")
        result = {"bundle_id": bundle_id, "bundle_revision": bundle["revision"], "source_version": payload["source_version"],
                  "source_id": source.id, "root_id": root, "closed_task_ids": ids, "owner": self.actor,
                  "recipient": payload["recipient"], "domain": source.domain, "expires_at": bundle["expires_at"],
                  "title": _text(title, "Continuation title", 160), "instruction": _text(instruction, "Next work", 12000),
                  "commitments": _text(commitments, "Pending commitments", 4000), "max_dollars": float(max_dollars),
                  "items": [{k: v for k, v in item.items() if k != "content_base64"} for item in payload["items"]],
                  "source_cost_scope": "Recorded episodes for the selected source task only; outside commitments are not measured automatically.",
                  "source_cost_dollars": float(self.world.query("SELECT COALESCE(SUM(cost_dollars),0) FROM episodes WHERE goal_id=?", (source.id,))[0][0]),
                  "open_questions": int(self.world.query("SELECT COUNT(*) FROM questions WHERE goal_id=? AND answer IS NULL", (source.id,))[0][0]),
                  "consequences": ["Acceptance closes this conversation and its listed subtasks to new execution; their private history remains with the original owner.",
                                   "The recipient owns a new, unstarted task with only these selected copies and next-work instructions.",
                                   "No original connections, credentials, learned memory, knowledge-source binding, project access or unselected conversation is transferred.",
                                   "Pending commitments are the sender's declaration, not an automatic audit of outside services. Administrative, budget and connection authority are checked again when the recipient starts.",
                                   "Revocation ends future offer/bundle access; accepted or downloaded copies cannot be recalled."]}
        result["review_version"] = digest(result)
        return result

    def create(self, bundle_id, *, expected_review, operation_id, **choices):
        operation_id = _operation(operation_id)
        identifier = "HOF-" + digest([self.actor, operation_id])[:32]
        request_hash = digest([bundle_id, expected_review, choices])
        old = self.store.get(identifier)
        if old:
            self._authorize(old, write=True)
            if old["request_hash"] != request_hash:
                raise RecordConflict("This reference belongs to a different offer.")
            return self.get(identifier)
        preview = self.prepare(bundle_id, **choices)
        if preview["review_version"] != expected_review:
            raise RecordConflict("The reviewed handoff changed. Preserve your draft and review again.")
        row = {"id": identifier, "schema": "lightwork.task-handoff.v1", "owner": self.actor,
               "recipient": preview["recipient"], "domain": preview["domain"], "state": "offered", "preview": preview,
               "request_hash": request_hash, "acceptance": None, "operations": {}}
        try:
            self.store.create(row, actor=self.actor, action="handoff_offered", max_records=1000)
        except RecordConflict:
            old = self.store.get(identifier)
            if not old or old["request_hash"] != request_hash:
                raise
        return self.get(identifier)

    def _accepted(self, row):
        receipt = _row_receipt(self.world, row["preview"]["root_id"], "handoff_closed")
        return receipt if receipt and receipt["handoff_id"] == row["id"] else None

    def get(self, identifier):
        row = self.store.get(identifier)
        self._authorize(row)
        accepted = self._accepted(row)
        result = copy.deepcopy({k: v for k, v in row.items() if k not in {"operations", "_audit_pending", "request_hash"}})
        if accepted:
            result["state"], result["acceptance"] = "accepted", accepted
        result["expired"] = row["preview"]["expires_at"] <= self.store.authoritative_time()
        result["can_accept"] = self.actor == row["recipient"] and result["state"] == "offered" and not result["expired"]
        result["can_withdraw"] = self.actor == row["owner"] and result["state"] == "offered"
        # The recipient's independent task remains private to the recipient.
        if result["acceptance"] and self.actor != row["recipient"]:
            result["acceptance"].pop("successor_id", None)
        return result

    def inbox(self):
        records = self.store.list(limit=1001)
        if len(records) > 1000:
            raise ValueError("The handoff inventory reached its supported limit.")
        result = []
        for row in records:
            try:
                self._authorize(row)
            except BundleDenied:
                continue
            # The listed row is already loaded and authorized: re-reading it
            # through get() cost a store read and a fresh authorization per row.
            state = "accepted" if self._accepted(row) else row["state"]
            result.append({"id": row["id"], "title": row["preview"]["title"], "state": state, "revision": row["revision"]})
        return result

    def respond(self, identifier, *, action, expected_revision, operation_id):
        operation_id = _operation(operation_id)
        request_hash = digest([self.actor, action, expected_revision])
        old = self.store.get(identifier)
        if not old or self.actor not in {old["owner"], old["recipient"]}:
            raise BundleDenied("This handoff is unavailable.")
        self.bundles._allowed(self.actor, old["domain"], "operate")
        previous = old["operations"].get(operation_id)
        if previous:
            if previous != request_hash:
                raise RecordConflict("This response reference belongs to a different action.")
            if action == "decline":
                return {"id": identifier, "state": "declined", "revision": old["revision"],
                        "content_withheld": True, "can_accept": False, "can_withdraw": False}
            return self.get(identifier)
        self._authorize(old, write=True)
        accepted = self._accepted(old)
        if accepted:
            if action == "accept" and accepted["actor"] == self.actor and accepted["operation_id"] == operation_id and accepted["request_hash"] == request_hash:
                return self.get(identifier)
            raise RecordConflict("Responsibility was already accepted; the former owner cannot revoke the recipient's task.")
        def mutate(row):
            self._authorize(row, write=True)
            if row["state"] != "offered" or self._accepted(row):
                raise RecordConflict("This handoff is no longer awaiting a response.")
            if action == "accept" and self.actor == row["recipient"]:
                row["acceptance"] = self._accept(row, operation_id, request_hash)
                row["state"] = "accepted"
            elif action == "withdraw" and self.actor == row["owner"]:
                row["state"] = "withdrawn"
            elif action == "decline" and self.actor == row["recipient"]:
                row["state"] = "declined"
            else:
                raise BundleDenied("Only the sender can withdraw and only the named recipient can accept or decline.")
            row["operations"][operation_id] = request_hash
        self.store.update(identifier, mutate, expected_revision=expected_revision, actor=self.actor, action="handoff_" + action)
        if action == "decline":
            return {"id": identifier, "state": "declined", "revision": expected_revision + 1,
                    "content_withheld": True, "can_accept": False, "can_withdraw": False}
        return self.get(identifier)

    def _review_current(self, row):
        p = row["preview"]
        if p["expires_at"] <= self.store.authoritative_time():
            raise RecordConflict("The handoff expired. Ask the sender for a fresh offer.")
        bundle = self.bundles.get(p["bundle_id"])
        if bundle["revision"] != p["bundle_revision"] or bundle["stale"] or bundle["status"] != "shared":
            raise RecordConflict("The selected bundle changed or was revoked. Review a fresh offer.")
        self.bundles._allowed(row["owner"], row["domain"], "operate")
        self.bundles._allowed(row["recipient"], row["domain"], "operate")
        root, ids = self._boundary(p["source_id"], row["owner"])
        if root != p["root_id"] or ids != p["closed_task_ids"]:
            raise RecordConflict("The source conversation or its subtasks changed. Review a fresh offer.")
        return bundle

    def _accept(self, row, operation_id, request_hash):
        p = row["preview"]
        with ExitStack() as stack:
            for goal_id in p["closed_task_ids"]:
                stack.enter_context(lease(self.world, goal_id))
            bundle = self._review_current(row)
            # All native starts also take these leases before reading closure.
            # The world transaction is the authoritative acceptance receipt.
            store = SubmissionStore(self.world)
            with store.transaction("chat-thread:" + str(p["root_id"])) as connection:
                def execute(sql, args=()):
                    return store.execute(connection, sql, args)
                if not store.sqlite:
                    execute("SELECT pg_advisory_xact_lock(?)", (71940242,))
                    for goal_id in p["closed_task_ids"]:
                        execute("SELECT id FROM goals WHERE id=? FOR UPDATE", (goal_id,))
                # Repeat after native tree/chat mutation fences are held.
                self._review_current(row)
                require_open(self.world, p["root_id"], execute=execute, decode=store.open)
                successor = self._successor(execute, store, row, bundle)
                receipt = {"handoff_id": row["id"], "source_id": p["source_id"], "root_id": p["root_id"],
                           "successor_id": successor, "original_author": row["owner"], "actor": self.actor,
                           "operation_id": operation_id, "request_hash": request_hash, "max_dollars": p["max_dollars"],
                           "source_version": p["source_version"], "accepted_at": time.time()}
                _record(execute, store.seal, p["root_id"], "handoff_closed", row["id"], row["owner"], request_hash, receipt)
                _record(execute, store.seal, successor, "handoff_lineage", row["id"], self.actor, request_hash, receipt)
                return receipt

    def _successor(self, execute, store, row, bundle):
        p, now = row["preview"], time.time()
        description = (p["instruction"] + "\n\nSender-declared pending commitments:\n" + p["commitments"] +
                       "\n\nOnly explicitly selected evidence is attached. Re-select your own authorized connections and knowledge sources before work that needs them.")
        columns = "title,description,status,created_at,updated_at,owner,domain,result"
        values = [store.seal(p["title"]), store.seal(description), "blocked", now, now, row["recipient"], row["domain"],
                  store.seal("Handoff accepted. Review the selected evidence and your current permissions, then explicitly resume to start. No model work has started.")]
        if not store.sqlite:
            columns += ",tenant_id"
            values.append(store.tenant)
        cursor = execute("INSERT INTO goals(" + columns + ") VALUES(" + ",".join("?" for _ in values) + ") RETURNING id", tuple(values))
        goal_id = int(cursor.fetchone()[0])
        for index, (item, content) in enumerate(self._prepared_items(bundle), 1):
            self._copy_item(execute, store, goal_id, index, item, content, now)
        return goal_id

    @staticmethod
    def _copy_item(execute, store, goal_id, index, item, content, now):
        from . import attachments
        if item["kind"] != "evidence":
            text = content.decode("utf-8")
            execute("INSERT INTO artifacts(goal_id,kind,title,content,version,created_at) VALUES(?,?,?,?,?,?)",
                    (goal_id, "markdown", item["title"], store.seal(text), 1, now))
            filename, mime = f"selected-{index}.md", "text/markdown"
        else:
            filename, mime = item["title"], item["source"]["mime"]
        saved = attachments.store(goal_id, filename, mime, content)
        execute("INSERT INTO attachments(goal_id,filename,mime,size_bytes,sha256,path,created_at) VALUES(?,?,?,?,?,?,?)",
                (goal_id, saved.filename, saved.mime, saved.size_bytes, saved.sha256, str(saved.path), now))
