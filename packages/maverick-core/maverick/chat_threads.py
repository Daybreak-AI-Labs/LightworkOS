"""Durable web-chat membership and serialized turn admission.

A goal's parent alone is not a conversation binding: workflow children also use
parent_id. Only a user turn in the owner's canonical web conversation binds it.
All new turn admission and chat restarts share a database transaction fence.
"""
from __future__ import annotations

import hashlib
import time
from contextlib import contextmanager
from dataclasses import dataclass

from .attachment_submissions import SubmissionConflict, SubmissionStore

_TERMINAL = ("done", "completed", "failed", "cancelled", "blocked", "error")
_BUSY = ("Lightwork is still working on the previous message. "
         "Wait for it to finish, or stop it, before sending the next one.")


@dataclass(frozen=True)
class ChatBinding:
    root_id: int
    conversation_id: int
    owner: str


@dataclass(frozen=True)
class ChatRestart:
    admitted: bool
    conversation_id: int | None


def question_version(question_id, asked_at, question):
    import json

    return hashlib.sha256(json.dumps([int(question_id), float(asked_at), str(question)],
                                     ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


class ChatThreads:
    def __init__(self, world):
        self.store = SubmissionStore(world)
        self.world = world

    def _scope(self, alias):
        if self.store.sqlite:
            return "1=1", ()
        return self.store.scope(f"{alias}.tenant_id")

    def _rows(self, sql, values=(), *, connection=None):
        self.store._check_context()
        if connection is None:
            return self.world.query(sql, values)
        return self.store.execute(connection, sql, values).fetchall()

    def binding(self, goal_id, *, connection=None):
        gs, gv = self._scope("g")
        rs, rv = self._scope("r")
        cs, cv = self._scope("c")
        ms, mv = self._scope("m")
        rows = self._rows(
            "SELECT r.id,c.id,r.owner FROM goals g JOIN goals r "
            "ON r.id=COALESCE(g.parent_id,g.id) AND r.parent_id IS NULL AND r.owner=g.owner "
            "JOIN conversations c ON c.channel='web' AND c.user_id="
            "(CASE WHEN r.owner='' THEN 'local' ELSE r.owner END || '/' || CAST(r.id AS TEXT)) "
            "WHERE g.id=? AND EXISTS (SELECT 1 FROM turns t JOIN goals m ON m.id=t.goal_id WHERE "
            "t.conversation_id=c.id AND t.role='user' AND m.owner=r.owner "
            "AND (m.id=g.id OR (g.id=r.id AND m.parent_id=r.id)) "
            f"AND {ms}) "
            f"AND {gs} AND {rs} AND {cs}",
            (goal_id, *mv, *gv, *rv, *cv), connection=connection,
        )
        return ChatBinding(int(rows[0][0]), int(rows[0][1]), rows[0][2]) if rows else None

    def members(self, binding, *, connection=None, limit=None):
        gs, gv = self._scope("g")
        tail = " LIMIT ?" if limit is not None else ""
        capped = (max(1, int(limit)),) if limit is not None else ()
        # SQLite: the unary "+" keeps the planner off idx_goals_owner_created_history,
        # which would scan and sort every goal the owner has to find one root's
        # children; the id and parent_id indexes reach them directly. The owner
        # predicate itself is unchanged.
        owner = "+g.owner=?" if self.store.sqlite else "g.owner=?"
        return self._rows(
            "SELECT g.id,g.status FROM goals g WHERE (g.id=? OR g.parent_id=?) "
            f"AND {owner} AND EXISTS (SELECT 1 FROM turns t WHERE t.goal_id=g.id "
            "AND t.conversation_id=? AND t.role='user') "
            f"AND {gs} ORDER BY g.id DESC{tail}",
            (binding.root_id, binding.root_id, binding.owner, binding.conversation_id, *gv, *capped),
            connection=connection,
        )

    def latest(self, goal_id):
        binding = self.binding(goal_id)
        members = self.members(binding, limit=1) if binding else []
        return int(members[0][0]) if members else int(goal_id)

    def history(self, goal_id, *, before_id=None, limit=50):
        """Page authorized earlier turns relative to the selected task."""
        from .world_model import Turn

        binding = self.binding(goal_id)
        if binding is None:
            return [], False
        gs, gv = self._scope("g")
        cs, cv = self._scope("c")
        cursor = " AND t.id < ?" if before_id is not None else ""
        cursor_values = (int(before_id),) if before_id is not None else ()
        size = max(1, min(100, int(limit)))
        receipt = self.store.for_goal(goal_id) if goal_id == binding.root_id else None
        copied_root = goal_id if receipt and receipt["detail"].get("alternative") else -1
        rows = self._rows(
            "SELECT t.id,t.conversation_id,t.goal_id,t.role,t.content,t.ts "
            "FROM turns t JOIN goals g ON g.id=t.goal_id "
            "JOIN conversations c ON c.id=t.conversation_id "
            "WHERE t.conversation_id=? AND g.owner=? AND (g.id=? OR g.parent_id=?) "
            f"AND (g.id < ? OR (g.id=? AND t.id < (SELECT MAX(u.id) FROM turns u "
            "WHERE u.conversation_id=t.conversation_id AND u.goal_id=g.id AND u.role='user'))) "
            f"AND {gs} AND {cs}{cursor} "
            "AND t.role IN ('user','assistant') ORDER BY t.id DESC LIMIT ?",
            (binding.conversation_id, binding.owner, binding.root_id, binding.root_id,
             goal_id, copied_root, *gv, *cv, *cursor_values, size + 1),
        )
        return list(reversed([Turn(r[0], r[1], r[2], r[3], self.store.open(r[4]), r[5])
                              for r in rows[:size]])), len(rows) > size

    def selected_turns(self, goal_id, *, turn_id=None):
        """Persisted web turns for this member, scoped to its canonical thread."""
        from .world_model import Turn

        binding = self.binding(goal_id)
        if binding is None:
            return []
        gs, gv = self._scope("g")
        cs, cv = self._scope("c")
        selected = " AND t.id=?" if turn_id is not None else ""
        selected_values = (int(turn_id),) if turn_id is not None else ()
        rows = self._rows(
            "SELECT t.id,t.conversation_id,t.goal_id,t.role,t.content,t.ts "
            "FROM turns t JOIN goals g ON g.id=t.goal_id "
            "JOIN conversations c ON c.id=t.conversation_id "
            "WHERE t.conversation_id=? AND t.goal_id=? AND g.owner=? "
            "AND (g.id=? OR g.parent_id=?) "
            f"AND {gs} AND {cs} AND t.role IN ('user','assistant'){selected} "
            "ORDER BY t.id LIMIT 101",
            (binding.conversation_id, goal_id, binding.owner, binding.root_id,
             binding.root_id, *gv, *cv, *selected_values),
        )
        if len(rows) > 100:
            raise ValueError("The selected message has too many turns to share.")
        return [Turn(r[0], r[1], r[2], r[3], self.store.open(r[4]), r[5])
                for r in rows]

    def _lock(self, connection, root_id):
        if not self.store.sqlite:
            key = int.from_bytes(hashlib.sha256(
                f"{self.store.tenant}\0chat-thread:{root_id}".encode()).digest()[:8], "big", signed=True)
            connection.execute("SELECT pg_advisory_xact_lock(%s)", (key,))

    def require_idle(self, connection, root_id, owner, *, except_goal=None):
        self._lock(connection, root_id)
        self._require_open(connection, root_id)
        scope, values = self._scope("g")
        rows = self._rows("SELECT g.status FROM goals g WHERE g.id=? AND g.parent_id IS NULL "
                          f"AND g.owner=? AND {scope}", (root_id, owner, *values), connection=connection)
        if not rows:
            raise SubmissionConflict("Chat is unavailable for this owner and tenant")
        if except_goal != root_id and rows[0][0] not in _TERMINAL:
            raise SubmissionConflict(_BUSY)
        binding = self.binding(root_id, connection=connection)
        if binding and any(int(row[0]) != except_goal and row[1] not in _TERMINAL
                           for row in self.members(binding, connection=connection)):
            raise SubmissionConflict(_BUSY)

    def record(self, connection, *, root_id, goal_id, owner, text, prior=()):
        """Bind a newly admitted draft inside the goal/receipt transaction."""
        now = time.time()
        identity = f"{owner or 'local'}/{root_id}"
        columns = "channel,user_id,created_at,last_seen"
        values = ["web", identity, now, now]
        conflict = "channel,user_id"
        if not self.store.sqlite:
            columns += ",tenant_id"
            values.append(self.store.tenant)
            conflict = "(COALESCE(tenant_id, '')),channel,user_id"
        self.store.execute(connection, f"INSERT INTO conversations({columns}) "
                           f"VALUES({','.join('?' for _ in values)}) ON CONFLICT ({conflict}) "
                           "DO UPDATE SET last_seen=excluded.last_seen", tuple(values))
        scope, scoped = self._scope("c")
        conversation_id = int(self._rows("SELECT c.id FROM conversations c WHERE "
                                        f"c.channel='web' AND c.user_id=? AND {scope}",
                                        (identity, *scoped), connection=connection)[0][0])
        if prior:
            if root_id != goal_id or len(prior) > 100:
                raise SubmissionConflict("Copied history requires a new bounded conversation")
            for turn in prior:
                if set(turn) != {"role", "content", "at"} or turn["role"] not in {"user", "assistant"}:
                    raise SubmissionConflict("Copied message history is invalid")
                self.store.execute(connection, "INSERT INTO turns(conversation_id,goal_id,role,content,ts) "
                    "VALUES(?,?,?,?,?)", (conversation_id, goal_id, turn["role"], self.store.seal(turn["content"]), turn["at"]))
        if root_id != goal_id and self.binding(root_id, connection=connection) is None:
            # Explicitly replying to a pre-chat task opens its conversation.
            # Merely viewing/resuming an ordinary API goal never does this.
            row = self._rows("SELECT title,description,result FROM goals WHERE id=?", (root_id,),
                             connection=connection)[0]
            title, description = self.store.open(row[0]), self.store.open(row[1]) or ""
            root_text = title if not description.strip() or description.strip() == title.strip() else f"{title}\n\n{description}"
            self.store.execute(connection, "INSERT INTO turns(conversation_id,goal_id,role,content,ts) "
                               "VALUES(?,?,'user',?,?)", (conversation_id, root_id, self.store.seal(root_text), now))
            result = self.store.open(row[2])
            prior_answer = self._rows("SELECT 1 FROM turns WHERE conversation_id=? AND goal_id=? "
                                      "AND role='assistant' LIMIT 1", (conversation_id, root_id), connection=connection)
            if result and not prior_answer:
                self.store.execute(connection, "INSERT INTO turns(conversation_id,goal_id,role,content,ts) "
                                   "VALUES(?,?,'assistant',?,?)", (conversation_id, root_id, self.store.seal(result), now))
        self.store.execute(connection, "INSERT INTO turns(conversation_id,goal_id,role,content,ts) "
                           "VALUES(?,?,'user',?,?)", (conversation_id, goal_id, self.store.seal(text), now))
        return conversation_id

    @contextmanager
    def _restart_transaction(self, goal_id):
        scope, values = self._scope("g")
        sql = f"SELECT g.parent_id,g.owner,g.status FROM goals g WHERE g.id=? AND {scope}"
        before = self._rows(sql, (goal_id, *values))
        if not before:
            raise SubmissionConflict("Task is unavailable in this tenant")
        root_id, owner = int(before[0][0] or goal_id), before[0][1]
        with self.store.transaction(f"chat-thread:{root_id}") as connection:
            lock = "" if self.store.sqlite else " FOR UPDATE"
            current = self._rows(sql + lock, (goal_id, *values), connection=connection)
            if not current or (int(current[0][0] or goal_id), current[0][1]) != (root_id, owner):
                raise SubmissionConflict("Task membership changed; reload before retrying")
            binding = self.binding(goal_id, connection=connection)
            yield connection, binding, current[0][2]

    def _require_open(self, connection, goal_id):
        from .goal_mutations import GoalMutationConflict
        from .human_conversation_handoffs import require_ai_open
        from .task_handoffs import require_open
        try:
            require_ai_open(self.world, goal_id,
                            execute=lambda sql, args: self.store.execute(connection, sql, args),
                            decode=self.store.open)
            require_open(self.world, goal_id,
                         execute=lambda sql, args: self.store.execute(connection, sql, args),
                         decode=self.store.open)
        except GoalMutationConflict as exc:
            raise SubmissionConflict(str(exc)) from exc

    def _pending(self, connection, goal_id):
        self._require_open(connection, goal_id)
        advance = "MAX" if self.store.sqlite else "GREATEST"
        scope, values = self._scope("goals")
        changed = self.store.execute(connection, "UPDATE goals SET status='pending',completed_at=NULL,"
                                     f"updated_at={advance}(updated_at+0.000001,?) WHERE id=? "
                                     f"AND status IN ('blocked','cancelled','failed') AND {scope}",
                                     (time.time(), goal_id, *values))
        if changed.rowcount != 1:
            raise SubmissionConflict("This message is already running or cannot be resumed")
        self.store.execute(connection, "DELETE FROM signoffs WHERE goal_id=?", (goal_id,))

    def resume(self, goal_id):
        """Reserve a restart, returning only an existing conversation binding.

        Even an ordinary goal takes the root fence: its first explicit chat
        reply can establish membership concurrently with this restart.
        """
        with self._restart_transaction(goal_id) as (connection, binding, _status):
            if binding is not None:
                self.require_idle(connection, binding.root_id, binding.owner, except_goal=goal_id)
            self._pending(connection, goal_id)
        return binding.conversation_id if binding is not None else None

    def answer_with_evidence(self, goal_id, question_id, text, *, expected_question,
                             operation_id, actor, request_hash, records, publish,
                             require_admission, require_authority):
        """Admit ready evidence, answer and last-question restart in one transaction.

        Evidence publishers run only after the exact question and fresh owner
        authority pass. Exact receipt replay never publishes or reserves again.
        """
        from .goal_mutations import _receipt, _record

        with self._restart_transaction(goal_id) as (connection, binding, status):
            require_authority()
            def execute(sql, args=()):
                return self.store.execute(connection, sql, args)
            prior = _receipt(execute, self.store.open, goal_id, "clarification", operation_id, actor, request_hash)
            if prior is not None:
                return prior
            if status in {"cancelled", "done", "completed", "failed", "error"}:
                raise SubmissionConflict("This task is no longer waiting for an answer. Review it before restarting.")
            questions = self._rows("SELECT id,asked_at,question FROM questions WHERE goal_id=? AND answer IS NULL",
                                   (goal_id,), connection=connection)
            question = next((row for row in questions if int(row[0]) == question_id), None)
            if question is None or question_version(question[0], question[1], self.store.open(question[2])) != expected_question:
                raise SubmissionConflict("The question changed or was answered. Your draft and selected files have been kept.")
            restart = status == "blocked" and len(questions) == 1
            if restart:
                if binding is not None:
                    self.require_idle(connection, binding.root_id, binding.owner, except_goal=goal_id)
                require_admission()
            # Identical filenames with different evidence would misbind companion text.
            existing = execute("SELECT filename,sha256 FROM attachments WHERE goal_id=?", (goal_id,)).fetchall()
            names = {row[0]: row[1] for row in existing}
            for record in records:
                if record.filename in names and names[record.filename] != record.sha256:
                    raise SubmissionConflict("A different file already uses this name. Rename the selected file before answering.")
                names[record.filename] = record.sha256
            attachment_ids = list(dict.fromkeys(self.store.admit(goal_id, records, publish=publish, connection=connection, verify_existing=True)))
            changed = execute("UPDATE questions SET answer=?,answered_at=? WHERE id=? AND goal_id=? AND answer IS NULL",
                              (self.store.seal(text), time.time(), question_id, goal_id))
            if changed.rowcount != 1:
                raise SubmissionConflict("The question changed; reload before answering")
            if restart:
                self._pending(connection, goal_id)
            result = {"received": True, "goal_id": goal_id, "question_id": question_id,
                      "question_version": expected_question, "attachment_ids": attachment_ids,
                      "admitted": restart, "conversation_id": binding.conversation_id if binding is not None else None,
                      "operation_id": operation_id, "replayed": False}
            _record(execute, self.store.seal, goal_id, "clarification", operation_id, actor, request_hash, result)
        return result

    def answer(self, goal_id, question_id, text, *, require_admission):
        """Save a clarification and reserve its last-question restart atomically.

        A refused restart leaves the final question open, so the client can
        retry the same answer after the newer turn or admission hold clears.
        """
        with self._restart_transaction(goal_id) as (connection, binding, status):
            if status in {"cancelled", "done", "completed", "failed", "error"}:
                raise SubmissionConflict("This task is no longer waiting for an answer. Review it before restarting.")
            questions = self._rows("SELECT id FROM questions WHERE goal_id=? AND answer IS NULL",
                                   (goal_id,), connection=connection)
            if question_id not in {int(row[0]) for row in questions}:
                raise LookupError("no such open question for this goal")
            restart = status == "blocked" and len(questions) == 1
            if restart:
                if binding is not None:
                    self.require_idle(connection, binding.root_id, binding.owner, except_goal=goal_id)
                require_admission()
                self._pending(connection, goal_id)
            changed = self.store.execute(connection, "UPDATE questions SET answer=?,answered_at=? "
                                         "WHERE id=? AND goal_id=? AND answer IS NULL",
                                         (self.store.seal(text), time.time(), question_id, goal_id))
            if changed.rowcount != 1:
                raise SubmissionConflict("The question changed; reload before answering")
        return ChatRestart(restart, binding.conversation_id if binding is not None else None)
