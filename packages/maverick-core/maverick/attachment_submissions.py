"""Transactional submission receipts and serialized attachment quota admission.

Files are staged separately. A durable draft explains any interrupted file/DB
boundary; only admitted submissions may claim execution. Both backends use one
transaction per operation, including pooled PostgreSQL.
"""
from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass

SQLITE_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS attachment_submissions ("
    "submission_key TEXT PRIMARY KEY, tenant_id TEXT, owner TEXT NOT NULL, "
    "goal_id INTEGER NOT NULL UNIQUE REFERENCES goals(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, "
    "state TEXT NOT NULL, detail TEXT NOT NULL, updated_at REAL NOT NULL)"
)
POSTGRES_SCHEMA = SQLITE_SCHEMA.replace("updated_at REAL", "updated_at DOUBLE PRECISION")


class SubmissionConflict(ValueError):
    pass


def _preparation_inputs(status, result, marker):
    if status not in {"draft", "blocked"} or (result is not None and not isinstance(result, str)):
        raise SubmissionConflict("Choose a draft or an explicitly prepared, unstarted task")
    if marker is not None and (
            not isinstance(marker, dict) or set(marker) != {"channel", "key"}
            or any(not isinstance(value, str) or not value or len(value) > 200
                   or any(ord(char) < 32 for char in value) for value in marker.values())):
        raise SubmissionConflict("Use the exact original task preparation identity")


@dataclass(frozen=True)
class AttachmentAdmission:
    """Metadata admission preserves an existing stored path verbatim."""

    filename: str
    mime: str
    size_bytes: int
    sha256: str
    path: str


class SubmissionStore:
    def __init__(self, world):
        from .paths import current_tenant_id_strict
        from .world_model import WorldModel, _dec_field, _enc_field

        self.world = world
        self.sqlite = isinstance(world, WorldModel)
        self._context_tenant = current_tenant_id_strict()
        self.tenant = None
        self.seal, self.open = _enc_field, _dec_field
        if not self.sqlite:
            from .world_model_backends.postgres import (
                PostgresWorldModel,
                _active_tenant,
                _seal,
                _unseal,
            )

            if not isinstance(world, PostgresWorldModel):
                raise TypeError("Submission admission requires a supported transactional world store")
            self.tenant = _active_tenant()
            self.seal, self.open = _seal, _unseal

    @contextmanager
    def transaction(self, lock: str, *, effect_guard=None):
        self._check_context()
        if self.sqlite:
            with self.world._writing() as connection:
                if not connection.in_transaction:
                    connection.execute("BEGIN IMMEDIATE")
                if effect_guard:
                    effect_guard()
                yield connection
                if effect_guard:
                    effect_guard()
        else:
            key = int.from_bytes(hashlib.sha256(f"{self.tenant}\0{lock}".encode()).digest()[:8], "big", signed=True)
            with self.world._tx() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
                if effect_guard:
                    effect_guard()
                yield cursor
                if effect_guard:
                    effect_guard()

    def execute(self, connection, sql, parameters=()):
        if self.sqlite:
            return connection.execute(sql, parameters)
        connection.execute(sql.replace("?", "%s"), parameters)
        return connection

    def scope(self, column="tenant_id"):
        self._check_context()
        return (f"{column} IS NULL", ()) if self.tenant is None else (f"{column} = ?", (self.tenant,))

    def _check_context(self):
        from .paths import current_tenant_id_strict

        if current_tenant_id_strict() != self._context_tenant:
            raise SubmissionConflict("Submission tenant context changed; rebuild its authority-bound store")

    def _receipt(self, connection, key):
        scope, values = self.scope()
        row = self.execute(connection, "SELECT goal_id, fingerprint, state, detail FROM attachment_submissions "
                           f"WHERE submission_key = ? AND {scope}", (key, *values)).fetchone()
        if row is None:
            return None
        return {"key": key, "goal_id": int(row[0]), "fingerprint": row[1], "state": row[2],
                "detail": json.loads(self.open(row[3]))}

    def token_key(self, token, owner):
        if not isinstance(token, str) or not 1 <= len(token) <= 200 or any(ord(c) < 32 for c in token):
            raise SubmissionConflict("Invalid submission key")
        return hashlib.sha256(json.dumps([self.tenant, owner, token], separators=(",", ":")).encode()).hexdigest()

    def lookup(self, *, token, owner):
        """Read an exact owner/tenant receipt without admitting or retrying work."""
        key = self.token_key(token, owner)
        scope, values = self.scope()
        sql = "SELECT goal_id,fingerprint,state,detail FROM attachment_submissions "
        sql += f"WHERE submission_key=? AND owner=? AND {scope}"
        if self.sqlite:
            row = self.world._read_one(sql, (key, owner, *values))
        else:
            with self.world._tx() as cursor:
                row = self.execute(cursor, sql, (key, owner, *values)).fetchone()
        if row is None:
            return None
        return {"key": key, "goal_id": int(row[0]), "fingerprint": row[1], "state": row[2],
                "detail": json.loads(self.open(row[3]))}

    def create(self, *, token, fingerprint, owner, title, description, manifest,
               parent_id=None, domain="", project_id=None, kind="chat",
               chat_text=None, chat_root_id=None, connection_references=None,
               chat_prior=(), attachment_records=(), submission_detail=None, before_create=None,
               initial_status="draft", initial_result=None, processed_message=None, effect_guard=None):
        from .template_connections import packed
        _preparation_inputs(initial_status, initial_result, processed_message)
        selection = packed(owner, connection_references or [])
        key = self.token_key(token, owner)
        with self.transaction("submission:" + key, effect_guard=effect_guard) as connection:
            prior = self._receipt(connection, key)
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise SubmissionConflict("Submission key already belongs to different content")
                prior["created"] = False
                return prior
            if before_create is not None:
                before_create(connection)
            self._prepared_marker(connection, processed_message)
            chat = None
            if chat_text is not None:
                from .chat_threads import ChatThreads

                chat = ChatThreads(self.world)
                if chat_root_id is not None:
                    if parent_id != chat_root_id:
                        raise SubmissionConflict("Chat parent does not match its root")
                    chat.require_idle(connection, chat_root_id, owner)
            now = time.time()
            if parent_id is not None:
                parent_sql, parent_values = "SELECT id FROM goals WHERE id=?", (parent_id,)
                if not self.sqlite:
                    scope, scoped_values = self.scope()
                    parent_sql += " AND " + scope
                    parent_values += scoped_values
                if self.execute(connection, parent_sql, parent_values).fetchone() is None:
                    raise SubmissionConflict("Parent task is unavailable in this tenant")
            columns = "parent_id,title,description,status,created_at,updated_at,owner,domain,project_id,connection_selection"
            values = [parent_id, self.seal(title), self.seal(description), initial_status, now, now, owner, domain, project_id, self.seal(selection)]
            if initial_result is not None:
                columns += ",result"
                values.append(self.seal(initial_result))
            if not self.sqlite:
                columns += ",tenant_id"
                values.append(self.tenant)
            sql = f"INSERT INTO goals({columns}) VALUES({','.join('?' for _ in values)})"
            cursor = self.execute(connection, sql + ("" if self.sqlite else " RETURNING id"), tuple(values))
            goal_id = int(cursor.lastrowid if self.sqlite else cursor.fetchone()[0])
            detail = {"manifest": manifest, "kind": kind,
                      "message": ("Pilot task prepared; no work has started. Freeze its pilot plan before starting it separately."
                                  if initial_status == "blocked" else "Submission admitted as a draft; preparing attachments.")}
            if processed_message is not None:
                detail["processed_message"] = dict(processed_message)
            if submission_detail:
                if set(submission_detail) & set(detail):
                    raise SubmissionConflict("Submission metadata cannot replace native admission state")
                detail.update(submission_detail)
            if chat is not None:
                detail["conversation_id"] = chat.record(connection, root_id=chat_root_id or goal_id,
                                                       goal_id=goal_id, owner=owner, text=chat_text,
                                                       prior=chat_prior)
            if attachment_records:
                self.admit(goal_id, attachment_records, connection=connection, verify_existing=True)
            self._prepared_marker(connection, processed_message, goal_id=goal_id, now=now)
            self.execute(connection, "INSERT INTO attachment_submissions "
                         "(submission_key,tenant_id,owner,goal_id,fingerprint,state,detail,updated_at) "
                         "VALUES(?,?,?,?,?,?,?,?)",
                         (key, self.tenant, owner, goal_id, fingerprint,
                          "admitted" if initial_status == "blocked" else "draft", self.seal(json.dumps(detail)), now))
            result = {**self._receipt(connection, key), "created": True}
            if before_create is not None:
                before_create(connection)
            return result

    def _prepared_marker(self, connection, marker, *, goal_id=None, now=None):
        if marker is None:
            return
        if goal_id is None:
            scope, scoped = ("1=1", ()) if self.sqlite else self.scope()
            existing = self.execute(connection, "SELECT goal_id FROM processed_messages "
                f"WHERE channel=? AND external_id=? AND {scope}",
                (marker["channel"], marker["key"], *scoped)).fetchone()
            if existing is not None:
                raise SubmissionConflict("This original task preparation is already retained. Read its original outcome; no new task was created.")
            return
        columns = "channel,external_id,goal_id,seen_at"
        values = [marker["channel"], marker["key"], goal_id, now]
        if not self.sqlite:
            columns += ",tenant_id"
            values.append(self.tenant)
        self.execute(connection, f"INSERT INTO processed_messages({columns}) "
            f"VALUES({','.join('?' for _ in values)})", tuple(values))

    def update(self, key, *, state, message, coverage=None, effect_guard=None):
        if state not in {"draft", "admitted", "ready", "rejected"}:
            raise ValueError("Invalid submission state")
        with self.transaction("submission:" + key, effect_guard=effect_guard) as connection:
            receipt = self._receipt(connection, key)
            if receipt is None:
                raise LookupError("Unknown submission")
            if receipt["state"] in {"dispatching", "dispatched"}:
                return receipt
            detail = {**receipt["detail"], "message": message}
            if coverage is not None:
                detail["coverage"] = coverage
            self.execute(connection, "UPDATE attachment_submissions SET state=?,detail=?,updated_at=? WHERE submission_key=?",
                         (state, self.seal(json.dumps(detail)), time.time(), key))
            # Preparation is a receipt state, not an answer. Writing it to
            # goals.result makes the chat render it as Lightwork's response.
            return self._receipt(connection, key)

    def claim_dispatch(self, key, *, effect_guard=None):
        with self.transaction("submission:" + key, effect_guard=effect_guard) as connection:
            receipt = self._receipt(connection, key)
            if receipt is None or receipt["state"] != "ready":
                return False
            from .chat_threads import ChatThreads

            chat = ChatThreads(self.world)
            binding = chat.binding(receipt["goal_id"], connection=connection)
            if binding is not None:
                chat.require_idle(connection, binding.root_id, binding.owner, except_goal=receipt["goal_id"])
            changed = self.execute(connection, "UPDATE goals SET status='pending',updated_at=? WHERE id=? AND status='draft'",
                                   (time.time(), receipt["goal_id"]))
            if changed.rowcount != 1:
                return False
            self.execute(connection, "UPDATE attachment_submissions SET state='dispatching',updated_at=? WHERE submission_key=?",
                         (time.time(), key))
            return True

    def record_dispatch_intent(self, key, intent, *, effect_guard=None):
        """Retain reviewed runner context before the cross-store dispatch boundary."""
        with self.transaction("submission:" + key, effect_guard=effect_guard) as connection:
            receipt = self._receipt(connection, key)
            if receipt is None:
                raise LookupError("Unknown submission")
            if receipt["state"] in {"dispatching", "dispatched"}:
                return
            detail = {**receipt["detail"], "dispatch_intent": intent}
            self.execute(connection, "UPDATE attachment_submissions SET detail=?,updated_at=? WHERE submission_key=?",
                         (self.seal(json.dumps(detail)), time.time(), key))

    def for_goal(self, goal_id):
        scope, values = self.scope()
        sql = "SELECT submission_key,goal_id,fingerprint,state,detail FROM attachment_submissions "
        sql += f"WHERE goal_id=? AND {scope}"
        if self.sqlite:
            row = self.world._read_one(sql, (goal_id, *values))
        else:
            with self.world._tx() as cursor:
                row = self.execute(cursor, sql, (goal_id, *values)).fetchone()
        if row is None:
            return None
        return {"key": row[0], "goal_id": int(row[1]), "fingerprint": row[2], "state": row[3],
                "detail": json.loads(self.open(row[4]))}

    def admit(self, goal_id, records, *, publish=None, connection=None, verify_existing=False):
        from .attachments import MAX_FILE_BYTES, MAX_GOAL_BYTES, AttachmentRejected

        if not records:
            return []
        if len(records) > 128:
            raise AttachmentRejected("Too many attachments in one batch")
        with (self.transaction(f"attachments:{goal_id}") if connection is None else nullcontext(connection)) as connection:
            params = (goal_id,)
            sql = "SELECT id FROM goals WHERE id=?"
            if not self.sqlite:
                scope, values = self.scope()
                sql += " AND " + scope + " FOR UPDATE"
                params += values
            if self.execute(connection, sql, params).fetchone() is None:
                raise AttachmentRejected("Unknown goal for the active tenant")
            identities = [(r.filename, r.mime, int(r.size_bytes), r.sha256) for r in records]
            total = int(self.execute(connection, "SELECT COALESCE(SUM(size_bytes),0) FROM attachments WHERE goal_id=?",
                                     (goal_id,)).fetchone()[0])
            terms = " OR ".join("(filename=? AND mime=? AND size_bytes=? AND sha256=?)" for _ in identities)
            values = (goal_id, *(value for identity in identities for value in identity))
            existing = self.execute(connection, "SELECT id,filename,mime,size_bytes,sha256,path FROM attachments "
                                    f"WHERE goal_id=? AND ({terms})", values).fetchall()
            known = {(row[1], row[2], int(row[3]), row[4]): int(row[0]) for row in existing}
            paths = {(row[1], row[2], int(row[3]), row[4]): row[5] for row in existing}
            novel = set(identities) - known.keys()
            if any(not 0 < item[2] <= MAX_FILE_BYTES for item in identities) or total + sum(item[2] for item in novel) > MAX_GOAL_BYTES:
                raise AttachmentRejected("Per-goal attachment quota exceeded")
            ids = []
            for record, identity in zip(records, identities, strict=True):
                if identity not in known:
                    if publish is not None:
                        record = publish(record)
                    sql = "INSERT INTO attachments(goal_id,filename,mime,size_bytes,sha256,path,created_at) VALUES(?,?,?,?,?,?,?)"
                    cursor = self.execute(connection, sql + ("" if self.sqlite else " RETURNING id"),
                                          (goal_id, *identity[:3], identity[3], str(record.path), time.time()))
                    known[identity] = int(cursor.lastrowid if self.sqlite else cursor.fetchone()[0])
                    paths[identity] = str(record.path)
                elif verify_existing:
                    from pathlib import Path

                    from .attachments import _verify_stored_attachment
                    try:
                        _verify_stored_attachment(Path(paths[identity]), identity[3])
                    except (OSError, AttachmentRejected):
                        if publish is None:
                            raise
                        repaired = publish(record)
                        self.execute(connection, "UPDATE attachments SET path=? WHERE id=? AND goal_id=?",
                                     (str(repaired.path), known[identity], goal_id))
                ids.append(known[identity])
            return ids
