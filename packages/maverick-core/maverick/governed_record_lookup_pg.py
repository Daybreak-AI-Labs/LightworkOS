"""Exact-key projections committed with their source in the governed PG table.

Derived rows reuse the established encrypted table, schema validation and forced
tenant RLS. No second authority or nested connection lease is introduced.
"""
from __future__ import annotations

import hashlib

from .governed_record_lookup import RecordLookupUnavailable, batch_limit, lookup_digest


class PostgresRecordLookup:
    def __init__(self, backend, spec):
        self.backend, self.spec = backend, spec
        self.namespace = "lookup-" + lookup_digest(backend.namespace + "\0" + spec.name)[:32]

    def prepare(self, cursor, tenant):
        # Tenant is part of the lock identity: unrelated tenants need not wait.
        key = int.from_bytes(hashlib.sha256((tenant + self.namespace).encode()).digest()[:8], "big", signed=True)
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (key,))

    def _read(self, cursor, tenant, namespace, record_id):
        from .governed_records import _row_record
        cursor.execute("SELECT revision,record_json,created_at,updated_at FROM governed_records "
                       "WHERE tenant_id=%s AND namespace=%s AND record_id=%s", (tenant, namespace, record_id))
        row = cursor.fetchone()
        return None if row is None else _row_record(row, record_id=record_id, prefix="IDX", require_encryption=True)

    def _write(self, cursor, tenant, namespace, record_id, body):
        from .governed_records import _encode_record
        # These are deterministic projections, not business revisions. The
        # source revision is carried separately and checked on every lookup.
        value = {**body, "id": record_id, "revision": 1, "created_at": 1.0, "updated_at": 1.0}
        cursor.execute("INSERT INTO governed_records VALUES (%s,%s,%s,1,%s,1,1) "
                       "ON CONFLICT (tenant_id,namespace,record_id) DO UPDATE SET record_json=EXCLUDED.record_json",
                       (tenant, namespace, record_id, _encode_record(value, require_encryption=True)))

    def _state(self, cursor, tenant):
        state = self._read(cursor, tenant, self.namespace, "IDX-state")
        if state is None:
            cursor.execute("SELECT 1 FROM governed_records WHERE tenant_id=%s AND namespace=%s LIMIT 1",
                           (tenant, self.namespace))
            phase = "clearing" if cursor.fetchone() is not None else "building"
            state = {"phase": phase, "cursor": "", "scanned": 0}
            self._write(cursor, tenant, self.namespace, "IDX-state", state)
        if state.get("phase") not in {"clearing", "building", "ready"}:
            raise RecordLookupUnavailable("record lookup migration state is invalid")
        return state

    @staticmethod
    def _record_key(record_id):
        return "IDX-" + lookup_digest(record_id)[:56]

    def _remove(self, cursor, tenant, record_id):
        reverse = self._read(cursor, tenant, self.namespace, record_id)
        if reverse is not None:
            for digest in reverse["digests"]:
                cursor.execute("DELETE FROM governed_records WHERE tenant_id=%s AND namespace=%s AND record_id=%s",
                               (tenant, self.namespace + "-" + digest, record_id))
            cursor.execute("DELETE FROM governed_records WHERE tenant_id=%s AND namespace=%s AND record_id=%s",
                           (tenant, self.namespace, record_id))

    def replace(self, cursor, tenant, source_id, source):
        state = self._state(cursor, tenant)
        if state["phase"] == "clearing":
            # Rebuild will visit current canonical rows after bounded clearing.
            # New writes must not endlessly repopulate the clearing frontier.
            return
        record_id = self._record_key(source_id)
        self._remove(cursor, tenant, record_id)
        if source is not None:
            keys = sorted(self.spec.keys(source))
            for digest in keys:
                self._write(cursor, tenant, self.namespace + "-" + digest, record_id,
                            {"source_id": source_id, "source_revision": source["revision"], "digest": digest})
            self._write(cursor, tenant, self.namespace, record_id, {"digests": keys, "source_id": source_id})

    def advance(self, cursor, tenant, *, limit=100, rebuild=False):
        from .governed_records import _row_record
        limit = batch_limit(limit)
        self.prepare(cursor, tenant)
        state = self._state(cursor, tenant)
        if rebuild:
            state = {"phase": "clearing", "cursor": "", "scanned": 0}
            self._write(cursor, tenant, self.namespace, "IDX-state", state)
        if state["phase"] == "clearing":
            cursor.execute("SELECT record_id FROM governed_records WHERE tenant_id=%s AND namespace=%s "
                           "AND record_id<>%s ORDER BY record_id LIMIT %s",
                           (tenant, self.namespace, "IDX-state", limit + 1))
            rows = cursor.fetchall()
            for (record_id,) in rows[:limit]:
                self._remove(cursor, tenant, record_id)
            if len(rows) <= limit:
                state["phase"] = "building"
            self._write(cursor, tenant, self.namespace, "IDX-state", state)
        elif state["phase"] == "building":
            cursor.execute("SELECT record_id,octet_length(record_json) FROM governed_records "
                           "WHERE tenant_id=%s AND namespace=%s AND record_id>%s ORDER BY record_id LIMIT %s",
                           (tenant, self.backend.namespace, state["cursor"], limit + 1))
            rows = cursor.fetchall()
            processed, read_bytes = 0, 0
            for source_id, size in rows[:limit]:
                if processed and read_bytes + size > 16 * 1024 * 1024:
                    break
                cursor.execute("SELECT revision,record_json,created_at,updated_at FROM governed_records "
                               "WHERE tenant_id=%s AND namespace=%s AND record_id=%s",
                               (tenant, self.backend.namespace, source_id))
                source = _row_record(cursor.fetchone(), record_id=source_id,
                                     prefix=self.backend.prefix, require_encryption=True)
                self.replace(cursor, tenant, source_id, source)
                state["cursor"], state["scanned"] = source_id, state["scanned"] + 1
                processed, read_bytes = processed + 1, read_bytes + size
                if state["scanned"] > self.spec.max_records:
                    raise RecordLookupUnavailable("record lookup source exceeds its record bound")
            if len(rows) <= processed:
                state["phase"] = "ready"
            self._write(cursor, tenant, self.namespace, "IDX-state", state)
        return {"ready": state["phase"] == "ready", "phase": state["phase"],
                "scanned": state["scanned"], "cursor": state["cursor"]}

    def lookup(self, cursor, tenant, digest):
        from .governed_records import _row_record
        if not self.advance(cursor, tenant, limit=10)["ready"]:
            return RecordLookupUnavailable("record lookup is rebuilding; retry shortly")
        cursor.execute("SELECT record_id,revision,record_json,created_at,updated_at FROM governed_records "
                       "WHERE tenant_id=%s AND namespace=%s ORDER BY record_id LIMIT 2",
                       (tenant, self.namespace + "-" + digest))
        rows = cursor.fetchall()
        if len(rows) > 1:
            return RecordLookupUnavailable("record lookup association is ambiguous")
        if not rows:
            return None
        record_id, revision, stored, created, updated = rows[0]
        mapping = _row_record((revision, stored, created, updated), record_id=record_id, prefix="IDX", require_encryption=True)
        source_id = mapping["source_id"]
        cursor.execute("SELECT revision,record_json,created_at,updated_at FROM governed_records "
                       "WHERE tenant_id=%s AND namespace=%s AND record_id=%s",
                       (tenant, self.backend.namespace, source_id))
        raw = cursor.fetchone()
        source = None if raw is None else _row_record(raw, record_id=source_id, prefix=self.backend.prefix,
                                                    require_encryption=True)
        if (source is None or source["revision"] != mapping["source_revision"]
                or mapping["digest"] != digest or digest not in self.spec.keys(source)):
            self._write(cursor, tenant, self.namespace, "IDX-state", {"phase": "clearing", "cursor": "", "scanned": 0})
            return RecordLookupUnavailable("record lookup association needs rebuilding")
        return source
