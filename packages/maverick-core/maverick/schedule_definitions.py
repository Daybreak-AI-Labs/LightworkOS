"""Durable schedule definitions sharing the queue's admission transaction.

An occurrence is immutable once admitted. Management changes the definition and
replaces only unattempted future occurrences, retaining their cancellation notes.
"""
from __future__ import annotations

import json
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS schedule_definitions (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  state TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  occurrence_cursor INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS schedule_definition_versions (
  id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  payload TEXT NOT NULL,
  state TEXT NOT NULL,
  actor TEXT NOT NULL,
  rationale TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY(id,revision)
);
"""


def register(connection, recurrence_id, kind, payload, now, *, state="active"):
    encoded = json.dumps(payload, sort_keys=True)
    inserted = connection.execute(
        "INSERT OR IGNORE INTO schedule_definitions (id,kind,payload,state,revision,created_at,updated_at) VALUES (?,?,?,?,1,?,?)",
        (recurrence_id, kind, encoded, state, now, now),
    ).rowcount
    if inserted:
        connection.execute(
            "INSERT INTO schedule_definition_versions VALUES (?,1,?,?,?,?,?)",
            (recurrence_id, encoded, state, "system", "Initial schedule definition", now),
        )


def adopt_existing(connection):
    """Adopt exact recurrence identities; never group schedules by matching text."""
    rows = connection.execute(
        "SELECT * FROM jobs WHERE recurrence_id IS NOT NULL "
        "AND recurrence_id NOT IN (SELECT id FROM schedule_definitions) ORDER BY id"
    ).fetchall()
    seen = set()
    for row in rows:
        identity = row["recurrence_id"]
        if identity in seen:
            continue
        seen.add(identity)
        states = connection.execute(
            "SELECT status,recurrence_reconcile_required FROM jobs WHERE recurrence_id=?",
            (identity,),
        ).fetchall()
        state = "parked" if any(item["recurrence_reconcile_required"] for item in states) else (
            "active" if any(item["status"] in {"pending", "running"} for item in states) else "retired"
        )
        register(connection, identity, row["kind"], json.loads(row["recurrence_payload"]),
                 row["created_at"], state=state)
        connection.execute("UPDATE schedule_definitions SET occurrence_cursor=(SELECT COALESCE(MAX(occurrence),-1)+1 FROM jobs WHERE recurrence_id=?) WHERE id=?", (identity, identity))


def recovery_evidence(connection, row):
    import hashlib

    candidates = [dict(item) for item in connection.execute(
        "SELECT * FROM jobs WHERE id>? AND kind=? AND recurrence_payload=? ORDER BY id",
        (row["id"], row["kind"], row["recurrence_payload"]),
    )]
    definition = connection.execute("SELECT * FROM schedule_definitions WHERE id=?", (row["recurrence_id"],)).fetchone()
    snapshot = [dict(row), candidates, dict(definition) if definition is not None else None]
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()


def public_definition(connection, row):
    payload = json.loads(row["payload"])
    jobs = connection.execute(
        "SELECT id,status,attempts,run_at,scheduled_at,updated_at,recurrence_reconcile_required "
        "FROM jobs WHERE recurrence_id=? ORDER BY id DESC", (row["id"],),
    ).fetchall()
    pending = [job for job in jobs if job["status"] == "pending" and job["attempts"] == 0]
    active = [job for job in jobs if job["status"] == "running" or (job["status"] == "pending" and job["attempts"] > 0)]
    state = "parked" if any(job["recurrence_reconcile_required"] for job in jobs) else row["state"]
    return {
        "id": jobs[0]["id"] if jobs else 0, "definition_id": row["id"],
        "revision": row["revision"], "state": state, "running": bool(active),
        "kind": row["kind"], "title": payload.get("title") or payload.get("template") or "Scheduled work",
        "cron": payload.get("__cron__", ""), "zone": payload.get("__tz__", ""),
        "schedule_id": payload.get("schedule_id") or row["id"],
        "next_run": min((job["run_at"] for job in pending), default=0) if state == "active" else 0,
        "history": [dict(job) for job in jobs[:50]], "history_total": len(jobs),
        "template_name": payload.get("template_name", ""), "template_version": payload.get("template_version", ""),
        "template_generation": payload.get("template_generation"),
        "owner": payload.get("owner", ""), "updated_at": row["updated_at"],
    }


def list_definitions(queue, *, owner=None):
    with queue._conn() as connection:
        rows = connection.execute("SELECT * FROM schedule_definitions ORDER BY created_at DESC,id").fetchall()
        return [public_definition(connection, row) for row in rows
                if owner is None or json.loads(row["payload"]).get("owner", "") == owner]


def _record_version(connection, row, *, payload, state, actor, rationale, now):
    revision = row["revision"] + 1
    encoded = json.dumps(payload, sort_keys=True)
    connection.execute("UPDATE schedule_definitions SET payload=?,state=?,revision=?,updated_at=? WHERE id=?",
                       (encoded, state, revision, now, row["id"]))
    connection.execute("INSERT INTO schedule_definition_versions VALUES (?,?,?,?,?,?,?)",
                       (row["id"], revision, encoded, state, actor, rationale, now))


def _future_occurrence(queue, connection, row, payload, now):
    from .scheduler import next_run

    latest = connection.execute(
        "SELECT * FROM jobs WHERE recurrence_id=? ORDER BY occurrence DESC LIMIT 1", (row["id"],),
    ).fetchone()
    occurrence = max(row["occurrence_cursor"], latest["occurrence"] + 1 if latest is not None else 0)
    run_at = next_run(payload["__cron__"], after=now, tz=payload.get("__tz__", ""))
    child = queue._insert_job(connection, row["kind"], payload, run_at, now,
                             recurrence_id=row["id"], occurrence=occurrence,
                             recurrence_payload=json.dumps(payload))
    if latest is not None and not latest["successor_id"]:
        prior = json.loads(latest["payload"])
        prior["__rearmed__"] = True
        connection.execute("UPDATE jobs SET successor_id=?,payload=? WHERE id=?",
                           (child, json.dumps(prior), latest["id"]))


def change_definition(queue, identity, *, expected_revision, state, actor,
                      owner=None, cron=None, zone=None, title=None, rationale="Reviewed schedule change"):
    from .scheduler import next_run, require_zone
    from .task_file_recovery import mutation_gate

    if state not in {"active", "paused", "retired"}:
        raise ValueError("Choose active, paused or retired.")
    if zone is not None:
        require_zone(zone)
    now = time.time()
    with mutation_gate(), queue._transaction() as connection:
        row = connection.execute("SELECT * FROM schedule_definitions WHERE id=?", (identity,)).fetchone()
        if row is None or (owner is not None and json.loads(row["payload"]).get("owner", "") != owner):
            raise KeyError("Schedule is unavailable.")
        if row["revision"] != expected_revision:
            raise ValueError("This schedule changed. Review its current version.")
        if connection.execute("SELECT 1 FROM jobs WHERE recurrence_id=? AND recurrence_reconcile_required=1", (identity,)).fetchone():
            raise ValueError("Review the parked occurrence before changing future scheduling.")
        if row["state"] == "retired" and state != "retired":
            raise ValueError("Retired schedules keep their history. Create a new schedule to restart work.")
        payload = json.loads(row["payload"])
        if cron is not None:
            payload["__cron__"] = cron
        if zone is not None:
            payload["__tz__"] = zone
        if title is not None:
            payload["title"] = title
        next_run(payload["__cron__"], after=now, tz=payload.get("__tz__", ""))
        _record_version(connection, row, payload=payload, state=state, actor=actor, rationale=rationale, now=now)
        # Preserve admitted execution and uncertain retries. Cancel only future,
        # never-attempted occurrences, with a durable reason instead of deletion.
        connection.execute(
            "UPDATE jobs SET status='cancelled',last_error=?,updated_at=? "
            "WHERE recurrence_id=? AND status='pending' AND attempts=0",
            ("Future occurrence replaced by reviewed schedule revision", now, identity),
        )
        if state == "active":
            _future_occurrence(queue, connection, row, payload, now)
        current = connection.execute("SELECT * FROM schedule_definitions WHERE id=?", (identity,)).fetchone()
        return public_definition(connection, current)
