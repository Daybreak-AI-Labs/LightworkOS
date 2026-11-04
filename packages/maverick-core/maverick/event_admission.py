"""Transactional template-event goal admission and durable delivery receipts.

Receipts intentionally outlive goal erasure: a historical external event may
never recreate deleted customer data or repeat its work. They contain only a
digest, a local goal ID and delivery state, not event fields or credentials.
"""
from __future__ import annotations

import hashlib
import json
import time
from contextlib import contextmanager

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_goal_admissions (
    admission_key TEXT PRIMARY KEY,
    trigger_key TEXT NOT NULL,
    goal_id INTEGER NOT NULL,
    delivery_state TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_pending ON event_goal_admissions(trigger_key,delivery_state);
CREATE TABLE IF NOT EXISTS event_trigger_batches (
    trigger_key TEXT PRIMARY KEY,
    batch_digest TEXT NOT NULL,
    sealed_batch TEXT NOT NULL
);
"""
POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_goal_admissions (
    tenant_id TEXT NOT NULL,
    admission_key TEXT NOT NULL,
    trigger_key TEXT NOT NULL,
    goal_id INTEGER NOT NULL,
    delivery_state TEXT NOT NULL DEFAULT 'pending',
    created_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(tenant_id, admission_key)
);
CREATE INDEX IF NOT EXISTS idx_event_pending ON event_goal_admissions(tenant_id,trigger_key,delivery_state);
CREATE TABLE IF NOT EXISTS event_trigger_batches (
    tenant_id TEXT NOT NULL,
    trigger_key TEXT NOT NULL,
    batch_digest TEXT NOT NULL,
    sealed_batch TEXT NOT NULL,
    PRIMARY KEY(tenant_id,trigger_key)
);
"""


class EventDispatchUncertain(RuntimeError):
    """A non-idempotent dispatch needs operator reconciliation, never replay."""


class LegacyEventGoalHeld(RuntimeError):
    """An unstarted event goal predates the verified admission protocol."""


class EventRegistryUnavailable(RuntimeError):
    """The automation registry cannot be read; execution may be retried later."""


def compatible_legacy_goal(origin: str, owner: str, trigger_key: str) -> bool:
    """Prove an old non-mail goal still belongs to its unchanged binding.

    The old receipt retained the trigger generation even though its origin did
    not. A missing receipt, registry, or immutable template is never proof.
    """
    return _compatible_goal_binding(origin, owner, trigger_key, allow_mail=False)


def compatible_current_goal(origin: str, owner: str, trigger_key: str) -> bool:
    """Prove a queued v2 goal still has its exact approved event binding.

    The poller verifies email senders before admitting a v2 goal. A later
    trigger edit (including its permitted senders) changes the generation and
    must revoke an unstarted goal before either local or remote execution.
    """
    return _compatible_goal_binding(origin, owner, trigger_key, allow_mail=True)


def compatible_event_goal(kind: str, origin: str, owner: str,
                          trigger_key: str) -> bool:
    if kind == "event":
        return compatible_legacy_goal(origin, owner, trigger_key)
    if kind == "event_v2":
        return compatible_current_goal(origin, owner, trigger_key)
    return False


@contextmanager
def execution_binding_lock(world, goal_id: int):
    """Pin an event binding through the pending-to-active transaction.

    Trigger edits take the dashboard registry lock. The read here finishes
    before acquiring that lock, then callers enter the world write transaction;
    this order also matches public-form decisions (registry before world).
    Callers must retry, rather than start, if an event origin appears between
    this preflight and their transactional origin read.
    """
    from .world_model import WorldModel

    if isinstance(world, WorldModel):
        event = world._read_one(
            "SELECT 1 FROM goal_origins WHERE goal_id=? "
            "AND kind IN ('event','event_v2')", (int(goal_id),),
        ) is not None
        if event:
            from threading import get_ident

            if world._writer_ident == get_ident():
                raise EventRegistryUnavailable(
                    "Event execution must begin outside a world transaction"
                )
    else:
        from .world_model_backends.postgres import PostgresWorldModel, _mutation_tenant_scope

        if not isinstance(world, PostgresWorldModel):
            raise TypeError("event execution requires a supported world model")
        if getattr(getattr(world, "_tx_depth", None), "value", 0):
            # A nested transaction already holds a world connection/row lock.
            # Acquiring the file registry now would invert the form/trigger
            # lock order, and the inner commit may precede the outer commit.
            raise EventRegistryUnavailable(
                "Event execution must begin outside a world transaction"
            )
        scoped, params = _mutation_tenant_scope("g.tenant_id")
        with world._tx() as cursor:
            cursor.execute(
                "SELECT 1 FROM goal_origins o JOIN goals g ON g.id=o.goal_id "
                "WHERE o.goal_id=%s AND o.kind IN ('event','event_v2') "
                "AND " + scoped,
                (int(goal_id), *params),
            )
            event = cursor.fetchone() is not None

    if event:
        try:
            from maverick_dashboard import event_triggers_store

            lock = event_triggers_store.registry_lock()
            lock.__enter__()
        except (ImportError, OSError, RuntimeError) as exc:
            raise EventRegistryUnavailable("Event automation registry lock is unavailable") from exc
        try:
            yield True
        finally:
            lock.__exit__(None, None, None)
    else:
        yield False


def _compatible_goal_binding(origin: str, owner: str, trigger_key: str, *,
                             allow_mail: bool) -> bool:
    if not origin or not trigger_key:
        return False
    try:
        from maverick_dashboard import event_triggers_store, triggers_store
        from maverick_dashboard.event_poll import _trigger_key

        from maverick.paths import current_tenant_id

        current = event_triggers_store.get_trigger(
            origin, tenant=current_tenant_id() or "", strict=True,
        )
        if (current is None or not current.get("source")
                or (current["source"] == "imap_email" and not allow_mail)
                or current.get("owner") != owner
                or current.get("flow")
                or _trigger_key(current) != trigger_key):
            return False
        triggers_store.bound_template(current)
        return True
    except EventRegistryUnavailable:
        raise
    except Exception:
        # A damaged/unreadable registry cannot authorize an old reservation.
        return False


@contextmanager
def _transaction(world, admission_key):
    from .paths import current_tenant_id_strict
    from .task_file_recovery import mutation_gate
    from .workspace_recovery import assert_bootstrap_start_allowed
    from .world_model import WorldModel
    from .world_model_backends.postgres import PostgresWorldModel, _active_tenant

    context_tenant = current_tenant_id_strict()
    with mutation_gate():
        assert_bootstrap_start_allowed()
        if isinstance(world, WorldModel):
            if world._event_admission_tenant != context_tenant:
                raise ValueError("event world belongs to a different tenant context")
            with world._writing() as conn:
                if not conn.in_transaction:
                    conn.execute("BEGIN IMMEDIATE")
                yield conn, "?", "admission_key=?", (admission_key,), False
                if current_tenant_id_strict() != context_tenant:
                    raise ValueError("event admission tenant context changed")
        elif isinstance(world, PostgresWorldModel):
            tenant = _active_tenant() or ""
            lock = int.from_bytes(hashlib.sha256(
                f"{tenant}:{admission_key}".encode()).digest()[:8], "big", signed=True)
            with world._tx() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (lock,))
                yield cur, "%s", "tenant_id=%s AND admission_key=%s", (tenant, admission_key), True
                if current_tenant_id_strict() != context_tenant:
                    raise ValueError("event admission tenant context changed")
        else:
            raise TypeError("template event admission requires a transactional world model")


def admit(world, admission_key: str, title: str, description: str, *,
          owner: str, origin: str, trigger_key: str,
          origin_kind: str = "event") -> tuple[int, str]:
    """Commit goal, origin and event receipt together, or reuse the original."""
    _, goal_id, state = admit_batch(
        world, [(admission_key, title, description)], owner=owner, origin=origin,
        trigger_key=trigger_key, origin_kind=origin_kind)[0]
    return goal_id, state


def admit_batch(world, entries: list[tuple], *, owner: str,
                origin: str, trigger_key: str,
                origin_kind: str = "event") -> list[tuple[str, int, str]]:
    """Commit the entire bounded polled batch before dispatching any of it."""
    if len(entries) > 25:
        raise ValueError("event admission batch exceeds poll limit")
    if origin_kind not in {"event", "event_v2"}:
        raise ValueError("event origin kind is invalid")
    admitted = []
    with _transaction(world, trigger_key) as (db, mark, where, scope, postgres):
        for entry in entries:
            admission_key, title, description = entry[:3]
            refs = entry[3] if len(entry) == 4 else []
            from .template_connections import packed
            selection = packed(owner, refs)
            key = (*scope[:-1], admission_key)
            result = db.execute(
                f"SELECT goal_id,delivery_state,trigger_key FROM event_goal_admissions WHERE {where}", key)
            row = (db if postgres else result).fetchone()
            if row is not None:
                if origin_kind == "event_v2":
                    proof = db.execute(
                        "SELECT o.kind,o.ref,g.owner,g.status FROM goal_origins o "
                        f"JOIN goals g ON g.id=o.goal_id WHERE o.goal_id={mark}",
                        (int(row[0]),),
                    )
                    kind = (db if postgres else proof).fetchone()
                    if kind is None:
                        goal = db.execute(
                            f"SELECT 1 FROM goals WHERE id={mark}", (int(row[0]),),
                        )
                        if (db if postgres else goal).fetchone() is None:
                            admitted.append((admission_key, int(row[0]), str(row[1])))
                            continue  # erased historical goal is safely retired by the caller
                    legacy_compatible = (
                        kind is not None and kind[0] == "event"
                        and origin_kind == "event_v2" and row[2] == trigger_key
                        and kind[1] == origin and kind[2] == owner
                        and kind[3] != "blocked"
                        and compatible_legacy_goal(origin, owner, str(row[2]))
                    )
                    if kind is None or (kind[0] != "event_v2" and not legacy_compatible):
                        raise EventDispatchUncertain(
                            "earlier event goal needs review before delivery"
                        )
                admitted.append((admission_key, int(row[0]), str(row[1])))
                continue
            now = time.time()
            if postgres:
                from .world_model_backends.postgres import _active_tenant, _seal
                db.execute(
                    "INSERT INTO goals(title,description,status,created_at,updated_at,owner,tenant_id,connection_selection) "
                    "VALUES(%s,%s,'pending',%s,%s,%s,%s,%s) RETURNING id",
                    (_seal(title), _seal(description), now, now, owner, _active_tenant(), _seal(selection)))
                goal_id = int(db.fetchone()[0])
            else:
                goal_id = world.create_goal(title, description, owner=owner,
                    **({"connection_references": refs} if refs else {}))
            db.execute(
                f"INSERT INTO goal_origins(goal_id,kind,ref,created_at) VALUES({mark},{mark},{mark},{mark})",
                (goal_id, origin_kind, origin, now))
            columns = "tenant_id,admission_key" if postgres else "admission_key"
            marks = ",".join([mark] * (len(key) + 3))
            db.execute(
                f"INSERT INTO event_goal_admissions({columns},goal_id,created_at,trigger_key) VALUES({marks})",
                (*key, goal_id, now, trigger_key))
            admitted.append((admission_key, goal_id, "pending"))
    return admitted


def transition(world, admission_key: str, before: str, after: str) -> bool:
    with _transaction(world, admission_key) as (db, mark, where, key, _):
        result = db.execute(
            f"UPDATE event_goal_admissions SET delivery_state={mark} "
            f"WHERE {where} AND delivery_state={mark}", (after, *key, before))
        return (db if result is None else result).rowcount == 1


def pending(world, trigger_key: str) -> list[tuple[str, int, str]]:
    """Repair admitted work even when its source has already dropped the item."""
    with _transaction(world, trigger_key) as (db, mark, _, key, postgres):
        tenant_clause = f"tenant_id={mark} AND " if postgres else ""
        args = (key[0], trigger_key) if postgres else (trigger_key,)
        result = db.execute(
            "SELECT admission_key,goal_id,delivery_state FROM event_goal_admissions WHERE "
            f"{tenant_clause}trigger_key={mark} AND delivery_state NOT IN ('delivered','retired') "
            "ORDER BY created_at,admission_key LIMIT 25", args)
        return [(str(r[0]), int(r[1]), str(r[2]))
                for r in (db if postgres else result).fetchall()]


def quarantine_legacy_mail_goals(world, trigger_name: str, authenticated_key: str) -> int:
    """Block queued, unstarted pre-gate email goals, including delivered receipts.

    A delivery receipt can be marked delivered before its queued goal is claimed.
    Retiring only ``pending()`` receipts would leave that old goal executable.
    The pending-only goal transition and receipt retirement share a transaction.
    """
    # The trigger identity includes its config. Adding required sender checks
    # changes that identity, so reconstructing an old key from today's config
    # cannot find earlier admitted goals. The durable goal origin links every
    # generation of this trigger to its name instead.
    with _transaction(world, authenticated_key) as (db, mark, _, scope, postgres):
        tenant_clause = f"a.tenant_id={mark} AND g.tenant_id=a.tenant_id AND " if postgres else ""
        args = (scope[0], trigger_name, authenticated_key) if postgres else (
            trigger_name, authenticated_key)
        result = db.execute(
            "SELECT a.admission_key,a.goal_id FROM event_goal_admissions a "
            "JOIN goals g ON g.id=a.goal_id "
            "JOIN goal_origins o ON o.goal_id=g.id WHERE "
            f"{tenant_clause}o.kind IN ('event','event_v2') AND o.ref={mark} "
            f"AND a.trigger_key<>{mark} AND g.status='pending' "
            "ORDER BY a.created_at,a.admission_key LIMIT 25", args,
        )
        rows = (db if postgres else result).fetchall()
        if postgres:
            from .world_model_backends.postgres import _seal as seal
        else:
            from .world_model import _enc_field as seal
        for key, goal_id in rows:
            now = time.time()
            update = db.execute(
                "UPDATE goals SET status='blocked', completed_at=NULL, "
                f"updated_at={('GREATEST' if postgres else 'MAX')}(updated_at + 0.000001, {mark}), "
                f"result={mark} WHERE id={mark} AND status='pending'"
                + (f" AND tenant_id={mark}" if postgres else ""),
                (now, seal("Earlier email request held because sender checks or the automation binding changed"), int(goal_id),
                 *((scope[0],) if postgres else ())),
            )
            if (db if postgres else update).rowcount != 1:
                raise EventDispatchUncertain("earlier email request started during quarantine")
            db.execute(
                f"DELETE FROM signoffs WHERE goal_id={mark}", (int(goal_id),),
            )
            db.execute(
                "UPDATE event_goal_admissions SET delivery_state='retired' "
                f"WHERE admission_key={mark}"
                + (f" AND tenant_id={mark}" if postgres else ""),
                (str(key), *((scope[0],) if postgres else ())),
            )
        return len(rows)


def admitted(world, admission_key: str) -> bool:
    """Whether this delivery has ever been admitted, including terminal work."""
    with _transaction(world, admission_key) as (db, mark, where, scope, postgres):
        result = db.execute(
            f"SELECT 1 FROM event_goal_admissions WHERE {where} LIMIT 1", scope,
        )
        return (db if postgres else result).fetchone() is not None


def poll_batch(world, trigger_key: str, candidate: dict | None = None) -> dict | None:
    """Durably retain all observed events before any goal/flow dispatch.

    Only one unpublished batch exists for a trigger generation. Competing
    pollers reuse it. Event fields and cursor are sealed like goal content.
    """
    with _transaction(world, trigger_key) as (db, mark, _, scope, postgres):
        where = f"tenant_id={mark} AND trigger_key={mark}" if postgres else f"trigger_key={mark}"
        result = db.execute(f"SELECT batch_digest,sealed_batch FROM event_trigger_batches WHERE {where}", scope)
        row = (db if postgres else result).fetchone()
        if row is not None:
            if postgres:
                from .world_model_backends.postgres import _unseal as open_batch
            else:
                from .world_model import _dec_field as open_batch
            return {**json.loads(open_batch(row[1])), "batch_digest": row[0]}
        if candidate is None:
            return None
        encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode()) > 8 * 1024 * 1024 or len(candidate["events"]) > 25:
            raise ValueError("event batch exceeds durable intake bound")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        if postgres:
            from .world_model_backends.postgres import _seal as seal_batch
        else:
            from .world_model import _enc_field as seal_batch
        columns = "tenant_id,trigger_key" if postgres else "trigger_key"
        marks = ",".join([mark] * (len(scope) + 2))
        db.execute(f"INSERT INTO event_trigger_batches({columns},batch_digest,sealed_batch) VALUES({marks})",
                   (*scope, digest, seal_batch(encoded)))
        return {**candidate, "batch_digest": digest}


def complete_poll_batch(world, trigger_key: str, digest: str) -> None:
    """Retire only the batch whose cursor publication was confirmed."""
    with _transaction(world, trigger_key) as (db, mark, _, scope, postgres):
        where = f"tenant_id={mark} AND trigger_key={mark}" if postgres else f"trigger_key={mark}"
        db.execute(f"DELETE FROM event_trigger_batches WHERE {where} AND batch_digest={mark}", (*scope, digest))
