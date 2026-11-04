"""Held federation admissions in the existing world-model delivery ledger.

The atomic reservation contains one goal and its immutable, sealed execution
contract. Only an acknowledged audit receipt releases that reservation. A
same-correlation retry repairs the pre-dispatch phases. Once dispatch is
claimed it is never automatically replayed: a process can die between claim
and execution, and that boundary is explicitly unknown.

The existing tenant/peer correlation bounds apply to retained admissions,
including erased-goal tombstones. They are storage limits, not an expiring
replay window; capacity pressure never silently reopens an old correlation.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import math
import time
from contextlib import contextmanager
from dataclasses import dataclass

from .event_admission import _transaction
from .paths import current_tenant_id_strict

PREFIX = "federation:"
HELD = "federation_audit_pending"
READY = "federation_ready"
DISPATCHING = "federation_dispatching"
RUNNING = "federation_running"
RETIRED = "federation_retired"
_permit = contextvars.ContextVar("federation_execution_permit", default=None)


class FederationAdmissionRequired(RuntimeError):
    """An ordinary dispatcher cannot adopt reserved federation authority."""


class FederationAdmissionRejected(ValueError):
    """A proven pre-admission validation refusal; no new work was committed."""


@dataclass(frozen=True)
class Reservation:
    key: str
    goal_id: int
    state: str
    contract: dict


def identity(peer: str, correlation: str) -> str:
    raw = json.dumps(["federation-admission/1", current_tenant_id_strict(), peer, correlation],
                     ensure_ascii=False, separators=(",", ":"))
    return PREFIX + hashlib.sha256(raw.encode()).hexdigest()


def _capability(raw):
    if raw is None:
        return None
    from .capability import Capability
    from .queue_dispatcher import _validate_capability_payload
    _validate_capability_payload(raw, require_sig=False)
    return Capability(**{key: frozenset(value) if key in {
        "allow_tools", "deny_tools", "allow_paths", "allow_hosts",
    } else tuple(value) if key == "ancestors" else value for key, value in raw.items()})


def _serialize(capability):
    from .queue_dispatcher import _serialize_capability
    return _serialize_capability(capability, signing_key=b"")


def execution_kwargs(reservation: Reservation) -> dict:
    contract = reservation.contract
    return {"channel": "federation", "user_id": f"federation:{contract['peer']}",
            "capability": _capability(contract["capability"]),
            "max_dollars": contract["max_dollars"],
            "max_wall_seconds": contract["max_wall_seconds"]}


def reserve(world, *, peer: str, correlation: str, digest: str, title: str,
            description: str, capability, max_dollars, max_wall_seconds, admit_new=None) -> Reservation:
    """Commit a held goal and pinned authority together, or reuse that goal."""
    from .orchestrator import _execution_principal
    from .world_model import _dec_field, _enc_field
    if not title.strip():
        raise FederationAdmissionRejected("title is required")
    for value in (max_dollars, max_wall_seconds):
        if value is not None and (isinstance(value, bool) or not math.isfinite(value) or value < 0):
            raise FederationAdmissionRejected("delegation budget is invalid")
    key = identity(peer, correlation)
    principal = _execution_principal(user_id=f"federation:{peer}", capability=capability)
    # Different correlations must share the capacity lock on PostgreSQL too;
    # SQLite's BEGIN IMMEDIATE already serializes competing writers.
    with _transaction(world, "federation-capacity") as (db, mark, where, scope, postgres):
        scope = (*scope[:-1], key)
        result = db.execute(
            f"SELECT goal_id,delivery_state,request_digest,sealed_contract "
            f"FROM event_goal_admissions WHERE {where}", scope)
        row = (db if postgres else result).fetchone()
        if row is not None:
            if row[2] != digest:
                raise FederationAdmissionRejected("correlation_id was already used with different delegation content")
            if row[1] == RETIRED:
                return Reservation(key, int(row[0]), RETIRED, {})
            contract = json.loads(_dec_field(row[3]))
            if (contract["tenant"] != current_tenant_id_strict() or
                    contract["peer"] != peer or contract["correlation"] != correlation):
                raise FederationAdmissionRequired("federation receipt identity mismatch")
            return Reservation(key, int(row[0]), str(row[1]), contract)
        from .federation import _CORRELATION_CACHE_MAX, _CORRELATION_PER_PEER_MAX
        peer_key = PREFIX + "peer:" + hashlib.sha256(json.dumps(
            [current_tenant_id_strict(), peer], separators=(",", ":"),
        ).encode()).hexdigest()
        tenant = f"tenant_id={mark} AND " if postgres else ""
        args = (scope[0], PREFIX + "%") if postgres else (PREFIX + "%",)
        result = db.execute(f"SELECT COUNT(*) FROM event_goal_admissions WHERE {tenant}admission_key LIKE {mark}", args)
        total = int((db if postgres else result).fetchone()[0])
        args = (scope[0], peer_key) if postgres else (peer_key,)
        result = db.execute(f"SELECT COUNT(*) FROM event_goal_admissions WHERE {tenant}trigger_key={mark}", args)
        per_peer = int((db if postgres else result).fetchone()[0])
        if total >= _CORRELATION_CACHE_MAX or per_peer >= min(_CORRELATION_CACHE_MAX, _CORRELATION_PER_PEER_MAX):
            raise FederationAdmissionRejected("correlation replay ledger capacity is full")
        if admit_new is not None and not admit_new():
            raise FederationAdmissionRejected("rate limit exceeded")
        now = time.time()
        contract = {"v": 1, "tenant": current_tenant_id_strict(), "peer": peer,
                    "correlation": correlation, "principal": principal,
                    "capability": _serialize(capability), "max_dollars": max_dollars,
                    "max_wall_seconds": max_wall_seconds, "occurred_at": now,
                    "event_id": key + ":acceptance", "request_digest": digest}
        encoded = json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > 512 * 1024:
            raise FederationAdmissionRejected("federation execution contract is too large")
        if postgres:
            from .world_model_backends.postgres import _active_tenant
            db.execute(
                "INSERT INTO goals(title,description,status,created_at,updated_at,owner,"
                "execution_principal,tenant_id) VALUES(%s,%s,'federation_held',%s,%s,%s,%s,%s) RETURNING id",
                (_enc_field(title.strip()), _enc_field(description), now, now,
                 f"federation:{peer}", principal, _active_tenant()))
            goal_id = int(db.fetchone()[0])
        else:
            goal_id = world.create_goal(title.strip(), description, owner=f"federation:{peer}",
                                        execution_principal=principal)
            db.execute("UPDATE goals SET status='federation_held' WHERE id=?", (goal_id,))
        db.execute(
            f"INSERT INTO goal_origins(goal_id,kind,ref,created_at) VALUES({mark},{mark},{mark},{mark})",
            (goal_id, "federation", key, now))
        columns = "tenant_id,admission_key" if postgres else "admission_key"
        marks = ",".join([mark] * (len(scope) + 6))
        db.execute(
            f"INSERT INTO event_goal_admissions({columns},trigger_key,goal_id,delivery_state,"
            f"created_at,request_digest,sealed_contract) VALUES({marks})",
            (*scope, peer_key, goal_id, HELD, now, digest, _enc_field(encoded)))
        return Reservation(key, goal_id, HELD, contract)


def current_ceiling_allows(reservation: Reservation, *, capability, max_dollars, max_wall_seconds) -> bool:
    """A retry cannot broaden its pinned grant or ignore a tightened ceiling."""
    contract = reservation.contract
    pinned = _capability(contract["capability"])
    if pinned is not None and pinned.is_expired():
        return False
    if capability is not None:
        if pinned is None:
            return False
        narrowed = _serialize(pinned.intersect(capability, principal=pinned.principal))
        original = _serialize(pinned)
        # The original delegation ancestry remains pinned. Intersect can add
        # this same peer a second time, which is not a permission expansion.
        narrowed.pop("ancestors", None)
        original.pop("ancestors", None)
        if narrowed != original:
            return False
    for field, ceiling in (("max_dollars", max_dollars), ("max_wall_seconds", max_wall_seconds)):
        if ceiling is not None and (contract[field] is None or contract[field] > ceiling):
            return False
    return True


def state(world, reservation: Reservation) -> str:
    with _transaction(world, reservation.key) as (db, _, where, scope, postgres):
        result = db.execute(f"SELECT delivery_state FROM event_goal_admissions WHERE {where}", scope)
        row = (db if postgres else result).fetchone()
        if row is None:
            raise FederationAdmissionRequired("federation admission receipt is missing")
        return str(row[0])


def acknowledge(world, reservation: Reservation) -> None:
    """Release only after the caller obtained the audit sink's actual ack."""
    with _transaction(world, reservation.key) as (db, mark, where, scope, postgres):
        result = db.execute(f"UPDATE event_goal_admissions SET delivery_state={mark} "
                            f"WHERE {where} AND delivery_state={mark}", (READY, *scope, HELD))
        if (db if postgres else result).rowcount == 1:
            db.execute(f"UPDATE goals SET status='pending' WHERE id={mark} AND status='federation_held'",
                       (reservation.goal_id,))


def claim(world, reservation: Reservation) -> bool:
    """Fence the first dispatch. A lost claimant is unknown, never replayed."""
    with _transaction(world, reservation.key) as (db, mark, where, scope, postgres):
        result = db.execute(f"SELECT status,owner,execution_principal FROM goals WHERE id={mark}",
                            (reservation.goal_id,))
        goal = (db if postgres else result).fetchone()
        if goal is None or goal[0] != "pending":
            return False
        if goal[1:] != (f"federation:{reservation.contract['peer']}", reservation.contract["principal"]):
            raise FederationAdmissionRequired("federation goal ownership or authority changed")
        result = db.execute(f"UPDATE event_goal_admissions SET delivery_state={mark} "
                            f"WHERE {where} AND delivery_state={mark}", (DISPATCHING, *scope, READY))
        if (db if postgres else result).rowcount != 1:
            return False
        db.execute(f"UPDATE goals SET status='active',updated_at={mark} WHERE id={mark}",
                   (time.time(), reservation.goal_id))
        return True


@contextmanager
def execution_scope(reservation: Reservation):
    if reservation.contract["tenant"] != current_tenant_id_strict():
        raise FederationAdmissionRequired("federation execution tenant mismatch")
    token = _permit.set(reservation)
    try:
        yield
    finally:
        _permit.reset(token)


def require_execution(world, goal_id: int, *, capability=None, budget=None,
                      max_dollars=None, max_wall_seconds=None, consume=False) -> None:
    """Common runner/orchestrator gate, independent of mutable goal status."""
    from .world_model import WorldModel, _dec_field
    from .world_model_backends.postgres import PostgresWorldModel
    if not isinstance(world, (WorldModel, PostgresWorldModel)):
        return  # Nonpersistent test worlds cannot contain durable admissions.
    with _transaction(world, f"federation-goal:{goal_id}") as (db, mark, _, scope, postgres):
        tenant = f"tenant_id={mark} AND " if postgres else ""
        args = (scope[0], goal_id, PREFIX + "%") if postgres else (goal_id, PREFIX + "%")
        result = db.execute(
            f"SELECT admission_key,delivery_state,sealed_contract FROM event_goal_admissions "
            f"WHERE {tenant}goal_id={mark} AND admission_key LIKE {mark}", args)
        row = (db if postgres else result).fetchone()
        if row is None:
            return
        permit = _permit.get()
        if (permit is None or permit.key != row[0] or permit.goal_id != goal_id or
                permit.contract["tenant"] != current_tenant_id_strict() or row[1] != DISPATCHING):
            raise FederationAdmissionRequired("federation admission requires its audited dispatch authority")
        contract = json.loads(_dec_field(row[2]))
        if contract != permit.contract or _serialize(capability) != contract["capability"]:
            raise FederationAdmissionRequired("federation execution authority differs from its pinned contract")
        grant = _capability(contract["capability"])
        if grant is not None and grant.is_expired():
            raise FederationAdmissionRequired("federation execution authority expired")
        for field, supplied in (("max_dollars", max_dollars), ("max_wall_seconds", max_wall_seconds)):
            limit = contract[field]
            actual = getattr(budget, field) if budget is not None else supplied
            if limit is not None and (actual is None or not math.isfinite(actual) or actual > limit):
                raise FederationAdmissionRequired("federation execution budget exceeds its pinned contract")
        if consume:
            params = (RUNNING, scope[0], row[0], DISPATCHING) if postgres else (RUNNING, row[0], DISPATCHING)
            result = db.execute(
                f"UPDATE event_goal_admissions SET delivery_state={mark} WHERE {tenant}"
                f"admission_key={mark} AND delivery_state={mark}", params)
            if (db if postgres else result).rowcount != 1:
                raise FederationAdmissionRequired("federation execution was already claimed")
