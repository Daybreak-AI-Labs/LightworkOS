"""Held federation admissions in the existing world-model delivery ledger.

The atomic reservation contains one goal and its immutable, sealed execution
contract. Only an acknowledged audit receipt releases that reservation. A
same-correlation retry repairs the pre-dispatch phases. Once dispatch is
claimed it is never automatically replayed: a process can die between claim
and execution, and that boundary is explicitly unknown.

The existing tenant/peer correlation bounds apply to retained admissions,
including erased-goal tombstones. They are storage limits, not an expiring
replay window; capacity pressure never silently reopens an old correlation.
No code removes admission rows, so the bounds are lifetime caps. An operator
can raise one peer's limit or start its count again (``set_admission_limit``,
``maverick trust admission-limit`` and the dashboard Agent trust page). A reset
only moves where counting starts: every retained row still answers a repeated
correlation, so no reset or raise reopens a replay.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import logging
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
_LIMITS_FILE = "federation_admission_limits.json"
log = logging.getLogger(__name__)


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
        from .federation import _CORRELATION_CACHE_MAX
        peer_key = _peer_key(peer)
        limits = _read_limits(strict=False)
        total, per_peer = _counts(db, mark, scope[0] if postgres else None, peer, limits)
        if total >= _CORRELATION_CACHE_MAX:
            raise FederationAdmissionRejected("correlation replay ledger capacity is full")
        if per_peer >= _peer_limit(peer, limits):
            log.warning(
                "federation: peer %r reached its limit of %d accepted requests and was refused. "
                "To let it continue, raise or reset the limit: `maverick trust admission-limit "
                "%s --limit N` or `--reset`, or Agent trust > Partner request limits.",
                peer, _peer_limit(peer, limits), peer)
            raise FederationAdmissionRejected(
                "correlation replay ledger capacity is full for this peer; "
                "the receiving operator can raise or reset its limit")
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
                (_enc_field(title.strip(), "goals.title", bind_tenant=True),
                 _enc_field(description, "goals.description", bind_tenant=True), now, now,
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


def _peer_key(peer: str) -> str:
    return PREFIX + "peer:" + hashlib.sha256(json.dumps(
        [current_tenant_id_strict(), peer], separators=(",", ":"),
    ).encode()).hexdigest()


def _limits_path():
    from .paths import data_dir
    return data_dir(_LIMITS_FILE)


def _read_limits(*, strict: bool) -> dict:
    """Operator limits per peer: ``{peer: {"limit": int|None, "counted_from":
    float|None}}``. An unreadable file means the defaults apply (the stricter
    reading); ``strict`` raises instead, so an edit never overwrites it."""
    path = _limits_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("limits file is not an object")
        return {str(k): v for k, v in raw.items() if isinstance(v, dict)}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        if strict:
            raise ValueError("the saved partner request limits could not be read") from exc
        log.warning("federation: %s is unreadable; default admission limits apply", path)
        return {}


def _peer_limit(peer: str, limits: dict) -> int:
    from .federation import _CORRELATION_CACHE_MAX, _CORRELATION_PER_PEER_MAX
    raw = (limits.get(peer) or {}).get("limit")
    chosen = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else _CORRELATION_PER_PEER_MAX
    return min(_CORRELATION_CACHE_MAX, chosen)


def _counted_from(entry: dict | None) -> float | None:
    raw = (entry or {}).get("counted_from")
    return float(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw) else None


def _counts(db, mark: str, tenant_id, peer: str, limits: dict) -> tuple[int, int]:
    """(workspace total, this peer's count) of retained admissions, each peer
    counted from its last operator reset."""
    postgres = tenant_id is not None
    tenant = f"tenant_id={mark} AND " if postgres else ""
    lead = (tenant_id,) if postgres else ()

    def count(where: str, args: tuple) -> int:
        result = db.execute(f"SELECT COUNT(*) FROM event_goal_admissions WHERE {tenant}{where}", (*lead, *args))
        return int((db if postgres else result).fetchone()[0])

    total = count(f"admission_key LIKE {mark}", (PREFIX + "%",))
    for name, entry in limits.items():
        since = _counted_from(entry)
        if since is not None:
            total -= count(f"trigger_key={mark} AND created_at<={mark}", (_peer_key(name), since))
    since = _counted_from(limits.get(peer))
    if since is None:
        per_peer = count(f"trigger_key={mark}", (_peer_key(peer),))
    else:
        per_peer = count(f"trigger_key={mark} AND created_at>{mark}", (_peer_key(peer), since))
    return total, per_peer


def admission_usage(world, peer: str) -> dict:
    """How many requests ``peer`` has used of its limit in this workspace."""
    limits = _read_limits(strict=False)
    with _transaction(world, "federation-capacity") as (db, mark, _, scope, postgres):
        _, used = _counts(db, mark, scope[0] if postgres else None, peer, limits)
    limit = _peer_limit(peer, limits)
    return {"peer": peer, "used": used, "limit": limit, "reached": used >= limit,
            "counted_from": _counted_from(limits.get(peer))}


def set_admission_limit(peer: str, *, limit: int | None = None, reset: bool = False,
                        actor: str) -> dict:
    """Raise (or set) ``peer``'s admission limit and/or restart its count.

    Operator-only: callers check authority. The audit row is written before
    the change is saved; a refused or failed audit write changes nothing."""
    from .audit import EventKind, audit_event
    from .federation import _CORRELATION_CACHE_MAX
    from .file_lock import atomic_write_text, cross_process_lock
    if limit is None and not reset:
        raise ValueError("choose a new limit, a reset, or both")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int)
                              or not 1 <= limit <= _CORRELATION_CACHE_MAX):
        raise ValueError(f"the limit must be a whole number from 1 to {_CORRELATION_CACHE_MAX:,}")
    path = _limits_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with cross_process_lock(path):
        limits = _read_limits(strict=True)
        old_limit = _peer_limit(peer, limits)
        entry = dict(limits.get(peer) or {})
        if limit is not None:
            entry["limit"] = limit
        if reset:
            entry["counted_from"] = time.time()
        new_limit = _peer_limit(peer, {peer: entry})
        if not audit_event(EventKind.FEDERATION_ADMISSION_LIMIT_CHANGED, agent="federation",
                           peer=peer, actor=actor, old_limit=old_limit, new_limit=new_limit,
                           reset=bool(reset)):
            raise RuntimeError("the change could not be recorded in the audit log, so it was not made")
        limits[peer] = entry
        atomic_write_text(path, json.dumps(limits, sort_keys=True))
    return {"peer": peer, "limit": new_limit, "counted_from": _counted_from(entry)}


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
