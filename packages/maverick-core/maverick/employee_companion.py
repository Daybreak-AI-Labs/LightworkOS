"""Bounded, private employee companion policy and conversation storage.

This is a single-control-plane file authority, not a new agent runtime. Callers
must authenticate the exact employee owner (including on reads) and revalidate
workspace membership under ``authority_effect_fence``. Administrative metadata
reads never decrypt conversation content. Policy retention changes may rewrite
encrypted history to enforce expiry, but never return that content to admins.

Each employee record atomically publishes policy, its required audit events,
and an optional tenant/owner-bound encrypted history. There is no plaintext
history fallback. Expiry runs on employee access or policy update, not in a
background sweeper; backups and replicas require separate retention controls.
The last 200 metadata events and 50 exchanges per employee are retained. This
bounded local event journal is not an immutable compliance audit archive. State
is host-local even when the existing world model uses a shared database; the
preview does not support multiple control-plane hosts.

Model turns reserve a short metadata lease before any provider call. Receipts
consume their request ID even after failure or expiry; this prevents duplicate
application dispatch, not exactly-once provider billing. No provider call runs
under a file lock. Policy changes and history deletion invalidate publication;
they cannot retract content already sent to a provider.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
from contextlib import contextmanager

from . import crypto_at_rest, file_lock
from .authority_effects import authority_effect_fence
from .ediscovery import (
    LegalHoldApplies,
    assert_personal_chats_erasable,
    in_hold,
    personal_hold_windows,
    personal_holds,
)
from .paths import canonical_tenant_id, current_tenant_id_strict, data_dir

MAX_EMPLOYEES = 1000
MAX_EVENTS = 200
MAX_HISTORY = 50
MAX_MESSAGE = 4000
MAX_RESPONSE = 12000
MAX_SOURCE_REFS = 50
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_TURN_RECEIPTS = 512
TURN_LEASE_SECONDS = 300
REQUEST_FRESH_SECONDS = 900
REQUEST_CLOCK_SKEW_SECONDS = 60
TURN_RECEIPT_SECONDS = 86400
_POLICY_FIELDS = {
    "owner", "revision", "enabled", "allowed_sources", "allowed_tools",
    "retention_days", "memory_enabled", "action_mode", "admin_content_access",
    "approvals", "updated_at", "updated_by",
}
_EVENT_FIELDS = {"id", "actor", "owner", "action", "revision", "time", "decision", "reason"}
_LEGACY_EXCHANGE_FIELDS = {
    "id", "time", "expires_at", "message", "response", "source_refs", "policy_revision",
}
_EXCHANGE_FIELDS = _LEGACY_EXCHANGE_FIELDS | {"kind", "model_route"}
_ACTIONS = {"policy_updated", "reply", "history_cleared", "history_expired", "turn_started",
            "draft_reply", "turn_failed", "turn_expired", "turn_cancelled"}
_REASONS = {"policy_updated": "admin_policy", "reply": "owner_and_policy",
            "history_cleared": "owner_request", "history_expired": "retention_policy",
            "turn_started": "owner_and_policy", "draft_reply": "owner_and_policy",
            "turn_failed": "request_abandoned", "turn_expired": "lease_expired",
            "turn_cancelled": "authority_changed"}
_HEX_ID = re.compile(r"[0-9a-f]{32}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_ID = re.compile(r"([1-9][0-9]{0,15})\.([0-9a-f]{32})\Z")
_RECORD_NAME = re.compile(r"[0-9a-f]{64}\.json\Z")
_SOURCE_REF = re.compile(r"task:[1-9][0-9]{0,18}\Z")
_MODEL_ROUTE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}\Z")
_RECORD_FIELDS = {"version", "tenant", "owner", "policy", "events", "history"}
_TURN_RECORD_FIELDS = {"history_generation", "turns", "turn_clock"}
_TURN_FIELDS = {"request_id", "fingerprint", "token", "revision", "history_generation",
                "state", "started_at", "finished_at", "expires_at", "trace_id"}
_TURN_STATES = {"pending", "completed", "failed", "expired", "cancelled"}


class CompanionError(RuntimeError):
    """Companion authority is unavailable or cannot be trusted."""


class CompanionValidationError(ValueError):
    """A request exceeds the bounded companion capability contract."""


class CompanionConflictError(CompanionError):
    """The administrator's policy changed since the request was admitted."""


class CompanionPolicyDenied(CompanionError):
    """The current policy does not permit this companion operation."""


def _identity(value: object) -> str:
    if (not isinstance(value, str) or not value.startswith("user:")
            or not value[5:].strip() or value != value.strip() or len(value) > 320
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CompanionValidationError("An exact authenticated employee identity is required")
    return value


def _integer(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= 2**53 - 1


def _timestamp(value: object) -> bool:
    return (type(value) in (int, float) and 0 <= value <= 2**53 - 1
            and math.isfinite(value))


def _choices(value: object, allowed: set[str]) -> bool:
    return (isinstance(value, list) and all(isinstance(item, str) for item in value)
            and len(value) == len(set(value)) and set(value) <= allowed)


def _validate_options(enabled, allowed_sources, allowed_tools, retention_days) -> None:
    if (type(enabled) is not bool
            or not _choices(allowed_sources, {"own_tasks"})
            or not _choices(allowed_tools, {"task_status", "draft_reply"})
            or type(retention_days) is not int or retention_days not in {0, 1, 7, 30}):
        raise CompanionValidationError("Unsupported companion policy or capability")


def _default_policy(owner: str) -> dict:
    return {
        "owner": owner, "revision": 0, "enabled": False,
        "allowed_sources": [], "allowed_tools": [], "retention_days": 0,
        "memory_enabled": False, "action_mode": "read_only",
        "admin_content_access": False, "approvals": "writes_blocked",
        "updated_at": 0, "updated_by": None,
    }


def _validate_policy(policy: object, owner: str) -> None:
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise CompanionValidationError("Invalid companion policy schema")
    _validate_options(policy["enabled"], policy["allowed_sources"],
                      policy["allowed_tools"], policy["retention_days"])
    if (policy["owner"] != owner or not _integer(policy["revision"])
            or policy["memory_enabled"] is not False
            or policy["admin_content_access"] is not False
            or policy["action_mode"] != "read_only" or policy["approvals"] != "writes_blocked"
            or not _timestamp(policy["updated_at"])):
        raise CompanionValidationError("Invalid companion policy authority")
    if policy["revision"] > 0:
        _identity(policy["updated_by"])
    elif policy != _default_policy(owner):
        raise CompanionValidationError("Invalid initial companion policy")


def _validate_event(event: object, owner: str, revision: int) -> None:
    if not isinstance(event, dict) or set(event) != _EVENT_FIELDS:
        raise CompanionValidationError("Invalid companion audit event")
    _identity(event["actor"])
    if (not isinstance(event["id"], str) or not _HEX_ID.fullmatch(event["id"])
            or event["owner"] != owner or not _integer(event["revision"])
            or event["revision"] > revision or not _timestamp(event["time"])
            or not isinstance(event["action"], str) or event["action"] not in _ACTIONS
            or event["decision"] != "allowed"
            or event["reason"] != _REASONS[event["action"]]):
        raise CompanionValidationError("Invalid companion audit authority")
    if event["action"] != "policy_updated" and event["actor"] != owner:
        raise CompanionValidationError("Invalid companion event owner")


def _validate_text(message: object, response: object, source_refs: object) -> None:
    if (not isinstance(message, str) or not message.strip() or len(message) > MAX_MESSAGE
            or not isinstance(response, str) or not response.strip() or len(response) > MAX_RESPONSE
            or not isinstance(source_refs, list) or len(source_refs) > MAX_SOURCE_REFS
            or any(not isinstance(ref, str) or not _SOURCE_REF.fullmatch(ref)
                   for ref in source_refs) or len(source_refs) != len(set(source_refs))):
        raise CompanionValidationError("Companion exchange exceeds the supported bounds")


def _validate_exchange(exchange: object, revision: int) -> None:
    if isinstance(exchange, dict) and set(exchange) == _LEGACY_EXCHANGE_FIELDS:
        exchange.update(kind="task_status", model_route=None)
    if not isinstance(exchange, dict) or set(exchange) != _EXCHANGE_FIELDS:
        raise CompanionValidationError("Invalid companion history schema")
    _validate_text(exchange["message"], exchange["response"], exchange["source_refs"])
    if (not isinstance(exchange["id"], str) or not _HEX_ID.fullmatch(exchange["id"])
            or not _timestamp(exchange["time"]) or not _timestamp(exchange["expires_at"])
            or not exchange["time"] < exchange["expires_at"] <= exchange["time"] + 30 * 86400
            or not _integer(exchange["policy_revision"], minimum=1)
            or exchange["policy_revision"] > revision):
        raise CompanionValidationError("Invalid companion history authority")
    if exchange["kind"] not in ("task_status", "draft"):
        raise CompanionValidationError("Invalid companion reply kind")
    _validate_model_route(exchange["model_route"])
    if exchange["kind"] == "task_status" and exchange["model_route"] is not None:
        raise CompanionValidationError("Task status cannot claim model provenance")


def _validate_model_route(model_route: object) -> None:
    if model_route is not None and (not isinstance(model_route, str)
                                    or not _MODEL_ROUTE.fullmatch(model_route)):
        raise CompanionValidationError("Invalid companion model route")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CompanionValidationError("Duplicate companion record field")
        result[key] = value
    return result


def _decode(raw: str | bytes):
    return json.loads(raw, object_pairs_hook=_unique_object)


def _request_timestamp(request_id: object) -> float:
    match = _REQUEST_ID.fullmatch(request_id) if isinstance(request_id, str) else None
    if match is None:
        raise CompanionValidationError("A timestamped companion request identifier is required")
    return int(match.group(1)) / 1000


def _validate_turn_receipt(turn: object, revision: int, generation: int) -> None:
    if not isinstance(turn, dict) or set(turn) != _TURN_FIELDS:
        raise CompanionValidationError("Invalid companion turn receipt")
    issued_at = _request_timestamp(turn["request_id"])
    if (not isinstance(turn["fingerprint"], str) or not _FINGERPRINT.fullmatch(turn["fingerprint"])
            or not isinstance(turn["token"], str) or not _HEX_ID.fullmatch(turn["token"])
            or not _integer(turn["revision"], minimum=1) or turn["revision"] > revision
            or not _integer(turn["history_generation"]) or turn["history_generation"] > generation
            or not isinstance(turn["state"], str) or turn["state"] not in _TURN_STATES
            or not _timestamp(turn["started_at"]) or not _timestamp(turn["expires_at"])
            or turn["expires_at"] != turn["started_at"] + TURN_LEASE_SECONDS):
        raise CompanionValidationError("Invalid companion turn authority")
    if not turn["started_at"] - REQUEST_FRESH_SECONDS <= issued_at <= turn["started_at"] + REQUEST_CLOCK_SKEW_SECONDS:
        raise CompanionValidationError("Invalid companion request admission time")
    if turn["state"] == "pending":
        if (turn["finished_at"] is not None or turn["revision"] != revision
                or turn["history_generation"] != generation):
            raise CompanionValidationError("Invalid active companion turn")
    elif not _timestamp(turn["finished_at"]) or turn["finished_at"] < turn["started_at"]:
        raise CompanionValidationError("Invalid companion turn completion")
    if turn["state"] == "completed":
        if not isinstance(turn["trace_id"], str) or not _HEX_ID.fullmatch(turn["trace_id"]):
            raise CompanionValidationError("Completed companion turn is missing its trace")
    elif turn["trace_id"] is not None:
        raise CompanionValidationError("Incomplete companion turn has a result trace")


def _turn_metadata(turn: dict) -> dict:
    return {key: turn[key] for key in
            ("request_id", "state", "started_at", "finished_at", "expires_at")}


class EmployeeCompanionStore:
    """Tenant-bound authority; employee authentication belongs to the service."""

    def __init__(self):
        tenant = current_tenant_id_strict()
        if not tenant:
            raise CompanionError("Companions require an authenticated named workspace")
        self.tenant = canonical_tenant_id(tenant)
        self.root = data_dir("employee_companions")
        self._check_context()

    def _check_context(self) -> None:
        tenant = current_tenant_id_strict()
        if not tenant or canonical_tenant_id(tenant) != self.tenant:
            raise CompanionError("Companion tenant context changed")
        if data_dir("employee_companions") != self.root:
            raise CompanionError("Companion storage root changed")
        # Match the existing control-plane single-owner deployment guard.
        if os.environ.get("MAVERICK_REPLICA_COUNT", "1").strip() != "1":
            raise CompanionError("Companions currently require one control-plane replica")

    @contextmanager
    def _locked(self):
        self._check_context()
        try:
            # Same lock ordering as API admission and role/offboarding mutations.
            # The existing cross-process fence is reentrant in this thread.
            with authority_effect_fence():
                file_lock.ensure_private_directory(self.root)
                with file_lock.cross_process_lock(self.root / "authority", strict=True):
                    self._check_context()
                    yield
        except (CompanionError, LegalHoldApplies):
            # A legal hold is a refusal, not a storage fault: it must reach the caller as itself.
            raise
        except (OSError, RuntimeError) as exc:
            raise CompanionError("Companion storage is unavailable; access refused") from exc

    def _path(self, owner: str):
        return self.root / (hashlib.sha256(owner.encode("utf-8")).hexdigest() + ".json")

    def _record_paths(self) -> list:
        paths = []
        for path in self.root.glob("*.json"):
            if not _RECORD_NAME.fullmatch(path.name):
                raise CompanionError("Companion authority contains an invalid record name")
            paths.append(path)
            if len(paths) > MAX_EMPLOYEES:
                raise CompanionError("Companion employee capacity exceeded")
        return sorted(paths)

    def _validate_record(self, state: object, owner: str) -> None:
        if (not isinstance(state, dict)
                or type(state.get("version")) is not int or state["version"] not in {1, 2}
                or set(state) != (_RECORD_FIELDS if state["version"] == 1
                                  else _RECORD_FIELDS | _TURN_RECORD_FIELDS)
                or state["tenant"] != self.tenant or state["owner"] != owner):
            raise CompanionValidationError("Invalid companion record identity")
        _validate_policy(state["policy"], owner)
        events = state["events"]
        if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
            raise CompanionValidationError("Invalid companion audit journal")
        for event in events:
            _validate_event(event, owner, state["policy"]["revision"])
        if events[-1]["revision"] != state["policy"]["revision"]:
            raise CompanionValidationError("Companion policy is missing its audit event")
        self._history_blob(state)
        if state["version"] == 2:
            self._validate_turn_state(state)

    @staticmethod
    def _validate_turn_state(state: dict) -> None:
        if (not _integer(state["history_generation"]) or not _timestamp(state["turn_clock"])
                or not isinstance(state["turns"], list) or len(state["turns"]) > MAX_TURN_RECEIPTS):
            raise CompanionValidationError("Invalid companion conversation state")
        ids, tokens, pending = set(), set(), 0
        for turn in state["turns"]:
            _validate_turn_receipt(turn, state["policy"]["revision"], state["history_generation"])
            if max(turn["started_at"], turn["finished_at"] or 0) > state["turn_clock"]:
                raise CompanionValidationError("Invalid companion request clock")
            if turn["request_id"] in ids or turn["token"] in tokens:
                raise CompanionValidationError("Duplicate companion turn authority")
            ids.add(turn["request_id"])
            tokens.add(turn["token"])
            pending += turn["state"] == "pending"
        if pending > 1:
            raise CompanionValidationError("Overlapping companion turns are invalid")

    @staticmethod
    def _history_blob(state: dict) -> bytes | None:
        history = state["history"]
        if history is None:
            return None
        if not isinstance(history, str) or len(history) > MAX_RECORD_BYTES:
            raise CompanionValidationError("Invalid companion history envelope")
        blob = base64.b64decode(history, validate=True)
        if not crypto_at_rest.is_bound(blob):
            raise CompanionValidationError("Companion history must be encrypted")
        return blob

    def _read_path(self, path) -> dict:
        try:
            file_lock.ensure_private_file(path)
            if path.stat().st_size > MAX_RECORD_BYTES:
                raise CompanionValidationError("Companion record exceeds its size limit")
            state = _decode(file_lock.atomic_read_text(path))
            if not isinstance(state, dict):
                raise CompanionValidationError("Invalid companion record")
            owner = _identity(state.get("owner"))
            if self._path(owner) != path:
                raise CompanionValidationError("Companion owner does not match its record")
            self._validate_record(state, owner)
            if state["version"] == 1:
                # Validate the exact legacy schema first. The next mutation
                # publishes v2 atomically; metadata reads do not rewrite files.
                state.update(version=2, history_generation=0, turns=[], turn_clock=0)
            return state
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise CompanionError("Companion stored authority is invalid; access refused") from exc

    def _read(self, owner: str) -> dict:
        path = self._path(owner)
        try:
            path.lstat()
        except FileNotFoundError:
            return {"version": 2, "tenant": self.tenant, "owner": owner,
                    "policy": _default_policy(owner), "events": [], "history": None,
                    "history_generation": 0, "turns": [], "turn_clock": 0}
        return self._read_path(path)

    def _save(self, state: dict) -> None:
        self._check_context()
        self._validate_record(state, state["owner"])
        path = self._path(state["owner"])
        paths = self._record_paths()
        if path not in paths and len(paths) >= MAX_EMPLOYEES:
            raise CompanionError("Companion employee capacity exceeded")
        raw = json.dumps(state, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
            raise CompanionError("Companion record exceeds its size limit")
        file_lock.atomic_write_text(path, raw)

    def _event(self, state: dict, actor: str, action: str) -> dict:
        event = {"id": uuid.uuid4().hex, "actor": actor, "owner": state["owner"],
                 "action": action, "revision": state["policy"]["revision"],
                 "time": max(time.time(), state["turn_clock"]),
                 "decision": "allowed", "reason": _REASONS[action]}
        state["events"] = [*state["events"], event][-MAX_EVENTS:]
        return event

    def _history(self, state: dict) -> list[dict]:
        blob = self._history_blob(state)
        if blob is None:
            return []
        try:
            history = _decode(crypto_at_rest.unseal_bound(
                blob, "employee_companion/history/" + state["owner"],
            ))
            if not isinstance(history, list) or len(history) > MAX_HISTORY:
                raise CompanionValidationError("Invalid companion history")
            for exchange in history:
                _validate_exchange(exchange, state["policy"]["revision"])
            return history
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise CompanionError("Companion private history is invalid; access refused") from exc

    def _retained(self, state: dict, *, now: float) -> list[dict]:
        policy = state["policy"]
        if not policy["enabled"] or policy["retention_days"] == 0:
            return []
        history = self._history(state)
        for exchange in history:
            exchange["expires_at"] = min(
                exchange["expires_at"], exchange["time"] + policy["retention_days"] * 86400,
            )
        return [exchange for exchange in history if exchange["expires_at"] > now]

    def _set_history(self, state: dict, history: list[dict]) -> None:
        if not history:
            state["history"] = None
            return
        raw = json.dumps(history, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        blob = crypto_at_rest.seal_bound(
            raw.encode("utf-8"), "employee_companion/history/" + state["owner"],
        )
        if not crypto_at_rest.is_bound(blob):
            raise CompanionError("Companion history encryption is unavailable")
        state["history"] = base64.b64encode(blob).decode("ascii")

    @staticmethod
    def _now(state: dict) -> float:
        now = time.time()
        if not _timestamp(now):
            raise CompanionError("Companion request clock is unavailable")
        # Receipt pruning must never make a consumed request fresh again after
        # a wall-clock rollback. Persist this floor with every turn mutation.
        state["turn_clock"] = max(now, state["turn_clock"])
        return state["turn_clock"]

    def _prepare_turns(self, state: dict) -> float:
        now = self._now(state)
        changed = False
        for turn in state["turns"]:
            if turn["state"] == "pending" and turn["expires_at"] <= now:
                turn.update(state="expired", finished_at=now)
                self._event(state, state["owner"], "turn_expired")
                changed = True
        retained = [turn for turn in state["turns"]
                    if turn["state"] == "pending" or turn["started_at"] + TURN_RECEIPT_SECONDS > now]
        if len(retained) != len(state["turns"]):
            state["turns"] = retained
            changed = True
        if changed:
            self._save(state)
        return now

    def _invalidate_turns(self, state: dict) -> None:
        now = self._now(state)
        state["history_generation"] += 1
        for turn in state["turns"]:
            if turn["state"] == "pending":
                turn.update(state="cancelled", finished_at=now)
                self._event(state, state["owner"], "turn_cancelled")

    def _held_by_matter(self, state: dict, kept: list[dict]) -> list[dict]:
        """``kept`` plus every stored exchange that an active legal matter holds in scope.

        Retention, disabling and pruning never remove a held exchange.  An unreadable
        matter ledger keeps every stored exchange.  Call this before the stored
        history is replaced.
        """
        try:
            windows = personal_hold_windows(state["owner"])
        except LegalHoldApplies:
            return self._history(state)
        if not windows:
            return kept
        original = self._history(state)
        by_id = {item["id"]: item for item in kept}
        return [by_id.get(item["id"], item) for item in original
                if item["id"] in by_id or in_hold(float(item["time"]), windows)]

    def _prune_history(self, state: dict) -> list[dict]:
        original = self._history(state)
        history = self._held_by_matter(state, self._retained(state, now=self._now(state)))
        if history != original:
            self._set_history(state, history)
            self._invalidate_turns(state)
            self._event(state, state["owner"], "history_expired")
            self._save(state)
        return history

    @staticmethod
    def _require_draft_policy(policy: dict) -> None:
        if not policy["enabled"] or "draft_reply" not in policy["allowed_tools"]:
            raise CompanionPolicyDenied("Your administrator has not allowed model conversation")

    @staticmethod
    def _find_turn(state: dict, request_id: str) -> dict | None:
        return next((turn for turn in state["turns"] if turn["request_id"] == request_id), None)

    def _require_turn(self, state: dict, *, request_id: str, token: str,
                      expected_revision: int, history_generation: int) -> dict:
        turn = self._find_turn(state, request_id)
        if (turn is None or not hmac.compare_digest(turn["token"], token)
                or turn["state"] != "pending"
                or turn["expires_at"] <= self._now(state)
                or state["policy"]["revision"] != expected_revision
                or turn["revision"] != expected_revision
                or state["history_generation"] != history_generation
                or turn["history_generation"] != history_generation):
            raise CompanionConflictError("Companion request is no longer active; refresh the conversation")
        self._require_draft_policy(state["policy"])
        return turn

    @staticmethod
    def _validate_ticket(request_id, token, expected_revision, history_generation) -> None:
        _request_timestamp(request_id)
        if (not isinstance(token, str) or not _HEX_ID.fullmatch(token)
                or not _integer(expected_revision) or not _integer(history_generation)):
            raise CompanionValidationError("Invalid companion turn ticket")

    def conversation_state(self, owner: str) -> dict:
        """Employee lifecycle metadata, with no lease secrets or private text."""
        owner = _identity(owner)
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            pending = next((turn for turn in state["turns"] if turn["state"] == "pending"), None)
            return {"history_generation": state["history_generation"],
                    "active_turn": _turn_metadata(pending) if pending else None}

    def _history_review(self, state: dict) -> dict:
        history = state["history"]
        pending = next((turn for turn in state["turns"] if turn["state"] == "pending"), None)
        # The opaque revision binds a review to the latest saved exchange,
        # policy, and pending reply without returning private conversation text.
        material = [state["policy"]["revision"], state["history_generation"],
                    state["events"][-1]["id"] if state["events"] else None,
                    pending["request_id"] if pending else None,
                    hashlib.sha256(history.encode()).hexdigest() if history else None]
        return {"revision": hashlib.sha256(json.dumps(material).encode()).hexdigest(),
                "saved_exchanges": len(self._history(state)),
                "reply_pending": pending is not None,
                "retention_days": state["policy"]["retention_days"],
                "enabled": state["policy"]["enabled"]}

    def history_review(self, owner: str) -> dict:
        owner = _identity(owner)
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            self._prune_history(state)
            return self._history_review(state)

    def history_clear_receipt(self, owner: str, operation_id: str) -> dict | None:
        owner = _identity(owner)
        if not isinstance(operation_id, str) or not _HEX_ID.fullmatch(operation_id):
            raise CompanionValidationError("Invalid companion operation")
        with self._locked():
            state = self._read(owner)
            return next((copy.deepcopy(event) for event in state["events"]
                         if event["id"] == operation_id and event["actor"] == owner
                         and event["action"] == "history_cleared"), None)

    def turn_status(self, owner: str, request_id: str) -> dict:
        """Recover request outcome without retrying it or exposing its content."""
        owner = _identity(owner)
        _request_timestamp(request_id)
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            turn = self._find_turn(state, request_id)
            return _turn_metadata(turn) if turn else {"request_id": request_id, "state": "not_started"}

    def turn_result(self, owner: str, request_id: str) -> dict:
        """Read this exact request's retained answer, never infer it from text.

        Callers must enforce current owner and source authority before exposing
        the answer. Clearing, expiry and retention limits can remove the answer
        while the consumed request receipt remains available.
        """
        owner = _identity(owner)
        _request_timestamp(request_id)
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            self._prune_history(state)
            turn = self._find_turn(state, request_id)
            if turn is None:
                return {"request": {"request_id": request_id, "state": "not_started"},
                        "reply": None, "binding": None}
            reply = next((copy.deepcopy(item) for item in self._history(state)
                          if turn["state"] == "completed" and item["id"] == turn["trace_id"]), None)
            return {"request": _turn_metadata(turn), "reply": reply,
                    "binding": {"revision": turn["revision"], "history_generation": turn["history_generation"],
                                "fingerprint": turn["fingerprint"]}}

    def reserve_turn(self, owner: str, *, request_id: str, expected_revision: int,
                     expected_history_generation: int, fingerprint: str) -> dict:
        """Admit exactly one application dispatch; a duplicate never gets a token.

        IDs are ``<issued Unix milliseconds>.<32 lowercase UUID hex digits>``.
        They must be fresh for a new admission. Receipts outlive that acceptance
        window and are never evicted early to make room for another paid call.
        """
        owner = _identity(owner)
        issued_at = _request_timestamp(request_id)
        if (not _integer(expected_revision) or not _integer(expected_history_generation)
                or not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint)):
            raise CompanionValidationError("Invalid companion request binding")
        with self._locked():
            state = self._read(owner)
            now = self._prepare_turns(state)
            self._prune_history(state)
            if (issued_at < now - REQUEST_FRESH_SECONDS
                    or issued_at > now + REQUEST_CLOCK_SKEW_SECONDS):
                raise CompanionConflictError("Companion request identifier expired; start a new message")
            previous = self._find_turn(state, request_id)
            if previous:
                if not hmac.compare_digest(previous["fingerprint"], fingerprint):
                    raise CompanionConflictError("Companion request identifier was already used for another message")
                return {**_turn_metadata(previous), "acquired": False}
            if (state["policy"]["revision"] != expected_revision
                    or state["history_generation"] != expected_history_generation):
                raise CompanionConflictError("Companion conversation changed; refresh before sending")
            self._require_draft_policy(state["policy"])
            if any(turn["state"] == "pending" for turn in state["turns"]):
                raise CompanionConflictError("Your companion is still replying; wait before sending again")
            if len(state["turns"]) >= MAX_TURN_RECEIPTS:
                raise CompanionError("Companion request capacity reached; try again after receipts expire")
            turn = {"request_id": request_id, "fingerprint": fingerprint, "token": uuid.uuid4().hex,
                    "revision": expected_revision, "history_generation": expected_history_generation,
                    "state": "pending", "started_at": now, "finished_at": None,
                    "expires_at": now + TURN_LEASE_SECONDS, "trace_id": None}
            state["turns"].append(turn)
            self._event(state, owner, "turn_started")
            self._save(state)
            return {**_turn_metadata(turn), "token": turn["token"], "revision": expected_revision,
                    "history_generation": expected_history_generation, "acquired": True}

    def validate_turn(self, owner: str, *, request_id: str, token: str,
                      expected_revision: int, history_generation: int) -> dict:
        """Recheck a reservation under the service's authority fence before I/O.

        This check is not permission to retry a physical model request. The
        caller must dispatch only once after acquiring the original ticket.
        """
        owner = _identity(owner)
        self._validate_ticket(request_id, token, expected_revision, history_generation)
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            self._prune_history(state)
            turn = self._require_turn(state, request_id=request_id, token=token,
                                      expected_revision=expected_revision,
                                      history_generation=history_generation)
            return _turn_metadata(turn)

    def _room_for_one(self, state: dict, history: list[dict]) -> list[dict]:
        """``history`` with the oldest exchanges no legal matter holds removed
        until one more fits under ``MAX_HISTORY``. Refuses when every stored
        exchange is held, because the cap must never evict a held one."""
        held = {item["id"] for item in self._held_by_matter(state, [])}
        history = list(history)
        while len(history) >= MAX_HISTORY:
            victim = next((item for item in history if item["id"] not in held), None)
            if victim is None:
                raise CompanionConflictError(
                    "Companion history is full of exchanges a legal matter holds; "
                    "the reply cannot be saved until the hold is released")
            history.remove(victim)
        return history

    def _record_reply(self, state: dict, *, message: str, response: str,
                      source_refs: list[str], action: str, model_route: str | None = None) -> dict:
        generation = state["history_generation"]
        history = self._prune_history(state)
        if state["history_generation"] != generation:
            raise CompanionConflictError("Companion context expired; refresh the conversation")
        now = self._now(state)
        policy = state["policy"]
        # A held exchange stays past its expiry; it is not live context.
        context_deadline = min((entry["expires_at"] for entry in history
                                if entry["expires_at"] > now), default=math.inf)
        before_reply = copy.deepcopy(state)
        event = self._event(state, state["owner"], action)
        if policy["retention_days"]:
            history = [*self._room_for_one(state, history), {
                "id": event["id"], "time": now,
                "expires_at": now + policy["retention_days"] * 86400,
                "message": message, "response": response,
                "source_refs": list(source_refs), "policy_revision": policy["revision"],
                "kind": "draft" if action == "draft_reply" else "task_status",
                "model_route": model_route,
            }]
        self._set_history(state, history)
        if self._now(state) >= context_deadline:
            # Expiry during sealing must invalidate the old context, without
            # accidentally publishing the new draft/event from this attempt.
            self._prune_history(before_reply)
            raise CompanionConflictError("Companion context expired before the reply could be saved")
        return {"trace": copy.deepcopy(event), "history": copy.deepcopy(history)}

    def finish_turn(self, owner: str, *, request_id: str, token: str,
                    expected_revision: int, history_generation: int, message: str,
                    response: str, source_refs: list[str], model_route: str | None = None) -> dict:
        """Publish one reply iff its admitted policy and history still exist."""
        owner = _identity(owner)
        self._validate_ticket(request_id, token, expected_revision, history_generation)
        _validate_text(message, response, source_refs)
        _validate_model_route(model_route)
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            self._prune_history(state)
            turn = self._require_turn(state, request_id=request_id, token=token,
                                      expected_revision=expected_revision,
                                      history_generation=history_generation)
            if source_refs and "own_tasks" not in state["policy"]["allowed_sources"]:
                raise CompanionPolicyDenied("Task context is not permitted by the current policy")
            result = self._record_reply(state, message=message, response=response,
                                        source_refs=source_refs, action="draft_reply", model_route=model_route)
            if self._now(state) >= turn["expires_at"]:
                # Encryption/storage preparation is still outside publication.
                # A lease that expired during that work cannot save its reply.
                raise CompanionConflictError("Companion request expired before the reply could be saved")
            turn.update(state="completed", finished_at=self._now(state), trace_id=result["trace"]["id"])
            self._save(state)
            return {**result, "response": response, "source_refs": list(source_refs)}

    def abandon_turn(self, owner: str, *, request_id: str, token: str) -> dict:
        """Consume a failed request without permitting an automatic retry."""
        owner = _identity(owner)
        self._validate_ticket(request_id, token, 0, 0)
        with self._locked():
            state = self._read(owner)
            now = self._prepare_turns(state)
            turn = self._find_turn(state, request_id)
            if turn is None or not hmac.compare_digest(turn["token"], token):
                raise CompanionConflictError("Companion request ticket is unavailable")
            if turn["state"] == "pending":
                turn.update(state="failed", finished_at=now)
                self._event(state, owner, "turn_failed")
                self._save(state)
            return _turn_metadata(turn)

    def policies(self) -> list[dict]:
        """Administrative policy metadata; never opens history envelopes."""
        with self._locked():
            return [copy.deepcopy(self._read_path(path)["policy"]) for path in self._record_paths()]

    def events(self) -> list[dict]:
        """Latest 200 tenant event metadata entries, without content decryption."""
        with self._locked():
            events = []
            for path in self._record_paths():
                events.extend(self._read_path(path)["events"])
                events = sorted(events, key=lambda event: event["time"])[-MAX_EVENTS:]
            return copy.deepcopy(events)

    def policy(self, owner: str) -> dict:
        owner = _identity(owner)
        with self._locked():
            return copy.deepcopy(self._read(owner)["policy"])

    def update_policy(self, owner: str, *, actor: str, expected_revision: int,
                      enabled: bool, allowed_sources: list[str], allowed_tools: list[str],
                      retention_days: int) -> dict:
        owner, actor = _identity(owner), _identity(actor)
        _validate_options(enabled, allowed_sources, allowed_tools, retention_days)
        if not _integer(expected_revision):
            raise CompanionValidationError("An exact policy revision is required")
        with self._locked():
            state = self._read(owner)
            if state["policy"]["revision"] != expected_revision:
                raise CompanionConflictError("Companion policy changed; reload before saving")
            # First apply the prior retention limit, so a longer policy cannot
            # resurrect already expired exchanges. Disabling always erases them.
            history = self._retained(state, now=time.time()) if enabled and retention_days else []
            state["policy"] = {
                **_default_policy(owner), "revision": expected_revision + 1, "enabled": enabled,
                "allowed_sources": list(allowed_sources), "allowed_tools": list(allowed_tools),
                "retention_days": retention_days, "updated_at": time.time(), "updated_by": actor,
            }
            for exchange in history:
                exchange["expires_at"] = min(
                    exchange["expires_at"], exchange["time"] + retention_days * 86400,
                )
            kept = [entry for entry in history if entry["expires_at"] > time.time()]
            self._set_history(state, self._held_by_matter(state, kept))
            self._invalidate_turns(state)
            self._event(state, actor, "policy_updated")
            self._save(state)
            return copy.deepcopy(state["policy"])

    def history(self, owner: str) -> list[dict]:
        owner = _identity(owner)
        with self._locked():
            state = self._read(owner)
            history = self._prune_history(state)
            return copy.deepcopy(history)

    def held_exchanges(self, owner: str) -> list[dict]:
        """Every stored exchange of ``owner``, read without pruning or saving (legal-matter export)."""
        owner = _identity(owner)
        with self._locked():
            return copy.deepcopy(self._history(self._read(owner)))

    def record_exchange(self, owner: str, *, message: str, response: str,
                        source_refs: list[str], expected_revision: int) -> dict:
        owner = _identity(owner)
        _validate_text(message, response, source_refs)
        if not _integer(expected_revision):
            raise CompanionValidationError("An exact policy revision is required")
        with self._locked():
            state = self._read(owner)
            self._prepare_turns(state)
            self._prune_history(state)
            policy = state["policy"]
            if policy["revision"] != expected_revision:
                raise CompanionConflictError("Companion policy changed; send the request again")
            if not policy["enabled"]:
                raise CompanionPolicyDenied("Your administrator has not enabled your companion")
            if ("own_tasks" not in policy["allowed_sources"]
                    or "task_status" not in policy["allowed_tools"]):
                raise CompanionPolicyDenied("Task sources are not permitted by the current policy")
            if any(turn["state"] == "pending" for turn in state["turns"]):
                raise CompanionConflictError("Your companion is still replying; wait before sending again")
            result = self._record_reply(state, message=message, response=response,
                                        source_refs=source_refs, action="reply")
            self._save(state)
            return result

    def clear_history(self, owner: str, *, actor: str, expected_revision: str | None = None,
                      operation_id: str | None = None) -> dict:
        owner, actor = _identity(owner), _identity(actor)
        if actor != owner:
            raise CompanionPolicyDenied("Only the employee can clear their private history")
        if operation_id is not None and not _HEX_ID.fullmatch(operation_id):
            raise CompanionValidationError("Invalid companion operation")
        with self._locked():
            state = self._read(owner)
            if operation_id is not None:
                receipt = next((event for event in state["events"] if event["id"] == operation_id), None)
                if receipt is not None:
                    if receipt["actor"] != actor or receipt["action"] != "history_cleared":
                        raise CompanionConflictError("Companion operation was already used")
                    return copy.deepcopy(receipt)
            if expected_revision is not None:
                self._prepare_turns(state)
                self._prune_history(state)
                if self._history_review(state)["revision"] != expected_revision:
                    raise CompanionConflictError("Companion conversation changed; review it again")
            # A legal matter naming this person may hold any of these exchanges; the clear stops
            # before anything changes.  Without such a matter the history need not be opened.
            if personal_holds(owner):
                assert_personal_chats_erasable(owner, [float(item["time"]) for item in self._history(state)],
                                               actor=actor)
            state["history"] = None
            self._invalidate_turns(state)
            event = self._event(state, actor, "history_cleared")
            if operation_id is not None:
                event["id"] = operation_id
            self._save(state)
            return copy.deepcopy(event)
