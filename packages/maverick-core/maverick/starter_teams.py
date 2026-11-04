"""Reviewed starter-team setup and durable, bounded evidence worklists.

Supported execution is deterministic analysis of supplied structured exports.
No provider, fleet, shell, payment, publishing or connector execution is exposed.
Single persistent application replica; cross-record admission uses a strict
local lock and fails closed when the deployment requires a shared backend.
"""
from __future__ import annotations

import copy
import re
import threading
import time
import uuid
from contextlib import contextmanager

from . import shoring
from .authority_effects import authority_effect_fence
from .file_lock import cross_process_lock
from .governed_operations import ServiceContext, digest
from .governed_records import GovernedRecordStore, RecordConflict
from .paths import data_dir, tenant_scope
from .starter_team_checks import (
    MAX_ROWS,
    _iso_date,
    catalog,
    evaluate,
    get_team,
    team_digest,
    validate_tables,
)

_SETUPS = GovernedRecordStore("starter_team_setups", "STS", "starter_team_setup", required_backend="local", archive_when_full=False)
_REVIEWS = GovernedRecordStore("starter_team_reviews", "STR", "starter_team_review", required_backend="local")
_CASES = GovernedRecordStore("starter_team_cases", "STC", "starter_team_case", required_backend="local", archive_when_full=False)
_LOCK = threading.RLock()
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}\Z")
_TTL = 600
_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})


def _clean(row):
    return copy.deepcopy({key: value for key, value in row.items() if key != "_audit_pending"})


def _material(row):
    return {key: value for key, value in row.items() if key not in _METADATA}


def _text(value, label, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"Provide a {label} of at most {maximum} characters")
    return value.strip()


def _idempotency(value):
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise ValueError("Use an operation key between 8 and 128 characters")
    return value


class StarterTeamService:
    """Request-authorized composition shared by direct UI and Copilot.

    The callback must return True, using current authenticated authority, for
    every operation. ``human`` is supplied only by that trusted composition.
    Review objects are compared to their immutable stored originals, never
    trusted merely because the caller supplies a matching digest.
    """

    def __init__(self, context: ServiceContext, authorize, *, clock=None, workspace_id=None):
        if not isinstance(context, ServiceContext) or not callable(authorize):
            raise TypeError("An authenticated context and current authorization callback are required")
        self.context, self.authorize = context, authorize
        self.clock = clock or time.time
        # Request-selection generations bind reviews, but a stable workspace
        # identity keeps saved work reachable after switching away and back.
        self.workspace_id = _text(workspace_id or context.workspace_authority, "workspace identity", 256)

    def _authorize(self, operation, team):
        if not shoring.enabled():
            raise PermissionError("Autonomous Shoring is disabled by your administrator")
        if self.authorize(self.context, operation, team) is not True:
            raise PermissionError("Current authority does not permit this starter-team operation")
        if operation in {"setup", "pause"} and not self.context.human:
            raise PermissionError("An authenticated human must review this change")

    @contextmanager
    def _scope(self):
        with tenant_scope(tenant=self.context.tenant):
            if _SETUPS.backend_kind != "local":
                raise RuntimeError("Starter teams require one persistent application replica")
            yield

    @contextmanager
    def _write(self, identity):
        with self._scope(), authority_effect_fence(), _LOCK:
            lock = data_dir("starter_team_locks", digest(identity) + ".lock")
            with cross_process_lock(lock, strict=True):
                yield

    def _identity(self):
        return {"tenant": self.context.tenant, "owner": self.context.resource_owner,
                "workspace": self.workspace_id}

    def _owned(self, row):
        if row is None or any(row.get(key) != value for key, value in self._identity().items()):
            raise KeyError("This starter-team record is unavailable in your workspace")
        return row

    def _read(self, store, identity, operation="read"):
        row = self._owned(store.get(identity))
        self._authorize(operation, get_team(row["team_id"]))
        return row

    def preview_setup(self, team_id, owner_label, scope, cadence="manual", max_rows=250):
        team = get_team(team_id)
        self._authorize("setup", team)
        if cadence not in {"manual", "hourly", "daily", "weekly", "monthly"}:
            raise ValueError("Choose a supported review cadence")
        if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
            raise ValueError(f"Row budget must be between 1 and {MAX_ROWS}")
        material = {"id": "STR-" + uuid.uuid4().hex, **self._identity(), "team_id": team_id,
                    "owner_label": _text(owner_label, "named accountable owner", 200),
                    "scope": _text(scope, "scope", 2000), "cadence": cadence, "max_rows": max_rows,
                    "context": self.context.binding(), "catalog_sha256": team_digest(team),
                    "expires_at": self.clock() + _TTL, "authority": "prepare_only",
                    "schedule_status": "review_reminder_only_no_automatic_execution",
                    "specialists": team["specialists"], "connections": team["connections"],
                    "blocked_actions": team["blocked_actions"], "stop_conditions": team["stop_conditions"],
                    "budget": {"max_rows": max_rows, "max_dollars": 0, "max_provider_calls": 0, "max_wall_seconds": 30},
                    "readiness": "sample_and_structured_exports_only"}
        material["binding_sha256"] = digest(material)
        with self._write(material["id"]):
            return _clean(_REVIEWS.create(material, action="setup_review_prepared", actor=self.context.actor,
                                         max_records=2000, effect_guard=lambda: self._authorize("setup", team)))

    def _review(self, review):
        if not isinstance(review, dict) or not isinstance(review.get("id"), str):
            raise ValueError("Prepare a setup review first")
        stored = self._read(_REVIEWS, review["id"], "setup")
        if _material(stored) != _material(review) or stored["context"] != self.context.binding():
            raise ValueError("The setup or your authority changed; prepare a new review")
        return stored

    @staticmethod
    def _setup_id(review):
        return "STS-" + digest(review["id"])[:40]

    def setup_for_review(self, review):
        with self._scope():
            stored = self._review(review)
            saved = _SETUPS.get(self._setup_id(stored))
            return _clean(self._owned(saved)) if saved is not None else None

    def save_setup(self, review, *, confirmed):
        if confirmed is not True:
            raise ValueError("Review the setup and explicitly confirm it")
        with self._write(review.get("id", "") if isinstance(review, dict) else ""):
            stored = self._review(review)
            team = get_team(stored["team_id"])
            prior = _SETUPS.get(self._setup_id(stored))
            if prior is not None:
                return _clean(self._owned(prior))
            if stored["expires_at"] <= self.clock() or stored["catalog_sha256"] != team_digest(team):
                raise ValueError("The review expired or the catalog changed; prepare a new review")
            value = {**_material(stored), "id": self._setup_id(stored), "review_id": stored["id"],
                     "review_sha256": stored["binding_sha256"], "paused": False, "status": "ready",
                     "pause_receipts": [], "business_acceptance": "not_customer_qualified"}
            return _clean(_SETUPS.create(value, action="setup_review_confirmed", actor=self.context.actor,
                                        max_records=500, effect_guard=lambda: self._authorize("setup", team)))

    def list_setups(self):
        with self._scope():
            out = []
            for row in _SETUPS.list(limit=501):
                if any(row.get(key) != value for key, value in self._identity().items()):
                    continue
                try:
                    self._authorize("read", get_team(row["team_id"]))
                except (PermissionError, KeyError):
                    continue
                out.append(_clean(row))
            return out

    def get_setup(self, setup_id):
        with self._scope():
            return _clean(self._read(_SETUPS, setup_id))

    def set_paused(self, setup_id, *, paused, expected_revision, idempotency_key=None):
        if type(paused) is not bool or type(expected_revision) is not int:
            raise ValueError("Pause needs a boolean and the current revision")
        key = _idempotency(idempotency_key or uuid.uuid4().hex)
        with self._write(setup_id):
            row = self._read(_SETUPS, setup_id, "pause")
            for receipt in row["pause_receipts"]:
                if receipt["idempotency_key"] == key:
                    if receipt["paused"] != paused or receipt["before_revision"] != expected_revision:
                        raise ValueError("This operation key belongs to a different pause change")
                    return _clean(row)
            team = get_team(row["team_id"])

            def change(current):
                current.update(paused=paused, status="paused" if paused else "ready")
                current["pause_receipts"] = [*current["pause_receipts"], {
                    "idempotency_key": key, "paused": paused, "before_revision": expected_revision,
                    "after_revision": expected_revision + 1, "actor": self.context.actor}][-100:]

            saved = _SETUPS.update(setup_id, change, expected_revision=expected_revision,
                                  action="team_paused" if paused else "team_resumed", actor=self.context.actor,
                                  effect_guard=lambda: self._authorize("pause", team))
            return _clean(saved)

    def get_pause_for_key(self, setup_id, key):
        row = self.get_setup(setup_id)
        for receipt in row["pause_receipts"]:
            if receipt["idempotency_key"] == key and receipt["actor"] == self.context.actor:
                return copy.deepcopy(receipt)
        return None

    def _case_id(self, setup_id, key):
        return "STC-" + digest({**self._identity(), "setup_id": setup_id, "key": _idempotency(key)})[:40]

    def get_case_for_key(self, setup_id, key):
        with self._scope():
            self._read(_SETUPS, setup_id)
            row = _CASES.get(self._case_id(setup_id, key))
            return _clean(self._read(_CASES, row["id"])) if row else None

    def get_case(self, case_id):
        with self._scope():
            return _clean(self._read(_CASES, case_id))

    def list_cases(self, setup_id):
        with self._scope():
            self._read(_SETUPS, setup_id)
            return [_clean(row) for row in _CASES.list(limit=5001)
                    if row.get("setup_id") == setup_id and all(row.get(key) == value for key, value in self._identity().items())]

    def run_sample(self, setup_id, *, idempotency_key):
        setup = self.get_setup(setup_id)
        sample = get_team(setup["team_id"])["sample"]
        return self._run(setup_id, sample["tables"], as_of=sample["as_of"],
                         idempotency_key=idempotency_key, mode="sample")

    def run_inputs(self, setup_id, tables, *, as_of, idempotency_key):
        return self._run(setup_id, tables, as_of=as_of, idempotency_key=idempotency_key, mode="supplied_export")

    def _run(self, setup_id, tables, *, as_of, idempotency_key, mode):
        _iso_date(as_of)
        with self._write(setup_id):
            setup = self._read(_SETUPS, setup_id, "run")
            team = get_team(setup["team_id"])
            validate_tables(team, tables, max_rows=setup["max_rows"])
            tables = copy.deepcopy(tables)
            identity = self._case_id(setup_id, idempotency_key)
            binding = digest({"tables": tables, "as_of": as_of, "mode": mode,
                              "setup_id": setup_id, "context": self.context.binding()})
            prior = _CASES.get(identity)
            if prior is not None:
                self._owned(prior)
                if prior["request_sha256"] != binding:
                    raise ValueError("This operation key belongs to different inputs or authority")
                if prior["status"] == "awaiting_review":
                    return _clean(prior)
            self._admit(setup, team)
            if prior is None:
                prior = _CASES.create({"id": identity, **self._identity(), "setup_id": setup_id,
                    "team_id": team["id"], "mode": mode, "status": "prepared", "output": None,
                    "idempotency_key": idempotency_key, "request_sha256": binding,
                    "input_sha256": digest(tables), "catalog_sha256": team_digest(team),
                    "tables": tables, "as_of": as_of, "context": self.context.binding(),
                    "handoffs": [], "setup_revision": setup["revision"]},
                    action="case_prepared", actor=self.context.actor, max_records=5000,
                    effect_guard=lambda: self._authorize("run", team))
            # Interrupted pure preparation can safely resume from its exact input.
            output = evaluate(team["id"], tables, as_of=as_of)
            output["readiness"] = "sample_qualified" if mode == "sample" else "structured_inputs_only"
            output["owner"] = setup["owner_label"]
            if mode == "sample":
                actual = sorted(item["id"] for item in output["findings"])
                if (actual != sorted(team["sample"]["expected_findings"])
                        or any(item["kind"] == "input_exception" for item in output["findings"])):
                    raise ValueError("The bundled sample failed its expected-result check; setup needs maintenance")
            self._admit(self._read(_SETUPS, setup_id, "run"), team)

            def complete(current):
                current.update(status="awaiting_review", output=output, handoffs=output["handoffs"])

            return _clean(_CASES.update(identity, complete, expected_revision=prior["revision"],
                                       action="worklist_prepared", actor=self.context.actor,
                                       effect_guard=lambda: self._authorize("run", team)))

    def _admit(self, setup, team):
        if setup["paused"]:
            raise ValueError("This team is paused; review and resume it before starting work")
        if setup["context"] != self.context.binding():
            raise PermissionError("Team authority changed; review a new setup before running")
        if setup["catalog_sha256"] != team_digest(team):
            raise ValueError("The team definition changed; review a new setup before running")


__all__ = ["StarterTeamService", "catalog", "evaluate", "get_team", "RecordConflict"]
