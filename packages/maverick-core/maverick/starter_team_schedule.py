"""Reviewed recurring admission for exact, human-approved starter-team inputs.

The local worker calls ``tick`` with current trusted authority. A tick consumes
one approved inbox item, never reloads a provider or reuses yesterday's export.
An interrupted tick reconciles the same runtime; it never guesses whether a
provider call happened. Reservations consume the reviewed maximum, not a claim
about actual spend. No scheduler starts merely by importing this module.
"""
from __future__ import annotations

import copy
import math
import re
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import date

from .authority_effects import authority_effect_fence
from .file_lock import cross_process_lock
from .governed_operations import ServiceContext, digest
from .governed_records import GovernedRecordStore
from .paths import current_tenant_id_strict, data_dir, tenant_scope
from .starter_team_checks import get_team, team_digest, validate_tables
from .starter_teams import StarterTeamService

_SCHEDULES = GovernedRecordStore("starter_team_schedules", "SCH", "starter_team_schedule", required_backend="local", archive_when_full=False)
_ITEMS = GovernedRecordStore("starter_team_inbox", "STI", "starter_team_inbox", required_backend="local", archive_when_full=False)
_TICKS = GovernedRecordStore("starter_team_ticks", "STT", "starter_team_tick", required_backend="local")
_LOCK = threading.RLock()
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}\Z")
_TTL = 600
_TERMINAL = frozenset({"completed", "blocked", "uncertain"})


def _clean(value):
    row = copy.deepcopy({key: item for key, item in value.items() if key != "_audit_pending"})
    if "definition" in row:
        row.update(row["definition"])
        row["interval_hours"] = row["definition"]["interval_seconds"] / 3600
    return row


def _key(value):
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise ValueError("Use a stable operation key between 8 and 128 characters")
    return value


def _finite(value, label, minimum, maximum):
    if type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value):
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return float(value)


def _setup_binding(setup):
    keys = ("id", "context", "catalog_sha256", "scope", "max_rows", "specialists", "authority", "review_sha256")
    return digest({key: setup[key] for key in keys})


class StarterTeamScheduleService:
    """Local persistent schedules with exact approvals and current authorization.

    ``runtime_factory`` is an internal composition/test seam, never request data.
    It receives the authenticated StarterTeamService and must provide the native
    runtime's review, approve, start and reconcile methods. The production
    default imports StarterTeamRuntime lazily.
    """

    def __init__(self, context: ServiceContext, authorize, *, clock=None, runtime_factory=None, workspace_id=None):
        self.service = StarterTeamService(context, authorize, workspace_id=workspace_id)
        self.context = context
        self.clock = clock or time.time
        self.runtime_factory = runtime_factory

    def _runtime(self, schedule_id=None):
        service = self.service
        if schedule_id is not None:
            def authorize(context, operation, team):
                if self.service.authorize(context, operation, team) is not True:
                    return False
                if operation == "runtime_start":
                    with self._scope():
                        schedule = self._read(_SCHEDULES, schedule_id, "run")
                        self._guard(schedule, "run", runnable=True)
                        if self.clock() >= schedule["definition"]["end_at"]:
                            raise PermissionError("The approved schedule window has ended")
                return True
            service = StarterTeamService(self.context, authorize, workspace_id=self.service.workspace_id)
        if self.runtime_factory is not None:
            return self.runtime_factory(service)
        from .starter_team_runtime import StarterTeamRuntime
        return StarterTeamRuntime(service, schedule_id=schedule_id)

    def _identity(self):
        return {"tenant": self.context.tenant, "owner": self.context.resource_owner,
                "workspace": self.service.workspace_id}

    def _authorize(self, operation, team_id):
        self.service._authorize(operation, get_team(team_id))

    def _human(self):
        if not self.context.human:
            raise PermissionError("An authenticated person must review this change")

    @contextmanager
    def _scope(self):
        with tenant_scope(tenant=self.context.tenant):
            if _SCHEDULES.backend_kind != "local":
                raise RuntimeError("Starter-team scheduling requires one persistent application replica")
            yield

    @contextmanager
    def _write(self, schedule_id):
        with self._scope(), authority_effect_fence(), _LOCK:
            path = data_dir("starter_team_schedule_locks", digest(schedule_id) + ".lock")
            with cross_process_lock(path, strict=True):
                yield

    def _owned(self, row):
        if row is None or any(row.get(key) != value for key, value in self._identity().items()):
            raise KeyError("This schedule is unavailable in your workspace")
        return row

    def _read(self, store, record_id, operation="read"):
        row = self._owned(store.get(record_id))
        self._authorize(operation, row["team_id"])
        return row

    def _definition_current(self, schedule, *, runnable=False):
        definition = schedule["definition"]
        if definition["context"] != self.context.binding():
            raise PermissionError("Schedule authority changed; prepare a new schedule review")
        setup = self.service.get_setup(definition["setup_id"])
        if definition["setup_sha256"] != _setup_binding(setup):
            raise ValueError("Team setup changed; prepare a new schedule review")
        if definition["catalog_sha256"] != team_digest(get_team(schedule["team_id"])):
            raise ValueError("Team definition changed; review the schedule again")
        if runnable and (setup["paused"] or schedule["paused"]):
            raise ValueError("This team or schedule is paused")
        return setup

    def _guard(self, schedule, operation, *, runnable=False):
        self._authorize(operation, schedule["team_id"])
        return self._definition_current(schedule, runnable=runnable)

    def preview_schedule(self, setup_id, *, interval_hours, start_at, end_at, max_runs,
                         max_dollars_per_run, max_total_dollars, max_wall_seconds=300):
        self._human()
        setup = self.service.get_setup(setup_id)
        self._authorize("setup", setup["team_id"])
        now = self.clock()
        interval = _finite(interval_hours, "Interval hours", 1, 8760) * 3600
        start = _finite(start_at, "Start time", now, now + 366 * 86400)
        end = _finite(end_at, "End time", start + 1, now + 366 * 86400)
        per_run = _finite(max_dollars_per_run, "Per-run dollar cap", 0.01, 100)
        total = _finite(max_total_dollars, "Total dollar cap", per_run, 1000)
        wall = _finite(max_wall_seconds, "Per-run wall seconds", 1, 1800)
        if type(max_runs) is not int or not 1 <= max_runs <= 100:
            raise ValueError("A schedule needs between 1 and 100 runs")
        definition = {"setup_id": setup_id, "setup_sha256": _setup_binding(setup),
                      "catalog_sha256": setup["catalog_sha256"], "context": self.context.binding(),
                      "interval_seconds": interval, "start_at": start, "end_at": end,
                      "max_runs": max_runs, "max_dollars_per_run": per_run,
                      "max_total_dollars": total, "max_wall_seconds": wall,
                      "input_policy": "each_exact_inbox_item_requires_human_runtime_approval",
                      "authority": "prepare_only", "trigger": "approved_inbox_at_or_after_due_time"}
        record = {"id": "SCH-" + uuid.uuid4().hex, **self._identity(), "team_id": setup["team_id"],
                  "definition": definition, "binding_sha256": digest(definition),
                  "expires_at": now + _TTL, "status": "awaiting_confirmation", "paused": True,
                  "run_count": 0, "committed_dollars": 0.0, "next_due": start,
                  "active_item_id": None, "active_reservation": None, "pause_receipts": []}
        with self._write(record["id"]):
            self._guard(record, "setup")
            return _clean(_SCHEDULES.create(record, action="schedule_review_prepared", actor=self.context.actor,
                max_records=500, effect_guard=lambda: self._guard(record, "setup")))

    def _review(self, review):
        if not isinstance(review, dict) or not isinstance(review.get("id"), str):
            raise ValueError("Prepare a schedule review first")
        row = self._read(_SCHEDULES, review["id"], "setup")
        if row["definition"] != review.get("definition") or row["binding_sha256"] != review.get("binding_sha256"):
            raise ValueError("This schedule review changed")
        self._guard(row, "setup")
        return row

    def schedule_for_review(self, review):
        with self._scope():
            row = self._review(review)
            return None if row["status"] == "awaiting_confirmation" else _clean(row)

    def save_schedule(self, review, *, confirmed):
        self._human()
        if confirmed is not True:
            raise ValueError("Review and confirm the exact schedule")
        with self._write(review.get("id", "") if isinstance(review, dict) else ""):
            row = self._review(review)
            if row["status"] != "awaiting_confirmation":
                return _clean(row)
            if self.clock() >= row["expires_at"]:
                raise ValueError("This schedule review expired")
            def activate(current):
                current.update(status="active", paused=False, approved_by=self.context.actor,
                               approved_at=self.clock(), approval_sha256=row["binding_sha256"])
            return _clean(_SCHEDULES.update(row["id"], activate, expected_revision=row["revision"],
                action="schedule_review_confirmed", actor=self.context.actor,
                effect_guard=lambda: self._guard(row, "setup")))

    def get_schedule(self, schedule_id):
        with self._scope():
            return _clean(self._read(_SCHEDULES, schedule_id))

    def list_schedules(self):
        with self._scope():
            rows = []
            for row in _SCHEDULES.list(limit=501):
                if any(row.get(key) != value for key, value in self._identity().items()):
                    continue
                try:
                    self._authorize("read", row["team_id"])
                except PermissionError:
                    continue
                rows.append(_clean(row))
            return rows

    def set_paused(self, schedule_id, *, paused, expected_revision, idempotency_key):
        self._human()
        key = _key(idempotency_key)
        if type(paused) is not bool or type(expected_revision) is not int:
            raise ValueError("Pause requires a boolean and the reviewed revision")
        with self._write(schedule_id):
            row = self._read(_SCHEDULES, schedule_id, "pause")
            for receipt in row["pause_receipts"]:
                if receipt["key"] == key:
                    if (receipt["paused"], receipt["before_revision"], receipt["actor"]) != (paused, expected_revision, self.context.actor):
                        raise ValueError("This operation key belongs to a different pause change")
                    return _clean(row)
            if row["status"] == "awaiting_confirmation":
                raise ValueError("Confirm the schedule review before changing its paused state")
            if not paused:
                self._guard(row, "pause")
            def change(current):
                current.update(paused=paused)
                current["pause_receipts"] = [*current["pause_receipts"], {
                    "key": key, "paused": paused, "before_revision": expected_revision,
                    "actor": self.context.actor, "recorded_at": self.clock()}][-100:]
            return _clean(_SCHEDULES.update(schedule_id, change, expected_revision=expected_revision,
                action="schedule_paused" if paused else "schedule_resumed", actor=self.context.actor,
                effect_guard=lambda: self._authorize("pause", row["team_id"])))

    def get_pause_for_key(self, schedule_id, key):
        row = self.get_schedule(schedule_id)
        return next((copy.deepcopy(value) for value in row["pause_receipts"]
                     if value["key"] == key and value["actor"] == self.context.actor), None)

    def _item_id(self, schedule_id, key):
        return "STI-" + digest({**self._identity(), "schedule_id": schedule_id, "key": _key(key)})[:40]

    def get_item(self, item_id):
        with self._scope():
            return _clean(self._read(_ITEMS, item_id))

    def get_item_for_key(self, schedule_id, key):
        with self._scope():
            self._read(_SCHEDULES, schedule_id)
            row = _ITEMS.get(self._item_id(schedule_id, key))
            return _clean(self._read(_ITEMS, row["id"])) if row else None

    def list_items(self, schedule_id):
        with self._scope():
            self._read(_SCHEDULES, schedule_id)
            return [_clean(row) for row in _ITEMS.list(limit=5001)
                    if row.get("schedule_id") == schedule_id and all(row.get(key) == value for key, value in self._identity().items())]

    def preview_item(self, schedule_id, tables, *, as_of, idempotency_key):
        self._human()
        date.fromisoformat(as_of)
        item_id = self._item_id(schedule_id, idempotency_key)
        with self._write(schedule_id):
            schedule = self._read(_SCHEDULES, schedule_id, "setup")
            setup = self._guard(schedule, "setup")
            if schedule["status"] == "awaiting_confirmation":
                raise ValueError("Confirm this schedule before submitting inputs")
            validate_tables(get_team(schedule["team_id"]), tables, max_rows=setup["max_rows"])
            binding = digest({"tables": tables, "as_of": as_of, "schedule_sha256": schedule["binding_sha256"],
                              "context": self.context.binding()})
            existing = _ITEMS.get(item_id)
            if existing is not None:
                self._owned(existing)
                if existing["input_binding"] != binding:
                    raise ValueError("This operation key belongs to different evidence")
                return _clean(existing)
            case = self.service.run_inputs(setup["id"], tables, as_of=as_of,
                                           idempotency_key="scheduled:" + item_id)
            definition = schedule["definition"]
            review = self._runtime(schedule_id).review_runtime(case["id"], max_dollars=definition["max_dollars_per_run"],
                                                   max_wall_seconds=definition["max_wall_seconds"])
            row = {"id": item_id, **self._identity(), "team_id": schedule["team_id"],
                   "schedule_id": schedule_id, "schedule_sha256": schedule["binding_sha256"],
                   "case_id": case["id"], "input_binding": binding, "input_sha256": digest(tables),
                   "as_of": as_of, "runtime_review": review, "runtime_review_sha256": digest(review),
                   "status": "awaiting_approval", "idempotency_key": idempotency_key}
            return _clean(_ITEMS.create(row, action="schedule_input_review_prepared", actor=self.context.actor,
                max_records=5000, effect_guard=lambda: self._guard(schedule, "setup")))

    def _item_review(self, review):
        if not isinstance(review, dict) or not isinstance(review.get("id"), str):
            raise ValueError("Prepare an input review first")
        row = self._read(_ITEMS, review["id"], "setup")
        keys = ("schedule_id", "schedule_sha256", "input_binding", "runtime_review", "runtime_review_sha256")
        if any(row[key] != review.get(key) for key in keys):
            raise ValueError("The evidence or runtime review changed")
        schedule = self._read(_SCHEDULES, row["schedule_id"], "setup")
        self._guard(schedule, "setup")
        if row["schedule_sha256"] != schedule["binding_sha256"]:
            raise ValueError("The schedule changed; prepare a new input review")
        return row, schedule

    def item_for_review(self, review):
        with self._scope():
            row, _schedule = self._item_review(review)
            return None if row["status"] == "awaiting_approval" else _clean(row)

    def approve_item(self, item_review, *, confirmed):
        self._human()
        if confirmed is not True:
            raise ValueError("Confirm this exact evidence and specialist runtime review")
        with self._write(item_review.get("schedule_id", "") if isinstance(item_review, dict) else ""):
            row, schedule = self._item_review(item_review)
            if row["status"] != "awaiting_approval":
                return _clean(row)
            self._runtime(schedule["id"]).approve_runtime(row["runtime_review"], confirmed=True)
            def approve(current):
                current.update(status="approved", approved_by=self.context.actor,
                               approved_at=self.clock(), approval_sha256=row["runtime_review_sha256"])
            return _clean(_ITEMS.update(row["id"], approve, expected_revision=row["revision"],
                action="schedule_input_approved", actor=self.context.actor,
                effect_guard=lambda: self._guard(schedule, "setup")))

    def _tick_id(self, schedule_id, key):
        return "STT-" + digest({**self._identity(), "schedule_id": schedule_id, "key": _key(key)})[:40]

    def tick_for_key(self, schedule_id, key):
        with self._scope():
            self._read(_SCHEDULES, schedule_id)
            row = _TICKS.get(self._tick_id(schedule_id, key))
            return _clean(self._read(_TICKS, row["id"])) if row else None

    def _next_item(self, schedule):
        if schedule["active_item_id"]:
            return self._read(_ITEMS, schedule["active_item_id"])
        eligible = [row for row in self.list_items(schedule["id"]) if row["status"] == "approved"]
        return min(eligible, key=lambda row: (row["approved_at"], row["id"])) if eligible else None

    def _admission_reason(self, schedule, item):
        definition, now = schedule["definition"], self.clock()
        if schedule["status"] == "awaiting_confirmation":
            return "schedule_review_required"
        if schedule["paused"]:
            return "paused"
        if now < definition["start_at"] or (not schedule["active_item_id"] and now < schedule["next_due"]):
            return "not_due"
        if now >= definition["end_at"]:
            return "schedule_window_ended"
        if not item:
            return "waiting_for_approved_inputs"
        if not schedule["active_item_id"]:
            if schedule["run_count"] >= definition["max_runs"]:
                return "run_limit_reached"
            if schedule["committed_dollars"] + definition["max_dollars_per_run"] > definition["max_total_dollars"] + 1e-9:
                return "total_budget_reserved"
        if item["status"] not in {"approved", "running"}:
            return "input_requires_review"
        if item.get("approval_sha256") != digest(item["runtime_review"]):
            raise PermissionError("The exact input runtime has no recorded human approval")
        return ""

    def _reconcile_active(self, schedule):
        if not schedule["active_item_id"]:
            return schedule
        item = self._read(_ITEMS, schedule["active_item_id"])
        if item["status"] == "approved":
            return self._recover_claim(schedule, item)
        if item["status"] not in _TERMINAL:
            return schedule
        def settle(current):
            current.update(active_item_id=None, active_reservation=None, paused=item["status"] != "completed",
                           status="active" if item["status"] == "completed" else "needs_review")
        return _SCHEDULES.update(schedule["id"], settle, expected_revision=schedule["revision"],
            action="schedule_occurrence_reconciled", actor=self.context.actor,
            effect_guard=lambda: self._authorize("run", schedule["team_id"]))

    @staticmethod
    def _reservation(schedule, item, occurrence):
        return {"item_id": item["id"], "occurrence": occurrence,
                "input_binding": item["input_binding"], "runtime_review_sha256": item["runtime_review_sha256"],
                "schedule_sha256": schedule["binding_sha256"],
                "max_dollars": schedule["definition"]["max_dollars_per_run"]}

    def _claim_recoverable(self, schedule, item):
        definition = schedule["definition"]
        approval = digest(item["runtime_review"])
        if (schedule.get("active_reservation") != self._reservation(schedule, item, schedule["run_count"])
                or item["schedule_id"] != schedule["id"] or item["schedule_sha256"] != schedule["binding_sha256"]
                or item.get("occurrence") is not None):
            return False
        if (item.get("approval_sha256") != approval or item["runtime_review_sha256"] != approval
                or item["runtime_review"]["context"] != self.context.binding()
                or item["runtime_review"]["max_dollars"] != definition["max_dollars_per_run"]
                or item["runtime_review"]["max_wall_seconds"] != definition["max_wall_seconds"]):
            return False
        expected = math.fsum([definition["max_dollars_per_run"]] * schedule["run_count"])
        return (1 <= schedule["run_count"] <= definition["max_runs"]
                and schedule["committed_dollars"] == expected
                and expected <= definition["max_total_dollars"] + 1e-9)

    def _recover_claim(self, schedule, item):
        # The schedule reservation is persisted before the inbox transition.
        # An interrupted second write proves no physical dispatch by this tick;
        # repair only that exact claim, retaining its occurrence and budget.
        definition = schedule["definition"]
        if schedule["paused"] or not definition["start_at"] <= self.clock() < definition["end_at"]:
            return schedule
        self._guard(schedule, "run", runnable=True)
        if not self._claim_recoverable(schedule, item):
            return _SCHEDULES.update(schedule["id"], lambda row: row.update(
                paused=True, status="needs_review", hold_reason="incomplete_reservation_requires_review"),
                expected_revision=schedule["revision"], action="schedule_incomplete_claim_held", actor=self.context.actor,
                effect_guard=lambda: self._guard(schedule, "run"))
        _ITEMS.update(item["id"], lambda row: row.update(status="running", occurrence=schedule["run_count"]),
            expected_revision=item["revision"], action="schedule_input_claim_recovered", actor=self.context.actor,
            effect_guard=lambda: self._guard(schedule, "run", runnable=True))
        return schedule

    def tick(self, schedule_id, *, idempotency_key, expected_revision=None, expected_item_id=None):
        """Admit or advance one reviewed item. Never dispatch on a replayed tick."""
        identity = self._tick_id(schedule_id, idempotency_key)
        request = digest({"schedule_id": schedule_id, "expected_revision": expected_revision,
                          "expected_item_id": expected_item_id, "context": self.context.binding()})
        with self._write(schedule_id):
            schedule = self._read(_SCHEDULES, schedule_id, "run")
            prior = _TICKS.get(identity)
            if prior is not None:
                if prior["request_sha256"] != request:
                    raise ValueError("This tick key belongs to a different reviewed request")
                return _clean(self._owned(prior))
            if expected_revision is not None and schedule["revision"] != expected_revision:
                raise ValueError("The schedule changed after the tick review")
            self._guard(schedule, "run")
            schedule = self._reconcile_active(schedule)
            item = self._next_item(schedule)
            if expected_item_id is not None and (item is None or item["id"] != expected_item_id):
                raise ValueError("The next approved input changed after review")
            reason = self._admission_reason(schedule, item)
            receipt = {"id": identity, **self._identity(), "team_id": schedule["team_id"],
                       "schedule_id": schedule_id, "item_id": item["id"] if item else None,
                       "status": "confirmed" if reason else "started", "reason": reason,
                       "idempotency_key": idempotency_key, "request_sha256": request,
                       "definition_sha256": schedule["binding_sha256"]}
            receipt = _TICKS.create(receipt, action="schedule_tick_recorded", actor=self.context.actor,
                max_records=10000, effect_guard=lambda: self._guard(schedule, "run"))
            if reason:
                return _clean(receipt)
            self._guard(schedule, "run", runnable=True)
            if not schedule["active_item_id"]:
                schedule = self._claim(schedule, item)
        # The provider/runtime must not hold the schedule lock. A human can
        # pause while it runs; the current-authority callback gates each stage.
        return self._dispatch_tick(schedule_id, item, receipt)

    def _claim(self, schedule, item):
        definition = schedule["definition"]
        def reserve(current):
            current.update(active_item_id=item["id"], run_count=current["run_count"] + 1,
                           active_reservation=self._reservation(schedule, item, current["run_count"] + 1),
                           committed_dollars=math.fsum([definition["max_dollars_per_run"]] * (current["run_count"] + 1)),
                           next_due=max(self.clock(), current["next_due"]) + definition["interval_seconds"])
        saved = _SCHEDULES.update(schedule["id"], reserve, expected_revision=schedule["revision"],
            action="schedule_occurrence_reserved", actor=self.context.actor,
            effect_guard=lambda: self._guard(schedule, "run", runnable=True))
        def claim(current):
            current.update(status="running", occurrence=saved["run_count"])
        _ITEMS.update(item["id"], claim, expected_revision=item["revision"], action="schedule_input_claimed",
            actor=self.context.actor, effect_guard=lambda: self._guard(saved, "run", runnable=True))
        return saved

    def _dispatch_tick(self, schedule_id, item, receipt):
        with self._scope():
            schedule = self._read(_SCHEDULES, schedule_id, "run")
            self._guard(schedule, "run", runnable=True)
            runtime = self._runtime(schedule_id)
            try:
                result = runtime.start_runtime(item["runtime_review"], confirmed=False)
            except Exception:
                # A refusal or unavailable response must not generate endless
                # background retries. Preserve the original item and reservation;
                # this pause does not assert that a provider effect did not occur.
                self._hold_after_failure(schedule_id, receipt)
                raise
            status = result.get("status")
            if status not in {"ready", "running", *_TERMINAL}:
                raise RuntimeError("The runtime did not confirm a recognized admission state")
        with self._write(schedule_id):
            current = self._read(_SCHEDULES, schedule_id, "run")
            source = self._read(_ITEMS, item["id"], "run")
            observed_revision = result.get("revision", 0)
            if type(observed_revision) is not int or observed_revision < 0:
                raise RuntimeError("The runtime observation revision is invalid")
            # Concurrent ticks may return in the opposite order. A late
            # running observation must never reopen a settled inbox item.
            if (source["status"] in _TERMINAL
                    or observed_revision < source.get("runtime_revision", 0)):
                status = source.get("runtime_status", source["status"])
                result = {"id": source.get("runtime_id", ""), "revision": source.get("runtime_revision", 0)}
                observed_revision = result["revision"]
            def settle_input(row):
                row.update(runtime_status=status, runtime_id=result.get("id", result.get("runtime_id", "")),
                           runtime_revision=observed_revision,
                           status=status if status in _TERMINAL else "running")
            _ITEMS.update(source["id"], settle_input, expected_revision=source["revision"],
                action="schedule_runtime_observed", actor=self.context.actor,
                effect_guard=lambda: self._authorize("run", current["team_id"]))
            if status in _TERMINAL and current["active_item_id"] == item["id"]:
                def release(row):
                    row.update(active_item_id=None, active_reservation=None, paused=status != "completed",
                               status="active" if status == "completed" else "needs_review")
                current = _SCHEDULES.update(schedule_id, release, expected_revision=current["revision"],
                    action="schedule_occurrence_settled", actor=self.context.actor,
                    effect_guard=lambda: self._authorize("run", current["team_id"]))
            def finish(row):
                row.update(status="confirmed", runtime_status=status, runtime_id=result.get("id", ""),
                           run_count=current["run_count"], committed_dollars=current["committed_dollars"],
                           next_due=current["next_due"])
            return _clean(_TICKS.update(receipt["id"], finish, expected_revision=receipt["revision"],
                action="schedule_tick_confirmed", actor=self.context.actor,
                effect_guard=lambda: self._authorize("run", current["team_id"])))

    def _hold_after_failure(self, schedule_id, receipt):
        with self._write(schedule_id):
            row = self._read(_SCHEDULES, schedule_id)
            def hold(current):
                current.update(paused=True, status="needs_review", hold_reason="runtime_did_not_confirm_progress")
            _SCHEDULES.update(schedule_id, hold, expected_revision=row["revision"],
                action="schedule_runtime_held", actor=self.context.actor,
                effect_guard=lambda: self._authorize("read", row["team_id"]))
            def note(current):
                current.update(status="needs_review", reason="runtime_did_not_confirm_progress")
            _TICKS.update(receipt["id"], note, expected_revision=receipt["revision"],
                action="schedule_tick_held", actor=self.context.actor,
                effect_guard=lambda: self._authorize("read", row["team_id"]))


def _runtime_schedule(review):
    from . import starter_teams as native

    tenant = current_tenant_id_strict()
    schedule = _SCHEDULES.get(review.get("schedule_id", ""))
    if (not tenant or schedule is None or tenant != review.get("tenant")
            or any(schedule.get(key) != review.get(key) for key in ("tenant", "owner", "workspace", "team_id"))):
        raise PermissionError("The runtime has no current schedule in this workspace")
    definition = schedule["definition"]
    if (schedule["status"] not in {"active", "needs_review"} or schedule["paused"]
            or schedule.get("approval_sha256") != digest(definition)
            or schedule["binding_sha256"] != digest(definition)):
        raise PermissionError("The approved schedule is paused or its authority changed")
    if not definition["start_at"] <= time.time() < definition["end_at"]:
        raise PermissionError("The approved schedule window is not active")
    if (definition["context"] != review.get("context") or definition["setup_id"] != review.get("setup_id")
            or definition["catalog_sha256"] != team_digest(get_team(schedule["team_id"]))):
        raise PermissionError("The reviewed schedule context or team changed")
    setup = native._SETUPS.get(definition["setup_id"])
    if setup is None or setup["paused"] or _setup_binding(setup) != definition["setup_sha256"]:
        raise PermissionError("The approved schedule team setup changed or is paused")
    return schedule


def require_current_runtime_authority(review):
    """Recheck a queued specialist's exact scheduled admission before execution.

    The native worker calls this again inside its authority effect fence. Its
    current account authorizer remains responsible for live role, membership,
    suite and budget-policy checks; this helper verifies persisted schedule and
    inbox authority in the worker's explicit tenant. It grants no new approval.
    """
    from . import starter_teams as native

    schedule = _runtime_schedule(review)
    item = _ITEMS.get(schedule.get("active_item_id") or "")
    if (item is None or item["status"] != "running" or item["schedule_id"] != schedule["id"]
            or any(item.get(key) != review.get(key) for key in ("tenant", "owner", "workspace", "team_id", "case_id"))):
        raise PermissionError("This runtime is not the schedule's active approved input")
    if (item["schedule_sha256"] != schedule["binding_sha256"]
            or item.get("approval_sha256") != digest(item["runtime_review"])
            or native._material(item["runtime_review"]) != native._material(review)):
        raise PermissionError("The exact scheduled runtime approval changed")
    definition = schedule["definition"]
    if (item.get("occurrence") != schedule["run_count"] or not 1 <= schedule["run_count"] <= definition["max_runs"]
            or review["max_dollars"] != definition["max_dollars_per_run"]
            or review["max_wall_seconds"] != definition["max_wall_seconds"]):
        raise PermissionError("The runtime differs from its reviewed schedule occurrence")
    expected = schedule["run_count"] * definition["max_dollars_per_run"]
    if not expected - 1e-8 <= schedule["committed_dollars"] <= definition["max_total_dollars"] + 1e-9:
        raise PermissionError("The schedule's reviewed budget reservation is unavailable")


def worker_schedules(*, now=None):
    """Trusted worker inventory in the explicitly active tenant; no dispatch.

    Not an HTTP authorization boundary. The worker must reconstruct current
    ServiceContext and pass a current authorization callback before ``tick``.
    """
    tenant = current_tenant_id_strict()
    if not tenant:
        raise PermissionError("Choose an explicit tenant before enumerating schedules")
    if _SCHEDULES.backend_kind != "local":
        raise RuntimeError("Starter-team scheduling requires one persistent application replica")
    current = time.time() if now is None else _finite(now, "Worker time", 0, 1e12)
    approved = {row["schedule_id"] for row in _ITEMS.list(limit=5001)
                if row.get("tenant") == tenant and row.get("status") == "approved"}
    return [_clean(row) for row in _SCHEDULES.list(limit=501)
            if row.get("tenant") == tenant and row.get("status") != "awaiting_confirmation"
            and not row.get("paused", True)
            and row["definition"]["start_at"] <= current < row["definition"]["end_at"]
            and (row.get("active_item_id") or row["id"] in approved and row["next_due"] <= current
                 and row["run_count"] < row["definition"]["max_runs"]
                 and row["committed_dollars"] + row["definition"]["max_dollars_per_run"]
                 <= row["definition"]["max_total_dollars"] + 1e-9)]


__all__ = ["StarterTeamScheduleService", "require_current_runtime_authority", "worker_schedules"]
