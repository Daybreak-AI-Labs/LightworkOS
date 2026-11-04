"""Frozen paired pilot plans and explicit, source-bound observations.

Measurements are attributed reports, never inferred time savings. Current
business-record acceptance is resolved independently on every report read.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import secrets
import time
from contextlib import contextmanager
from dataclasses import asdict
from decimal import Decimal

from maverick.governed_records import GovernedRecordStore
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES
from maverick.privacy_ops import RecordConflict

STORE = GovernedRecordStore("outcome_pilots", "OPL", "outcome_pilots")
ADMISSION_INDEX = GovernedRecordStore(
    "outcome_pilot_admission_index", "OPI", "outcome_pilot_admission_index",
)
LIMIT = 1000
_ADMISSION_INDEX_ID = "OPI-active-work-items"
_ADMISSION_INDEX_SCHEMA = "lightwork.outcome-pilot-admission-index.v1"
_ADMISSION_MANIFEST_SCHEMA = "lightwork.outcome-pilot-admission-manifest.v1"
_ACTIVE_STATES = frozenset({"preparing", "frozen"})
_MAX_CASES = 100
_MAX_INDEX_RETRIES = 32


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _owned(record, context):
    if record is None or record.get("context") != context:
        raise LookupError("This pilot is unavailable in your account and workspace.")
    return record


def get(pilot_id, context):
    return _owned(STORE.get(pilot_id), context)


def listing(context, *, cursor="", limit=100, records=False):
    """Page through records after filtering by the exact account context.

    ``records=True`` returns the full records the scan already read, so a caller
    that needs them does not read each one again."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("Pilot page size must be between 1 and 200")
    if not isinstance(cursor, str) or len(cursor) > 256:
        raise ValueError("Pilot page cursor is invalid")
    items = []
    last_visible_cursor = cursor
    has_more = False
    for backend_cursor, record_id in STORE.iter_record_ids(
        start_after=cursor,
        limit=LIMIT + 1,
    ):
        # Every backend exposes a rotating scan. Stop before it wraps so a
        # continuation never repeats an earlier page.
        if cursor and backend_cursor <= cursor:
            break
        record = STORE.get(record_id)
        if record is None or record.get("context") != context:
            continue
        if len(items) == limit:
            has_more = True
            break
        items.append(record if records else {
            "id": record["id"],
            "title": record["title"],
            "revision": record["revision"],
            "created_at": record["created_at"],
            "cases": len(record["cases"]),
        })
        last_visible_cursor = backend_cursor
    return {
        "items": items,
        "partial": has_more,
        "page": {
            "has_more": has_more,
            "next_cursor": last_visible_cursor if has_more else None,
        },
    }


def _work_item_key(case):
    return digest({"kind": case["kind"], "reference": case["reference"]})


def _manifest_entries(record):
    contract = f"outcome-pilot:{record['id']}:{record['plan_version']}"
    return [{
        "case_id": case["id"],
        "admission_id": f"{record['id']}:{case['id']}",
        "work_item_id": f"{case['kind']}:{case['reference']}",
        "acceptance_contract_ref": contract,
        "input_version": case["input_version"],
        "accounting_record_id": None,
        "admitted_at": None,
    } for case in record["cases"]]


def admission_manifest(record):
    """Build the complete expected-case manifest before any case is admitted."""
    entries = _manifest_entries(record)
    expected = [{key: entry[key] for key in (
        "case_id", "admission_id", "work_item_id",
        "acceptance_contract_ref", "input_version",
    )} for entry in entries]
    return {
        "schema": _ADMISSION_MANIFEST_SCHEMA,
        "status": "pending",
        "pilot_id": record["id"],
        "plan_version": record["plan_version"],
        "expected_count": len(entries),
        "admitted_count": 0,
        "manifest_sha256": digest(expected),
        "completion_sha256": None,
        "entries": entries,
    }


def completed_admission_manifest(record, admissions):
    """Bind every expected case to its durable accounting admission atomically."""
    expected = admission_manifest(record)
    if not isinstance(admissions, dict) or set(admissions) != {
        entry["case_id"] for entry in expected["entries"]
    }:
        raise ValueError("Outcome accounting did not return every planned case admission.")
    entries = []
    for entry in expected["entries"]:
        admitted = admissions[entry["case_id"]]
        identifier = admitted.get("id") if isinstance(admitted, dict) else None
        admitted_at = admitted.get("admitted_at") if isinstance(admitted, dict) else None
        if (not isinstance(identifier, str) or not identifier or len(identifier) > 200
                or isinstance(admitted_at, bool) or not isinstance(admitted_at, (int, float))
                or not math.isfinite(admitted_at) or admitted_at < 0):
            raise ValueError("Outcome accounting returned an invalid case admission.")
        entries.append({**entry, "accounting_record_id": identifier,
                        "admitted_at": admitted_at})
    completion = [{"case_id": row["case_id"],
                   "accounting_record_id": row["accounting_record_id"],
                   "admitted_at": row["admitted_at"]} for row in entries]
    return {**expected, "status": "complete", "admitted_count": len(entries),
            "completion_sha256": digest([expected["manifest_sha256"], completion]),
            "entries": entries}


def validate_admission_manifest(record, *, require_complete=False):
    """Validate stored manifest shape and its exact binding to the frozen plan."""
    manifest = record.get("admission_manifest")
    manifest_keys = {"schema", "status", "pilot_id", "plan_version",
                     "expected_count", "admitted_count", "manifest_sha256",
                     "completion_sha256", "entries"}
    if not isinstance(manifest, dict) or set(manifest) != manifest_keys:
        raise RecordConflict("This pilot has no durable admission manifest. Retry its original creation request before work starts.")
    expected = admission_manifest(record)
    for key in ("schema", "pilot_id", "plan_version", "expected_count", "manifest_sha256"):
        if manifest.get(key) != expected[key]:
            raise RecordConflict("This pilot admission manifest does not match its frozen plan.")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != expected["expected_count"]:
        raise RecordConflict("This pilot admission manifest is incomplete.")
    immutable = ("case_id", "admission_id", "work_item_id",
                 "acceptance_contract_ref", "input_version")
    entry_keys = {*immutable, "accounting_record_id", "admitted_at"}
    if any(any(row.get(key) != expected_row[key] for key in immutable)
           for row, expected_row in zip(entries, expected["entries"], strict=True)
           if isinstance(row, dict)) or any(not isinstance(row, dict)
                                             or set(row) != entry_keys for row in entries):
        raise RecordConflict("This pilot admission manifest does not match its frozen cases.")
    status = manifest.get("status")
    if status not in {"pending", "complete"}:
        raise RecordConflict("This pilot admission manifest has an invalid state.")
    if status == "pending":
        if (manifest.get("admitted_count") != 0
                or manifest.get("completion_sha256") is not None
                or any(row.get("accounting_record_id") is not None
                       or row.get("admitted_at") is not None for row in entries)):
            raise RecordConflict("This pilot has a partially published admission manifest.")
    else:
        if manifest.get("admitted_count") != len(entries):
            raise RecordConflict("This pilot admission manifest is incomplete.")
        completion = []
        for row in entries:
            identifier, admitted_at = row.get("accounting_record_id"), row.get("admitted_at")
            if (not isinstance(identifier, str) or not identifier or len(identifier) > 200
                    or isinstance(admitted_at, bool) or not isinstance(admitted_at, (int, float))
                    or not math.isfinite(admitted_at) or admitted_at < 0):
                raise RecordConflict("This pilot admission manifest contains an invalid admission.")
            completion.append({"case_id": row["case_id"],
                               "accounting_record_id": identifier,
                               "admitted_at": admitted_at})
        if (len({row["accounting_record_id"] for row in completion}) != len(completion)
                or manifest.get("completion_sha256")
                != digest([manifest["manifest_sha256"], completion])):
            raise RecordConflict("This pilot admission manifest failed its integrity check.")
    if require_complete and status != "complete":
        raise RecordConflict("Every frozen case must be admitted before this pilot can run or accept observations.")
    return manifest


def _sha256_text(value):
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _valid_claim(value):
    return (isinstance(value, dict)
            and set(value) == {"pilot_id", "creation_request"}
            and isinstance(value.get("pilot_id"), str)
            and value["pilot_id"].startswith("OPL-")
            and _sha256_text(value.get("creation_request")))


def _existing_work_item_claims():
    rows = STORE.list(limit=LIMIT + 1)
    if len(rows) > LIMIT:
        raise RecordConflict("Pilot admission could not prove complete active-work coverage.")
    discovered = {}
    for row in rows:
        if row.get("state", "frozen") not in _ACTIVE_STATES:
            continue
        claim = {"pilot_id": row.get("id"),
                 "creation_request": row.get("creation_request")}
        if not _valid_claim(claim):
            raise RecordConflict("Pilot admission could not verify an existing pilot identity.")
        for case in row.get("cases", []):
            try:
                key = _work_item_key(case)
            except (KeyError, TypeError, ValueError) as exc:
                raise RecordConflict("Pilot admission could not verify an existing work-item claim.") from exc
            claimed = discovered.setdefault(key, claim)
            if claimed != claim:
                raise RecordConflict("Existing pilot records contain conflicting active work-item claims.")
    return discovered


def original_plan_claim(identifier, creation_request=None):
    """Pure exact custody of a plan claimed before its pilot row existed."""
    current = ADMISSION_INDEX.get(_ADMISSION_INDEX_ID)
    if current is None:
        return False
    claims = current.get("claims")
    if (current.get("schema") != _ADMISSION_INDEX_SCHEMA or not isinstance(claims, dict)
            or len(claims) > LIMIT * _MAX_CASES
            or any(not _sha256_text(key) or not _valid_claim(value) for key, value in claims.items())):
        raise RecordConflict("The original plan admission cannot be verified. No work was repeated.")
    matching = [value for value in claims.values() if value["pilot_id"] == identifier]
    if creation_request is not None and any(value["creation_request"] != creation_request for value in matching):
        raise RecordConflict("This original request belongs to another plan.")
    return bool(matching)


def _claim_work_items(identifier, cases, actor, creation_request, *, before_write=None):
    """Atomically claim all exact work items within the current tenant."""
    candidate = {"pilot_id": identifier, "creation_request": creation_request}
    if not _sha256_text(creation_request):
        raise RecordConflict("Pilot admission requires an exact creation identity.")
    requested = {_work_item_key(case) for case in cases}
    if len(requested) != len(cases):
        raise ValueError("Each pilot case must use a different task or vendor case.")
    discovered = _existing_work_item_claims()
    for _ in range(_MAX_INDEX_RETRIES):
        current = ADMISSION_INDEX.get(_ADMISSION_INDEX_ID)
        claims = {} if current is None else current.get("claims")
        if current is not None and (current.get("schema") != _ADMISSION_INDEX_SCHEMA
                                    or not isinstance(claims, dict)
                                    or len(claims) > LIMIT * _MAX_CASES
                                    or any(not _sha256_text(key) or not _valid_claim(value)
                                           for key, value in claims.items())):
            raise RecordConflict("Pilot admission could not verify the tenant work-item index.")
        claims = dict(claims or {})
        for key, prior_claim in discovered.items():
            claimed = claims.setdefault(key, prior_claim)
            if claimed != prior_claim:
                raise RecordConflict("Existing pilot records conflict with the tenant work-item index.")
        if any(value["pilot_id"] == identifier and value != candidate
               for value in claims.values()):
            raise RecordConflict("This operation reference already belongs to another pilot.")
        if any(claims.get(key) is not None and claims[key] != candidate
               for key in requested):
            raise RecordConflict("One or more selected work items already belongs to an active or frozen pilot in this tenant. No allocation model is configured.")
        updated = {**claims, **dict.fromkeys(requested, candidate)}
        if len(updated) > LIMIT * _MAX_CASES:
            raise RecordConflict("The tenant pilot work-item admission index reached its safe limit.")
        if current is not None and updated == claims:
            return current
        try:
            if current is None:
                with _guided_creation(_ADMISSION_INDEX_ID, before_write, store=ADMISSION_INDEX):
                    return ADMISSION_INDEX.create({
                        "id": _ADMISSION_INDEX_ID,
                        "schema": _ADMISSION_INDEX_SCHEMA,
                        "claims": updated,
                    }, action="claim_outcome_pilot_work", actor=actor,
                       **({"effect_guard": before_write} if before_write is not None else {}))
            def mutate(value, claimed=updated):
                if before_write is not None:
                    before_write()
                value.update(claims=claimed)
            saved = ADMISSION_INDEX.update(
                _ADMISSION_INDEX_ID,
                mutate,
                expected_revision=current["revision"],
                action="claim_outcome_pilot_work",
                actor=actor,
                **({"effect_guard": before_write} if before_write is not None else {}),
            )
            if saved is not None:
                return saved
        except RecordConflict:
            continue
    raise RecordConflict("Pilot admission changed repeatedly. Retry with the same operation reference.")


def _ensure_manifest(record):
    """Migrate an exact legacy creation retry to a fail-closed pending manifest."""
    if record.get("admission_manifest") is not None:
        validate_admission_manifest(record)
        return record
    pending = admission_manifest(record)
    try:
        saved = STORE.update(
            record["id"], lambda current: current.update(admission_manifest=pending),
            expected_revision=record["revision"], action="prepare_pilot_admission_manifest",
            actor=record["actor"],
        )
    except RecordConflict:
        saved = STORE.get(record["id"])
    if saved is None:
        raise RecordConflict("The pilot disappeared while its admission manifest was prepared.")
    validate_admission_manifest(saved)
    return saved


def prepare_admission(pilot_id, *, context, resolve):
    """Resume exact plan preparation so the app can finish an uncertain create."""
    record = get(pilot_id, context)
    _claim_work_items(
        record["id"], record["cases"], record["actor"],
        record.get("creation_request"),
    )
    record = _ensure_manifest(record)
    return _finish_protected_plan(record, resolve) if record.get("state") == "preparing" else record


def _release_for_plan(body, mode, actor, resolve_release):
    candidate_id = body.get("candidate_id")
    if candidate_id is None:
        return None
    from .outcome_pilot_releases import ReleaseBinding

    if mode != "exclude_local_learning":
        raise ValueError("An improvement candidate needs protected evaluation tasks and prior-exposure checks.")
    if not actor.startswith("user:") or not callable(resolve_release):
        raise PermissionError("A named account and trusted release connection are required for an improvement pilot.")
    release_binding = resolve_release(candidate_id)
    if type(release_binding) is not ReleaseBinding or release_binding.candidate_id != candidate_id:
        raise ValueError("The selected improvement candidate could not be bound to this pilot.")
    return release_binding


@contextmanager
def _guided_creation(identifier, before_write, *, store=STORE):
    if before_write is None:
        yield
        return
    # The bounded local create takes namespace admission before its row lock.
    # Re-enter those exact native locks, rather than check before a writer wait.
    from maverick.file_lock import cross_process_lock

    backend = store._backend()
    if backend.kind == "postgres" and backend.shared:
        # The native transaction supplies the callback after SQL writer waits
        # and immediately before its effect and commit. This installation’s
        # authority fence remains distinct from multi-replica control planes.
        yield
        return
    native_store = getattr(backend, "_store", None)
    if native_store is None:
        raise ValueError("Reviewed pilot creation is unavailable with this storage service. No plan was created.")
    with cross_process_lock(native_store._dir() / ".namespace-admission", strict=True), cross_process_lock(native_store._path(identifier), strict=True):
        before_write()
        yield


def create(body, *, context, actor, resolve, resolve_release=None, before_write=None):
    mode = body.get("learning_mode", "observational")
    if mode not in {"observational", "exclude_local_learning"}:
        raise ValueError("Choose an available pilot learning-data treatment.")
    if mode == "exclude_local_learning":
        if not actor.startswith("user:"):
            raise ValueError("Sign in with a named account before freezing a protected pilot.")
        if any(case["kind"] != "goal" for case in body["cases"]):
            raise ValueError("Local learning exclusion currently supports tasks only. Vendor cases can use an observational pilot.")
        if len(str(body.get("prior_exposure_statement", "")).strip()) < 20:
            raise ValueError("Record the prior-exposure checks and any remaining limitations before freezing this pilot.")
    request = digest(body)
    identifier = "OPL-" + digest([context, body["operation_id"]])[:48]
    existing = STORE.get(identifier)
    if existing:
        _owned(existing, context)
        if existing["creation_request"] != request:
            raise RecordConflict("This operation reference already belongs to another pilot.")
        return prepare_admission(identifier, context=context, resolve=resolve)
    release_binding = _release_for_plan(body, mode, actor, resolve_release)
    sources, cases = set(), []
    for index, case in enumerate(body["cases"]):
        key = (case["kind"], case["reference"])
        if key in sources:
            raise ValueError("Each pilot case must use a different task or vendor case.")
        sources.add(key)
        source = resolve(*key)
        if not source["unstarted"]:
            raise ValueError("Plan cases before their AI work starts. Completed work cannot enter a new pilot.")
        cases.append({**case, "id": str(index + 1), "input_version": source["input_version"],
                      "allocation": "development", "measurement": None})
    holdout = set(secrets.SystemRandom().sample(range(len(cases)), max(1, len(cases) // 2)))
    for index in holdout:
        cases[index]["allocation"] = "holdout"
    record = {"id": identifier, "schema": "lightwork.outcome-pilot.v1", "context": context,
              "title": body["title"], "customer": body["customer"], "workflow": body["workflow"],
              "criteria": body["criteria"], "cases": cases, "actor": actor,
              "learning_mode": mode, "prior_exposure_statement": body.get("prior_exposure_statement", ""),
              "state": "preparing" if mode == "exclude_local_learning" else "frozen",
              "creation_request": request, "frozen_at": time.time(), "operations": {}}
    if release_binding is not None:
        record["release_binding"] = asdict(release_binding)
    plan_material = {k: record[k] for k in ("title", "customer", "workflow", "criteria", "cases", "frozen_at", "learning_mode", "prior_exposure_statement")}
    if release_binding is not None:
        plan_material["release_binding"] = record["release_binding"]
    record["plan_version"] = digest(plan_material)
    record["admission_manifest"] = admission_manifest(record)
    # Recheck after assembling the whole plan. This detects concurrent starts;
    # sources remain separate stores, so report eligibility also checks times.
    for case in cases:
        source = resolve(case["kind"], case["reference"])
        if not source["unstarted"] or source["input_version"] != case["input_version"]:
            raise RecordConflict("A case changed while the plan was being prepared.")
    _claim_work_items(identifier, cases, actor, request, before_write=before_write)
    try:
        with _guided_creation(identifier, before_write):
            saved = STORE.create(record, action="prepare_outcome_pilot" if mode == "exclude_local_learning" else "freeze_outcome_pilot", actor=actor, max_records=LIMIT,
                                 **({"effect_guard": before_write} if before_write is not None else {}))
    except RecordConflict:
        concurrent = get(identifier, context)
        if concurrent["creation_request"] != request:
            raise
        saved = concurrent
    return _finish_protected_plan(saved, resolve, before_write=before_write) if saved.get("state") == "preparing" else saved


def _finish_protected_plan(record, resolve, *, before_write=None):
    from maverick.pilot_learning import protect
    for case in record["cases"]:
        source = resolve(case["kind"], case["reference"])
        if not source["unstarted"] or source["input_version"] != case["input_version"]:
            raise RecordConflict("Work started or inputs changed before the protected plan could freeze. Its learning exclusions are retained; prepare new unstarted cases.")
    for case in record["cases"]:
        if case["allocation"] == "holdout":
            if before_write is not None:
                before_write()
            protect(int(case["reference"]), pilot_id=record["id"], plan_version=record["plan_version"],
                    input_version=case["input_version"], actor=record["actor"])
    for case in record["cases"]:
        source = resolve(case["kind"], case["reference"])
        if not source["unstarted"] or source["input_version"] != case["input_version"]:
            raise RecordConflict("A task started while exclusions were being installed. The plan is not frozen; prepare new unstarted cases.")
    def freeze(current):
        if before_write is not None:
            before_write()
        current.update(state="frozen")
    return STORE.update(record["id"], freeze, expected_revision=record["revision"],
                        action="freeze_protected_outcome_pilot", actor=record["actor"],
                        **({"effect_guard": before_write} if before_write is not None else {}))


def complete_admission(pilot_id, manifest, *, context, actor, resolve, before_write=None):
    """Publish one all-case admission manifest after verifying admission preceded work."""
    record = get(pilot_id, context)
    validate_admission_manifest(record)
    candidate = {**record, "admission_manifest": copy.deepcopy(manifest)}
    completed = validate_admission_manifest(candidate, require_complete=True)
    if record["admission_manifest"].get("status") == "complete":
        if record["admission_manifest"] != completed:
            raise RecordConflict("This pilot already has a different completed admission manifest.")
        return record
    if record.get("state", "frozen") != "frozen":
        raise RecordConflict("This pilot must finish freezing before its admissions can complete.")
    admitted = {entry["case_id"]: entry for entry in completed["entries"]}
    for case in record["cases"]:
        source = resolve(case["kind"], case["reference"])
        if source.get("input_version") != case["input_version"]:
            raise RecordConflict("A case changed before every frozen admission completed.")
        started_at = source.get("first_started_at")
        if source.get("unstarted") is True and started_at is None:
            continue
        admitted_at = admitted[case["id"]]["admitted_at"]
        if (isinstance(started_at, bool) or not isinstance(started_at, (int, float))
                or not math.isfinite(started_at) or started_at <= admitted_at):
            raise RecordConflict("Work started before its durable pilot admission could be verified. No observations can be accepted.")

    def mutate(current):
        if before_write is not None:
            before_write()
        _owned(current, context)
        validate_admission_manifest(current)
        if current["admission_manifest"]["status"] == "complete":
            if current["admission_manifest"] != completed:
                raise RecordConflict("This pilot already has a different completed admission manifest.")
            return
        current["admission_manifest"] = copy.deepcopy(completed)

    try:
        saved = STORE.update(
            pilot_id, mutate, expected_revision=record["revision"],
            action="complete_outcome_pilot_admission", actor=actor,
            **({"effect_guard": before_write} if before_write is not None else {}),
        )
    except RecordConflict:
        current = get(pilot_id, context)
        if current.get("admission_manifest") == completed:
            return current
        raise
    if saved is None:
        raise RecordConflict("The pilot disappeared before its admissions completed.")
    return saved


def observe(pilot_id, case_id, body, *, context, actor, resolve, before_write=None):
    record = get(pilot_id, context)
    if record.get("state", "frozen") != "frozen":
        raise RecordConflict("This plan has not finished freezing its learning policy. No observation was accepted.")
    manifest = validate_admission_manifest(record, require_complete=True)
    request = digest([case_id, {k: v for k, v in body.items() if k != "expected_revision"}])
    prior = record["operations"].get(body["operation_id"])
    if prior is not None:
        if prior != request:
            raise RecordConflict("This operation reference was already used for a different observation.")
        return record
    case = next((c for c in record["cases"] if c["id"] == case_id), None)
    if case is None:
        raise LookupError("This pilot case does not exist.")
    source = resolve(case["kind"], case["reference"])
    if source["version"] != body["source_version"]:
        raise RecordConflict("The source changed. Review its current result before recording an observation.")
    if source["input_version"] != case["input_version"]:
        raise RecordConflict("The task inputs changed after this plan was frozen. This case is not a valid pair.")
    admission = next(row for row in manifest["entries"] if row["case_id"] == case_id)
    started_at = source.get("first_started_at")
    if not (source.get("unstarted") is True and started_at is None) and (
        isinstance(started_at, bool)
        or not isinstance(started_at, (int, float))
        or not math.isfinite(started_at)
        or started_at <= admission["admitted_at"]
    ):
        raise RecordConflict(
            "Work started before its durable pilot admission could be verified."
        )
    measurement = {k: v for k, v in body.items() if k not in {"expected_revision", "operation_id"}}
    measurement.update(
        actor=actor,
        observed_at=time.time(),
        source_operation_id=body["operation_id"],
    )

    def mutate(current):
        if before_write is not None:
            before_write()
        _owned(current, context)
        if len(current["operations"]) >= 5000:
            raise ValueError("This pilot reached its observation history limit. Export its record before further work.")
        rows = copy.deepcopy(current["cases"])
        selected = next(c for c in rows if c["id"] == case_id)
        history = selected.setdefault("history", [])
        if selected["measurement"] is not None:
            history.append(selected["measurement"])
        selected["measurement"] = measurement
        current["cases"] = rows
        current["operations"] = {**current["operations"], body["operation_id"]: request}

    saved = STORE.update(pilot_id, mutate, expected_revision=body["expected_revision"],
                         action="record_pilot_observation", actor=actor,
                         **({"effect_guard": before_write} if before_write is not None else {}))
    if saved is None:
        raise RecordConflict("The pilot disappeared. Refresh before continuing.")
    return saved


def _pair(case, source, frozen_at, admitted_at=None):
    measurement = case["measurement"]
    if source.get("sample"):
        return "sample"
    if source["input_version"] != case["input_version"]:
        return "inputs_changed"
    started_at = source.get("first_started_at")
    if started_at is not None and (
        isinstance(started_at, bool)
        or not isinstance(started_at, (int, float))
        or not math.isfinite(started_at)
    ):
        return "invalid_start_time"
    if started_at is not None and started_at <= frozen_at:
        return "started_before_plan"
    if (
        admitted_at is not None
        and started_at is not None
        and started_at <= admitted_at
    ):
        return "started_before_admission"
    if measurement is None:
        return "unmeasured"
    if measurement["source_version"] != source["version"]:
        return "stale"
    if not source["finished"]:
        return "unfinished"
    if any(measurement.get(field) is None for field in
           ("baseline_minutes", "ai_hands_on_minutes", "review_minutes", "rework_minutes", "corrections")):
        return "partial_measurement"
    return "paired"


def _evidence_readiness(record, rows, groups, admission):
    """Qualify complete reported evidence, never infer business or release lift."""
    admitted = (record.get("state", "frozen") == "frozen"
                and admission["status"] == "complete"
                and admission["admitted_count"] == admission["expected_count"] == len(rows))
    paired = admitted and bool(rows) and all(row["status"] == "paired" for row in rows)
    criteria = paired and all(type(row["measurement"].get("criteria_met")) is bool for row in rows)
    costs = paired and groups["all"]["reported_cost_difference"] is not None and all(
        isinstance(row["measurement"].get("cost_coverage"), dict)
        and set(row["measurement"]["cost_coverage"]) == set(COST_COVERAGE_FAMILIES)
        and all(isinstance(value, dict) and value.get("status") in {"included", "zero"}
                for value in row["measurement"]["cost_coverage"].values())
        for row in rows
    )
    next_steps = []
    if not admitted:
        next_steps.append("Complete admission for every frozen case before treating the comparison as reviewable.")
    if any(row["status"] == "unavailable" for row in rows):
        next_steps.append("Restore authorized access to unavailable cases; keep them in the denominator.")
    if not paired:
        next_steps.append("Review every planned case, including missing, changed, rejected, or unfinished work; do not drop it from the cohort.")
    if paired and not criteria:
        next_steps.append("Record whether every case met the criteria frozen before work began.")
    if paired and not costs:
        next_steps.append("Complete total-cost evidence and every cost family for every case in one currency before using a cost comparison.")
    return {
        "reported_effort_comparison_ready": paired,
        "frozen_criteria_review_ready": criteria,
        "reported_cost_comparison_ready": costs,
        "causal_release_lift_qualified": False,
        "comparison_basis": "operator_reported_observational",
        "next_steps": next_steps,
    }


def report(record, *, resolve):
    admitted = False
    admission = {"status": "invalid", "expected_count": len(record["cases"]),
                 "admitted_count": 0, "manifest_sha256": None,
                 "completion_sha256": None}
    admitted_entries = {}
    try:
        manifest = validate_admission_manifest(record)
        admitted = manifest["status"] == "complete"
        if admitted:
            admitted_entries = {
                row["case_id"]: row["admitted_at"] for row in manifest["entries"]
            }
        admission = {key: manifest[key] for key in (
            "status", "expected_count", "admitted_count", "manifest_sha256",
            "completion_sha256",
        )}
    except RecordConflict:
        pass
    rows = []
    for case in record["cases"]:
        row = {**case}
        try:
            source = resolve(case["kind"], case["reference"])
            row.update(
                source=source,
                status=_pair(
                    case,
                    source,
                    record["frozen_at"],
                    admitted_entries.get(case["id"]),
                ),
            )
            if record.get("state", "frozen") != "frozen":
                row["status"] = "plan_not_frozen"
            elif not admitted:
                row["status"] = "admission_incomplete"
            if record.get("learning_mode") == "exclude_local_learning" and case["allocation"] == "holdout":
                from maverick.pilot_learning import evidence
                row["learning_exclusion"] = evidence(int(case["reference"]), pilot_id=record["id"],
                    plan_version=record["plan_version"], input_version=case["input_version"])
                if source["input_version"] != case["input_version"]:
                    row["learning_exclusion"]["enforced"] = False
        except Exception:
            # A previously permitted source cannot leak its title or observations
            # once source permissions have been revoked.
            row = {"id": case["id"], "allocation": case["allocation"], "status": "unavailable"}
        rows.append(row)
    groups = {}
    for allocation in ("all", "development", "holdout"):
        selected = [r for r in rows if allocation == "all" or r["allocation"] == allocation]
        paired = [r for r in selected if r["status"] == "paired"]
        accepted = [r for r in selected if r.get("source", {}).get("accepted") is True]
        minutes = sum(r["measurement"]["baseline_minutes"] - sum(r["measurement"][f] for f in
                     ("ai_hands_on_minutes", "review_minutes", "rework_minutes")) for r in paired)
        complete_cost = bool(paired) and all(r["measurement"].get("baseline_cost") is not None
            and r["measurement"].get("ai_total_cost") is not None for r in paired)
        currencies = {r["measurement"]["currency"] for r in paired}
        cost_difference = None
        if complete_cost and len(currencies) == 1:
            cost_difference = str(sum((Decimal(r["measurement"]["baseline_cost"]) -
                Decimal(r["measurement"]["ai_total_cost"]) for r in paired), Decimal(0)))
        groups[allocation] = {"planned": len(selected), "paired": len(paired), "accepted": len(accepted),
            "unavailable": sum(r["status"] == "unavailable" for r in selected),
            "acceptance_rate": len(accepted) / len(selected) if selected else None,
            "reported_minutes_difference": minutes if paired else None,
            "reported_cost_difference": cost_difference,
            "reported_ai_cost_per_accepted": str(sum((Decimal(r["measurement"]["ai_total_cost"]) for r in paired), Decimal(0)) / len(accepted))
                if complete_cost and len(currencies) == 1 and len(paired) == len(selected) and accepted else None,
            "criteria_met": sum(r["measurement"].get("criteria_met") is True and r["source"]["accepted"] for r in paired),
            "currency": next(iter(currencies)) if len(currencies) == 1 else None,
            "corrections": sum(r["measurement"]["corrections"] for r in paired) if paired else None}
    holdouts = [row for row in rows if row["allocation"] == "holdout"]
    learning = {"mode": record.get("learning_mode", "observational"),
                "automatic_local_exclusion_enforced": record.get("state", "frozen") == "frozen" and bool(holdouts) and all(row.get("learning_exclusion", {}).get("enforced") for row in holdouts),
                "prior_exposure_statement": record.get("prior_exposure_statement", ""),
                "prior_exposure_actor": record["actor"], "provider_training_verified": False,
                "manual_imports_or_relabelled_copies_covered": False}
    learning["evidence_version"] = digest([record["plan_version"], learning,
        [{"id": row["id"], "source_version": row.get("source", {}).get("version"),
          "exclusion": row.get("learning_exclusion")} for row in rows]])
    reviewed = record.get("independent_review")
    learning["independent_review"] = {**reviewed, "current": reviewed["evidence_version"] == learning["evidence_version"]} if reviewed else None
    learning["review_history"] = record.get("independent_review_history", [])
    limitations = ["Observations and evidence references are attributed to their recorder; they are not independently verified.",
        "Time fields are non-overlapping hands-on effort. Wall time and costs remain separate observations.",
        "All planned cases remain in the acceptance denominator, including missing and rejected cases.",
        "Paired comparisons include current complete observations, including rejected results. Missing pairs can bias comparisons.",
        "The selected local-learning mode covers automatic goal-bound capture, replay and ingestion only. It does not prove prior exposure, provider training exclusion or manually relabelled imports.",
        "Recorded runtime prices are not provider invoices. Reported total cost must include review, rework, and failed attempts."]
    if record.get("release_binding") is not None:
        limitations.append("The frozen release binding records a deployed baseline and proposed candidate at planning time. Case execution does not yet attest which release handled each case, so this pilot cannot establish release lift or a causal improvement.")
    readiness = _evidence_readiness(record, rows, groups, admission)
    return {"id": record["id"], "title": record["title"], "customer": record["customer"],
            "workflow": record["workflow"], "criteria": record["criteria"], "revision": record["revision"],
            "plan_version": record["plan_version"], "frozen_at": record["frozen_at"], "cases": rows,
            "state": record.get("state", "frozen"),
            "admission": admission,
            "groups": groups, "measurement_basis": "operator_reported",
            "evidence_readiness": readiness,
            "release_binding": record.get("release_binding"),
            "case_exposure_verified": False, "causal_lift_qualified": False,
            "learning_policy": learning,
            "provider_invoice_verified": False, "holdout_exposure_verified": False,
            "limitations": limitations}


def review_queue(actor, *, limit=200):
    """Protected pilots in the current workspace that this person may review.

    The store is already workspace-scoped. A reviewer never sees their own
    pilots, only frozen plans, and only the fields needed to pick one.
    """
    if not isinstance(actor, str) or not actor.startswith("user:"):
        return []
    items = []
    for _cursor, record_id in STORE.iter_record_ids(limit=LIMIT):
        record = STORE.get(record_id)
        if (
            record is None
            or record.get("learning_mode") != "exclude_local_learning"
            or record.get("state") != "frozen"
            or record.get("actor") == actor
        ):
            continue
        review = record.get("independent_review") or {}
        items.append({
            "id": record["id"],
            "title": record["title"],
            "frozen_at": record.get("frozen_at"),
            "decision": review.get("decision") if isinstance(review, dict) else None,
        })
        if len(items) >= limit:
            break
    items.sort(key=lambda item: (item["decision"] is not None, -(item["frozen_at"] or 0)))
    return items


def independent_review(pilot_id, body, *, actor, resolve, before_write=None):
    if body.get("confirm") is not True:
        raise ValueError("Explicitly confirm the exact learning-policy evidence you reviewed.")
    record = STORE.get(pilot_id)
    if record is None:
        raise LookupError("Pilot unavailable.")
    validate_admission_manifest(record, require_complete=True)
    if not actor.startswith("user:") or actor == record["actor"]:
        raise PermissionError("A different named administrator must perform the independent review.")
    # The API enforces global administrator access; resolve reauthorizes every
    # underlying source before disclosing or accepting the review.
    for case in record["cases"]:
        resolve(case["kind"], case["reference"])
    snapshot = report(record, resolve=resolve)["learning_policy"]
    if snapshot["evidence_version"] != body["evidence_version"]:
        raise RecordConflict("The plan, source or exclusion evidence changed. Review it again.")
    if body["decision"] == "accepted_local_scope" and not snapshot["automatic_local_exclusion_enforced"]:
        raise ValueError("Local exclusion is not established for every holdout task. Request more evidence instead.")
    request = digest([actor, {key: value for key, value in body.items() if key != "expected_revision"}])
    previous = record.setdefault("review_operations", {}).get(body["operation_id"])
    if previous is not None:
        if previous != request:
            raise RecordConflict("This review reference was already used differently.")
        return record
    def update(current):
        if before_write is not None:
            before_write()
        if len(current.get("review_operations", {})) >= 100:
            raise ValueError("This pilot has reached its independent review history limit.")
        if current.get("independent_review"):
            current.setdefault("independent_review_history", []).append(current["independent_review"])
        current["independent_review"] = {"actor": actor, "decision": body["decision"], "notes": body["notes"],
                                         "evidence_version": body["evidence_version"], "reviewed_at": time.time(), "operation_id": body["operation_id"]}
        current.setdefault("review_operations", {})[body["operation_id"]] = request
    return STORE.update(pilot_id, update, expected_revision=body["expected_revision"], action="independent_learning_review", actor=actor,
                        **({"effect_guard": before_write} if before_write is not None else {}))
