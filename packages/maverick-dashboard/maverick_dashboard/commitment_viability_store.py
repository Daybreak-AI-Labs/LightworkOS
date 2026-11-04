"""Owner-scoped, durable research pilots for modeled customer commitments.

Every source in this bounded pilot is an attributed operator assertion. Its
revision binds the exact entered fact, actor and time; it is not independent
supplier, inventory or production-system verification. No path here reserves
external resources or changes an accepted customer order.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict

from maverick.commitment_viability import (
    Commitment,
    Demand,
    Evidence,
    Lot,
    OwnerConfirmation,
    ReversibleOption,
    SharedDependency,
    Snapshot,
    TraceObservation,
    assess,
    confirm_dependency,
    confirm_option,
    explain_resource_gaps,
    propose_shared_dependencies,
)
from maverick.constant_time import text_equals
from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict

STORE = GovernedRecordStore("commitment_viability", "CMV", "commitment_viability", archive_when_full=False)
ARCHIVE = GovernedRecordStore("commitment_viability_archive", "CMA", "commitment_viability_archive")
LIMIT = 1_000
SCHEMA = "lightwork.commitment-viability-pilot.v1"
ARCHIVE_SCHEMA = "lightwork.commitment-viability-archive.v1"
_MAX_OPERATIONS = 500
_MAX_TRACES = 64


class CommitmentAuditPending(RuntimeError):
    """A saved review cannot accept another change until its receipt is delivered."""


def _settle_audit(record: dict) -> dict:
    if record.get("_audit_pending"):
        record = STORE._flush(record)
    return record


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _owned(record: dict | None, context: str) -> dict:
    if record is None or not hmac.compare_digest(str(record.get("context") or ""), context):
        raise LookupError("This promise review is unavailable in your account and workspace.")
    if record.get("schema") != SCHEMA:
        raise RecordConflict("This promise review has an unsupported saved format.")
    return record


def get(identifier: str, context: str) -> dict:
    return _settle_audit(_owned(STORE.get(identifier), context))


def _archive_id(identifier: str) -> str:
    return "CMA-" + identifier.removeprefix("CMV-")


def archived_get(identifier: str, context: str) -> dict:
    archive = ARCHIVE.get(_archive_id(identifier))
    if (archive is None or archive.get("schema") != ARCHIVE_SCHEMA
            or not hmac.compare_digest(str(archive.get("context") or ""), context)):
        raise LookupError("This promise review is unavailable in your account and workspace.")
    archive = _settle_archive_audit(archive)
    source = archive.get("source")
    if (not isinstance(source, dict) or source.get("id") != identifier
            or source.get("schema") != SCHEMA or source.get("context") != context
            or not hmac.compare_digest(str(archive.get("source_sha256") or ""), _digest(source))):
        raise RecordConflict("The archived review could not be verified.")
    return archive


def _settle_archive_audit(record: dict) -> dict:
    return ARCHIVE._flush(record) if record.get("_audit_pending") else record


def read(identifier: str, context: str) -> tuple[dict, dict | None]:
    try:
        return get(identifier, context), None
    except LookupError:
        archive = archived_get(identifier, context)
        return archive["source"], archive


def listing(context: str, *, cursor: str = "", limit: int = 50,
            archived: bool = False) -> dict:
    if not isinstance(cursor, str) or len(cursor) > 256 or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Review page is invalid")
    rows = []
    next_cursor = cursor
    more = False
    scanned = 0
    store = ARCHIVE if archived else STORE
    for backend_cursor, identifier in store.iter_record_ids(start_after=cursor, limit=LIMIT + 1):
        if cursor and backend_cursor <= cursor:
            break
        scanned += 1
        record = store.get(identifier)
        if len(rows) == limit:
            more = True
            break
        next_cursor = backend_cursor
        if record is None or record.get("context") != context:
            continue
        if archived:
            rows.append({"id": record["source"]["id"], "title": record["source"]["title"],
                         "revision": record["source"]["revision"],
                         "updated_at": record["retired_at"], "archived": True})
        else:
            rows.append({"id": record["id"], "title": record["title"],
                         "revision": record["revision"], "updated_at": record["updated_at"],
                         "archived": False})
    if scanned == LIMIT + 1:
        more = True
    return {"items": rows, "page": {"has_more": more,
                                    "next_cursor": next_cursor if more else None}}


def _source(identifier: str, suffix: str, payload: object, *, actor: str,
            observed_at: float, expires_at: float, note: str) -> tuple[Evidence, dict]:
    source_id = f"{identifier}:{suffix}"
    revision = _digest([payload, actor, observed_at, expires_at, note])
    evidence = Evidence(source_id, revision, observed_at, expires_at)
    return evidence, {"source_id": source_id, "revision": revision,
                      "kind": "operator_assertion", "entered_by": actor,
                      "entered_at": observed_at, "review_by": expires_at,
                      "basis": note}


def _evidence(raw: dict) -> Evidence:
    return Evidence(**raw)


def _snapshot(raw: dict) -> Snapshot:
    return Snapshot(
        revision=raw["revision"],
        commitments=tuple(Commitment(
            item["id"], item["due_at"], tuple(Demand(**part) for part in item["demands"]),
            _evidence(item["acceptance"]),
        ) for item in raw["commitments"]),
        lots=tuple(Lot(item["id"], item["kind"], item["key"], item["units"],
                       item["ready_at"], item["certainty"], _evidence(item["evidence"]))
                   for item in raw["lots"]),
        options=tuple(ReversibleOption(
            item["id"], item["kind"], item["key"], item["units"], item["ready_at"],
            item["expires_at"], _evidence(item["evidence"]), item["cost_note"],
            OwnerConfirmation(**item["owner_confirmation"])
            if item["owner_confirmation"] is not None else None, item["lead_seconds"],
        ) for item in raw["options"]),
        dependencies=tuple(SharedDependency(**item) for item in raw["dependencies"]),
    )


def _traces(record: dict) -> tuple[TraceObservation, ...]:
    return tuple(TraceObservation(
        item["id"], item["commitment_id"], item["resource_key"], item["units"],
        item["start_at"], item["end_at"], item["blocked"], _evidence(item["evidence"]),
    ) for item in record["traces"])


def _current_versions(record: dict) -> dict[str, str]:
    return {row["source_id"]: row["revision"] for row in record["sources"]}


def _actor_key(actor: str) -> str:
    return "owner-" + hashlib.sha256(actor.encode("utf-8")).hexdigest()[:32]


def create(context: str, actor: str, body: dict) -> dict:
    request = _digest(body)
    identifier = "CMV-" + _digest([context, body["operation_id"]])[:48]
    try:
        archived_get(identifier, context)
    except LookupError:
        pass
    else:
        raise RecordConflict("This request belongs to an archived review. Start a new review for current work.")
    prior = STORE.get(identifier)
    if prior is not None:
        prior = _owned(prior, context)
        if prior.get("retirement"):
            raise RecordConflict("This review is being archived. Open its saved history instead.")
        if not text_equals(str(prior.get("owner") or ""), actor):
            raise PermissionError("Only the person who started this review can repeat its creation.")
        if prior.get("creation_request") != request:
            raise RecordConflict("This request reference was used for different work.")
        return _settle_audit(prior)
    now = time.time()
    valid_until = body["review_by"]
    if not now < valid_until <= now + 30 * 24 * 3600:
        raise ValueError("Choose a review time within the next 30 days.")
    if body["option_expires_at"] <= now or body["option_expires_at"] > valid_until:
        raise ValueError("The option must expire after now and before the review time.")
    if body["order_a_due_at"] <= now or body["order_b_due_at"] <= now:
        raise ValueError("Choose future delivery dates for both commitments.")
    note = body["basis"]
    facts = [
        ("order-a", {"name": body["order_a_name"], "due_at": body["order_a_due_at"],
                     "material_units": body["order_a_material_units"],
                     "uses_shared_capacity": body["order_a_uses_capacity"]}),
        ("order-b", {"name": body["order_b_name"], "due_at": body["order_b_due_at"],
                     "material_units": body["order_b_material_units"],
                     "uses_shared_capacity": body["order_b_uses_capacity"]}),
        ("capacity", {"name": body["capacity_name"], "units": body["capacity_units"]}),
        ("stock", {"name": body["material_name"], "units": body["stock_units"],
                   "certainty": body["stock_certainty"]}),
        ("option", {"name": body["option_name"], "kind": body["option_kind"],
                    "units": body["option_units"], "ready_at": body["option_ready_at"],
                    "expires_at": body["option_expires_at"],
                    "lead_seconds": body["option_lead_seconds"]}),
    ]
    source_rows = []
    evidence = {}
    for suffix, fact in facts:
        proof, row = _source(identifier, suffix, fact, actor=actor,
                             observed_at=now, expires_at=valid_until, note=note)
        evidence[suffix] = proof
        source_rows.append(row)
    commitments = []
    for suffix, _name, due, units, uses_capacity in (
        ("order-a", body["order_a_name"], body["order_a_due_at"],
         body["order_a_material_units"], body["order_a_uses_capacity"]),
        ("order-b", body["order_b_name"], body["order_b_due_at"],
         body["order_b_material_units"], body["order_b_uses_capacity"]),
    ):
        demands = [Demand("material", "material", units)]
        if uses_capacity:
            demands.append(Demand("capacity", "work-center", 1))
        commitments.append(Commitment(suffix, due, tuple(demands), evidence[suffix]))
    lots = [Lot("shared-capacity", "capacity", "work-center", body["capacity_units"],
                now, "confirmed", evidence["capacity"])]
    if body["stock_units"]:
        lots.append(Lot("available-stock", "material", "material", body["stock_units"],
                        now, body["stock_certainty"], evidence["stock"]))
    option_key = "material" if body["option_kind"] == "material" else "work-center"
    option = ReversibleOption("conditional-option", body["option_kind"], option_key,
                              body["option_units"], body["option_ready_at"],
                              body["option_expires_at"], evidence["option"],
                              body["option_cost_note"], None, body["option_lead_seconds"])
    model = Snapshot(0, tuple(commitments), tuple(lots), (option,))
    record = {"id": identifier, "schema": SCHEMA, "context": context,
              "owner": actor, "title": body["title"], "basis": note,
              "labels": {"order-a": body["order_a_name"], "order-b": body["order_b_name"],
                         "work-center": body["capacity_name"], "material": body["material_name"],
                         "conditional-option": body["option_name"]},
              "model": asdict(model), "sources": source_rows, "traces": [],
              "creation_request": request, "operations": {body["operation_id"]: request}}
    try:
        saved = STORE.create(record, action="create_commitment_review", actor=actor,
                             max_records=LIMIT)
    except RecordConflict as exc:
        prior = get(identifier, context)
        if not text_equals(str(prior.get("owner") or ""), actor):
            raise PermissionError("Only the person who started this review can repeat its creation.") from exc
        if prior.get("creation_request") != request:
            raise
        return prior
    saved = _settle_audit(saved)
    # Admission can wait for the governed store's capacity lock. Never report
    # an expired, overdue, or already-closed review as newly actionable.
    current = time.time()
    if (current >= valid_until or current >= body["option_expires_at"]
            or current >= min(body["order_a_due_at"], body["order_b_due_at"])):
        raise RecordConflict("The review window closed while saving. Check saved reviews, then start a new review with current figures.")
    return saved


def project(record: dict, *, now: float | None = None,
            archive: dict | None = None) -> dict:
    now = time.time() if now is None else now
    model = _snapshot(record["model"])
    revisions = _current_versions(record)
    result = assess(model, now=now, current_source_revisions=revisions)
    gaps = explain_resource_gaps(model, now=now, current_source_revisions=revisions)
    proposals = propose_shared_dependencies(model, _traces(record), now=now,
                                            current_source_revisions=revisions)
    return {"id": record["id"], "title": record["title"],
            "revision": record["revision"], "model_revision": model.revision,
            "labels": record["labels"], "basis": record["basis"],
            "model": asdict(model), "traces": record["traces"],
            "sources": record["sources"], "assessment": asdict(result),
            "resource_gaps": [asdict(item) for item in gaps],
            "resource_gap_blocked_by_order_change": any(
                not item.acceptance.current(now, revisions) for item in model.commitments),
            "proposals": [asdict(item) for item in proposals],
            "audit_status": "pending" if record.get("_audit_pending") else "recorded",
            "archived": archive is not None,
            "archive_pending": bool(record.get("retirement")) and archive is None,
            "retired_at": archive.get("retired_at") if archive else None,
            "retired_by": archive.get("retired_by") if archive else None,
            "source_quality": "operator_reported",
            "external_reservation_verified": False}


def _repeat_or_update(identifier: str, context: str, actor: str, expected_revision: int,
                      operation_id: str, payload: dict, action: str, mutate) -> dict:
    request = _digest([action, payload])
    prior = get(identifier, context)
    if prior.get("retirement"):
        raise RecordConflict("This review is being archived. Its history remains available, but changes are closed.")
    prior_request = prior["operations"].get(operation_id)
    if prior_request is not None:
        if prior_request != request:
            raise RecordConflict("This request reference was used for different work.")
        return prior
    if prior.get("_audit_pending"):
        raise CommitmentAuditPending("The previous change is waiting for its activity receipt. Refresh this review before making another change.")
    if len(prior["operations"]) >= _MAX_OPERATIONS:
        raise ValueError("This review reached its decision history limit. Start a new review.")

    def update(current: dict) -> None:
        _owned(current, context)
        if current.get("retirement"):
            raise RecordConflict("This review is being archived. Its history remains available, but changes are closed.")
        if current.get("_audit_pending"):
            raise CommitmentAuditPending("The previous change is waiting for its activity receipt. Refresh this review before making another change.")
        existing = current["operations"].get(operation_id)
        if existing is not None:
            if existing != request:
                raise RecordConflict("This request reference was used for different work.")
            return
        mutate(current)
        current["operations"] = {**current["operations"], operation_id: request}

    try:
        saved = STORE.update(identifier, update, expected_revision=expected_revision,
                             action=action, actor=actor)
    except CommitmentAuditPending:
        raise
    except Exception:
        # A write can commit before the caller sees its response. Read back the
        # exact request before reporting failure; never blindly repeat a write.
        latest = get(identifier, context)
        if latest["operations"].get(operation_id) == request:
            return latest
        raise
    if saved is None:
        raise LookupError("This promise review is no longer available.")
    return _settle_audit(saved)


def record_trace(identifier: str, context: str, actor: str, body: dict) -> dict:
    prior = get(identifier, context)
    if prior.get("retirement"):
        raise RecordConflict("This review is being archived. Its history remains available, but changes are closed.")
    prior_request = prior["operations"].get(body["operation_id"])
    if prior_request is not None:
        if prior_request != _digest(["record_commitment_observation", body]):
            raise RecordConflict("This request reference was used for different work.")
        return prior
    if prior.get("_audit_pending"):
        raise CommitmentAuditPending("The previous change is waiting for its activity receipt. Refresh this review before making another change.")
    if body["running_order"] == body["blocked_order"]:
        raise ValueError("Choose two different orders.")
    now = time.time()
    if not 0 < body["started_at"] < body["ended_at"] <= now:
        raise ValueError("Enter a completed work interval ending no later than now.")
    if body["ended_at"] > body["observed_at"] or body["observed_at"] > now:
        raise ValueError("The observation must follow the work it describes.")
    if body["review_by"] <= now or body["review_by"] > now + 30 * 24 * 3600:
        raise ValueError("Choose a review time within the next 30 days.")

    def mutate(current: dict) -> None:
        committed_at = time.time()
        if body["review_by"] <= committed_at:
            raise RecordConflict("This observation expired while saving. Review its source and enter it again.")
        if len(current["traces"]) + 2 > _MAX_TRACES:
            raise ValueError("This review reached its observation limit. Start a new review.")
        model = _snapshot(current["model"])
        labels = {item.id for item in model.commitments}
        if body["running_order"] not in labels or body["blocked_order"] not in labels:
            raise ValueError("Choose current orders from this review.")
        rows = []
        for role, selected, blocked in (("running", body["running_order"], False),
                                        ("blocked", body["blocked_order"], True)):
            suffix = f"trace-{_digest(body['operation_id'])[:20]}-{role}"
            fact = {"commitment": selected, "resource": "work-center", "units": 1,
                    "start_at": body["started_at"], "end_at": body["ended_at"],
                    "blocked": blocked, "reported_observed_at": body["observed_at"],
                    "basis": body["basis"]}
            evidence, source = _source(identifier, suffix, fact, actor=actor,
                                       observed_at=committed_at,
                                       expires_at=body["review_by"], note=body["basis"])
            row = TraceObservation(suffix, selected, "work-center", 1,
                                   body["started_at"], body["ended_at"], blocked, evidence)
            rows.append(asdict(row))
            current["sources"].append(source)
        current["traces"] = [*current["traces"], *rows]
        current["model"] = asdict(Snapshot(model.revision + 1, model.commitments,
                                           model.lots, model.options, model.dependencies))

    return _repeat_or_update(identifier, context, actor, body["expected_revision"],
                             body["operation_id"], body, "record_commitment_observation", mutate)


def confirm(identifier: str, context: str, actor: str, body: dict) -> dict:
    prior = get(identifier, context)
    if not text_equals(str(prior.get("owner") or ""), actor):
        raise PermissionError("Only the person who started this review can confirm its choices.")

    def mutate(current: dict) -> None:
        now = time.time()
        if not text_equals(str(current.get("owner") or ""), actor):
            raise PermissionError("Only the person who started this review can confirm its choices.")
        model = _snapshot(current["model"])
        revisions = _current_versions(current)
        if body["kind"] == "dependency":
            proposals = propose_shared_dependencies(model, _traces(current), now=now,
                                                    current_source_revisions=revisions)
            proposal = next((item for item in proposals if item.id == body["proposal_id"]), None)
            if proposal is None:
                raise RecordConflict("The observed work changed. Review a current suggestion.")
            updated = confirm_dependency(model, proposal, _traces(current),
                                         actor=_actor_key(actor), expected_revision=model.revision,
                                         now=now, current_source_revisions=revisions)
        else:
            updated = confirm_option(model, body["option_id"], actor=_actor_key(actor),
                                     expected_revision=model.revision, now=now,
                                     current_source_revisions=revisions)
        current["model"] = asdict(updated)

    return _repeat_or_update(identifier, context, actor, body["expected_revision"],
                             body["operation_id"], body, "confirm_commitment_model", mutate)


def _mark_retirement(identifier: str, context: str, actor: str, body: dict) -> dict:
    operation_id = body["operation_id"]
    try:
        current = get(identifier, context)
    except LookupError:
        archived = archived_get(identifier, context)
        prior_revision = archived["source"]["retirement"]["expected_revision"]
        if (not text_equals(str(archived["retired_by"]), actor)
                or body["expected_revision"] not in {prior_revision, archived["source"]["revision"]}):
            raise RecordConflict("This review was already archived. Open its saved history.") from None
        return archived
    if not text_equals(str(current.get("owner") or ""), actor):
        raise PermissionError("Only the person who started this review can finish and archive it.")
    marker = current.get("retirement")
    if marker:
        if (marker.get("actor") != actor
                or body["expected_revision"] not in {marker.get("expected_revision"),
                                                       current["revision"]}
                or (operation_id != marker.get("operation_id")
                    and body["expected_revision"] != current["revision"])):
            raise RecordConflict("This review is already being archived. Refresh its history.")
    else:
        if current.get("_audit_pending"):
            raise CommitmentAuditPending("The last change needs an activity receipt before this review can be archived.")

        def mark(record: dict) -> None:
            _owned(record, context)
            if not text_equals(str(record.get("owner") or ""), actor):
                raise PermissionError("Only the person who started this review can finish and archive it.")
            if record.get("retirement"):
                raise RecordConflict("This review is already being archived. Refresh its history.")
            if record.get("_audit_pending"):
                raise CommitmentAuditPending("The last change needs an activity receipt before this review can be archived.")
            record["retirement"] = {"operation_id": operation_id, "actor": actor,
                                    "expected_revision": body["expected_revision"],
                                    "at": time.time()}

        try:
            saved = STORE.update(identifier, mark,
                                 expected_revision=body["expected_revision"],
                                 action="retire_commitment_review", actor=actor)
        except Exception:
            # A committed update may lose its response. An exact marked retry
            # resumes; no second retirement event or decision is inferred.
            latest = get(identifier, context)
            if latest.get("retirement", {}).get("operation_id") != operation_id:
                raise
            saved = latest
        if saved is None:
            raise LookupError("This promise review is no longer available.")
        current = _settle_audit(saved)
    if current.get("_audit_pending"):
        raise CommitmentAuditPending("The archive request was saved, but its activity receipt is pending. Refresh and retry the same request.")
    return current


def _retain_then_release(identifier: str, context: str, actor: str,
                         operation_id: str, current: dict) -> dict:

    source = dict(current)
    source.pop("_audit_pending", None)
    archived_record = {"id": _archive_id(identifier), "schema": ARCHIVE_SCHEMA,
                       "context": context, "owner": actor, "title": source["title"],
                       "source": source, "source_sha256": _digest(source),
                       "retired_at": source["retirement"]["at"], "retired_by": actor,
                       "retirement_operation_id": operation_id}
    try:
        archived = ARCHIVE.create(archived_record, action="archive_commitment_review",
                                  actor=actor)
    except RecordConflict as exc:
        try:
            archived = archived_get(identifier, context)
        except LookupError:
            raise RecordConflict("The archive could not be verified. The active review was retained.") from exc
    except Exception as exc:
        try:
            archived = archived_get(identifier, context)
        except LookupError:
            raise RuntimeError("The archive save is uncertain. Refresh this review before retrying.") from exc
    archived = _settle_archive_audit(archived)
    if archived.get("source_sha256") != archived_record["source_sha256"]:
        raise RecordConflict("The retained review differs from the current history. Nothing was removed.")
    if archived.get("_audit_pending"):
        raise CommitmentAuditPending("The review was retained, but its archive receipt is pending. Refresh and retry the same request.")
    try:
        removed = STORE.delete(identifier, expected_revision=current["revision"])
    except Exception:
        if STORE.get(identifier) is not None:
            raise
        removed = True
    if not removed and STORE.get(identifier) is not None:
        raise RecordConflict("The review changed while archiving. Its retained copy was not removed.")
    return archived_get(identifier, context)


def retire(identifier: str, context: str, actor: str, body: dict) -> dict:
    """Close decisions, preserve the full review, then release its active slot.

    The two governed receipts must be delivered before removing the active
    copy. A failed step leaves the marked active review for an exact retry.
    """
    current = _mark_retirement(identifier, context, actor, body)
    if current.get("schema") == ARCHIVE_SCHEMA:
        return current
    return _retain_then_release(identifier, context, actor, body["operation_id"], current)


__all__ = ["STORE", "ARCHIVE", "SCHEMA", "CommitmentAuditPending", "create", "get",
           "archived_get", "read", "listing", "project", "record_trace", "confirm", "retire"]
