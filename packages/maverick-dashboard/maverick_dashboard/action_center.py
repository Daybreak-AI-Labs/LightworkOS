"""An attention queue with private, version-bound read and snooze preferences."""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable

from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict

_PREFERENCES = GovernedRecordStore("action_center_preferences", "ACP", "attention_preferences")
SOURCE_LIMIT = 2000
_VENDOR_CASE_ID = re.compile(r"VON-[A-Za-z0-9_-]{1,59}\Z")
_VENDOR_OPERATION_ID = re.compile(r"VOP-[a-f0-9]{32}\Z")
_VENDOR_PROJECT = re.compile(r"[A-Z][A-Z0-9_]{1,31}\Z")
_RECONCILIATION_REASONS = frozenset({
    "current_connection_access_unavailable",
    "no_matching_effect_observed",
    "multiple_matching_effects_observed",
    "matching_effect_content_mismatch",
    "authoritative_readback_unavailable",
    "receipt_recorded_readback_unverified",
    "attempt_result_unrecorded",
})
_READBACK_STATES = frozenset({
    "not_completed", "access_unavailable", "no_match", "multiple_matches",
    "readback_mismatch", "readback_unavailable", "exact_match_verified",
})


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _item(kind, key, title, *, href, owner="", due_at=None, updated_at=0, version=None, reason=""):
    identity = _digest([kind, str(key)])[:32]
    value = {"id": identity, "kind": kind, "title": str(title)[:500], "href": href,
             "owner": owner or "", "due_at": due_at, "updated_at": updated_at or 0,
             "reason": reason}
    value["source_version"] = _digest([value, version])
    return value


def _projection_error():
    raise ValueError("invalid reconciliation projection")


def _closed(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        _projection_error()
    return value


def _bounded_text(value, *, limit=2000):
    if (not isinstance(value, str) or not value or value.strip() != value
            or len(value) > limit):
        _projection_error()
    return value


def _timestamp(value, *, optional=False):
    if optional and value is None:
        return None
    if (isinstance(value, bool) or not isinstance(value, int | float)
            or not math.isfinite(float(value)) or float(value) <= 0):
        _projection_error()
    return float(value)


def _project_observation(value):
    if not isinstance(value, dict):
        _projection_error()
    kind = value.get("kind")
    if kind == "execution_attempt":
        _closed(value, {"kind", "state", "count", "observed_at"})
        if value.get("state") != "recorded" or type(value.get("count")) is not int \
                or value["count"] < 1:
            _projection_error()
        return {"kind": kind, "state": "recorded", "count": value["count"],
                "observed_at": _timestamp(value.get("observed_at"))}
    if kind == "provider_receipt":
        _closed(value, {"kind", "state"})
        if value.get("state") not in {"recorded", "not_recorded"}:
            _projection_error()
        return {"kind": kind, "state": value["state"]}
    if kind != "authoritative_readback":
        _projection_error()
    allowed = {"kind", "state", "observed_at", "match_count", "match_count_lower_bound"}
    if not set(value).issubset(allowed) or not {"kind", "state", "observed_at"}.issubset(value):
        _projection_error()
    state = value.get("state")
    if state not in _READBACK_STATES:
        _projection_error()
    exact, lower = value.get("match_count"), value.get("match_count_lower_bound")
    if exact is not None and (type(exact) is not int or exact < 0):
        _projection_error()
    if lower is not None and (type(lower) is not int or lower < 2):
        _projection_error()
    if exact is not None and lower is not None:
        _projection_error()
    if state == "no_match" and exact != 0:
        _projection_error()
    if state == "multiple_matches" and not (
        type(exact) is int and exact >= 2 or type(lower) is int and lower >= 2
    ):
        _projection_error()
    if state == "not_completed" and (exact is not None or lower is not None):
        _projection_error()
    observed_at = _timestamp(value.get("observed_at"), optional=True)
    if (state == "not_completed") != (observed_at is None):
        _projection_error()
    if state in {"exact_match_verified", "readback_mismatch"} and exact != 1:
        _projection_error()
    projected = {"kind": kind, "state": state, "observed_at": observed_at}
    if exact is not None:
        projected["match_count"] = exact
    if lower is not None:
        projected["match_count_lower_bound"] = lower
    return projected


def _project_reconciliation(value):
    _closed(value, {
        "schema", "attempted_action", "known_observations", "uncertainty",
        "safe_next_check", "responsible_operator", "resolution",
    })
    if value.get("schema") != "lightwork.vendor-onboarding.reconciliation-summary.v1":
        _projection_error()
    attempted = _closed(value.get("attempted_action"), {
        "operation_id", "action", "attempt_count", "started_at", "target",
    })
    target = _closed(attempted.get("target"), {"provider", "project"})
    if (not isinstance(attempted.get("operation_id"), str)
            or not _VENDOR_OPERATION_ID.fullmatch(attempted["operation_id"])
            or attempted.get("action") != "jira.create"
            or type(attempted.get("attempt_count")) is not int
            or attempted["attempt_count"] < 1
            or target.get("provider") != "jira"
            or not isinstance(target.get("project"), str)
            or not _VENDOR_PROJECT.fullmatch(target["project"])):
        _projection_error()
    attempted = {
        "operation_id": attempted["operation_id"], "action": "jira.create",
        "attempt_count": attempted["attempt_count"],
        "started_at": _timestamp(attempted.get("started_at")),
        "target": {"provider": "jira", "project": target["project"]},
    }
    observations = value.get("known_observations")
    if not isinstance(observations, list) or len(observations) != 3:
        _projection_error()
    observations = [_project_observation(item) for item in observations]
    if {item["kind"] for item in observations} != {
        "execution_attempt", "provider_receipt", "authoritative_readback",
    }:
        _projection_error()
    observed = {item["kind"]: item for item in observations}
    if (observed["execution_attempt"]["count"] != attempted["attempt_count"]
            or observed["execution_attempt"]["observed_at"] != attempted["started_at"]):
        _projection_error()
    uncertainty = _closed(value.get("uncertainty"), {"state", "reason", "explanation"})
    if (uncertainty.get("state") != "unresolved"
            or uncertainty.get("reason") not in _RECONCILIATION_REASONS):
        _projection_error()
    uncertainty = {"state": "unresolved", "reason": uncertainty["reason"],
                   "explanation": _bounded_text(uncertainty.get("explanation"))}
    next_check = value.get("safe_next_check")
    if not isinstance(next_check, dict):
        _projection_error()
    kind = next_check.get("kind")
    expected_keys = {"kind", "label", "mode", "href"} if kind == "restore_access" else {
        "kind", "label", "mode",
    }
    _closed(next_check, expected_keys)
    if kind not in {"check_status", "review_ambiguity", "restore_access"} \
            or next_check.get("mode") != "read_only":
        _projection_error()
    next_check = {"kind": kind, "label": _bounded_text(next_check.get("label"), limit=500),
                  "mode": "read_only"}
    if kind == "restore_access":
        if value["safe_next_check"].get("href") != "/connections":
            _projection_error()
        next_check["href"] = "/connections"
    reason = uncertainty["reason"]
    readback_state = observed["authoritative_readback"]["state"]
    receipt_state = observed["provider_receipt"]["state"]
    expected = {
        "current_connection_access_unavailable": ("restore_access", None),
        "no_matching_effect_observed": ("check_status", "no_match"),
        "multiple_matching_effects_observed": ("review_ambiguity", "multiple_matches"),
        "matching_effect_content_mismatch": ("review_ambiguity", "readback_mismatch"),
        "authoritative_readback_unavailable": ("check_status", "readback_unavailable"),
        "receipt_recorded_readback_unverified": ("check_status", "not_completed"),
        "attempt_result_unrecorded": ("check_status", "not_completed"),
    }[reason]
    if kind != expected[0] or (expected[1] is not None and readback_state != expected[1]):
        _projection_error()
    if reason == "receipt_recorded_readback_unverified" and receipt_state != "recorded":
        _projection_error()
    if reason == "attempt_result_unrecorded" and receipt_state != "not_recorded":
        _projection_error()
    responsible = _closed(value.get("responsible_operator"), {"principal", "business_owner"})
    responsible = {
        "principal": _bounded_text(responsible.get("principal"), limit=256),
        "business_owner": _bounded_text(responsible.get("business_owner"), limit=256),
    }
    resolution = _closed(value.get("resolution"), {
        "automatic_compensation_supported", "unreviewed_replacement_allowed",
        "requires_separate_review", "explanation",
    })
    if (resolution.get("automatic_compensation_supported") is not False
            or resolution.get("unreviewed_replacement_allowed") is not False
            or resolution.get("requires_separate_review") is not True):
        _projection_error()
    resolution = {
        "automatic_compensation_supported": False,
        "unreviewed_replacement_allowed": False,
        "requires_separate_review": True,
        "explanation": _bounded_text(resolution.get("explanation")),
    }
    return {
        "schema": "lightwork.vendor-onboarding.reconciliation-summary.v1",
        "attempted_action": attempted, "known_observations": observations,
        "uncertainty": uncertainty, "safe_next_check": next_check,
        "responsible_operator": responsible, "resolution": resolution,
    }


def _vendor_reconciliation_item(case: dict) -> dict:
    if not isinstance(case, dict):
        _projection_error()
    case_id = case.get("id")
    vendor_name = case.get("vendor_name")
    revision = case.get("revision")
    owner = case.get("owner")
    if (not isinstance(case_id, str) or not _VENDOR_CASE_ID.fullmatch(case_id)
            or type(revision) is not int or revision < 1
            or case.get("schema") != "lightwork.vendor-onboarding.v1"
            or case.get("stage") not in {"executing", "reconciliation_required"}):
        _projection_error()
    vendor_name = _bounded_text(vendor_name, limit=256)
    owner = _bounded_text(owner, limit=256)
    updated_at = _timestamp(case.get("updated_at"))
    due_at = _timestamp(case.get("due_at"), optional=True)
    reconciliation = _project_reconciliation(case.get("reconciliation"))
    if reconciliation["responsible_operator"]["business_owner"] != owner:
        _projection_error()
    item = _item(
        "vendor_reconciliation",
        case_id,
        f"Resolve uncertain Jira task for {vendor_name}",
        href=f"/third-party/vendor-onboarding?case={case_id}",
        owner=reconciliation["responsible_operator"]["principal"],
        due_at=due_at,
        updated_at=updated_at,
        version=[revision, reconciliation],
        reason=reconciliation["uncertainty"]["explanation"],
    )
    item["reconciliation"] = reconciliation
    return item


def _collect_vendor_reconciliations(source: Callable[[], dict]) -> tuple[list[dict], str]:
    result = source()
    if (not isinstance(result, dict) or not isinstance(result.get("items"), list)
            or type(result.get("complete")) is not bool):
        raise ValueError("invalid reconciliation source")
    if len(result["items"]) > SOURCE_LIMIT:
        raise ValueError("unbounded reconciliation source")
    return (
        [_vendor_reconciliation_item(case) for case in result["items"]],
        "current" if result["complete"] else "partial",
    )


def _vendor_reconciliation_source(
    source: Callable[[], dict] | None,
) -> tuple[list[dict], list[dict]]:
    if source is None:
        return [], []
    try:
        items, status = _collect_vendor_reconciliations(source)
        return items, [{"kind": "vendor_reconciliation", "status": status}]
    except Exception:
        return [], [{"kind": "vendor_reconciliation", "status": "unavailable"}]


def _evidence_source_approvals(source: Callable[[], dict] | None):
    if source is None:
        return [], []
    try:
        result = source()
        if (not isinstance(result, dict) or result.get("coverage") not in {
                "current", "partial", "disabled"} or result.get("limit") != 64
                or not isinstance(result.get("items"), list) or len(result["items"]) > 64):
            raise ValueError("Evidence source approvals are unavailable")
        items = []
        for row in result["items"]:
            items.append(_item("evidence_source_approval", row["id"],
                "Review evidence source: " + _bounded_text(row["title"], limit=100),
                href="/compliance/continuous-evidence#trc-sources",
                updated_at=_timestamp(row["updated_at"]), version=row["version"],
                reason="Another administrator saved this source setup. Review its account and checks before approving; collection starts separately."))
        return items, [{"kind": "evidence_source_approval", "status": result["coverage"],
                        "limit": 64}]
    except Exception:
        return [], [{"kind": "evidence_source_approval", "status": "unavailable"}]


def _owned_task_attention(world, principal, task_allowed=None):
    """Private task questions and recovery never inherit a fleet-wide view."""
    items, coverage = [], []
    owner = principal or ""
    for task_status in ("blocked", "failed"):
        try:
            rows = world.list_goals(status=task_status, owner=owner, limit=SOURCE_LIMIT + 1, order="desc")
            for goal in rows[:SOURCE_LIMIT]:
                if goal.owner != owner or (task_allowed is not None and not task_allowed(goal)):
                    continue
                questions = world.open_questions(goal_id=goal.id) if task_status == "blocked" else []
                version = [[question.id, question.asked_at, question.question] for question in questions]
                reason = (f"{len(questions)} clarification question(s) waiting for your answer" if questions
                          else "Review the stopped task before choosing whether to restart; no retry happens automatically")
                items.append(_item("task_attention", goal.id, goal.title,
                                   href=f"/chat/goal/{goal.id}", owner=owner,
                                   updated_at=goal.updated_at, version=[task_status, version], reason=reason))
            coverage.append({"kind": "task_attention", "status": "partial" if len(rows) > SOURCE_LIMIT else "current"})
        except Exception:
            coverage.append({"kind": "task_attention", "status": "unavailable"})
    states = [source["status"] for source in coverage]
    return items, [{"kind": "task_attention", "status": "unavailable" if "unavailable" in states else "partial" if "partial" in states else "current"}]


def _approval_source(world, principal, approval_allowed):
    items, coverage = [], []
    try:
        rows = world.pending_approvals()
        for row in rows[:SOURCE_LIMIT]:
            if approval_allowed is None or not approval_allowed(row):
                continue
            if row.claimed_by and row.claimed_by != principal:
                continue
            state = world.approval_state(row.id)
            if not state or state["status"] != "pending":
                continue
            if principal and (principal in state["approvers"] or row.requested_by == principal):
                continue
            items.append(_item("approval", row.id, str(row.action).replace("_", " "),
                href=f"/approvals#approval-{row.id}", owner=row.claimed_by,
                updated_at=row.requested_at, version=[row.detail, row.risk, state],
                reason="Assigned approval" if row.claimed_by else "Available for an independent review"))
        coverage.append({"kind": "approval", "status": "partial" if len(rows) > SOURCE_LIMIT else "current"})
    except Exception:
        coverage.append({"kind": "approval", "status": "unavailable"})
    return items, coverage


def _flow_approval_source(source: Callable[[], dict], principal: str | None):
    """Put currently authorized flow pauses in the same Approvals filter."""
    try:
        result = source()
        if (not isinstance(result, dict) or not isinstance(result.get("items"), list)
                or result.get("coverage") not in {"current", "partial", "unavailable"}):
            raise ValueError("invalid flow approval source")
        items = []
        for row in result["items"][:SOURCE_LIMIT]:
            item = _item(
                "approval", f"flow:{row['run_id']}", row["title"],
                href=row["href"], owner=principal or row["owner"],
                due_at=row["due_at"], updated_at=row["updated_at"],
                version=[row["approval_binding_sha256"], row["approval_card_status"]],
                reason=("Flow approval waiting for you. Review the card, then approve or reject."
                        if row["approval_card_status"] == "current"
                        else "Flow approval details changed. Review them again before you approve or reject."),
            )
            item["flow_run_id"] = row["run_id"]
            items.append(item)
        status = "partial" if len(result["items"]) > SOURCE_LIMIT else result["coverage"]
        return items, [{"kind": "flow_approval", "status": status}]
    except Exception:
        return [], [{"kind": "flow_approval", "status": "unavailable"}]


def _signoff_source(world, owner, specs):
    items, coverage = [], []
    try:
        rows = world.list_goals(status="done", owner=owner, limit=SOURCE_LIMIT + 1, order="desc")
        # Resolve current suite permissions only when this owner has completed
        # work. Loading every specialist pack for an empty queue delays unrelated
        # assigned reviews; authorization-dependent specs must never be cached.
        resolved_specs = (specs() if callable(specs) else specs) if rows else []
        scoped_specs = {spec["domain"]: spec for spec in resolved_specs if spec.get("gate")}
        candidates = [goal for goal in rows[:SOURCE_LIMIT] if goal.domain in scoped_specs]
        signed = world.signoffs_for_goals([goal.id for goal in candidates])
        for goal in candidates:
            if signed.get(goal.id) == "approved":
                continue
            spec = scoped_specs[goal.domain]
            items.append(_item("signoff", goal.id, spec["deliverable"],
                href=f"/chat/goal/{goal.id}", owner=getattr(goal, "owner", ""),
                updated_at=goal.updated_at, version=[goal.title, spec.get("gate")],
                reason="Result was rejected. Revise it, then ask for approval again." if signed.get(goal.id) == "rejected" else "Finished result waiting for approval"))
        coverage.append({"kind": "signoff", "status": "partial" if len(rows) > SOURCE_LIMIT else "current"})
    except Exception:
        coverage.append({"kind": "signoff", "status": "unavailable"})
    return items, coverage


def _assessment_source(assessments, assessment_allowed, principal):
    items, coverage = [], []
    try:
        rows = assessments()
        for row in rows:
            if not assessment_allowed(row):
                continue
            assigned = row.get("assignee") or ""
            if assigned and assigned != principal:
                continue
            dates = [float(row[key]) for key in ("next_review_at", "renewal_at", "acceptance_expires_at") if row.get(key)]
            due_at = min(dates) if dates else None
            if row.get("status") not in {"pending_review", "needs_more"} and not row.get("review_due"):
                continue
            items.append(_item("assessment", row["id"], row["subject"],
                href="#assessment", owner=assigned, due_at=due_at,
                updated_at=row.get("created_at"), version=row.get("revision"),
                reason=row.get("review_due_reason") or ("Assigned assessment" if assigned else "Unassigned assessment")))
            items[-1]["assessment_id"] = row["id"]
        coverage.append({"kind": "assessment", "status": "current"})
    except Exception:
        coverage.append({"kind": "assessment", "status": "unavailable"})
    return items, coverage


def _governance_sources(source):
    kinds = {"lifecycle_review", "drop_authority_review", "trust_center_review", "disclosure_review"}
    if source is None:
        return [], []
    try:
        result = source()
        if (not isinstance(result, dict) or set(result) != {"items", "coverage"}
                or not isinstance(result["items"], list) or len(result["items"]) > 6 * 99
                or not isinstance(result["coverage"], list) or len(result["coverage"]) != len(kinds)
                or {row["kind"] for row in result["coverage"]} != kinds
                or any(row["status"] not in {"current", "partial", "disabled", "denied", "unavailable"}
                       or row["limit"] != 99 for row in result["coverage"])):
            raise ValueError("Current governance reviews are unavailable")
        items = []
        for row in result["items"]:
            if row["kind"] not in kinds or not row["href"].startswith("/") or row["href"].startswith("//"):
                raise ValueError("Current governance review destination is unavailable")
            items.append(_item(row["kind"], row["key"], _bounded_text(row["title"], limit=500),
                href=row["href"], due_at=_timestamp(row["due_at"], optional=True),
                updated_at=_timestamp(row["updated_at"]), version=row["version"],
                reason=_bounded_text(row["reason"])))
        return items, result["coverage"]
    except Exception:
        return [], [{"kind": kind, "status": "unavailable", "limit": 99} for kind in sorted(kinds)]


def collect(world, *, principal: str | None, owner: str | None,
            specs: list[dict] | Callable[[], list[dict]],
            assessments: Callable[[], list[dict]], assessment_allowed: Callable[[dict], bool],
            project_reviews: Callable[[], list[dict]] | None = None,
            vendor_reconciliations: Callable[[], dict] | None = None,
            connection_attention: Callable[[], dict] | None = None,
            evidence_source_approvals: Callable[[], dict] | None = None,
            governance_reviews: Callable[[], dict] | None = None,
            flow_approvals: Callable[[], dict] | None = None,
            approval_allowed: Callable[[object], bool] | None = None,
            task_allowed: Callable[[object], bool] | None = None,
            now: float | None = None) -> dict:
    """Project only authorized content; report failed or bounded sources honestly."""
    now = time.time() if now is None else now
    items, coverage = [], []
    task_items, task_coverage = _owned_task_attention(world, principal, task_allowed)
    items.extend(task_items)
    coverage.extend(task_coverage)
    for source_items, source_coverage in (
        _approval_source(world, principal, approval_allowed),
        _signoff_source(world, owner, specs),
        _assessment_source(assessments, assessment_allowed, principal),
    ):
        items.extend(source_items)
        coverage.extend(source_coverage)
    if flow_approvals is not None:
        flow_items, flow_coverage = _flow_approval_source(flow_approvals, principal)
        items.extend(flow_items)
        coverage.extend(flow_coverage)
    if project_reviews is not None:
        try:
            reviews = project_reviews()
            for review in reviews:
                owner_action = review.get("owner") == principal and (review["status"] == "changes_requested" or review["stale"])
                if not owner_action and (review["reviewer"] != principal or review["status"] != "pending"):
                    continue
                items.append(_item("project_review", review["id"], review["title"],
                    href="/project-reviews#packet=" + review["id"], owner=principal if owner_action else review["reviewer"],
                    due_at=review["due_at"], updated_at=review["updated_at"],
                    version=[review["revision"], review["source_version"], review["stale"]],
                    reason=("Address reviewer changes and submit a fresh packet" if review["status"] == "changes_requested" else "Source changed; submit a fresh result") if owner_action else ("Source changed; ask the owner for a fresh result" if review["stale"] else "Assigned project result review")))
            coverage.append({"kind": "project_review", "status": "current"})
        except Exception:
            coverage.append({"kind": "project_review", "status": "unavailable"})
    if connection_attention is not None:
        try:
            connections = connection_attention()
            if connections.get("coverage") not in {"current", "disabled", "unavailable", "partial"} or not isinstance(connections.get("items"), list):
                raise ValueError("Connection coverage is unavailable")
            for connection in connections["items"][:SOURCE_LIMIT]:
                href = str(connection["href"])
                if not href.startswith("/") or href.startswith("//"):
                    raise ValueError("Invalid connection recovery destination")
                items.append(_item("connection_attention", connection["name"], connection["title"],
                                   href=href, owner=principal or "", version=connection["revision"], reason=connection["reason"]))
            coverage.append({"kind": "connection_attention", "status": "partial" if len(connections["items"]) > SOURCE_LIMIT else connections["coverage"]})
        except Exception:
            coverage.append({"kind": "connection_attention", "status": "unavailable"})
    else:
        coverage.append({"kind": "connection_attention", "status": "unavailable"})
    reconciliations, reconciliation_coverage = _vendor_reconciliation_source(
        vendor_reconciliations,
    )
    items.extend(reconciliations)
    coverage.extend(reconciliation_coverage)
    evidence_items, evidence_coverage = _evidence_source_approvals(evidence_source_approvals)
    items.extend(evidence_items)
    coverage.extend(evidence_coverage)
    review_items, review_coverage = _governance_sources(governance_reviews)
    items.extend(review_items)
    coverage.extend(review_coverage)
    for row in items:
        row["overdue"] = bool(row["due_at"] and row["due_at"] <= now)
        row["assignment"] = "mine" if principal and row["owner"] == principal else "available"
    items.sort(key=lambda row: (not row["overdue"], row["due_at"] or float("inf"), -row["updated_at"], row["id"]))
    return {"items": items, "coverage": coverage, "generated_at": now}


def preferences(context: str) -> dict:
    record = _PREFERENCES.get("ACP-" + context[:59])
    if record is None:
        return {"revision": 0, "states": {}}
    if record.get("context") != context:
        raise ValueError("Attention preferences do not match this account.")
    return {"revision": record["revision"], "states": record["states"]}


def apply_preferences(model: dict, preference: dict, *, now: float) -> dict:
    for row in model["items"]:
        state = preference["states"].get(row["id"], {})
        current = state.get("source_version") == row["source_version"]
        row["read"] = bool(current and state.get("read"))
        row["snoozed_until"] = state.get("snoozed_until", 0) if current else 0
        row["snoozed"] = row["snoozed_until"] > now
    return {**model, "revision": preference["revision"], "context": model.get("context", "")}


def save_preference(context: str, item: dict, *, expected_revision: int, operation_id: str,
                    read: bool, snoozed_until: float, actor: str) -> dict:
    record_id = "ACP-" + context[:59]
    record = _PREFERENCES.get(record_id)
    state = {"source_version": item["source_version"], "read": read, "snoozed_until": snoozed_until}
    request = _digest([item["id"], state])
    if record and record.get("last_operation") == operation_id:
        if record.get("last_request") != request:
            raise RecordConflict("This retry reference was already used for a different change.")
        return {"revision": record["revision"]}
    if (record or {}).get("revision", 0) != expected_revision:
        raise RecordConflict("Attention preferences changed in another window. Refresh before trying again.")

    def mutate(value):
        if value.get("context") != context:
            raise RecordConflict("The account context changed.")
        states = dict(value.get("states") or {})
        if item["id"] not in states and len(states) >= 5000:
            # Discard the oldest preference, never a business record.
            states.pop(next(iter(states)))
        states[item["id"]] = state
        value.update(states=states, last_operation=operation_id, last_request=request)

    if record is None:
        value = {"id": record_id, "schema": "lightwork.attention-preferences.v1", "context": context, "states": {}}
        mutate(value)
        saved = _PREFERENCES.create(value, action="set_attention_preference", actor=actor)
    else:
        saved = _PREFERENCES.update(record_id, mutate, expected_revision=expected_revision,
                                     action="set_attention_preference", actor=actor)
    if saved is None:
        raise RecordConflict("Attention preferences disappeared. Refresh before trying again.")
    return {"revision": saved["revision"]}
