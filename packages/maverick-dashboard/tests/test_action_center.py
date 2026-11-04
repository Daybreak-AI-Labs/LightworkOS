"""Personal attention without widening business-record permissions."""
import copy
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick import audit, config, world_model
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import action_center as center
from maverick_dashboard import action_center_api as api
from maverick_dashboard.app import app

CTX = hashlib.sha256(b"alice").hexdigest()


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)
    monkeypatch.setattr(api.config, "get_features", lambda: {"action_center": True})
    monkeypatch.setattr(api.config, "config_source_errors", lambda **kwargs: [])
    config.reset_config_cache()
    yield
    config.reset_config_cache()


class World:
    def pending_approvals(self):
        return [SimpleNamespace(id=1, claimed_by=None, requested_by="user:submitter", action="publish_report",
            risk="high", detail="private details", requested_at=10)]

    def approval_state(self, identifier):
        return {"status": "pending", "approvers": [], "approvals_required": 1}

    def list_goals(self, **kwargs):
        assert kwargs["owner"] == "user:alice"
        if kwargs.get("status") != "done":
            return []
        return [SimpleNamespace(id=1, domain="forecast", title="Forecast", owner="user:alice", updated_at=20),
                SimpleNamespace(id=2, domain="restricted", title="Restricted", owner="user:alice", updated_at=20)]

    def signoffs_for_goals(self, ids):
        assert ids == [1]
        return {}


def model(world=None):
    assessments = [
        {"id":"a1", "type":"privacy", "subject":"Mine", "assignee":"user:alice", "status":"approved",
         "revision":1, "review_due":True, "next_review_at":50},
        {"id":"a2", "type":"privacy", "subject":"Other person's assessment", "assignee":"user:bob", "status":"needs_more", "revision":1},
        {"id":"a3", "type":"restricted", "subject":"Restricted assessment", "status":"pending_review", "revision":1},
    ]
    return center.collect(world or World(), principal="user:alice", owner="user:alice",
        specs=[{"domain":"forecast", "gate":"human", "deliverable":"Cash forecast"}],
        assessments=lambda: assessments, assessment_allowed=lambda row: row["type"] == "privacy",
        approval_allowed=lambda row: True, connection_attention=lambda: {"items": [], "coverage": "current"}, now=100)


def test_unified_items_respect_owner_suite_assignment_and_due_state():
    value = model()
    assert {row["kind"] for row in value["items"]} == {"approval", "assessment", "signoff"}
    assert value["items"][0]["title"] == "Mine"
    assert value["items"][0]["overdue"] is True
    assert value["items"][0]["assignment"] == "mine"
    assert all(row["status"] == "current" for row in value["coverage"])
    assert "Restricted" not in str(value) and "Other person's" not in str(value)


@pytest.mark.parametrize("relationship", ["claimed", "requested", "voted"])
def test_approvals_do_not_ask_for_others_claims_self_approval_or_duplicate_votes(relationship):
    world = World()
    row = world.pending_approvals()[0]
    if relationship == "claimed":
        row.claimed_by = "user:bob"
    elif relationship == "requested":
        row.requested_by = "user:alice"
    else:
        world.approval_state = lambda identifier: {"status":"pending", "approvers":["user:alice"]}
    world.pending_approvals = lambda: [row]
    assert not any(item["kind"] == "approval" for item in model(world)["items"])


def test_failed_source_is_not_reported_clear():
    class Broken(World):
        def pending_approvals(self):
            raise OSError("private database error")
    result = model(Broken())
    assert {"kind":"approval", "status":"unavailable"} in result["coverage"]
    assert "private database error" not in str(result)
    assert len(result["items"]) == 2


def test_project_review_actions_use_authorized_inbox_and_current_assignment():
    rows = [{"id": "PRP-test", "title": "Selected result", "reviewer": "user:alice", "status": "pending",
             "due_at": 50, "updated_at": 20, "revision": 2, "source_version": "a" * 64, "stale": True},
            {"id": "PRP-other", "title": "Another reviewer", "reviewer": "user:bob", "status": "pending"}]
    value = center.collect(World(), principal="user:alice", owner="user:alice", specs=[],
        assessments=list, assessment_allowed=lambda row: True, project_reviews=lambda: rows, now=100)
    reviews = [row for row in value["items"] if row["kind"] == "project_review"]
    assert len(reviews) == 1 and reviews[0]["overdue"]
    assert reviews[0]["href"] == "/project-reviews#packet=PRP-test"
    assert reviews[0]["reason"].startswith("Source changed")


def _reconciliation_case(**changes):
    value = {
        "id": "VON-uncertain",
        "schema": "lightwork.vendor-onboarding.v1",
        "vendor_name": "Northstar AI",
        "revision": 7,
        "owner": "procurement",
        "stage": "reconciliation_required",
        "updated_at": 90,
        "due_at": 120,
        "reconciliation": {
            "schema": "lightwork.vendor-onboarding.reconciliation-summary.v1",
            "attempted_action": {
                "operation_id": "VOP-" + "1" * 32,
                "action": "jira.create",
                "attempt_count": 1,
                "started_at": 80,
                "target": {"provider": "jira", "project": "VEND"},
            },
            "known_observations": [
                {"kind": "execution_attempt", "state": "recorded", "count": 1,
                 "observed_at": 80},
                {"kind": "provider_receipt", "state": "not_recorded"},
                {"kind": "authoritative_readback", "state": "no_match", "match_count": 0,
                 "observed_at": 85},
            ],
            "uncertainty": {
                "state": "unresolved",
                "reason": "no_matching_effect_observed",
                "explanation": "No matching Jira task was observed; absence is not proof of no effect.",
            },
            "safe_next_check": {
                "kind": "check_status",
                "label": "Check the original Jira destination again",
                "mode": "read_only",
            },
            "responsible_operator": {
                "principal": "user:alice",
                "business_owner": "procurement",
            },
            "resolution": {
                "automatic_compensation_supported": False,
                "unreviewed_replacement_allowed": False,
                "requires_separate_review": True,
                "explanation": "Any supported resolution requires a separate reviewed action.",
            },
        },
    }
    value.update(changes)
    return value


def _case_page(cases, *, has_more=False, next_cursor=None, limit=100, **changes):
    value = {
        "schema": "lightwork.vendor-onboarding.case-page.v1",
        "cases": cases,
        "view": "unresolved",
        "limit": limit,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "record_reads": len(cases),
        "scan_complete": not has_more,
        "order": "case_id_ascending",
    }
    value.update(changes)
    return value


def test_vendor_reconciliation_is_actionable_without_exposing_or_authorizing_a_write():
    result = center.collect(
        World(), principal="user:alice", owner="user:alice", specs=[],
        assessments=list, assessment_allowed=lambda row: True,
        vendor_reconciliations=lambda: {
            "items": [_reconciliation_case()], "complete": True,
        },
        now=100,
    )
    item = next(row for row in result["items"] if row["kind"] == "vendor_reconciliation")
    assert item["title"] == "Resolve uncertain Jira task for Northstar AI"
    assert item["href"] == "/third-party/vendor-onboarding?case=VON-uncertain"
    assert item["assignment"] == "mine"
    assert item["reconciliation"]["safe_next_check"]["mode"] == "read_only"
    assert item["reconciliation"]["resolution"]["unreviewed_replacement_allowed"] is False
    assert {row["kind"]: row["status"] for row in result["coverage"]}[
        "vendor_reconciliation"
    ] == "current"


def test_current_access_loss_is_an_in_app_resolution_path_without_a_retry_write():
    case = _reconciliation_case()
    case["reconciliation"]["uncertainty"] = {
        "state": "unresolved",
        "reason": "current_connection_access_unavailable",
        "explanation": "Current Jira access is unavailable; no provider request was made.",
    }
    case["reconciliation"]["safe_next_check"] = {
        "kind": "restore_access",
        "label": "Restore the original Jira connection access, then check status",
        "mode": "read_only",
        "href": "/connections",
    }
    result = center.collect(
        World(), principal="user:alice", owner="user:alice", specs=[],
        assessments=list, assessment_allowed=lambda row: True,
        vendor_reconciliations=lambda: {"items": [case], "complete": True}, now=100,
    )
    item = next(row for row in result["items"] if row["kind"] == "vendor_reconciliation")
    assert item["reconciliation"]["safe_next_check"] == case["reconciliation"][
        "safe_next_check"
    ]
    assert item["reconciliation"]["resolution"]["requires_separate_review"] is True


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda value: value.pop("revision"), id="missing-revision"),
        pytest.param(lambda value: value.__setitem__("revision", "7"), id="string-revision"),
        pytest.param(lambda value: value.pop("owner"), id="missing-owner"),
        pytest.param(lambda value: value.__setitem__("vendor_name", ""), id="empty-vendor"),
        pytest.param(lambda value: value.__setitem__("due_at", "soon"), id="string-due"),
        pytest.param(lambda value: value.__setitem__("updated_at", float("nan")), id="nan-update"),
        pytest.param(
            lambda value: value["reconciliation"]["attempted_action"].__setitem__("action", ""),
            id="empty-attempted-action",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["attempted_action"]["target"].__setitem__(
                "project", "vend",
            ),
            id="malformed-target",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["attempted_action"].__setitem__(
                "attempt_count", -1,
            ),
            id="negative-attempt-count",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["known_observations"].__setitem__(0, None),
            id="null-observation",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["known_observations"].__setitem__(1, "recorded"),
            id="string-observation",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["known_observations"][2].__setitem__(
                "provider_body", "PRIVATE_PROVIDER_BODY",
            ),
            id="nested-extra-field",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["uncertainty"].pop("reason"),
            id="missing-reason",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["safe_next_check"].__setitem__("label", ""),
            id="empty-next-label",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["responsible_operator"].__setitem__(
                "principal", " user:alice ",
            ),
            id="whitespace-principal",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["responsible_operator"].pop(
                "business_owner",
            ),
            id="missing-business-owner",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["resolution"].__setitem__(
                "automatic_compensation_supported", True,
            ),
            id="compensation-claimed",
        ),
        pytest.param(
            lambda value: value["reconciliation"]["resolution"].__setitem__(
                "explanation", "",
            ),
            id="empty-resolution-explanation",
        ),
    ],
)
def test_malformed_reconciliation_fields_fail_closed_without_detail_leak(mutate):
    case = _reconciliation_case()
    mutate(case)
    result = center.collect(
        World(), principal="user:alice", owner="user:alice", specs=[],
        assessments=list, assessment_allowed=lambda row: True,
        vendor_reconciliations=lambda: {"items": [case], "complete": True}, now=100,
    )
    assert not any(row["kind"] == "vendor_reconciliation" for row in result["items"])
    assert {row["kind"]: row["status"] for row in result["coverage"]}[
        "vendor_reconciliation"
    ] == "unavailable"
    assert "PRIVATE_PROVIDER_BODY" not in str(result)


def test_failed_reconciliation_source_is_explicitly_unavailable_without_detail_leak():
    private = "provider response containing private details"

    def broken():
        raise RuntimeError(private)

    result = center.collect(
        World(), principal="user:alice", owner="user:alice", specs=[],
        assessments=list, assessment_allowed=lambda row: True,
        vendor_reconciliations=broken, now=100,
    )
    assert {row["kind"]: row["status"] for row in result["coverage"]}[
        "vendor_reconciliation"
    ] == "unavailable"
    assert private not in str(result)


def test_request_bound_reconciliation_source_pages_without_provider_mutation(monkeypatch):
    from maverick_dashboard import vendor_onboarding_api

    calls = []

    class Service:
        def list_page(self, context, **kwargs):
            calls.append((context, kwargs))
            if len(calls) == 1:
                return _case_page(
                    [_reconciliation_case()], has_more=True, next_cursor="next-page",
                )
            return _case_page([_reconciliation_case(id="VON-second")])

    binding = SimpleNamespace(service=Service(), context="current-authority")
    monkeypatch.setattr(vendor_onboarding_api, "_binding", lambda request: binding)
    result = api._vendor_reconciliation_rows(object())
    assert [row["id"] for row in result["items"]] == ["VON-uncertain", "VON-second"]
    assert result["complete"] is True
    assert calls == [
        ("current-authority", {"limit": 100, "cursor": "", "view": "unresolved"}),
        ("current-authority", {"limit": 100, "cursor": "next-page", "view": "unresolved"}),
    ]


def test_request_bound_reconciliation_source_has_a_hard_page_cap(monkeypatch):
    from maverick_dashboard import vendor_onboarding_api

    calls = 0

    class Service:
        def list_page(self, context, **kwargs):
            nonlocal calls
            calls += 1
            return _case_page([], has_more=True, next_cursor=f"page-{calls}")

    binding = SimpleNamespace(service=Service(), context="current-authority")
    monkeypatch.setattr(vendor_onboarding_api, "_binding", lambda request: binding)
    result = api._vendor_reconciliation_rows(object())
    assert result == {"items": [], "complete": False}
    assert calls == 20


@pytest.mark.parametrize(
    "change",
    [
        {"schema": "lightwork.vendor-onboarding.case-page.v2"},
        {"view": "all"},
        {"limit": 99},
        {"scan_complete": True},
        {"has_more": False, "scan_complete": True,
         "next_cursor": "cursor-without-has-more"},
        {"private_provider_page": "PRIVATE_PROVIDER_BODY"},
    ],
)
def test_request_bound_reconciliation_source_rejects_malformed_page_contract(
    monkeypatch, change,
):
    from maverick_dashboard import vendor_onboarding_api

    class Service:
        def list_page(self, context, **kwargs):
            page = _case_page([], has_more=True, next_cursor="next-page")
            page.update(change)
            return page

    binding = SimpleNamespace(service=Service(), context="current-authority")
    monkeypatch.setattr(vendor_onboarding_api, "_binding", lambda request: binding)
    with pytest.raises(ValueError, match="source is unavailable"):
        api._vendor_reconciliation_rows(object())


def test_versioned_preferences_survive_reload_and_changed_items_become_unread():
    item = model()["items"][0]
    center.save_preference(CTX, item, expected_revision=0, operation_id="first-operation",
                           read=True, snoozed_until=500, actor="user:alice")
    preference = center.preferences(CTX)
    saved = center.apply_preferences(model(), preference, now=100)["items"][0]
    assert saved["read"] and saved["snoozed"]
    changed = model()
    changed["items"][0]["source_version"] = "f" * 64
    restored = center.apply_preferences(changed, center.preferences(CTX), now=100)["items"][0]
    assert not restored["read"] and not restored["snoozed"]
    expired = center.apply_preferences(model(), center.preferences(CTX), now=501)["items"][0]
    assert expired["read"] and not expired["snoozed"]


def test_exact_retry_and_concurrent_changes_are_safe():
    item = model()["items"][0]
    kwargs = dict(expected_revision=0, operation_id="first-operation", read=True, snoozed_until=0, actor="user:alice")
    result = center.save_preference(CTX, item, **kwargs)
    assert center.save_preference(CTX, item, **kwargs) == result
    with pytest.raises(RecordConflict):
        center.save_preference(CTX, item, **{**kwargs, "read":False})

    def attempt(value):
        try:
            return center.save_preference(CTX, item, expected_revision=1, operation_id=value,
                read=False, snoozed_until=0, actor="user:alice")
        except RecordConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["concurrent-one", "concurrent-two"]))
    assert sum(value is not None for value in results) == 1


def test_preferences_are_isolated_by_workspace_and_account():
    item = model()["items"][0]
    with tenant_scope(tenant="alpha"):
        center.save_preference(CTX, item, expected_revision=0, operation_id="first-operation",
            read=True, snoozed_until=0, actor="user:alice")
        assert center.preferences(hashlib.sha256(b"bob").hexdigest())["revision"] == 0
    with tenant_scope(tenant="beta"):
        assert center.preferences(CTX)["revision"] == 0


def _client_model(monkeypatch):
    value = model()
    monkeypatch.setattr(api, "_model", lambda request: copy.deepcopy(value))
    monkeypatch.setattr(api, "context_for", lambda request: CTX)
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin":"http://127.0.0.1", "X-Lightwork-Action-Context":CTX}), value


def test_api_preferences_recheck_current_source_then_paginate_and_keep_snoozed_overdue_visible(monkeypatch):
    client, value = _client_model(monkeypatch)
    snapshot = client.get("/api/v1/action-center?limit=1").json()
    assert snapshot["total"] == 3 and snapshot["has_more"]
    item = snapshot["items"][0]
    body = {"expected_revision":0, "operation_id":"operation-00000001", "source_version":item["source_version"],
            "read":True, "snoozed_until":time.time()+3600}
    response = client.put(f"/api/v1/action-center/{item['id']}/preference", json=body)
    assert response.status_code == 200, response.text
    active = client.get("/api/v1/action-center").json()
    assert active["counts"]["snoozed"] == 1 and len(active["items"]) == 3
    assert active["items"][0]["read"] is True
    assert client.get("/api/v1/action-center?view=snoozed").json()["total"] == 1
    assert client.get("/api/v1/action-center?kind=approval").json()["total"] == 1
    assert client.get("/api/v1/action-center?kind=vendor_reconciliation").status_code == 200
    value["items"][0]["source_version"] = "f" * 64
    assert client.put(f"/api/v1/action-center/{item['id']}/preference", json=body).status_code == 409
    value["items"].pop(0)
    assert client.put(f"/api/v1/action-center/{item['id']}/preference", json=body).status_code == 404


def test_api_refuses_changed_context_or_disabled_feature(monkeypatch):
    client, value = _client_model(monkeypatch)
    item = value["items"][0]
    body = {"expected_revision":0, "operation_id":"operation-00000001", "source_version":item["source_version"], "read":True}
    assert client.put(f"/api/v1/action-center/{item['id']}/preference", json=body,
                       headers={"X-Lightwork-Action-Context":"wrong"}).status_code == 409
    monkeypatch.setattr(api.config, "get_features", lambda: {"action_center":False})
    assert client.get("/action-center").status_code == 403
    assert client.get("/api/v1/action-center").status_code == 403


def test_api_refuses_a_non_ascii_context_header_like_any_other_wrong_one(monkeypatch):
    client, value = _client_model(monkeypatch)
    item = value["items"][0]
    body = {"expected_revision":0, "operation_id":"operation-00000001", "source_version":item["source_version"], "read":True}
    # Header text arrives decoded as latin-1, so this is a non-ASCII str.
    odd = {"X-Lightwork-Action-Context": b"caf\xe9"}
    assert client.get("/api/v1/action-center", headers=odd).status_code == 409
    assert client.put(f"/api/v1/action-center/{item['id']}/preference", json=body, headers=odd).status_code == 409


def test_api_and_page_permission_floor_and_private_caching(monkeypatch):
    from maverick_dashboard import auth
    client, _ = _client_model(monkeypatch)
    page = client.get("/action-center")
    assert page.status_code == 200
    assert 'value="vendor_reconciliation"' in page.text
    assert client.get("/static/lightwork-action-center.js").status_code == 200
    assert client.get("/api/v1/action-center").headers["cache-control"] == "private, no-store"
    monkeypatch.setattr(auth, "has_permission", lambda request, permission: False)
    assert client.get("/api/v1/action-center").status_code == 403


def test_owned_questions_are_grouped_and_a_changed_question_invalidates_snooze():
    class Questions(World):
        questions = [SimpleNamespace(id=10, question="Confirm the period", asked_at=30), SimpleNamespace(id=11, question="Which account?", asked_at=31)]
        def list_goals(self, **kwargs):
            if kwargs["status"] == "blocked":
                return [SimpleNamespace(id=8, title="Waiting task", owner="user:alice", updated_at=32)]
            return []
        def open_questions(self, **kwargs):
            return self.questions
    world = Questions()
    first = model(world)
    item = next(row for row in first["items"] if row["kind"] == "task_attention")
    assert len([row for row in first["items"] if row["kind"] == "task_attention"]) == 1
    preference = {"revision": 1, "states": {item["id"]: {"source_version": item["source_version"], "read": True, "snoozed_until": 500}}}
    world.questions = [SimpleNamespace(id=12, question="A different prerequisite?", asked_at=40)]
    changed = center.apply_preferences(model(world), preference, now=100)
    new = next(row for row in changed["items"] if row["kind"] == "task_attention")
    assert not new["snoozed"] and not new["read"]


def test_approval_source_refuses_content_without_explicit_authority_callback():
    result = center.collect(World(), principal="user:alice", owner="user:alice", specs=[],
                            assessments=list, assessment_allowed=lambda row: False)
    assert not any(row["kind"] == "approval" for row in result["items"])


@pytest.mark.parametrize("enabled", [True, False])
def test_supplier_reconciliations_follow_the_vendor_onboarding_switch(monkeypatch, tmp_path, enabled):
    # The source was gated on a [features] key no reader sets, so supplier
    # cases waiting on reconciliation never reached Action Center.
    (tmp_path / "config.toml").write_text(f"[vendor_onboarding]\nenable = {str(enabled).lower()}\n")
    config.reset_config_cache()
    seen, value = {}, model()

    def collect(world, **kwargs):
        seen.update(kwargs)
        return copy.deepcopy(value)

    monkeypatch.setattr(api.action_center, "collect", collect)
    monkeypatch.setattr(api, "context_for", lambda request: CTX)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Lightwork-Action-Context": CTX})
    try:
        assert client.get("/api/v1/action-center").status_code == 200
    finally:
        config.reset_config_cache()
    assert (seen["vendor_reconciliations"] is not None) is enabled
