"""Reviewed starter-team routes use the real bounded service and durable store."""
from __future__ import annotations

import csv
import io
from dataclasses import replace

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from maverick import config, starter_team_checks, world_model
from maverick.governed_operations import ServiceContext
from maverick_dashboard import starter_teams_api as native
from maverick_dashboard.app import app

BASE = "/api/v1/starter-teams"


@pytest.fixture
def web(tmp_path, monkeypatch):
    """Stub authenticated identity only; retain native storage, crypto and checks."""
    from maverick import audit, governed_records

    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_SHORING", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in ("MAVERICK_TENANT", "MAVERICK_REPLICA_COUNT", "MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND",
                 "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    config.reset_config_cache()
    state = {"context": ServiceContext(
        "starter-api-a", "user:reviewer", "user:reviewer", "user:reviewer", "structured-inputs",
        human=True, authorization_role="operator", authorization_policy="operator-policy-v1",
        budget_authority="offline-budget-v1", workspace_authority="workspace-selection-a-v1",
    ), "denied": set()}

    def trusted_context(_request):
        return state["context"]

    def suite_authority(_request, team):
        if team["id"] in state["denied"]:
            raise HTTPException(403, "Current department access denied")

    monkeypatch.setattr(native, "context", trusted_context)
    monkeypatch.setattr(native, "require_team", suite_authority)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    yield client, state
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _review(client, action, arguments, *, context=None):
    if context is None:
        response = client.get(BASE)
        assert response.status_code == 200, response.text
        context = response.json()["context"]
    return client.post(BASE + "/review", json={
        "action": action, "arguments": arguments, "expected_context": context,
    })


def _setup_args(team="order_management"):
    return {"team_id": team, "owner_label": "Taylor, operations owner",
            "scope": "Synthetic order portfolio only", "cadence": "manual", "max_rows": 250}


def _save(client, team="order_management"):
    review = _review(client, "setup", _setup_args(team))
    assert review.status_code == 200, review.text
    token = review.json()["token"]
    response = client.post(BASE + "/confirm", json={"token": token, "confirmed": True})
    assert response.status_code == 200, response.text
    return response.json()["setup"], token


def _csv_inputs(team):
    result = {}
    for definition in team["inputs"]:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=definition["columns"])
        writer.writeheader()
        writer.writerows(team["sample"]["tables"][definition["key"]])
        result[definition["key"]] = stream.getvalue()
    return result


def test_catalog_lists_all_37_without_claiming_provider_readiness(web):
    client, _ = web
    response = client.get(BASE)
    assert response.status_code == 200
    value = response.json()
    assert len(value["teams"]) == 37
    assert value["setups"] == []
    assert len(value["context"]) == 64
    assert "no-store" in response.headers["cache-control"]
    assert "without calling an AI service" in value["notice"]
    assert "require qualification" in value["notice"]


def test_setup_requires_confirmation_and_recovers_exact_original(web):
    client, _ = web
    reviewed = _review(client, "setup", _setup_args())
    assert reviewed.status_code == 200, reviewed.text
    token = reviewed.json()["token"]
    denied = client.post(BASE + "/confirm", json={"token": token, "confirmed": False})
    assert denied.status_code == 422
    assert client.get(BASE).json()["setups"] == []
    saved = client.post(BASE + "/confirm", json={"token": token, "confirmed": True})
    assert saved.status_code == 200, saved.text
    original = client.post(BASE + "/original", json={"token": token})
    replay = client.post(BASE + "/confirm", json={"token": token, "confirmed": True})
    assert original.json()["setup"]["id"] == saved.json()["setup"]["id"]
    assert replay.json()["setup"]["id"] == saved.json()["setup"]["id"]
    assert len(client.get(BASE).json()["setups"]) == 1


def test_page_context_must_match_before_reviewing_setup(web):
    client, state = web
    old = client.get(BASE).json()["context"]
    state["context"] = replace(state["context"], tenant="starter-api-b", workspace_authority="workspace-b")
    refused = _review(client, "setup", _setup_args(), context=old)
    assert refused.status_code == 409
    assert client.get(BASE).json()["setups"] == []


def test_confirm_rejects_changed_workspace_or_role(web):
    client, state = web
    review = _review(client, "setup", _setup_args())
    assert review.status_code == 200
    state["context"] = replace(state["context"], authorization_policy="operator-policy-v2")
    response = client.post(BASE + "/confirm", json={"token": review.json()["token"], "confirmed": True})
    assert response.status_code == 409
    assert client.get(BASE).json()["setups"] == []


def test_cross_origin_review_and_confirm_are_refused(web):
    client, _ = web
    context = client.get(BASE).json()["context"]
    refused = client.post(BASE + "/review", headers={"Origin": "https://untrusted.example"},
                          json={"action": "setup", "arguments": _setup_args(), "expected_context": context})
    assert refused.status_code == 403
    review = _review(client, "setup", _setup_args())
    refused = client.post(BASE + "/confirm", headers={"Origin": "https://untrusted.example"},
                          json={"token": review.json()["token"], "confirmed": True})
    assert refused.status_code == 403
    assert client.get(BASE).json()["setups"] == []


def test_sample_run_is_durable_replayable_and_has_source_evidence(web):
    client, _ = web
    setup, _ = _save(client)
    review = _review(client, "sample", {"setup_id": setup["id"]})
    assert review.status_code == 200, review.text
    body = {"token": review.json()["token"], "confirmed": True}
    response = client.post(BASE + "/confirm", json=body)
    assert response.status_code == 200, response.text
    case = response.json()["case"]
    assert case["mode"] == "sample"
    assert case["status"] == "awaiting_review"
    assert case["output"]["readiness"] == "sample_qualified"
    assert case["output"]["external_effects"] == []
    assert case["output"]["evidence"]
    again = client.post(BASE + "/confirm", json=body)
    assert again.status_code == 200
    assert again.json()["case"]["id"] == case["id"]
    assert len(client.get(f"{BASE}/setups/{setup['id']}/cases").json()["cases"]) == 1
    assert client.get(f"{BASE}/cases/{case['id']}").json()["case"]["output"] == case["output"]


def test_supplied_csv_checks_use_real_rules_and_remain_unqualified(web):
    client, _ = web
    setup, _ = _save(client, "grant_operations")
    team = starter_team_checks.get_team(setup["team_id"])
    review = _review(client, "inputs", {"setup_id": setup["id"], "as_of": team["sample"]["as_of"],
                                        "tables": _csv_inputs(team)})
    assert review.status_code == 200, review.text
    response = client.post(BASE + "/confirm", json={"token": review.json()["token"], "confirmed": True})
    assert response.status_code == 200, response.text
    output = response.json()["case"]["output"]
    assert {row["id"] for row in output["findings"]} == set(team["sample"]["expected_findings"])
    assert output["readiness"] == "structured_inputs_only"
    assert output["business_acceptance"] == "pending_human_review"
    assert output["usage"]["provider_calls"] == 0


@pytest.mark.parametrize("problem", ["invalid_calendar_date", "saved_row_budget"])
def test_input_review_refuses_known_invalid_work_before_confirmation(web, problem):
    client, _ = web
    args = _setup_args()
    if problem == "saved_row_budget":
        args["max_rows"] = 2
    setup_review = _review(client, "setup", args)
    saved = client.post(BASE + "/confirm", json={"token": setup_review.json()["token"], "confirmed": True})
    assert saved.status_code == 200, saved.text
    setup = saved.json()["setup"]
    team = starter_team_checks.get_team(setup["team_id"])
    response = _review(client, "inputs", {
        "setup_id": setup["id"], "tables": _csv_inputs(team),
        "as_of": "2026-02-30" if problem == "invalid_calendar_date" else team["sample"]["as_of"],
    })
    assert response.status_code == 422, response.text
    assert "token" not in response.json()
    assert client.get(f"{BASE}/setups/{setup['id']}/cases").json()["cases"] == []


def test_revoked_department_access_blocks_confirm_and_readback(web):
    client, state = web
    setup, _ = _save(client)
    review = _review(client, "sample", {"setup_id": setup["id"]})
    assert review.status_code == 200
    state["denied"].add(setup["team_id"])
    refused = client.post(BASE + "/confirm", json={"token": review.json()["token"], "confirmed": True})
    assert refused.status_code == 403
    assert client.get(f"{BASE}/setups/{setup['id']}/cases").status_code == 403


def test_other_owner_and_tenant_cannot_read_saved_case(web):
    client, state = web
    setup, _ = _save(client)
    review = _review(client, "sample", {"setup_id": setup["id"]})
    result = client.post(BASE + "/confirm", json={"token": review.json()["token"], "confirmed": True})
    assert result.status_code == 200, result.text
    case_id = result.json()["case"]["id"]
    previous = state["context"]
    state["context"] = replace(previous, actor="user:other", resource_owner="user:other", credential_authority="user:other")
    assert client.get(f"{BASE}/cases/{case_id}").status_code in {403, 404, 422}
    assert client.get(BASE).json()["setups"] == []
    state["context"] = replace(previous, tenant="starter-api-b", workspace_authority="workspace-b")
    assert client.get(f"{BASE}/cases/{case_id}").status_code in {403, 404, 422}
    assert client.get(BASE).json()["setups"] == []


def test_pause_invalidates_pending_run_review_and_resume_recovers(web):
    client, _ = web
    setup, _ = _save(client)
    pending = _review(client, "sample", {"setup_id": setup["id"]}).json()["token"]
    pause = _review(client, "pause", {"setup_id": setup["id"], "paused": True})
    assert pause.status_code == 200, pause.text
    result = client.post(BASE + "/confirm", json={"token": pause.json()["token"], "confirmed": True})
    assert result.status_code == 200, result.text
    assert result.json()["setup"]["paused"] is True
    refused = client.post(BASE + "/confirm", json={"token": pending, "confirmed": True})
    assert refused.status_code == 409
    assert client.get(f"{BASE}/setups/{setup['id']}/cases").json()["cases"] == []
    resume = _review(client, "pause", {"setup_id": setup["id"], "paused": False})
    result = client.post(BASE + "/confirm", json={"token": resume.json()["token"], "confirmed": True})
    assert result.status_code == 200
    assert result.json()["setup"]["paused"] is False


@pytest.mark.parametrize("bad", ["tampered", "MVKAR1:not-a-valid-seal"])
def test_review_token_tampering_cannot_change_setup(web, bad):
    client, _ = web
    response = client.post(BASE + "/confirm", json={"token": bad, "confirmed": True})
    assert response.status_code == 409
    assert client.get(BASE).json()["setups"] == []


@pytest.mark.parametrize("damage", ["missing_table", "duplicate_header", "nonfinite_number", "extra_cell"])
def test_csv_rejects_incomplete_or_ambiguous_inputs(damage):
    team = starter_team_checks.get_team("order_management")
    tables = _csv_inputs(team)
    if damage == "missing_table":
        tables.clear()
    elif damage == "duplicate_header":
        tables["records"] = "id,id,source\na,b,sample://bad\n"
    elif damage == "nonfinite_number":
        rows = [dict(row) for row in team["sample"]["tables"]["records"]]
        rows[0]["allocated_qty"] = "NaN"
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=team["inputs"][0]["columns"])
        writer.writeheader()
        writer.writerows(rows)
        tables["records"] = stream.getvalue()
    else:
        lines = tables["records"].splitlines()
        lines[1] += ",unexpected"
        tables["records"] = "\n".join(lines)
    with pytest.raises(ValueError):
        native.csv_tables(team, tables)


def test_copilot_uses_same_review_execute_and_original_case(web):
    from maverick_dashboard import product_operations_starter_teams as copilot

    client, _ = web
    setup, _ = _save(client)
    request = Request({"type": "http", "headers": [], "method": "POST", "path": "/starter-teams"})
    args = {"setup_id": setup["id"]}
    adapter = next(row for row in copilot.entries() if row.id == "teams.starter.sample")
    preview = adapter.prepare(request, {}, args)
    outcome = adapter.execute(request, {}, args, preview.native, "copilot-sample-0001")
    assert outcome.status == "confirmed"
    recovered = adapter.recover(request, {}, args, preview.native, "copilot-sample-0001")
    assert recovered is not None and recovered.status == "replayed"
    assert recovered.details == outcome.details
    cases = client.get(f"{BASE}/setups/{setup['id']}/cases").json()["cases"]
    assert len(cases) == 1
    assert cases[0]["output"]["readiness"] == "sample_qualified"


def test_unapproved_runtime_preview_is_not_a_confirmed_original(web, monkeypatch):
    from maverick import starter_team_runtime
    from maverick_dashboard import product_operations_starter_teams as copilot

    client, _ = web
    setup, _ = _save(client)
    team = starter_team_checks.get_team(setup["team_id"])
    evidence = _review(client, "inputs", {"setup_id": setup["id"], "as_of": team["sample"]["as_of"],
                                          "tables": _csv_inputs(team)})
    result = client.post(BASE + "/confirm", json={"token": evidence.json()["token"], "confirmed": True})
    assert result.status_code == 200, result.text
    case_id = result.json()["case"]["id"]
    # No specialist is dispatched: isolate the review/receipt lifecycle from
    # operator-specific specialist readiness and provider configuration.
    monkeypatch.setattr(starter_team_runtime, "_envelope", lambda team, case, actor: [
        {"specialist": name, "phase": "review"} for name in team["specialists"]
    ])
    reviewed = _review(client, "runtime", {"case_id": case_id, "max_dollars": 1.0, "max_wall_seconds": 900})
    assert reviewed.status_code == 200, reviewed.text
    visible_evidence = reviewed.json()["preview"]["Evidence shared with the AI service"]
    for row in team["sample"]["tables"]["records"]:
        assert any(row["id"] in item and row["source"] in item for item in visible_evidence)
    token = reviewed.json()["token"]
    original = client.post(BASE + "/original", json={"token": token})
    assert original.status_code == 200, original.text
    assert original.json()["status"] == "unconfirmed"
    request = Request({"type": "http", "headers": [], "method": "POST", "path": "/starter-teams"})
    material = native.open_token(token, recovery=True)
    assert copilot.recover(request, {}, {}, material, material["operation_id"]) is None


def test_ordinary_page_exposes_inputs_review_and_recovery(web):
    client, _ = web
    response = client.get("/starter-teams")
    assert response.status_code == 200, response.text
    assert "Review your setup" in response.text
    assert "Check your records" in response.text
    assert "Check original result" in response.text
    assert 'aria-labelledby="st-review-title"' in response.text
    assert "specialist AI work" in response.text


@pytest.mark.parametrize("script", ["lightwork-starter-teams.js", "lightwork-starter-team-schedules.js"])
def test_starter_page_scripts_are_served_by_asset_allowlist(web, script):
    client, _ = web
    page = client.get("/starter-teams")
    assert f"/static/{script}" in page.text
    asset = client.get(f"/static/{script}")
    assert asset.status_code == 200, asset.text
    assert "javascript" in asset.headers["content-type"]
    assert "async function confirm" in asset.text


def test_runtime_prerequisites_are_actionable_without_exposing_unexpected_errors():
    def fail(message):
        raise ValueError(message)

    expected = "Configure an authorized AI provider before running specialists"
    with pytest.raises(HTTPException) as exc:
        native.call(lambda: fail(expected))
    assert exc.value.detail == expected
    with pytest.raises(HTTPException) as exc:
        native.call(lambda: fail("sensitive internal input"))
    assert "sensitive" not in exc.value.detail


def _identity_request(monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import vendor_onboarding_composition as authority

    request = Request({"type": "http", "headers": [], "method": "POST", "path": BASE + "/confirm"})
    monkeypatch.setattr(native.auth, "require_permission", lambda request, permission: None)
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(native.shoring, "enabled", lambda: True)
    monkeypatch.setattr(native, "current_tenant_id_strict", lambda: "named-workspace")
    monkeypatch.setattr(native.auth, "caller_principal", lambda request: "user:reviewer")
    monkeypatch.setattr(native.auth, "caller_role", lambda request: "operator")
    monkeypatch.setattr(registry, "assert_tenant_active", lambda tenant: None)
    monkeypatch.setattr(authority, "_budget_authority", lambda tenant: "budget-policy")
    monkeypatch.setattr(authority, "_role_authority", lambda role: "operator-policy")
    monkeypatch.setattr(authority, "_workspace_authority", lambda request, actor, tenant: "workspace-generation")
    return request


@pytest.mark.parametrize("kind", ["interactive", "key_id", "key_scopes"])
def test_context_distinguishes_interactive_people_from_key_bearers(monkeypatch, kind):
    request = _identity_request(monkeypatch)
    if kind == "key_id":
        request.state.api_key_id = "key-one"
    elif kind == "key_scopes":
        request.state.api_key_scopes = frozenset({"tasks:write"})
    resolved = native.context(request)
    assert resolved.human is (kind == "interactive")
    assert resolved.actor == "user:reviewer"
    if kind == "interactive":
        assert resolved.authorization_policy == "operator-policy"
    else:
        assert resolved.authorization_policy != "operator-policy"


def test_context_binds_exact_key_identity_and_scopes(monkeypatch):
    request = _identity_request(monkeypatch)
    request.state.api_key_id = "key-one"
    request.state.api_key_scopes = frozenset({"tasks:write"})
    first = native.context(request)
    request.state.api_key_id = "key-two"
    assert native.context(request).binding() != first.binding()
    request.state.api_key_id = "key-one"
    request.state.api_key_scopes = frozenset({"tasks:write", "approvals:decide"})
    assert native.context(request).binding() != first.binding()


def test_saved_service_rechecks_human_authority_even_with_identical_binding(web):
    _, state = web
    request = Request({"type": "http", "headers": [], "method": "POST", "path": BASE + "/confirm"})
    service = native.service(request)
    state["context"] = replace(state["context"], human=False)
    assert service.context.binding() == state["context"].binding()
    with pytest.raises(PermissionError):
        service.preview_setup("order_management", "Owner", "Approved records only")


def test_team_authorization_requires_inherited_department_access(monkeypatch):
    from maverick import domain
    from maverick_dashboard import api

    request = Request({"type": "http", "headers": [], "method": "GET", "path": BASE})
    monkeypatch.setattr(domain, "suites_for_domain", lambda name: frozenset({"operations", "legal"}))
    monkeypatch.setattr(api, "_department_entitled_for_request", lambda suite: True)
    seen = []

    def require_suite(_request, suite):
        seen.append(suite)
        if suite == "legal":
            raise HTTPException(403, "Inherited department unavailable")

    monkeypatch.setattr(native.auth, "require_suite", require_suite)
    with pytest.raises(HTTPException) as exc:
        native.require_team(request, {"specialists": ["custom_contract_fork"]})
    assert exc.value.status_code == 403
    assert "legal" in seen
