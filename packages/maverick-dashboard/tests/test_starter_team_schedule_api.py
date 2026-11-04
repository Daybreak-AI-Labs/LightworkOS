"""Schedule route reviews retain native records, crypto and authority checks."""
from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import replace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import config, starter_team_schedule, world_model
from maverick.governed_operations import ServiceContext, digest
from maverick.starter_team_checks import get_team
from maverick_dashboard import product_operations_starter_team_schedules as copilot
from maverick_dashboard import starter_team_schedule_api as schedules
from maverick_dashboard import starter_teams_api as native
from maverick_dashboard.app import app

BASE = "/api/v1/starter-team-schedules"


@pytest.fixture
def web(tmp_path, monkeypatch):
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
        "schedule-api", "user:reviewer", "user:reviewer", "user:reviewer", "structured-inputs",
        human=True, authorization_role="operator", authorization_policy="operator-policy-v1",
        budget_authority="offline-budget-v1", workspace_authority="workspace-selection-v1"),
        "now": time.time(), "denied": False, "starts": [], "approved": set()}
    monkeypatch.setattr(native, "context", lambda request: state["context"])

    def suite_authority(request, team):
        if state["denied"]:
            raise HTTPException(403, "Department access denied")

    monkeypatch.setattr(native, "require_team", suite_authority)
    monkeypatch.setattr(starter_team_schedule.time, "time", lambda: state["now"])

    def runtime(service, schedule_id=None):
        core = service.service

        class OfflineRuntime:
            def review_runtime(self, case_id, *, max_dollars, max_wall_seconds):
                case = core.get_case(case_id)
                return {"runtime_id": "fixture-" + case_id, "case_id": case_id, "team_id": case["team_id"],
                        "input_sha256": case["input_sha256"], "context": core.context.binding(),
                        "scope": "Approved synthetic evidence only", "owner_label": "Taylor",
                        "source_scope": [row["source"] for row in case["output"]["evidence"]],
                        "phases": [{"domain": name, "instruction": "Prepare a cited review"}
                                   for name in get_team(case["team_id"])["specialists"]],
                        "allowed_tools": [], "max_dollars": max_dollars, "max_wall_seconds": max_wall_seconds}

            def approve_runtime(self, review, *, confirmed):
                assert confirmed is True and core.context.human
                state["approved"].add(digest(review))

            def start_runtime(self, review, *, confirmed):
                assert confirmed is False and digest(review) in state["approved"]
                core._authorize("runtime_start", get_team(review["team_id"]))
                state["starts"].append(review)
                return {"id": review["runtime_id"], "status": "completed"}

        return OfflineRuntime()

    monkeypatch.setattr(starter_team_schedule.StarterTeamScheduleService, "_runtime", runtime)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    setup_service = native.service(None)
    setup_review = setup_service.preview_setup("data_quality_operations", "Taylor", "Approved synthetic records")
    state["setup"] = setup_service.save_setup(setup_review, confirmed=True)
    yield client, state
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _args(state):
    return {"setup_id": state["setup"]["id"], "start_at": state["now"] + 1,
            "end_at": state["now"] + 8 * 3600, "interval_hours": 1, "max_runs": 3,
            "max_dollars_per_run": 1.0, "max_total_dollars": 3.0, "max_wall_seconds": 120}


def _review(client, state, action, arguments):
    return client.post(BASE + "/review", json={"action": action, "arguments": arguments,
        "expected_context": digest(state["context"].binding())})


def _confirm(client, token):
    return client.post(BASE + "/confirm", json={"token": token, "confirmed": True})


def _save(client, state):
    response = _review(client, state, "schedule", _args(state))
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    response = _confirm(client, token)
    assert response.status_code == 200, response.text
    return response.json()["schedule"], token


def _item_args(schedule):
    team = get_team("data_quality_operations")
    tables = {}
    for table in team["inputs"]:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=table["columns"])
        writer.writeheader()
        writer.writerows(team["sample"]["tables"][table["key"]])
        tables[table["key"]] = stream.getvalue()
    return {"schedule_id": schedule["id"], "as_of": team["sample"]["as_of"], "tables": tables}


def _approve_item(client, state, schedule):
    response = _review(client, state, "item", _item_args(schedule))
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    response = _confirm(client, token)
    assert response.status_code == 200, response.text
    return response.json()["item"], token


def test_schedule_review_confirmation_and_original_recovery(web):
    client, state = web
    reviewed = _review(client, state, "schedule", _args(state))
    assert reviewed.status_code == 200, reviewed.text
    preview = reviewed.json()["preview"]
    assert preview["Maximum runs"] == 3 and preview["Maximum total dollars"] == 3
    token = reviewed.json()["token"]
    assert client.get(BASE).json()["schedules"] == []
    assert client.post(BASE + "/confirm", json={"token": token}).status_code == 422
    saved = _confirm(client, token)
    assert saved.status_code == 200, saved.text
    replay = client.post(BASE + "/original", json={"token": token})
    assert replay.json()["schedule"]["id"] == saved.json()["schedule"]["id"]
    assert len(client.get(BASE).json()["schedules"]) == 1
    assert state["starts"] == []


def test_each_evidence_package_is_reviewed_before_due_dispatch_and_replay(web):
    client, state = web
    schedule, _ = _save(client, state)
    response = _review(client, state, "item", _item_args(schedule))
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["preview"]["Supplied records"]
    assert value["preview"]["Specialist work"]
    assert value["preview"]["Maximum dollars"] == 1
    assert state["approved"] == set()
    state["now"] += 2
    assert _review(client, state, "tick", {"schedule_id": schedule["id"]}).status_code == 422
    approved = _confirm(client, value["token"])
    assert approved.status_code == 200, approved.text
    assert len(state["approved"]) == 1 and state["starts"] == []
    tick = _review(client, state, "tick", {"schedule_id": schedule["id"]})
    assert tick.status_code == 200, tick.text
    token = tick.json()["token"]
    result = _confirm(client, token)
    assert result.status_code == 200, result.text
    assert result.json()["tick"]["runtime_status"] == "completed"
    assert "Specialist work completed" in result.json()["outcome"]["Status"]
    assert _confirm(client, token).json() == result.json()
    assert client.post(BASE + "/original", json={"token": token}).json() == result.json()
    assert len(state["starts"]) == 1


def test_large_valid_csv_review_is_rejected_before_issuing_unusable_token(web, monkeypatch):
    client, state = web
    team = get_team("grant_operations")
    setup_service = native.service(None)
    setup_review = setup_service.preview_setup(team["id"], "Taylor", "Approved synthetic grant records")
    state["setup"] = setup_service.save_setup(setup_review, confirmed=True)
    schedule, _ = _save(client, state)
    tables = {}
    for definition in team["inputs"]:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=definition["columns"])
        writer.writeheader()
        seed = team["sample"]["tables"][definition["key"]][0]
        for index in range(70):
            writer.writerow({**seed, "id": str(index) + "\U0001f4c4" * 300,
                             "source": "sample://" + str(index) + "\U0001f4c4" * 300})
        tables[definition["key"]] = stream.getvalue()
        assert len(tables[definition["key"]].encode("utf-8")) < 200_000

    # Keep real CSV checks, cases and records. The offline runtime carries the
    # same complete evidence rows as the native runtime, without a provider.
    offline_factory = starter_team_schedule.StarterTeamScheduleService._runtime

    def runtime_with_full_evidence(workflow, schedule_id=None):
        runtime = offline_factory(workflow, schedule_id)
        original = runtime.review_runtime

        def review_runtime(case_id, **limits):
            review = original(case_id, **limits)
            review["source_scope"] = workflow.service.get_case(case_id)["output"]["evidence"]
            assert len(json.dumps(review["source_scope"]).encode("utf-8")) > 2_000_000
            return review

        runtime.review_runtime = review_runtime
        return runtime

    monkeypatch.setattr(starter_team_schedule.StarterTeamScheduleService, "_runtime", runtime_with_full_evidence)
    response = _review(client, state, "item", {"schedule_id": schedule["id"],
        "as_of": team["sample"]["as_of"], "tables": tables})
    assert response.status_code == 422, response.text
    assert "smaller set of records" in response.json()["detail"]
    assert "token" not in response.json()
    items = schedules.service(None).list_items(schedule["id"])
    assert len(items) == 1 and items[0]["status"] == "awaiting_approval"
    assert state["approved"] == set() and state["starts"] == []


def test_pause_after_tick_review_refuses_stale_dispatch(web):
    client, state = web
    schedule, _ = _save(client, state)
    _approve_item(client, state, schedule)
    state["now"] += 2
    tick = _review(client, state, "tick", {"schedule_id": schedule["id"]}).json()["token"]
    pause = _review(client, state, "pause", {"schedule_id": schedule["id"], "paused": True})
    assert pause.status_code == 200, pause.text
    assert _confirm(client, pause.json()["token"]).status_code == 200
    assert _confirm(client, tick).status_code == 422
    assert state["starts"] == []


def test_review_rejects_changed_context_before_writing(web):
    client, state = web
    response = client.post(BASE + "/review", json={"action": "schedule", "arguments": _args(state), "expected_context": "0" * 64})
    assert response.status_code == 409
    assert client.get(BASE).json()["schedules"] == []


def test_confirm_and_recovery_reject_different_workspace_authority(web):
    client, state = web
    token = _review(client, state, "schedule", _args(state)).json()["token"]
    state["context"] = replace(state["context"], workspace_authority="workspace-changed")
    assert _confirm(client, token).status_code == 409
    assert client.post(BASE + "/original", json={"token": token}).status_code == 409


def test_schedule_mutations_reject_api_key_authority(web, monkeypatch):
    client, state = web
    monkeypatch.setattr(schedules.auth, "api_key_scopes", lambda request: {"operate"})
    response = _review(client, state, "schedule", _args(state))
    assert response.status_code == 403
    assert "Sign in" in response.json()["detail"]
    assert state["starts"] == []


def test_changed_department_access_blocks_approval(web):
    client, state = web
    token = _review(client, state, "schedule", _args(state)).json()["token"]
    state["denied"] = True
    assert _confirm(client, token).status_code == 403


def test_revoked_schedule_is_omitted_from_operational_list(web):
    client, state = web
    _save(client, state)
    state["denied"] = True
    response = client.get(BASE)
    assert response.status_code == 200
    assert response.json()["schedules"] == []


def test_token_tampering_and_missing_origin_do_not_save(web):
    client, state = web
    token = _review(client, state, "schedule", _args(state)).json()["token"]
    assert _confirm(client, token[:-12] + "aaaaaaaaaaaa").status_code == 409
    assert client.post(BASE + "/confirm", headers={"Origin": "https://elsewhere.invalid"}, json={"token": token, "confirmed": True}).status_code == 403


@pytest.mark.parametrize("field,value", [("max_runs", 0), ("max_total_dollars", -1), ("max_wall_seconds", 1801), ("interval_hours", 0)])
def test_schedule_bounds_are_validated_before_review(web, field, value):
    client, state = web
    arguments = _args(state)
    arguments[field] = value
    assert _review(client, state, "schedule", arguments).status_code == 422


def test_copilot_and_page_use_same_native_execution_and_recovery(web):
    client, state = web
    material, _ = schedules.prepare_operation(None, "schedule", _args(state))
    outcome = copilot.execute(None, {}, {}, material, "copilot-operation-0001")
    assert outcome.status == "confirmed"
    receipt = copilot.recover(None, {}, {}, material, "copilot-operation-0001")
    assert receipt.status == "replayed" and receipt.details == outcome.details
    assert len(client.get(BASE).json()["schedules"]) == 1
    assert len(copilot.entries()) == 5
    assert all(entry.execute is copilot.execute for entry in copilot.entries() if entry.execute)


def test_tick_preview_matches_approval_order_and_active_item():
    class Workflow:
        def list_items(self, schedule_id):
            return [{"id": "second", "status": "approved", "approved_at": 20, "created_at": 1},
                    {"id": "first", "status": "approved", "approved_at": 10, "created_at": 2}]

        def get_item(self, item_id):
            return {"id": item_id, "status": "running"}

    schedule = {"id": "schedule", "revision": 3, "active_item_id": None}
    material, _ = schedules._tick_material(Workflow(), schedule)
    assert material["expected_item_id"] == "first" and material["expected_revision"] == 3
    schedule["active_item_id"] = "active"
    material, _ = schedules._tick_material(Workflow(), schedule)
    assert material["expected_item_id"] == "active"
