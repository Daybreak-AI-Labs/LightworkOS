"""Ekko dashboard lifecycle, discovery, and preview-only authoring handoff."""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, time, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from maverick import config
from maverick.work_discovery_planning import BenefitAssumptions, OpportunityPlans, pilot_summary
from maverick.work_discovery_store import WorkDiscoveryStore
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(tmp_path, monkeypatch, *, enabled: bool = True):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "\n".join([
            "[ekko]",
            f"enable = {'true' if enabled else 'false'}",
            'capture_level = "application_metadata"',
            'allowed_apps = ["excel", "powerpoint"]',
            (
                'blocked_apps = ["email", "outlook", "gmail", "chat", "teams", '
                '"slack", "crm", "salesforce", "erp", "sap", "database"]'
            ),
            "retention_days = 14",
            "min_occurrences = 2",
            "min_distinct_days = 2",
            "poll_interval_seconds = 5",
            "provider_egress = false",
            "",
        ]),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    for name in ("MAVERICK_EKKO", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    from maverick.config import reset_config_cache

    reset_config_cache()
    return cfg


def _enroll(owner: str | None = None, device: str = "desk"):
    from maverick.config import get_ekko_policy
    from maverick.work_discovery_identity import local_os_principal
    from maverick.work_discovery_store import WorkDiscoveryStore

    store = WorkDiscoveryStore(owner or local_os_principal(), device)
    store.enroll(get_ekko_policy())
    return store


def _seed_recurring_evidence(store, *, guided=False) -> None:
    from maverick.work_discovery import SessionState, WorkEvent

    policy = store.get_policy()
    assert policy is not None
    first_day = datetime.now(timezone.utc).date() - timedelta(days=2)
    base = datetime.combine(first_day, time(hour=12), tzinfo=timezone.utc).timestamp()
    for day in range(2):
        session = store.create_session(
            policy=policy,
            session_id=f"repeat-{day}",
            started_at=base + day * 86_400,
        )
        collector_id = f"collector-seed-{day}"
        store.claim_collector(
            session.session_id,
            collector_id,
            policy=policy,
            ttl_seconds=30,
        )
        store.append_event(WorkEvent(
            event_id=f"event-{day}-1",
            session_id=session.session_id,
            sequence=1,
            occurred_at=base + day * 86_400 + 10,
            app="excel",
            action="download" if guided else "switch",
            object_type="report" if guided else "none",
            duration_seconds=120,
        ), policy=policy, collector_id=collector_id)
        store.append_event(WorkEvent(
            event_id=f"event-{day}-2",
            session_id=session.session_id,
            sequence=2,
            occurred_at=base + day * 86_400 + 140,
            app="powerpoint",
            action="create" if guided else "switch",
            object_type="presentation" if guided else "none",
            duration_seconds=480,
        ), policy=policy, collector_id=collector_id)
        store.transition_session(
            session.session_id,
            SessionState.STOPPED,
            at=base + day * 86_400 + 700,
        )


def test_ekko_page_and_agent_factory_entry_explain_the_safe_boundary(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch, enabled=False)

    page = client.get("/ekko")
    assert page.status_code == 200
    for phrase in (
        "EKKO",
        "Work Discovery",
        "Ekko is off by default",
        "Never captures",
        "never an employee performance score",
        "lightwork.authoring-handoff",
        'id="ekko-enroll-go"',
        'id="ekko-enroll-days"',
        '<select class="select" id="ekko-device"',
    ):
        assert phrase in page.text
    assert "collector online" not in page.text.lower()
    assert "recorder lost contact" in page.text.lower()
    from test_support.plain_language import developer_terms
    assert developer_terms(page.text) == []
    from test_support.plain_language import visible_text
    content = visible_text(page.text[page.text.index("<main"):])
    for gone in ("maverick ekko", "tenant", "egress", "DGM", "collector", "Device ID"):
        assert gone not in content
    assert "Request failed (" not in page.text

    factory = client.get("/agents")
    assert factory.status_code == 200
    assert 'id="ekko-work-discovery-card"' in factory.text
    assert 'href="/ekko"' in factory.text


@pytest.mark.parametrize("enabled", [False, True])
def test_ekko_initial_render_runs_after_shared_ui_helpers(tmp_path, monkeypatch, enabled):
    """The immediate status render needs mvEl before its client script executes."""
    _isolate(tmp_path, monkeypatch, enabled=enabled)
    page = client.get("/ekko")
    assert page.status_code == 200
    shared_helpers = page.text.index('<script src="/static/lightwork-ui.js')
    client_start = page.text.index("var initial = JSON.parse(document.getElementById('ekko-initial')")
    initial_render = page.text.index("renderStatus(initial);", client_start)
    assert shared_helpers < client_start < initial_render


def test_status_is_default_off_and_payload_cannot_inject_owner_or_tenant(
    tmp_path, monkeypatch,
):
    _isolate(tmp_path, monkeypatch, enabled=False)
    status = client.get("/api/v1/ekko/status?device_id=desk")
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    assert status.json()["enrollment"] is None

    injected = client.post(
        "/api/v1/ekko/sessions",
        json={
            "device_id": "desk",
            "acknowledge_capture_scope": True,
            "owner": "user:mallory",
            "tenant": "other-client",
        },
    )
    assert injected.status_code == 422


def test_owner_bound_session_start_pause_resume_stop(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enroll(device="desk")

    missing_ack = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": False},
    )
    assert missing_ack.status_code == 400

    started = client.post(
        "/api/v1/ekko/sessions",
        json={"device_id": "desk", "acknowledge_capture_scope": True},
    )
    assert started.status_code == 201
    session_id = started.json()["session"]["session_id"]
    assert started.json()["session"]["state"] == "running"
    assert started.json()["unsaved"] is True

    for action, expected in (
        ("pause", "paused"),
        ("resume", "running"),
        ("stop", "stopped"),
    ):
        response = client.post(
            f"/api/v1/ekko/sessions/{session_id}/{action}",
            json={"device_id": "desk"},
        )
        assert response.status_code == 200
        assert response.json()["session"]["state"] == expected

    # A different device selector remains inside the same owner but cannot see
    # or mutate the enrolled device's session.
    hidden = client.get("/api/v1/ekko/status?device_id=other-device").json()
    assert hidden["session"] is None and hidden["event_count"] == 0
    denied = client.post(
        f"/api/v1/ekko/sessions/{session_id}/pause",
        json={"device_id": "other-device"},
    )
    assert denied.status_code == 404


def test_mining_and_handoff_are_evidence_backed_preview_only(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    _isolate(tmp_path, monkeypatch)
    store = _enroll(device="desk")
    _seed_recurring_evidence(store)

    mined = client.post(
        "/api/v1/ekko/candidates/mine",
        json={"device_id": "desk"},
    )
    assert mined.status_code == 200
    assert mined.json()["count"] >= 1
    candidate = mined.json()["candidates"][0]
    assert candidate["occurrences"] >= 2
    assert candidate["distinct_days"] == 2
    assert candidate["evidence"]

    handoff = client.post(
        f"/api/v1/ekko/candidates/{candidate['opportunity_id']}/handoff",
        json=_review_payload(candidate),
    )
    assert handoff.status_code == 200
    body = handoff.json()
    assert body["unsaved"] is True
    assert body["requires_human_approval"] is True
    assert body["redirect"] == "/flows/designer"
    assert body["context"] == client.get("/api/v1/templates/draft-context").json()["context"]
    assert body["flow"]["start"] == "human-review"
    assert body["flow"]["version"] == 0
    assert body["flow"]["revision"] == ""
    nodes = {node["id"]: node for node in body["flow"]["nodes"]}
    assert nodes["human-review"]["kind"] == "approval"
    assert nodes["human-review"]["next"] == "prepare-inputs"
    assert nodes["check-result"]["next"] == "review-result"
    assert nodes["review-result"]["kind"] == "approval"
    assert nodes["review-result"].get("next") is None
    assert "approved, content-free application metadata" in body["brief"]
    assert "do not" in body["brief"].lower()

    saved = client.post("/api/v1/flows", json={"flow": body["flow"]})
    assert saved.status_code == 201, saved.text
    assert saved.json()["published"] is False
    again = client.post(
        f"/api/v1/ekko/candidates/{candidate['opportunity_id']}/handoff",
        json=_review_payload(candidate),
    )
    assert again.status_code == 200
    assert again.json()["flow"]["id"] != body["flow"]["id"]

    erased = client.delete("/api/v1/ekko/data?device_id=desk")
    assert erased.status_code == 200
    assert erased.json()["erased"]["sessions"] == 2
    assert erased.json()["erased"]["events"] == 4
    assert client.get(
        "/api/v1/ekko/candidates?device_id=desk"
    ).json()["candidates"] == []


def test_workflow_handoff_refuses_off_engine_before_unusable_editor(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "0")
    _isolate(tmp_path, monkeypatch)
    store = _enroll(device="desk")
    _seed_recurring_evidence(store)
    status = client.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["workflows_enabled"] is False
    assert status["workflows_control_managed"] is True
    opportunity_id = client.get("/api/v1/ekko/candidates?device_id=desk").json()["candidates"][0]["opportunity_id"]

    refused = client.post(
        f"/api/v1/ekko/candidates/{opportunity_id}/handoff",
        json={"device_id": "desk", "kind": "flow"},
    )
    assert refused.status_code == 409
    assert "installation" in refused.json()["detail"]
    assert "/learning#lrn-flows-on" not in client.get("/ekko?device_id=desk").text
    assert client.post(
        f"/api/v1/ekko/candidates/{opportunity_id}/handoff",
        json=_review_payload(client.get("/api/v1/ekko/candidates?device_id=desk").json()["candidates"][0], kind="agent"),
    ).status_code == 200

    monkeypatch.delenv("MAVERICK_FLOWS")
    status = client.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["workflows_enabled"] is False
    assert status["workflows_control_managed"] is False
    assert "/learning#lrn-flows-on" in client.get("/ekko?device_id=desk").text
    refused = client.post(
        f"/api/v1/ekko/candidates/{opportunity_id}/handoff",
        json={"device_id": "desk", "kind": "flow"},
    )
    assert refused.status_code == 409
    assert "Learning" in refused.json()["detail"]


def test_forget_device_revokes_enrollment_and_erases_data(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = _enroll(device="desk")
    session = store.create_session(policy=store.get_policy())

    forgotten = client.delete("/api/v1/ekko/device?device_id=desk")

    assert forgotten.status_code == 200
    assert forgotten.json()["forgotten"]["enrollments"] == 1
    status = client.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["enrollment"] is None
    assert status["session"] is None
    assert store.get_session(session.session_id) is None


def test_ekko_inline_script_runs_after_shared_ui_helpers_load(tmp_path, monkeypatch):
    # Regression: the page script calls renderStatus(initial) at parse time and
    # uses mvEl/mvToast/mvConfirm from /static/lightwork-ui.js, which base.html
    # loads after the content block. Emitting the script inside the content block
    # threw ``ReferenceError: mvEl is not defined`` on every page load.
    _isolate(tmp_path, monkeypatch, enabled=False)

    page = client.get("/ekko")
    assert page.status_code == 200
    html = page.text

    ui_tag = '<script src="/static/lightwork-ui.js'
    # The bootstrap must be a <script> element, not any element with these attributes.
    bootstrap = re.search(r'<script\b[^>]*\bid="ekko-initial"[^>]*type="application/json">', html)
    assert ui_tag in html
    assert bootstrap is not None

    first_mv_el = html.index("mvEl(")
    inline_script_open = html.rfind('<script nonce="', 0, first_mv_el)
    assert inline_script_open != -1
    assert inline_script_open > html.index(ui_tag)
    # The JSON bootstrap must still precede the code that reads it.
    assert bootstrap.start() < inline_script_open


def test_enroll_from_the_page_narrows_apps_and_is_audited(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    status = client.get("/api/v1/ekko/status?device_id=desk").json()
    assert status["app_choices"] == [
        {"value": "excel", "label": "Microsoft Excel"},
        {"value": "powerpoint", "label": "Microsoft PowerPoint"},
    ]
    assert status["enrollment_days"] == 30

    base = {"device_id": "desk", "apps": ["excel"], "days": 14}
    assert client.post("/api/v1/ekko/enroll", json=base).status_code == 400  # no consent tick
    outside = client.post("/api/v1/ekko/enroll", json={**base, "apps": ["slack"], "acknowledge_capture_scope": True})
    assert outside.status_code == 422
    assert "apps your administrator allows" in outside.json()["detail"]
    assert client.post("/api/v1/ekko/enroll", json={**base, "days": 365, "acknowledge_capture_scope": True}).status_code == 422
    injected = client.post("/api/v1/ekko/enroll", json={**base, "acknowledge_capture_scope": True, "owner": "user:mallory"})
    assert injected.status_code == 422

    kinds: list[tuple[str, dict]] = []
    from maverick_dashboard import ekko_routes

    real = ekko_routes._audit

    def spy(kind, **payload):
        kinds.append((str(kind), payload))
        return real(kind, **payload)

    monkeypatch.setattr(ekko_routes, "_audit", spy)
    enrolled = client.post("/api/v1/ekko/enroll", json={**base, "acknowledge_capture_scope": True})
    assert enrolled.status_code == 200, enrolled.text
    body = enrolled.json()
    assert body["status"]["enrollment"]["active"] is True
    assert body["status"]["allowed_apps"] == ["excel"]  # narrowed, never widened
    assert [p.get("state") for _, p in kinds] == ["enroll_authorized", "enrolled"]
    assert kinds[0][1]["required"] is True
    # enrolling only records consent; nothing is watched yet
    assert body["status"]["session"] is None

    started = client.post("/api/v1/ekko/sessions", json={"device_id": "desk", "acknowledge_capture_scope": True})
    assert started.status_code == 201
    revoked = client.post("/api/v1/ekko/revoke", json={"device_id": "desk"})
    assert revoked.status_code == 200 and revoked.json()["revoked"] is True
    after = revoked.json()["status"]
    assert not (after["enrollment"] or {}).get("active")
    assert after["session"]["state"] == "stopped"


def test_enroll_needs_ekko_on_and_operate(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch, enabled=False)
    off = client.post("/api/v1/ekko/enroll", json={"device_id": "desk", "apps": ["excel"],
                                                   "acknowledge_capture_scope": True})
    assert off.status_code == 409
    assert "turned off" in off.json()["detail"]
    from maverick_dashboard import auth

    def deny(request, permission):
        from fastapi import HTTPException
        assert permission == "operate"
        raise HTTPException(status_code=403, detail="no")

    monkeypatch.setattr(auth, "require_permission", deny)
    assert client.post("/api/v1/ekko/enroll", json={"device_id": "desk", "apps": ["excel"],
                                                    "acknowledge_capture_scope": True}).status_code == 403
    assert client.post("/api/v1/ekko/revoke", json={"device_id": "desk"}).status_code == 403


def _review_payload(candidate, kind="flow"):
    return {"device_id": "desk", "kind": kind, "evidence_revision": candidate["evidence_revision"], "review": {
        "goal": "Prepare a weekly summary", "inputs": "The export selected for this run",
        "output": "A presentation with totals and exceptions", "approval": "I verify figures before sharing",
    }}


def test_handoff_requires_task_context_and_current_evidence(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = _enroll(device="desk")
    _seed_recurring_evidence(store)
    state = client.get("/api/v1/ekko/candidates?device_id=desk").json()
    assert state["progress"]["activities"] == 4
    assert state["progress"]["observed_days"] == 2
    candidate = state["candidates"][0]
    assert candidate["estimated_minutes_per_run"] is None
    path = f"/api/v1/ekko/candidates/{candidate['opportunity_id']}/handoff"
    missing = client.post(path, json={"device_id": "desk", "kind": "agent"})
    assert missing.status_code == 422
    payload = _review_payload(candidate, kind="agent")
    payload["evidence_revision"] = "0" * 64
    stale = client.post(path, json=payload)
    assert stale.status_code == 409
    assert "evidence changed" in stale.json()["detail"]
    payload = _review_payload(candidate, kind="agent")
    payload["review"]["goal"] = "   "
    assert client.post(path, json=payload).status_code == 422
    payload = _review_payload(candidate, kind="agent")
    payload["review"]["owner"] = "someone-else"
    assert client.post(path, json=payload).status_code == 422
    client.delete("/api/v1/ekko/data?device_id=desk")
    assert client.post(path, json=_review_payload(candidate, kind="agent")).status_code == 404


def test_discovery_progress_for_an_empty_device_is_actionable(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    body = client.get("/api/v1/ekko/candidates?device_id=desk").json()
    assert body["candidates"] == []
    assert body["progress"]["activities"] == 0
    assert "Enroll this device" in body["progress"]["next_step"]


def test_copilot_discovery_review_keeps_recorded_activity_on_the_page(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    from maverick_dashboard import product_operations_ekko_recording as operations

    monkeypatch.setattr(operations.native, "recording_options", lambda request: {
        "context": "a" * 64, "active_app": False,
        "availability_message": "Not available here", "platform": "test",
    })
    adapter = next(item for item in operations.entries() if item.id == "learning.ekko_discovery_review")
    state = adapter.snapshot(None, {})
    assert state.details == {}
    assert "not sent to Copilot" in state.summary
    preview = adapter.prepare(None, {}, {})
    assert preview.native == {"ekko_discovery_review": {"scope": "current_page", "context": "a" * 64}}
    with pytest.raises(Exception) as error:
        adapter.snapshot(None, {"device_id": "someone-else"})
    assert error.value.status_code == 422


@pytest.fixture
def planning(tmp_path, monkeypatch):
    cfg = _isolate(tmp_path, monkeypatch)
    cfg.write_text(cfg.read_text() + "planning_enabled = true\n")
    config.reset_config_cache()
    store = _enroll(device="desk")
    _seed_recurring_evidence(store)
    candidate = client.get("/api/v1/ekko/candidates?device_id=desk").json()["candidates"][0]
    payload = _review_payload(candidate)
    payload.pop("kind")
    payload["context"] = client.get("/api/v1/ekko/plans?device_id=desk").json()["context"]
    payload.update(stage="shortlisted", expected_revision="", acknowledge_private_storage=True, assumptions={
        "runs_per_week": 10, "manual_minutes": 30, "remaining_minutes": 6, "setup_hours": 3,
    })
    return store, candidate, payload, cfg


def save(candidate, payload):
    return client.put(f"/api/v1/ekko/candidates/{candidate['opportunity_id']}/plan", json=payload)


def test_save_reload_and_revision_conflict_preserve_private_plan(planning):
    store, candidate, payload, _ = planning
    response = save(candidate, payload)
    assert response.status_code == 200, response.text
    plan = response.json()["plan"]
    assert response.json()["started_work"] is False
    assert plan["benefit"]["weekly_hours"] == 4
    assert plan["benefit"]["four_week_hours_after_setup"] == 13
    assert plan["benefit"]["break_even_weeks"] == 0.75
    assert payload["review"]["goal"].encode() not in store.path.read_bytes()
    assert client.get("/api/v1/ekko/plans?device_id=desk").json()["plans"] == [plan]
    payload["review"]["goal"] = "An older tab must not overwrite this"
    assert save(candidate, payload).status_code == 409
    payload["expected_revision"] = plan["revision"]
    assert save(candidate, payload).status_code == 200


def test_pilot_retry_is_idempotent_and_failed_outputs_count_rework(planning):
    _, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    path = f"/api/v1/ekko/plans/{candidate['opportunity_id']}/runs"
    sample = {"device_id": "desk", "context": payload["context"], "expected_revision": plan["revision"],
              "sample_id": "pilot-run-one", "manual_minutes": 30, "remaining_minutes": 6, "accepted": True}
    first = client.post(path, json=sample)
    assert first.status_code == 200, first.text
    assert client.post(path, json=sample).json() == first.json()
    assert first.json()["plan"]["pilot"]["total_minutes_saved"] == 24
    sample.update(sample_id="pilot-run-two", expected_revision=first.json()["plan"]["revision"],
                  remaining_minutes=10, accepted=False)
    second = client.post(path, json=sample).json()["plan"]
    assert second["pilot"] == {"basis": "owner_reported_pilot", "runs": 2,
                               "accepted": 1, "median_minutes_saved": 7, "total_minutes_saved": 14}
    sample["remaining_minutes"] = 2
    assert client.post(path, json=sample).status_code == 409


def test_plans_cannot_cross_owner_device_or_tenant_even_in_shared_database(planning):
    store, candidate, payload, _ = planning
    save(candidate, payload)
    for owner, device, tenant in (("another-person", store.device_id, store.tenant),
                                  (store.owner, "another-device", store.tenant),
                                  (store.owner, store.device_id, "another-workspace")):
        foreign = OpportunityPlans(WorkDiscoveryStore(owner, device, tenant=tenant, path=store.path))
        assert foreign.list() == []
        assert foreign.delete(candidate["opportunity_id"], expected_revision="x" * 32) is False
    assert client.get("/api/v1/ekko/plans?device_id=another-device").json()["plans"] == []


def test_scope_encryption_rejects_ciphertext_transplant(planning):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    foreign = WorkDiscoveryStore("another-person", store.device_id, tenant=store.tenant, path=store.path)
    with store._transaction() as conn:
        blob = conn.execute("SELECT payload FROM ekko_plans").fetchone()[0]
        conn.execute("INSERT INTO ekko_plans VALUES (?,?,?,?,?,?,?)",
                     (*foreign._scope, candidate["opportunity_id"], plan["revision"], blob, plan["expires_at"]))
    with pytest.raises(Exception, match="scope"):
        OpportunityPlans(foreign).list()


def test_expired_plans_and_explicit_source_erasure_remove_notes(planning):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    future = WorkDiscoveryStore(store.owner, store.device_id, tenant=store.tenant,
                                path=store.path, clock=lambda: plan["expires_at"] + 1)
    assert OpportunityPlans(future).list() == []
    with sqlite3.connect(store.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ekko_plans").fetchone()[0] == 0


def test_session_erasure_clears_linked_plans(planning):
    store, candidate, payload, _ = planning
    save(candidate, payload)
    store.erase(session_id="repeat-0")
    assert OpportunityPlans(store).list() == []


def test_disabled_planning_keeps_read_and_delete_available(planning):
    _, candidate, payload, cfg = planning
    plan = save(candidate, payload).json()["plan"]
    cfg.write_text(cfg.read_text().replace("planning_enabled = true", "planning_enabled = false"))
    config.reset_config_cache()
    assert save(candidate, payload).status_code == 409
    current = client.get("/api/v1/ekko/plans?device_id=desk").json()
    assert current["plans"]
    deleted = client.request("DELETE", f"/api/v1/ekko/plans/{candidate['opportunity_id']}",
                             json={"device_id": "desk", "context": current["context"], "expected_revision": plan["revision"]})
    assert deleted.status_code == 200 and deleted.json()["removed"]


def test_benefit_math_preserves_unknown_and_negative_outcomes():
    assert BenefitAssumptions().estimate()["weekly_hours"] is None
    assert BenefitAssumptions(10, 30).estimate()["weekly_hours"] is None
    assert BenefitAssumptions(10, 30, 0, 0).estimate()["weekly_hours"] == 5
    assert BenefitAssumptions(10, 5, 8, 2).estimate()["weekly_hours"] == -0.5
    assert BenefitAssumptions(10, 5, 8, 2).estimate()["break_even_weeks"] is None
    assert pilot_summary([])["median_minutes_saved"] is None
    with pytest.raises(ValueError):
        BenefitAssumptions(manual_minutes=float("nan"))


def test_private_save_requires_acknowledgement_and_current_authority(planning, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import auth

    store, candidate, payload, _ = planning
    assert save(candidate, {**payload, "acknowledge_private_storage": False}).status_code == 422
    assert OpportunityPlans(store).list() == []
    plan = save(candidate, payload).json()["plan"]

    def deny(request, permission):
        raise HTTPException(403, "Access removed")

    monkeypatch.setattr(auth, "require_permission", deny)
    assert client.get("/api/v1/ekko/plans?device_id=desk").status_code == 403
    assert save(candidate, {**payload, "expected_revision": plan["revision"]}).status_code == 403
    assert OpportunityPlans(store).list() == [plan]


def test_concurrent_plan_edits_cannot_overwrite_each_other(planning):
    from concurrent.futures import ThreadPoolExecutor

    _, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    edits = [{**payload, "expected_revision": plan["revision"], "stage": stage} for stage in ("pilot", "parked")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda edit: save(candidate, edit), edits))
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner = next(response.json()["plan"] for response in responses if response.status_code == 200)
    assert client.get("/api/v1/ekko/plans?device_id=desk").json()["plans"] == [winner]


def test_pilot_is_bounded_and_never_extends_retention(planning):
    _, candidate, payload, _ = planning
    payload["review"]["goal"] = "Private task ✨" * 60
    plan = save(candidate, payload).json()["plan"]
    expires_at = plan["expires_at"]
    path = f"/api/v1/ekko/plans/{candidate['opportunity_id']}/runs"
    for number in range(30):
        sample = {"device_id": "desk", "context": payload["context"], "expected_revision": plan["revision"], "sample_id": f"pilot-run-{number}",
                  "manual_minutes": 30, "remaining_minutes": 6, "accepted": True}
        result = client.post(path, json=sample)
        assert result.status_code == 200, result.text
        plan = result.json()["plan"]
        assert plan["expires_at"] == expires_at
    sample.update(sample_id="pilot-run-limit", expected_revision=plan["revision"])
    assert client.post(path, json=sample).status_code == 422
    assert client.delete("/api/v1/ekko/data?device_id=desk").status_code == 200
    assert client.get("/api/v1/ekko/plans?device_id=desk").json()["plans"] == []


def test_plan_audit_has_no_task_notes_and_failed_audit_rolls_back_save(planning, monkeypatch):
    store, candidate, payload, _ = planning
    plan = save(candidate, payload).json()["plan"]
    seen = []
    store.flush_audit_outbox(recorder=lambda kind, **data: seen.append((kind, data)) or True)
    entries = [data for kind, data in seen if kind == "ekko_opportunity_plan"]
    assert len(entries) == 1
    assert entries[0]["lifecycle"]["basis"] == "owner_supplied"
    assert all(value not in str(entries) for value in payload["review"].values())
    monkeypatch.setattr("maverick.work_discovery_store.MAX_AUDIT_OUTBOX", 0)
    payload.update(expected_revision=plan["revision"], stage="pilot")
    assert save(candidate, payload).status_code == 503
    assert OpportunityPlans(store).list() == [plan]
    # Privacy deletion remains available even if audit delivery is blocked.
    assert OpportunityPlans(store).delete(candidate["opportunity_id"], expected_revision=plan["revision"])


def test_plan_save_respects_the_existing_database_size_limit(planning, monkeypatch):
    store, candidate, payload, _ = planning
    monkeypatch.setattr("maverick.work_discovery_store.MAX_DATABASE_BYTES", 1)
    assert save(candidate, payload).status_code == 503
    assert OpportunityPlans(store).list() == []


def test_plan_mutations_reject_stale_workspace_context(planning):
    store, candidate, payload, _ = planning
    stale = save(candidate, {**payload, "context": "0" * 64})
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "ekko_context_changed"
    assert OpportunityPlans(store).list() == []
    plan = save(candidate, payload).json()["plan"]
    path = f"/api/v1/ekko/plans/{candidate['opportunity_id']}"
    stale_revision = {"device_id": "desk", "expected_revision": plan["revision"], "context": "0" * 64}
    assert client.request("DELETE", path, json=stale_revision).status_code == 409
    assert client.post(path + "/runs", json={**stale_revision, "sample_id": "stale-run-one", "manual_minutes": 30,
                                            "remaining_minutes": 6, "accepted": True}).status_code == 409
    assert OpportunityPlans(store).list() == [plan]


@pytest.fixture
def factory(planning):
    _, _, payload, cfg = planning
    cfg.write_text(cfg.read_text() + "build_enabled = true\n[flows]\nenable = true\n")
    config.reset_config_cache()
    payload["context"] = client.get("/api/v1/ekko/plans?device_id=desk").json()["context"]
    return planning


def scan_build(brief="", device="desk"):
    context = client.get("/api/v1/ekko/build/options").json()["context"]
    body = {"context": context, "device_id": device, "brief": brief}
    response = client.post("/api/v1/ekko/build/scan", json=body)
    assert response.status_code == 200, response.text
    return response.json(), body


def build_scan(found, body):
    return client.post("/api/v1/ekko/build/drafts", json={**body, "scan_revision": found["scan_revision"], "acknowledge_draft_storage": True})


def test_factory_builds_real_native_drafts_and_preserves_edited_originals(factory):
    from maverick.flow import store

    _, candidate, payload, _ = factory
    assert save(candidate, payload).status_code == 200
    found, body = scan_build("Review supplier contracts\nReconcile invoice totals")
    assert found["ready"] == 3
    assert all("review" not in row and "proof" not in row for row in found["proposals"])
    result = build_scan(found, body)
    assert result.status_code == 200, result.text
    assert result.json()["built"] == 3 and result.json()["started_work"] is False
    flows = store.list_flows()
    assert len(flows) == 3
    assert all(store.load_published_bundle(flow.id) is None and flow.schedule == "" for flow in flows)
    original = flows[0]
    original.name = "My edited workflow"
    store.save_flow(original, expected_version=original.version, expected_revision=original.revision)
    again = build_scan(found, body)
    assert again.status_code == 200 and again.json()["built"] == 0 and again.json()["existing"] == 3
    assert store.load_flow(original.id).name == "My edited workflow"


def test_factory_respects_opt_in_acknowledgement_stale_context_and_sources(factory):
    store, candidate, payload, cfg = factory
    assert save(candidate, payload).status_code == 200
    found, body = scan_build()
    base = {**body, "scan_revision": found["scan_revision"]}
    assert client.post("/api/v1/ekko/build/drafts", json=base).status_code == 422
    assert build_scan(found, {**body, "context": "0" * 64}).status_code == 409
    store.erase(session_id="repeat-0")
    assert build_scan(found, body).status_code == 409
    cfg.write_text(cfg.read_text().replace("build_enabled = true", "build_enabled = false"))
    config.reset_config_cache()
    fresh, body = scan_build("Review supplier contracts")
    assert fresh["enabled"] is False
    assert build_scan(fresh, body).status_code == 409


def test_factory_does_not_guess_a_task_from_app_switches_and_respects_parked_plans(factory):
    _, candidate, payload, _ = factory
    found, _ = scan_build()
    assert found["ready"] == 0 and len(found["missing"]) == 1
    payload["stage"] = "parked"
    assert save(candidate, payload).status_code == 200
    found, _ = scan_build()
    assert found["ready"] == 0 and found["missing"] == []


def test_factory_reuses_an_existing_owned_workflow_with_the_same_business_title(factory):
    from maverick.flow import store
    from maverick.work_discovery_factory import build_task_flow, review_for_task

    flow = build_task_flow(review_for_task("Review supplier contracts"), identifier="existing-contract-review")
    store.save_flow(flow, expected_version=0, expected_revision="")
    found, body = scan_build("Review supplier contracts")
    assert found["ready"] == 0 and found["existing"] == 1
    assert found["proposals"][0]["href"].endswith("existing-contract-review")
    assert build_scan(found, body).json()["built"] == 0


def test_factory_can_recover_a_partial_batch_without_duplicating_saved_work(factory, monkeypatch):
    from fastapi import HTTPException
    from maverick.flow import store
    from maverick_dashboard import flows_api

    original = flows_api._save_flow_definition
    calls = []

    def fail_second(request, payload, **kwargs):
        calls.append(payload.flow["id"])
        if len(calls) == 2:
            raise HTTPException(503, "Storage temporarily unavailable")
        return original(request, payload, **kwargs)

    found, body = scan_build("Review supplier contracts\nReconcile invoice totals")
    monkeypatch.setattr(flows_api, "_save_flow_definition", fail_second)
    first = build_scan(found, body)
    assert first.status_code == 200, first.text
    assert first.json()["built"] == 1 and first.json()["blocked"] == 1
    monkeypatch.setattr(flows_api, "_save_flow_definition", original)
    second = build_scan(found, body)
    assert second.json()["built"] == 1 and second.json()["existing"] == 1
    assert len(store.list_flows()) == 2


def test_factory_continues_beyond_one_batch_without_rebuilding_completed_tasks(factory):
    from maverick.flow import store

    _, candidate, payload, _ = factory
    assert save(candidate, payload).status_code == 200
    brief = "\n".join(f"Review supplier contract number {index}" for index in range(20))
    found, body = scan_build(brief)
    assert found["ready"] == 21
    first = build_scan(found, body)
    assert first.status_code == 200, first.text
    assert first.json()["built"] == 20 and first.json()["remaining"] == 1
    refreshed, fresh_body = scan_build(brief)
    assert refreshed["ready"] == 1 and refreshed["existing"] == 20
    final = build_scan(refreshed, fresh_body)
    assert final.status_code == 200, final.text
    assert final.json()["built"] == 1 and final.json()["remaining"] == 0
    assert len(store.list_flows()) == 21


def test_copilot_build_receipt_cannot_recreate_a_subsequently_deleted_workflow(factory):
    from maverick.flow import store

    *_, cfg = factory
    cfg.write_text(cfg.read_text() + '\n[features]\ncopilot_operations=true\n[copilot]\noperation_families=["learning"]\n')
    config.reset_config_cache()
    base, scope = "/api/v1/copilot/product-operations", {"page": "/ekko", "selection": {}}
    catalog = client.post(base + "/catalog", json=scope).json()
    operation = next(row for row in catalog["operations"] if row["id"] == "learning.ekko_find_build")
    prepared = client.post(base + "/prepare", json={**scope, "operation": operation["id"],
        "context": catalog["context"], "revision": operation["revision"],
        "arguments": {"device_id": "desk", "brief": "Review supplier contracts"}})
    assert prepared.status_code == 200, prepared.text
    body = {"token": prepared.json()["token"], "confirmed": True}
    applied = client.post(base + "/execute", json=body)
    assert applied.status_code == 200, applied.text
    assert applied.json()["status"] == "confirmed"
    flow, = store.list_flows()
    assert store.delete_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision, expected_release_id="")
    repeated = client.post(base + "/execute", json=body)
    assert repeated.status_code == 200 and repeated.json()["status"] == "replayed"
    assert store.list_flows() == []


def test_factory_builds_guided_task_steps_without_an_extra_context_form(factory):
    from maverick.flow import store

    *_, cfg = factory
    cfg.write_text(cfg.read_text().replace('capture_level = "application_metadata"', 'capture_level = "guided"'))
    config.reset_config_cache()
    recorded = _enroll(device="guided-desk")
    _seed_recurring_evidence(recorded, guided=True)
    found, body = scan_build(device="guided-desk")
    assert found["ready"] == 1 and found["missing"] == []
    assert found["proposals"][0]["source"] == "Guided recorded task steps"
    result = build_scan(found, body)
    assert result.status_code == 200 and result.json()["built"] == 1
    flow, = store.list_flows()
    assert "1. download report in excel; 2. create presentation in powerpoint" in flow.nodes["produce"].brief
    recorded.erase()
    assert build_scan(found, body).status_code == 409
