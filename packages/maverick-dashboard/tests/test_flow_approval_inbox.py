"""A paused flow approval reaches both inboxes without widening run access."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.testclient import TestClient


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    from maverick_dashboard import auth
    from maverick_dashboard.app import app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    actor = {"principal": "user:owner"}

    async def bind(request: Request):
        request.state.principal = SimpleNamespace(principal=actor["principal"])
        return request.state.principal

    app.dependency_overrides[auth.require_principal_in_request_context] = bind
    monkeypatch.setattr(auth, "role_for_principal", lambda _principal: "operator")
    try:
        yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), actor
    finally:
        app.dependency_overrides.clear()
        config.reset_config_cache()


def _pause(*, assignee="@reviewer", expires_at=None):
    from maverick.approval_cards import build_approval_card, digest
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode

    saved = store.save_flow(Flow(
        id="inbox-flow", name="Private flow", owner="user:owner", start="gate",
        nodes={"gate": FlowNode(id="gate", kind="approval", prompt="Review continuation", assignee=assignee)},
    ))
    release = store.publish_flow(
        saved.id, expected_version=saved.version, expected_revision=saved.revision,
    )
    due = expires_at if expires_at is not None else time.time() + 3600
    continuation = {"kind": "complete", "id": "end"}
    data = {"private_input": "OWNER-PRIVATE-DATA"}
    card = build_approval_card(
        action="flow.resume", summary="Review the proposed continuation",
        target_label="Continue the private flow",
        target={"flow_id": saved.id, "pause_node": "gate", "continuation": continuation},
        parameters={"data": data, "continuation": continuation},
        parameter_summary=["Continue after the gate"],
        actor="user:owner", workspace="local", role="flow-execution-owner",
        authority_versions={
            "definition_digest": release["definition_digest"],
            "release_digest": release["release_digest"],
            "release_id": release["release_id"],
            "execution_principal_sha256": digest("user:owner"),
            "allowed_suites_sha256": digest(None),
        },
        input_versions={"run_data_sha256": digest(data), "definition_revision": release["definition_revision"]},
        credential_versions={"resolution": "worker-dispatch"},
        budget={"currency": "USD", "maximum": "configured runtime limit"},
        expires_at=due, known_effects=["The flow continues once."],
        unresolved_assumptions=[], before="The flow is paused.",
        after="The flow may continue.", irreversible=True,
    )
    store.save_run(store.FlowRun(
        run_id="review-run", flow_id=saved.id, status="paused_approval",
        owner="user:owner", cursor="gate", prompt="Review continuation",
        created=time.time(), updated=time.time(), resume_at=due,
        data=data, input_data={"private_input": "OWNER-PRIVATE-DATA"},
        human={"assignee": assignee, "choices": [], "form": [], "approval_card": card},
        definition_digest=release["definition_digest"],
        release_digest=release["release_digest"],
        release_id=release["release_id"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))


def test_named_assignee_sees_both_inboxes_and_only_approval_detail(setup, monkeypatch):
    client, actor = setup
    _pause()
    from maverick_dashboard import action_center_api

    monkeypatch.setattr(action_center_api.config, "get_features", lambda: {"action_center": True})
    monkeypatch.setattr(action_center_api.config, "config_source_errors", lambda **_k: [])
    actor["principal"] = "user:reviewer"
    approvals = client.get("/api/v1/approvals")
    assert approvals.status_code == 200, approvals.text
    assert approvals.headers["Cache-Control"] == "private, no-store"
    rows = approvals.json()["flow_approvals"]
    assert len(rows) == 1 and rows[0]["approval_card_status"] == "current"
    assert rows[0]["href"] == "/flows/inbox-flow/runs/review-run?approval_review=1"
    assert "OWNER-PRIVATE-DATA" not in approvals.text

    page = client.get("/approvals")
    assert page.status_code == 200, page.text
    assert page.headers["Cache-Control"] == "private, no-store"
    assert 'id="flow-approval-review-run"' in page.text
    assert "Review and decide" in page.text
    assert "All clear" not in page.text
    assert "OWNER-PRIVATE-DATA" not in page.text

    center = client.get("/api/v1/action-center", params={"kind": "approval"})
    assert center.status_code == 200, center.text
    flow_items = [item for item in center.json()["items"] if item.get("flow_run_id") == "review-run"]
    assert len(flow_items) == 1 and flow_items[0]["href"] == rows[0]["href"]
    assert "OWNER-PRIVATE-DATA" not in center.text

    detail = client.get("/api/v1/flows/runs/review-run")
    assert detail.status_code == 200, detail.text
    assert detail.json()["approval_review_only"] is True
    assert detail.json()["approval_binding_sha256"]
    assert "OWNER-PRIVATE-DATA" not in detail.text
    assert "input_data" not in detail.json() and "nodes" not in detail.json()
    review_page = client.get(rows[0]["href"])
    assert review_page.status_code == 200
    assert "lightwork-learning-example.js" not in review_page.text
    assert "OWNER-PRIVATE-DATA" not in review_page.text
    preview = client.post("/api/v1/flows/runs/review-run/approval-preview", json={"inputs": {}})
    assert preview.status_code == 200, preview.text
    assert preview.json()["approval_binding_sha256"] == detail.json()["approval_binding_sha256"]
    decision = client.post("/api/v1/flows/runs/review-run/resume", json={
        "decision": "approved", "approval_binding_sha256": preview.json()["approval_binding_sha256"],
    })
    assert decision.status_code == 200, decision.text
    assert decision.json()["status"] == "resuming"


def test_assignee_detail_excludes_unbound_owner_prompt(setup):
    client, actor = setup
    _pause()
    from maverick.flow import store

    run = store.load_run("review-run")
    run.prompt = "OWNER-PRIVATE-PROMPT"
    store.save_run(run)
    actor["principal"] = "user:reviewer"

    detail = client.get("/api/v1/flows/runs/review-run")
    assert detail.status_code == 200, detail.text
    assert detail.json()["approval_review_only"] is True
    assert "prompt" not in detail.json()
    assert "OWNER-PRIVATE-PROMPT" not in detail.text
    assert detail.json()["human"]["approval_card"]["summary"] == "Review the proposed continuation"


@pytest.mark.parametrize("field,value", [
    ("form", [{"name": "private", "label": "OWNER-PRIVATE-FORM"}]),
    ("choices", ["OWNER-PRIVATE-CHOICE"]),
])
def test_assignee_cannot_read_decision_fields_changed_after_release(setup, field, value):
    client, actor = setup
    _pause()
    from maverick.flow import store
    from maverick_dashboard.flow_approval_inbox import _pending_for_actor

    run = store.load_run("review-run")
    run.human[field] = value
    store.save_run(run)
    actor["principal"] = "user:reviewer"

    detail = client.get("/api/v1/flows/runs/review-run")
    assert detail.status_code == 404
    assert "OWNER-PRIVATE" not in detail.text
    assert _pending_for_actor("user:reviewer", owner="user:reviewer", request=None, limit=10)["items"] == []


def test_owner_and_unrelated_user_cannot_vote_on_assigned_pause(setup):
    client, actor = setup
    _pause()
    actor["principal"] = "user:owner"
    assert client.get("/api/v1/approvals").json()["flow_approvals"] == []
    # The owner still has ordinary owner-scoped run history, but the inbox
    # points only at the declared reviewer.
    owned = client.get("/api/v1/flows/runs/review-run")
    assert owned.status_code == 200
    wrong_vote = client.post("/api/v1/flows/runs/review-run/resume", json={
        "decision": "approved",
        "approval_binding_sha256": owned.json()["approval_binding_sha256"],
    })
    assert wrong_vote.status_code == 403
    actor["principal"] = "user:unrelated"
    assert client.get("/api/v1/approvals").json()["flow_approvals"] == []
    assert client.get("/api/v1/flows/runs/review-run").status_code == 404
    assert client.post("/api/v1/flows/runs/review-run/approval-preview", json={"inputs": {}}).status_code == 404
    assert client.post("/api/v1/flows/runs/review-run/resume", json={"decision": "approved", "approval_binding_sha256": "a" * 64}).status_code == 404


def test_expired_or_stale_card_is_not_shared_with_assignee(setup):
    client, actor = setup
    _pause(expires_at=time.time() - 1)
    actor["principal"] = "user:reviewer"
    assert client.get("/api/v1/approvals").json()["flow_approvals"] == []
    assert client.get("/api/v1/flows/runs/review-run").status_code == 404
    actor["principal"] = "user:owner"
    recovery = client.get("/api/v1/approvals").json()["flow_approvals"]
    assert len(recovery) == 1 and recovery[0]["approval_card_status"] == "unavailable"
    assert recovery[0]["approval_card"] is None


def test_unassigned_expired_card_stays_visible_to_owner_as_unavailable(setup):
    client, actor = setup
    _pause(assignee="", expires_at=time.time() - 1)
    actor["principal"] = "user:owner"
    owner_rows = client.get("/api/v1/approvals").json()["flow_approvals"]
    assert len(owner_rows) == 1 and owner_rows[0]["approval_card_status"] == "unavailable"
    assert owner_rows[0]["approval_card"] is None


def test_stale_card_cannot_be_used_as_an_assignee_read_grant(setup):
    client, actor = setup
    _pause()
    from maverick.flow import store

    run = store.load_run("review-run")
    run.human["approval_card"]["target"]["sha256"] = "f" * 64
    store.save_run(run)
    actor["principal"] = "user:reviewer"
    assert client.get("/api/v1/approvals").json()["flow_approvals"] == []
    assert client.get("/api/v1/flows/runs/review-run").status_code == 404


def test_named_assignee_gets_existing_personal_decision_alert(setup, monkeypatch, tmp_path):
    _client, actor = setup
    _pause()
    from maverick import budget_guidance
    from maverick.personal_notifications import PersonalInbox
    from maverick_dashboard import personal_notifications_api as notifications
    from maverick_dashboard import rbac

    rbac.set_role("user:reviewer", "operator")
    actor["principal"] = "user:reviewer"
    monkeypatch.setattr(budget_guidance, "warning_sources", lambda _actor: [])
    world = SimpleNamespace(
        list_projects=lambda **_kw: [],
        personal_alert_goals=lambda _actor, **_kw: [],
        pending_approvals=list,
    )
    request = Request({"type": "http", "method": "GET", "path": "/notifications", "headers": []})
    request.state.principal = SimpleNamespace(principal=actor["principal"])
    sources, _tasks, _projects, limited = notifications._projection(
        request, actor["principal"], world=world,
    )
    flow_sources = [row for row in sources if row["ref"] == "flow-approval:review-run"]
    assert len(flow_sources) == 1 and not limited
    assert flow_sources[0]["category"] == "needs-decision"
    assert "OWNER-PRIVATE-DATA" not in str(flow_sources)
    alert = PersonalInbox(actor["principal"], path=tmp_path / "personal.enc").refresh(sources, {})
    assert len(alert["items"]) == 1
    assert alert["items"][0]["href"] == flow_sources[0]["href"]

    # The background observer uses the same current-card projection after its
    # own membership and role checks, so an enrolled recipient can be alerted
    # while the page is closed when background alerts are enabled.
    observed, *_ = notifications._projection(None, actor["principal"], world=world)
    assert [row["ref"] for row in observed] == ["flow-approval:review-run"]
