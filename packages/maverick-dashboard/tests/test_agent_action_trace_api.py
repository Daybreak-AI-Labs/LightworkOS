from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick import governance, governed_actions
from maverick_dashboard import agent_action_trace_api as api

BASE = "/api/v1/security/governance/agent-actions"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick.world_model import WorldModel
    from maverick_dashboard import _shared, auth

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:alice")
    monkeypatch.setattr("maverick.personal_notification_recipients.enroll_task_owner", lambda _owner: None)
    # Source access checks require a real transactional world, not a goal-only
    # stub. Keep the same IDs and ownership used by the lineage assertions.
    world = WorldModel(tmp_path / "world.db")
    try:
        for goal_id in range(1, 10):
            owner = "user:bob" if goal_id == 9 else "user:alice"
            assert world.create_goal(f"Task {goal_id}", owner=owner) == goal_id
        monkeypatch.setattr(_shared, "_world", lambda: world)
        permissions: list[str] = []
        monkeypatch.setattr(api, "require_permission", lambda _r, p: permissions.append(p))
        monkeypatch.setattr(governed_actions, "_lineage_dir", lambda store_dir=None: tmp_path)
        app = FastAPI()
        app.include_router(api.router, prefix="/api/v1")
        with TestClient(app, base_url="http://127.0.0.1") as test_client:
            yield test_client, permissions, tmp_path
    finally:
        world.close()


def test_policy_check_reports_the_verdict_read_only(client, monkeypatch) -> None:
    test_client, permissions, _ = client
    seen = {}

    def evaluate(action, *, risk=None):
        seen.update(action=action, risk=risk)
        return governance.Verdict(
            decision=governance.Decision.REQUIRE_HUMAN, reason="A person must approve.", rule="require_human_actions"
        )

    monkeypatch.setattr(governance, "evaluate", evaluate)
    body = test_client.get(f"{BASE}/check", params={"action": "send_email", "risk": "high"}).json()
    assert body == {"action": "send_email", "risk": "high", "decision": "require_human",
                    "reason": "A person must approve.", "rule": "require_human_actions"}
    assert seen == {"action": "send_email", "risk": "high"}
    assert permissions == ["view"]
    assert test_client.get(f"{BASE}/check", params={"action": "<script>"}).status_code == 422
    assert test_client.get(f"{BASE}/check", params={"action": "x", "risk": "extreme"}).status_code == 422


def test_lineage_and_impact_come_from_the_workspace_store(client) -> None:
    test_client, permissions, _ = client
    assert governed_actions.record_tool_lineage(
        7, "send_email", {"to": "secret@example.com"}, skills=("triage",), sources=("kb:policy",), force=True
    )
    body = test_client.get(f"{BASE}/lineage/7").json()
    assert body["chain"] == "valid"
    assert body["items"][0]["action"] == "send_email"
    assert body["items"][0]["skills"] == ["triage"]
    assert "secret@example.com" not in str(body)
    assert test_client.get(f"{BASE}/lineage/8").json()["chain"] == "missing"
    hits = test_client.get(f"{BASE}/impact", params={"name": "triage", "kind": "skill"}).json()
    assert [(hit["goal_id"], hit["via"]) for hit in hits["items"]] == [(7, "skill")]
    assert "hash" not in hits["items"][0]
    assert (hits["unreadable_ledgers"], hits["complete"]) == (0, True)
    assert set(permissions) == {"view"}


def test_impact_reports_ledgers_it_could_not_read(client) -> None:
    test_client, _, store = client
    for goal_id in (7, 8):
        assert governed_actions.record_tool_lineage(goal_id, "send_email", {}, skills=("triage",), force=True)
    with (store / "8.ndjson").open("a", encoding="utf-8") as fh:
        fh.write("not json\n")
    hits = test_client.get(f"{BASE}/impact", params={"name": "triage", "kind": "skill"}).json()
    assert [hit["goal_id"] for hit in hits["items"]] == [7]
    assert (hits["unreadable_ledgers"], hits["complete"]) == (1, False)
    assert "8.ndjson" not in str(hits)


def test_a_broken_lineage_chain_is_reported(client, monkeypatch) -> None:
    from maverick_dashboard import auth
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:bob")
    test_client, _, store = client
    governed_actions.record_tool_lineage(9, "send_email", {}, force=True)
    path = store / "9.ndjson"
    path.write_text(path.read_text().replace("send_email", "delete_all"))
    assert test_client.get(f"{BASE}/lineage/9").json()["chain"] == "broken"


def test_lineage_and_impact_follow_the_task_owner_check(client, monkeypatch) -> None:
    from maverick_dashboard import auth

    test_client, _, _ = client
    for goal_id in (7, 9):
        assert governed_actions.record_tool_lineage(
            goal_id, "send_email", {"to": "x"}, sources=("hr/salaries.xlsx",), force=True
        )
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:bob")
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda principal: False)
    # Someone else's task looks exactly like a task that does not exist.
    assert test_client.get(f"{BASE}/lineage/7").status_code == 404
    assert test_client.get(f"{BASE}/lineage/404").status_code == 404
    assert test_client.get(f"{BASE}/lineage/9").json()["count"] == 1
    hits = test_client.get(f"{BASE}/impact", params={"name": "hr/salaries.xlsx"}).json()
    assert [hit["goal_id"] for hit in hits["items"]] == [9]


def test_lineage_uses_the_shared_world_without_importing_the_api_facade(client, monkeypatch) -> None:
    from maverick_dashboard import api as facade

    monkeypatch.setattr(facade, "_world", lambda: pytest.fail("the API facade was consulted"))
    test_client, _, _ = client
    response = test_client.get(f"{BASE}/lineage/7")
    assert response.status_code == 200
    assert response.json()["chain"] == "missing"
