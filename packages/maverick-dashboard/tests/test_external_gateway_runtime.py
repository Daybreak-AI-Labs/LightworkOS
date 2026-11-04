"""The external runtime gateway's evaluate and execute flows against the real
dashboard app: runtime allow/deny, immediate reads, previews without effect,
denied changes without effect, exactly-once parking, human approval, commit,
commit replay without a second effect, compensation, an outage after the
effect, and the runtime policy and context binding at commit."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick import ai_runtime_guardrails as runtime
from maverick import external_agents
from maverick import model_risk_assurance as assurance
from maverick_dashboard.app import app

ASSET_ID = "MAA-" + ("4" * 32)
ASSET_DIGEST = "5" * 64
ALLOW_PROBE = "pilot-allow-private-canary"
DENY_PROBE = "pilot-deny-private-canary"


class _PilotConnector:
    def __init__(self, *, fail_after_change: bool = False):
        self.state = "baseline"
        self.writes = []
        self.fail_after_change = fail_after_change

    def read(self, params):
        assert params == {"path": "/state"}
        return json.dumps({"state": self.state}, sort_keys=True)

    def preview_write(self, params):
        return f"would {params['op'].upper()} pilot{params['path']}"

    def write(self, params):
        self.writes.append(dict(params))
        self.state = str(params["body"]["state"])
        if self.fail_after_change and self.state == "changed":
            raise TimeoutError("simulated response loss after effect")
        return "pilot state updated"


class _RuntimeService:
    @staticmethod
    def evaluate(request):
        decision = "block" if DENY_PROBE in request.content else "allow"
        return runtime.RuntimeGuardrailResult(
            decision=decision,
            redacted_content=None,
            receipt={
                "stage": str(request.stage),
                "decision": decision,
                "categories": ["policy"] if decision == "block" else [],
                "rule_ids": ["pilot/block"] if decision == "block" else [],
                "control_ids": [],
                "input_sha256": "6" * 64,
                "output_sha256": "7" * 64,
                "policy_sha256": "8" * 64,
                "evaluated_at": 1_800_000_000.0,
                "asset_binding": {
                    # Bound to the current workspace, as a native receipt is.
                    "tenant_ref": runtime._tenant_ref(),
                    "asset_id": ASSET_ID,
                    "asset_revision": 1,
                    "asset_version_digest": ASSET_DIGEST,
                },
            },
        )


class _BlockActionRuntimeService:
    @staticmethod
    def evaluate(request):
        result = _RuntimeService.evaluate(request)
        if str(request.stage) != "action":
            return result
        return runtime.RuntimeGuardrailResult(
            decision="block",
            redacted_content=None,
            receipt={
                **result.receipt,
                "decision": "block",
                "categories": ["policy"],
                "rule_ids": ["pilot/current-policy-block"],
            },
        )


def _stub_review_is_current(monkeypatch, assurance):
    """These stubbed records stand for a current reviewed declaration only
    while it is approved for the observed version. The full review binding
    (record digests, profile and hierarchy) is model_risk_assurance's own
    check, which hand-written stub records cannot satisfy."""
    monkeypatch.setattr(assurance._DEFAULT, "_declaration_is_current", lambda declaration, observation: (
        declaration.get("status") == "approved"
        and declaration.get("observed_version_digest") == observation.get("version_digest")))


@pytest.fixture
def pilot_estate(tmp_path, monkeypatch):
    from maverick import agent_trust, config, governed_rest, world_model
    from maverick_dashboard import external_gateway

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    # Safeguard activity is retained per workspace; unbound mode refuses it.
    monkeypatch.setenv("MAVERICK_TENANT", "pilot-workspace")
    monkeypatch.setenv("MAVERICK_EXTERNAL_CONNECTORS", "pilot")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(agent_trust, "managed_path", lambda: tmp_path / "agent_trust.json")
    monkeypatch.setattr(external_agents, "registry_path", lambda: tmp_path / "external_agents.json")
    monkeypatch.setattr(external_gateway, "_rate_times", {})
    (tmp_path / "config.toml").write_text(
        "[ai_runtime_guardrails]\nenable = true\n"
        "[ai_policy_management]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    connector = _PilotConnector()
    monkeypatch.setitem(governed_rest.GOVERNED_REST_FACTORIES, "pilot", lambda: connector)
    monkeypatch.setattr(runtime, "enabled", lambda: True)
    monkeypatch.setattr(runtime, "default_service", _RuntimeService())
    monkeypatch.setattr(runtime, "dynamic_risk_receipt", lambda _result: None)
    monkeypatch.setattr(assurance, "enabled", lambda: True)
    _stub_review_is_current(monkeypatch, assurance)
    monkeypatch.setattr(
        assurance,
        "get_observation",
        lambda _asset_id: {
            "asset_id": ASSET_ID,
            "revision": 1,
            "version_digest": ASSET_DIGEST,
            "identity": {"asset_type": "agent"},
        },
    )
    monkeypatch.setattr(
        assurance,
        "get_declaration",
        lambda _asset_id: {
            "status": "approved",
            "observed_version_digest": ASSET_DIGEST,
            "risk_tier": "high",
            "risk_context": {},
        },
    )
    admin = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    enrolled = admin.post(
        "/api/v1/external-agents",
        json={
            "id": "pilot-agent",
            "platform": "custom",
            "description": "runtime policy acceptance pilot",
            "owner": "pilot@corp.test",
            "department": "assurance",
            "max_risk": "high",
            "max_dollars": 5.0,
        },
    )
    assert enrolled.status_code == 201
    credential = admin.post(
        "/api/v1/external-agents/pilot-agent/credentials",
        json={"surface": "rest"},
    )
    assert credential.status_code == 200
    yield admin, connector, credential.json()["token"], governed_rest
    config.reset_config_cache()


def _approve(approval_id, _label):
    from maverick.world_model import open_world

    # The workspace's own world, where the gateway parked the approval.
    return open_world().decide_approval(
        approval_id,
        "approved",
        decided_by="pilot-operator@corp.test",
    )


def _gateway(token):
    return TestClient(app, base_url="http://127.0.0.1"), {"Authorization": f"Bearer {token}"}


_RUNTIME = {
    "runtime_asset_id": ASSET_ID,
    "runtime_asset_revision": 1,
    "runtime_asset_version_digest": ASSET_DIGEST,
}
_READ = {"connector": "pilot", "op": "get", "path": "/state", "detail": ALLOW_PROBE, **_RUNTIME}
_COMMIT_FIELDS = ("connector", "op", "path", "body", "detail", "runtime_asset_id",
                  "runtime_asset_revision", "runtime_asset_version_digest")


def _change(state, key):
    return {"connector": "pilot", "op": "patch", "path": "/state",
            "body": {"state": state, "private_marker": "raw-body-canary"},
            "detail": ALLOW_PROBE, "idempotency_key": key, **_RUNTIME}


def _commit(bare, headers, execution_id, request):
    return bare.post(f"/api/v1/external/executions/{execution_id}/commit", headers=headers,
                     json={key: request[key] for key in _COMMIT_FIELDS}).json()


def _read_state(bare, headers):
    read = bare.post("/api/v1/external/execute", headers=headers, json=_READ).json()
    assert read["allowed"] is True and read["status"] == "executed", read
    return json.loads(read["result"])["state"]


def test_runtime_evaluate_follows_the_current_policy(pilot_estate):
    _, _, token, _ = pilot_estate
    bare, headers = _gateway(token)

    def evaluate(content):
        return bare.post("/api/v1/external/runtime/evaluate", headers=headers, json={
            "stage": "prompt", "content": content, "asset_id": ASSET_ID,
            "asset_revision": 1, "asset_version_digest": ASSET_DIGEST,
        }).json()

    assert evaluate(ALLOW_PROBE)["decision"] == "allow"
    # Evaluation has no effect, so asking again gives the same answer.
    assert evaluate(ALLOW_PROBE)["decision"] == "allow"
    assert evaluate(DENY_PROBE)["decision"] != "allow"


def test_reads_run_now_while_previews_and_denied_changes_have_no_effect(pilot_estate):
    _, connector, token, _ = pilot_estate
    bare, headers = _gateway(token)
    assert _read_state(bare, headers) == "baseline"

    preview = bare.post("/api/v1/external/execute", headers=headers,
                        json={**_change("changed", "preview-change"), "preview": True}).json()
    assert preview["allowed"] is True and preview["rule"] == "preview"

    blocked = bare.post("/api/v1/external/execute", headers=headers,
                        json={**_change("changed", "blocked-change"), "detail": DENY_PROBE}).json()
    assert blocked["allowed"] is False and blocked["rule"] == "runtime_guardrail"
    assert blocked["runtime_guardrail"]["decision"] == "block"

    assert connector.writes == []
    assert _read_state(bare, headers) == "baseline"


def test_a_change_parks_once_commits_once_after_approval_and_can_be_undone(pilot_estate):
    _, connector, token, _ = pilot_estate
    bare, headers = _gateway(token)
    change = _change("changed", "acceptance-change")

    parked = bare.post("/api/v1/external/execute", headers=headers, json=change).json()
    replay = bare.post("/api/v1/external/execute", headers=headers, json=change).json()
    assert parked["rule"] == "approval_required" and parked["execution_id"]
    assert replay["execution_id"] == parked["execution_id"] and replay["duplicate"] is True
    status = bare.get(f"/api/v1/external/executions/{parked['execution_id']}",
                      headers=headers).json()
    assert status["status"] == "pending" and status["approval_status"] == "pending"
    assert connector.writes == []

    assert _approve(parked["approval_id"], "change") is True
    status = bare.get(f"/api/v1/external/executions/{parked['execution_id']}",
                      headers=headers).json()
    assert status["approval_status"] == "approved"
    assert _commit(bare, headers, parked["execution_id"], change)["status"] == "executed"
    # A caller that lost the commit response reads the outcome from the status
    # route, and committing the same execution again never repeats the effect.
    status = bare.get(f"/api/v1/external/executions/{parked['execution_id']}",
                      headers=headers).json()
    assert status["status"] == "executed"
    again = _commit(bare, headers, parked["execution_id"], change)
    assert again["rule"] == "already_finished" and again["status"] == "executed"
    assert len(connector.writes) == 1
    assert _read_state(bare, headers) == "changed"

    undo = _change("baseline", "acceptance-compensate")
    compensation = bare.post("/api/v1/external/execute", headers=headers, json=undo).json()
    assert compensation["rule"] == "approval_required"
    assert compensation["execution_id"] != parked["execution_id"]
    assert _approve(compensation["approval_id"], "compensation") is True
    assert _commit(bare, headers, compensation["execution_id"], undo)["status"] == "executed"
    assert [item["body"]["state"] for item in connector.writes] == ["changed", "baseline"]
    assert _read_state(bare, headers) == "baseline"


def test_a_change_waits_for_a_person_and_is_never_approved_for_them(pilot_estate):
    _, connector, token, _ = pilot_estate
    bare, headers = _gateway(token)
    change = _change("changed", "human-boundary-change")

    parked = bare.post("/api/v1/external/execute", headers=headers, json=change).json()
    assert parked["rule"] == "approval_required"
    refused = _commit(bare, headers, parked["execution_id"], change)
    assert refused.get("status") != "executed"
    status = bare.get(f"/api/v1/external/executions/{parked['execution_id']}",
                      headers=headers).json()
    assert status["approval_status"] == "pending"
    assert connector.writes == []


def test_connector_outage_after_effect_stays_indeterminate_and_is_not_retried(
    pilot_estate,
    monkeypatch,
):
    _, old_connector, token, governed_rest = pilot_estate
    connector = _PilotConnector(fail_after_change=True)
    monkeypatch.setitem(governed_rest.GOVERNED_REST_FACTORIES, "pilot", lambda: connector)
    bare, headers = _gateway(token)
    change = _change("changed", "connector-outage-change")

    parked = bare.post("/api/v1/external/execute", headers=headers, json=change).json()
    assert _approve(parked["approval_id"], "change") is True
    committed = _commit(bare, headers, parked["execution_id"], change)

    # The gateway records an outage after the effect as indeterminate, not failed.
    assert committed["status"] == "indeterminate", committed
    assert _commit(bare, headers, parked["execution_id"], change).get("status") != "executed"
    assert old_connector.writes == []
    assert connector.state == "changed"
    assert len(connector.writes) == 1


def test_commit_rebinds_current_runtime_policy_before_external_effect(
    pilot_estate,
    monkeypatch,
):
    _, connector, token, _ = pilot_estate
    bare = TestClient(app, base_url="http://127.0.0.1")
    headers = {"Authorization": f"Bearer {token}"}
    request = {
        "connector": "pilot",
        "op": "patch",
        "path": "/state",
        "body": {"state": "changed"},
        "detail": ALLOW_PROBE,
        "idempotency_key": "policy-rebind-change",
        "runtime_asset_id": ASSET_ID,
        "runtime_asset_revision": 1,
        "runtime_asset_version_digest": ASSET_DIGEST,
    }
    parked = bare.post(
        "/api/v1/external/execute", headers=headers, json=request,
    ).json()
    assert parked["rule"] == "approval_required"
    assert _approve(parked["approval_id"], "change") is True

    monkeypatch.setattr(runtime, "default_service", _BlockActionRuntimeService())
    commit_body = {
        key: request[key]
        for key in (
            "connector",
            "op",
            "path",
            "body",
            "detail",
            "runtime_asset_id",
            "runtime_asset_revision",
            "runtime_asset_version_digest",
        )
    }
    blocked = bare.post(
        f"/api/v1/external/executions/{parked['execution_id']}/commit",
        headers=headers,
        json=commit_body,
    ).json()
    assert blocked["allowed"] is False
    assert blocked["rule"] == "runtime_guardrail"
    assert blocked["status"] == "block"
    assert connector.writes == []

    # Rolling the test policy back to the previously accepted service allows
    # the same digest-bound commit; no new approval or effect was created by
    # the blocked attempt.
    monkeypatch.setattr(runtime, "default_service", _RuntimeService())
    committed = bare.post(
        f"/api/v1/external/executions/{parked['execution_id']}/commit",
        headers=headers,
        json=commit_body,
    ).json()
    assert committed["status"] == "executed"
    assert len(connector.writes) == 1


def test_commit_cannot_swap_the_runtime_context_that_was_approved(pilot_estate):
    _, connector, token, _ = pilot_estate
    bare = TestClient(app, base_url="http://127.0.0.1")
    headers = {"Authorization": f"Bearer {token}"}
    request = {
        "connector": "pilot",
        "op": "patch",
        "path": "/state",
        "body": {"state": "changed"},
        "detail": ALLOW_PROBE,
        "idempotency_key": "context-binding-change",
        "runtime_asset_id": ASSET_ID,
        "runtime_asset_revision": 1,
        "runtime_asset_version_digest": ASSET_DIGEST,
    }
    parked = bare.post(
        "/api/v1/external/execute", headers=headers, json=request,
    ).json()
    assert _approve(parked["approval_id"], "change") is True
    swapped = {
        key: request[key]
        for key in (
            "connector",
            "op",
            "path",
            "body",
            "detail",
            "runtime_asset_id",
            "runtime_asset_revision",
            "runtime_asset_version_digest",
        )
    }
    swapped["detail"] = ALLOW_PROBE + "-different-context"
    refused = bare.post(
        f"/api/v1/external/executions/{parked['execution_id']}/commit",
        headers=headers,
        json=swapped,
    ).json()
    assert refused["allowed"] is False
    assert refused["rule"] == "digest_mismatch"
    assert connector.writes == []
