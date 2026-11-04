"""Legacy attribution labels never broaden employee workflow authority."""
from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi import HTTPException
from starlette.requests import Request


@pytest.fixture
def local_runs(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    config.reset_config_cache()
    flow = store.save_flow(Flow(id="local-flow", name="Local flow", start="a", nodes={
        "a": FlowNode(id="a", kind="agent", brief="Local brief")}))
    release = store.publish_flow(flow.id, expected_version=flow.version,
                                 expected_revision=flow.revision)
    run = store.FlowRun(run_id="legacy-run", flow_id=flow.id, status="completed",
                        owner="operator", data={"answer": "private local answer"},
                        definition_digest=release["definition_digest"],
                        subflow_digests=release["subflow_digests"])
    store.save_run(run)
    yield store, run
    config.reset_config_cache()


def _request():
    return Request({"type": "http", "method": "GET", "scheme": "http",
                    "path": "/api/v1/flows/runs/legacy-run", "headers": []})


@pytest.mark.parametrize("label", ["operator", "local:dashboard"])
def test_proven_local_legacy_attribution_can_be_read(local_runs, label):
    from maverick_dashboard import api
    store, run = local_runs
    run.owner = label
    store.save_run(run)
    assert api._load_owned_run(_request(), run.run_id).data["answer"] == "private local answer"


@pytest.mark.parametrize("change", ["missing_snapshot", "named_executor", "execution_channel", "named_owner", "wrong_definition", "missing_child"])
def test_unproven_legacy_record_does_not_gain_local_access(local_runs, change):
    from maverick_dashboard import api
    store, original = local_runs
    run = replace(original, run_id="unproven-run", release_digest="", release_id="")
    if change == "missing_snapshot":
        run.definition_digest = ""
    elif change == "named_executor":
        run.execution_user_id = "employee"
    elif change == "execution_channel":
        run.execution_channel = "api"
    elif change == "wrong_definition":
        run.flow_id = "another-flow"
    elif change == "missing_child":
        run.subflow_digests = {"missing-child": None}
    else:
        run.owner = "user:employee"
    store.save_run(run)
    with pytest.raises(HTTPException) as exc:
        api._load_owned_run(_request(), run.run_id)
    assert exc.value.status_code == 404


def test_legacy_access_refuses_employee_owned_pinned_definition(local_runs):
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import api
    store, run = local_runs
    flow = store.save_flow(Flow(id="private-flow", name="Private", owner="user:employee",
                               start="a", nodes={"a": FlowNode(id="a", kind="agent", brief="Private")}))
    release = store.publish_flow(flow.id, expected_version=flow.version,
                                 expected_revision=flow.revision)
    run = replace(run, run_id="private-run", flow_id=flow.id,
                  definition_digest=release["definition_digest"], release_digest="", release_id="")
    store.save_run(run)
    with pytest.raises(HTTPException) as exc:
        api._load_owned_run(_request(), run.run_id)
    assert exc.value.status_code == 404


def test_named_and_token_callers_cannot_inherit_legacy_local_label(local_runs, monkeypatch):
    from maverick_dashboard import api
    _, run = local_runs
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:admin")
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:admin")
    with pytest.raises(HTTPException) as exc:
        api._load_owned_run(_request(), run.run_id)
    assert exc.value.status_code == 404
    monkeypatch.setattr(api, "caller_principal", lambda request: None)
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "local-regression-token")
    with pytest.raises(HTTPException) as exc:
        api._load_owned_run(_request(), run.run_id)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_flow_stream_rechecks_authority_before_next_snapshot(local_runs, monkeypatch):
    from maverick_dashboard import api, auth, flows_api
    _, run = local_runs
    request = _request()
    async def connected():
        return False
    request.is_disconnected = connected
    # The stream handler lives in flows_api and calls its own _require_flows;
    # require_permission is reached through the api seam, so it is patched there.
    monkeypatch.setattr(flows_api, "_require_flows", lambda: None)
    calls = []
    def authority(request, permission):
        calls.append(permission)
        if len(calls) > 1:
            raise HTTPException(status_code=403, detail="revoked")
    monkeypatch.setattr(api, "require_permission", authority)
    assert auth.anonymous_local_access_allowed()
    response = await api.flow_run_events_stream(request, run.run_id)
    body = "".join([frame async for frame in response.body_iterator])
    assert "permission_denied" in body
    assert "private local answer" not in body
