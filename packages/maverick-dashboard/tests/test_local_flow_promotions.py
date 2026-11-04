"""One native, signed local taught-flow release journey; OIDC verification stubbed.

Actual rules execute, practice/result storage, current memberships, independent
approval, publication, canary and restore are native. No AI/connector effects.
"""
from __future__ import annotations

import pytest
from maverick import config
from maverick.flow import Flow, FlowNode, execution, store
from maverick.flow.evolve import attach_learned_operator, remove_learned_operator
from maverick.flow.learned_operator import synthesize
from maverick.paths import tenant_scope
from maverick.tenant.registry import create_tenant, get_tenant
from maverick_dashboard import local_flow_promotions as release_module
from maverick_dashboard import rbac, workspace_tenants

# Import the app while collecting: a cold import inside the harness fixture would
# claim this workspace id for the test's home before the test creates it.
from maverick_dashboard.app import app as _installed_app  # noqa: F401

from test_support.action_episode_api import OWNER, TENANT
from test_support.action_episode_api import harness as harness

LOCAL = "/api/v1/research/local-flow-release"
BASE = "/api/v1/research/promotions"
COPILOT = "/api/v1/copilot/product-operations"


def _artifact(multiply):
    spec = {"inputs": {name: {"type": "integer", "min": 0, "max": 20}
                       for name in ("quantity", "unit_price")}, "output_type": "integer"}
    return synthesize(spec, [{"inputs": {"quantity": quantity, "unit_price": price},
                             "output": quantity * price if multiply else quantity + price}
                            for quantity, price in ((2, 3), (7, 4), (0, 9))])


def test_native_rule_only_practice_independent_copilot_release_canary_and_restore(harness, monkeypatch):
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_CANDIDATE_PROMOTION", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    harness.flags["learned_operators"] = True
    original_global = config.load_global_config
    global_config = {**original_global(), "features": {"copilot_operations": True},
                     "copilot": {"operation_families": ["learning"]}}
    monkeypatch.setattr(config, "load_global_config", lambda: global_config)
    monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": True})
    if get_tenant(TENANT) is None:
        create_tenant(TENANT)
    for actor in (OWNER, "user:admin"):
        rbac.set_role(actor, "admin", actor="user:admin")
        rbac.set_tenant_role(TENANT, actor, "admin", actor="user:admin")
        workspace_tenants.set_selection(actor, TENANT)

    def no_work(*_args, **_kwargs):
        pytest.fail("A rule-only flow must never invoke AI or connected tools")

    with tenant_scope(tenant=TENANT):
        source = Flow(id="taught-release", name="Calculate order total", owner=OWNER,
                      start="calculate", nodes={"calculate": FlowNode(id="calculate", kind="agent",
                      brief="Calculate total", output="total", label="Calculate total")})
        source = store.save_flow(attach_learned_operator(source, "calculate", _artifact(False)))
    options = harness.client.get(LOCAL)
    assert options.status_code == 200, options.text
    context = options.json()["context"]
    rule_body = {"context": context, "confirm": True, "flow_id": source.id,
                 "version": source.version, "revision": source.revision}
    saved = harness.client.post(LOCAL + "/rules-only", json=rule_body)
    assert saved.status_code == 200, saved.text
    with tenant_scope(tenant=TENANT):
        baseline = store.load_flow(source.id)
        assert baseline.nodes["calculate"].learned_fallback is False
        assert remove_learned_operator(baseline, "calculate").nodes["calculate"].learned_fallback is True
    published = harness.client.post("/api/v1/flows/" + source.id + "/publish",
                                   json={"version": baseline.version, "revision": baseline.revision})
    assert published.status_code == 200, published.text
    with tenant_scope(tenant=TENANT):
        prior_release = store.load_published_bundle(source.id)[1]
        original_inputs = {"quantity": 2, "unit_price": 3}
        queued_case = store.FlowRun(run_id=store.new_run_id(), flow_id=baseline.id, status="queued", owner=OWNER,
            input_data=original_inputs, definition_digest=prior_release["definition_digest"], definition_version=baseline.version,
            definition_revision=baseline.revision, release_digest=prior_release["release_digest"], release_id=prior_release["release_id"])
        store.save_run(queued_case)
        original_case = execution.execute(baseline, owner=OWNER, run_id=queued_case.run_id, data=original_inputs,
            agent_runner=no_work, action_runner=no_work)
        assert original_case.status == "completed" and original_case.data["total"] == 5
        candidate = store.save_flow(attach_learned_operator(baseline, "calculate", _artifact(True)),
            expected_version=baseline.version, expected_revision=baseline.revision)
        practice = execution.execute(candidate, owner=OWNER, data={"quantity": 2, "unit_price": 3},
            agent_runner=no_work, action_runner=no_work, record_outcomes=False)
        assert practice.status == "completed" and practice.data["total"] == 6
        stopped = execution.execute(candidate, owner=OWNER, data={"quantity": 30, "unit_price": 3},
            agent_runner=no_work, action_runner=no_work, record_outcomes=False)
        assert stopped.status == "failed"
    comparisons = "/api/v1/research/flow-comparisons"
    options = harness.client.get(comparisons, params={"flow_id": source.id})
    assert options.status_code == 200, options.text
    checked = options.json()
    original = harness.client.get(comparisons + "/case", params={"flow_id": source.id,
        "run_id": original_case.run_id, "output": "total"})
    assert original.status_code == 200, original.text
    compare_body = {"context": checked["context"], "confirm": True, "authorize_case_use": True,
        "operation": "a" * 32, "flow_id": source.id, "version": candidate.version, "revision": candidate.revision,
        "baseline_release": checked["baseline_release"], "bundle": checked["bundle"], "output": "total",
        "cases": [{"run_id": original_case.run_id, "source_version": original.json()["version"], "expected": "6"}]}
    refusal = harness.client.post(comparisons, json={**compare_body, "authorize_case_use": False})
    assert refusal.status_code == 409, refusal.text
    paired = harness.client.post(comparisons, json=compare_body)
    assert paired.status_code == 200, paired.text
    pair = paired.json()
    assert pair["summary"]["baseline_matches"] == 0 and pair["summary"]["candidate_matches"] == 1
    assert pair["cases"][0]["inputs"] == original_inputs
    assert pair["cases"][0]["results"]["baseline"]["result"] == "5"
    assert pair["cases"][0]["results"]["candidate"]["result"] == "6"
    with tenant_scope(tenant=TENANT):
        before_readback = len(store.list_runs(flow_id=source.id, owner=OWNER))
    assert harness.client.post(comparisons, json=compare_body).json()["id"] == pair["id"]
    assert harness.client.get(comparisons + "/" + pair["id"]).status_code == 200
    with tenant_scope(tenant=TENANT):
        assert len(store.list_runs(flow_id=source.id, owner=OWNER)) == before_readback
    prepared = harness.client.post(LOCAL + "/prepare", json={**rule_body, "version": candidate.version,
                                                           "practice_run": practice.run_id, "comparison_id": pair["id"]})
    assert prepared.status_code == 200, prepared.text
    assert "No release was activated" in prepared.text
    assert app.state.local_flow_promotions_installed is True
    catalog = harness.client.post(COPILOT + "/catalog", json={"page": "/research", "selection": {}})
    assert catalog.status_code == 200, catalog.text
    operation = next(row for row in catalog.json()["operations"] if row["id"] == "learning.release_request")
    review = harness.client.post(COPILOT + "/prepare", json={"page": "/research", "selection": {},
        "context": catalog.json()["context"], "revision": operation["revision"],
        "operation": operation["id"], "arguments": {"candidate": "order-total-release"}})
    assert review.status_code == 200, review.text
    request = harness.client.post(COPILOT + "/execute", json={"token": review.json()["token"], "confirmed": True})
    assert request.status_code == 200, request.text
    row = harness.client.get(BASE + "/order-total-release").json()["candidate"]
    owner_review = harness.client.post(BASE + "/order-total-release/review", json={"context": context, "confirm": True,
        "expected_revision": row["revision"], "approve": True, "reason_code": "reviewed_scope", "note": "I checked it"})
    assert owner_review.status_code == 403, owner_review.text
    admin_headers = {"Authorization": "Bearer admin"}
    admin_context = harness.client.get(BASE, headers=admin_headers).json()["context"]
    exact = harness.client.get(LOCAL + "/review/order-total-release", headers=admin_headers)
    assert exact.status_code == 200 and exact.json()["steps"][0]["examples"] == _artifact(True)["examples"]
    assert exact.json()["known_case_comparison"]["candidate_matches"] == 1
    assert exact.json()["known_case_comparison"]["reviewed_cases"][0]["inputs"] == original_inputs

    def decide(action, **extra):
        current = harness.client.get(BASE + "/order-total-release", headers=admin_headers).json()["candidate"]
        response = harness.client.post(BASE + "/order-total-release/" + action, headers=admin_headers,
            json={"context": admin_context, "confirm": True, "expected_revision": current["revision"], **extra})
        assert response.status_code == 200, response.text
        return response.json()

    assert decide("review", approve=True, reason_code="reviewed_scope", note="Checked complete examples, domain and readiness limits")["state"] == "authorized"
    assert decide("stage")["state"] == "staged"
    assert decide("activate")["state"] == "canary"
    assert harness.client.get(comparisons, params={"flow_id": source.id}).json()["can_compare"] is False
    assert harness.client.get(comparisons + "/" + pair["id"]).json()["state"] == "done"
    early = harness.client.get(BASE + "/order-total-release", headers=admin_headers).json()["candidate"]
    assert early["local_release"]["can_assess"] is False
    refusal = harness.client.post(BASE + "/order-total-release/canary", headers=admin_headers,
        json={"context": admin_context, "confirm": True, "expected_revision": early["revision"]})
    assert refusal.status_code == 409
    with tenant_scope(tenant=TENANT):
        flow, activated = store.load_published_bundle(source.id)
        assert activated["release_id"] != prior_release["release_id"]
        queued = store.FlowRun(run_id=store.new_run_id(), flow_id=flow.id, status="queued", owner=OWNER,
            definition_digest=activated["definition_digest"], definition_version=flow.version,
            definition_revision=flow.revision, release_digest=activated["release_digest"], release_id=activated["release_id"])
        store.save_run(queued)
        real = execution.execute(flow, owner=OWNER, run_id=queued.run_id, data={"quantity": 2, "unit_price": 3},
                                 agent_runner=no_work, action_runner=no_work)
        assert real.status == "completed" and real.data["total"] == 6 and real.release_id == activated["release_id"]
    assessed = decide("canary")
    assert assessed["state"] == "active" and assessed["local_release"]["observed_runs"] == 1
    restored = decide("rollback", reason_code="operator_requested")
    assert restored["state"] == "rolled_back"
    with tenant_scope(tenant=TENANT):
        flow, restored_release = store.load_published_bundle(source.id)
        assert restored_release["release_digest"] == prior_release["release_digest"]
        assert restored_release["release_id"] not in {prior_release["release_id"], activated["release_id"]}
        assert store.load_flow(source.id).version == candidate.version
        for old in (prior_release, activated):
            with pytest.raises(store.FlowSnapshotError):
                with store.active_release_guard(source.id, expected_release_id=old["release_id"]):
                    pytest.fail("Old waiting work regained activation")
    assert not harness.calls


def _enable(harness, monkeypatch):
    monkeypatch.setenv("MAVERICK_CANDIDATE_PROMOTION", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    harness.flags["learned_operators"] = True
    if get_tenant(TENANT) is None:
        create_tenant(TENANT)
    for actor in (OWNER, "user:admin"):
        rbac.set_role(actor, "admin", actor="user:admin")
        rbac.set_tenant_role(TENANT, actor, "admin", actor="user:admin")
        workspace_tenants.set_selection(actor, TENANT)


def _taught(flow_id):
    return Flow(id=flow_id, name="Calculate order total", owner=OWNER, start="calculate", nodes={
        "calculate": FlowNode(id="calculate", kind="agent", brief="Calculate total", output="total", label="Calculate total")})


def _published(harness, monkeypatch):
    """A rule-only taught workflow with its exact baseline published."""
    _enable(harness, monkeypatch)
    with tenant_scope(tenant=TENANT):
        source = store.save_flow(attach_learned_operator(_taught("taught-release"), "calculate", _artifact(False)))
    context = harness.client.get(LOCAL).json()["context"]
    saved = harness.client.post(LOCAL + "/rules-only", json={
        "context": context, "confirm": True, "flow_id": source.id, "version": source.version, "revision": source.revision})
    assert saved.status_code == 200, saved.text
    with tenant_scope(tenant=TENANT):
        baseline = store.load_flow(source.id)
    published = harness.client.post("/api/v1/flows/" + source.id + "/publish",
                                    json={"version": baseline.version, "revision": baseline.revision})
    assert published.status_code == 200, published.text
    with tenant_scope(tenant=TENANT):
        return baseline, store.load_published_bundle(source.id)[1]


def _runs(flow, count, *, status, release_id=""):
    for _ in range(count):
        store.save_run(store.FlowRun(run_id=store.new_run_id(), flow_id=flow.id, status=status, owner=OWNER, release_id=release_id))


def test_one_unreadable_publication_does_not_hide_the_other_workflows(harness, monkeypatch):
    _enable(harness, monkeypatch)
    with tenant_scope(tenant=TENANT):
        for flow_id in ("good-flow", "bad-flow"):
            store.save_flow(attach_learned_operator(_taught(flow_id), "calculate", _artifact(False)))
        pointer = store._published_pointer_path("bad-flow")
        pointer.parent.mkdir(parents=True, exist_ok=True)
        pointer.write_text("{not json", encoding="utf-8")
        with pytest.raises(store.FlowSnapshotError):
            store.load_published_bundle("bad-flow")
    response = harness.client.get(LOCAL)
    assert response.status_code == 200, response.text
    assert [row["id"] for row in response.json()["flows"]] == ["good-flow"]


def test_pending_work_fingerprint_covers_waiting_runs_older_than_the_latest_fifty(harness, monkeypatch):
    baseline, published = _published(harness, monkeypatch)
    monkeypatch.setattr(release_module, "_target_record", lambda *_args: {
        "tenant": TENANT, "owner": OWNER, "flow_id": baseline.id, "binding": "0" * 64})
    with tenant_scope(tenant=TENANT):
        waiting = store.FlowRun(run_id=store.new_run_id(), flow_id=baseline.id, status="queued", owner=OWNER,
                                release_id=published["release_id"])
        store.save_run(waiting)
        _runs(baseline, 60, status="completed", release_id=published["release_id"])
        observed = release_module.LocalFlowDeployment().observe(TENANT, release_module.TARGET)
    assert observed.pending_intents_sha256 == release_module._sha([(waiting.run_id, "queued", published["release_id"])])


def test_practice_run_picker_finds_a_practice_run_buried_under_real_runs(harness, monkeypatch):
    baseline, published = _published(harness, monkeypatch)

    def no_work(*_args, **_kwargs):
        pytest.fail("A rule-only flow must never invoke AI or connected tools")

    with tenant_scope(tenant=TENANT):
        candidate = store.save_flow(attach_learned_operator(baseline, "calculate", _artifact(True)),
                                    expected_version=baseline.version, expected_revision=baseline.revision)
        practice = execution.execute(candidate, owner=OWNER, data={"quantity": 2, "unit_price": 3},
                                     agent_runner=no_work, action_runner=no_work, record_outcomes=False)
        assert practice.status == "completed" and practice.dry_run is True
        _runs(candidate, 60, status="completed", release_id=published["release_id"])
    response = harness.client.get(LOCAL)
    assert response.status_code == 200, response.text
    [flow] = response.json()["flows"]
    assert [row["id"] for row in flow["practice_runs"]] == [practice.run_id]
