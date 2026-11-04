"""Native paired-replay comparison routes; OIDC verification stubbed.

Refusals keep their own status and message, and the retained-comparison lists
show the newest rows, not the oldest.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick.flow import Flow, FlowNode, execution, store
from maverick.flow.evolve import attach_learned_operator
from maverick.flow.learned_operator import synthesize
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.tenant.registry import create_tenant, get_tenant
from maverick_dashboard import local_flow_comparisons as comparisons
from maverick_dashboard import rbac, workspace_tenants

# Import the app while collecting: a cold import inside the harness fixture would
# claim this workspace id for the test's home before the test creates it.
from maverick_dashboard.app import app as _installed_app  # noqa: F401

from test_support.action_episode_api import OWNER, TENANT
from test_support.action_episode_api import harness as harness

LOCAL = "/api/v1/research/local-flow-release"
API = "/api/v1/research/flow-comparisons"


def _artifact(multiply):
    spec = {"inputs": {name: {"type": "integer", "min": 0, "max": 20}
                       for name in ("quantity", "unit_price")}, "output_type": "integer"}
    return synthesize(spec, [{"inputs": {"quantity": quantity, "unit_price": price},
                             "output": quantity * price if multiply else quantity + price}
                            for quantity, price in ((2, 3), (7, 4), (0, 9))])


def _no_work(*_args, **_kwargs):
    pytest.fail("A rule-only flow must never invoke AI or connected tools")


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


def _journey(harness, monkeypatch):
    """A published rule-only baseline, a changed saved draft and one finished real run."""
    _enable(harness, monkeypatch)
    with tenant_scope(tenant=TENANT):
        source = Flow(id="taught-release", name="Calculate order total", owner=OWNER,
                      start="calculate", nodes={"calculate": FlowNode(id="calculate", kind="agent",
                      brief="Calculate total", output="total", label="Calculate total")})
        source = store.save_flow(attach_learned_operator(source, "calculate", _artifact(False)))
    context = harness.client.get(LOCAL).json()["context"]
    saved = harness.client.post(LOCAL + "/rules-only", json={
        "context": context, "confirm": True, "flow_id": source.id,
        "version": source.version, "revision": source.revision})
    assert saved.status_code == 200, saved.text
    with tenant_scope(tenant=TENANT):
        baseline = store.load_flow(source.id)
    published = harness.client.post("/api/v1/flows/" + source.id + "/publish",
                                    json={"version": baseline.version, "revision": baseline.revision})
    assert published.status_code == 200, published.text
    with tenant_scope(tenant=TENANT):
        release = store.load_published_bundle(source.id)[1]
        inputs = {"quantity": 2, "unit_price": 3}
        queued = store.FlowRun(run_id=store.new_run_id(), flow_id=baseline.id, status="queued", owner=OWNER,
            input_data=inputs, definition_digest=release["definition_digest"], definition_version=baseline.version,
            definition_revision=baseline.revision, release_digest=release["release_digest"], release_id=release["release_id"])
        store.save_run(queued)
        original = execution.execute(baseline, owner=OWNER, run_id=queued.run_id, data=inputs,
                                     agent_runner=_no_work, action_runner=_no_work)
        assert original.status == "completed" and original.data["total"] == 5
        candidate = store.save_flow(attach_learned_operator(baseline, "calculate", _artifact(True)),
            expected_version=baseline.version, expected_revision=baseline.revision)
    checked = harness.client.get(API, params={"flow_id": source.id})
    assert checked.status_code == 200, checked.text
    checked = checked.json()
    case = harness.client.get(API + "/case", params={"flow_id": source.id, "run_id": original.run_id, "output": "total"})
    assert case.status_code == 200, case.text
    body = {"context": checked["context"], "confirm": True, "authorize_case_use": True,
            "operation": "a" * 32, "flow_id": source.id, "version": candidate.version, "revision": candidate.revision,
            "baseline_release": checked["baseline_release"], "bundle": checked["bundle"], "output": "total",
            "cases": [{"run_id": original.run_id, "source_version": case.json()["version"], "expected": "6"}]}
    return SimpleNamespace(source=source, baseline=baseline, candidate=candidate, release=release,
                           original=original, checked=checked, body=body)


def _retain(journey, count, *, state="done"):
    """Retain ``count`` comparison rows for the journey's flow, oldest first."""
    ids = []
    with tenant_scope(tenant=TENANT):
        store_ = comparisons.records()
        for index in range(count):
            row = store_.create({"id": "FCP-" + format(index, "032x"), "tenant": TENANT, "owner": OWNER,
                                 "flow_id": journey.source.id, "state": state, "cases": [{}],
                                 "root": journey.checked["root"], "bundle_sha": journey.checked["bundle"],
                                 "baseline": journey.release},
                                action="flow.comparison.authorize", actor=OWNER, max_records=1000)
            ids.append(row["id"])
    return ids


def test_refused_comparison_keeps_its_status_and_message(harness, monkeypatch):
    journey = _journey(harness, monkeypatch)
    monkeypatch.delenv("MAVERICK_CANDIDATE_PROMOTION")
    response = harness.client.post(API, json=journey.body)
    assert response.status_code == 409, response.text
    assert "Enable release decisions" in response.json()["detail"]


def test_failed_replay_reports_the_recorded_unavailable_comparison(harness, monkeypatch):
    journey = _journey(harness, monkeypatch)

    def broken(*_args, **_kwargs):
        raise RuntimeError("replay storage failed")

    monkeypatch.setattr(comparisons, "_replay", broken)
    response = harness.client.post(API, json=journey.body)
    assert response.status_code == 409, response.text
    assert "did not produce complete current evidence" in response.json()["detail"]
    assert "no AI or connected work was started" in response.json()["detail"]
    history = harness.client.get(API + "/history", params={"flow_id": journey.source.id}).json()
    assert [row["state"] for row in history["comparisons"]] == ["unavailable"]


def test_concurrent_duplicate_create_is_a_conflict_not_an_outage(harness, monkeypatch):
    journey = _journey(harness, monkeypatch)

    class Racing:
        def get(self, _identifier):
            return None

        def create(self, *_args, **_kwargs):
            raise RecordConflict("governed record already exists")

    monkeypatch.setattr(comparisons, "records", lambda: Racing())
    response = harness.client.post(API, json=journey.body)
    assert response.status_code == 409, response.text
    assert "just recorded by another request" in response.json()["detail"]


def test_retained_comparison_lists_show_the_newest_fifty(harness, monkeypatch):
    journey = _journey(harness, monkeypatch)
    ids = _retain(journey, 60)
    newest_first = list(reversed(ids[-50:]))
    history = harness.client.get(API + "/history", params={"flow_id": journey.source.id})
    assert history.status_code == 200, history.text
    assert [row["id"] for row in history.json()["comparisons"]] == newest_first
    picker = harness.client.get(API, params={"flow_id": journey.source.id})
    assert picker.status_code == 200, picker.text
    assert [row["id"] for row in picker.json()["comparisons"]] == newest_first
    release = harness.client.get(LOCAL)
    assert release.status_code == 200, release.text
    [flow] = release.json()["flows"]
    assert [row["id"] for row in flow["comparisons"]] == newest_first


def test_a_bad_workflow_choice_is_a_plain_refusal_not_a_server_error(harness, monkeypatch):
    journey = _journey(harness, monkeypatch)
    history = harness.client.get(API + "/history", params={"flow_id": "not a saved workflow!"})
    assert history.status_code == 422, history.text
    assert "Choose a saved workflow" in history.json()["detail"]
    case = harness.client.get(API + "/case", params={"flow_id": journey.source.id, "run_id": "r", "output": "nope"})
    assert case.status_code == 422, case.text
    assert "Choose a current result" in case.json()["detail"]

