"""Selected pilot release checks in the shared Copilot operation catalog."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick_dashboard import product_operations as ops
from maverick_dashboard import product_operations_outcome_pilots as pilots

BASE = "/api/v1/copilot/product-operations"
PILOT_ID = "OPL-" + "a" * 48
SELECTION = {"kind": "outcome_pilot", "id": PILOT_ID}
BINDING = {
    "candidate_id": "candidate-1", "target_id": "target-1", "run_id": "run-1",
    "baseline_sha256": "a" * 64, "candidate_sha256": "b" * 64,
    "promotion_manifest_sha256": "c" * 64, "deployment_observation_sha256": "d" * 64,
    "observed_at": 1.0, "promotion_revision": 1, "promotion_state": "staged",
}


def _harness(monkeypatch):
    current = {"context": "account-workspace", "release": "baseline_active", "paired": 0,
               "binding": dict(BINDING), "available": True, "reads": 0}

    monkeypatch.setattr(pilots.outcome_pilots_api, "_context", lambda _request: current["context"])

    def get(pilot_id, context):
        if not current["available"] or pilot_id != PILOT_ID or context != current["context"]:
            raise LookupError("not owned")
        return {"id": PILOT_ID, "title": "Receiving pilot", "plan_version": "frozen-1",
                "release_binding": current["binding"]}

    monkeypatch.setattr(pilots.outcome_pilots, "get", get)
    monkeypatch.setattr(pilots.outcome_pilots_api, "_resolver", lambda _request: lambda *_args: {})
    monkeypatch.setattr(pilots.outcome_pilots, "report", lambda _record, resolve: {
        "title": "Receiving pilot", "revision": 1,
        "groups": {"all": {"planned": 4, "paired": current["paired"], "accepted": 0,
                           "reported_minutes_difference": None, "reported_cost_difference": None}},
        "evidence_readiness": {"reported_effort_comparison_ready": current["paired"] == 4,
                               "reported_cost_comparison_ready": False,
                               "causal_release_lift_qualified": False, "next_steps": ["Record cost evidence."]},
        "limitations": ["Operator reported."],
        "cases": [{"id": str(i), "status": "paired" if i <= current["paired"] else "unmeasured"}
                  for i in range(1, 5)],
    })
    def status(_request, _binding):
        current["reads"] += 1
        return {"promotion_state": "staged", "deployment_state": current["release"],
                "release_evidence_current": current["release"] != "unavailable",
                "case_exposure_verified": False, "causal_lift_qualified": False,
                "checked_at": float(current["reads"])}

    monkeypatch.setattr(pilots.outcome_pilot_releases, "status", status)
    monkeypatch.setattr(ops, "_same_origin", lambda _request: None)
    monkeypatch.setattr(ops, "_gate", lambda _request: None)
    monkeypatch.setattr(ops, "_context", lambda _request: "e" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in pilots.entries()})
    app = FastAPI()
    app.include_router(ops.router)
    return TestClient(app, base_url="http://127.0.0.1"), current


def test_selected_pilot_release_is_read_only_and_rechecks_fresh_state(monkeypatch):
    client, current = _harness(monkeypatch)
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": "/outcome-pilots", "selection": SELECTION}).json()
        item = catalog["operations"][0]
        assert item["id"] == "learning.pilot_release_status" and item["available"]
        assert item["confirmation_required"] is False
        assert item["details"]["case_exposure_verified"] is False
        assert item["details"]["causal_lift_qualified"] is False
        review = client.post(BASE + "/prepare", json={"page": "/outcome-pilots", "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"],
            "arguments": {}})
        assert review.status_code == 200 and review.json()["read_only"] is True
        assert "token" not in review.json()
        current["release"] = "candidate_active"
        stale = client.post(BASE + "/prepare", json={"page": "/outcome-pilots", "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"],
            "arguments": {}})
        assert stale.status_code == 409


# Operations about one selected pilot. The page also lists its own complete
# controls (open the form, prepare, plan, observe, review), which are not
# claims about a selected pilot.
SELECTED_PILOT_OPERATIONS = {"learning.pilot_release_status", "learning.pilot_value_evidence"}


def _about_selected_pilot(catalog):
    return [item for item in catalog["operations"] if item["id"] in SELECTED_PILOT_OPERATIONS]


def test_missing_pilot_or_release_is_not_advertised_as_actionable(monkeypatch):
    client, current = _harness(monkeypatch)
    with client:
        unselected = client.post(BASE + "/catalog", json={"page": "/outcome-pilots", "selection": {}}).json()
        assert _about_selected_pilot(unselected) == []
        current["binding"] = None
        blocked = client.post(BASE + "/catalog", json={"page": "/outcome-pilots", "selection": SELECTION}).json()
        release = next(item for item in blocked["operations"] if item["id"] == "learning.pilot_release_status")
        assert release["available"] is False
        current["available"] = False
        hidden = client.post(BASE + "/catalog", json={"page": "/outcome-pilots", "selection": SELECTION}).json()
        assert _about_selected_pilot(hidden) == []


def test_copilot_reads_the_full_pilot_evidence_boundary_and_rechecks_changes(monkeypatch):
    client, current = _harness(monkeypatch)
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": "/outcome-pilots", "selection": SELECTION}).json()
        value = next(item for item in catalog["operations"] if item["id"] == "learning.pilot_value_evidence")
        assert value["available"] and value["confirmation_required"] is False
        assert value["details"]["groups"]["all"]["paired"] == 0
        assert value["details"]["evidence_readiness"]["reported_cost_comparison_ready"] is False
        prepared = client.post(BASE + "/prepare", json={"page": "/outcome-pilots", "selection": SELECTION,
            "operation": value["id"], "context": catalog["context"], "revision": value["revision"],
            "arguments": {}})
        assert prepared.status_code == 200 and prepared.json()["read_only"] is True
        current["paired"] = 4
        stale = client.post(BASE + "/prepare", json={"page": "/outcome-pilots", "selection": SELECTION,
            "operation": value["id"], "context": catalog["context"], "revision": value["revision"],
            "arguments": {}})
        assert stale.status_code == 409
