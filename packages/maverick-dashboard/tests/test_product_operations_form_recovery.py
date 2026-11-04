"""The shared Copilot form action uses the exact native recovery decision."""
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard import product_operations as ops
from maverick_dashboard import product_operations_form_recovery as forms

BASE = "/api/v1/copilot/product-operations"
SELECTION = {"kind": "form_recovery", "name": "order-intake", "sequence": 7}


def _harness(monkeypatch):
    current = {"pending": True, "calls": 0, "owner": True,
               "receipt_hash": "b" * 64, "damaged": False}

    def waiting(_request, _response, name):
        if not current["owner"] or name != "order-intake":
            from fastapi import HTTPException
            raise HTTPException(404, "not owned")
        return {"binding_revision": "d" * 64, "submissions": [],
                "interrupted_decision": ({
                    "sequence": 7, "fields": {"purchase order": "PO-17"},
                    "fields_sha256": "a" * 64, "decision_sha256": "b" * 64,
                    "reason": "Incorrect customer account", "decided_by": "user:owner",
                    "received_at": 1.0,
                } if current["pending"] else None)}

    def recover(_request, _response, name, sequence, body):
        assert name == "order-intake" and sequence == 7
        assert body.expected_generation == "d" * 64
        assert body.expected_fields_sha256 == "a" * 64
        assert body.expected_decision_sha256 == "b" * 64
        current["calls"] += 1
        current["pending"] = False
        return {"sequence": 7, "do_not_run": True, "decision_sha256": "b" * 64}

    def receipt(_request, _response, name, sequence):
        if not current["owner"] or name != "order-intake" or sequence != 7:
            raise HTTPException(404, "not owned")
        if current["damaged"]:
            raise HTTPException(503, "unverifiable")
        if current["pending"]:
            raise HTTPException(503, "marker is still held")
        return {"sequence": 7, "binding_revision": "d" * 64,
                "fields_sha256": "a" * 64, "decision_sha256": current["receipt_hash"],
                "do_not_run": True}

    monkeypatch.setattr(forms.native, "waiting_form_submissions", waiting)
    monkeypatch.setattr(forms.native, "recover_form_submission_decision", recover)
    monkeypatch.setattr(forms.native, "form_submission_decision_receipt", receipt)
    monkeypatch.setattr(forms, "context_for", lambda _request: "owner-workspace")
    monkeypatch.setattr(ops, "_same_origin", lambda _request: None)
    monkeypatch.setattr(ops, "_gate", lambda _request: None)
    monkeypatch.setattr(ops, "_context", lambda _request: "c" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in forms.entries()})
    app = FastAPI()
    app.include_router(ops.router)
    return TestClient(app, base_url="http://127.0.0.1"), current


def test_exact_held_decision_requires_review_and_runs_native_recovery_once(monkeypatch):
    client, current = _harness(monkeypatch)
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": "/automations", "selection": SELECTION}).json()
        item = catalog["operations"][0]
        assert item["id"] == "learning.form_decision_recovery" and item["available"]
        review = client.post(BASE + "/prepare", json={"page": "/automations", "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"],
            "arguments": {}})
        assert review.status_code == 200
        assert review.json()["read_only"] is False
        assert "PO-17" in str(review.json()["changes"])
        token = review.json()["token"]
        denied = client.post(BASE + "/execute", json={"token": token, "confirmed": False})
        assert denied.status_code == 400 and current["calls"] == 0
        done = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert done.status_code == 200 and done.json()["status"] == "confirmed"
        assert current["calls"] == 1
        # The decision has left the waiting page, as it does after the cursor
        # advances. The exact signed receipt still proves the lost response.
        again = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert again.status_code == 200 and again.json()["status"] == "replayed"
        assert current["calls"] == 1


def test_lost_response_never_replays_a_changed_or_unverifiable_receipt(monkeypatch):
    client, current = _harness(monkeypatch)
    with client:
        catalog = client.post(BASE + "/catalog", json={"page": "/automations", "selection": SELECTION}).json()
        item = catalog["operations"][0]
        prepared = client.post(BASE + "/prepare", json={"page": "/automations", "selection": SELECTION,
            "operation": item["id"], "context": catalog["context"], "revision": item["revision"],
            "arguments": {}}).json()
        token = prepared["token"]
        current["pending"] = False
        current["receipt_hash"] = "9" * 64
        changed = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert changed.status_code == 409 and current["calls"] == 0
        current["damaged"] = True
        damaged = client.post(BASE + "/execute", json={"token": token, "confirmed": True})
        assert damaged.status_code == 503 and current["calls"] == 0


def test_unowned_or_unselected_recovery_is_not_advertised(monkeypatch):
    client, current = _harness(monkeypatch)
    with client:
        empty = client.post(BASE + "/catalog", json={"page": "/automations", "selection": {}}).json()
        assert empty["operations"] == []
        current["owner"] = False
        hidden = client.post(BASE + "/catalog", json={"page": "/automations", "selection": SELECTION}).json()
        assert hidden["operations"] == []
