"""Copilot uses the reviewed suggested-skill service, never its own write path."""
from contextlib import nullcontext

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard import product_operations as ops
from maverick_dashboard import product_operations_skills as suggested

BASE = "/api/v1/copilot/product-operations"


def _harness(monkeypatch):
    row = {"name": "renewal-timing", "triggers": ["review customer renewals"],
           "tools": [], "instructions": "# Steps\n1. Check the date with the account owner.",
           "source_tasks": [17], "fingerprint": "a" * 64, "ok": True,
           "problems": [], "suggestions": []}
    state = {"suggestions": [row], "added": [], "can_add": True,
             "blocked": "", "allowed": True, "calls": []}
    codec = Fernet(Fernet.generate_key())
    monkeypatch.setattr(ops, "_same_origin", lambda request: None)
    monkeypatch.setattr(ops, "_gate", lambda request: None)
    # The status-only gate is bypassed too: this harness exercises the adapters.
    monkeypatch.setattr(ops, "_read_gate", lambda request: None)
    monkeypatch.setattr(ops, "_context", lambda request: "c" * 64)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in suggested.entries()})
    monkeypatch.setattr(ops.crypto_at_rest, "seal_to_str", lambda value: "sealed:" + codec.encrypt(value.encode()).decode())
    monkeypatch.setattr(ops.crypto_at_rest, "is_sealed_str", lambda value: value.startswith("sealed:"))
    monkeypatch.setattr(ops.crypto_at_rest, "unseal_from_str", lambda value: codec.decrypt(value[7:].encode()).decode())
    from maverick import authority_effects
    monkeypatch.setattr(authority_effects, "authority_effect_fence", nullcontext)
    monkeypatch.setattr(suggested.auth, "require_permission", lambda request, permission: (
        None if state["allowed"] else (_ for _ in ()).throw(HTTPException(403, "denied"))))
    monkeypatch.setattr(suggested.native, "_learned_candidates", lambda: {
        key: value for key, value in state.items() if key in {"suggestions", "added", "can_add", "blocked"}})

    state["done"] = {}

    def prepare(request, name, action, fingerprint, publish_name=""):
        rows = state["suggestions"] if action == "admit" else state["added"]
        row = next((item for item in rows if item["name"] == name and item["fingerprint"] == fingerprint), None)
        if row is None:
            raise HTTPException(409, "This suggestion changed or is unavailable. Refresh before reviewing it.")
        return {"action": action, "name": name, "fingerprint": fingerprint, "publish_name": publish_name or name,
                "changes": [{"label": "Full instructions", "after": row.get("instructions", "")}],
                "message": "Read every instruction and its source tasks."}

    def apply(request, prepared, operation, *, expires):
        """The Skills page's reviewed custody: one effect per original request."""
        if operation in state["done"]:
            return state["done"][operation]
        if prepare(request, prepared["name"], prepared["action"], prepared["fingerprint"], prepared["publish_name"]) != prepared:
            raise HTTPException(409, "The reviewed skill or its source changed.")
        if prepared["action"] == "admit":
            state["calls"].append(("admit", prepared["name"], prepared["fingerprint"], prepared["publish_name"], True))
            state["suggestions"] = []
            state["added"] = [{"name": prepared["publish_name"], "fingerprint": "b" * 64,
                               "candidate_fingerprint": prepared["fingerprint"]}]
        else:
            state["calls"].append(("withdraw", prepared["name"], prepared["fingerprint"], True))
            state["added"] = []
        state["done"][operation] = {"operation": operation, "confirmed": True, "name": prepared["publish_name"],
                                    "message": "Your original reviewed skill was changed."}
        return state["done"][operation]

    monkeypatch.setattr(suggested.changes, "prepare", prepare)
    monkeypatch.setattr(suggested.changes, "apply", apply)
    monkeypatch.setattr(suggested.changes, "original_for_review",
                        lambda request, prepared, operation: state["done"].get(operation))

    def authority(request, context=None, **_):
        suggested.auth.require_permission(request, "admin")
        return "c" * 64
    monkeypatch.setattr(suggested.changes, "authority", authority)
    app = FastAPI()
    app.include_router(ops.router)
    return TestClient(app, base_url="http://127.0.0.1"), state


def _catalog(client):
    return client.post(BASE + "/catalog", json={"page": "/skills", "selection": {}}).json()


def _prepare(client, catalog, operation, arguments):
    entry = next(row for row in catalog["operations"] if row["id"] == operation)
    return client.post(BASE + "/prepare", json={"page": "/skills", "selection": {},
        "operation": operation, "context": catalog["context"],
        "revision": entry["revision"], "arguments": arguments})


def test_copilot_reviews_exact_candidate_then_calls_native_admit_and_withdraw(monkeypatch):
    client, state = _harness(monkeypatch)
    with client:
        catalog = _catalog(client)
        assert {row["id"] for row in catalog["operations"]} == {
            "skills.review_suggestions", "skills.admit_suggestion", "skills.withdraw_suggestion",
            "skills.read_original_change"}
        read = _prepare(client, catalog, "skills.review_suggestions", {})
        assert read.status_code == 200 and read.json()["read_only"]
        assert "Check the date" in read.json()["details"]["suggestions"][0]["instructions"]
        assert state["calls"] == []

        review = _prepare(client, catalog, "skills.admit_suggestion",
                          {"candidate": "renewal-timing", "name": "renewal-timing"})
        assert review.status_code == 200, review.text
        assert "Check the date" in str(review.json()["changes"])
        assert client.post(BASE + "/execute", json={"token": review.json()["token"],
            "confirmed": False}).status_code == 400
        assert state["calls"] == []
        done = client.post(BASE + "/execute", json={"token": review.json()["token"],
            "confirmed": True})
        assert done.status_code == 200 and done.json()["status"] == "confirmed"
        assert state["calls"] == [("admit", "renewal-timing", "a" * 64, "renewal-timing", True)]
        replay = client.post(BASE + "/execute", json={"token": review.json()["token"],
            "confirmed": True})
        assert replay.json()["status"] == "replayed" and len(state["calls"]) == 1

        current = _catalog(client)
        removal = _prepare(client, current, "skills.withdraw_suggestion", {"name": "renewal-timing"})
        assert removal.status_code == 200
        result = client.post(BASE + "/execute", json={"token": removal.json()["token"],
            "confirmed": True})
        assert result.status_code == 200 and result.json()["status"] == "confirmed"
        assert state["calls"][-1] == ("withdraw", "renewal-timing", "b" * 64, True)


def test_copilot_stale_suggestion_or_lost_admin_never_admits(monkeypatch):
    client, state = _harness(monkeypatch)
    with client:
        catalog = _catalog(client)
        review = _prepare(client, catalog, "skills.admit_suggestion",
                          {"candidate": "renewal-timing", "name": "renewal-timing"})
        token = review.json()["token"]
        state["suggestions"][0]["fingerprint"] = "d" * 64
        assert client.post(BASE + "/execute", json={"token": token, "confirmed": True}).status_code == 409
        assert state["calls"] == []
        state["allowed"] = False
        assert _catalog(client)["operations"] == []


def test_copilot_can_review_and_withdraw_a_paused_installed_suggestion(monkeypatch):
    client, state = _harness(monkeypatch)
    state["suggestions"] = []
    state["added"] = [{"name": "renewal-timing", "fingerprint": "b" * 64,
                       "candidate_fingerprint": "a" * 64, "source_shared": False,
                       "status": "Paused: source task access is unavailable."}]
    with client:
        catalog = _catalog(client)
        operation = next(row for row in catalog["operations"]
                         if row["id"] == "skills.withdraw_suggestion")
        assert "paused" in str(operation).lower()
        review = _prepare(client, catalog, "skills.withdraw_suggestion",
                          {"name": "renewal-timing"})
        assert review.status_code == 200, review.text
        assert "source task access is unavailable" in review.json()["summary"].lower()
        result = client.post(BASE + "/execute", json={"token": review.json()["token"],
            "confirmed": True})
        assert result.status_code == 200, result.text
        assert state["calls"][-1] == ("withdraw", "renewal-timing", "b" * 64, True)
