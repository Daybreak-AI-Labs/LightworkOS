"""Collaborative supervision API: claim/release/attribution on approvals."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import app as app_mod
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    yield


def _park():
    from maverick.approval_cards import build_approval_card, encode_approval_detail

    card = build_approval_card(
        action="wire_transfer",
        summary="Review the exact transfer",
        target_label="Reviewed account",
        target={"account": "acct"},
        parameters={"amount": "$5k"},
        parameter_summary=["Transfer the reviewed amount once"],
        actor="operator",
        workspace="local",
        role="operator",
        authority_versions={"role_revision": "local-v1"},
        input_versions={"request_revision": "request-v1"},
        credential_versions={},
        budget={"currency": "USD", "maximum": "5000"},
        expires_at=time.time() + 300,
        known_effects=["Funds can leave the reviewed account."],
        unresolved_assumptions=[],
        before="The transfer is pending.",
        after="The reviewed transfer may be submitted.",
        irreversible=True,
    )
    approval_id = app_mod._world().create_approval(
        "wire_transfer",
        risk="high",
        scope="acct",
        detail=encode_approval_detail(card),
    )
    return approval_id, card["binding_sha256"]


def test_claim_release_roundtrip():
    aid, _ = _park()
    r = client.post(f"/api/v1/approvals/{aid}/claim")
    assert r.status_code == 200 and r.json() == {"claimed_by": "operator"}
    listing = client.get("/api/v1/approvals").json()["approvals"]
    assert listing[0]["claimed_by"] == "operator"
    assert client.post(f"/api/v1/approvals/{aid}/release").json() == {"released": True}
    assert client.get("/api/v1/approvals").json()["approvals"][0]["claimed_by"] is None


def test_conflicting_claim_409(monkeypatch):
    aid, _ = _park()
    app_mod._world().claim_approval(aid, "alice")
    r = client.post(f"/api/v1/approvals/{aid}/claim")
    assert r.status_code == 409 and "alice" in r.json()["detail"]
    # Release without holding -> 409 too.
    assert client.post(f"/api/v1/approvals/{aid}/release").status_code == 409


def test_decide_records_supervisor():
    aid, binding = _park()
    assert client.post(
        f"/api/v1/approvals/{aid}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={"X-Lightwork-Approval-Binding": binding},
    ).status_code == 204
    a = app_mod._world().get_approval(aid)
    assert a.status == "approved" and a.decided_by == "operator"


def test_unknown_approval_404():
    assert client.post("/api/v1/approvals/424242/claim").status_code == 404
