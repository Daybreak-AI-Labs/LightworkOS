"""The /workforce panels do only the work they show.

The posture call audited all 2,031 packs to count two numbers, the inventory
computed a runtime capability per pack that it never shows, and the board
assembled the Operating Record twice: about 0.3 s of server work per visit,
which the next tab waited behind when someone left the page early.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dash_app._world_cache.clear()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    dash_app._world_cache.clear()


def _count(monkeypatch, module, name):
    calls = []
    real = getattr(module, name)
    monkeypatch.setattr(module, name, lambda *a, **k: calls.append(1) or real(*a, **k))
    return calls


def test_posture_counts_without_auditing_every_pack(client, monkeypatch):
    from maverick import domain_audit
    from maverick.domain_audit import audit_roster, summarize

    audits = _count(monkeypatch, domain_audit, "audit_profile")
    body = client.get("/api/v1/workforce/posture").json()
    assert audits == []
    full = summarize(audit_roster())
    assert body["autonomy_posture"] == full["autonomy_posture"]
    assert body["packs_onboarding"] == full["packs_onboarding"]


def test_inventory_skips_the_runtime_capability_it_never_shows(client, monkeypatch):
    from maverick import domain_audit
    from maverick_dashboard import workforce_ops_api

    expected = workforce_ops_api._inventory(None)
    capabilities = _count(monkeypatch, domain_audit, "domain_capability")
    response = client.get("/api/v1/workforce-ops/inventory")
    assert response.status_code == 200 and capabilities == []
    assert response.json() == expected


def test_the_board_assembles_the_operating_record_once(client, monkeypatch):
    from maverick import operating_record, outcomes

    assemblies = _count(monkeypatch, operating_record, "assemble")
    monkeypatch.setattr(outcomes, "assemble", operating_record.assemble)
    response = client.get("/api/v1/dashboards/workforce")
    assert response.status_code == 200 and len(assemblies) == 1
