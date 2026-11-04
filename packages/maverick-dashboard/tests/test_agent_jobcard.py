"""The Agent Manager card endpoint: JD + scorecard + cost tier in one call,
and the settable model cost-tier table."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _some_agent() -> str:
    from maverick.domain_edit import list_agents
    agents = list_agents()
    # A finance specialist exists in the shipped catalog; fall back to the first.
    for a in agents:
        if a["name"] == "finance_ap":
            return "finance_ap"
    return agents[0]["name"]


def test_jobcard_unifies_jd_scorecard_and_cost_tier():
    name = _some_agent()
    r = client.get(f"/api/v1/agents/{name}/jobcard")
    assert r.status_code == 200, r.text
    body = r.json()
    jd = body["job_description"]
    assert jd["name"] == name
    # A real specialist declares a mission and (usually) tools/guardrails.
    assert "mission" in jd and "responsibilities" in jd
    assert isinstance(jd["tools"], list) and isinstance(jd["guardrails"], list)
    # Scorecard is present (empty is fine on a fresh world).
    sc = body["scorecard"]
    assert sc["agent"] == name and sc["runs"] == 0
    # Cost tier reflects the agent's configured model, banded.
    ct = body["cost_tier"]
    assert ct["band"] in ("low", "medium", "high", "very_high")
    assert ct["label"] in ("Low", "Medium", "High", "Very High")


def test_jobcard_404_for_unknown_agent():
    assert client.get("/api/v1/agents/not_a_real_agent/jobcard"
                      ).status_code == 404


def test_jobcard_uses_configured_runtime_override_not_pack_declaration(monkeypatch):
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai_compatible:fake-model")
    response = client.get(f"/api/v1/agents/{_some_agent()}/jobcard")
    assert response.status_code == 200
    assert response.json()["cost_tier"]["model"] == "openai_compatible:fake-model"
    assert response.json()["cost_tier"]["band"] is None
    assert response.json()["cost_tier"]["label"] == "Unknown"


def test_jobcard_page_names_approval_evidence_and_global_cost_band():
    page = client.get(f"/agents?name={_some_agent()}")
    assert page.status_code == 200
    assert "Approved results" in page.text
    assert "Cost band for this model across Lightwork" in page.text
    assert "Value delivered" not in page.text


def test_cost_tier_table_and_set_roundtrip():
    listing = client.get("/api/v1/model-cost-tiers").json()
    assert listing["bands"] == ["low", "medium", "high", "very_high"]
    opus = next(m for m in listing["models"]
                if m["model"] == "claude-opus-4-8")
    assert opus["band"] == "very_high" and opus["overridden"] is False
    # Set Opus to Low (admin, auth-off in tests) — override wins.
    r = client.post("/api/v1/model-cost-tiers",
                    json={"model": "claude-opus-4-8", "band": "low"})
    assert r.status_code == 200 and r.json()["band"] == "low"
    assert r.json()["overridden"] is True
    # Clearing (band=null) reverts to the derived very_high.
    r = client.post("/api/v1/model-cost-tiers",
                    json={"model": "claude-opus-4-8", "band": None})
    assert r.json()["band"] == "very_high" and r.json()["overridden"] is False
    # A bad band is a 422.
    assert client.post("/api/v1/model-cost-tiers",
                       json={"model": "x", "band": "cheap"}).status_code == 422
