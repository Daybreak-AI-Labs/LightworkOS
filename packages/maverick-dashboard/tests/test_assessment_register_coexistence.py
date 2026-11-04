"""Running one agent (capability) assessment must not break the audit binder,
the finance board or the question analytics.

The capability-review register is saved as ``assessments/register.json``, in
the same directory as the per-subject questionnaire records. The metrics that
feed those screens iterate that directory, and must not raise on the register
file, or the first agent assessment would turn all four screens into a 500."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

_SCREENS = (
    "/audit/binder",
    "/api/v1/audit/binder",
    "/api/v1/finance/board",
    "/api/v1/assess/question-roi?type=dpia",
)

_SURFACE = {
    "kind": "agent", "subject": "calm_bot", "description": "reads and summarizes",
    "allow_tools": ["read_file"], "deny_tools": [], "max_risk": "low",
    "allow_paths": [], "allow_hosts": [], "mcp_servers": [],
    "knowledge_sources": [], "has_human_gate": True, "steps": 1,
}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    from maverick import world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _client() -> TestClient:
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_governance_screens_survive_a_capability_assessment(monkeypatch):
    from maverick import assessments
    from maverick.assessment import AssessmentSession, decide_assessment, save_session
    from maverick.paths import data_dir

    monkeypatch.setattr(assessments, "subject_surface", lambda kind, name: dict(_SURFACE))
    session = AssessmentSession(type="dpia", subject="Payroll")
    save_session(session)
    decide_assessment(session.id, "approved", decided_by="dpo")
    client = _client()

    for path in _SCREENS:
        assert client.get(path).status_code == 200, f"{path} before the assessment"

    refreshed = client.post(
        "/api/v1/assessments/agent/calm_bot/refresh", json={"expected_revision": 0},
    )
    assert refreshed.status_code == 200
    assert data_dir("assessments", "register.json").exists()

    for path in _SCREENS:
        assert client.get(path).status_code == 200, f"{path} after the assessment"
    roi = client.get("/api/v1/assess/question-roi?type=dpia").json()
    assert roi["assessed"] == 1
