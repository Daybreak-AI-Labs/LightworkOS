"""POST /api/v1/skills/create — author a skill from the dashboard form. Shares
the MAVERICK_ALLOW_SKILL_INSTALL opt-in with install; writes to the skills dir."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

_GOOD = {
    "name": "Weekly Status Rollup",
    "instructions": "# What this does\n\nSummarize the week.\n\n# Steps\n1. Gather.\n2. Write.",
    "triggers": ["weekly status", "status rollup"],
    "tools_needed": ["read_file"],
}


def _skills_dir(tmp_path, monkeypatch):
    from maverick import skills
    monkeypatch.setattr(skills, "SKILLS_DIR", tmp_path / "skills")


def test_create_requires_opt_in(tmp_path, monkeypatch):
    _skills_dir(tmp_path, monkeypatch)
    monkeypatch.delenv("MAVERICK_ALLOW_SKILL_INSTALL", raising=False)
    r = client.post("/api/v1/skills/create", json=_GOOD)
    assert r.status_code == 403


def test_create_writes_skill_when_opted_in(tmp_path, monkeypatch):
    _skills_dir(tmp_path, monkeypatch)
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    r = client.post("/api/v1/skills/create", json=_GOOD)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "weekly-status-rollup"          # kebab id
    assert "weekly status" in body["triggers"]
    assert (tmp_path / "skills" / "weekly-status-rollup.md").exists()


def test_create_rejects_missing_trigger(tmp_path, monkeypatch):
    _skills_dir(tmp_path, monkeypatch)
    monkeypatch.setenv("MAVERICK_ALLOW_SKILL_INSTALL", "1")
    bad = dict(_GOOD, triggers=[])
    r = client.post("/api/v1/skills/create", json=bad)
    assert r.status_code == 422
