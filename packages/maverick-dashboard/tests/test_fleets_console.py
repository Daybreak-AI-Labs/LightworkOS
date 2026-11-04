"""Operator console (/fleets) — the EU AI Act Art 14 human-oversight UI.

Hermetic, like the other dashboard tests: OIDC off (``require_principal``
returns None by default), HOME + MAVERICK_HOME isolated to a tmp_path so fleets
and the audit log land in the temp dir, and the WorldModel points at a fresh DB.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _owner_client(monkeypatch):
    from maverick.oidc import VerifiedPrincipal
    from maverick_dashboard import auth, rbac
    from maverick_dashboard.app import app

    rbac.set_role("user:dana", "operator")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kwargs: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token}))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer dana"})


def _isolate(monkeypatch, tmp_path):
    # Fleets + audit log resolve under MAVERICK_HOME; the dashboard WorldModel
    # (used for the pending-approval count) resolves DEFAULT_DB.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _save_fleet(name="acme", owner="user:dana"):
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    fleet = Fleet(
        name=name,
        owner=owner,
        agents=(
            FleetAgent("researcher", "researcher", "digs through sources"),
            FleetAgent("coder", "coder"),
        ),
    )
    return save_fleet(fleet)


def test_fleets_page_lists_a_saved_fleet(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    r = _owner_client(monkeypatch).get("/fleets")
    assert r.status_code == 200
    text = r.text
    # Fleet name, owner, and each agent (name + role) are rendered.
    assert "acme" in text
    assert "dana" in text                       # owner shown as a name
    assert "Researcher" in text                 # roles shown as job titles
    assert "Coder" in text
    assert 'id="team-acme"' in text  # deployment links target the exact team
    from test_support.plain_language import developer_terms
    assert developer_terms(text) == []


def test_fleets_empty_state_shows_create_hint(monkeypatch, tmp_path):
    # Everything is managed in-app: the empty state points at the on-page
    # create form, never at a CLI command.
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/fleets")
    assert r.status_code == 200
    assert "Create a team" in r.text
    assert "maverick fleet" not in r.text


def test_fleets_page_reachable(monkeypatch, tmp_path):
    # The Teams destination keeps its existing /fleets URL for saved links.
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/fleets")
    assert r.status_code == 200
    # Shared hero h1 (page-title + hero-title classes) carries the page name.
    assert ">Teams</h1>" in r.text


def test_recent_oversight_panel_shows_governance_holds(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    # A governance verdict the kernel records when it parks/blocks an action.
    from maverick.audit import record
    record(
        "governance_denied",
        agent="acme.coder",
        tool="shell",
        rule="require_human_actions",
        reason="'shell' requires human approval",
    )
    r = _client().get("/fleets")
    assert r.status_code == 200
    text = r.text
    assert "recent decisions by your company rules" in text.lower()
    assert "Shell" not in text
    assert "requires human approval" not in text
    assert "Require human actions" in text
    # Links the operator to the pending-approval (Art 14) queue.
    assert 'href="/approvals"' in text


def test_governance_hold_gets_source_label_on_approvals(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    # A governance REQUIRE_HUMAN hold: parked with trusted provenance metadata.
    w.create_approval(
        "shell", risk="high", detail="policy requires operator review",
        provenance="governance",
    )
    # An ordinary high-risk consent hold can contain spoofed governance phrasing
    # in its untrusted detail, but that must not drive the source badge.
    w.create_approval(
        "rm-rf", risk="high", scope="/tmp/build",
        detail="requires human approval before cleanup",
    )
    r = _client().get("/approvals")
    assert r.status_code == 200
    text = r.text
    # The trusted governance hold is labelled so an operator can tell it apart,
    # and the spoofed ordinary hold does not create a second Art-14 badge.
    assert text.count("Required human oversight (EU AI Act)") == 1
    assert text.count('class="muted">An agent asked for permission</span>') == 1
    # Both holds still render in the queue (shell reads as its plain step words).
    assert "Run a command" in text
    assert "Rm rf" in text


def test_api_fleets_returns_roster(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    body = _owner_client(monkeypatch).get("/api/v1/fleets").json()
    assert len(body["fleets"]) == 1
    f = body["fleets"][0]
    assert f["name"] == "acme"
    assert f["owner"] == "user:dana"
    assert {a["name"] for a in f["agents"]} == {"researcher", "coder"}


def test_api_fleets_empty(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    body = _client().get("/api/v1/fleets").json()
    assert body == {"fleets": []}
