"""The Safety monitoring (Immune) and Code pages, through the real dashboard app."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import immune_console

STATIC = Path(immune_console.__file__).parent / "static" / "lightwork-immune-console.js"
TEMPLATES = Path(immune_console.__file__).parent / "templates"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    try:
        yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    finally:
        config.reset_config_cache()
        audit_writer._default = None
        audit_writer._defaults.clear()
        dash_app._world_cache.clear()


@pytest.mark.parametrize("path", ["/immune", "/code"])
def test_pages_render_accessibly_with_a_tight_csp(client, path):
    from maverick.a11y_audit import audit_html
    response = client.get(path)
    assert response.status_code == 200, response.text[:300]
    assert "style-src 'self' 'nonce-" in response.headers["content-security-policy"]
    script = "lightwork-code.js" if path == "/code" else "lightwork-immune-console.js"
    assert f'/static/{script}' in response.text
    assert audit_html(response.text) == []
    assert "<th>" not in response.text
    assert client.get(path + "?x=1").status_code == 404
    assert client.get(f"/static/{script}").status_code == 200


def test_immune_summary_is_counts_and_labels_only(client, monkeypatch):
    from maverick import ifc
    from maverick.immune import report

    monkeypatch.setattr(report, "_composition", lambda: {
        "available": True, "agents": 2, "by_kind": {"trifecta": 1}, "by_sink_risk": {},
        "trifectas": [{"path": ["a", "b"], "witness": {"sensitive": ["a", "read_file"]},
                       "sink_risk": "low"}]})
    tracker = ifc.FlowTracker(mode="block")
    tracker.observe_output("x", "sql_query", "secret payroll rows " * 5)
    d = tracker.decide("x", "email", {"body": "secret payroll rows " * 5})
    ifc.record(d, agent="x", goal_id=7, outcome="blocked")
    data = client.get("/api/v1/immune/summary").json()
    assert data["schema"] == "lightwork.immune-summary.v1"
    assert data["composition"]["by_kind"] == {"trifecta": 1}
    assert data["ifc"]["by_outcome"] == {"blocked": 1}
    assert data["ifc"]["recent"][0]["labels"] == ["data:sql_query"]
    assert data["oversight"]["available"] is True
    assert "payroll" not in json.dumps(data)
    assert client.get("/api/v1/immune/summary?x=1").status_code == 404


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_code_summary_lists_repos_and_proposals_never_code(client, monkeypatch, tmp_path):
    from maverick import config
    from maverick.codebase import features, vault
    from maverick_dashboard import app as dash_app

    assert client.get("/api/v1/code/summary").json()["enabled"] is False
    monkeypatch.setattr(config, "get_codebase",
                        lambda: {"enable": True, "default_protect": "block"})
    src = tmp_path / "src"
    src.mkdir()
    for args in (["init", "-q", "-b", "main"], ):
        subprocess.run(["git", *args], cwd=src, check=True)
    (src / "a.py").write_text("SECRET_ALGORITHM = 42\n")
    subprocess.run(["git", "add", "-A"], cwd=src, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "i"],
                   cwd=src, check=True)
    vault.register("core", str(src))
    world = dash_app._world()
    features.propose(world, "core", "Tune", "", lambda gid, work: (work / "a.py").write_text(
        "SECRET_ALGORITHM = 43\n"))
    data = client.get("/api/v1/code/summary").json()
    assert [r["name"] for r in data["repos"]] == ["core"]
    assert data["proposals"][0]["status"] == "pending" and data["proposals"][0]["files"] == 1
    assert "SECRET_ALGORITHM" not in json.dumps(data)


def test_permissions_are_enforced(monkeypatch):
    from fastapi import FastAPI, HTTPException

    def deny(request, perm):
        raise HTTPException(status_code=403, detail=perm)
    monkeypatch.setattr(immune_console, "require_permission", deny)
    app = FastAPI()
    app.include_router(immune_console.create_immune_console_router(), prefix="/api/v1")
    c = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert c.get("/api/v1/immune/summary").json()["detail"] == "audit"
    assert c.get("/api/v1/code/summary").json()["detail"] == "operate"


def test_client_never_injects_html():
    js = STATIC.read_text(encoding="utf-8") + (
        STATIC.parent / "lightwork-code.js").read_text(encoding="utf-8")
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function"):
        assert banned not in js
    from maverick.a11y_audit import audit_file
    assert audit_file(TEMPLATES / "immune.html") == []
    assert audit_file(TEMPLATES / "code.html") == []


def test_canaries_are_valid_cards_a_reviewer_can_approve(client, monkeypatch, tmp_path):
    """A canary nobody can approve can never record a miss."""
    import random
    import time

    from maverick import config
    from maverick.approval_cards import build_approval_card, encode_approval_detail
    from maverick.immune import oversight
    from maverick_dashboard import app as dash_app
    monkeypatch.setattr(config, "get_immune", lambda: {"canaries": True, "twin_record": False})
    world = dash_app._world()
    world.create_approval("wire-funds", risk="high", detail=encode_approval_detail(
        build_approval_card(
            action="wire-funds", summary="Pay $10,000.00 to ops@acme.com", target_label="acme",
            target={"v": "acme"}, parameters={"n": 1}, parameter_summary=["Pay once"],
            actor="user:alice", workspace="default", role="operator", authority_versions={},
            input_versions={}, credential_versions={}, budget={}, expires_at=time.time() + 600,
            known_effects=["Moves money."], unresolved_assumptions=[], before="Unpaid.",
            after="Paid.", irreversible=True)))
    generated = oversight.generate_canary(world, rng=random.Random(0))["approval_id"]
    manual = oversight.seed_canary(world, action="wire-funds", detail="Pay $500.00 to acct 12345678",
                                   decision_class="payments", flaw="acct changed")
    rows = {r["id"]: r for r in client.get("/api/v1/approvals").json()["approvals"]}
    for cid in (generated, manual):
        row = rows[cid]
        assert row["approval_card_status"] == "current", row
        response = client.post(f"/api/v1/approvals/{cid}/approve", json={"acknowledged": True, "confirmation": "approve"}, headers={
            "X-Lightwork-Approval-Binding": row["approval_card"]["binding_sha256"]})
        assert response.status_code in (200, 204), response.text[:300]
    assert sum(s.missed for s in oversight.score(world).values()) == 2


def test_a_vault_error_is_a_503_not_a_crash(client, monkeypatch):
    from maverick import config
    from maverick.codebase import features, vault
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True, "default_protect": "block"})

    def broken(world):
        raise vault.VaultError("git exited 128: /srv/secret/path")
    monkeypatch.setattr(features, "summary", broken)
    response = client.get("/api/v1/code/summary")
    assert response.status_code == 503 and "secret" not in response.text


def test_a_codebase_merge_approval_can_be_approved_in_the_dashboard(client):
    from maverick.codebase.features import _approval_detail
    from maverick_dashboard import app as dash_app
    p = {"id": "0123456789abcdef", "repo": "r", "title": "t", "branch": "lightwork/t-012345",
         "head": "a" * 40, "base": "b" * 40, "files": ["x.py"], "tests": None, "review": None,
         "diff_truncated": False, "diff_chars": 1}
    goal_id = dash_app._world().create_goal("Review this code change")
    from maverick.logging_config import reset_goal_context, set_goal_context
    context = set_goal_context(goal_id)
    try:
        aid = dash_app._world().create_approval(
            "codebase_merge", risk="high", scope="r", provenance="codebase",
            requested_by="agent:codebase", detail=_approval_detail(p))
    finally:
        reset_goal_context(context)
    row = {r["id"]: r for r in client.get("/api/v1/approvals").json()["approvals"]}[aid]
    assert row["approval_card_status"] == "current"
    response = client.post(f"/api/v1/approvals/{aid}/approve", json={"acknowledged": True, "confirmation": "approve"}, headers={
        "X-Lightwork-Approval-Binding": row["approval_card"]["binding_sha256"]})
    assert response.status_code in (200, 204), response.text[:300]
