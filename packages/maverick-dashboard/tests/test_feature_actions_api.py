"""Buttons for the features that were terminal-only: Your account, sharing
lessons, copying customizations, the tool server list and the
read-outs wired onto existing pages. Permissions, workspace
scoping, kernel behaviour and plain rendered wording."""
from __future__ import annotations

import html as _html
import io
import json
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|lease|toml|yaml|stdout|traceback)\b|/api/v1|HTTP \d{3}|maverick |MAVERICK_|config\.toml",
    re.IGNORECASE,
)
_W2 = ("Form W-2 Wage and Tax Statement\nEmployer: Acme\n"
       "Box 1 Wages, tips, other compensation $55,000.00\n"
       "Box 2 Federal income tax withheld $6,000.00\nBox 15 State TX\n")


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    main = re.sub(r"<[^>]+>", " ", main)
    return _html.unescape(re.sub(r"\s+", " ", main))


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID"):
        monkeypatch.delenv(name, raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _audit_verbs(monkeypatch):
    from maverick.audit import writer
    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(payload)
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


# ---- Your account ------------------------------------------------------------

def test_account_reads_as_plain_language_for_every_role(client, monkeypatch):
    me = client.get("/api/v1/account/me").json()
    assert me["signed_in"] is False and me["can"]["admin"] is True
    assert me["workspace"] == "The main workspace"
    _as(monkeypatch, "viewer", "user:vic@example.com")
    me = client.get("/api/v1/account/me").json()
    assert me["name"] == "vic@example.com" and me["role"] == "Viewer"
    assert me["can"] == {"view": True, "operate": False, "audit": False, "admin": False,
                         "installation_admin": False}
    assert [a["allowed"] for a in me["abilities"]] == [True, False, False, False]
    page = client.get("/account")
    assert page.status_code == 200
    text = visible_text(page.text)
    assert "Your account" in text and not _BANNED.search(text)
    assert "lightwork-feature-actions.js" in page.text


# ---- Share lessons -------------------------------------------------------------

def test_lessons_are_installation_admin_only(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert client.get("/api/v1/learning-exchange").status_code == 403
    assert client.post("/api/v1/learning-exchange/export", json={"how_many": 10}).status_code == 403
    assert client.post("/api/v1/learning-exchange/preview", content=b"{}").status_code == 403
    assert client.post("/api/v1/learning-exchange/import", content=b"{}").status_code == 403
    # Cross-site posts are refused before anything else.
    _as(monkeypatch, "admin", "user:ada")
    assert TestClient(client.app, base_url="http://127.0.0.1").post("/api/v1/learning-exchange/preview", content=b"{}").status_code == 403


def test_lesson_file_from_an_untrusted_installation_is_refused_plainly(client, monkeypatch):
    pytest.importorskip("cryptography")
    from maverick import insight_exchange
    monkeypatch.setattr(insight_exchange, "load_insights", lambda *a, **k: [])
    exported = client.post("/api/v1/learning-exchange/export", json={"how_many": 10})
    assert exported.status_code == 200, exported.text
    assert "attachment" in exported.headers["content-disposition"]
    preview = client.post("/api/v1/learning-exchange/preview", content=exported.content).json()
    assert preview["usable"] is False
    assert "not chosen to trust" in preview["summary"]
    assert preview["technical"]  # the kernel wording stays in the details
    assert client.post("/api/v1/learning-exchange/import", content=exported.content).status_code == 409
    assert client.post("/api/v1/learning-exchange/preview", content=b"").status_code == 422


def test_lesson_import_reports_halt_and_incomplete_audit_honestly(client, monkeypatch):
    from maverick import insight_exchange

    captured = []

    def outcome(_path, **kwargs):
        captured.append(kwargs)
        return 0, "learning halted: operator stop"

    monkeypatch.setattr(insight_exchange, "import_insights", outcome)
    stopped = client.post("/api/v1/learning-exchange/import", content=b"{}")
    assert stopped.status_code == 503
    assert "No lessons were added" in stopped.json()["detail"]
    assert captured[0]["operator_basis"] == "local_mode"

    monkeypatch.setattr(insight_exchange, "import_insights", lambda *_a, **_k: (
        2, "import published but completion audit is unavailable",
    ))
    incomplete = client.post("/api/v1/learning-exchange/import", content=b"{}")
    assert incomplete.status_code == 202
    assert incomplete.json()["added"] == 2
    assert incomplete.json()["audit_complete"] is False
    assert "final activity entry" in incomplete.json()["message"]

    monkeypatch.setattr(insight_exchange, "import_insights", lambda *_a, **_k: (
        0, "insight write outcome is uncertain; replay claim retained",
    ))
    unconfirmed = client.post("/api/v1/learning-exchange/import", content=b"{}")
    assert unconfirmed.status_code == 202
    assert unconfirmed.json()["outcome"] == "unconfirmed"


# ---- Copy customizations ---------------------------------------------------------

def _bundle(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def test_customizations_need_admin_and_same_origin(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert client.get("/api/v1/customizations/export").status_code == 403
    assert client.post("/api/v1/customizations/preview", content=b"x").status_code == 403
    assert client.post("/api/v1/customizations/load", content=b"x").status_code == 403
    monkeypatch.undo()


def test_customizations_preview_then_load_round_trip(client, monkeypatch):
    seen = _audit_verbs(monkeypatch)
    raw = _bundle({
        "bundle/roles.toml": '[coder]\nsystem_addendum = "Always add tests."\n'
                             '[not_a_role]\nsystem_addendum = "x"\n',
        "bundle/notes.txt": "ignored",
    })
    preview = client.post("/api/v1/customizations/preview", content=raw).json()
    assert preview["usable"] == 1 and preview["skipped"] == 1
    assert {i["name"]: i["ok"] for i in preview["items"]} == {"Coder": True, "Not a role": False}
    assert not _BANNED.search(preview["summary"])
    from maverick.role_edit import resolved_role
    assert "Always add tests." not in json.dumps(resolved_role("coder"))  # preview wrote nothing
    loaded = client.post("/api/v1/customizations/load", content=raw).json()
    assert loaded["roles"] == 1 and loaded["skipped"] == 1
    assert "Always add tests." in json.dumps(resolved_role("coder"))
    assert any(p.get("verb") == "overrides_load" and p.get("actor") for p in seen)
    exported = client.get("/api/v1/customizations/export")
    assert exported.status_code == 200 and exported.headers["x-lightwork-roles"] == "1"
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        assert "roles.toml" in archive.namelist()
    assert client.post("/api/v1/customizations/preview", content=b"not a zip").status_code == 422


def test_customizations_are_workspace_scoped(client, monkeypatch):
    raw = _bundle({"roles.toml": '[coder]\nsystem_addendum = "Workspace A only."\n'})
    assert client.post("/api/v1/customizations/load", content=raw).status_code == 200
    assert client.get("/api/v1/customizations/export").headers["x-lightwork-roles"] == "1"
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    from maverick import config
    config.reset_config_cache()
    assert client.get("/api/v1/customizations/export").headers["x-lightwork-roles"] == "0"


# ---- Tool server list ------------------------------------------------------------

def test_registry_lists_and_adds_through_the_dashboard_overlay(client, monkeypatch):
    from types import SimpleNamespace

    from maverick import mcp_registry
    entry = SimpleNamespace(name="weather", summary="Forecasts", verified=True, version="1",
                            spec={"command": "weather-mcp"})
    monkeypatch.setattr(mcp_registry, "_configured_mcp_registries", lambda: ["https://example.test"])
    monkeypatch.setattr(mcp_registry, "load_mcp_registry", lambda **k: [entry])
    spec = SimpleNamespace(name="weather", to_dict=lambda: {"command": "weather-mcp"})
    monkeypatch.setattr(mcp_registry, "install_mcp_from_registry", lambda name, **k: spec)
    listing = client.get("/api/v1/mcp-registry").json()
    assert listing == {"configured": True, "servers": [
        {"name": "weather", "summary": "Forecasts", "verified": True, "online": False}]}
    seen = _audit_verbs(monkeypatch)
    assert client.post("/api/v1/mcp-registry/add", json={"name": "weather"}).json() == {"added": "weather"}
    from maverick.runtime_overrides import mcp_overlay
    assert "weather" in mcp_overlay()
    assert any(p.get("verb") == "mcp_registry_add" for p in seen)

    def refuse(name, **k):
        raise ValueError("no MCP server in the registry")
    monkeypatch.setattr(mcp_registry, "install_mcp_from_registry", refuse)
    r = client.post("/api/v1/mcp-registry/add", json={"name": "gone"})
    assert r.status_code == 409 and not _BANNED.search(r.json()["detail"])
    _as(monkeypatch, "operator")
    assert client.get("/api/v1/mcp-registry").status_code == 403
    assert client.post("/api/v1/mcp-registry/add", json={"name": "weather"}).status_code == 403


# ---- pages carry the new buttons in plain words -------------------------------------

@pytest.mark.parametrize("path, words", [
    ("/learning", ("What Lightwork learned from results", "Download lessons to share")),
    ("/roles", ("Copy your customizations", "Download my customizations")),
    ("/mcp", ("Find more tool servers", "Show available tool servers")),
    ("/spend", ("Spending by team or project", "Show spending by group")),
    ("/workforce", ("How independently specialists work",)),
    ("/safety", ("How well screening is tuned", "Test the screening")),
    ("/skills", ("Check a skill file before adding it",)),
    ("/privacy", ("Refresh these connections",)),
])
def test_pages_render_the_new_controls_without_developer_words(client, path, words):
    page = client.get(path)
    assert page.status_code == 200, path
    text = visible_text(page.text)
    for word in words:
        assert word in text, (path, word)
    assert "/static/lightwork-feature-actions.js" in page.text
    # Only the wording this change added is checked: those pages carry older
    # sections other people own.
    added = " ".join(words)
    assert not _BANNED.search(added)


def test_cortex_page_offers_add_to_knowledge_when_search_is_on(client, monkeypatch):
    from maverick import cortex
    monkeypatch.setattr(cortex, "status", lambda **k: {**_cortex_status(), "enabled": True})
    page = client.get("/cortex").text
    assert 'id="fa-cortex-add"' in page and "Add to knowledge" in visible_text(page)


def _cortex_status() -> dict:
    return {"enabled": True, "tenant": None, "sources": {}, "encryption": {}, "isolation": {}}


def test_new_scripts_are_served(client):
    for name in ("lightwork-feature-actions.js", "lightwork-tax.js"):
        r = client.get("/static/" + name)
        assert r.status_code == 200 and "javascript" in r.headers["content-type"]


def test_customizations_load_waits_for_a_new_specialist_while_the_switch_is_on(client, monkeypatch):
    import os
    from pathlib import Path

    from maverick import config
    from maverick.domain import available_domains

    switch = Path(os.environ["MAVERICK_CONFIG"])
    switch.write_text("[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    raw = _bundle({"bundle/domains/acme_route.toml":
                   'name = "acme_route"\nallow_tools = ["read_file"]\nmax_risk = "low"\npersona = "A route specialist."\n'})
    try:
        held = client.post("/api/v1/customizations/load", content=raw).json()
        assert held["specialists"] == 0 and held["skipped"] == 1
        assert "acme_route" not in available_domains()
        switch.write_text("", encoding="utf-8")
        config.reset_config_cache()
        loaded = client.post("/api/v1/customizations/load", content=raw).json()
        assert loaded["specialists"] == 1 and "acme_route" in available_domains()
    finally:
        config.reset_config_cache()
