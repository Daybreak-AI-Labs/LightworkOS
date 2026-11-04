"""Skill Store: plain wording, find/sort, and admin-managed catalog addresses."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.catalog.load_catalog", lambda kind, **_k: [])
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _client() -> TestClient:
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _visible(html: str) -> str:
    main = html.split('<main id="content"', 1)[-1]
    main = re.sub(r"(?s)<(script|style)\b.*?</\1>", " ", main)
    return re.sub(r"(?s)<[^>]+>", " ", main)


def test_store_empty_state_offers_next_steps_in_plain_words():
    html = _client().get("/store").text
    text = _visible(html)
    assert "No skills to show" in text
    assert 'href="/skills"' in html
    assert "Built-in catalog" in text
    for word in ("deployment", "HTTP", "catalogs]", "config.toml", "sha256", "v0"):
        assert word not in text, word


def test_admin_adds_removes_and_resets_catalogs():
    from maverick.catalog import _configured_indexes

    c = _client()
    r = c.post("/store/catalogs", data={"action": "add", "url": "https://skills.example.com/catalog/"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/store?saved=add"
    assert _configured_indexes() == ["https://skills.example.com/catalog"]
    html = c.get("/store?saved=add").text
    assert "https://skills.example.com/catalog" in html
    assert "Use the built-in catalog" in html

    r = c.post("/store/catalogs", data={"action": "add", "url": "http://insecure.example.com"},
               follow_redirects=False)
    assert r.headers["location"] == "/store?saved=bad-address"
    assert _configured_indexes() == ["https://skills.example.com/catalog"]

    r = c.post("/store/catalogs", data={"action": "reset"}, follow_redirects=False)
    assert r.status_code == 303
    from maverick.catalog import DEFAULT_INDEXES

    assert _configured_indexes() == [u.rstrip("/") for u in DEFAULT_INDEXES]


def test_catalog_changes_need_same_origin():
    from maverick_dashboard.app import app

    r = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "https://evil.example"}).post(
        "/store/catalogs", data={"action": "reset"}, follow_redirects=False)
    assert r.status_code == 403


def test_add_button_is_disabled_without_the_install_opt_in(monkeypatch):
    from types import SimpleNamespace

    entry = SimpleNamespace(name="weekly-report", to_dict=lambda: {
        "name": "weekly-report", "version": "1.0.0", "summary": "Writes the weekly report.",
        "author": "Acme", "verified": True, "install_count": 3})
    monkeypatch.setattr("maverick.catalog.load_catalog", lambda kind, **_k: [entry])
    monkeypatch.delenv("MAVERICK_ALLOW_SKILL_INSTALL", raising=False)
    html = _client().get("/store").text
    assert "Weekly report" in html and "Checked author" not in html
    assert "catalog-provided" in html
    assert re.search(r'aria-label="Add to workspace: Weekly report"\s+disabled', html)
    assert "switched off on this server" in html


def test_catalog_changes_are_recorded_with_who_made_them(monkeypatch):
    import maverick.audit as audit
    from maverick.audit import EventKind

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    c = _client()
    r = c.post("/store/catalogs",
               data={"action": "add", "url": "https://skills.example.com/c?token=abc"},
               follow_redirects=False)
    assert r.status_code == 303
    (row,) = rows
    assert row["kind"] == EventKind.SETTING_CHANGED
    assert (row["section"], row["key"]) == ("catalogs", "indexes")
    assert row["actor"]
    assert "https://skills.example.com/c" in row["new"]
    # A token inside an address is never written to the record.
    assert "token=abc" not in repr(row)
    assert row["old"] == ["built-in catalog"]
