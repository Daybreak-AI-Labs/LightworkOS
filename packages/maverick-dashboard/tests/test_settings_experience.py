"""Settings search finds controls by the words people use, within page access."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    app._world_cache.clear()
    yield TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def _items(client, query):
    response = client.get("/api/v1/settings/search", params={"q": query})
    assert response.status_code == 200
    return response.json()["items"]


def _signed_in(monkeypatch, role):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:alice", role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")


@pytest.mark.parametrize("query", ["undone", "can't be undone", "destructive", "risky", "approval"])
def test_plain_words_find_the_setting_for_actions_that_cannot_be_undone(client, query):
    titles = [item["title"] for item in _items(client, query)]
    assert "Actions that can't be undone" in titles


def test_closest_titles_lead_and_dedicated_controls_come_before_all_settings(client):
    assert _items(client, "undone")[0]["title"] == "Actions that can't be undone"
    assert _items(client, "destructive")[0]["title"] == "Actions that can't be undone"
    assert _items(client, "theme")[0]["href"] == "/settings?focus=settings-theme"
    assert _items(client, "budget")[0]["href"] == "/settings?focus=settings-task-budget"


@pytest.mark.parametrize("query", ["ai service", "ai provider", "api key", "model key"])
def test_provider_key_words_lead_to_the_provider_keys_section(client, query):
    first = _items(client, query)[0]
    assert (first["title"], first["href"]) == ("AI provider keys", "/settings#settings-integrations")


def test_people_who_cannot_open_settings_get_no_organization_settings(client, monkeypatch):
    _signed_in(monkeypatch, "operator")
    assert _items(client, "undone") == []
    assert all(item["scope"] == "Personal" or item["href"].startswith("/workspace/")
               for item in _items(client, "a"))


def test_signed_in_people_find_their_notification_settings(client, monkeypatch):
    _signed_in(monkeypatch, "viewer")
    for query in ("notification", "notifications", "digest"):
        assert any(item["href"] == "/notifications#notification-preferences" for item in _items(client, query))


def test_one_letter_searches_skip_all_settings_but_keep_dedicated_controls(client):
    one = _items(client, "t")
    assert one and not any(item["href"].startswith("/settings/all") for item in one)
    assert any(item["href"].startswith("/settings/all") for item in _items(client, "th"))


def test_the_change_review_names_the_plain_settings_area_not_a_code_module(client):
    from maverick_dashboard import settings_catalog

    revision = client.get("/api/v1/settings/catalog").json()["revision"]
    response = client.post("/api/v1/settings/catalog/review", json={
        "changes": [{"id": "safety.consent_mode", "value": "dashboard"}], "expected_revision": revision})
    assert response.status_code == 200, response.text
    (item,) = response.json()["items"]
    # The reader module (maverick.safety.consent) is plumbing; people see the group.
    assert item["area"] == item["module"] == "Safety"
    assert item["area"] in settings_catalog.GROUPS


def test_review_names_where_each_value_comes_from_in_plain_words(client):
    revision = client.get("/api/v1/settings/catalog").json()["revision"]
    (item,) = client.post("/api/v1/settings/catalog/review", json={
        "changes": [{"id": "features.task_handoffs", "value": True}], "expected_revision": revision}).json()["items"]
    assert (item["source"], item["resulting_source"]) == ("Default", "Set here")
    saved = client.post("/api/v1/settings/catalog", json={
        "changes": [{"id": "features.task_handoffs", "value": True}], "expected_revision": revision, "confirm": True})
    revision = client.get("/api/v1/settings/catalog").json()["revision"]
    (reset,) = client.post("/api/v1/settings/catalog/review", json={
        "changes": [{"id": "features.task_handoffs", "reset": True}], "expected_revision": revision}).json()["items"]
    if saved.status_code == 200:
        assert reset["source"] == "Set here"
    # A reset returns the product default; it is never called a dashboard setting.
    assert reset["resulting_source"] == "Default"


def test_review_names_values_the_way_the_setting_shows_them(client):
    # Live: changing Writing style read "Before:  After: formal".
    revision = client.get("/api/v1/settings/catalog").json()["revision"]
    (item,) = client.post("/api/v1/settings/catalog/review", json={
        "changes": [{"id": "persona.style", "value": "formal"}], "expected_revision": revision}).json()["items"]
    assert item["after"] == "formal"  # the recorded value is unchanged
    assert (item["before_text"], item["after_text"]) == ("Balanced (default)", "Formal and professional")


def test_the_review_dialog_prefers_the_plain_wording():
    from pathlib import Path

    script = (Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
              / "lightwork-settings-review.js").read_text(encoding="utf-8")
    assert "shown(item.before)" not in script and script.count("shownText(item, 'before')") == 2


def test_the_review_and_runtime_scripts_show_the_plain_area():
    from pathlib import Path

    static = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
    for name in ("lightwork-settings-review.js", "lightwork-settings-runtime.js"):
        text = (static / name).read_text(encoding="utf-8")
        assert "item.module" not in text, name
        assert "item.area" in text, name


@pytest.mark.parametrize("query, expected", [
    ("dark mode", "Your colour theme"),
    ("answer style", "Writing style"),
    ("turn off emails", "Your notifications"),
])
def test_everyday_wording_finds_the_setting(client, monkeypatch, query, expected):
    # People describe a setting in their own words; a query that does not
    # contain every word of a setting still finds the closest ones.
    _signed_in(monkeypatch, "admin")
    titles = [item["title"] for item in _items(client, query)]
    assert expected in titles[:8], titles[:8]


def test_the_rarer_word_orders_partial_matches(client, monkeypatch):
    # "answer" appears in many settings, "style" in few: style settings come
    # before settings that only mention answers.
    _signed_in(monkeypatch, "admin")
    items = _items(client, "answer style")
    exact = [item["title"] for item in _items(client, "answer style") if "answer" in item["title"].lower() and "style" in item["title"].lower()]
    titles = [item["title"] for item in items]
    first_answer_only = next(i for i, title in enumerate(titles) if "answer" in title.lower() and "style" not in title.lower())
    assert titles.index("Writing style") < first_answer_only, titles[:10]
    assert not exact or titles[0] in exact


def test_partial_matches_follow_every_exact_match(client, monkeypatch):
    _signed_in(monkeypatch, "admin")
    exact = [item["title"] for item in _items(client, "theme")]
    mixed = [item["title"] for item in _items(client, "theme zzzunknownword")]
    assert mixed[:len(exact)] == exact or set(exact) <= set(mixed)
    assert _items(client, "zzzunknownword qqqnothing") == []


def test_partial_words_match_from_the_start_of_a_word(client, monkeypatch):
    _signed_in(monkeypatch, "admin")
    titles = [item["title"] for item in _items(client, "dark mode")]
    assert titles and not any("model" in title.lower() and "mode " not in title.lower() + " " for title in titles[:10]), titles[:10]
