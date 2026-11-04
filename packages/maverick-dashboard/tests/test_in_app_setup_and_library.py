"""In-app setup/library actions preserve authority, input and write boundaries."""
from concurrent.futures import ThreadPoolExecutor

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    return TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_initial_settings_create_once_and_preserve_private_configuration(client, tmp_path):
    from maverick.budget import budget_from_config
    from maverick.file_lock import private_path_is_restricted

    page = client.get("/start")
    assert page.status_code == 200
    assert "There is no spending or time limit for each task yet" in page.text
    assert "$1 limit" not in page.text
    with ThreadPoolExecutor(max_workers=2) as workers:
        responses = list(workers.map(lambda _: client.post("/api/v1/setup/initialize", json={"confirm": True}), range(2)))
    assert sorted(response.status_code for response in responses) == [201, 409]
    path = tmp_path / "config.toml"
    before = path.read_bytes()
    config = tomllib.loads(before.decode())
    assert config["budget"] == {"strict_pricing": True}
    budget = budget_from_config()
    for key in ("max_dollars", "max_wall_seconds", "max_input_tokens", "max_output_tokens", "max_tool_calls"):
        assert getattr(budget, key) is None
    assert config["capabilities"]["code_exec"] is False
    assert "shell" in config["security"]["denied_tools"]
    assert private_path_is_restricted(path)
    assert client.post("/api/v1/setup/initialize", json={"confirm": True}).status_code == 409
    assert path.read_bytes() == before
    assert client.get("/api/v1/setup/checks").json()["live_provider_verified"] is False


@pytest.mark.parametrize("payload,status", [({"confirm": False},400), ({"confirm":"yes"},422), ({"confirm":True,"path":"elsewhere"},422)])
def test_initial_settings_requires_review_and_rejects_client_paths(client, tmp_path, payload, status):
    assert client.post("/api/v1/setup/initialize", json=payload).status_code == status
    assert not (tmp_path / "config.toml").exists()


def test_invalid_overlay_is_checked_fresh_and_preserved(client, tmp_path):
    overlay = tmp_path / "dashboard-config.toml"
    overlay.write_text("[broken", encoding="utf-8")
    # The central authentication boundary rejects unreadable policy before
    # dispatching the request to the setup route.
    assert client.post("/api/v1/setup/initialize", json={"confirm":True}).status_code == 401
    assert not (tmp_path / "config.toml").exists()
    assert overlay.read_text() == "[broken"


def test_initial_settings_preserves_existing_settings_overlay(client, tmp_path):
    from maverick.budget import budget_from_config
    from maverick.config import load_config

    overlay = tmp_path / "dashboard-config.toml"
    overlay.write_text("[budget]\nmax_dollars = 0.5\n", encoding="utf-8")
    assert client.post("/api/v1/setup/initialize", json={"confirm":True}).status_code == 201
    assert load_config()["budget"]["max_dollars"] == 0.5
    assert budget_from_config().max_dollars == 0.5
    assert overlay.read_text() == "[budget]\nmax_dollars = 0.5\n"


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_only_global_admin_can_initialize_or_download_report(client, monkeypatch, tmp_path, role):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:person", role)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:person")
    assert client.post("/api/v1/setup/initialize", json={"confirm":True}).status_code == 403
    assert client.get("/api/v1/setup/checks").status_code == 403
    assert not (tmp_path / "config.toml").exists()


def _template():
    from maverick.templates import save_user_template

    return save_user_template("review-test", title="Review {{ company }}", body="{{ company }}\n" + "Full context. " * 500, params=["company"], owner="local")


def test_prepare_uses_full_template_without_starting_a_goal(client):
    _template()
    response = client.post("/api/v1/templates/review-test/prepare", json={"params":{"company":"Example <script>"}})
    assert response.status_code == 200
    result = response.json()
    assert result["title"] == "Review Example <script>"
    assert len(result["description"]) > 2000
    assert "{{ company }}" not in result["description"]
    assert result["started"] is False
    assert result["context"] == client.get("/api/v1/templates/draft-context").json()["context"]
    from maverick_dashboard._shared import _world
    assert _world().list_goals(limit=1) == []


@pytest.mark.parametrize("params", [{}, {"company":""}, {"company":"x","extra":"y"}, {"company":"x"*10001}])
def test_prepare_rejects_missing_unknown_empty_or_unbounded_inputs(client, params):
    _template()
    assert client.post("/api/v1/templates/review-test/prepare", json={"params":params}).status_code == 400


def test_ratings_are_validated_and_persisted(client):
    _template()
    for stars in [True, "4", 0, 6, 1.5]:
        assert client.post("/api/v1/templates/review-test/rating", json={"stars":stars}).status_code == 422
    assert client.post("/api/v1/templates/missing/rating", json={"stars":4}).status_code == 404
    result = client.post("/api/v1/templates/review-test/rating", json={"stars":4})
    assert result.json() == {"name":"review-test", "stars":4, "saved":True}
    from maverick.marketplace.ratings import RatingsLedger
    assert RatingsLedger().my_rating("templates", "review-test")["stars"] == 4


def test_prepare_rejects_oversized_rendered_draft_without_truncation(client):
    from maverick.templates import save_user_template

    save_user_template("large-draft", title="Review", body="x" * 16001, owner="local")
    result = client.post("/api/v1/templates/large-draft/prepare", json={"params":{}})
    assert result.status_code == 400
    assert "16,000" in result.json()["detail"]


def test_viewer_cannot_prepare_rate_or_edit_facts(client, monkeypatch):
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:viewer", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:viewer")
    for path, payload in [("/templates/review-test/prepare", {"params":{}}), ("/templates/review-test/rating", {"stars":4}), ("/facts", {"key":"hours", "value":"9 to 5"})]:
        assert client.post("/api/v1" + path, json=payload).status_code == 403
    assert 'id="fact-editor"' not in client.get("/facts").text


def test_fact_editor_roundtrips_text_and_escapes_rendered_values(client):
    payload = {"key":"Office <hours>", "value":"9 to 5\n<script>alert(1)</script>"}
    assert client.post("/api/v1/facts", json=payload).status_code == 204
    assert client.get("/api/v1/facts").json()[payload["key"]] == payload["value"]
    page = client.get("/facts").text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert 'id="fact-editor"' in page


def test_draft_context_changes_with_caller_and_workspace(client, monkeypatch):
    from maverick import paths
    from maverick_dashboard import in_app_routes

    before = client.get("/api/v1/templates/draft-context").json()["context"]
    monkeypatch.setattr(in_app_routes, "caller_principal", lambda _request: "user:second")
    after = client.get("/api/v1/templates/draft-context").json()["context"]
    assert after != before
    monkeypatch.setattr(paths, "current_tenant_id", lambda: "another-workspace")
    assert client.get("/api/v1/templates/draft-context").json()["context"] != after


@pytest.mark.parametrize("name", ["lightwork-facts.js", "lightwork-consent-policy-editor.js", "lightwork-setup.js", "lightwork-template-library.js", "lightwork-connections.js", "lightwork-account-inventory.js", "lightwork-schedule-management.js", "lightwork-guided-actions.js", "lightwork-guided-actions.css"])
def test_new_form_assets_are_served(client, name):
    from pathlib import Path

    import maverick_dashboard

    response = client.get("/static/" + name)
    assert response.status_code == 200
    assert response.content == (Path(maverick_dashboard.__file__).parent / "static" / name).read_bytes()
