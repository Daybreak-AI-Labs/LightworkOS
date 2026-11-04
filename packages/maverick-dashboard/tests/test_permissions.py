"""Permissions page + snapshot + tool disable/enable via the overlay."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    from maverick import runtime_overrides, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "ro.toml")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def test_permissions_api_shape(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    r = client.get("/api/v1/permissions")
    assert r.status_code == 200
    body = r.json()
    for key in ("tools", "capabilities", "channels", "sandbox", "budget",
                "network", "providers", "retention", "overlay_denied"):
        assert key in body
    assert isinstance(body["tools"], list)
    assert body["tool_page"]["per_page"] == 100


def test_permissions_corrupt_policy_returns_sanitized_503(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    policy = tmp_path / "ro.toml"
    policy.write_text("invalid TOML from C:/private/operator/path {")

    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False)
    response = client.get(
        "/api/v1/permissions",
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 503
    assert response.json()["code"] == "operator_policy_unavailable"
    assert "C:/private/operator/path" not in response.text


def test_permissions_tools_include_enabled_flag(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    body = client.get("/api/v1/permissions").json()
    # The registry builds a bunch of tools; each carries an enabled flag.
    assert body["tools"], "expected some tools registered"
    assert all("enabled" in t for t in body["tools"])
    assert all(
        {
            "usable",
            "catalog_present",
            "configured",
            "provider_ready",
            "connection_ready",
            "feature_policy_allowed",
            "base_acl_allowed",
            "policy_allowed",
            "sandbox_constructed",
            "sandbox_ready",
            "runtime_ready",
            "prerequisites",
            "unready_dimensions",
            "reason",
        }
        <= set(t)
        for t in body["tools"]
    )
    assert all(t["enabled"] is t["usable"] for t in body["tools"])
    assert not any(t["enabled"] for t in body["tools"])


def test_permissions_warns_on_local_sandbox(monkeypatch, tmp_path):
    """The default (no-isolation) local sandbox must be flagged on the
    permissions surface, and an isolated backend must NOT be flagged."""
    _isolate(monkeypatch, tmp_path)  # no config file -> defaults to local
    client = _client()
    body = client.get("/api/v1/permissions").json()
    assert body["sandbox_warning"], "local sandbox should be flagged"
    assert "isolation" in body["sandbox_warning"]
    # Page renders the banner too.
    assert "⚠" in client.get("/permissions").text

    # An explicit docker backend is isolated -> no warning.
    (tmp_path / "config.toml").write_text('[sandbox]\nbackend = "docker"\n')
    body2 = client.get("/api/v1/permissions").json()
    assert body2["sandbox_warning"] is None


def test_disable_tool_then_shows_disabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    # shell is registered and ACL-admitted, but unknown dependencies mean it is
    # not represented as usable before or after the dashboard policy mutation.
    before = {
        t["name"]: t
        for t in client.get("/api/v1/permissions", params={"q": "shell"}).json()["tools"]
    }
    assert before["shell"]["base_acl_allowed"] is True
    assert before["shell"]["policy_allowed"] is True
    assert before["shell"]["enabled"] is False

    r = client.post("/api/v1/permissions/tools/shell/disable", headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 204

    after = {
        t["name"]: t
        for t in client.get("/api/v1/permissions", params={"q": "shell"}).json()["tools"]
    }
    assert after["shell"]["base_acl_allowed"] is True
    assert after["shell"]["policy_allowed"] is False
    assert after["shell"]["enabled"] is False
    # Overlay file records it.
    assert "shell" in client.get("/api/v1/permissions").json()["overlay_denied"]


def test_enable_tool_clears_override(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    client.post("/api/v1/permissions/tools/shell/disable", headers={"Origin": "http://127.0.0.1"})
    r = client.post("/api/v1/permissions/tools/shell/enable", headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 200
    assert r.json()["tool"]["policy_allowed"] is True
    assert r.json()["tool"]["usable"] is False
    assert r.json()["tool"]["state"] == "readiness_unknown"
    body = client.get("/api/v1/permissions").json()
    assert "shell" not in body["overlay_denied"]
    names = {
        t["name"]: t
        for t in client.get("/api/v1/permissions", params={"q": "shell"}).json()["tools"]
    }
    assert names["shell"]["base_acl_allowed"] is True
    assert names["shell"]["policy_allowed"] is True
    assert names["shell"]["enabled"] is False


def test_enable_reports_when_base_policy_still_denies_tool(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    (tmp_path / "config.toml").write_text(
        '[security]\ndenied_tools = ["shell"]\n', encoding="utf-8"
    )
    from maverick import config

    config.reset_config_cache()
    client = _client()
    # A dashboard override may also exist; clearing it must not falsify the
    # effective config ACL result.
    client.post(
        "/api/v1/permissions/tools/shell/disable",
        headers={"Origin": "http://127.0.0.1"},
    )
    response = client.post(
        "/api/v1/permissions/tools/shell/enable",
        headers={"Origin": "http://127.0.0.1"},
    )

    assert response.status_code == 200
    tool = response.json()["tool"]
    assert tool["catalog_present"] is True
    assert tool["base_acl_allowed"] is False
    assert tool["policy_allowed"] is False
    assert tool["enabled"] is False
    assert tool["state"] == "policy_blocked"
    assert "configured base ACL" in tool["reason"]


def test_disable_tool_rejects_invalid_name(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    r = client.post('/api/v1/permissions/tools/bad"name/disable', headers={"Origin": "http://127.0.0.1"})
    assert r.status_code == 400


def test_permissions_page_renders(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    r = client.get("/permissions")
    assert r.status_code == 200
    text = r.text
    assert "what lightwork can do" in text.lower()
    assert "your data" in text.lower()
    assert "No telemetry" in text
    assert "retained locally until you delete it" in text
    assert "until you delete them day(s)" not in text
    # Nav link present.
    assert 'href="/permissions"' in text


def test_permissions_uses_same_env_provider_provenance_as_settings(
    monkeypatch, tmp_path
):
    _isolate(monkeypatch, tmp_path)
    from maverick import config

    for env_names in config.PROVIDER_KEY_ENV_MAP.values():
        for env_name in env_names:
            monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "env-only-secret")  # pragma: allowlist secret

    body = _client().get("/api/v1/permissions").json()
    state = next(row for row in body["provider_states"] if row["name"] == "openai")
    assert state["configured"] is True
    assert state["api_key_source"] == "environment:OPENAI_API_KEY"  # pragma: allowlist secret
    assert "openai" in body["providers"]
    assert "env-only-secret" not in str(body)  # pragma: allowlist secret


def test_permissions_page_shows_disable_buttons(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    r = client.get("/permissions")
    assert "perm-toggle" in r.text
    assert ">Block</button>" in r.text


def test_permissions_catalog_is_filtered_and_paginated_server_side(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import app as dashboard_app

    tools = []
    for index in range(2500):
        allowed = index % 2 == 0
        row = dashboard_app._tool_permission_row(
            f"tool-{index:04d}",
            catalog_present=True,
            base_acl_allowed=allowed,
            provider_status="ready",
            connection_status="ready",
            feature_policy_status="ready",
            sandbox_status="ready",
            sandbox_constructed=True,
        )
        row["reason"] = "alpha family" if index < 1200 else "omega family"
        tools.append(row)
    snapshot = dashboard_app._permissions_snapshot()
    snapshot["tools"] = tools
    monkeypatch.setattr(dashboard_app, "_permissions_snapshot", lambda: snapshot)

    response = _client().get(
        "/permissions",
        params={"q": "alpha", "state": "blocked", "page": 2, "per_page": 25},
    )

    assert response.status_code == 200
    assert response.text.count('data-tool-name="') == 25
    assert "Showing 25 of 600 matching tools" in response.text
    assert "2500 in the catalog" in response.text
    assert "Page 2 of 24" in response.text
    assert "tool-0051" in response.text
    assert "tool-0001" not in response.text

    api = _client().get(
        "/api/v1/permissions",
        params={"q": "omega", "state": "admitted", "per_page": 10},
    ).json()
    assert len(api["tools"]) == 10
    assert api["tool_page"]["filtered_total"] == 650
    assert api["tool_page"]["complete"] is False


def test_permissions_rejects_unbounded_or_unknown_filters(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    assert client.get("/api/v1/permissions", params={"per_page": 101}).status_code == 422
    response = client.get("/permissions", params={"state": "invented"})
    assert response.status_code == 400
