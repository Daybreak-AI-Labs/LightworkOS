"""Top-level integration inventories expose closed readiness states."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path: Path):
    home = tmp_path / "maverick-home"
    config_path = home / "config.toml"
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    for name in (
        "MAVERICK_AUTH_REQUIRED",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_ENTERPRISE",
        "MAVERICK_TENANT",
        "MAVERICK_AUDIT_SIGNING_KEY",
        "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED",
    ):
        monkeypatch.delenv(name, raising=False)

    import maverick.runtime_overrides as runtime_overrides
    from maverick import config, world_model
    from maverick.audit import signing
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import integration_readiness

    for name in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in ("GOOGLE_API_KEY", "GROK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    signing._reset_injected_keypair_cache()
    integration_readiness._clear_for_testing()
    monkeypatch.setattr(world_model, "DEFAULT_DB", home / "world.db")
    monkeypatch.setattr(
        runtime_overrides,
        "OVERRIDES_PATH",
        home / "runtime-overrides.toml",
    )
    dashboard_app._world_cache.clear()
    yield config_path
    integration_readiness._clear_for_testing()
    config.reset_config_cache()
    signing._reset_injected_keypair_cache()


def _client(*, auth_token: str = "") -> TestClient:
    from maverick_dashboard.app import app

    headers = {"Origin": "http://127.0.0.1"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    return TestClient(app, base_url="http://127.0.0.1", headers=headers)


def test_settings_renders_readiness_for_every_provider_row():
    from maverick_dashboard.settings_store import PROVIDERS

    response = _client().get("/settings")
    assert response.status_code == 200
    for provider in PROVIDERS:
        assert provider["label"] in response.text
    assert response.text.count("Connection test:") >= len(PROVIDERS)
    assert "Not set up" in response.text


def test_provider_unknown_then_fingerprint_bound_live_verified(monkeypatch):
    from maverick import providers
    from maverick_dashboard import integration_readiness, settings_store

    settings_store.set_provider(
        "openai",
        api_key="test-provider-key",  # pragma: allowlist secret
    )
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    monkeypatch.setattr(
        integration_readiness,
        "probe_provider",
        lambda _name, _config: {
            "verified": True,
            "detail": "bounded provider probe passed",
            "evidence": {"kind": "live_status_probe", "http_status": 200},
        },
    )
    client = _client()

    before = client.get("/api/v1/providers").json()["providers"]
    openai_before = next(row for row in before if row["name"] == "openai")
    assert openai_before["readiness"]["configured"] is True
    assert openai_before["readiness"]["live"]["status"] == "unknown"
    assert openai_before["readiness"]["live"]["verified"] is None

    tested = client.post(
        "/settings/providers/test",
        data={"provider": "openai"},
        follow_redirects=False,
    )
    assert tested.status_code == 303
    after = client.get("/api/v1/providers").json()["providers"]
    openai_after = next(row for row in after if row["name"] == "openai")
    assert openai_after["readiness"]["runtime"]["status"] == "passed"
    assert openai_after["readiness"]["live"]["status"] == "verified"
    assert openai_after["readiness"]["state"] == "live_verified"
    settings_page = client.get("/settings")
    assert settings_page.status_code == 200
    assert "bounded provider probe passed" in settings_page.text
    providers_page = client.get("/providers")
    assert providers_page.status_code == 200
    assert "1 connected" in providers_page.text and ">Connected<" in providers_page.text


def test_provider_probe_truth_for_loopback_runtime_and_unsupported(monkeypatch):
    from maverick import config, providers
    from maverick.tools import _ssrf
    from maverick_dashboard import integration_readiness, settings_store

    requests = []

    def configured_get(url: str, **kwargs):
        requests.append((url, kwargs))
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return SimpleNamespace(status_code=200)

    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("127.0.0.1")
    monkeypatch.setattr(httpx, "get", configured_get)
    for name, base_url, suffix in (
        ("ollama", "http://localhost:11434", "api/tags"),
        ("vllm", "http://127.0.0.1:9815/v1", "models"),
        ("tgi", "http://10.0.0.7:8080/v1", "models"),
        ("openai_compatible", "http://192.168.1.5:1234/v1", "models"),
    ):
        result = integration_readiness.probe_provider(name, {"base_url": base_url})
        assert result["verified"] is True
        assert requests[-1][0] == base_url + "/" + suffix
    assert integration_readiness.probe_provider("ollama", {})["verified"] is True
    with pytest.raises(_ssrf.BlockedHost):
        _ssrf.resolve_pinned_ip("127.0.0.1")
    for invalid in ("file:///tmp/model", "http://user:pass@127.0.0.1/v1", "http://[invalid"):  # pragma: allowlist secret
        rejected = integration_readiness.probe_provider("vllm", {"base_url": invalid})
        assert rejected["verified"] is False
        assert "address must be an HTTP or HTTPS URL" in rejected["detail"]
    assert len(requests) == 5

    # Hosted providers still use the pinned public-only fetch policy.
    hosted = integration_readiness.probe_provider(
        "openai", {"api_key": "test-key", "base_url": "http://10.0.0.7/v1"}  # pragma: allowlist secret
    )
    assert hosted["verified"] is False
    assert hosted["evidence"]["blocked_by_egress_policy"] is True
    assert len(requests) == 5
    settings_store.set_provider("openai", api_key="test-key", base_url="http://10.0.0.7/v1")  # pragma: allowlist secret
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    integration_readiness.record(
        "provider", "openai", config.get_provider_config("openai"),
        verified=False, detail=hosted["detail"], evidence=hosted["evidence"],
    )
    page = _client().get("/settings")
    assert "Blocked by outbound-connection rules" in page.text
    assert "Some details are missing or wrong" not in page.text

    # Azure/Bedrock now have native bounded probes. Keep this assertion on a
    # provider without a probe, not on a supported cloud connection.
    unsupported_name = "custom_provider"
    material = {"api_key": "test-provider-key"}  # pragma: allowlist secret
    unsupported = integration_readiness.probe_provider(unsupported_name, material)
    assert unsupported["verified"] is None
    assert unsupported["evidence"]["kind"] == "unsupported"
    integration_readiness.record(
        "provider",
        unsupported_name,
        material,
        verified=unsupported["verified"],
        detail=unsupported["detail"],
        evidence=unsupported["evidence"],
    )
    monkeypatch.setattr(config, "get_provider_config", lambda _name: material)
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])
    readiness = integration_readiness.provider_readiness(unsupported_name, configured=True)
    assert readiness["runtime"]["status"] == "unknown"
    assert readiness["live"]["status"] == "unknown"
    assert readiness["live"]["checked"] is True
    assert readiness["state"] == "dependency_passed_runtime_unknown"

    cli_material = {"binary": "codex-test"}
    monkeypatch.setattr(integration_readiness.shutil, "which", lambda _binary: "codex")
    monkeypatch.setattr(
        integration_readiness.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )
    cli_probe = integration_readiness.probe_provider("codex_cli", cli_material)
    assert cli_probe["verified"] is None
    integration_readiness.record(
        "provider",
        "codex_cli",
        cli_material,
        verified=cli_probe["verified"],
        detail=cli_probe["detail"],
        evidence=cli_probe["evidence"],
    )
    monkeypatch.setattr(config, "get_provider_config", lambda _name: cli_material)
    cli_readiness = integration_readiness.provider_readiness(
        "codex_cli", configured=True
    )
    assert cli_readiness["runtime"]["status"] == "passed"
    assert cli_readiness["live"]["status"] == "unknown"
    assert cli_readiness["state"] == "runtime_passed_live_unknown"


def test_self_hosted_probe_reaches_loopback_without_following_a_redirect():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from maverick_dashboard import integration_readiness

    requests = []
    redirect = [False]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/v1/models" and redirect[0]:
                self.send_response(302)
                self.send_header("Location", "/secret")
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            material = {"base_url": f"http://127.0.0.1:{server.server_port}/v1"}
            passed = integration_readiness.probe_provider("vllm", material)
            root = {"base_url": f"http://127.0.0.1:{server.server_port}"}
            assert integration_readiness.probe_provider("vllm", root)["verified"] is True
            assert integration_readiness.probe_provider("tgi", root)["verified"] is True
            assert integration_readiness.probe_provider("ollama", material)["verified"] is True
            redirect[0] = True
            result = integration_readiness.probe_provider("vllm", material)
        finally:
            server.shutdown()
            worker.join(timeout=5)
    assert passed["verified"] is True
    assert result["verified"] is False
    assert result["evidence"]["http_status"] == 302
    assert requests == ["/v1/models", "/v1/models", "/v1/models", "/api/tags", "/v1/models"]


def test_channel_failure_and_mcp_unknown_then_failed(_isolate: Path):
    _isolate.parent.mkdir(parents=True, exist_ok=True)
    _isolate.write_text(
        """
[channels.slack]
enabled = true
bot_token = "xoxb-test"

[mcp_servers.broken]
command = "lightwork-command-that-does-not-exist"
""".strip(),
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    client = _client()

    channel = client.get("/api/v1/channels").json()["channels"][0]
    assert channel["configured"] is True
    assert channel["readiness"]["runtime"]["status"] == "failed"
    assert channel["readiness"]["live"]["status"] == "unknown"
    assert channel["readiness"]["state"] == (
        "dependency_failed" if channel["readiness"]["dependency"]["status"] == "failed"
        else "runtime_failed"
    )
    channel_page = client.get("/channels")
    assert channel_page.status_code == 200
    assert "Connection test:" in channel_page.text

    server = client.get("/api/v1/mcp").json()["servers"][0]
    assert server["readiness"]["dependency"]["status"] == "failed"
    assert server["readiness"]["runtime"]["status"] == "unknown"
    assert server["readiness"]["live"]["status"] == "unknown"

    tested = client.post(
        "/mcp/test",
        data={"name": "broken"},
        follow_redirects=False,
    )
    assert tested.status_code == 303
    failed = client.get("/api/v1/mcp").json()["servers"][0]
    assert failed["readiness"]["runtime"]["status"] == "failed"
    assert failed["readiness"]["live"]["status"] == "failed"
    mcp_page = client.get("/mcp")
    assert mcp_page.status_code == 200
    assert "MCP readiness handshake failed" in mcp_page.text


def test_corrupt_config_is_visible_unavailable_not_empty(
    _isolate: Path, monkeypatch
):
    # A running dashboard whose config is corrupted after start: its client
    # binding (unbound here) was resolved at start, so sign-in is still
    # recorded and the integration pages themselves report the failure.
    from maverick import client as client_binding
    from maverick import config

    client_binding.strict_client_id()
    _isolate.parent.mkdir(parents=True, exist_ok=True)
    _isolate.write_text("[channels\n", encoding="utf-8")
    config.reset_config_cache()
    token = "test-dashboard-admin-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    monkeypatch.setenv(
        "MAVERICK_AUDIT_SIGNING_KEY",
        hashlib.sha256(str(_isolate).encode()).hexdigest(),
    )
    client = _client(auth_token=token)
    for path in ("/settings", "/providers", "/mcp", "/channels"):
        response = client.get(path, headers={"Accept": "text/html"})
        assert response.status_code == 503, path
        assert "Temporarily unavailable" in response.text
        assert "No tool servers connected yet" not in response.text
        assert "No channels configured yet" not in response.text

    assert client.get("/api/v1/mcp").status_code == 500
    assert client.get("/api/v1/channels").status_code == 500
