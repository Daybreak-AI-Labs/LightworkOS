"""A clean-home install reaches activation and evidence-visible cockpit pages."""
from __future__ import annotations

import json

from click.testing import CliRunner
from fastapi.testclient import TestClient


def test_headless_first_run_journey(monkeypatch, tmp_path):
    home = tmp_path / "maverick-home"
    installed = home / "config.toml"
    source = tmp_path / "reviewed-config.toml"
    source.write_text(
        "\n".join(
            [
                "[providers.anthropic]",
                'api_key = "${ANTHROPIC_API_KEY}"',
                "[sandbox]",
                'backend = "local"',
                "[evidence_graph]",
                "enable = true",
                "[evidence_gateway]",
                "enable = true",
                "[model_risk_assurance]",
                "enable = true",
                "gate_promotions = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(installed))
    monkeypatch.setenv("MAVERICK_TENANT", "first-run-company")
    # Offline preflight checks presence only. No provider request is made.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-present")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)

    from maverick import config, providers, world_model
    from maverick.cli import main

    # A clean home runs on effective defaults, so the missing piece before
    # setup is the AI provider, not the configuration file itself.
    for name in config.PROVIDER_KEY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    before = CliRunner().invoke(main, ["preflight", "--json"])
    assert before.exit_code == 1
    checks = {check["id"]: check["status"] for check in json.loads(before.output)["checks"]}
    assert checks["config"] == "ready" and checks["provider"] == "blocked"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-present")

    installed_result = CliRunner().invoke(
        main,
        ["init", "--from-file", str(source)],
    )
    assert installed_result.exit_code == 0, installed_result.output
    assert "installed config" in installed_result.output
    config.reset_config_cache()
    monkeypatch.setattr(providers, "missing_sdks", lambda _specs: [])

    ready = CliRunner().invoke(
        main,
        ["preflight", "--profile", "cockpit", "--json"],
    )
    assert ready.exit_code == 0, ready.output
    report = json.loads(ready.output)
    assert report["ready"] is True
    assert report["blocker_count"] == 0

    from maverick_dashboard import app as dashboard

    monkeypatch.setattr(world_model, "DEFAULT_DB", home / "world.db")
    dashboard._world_cache.clear()
    client = TestClient(
        dashboard.app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1"},
    )

    started = client.get("/start")
    assert started.status_code == 200, started.text
    # A saved key that never passed a connection test is "not tested yet",
    # never "configured": the same truth every readiness page tells.
    assert "not tested yet" in started.text
    assert "Your setup checklist is complete" not in started.text
    assert "Installation checks" in started.text

    from maverick import ai_evidence_gateway

    gateway_summary = ai_evidence_gateway.summary()
    assert gateway_summary["current_policy_count"] == 0
    assurance = client.get("/security/assurance")
    assert assurance.status_code == 200, assurance.text
    assert "Not started" in assurance.text
    assert "Load sample data" in assurance.text
    assert "production policy" in assurance.text
