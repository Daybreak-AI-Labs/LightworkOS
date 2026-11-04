"""Dashboard model-route readiness uses the provider the operation will run.

`/chat/send` and `POST /api/v1/goals` must not hard-fail when
`ANTHROPIC_API_KEY` isn't set but the user has OpenAI or Gemini selected. A credential for an unrelated provider must not admit a route
that will still fail, while selected keyless self-hosted routes remain valid.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _strip_provider_env(monkeypatch):
    for v in (
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
        "OPENROUTER_API_KEY", "MOONSHOT_API_KEY", "DEEPSEEK_API_KEY",
        "XAI_API_KEY", "GOOGLE_API_KEY", "GROK_API_KEY",
        "MAVERICK_MODEL_OVERRIDE",
    ):
        monkeypatch.delenv(v, raising=False)


def test_chat_send_blocks_when_no_provider_key(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    _strip_provider_env(monkeypatch)
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "anthropic:test-model")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.post(
        "/chat/send",
        data={"title": "x"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert resp.status_code == 400
    detail = resp.json()["detail"]
    # Actionable message: pointers to `maverick init` and the env vars.
    assert "maverick init" in detail
    assert "ANTHROPIC_API_KEY" in detail or "OPENAI_API_KEY" in detail


def test_chat_send_accepts_openai_key(monkeypatch, tmp_path):
    """An OpenAI key is enough: the check does not look only at ANTHROPIC."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    _strip_provider_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-test")
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "openai:test-model")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.post(
        "/chat/send",
        data={"title": "x"},
        headers={"Origin": "http://127.0.0.1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303  # redirect to /chat/goal/{id}


def test_api_goals_blocks_when_no_provider_key(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    _strip_provider_env(monkeypatch)
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "anthropic:test-model")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.post(
        "/api/v1/goals",
        json={"title": "x"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert resp.status_code == 400
    assert "maverick init" in resp.json()["detail"]
    # An existing installation changes keys in Settings: `maverick init` refuses there.
    assert "Lightwork > Settings" in resp.json()["detail"]


def test_api_goals_reports_unavailable_runtime_policy_as_503(
    monkeypatch,
    tmp_path,
):
    from maverick import operator_preflight, world_model
    from maverick.runtime_overrides import RuntimeOverridesSecurityError
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    _strip_provider_env(monkeypatch)
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "anthropic:test-model")

    def unavailable(_cfg):
        raise RuntimeOverridesSecurityError("private runtime policy path")

    monkeypatch.setattr(
        operator_preflight,
        "_routed_configuration_missing",
        unavailable,
    )
    dash_app._world_cache.clear()
    client = TestClient(dash_app.app, base_url="http://127.0.0.1", raise_server_exceptions=False)

    resp = client.post(
        "/api/v1/goals",
        json={"title": "x"},
        headers={"Origin": "http://127.0.0.1"},
    )

    assert resp.status_code == 503
    assert resp.json()["code"] == "operator_policy_unavailable"
    assert "private runtime policy path" not in resp.text


def test_goal_create_accepts_config_only_selfhosted_provider(monkeypatch, tmp_path):
    """Platform-test regression: a keyless self-hosted provider configured
    ONLY in config.toml (the Ollama/vLLM path) must pass the dashboard's
    provider gate -- the CLI preflight accepted it while the dashboard 400'd,
    because each component had its own 'provider configured?' predicate."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    _strip_provider_env(monkeypatch)
    for v in ("VLLM_BASE_URL", "TGI_BASE_URL", "OPENAI_COMPATIBLE_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[providers.vllm]\nbase_url = "http://127.0.0.1:9911/v1"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE", "vllm:local-model")

    # Patch the runner so nothing actually executes.
    import maverick.runner as runner_mod
    monkeypatch.setattr(
        runner_mod, "run_goal_in_thread",
        lambda *a, **k: None,
    )

    client = _client()
    resp = client.post(
        "/api/v1/goals",
        json={"title": "self-hosted goal"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert resp.status_code == 201, resp.text
