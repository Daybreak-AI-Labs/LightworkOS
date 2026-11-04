"""The dashboard's OpenAI-compatible gateway endpoint: self-authenticating.

The endpoint sits outside /api/v1 (foreign agents hold the gateway bearer,
never the dashboard bearer or a browser origin), 403s with guidance while
the feature is off, and relays exactly what the governed core decides.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick import config
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", str(tmp_path / "world.db"))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_TENANT",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_GATEWAY_TOKEN", "gw-secret")
    monkeypatch.setenv("LLM_GATEWAY_UPSTREAM_TOKEN", "up-secret")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _enable(tmp_path):
    (tmp_path / "config.toml").write_text(
        '[llm_gateway]\nenable = true\nupstream_url = "https://api.openai.com"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()


def test_disabled_endpoint_explains_the_knob():
    response = client.post(
        "/gateway/v1/chat/completions",
        json={"model": "gpt-5.2", "messages": []},
    )
    assert response.status_code == 403
    assert "[llm_gateway]" in response.json()["error"]["message"]


def test_gateway_bearer_gates_the_endpoint(tmp_path, monkeypatch):
    _enable(tmp_path)
    from maverick import llm_gateway as gw

    monkeypatch.setattr(
        gw,
        "_default_upstream",
        lambda url, headers, body: (
            200,
            {
                "id": "chatcmpl-1",
                "choices": [{"message": {"role": "assistant", "content": "hi"}}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 1},
            },
        ),
    )
    denied = client.post(
        "/gateway/v1/chat/completions",
        json={"model": "gpt-5.2", "messages": [{"role": "user", "content": "q"}]},
        headers={"Authorization": "Bearer wrong"},
    )
    assert denied.status_code == 401

    granted = client.post(
        "/gateway/v1/chat/completions",
        json={"model": "gpt-5.2", "messages": [{"role": "user", "content": "q"}]},
        headers={"Authorization": "Bearer gw-secret"},
    )
    assert granted.status_code == 200
    assert granted.json()["choices"][0]["message"]["content"] == "hi"
    assert gw.list_callers()[0]["last_status"] == "ok"


def test_malformed_json_is_a_client_error(tmp_path):
    _enable(tmp_path)
    response = client.post(
        "/gateway/v1/chat/completions",
        content=b"not json",
        headers={
            "Authorization": "Bearer gw-secret",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 400


def test_otel_ingestion_endpoint(tmp_path):
    _enable(tmp_path)
    payload = {
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name",
                 "value": {"stringValue": "crew-planner"}},
            ]},
            "scopeSpans": [{"spans": [
                {"name": "chat", "attributes": [
                    {"key": "gen_ai.system",
                     "value": {"stringValue": "openai"}},
                    {"key": "gen_ai.request.model",
                     "value": {"stringValue": "gpt-5.2"}},
                ]},
            ]}],
        }]
    }
    unauthorized = client.post("/gateway/v1/otel", json=payload)
    assert unauthorized.status_code == 401

    accepted = client.post(
        "/gateway/v1/otel", json=payload,
        headers={"Authorization": "Bearer gw-secret"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"ingested": 1, "skipped": 0}

    malformed = client.post(
        "/gateway/v1/otel", content=b"not-json",
        headers={"Authorization": "Bearer gw-secret",
                 "Content-Type": "application/json"},
    )
    assert malformed.status_code == 400


def test_otel_endpoint_off_is_403(tmp_path):
    response = client.post("/gateway/v1/otel", json={})
    assert response.status_code == 403


def test_oversized_body_is_413_before_auth(tmp_path):
    # The body cap applies while READING, pre-auth: an anonymous client
    # streaming an oversized body gets the OpenAI-style 413 envelope and
    # never allocates the full payload server-side.
    (tmp_path / "config.toml").write_text(
        '[llm_gateway]\nenable = true\n'
        'upstream_url = "https://api.openai.com"\n'
        'max_body_bytes = 4096\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    response = client.post(
        "/gateway/v1/chat/completions",
        content=b"x" * 8192,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["type"] == "invalid_request_error"


def test_otel_ingestion_skips_malformed_spans(tmp_path):
    # One good span and two broken ones (a non-mapping span, a span whose
    # usage attributes are junk strings): the good span ingests, the rest
    # count as skipped, and nothing 500s.
    _enable(tmp_path)
    payload = {
        "resourceSpans": [{
            "resource": {"attributes": [
                {"key": "service.name",
                 "value": {"stringValue": "crew-planner"}},
            ]},
            "scopeSpans": [{"spans": [
                {"name": "chat", "attributes": [
                    {"key": "gen_ai.system",
                     "value": {"stringValue": "openai"}},
                    {"key": "gen_ai.request.model",
                     "value": {"stringValue": "gpt-5.2"}},
                    {"key": "gen_ai.usage.input_tokens",
                     "value": {"intValue": "7"}},
                ]},
                "not-a-span",
                {"name": "chat", "attributes": [
                    {"key": "gen_ai.request.model",
                     "value": {"stringValue": "gpt-5.2"}},
                    {"key": "gen_ai.usage.input_tokens",
                     "value": {"intValue": "junk"}},
                ]},
            ]}],
        }]
    }
    accepted = client.post(
        "/gateway/v1/otel", json=payload,
        headers={"Authorization": "Bearer gw-secret"},
    )
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body["ingested"] == 1
    assert body["skipped"] == 2
    from maverick import llm_gateway as gw

    callers = gw.list_callers()
    assert len(callers) == 1
    assert callers[0]["model"] == "gpt-5.2"
    assert callers[0]["prompt_tokens"] == 7


def test_anthropic_gateway_endpoint_uses_native_envelope(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_ANTHROPIC_TOKEN", "anthropic-up-secret")
    (tmp_path / "config.toml").write_text(
        '[llm_gateway]\nenable = true\nupstream_url = "https://api.openai.com"\n'
        'anthropic_upstream_url = "https://api.anthropic.com"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    from maverick import llm_gateway as gw

    seen = {}

    def upstream(url, headers, body):
        seen.update({"url": url, "headers": headers, "body": body})
        return 200, {
            "id": "msg-1",
            "type": "message",
            "content": [{"type": "text", "text": "hi"}],
            "usage": {"input_tokens": 2, "output_tokens": 1},
        }

    monkeypatch.setattr(gw, "_default_upstream", upstream)
    denied = client.post(
        "/gateway/v1/messages",
        json={"model": "claude-test", "max_tokens": 8, "messages": []},
        headers={"Authorization": "Bearer wrong"},
    )
    assert denied.status_code == 401
    assert denied.json()["type"] == "error"
    assert denied.json()["error"]["type"] == "authentication_error"

    accepted = client.post(
        "/gateway/v1/messages",
        json={"model": "claude-test", "max_tokens": 8, "messages": []},
        headers={"Authorization": "Bearer gw-secret"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["type"] == "message"
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == "anthropic-up-secret"
