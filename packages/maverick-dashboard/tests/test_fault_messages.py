"""Fault injection: when an AI service fails, every page says what broke,
whether work is safe, when Lightwork tries again and another way to carry on,
and never shows a raw code as the main text."""
from __future__ import annotations

import re
from html import unescape

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()
    dash_app._world_cache.clear()


def _timeouts(monkeypatch, providers, *, in_use):
    """The provider timed out often enough that the circuit breaker paused it."""
    from maverick import circuit_breaker, service_status

    rows = [{"key": "llm:" + name, "state": "open", "opened_at": 2_000_000_000.0, "cooldown_seconds": 60}
            for name in providers]
    monkeypatch.setattr(circuit_breaker, "snapshot", lambda: rows)
    monkeypatch.setattr(service_status, "providers_in_use", lambda: set(in_use))


def _banner(page: str) -> str:
    found = re.search(r'id="service-status-banner".*?</div>', page, re.DOTALL)
    assert found, "no service banner"
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", found.group(0))).split())


@pytest.mark.parametrize("path", ["/", "/chat", "/approvals", "/settings"])
def test_a_provider_outage_says_what_broke_what_is_safe_when_and_another_way(client, monkeypatch, path):
    _timeouts(monkeypatch, ["anthropic"], in_use={"anthropic"})
    text = _banner(client.get(path).text)
    assert "Anthropic is paused after repeated errors" in text          # what broke
    assert "What they already finished is kept" in text                 # what is safe
    assert re.search(r"tries Anthropic again at .*\d", text)             # when it returns
    assert "set up another AI service under Settings > AI models" in text  # another way
    assert not re.search(r"\b(5\d\d|Traceback|Exception|HTTPError)\b", text)  # no raw code as the message


def test_with_a_healthy_backup_the_banner_says_new_work_carries_on(client, monkeypatch):
    _timeouts(monkeypatch, ["anthropic"], in_use={"anthropic", "openai"})
    text = _banner(client.get("/").text)
    assert "still working with OpenAI" in text and "start new work as usual: it uses OpenAI" in text


def _notice(page: str, kind: str) -> str:
    found = re.search(rf'id="service-status-banner-{kind}".*?</div>', page, re.DOTALL)
    assert found, f"no {kind} banner"
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", found.group(0))).split())


def _no_raw_code(text):
    assert not re.search(r"\b([45]\d\d|Traceback|Exception|OperationalError|sqlite3?)\b", text), text


@pytest.mark.parametrize("path", ["/", "/chat", "/approvals"])
def test_an_expired_connection_says_what_broke_what_is_safe_when_and_another_way(client, monkeypatch, tmp_path, path):
    from maverick import config, connections

    (tmp_path / "config.toml").write_text("[connections]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    connections.set_connection("team-slack", connector="slack", token="xoxb-test-token")  # pragma: allowlist secret
    connections.record_test_result("team-slack", reachable=True, authenticated=False, status=401,
                                   outcome="sign_in_refused")
    text = _notice(client.get(path).text, "connector")
    assert "team-slack can't be used right now" in text                    # what broke
    assert "everything else keeps working" in text                         # what is safe
    assert "as soon as it is reconnected in Connections" in text           # when it returns
    assert "do that step by hand or use another connection" in text        # another way
    _no_raw_code(text)


def test_a_read_only_database_says_what_broke_what_is_safe_when_and_another_way(client, monkeypatch):
    from maverick import service_status

    monkeypatch.setattr(service_status, "_world_writable", lambda: False)
    text = _notice(client.get("/").text, "database")
    assert "can't save changes right now" in text                          # what broke
    assert "Everything already saved is safe" in text                      # what is safe
    assert "as soon as an administrator makes the database writable" in text  # when it returns
    assert "you can still read and export" in text                         # another way
    _no_raw_code(text)


def test_a_write_refused_by_a_read_only_database_answers_in_plain_words(client, monkeypatch):
    import sqlite3

    from maverick.world_model import WorldModel

    def refuse(*args, **kwargs):
        raise sqlite3.OperationalError("attempt to write a readonly database")

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")  # pragma: allowlist secret
    monkeypatch.setattr(WorldModel, "create_goal", refuse)
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, raise_server_exceptions=False)
    answer = client.post("/api/v1/goals", json={"title": "Pay the March invoices"})
    assert answer.status_code == 503, answer.text
    detail = answer.json()["detail"]
    assert detail.startswith("Lightwork can't save changes right now because its database is read-only.")
    assert "Nothing was changed" in detail
    _no_raw_code(detail)
    import asyncio

    from maverick_dashboard.app import unhandled_exception_handler
    from starlette.requests import Request

    browser = Request({"type": "http", "method": "POST", "path": "/chat/send", "query_string": b"",
                       "headers": [(b"accept", b"text/html")], "app": app, "state": {}})
    page = asyncio.run(unhandled_exception_handler(browser, sqlite3.OperationalError(
        "attempt to write a readonly database")))
    main = re.search(r"<main.*?</main>", page.body.decode(), re.DOTALL).group(0)
    text = " ".join(unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<script.*?</script>", "", main, flags=re.DOTALL))).split())
    assert page.status_code == 503 and "Lightwork can't save changes right now" in text
    assert "nothing was changed" in text and "Everything already saved is safe" in text
    _no_raw_code(text.split("Support reference")[0])
