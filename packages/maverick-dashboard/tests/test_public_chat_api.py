"""Public website chat widget: gate, origins, keys, sessions, limits, answers, transcripts."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

SHOP = "https://shop.example"
EVIL = "https://evil.example"
OTHER = "https://store.example"
ON = "[public_chat]\nenabled = true\n"
OFF = "[public_chat]\nenabled = false\n"
WIDGET = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork-public-chat-widget.js"


def _write_config(tmp_path, text):
    from maverick import config

    (tmp_path / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


@pytest.fixture
def chat(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import public_chat_api as api
    from maverick_dashboard.consent_public_api import PublicConsentRateLimiter

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    _write_config(tmp_path, ON)
    clock = {"now": 1_800_000_000.0}
    monkeypatch.setattr(api, "_now", lambda: clock["now"])
    from maverick_dashboard import public_chat_store as store_module

    monkeypatch.setattr(store_module, "_last_sweep", None)
    # The limiters run on the same injected clock as the visitor-session TTL.
    monkeypatch.setattr(api, "_SESSION_KEY_LIMITER", PublicConsentRateLimiter(
        limit_source=lambda: api.SESSION_KEY_PER_MINUTE, clock=lambda: clock["now"]))
    monkeypatch.setattr(api, "_SESSION_CLIENT_LIMITER", PublicConsentRateLimiter(
        limit_source=lambda: api.SESSION_CLIENT_PER_MINUTE, clock=lambda: clock["now"]))
    monkeypatch.setattr(api, "_CLIENT_DAY_LIMITER", api._ClientDayLimiter())
    yield SimpleNamespace(
        client=TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}),
        anon=TestClient(dash_app.app, base_url="http://127.0.0.1"),
        clock=clock, home=tmp_path / "mh", api=api, tmp=tmp_path, monkeypatch=monkeypatch,
    )
    config.reset_config_cache()


@pytest.fixture
def model(monkeypatch):
    from maverick import llm as llm_module

    fake = SimpleNamespace(text="We are open 9 to 5, Monday to Friday.", dollars=0.01,
                           calls=[], error=None, enforce=False)

    class FakeLLM:
        def __init__(self, spec):
            self.spec = spec

        def complete(self, system, messages, tools=None, budget=None, max_tokens=0, **kwargs):
            fake.calls.append({"system": system, "messages": messages, "tools": tools,
                               "max_tokens": max_tokens, **kwargs})
            if fake.error is not None:
                raise fake.error
            budget.dollars = fake.dollars
            if fake.enforce:  # the real budget refuses an overrun after the call is billed
                budget.check()
            return SimpleNamespace(text=fake.text)

    monkeypatch.setattr(llm_module, "LLM", FakeLLM)
    monkeypatch.setattr(llm_module, "model_for_role", lambda role, **kwargs: "fake:model")
    return fake


def _site(chat, **overrides):
    body = {"display_name": "Acme shop", "origins": [SHOP], "specialist": "finance_ap",
            "greeting": "Hello, how can I help?", "daily_cap_dollars": 1.0,
            "messages_per_session": 10, "messages_per_minute": 6, "retention_days": 30}
    body.update(overrides)
    response = chat.client.post("/api/v1/public-chat/sites", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _start(chat, key, origin=SHOP):
    headers = {"Origin": origin, "Authorization": f"PublicChatKey {key}"} if origin else {
        "Authorization": f"PublicChatKey {key}"}
    return chat.anon.post("/public/chat/v1/sessions", headers=headers, content=b"{}")


def _say(chat, token, text, origin=SHOP):
    headers = {"Authorization": f"PublicChatSession {token}", "Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    return chat.anon.post("/public/chat/v1/messages", headers=headers,
                          content=json.dumps({"message": text}).encode("utf-8"))


def _session(chat, key):
    response = _start(chat, key)
    assert response.status_code == 201, response.text
    return response.json()["session_token"]


def test_disabled_gate_returns_404_and_stores_nothing(chat, model):
    _write_config(chat.tmp, OFF)
    assert chat.anon.get("/public/chat/v1/widget.js").status_code == 404
    assert _start(chat, "lwpk_" + "a" * 43).status_code == 404
    assert _say(chat, "lwps_" + "a" * 43, "hello").status_code == 404
    assert chat.anon.options("/public/chat/v1/sessions", headers={
        "Origin": SHOP, "Access-Control-Request-Method": "POST"}).status_code == 404
    admin = chat.client.post("/api/v1/public-chat/sites", json={"display_name": "x"})
    assert admin.status_code == 404
    assert chat.client.get("/api/v1/public-chat/sites").status_code == 404
    assert not (chat.home / "public_chat").exists()


def test_widget_is_static_cacheable_and_contains_no_secret(chat):
    response = chat.anon.get("/public/chat/v1/widget.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/javascript")
    assert "max-age=" in response.headers["cache-control"]
    # The prefix is public text; a key-shaped token (prefix plus 32 random bytes) is not.
    assert re.search(r"lwp[ks]_[A-Za-z0-9_-]{20,}", response.text) is None
    assert "data-key" in response.text


def test_widget_inserts_text_only_and_never_evaluates_markup():
    source = WIDGET.read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                      "createContextualFragment", "DOMParser", "eval(", "Function(",
                      "setTimeout(\"", "setTimeout('", "setInterval(\"", "setInterval('",
                      "javascript:"):
        assert forbidden not in source, forbidden
    assert "textContent" in source and "attachShadow" in source


def test_widget_panel_uses_a_closed_shadow_root():
    source = WIDGET.read_text(encoding="utf-8")
    # Closed mode keeps the page's own scripts from reading the chat via host.shadowRoot.
    assert 'attachShadow({ mode: "closed" })' in source
    assert 'mode: "open"' not in source


def test_widget_waits_for_the_body_before_mounting():
    source = WIDGET.read_text(encoding="utf-8")
    # An async tag in <head> can run before <body> exists; the panel mounts when the document is ready.
    assert 'addEventListener("DOMContentLoaded"' in source
    assert "document.body" in source


def test_admin_create_shows_key_once_and_stores_only_its_digest(chat, model):
    created = _site(chat)
    key = created["publishable_key"]
    assert key.startswith("lwpk_") and len(key) == len("lwpk_") + 43
    assert "publishable_key" not in chat.client.get("/api/v1/public-chat/sites").json()["sites"][0]
    index_bytes = (chat.home / "public_chat" / "index.sqlite3").read_bytes()
    assert hashlib.sha256(key.encode("utf-8")).hexdigest().encode("ascii") in index_bytes
    assert key.encode("utf-8") not in index_bytes


@pytest.mark.parametrize("bad", [
    {"daily_cap_dollars": 0},
    {"daily_cap_dollars": -1},
    {"messages_per_session": 31},
    {"messages_per_minute": 7},
    {"retention_days": 0},
    {"messages_per_client_per_day": 0},
    {"messages_per_client_per_day": 5001},
    {"origins": ["http://shop.example"]},
    {"origins": ["https://*.example"]},
    {"origins": ["https://shop.example/path"]},
    {"origins": ["https://shop.example?x=1"]},
    {"origins": ["https://user@shop.example"]},
    {"origins": ["http://localhost:3000"]},
    {"origins": [f"https://s{i}.example" for i in range(21)]},
    {"specialist": "no_such_specialist"},
])
def test_admin_create_rejects_out_of_bounds_values(chat, model, bad):
    body = {"display_name": "Acme shop", "origins": [SHOP], "specialist": "finance_ap",
            "greeting": "Hi", "daily_cap_dollars": 1.0}
    body.update(bad)
    response = chat.client.post("/api/v1/public-chat/sites", json=body)
    # Each bad value is a validation refusal, not a missing route or a conflict.
    assert response.status_code == 422, response.text


def test_origin_normalization_is_exact_and_localhost_needs_the_dev_flag(chat):
    from maverick_dashboard import public_chat_store as store

    assert store.normalize_origin("https://Shop.Example/", allow_localhost=False) == SHOP
    for bad in ("http://shop.example", "https://shop.example:8443/x", "https://a b.example",
                "https://", "null", "https://127.0.0.1", "https://[::1]"):
        with pytest.raises(ValueError):
            store.normalize_origin(bad, allow_localhost=False)
    assert store.normalize_origin("http://localhost:3000", allow_localhost=True) == (
        "http://localhost:3000")
    with pytest.raises(ValueError):
        store.normalize_origin("http://localhost:3000", allow_localhost=False)


def test_bad_or_revoked_key_is_a_generic_401(chat, model):
    created = _site(chat)
    unknown = _start(chat, "lwpk_" + "b" * 43)
    assert unknown.status_code == 401
    assert unknown.json()["detail"] == "invalid publishable key"
    assert chat.client.post(f"/api/v1/public-chat/sites/{created['site']['id']}/revoke").status_code == 200
    revoked = _start(chat, created["publishable_key"])
    assert revoked.status_code == 401
    assert revoked.json() == unknown.json()
    assert created["publishable_key"] not in revoked.text


def test_wrong_or_missing_origin_is_403(chat, model):
    key = _site(chat)["publishable_key"]
    assert _start(chat, key, origin=EVIL).status_code == 403
    assert _start(chat, key, origin=None).status_code == 403
    assert _start(chat, key, origin="null").status_code == 403


@pytest.mark.parametrize("origin", [EVIL, None, OTHER])
def test_message_with_wrong_or_missing_origin_is_refused_and_counted_nowhere(chat, model, origin):
    # OTHER is a listed origin of the same site: only the session's own origin binding refuses it.
    created = _site(chat, origins=[SHOP, OTHER], messages_per_session=2)
    token = _session(chat, created["publishable_key"])
    refused = _say(chat, token, "hello", origin=origin)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "this website is not allowed to use this chat"
    assert "access-control-allow-origin" not in refused.headers
    assert model.calls == []
    # The refusal used no message from the session and wrote no transcript row.
    assert _say(chat, token, "hi").json()["remaining_messages"] == 1
    site_id = created["site"]["id"]
    viewed = chat.client.get(f"/api/v1/public-chat/sites/{site_id}/transcripts").json()
    assert [row["text"] for row in viewed["messages"]] == ["hi", model.text]


def test_cors_is_granted_only_to_the_sites_exact_origins(chat, model):
    key = _site(chat)["publishable_key"]
    preflight = chat.anon.options("/public/chat/v1/sessions", headers={
        "Origin": SHOP, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, content-type"})
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == SHOP
    denied = chat.anon.options("/public/chat/v1/sessions", headers={
        "Origin": EVIL, "Access-Control-Request-Method": "POST"})
    assert denied.status_code == 403
    assert "access-control-allow-origin" not in denied.headers
    allowed = _start(chat, key)
    assert allowed.headers["access-control-allow-origin"] == SHOP
    refused = _start(chat, key, origin=EVIL)
    assert "access-control-allow-origin" not in refused.headers


def test_session_token_is_digest_only_bounded_and_expires(chat, model):
    key = _site(chat)["publishable_key"]
    body = _start(chat, key).json()
    token = body["session_token"]
    assert token.startswith("lwps_") and body["ttl_seconds"] <= 3600
    assert body["greeting"] == "Hello, how can I help?"
    assert token.encode("utf-8") not in (chat.home / "public_chat" / "index.sqlite3").read_bytes()
    assert _say(chat, token, "hello").status_code == 200
    chat.clock["now"] += body["ttl_seconds"] + 1
    expired = _say(chat, token, "hello again")
    assert expired.status_code == 401
    assert expired.json()["detail"] == "chat session expired or invalid"


def test_session_starts_are_rate_limited_per_key_and_per_client(chat, model):
    key = _site(chat)["publishable_key"]
    chat.monkeypatch.setattr(chat.api, "SESSION_CLIENT_PER_MINUTE", 2)
    assert _start(chat, key).status_code == 201
    assert _start(chat, key).status_code == 201
    limited = _start(chat, key)
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
    chat.clock["now"] += 61
    assert _start(chat, key).status_code == 201
    chat.monkeypatch.setattr(chat.api, "SESSION_KEY_PER_MINUTE", 1)
    chat.clock["now"] += 61
    assert _start(chat, key).status_code == 201
    assert _start(chat, key).status_code == 429


def _client_request(peer, forwarded=None):
    from starlette.requests import Request

    headers = [(b"x-forwarded-for", forwarded.encode("ascii"))] if forwarded is not None else []
    return Request({"type": "http", "method": "POST", "path": "/public/chat/v1/sessions",
                    "headers": headers, "client": (peer, 40000), "query_string": b""})


def test_session_limits_use_the_real_client_only_behind_a_pinned_proxy(chat, model):
    from maverick_dashboard import public_chat_api as api

    _write_config(chat.tmp, ON + '[auth.proxy]\ntrusted_proxies = ["10.0.0.0/24"]\n')
    digest = api._client_digest
    behind_proxy = digest(_client_request("10.0.0.5", forwarded="198.51.100.7"))
    assert behind_proxy == hashlib.sha256(b"198.51.100.7").hexdigest()
    # A visitor who sends the header directly is not behind the pinned proxy, so it is ignored.
    direct = digest(_client_request("203.0.113.9", forwarded="198.51.100.7"))
    assert direct == hashlib.sha256(b"203.0.113.9").hexdigest()


def test_message_limits_per_session_and_per_minute(chat, model):
    key = _site(chat, messages_per_session=3, messages_per_minute=2)["publishable_key"]
    token = _session(chat, key)
    assert _say(chat, token, "one").status_code == 200
    assert _say(chat, token, "two").status_code == 200
    minute = _say(chat, token, "three")
    assert minute.status_code == 429
    chat.clock["now"] += 61
    assert _say(chat, token, "three").status_code == 200
    assert _say(chat, token, "four").status_code == 429


def test_a_client_address_is_capped_per_site_per_day_across_its_sessions(chat, model):
    created = _site(chat, messages_per_session=10, messages_per_client_per_day=3)
    key = created["publishable_key"]
    first = _session(chat, key)
    assert _say(chat, first, "one").status_code == 200
    assert _say(chat, first, "two").status_code == 200
    # A new session has its own per-session count, but the client's day is shared by all its sessions.
    assert _say(chat, _session(chat, key), "three").status_code == 200
    capped = _say(chat, _session(chat, key), "four")
    assert capped.status_code == 429
    assert capped.json()["detail"] == "you have reached the daily message limit for this chat. Try again later."
    assert "access-control-allow-origin" in capped.headers
    assert len(model.calls) == 3
    # Each message counts for 24 hours from when it was sent: the first slot frees only after a full day.
    chat.clock["now"] += 86_399
    assert _say(chat, _session(chat, key), "still capped").status_code == 429
    chat.clock["now"] += 1
    assert _say(chat, _session(chat, key), "a day later").status_code == 200


def test_the_daily_client_cap_is_counted_separately_for_each_site(chat, model):
    first = _site(chat, messages_per_client_per_day=1)
    second = _site(chat, origins=[OTHER], messages_per_client_per_day=1)
    assert _say(chat, _session(chat, first["publishable_key"]), "one").status_code == 200
    assert _say(chat, _session(chat, first["publishable_key"]), "two").status_code == 429
    other_token = _start(chat, second["publishable_key"], origin=OTHER).json()["session_token"]
    assert _say(chat, other_token, "one", origin=OTHER).status_code == 200


def _visitor(address):
    """A client on its own peer address, for the same site: the daily count is kept per address."""
    from fastapi.testclient import TestClient
    from maverick_dashboard import app as dash_app

    return TestClient(dash_app.app, base_url="http://127.0.0.1", client=(address, 50000))


def _visit(client, key, origin=SHOP, forwarded=None):
    headers = {"Origin": origin, "Authorization": f"PublicChatKey {key}"}
    if forwarded is not None:
        headers["X-Forwarded-For"] = forwarded
    response = client.post("/public/chat/v1/sessions", headers=headers, content=b"{}")
    assert response.status_code == 201, response.text
    return response.json()["session_token"]


def _ask(client, token, text, origin=SHOP, forwarded=None):
    headers = {"Authorization": f"PublicChatSession {token}", "Content-Type": "application/json",
               "Origin": origin}
    if forwarded is not None:
        headers["X-Forwarded-For"] = forwarded
    return client.post("/public/chat/v1/messages", headers=headers,
                       content=json.dumps({"message": text}).encode("utf-8"))


def test_the_daily_count_is_kept_per_client_address_on_one_site(chat, model):
    key = _site(chat, messages_per_client_per_day=1)["publishable_key"]
    first, second = _visitor("198.51.100.10"), _visitor("198.51.100.11")
    assert _ask(first, _visit(first, key), "one").status_code == 200
    assert _ask(first, _visit(first, key), "two").status_code == 429
    # A different address on the same site has its own day, not the first address's exhausted one.
    assert _ask(second, _visit(second, key), "one").status_code == 200
    assert len(model.calls) == 2


def test_an_untrusted_forwarded_address_cannot_move_a_client_to_another_day(chat, model):
    key = _site(chat, messages_per_client_per_day=1)["publishable_key"]
    visitor = _visitor("203.0.113.9")
    # No proxy is trusted, so the forwarded header is ignored: each try is the same address.
    assert _ask(visitor, _visit(visitor, key), "one", forwarded="198.51.100.7").status_code == 200
    assert _ask(visitor, _visit(visitor, key), "two", forwarded="198.51.100.8").status_code == 429
    # Nor does a forwarded header frame the address it names: that address keeps its own day.
    named = _visitor("198.51.100.7")
    assert _ask(named, _visit(named, key), "named").status_code == 200
    assert len(model.calls) == 2


def test_the_client_daily_cap_defaults_to_200_and_accepts_up_to_5000(chat, model):
    created = _site(chat)
    assert created["site"]["messages_per_client_per_day"] == 200
    assert chat.client.get("/api/v1/public-chat/sites").json()["sites"][0]["messages_per_client_per_day"] == 200
    assert _site(chat, origins=[OTHER], messages_per_client_per_day=5000)["site"][
        "messages_per_client_per_day"] == 5000


def test_the_client_day_limiter_keeps_bounded_memory(monkeypatch):
    from maverick_dashboard import public_chat_api as api

    limiter = api._ClientDayLimiter()
    monkeypatch.setattr(api, "_MAX_CLIENT_DAY_BUCKETS", 2)
    assert limiter.allow("site", "a", 1, 0.0) and limiter.allow("site", "b", 1, 1.0)
    # The table is full. A new client is counted anyway, in place of the client counted longest ago.
    assert limiter.allow("site", "c", 1, 2.0)
    assert len(limiter._buckets) == 2
    assert ("site", "a") not in limiter._buckets
    # A client still in the table keeps its count: at its limit it is refused, and nothing is added.
    assert not limiter.allow("site", "b", 1, 3.0)
    assert not limiter.allow("site", "c", 1, 3.0)
    assert len(limiter._buckets) == 2


def test_a_burst_of_new_clients_never_refuses_a_new_visitor(monkeypatch):
    from maverick_dashboard import public_chat_api as api

    limiter = api._ClientDayLimiter()
    monkeypatch.setattr(api, "_MAX_CLIENT_DAY_BUCKETS", 2)
    assert limiter.allow("site", "old", 1, 0.0)  # its day ends at 86400
    assert limiter.allow("site", "live", 1, 3_600.0)
    # The table is full, and the old client's day has ended: it gives way, and the live client keeps its count.
    assert limiter.allow("site", "new", 1, 86_400.0)
    assert ("site", "old") not in limiter._buckets
    assert ("site", "live") in limiter._buckets
    # Nothing has expired now, so a burst of new addresses pushes out the least recently counted client each time.
    assert all(limiter.allow("site", f"burst-{number}", 1, 86_401.0 + number) for number in range(10))
    assert len(limiter._buckets) == 2
    assert ("site", "burst-9") in limiter._buckets


def test_a_site_store_from_before_the_client_cap_gains_the_column(chat, model):
    import sqlite3

    from maverick_dashboard import public_chat_store as store

    path = store.sites_path(None)
    path.parent.mkdir(parents=True, exist_ok=True)
    legacy = sqlite3.connect(str(path))
    try:
        legacy.execute("CREATE TABLE chat_sites (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
                       "origins_json TEXT NOT NULL, specialist TEXT NOT NULL, greeting TEXT NOT NULL, "
                       "daily_cap_dollars REAL NOT NULL, messages_per_session INTEGER NOT NULL, "
                       "messages_per_minute INTEGER NOT NULL, retention_days INTEGER NOT NULL, "
                       "state TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL)")
        legacy.execute("INSERT INTO chat_sites VALUES ('old', 'Old shop', ?, 'finance_ap', '', 1.0, "
                       "10, 6, 30, 'active', 1.0, 1.0)", (json.dumps([SHOP]),))
        legacy.commit()
    finally:
        legacy.close()
    assert store.get_site(None, "old")["messages_per_client_per_day"] == 200
    assert store.get_site(None, "old")["messages_per_client_per_day"] == 200


def test_per_minute_limit_is_a_sliding_window_not_a_fixed_one(chat, model):
    key = _site(chat, messages_per_session=30, messages_per_minute=6)["publishable_key"]
    token = _session(chat, key)
    assert _say(chat, token, "one").status_code == 200  # t=0
    chat.clock["now"] += 59
    for text in ("two", "three", "four", "five", "six"):  # t=59: six in the last minute
        assert _say(chat, token, text).status_code == 200
    chat.clock["now"] += 1  # t=60: only the t=0 message has aged out
    assert _say(chat, token, "seven").status_code == 200
    assert _say(chat, token, "eight").status_code == 429


def test_message_body_is_capped_at_4_kib(chat, model):
    key = _site(chat)["publishable_key"]
    token = _session(chat, key)
    big = chat.anon.post("/public/chat/v1/messages", headers={
        "Origin": SHOP, "Authorization": f"PublicChatSession {token}",
        "Content-Type": "application/json"}, content=b"{" + b" " * 5000 + b"}")
    assert big.status_code == 413
    assert model.calls == []


def test_answer_path_is_tool_free_budgeted_and_never_reaches_the_agent(chat, model, monkeypatch):
    from maverick import agent as agent_module

    def _no_agent(self, *args, **kwargs):
        raise AssertionError("the agent loop must not be reached from a public visitor")

    monkeypatch.setattr(agent_module.Agent, "__init__", _no_agent)
    key = _site(chat)["publishable_key"]
    token = _session(chat, key)
    response = _say(chat, token, "What are your opening hours?")
    assert response.status_code == 200
    assert response.json()["answer"] == model.text
    call = model.calls[0]
    assert call["tools"] is None
    assert call["_no_failover"] is True and call["max_physical_attempts"] == 1
    assert callable(call["dispatch_guard"])
    assert call["max_tokens"] <= 300
    assert "answer only" in call["system"].lower()
    assert "untrusted" in call["system"].lower()
    assert "fictional test material" not in call["system"]
    assert call["messages"] == [{"role": "user", "content": "What are your opening hours?"}]


def test_a_shared_root_site_never_answers_inside_another_tenant(chat, model, monkeypatch):
    # The site was created with no tenant, so it is stored under the shared root. A request
    # whose active tenant is another one must not answer with that tenant's specialists or budget.
    key = _site(chat)["publishable_key"]
    token = _session(chat, key)
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    response = _say(chat, token, "hello")
    assert response.status_code == 503
    assert model.calls == []


def test_daily_cap_stops_answers_politely_before_each_call(chat, model):
    key = _site(chat, daily_cap_dollars=0.10)["publishable_key"]
    token = _session(chat, key)
    model.dollars = 0.04
    assert _say(chat, token, "one").json()["answer"] == model.text
    assert _say(chat, token, "two").json()["answer"] == model.text
    polite = _say(chat, token, "three")
    assert polite.status_code == 200
    assert "not available right now" in polite.json()["answer"]
    assert len(model.calls) == 2


def test_a_call_billed_above_its_hold_counts_at_its_billed_cost(chat, model):
    # The hold is 0.05 and this call bills 0.07, so the budget refuses it after billing.
    key = _site(chat, daily_cap_dollars=0.10)["publishable_key"]
    token = _session(chat, key)
    model.dollars, model.enforce = 0.07, True
    over = _say(chat, token, "one")
    assert over.status_code == 200
    assert "not available right now" in over.json()["answer"]
    listed = chat.client.get("/api/v1/public-chat/sites").json()["sites"][0]
    assert listed["spent_today_dollars"] == 0.07
    # 0.07 spent plus the next 0.05 hold is over the 0.10 cap, so no second call is made.
    model.enforce = False
    assert "not available right now" in _say(chat, token, "two").json()["answer"]
    assert len(model.calls) == 1


def test_failed_provider_call_keeps_its_reservation_and_is_not_retried(chat, model):
    # Cap 0.10 and a 0.05 reservation per answer: the failed call is treated as
    # possibly billed, so it keeps its 0.05 and only one more answer fits.
    key = _site(chat, daily_cap_dollars=0.10)["publishable_key"]
    token = _session(chat, key)
    model.error = RuntimeError("provider timeout")
    response = _say(chat, token, "one")
    # A provider failure is a server error (503), not a polite answer: a cap refusal is a
    # normal answer, but an outage must show up as a failed request.
    assert response.status_code == 503
    assert response.json()["detail"] == "this chat is not available right now"
    assert "provider timeout" not in response.text
    assert len(model.calls) == 1
    model.error = None
    assert _say(chat, token, "two").json()["answer"] == model.text
    polite = _say(chat, token, "three")
    assert "not available right now" in polite.json()["answer"]
    assert len(model.calls) == 2


def test_revoked_site_ends_existing_sessions(chat, model):
    created = _site(chat)
    token = _session(chat, created["publishable_key"])
    chat.client.post(f"/api/v1/public-chat/sites/{created['site']['id']}/revoke")
    response = _say(chat, token, "still there?")
    assert response.status_code == 401
    assert response.json()["detail"] == "chat session expired or invalid"


def test_rotate_invalidates_the_old_key_and_returns_a_new_one_once(chat, model):
    created = _site(chat)
    old = created["publishable_key"]
    rotated = chat.client.post(f"/api/v1/public-chat/sites/{created['site']['id']}/rotate").json()
    new = rotated["publishable_key"]
    assert new != old and new.startswith("lwpk_")
    assert _start(chat, old).status_code == 401
    assert _start(chat, new).status_code == 201


def test_transcripts_are_sealed_tenant_scoped_and_purged_after_retention(chat, model, monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    created = _site(chat, retention_days=1)
    site_id = created["site"]["id"]
    token = _session(chat, created["publishable_key"])
    question = "Can I get a refund for order 88412?"
    assert _say(chat, token, question).status_code == 200
    viewed = chat.client.get(f"/api/v1/public-chat/sites/{site_id}/transcripts").json()
    assert [row["text"] for row in viewed["messages"]] == [question, model.text]
    from maverick_dashboard import public_chat_store as store

    tenant_db = store.sites_path("tenant-a")
    assert tenant_db.exists() and tenant_db != store.sites_path("tenant-b")
    assert question.encode("utf-8") not in tenant_db.read_bytes()
    assert question.encode("utf-8") not in store.index_path().read_bytes()
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert chat.client.get("/api/v1/public-chat/sites").json()["sites"] == []
    assert chat.client.get(f"/api/v1/public-chat/sites/{site_id}/transcripts").status_code == 404
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    chat.clock["now"] += 2 * 86_400
    assert chat.client.get(f"/api/v1/public-chat/sites/{site_id}/transcripts").json()["messages"] == []


def _stored_rows(tenant, site_id):
    """Transcript rows as they sit on disk, read directly with no admin view."""
    import sqlite3

    from maverick_dashboard import public_chat_store as store

    with sqlite3.connect(str(store.sites_path(tenant))) as db:
        return db.execute("SELECT COUNT(*) FROM chat_transcripts WHERE site_id = ?",
                          (site_id,)).fetchone()[0]


def test_revoking_a_site_deletes_its_transcripts_at_once(chat, model):
    created = _site(chat)
    site_id = created["site"]["id"]
    token = _session(chat, created["publishable_key"])
    assert _say(chat, token, "is this stored?").status_code == 200
    assert _stored_rows(None, site_id) == 2
    chat.client.post(f"/api/v1/public-chat/sites/{site_id}/revoke")
    assert _stored_rows(None, site_id) == 0


def test_retention_is_enforced_for_every_tenant_on_a_visit_without_an_admin_read(chat, model, monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    old = _site(chat, retention_days=1)
    kept = _site(chat, origins=[OTHER], retention_days=30)
    for created, origin in ((old, SHOP), (kept, OTHER)):
        token = _start(chat, created["publishable_key"], origin=origin).json()["session_token"]
        assert _say(chat, token, "question", origin=origin).status_code == 200
        assert _stored_rows("tenant-a", created["site"]["id"]) == 2
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    fresh = _site(chat, origins=[EVIL])
    chat.clock["now"] += 2 * 86_400
    # A visit to another tenant's chat runs the sweep for every tenant, not only its own.
    assert _start(chat, fresh["publishable_key"], origin=EVIL).status_code == 201
    assert _stored_rows("tenant-a", old["site"]["id"]) == 0
    assert _stored_rows("tenant-a", kept["site"]["id"]) == 2  # inside its 30 days


def test_the_background_sweep_creates_no_files_where_chat_was_never_used(chat, model, monkeypatch):
    from maverick import compliance_history, deadline_alerts, webhook_subscriptions
    from maverick_dashboard import deadline_alerts_scheduler as scheduler
    from maverick_dashboard import public_chat_store as store

    monkeypatch.setattr(deadline_alerts, "settings", lambda: {"enabled": False, "poll_seconds": 900})
    monkeypatch.setattr(webhook_subscriptions, "process_due", lambda **kwargs: 0)
    monkeypatch.setattr(compliance_history, "recheck_if_due", lambda **kwargs: None)
    scheduler._tick(chat.clock["now"], {})
    # The sweep ran on this pass (so the pass is what keeps it from creating files), and it still created none.
    assert store._last_sweep == chat.clock["now"]
    assert not (chat.home / "public_chat").exists()


def test_an_idle_install_purges_expired_transcripts_on_the_background_schedule(chat, model, monkeypatch):
    # No visit and no admin view happens: only the dashboard's scheduler pass runs the sweep.
    from maverick import compliance_history, deadline_alerts, webhook_subscriptions
    from maverick_dashboard import deadline_alerts_scheduler as scheduler
    from maverick_dashboard import public_chat_store as store

    monkeypatch.setattr(deadline_alerts, "settings", lambda: {"enabled": False, "poll_seconds": 900})
    monkeypatch.setattr(webhook_subscriptions, "process_due", lambda **kwargs: 0)
    monkeypatch.setattr(compliance_history, "recheck_if_due", lambda **kwargs: None)
    created = _site(chat, retention_days=1)
    site_id = created["site"]["id"]
    site = store.get_site(None, site_id)
    t0 = chat.clock["now"]
    store.append_transcript(None, site, "conversation", "visitor", "inside retention", now=t0)
    store.append_transcript(None, site, "conversation", "visitor", "two days old", now=t0 - 2 * 86_400)
    assert _stored_rows(None, site_id) == 2
    # The dashboard starts: the first pass sweeps at once. Nothing has expired yet except the old row.
    scheduler._tick(t0, {})
    assert store._last_sweep == t0
    assert _stored_rows(None, site_id) == 1
    # Half an hour later the sweep is not due, so it does not run.
    store.append_transcript(None, site, "conversation", "visitor", "two days old again", now=t0 - 2 * 86_400)
    scheduler._tick(t0 + 1_800, {})
    assert _stored_rows(None, site_id) == 2
    # An hour after the last sweep it runs again, with no visit needed.
    scheduler._tick(t0 + 3_600, {})
    assert store._last_sweep == t0 + 3_600
    assert _stored_rows(None, site_id) == 1


def test_a_workspace_with_a_broken_file_does_not_stop_the_others_being_swept(chat, model, monkeypatch, caplog):
    from maverick_dashboard import public_chat_store as store

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    broken = _site(chat, retention_days=1)
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    healthy = _site(chat, origins=[OTHER], retention_days=1)
    t0 = chat.clock["now"]
    for tenant, created in (("tenant-a", broken), ("tenant-b", healthy)):
        site = store.get_site(tenant, created["site"]["id"])
        store.append_transcript(tenant, site, "conversation", "visitor", "two days old", now=t0 - 2 * 86_400)
    assert _stored_rows("tenant-b", healthy["site"]["id"]) == 1
    # tenant-a's sites file is damaged, so it can be neither read nor written.
    store.sites_path("tenant-a").write_bytes(b"this is not a database\n" * 100)
    failed = store.purge_expired(now=t0)
    assert failed == ["tenant-a"]
    assert _stored_rows("tenant-b", healthy["site"]["id"]) == 0
    assert "retention sweep failed for workspace tenant-a" in caplog.text


def test_auth_exemption_covers_only_the_public_prefix(chat):
    from maverick_dashboard import auth

    assert auth._self_authenticated_path("/public/chat/v1/sessions")
    assert auth._self_authenticated_path("/public/chat/v1/widget.js")
    assert not auth._self_authenticated_path("/api/v1/public-chat/sites")
    assert not auth._self_authenticated_path("/public/chat/v1x")


def test_admin_actions_are_audited_without_key_material(chat, model, monkeypatch):
    from maverick import audit

    recorded = []

    def _record(kind, **detail):
        recorded.append({"kind": str(kind), **detail})

    monkeypatch.setattr(audit, "audit_event", _record)
    created = _site(chat)
    site_id = created["site"]["id"]
    chat.client.post(f"/api/v1/public-chat/sites/{site_id}/rotate")
    chat.client.get(f"/api/v1/public-chat/sites/{site_id}/transcripts")
    chat.client.post(f"/api/v1/public-chat/sites/{site_id}/revoke")
    verbs = [row.get("verb") for row in recorded if str(row.get("verb", "")).startswith("public_chat")]
    assert verbs == ["public_chat_site_created", "public_chat_key_rotated",
                     "public_chat_transcripts_viewed", "public_chat_site_revoked"]
    assert all(created["publishable_key"] not in json.dumps(row, default=str) for row in recorded)


def test_a_refused_site_creation_writes_no_created_audit_event(chat, model, monkeypatch):
    from maverick import audit

    recorded = []
    monkeypatch.setattr(audit, "audit_event", lambda kind, **detail: recorded.append(detail))
    _site(chat)
    duplicate = chat.client.post("/api/v1/public-chat/sites", json={
        "display_name": "Second", "origins": [SHOP], "specialist": "finance_ap",
        "daily_cap_dollars": 1.0})
    assert duplicate.status_code == 409
    created = [row for row in recorded if row.get("verb") == "public_chat_site_created"]
    assert len(created) == 1


def test_a_failed_index_write_leaves_no_site_behind(chat, model, monkeypatch):
    import sqlite3

    from maverick_dashboard import public_chat_store as store

    real_write = store._write

    def _failing_index(path, schema):
        if path == store.index_path():
            raise sqlite3.OperationalError("database is locked")
        return real_write(path, schema)

    monkeypatch.setattr(store, "_write", _failing_index)
    failed = chat.client.post("/api/v1/public-chat/sites", json={
        "display_name": "Acme shop", "origins": [SHOP], "specialist": "finance_ap",
        "daily_cap_dollars": 1.0})
    assert failed.status_code == 503
    monkeypatch.setattr(store, "_write", real_write)
    assert chat.client.get("/api/v1/public-chat/sites").json()["sites"] == []


def test_a_site_whose_creation_cannot_be_audited_is_revoked_again(chat, model, monkeypatch):
    from maverick import audit

    def _refuse(kind, **detail):
        raise audit.AuditRefused("the activity record is closed")

    monkeypatch.setattr(audit, "audit_event", _refuse)
    response = chat.client.post("/api/v1/public-chat/sites", json={
        "display_name": "Acme shop", "origins": [SHOP], "specialist": "finance_ap",
        "daily_cap_dollars": 1.0})
    assert response.status_code == 503
    assert "publishable_key" not in response.text
    listed = chat.client.get("/api/v1/public-chat/sites").json()["sites"]
    assert [site["state"] for site in listed] == ["revoked"]


def test_admin_create_refuses_an_oversized_body(chat, model):
    body = json.dumps({"display_name": "x" * 20_000, "origins": [SHOP], "specialist": "finance_ap",
                       "daily_cap_dollars": 1.0})
    response = chat.client.post("/api/v1/public-chat/sites", content=body.encode("utf-8"),
                                headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert chat.client.get("/api/v1/public-chat/sites").json()["sites"] == []


def test_admin_routes_need_the_admin_permission(chat, model, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import auth

    def _deny(request, permission, **kwargs):
        raise HTTPException(status_code=403, detail="not allowed")

    monkeypatch.setattr(auth, "require_permission", _deny)
    response = chat.client.post("/api/v1/public-chat/sites", json={"display_name": "x"})
    assert response.status_code == 403
    assert not (chat.home / "public_chat" / "index.sqlite3").exists()


def test_public_routes_are_mounted_in_the_real_app(chat):
    app_module = importlib.import_module("maverick_dashboard.app")
    assert "/api/v1/public-chat/sites" in app_module.app.openapi()["paths"]
    assert not any(path.startswith("/public/chat/") for path in app_module.app.openapi()["paths"])
    assert chat.anon.get("/public/chat/v1/widget.js").status_code == 200


def test_settings_catalog_offers_the_two_public_chat_switches():
    """Both switches are off by default, and the page reads them from the feature's own module."""
    from maverick.migrate import KNOWN_SECTIONS
    from maverick_dashboard import settings_catalog as catalog

    assert "public_chat" in KNOWN_SECTIONS
    enabled = catalog.BY_ID["public_chat.enabled"]
    assert enabled.default is False
    assert enabled.reader == "maverick_dashboard.public_chat_api"
    local = catalog.BY_ID["public_chat.allow_localhost_origins"]
    assert local.default is False and local.reader == enabled.reader


PARTIAL = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "_public_chat_admin.html"
ADMIN_JS = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork-public-chat-admin.js"


def test_the_channels_page_shows_the_public_chat_section_only_while_enabled(chat, model):
    shown = chat.client.get("/channels")
    assert shown.status_code == 200
    assert 'id="pc-sites"' in shown.text and 'name="daily_cap_dollars"' in shown.text
    assert '<option value="finance_ap"' in shown.text
    assert "/static/lightwork-public-chat-admin.js" in shown.text
    _write_config(chat.tmp, OFF)
    hidden = chat.client.get("/channels")
    assert hidden.status_code == 200
    assert "Chat on your public website" not in hidden.text
    assert "pc-sites" not in hidden.text and "lightwork-public-chat-admin.js" not in hidden.text


def test_the_channels_page_serves_the_admin_script_it_references(chat, model):
    page = chat.client.get("/channels")
    assert page.status_code == 200
    source = "/static/lightwork-public-chat-admin.js"
    assert source in page.text
    script = chat.client.get(source)
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("application/javascript")
    assert script.content == ADMIN_JS.read_bytes()


def test_the_section_needs_the_same_admin_check_as_the_admin_api(chat, model, monkeypatch):
    from maverick_dashboard import auth

    assert chat.api.admin_section_context(object()) != {}
    monkeypatch.setattr(auth, "has_permission", lambda request, permission, **kwargs: False)
    assert chat.api.admin_section_context(object()) == {}
    assert "pc-sites" not in chat.client.get("/channels").text


def test_the_section_has_no_inline_handlers_styles_or_inline_scripts():
    html = PARTIAL.read_text(encoding="utf-8")
    assert re.search(r"\son[a-z]+\s*=", html) is None
    assert "style=" not in html
    # Behaviour lives in the static script, loaded with src; an inline script would need a nonce.
    for tag in re.findall(r"<script[^>]*>", html):
        assert "src=" in tag


def test_the_section_script_renders_text_only_and_keeps_no_key_in_the_browser():
    source = ADMIN_JS.read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "localStorage",
                      "sessionStorage", "eval(", "Function("):
        assert forbidden not in source, forbidden
    assert "textContent" in source
    # Recent messages: bounded to 50 and shown newest first.
    assert "limit=50" in source and "slice().reverse()" in source


def test_the_form_limits_are_the_api_limits():
    from maverick_dashboard.public_chat_api import SiteIn

    html = PARTIAL.read_text(encoding="utf-8")

    def tag(name):
        return re.search(rf'<input[^>]*name="{name}"[^>]*>', html).group(0)

    def attribute(name, attr):
        return re.search(rf'\s{attr}="([^"]+)"', tag(name)).group(1)

    def bounds(name):
        found = {}
        for item in SiteIn.model_fields[name].metadata:
            for attr in ("gt", "ge", "le", "max_length"):
                if hasattr(item, attr):
                    found[attr] = getattr(item, attr)
        return found

    for name in ("messages_per_session", "messages_per_minute", "messages_per_client_per_day",
                 "retention_days", "daily_cap_dollars"):
        limits = bounds(name)
        assert float(attribute(name, "max")) == float(limits["le"]), name
        if "ge" in limits:
            assert float(attribute(name, "min")) == float(limits["ge"]), name
    for name in ("display_name", "greeting"):
        assert int(attribute(name, "maxlength")) == bounds(name)["max_length"], name


def test_the_admin_form_sends_whole_dollar_limits_the_api_accepts(chat, model):
    created = _site(chat, daily_cap_dollars=5, messages_per_client_per_day=5000)
    assert created["site"]["daily_cap_dollars"] == 5.0


def test_the_catalog_and_docs_say_where_websites_are_managed():
    from pathlib import Path

    from maverick_dashboard import settings_catalog as catalog

    enabled = catalog.BY_ID["public_chat.enabled"]
    assert "Channels page" in enabled.help
    assert "does not exist" not in enabled.help and "not built" not in enabled.help
    docs = (Path(__file__).resolve().parents[3] / "docs" / "public-chat.md").read_text(encoding="utf-8")
    assert "dashboard page for this is not built" not in docs
    assert "A scheduled sweep is not built" not in docs
    assert "Channels page" in docs


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_a_non_admin_gets_no_site_admin_route_and_no_channels_page(chat, model, monkeypatch, role):
    from maverick_dashboard import auth

    # Made while auth is off, as the local administrator; the caller is a signed-in non-admin below.
    created = _site(chat)
    site_id = created["site"]["id"]
    token = _session(chat, created["publishable_key"])
    assert _say(chat, token, "a question").status_code == 200
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:staff")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: role)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: role)
    refused = [
        chat.client.get("/api/v1/public-chat/sites"),
        chat.client.post("/api/v1/public-chat/sites", json={"display_name": "x"}),
        chat.client.post(f"/api/v1/public-chat/sites/{site_id}/rotate"),
        chat.client.post(f"/api/v1/public-chat/sites/{site_id}/revoke"),
        chat.client.get(f"/api/v1/public-chat/sites/{site_id}/transcripts"),
    ]
    assert [response.status_code for response in refused] == [403] * 5
    # The refusals changed nothing: the key still works and the stored messages remain.
    assert _start(chat, created["publishable_key"]).status_code == 201
    assert _stored_rows(None, site_id) == 2
    # The Channels page itself is closed to this role, so the section is never sent to it.
    assert chat.client.get("/channels").status_code == 403


@pytest.mark.parametrize("role", ["operator", "viewer"])
def test_the_section_context_is_empty_for_a_non_admin_principal(chat, model, monkeypatch, role):
    from maverick_dashboard import auth
    from starlette.requests import Request

    request = Request({"type": "http", "method": "GET", "path": "/channels", "headers": [],
                       "client": ("203.0.113.9", 40000), "query_string": b""})
    request.state.principal = SimpleNamespace(principal="user:staff")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: role)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: role)
    assert chat.api.admin_section_context(request) == {}
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin")
    assert chat.api.admin_section_context(request)["public_chat_section"] is True


def test_an_admin_caller_gets_the_routes_and_the_section(chat, model, monkeypatch):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:owner")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "admin")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin")
    assert chat.client.get("/api/v1/public-chat/sites").status_code == 200
    shown = chat.client.get("/channels")
    assert shown.status_code == 200
    assert "pc-sites" in shown.text
