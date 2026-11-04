"""Out-of-process model proxy: key injection, header scrubbing, SSRF guard."""
from __future__ import annotations

from maverick import model_proxy as mp


class _FakeResp:
    def __init__(self, status=200, headers=None, content=b"ok"):
        self.status_code = status
        self.headers = headers or {"Content-Type": "application/json",
                                   "Transfer-Encoding": "chunked"}
        self.content = content


class _FakeClient:
    def __init__(self, resp=None, raises=None):
        self.calls: list = []
        self._resp = resp or _FakeResp()
        self._raises = raises

    def request(self, method, url, headers=None, content=None, timeout=None):
        self.calls.append({"method": method, "url": url,
                           "headers": headers or {}, "content": content})
        if self._raises:
            raise self._raises
        return self._resp


def _cfg(**kw):
    base = dict(upstream="https://api.anthropic.com", api_key="PROXY-KEY",  # pragma: allowlist secret
                client_token="CLIENT-TOKEN")
    base.update(kw)
    return mp.ProxyConfig(**base)


# ---- build_request (security core) ----

def test_drops_client_auth_and_injects_proxy_key_bearer():
    url, h = mp.build_request(
        _cfg(), "v1/messages",
        {"Authorization": "Bearer AGENT-KEY", "x-api-key": "AGENT",
         "Content-Type": "application/json"},
    )
    assert url == "https://api.anthropic.com/v1/messages"
    assert h["Authorization"] == "Bearer PROXY-KEY"
    assert "AGENT-KEY" not in h.get("Authorization", "")
    assert "x-api-key" not in h               # client credential dropped
    assert h["Content-Type"] == "application/json"


def test_x_api_key_auth_style():
    _, h = mp.build_request(
        _cfg(auth_style="x-api-key"), "v1/messages",
        {"Authorization": "Bearer AGENT-KEY"},
    )
    assert h["x-api-key"] == "PROXY-KEY"
    assert "Authorization" not in h


def test_scrubs_hop_by_hop_headers():
    _, h = mp.build_request(
        _cfg(), "v1/x",
        {"Host": "evil", "Connection": "keep-alive", "Content-Length": "5",
         "Transfer-Encoding": "chunked", "Accept": "application/json"},
    )
    for bad in ("Host", "Connection", "Content-Length", "Transfer-Encoding"):
        assert bad not in h
    assert h["Accept"] == "application/json"


def test_blocks_host_outside_allow_set():
    cfg = _cfg(allow_hosts=frozenset({"api.openai.com"}))
    try:
        mp.build_request(cfg, "v1/x", {})
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "not in allow-set" in str(e)


def test_allowed_defaults_to_upstream_host():
    assert _cfg().allowed() == frozenset({"api.anthropic.com"})


# ---- forward / handle ----

def test_forward_sends_proxy_key_and_returns_response():
    client = _FakeClient(_FakeResp(200, {"Content-Type": "application/json",
                                         "Connection": "close"}, b"{}"))
    status, headers, body = mp.forward(
        _cfg(), "POST", "v1/messages",
        {"Authorization": "Bearer AGENT-KEY"}, b'{"x":1}', client=client)
    assert status == 200 and body == b"{}"
    assert "Connection" not in headers          # hop-by-hop scrubbed on response too
    sent = client.calls[0]
    assert sent["headers"]["Authorization"] == "Bearer PROXY-KEY"
    assert sent["url"] == "https://api.anthropic.com/v1/messages"
    assert sent["content"] == b'{"x":1}'


def test_handle_blocked_host_returns_403():
    cfg = _cfg(allow_hosts=frozenset({"api.openai.com"}))
    status, _, body = mp.handle(
        cfg, "POST", "v1/messages",
        {"Authorization": "Bearer CLIENT-TOKEN"}, b"", client=_FakeClient())
    assert status == 403 and b"not in allow-set" in body


def test_handle_upstream_error_returns_502():
    client = _FakeClient(raises=RuntimeError("connection refused"))
    status, _, body = mp.handle(
        _cfg(), "POST", "v1/messages",
        {"Authorization": "Bearer CLIENT-TOKEN"}, b"", client=client)
    assert status == 502 and b"proxy error" in body


def test_handle_requires_client_token():
    status, _, body = mp.handle(
        _cfg(), "POST", "v1/messages", {}, b"", client=_FakeClient())
    assert status == 401 and b"authentication required" in body


def test_handle_blocks_non_model_routes_even_when_authenticated():
    status, _, body = mp.handle(
        _cfg(), "GET", "/v1/files?limit=1",
        {"Authorization": "Bearer CLIENT-TOKEN"}, b"", client=_FakeClient())
    assert status == 403 and b"route not allowed" in body


def test_handle_forwards_allowed_route_with_proxy_key_after_client_auth():
    client = _FakeClient()
    status, _, body = mp.handle(
        _cfg(), "POST", "/v1/messages?beta=1",
        {"Authorization": "Bearer CLIENT-TOKEN", "Content-Type": "application/json"},
        b"{}", client=client)
    assert status == 200 and body == b"ok"
    sent = client.calls[0]
    assert sent["url"] == "https://api.anthropic.com/v1/messages?beta=1"
    assert sent["headers"]["Authorization"] == "Bearer PROXY-KEY"
    assert "CLIENT-TOKEN" not in sent["headers"]["Authorization"]


def test_custom_allowed_routes_can_enable_provider_specific_path():
    client = _FakeClient()
    cfg = _cfg(allowed_routes=frozenset({"GET /v1/models"}))
    status, _, _ = mp.handle(
        cfg, "GET", "/v1/models",
        {"x-maverick-proxy-token": "CLIENT-TOKEN"}, b"", client=client)
    assert status == 200
    assert client.calls[0]["url"] == "https://api.anthropic.com/v1/models"


# ---- config ----

def test_config_from_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROXY_UPSTREAM", "https://api.openai.com")
    monkeypatch.setenv("MAVERICK_PROXY_KEY", "sk-secret")
    monkeypatch.setenv("MAVERICK_PROXY_LISTEN", "0.0.0.0:9000")
    monkeypatch.setenv("MAVERICK_PROXY_AUTH_STYLE", "bearer")
    monkeypatch.setenv("MAVERICK_PROXY_CLIENT_TOKEN", "client-secret")
    monkeypatch.setenv("MAVERICK_PROXY_ALLOWED_ROUTES", "GET /v1/models, post v1/messages")
    cfg = mp.config_from_env()
    assert cfg.upstream == "https://api.openai.com" and cfg.api_key == "sk-secret"  # pragma: allowlist secret
    assert cfg.listen_host == "0.0.0.0" and cfg.listen_port == 9000
    assert cfg.client_token == "client-secret"
    assert cfg.allowed_routes == frozenset({"GET /v1/models", "POST /v1/messages"})
    assert cfg.allowed() == frozenset({"api.openai.com"})


def test_config_from_env_none_when_unset(monkeypatch):
    for k in ("MAVERICK_PROXY_UPSTREAM", "MAVERICK_PROXY_KEY",
              "MAVERICK_PROXY_LISTEN", "MAVERICK_PROXY_AUTH_STYLE",
              "MAVERICK_PROXY_CLIENT_TOKEN", "MAVERICK_PROXY_ALLOWED_ROUTES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(mp, "load_config", dict)
    assert mp.config_from_env() is None


def test_split_listen():
    assert mp._split_listen("") == ("127.0.0.1", mp.DEFAULT_PORT)
    assert mp._split_listen("1.2.3.4:80") == ("1.2.3.4", 80)
    assert mp._split_listen("host-only") == ("host-only", mp.DEFAULT_PORT)
    assert mp._split_listen("bad:port") == ("127.0.0.1", mp.DEFAULT_PORT)
