"""http_fetch resolve-once-pin (DNS-rebind protection) + the robots fetch going
through the SSRF-safe, IP-pinned client."""
from __future__ import annotations

import pytest


def test_resolve_pinned_rejects_a_private_resolving_host(monkeypatch):
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    from maverick.tools.http_fetch import _resolve_pinned
    # localhost resolves to a loopback IP -> refused, and no pin is handed to the
    # connection layer, so it can't re-resolve to an internal address.
    with pytest.raises(ValueError):
        _resolve_pinned("localhost")


def test_resolve_pinned_honors_allow_private(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    from maverick.tools.http_fetch import _resolve_pinned
    assert _resolve_pinned("localhost") == "localhost"   # override: no pinning


def test_check_robots_uses_the_ssrf_safe_client(monkeypatch):
    import maverick.tools._ssrf as ssrf
    seen = {}

    class _Resp:
        status_code = 200
        text = "User-agent: *\nDisallow:"

    def _fake_safe_get(url, **kwargs):
        seen["url"] = url
        return _Resp()

    monkeypatch.setattr(ssrf, "safe_get", _fake_safe_get)
    from maverick.tools.http_fetch import _check_robots
    assert _check_robots("https://example.com/page") is True
    assert seen["url"].endswith("/robots.txt")          # fetched via safe_get, pinned


@pytest.fixture
def allow_private_setting(monkeypatch, tmp_path):
    """``[tools] fetch_allow_private = "1"`` in the config file, no env var."""
    from maverick import config
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[tools]\nfetch_allow_private = "1"\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_allow_private_setting_reaches_every_check_of_the_fetch(allow_private_setting):
    # The All settings switch does what its label says: the first host check,
    # the pinned connect, the agent tool's preflight and the httpx pin all agree.
    from urllib.parse import urlparse

    from maverick.tools import _ssrf
    from maverick.tools.http_fetch import _preflight_fetch, _resolve_pinned, is_blocked_host
    assert is_blocked_host("localhost") is False
    assert _resolve_pinned("localhost") == "localhost"
    url = "https://127.0.0.1/x"
    assert _preflight_fetch(url, urlparse(url)) is None
    assert _ssrf.resolve_pinned_ip("127.0.0.1") == "127.0.0.1"


def test_without_the_setting_the_pinned_connect_stays_closed(monkeypatch, tmp_path):
    from maverick import config
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    config.reset_config_cache()
    from maverick.tools.http_fetch import _resolve_pinned
    with pytest.raises(ValueError):
        _resolve_pinned("localhost")
    config.reset_config_cache()


def test_shared_address_space_is_refused_at_the_pinned_connect(monkeypatch):
    # 100.64.0.0/10 (carrier-grade NAT) holds Alibaba Cloud's metadata service
    # at 100.100.100.200; ipaddress does not call it private.
    import socket
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.100.100.200", 0))])
    from maverick.tools.http_fetch import _check_url_allowed, _resolve_pinned
    with pytest.raises(ValueError):
        _resolve_pinned("metadata.test")
    with pytest.raises(ValueError):
        _check_url_allowed("https://metadata.test/latest/meta-data/", allow_http=False)


def test_fetch_override_keeps_link_local_blocked(monkeypatch):
    import socket

    from maverick.tools import http_fetch

    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")

    def fake(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert http_fetch.is_blocked_host("metadata.internal") is True
    import pytest

    with pytest.raises(http_fetch.BlockedAddress):
        http_fetch._resolve_pinned("metadata.internal")

    def fake_private(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_private)
    assert http_fetch.is_blocked_host("intranet.example") is False
    assert http_fetch._resolve_pinned("intranet.example") == "intranet.example"  # override: no pinning
