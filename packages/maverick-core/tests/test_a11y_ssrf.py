"""a11y `check` must refuse file:// and private/metadata URLs (LFI / SSRF):
pa11y and axe drive a real headless browser, so the target URL is attacker-
reachable just like an http_fetch."""
from __future__ import annotations

import pytest
from maverick.tools.a11y import _check_url, _pin_url, a11y


def test_rejects_file_scheme():
    out = _check_url("file:///etc/passwd")
    assert out is not None and "http(s)" in out


def test_rejects_non_http_scheme():
    assert _check_url("ftp://example.com/x") is not None


def test_rejects_loopback_host():
    assert _check_url("http://127.0.0.1/") is not None


def test_rejects_metadata_ip():
    assert _check_url("http://169.254.169.254/latest/meta-data/") is not None


def test_allow_private_override_permits_loopback(monkeypatch):
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    assert _check_url("http://127.0.0.1/") is None


def test_check_op_blocks_file_url_before_runner():
    # The URL guard runs BEFORE _ensure_runner, so a file:// target is refused
    # with the SSRF error even when no pa11y/axe binary is installed.
    out = a11y().fn({"op": "check", "url": "file:///etc/passwd"})
    assert out.startswith("ERROR") and "http(s)" in out


def test_pin_url_rewrites_host_to_pinned_ip(monkeypatch):
    # _pin_url must swap the hostname for a single validated public IP so the
    # headless browser cannot re-resolve and DNS-rebind after the guard passes.
    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", lambda host: "93.184.216.34")
    assert _pin_url("http://evil.example:8080/x") == "http://93.184.216.34:8080/x"


def test_pin_url_refuses_rebind_to_private_ip(monkeypatch):
    # If the second resolution now returns a private/metadata IP, resolve_pinned_ip
    # raises BlockedHost; _pin_url propagates it so the caller fails closed rather
    # than handing the browser a fetchable rebound URL.
    import maverick.tools._ssrf as _ssrf

    def _rebind(host):
        raise _ssrf.BlockedHost("rebound to 169.254.169.254")

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", _rebind)
    with pytest.raises(_ssrf.BlockedHost):
        _pin_url("http://evil.example/")


def test_pin_url_keeps_hostname_for_https(monkeypatch):
    # For HTTPS the host must NOT be rewritten to an IP literal: the browser
    # validates the TLS cert against the netloc, and an IP won't match the
    # cert's SAN, so every real HTTPS target would fail. resolve_pinned_ip still
    # runs (re-validates the host is public), but the URL is handed back intact.
    import maverick.tools._ssrf as _ssrf
    calls = []
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip",
                        lambda host: calls.append(host) or "93.184.216.34")
    assert _pin_url("https://example.com/x") == "https://example.com/x"
    assert calls == ["example.com"]  # the public-IP re-validation still happened


def test_pin_url_refuses_https_rebind_to_private_ip(monkeypatch):
    # HTTPS still fails closed when re-resolution now returns a private IP.
    import maverick.tools._ssrf as _ssrf

    def _rebind(host):
        raise _ssrf.BlockedHost("rebound to 169.254.169.254")

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", _rebind)
    with pytest.raises(_ssrf.BlockedHost):
        _pin_url("https://evil.example/")


def test_check_html_path_still_allowed_without_url_guard(monkeypatch):
    # check_html takes a confined local path, not a URL -- the url guard must
    # not interfere with it. With no sandbox and no binary, we just get the
    # runner-missing error (not an SSRF rejection).
    out = a11y().fn({"op": "check_html", "path": "report.html"})
    assert out.startswith("ERROR")
    assert "http(s)" not in out
