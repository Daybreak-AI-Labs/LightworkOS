"""`maverick doctor` flags an insecure reverse-proxy-SSO config: proxy auth on
with no trusted_proxies pin and the loopback fallback still active.
Advisory -- a warning, never a failure; off-by-default/pinned configs are silent."""
from __future__ import annotations

import maverick.health as h
import maverick.proxy_auth as pa


def test_proxy_auth_off_is_silent(monkeypatch, capsys):
    monkeypatch.delenv("MAVERICK_PROXY_AUTH", raising=False)
    monkeypatch.setattr(pa, "_section", dict)
    h._FAILURES.clear()
    h._check_proxy_auth()
    assert "proxy-auth" not in capsys.readouterr().out


def test_proxy_auth_unpinned_default_is_safe(monkeypatch, capsys):
    # #11: with no pin and trust_loopback unset, the loopback fallback is now
    # OFF by default -> the forwarded header is refused from every peer, so the
    # doctor reports it safe (green), not a spoofing risk.
    monkeypatch.setenv("MAVERICK_PROXY_AUTH", "1")
    monkeypatch.setattr(pa, "_section", dict)  # no pin, no trust_loopback override
    h._FAILURES.clear()
    h._check_proxy_auth()
    out = capsys.readouterr().out
    assert "proxy-auth" in out and "loopback fallback disabled" in out
    assert h._FAILURES == []


def test_proxy_auth_explicit_loopback_trust_warns(monkeypatch, capsys):
    # An explicit trust_loopback = true with no pin stays spoofable by any
    # co-located loopback process -> advisory warning, never a failure.
    monkeypatch.setenv("MAVERICK_PROXY_AUTH", "1")
    monkeypatch.setattr(pa, "_section", lambda: {"trust_loopback": True})
    h._FAILURES.clear()
    h._check_proxy_auth()
    out = capsys.readouterr().out
    assert "proxy-auth" in out and "spoof" in out
    assert "✗" not in out          # advisory (yellow), not a red failure
    assert h._FAILURES == []        # does not affect the exit code


def test_proxy_auth_pinned_is_green(monkeypatch, capsys):
    monkeypatch.setenv("MAVERICK_PROXY_AUTH", "1")
    monkeypatch.setattr(pa, "_section", lambda: {"trusted_proxies": ["10.0.0.5"]})
    h._FAILURES.clear()
    h._check_proxy_auth()
    out = capsys.readouterr().out
    assert "proxy-auth" in out and "pinned" in out
    assert h._FAILURES == []
