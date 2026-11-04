"""Tests for the dns_lookup tool (maverick.tools.dns_lookup)."""
from __future__ import annotations

# ---------- DNS lookup tool ----------

def test_dns_requires_op():
    from maverick.tools.dns_lookup import dns_lookup
    assert "op is required" in dns_lookup().fn({})


def test_dns_socket_fallback_for_a(monkeypatch):
    """Without dnspython, A queries fall back to getaddrinfo."""
    monkeypatch.setattr(
        "maverick.tools.dns_lookup._have_dnspython", lambda: False,
    )
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda host, *a, **k: [
            (0, 0, 0, "", ("93.184.216.34", 0)),
        ],
    )
    from maverick.tools.dns_lookup import dns_lookup
    out = dns_lookup().fn({"op": "resolve", "host": "example.com", "type": "A"})
    assert "93.184.216.34" in out


def test_dns_socket_fallback_refuses_mx(monkeypatch):
    monkeypatch.setattr(
        "maverick.tools.dns_lookup._have_dnspython", lambda: False,
    )
    from maverick.tools.dns_lookup import dns_lookup
    out = dns_lookup().fn({"op": "resolve", "host": "example.com", "type": "MX"})
    assert "dnspython" in out


def test_dns_reverse_socket_fallback(monkeypatch):
    monkeypatch.setattr(
        "maverick.tools.dns_lookup._have_dnspython", lambda: False,
    )
    monkeypatch.setattr(
        "socket.gethostbyaddr",
        lambda ip: ("a.example.com", [], [ip]),
    )
    from maverick.tools.dns_lookup import dns_lookup
    out = dns_lookup().fn({"op": "reverse", "ip": "1.2.3.4"})
    assert "a.example.com" in out


def test_dns_reverse_requires_ip():
    from maverick.tools.dns_lookup import dns_lookup
    out = dns_lookup().fn({"op": "reverse"})
    assert "requires ip" in out
