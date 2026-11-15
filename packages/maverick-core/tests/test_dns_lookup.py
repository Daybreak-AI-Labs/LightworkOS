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


def test_dns_rejects_record_types_outside_the_schema(monkeypatch):
    monkeypatch.setattr("maverick.tools.dns_lookup._have_dnspython", lambda: True)
    from maverick.tools.dns_lookup import dns_lookup
    out = dns_lookup().fn({"op": "resolve", "host": "example.com", "type": "AXFR"})
    assert out.startswith("ERROR") and "rtype" in out


def test_dns_lookup_obeys_the_egress_policy(monkeypatch):
    """A DNS query carries the name to a resolver, so the network posture and
    the egress lists that hold http_fetch hold dns_lookup too."""
    import maverick.tenant.egress as egress
    seen: list[tuple[str, str]] = []

    def _deny(tool, host):
        seen.append((tool, host))
        return False

    monkeypatch.setattr(egress, "egress_allowed", _deny)
    monkeypatch.setattr("maverick.tools.dns_lookup._have_dnspython", lambda: False)

    def _no_resolve(*a, **k):
        raise AssertionError("a denied name must not be resolved")

    monkeypatch.setattr("socket.getaddrinfo", _no_resolve)
    monkeypatch.setattr("socket.gethostbyaddr", _no_resolve)
    from maverick.tools.dns_lookup import dns_lookup
    tool = dns_lookup()
    out = tool.fn({"op": "resolve", "host": "secret.attacker.example", "type": "A"})
    assert out.startswith("ERROR") and "egress policy" in out
    out = tool.fn({"op": "reverse", "ip": "203.0.113.9"})
    assert out.startswith("ERROR") and "egress policy" in out
    assert seen == [("dns_lookup", "secret.attacker.example"), ("dns_lookup", "203.0.113.9")]
