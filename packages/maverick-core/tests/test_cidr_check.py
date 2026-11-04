"""cidr_check: ordered CIDR access-control evaluation."""
from __future__ import annotations

from maverick.tools.cidr_check import cidr_check


def _c(ip, rules, default=None):
    args = {"op": "check", "ip": ip, "rules": rules}
    if default is not None:
        args["default"] = default
    return cidr_check().fn(args)


def test_first_match_wins():
    rules = [
        {"cidr": "10.0.0.0/8", "action": "deny"},
        {"cidr": "10.0.0.0/24", "action": "allow"},  # never reached for 10.x
    ]
    out = _c("10.0.0.5", rules)
    assert out.startswith("DENY") and "rule 0" in out


def test_allow_match():
    out = _c("192.168.1.10", [{"cidr": "192.168.0.0/16", "action": "allow"}])
    assert out.startswith("ALLOW") and "192.168.0.0/16 allow" in out


def test_default_deny_when_no_match():
    out = _c("8.8.8.8", [{"cidr": "10.0.0.0/8", "action": "allow"}])
    assert out.startswith("DENY") and "matched no rule (default deny)" in out


def test_default_allow_override():
    out = _c("8.8.8.8", [{"cidr": "10.0.0.0/8", "action": "deny"}], default="allow")
    assert out.startswith("ALLOW") and "default allow" in out


def test_ipv6():
    out = _c("2001:db8::1", [{"cidr": "2001:db8::/32", "action": "allow"}])
    assert out.startswith("ALLOW")


def test_family_mismatch_skips_rule():
    # v4 address must not match a v6 rule; falls through to default
    out = _c("10.0.0.1", [{"cidr": "2001:db8::/32", "action": "allow"}])
    assert out.startswith("DENY") and "no rule" in out


def test_errors():
    t = cidr_check()
    assert t.fn({"op": "check", "ip": "nope", "rules": []}).startswith("ERROR")
    assert t.fn({"op": "check", "ip": "10.0.0.1", "rules": {}}).startswith("ERROR")
    assert t.fn({"op": "check", "ip": "10.0.0.1", "rules": [{"cidr": "x", "action": "allow"}]}).startswith("ERROR")
    assert t.fn({"op": "check", "ip": "10.0.0.1", "rules": [{"cidr": "10.0.0.0/8", "action": "maybe"}]}).startswith("ERROR")
    assert t.fn({"op": "check", "ip": "10.0.0.1", "rules": [], "default": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "ip": "10.0.0.1", "rules": []}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "cidr_check" in names
