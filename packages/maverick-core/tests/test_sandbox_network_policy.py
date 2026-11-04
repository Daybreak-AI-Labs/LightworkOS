"""Per-tool network egress policy."""
from __future__ import annotations

from maverick.sandbox.network_policy import describe, host_allowed

_POLICY = {
    "http_fetch": {"allow_egress": ["api.github.com", "*.openai.com"]},
    "shell": {"deny_egress": ["*"]},
    "mixed": {"allow_egress": ["*.example.com"], "deny_egress": ["evil.example.com"]},
}


def test_no_policy_allows_all():
    assert host_allowed("anytool", "anywhere.com", {})
    assert host_allowed("anytool", "anywhere.com", _POLICY)  # tool not in policy


def test_allow_list_restricts():
    assert host_allowed("http_fetch", "api.github.com", _POLICY)
    assert host_allowed("http_fetch", "api.openai.com", _POLICY)  # glob
    assert not host_allowed("http_fetch", "evil.com", _POLICY)


def test_deny_all():
    assert not host_allowed("shell", "anything.com", _POLICY)


def test_deny_wins_over_allow():
    assert host_allowed("mixed", "good.example.com", _POLICY)
    assert not host_allowed("mixed", "evil.example.com", _POLICY)


def test_host_case_insensitive():
    assert host_allowed("http_fetch", "API.GitHub.com", _POLICY)


def test_trailing_root_dot_canonicalized_for_deny_rules():
    policy = {
        "http_fetch": {"deny_egress": ["pastebin.com", "*.example.com"]},
    }

    assert not host_allowed("http_fetch", "pastebin.com.", policy)
    assert not host_allowed("http_fetch", "evil.example.com.", policy)


def test_trailing_root_dot_canonicalized_for_allow_rules():
    policy = {
        "http_fetch": {"allow_egress": ["api.github.com.", "*.openai.com."]},
    }

    assert host_allowed("http_fetch", "api.github.com", policy)
    assert host_allowed("http_fetch", "api.openai.com.", policy)


def test_scalar_string_deny_rule_is_honored():
    # A hand-edited config may give a bare string instead of a list. Iterating a
    # string yields characters, which used to make a string deny rule silently
    # never match (fail-OPEN). A lone string must act as a single-pattern list.
    assert not host_allowed("shell", "anything.com", {"shell": {"deny_egress": "*"}})
    assert not host_allowed(
        "http_fetch", "api.evil.com", {"http_fetch": {"deny_egress": "api.evil.com"}}
    )
    # And a scalar allow rule restricts to exactly that host.
    pol = {"http_fetch": {"allow_egress": "api.github.com"}}
    assert host_allowed("http_fetch", "api.github.com", pol)
    assert not host_allowed("http_fetch", "evil.com", pol)


def test_describe():
    assert "unrestricted" in describe("unknown", _POLICY)
    assert "allow=" in describe("http_fetch", _POLICY)
    assert "deny=" in describe("shell", _POLICY)


def test_unknown_work_area_network_policy_keeps_commands_offline():
    # [sandbox] network_policy only ever narrows: a value this module does not
    # know (a typo, "true", "offline") must keep the work area offline, like an
    # unknown [security] network_policy does, never silently leave it open.
    from maverick.sandbox.network_policy import work_area_offline

    for value in ("deny all", "true", "offline", "none", "allowlist"):
        assert work_area_offline({"sandbox": {"network_policy": value}}) is True, value
    assert work_area_offline({"sandbox": {"network_policy": "deny-all"}}) is True
    assert work_area_offline({"sandbox": {"network_policy": ""}}) is False
    assert work_area_offline({"sandbox": {}}) is False
    assert work_area_offline({}) is False
