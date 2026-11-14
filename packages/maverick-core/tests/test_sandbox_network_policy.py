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


def test_unparseable_config_or_malformed_values_block_the_network(tmp_path, monkeypatch, caplog):
    # load_config() returns defaults for a config it cannot parse, so a
    # deny-all posture would silently become "open". It must block instead,
    # as must non-string posture values and a tool rule that is not a table.
    from maverick import config
    from maverick.sandbox.network_policy import (
        denied_tools,
        network_posture,
        offline_reason,
        work_area_offline,
    )

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    cfg = config.config_path()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text('[security]\nnetwork_policy = "deny-all"\n[sandbox\n', encoding="utf-8")
    config.reset_config_cache()
    try:
        assert network_posture() == "deny-all"
        assert "http_fetch" in denied_tools()
        assert work_area_offline() is True
        # The reason names the file, and no misleading "unknown value" warning.
        assert str(cfg) in offline_reason() and "could not be read" in offline_reason()
        assert str(cfg) in describe("http_fetch")
        assert "unknown" not in caplog.text
    finally:
        config.reset_config_cache()

    for value in (False, 0):
        assert network_posture({"security": {"network_policy": value}}) == "deny-all"
        assert work_area_offline({"sandbox": {"network_policy": value}}) is True
    assert not host_allowed("shell", "example.com", {"shell": "deny"})
    assert "blocked" in describe("shell", {"shell": ["*"]})
