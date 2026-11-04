"""Containment mode: profile defaults, config knobs, registry-ACL composition
(existing denials preserved), env hardening, ephemeral workdir lifecycle.
Offline; composes existing seams without touching sandbox backends.
"""
from __future__ import annotations

import pytest
from maverick import containment
from maverick.file_lock import private_path_is_restricted
from maverick.tools import ToolRegistry


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_CONTAINMENT", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nonexistent.toml"))


def _config(monkeypatch, tmp_path, body: str):
    cfg = tmp_path / "config.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))


# --- profile ----------------------------------------------------------------

def test_profile_defaults():
    p = containment.ContainmentProfile()
    assert p.no_network is True
    assert p.ephemeral_workspace is True
    assert p.max_wall_seconds == 1800.0
    # The obviously-exfil set: generic egress + send-ish connectors.
    for tool in ("http_fetch", "web_search", "browser", "websocket",
                 "email", "gmail", "slack_bot", "notify"):
        assert tool in p.deny_tools


def test_enabled_default_off():
    assert containment.enabled() is False


def test_enabled_env_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_CONTAINMENT", "1")
    assert containment.enabled() is True
    # Env wins over config in BOTH directions.
    _config(monkeypatch, tmp_path, "[containment]\nenabled = true\n")
    monkeypatch.setenv("MAVERICK_CONTAINMENT", "0")
    assert containment.enabled() is False


def test_enabled_from_config(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path, "[containment]\nenabled = true\n")
    assert containment.enabled() is True


def test_profile_from_config_extends_deny_never_shrinks(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[containment]\ndeny_tools = ["my_connector"]\n'
            "no_network = false\nmax_wall_seconds = 60\n")
    p = containment.profile_from_config()
    assert "my_connector" in p.deny_tools
    assert p.deny_tools >= containment.DEFAULT_DENY_TOOLS  # built-ins kept
    assert p.no_network is False
    assert p.max_wall_seconds == 60.0


def test_profile_from_config_bad_values_fall_back(monkeypatch, tmp_path):
    _config(monkeypatch, tmp_path,
            '[containment]\nmax_wall_seconds = "soon"\ndeny_tools = "oops"\n')
    p = containment.profile_from_config()
    assert p.max_wall_seconds == 1800.0
    assert p.deny_tools == containment.DEFAULT_DENY_TOOLS


# --- apply: ACL composition ---------------------------------------------------

def test_apply_preserves_existing_acl_denials():
    reg = ToolRegistry()
    reg.set_acl(allowed={"read_file", "shell"}, denied={"shell"}, max_risk="medium")
    env: dict = {}
    report = containment.apply(containment.ContainmentProfile(),
                               registry=reg, sandbox_env=env)
    # set_acl REPLACES, so apply must have re-submitted the old ACL + denials.
    assert "shell" in reg._acl_denied                       # pre-existing kept
    assert reg._acl_denied >= containment.DEFAULT_DENY_TOOLS  # containment added
    assert reg._acl_allowed == {"read_file", "shell"}       # allow-list intact
    assert reg._acl_max_risk == "medium"                    # ceiling intact
    assert report.preserved_denials == frozenset({"shell"})
    assert report.denied_tools == containment.DEFAULT_DENY_TOOLS


def test_apply_on_pristine_registry():
    reg = ToolRegistry()
    report = containment.apply(containment.ContainmentProfile(),
                               registry=reg, sandbox_env={})
    assert reg._acl_denied == set(containment.DEFAULT_DENY_TOOLS)
    assert reg._acl_allowed == set()  # empty allow-list still means "all"
    assert report.preserved_denials == frozenset()


def test_denied_tools_actually_blocked_by_registry_acl():
    reg = ToolRegistry()
    containment.apply(containment.ContainmentProfile(), registry=reg,
                      sandbox_env={})
    assert reg._acl_allows("http_fetch") is False
    assert reg._acl_allows("read_file") is True


# --- apply: env hardening -----------------------------------------------------

def test_apply_hardens_sandbox_env_in_place():
    env = {"PATH": "/usr/bin", "NO_PROXY": "*", "no_proxy": "localhost"}
    report = containment.apply(containment.ContainmentProfile(),
                               registry=ToolRegistry(), sandbox_env=env)
    assert env["PATH"] == "/usr/bin"                      # unrelated vars kept
    assert "NO_PROXY" not in env and "no_proxy" not in env  # bypass stripped
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        assert env[var] == containment.NO_EGRESS_PROXY
    assert env["MAVERICK_CONTAINMENT"] == "1"             # nested runs contained
    assert "HTTP_PROXY" in report.env_keys_set
    assert "MAVERICK_CONTAINMENT" in report.env_keys_set


def test_apply_no_network_false_leaves_env_alone():
    env = {"NO_PROXY": "*"}
    report = containment.apply(
        containment.ContainmentProfile(no_network=False),
        registry=ToolRegistry(), sandbox_env=env)
    assert env == {"NO_PROXY": "*"}
    assert report.env_keys_set == ()
    assert report.no_network is False


def test_assert_no_network_env_is_pure():
    original = {"HTTPS_PROXY": "http://corp:3128", "NO_PROXY": "*"}
    hardened = containment.assert_no_network_env(original)
    assert original == {"HTTPS_PROXY": "http://corp:3128", "NO_PROXY": "*"}
    assert hardened["HTTPS_PROXY"] == containment.NO_EGRESS_PROXY
    assert "NO_PROXY" not in hardened


# --- report -------------------------------------------------------------------

def test_report_contents():
    profile = containment.ContainmentProfile(max_wall_seconds=120.0)
    report = containment.apply(profile, registry=ToolRegistry(), sandbox_env={})
    assert report.max_wall_seconds == 120.0
    assert report.ephemeral_workspace is True
    assert report.no_network is True
    assert report.denied_tools == profile.deny_tools


# --- ephemeral workdir --------------------------------------------------------

def test_ephemeral_workdir_created_0700_and_cleanup_removes():
    wd = containment.make_ephemeral_workdir()
    assert wd.path.is_dir()
    assert private_path_is_restricted(wd.path, 0o700)
    (wd.path / "scratch.txt").write_text("contained", encoding="utf-8")
    wd.cleanup()
    assert not wd.path.exists()
    wd.cleanup()  # idempotent


def test_ephemeral_workdir_is_outside_maverick_home(tmp_path):
    wd = containment.make_ephemeral_workdir()
    try:
        from maverick.paths import maverick_home
        assert maverick_home() not in wd.path.parents
    finally:
        wd.cleanup()
