"""[auth.mfa], [auth.ip_allowlist] and [auth.sessions] knobs: defaults,
config values, environment overrides and fail-closed handling of bad values."""
from __future__ import annotations

import pytest
from maverick import config


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_MFA_REQUIRE", "MAVERICK_MFA_STEP_UP_MINUTES",
                 "MAVERICK_IP_ALLOWLIST"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _write(tmp_path, text: str) -> None:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(text, encoding="utf-8")
    config.reset_config_cache()


def test_defaults_are_off_and_permissive():
    mfa = config.get_auth_mfa()
    assert mfa["require"] is False and mfa["step_up_minutes"] == 15
    assert mfa["amr_values"] == list(config.DEFAULT_MFA_AMR_VALUES)
    assert mfa["acr_values"] == []
    assert mfa["saml_authn_contexts"] == list(config.DEFAULT_MFA_SAML_CONTEXTS)
    assert config.get_ip_allowlist() == {"cidrs": [], "workspace_cidrs": []}
    # Browser session limits (company-wide hours, idle minutes) are off (0).
    assert config.get_auth_sessions() == {"retention_days": 30, "company_hours": 0, "idle_minutes": 0}


def test_config_values_are_read(tmp_path):
    _write(tmp_path, """
[auth.mfa]
require = true
step_up_minutes = 30
amr_values = ["otp", " fido "]
acr_values = ["urn:x:mfa"]
saml_authn_contexts = ["urn:x:saml"]

[auth.ip_allowlist]
cidrs = ["10.0.0.0/8", "192.0.2.1"]
workspace_cidrs = ["10.1.0.0/16"]

[auth.sessions]
retention_days = 7
company_hours = 12
idle_minutes = 30
""")
    mfa = config.get_auth_mfa()
    assert mfa == {"require": True, "step_up_minutes": 30, "amr_values": ["otp", "fido"],
                   "acr_values": ["urn:x:mfa"], "saml_authn_contexts": ["urn:x:saml"]}
    assert config.get_ip_allowlist() == {"cidrs": ["10.0.0.0/8", "192.0.2.1"],
                                         "workspace_cidrs": ["10.1.0.0/16"]}
    assert config.get_auth_sessions() == {"retention_days": 7, "company_hours": 12, "idle_minutes": 30}


def test_environment_wins(tmp_path, monkeypatch, caplog):
    _write(tmp_path, "[auth.mfa]\nrequire = true\nstep_up_minutes = 30\n"
                     "[auth.ip_allowlist]\ncidrs = [\"10.0.0.0/8\"]\n")
    monkeypatch.setenv("MAVERICK_MFA_REQUIRE", "false")
    monkeypatch.setenv("MAVERICK_MFA_STEP_UP_MINUTES", "3")
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", "192.0.2.0/24, 198.51.100.7")
    mfa = config.get_auth_mfa()
    assert mfa["require"] is False and mfa["step_up_minutes"] == 3
    assert config.get_ip_allowlist()["cidrs"] == ["192.0.2.0/24", "198.51.100.7"]
    monkeypatch.setenv("MAVERICK_IP_ALLOWLIST", " , ")  # lists nothing: never "allow everyone"
    monkeypatch.setattr(config, "_IP_ALLOWLIST_REPORTED", set())
    with caplog.at_level("ERROR"), pytest.raises(ValueError):
        config.get_ip_allowlist()
    assert "MAVERICK_IP_ALLOWLIST" in caplog.text
    caplog.clear()
    with caplog.at_level("ERROR"), pytest.raises(ValueError):
        config.get_ip_allowlist()  # the same bad value on the next request
    assert "MAVERICK_IP_ALLOWLIST" not in caplog.text


def test_bad_values_fail_closed_or_fall_back(tmp_path):
    _write(tmp_path, "[auth.mfa]\nrequire = \"maybe\"\nstep_up_minutes = \"soon\"\n"
                     "amr_values = \"otp, sms\"\n[auth.sessions]\nretention_days = -4\n")
    mfa = config.get_auth_mfa()
    assert mfa["require"] is True            # a non-bool security switch counts as on
    assert mfa["step_up_minutes"] == 15      # nonsense: the documented default
    assert mfa["amr_values"] == ["otp", "sms"]  # a comma string is tolerated
    assert config.get_auth_sessions()["retention_days"] == 1


@pytest.mark.parametrize("line", ["company_hours = 169", "idle_minutes = -1",
                                  "idle_minutes = true", "company_hours = \"8\""])
def test_bad_session_limits_fail_closed(tmp_path, line):
    _write(tmp_path, "[auth.sessions]\n" + line + "\n")
    with pytest.raises(ValueError, match="auth.sessions"):
        config.get_auth_sessions()


def test_session_limits_fail_closed_when_the_source_breaks_during_the_load(tmp_path, monkeypatch):
    # The check before the load sees a clean file; the file breaks just before
    # the load reads it. The defaults must not be used in its place.
    _write(tmp_path, "[auth.sessions]\ncompany_hours = 8\n")
    assert config.get_auth_sessions()["company_hours"] == 8
    real_load = config.load_global_config

    def load_after_the_file_breaks():
        (tmp_path / "home" / "config.toml").write_text("[auth.sessions\n", encoding="utf-8")
        return real_load()

    monkeypatch.setattr(config, "load_global_config", load_after_the_file_breaks)
    with pytest.raises(ValueError, match="Sign-in settings cannot be read"):
        config.get_auth_sessions()


@pytest.mark.parametrize("text", [
    "[auth.ip_allowlist]\ncidrs = 5\n",
    "[auth.ip_allowlist]\ncidrs = true\n",
    "[auth.ip_allowlist]\nworkspace_cidrs = 1.5\n",
    "[auth.ip_allowlist]\nworkspace_cidrs = false\n",
    "[auth.ip_allowlist.cidrs]\nnetwork = \"10.0.0.0/8\"\n",
    "[auth]\nip_allowlist = true\n",
    "[auth]\nip_allowlist = \"10.0.0.0/8\"\n",
])
def test_a_mistyped_allowlist_is_unreadable_not_empty(tmp_path, text):
    # An empty list allows every address, so a policy that cannot be read must raise
    # (callers fail closed to the local computer) rather than read as "allow everyone".
    _write(tmp_path, text)
    with pytest.raises(ValueError, match="ip_allowlist"):
        config.get_ip_allowlist()


def test_the_allowlist_still_accepts_a_comma_separated_text_and_an_empty_list(tmp_path):
    _write(tmp_path, "[auth.ip_allowlist]\ncidrs = \"10.0.0.0/8, 192.0.2.1\"\nworkspace_cidrs = []\n")
    assert config.get_ip_allowlist() == {"cidrs": ["10.0.0.0/8", "192.0.2.1"], "workspace_cidrs": []}


@pytest.mark.parametrize("value", ["inf", "-inf", "1e999", "nan"])
def test_an_unusable_step_up_window_falls_back_to_the_default(tmp_path, value):
    _write(tmp_path, f"[auth.mfa]\nrequire = true\nstep_up_minutes = {value}\n")
    mfa = config.get_auth_mfa()  # must not raise: a raise reads as "policy unreadable" and locks everyone out
    assert mfa["require"] is True and mfa["step_up_minutes"] == config.DEFAULT_STEP_UP_MINUTES


def test_an_unusable_step_up_window_in_the_environment_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("MAVERICK_MFA_STEP_UP_MINUTES", "1e999")
    assert config.get_auth_mfa()["step_up_minutes"] == config.DEFAULT_STEP_UP_MINUTES
