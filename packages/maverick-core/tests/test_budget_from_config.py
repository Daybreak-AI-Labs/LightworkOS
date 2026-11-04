"""budget_from_config() wires the [budget] section that was dead before.

config.get_budget_overrides() existed but was never called, so the
[budget] section of config.toml had no effect on any run. budget_from_config
is the single funnel; precedence is defaults < [budget] config < explicit
override, with None treated as "unset" and malformed config skipped.
"""
import pytest
from maverick.budget import Budget, budget_from_config, resolve_budget_caps


@pytest.fixture
def set_budget_cfg(monkeypatch):
    def _set(cfg: dict):
        monkeypatch.setattr("maverick.config.get_budget_overrides", lambda: cfg)
    return _set


def test_no_config_uses_budget_defaults(set_budget_cfg):
    set_budget_cfg({})
    b = budget_from_config()
    assert b.max_dollars == Budget().max_dollars is None
    assert b.max_wall_seconds == Budget().max_wall_seconds


def test_ordinary_task_has_no_generated_caps_and_tracks_usage(set_budget_cfg):
    set_budget_cfg({})
    b = budget_from_config()
    assert all(getattr(b, key) is None for key in (
        "max_dollars", "max_wall_seconds", "max_input_tokens", "max_output_tokens", "max_tool_calls",
    ))
    b.dollars, b.input_tokens, b.output_tokens, b.tool_calls = 123, 2_000_000, 900_000, 5001
    b.check()
    assert b.reserve(50) == 50
    b.release(50)
    assert b.dollars == 123
    from maverick.tools.budget_status import budget_status
    text = budget_status(budget=b).fn({})
    assert text.count("no task limit") == 5 and "123.0000" in text


def test_legacy_limits_are_preserved_until_deliberate_disable(set_budget_cfg):
    from maverick.runtime_overrides import set_task_limits

    set_budget_cfg({"max_dollars": 5.0, "max_wall_seconds": 3600.0, "max_tool_calls": 500})
    assert resolve_budget_caps() == {"max_dollars": 5, "max_wall_seconds": 3600, "max_tool_calls": 500}
    set_task_limits(False)
    assert resolve_budget_caps() == {}
    assert resolve_budget_caps(max_dollars=7) == {"max_dollars": 7}
    set_task_limits(True)
    assert resolve_budget_caps()["max_dollars"] == 5


def test_disabled_configured_caps_preserve_explicit_invocation_env(set_budget_cfg, monkeypatch):
    set_budget_cfg({"task_limits_enabled": False, "max_dollars": 5})
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "0.75")
    assert resolve_budget_caps() == {"max_dollars": 0.75}


def test_config_applies(set_budget_cfg):
    set_budget_cfg({"max_dollars": 1.5, "max_tool_calls": 42})
    b = budget_from_config()
    assert b.max_dollars == pytest.approx(1.5)
    assert b.max_tool_calls == 42


def test_explicit_override_beats_config(set_budget_cfg):
    set_budget_cfg({"max_dollars": 1.5})
    assert budget_from_config(max_dollars=9.0).max_dollars == pytest.approx(9.0)


def test_none_override_is_unset(set_budget_cfg):
    set_budget_cfg({"max_dollars": 1.5})
    # Passing through an unset optional flag must not clobber config.
    assert budget_from_config(max_dollars=None).max_dollars == pytest.approx(1.5)


def test_config_beats_caller_defaults(set_budget_cfg):
    set_budget_cfg({"max_dollars": 1.5})
    b = budget_from_config(defaults={"max_dollars": 2.0, "max_wall_seconds": 1800.0})
    assert b.max_dollars == pytest.approx(1.5)        # config wins over defaults
    assert b.max_wall_seconds == pytest.approx(1800.0)  # defaults fill the gap


def test_defaults_used_when_no_config(set_budget_cfg):
    set_budget_cfg({})
    b = budget_from_config(defaults={"max_dollars": 2.0})
    assert b.max_dollars == pytest.approx(2.0)


def test_malformed_config_value_is_refused(set_budget_cfg):
    set_budget_cfg({"max_dollars": "not-a-number"})
    with pytest.raises(ValueError, match="finite non-negative"):
        budget_from_config(defaults={"max_dollars": 2.0})


# ---- MAVERICK_BUDGET_DOLLARS env override (the cookbooks' documented knob) ----

def test_env_budget_dollars_applies_over_config(set_budget_cfg, monkeypatch):
    set_budget_cfg({"max_dollars": 5.0})
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "0.5")
    assert budget_from_config().max_dollars == pytest.approx(0.5)


def test_explicit_override_beats_env(set_budget_cfg, monkeypatch):
    set_budget_cfg({})
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "0.5")
    # An explicit --max-dollars flag is more specific than the env var.
    assert budget_from_config(max_dollars=3.0).max_dollars == pytest.approx(3.0)


def test_malformed_env_budget_dollars_is_refused(set_budget_cfg, monkeypatch):
    set_budget_cfg({"max_dollars": 1.5})
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "not-a-number")
    with pytest.raises(ValueError, match="MAVERICK_BUDGET_DOLLARS"):
        budget_from_config()


def test_nonfinite_env_budget_dollars_is_refused(set_budget_cfg, monkeypatch):
    set_budget_cfg({"max_dollars": 1.5})
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "inf")
    with pytest.raises(ValueError, match="MAVERICK_BUDGET_DOLLARS"):
        budget_from_config()


def test_empty_env_budget_dollars_ignored(set_budget_cfg, monkeypatch):
    set_budget_cfg({"max_dollars": 1.5})
    monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "")
    assert budget_from_config().max_dollars == pytest.approx(1.5)


def test_resolve_budget_caps_reports_the_precedence_without_reserving(set_budget_cfg, monkeypatch):
    set_budget_cfg({"max_dollars": 1.5})
    monkeypatch.delenv("MAVERICK_BUDGET_DOLLARS", raising=False)
    caps = resolve_budget_caps(defaults={"max_dollars": 2.0, "max_wall_seconds": 1800.0})
    assert caps["max_dollars"] == pytest.approx(1.5)
    assert caps["max_wall_seconds"] == pytest.approx(1800.0)
    assert resolve_budget_caps(defaults={"max_dollars": 2.0}, max_dollars=9.0)["max_dollars"] == 9.0


def test_configured_max_dollars_is_the_settings_cap_then_config_then_fallback(set_budget_cfg, monkeypatch, tmp_path):
    from maverick import runtime_overrides
    from maverick.runner import DEFAULT_MAX_DOLLARS, configured_max_dollars

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_BUDGET_DOLLARS", raising=False)
    set_budget_cfg({})
    assert configured_max_dollars() == pytest.approx(DEFAULT_MAX_DOLLARS)

    set_budget_cfg({"max_dollars": 40.0})
    assert configured_max_dollars() == pytest.approx(40.0)

    # The dashboard's Settings spend cap outranks the [budget] section.
    runtime_overrides.set_budget(25000.01)
    assert configured_max_dollars() == pytest.approx(25000.01)
    runtime_overrides.clear_budget()
    assert configured_max_dollars() == pytest.approx(40.0)


def test_goal_defaults_bound_unconfigured_runs_and_keep_legacy_no_cap_choice(
    set_budget_cfg, monkeypatch, tmp_path,
):
    from maverick.runner import (
        configured_max_dollars,
        configured_max_wall_seconds,
        goal_budget_defaults,
        requested_goal_dollars,
        requested_goal_wall_seconds,
    )

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_BUDGET_DOLLARS", raising=False)
    set_budget_cfg({})
    assert configured_max_dollars() == 2.0
    assert configured_max_wall_seconds() == 1800.0
    assert requested_goal_dollars(9.0) == 9.0
    assert requested_goal_wall_seconds(3600.0) == 3600.0
    fresh = budget_from_config(defaults=goal_budget_defaults())
    assert (fresh.max_dollars, fresh.max_wall_seconds) == (2.0, 1800.0)

    # Older installations saved an empty [budget] after choosing no task cap.
    (tmp_path / "config.toml").write_text("[budget]\n", encoding="utf-8")
    assert configured_max_dollars() is None
    assert configured_max_wall_seconds() is None
    legacy = budget_from_config(defaults=goal_budget_defaults())
    assert legacy.max_dollars is None and legacy.max_wall_seconds is None


def test_goal_defaults_preserve_config_request_and_explicit_opt_out(
    set_budget_cfg, monkeypatch, tmp_path,
):
    from maverick.runner import (
        configured_max_dollars,
        configured_max_wall_seconds,
        goal_budget_defaults,
        requested_goal_dollars,
        requested_goal_wall_seconds,
    )

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text("[budget]\n", encoding="utf-8")
    set_budget_cfg({"max_dollars": 9.0, "max_wall_seconds": 600.0})
    assert (configured_max_dollars(), configured_max_wall_seconds()) == (9.0, 600.0)
    assert requested_goal_dollars(20.0) == 9.0
    assert requested_goal_wall_seconds(900.0) == 600.0
    configured = budget_from_config(defaults=goal_budget_defaults())
    assert (configured.max_dollars, configured.max_wall_seconds) == (9.0, 600.0)
    requested = budget_from_config(
        defaults=goal_budget_defaults(), max_dollars=4.0, max_wall_seconds=300.0,
    )
    assert (requested.max_dollars, requested.max_wall_seconds) == (4.0, 300.0)

    set_budget_cfg({"task_limits_enabled": False})
    assert configured_max_dollars() is None and configured_max_wall_seconds() is None
    disabled = budget_from_config(defaults=goal_budget_defaults())
    assert disabled.max_dollars is None and disabled.max_wall_seconds is None
    assert budget_from_config(defaults=goal_budget_defaults(), max_dollars=0.5).max_dollars == 0.5
