"""Host-safety guard for the computer-use tool.

When sandboxing is REQUIRED (``MAVERICK_COMPUTER_REQUIRE_SANDBOX=1`` or
enterprise mode) the tool must refuse to drive what looks like the operator's
real display (``DISPLAY=:0``) unless an explicit allow flag or a remote display
is configured. CRITICAL: with neither the require-flag nor enterprise mode the
guard is a no-op and default behavior is unchanged (kernel rule 1).

All hermetic: env is driven entirely through monkeypatch and config loading is
pinned to a tmp HOME so ``enterprise_enabled()`` can't read a real config.
"""
from __future__ import annotations

import maverick.tools.computer as computer
import pytest
from maverick.tools.computer import _host_safety_error, _run_computer_action


@pytest.fixture(autouse=True)
def _hermetic_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # Start from a clean slate: no require flag, no enterprise, no allow/remote.
    for var in (
        "MAVERICK_COMPUTER_REQUIRE_SANDBOX",
        "MAVERICK_COMPUTER_ALLOW_HOST",
        "MAVERICK_COMPUTER_DISPLAY",
        "MAVERICK_COMPUTER_DISABLE",
        "MAVERICK_ENTERPRISE",
    ):
        monkeypatch.delenv(var, raising=False)
    # Simulate the operator's real console seat.
    monkeypatch.setenv("DISPLAY", ":0")


# --- not required => no-op (default behavior unchanged) --------------------

def test_guard_noop_when_not_required(monkeypatch):
    # Neither require flag nor enterprise mode: guard returns None even on :0.
    assert _host_safety_error() is None


def test_run_action_unaffected_when_not_required(monkeypatch):
    # Full entry path: with the guard disengaged, a screenshot reaches its
    # handler (here stubbed) -- no host-guard ERROR is injected.
    monkeypatch.setattr(computer, "_do_screenshot", lambda: "OK-SCREENSHOT")
    out = _run_computer_action({"action": "screenshot"})
    assert out == "OK-SCREENSHOT"


# --- required + unsafe host => ERROR with guidance -------------------------

def test_required_unsafe_host_errors(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    err = _host_safety_error()
    assert err is not None and err.startswith("ERROR:")
    # Guidance names every escape hatch the operator can use.
    assert "MAVERICK_COMPUTER_ALLOW_HOST" in err
    assert "MAVERICK_COMPUTER_DISPLAY" in err
    assert "DISPLAY=:0" in err


def test_required_unsafe_blocks_actuation(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    # A click must be refused before any pyautogui import / consent gate.
    out = _run_computer_action({"action": "left_click", "coordinate": [10, 10]})
    assert out.startswith("ERROR:") and "refused" in out


def test_enterprise_mode_triggers_guard(monkeypatch):
    # Enterprise mode (env tristate) flips the requirement on without the
    # explicit sandbox flag.
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert _host_safety_error() is not None


# --- required + allow / remote display => proceeds (no guard ERROR) --------

def test_allow_flag_lets_it_proceed(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("MAVERICK_COMPUTER_ALLOW_HOST", "1")
    assert _host_safety_error() is None


def test_configured_display_must_match_backend_display(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("MAVERICK_COMPUTER_DISPLAY", ":99")
    # MAVERICK_COMPUTER_DISPLAY is only a declaration; the backends still use
    # DISPLAY, so leaving DISPLAY on the host console must not bypass the guard.
    err = _host_safety_error()
    assert err is not None and err.startswith("ERROR:")


def test_matching_configured_display_lets_it_proceed(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("MAVERICK_COMPUTER_DISPLAY", ":99")
    monkeypatch.setenv("DISPLAY", ":99")
    assert _host_safety_error() is None


def test_nondefault_display_without_configured_display_errors(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    # Real desktop sessions are not guaranteed to be on :0, so a non-default
    # DISPLAY alone is not enough evidence that the backend is sandboxed.
    monkeypatch.setenv("DISPLAY", ":99")
    err = _host_safety_error()
    assert err is not None and err.startswith("ERROR:")


def test_allow_lets_full_action_path_proceed(monkeypatch):
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    monkeypatch.setenv("MAVERICK_COMPUTER_ALLOW_HOST", "1")
    monkeypatch.setattr(computer, "_do_screenshot", lambda: "OK-SCREENSHOT")
    out = _run_computer_action({"action": "screenshot"})
    assert out == "OK-SCREENSHOT"


# --- kill switch still wins / precedence -----------------------------------

def test_disable_kill_switch_precedes_guard(monkeypatch):
    # MAVERICK_COMPUTER_DISABLE is checked first; its message wins.
    monkeypatch.setenv("MAVERICK_COMPUTER_DISABLE", "1")
    monkeypatch.setenv("MAVERICK_COMPUTER_REQUIRE_SANDBOX", "1")
    out = _run_computer_action({"action": "left_click", "coordinate": [1, 2]})
    assert "MAVERICK_COMPUTER_DISABLE" in out
