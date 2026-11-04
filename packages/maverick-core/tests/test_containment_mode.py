"""containment_mode: level -> restrictions resolver + per-action policy check."""
from __future__ import annotations

from maverick.tools.containment_mode import containment_mode


def _plan(level):
    return containment_mode().fn({"op": "plan", "level": level})


def _check(action, level):
    return containment_mode().fn({"op": "check", "action": action, "level": level})


def test_plan_off_has_no_restrictions():
    out = _plan("off")
    assert "level: off" in out
    assert "none" in out


def test_plan_full_is_ephemeral_no_network():
    out = _plan("full")
    assert "network: deny all egress" in out
    assert "ephemeral" in out
    assert "throwaway tmp" in out
    assert "credentials: none" in out


def test_network_level_denies_egress_only():
    assert _check("http_fetch", "network").startswith("DENY")
    # filesystem persistence is still allowed at the network level.
    assert _check("write_file", "network").startswith("ALLOW")


def test_full_level_denies_persist_and_creds():
    assert _check("write_file", "full").startswith("DENY")
    assert _check("read_secret", "full").startswith("DENY")
    assert _check("http_fetch", "full").startswith("DENY")


def test_off_allows_everything():
    assert _check("http_fetch", "off").startswith("ALLOW")
    assert _check("write_file", "off").startswith("ALLOW")


def test_unknown_action_fails_closed_at_full():
    # The maximal containment level denies anything it can't classify.
    out = _check("teleport", "full")
    assert out.startswith("DENY")
    assert "fail-closed" in out


def test_unknown_action_fails_open_below_full():
    # off/network make only targeted promises, so an unknown action fails open.
    for level in ("off", "network"):
        out = _check("teleport", level)
        assert out.startswith("ALLOW")
        assert "fail-open" in out


def test_errors():
    t = containment_mode()
    assert t.fn({"op": "plan", "level": "lockdown"}).startswith("ERROR")  # bad level
    assert t.fn({"op": "check", "level": "full"}).startswith("ERROR")  # no action
    assert t.fn({"op": "nope", "level": "off"}).startswith("ERROR")  # bad op
