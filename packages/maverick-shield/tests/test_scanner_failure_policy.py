"""A failed detector must remain observable to required-policy callers."""
from __future__ import annotations

import pytest
from maverick_shield import Shield, guard


def _unavailable(*args, **kwargs):
    raise RuntimeError("detector unavailable")


@pytest.mark.parametrize("sink", ["scan_input", "scan_output", "scan_tool_call"])
def test_strict_backend_failure_blocks_each_sink(monkeypatch, sink):
    monkeypatch.setattr(guard, "builtin_scan", _unavailable)
    shield = Shield(profile="strict", backend="builtin", warn_if_missing=False)
    args = ("read_file", {"path": "contract.txt"}) if sink == "scan_tool_call" else ("hello",)
    verdict = getattr(shield, sink)(*args)
    assert not verdict.allowed
    assert verdict.scan_error


def test_optional_failure_is_allowed_but_not_reported_as_checked(monkeypatch):
    monkeypatch.setattr(guard, "builtin_scan", _unavailable)
    verdict = Shield(backend="builtin", warn_if_missing=False).scan_input("hello")
    assert verdict.allowed
    assert verdict.scan_error


def test_sdk_exception_reaches_strict_policy(monkeypatch):
    shield = Shield(profile="strict", warn_if_missing=False)
    shield.backend = Shield.BACKEND_SDK
    shield._sdk = type("Unavailable", (), {"scanInput": _unavailable})()
    assert not shield.scan_input("hello").allowed


@pytest.mark.parametrize("detector", ["output_policy_scan", "_constitutional_scan"])
def test_strict_secondary_detector_failure_blocks(monkeypatch, detector):
    monkeypatch.setattr(guard, detector, _unavailable)
    shield = Shield(profile="strict", backend="builtin", warn_if_missing=False)
    shield._constitution = [object()]
    assert not shield.scan_output("hello").allowed


def test_required_policy_sees_absorbed_backend_error(monkeypatch):
    from maverick import shield_policy

    monkeypatch.setattr(guard, "builtin_scan", _unavailable)
    monkeypatch.setattr(shield_policy, "shield_required", lambda: True)
    assert shield_policy.scan_block("hello") == "shield scan error"


@pytest.mark.parametrize("options", [{"backend": "none"}, {"scan_input": False},
                                     {"profile": "off"}])
def test_required_check_cannot_be_disabled(options):
    verdict = Shield(fail_closed=True, **options).scan_input("hello")
    assert not verdict.allowed and verdict.scan_error


def test_required_from_config_blocks_disabled_sink(monkeypatch):
    from maverick import config, shield_policy

    monkeypatch.setattr(config, "get_safety", lambda: {"scan_input": False})
    monkeypatch.setattr(shield_policy, "shield_required", lambda: True)
    assert not Shield.from_config(warn_if_missing=False).scan_input("hello").allowed


def test_strict_config_requires_present_shield_even_with_optional_flag(monkeypatch):
    from maverick import config, shield_policy

    monkeypatch.setattr(config, "load_config", lambda: {"safety": {"profile": "Strict"}})
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    assert shield_policy.shield_required()


def test_strict_phishing_detector_failure_blocks(monkeypatch):
    from maverick_shield import phishing

    monkeypatch.setattr(phishing, "detect_phishing", _unavailable)
    verdict = Shield(profile="strict", warn_if_missing=False).scan_output("hello")
    assert not verdict.allowed and verdict.scan_error


@pytest.mark.parametrize("profile,allowed", [("balanced", True), ("strict", False)])
def test_decode_failure_preserves_policy_and_error(monkeypatch, profile, allowed):
    from maverick_shield import deobfuscate

    monkeypatch.setattr(deobfuscate, "decoded_variants", _unavailable)
    verdict = Shield(profile=profile, warn_if_missing=False).scan_input("hello")
    assert verdict.allowed is allowed and verdict.scan_error
