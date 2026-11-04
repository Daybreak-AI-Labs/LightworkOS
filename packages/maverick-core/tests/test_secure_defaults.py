"""Secure-by-default posture: the hardened controls default ON in production.

The suite-wide conftest pins MAVERICK_SECURE_DEFAULT=0 (legacy posture) so other
tests assert explicit on/off mechanics; these override it to the production
default and verify each control comes up hardened.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from maverick.security_defaults import secure_by_default

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def _core_project_metadata() -> dict:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))


def test_core_install_requires_at_rest_crypto_backend():
    deps = _core_project_metadata()["project"]["dependencies"]
    assert any(dep.startswith("cryptography>=") for dep in deps)


@pytest.fixture
def secure(monkeypatch):
    # Unset -> production default (secure). Belt-and-suspenders: also clear the
    # per-control knobs so we observe the DEFAULT, not an explicit override.
    monkeypatch.delenv("MAVERICK_SECURE_DEFAULT", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    monkeypatch.setattr("maverick.config.load_config", dict)


def test_secure_by_default_is_on_when_unset(secure):
    assert secure_by_default() is True


def test_secure_by_default_env_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    assert secure_by_default() is False
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "1")
    assert secure_by_default() is True


def test_secure_by_default_config_off(monkeypatch):
    monkeypatch.delenv("MAVERICK_SECURE_DEFAULT", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"security": {"secure_defaults": False}})
    assert secure_by_default() is False


def test_audit_signing_on_by_default(secure):
    from maverick.audit.writer import _resolve_signing
    assert _resolve_signing(None) is True


def test_audit_signing_explicit_knob_wins(secure, monkeypatch):
    # An operator that explicitly disables signing still wins over the default.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    from maverick.audit.writer import _resolve_signing
    assert _resolve_signing(None) is False
    # And the explicit arg always wins.
    assert _resolve_signing(False) is False
    assert _resolve_signing(True) is True


def test_at_rest_encryption_on_by_default(secure, monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_ENCRYPT_AT_REST", raising=False)
    from maverick import crypto_at_rest as car
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")
    assert car.at_rest_enabled() is True
    if not car._have_crypto():
        pytest.skip("cryptography is now a base dependency but is not installed in this environment")
    # Zero-config round-trip: the key auto-generates and seal->unseal restores.
    sealed = car.seal_to_str("PHI: patient record")
    assert sealed != "PHI: patient record"          # actually sealed
    assert car.unseal_from_str(sealed) == "PHI: patient record"


def test_at_rest_reads_are_plaintext_tolerant(secure, monkeypatch, tmp_path):
    # Existing plaintext (written before the flip) still reads back unchanged.
    from maverick import crypto_at_rest as car
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")
    assert car.unseal_from_str("legacy plaintext value") == "legacy plaintext value"


def test_at_rest_explicit_off_wins(secure, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import crypto_at_rest as car
    assert car.at_rest_enabled() is False


def test_consent_gates_high_and_critical_risk_by_default(secure, monkeypatch):
    from maverick.safety import consent
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    assert consent._resolve_mode("high") == "ask"
    assert consent._resolve_mode("critical") == "ask"
    # Low/medium stay frictionless so normal goals are unaffected.
    assert consent._resolve_mode("low") == "auto-approve"
    assert consent._resolve_mode("medium") == "auto-approve"


def test_consent_high_risk_denied_non_interactive(secure, monkeypatch):
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    from maverick.safety.consent import require_consent
    # No operator present (non-tty) -> a critical action is fail-closed.
    assert require_consent("wipe-prod", risk="critical", scope="db").granted is False
    # ...but a low-risk action still proceeds.
    assert require_consent("read-file", risk="low", scope="f").granted is True


def test_consent_explicit_mode_opts_out(secure, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    from maverick.safety import consent
    assert consent._resolve_mode("critical") == "auto-approve"


def test_tool_risk_ceiling_caps_critical_by_default(secure, monkeypatch):
    from maverick.safety.tool_acl import resolve_max_risk
    # No configured ceiling -> default cap at 'high' (drops only CRITICAL tools).
    assert resolve_max_risk() == "high"


def test_tool_risk_ceiling_explicit_config_wins(secure, monkeypatch):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"security": {"max_risk": "low"}})
    from maverick.safety.tool_acl import resolve_max_risk
    assert resolve_max_risk() == "low"   # tighter explicit ceiling wins


def test_tool_risk_ceiling_off_when_secure_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "0")
    monkeypatch.setattr("maverick.config.load_config", dict)
    from maverick.safety.tool_acl import resolve_max_risk
    assert resolve_max_risk() is None    # legacy: no cap
