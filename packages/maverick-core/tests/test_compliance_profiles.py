"""Tests for compliance mode profiles (HIPAA). Pure data + pure functions."""
from __future__ import annotations

import pytest
from maverick import compliance_profiles as cp


def test_hipaa_profile_present_and_shaped():
    prof = cp.get_profile("HIPAA")  # case-insensitive
    assert prof is not None
    assert prof.key == "hipaa"
    assert "45 CFR" in prof.name
    assert cp.FLOOR_PII_REDACTION in prof.required_floors
    assert cp.FLOOR_ENCRYPTION_AT_REST in prof.required_floors


def test_hipaa_policy_requires_human_on_high_risk():
    pol = cp.compile_policy(["hipaa"])
    assert pol.require_human_min_risk == "high"


def test_compile_policy_case_insensitive():
    # Mixed-case keys must compile the same policy as lowercase (and as the
    # case-insensitive required_floors/get_profile contract).
    assert cp.compile_policy(["HIPAA"]).require_human_min_risk == "high"
    assert cp.compile_policy([" HiPaA "]).require_human_min_risk == "high"


def test_profile_posture_case_insensitive():
    out = cp.profile_posture(["HIPAA"])
    assert "require-human at/above risk 'high'" in out
    assert out != "compliance profiles: none active"


def test_unknown_profile_is_not_silently_compiled_default_open():
    assert cp.get_profile("sox") is None
    with pytest.raises(cp.ComplianceProfileError, match="unknown profile"):
        cp.compile_policy(["nope"])


def test_required_floors_union():
    floors = cp.required_floors(["hipaa", "gdpr"])
    assert cp.FLOOR_EGRESS_LOCK in floors and cp.FLOOR_AUDIT_LOG in floors


def test_posture_report():
    out = cp.profile_posture(["hipaa"])
    assert "HIPAA" in out and "required floors:" in out
    assert "require-human at/above risk 'high'" in out
    assert cp.profile_posture([]) == "compliance profiles: none active"


def test_configured_profiles_reads_config(monkeypatch):
    import maverick.config as config_mod

    def _fake_load():
        return {"compliance": {"profiles": ["HIPAA", "hipaa"]}}

    monkeypatch.setattr(config_mod, "load_config", _fake_load)
    monkeypatch.setattr(config_mod, "config_source_errors", dict)
    monkeypatch.delenv("MAVERICK_COMPLIANCE_PROFILES", raising=False)
    assert cp.configured_profiles() == ["hipaa"]


@pytest.mark.parametrize(
    "config, message",
    [
        ({"compliance": "hipaa"}, "configuration table"),
        ({"compliance": {"profiles": "hipaa"}}, "list of non-empty strings"),
        ({"compliance": {"profiles": [""]}}, "list of non-empty strings"),
        ({"compliance": {"profiles": ["hipa"]}}, "unknown profile"),
    ],
)
def test_configured_profiles_reject_malformed_or_unknown_policy(
    monkeypatch, config, message
):
    import maverick.config as config_mod

    monkeypatch.setattr(config_mod, "load_config", lambda: config)
    monkeypatch.setattr(config_mod, "config_source_errors", dict)
    monkeypatch.delenv("MAVERICK_COMPLIANCE_PROFILES", raising=False)
    with pytest.raises(cp.ComplianceProfileError, match=message):
        cp.configured_profiles()


def test_environment_profiles_are_strict_and_join_the_active_set(monkeypatch):
    import maverick.config as config_mod

    monkeypatch.setattr(config_mod, "load_config", lambda: {
        "compliance": {"profiles": ["gdpr"]}
    })
    monkeypatch.setattr(config_mod, "config_source_errors", dict)
    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "HIPAA, gdpr")
    assert cp.configured_profiles() == ["gdpr", "hipaa"]
    assert cp.FLOOR_EGRESS_LOCK in cp.configured_required_floors()

    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "not-a-profile")
    with pytest.raises(cp.ComplianceProfileError, match="unknown profile"):
        cp.configured_profiles()

    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "gdpr,,hipaa")
    with pytest.raises(cp.ComplianceProfileError, match="non-empty strings"):
        cp.configured_profiles()


def test_deployment_encryption_floor_uses_strict_shared_resolver(monkeypatch):
    from maverick.crypto_at_rest import deployment_at_rest_enabled

    monkeypatch.delenv("MAVERICK_ENCRYPT_AT_REST", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.delenv("MAVERICK_SECURE_DEFAULT", raising=False)
    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "hipaa")
    assert deployment_at_rest_enabled(config={}, source_errors={}) is True

    monkeypatch.setenv("MAVERICK_COMPLIANCE_PROFILES", "unknown")
    assert deployment_at_rest_enabled(config={}, source_errors={}) is False


def test_floor_consumers_fail_closed_when_policy_source_is_invalid(monkeypatch):
    import maverick.config as config_mod

    monkeypatch.setattr(config_mod, "load_config", dict)
    monkeypatch.setattr(
        config_mod, "config_source_errors", lambda: {"config.toml": "parse error"}
    )
    assert cp.configured_required_floors() == cp.ALL_REQUIRED_FLOORS
    assert all(cp.requires_floor(floor) for floor in cp.ALL_REQUIRED_FLOORS)


@pytest.mark.parametrize(
    "config",
    [
        {"compliance": "hipaa"},
        {"compliance": {"profiles": "hipaa"}},
        {"compliance": {"profiles": ["unknown"]}},
    ],
)
def test_deployment_enterprise_admission_cannot_bypass_strict_profiles(
    monkeypatch, config
):
    from maverick.enterprise import deployment_enterprise_enabled

    monkeypatch.delenv("MAVERICK_COMPLIANCE_PROFILES", raising=False)
    assert deployment_enterprise_enabled(config=config, source_errors={}) is True


def test_list_profiles():
    keys = {p.key for p in cp.list_profiles()}
    assert "hipaa" in keys


def test_from_config_unchanged_when_no_profiles(monkeypatch):
    """Default behavior is identical when [compliance] is unset."""
    import maverick.compliance_profiles as cpmod
    from maverick.governance import Policy

    monkeypatch.setattr(cpmod, "configured_profiles", lambda *_a, **_k: [])
    pol = Policy.from_config()
    assert pol.require_human_min_risk is None
    assert not pol.require_human_actions


def test_from_config_hipaa_tightens_live_policy(monkeypatch):
    """[compliance] profiles=['hipaa'] folds require-human-on-high into the live policy."""
    import maverick.compliance_profiles as cpmod
    from maverick.governance import Decision, Policy, evaluate

    monkeypatch.setattr(cpmod, "configured_profiles", lambda *_a, **_k: ["hipaa"])
    pol = Policy.from_config()
    assert pol.require_human_min_risk == "high"
    # A high-risk action now routes to a human under HIPAA mode.
    v = evaluate("shell", risk="high", policy=pol)
    assert v.decision == Decision.REQUIRE_HUMAN


def test_no_import_cycle():
    # Importing governance then compliance_profiles (and vice versa) must not cycle.
    import importlib
    importlib.import_module("maverick.governance")
    importlib.import_module("maverick.compliance_profiles")


def test_hipaa_required_floors_are_runtime_enforced(monkeypatch):
    """HIPAA-only config must fail closed instead of merely documenting floors."""
    import maverick.compliance_profiles as cpmod
    from maverick.audit.writer import _resolve_signing
    from maverick.crypto_at_rest import at_rest_enabled
    from maverick.enterprise import EgressBlocked, assert_provider_allowed, enterprise_enabled
    from maverick.privacy import anon_enabled

    monkeypatch.setattr(cpmod, "configured_profiles", lambda *_a, **_k: ["hipaa"])
    for env in (
        "MAVERICK_ENTERPRISE",
        "MAVERICK_ENCRYPT_AT_REST",
        "MAVERICK_AUDIT_SIGN",
        "MAVERICK_ANON",
    ):
        monkeypatch.setenv(env, "0")
    # HIPAA also requires off-host audit-key custody. Supply a deterministic
    # injected Ed25519 seed so this test exercises the provider-denial floor,
    # rather than correctly stopping one step earlier on a missing audit key.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", "00" * 32)

    assert enterprise_enabled() is True
    assert at_rest_enabled() is True
    assert _resolve_signing(False) is True
    assert anon_enabled() is True
    try:
        assert_provider_allowed("openai")
    except EgressBlocked:
        pass
    else:  # pragma: no cover - assertion path
        raise AssertionError("HIPAA egress lock allowed a cloud provider")
