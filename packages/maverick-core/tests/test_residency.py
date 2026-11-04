"""Data residency / region pinning: off by default; strict mode pins a
declared region against an allowed set and refuses boot when incoherent."""
from __future__ import annotations

import pytest
from maverick import residency


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in ("MAVERICK_RESIDENCY_STRICT", "MAVERICK_DATA_REGION",
                "MAVERICK_RESIDENCY_ALLOWED"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_off_by_default_is_noop():
    assert residency.residency_strict() is False
    ok, _ = residency.check_residency()
    assert ok is True
    residency.require_residency_or_die()  # no raise


def test_strict_without_region_fails(monkeypatch):
    monkeypatch.setenv("MAVERICK_RESIDENCY_STRICT", "1")
    ok, detail = residency.check_residency()
    assert ok is False and "no region declared" in detail
    with pytest.raises(residency.ResidencyError):
        residency.require_residency_or_die()


def test_strict_region_in_allowed_group_passes(monkeypatch):
    # region DE satisfies an allowed set of ["EU"] (group expansion).
    monkeypatch.setenv("MAVERICK_RESIDENCY_STRICT", "1")
    monkeypatch.setenv("MAVERICK_DATA_REGION", "de")
    monkeypatch.setenv("MAVERICK_RESIDENCY_ALLOWED", "EU")
    ok, detail = residency.check_residency()
    assert ok is True and "DE" in detail
    residency.require_residency_or_die()


def test_strict_region_outside_allowed_fails(monkeypatch):
    monkeypatch.setenv("MAVERICK_RESIDENCY_STRICT", "1")
    monkeypatch.setenv("MAVERICK_DATA_REGION", "US")
    monkeypatch.setenv("MAVERICK_RESIDENCY_ALLOWED", "EU")
    ok, detail = residency.check_residency()
    assert ok is False and "not fully within the allowed set" in detail
    with pytest.raises(residency.ResidencyError):
        residency.require_residency_or_die()


def test_strict_region_no_allowlist_passes(monkeypatch):
    # A declared region with no allowlist is unconstrained -> ok.
    monkeypatch.setenv("MAVERICK_RESIDENCY_STRICT", "1")
    monkeypatch.setenv("MAVERICK_DATA_REGION", "US")
    ok, _ = residency.check_residency()
    assert ok is True


def test_group_region_needs_all_members_allowed(monkeypatch):
    # A declared GROUP region is admitted only when EVERY member is allowed.
    monkeypatch.setenv("MAVERICK_RESIDENCY_STRICT", "1")
    monkeypatch.setenv("MAVERICK_DATA_REGION", "EU")
    # allowed=EU (or EEA superset) admits a declared EU region...
    monkeypatch.setenv("MAVERICK_RESIDENCY_ALLOWED", "EU")
    assert residency.check_residency()[0] is True
    monkeypatch.setenv("MAVERICK_RESIDENCY_ALLOWED", "EEA")
    assert residency.check_residency()[0] is True
    # ...but a PARTIAL member list does NOT: declaring "EU" while only DE,FR are
    # permitted would let data sit in the other 25 EU states. Must fail.
    monkeypatch.setenv("MAVERICK_RESIDENCY_ALLOWED", "DE,FR")
    assert residency.check_residency()[0] is False


def test_superset_group_region_does_not_bypass_subset_policy(monkeypatch):
    # The residency bypass: declaring EEA (which includes non-EU IS/LI/NO) must
    # NOT satisfy an EU-only allowlist on any-member-overlap.
    monkeypatch.setenv("MAVERICK_RESIDENCY_STRICT", "1")
    monkeypatch.setenv("MAVERICK_DATA_REGION", "EEA")
    monkeypatch.setenv("MAVERICK_RESIDENCY_ALLOWED", "EU")
    ok, detail = residency.check_residency()
    assert ok is False
    assert "not fully within" in detail
    with pytest.raises(residency.ResidencyError):
        residency.require_residency_or_die()


def test_config_drives_when_env_absent(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"residency": {
            "strict": True, "region": "US", "allowed_regions": ["EU"]}},
    )
    ok, detail = residency.check_residency()
    assert ok is False and "not fully within the allowed set" in detail


def test_verify_deployment_includes_residency(monkeypatch):
    # The guarantee surfaces in verify_deployment and passes when off.
    from maverick.deployment import verify_deployment
    names = {c.name for c in verify_deployment()}
    assert "Data residency" in names
