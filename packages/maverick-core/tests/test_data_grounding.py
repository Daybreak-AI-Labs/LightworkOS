"""Suite-keyed primary-source data grounding.

``domain_capability`` layers each pack's suite-relevant public-data connectors
(SEC EDGAR, FRED, openFDA, USAspending, weather, ...) into its capability so an
analyst pack reaches for primary sources by default. The grant is additive and
LOW-risk (GET-only, deferred), keyed by suite, on by default with a kill-switch,
and never widens a host-restricted pack's egress.
"""
from __future__ import annotations

from maverick.domain import (
    builtin_dir,
    domain_capability,
    load_domains,
    suite_for,
)
from maverick.tools.enterprise_connectors import (
    PUBLIC_DATA_CONNECTOR_NAMES,
    SUITE_DATA_CONNECTORS,
    data_connectors_for_suite,
)

_DOMAINS = load_domains(builtin_dir())


def _pick(suite: str):
    """A real pack in ``suite`` with a non-empty allowlist (so it is expanded)."""
    for name, p in _DOMAINS.items():
        if suite_for(name) == suite and p.allow_tools:
            return name, p
    return None, None


# --- the mapping is well-formed ---------------------------------------------

def test_mapping_references_only_real_connectors_and_suites():
    valid = set(PUBLIC_DATA_CONNECTOR_NAMES)
    from maverick.domain import SUITE_PREFIXES
    real_suites = set(SUITE_PREFIXES.values())
    for suite, conns in SUITE_DATA_CONNECTORS.items():
        assert suite in real_suites, f"unknown suite {suite!r}"
        bad = [c for c in conns if c not in valid]
        assert not bad, f"{suite}: unknown connectors {bad}"


def test_every_public_data_connector_is_used_by_some_suite():
    used = set().union(*SUITE_DATA_CONNECTORS.values())
    assert used == set(PUBLIC_DATA_CONNECTOR_NAMES)


# --- the grant lands in the capability --------------------------------------

def test_representative_packs_get_their_suite_sources():
    cases = [
        ("healthcare", "openfda"),
        ("utilities", "eia"),
        ("legal", "courtlistener"),
        ("government_contracting", "usaspending"),
        ("insurance", "nws_weather"),
        ("esg_sustainability", "climatiq"),
        ("real_estate", "census"),
        ("banking", "fdic"),
    ]
    for suite, probe in cases:
        name, p = _pick(suite)
        assert p is not None, f"no pack found for suite {suite}"
        assert probe in data_connectors_for_suite(suite)
        cap = domain_capability(p, None, f"agent:{name}-1")
        assert cap.permits(probe), f"{name} should reach {probe}"


def test_grant_is_suite_scoped_not_global():
    # finance is not a health suite -> it must NOT get openfda.
    name, p = _pick("finance")
    assert p is not None
    assert "openfda" not in data_connectors_for_suite("finance")
    cap = domain_capability(p, None, f"agent:{name}-1")
    assert not cap.permits("openfda")


def test_kill_switch_withholds_the_grant(monkeypatch):
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "off")
    name, p = _pick("healthcare")
    cap = domain_capability(p, None, f"agent:{name}-1")
    assert not cap.permits("openfda")
    # the pack's own declared tools are unaffected by the switch
    assert cap.permits("knowledge_search")


def test_host_restricted_pack_keeps_its_egress_allowlist():
    # finance_treasury restricts allow_hosts to its banks; granting data
    # connectors must NOT silently widen that egress boundary.
    ft = _DOMAINS["finance_treasury"]
    assert ft.allow_hosts, "fixture expects a host-restricted pack"
    cap = domain_capability(ft, None, "agent:finance_treasury-1")
    assert cap.permits("fred")  # tool is granted
    assert set(cap.allow_hosts) == set(ft.allow_hosts)  # but egress is unchanged


def test_empty_allowlist_pack_is_not_broadened():
    # A pack with no allowlist means "inherit all"; the data grant must not
    # convert that into a narrow allow-set.
    for name, p in _DOMAINS.items():
        if not p.allow_tools:
            cap = domain_capability(p, None, f"agent:{name}-1")
            assert not cap.allow_tools, f"{name}: empty allowlist must stay open"
            break


def test_config_file_kill_switch_withholds_the_grant(monkeypatch):
    monkeypatch.delenv("MAVERICK_WORKFORCE_DATA_GROUNDING", raising=False)
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"workforce": {"data_grounding": False}})
    name, p = _pick("healthcare")
    cap = domain_capability(p, None, f"agent:{name}-1")
    assert not cap.permits("openfda")
    assert cap.permits("knowledge_search")


def test_malformed_data_grounding_booleans_fail_closed(monkeypatch):
    import maverick.config as config
    from maverick.domain import data_grounding_enabled

    monkeypatch.delenv("MAVERICK_WORKFORCE_DATA_GROUNDING", raising=False)
    monkeypatch.setattr(config, "config_source_errors", dict)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda *a, **k: {"workforce": {"data_grounding": "false"}},
    )
    assert data_grounding_enabled() is False

    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "not-a-bool")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda *a, **k: {"workforce": {"data_grounding": True}},
    )
    assert data_grounding_enabled() is False


def test_data_grounding_policy_loss_blocks_positive_override(monkeypatch):
    import maverick.config as config
    from maverick.domain import data_grounding_enabled

    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "on")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda *a, **k: {"workforce": {"data_grounding": True}},
    )
    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda: {"config.toml": "invalid TOML"},
    )

    assert data_grounding_enabled() is False
