"""Roster-wide safety invariant on the RUNTIME capability path.

``test_fleet_spine`` / ``domain_audit`` check the invariant via
``profile.capability()``. But the fleet actually runs a pack under
``domain_capability()``, which *layers* extra grants: the governed-action
bundle (when ``[workforce] levels`` is on) and the suite's primary-source data
connectors (when ``[workforce] data_grounding`` is on). This asserts the
load-bearing invariant survives those layers across the WHOLE roster, in the
most permissive mode -- so a future connector misclassification or a wrong
suite mapping that made a mutator reachable would fail here.
"""
from __future__ import annotations

import pytest
from maverick.domain import available_domains, domain_capability, suite_for
from maverick.domain_audit import _HOST_CONTROL
from maverick.safety.tool_risk import tool_risk
from maverick.tools.enterprise_connectors import (
    PUBLIC_DATA_CONNECTOR_NAMES,
    data_connectors_for_suite,
)

_DOMAINS = available_domains()
_NAMES = sorted(_DOMAINS)


def _is_builder(p) -> bool:
    return bool(set(p.allow_tools) & {"shell", "code_exec"})


@pytest.fixture()
def _most_permissive(monkeypatch):
    # levels on (adds the high-risk governed bundle + lifts the ceiling) AND
    # data grounding on (adds the suite's data connectors) -- the worst case.
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "true")
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "on")


def test_no_drafting_agent_reaches_a_mutator_on_the_runtime_path(_most_permissive):
    """The whole roster, under levels+grounding: no non-builder reaches a
    state-mutating / host-control tool."""
    offenders = []
    for name in _NAMES:
        p = _DOMAINS[name]
        if _is_builder(p):
            continue  # builders are *supposed* to reach shell/code_exec
        cap = domain_capability(p, None, f"agent:{name}-1")
        reach = [t for t in _HOST_CONTROL if cap.permits(t)]
        if reach:
            offenders.append((name, reach))
    assert not offenders, f"{len(offenders)} drafting packs reach a mutator: {offenders[:10]}"


def test_capability_builds_for_every_pack_in_every_mode(monkeypatch):
    """domain_capability never raises, in any of the 4 governance modes."""
    for levels in ("false", "true"):
        for grounding in ("off", "on"):
            monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", levels)
            monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", grounding)
            for name in _NAMES:
                # must not raise
                domain_capability(_DOMAINS[name], None, f"agent:{name}-1")


def test_data_grounding_grants_are_valid_low_risk_and_present(_most_permissive):
    valid = set(PUBLIC_DATA_CONNECTOR_NAMES)
    for name in _NAMES:
        p = _DOMAINS[name]
        if not p.allow_tools:
            continue  # empty allowlist == inherit-all; grant intentionally skipped
        granted = data_connectors_for_suite(suite_for(name))
        if not granted:
            continue
        cap = domain_capability(p, None, f"agent:{name}-1")
        for c in granted:
            assert c in valid, f"{name}: unknown connector {c}"
            assert tool_risk(c) == "low", f"{name}: {c} is not low-risk"
            assert cap.permits(c), f"{name}: granted {c} not permitted at runtime"


def test_grounding_off_withholds_the_grant(monkeypatch):
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "off")
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "false")
    # find a pack whose suite has a data grant, assert it is NOT reachable
    for name in _NAMES:
        p = _DOMAINS[name]
        if not p.allow_tools:
            continue
        granted = data_connectors_for_suite(suite_for(name))
        extra = [c for c in granted if c not in set(p.allow_tools)]
        if not extra:
            continue
        cap = domain_capability(p, None, f"agent:{name}-1")
        assert not cap.permits(extra[0]), f"{name}: {extra[0]} leaked with grounding off"
        return
    pytest.skip("no pack with a data grant beyond its own allowlist")


# Mutators that are NOT builder-defining: injecting one keeps the pack a
# non-builder, so the "no drafting agent reaches a mutator" check still applies
# to it (injecting shell/code_exec would instead reclassify it as a builder and
# legitimately exempt it -- which would NOT prove the detector fires).
_NONBUILDER_MUTATORS = tuple(t for t in _HOST_CONTROL if t not in ("shell", "code_exec"))


def test_invariant_detector_catches_an_injected_mutator(monkeypatch):
    """Fault injection: prove the runtime guard is NOT vacuous.

    If a regression added a state-mutating tool to a high-ceiling drafting
    pack's allowlist, the same reachability scan that
    ``test_no_drafting_agent_reaches_a_mutator_*`` runs must flag it. We corrupt
    a copy of a real pack (never mutating the shared roster) and assert the
    corrupt pack reaches the injected mutator while the clean pack does not.
    """
    import dataclasses

    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "true")
    for name in _NAMES:
        p = _DOMAINS[name]
        if _is_builder(p):
            continue
        deny, allow = set(p.deny_tools), set(p.allow_tools)
        inj = next((t for t in _NONBUILDER_MUTATORS
                    if t not in deny and t not in allow), None)
        if inj is None:
            continue  # this pack denies every non-builder mutator -- doubly safe
        corrupt = dataclasses.replace(p, allow_tools=[*p.allow_tools, inj], max_risk="high")
        assert not _is_builder(corrupt), "injection must not reclassify as builder"
        corrupt_cap = domain_capability(corrupt, None, f"agent:{name}-1")
        clean_cap = domain_capability(p, None, f"agent:{name}-1")
        assert corrupt_cap.permits(inj), (
            f"detector blind: injected {inj!r} into {name} is not reachable -- "
            "the roster invariant would fail to catch this regression")
        assert not clean_cap.permits(inj), (
            f"control failed: clean {name} already reaches {inj!r}")
        return
    pytest.skip("no injectable non-builder pack found")
