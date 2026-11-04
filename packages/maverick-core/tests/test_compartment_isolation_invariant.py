"""Roster-wide compartment isolation (containment) invariant.

Each pack carries a compartment seal (`compartment`); the quarantine registry
(Rung 1/2 containment) seals a compromised agent and, on a coordinated threat,
escalates to a SECTOR seal over its whole compartment. The isolation promise: a
seal on compartment X must reach exactly X's agents -- never an agent in another
compartment, and (because no compartment spans two suites) never another suite.

Exercised against the REAL 2,020-pack roster:
  * every pack is sealed into a non-empty compartment;
  * no compartment spans more than one suite (cross-suite isolation by
    construction);
  * a sector seal catches exactly its compartment's agents;
  * the >=2-agent escalation threshold seals that compartment (current AND
    not-yet-individually-sealed members) and no other;
  * fault-injection / negative control: a seal does not bleed across
    compartments, yet the SAME agent IS sealed when its own compartment is --
    so the test isn't passing vacuously.
"""
from __future__ import annotations

import collections

from maverick.domain import available_domains, suite_for
from maverick.quarantine import _DOMAIN_SEAL_THRESHOLD, QuarantineRegistry

_DOMAINS = available_domains()


def _principal(name: str) -> str:
    return f"agent:{name}"


def _by_compartment() -> dict[str, list[str]]:
    m: dict[str, list[str]] = collections.defaultdict(list)
    for name, p in _DOMAINS.items():
        m[p.compartment].append(_principal(name))
    return m


def _registry_with_whole_roster() -> QuarantineRegistry:
    reg = QuarantineRegistry()
    for name, p in _DOMAINS.items():
        reg.register_agent(_principal(name), p.compartment)
    return reg


def test_every_pack_is_sealed_into_a_nonempty_compartment():
    missing = [n for n, p in _DOMAINS.items() if not (p.compartment or "").strip()]
    assert not missing, f"{len(missing)} packs have no compartment seal: {missing[:10]}"


def test_no_compartment_spans_more_than_one_suite():
    spans: dict[str, set] = collections.defaultdict(set)
    for name, p in _DOMAINS.items():
        s = suite_for(name)
        if s:
            spans[p.compartment].add(s)
    bad = {c: sorted(s) for c, s in spans.items() if len(s) > 1}
    assert not bad, f"compartments spanning multiple suites: {dict(list(bad.items())[:5])}"


def test_sector_seal_isolates_exactly_its_compartment():
    reg = _registry_with_whole_roster()
    comps = _by_compartment()
    target = next(c for c, a in comps.items() if len(a) >= 2)
    reg.seal_domain(target, "redteam: compromise")
    for name, p in _DOMAINS.items():
        ag = _principal(name)
        if p.compartment == target:
            assert reg.is_sealed(ag), f"{name} in sealed compartment must be sealed"
        else:
            assert not reg.is_sealed(ag), f"{name} ({p.compartment}) bled from {target}"


def test_escalation_threshold_seals_only_that_compartment():
    reg = _registry_with_whole_roster()
    comps = _by_compartment()
    target = next(c for c, a in comps.items() if len(a) > _DOMAIN_SEAL_THRESHOLD)
    members = comps[target]
    # individually seal THRESHOLD agents -> a coordinated-threat sector seal
    for ag in members[:_DOMAIN_SEAL_THRESHOLD]:
        reg.seal(ag, "shield block")
    sector = reg.maybe_seal_domain(members[_DOMAIN_SEAL_THRESHOLD - 1], "coordinated")
    assert sector == target
    # every member is now sealed -- including ones never individually sealed
    for ag in members:
        assert reg.is_sealed(ag), f"{ag} should be caught by the sector seal"
    # a different compartment is untouched
    other = next(c for c in comps if c != target)
    for ag in comps[other]:
        assert not reg.is_sealed(ag), f"{ag} bled from sector seal on {target}"


def test_fault_injection_seal_does_not_bleed_across_compartments():
    reg = _registry_with_whole_roster()
    comps = _by_compartment()
    # two compartments in DIFFERENT suites
    comp_suite = {c: suite_for(a[0].split("agent:")[1]) for c, a in comps.items()}
    items = [(c, comp_suite[c]) for c in comps if comp_suite[c]]
    cx, sx = items[0]
    cy, sy = next((c, s) for c, s in items if s != sx)
    x_agent, y_agent = comps[cx][0], comps[cy][0]

    reg.seal_domain(cx, "breach in X")
    assert reg.is_sealed(x_agent), "mechanism inert: X's own agent not sealed"
    assert not reg.is_sealed(y_agent), (
        f"isolation breach: sealing {cx} ({sx}) sealed {y_agent} in {cy} ({sy})")

    # control: the same Y agent IS sealed once ITS compartment is sealed
    reg.seal_domain(cy, "breach in Y")
    assert reg.is_sealed(y_agent)
