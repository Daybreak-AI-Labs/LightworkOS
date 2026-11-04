"""Roster-wide privilege-escalation (capability attenuation) invariant.

The capability model's core security promise: a child spawned under a parent
grant can NEVER exceed it. When the fleet spawns a specialist, it runs the pack
under ``domain_capability(profile, parent_cap, principal)`` -> ``parent.attenuate
(...)``. This proves, across the WHOLE roster and in both governance modes, that
the resulting child capability is contained by a deliberately narrow parent:

  * no tool the child permits is forbidden by the parent,
  * the child's risk ceiling never rises above the parent's,
  * no host the child reaches is outside the parent's allow-list,

even when autonomy-levels-on lifts the pack's own ceiling to ``high`` and the
data-grounding grant adds connectors -- the parent still caps everything.

Includes a fault-injection control: a deliberately greedy pack (allows shell,
wire_transfer, ... at high risk, denies nothing) is fully contained by the
narrow parent, while the SAME pack with no parent is not -- so the test would
catch a broken ``attenuate`` rather than passing vacuously.
"""
from __future__ import annotations

import dataclasses

import pytest
from maverick.capability import Capability
from maverick.domain import available_domains, domain_capability
from maverick.safety.tool_risk import risk_rank

_DOMAINS = available_domains()
_NAMES = sorted(_DOMAINS)

# A tightly-scoped supervisor grant: read-only, low ceiling, shell denied,
# only government hosts reachable.
_PARENT = Capability(
    principal="parent:supervisor",
    allow_tools=frozenset({"knowledge_search", "read_file"}),
    deny_tools=frozenset({"shell", "write_file"}),
    max_risk="low",
    allow_hosts=frozenset({"*.gov"}),
)

_PROBE_TOOLS = (
    "knowledge_search", "read_file", "web_search", "write_file", "shell",
    "code_exec", "browser", "computer", "email", "notify", "wire_transfer",
    "release_payment", "fred", "sec_edgar", "openfda", "spawn_specialist",
    "send_to_agent", "ask_user",
)
_PROBE_HOSTS = ("data.sec.gov", "api.stlouisfed.org", "evil.example.com", "10.0.0.5")


@pytest.fixture()
def _both_modes_on(monkeypatch):
    # the worst case for escalation: pack ceiling lifted to high + grants added.
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "on")


def _assert_contained(child: Capability, name: str):
    for t in _PROBE_TOOLS:
        if child.permits(t):
            assert _PARENT.permits(t), f"{name}: child escalates tool {t!r} past parent"
    if child.max_risk is not None:
        assert risk_rank(child.max_risk) <= risk_rank(_PARENT.max_risk), (
            f"{name}: child risk {child.max_risk} exceeds parent {_PARENT.max_risk}")
    for h in _PROBE_HOSTS:
        if child.permits_host(h):
            assert _PARENT.permits_host(h), f"{name}: child reaches host {h!r} past parent"


def test_no_pack_escalates_beyond_a_narrow_parent(_both_modes_on, monkeypatch):
    for levels in ("false", "true"):
        monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", levels)
        for name in _NAMES:
            child = domain_capability(_DOMAINS[name], _PARENT, f"agent:{name}-child")
            _assert_contained(child, name)


def test_disjoint_allowlist_collapses_to_deny_not_all():
    # A child whose pack allowlist is disjoint from the parent's must NOT
    # fail open to "all" -- it collapses to deny-all.
    child = _PARENT.attenuate(principal="c", allow={"some_unrelated_tool"})
    assert not child.permits("knowledge_search")
    assert not child.permits("shell")
    assert not child.permits("some_unrelated_tool")


def test_fault_injection_greedy_pack_is_contained(monkeypatch):
    """A hostile pack that allows every dangerous tool at high risk is fully
    contained by the narrow parent -- and demonstrably greedy without it."""
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "true")
    base = _DOMAINS[_NAMES[0]]
    greedy = dataclasses.replace(
        base,
        allow_tools=["shell", "code_exec", "wire_transfer", "browser",
                     "release_payment", "knowledge_search"],
        deny_tools=[],
        max_risk="high",
    )
    # Without a parent, the greedy pack really does reach shell (genuinely greedy).
    solo = domain_capability(greedy, None, "agent:greedy-solo")
    assert solo.permits("shell"), "fixture not greedy -- solo should reach shell"

    # Under the narrow parent, every escalation is contained.
    child = domain_capability(greedy, _PARENT, "agent:greedy-child")
    assert not child.permits("shell")
    assert not child.permits("wire_transfer")
    assert not child.permits("release_payment")
    assert risk_rank(child.max_risk) <= risk_rank(_PARENT.max_risk)
    _assert_contained(child, "greedy")


def test_levels_on_high_ceiling_still_capped_by_low_parent(monkeypatch):
    # Specifically guard the lift: levels-on raises a non-empty pack to high,
    # but attenuation under a low parent must keep the child at low.
    monkeypatch.setenv("MAVERICK_WORKFORCE_LEVELS", "true")
    monkeypatch.setenv("MAVERICK_WORKFORCE_DATA_GROUNDING", "on")
    capped = 0
    for name in _NAMES:
        child = domain_capability(_DOMAINS[name], _PARENT, f"agent:{name}-c")
        if child.max_risk is not None:
            assert risk_rank(child.max_risk) <= risk_rank("low")
            capped += 1
    assert capped > 0
