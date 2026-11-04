"""Roster-wide autonomy governance-decision invariants.

The other roster guards check *tool reachability*. This checks the OTHER half of
the agent-as-employee promise: the authority dial. For every pack, across every
risk tier and graduation state, the resolver's governance decision must honour:

  A. levels OFF  -> every action stages for a human (SUGGEST / require_human),
     byte-for-byte the historical default (kernel rule 1).
  B. onboarding  -> NEVER autonomous (`allow`) for any risk: a new hire is
     supervised until it graduates.
  C. high-risk   -> NEVER autonomous, even graduated: high-stakes actions always
     keep a human in the loop.
  D. graduation actually unlocks low-risk autonomy for the STANDARD-tier packs
     (a positive control, so A-C aren't passing because the dial is inert).

Plus a fault-injection negative control proving the checks would CATCH a
misconfigured pack rather than passing vacuously.
"""
from __future__ import annotations

from dataclasses import replace

from maverick.agent_autonomy import (
    AutonomyLevel,
    AutonomyProfile,
    default_profile_for,
    resolve,
)
from maverick.domain import available_domains

_DOMAINS = available_domains()
_NAMES = sorted(_DOMAINS)
_RISKS = ("low", "medium", "high")


def _profile(name):
    return _DOMAINS[name].autonomy or default_profile_for(name)


def test_A_levels_off_always_stages_for_a_human():
    for name in _NAMES:
        prof = _profile(name)
        for risk in _RISKS:
            v = resolve(prof, risk=risk, levels_enabled=False)
            assert v.level is AutonomyLevel.SUGGEST, (name, risk, v.level)
            assert v.decision == "require_human", (name, risk, v.decision)


def test_B_onboarding_is_never_autonomous():
    for name in _NAMES:
        prof = replace(_profile(name), onboarding=True)
        for risk in _RISKS:
            v = resolve(prof, risk=risk, levels_enabled=True)
            assert v.decision != "allow", (
                f"{name}: onboarding agent autonomous on {risk}-risk "
                f"({v.level.value})")


def test_C_high_risk_is_never_autonomous_even_graduated():
    for name in _NAMES:
        prof = replace(_profile(name), onboarding=False)  # graduated
        v = resolve(prof, risk="high", levels_enabled=True)
        assert v.decision != "allow", (
            f"{name}: high-risk action resolves autonomous ({v.level.value})")


def test_D_graduation_unlocks_low_risk_autonomy_for_some_packs():
    # Positive control: the dial is not inert -- a meaningful share of packs
    # (the STANDARD tier) act autonomously on low-risk work once graduated.
    unlocked = 0
    for name in _NAMES:
        prof = replace(_profile(name), onboarding=False)
        if resolve(prof, risk="low", levels_enabled=True).decision == "allow":
            unlocked += 1
    assert unlocked > 100, f"only {unlocked} packs unlock low-risk autonomy"


def test_fault_injection_resolver_flags_a_misconfigured_high_auto_pack():
    """A pack mis-set to AUTO on high-risk would be caught by invariant C --
    proving C is not vacuous. And onboarding (B) still protects even that pack."""
    bad = AutonomyProfile(
        default=AutonomyLevel.AUTO,
        high=AutonomyLevel.AUTO,
        onboarding=False,
    )
    v = resolve(bad, risk="high", levels_enabled=True)
    assert v.decision == "allow", "fault not realized: resolver should honour AUTO"
    # i.e. test_C would FAIL for a pack with this profile -> the guard fires.

    # But onboarding still clamps even a misconfigured AUTO down out of autonomy.
    vo = resolve(replace(bad, onboarding=True), risk="high", levels_enabled=True)
    assert vo.decision != "allow", "onboarding clamp must defeat a high=AUTO misconfig"
