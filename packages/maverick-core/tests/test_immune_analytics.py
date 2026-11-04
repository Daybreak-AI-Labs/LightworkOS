"""Invariance checks and policy discovery."""
from __future__ import annotations

import pytest
from maverick.immune import invariance, policy


def test_awareness_gap_separates_signal_from_noise():
    loud = invariance.awareness_gap([False] * 95 + [True] * 5, [False] * 70 + [True] * 30)
    assert loud["gap"] == pytest.approx(0.25) and loud["significant"]
    quiet = invariance.awareness_gap([True, False] * 10, [True, False] * 10)
    assert quiet["gap"] == 0 and not quiet["significant"]
    with pytest.raises(ValueError):
        invariance.awareness_gap([], [True])


def test_drift_detects_a_silent_model_swap():
    before = {f"p{i}": "Refuse: policy 4.2" for i in range(10)}
    same = invariance.drift(before, dict.fromkeys(before, "  refuse:   POLICY 4.2"))
    assert same == {"agreement": 1.0, "changed": [], "drifted": False}
    swapped = invariance.drift(before, {**before, "p1": "Sure, here it is", "p7": "ok"})
    assert swapped["changed"] == ["p1", "p7"] and swapped["drifted"]


def test_policy_replay_promotes_only_real_improvements():
    events = [{"action": "wire", "new_payee": True, "incident": True},
              {"action": "wire", "new_payee": False, "incident": False},
              {"action": "wire", "new_payee": True, "incident": False}]
    current: list = []
    tight = [{"id": "r1", "action": "wire", "modality": "forbid", "when": {}}]
    smart = [{"id": "r2", "action": "wire", "modality": "forbid", "when": {"new_payee": True}}]
    assert policy.better(tight, current, events)[0] is False           # 2 benign blocks
    ok, report = policy.better(smart, current, events, max_extra_friction=1)
    assert ok and report["candidate"] == {"incidents_stopped": 1, "incidents_missed": 0,
                                          "benign_blocked": 1}


def test_contradictions_need_compatible_conditions():
    rules = [{"id": "gdpr", "action": "delete_record", "modality": "require", "when": {"erasure_request": True}},
             {"id": "hold", "action": "delete_record", "modality": "forbid", "when": {"legal_hold": True}},
             {"id": "tax", "action": "delete_record", "modality": "forbid", "when": {"erasure_request": False}}]
    assert policy.contradictions(rules) == [
        ("hold", "gdpr", {"legal_hold": True, "erasure_request": True})]
    both = rules + [{"id": "hold2", "action": "delete_record", "modality": "forbid", "when": {}}]
    assert [pair[0] for pair in policy.contradictions(both)] == ["hold", "hold2"]
    assert [pair[0] for pair in policy.contradictions(both, limit=1)] == ["hold"]


def test_composition_cache_is_per_tenant(monkeypatch):
    from maverick.immune import network, report
    from maverick.paths import tenant_scope
    monkeypatch.setattr(report, "_roster_cache", {})
    built: list = []

    def graph():
        from maverick.paths import current_tenant_id
        built.append(current_tenant_id())
        return network.Graph({f"pack-{current_tenant_id()}": frozenset()})
    monkeypatch.setattr(network, "roster_graph", graph)
    with tenant_scope(tenant="acme"):
        assert report._composition()["agents"] == 1
        report._composition()
    with tenant_scope(tenant="globex"):
        report._composition()
    assert built == ["acme", "globex"]
