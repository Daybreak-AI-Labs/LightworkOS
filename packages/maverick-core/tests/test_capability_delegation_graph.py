"""capability_delegation_graph: delegation-risk analysis."""
from __future__ import annotations

from maverick.tools.capability_delegation_graph import capability_delegation_graph


def _an(grants, **kw):
    return capability_delegation_graph().fn({"op": "analyze", "grants": grants, **kw})


def test_clean_simple_chain():
    grants = [
        {"from": "root", "to": "alice", "capability": "read"},
        {"from": "alice", "to": "bob", "capability": "read"},
    ]
    assert _an(grants).startswith("CLEAN")


def test_cycle_detected():
    grants = [
        {"from": "a", "to": "b", "capability": "x"},
        {"from": "b", "to": "a", "capability": "x"},
    ]
    out = _an(grants)
    assert out.startswith("RISK") and "delegation-cycle" in out


def test_over_broad_fanout():
    grants = [{"from": "a", "to": f"u{i}", "capability": "x"} for i in range(6)]
    assert "over-broad fan-out" in _an(grants)


def test_sensitive_capability_holder():
    grants = [{"from": "root", "to": "svc", "capability": "spend_money"}]
    out = _an(grants, sensitive=["spend_money"])
    assert "sensitive-capability holder" in out and "svc" in out


def test_missing_grants_errors():
    assert capability_delegation_graph().fn({"op": "analyze"}).startswith("ERROR")


def test_non_dict_grant_does_not_crash():
    # Model-supplied grants may contain non-objects; must not raise.
    assert _an([1, 2, 3]).startswith(("CLEAN", "RISK"))
    assert _an([None, {"from": "a", "to": "b"}]).startswith(("CLEAN", "RISK"))
