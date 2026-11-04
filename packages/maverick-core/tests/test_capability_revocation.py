"""capability_revocation: transitive revocation propagation."""
from __future__ import annotations

from maverick.tools.capability_revocation import capability_revocation


def _run(**kw):
    return capability_revocation().fn({"op": "propagate", **kw})


def test_transitive_chain():
    grants = [
        {"from": "root", "to": "a", "capability": "deploy"},
        {"from": "a", "to": "b", "capability": "deploy"},
        {"from": "b", "to": "c", "capability": "deploy"},
    ]
    out = _run(grants=grants, principal="root", capability="deploy")
    assert out.startswith("REVOKED")
    for p in ("a", "b", "c"):
        assert p in out
    assert "3 principal(s)" in out


def test_only_matching_capability_propagates():
    grants = [
        {"from": "root", "to": "a", "capability": "deploy"},
        {"from": "a", "to": "b", "capability": "read"},  # different cap
    ]
    out = _run(grants=grants, principal="root", capability="deploy")
    assert "a" in out
    assert "b" not in out  # b got 'read', not 'deploy'


def test_no_downstream():
    grants = [{"from": "root", "to": "a", "capability": "deploy"}]
    out = _run(grants=grants, principal="a", capability="deploy")
    assert out.startswith("REVOKED")
    assert "no downstream" in out


def test_independent_path_keeps_capability():
    """A principal granted the cap by an UN-revoked grantor keeps it — only
    holders solely-via the revoked holder lose it (the docstring's 'only')."""
    grants = [
        {"from": "alice", "to": "carol", "capability": "deploy"},
        {"from": "bob", "to": "carol", "capability": "deploy"},  # independent grantor
    ]
    out = _run(grants=grants, principal="alice", capability="deploy")
    # carol still holds it via bob, so she is NOT downstream-revoked.
    assert "no downstream" in out
    assert "carol" not in out


def test_loses_only_when_all_paths_revoked():
    """A middle node held only via the revoked holder loses it, but a leaf with
    one surviving (independent) path keeps it."""
    grants = [
        {"from": "owner", "to": "mid", "capability": "publish"},
        {"from": "mid", "to": "leaf", "capability": "publish"},
        {"from": "side", "to": "leaf", "capability": "publish"},  # surviving path
    ]
    out = _run(grants=grants, principal="owner", capability="publish")
    assert "1 principal(s)" in out
    assert "- mid" in out        # mid held it only via owner
    assert "leaf" not in out     # leaf survives via side


def test_cycle_terminates():
    grants = [
        {"from": "a", "to": "b", "capability": "x"},
        {"from": "b", "to": "a", "capability": "x"},  # cycle back to a
        {"from": "b", "to": "c", "capability": "x"},
    ]
    out = _run(grants=grants, principal="a", capability="x")
    # BFS must terminate; b and c lose it (a is the revoked root, not a loser).
    assert "b" in out and "c" in out


def test_errors():
    assert _run(grants="nope", principal="a", capability="x").startswith("ERROR")
    assert _run(grants=[], principal="", capability="x").startswith("ERROR")
    assert _run(grants=[], principal="a", capability="").startswith("ERROR")
    assert capability_revocation().fn(
        {"op": "bad", "grants": [], "principal": "a", "capability": "x"}
    ).startswith("ERROR")


def test_factory_contract():
    t = capability_revocation()
    assert t.name == "capability_revocation"
    assert t.parallel_safe is True
    assert t.input_schema["required"] == ["grants", "principal", "capability"]
