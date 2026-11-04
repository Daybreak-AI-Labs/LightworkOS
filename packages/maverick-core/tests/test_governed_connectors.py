"""Governed connectors: typed, risk-classed, lineage-tracked read/write to a
system of record (reference in-memory connector)."""
from __future__ import annotations

import pytest
from maverick.governed_actions import ActionError, GovernedActions
from maverick.governed_connectors import InMemoryConnector, register_connector


def _wired():
    ga = GovernedActions()
    conn = InMemoryConnector(store={"acct-1": "active"})
    rname, wname = register_connector(ga, conn)
    return ga, conn, rname, wname


def test_register_exposes_read_low_and_write_high():
    ga, _conn, rname, wname = _wired()
    assert (rname, wname) == ("memory.read", "memory.write")
    assert ga.get(rname).risk == "low"
    assert ga.get(wname).risk == "high"


def test_read_is_low_risk_and_needs_no_approver():
    ga, _conn, rname, _w = _wired()
    assert ga.commit(rname, {"key": "acct-1"}) == "active"
    assert ga.lineage[-1].action == "memory.read"


def test_write_preview_has_no_side_effect():
    ga, conn, _r, wname = _wired()
    pv = ga.simulate(wname, {"key": "acct-1", "value": "closed"})
    assert "'active' -> 'closed'" in pv.effect
    assert pv.requires_approval is True        # write is high risk
    assert conn.store["acct-1"] == "active"    # simulate must not write


def test_write_requires_approver_then_commits_with_lineage():
    ga, conn, _r, wname = _wired()
    with pytest.raises(ActionError, match="requires an approver"):
        ga.commit(wname, {"key": "acct-1", "value": "closed"})
    out = ga.commit(wname, {"key": "acct-1", "value": "closed"}, approver="alice",
                    sources=("ticket-42",))
    assert out == "wrote acct-1"
    assert conn.store["acct-1"] == "closed"
    assert ga.verify_lineage().startswith("VALID")
    t = ga.trace()
    assert t["approver"] == "alice" and t["sources"] == ["ticket-42"]


def test_write_typing_enforced():
    ga, _conn, _r, wname = _wired()
    with pytest.raises(ActionError, match="must be str"):
        ga.commit(wname, {"key": "acct-1", "value": 99}, approver="x")
