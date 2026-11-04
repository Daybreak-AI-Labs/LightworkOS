"""Capability negotiation at swarm boot: narrow-only handshake + required check."""
from __future__ import annotations

import pytest
from maverick.capability import Capability
from maverick.capability_boot import BootNegotiation, negotiate_boot


def test_enforcement_off_is_unrestricted():
    neg = negotiate_boot(None, principal="agent:x")
    assert neg.ok and neg.granted is None
    assert "enforcement off" in neg.reason


def test_requested_scope_narrows_parent():
    parent = Capability(principal="root")  # empty allow == all tools
    neg = negotiate_boot(parent, principal="agent:coder-1",
                         requested_tools={"read_file", "http_fetch"})
    assert neg.ok
    assert neg.granted.principal == "agent:coder-1"
    assert neg.granted.permits("read_file")
    assert not neg.granted.permits("shell")   # not requested -> not granted


def test_cannot_broaden_beyond_parent():
    parent = Capability(principal="root", allow_tools=frozenset({"read_file"}))
    # child asks for shell too, but parent only had read_file
    neg = negotiate_boot(parent, principal="agent:c",
                         requested_tools={"read_file", "shell"})
    assert not neg.granted.permits("shell")
    assert "shell" in neg.denied_tools
    assert neg.ok  # denied_tools is informational, not a hard failure


def test_required_capability_denied_fails_boot():
    parent = Capability(principal="root", allow_tools=frozenset({"read_file"}))
    neg = negotiate_boot(parent, principal="agent:c",
                         required_tools={"shell"})  # parent can't grant shell
    assert neg.ok is False
    assert "shell" in neg.denied_required
    assert "required capabilities not granted" in neg.reason


def test_required_capability_granted_ok():
    parent = Capability(principal="root")  # all tools
    neg = negotiate_boot(parent, principal="agent:c",
                         requested_tools={"read_file", "shell"},
                         required_tools={"shell"})
    assert neg.ok and neg.granted.permits("shell")


def test_max_risk_tightens():
    parent = Capability(principal="root")  # no risk cap
    neg = negotiate_boot(parent, principal="agent:c", max_risk="low")
    assert neg.granted.max_risk == "low"


def test_record_is_serializable():
    parent = Capability(principal="root", allow_tools=frozenset({"read_file"}))
    rec = negotiate_boot(parent, principal="agent:c",
                         required_tools={"shell"}).record()
    assert rec["ok"] is False and "shell" in rec["denied_required"]
    assert rec["principal"] == "agent:c"
    import json
    json.dumps(rec)  # must not raise


def test_boot_negotiation_dataclass_defaults():
    n = BootNegotiation(granted=None, ok=True)
    assert n.denied_tools == [] and n.denied_required == []


# ---- spawn integration ----

def test_child_capability_negotiates(monkeypatch):
    from maverick.tools.spawn import _child_capability

    class _Parent:
        capability = Capability(principal="root")

    cap = _child_capability(_Parent(), "coder", 1,
                            requested_tools={"read_file"})
    assert cap.principal == "agent:coder-1"
    assert cap.permits("read_file") and not cap.permits("shell")


def test_child_capability_none_when_enforcement_off():
    from maverick.tools.spawn import _child_capability

    class _Parent:
        capability = None

    assert _child_capability(_Parent(), "coder", 1) is None


def test_child_capability_raises_on_denied_required():
    from maverick.tools.spawn import CapabilityBootDenied, _child_capability

    class _Parent:
        capability = Capability(principal="root",
                                allow_tools=frozenset({"read_file"}))

    with pytest.raises(CapabilityBootDenied):
        _child_capability(_Parent(), "coder", 1, required_tools={"shell"})
