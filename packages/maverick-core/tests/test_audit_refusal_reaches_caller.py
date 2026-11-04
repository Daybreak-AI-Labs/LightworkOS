"""A compliance-floored refusal to write must not be swallowed by its caller.

``audit.writer`` deliberately raises rather than downgrading to plaintext when an
active compliance profile mandates signed, tamper-evident logs and the signer
will not start. That refusal only means anything if it reaches whoever was about
to act: ``agent._audit_tool_event`` wrapped the call in a bare
``except Exception: pass``, so the writer's careful choice between "write
unsigned" and "refuse" collapsed into a third outcome it never offered -- write
nothing, and run the tool anyway.

Under HIPAA-style profiles the claim being sold is that every action lands on a
tamper-evident chain. An unrecorded action is the breach of that claim; a noisy
failure is not.
"""
from __future__ import annotations

import logging

import pytest
from maverick.audit import AuditWriteRefused


def test_refusal_is_a_runtime_error_subclass() -> None:
    """Pre-existing ``except RuntimeError`` handlers must keep working.

    The refusal was an unnamed RuntimeError before it had a class. Narrowing it
    to a bare Exception subclass would have silently un-handled it wherever a
    caller was already catching RuntimeError deliberately.
    """
    assert issubclass(AuditWriteRefused, RuntimeError)


class _Ctx:
    goal_id = 7


class _FakeAgent:
    """The smallest thing carrying the real ``_audit_tool_event`` implementation."""

    name = "tester"
    ctx = _Ctx()

    def __init__(self):
        from maverick.agent import Agent

        self._audit_tool_event = Agent._audit_tool_event.__get__(self, _FakeAgent)


def test_compliance_refusal_propagates_out_of_the_tool_audit_path(monkeypatch):
    """The refusal reaches the caller instead of the tool running unlogged."""
    import maverick.audit as audit_mod

    def _refuse(*a, **kw):
        raise AuditWriteRefused(
            "audit: an active compliance profile requires signed, tamper-evident "
            "audit logs, but the audit signer could not initialize -- refusing to "
            "write UNSIGNED."
        )

    monkeypatch.setattr(audit_mod, "record", _refuse)
    with pytest.raises(AuditWriteRefused, match="refusing to write UNSIGNED"):
        _FakeAgent()._audit_tool_event("tool_start", tool="wire_transfer")


def test_ordinary_audit_failures_are_still_swallowed_but_logged(monkeypatch, caplog):
    """A broken log must not crash a run -- but must not be invisible either.

    The old bare ``pass`` made a permanently broken audit path indistinguishable
    from a healthy one, which is how "every action is logged" stays true-looking
    while being false.
    """
    import maverick.audit as audit_mod

    def _boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(audit_mod, "record", _boom)
    # The warning now comes from audit_event in maverick.audit.writer rather
    # than from the agent: the contract moved into one helper so it stops
    # depending on ~93 call sites each remembering to apply it.
    with caplog.at_level(logging.WARNING, logger="maverick.audit.writer"):
        _FakeAgent()._audit_tool_event("tool_start", tool="wire_transfer")

    messages = [r.getMessage() for r in caplog.records]
    assert any("write failed" in m for m in messages), messages
    assert any("tool_start" in m for m in messages), messages
    # exc_info is what makes it diagnosable rather than merely noisy.
    assert any(r.exc_info for r in caplog.records)


def test_a_successful_write_returns_quietly(monkeypatch, caplog):
    """No warning on the happy path, or the signal is worthless."""
    import maverick.audit as audit_mod

    seen = {}

    def _ok(kind, **payload):
        seen["kind"] = kind
        seen["payload"] = payload
        return True

    monkeypatch.setattr(audit_mod, "record", _ok)
    with caplog.at_level(logging.WARNING, logger="maverick.agent"):
        _FakeAgent()._audit_tool_event("tool_start", tool="wire_transfer")

    assert seen["kind"] == "tool_start"
    assert seen["payload"]["tool"] == "wire_transfer"
    assert seen["payload"]["goal_id"] == 7
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
