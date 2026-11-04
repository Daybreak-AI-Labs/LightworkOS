"""Agent-building guidance comparisons keep provider calls outside the authority fence."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick.authority_effects import authority_effect_fence
from maverick_dashboard import factory_guidance

PREPARED = {"correction": {"detail": "read_file"}}
CASE = {"name": "invoice_helper", "description": "Reads invoices and lists what is overdue.", "goals": []}
ANSWER = '{"allow_tools": ["read_file"], "deny_tools": [], "max_risk": "low"}'


class Provider:
    """Records whether another authority writer could take the fence mid-call."""

    def __init__(self):
        self.writer_blocked = []
        self.dispatch_checks = 0

    def complete(self, *, system, messages, budget, max_tokens, dispatch_guard=None):
        taken = []

        def writer():
            with authority_effect_fence():
                taken.append(True)

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        thread.join(3)
        self.writer_blocked.append(thread.is_alive())
        if dispatch_guard is not None:
            self.dispatch_checks += 1
            dispatch_guard()
        return SimpleNamespace(text=ANSWER)


def test_the_provider_call_does_not_hold_the_authority_fence(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    provider, checks = Provider(), []
    value = factory_guidance._proposal(provider, PREPARED, CASE, "guidance", object(), lambda: checks.append(True))
    assert provider.writer_blocked == [False], "a role change or revocation had to wait for the AI call"
    assert value["maximum_risk"] == "low"
    # Authority is still re-read before the request and again at the physical send.
    assert provider.dispatch_checks == 1 and len(checks) >= 2


def test_authority_withdrawn_before_dispatch_still_refuses_the_request(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    calls = []

    def guard():
        calls.append(True)
        if len(calls) > 1:
            raise HTTPException(409, "The reviewed sources changed.")

    with pytest.raises(HTTPException, match="reviewed sources changed"):
        factory_guidance._proposal(Provider(), PREPARED, CASE, "guidance", object(), guard)
