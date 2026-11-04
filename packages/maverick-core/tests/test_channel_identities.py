"""Chat-account links: access is audited before it exists, never after."""
from __future__ import annotations

import pytest
from maverick import audit
from maverick import channel_identities as identities


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


def refusing(monkeypatch):
    def refuse(*args, **kwargs):
        raise audit.AuditRefused("policy requires off-host signing")

    monkeypatch.setattr(audit, "audit_event", refuse)


def test_a_link_the_audit_policy_refuses_leaves_no_link(monkeypatch):
    refusing(monkeypatch)
    with pytest.raises(audit.AuditRefused):
        identities.link("slack", "U123", "user:alice", actor="user:admin")
    assert identities.principal_for("slack", "U123") is None


def test_a_redeemed_code_the_audit_policy_refuses_stays_redeemable(monkeypatch):
    code = identities.issue_link_code("user:alice", "slack")["code"]
    real = audit.audit_event
    refusing(monkeypatch)
    with pytest.raises(audit.AuditRefused):
        identities.redeem_link_code("slack", "U123", code)
    assert identities.principal_for("slack", "U123") is None
    monkeypatch.setattr(audit, "audit_event", real)
    assert identities.redeem_link_code("slack", "U123", code) == "user:alice"
    assert identities.principal_for("slack", "U123") == "user:alice"


def test_an_audited_link_works_and_unlinking_is_never_blocked_by_the_audit(monkeypatch):
    identities.link("slack", "U123", "user:alice", actor="user:admin")
    assert identities.principal_for("slack", "U123") == "user:alice"
    refusing(monkeypatch)
    with pytest.raises(audit.AuditRefused):
        identities.unlink("slack", "U123", actor="user:admin")
    assert identities.principal_for("slack", "U123") is None           # access was cut off first
