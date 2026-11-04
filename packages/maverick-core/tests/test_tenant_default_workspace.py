"""Creating the first explicit workspace must not lock out the deployment's
implicit default one.

A fresh install runs every task inside its bound tenant (``MAVERICK_TENANT``
or the ``[client] id`` floor) and no roster file exists, so admission is
open. The moment an operator creates the first named workspace the roster
comes into being, and the implicit default must have a row in it, or every
task is refused with ``tenant is suspended or unknown``.
"""
from __future__ import annotations

import pytest
from maverick.tenant import registry as tr


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    from maverick import client

    client.reset_client_cache()
    yield
    client.reset_client_cache()


@pytest.fixture
def audit_rows(monkeypatch):
    rows: list[tuple[str, dict]] = []
    import maverick.audit as audit

    def _record(kind, **payload):
        rows.append((str(kind), payload))
        return True

    monkeypatch.setattr(audit, "audit_event", _record, raising=False)
    return rows


def test_first_workspace_registers_the_bound_default_tenant(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    assert tr.get_tenant("owner-browser") is None

    tr.create_tenant("acme", display_name="Acme")

    default = tr.get_tenant("owner-browser")
    assert default is not None and default.active
    assert default.max_daily_dollars == 0.0
    # The implicit default keeps working exactly as before the roster existed.
    tr.assert_tenant_active("owner-browser")
    assert tr.is_active("owner-browser")
    assert [t.id for t in tr.list_tenants()] == ["acme", "owner-browser"]
    kinds = [kind for kind, _ in audit_rows]
    assert "tenant_default_registered" in kinds
    payload = dict(audit_rows)["tenant_default_registered"]
    assert payload["tenant"] == "owner-browser"


def test_client_floor_counts_as_the_default_tenant(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "owner-browser")
    tr.create_tenant("acme")
    assert tr.is_active("owner-browser")
    tr.assert_tenant_active("owner-browser")


def test_an_install_that_already_hit_the_bug_is_repaired_on_admission(monkeypatch, audit_rows):
    # Roster written while unbound: only "acme" exists.
    tr.create_tenant("acme")
    assert tr.get_tenant("owner-browser") is None
    # The deployment is bound to owner-browser; this must not raise
    # TenantSuspended and show the raw text in the chat.
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")

    tr.assert_tenant_active("owner-browser")

    default = tr.get_tenant("owner-browser")
    assert default is not None and default.active
    assert [kind for kind, _ in audit_rows] == ["tenant_default_registered"]
    # Idempotent: a second admission neither re-registers nor re-audits.
    tr.assert_tenant_active("owner-browser")
    assert tr.is_active("owner-browser")
    assert [kind for kind, _ in audit_rows] == ["tenant_default_registered"]


def test_ensure_default_is_a_no_op_without_a_roster_or_a_binding(audit_rows, tmp_path):
    assert tr.ensure_default_tenant_registered() is None
    assert not (tmp_path / "tenant_registry.json").exists()
    assert audit_rows == []


def test_a_deliberately_paused_default_stays_paused(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    tr.create_tenant("acme")
    tr.suspend_tenant("owner-browser")

    assert not tr.is_active("owner-browser")
    with pytest.raises(tr.TenantSuspended):
        tr.assert_tenant_active("owner-browser")


def test_other_unknown_tenants_are_still_refused(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    tr.create_tenant("acme")
    assert not tr.is_active("ghost")
    with pytest.raises(tr.TenantSuspended):
        tr.assert_tenant_active("ghost")


def test_creating_the_default_itself_does_not_duplicate_it(monkeypatch, audit_rows):
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    rec = tr.create_tenant("owner-browser", display_name="Mine")
    assert rec.display_name == "Mine"
    assert [t.id for t in tr.list_tenants()] == ["owner-browser"]
    assert audit_rows == []


def test_repair_inside_a_held_roster_lock_does_not_deadlock(monkeypatch, audit_rows):
    """provider_admission calls assert_tenant_active while holding the roster
    lock; the repair must reuse that lock instead of waiting on it forever."""
    import threading

    tr.create_tenant("acme")
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    outcome: dict[str, object] = {}

    def _admit():
        try:
            with tr._locked(strict=True):
                tr.assert_tenant_active("owner-browser")
            outcome["ok"] = True
        except Exception as exc:  # noqa: BLE001 -- the failure is the finding
            outcome["error"] = exc

    worker = threading.Thread(target=_admit, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "assert_tenant_active deadlocked on the roster lock"
    assert outcome == {"ok": True}
    assert tr.get_tenant("owner-browser").active
    # And the lock is released for the next admission.
    with tr._locked():
        pass
