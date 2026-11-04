"""Durable stores retain recoverable state when audit policy refuses a row."""

from __future__ import annotations

import copy

import pytest
from maverick.audit import AuditRefused, AuditWriteRefused


def _audit_refuses(monkeypatch) -> None:
    import maverick.audit as audit

    def refuse(*_args, **_kwargs):
        raise AuditWriteRefused("configured signing floor refused the row")

    monkeypatch.setattr(audit, "record", refuse)


def _audit_succeeds(monkeypatch) -> None:
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_license_registration_refusal_restores_absent_store(monkeypatch):
    from maverick import license_registry

    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        license_registry.add_license(
            name="Money transmitter",
            jurisdiction="NY",
            authority="NYDFS",
            license_number="MT-1",
        )

    assert license_registry._load() == []
    assert not license_registry._store_path().exists()


@pytest.mark.parametrize("mutation", ["evidence", "renew", "status"])
def test_license_mutation_refusal_restores_exact_prior_record(
    mutation,
    monkeypatch,
):
    from maverick import license_registry

    _audit_succeeds(monkeypatch)
    rec = license_registry.add_license(
        name="Producer",
        jurisdiction="CA",
        authority="CDI",
        license_number="P-1",
        status="pending",
        renewal_at=2_000_000_000,
    )
    prior = copy.deepcopy(license_registry._load())
    _audit_refuses(monkeypatch)

    with pytest.raises(AuditRefused):
        if mutation == "evidence":
            license_registry.attach_evidence(rec["id"], note="filed")
        elif mutation == "renew":
            license_registry.renew(rec["id"], note="renewed")
        else:
            license_registry.set_status(rec["id"], "active")

    assert license_registry._load() == prior


def test_platform_hunt_refusal_keeps_durable_outbox_pending(tmp_path):
    from maverick.platform_hunt import HuntStore

    def refuse(_kind, _payload):
        raise AuditWriteRefused("off-host custody refused local signing")

    store = HuntStore(tmp_path / "hunt.sqlite3", audit_recorder=refuse)

    with pytest.raises(AuditRefused):
        store.ensure_audit_custody_witness()

    assert store.pending_audit_count() == 1
