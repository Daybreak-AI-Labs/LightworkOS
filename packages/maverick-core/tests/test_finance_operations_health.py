"""Tenant-scoped finance scheduler success receipts."""
from __future__ import annotations

import pytest
from maverick.finance import operations_health


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")


def test_success_receipts_are_atomic_bounded_server_timed_and_tenant_scoped(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setattr(operations_health.time, "time", lambda: 100.0)
    token = set_tenant("tenant-a")
    try:
        saved = operations_health.record_success(
            "regulatory_poll",
            "federal-register",
            details={"items_seen": 0},
        )
        assert saved["succeeded_at"] == 100.0
        assert operations_health.success_receipts(component="regulatory_poll") == [saved]
    finally:
        reset_tenant(token)

    token = set_tenant("tenant-b")
    try:
        assert operations_health.success_receipts(component="regulatory_poll") == []
    finally:
        reset_tenant(token)


def test_receipt_rejects_oversized_details():
    with pytest.raises(ValueError, match="oversized"):
        operations_health.record_success(
            "regulatory_poll",
            "source",
            details={"value": "x" * (17 * 1024)},
        )


def test_receipt_file_evicts_oldest_to_remain_byte_bounded(monkeypatch):
    clock = iter(range(1, 40))
    monkeypatch.setattr(operations_health.time, "time", lambda: float(next(clock)))

    latest = None
    for index in range(30):
        latest = operations_health.record_success(
            "regulatory_poll",
            f"source-{index:02d}",
            details={"value": "x" * (16 * 1024 - 100)},
        )
        assert operations_health._path().stat().st_size <= operations_health._MAX_FILE_BYTES

    receipts = operations_health.success_receipts(component="regulatory_poll")
    assert latest is not None
    assert receipts[0] == latest
    assert receipts[-1]["key"] != "source-00"
    assert len(receipts) < 30


def test_single_receipt_that_cannot_fit_is_not_persisted(monkeypatch):
    monkeypatch.setattr(operations_health, "_MAX_FILE_BYTES", 64)

    with pytest.raises(ValueError, match="cannot fit its storage bound"):
        operations_health.record_success(
            "regulatory_poll",
            "source",
            details={"value": "small"},
        )

    assert not operations_health._path().exists()
