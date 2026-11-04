"""Channel receipts never strand a message and never fill intake forever."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from maverick import world_model
from maverick_channels import delivery
from maverick_channels.base import Channel, IncomingMessage


class Adapter(Channel):
    name = "fixture"

    async def start(self):
        pass

    async def stop(self):
        pass

    async def send(self, user_id, text):
        pass


@pytest.fixture
def journal(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORD_BACKEND", "local")
    return delivery.DeliveryJournal()


def _msg(i):
    return IncomingMessage(user_id="person", text="q", channel="fixture", message_id=f"e{i}")


def _run(journal, i, handler, send=None):
    async def default_send(reply):
        return "pid"
    return asyncio.run(Adapter(handler).process_message(
        _msg(i), external_id=f"e{i}", account="acct", authorize=lambda: True,
        send=send or default_send, journal=journal))


def test_old_delivered_receipts_are_released_so_intake_never_fills(journal, monkeypatch):
    monkeypatch.setattr(delivery, "MAX_RECORDS", 3)

    async def handler(m):
        return "a"
    rows = [_run(journal, i, handler) for i in range(3)]
    later = max(r["updated_at"] for r in rows) + delivery.RETENTION_SECONDS + 10
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: later))
    journal.compact_delivered(limit=3)                         # payloads cleared
    assert journal.store.count() == 3                          # tombstones kept for dedup
    much_later = later + delivery.TOMBSTONE_SECONDS
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: much_later))
    journal.compact_delivered(limit=3)
    assert journal.store.count() == 0
    assert _run(journal, 99, handler)["delivery"] == "delivered"


def test_automatic_maintenance_frees_expired_receipts_without_replaying_unknowns(journal, monkeypatch):
    monkeypatch.setattr(delivery, "MAX_RECORDS", 2)
    monkeypatch.setattr(delivery, "MAINTENANCE_INTERVAL_SECONDS", 0)
    delivery._maintenance_last.clear()

    async def handler(message):
        return "answered"

    delivered = _run(journal, 1, handler)
    uncertain = journal.admit(_msg(2), external_id="e2", account="acct")
    uncertain = journal.change(uncertain, execution="execution_unknown", delivery="delivered")
    future = delivered["updated_at"] + delivery.RETENTION_SECONDS + delivery.TOMBSTONE_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: future))

    assert _run(journal, 3, handler)["delivery"] == "delivered"
    assert journal.get(uncertain["id"])["execution"] == "execution_unknown"
    assert journal.get(delivered["id"]) is None


@pytest.mark.parametrize("ids,expected_used,exact,full", [
    (("a", "b"), 2, True, False),
    (("a", "b", "c"), 3, True, True),
    (("a", "b", "c", "d"), 4, False, True),
])
def test_capacity_status_pages_past_short_backend_windows(monkeypatch, ids, expected_used, exact, full):
    class ShortPages:
        def iter_record_ids(self, *, start_after="", limit=100):
            pivot = next((i for i, key in enumerate(ids) if key > start_after), len(ids))
            for key in (ids[pivot:] + ids[:pivot])[:min(limit, 2)]:
                yield key, key

    monkeypatch.setattr(delivery, "intake_record_limit", lambda: 3)
    status = delivery.DeliveryJournal(store=ShortPages()).capacity_status()
    assert status["used"] == expected_used and status["limit"] == 3
    assert status["count_exact"] is exact and status["full"] is full


def test_intake_capacity_reads_current_setting_and_rejects_invalid_limits(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"channels": {"max_intake_records": 50000}})
    assert delivery.intake_record_limit() == 50000
    for bad in (True, 50000.5, "50000", 100001, 999):
        monkeypatch.setattr(config, "load_config", lambda bad=bad: {"channels": {"max_intake_records": bad}})
        with pytest.raises(ValueError, match="intake capacity"):
            delivery.intake_record_limit()


def test_a_failed_world_mark_hands_the_message_back_to_recovery(journal, monkeypatch):
    row = journal.admit(_msg(1), external_id="e1", account="acct")
    real = world_model.WorldModel.mark_message_processed

    def boom(self, *a, **k):
        raise OSError("world db locked")
    monkeypatch.setattr(world_model.WorldModel, "mark_message_processed", boom)
    with pytest.raises(OSError):
        journal.claim_execution(row)
    monkeypatch.setattr(world_model.WorldModel, "mark_message_processed", real)
    assert journal.get(row["id"])["execution"] == "received"
    rows, _ = journal.recovery_window(channel="fixture", account="acct")
    assert [r["id"] for r in rows] == [row["id"]]


def test_a_cancelled_handler_is_recorded_as_unknown_with_a_reply(journal):
    async def handler(m):
        raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        _run(journal, 2, handler, send=lambda r: None)
    row = journal.get(delivery._record_id("fixture", "acct", "e2"))
    assert row["execution"] == "execution_unknown" and row["delivery"] == "ready"


def test_a_claim_abandoned_by_a_dead_process_is_surfaced_not_rerun(journal, monkeypatch):
    row = journal.admit(_msg(3), external_id="e3", account="acct")
    claimed = journal.claim_execution(row)          # the process dies in the handler here
    later = claimed["updated_at"] + delivery.STALE_CLAIM_SECONDS + 10
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: later))
    rows, _ = journal.recovery_window(channel="fixture", account="acct")
    surfaced = journal.get(row["id"])
    assert surfaced["execution"] == "execution_unknown" and surfaced["delivery"] == "ready"
    assert [r["id"] for r in rows] == [row["id"]]   # its reply is now delivered


def test_a_send_abandoned_by_a_dead_process_is_surfaced_as_unknown_not_replayed(journal, monkeypatch):
    row = journal.admit(_msg(4), external_id="e4", account="acct")
    sending = journal.change(row, execution="completed", delivery="sending", chunks={
        "reply": {"state": "sending", "payload_sha256": "x", "attempt_id": "a"},
        "text-0": {"state": "delivered", "payload_sha256": "y", "attempt_id": "b"}})
    journal.recovery_window(channel="fixture", account="acct")
    assert journal.get(row["id"])["delivery"] == "sending"                # a live send is left alone
    later = sending["updated_at"] + delivery.STALE_CLAIM_SECONDS + 10
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: later))
    rows, _ = journal.recovery_window(channel="fixture", account="acct")
    surfaced = journal.get(row["id"])
    assert surfaced["delivery"] == "delivery_unknown"
    assert surfaced["chunks"]["reply"]["state"] == "delivery_unknown"
    assert surfaced["chunks"]["text-0"]["state"] == "delivered"           # a finished chunk keeps its outcome
    assert [r["id"] for r in rows if r["id"] == row["id"]] == []           # never offered for sending again
