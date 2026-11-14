"""Definitive rejection is bounded; crashed intake and live work stay distinct."""
import asyncio
from types import SimpleNamespace

import pytest
from maverick import file_lock, paths, world_model
from maverick_channels import delivery, transport_worker
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
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORD_BACKEND", "local")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return delivery.DeliveryJournal()


def message(identity):
    return IncomingMessage(user_id="person", text=identity, channel="fixture", message_id=identity)


def test_provider_rejections_back_off_across_restart_then_release_conversation(journal, monkeypatch):
    calls, handled = [], []
    now = [delivery.time.time()]
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: now[0]))
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: now[0])

    async def handler(inbound):
        handled.append(inbound.text)
        return inbound.text

    async def send(inbound, reply, route):
        calls.append(reply.text)
        if reply.text == "first":
            raise delivery.DeliveryNotSent("provider refused")
        return "accepted"

    def worker():
        return transport_worker.TransportWorker(Adapter(handler), account="acct", authorize=lambda _: True,
                                                send=send, journal=journal)

    async def run():
        first = journal.admit(message("first"), external_id="first", account="acct")
        second = journal.admit(message("second"), external_id="second", account="acct")
        current = worker()
        await current._process(first["id"])
        prior_delay = 0
        for attempt in range(1, 9):
            row = journal.get(first["id"])
            assert row["chunks"]["reply"]["attempts"] == attempt
            if attempt == 8:
                assert row["delivery"] == "delivery_failed"
                break
            delay = row["chunks"]["reply"]["retry_at"] - now[0]
            assert delay >= 30 and delay > prior_delay
            prior_delay = delay
            current = worker()  # No in-memory timer survives the restart.
            await current._process(first["id"])
            assert calls == ["first"] * attempt
            await current._process(second["id"])
            assert handled == ["first"]
            now[0] += delay + 1
            await current._process(first["id"])
        await current._process(first["id"])
        await current._process(second["id"])
        assert calls == ["first"] * 8 + ["second"]
        assert handled == ["first", "second"]
    asyncio.run(run())


@pytest.mark.parametrize("sweep", ["recovery", "compaction"])
def test_abandoned_staging_is_released_without_executing(journal, monkeypatch, sweep):
    row = journal.admit(message("staged"), external_id="staged", account="acct")
    row = journal.change(row, execution="staging")
    future = row["updated_at"] + delivery.STALE_CLAIM_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: future))
    if sweep == "recovery":
        rows, _ = journal.recovery_window(channel="fixture", account="acct")
        assert rows == []
    else:
        journal.compact_delivered()
    assert journal.get(row["id"]) is None


def test_stale_sweep_does_not_change_a_running_handler(journal, monkeypatch):
    async def handler(inbound):
        row = journal.get(delivery._record_id("fixture", "acct", "live"))
        future = row["updated_at"] + delivery.STALE_CLAIM_SECONDS + 1
        monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: future))
        journal.recovery_window(channel="fixture", account="acct")
        assert journal.get(row["id"])["execution"] == "execution_started_unconfirmed"
        return "done"

    async def send(reply):
        return "accepted"
    result = asyncio.run(Adapter(handler).process_message(message("live"), external_id="live", account="acct",
                         authorize=lambda: True, send=send, journal=journal))
    assert result["execution"] == "completed" and result["delivery"] == "delivered"


@pytest.mark.parametrize("uncertainty", ["remote", "lock_unavailable", "workspace_changed", "identity_missing", "identity_corrupt"])
def test_stale_claim_retains_uncertain_ownership(journal, monkeypatch, uncertainty):
    row = journal.admit(message("uncertain"), external_id="uncertain", account="acct")
    row = journal.claim_execution(row)
    if uncertainty == "remote":
        row = journal.change(row, activity_scope="another-replica-and-home")
    elif uncertainty == "lock_unavailable":
        def unavailable(*args, **kwargs):
            raise OSError("filesystem locking unavailable")
        monkeypatch.setattr(delivery, "_receipt_activity", unavailable)
    else:
        identity = paths.data_dir("channels", "receipt-activity", "workspace-id")
        if uncertainty == "identity_missing":
            identity.unlink()
        else:
            replacement = b"b" * 32 if uncertainty == "workspace_changed" else b"invalid"
            file_lock.atomic_write_bytes(identity, replacement)
            if uncertainty == "workspace_changed":
                assert delivery._activity_scope() != row["activity_scope"]  # Same host/path, different lock volume.
    future = row["updated_at"] + delivery.STALE_CLAIM_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: future))
    rows, _ = journal.recovery_window(channel="fixture", account="acct")
    assert rows == []
    assert journal.get(row["id"])["execution"] == "execution_started_unconfirmed"
    if uncertainty == "identity_missing":
        assert not identity.exists()
    elif uncertainty == "identity_corrupt":
        assert identity.read_bytes() == b"invalid"



def test_source_withheld_never_uses_the_provider_rejection_allowance(journal, monkeypatch):
    allowed = [False]

    def require_source(row):
        if not allowed[0]:
            raise PermissionError("Source access withdrawn")
    monkeypatch.setattr(delivery, "_require_reply_source", require_source)
    calls = []

    async def handler(inbound):
        return "answer"

    async def send(reply):
        calls.append(reply.text)
        return "accepted"

    async def run():
        channel = Adapter(handler)
        for _ in range(10):
            row = await channel.process_message(message("held"), external_id="held", account="acct",
                      authorize=lambda: True, send=send, journal=journal)
            assert row["delivery"] == "retryable"
            assert row["chunks"]["reply"]["attempts"] == 0
            assert delivery.retry_delay(row) == 0
        assert calls == []
        allowed[0] = True
        row = await channel.process_message(message("held"), external_id="held", account="acct",
                  authorize=lambda: True, send=send, journal=journal)
        assert row["delivery"] == "delivered" and calls == ["answer"]
    asyncio.run(run())



def test_automatic_recovery_waits_but_explicit_recovery_remains_immediate(journal, monkeypatch):
    now = delivery.time.time()
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: now))
    calls, handled = [], []

    async def handler(inbound):
        handled.append(inbound.text)
        return "answer"

    async def send(reply):
        calls.append(reply.text)
        if len(calls) == 1:
            raise delivery.DeliveryNotSent("provider refused")
        return "accepted"

    async def send_saved(inbound, reply, route):
        return await send(reply)

    async def run():
        channel = Adapter(handler)
        row = await channel.process_message(message("recover"), external_id="recover", account="acct",
                    authorize=lambda: True, send=send, journal=journal)
        assert row["delivery"] == "retryable"
        kwargs = dict(account="acct", authorize=lambda _: True, send=send_saved, journal=journal)
        assert await delivery.recover_messages(channel, respect_retry_at=True, **kwargs) == []
        assert calls == ["answer"]
        result = await delivery.recover_messages(channel, **kwargs)
        assert result[0]["delivery"] == "delivered"
        assert calls == ["answer", "answer"] and handled == ["recover"]
    asyncio.run(run())
