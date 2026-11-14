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
            raise delivery.DeliveryRejected("provider refused")
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
            raise delivery.DeliveryRejected("provider refused")
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


@pytest.mark.parametrize("phase", ["execution", "staging"])
def test_live_legacy_owner_without_scope_is_never_declared_abandoned(journal, monkeypatch, phase):
    incoming = message("legacy")
    incoming.attachments = [{"filename": "note.txt", "mime": "text/plain", "data": b"live legacy input"}]
    row = journal.admit(incoming, external_id="legacy", account="acct")
    row = journal.claim_execution(row) if phase == "execution" else journal.change(row, execution="staging")
    # An earlier build persisted this protocol without the new ownership field
    # or activity locks. Its still-running handler/publisher owns this revision.
    row = journal.store.update(row["id"], lambda record: record.pop("activity_scope"),
                               expected_revision=row["revision"], action="legacy_fixture", actor="test")
    blob = delivery._blob_path(row["id"], row["message"]["attachments"][0]["sha256"])
    later = row["updated_at"] + delivery.STALE_CLAIM_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: later))

    async def run():
        ready, finish = asyncio.Event(), asyncio.Event()

        async def legacy_owner():
            ready.set()
            await finish.wait()
            return journal.change(row, execution="completed" if phase == "execution" else "received")

        owner = asyncio.create_task(legacy_owner())
        await ready.wait()
        try:
            if phase == "execution":
                journal._surface_stale_claim(row)
            else:
                journal._compact_receipt(row, later)
            assert not owner.done()
            assert journal.get(row["id"]) == row
            assert blob.exists()
        finally:
            finish.set()
            await owner
    asyncio.run(run())


def test_temporary_not_sent_is_retried_past_the_rejection_allowance(journal):
    """Throttled, disconnected or unavailable sends were never refused: no limit applies."""
    assert type(delivery.provider_refusal(429, "throttled")) is delivery.DeliveryNotSent
    assert type(delivery.provider_refusal(401, "session expired")) is delivery.DeliveryNotSent
    assert type(delivery.provider_refusal(400, "bad request")) is delivery.DeliveryNotSent
    assert type(delivery.provider_refusal(404, "no such recipient")) is delivery.DeliveryRejected
    calls = []

    async def handler(inbound):
        return "answer"

    async def send(reply):
        calls.append(reply.text)
        if len(calls) <= delivery.MAX_PROVIDER_ATTEMPTS + 2:
            raise delivery.DeliveryNotSent("provider is throttling; nothing was sent")
        return "accepted"

    async def run():
        channel = Adapter(handler)
        for _ in range(delivery.MAX_PROVIDER_ATTEMPTS + 2):
            row = await channel.process_message(message("busy"), external_id="busy", account="acct",
                      authorize=lambda: True, send=send, journal=journal)
            assert row["delivery"] == "retryable"
            assert row["chunks"]["reply"]["attempts"] == 0
            assert delivery.retry_delay(row) == 0
        row = await channel.process_message(message("busy"), external_id="busy", account="acct",
                  authorize=lambda: True, send=send, journal=journal)
        assert row["delivery"] == "delivered"
        assert len(calls) == delivery.MAX_PROVIDER_ATTEMPTS + 3
    asyncio.run(run())


class _Response:
    def __init__(self, status_code, body):
        self.status_code, self._body = status_code, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


@pytest.mark.parametrize(("status", "refused", "expected"), [
    (400, False, delivery.DeliveryNotSent), (403, False, delivery.DeliveryNotSent),
    (401, True, delivery.DeliveryNotSent), (429, True, delivery.DeliveryNotSent),
    (409, True, delivery.DeliveryNotSent), (400, True, delivery.DeliveryRejected),
    (403, True, delivery.DeliveryRejected), (404, False, delivery.DeliveryRejected),
    (410, False, delivery.DeliveryRejected), (413, False, delivery.DeliveryRejected),
    (422, False, delivery.DeliveryRejected),
])
def test_bare_400_or_403_is_not_evidence_of_a_refused_message(status, refused, expected):
    # Providers also answer throttling, quotas and expired credentials with 400/403.
    assert type(delivery.provider_refusal(status, "refused", refused=refused)) is expected


@pytest.mark.parametrize(("status", "body", "expected"), [
    (400, {"error": {"code": 4, "message": "Application request limit reached"}}, delivery.DeliveryNotSent),
    (400, {"error": {"code": 190, "message": "Session has expired"}}, delivery.DeliveryNotSent),
    (400, {"error": {"code": 130429, "message": "Rate limit hit"}}, delivery.DeliveryNotSent),
    (403, {"error": {"code": 131056}}, delivery.DeliveryNotSent),
    (400, {"error": {"code": 100, "is_transient": True}}, delivery.DeliveryNotSent),
    (400, ValueError("not json"), delivery.DeliveryNotSent),
    (400, {"unexpected": "shape"}, delivery.DeliveryNotSent),
    (400, {"error": {"code": 100, "message": "Invalid parameter"}}, delivery.DeliveryRejected),
    (400, {"error": {"code": 131026, "message": "Message undeliverable"}}, delivery.DeliveryRejected),
])
def test_graph_refusal_needs_a_message_level_error_code(status, body, expected):
    from maverick_channels.threads import ThreadsChannel
    from maverick_channels.whatsapp_cloud import graph_refusal

    response = _Response(status, body)
    assert type(graph_refusal(response, "refused")) is expected
    with pytest.raises(delivery.DeliveryNotSent) as raised:
        ThreadsChannel._check_send(response)
    assert type(raised.value) is expected


@pytest.mark.parametrize(("body", "expected"), [
    ({"error": "ExpiredToken", "message": "Token has expired"}, delivery.DeliveryNotSent),
    ({"error": "InvalidToken"}, delivery.DeliveryNotSent),
    ({"error": "InvalidRequest", "message": "Record/text must not be longer than 300 graphemes"},
     delivery.DeliveryNotSent),
])
def test_bluesky_expired_token_is_temporary(body, expected):
    from maverick_channels import bluesky

    assert type(bluesky._reply_refusal(_Response(400, body))) is expected
    assert type(bluesky._reply_refusal(_Response(404, {}))) is delivery.DeliveryRejected
