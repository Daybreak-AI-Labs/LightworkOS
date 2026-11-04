"""Actual durable CAS journal and local world; no provider or agent calls."""
from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import world_model
from maverick.privacy_ops import RecordConflict
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
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORD_BACKEND", "local")
    return delivery.DeliveryJournal()


def _message(text="Question"):
    return IncomingMessage(user_id="person", text=text, channel="fixture", message_id="event1")


def test_intake_failure_never_claims_execution_or_runs_handler(isolated, monkeypatch):
    async def handler(msg):
        pytest.fail("Handler ran before durable intake")
    monkeypatch.setattr(isolated.store, "create", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk unavailable")))
    with pytest.raises(OSError):
        asyncio.run(Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                    authorize=lambda: True, send=lambda reply: None, journal=isolated))
    with world_model.WorldModel(world_model.DEFAULT_DB) as world:
        assert not world.is_processed_message("fixture", "event1")


def test_saved_reply_retries_only_definitively_unsent_chunk(isolated):
    runs, calls = [], []
    async def handler(msg):
        runs.append(msg.text)
        return "answer"
    async def send(reply):
        calls.append(reply.text)
        if len(calls) == 1:
            raise delivery.DeliveryNotSent("fixture rejection before acceptance")
        return "provider-message-id"
    channel = Adapter(handler)
    async def run():
        args = dict(external_id="event1", account="account1", authorize=lambda: True, send=send, journal=isolated)
        first = await channel.process_message(_message(), **args)
        assert first["execution"] == "completed" and first["delivery"] == "retryable"
        second = await channel.process_message(_message(), **args)
        assert second["delivery"] == "delivered"
        await channel.process_message(_message(), **args)
    asyncio.run(run())
    assert runs == ["Question"] and calls == ["answer", "answer"]


def test_ambiguous_send_redelivery_never_reexecutes_or_resends(isolated):
    runs, sends = [], []
    async def handler(msg):
        runs.append(msg.text)
        return "answer"
    async def send(reply):
        sends.append(reply.text)
        raise TimeoutError("possibly accepted upstream")
    async def run():
        for _ in range(2):
            row = await Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                        authorize=lambda: True, send=send, journal=isolated)
            assert row["delivery"] == "delivery_unknown"
    asyncio.run(run())
    assert runs == ["Question"] and sends == ["answer"]


def test_crash_after_execution_claim_is_explicit_and_never_reopened(isolated):
    row = isolated.admit(_message(), external_id="event1", account="account1")
    claimed = isolated.claim_execution(row)
    assert claimed["execution"] == "execution_started_unconfirmed"
    async def handler(msg):
        pytest.fail("Unknown execution replayed")
    actual = asyncio.run(Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                         authorize=lambda: True, send=lambda reply: None, journal=delivery.DeliveryJournal()))
    assert actual["execution"] == "execution_started_unconfirmed"


def test_concurrent_admission_and_execution_claim_has_one_owner(isolated):
    def admit(_):
        return delivery.DeliveryJournal().admit(_message(), external_id="event1", account="account1")
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(admit, range(8)))
    assert len({row["id"] for row in receipts}) == 1
    current = isolated.get(receipts[0]["id"])
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda _: isolated.claim_execution(current), range(8)))
    assert sum(row is not None for row in claims) == 1


def test_legacy_processed_receipt_is_not_automatically_reopened(isolated):
    with world_model.WorldModel(world_model.DEFAULT_DB) as world:
        world.mark_message_processed("fixture", "event1")
    row = isolated.admit(_message(), external_id="event1", account="account1")
    assert isolated.claim_execution(row) is None
    assert isolated.get(row["id"])["execution"] == "execution_unknown"


def test_authority_change_prevents_delayed_execution_and_delivery(isolated):
    authorized, runs = [True], []
    async def handler(msg):
        runs.append(msg.text)
        authorized[0] = False
        return "answer"
    async def send(reply):
        pytest.fail("Reply delivered after grant removed")
    channel = Adapter(handler)
    row = isolated.admit(_message(), external_id="event1", account="account1")
    with pytest.raises(PermissionError):
        asyncio.run(channel.process_message(_message(), external_id="event1", account="account1",
                    authorize=lambda: authorized[0], send=send, journal=isolated, receipt=row))
    assert runs == ["Question"]
    assert isolated.get(row["id"])["reply"]["text"] == "answer"


def test_chunk_recovery_preserves_confirmed_prefix_and_provider_ids(isolated):
    calls = []
    async def handler(msg):
        return "answer"
    async def send(reply):
        for index in range(2):
            async def call(index=index):
                calls.append(index)
                if calls == [0, 1]:
                    raise delivery.DeliveryNotSent("second chunk refused")
                return f"provider-{index}"
            await delivery.send_chunk(str(index), f"part{index}", call)
    async def run():
        args = dict(external_id="event1", account="account1", authorize=lambda: True, send=send, journal=isolated)
        row = await Adapter(handler).process_message(_message(), **args)
        assert row["delivery"] == "retryable"
        row = await Adapter(handler).process_message(_message(), **args)
        assert row["chunks"]["0"]["provider_id"] == "provider-0"
        assert row["delivery"] == "delivered"
    asyncio.run(run())
    assert calls == [0, 1, 1]


def test_refused_reply_source_leaves_the_chunk_retryable_and_never_calls_the_provider(isolated, monkeypatch):
    calls, allowed = [], [False]

    def require_source(row):
        if not allowed[0]:
            raise PermissionError("Current task ownership and source access are required for this reply")
    monkeypatch.setattr(delivery, "_require_reply_source", require_source)

    async def handler(msg):
        return "answer"

    async def send(reply):
        calls.append(reply.text)
        return "provider-1"

    async def run():
        args = dict(external_id="event1", account="account1", authorize=lambda: True, send=send, journal=isolated)
        first = await Adapter(handler).process_message(_message(), **args)
        assert first["delivery"] == "retryable" and first["chunks"]["reply"]["state"] == "retryable"
        assert calls == []  # the provider was never reached
        allowed[0] = True  # the ownership check passes again: the reply goes out
        second = await Adapter(handler).process_message(_message(), **args)
        assert second["delivery"] == "delivered"
    asyncio.run(run())
    assert calls == ["answer"]


def test_account_and_payload_binding_and_capacity_do_not_evict_unknowns(isolated, monkeypatch):
    monkeypatch.setattr(delivery, "MAX_RECORDS", 2)
    first = isolated.admit(_message(), external_id="event1", account="account1")
    second = isolated.admit(_message(), external_id="event1", account="account2")
    assert first["id"] != second["id"]
    with pytest.raises(ValueError, match="different content"):
        isolated.admit(_message("replacement"), external_id="event1", account="account1")
    from maverick.governed_records import GovernedRecordCapacityError
    with pytest.raises(GovernedRecordCapacityError):
        isolated.admit(_message(), external_id="event2", account="account1")
    assert len(isolated.store.list(limit=3)) == 2
    assert isolated.compact_delivered() == 0


def test_attachment_bytes_survive_restart_and_corruption_blocks_execution(isolated):
    msg = _message()
    msg.attachments = [{"filename": "source.txt", "mime": "text/plain", "data": b"source bytes"}]
    row = isolated.admit(msg, external_id="event1", account="account1")
    replay = delivery._materialize(delivery.DeliveryJournal().get(row["id"]))
    assert replay.attachments == msg.attachments
    sha = row["message"]["attachments"][0]["sha256"]
    delivery._blob_path(row["id"], sha).write_bytes(b"changed")
    from maverick.attachments import AttachmentRejected
    with pytest.raises(AttachmentRejected):
        delivery._materialize(row)


def test_attachment_blobs_are_sealed_at_rest_when_encryption_is_on(isolated, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    msg = _message()
    msg.attachments = [{"filename": "payroll.csv", "mime": "text/plain", "data": b"salary,9000"}]
    row = isolated.admit(msg, external_id="event1", account="account1")
    path = delivery._blob_path(row["id"], row["message"]["attachments"][0]["sha256"])
    assert b"salary" not in path.read_bytes()
    assert delivery._materialize(delivery.DeliveryJournal().get(row["id"])).attachments == msg.attachments


@pytest.mark.skipif(os.name != "nt", reason="native Windows extended-path inspection")
def test_attachment_recovery_beyond_windows_max_path_preserves_digest_checks(isolated, monkeypatch):
    from maverick import paths
    from maverick.attachments import AttachmentRejected

    original = paths.data_dir

    def nested_blob_root(*parts):
        if parts[:2] == ("channels", "intake-blobs"):
            return original(*parts[:2], "deep-private-root-" * 8, *parts[2:])
        return original(*parts)

    monkeypatch.setattr(paths, "data_dir", nested_blob_root)
    message = _message()
    message.attachments = [{"filename": "source.txt", "mime": "text/plain", "data": b"retained bytes"}]
    row = isolated.admit(message, external_id="event1", account="account1")
    sha = row["message"]["attachments"][0]["sha256"]
    path = delivery._blob_path(row["id"], sha)
    assert len(str(path)) > 260
    try:
        assert delivery._materialize(delivery.DeliveryJournal().get(row["id"])).attachments == message.attachments
        path.write_bytes(b"different bytes")
        with pytest.raises(AttachmentRejected):
            delivery._materialize(row)
    finally:
        # Use the same extended path for this owned test artifact's cleanup.
        path.unlink(missing_ok=True)
        path.parent.rmdir()
        path.parent.parent.rmdir()


def test_revision_fence_rejects_stale_completion(isolated):
    row = isolated.admit(_message(), external_id="event1", account="account1")
    isolated.claim_execution(row)
    with pytest.raises(RecordConflict):
        isolated.change(row, execution="completed")


def test_send_receipt_commit_failure_retains_unknown_and_never_resends(isolated, monkeypatch):
    calls, runs = [], []
    change = isolated.change
    failed = []
    def fail_confirmation(row, **updates):
        if (not failed and updates.get("chunks", {}).get("reply", {}).get("state") == "delivered"):
            failed.append(True)
            raise OSError("receipt write lost after send")
        return change(row, **updates)
    monkeypatch.setattr(isolated, "change", fail_confirmation)
    async def handler(msg):
        runs.append(msg.text)
        return "answer"
    async def send(reply):
        calls.append(reply.text)
        return "accepted-provider-id"
    async def run():
        for _ in range(2):
            row = await Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                        authorize=lambda: True, send=send, journal=isolated)
            assert row["delivery"] == "delivery_unknown"
        assert row["chunks"]["reply"]["state"] == "sending"
    asyncio.run(run())
    assert calls == ["answer"] and runs == ["Question"]


def test_each_chunk_rechecks_authority_and_resumption_preserves_confirmed_prefix(isolated):
    allowed, calls = [True], []
    async def handler(msg):
        return "answer"
    async def send(reply):
        for index in range(2):
            async def call(index=index):
                calls.append(index)
                allowed[0] = False
            await delivery.send_chunk(str(index), str(index), call)
    row = asyncio.run(Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                     authorize=lambda: allowed[0], send=send, journal=isolated))
    assert calls == [0] and row["delivery"] == "delivery_unknown"
    assert row["chunks"]["0"]["state"] == "delivered"


def test_pre_ack_receipt_cannot_be_used_under_another_account(isolated):
    receipt = isolated.admit(_message(), external_id="event1", account="account1")
    async def handler(msg):
        pytest.fail("Cross-account receipt executed")
    with pytest.raises(PermissionError):
        asyncio.run(Adapter(handler).process_message(_message(), external_id="event1", account="account2",
                    authorize=lambda: True, send=lambda reply: None, receipt=receipt, journal=isolated))


def test_preparation_persists_attachments_before_handler_and_keeps_routing_identity(isolated):
    async def prepare(msg):
        msg.attachments = [{"filename": "download.txt", "mime": "text/plain", "data": b"downloaded"}]
        return msg
    async def handler(msg):
        assert msg.attachments[0]["data"] == b"downloaded"
        row = isolated.store.list(limit=1)[0]
        assert row["message"]["attachments"][0]["sha256"]
        return "answer"
    async def send(reply):
        return None
    row = asyncio.run(Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                    authorize=lambda: True, send=send, prepare=prepare, journal=isolated))
    assert row["delivery"] == "delivered"


def test_a_receipt_saved_by_an_earlier_build_still_runs_after_preparation(isolated):
    # Receipts saved before question_reply_only existed lack the key. Rebuilt
    # for preparation the message has its default (False); compared with the
    # missing key (None) it looked changed, so the message never ran.
    receipt = isolated.admit(_message(), external_id="event1", account="account1")
    older = {key: value for key, value in receipt["message"].items() if key != "question_reply_only"}
    receipt = isolated.change(receipt, message=older)
    ran = []
    async def prepare(msg):
        return msg
    async def handler(msg):
        ran.append(msg.text)
        return "answer"
    async def send(reply):
        return None
    row = asyncio.run(Adapter(handler).process_message(_message(), external_id="event1", account="account1",
                      authorize=lambda: True, send=send, prepare=prepare, receipt=receipt, journal=isolated))
    assert ran == ["Question"] and row["delivery"] == "delivered"


def test_retention_clears_only_confirmed_terminal_payloads_and_preserves_claim(isolated, monkeypatch):
    first = isolated.admit(_message(), external_id="event1", account="account1")
    first = isolated.change(first, execution="completed", delivery="delivered", reply={"text": "secret reply"})
    second = isolated.admit(_message(), external_id="event2", account="account1")
    second = isolated.change(second, execution="execution_unknown", delivery="delivered", reply={"text": "generic error"})
    class FutureClock:
        @staticmethod
        def time():
            return max(first["updated_at"], second["updated_at"]) + delivery.RETENTION_SECONDS + 1
    monkeypatch.setattr(delivery, "time", FutureClock)
    assert isolated.compact_delivered() == 1
    assert isolated.get(first["id"])["message"] == {}
    assert isolated.get(first["id"])["compacted"]
    assert isolated.get(second["id"])["message"]["text"] == "Question"
    assert isolated.admit(_message(), external_id="event1", account="account1")["compacted"]


def test_retention_visits_all_rows_across_restart_and_keeps_tombstones(isolated, monkeypatch):
    from types import SimpleNamespace

    eligible = []
    for index in range(3):
        row = isolated.admit(_message(), external_id=f"old-{index}", account="account1")
        eligible.append(isolated.change(row, execution="completed", delivery="delivered", reply={"text": "private"}))
    held = isolated.admit(_message(), external_id="held", account="account1")
    held = isolated.change(held, execution="execution_unknown")
    recent = isolated.admit(_message(), external_id="recent", account="account1")
    future = max(row["updated_at"] for row in eligible) + delivery.RETENTION_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: future))
    assert sum(delivery.DeliveryJournal().compact_delivered(limit=2) for _ in range(8)) == 3
    assert all(isolated.get(row["id"])["message"] == {} for row in eligible)
    assert isolated.get(held["id"])["message"]["text"] == "Question"
    assert isolated.get(recent["id"])["execution"] == "received"
    assert isolated.store.count() == 5


def _delivered_with_blobs(journal, monkeypatch):
    from types import SimpleNamespace

    message = _message()
    message.attachments = [{"filename": f"source-{index}.txt", "mime": "text/plain",
                            "data": f"retained {index}".encode()} for index in range(3)]
    row = journal.admit(message, external_id="event1", account="account1")
    row = journal.change(row, execution="completed", delivery="delivered", reply={"text": "answer"})
    paths = [delivery._blob_path(row["id"], item["sha256"]) for item in row["message"]["attachments"]]
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: row["updated_at"] + delivery.RETENTION_SECONDS + 1))
    return message, row, paths


@pytest.mark.parametrize("failure_index", [0, 1, 2])
def test_retention_resumes_partial_deletion_after_restart_without_replay(isolated, monkeypatch, failure_index):
    from pathlib import Path
    from types import SimpleNamespace

    message, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    unlink = Path.unlink

    def interrupted(path, *args, **kwargs):
        if path == paths[failure_index]:
            raise PermissionError("attachment temporarily locked")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", interrupted)
        with pytest.raises(PermissionError, match="temporarily locked"):
            isolated.compact_delivered()
    pending = delivery.DeliveryJournal().get(row["id"])
    assert pending["cleanup_pending"] == [path.name for path in paths]
    assert pending["message"] == {} and not pending["compacted"]
    assert [path.exists() for path in paths] == [index >= failure_index for index in range(3)]
    # The intent's fresh timestamp must not postpone cleanup another 30 days.
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: pending["updated_at"]))
    reopened = delivery.DeliveryJournal()
    assert reopened.compact_delivered() == 1
    assert all(not path.exists() for path in paths)
    completed = reopened.get(row["id"])
    assert completed["compacted"] and completed["cleanup_pending"] == []
    assert completed["execution"] == "completed" and completed["delivery"] == "delivered"
    assert reopened.admit(message, external_id="event1", account="account1")["compacted"]
    assert reopened.claim_execution(completed) is None
    assert sum(reopened.compact_delivered() for _ in range(3)) == 0


def test_retention_recovers_when_final_completion_write_fails(isolated, monkeypatch):
    _, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    change = isolated.change

    def interrupted(receipt, **updates):
        if updates.get("compacted"):
            raise OSError("receipt publication interrupted")
        return change(receipt, **updates)

    monkeypatch.setattr(isolated, "change", interrupted)
    with pytest.raises(OSError, match="publication interrupted"):
        isolated.compact_delivered()
    assert all(not path.exists() for path in paths)
    assert isolated.get(row["id"])["cleanup_pending"] == [path.name for path in paths]
    assert delivery.DeliveryJournal().compact_delivered() == 1
    assert isolated.get(row["id"])["compacted"]


def test_retention_stale_intent_never_deletes_files(isolated, monkeypatch):
    _, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    change = isolated.change

    def competing_hold(receipt, **updates):
        change(receipt, restore_hold=True)
        return change(receipt, **updates)

    monkeypatch.setattr(isolated, "change", competing_hold)
    assert isolated.compact_delivered() == 0
    assert all(path.exists() for path in paths)
    held = isolated.get(row["id"])
    assert held["restore_hold"] and "cleanup_pending" not in held
    assert held["message"]["attachments"]


def test_concurrent_retention_completion_is_idempotent(isolated, monkeypatch):
    _, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    change = isolated.change
    other_counts = []

    def competing_completion(receipt, **updates):
        if updates.get("compacted"):
            other_counts.append(delivery.DeliveryJournal().compact_delivered())
        return change(receipt, **updates)

    monkeypatch.setattr(isolated, "change", competing_completion)
    assert isolated.compact_delivered() == 0
    assert other_counts == [1]
    assert all(not path.exists() for path in paths)
    assert isolated.get(row["id"])["compacted"]


def test_retention_preserves_pending_files_under_restore_hold(isolated, monkeypatch):
    _, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    isolated.change(row, message={}, cleanup_pending=[path.name for path in paths], compacted=False, restore_hold=True)
    assert delivery.DeliveryJournal().compact_delivered() == 0
    assert all(path.exists() for path in paths)


def test_retention_recovers_legacy_compacted_orphans(isolated, monkeypatch):
    message, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    isolated.change(row, message={}, reply=None, route={}, chunks={}, compacted=True)
    assert delivery.DeliveryJournal().compact_delivered() == 1
    assert all(not path.exists() for path in paths)
    assert isolated.get(row["id"])["cleanup_pending"] == []
    assert isolated.admit(message, external_id="event1", account="account1")["compacted"]


@pytest.mark.parametrize("invalid_entry", ["unknown-name", "directory", "over-capacity"])
def test_legacy_retention_refuses_invalid_or_unbounded_directory(isolated, monkeypatch, invalid_entry):
    _, row, paths = _delivered_with_blobs(isolated, monkeypatch)
    isolated.change(row, message={}, compacted=True)
    directory = paths[0].parent
    if invalid_entry == "unknown-name":
        (directory / "unrelated.txt").write_text("keep", encoding="utf-8")
    elif invalid_entry == "directory":
        (directory / ("a" * 64)).mkdir()
    else:
        # A receipt may own inbound and reply attachments (2 x the per-message
        # cap); one more entry than that is unbounded.
        for index in range(2 * delivery.MAX_ATTACHMENTS):
            (directory / f"{index:064x}").write_bytes(b"keep")
    with pytest.raises(ValueError, match="Invalid channel attachment"):
        delivery.DeliveryJournal().compact_delivered()
    assert all(path.exists() for path in paths)
    assert "cleanup_pending" not in isolated.get(row["id"])


def test_failed_cleanup_does_not_starve_later_receipts(isolated, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace

    _, first, paths = _delivered_with_blobs(isolated, monkeypatch)
    second = isolated.admit(_message(), external_id="event2", account="account1")
    second = isolated.change(second, execution="completed", delivery="delivered")
    monkeypatch.setattr(delivery, "time", SimpleNamespace(
        time=lambda: second["updated_at"] + delivery.RETENTION_SECONDS + 1))
    # Start directly before the attachment-bearing receipt in the real scan.
    from maverick.governed_records import GovernedRecordStore
    ordered = list(isolated.store.iter_record_ids(limit=10))
    index = next(i for i, (_, record_id) in enumerate(ordered) if record_id == first["id"])
    before = ordered[(index - 1) % len(ordered)][0]
    cursors = GovernedRecordStore("channel-delivery-cursors", "chc", "channel_delivery_cursor")
    cursors.create({"id": "chc-" + delivery._digest(["maintenance", "retention", 1])[:56],
                    "cursor": before, "purpose": "retention"},
                   action="retention_cursor_created", actor="system:channel", max_records=1000)
    unlink = Path.unlink

    def locked(path, *args, **kwargs):
        if path in paths:
            raise PermissionError("locked")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", locked)
        with pytest.raises(PermissionError, match="locked"):
            isolated.compact_delivered(limit=1)
        assert delivery.DeliveryJournal().compact_delivered(limit=1) == 1
        assert isolated.get(second["id"])["compacted"]
        with pytest.raises(PermissionError, match="locked"):
            delivery.DeliveryJournal().compact_delivered(limit=1)
    assert delivery.DeliveryJournal().compact_delivered() == 1
    assert all(not path.exists() for path in paths)


def test_recovered_telegram_download_retries_before_execution_claim(isolated):
    from types import SimpleNamespace

    from maverick_channels.telegram import TelegramChannel

    attempts, handled, sent = [], [], []
    message = IncomingMessage(user_id="7", sender_id="7", text="Read report", channel="telegram", message_id="5")
    route = {"files": [{"file_id": "report", "filename": "report.txt", "mime": "text/plain", "size": 6}]}
    receipt = isolated.admit(message, external_id="5", account="account", route=route)

    async def download():
        return bytearray(b"report")

    async def get_file(file_id):
        attempts.append(file_id)
        if len(attempts) == 1:
            raise TimeoutError("temporary download interruption")
        return SimpleNamespace(download_as_bytearray=download)

    async def handler(incoming):
        handled.append(incoming.attachments)
        return "done"

    async def send(incoming, reply, route):
        sent.append(reply.text)
        return "receipt"

    async def run():
        adapter = TelegramChannel.__new__(TelegramChannel)
        adapter.handler = handler
        adapter._app = SimpleNamespace(bot=SimpleNamespace(get_file=get_file))
        kwargs = dict(account="account", authorize=lambda _: True, send=send,
                      prepare=adapter._prepare_saved, journal=delivery.DeliveryJournal())
        (outcome,) = await delivery.recover_messages(adapter, **kwargs)
        assert isinstance(outcome, TimeoutError)  # deferred, not raised: the window still advances
        row = isolated.get(receipt["id"])
        assert row["execution"] == "received" and row["delivery"] == "not_ready"
        assert handled == [] and sent == []
        await delivery.recover_messages(adapter, **kwargs)
        await delivery.recover_messages(adapter, **kwargs)

    asyncio.run(run())
    assert len(attempts) == 2 and len(handled) == 1 and sent == ["done"]
    assert handled[0] == [{"filename": "report.txt", "mime": "text/plain", "data": b"report"}]


def test_one_failing_row_does_not_starve_the_rest_of_the_window(isolated):
    """Regression: an exception on one recovered row skipped
    finish_recovery_window, so every later row in the window starved."""
    first = IncomingMessage(user_id="1", sender_id="1", text="broken", channel="telegram", message_id="1")
    second = IncomingMessage(user_id="2", sender_id="2", text="fine", channel="telegram", message_id="2")
    isolated.admit(first, external_id="1", account="acct", route={})
    isolated.admit(second, external_id="2", account="acct", route={})
    handled, sent = [], []

    async def handler(incoming):
        handled.append(incoming.text)
        return "ok"

    async def prepare(message, route):
        if message.text == "broken":
            raise RuntimeError("blob missing")
        return message

    async def send(incoming, reply, route):
        sent.append(incoming.text)
        return "receipt"

    class _Adapter:
        name = "telegram"

    adapter = _Adapter()
    adapter.handler = handler
    outcomes = asyncio.run(delivery.recover_messages(
        adapter, account="acct", authorize=lambda _m: True, send=send, prepare=prepare,
        journal=delivery.DeliveryJournal()))
    assert any(isinstance(o, RuntimeError) for o in outcomes)
    assert handled == ["fine"] and sent == ["fine"]


class _RotatingIds:
    """A store scan that wraps like the real backends, two ids per page; the
    first id is deleted after the first page (compaction during the scan)."""

    def __init__(self, ids):
        self.ids, self.calls = sorted(ids), 0

    def iter_record_ids(self, *, start_after="", limit=100):
        self.calls += 1
        if self.calls == 2:
            self.ids.pop(0)
        later = [i for i in self.ids if i > start_after]
        ordered = later + [i for i in self.ids if i <= start_after]
        return [(i, i) for i in ordered[:min(limit, 2)]]


def test_capacity_count_stops_at_the_wrap_even_when_the_first_record_is_gone(isolated, monkeypatch):
    # Wrap was detected only by meeting the first record again; compaction
    # removing it mid-scan made the count run past the limit and report full.
    monkeypatch.setattr(isolated, "store", _RotatingIds(["a", "b", "c", "d", "e"]))
    status = isolated.capacity_status()
    assert status["used"] == 5 and status["count_exact"] is True and status["full"] is False


def test_a_phone_call_answer_is_cleared_like_a_delivered_message(isolated, monkeypatch):
    # A voice answer goes back in the call's own HTTP response, so its receipt
    # always ends "delivery unknown" and nothing can resolve it. Kept forever,
    # these receipts filled the intake every chat app shares.
    from types import SimpleNamespace

    call = IncomingMessage(user_id="+15550100", text="What is due today?", channel="voice", message_id="7:call-1:1")
    row = isolated.admit(call, external_id="7:call-1:1", account="voice-account",
                         route={"response_transport": "http", "function": "lightwork_request"})
    row = isolated.change(row, execution="completed", delivery="delivery_unknown", reply={"text": "Two invoices."})
    chat = isolated.admit(_message(), external_id="chat-1", account="account1")
    chat = isolated.change(chat, execution="completed", delivery="delivery_unknown", reply={"text": "kept"})
    later = max(row["updated_at"], chat["updated_at"]) + delivery.RETENTION_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: later))
    assert isolated.compact_delivered() == 1
    assert isolated.get(row["id"])["compacted"] and isolated.get(row["id"])["message"] == {}
    assert isolated.get(chat["id"])["reply"] == {"text": "kept"}  # a chat app's unknown send stays for review
    much_later = isolated.get(row["id"])["updated_at"] + delivery.TOMBSTONE_SECONDS + 1
    monkeypatch.setattr(delivery, "time", SimpleNamespace(time=lambda: much_later))
    assert isolated.compact_delivered(release_only=True) == 1
    assert isolated.get(row["id"]) is None


def test_a_message_saved_by_the_build_before_the_new_fields_is_still_the_same_message(isolated):
    # Four fields were added to the saved message, which changed every
    # message's identity hash. A polling channel (Mastodon, Bluesky, iMessage)
    # re-reading a message the earlier build saved was refused as different
    # content and retried it forever, so intake stopped.
    row = isolated.admit(_message(), external_id="event1", account="account1", route={"reply_to": "1"})
    new_fields = ("provider_tenant_id", "provider_sender_id", "conversation_ref", "question_reply_only")
    earlier = {key: value for key, value in row["message"].items() if key not in new_fields}
    row = isolated.change(row, message=earlier, fingerprint=delivery._digest([earlier, {"reply_to": "1"}]))
    again = isolated.admit(_message(), external_id="event1", account="account1", route={"reply_to": "1"})
    assert again["id"] == row["id"]
    with pytest.raises(ValueError, match="different content"):
        isolated.admit(_message("Something else"), external_id="event1", account="account1",
                       route={"reply_to": "1"})
