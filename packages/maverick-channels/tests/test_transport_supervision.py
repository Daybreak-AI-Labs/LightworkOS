"""Owned local transport streams, actual journal, no external provider calls."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from maverick_channels import transport_worker
from maverick_channels.base import Channel, IncomingMessage
from maverick_channels.delivery import (
    DeliveryJournal,
    DeliveryNotSent,
    DeliveryUnknown,
    delivery_active,
    send_chunk,
)
from maverick_channels.irc import IRCChannel, format_privmsg
from maverick_channels.signal import SignalChannel
from maverick_channels.transport_worker import TransportWorker


async def until(predicate, *, on_timeout=None):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.005)
    try:
        await asyncio.wait_for(wait(), timeout=5)
    except asyncio.TimeoutError:
        if on_timeout is not None:
            try:
                on_timeout()
            except Exception:
                pass  # Diagnostics must not replace the original timeout.
        raise


def transport_timeout_snapshot(worker, handler_started_count):
    """Report owned queue state and stack locations without message contents."""
    def frame_location(frame):
        return {"file": Path(frame.f_code.co_filename).name,
                "function": frame.f_code.co_name, "line": frame.f_lineno}

    def task_location(task):
        if task is None:
            return None
        locations, seen = [], set()
        awaiting = task.get_coro()
        while awaiting is not None and id(awaiting) not in seen:
            seen.add(id(awaiting))
            frame = getattr(awaiting, "cr_frame", None) or getattr(awaiting, "gi_frame", None)
            if frame is not None:
                locations.append(frame_location(frame))
            awaiting = getattr(awaiting, "cr_await", None) or getattr(awaiting, "gi_yieldfrom", None)
        return {"done": task.done(), "cancelled": task.cancelled(), "stack": locations}

    threads = []
    for current in sys._current_frames().values():
        locations = []
        while current is not None:
            locations.append(frame_location(current))
            current = current.f_back
        threads.append(locations)
    print("TRANSPORT_TIMEOUT " + json.dumps({
        "handler_started_count": handler_started_count,
        "pending_count": len(worker.pending), "overflow": worker._overflow,
        "wake": worker._wake.is_set(), "generation": worker._generation,
        "closing": worker._closing,
        "worker": task_location(worker.task), "scan": task_location(worker._scan_task),
        "threads": threads,
    }, sort_keys=True))


class Adapter(Channel):
    name = "supervision-fixture"
    async def start(self):
        pass
    async def stop(self):
        pass
    async def send(self, user_id, text):
        pass


def test_recovery_scan_keeps_oldest_order_across_short_store_pages():
    class ShortPages:
        ids = ("a", "b", "c")

        def iter_record_ids(self, *, start_after="", limit=100):
            pivot = next((i for i, key in enumerate(self.ids) if key > start_after), len(self.ids))
            for key in (self.ids[pivot:] + self.ids[:pivot])[:2]:
                yield key, key

    class Journal:
        store = ShortPages()

        def get(self, record_id):
            return {"id": record_id, "channel": Adapter.name,
                    "account_sha256": transport_worker._digest("account"),
                    "execution": "received", "delivery": "not_ready",
                    "created_at": {"a": 3, "b": 1, "c": 2}[record_id]}

    worker = TransportWorker(Adapter(AsyncMock()), account="account",
                             authorize=lambda msg: True, send=AsyncMock(), journal=Journal())
    assert worker._oldest_window() == (["b", "c", "a"], False)


def test_bounded_queue_overflow_is_durable_serial_and_in_intake_order(monkeypatch):
    monkeypatch.setattr(transport_worker, "MAX_PENDING", 2)
    async def run():
        release, started, order = asyncio.Event(), asyncio.Event(), []
        active, peak = 0, 0
        async def handler(message):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            order.append(message.text)
            started.set()
            await release.wait()
            active -= 1
            return "answer"
        async def send(*args):
            return "confirmed-fixture"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True, send=send).start()
        for index in range(8):
            await worker.submit(IncomingMessage(user_id="person", sender_id="person", text=str(index),
                                channel=Adapter.name, message_id=str(index)), external_id=str(index))
            if index == 0:
                await started.wait()
            assert len(worker.pending) <= 2
        assert worker.overflow_count and DeliveryJournal().store.count() == 8
        release.set()
        await until(lambda: len(order) == 8,
                    on_timeout=lambda: transport_timeout_snapshot(worker, len(order)))
        await worker.close()
        assert worker.task.done() and peak == 1 and order == [str(index) for index in range(8)]
    asyncio.run(run())


@pytest.mark.parametrize("diagnostic_failure", [False, True])
def test_transport_timeout_diagnostic_preserves_failure_without_message_content(monkeypatch, capsys, diagnostic_failure):
    failure = asyncio.TimeoutError("fixture deadline")

    async def timed_out(awaitable, *, timeout):
        assert timeout == 5
        awaitable.close()
        raise failure

    monkeypatch.setattr(asyncio, "wait_for", timed_out)

    async def run():
        private_text = "private-fixture-message-must-not-appear"
        worker = TransportWorker(Adapter(AsyncMock()), account=private_text,
                                 authorize=lambda msg: True, send=AsyncMock())
        worker.pending.append(private_text)
        worker.task = asyncio.current_task()

        def diagnose():
            if diagnostic_failure:
                raise RuntimeError(private_text)
            transport_timeout_snapshot(worker, 0)

        with pytest.raises(asyncio.TimeoutError) as raised:
            await until(lambda: False, on_timeout=diagnose)
        assert raised.value is failure
        output = capsys.readouterr().out
        assert private_text not in output
        if not diagnostic_failure:
            diagnostic = json.loads(output.removeprefix("TRANSPORT_TIMEOUT "))
            assert diagnostic["handler_started_count"] == 0 and diagnostic["pending_count"] == 1
            assert diagnostic["worker"]["stack"] and diagnostic["threads"]
        assert worker.pending[0] == private_text and not worker._closing

    asyncio.run(run())


class Writer:
    def __init__(self, callback=None):
        self.writes, self.callback, self.closed = [], callback, False
    def write(self, data):
        self.writes.append(data)
        if self.callback:
            self.callback(data)
    async def drain(self):
        pass
    def close(self):
        self.closed = True
    async def wait_closed(self):
        pass


class Process:
    pid = 314
    def __init__(self):
        self.returncode = None
        self.stdout, self.stderr = asyncio.StreamReader(), asyncio.StreamReader()
        self.stdin = Writer(self.rpc)
        self.terminated = self.killed = False
    def rpc(self, line):
        data = json.loads(line)
        result = {"id": data["id"], "jsonrpc": "2.0"}
        if data.get("params", {}).get("message") == "rpc-error":
            result["error"] = {"code": -32602, "message": "private provider error"}
        else:
            result["result"] = {"timestamp": 777}
        self.stdout.feed_data((json.dumps(result) + "\n").encode())
    def terminate(self):
        self.terminated = True
        self.returncode = 0
        self.stdout.feed_eof()
        self.stderr.feed_eof()
    def kill(self):
        self.killed = True
        self.terminate()
    async def wait(self):
        await until(lambda: self.returncode is not None)
        return self.returncode


def receive(index=1):
    return (json.dumps({"method": "receive", "params": {"envelope": {"source": "+owner",
            "dataMessage": {"message": str(index), "timestamp": index}}}}) + "\n").encode()


def test_signal_blocked_agent_does_not_block_rpc_stderr_or_owned_shutdown(monkeypatch):
    monkeypatch.setattr(transport_worker, "SHUTDOWN_TIMEOUT", 0.05)
    async def run():
        started = asyncio.Event()
        async def handler(message):
            started.set()
            await asyncio.Event().wait()
        proc = Process()
        monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
        channel = SignalChannel(handler, "+self", signal_cli_path="local-fixture", allowed_user_ids={"+owner"})
        running = asyncio.create_task(channel.start())
        await until(lambda: channel._worker is not None)
        proc.stdout.feed_data(receive())
        await asyncio.wait_for(started.wait(), timeout=5)
        proc.stderr.feed_data(b"fixture-sensitive-stderr\n" * 10000)
        assert await asyncio.wait_for(channel._send_rpc("send", {"message": "probe"}), timeout=1) == {"timestamp": 777}
        with pytest.raises(DeliveryNotSent, match="rejected"):
            await channel._send_rpc("send", {"message": "rpc-error"})
        await until(lambda: channel._stderr_bytes == 250000)
        await channel.stop()
        await asyncio.wait_for(running, timeout=1)
        assert proc.terminated and channel._reader_task.done() and channel._stderr_task.done() and channel._worker.task.done()
        assert not channel._pending_rpc
        row = DeliveryJournal().store.list(limit=1)[0]
        # Cancelled mid-handler at shutdown: recorded as unknown (never re-run)
        # with a reply for the sender, not left "started" with no outcome.
        assert row["execution"] == "execution_unknown" and row["delivery"] == "ready"
    asyncio.run(run())


def test_signal_duplicate_provider_event_executes_once_and_waits_for_send_ack(monkeypatch):
    async def run():
        proc, handler = Process(), AsyncMock(return_value="answer")
        monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
        channel = SignalChannel(handler, "+self", signal_cli_path="local-fixture", allowed_user_ids={"+owner"})
        running = asyncio.create_task(channel.start())
        await until(lambda: channel._worker is not None)
        proc.stdout.feed_data(receive() + receive())
        await until(lambda: bool(proc.stdin.writes))
        await until(lambda: DeliveryJournal().store.list(limit=1)[0]["delivery"] == "delivered")
        await channel.stop()
        await running
        handler.assert_awaited_once()
        assert len(proc.stdin.writes) == 1
        row = DeliveryJournal().store.list(limit=1)[0]
        assert row["chunks"]["signal-0"]["provider_id"] == "777"
    asyncio.run(run())


def test_irc_ping_remains_responsive_during_agent_and_stop_owns_reader(monkeypatch):
    monkeypatch.setattr(transport_worker, "SHUTDOWN_TIMEOUT", 0.05)
    async def run():
        reader, writer, started = asyncio.StreamReader(), Writer(), asyncio.Event()
        monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
        async def handler(message):
            started.set()
            await asyncio.Event().wait()
        channel = IRCChannel(handler, "fixture.invalid", nick="bot", channels=["#room"], allowed_user_ids={"owner"})
        running = asyncio.create_task(channel.start())
        await until(lambda: channel._reader_task is not None)
        reader.feed_data(b"@account=owner;msgid=event1 :nick!u@h PRIVMSG #room :question\r\n")
        await asyncio.wait_for(started.wait(), timeout=5)
        reader.feed_data(b"PING :still-responsive\r\n")
        await until(lambda: b"PONG :still-responsive\r\n" in writer.writes)
        await channel.stop()
        await running
        assert writer.closed and channel._worker.task.done() and channel._reader_task.done()
    asyncio.run(run())


@pytest.mark.parametrize("current_account", ["owner", "different-person"])
def test_irc_saved_direct_reply_rechecks_whois_and_never_claims_remote_delivery(monkeypatch, current_account):
    async def run():
        reader = asyncio.StreamReader()
        def reply(data):
            if data.startswith(b"WHOIS nick"):
                reader.feed_data(f":server 330 bot nick {current_account} :account\r\n:server 318 bot nick :end\r\n".encode())
        writer = Writer(reply)
        monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
        channel = IRCChannel(AsyncMock(return_value="answer"), "fixture.invalid", nick="bot", allowed_user_ids={"owner"})
        running = asyncio.create_task(channel.start())
        await until(lambda: channel._reader_task is not None)
        reader.feed_data(b"@account=owner;msgid=event1 :nick!u@h PRIVMSG bot :question\r\n")
        expected = "delivery_unknown" if current_account == "owner" else "retryable"
        await until(lambda: bool(DeliveryJournal().store.list(limit=1))
                     and DeliveryJournal().store.list(limit=1)[0]["delivery"] == expected)
        await channel.stop()
        await running
        assert any(line.startswith(b"PRIVMSG nick") for line in writer.writes) == (current_account == "owner")
        channel.handler.assert_awaited_once()
    asyncio.run(run())


def test_irc_unicode_chunks_obey_wire_byte_limit_without_losing_text():
    text = "🌅" * 350
    lines = format_privmsg("#room", text)
    assert all(len((line + "\r\n").encode()) <= 512 for line in lines)
    assert "".join(line.split(" :", 1)[1] for line in lines) == text


def test_signal_missing_rpc_ack_is_unknown_and_child_kill_is_awaited(monkeypatch):
    from maverick_channels import signal

    monkeypatch.setattr(signal, "RPC_TIMEOUT_SECONDS", 0.03)
    monkeypatch.setattr(signal, "STOP_TIMEOUT_SECONDS", 0.03)
    async def run():
        proc = Process()
        proc.stdin.callback = None  # The daemon accepts bytes but never replies.
        def ignore_terminate():
            proc.terminated = True
        def kill():
            proc.killed = True
            proc.returncode = -1
            proc.stdout.feed_eof()
            proc.stderr.feed_eof()
        proc.terminate, proc.kill = ignore_terminate, kill
        monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=proc))
        channel = SignalChannel(AsyncMock(return_value="answer"), "+self", signal_cli_path="fixture",
                                 allowed_user_ids={"+owner"})
        running = asyncio.create_task(channel.start())
        await until(lambda: channel._worker is not None)
        proc.stdout.feed_data(receive())
        await until(lambda: bool(DeliveryJournal().store.list(limit=1))
                     and DeliveryJournal().store.list(limit=1)[0]["delivery"] == "delivery_unknown")
        proc.stdout.feed_data(receive())
        await channel.stop()
        await running
        assert proc.killed and proc.returncode == -1 and len(proc.stdin.writes) == 1
        channel.handler.assert_awaited_once()
    asyncio.run(run())


def test_worker_restart_recovers_received_records_in_order_without_reopening_unknown():
    journal = DeliveryJournal()
    for index in range(4):
        row = journal.admit(IncomingMessage(user_id="person", sender_id="person", text=str(index),
                             channel=Adapter.name, message_id=str(index)), external_id=str(index), account="account")
        if index == 0:
            journal.claim_execution(row)  # Crash after execution claim, before saved result.
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed")).start()
        await until(lambda: len(order) == 3)
        await worker.close()
        assert order == ["1", "2", "3"]
    asyncio.run(run())


def test_definite_delivery_retry_preserves_conversation_order(monkeypatch):
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.08)
    async def run():
        order, sends = [], []
        async def handler(message):
            order.append(message.text)
            return message.text
        async def send(message, reply, route):
            sends.append(reply.text)
            if len(sends) == 1:
                raise DeliveryNotSent("definite fixture rejection")
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True, send=send).start()
        for index in range(2):
            await worker.submit(IncomingMessage(user_id="person", sender_id="person", text=str(index),
                                channel=Adapter.name, message_id=str(index)), external_id=str(index))
        await until(lambda: len(sends) == 3)
        await worker.close()
        assert order == ["0", "1"] and sends == ["0", "0", "1"]
    asyncio.run(run())


def test_a_reply_the_source_check_holds_back_does_not_block_the_next_message(monkeypatch):
    # A reply whose task or sources the person can no longer use is refused
    # before sending and stays retryable (the check may pass again). It must
    # not block the conversation, or none of the person's later messages run.
    from maverick_channels import delivery

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    def source_check(row):
        if row["message"]["text"] == "0":
            raise PermissionError("The saved reply's task ownership changed")
    monkeypatch.setattr(delivery, "_require_reply_source", source_check)
    async def run():
        order, sends = [], []
        async def handler(message):
            order.append(message.text)
            return message.text
        async def send(message, reply, route):
            sends.append(reply.text)
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True, send=send).start()
        for index in range(2):
            await worker.submit(IncomingMessage(user_id="person", sender_id="person", text=str(index),
                                channel=Adapter.name, message_id=str(index)), external_id=str(index))
        await until(lambda: sends == ["1"])
        await worker.close()
        assert order == ["0", "1"]
    asyncio.run(run())
    held = [row for row in DeliveryJournal().store.list(limit=5) if row["message"]["text"] == "0"]
    assert held[0]["delivery"] == "retryable" and held[0]["chunks"]["reply"]["withheld"] is True


def test_shutdown_joins_cooperative_read_only_scan(monkeypatch):
    import threading

    monkeypatch.setattr(transport_worker, "SHUTDOWN_TIMEOUT", 0.03)
    entered = threading.Event()
    async def run():
        worker = TransportWorker(Adapter(AsyncMock()), account="account", authorize=lambda msg: True, send=AsyncMock())
        def scan():
            entered.set()
            worker._stop_scan.wait(timeout=1)
            return [], False
        monkeypatch.setattr(worker, "_oldest_window", scan)
        worker.start()
        await until(entered.is_set)
        await worker.close()
        assert worker.task.done() and worker._scan_task.done()
    asyncio.run(run())


def test_the_oldest_window_scan_stops_at_the_wrap_when_the_first_record_is_gone(monkeypatch):
    # Same wrap rule as the capacity count: one pass, no duplicates, even when
    # compaction deletes the first record while the scan is running.
    from types import SimpleNamespace

    from maverick_channels.delivery import _digest

    ids = ["a", "b", "c", "d", "e"]
    rows = {i: {"id": i, "channel": Adapter.name, "account_sha256": _digest("account"),
                "execution": "received", "delivery": "not_ready", "created_at": n} for n, i in enumerate(ids)}
    class Store:
        calls = 0
        def iter_record_ids(self, *, start_after="", limit=100):
            Store.calls += 1
            if Store.calls == 2:
                ids.pop(0)
            later = [i for i in ids if i > start_after]
            ordered = later + [i for i in ids if i <= start_after]
            return [(i, i) for i in ordered[:min(limit, 2)]]
    worker = TransportWorker(Adapter(AsyncMock()), account="account", authorize=lambda msg: True, send=AsyncMock())
    worker.journal = SimpleNamespace(store=Store(), get=lambda record_id: rows.get(record_id))
    selected, more = worker._oldest_window()
    assert selected == ["a", "b", "c", "d", "e"] and more is False


def test_an_idle_worker_does_not_reread_every_receipt_each_retry_period(monkeypatch):
    # Every idle timeout re-read and decrypted every saved receipt, about
    # 20,000 reads every 30 seconds per worker at the default intake size.
    # With nothing waiting on a retry, the worker now stays idle.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    async def run():
        worker = TransportWorker(Adapter(AsyncMock(return_value="answer")), account="account",
                                 authorize=lambda msg: True, send=AsyncMock(return_value="confirmed"))
        scans = []
        original = worker._oldest_window
        def counted():
            scans.append(1)
            return original()
        worker._oldest_window = counted
        worker.start()
        await asyncio.sleep(0.3)
        idle_scans = len(scans)
        await worker.close()
        assert idle_scans == 1  # the start-up recovery scan only
    asyncio.run(run())


def test_a_retry_time_for_a_receipt_no_longer_waiting_is_forgotten(monkeypatch):
    # Otherwise one finished or removed receipt would keep the idle worker
    # rescanning every retry period forever.
    import time as clock

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    async def run():
        worker = TransportWorker(Adapter(AsyncMock(return_value="answer")), account="account",
                                 authorize=lambda msg: True, send=AsyncMock(return_value="confirmed"))
        worker._retry_after["chd-gone"] = clock.monotonic() + 3600
        scans = []
        original = worker._oldest_window
        worker._oldest_window = lambda: scans.append(1) or original()
        worker.start()
        await asyncio.sleep(0.3)
        idle_scans, remembered = len(scans), dict(worker._retry_after)
        await worker.close()
        assert remembered == {} and idle_scans == 1
    asyncio.run(run())


def test_a_recovery_scan_that_failed_is_retried_after_the_retry_period(monkeypatch):
    # A transient store read error in the start-up scan must not leave the
    # worker idle with saved messages it never recovers.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    journal = DeliveryJournal()
    journal.admit(IncomingMessage(user_id="person", sender_id="person", text="saved",
                                  channel=Adapter.name, message_id="1"), external_id="1", account="account")
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"))
        original, scans = worker._oldest_window, []
        def flaky():
            scans.append(1)
            if len(scans) == 1:
                raise OSError("store read failed")
            return original()
        worker._oldest_window = flaky
        worker.start()
        await until(lambda: order == ["saved"])
        await worker.close()
    asyncio.run(run())


def test_one_unreadable_saved_receipt_does_not_stop_recovery_or_new_messages(monkeypatch):
    # A receipt whose sealed form no longer opens made every recovery scan
    # fail, so the worker held every message behind a scan that never ended.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    journal = DeliveryJournal()
    for index in range(2):
        journal.admit(IncomingMessage(user_id="person", sender_id="person", text=f"saved-{index}",
                                      channel=Adapter.name, message_id=str(index)),
                      external_id=str(index), account="account")
    poisoned = next(record_id for _, record_id in journal.store.iter_record_ids(start_after="", limit=10))
    real_get = journal.get

    def get(record_id):
        if record_id == poisoned:
            raise ValueError("sealed receipt does not authenticate")
        return real_get(record_id)

    journal.get = get
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal).start()
        await until(lambda: len(order) == 1)
        await worker.submit(IncomingMessage(user_id="other", sender_id="other", text="new", channel=Adapter.name,
                                            message_id="9"), external_id="9")
        await until(lambda: len(order) == 2)
        await worker.close()
        assert order[1] == "new"
    asyncio.run(run())


def test_a_receipt_that_could_not_be_read_once_is_recovered_by_the_next_scan(monkeypatch):
    # A passing read error (a key briefly unavailable, a dropped connection)
    # must not leave the receipt unscanned until another message arrives.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    journal = DeliveryJournal()
    journal.admit(IncomingMessage(user_id="person", sender_id="person", text="saved",
                                  channel=Adapter.name, message_id="1"), external_id="1", account="account")
    real_get, failures = journal.get, []

    def get(record_id):
        if not failures:
            failures.append(record_id)
            raise OSError("key briefly unavailable")
        return real_get(record_id)

    journal.get = get
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal).start()
        await until(lambda: order == ["saved"])
        await worker.close()
    asyncio.run(run())



def _unreadable_journal(count, failing):
    """A journal with ``count`` saved receipts; ``failing(record_id)`` says
    whether reading that receipt raises right now."""
    journal = DeliveryJournal()
    for index in range(count):
        journal.admit(IncomingMessage(user_id="person", sender_id="person", text=f"saved-{index}",
                                      channel=Adapter.name, message_id=str(index)),
                      external_id=str(index), account="account")
    real_get = journal.get

    def get(record_id):
        if failing(record_id):
            raise ValueError("sealed receipt does not open")
        return real_get(record_id)

    journal.get = get
    return journal


def test_a_receipt_that_never_opens_is_reported_once_and_does_not_hold_new_messages(monkeypatch, caplog):
    # While a receipt stays unreadable the worker keeps scanning (it may open
    # again) and answers new messages; the warning is written when the set of
    # unreadable receipts changes, not every scan.
    import logging

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    poisoned = []
    journal = _unreadable_journal(1, lambda record_id: record_id in poisoned)
    poisoned.append(next(record_id for _, record_id in journal.store.iter_record_ids(start_after="", limit=10)))
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal).start()
        for index in range(3):
            await worker.submit(IncomingMessage(user_id="p", sender_id="p", text=f"new-{index}",
                                                channel=Adapter.name, message_id=f"n{index}"), external_id=f"n{index}")
        await until(lambda: len(order) == 3)
        await asyncio.sleep(0.2)
        await worker.close()
        assert order == ["new-0", "new-1", "new-2"]
    with caplog.at_level(logging.WARNING):
        asyncio.run(run())
    assert sum("could not be read" in record.getMessage() for record in caplog.records) == 1


def test_a_receipt_that_opens_again_is_answered_before_a_newer_message(monkeypatch):
    # The start-up scan could not read X; the key comes back; the person
    # sends Y. X was accepted first, so it is answered first.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 60)
    outage = [True]
    journal = _unreadable_journal(1, lambda record_id: outage[0])
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal).start()
        await asyncio.sleep(0.05)
        outage[0] = False
        await worker.submit(IncomingMessage(user_id="person", sender_id="person", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await until(lambda: len(order) == 2)
        await worker.close()
        assert order == ["saved-0", "Y"]
    asyncio.run(run())


def test_every_receipt_is_recovered_after_a_store_wide_read_outage(monkeypatch):
    # The at-rest key is unavailable over several retry periods, then back:
    # nothing stays skipped.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.02)
    outage = [True]
    journal = _unreadable_journal(3, lambda record_id: outage[0])
    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal).start()
        await asyncio.sleep(0.2)
        assert order == []
        outage[0] = False
        await until(lambda: len(order) == 3)
        await worker.close()
    asyncio.run(run())


def test_a_conversation_waits_behind_a_briefly_unreadable_receipt(monkeypatch):
    # X's send is refused, so the person's next message Y waits behind X. X
    # then cannot be read three times in a row: Y keeps waiting, and goes out
    # after X once X opens again.
    # The worker's clock is the test's, and X's failed reads start only once
    # Y waits behind X. On the real clock the worker rescans every retry
    # period and Y's admission runs in a thread: a runner that stalled it for
    # three periods used up X's failed reads before Y was saved, and one that
    # resumed the test a period late let X's retry come due first. Either way
    # the worker rightly resent X before Y.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)  # real seconds between idle scans
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    state = {"x": None, "fail_left": 0}
    journal = _unreadable_journal(0, lambda record_id: False)
    readable_get = journal.get

    def get(record_id):
        if record_id == state["x"] and state["fail_left"] > 0:
            state["fail_left"] -= 1
            raise OSError("key briefly unavailable")
        return readable_get(record_id)

    journal.get = get
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if len(sends) == 1:
            raise DeliveryNotSent("X's first send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: y["id"] in worker._retry_after)  # Y waits for X's retry
        state["fail_left"] = 3  # before the clock moves, so no scan finds X due and readable
        now[0] += transport_worker.RETRY_DELAY  # X's retry comes due, and Y's with it
        await until(lambda: "Y" in sends and sends.count("X") == 2)
        await worker.close()
        # Only X could not be read, but it still holds its conversation: Y's
        # reply waits for X's (the next test: the whole store cannot be read).
        assert sends == ["X", "X", "Y"] and worker._blocked_conversations == {}
    asyncio.run(run())


def test_a_blocked_conversation_keeps_its_order_through_a_store_wide_read_outage(monkeypatch):
    # X's send is refused and Y waits behind X; then no receipt can be read
    # (the at-rest key is unavailable) when X's retry comes due and for a few
    # retry periods after. Y cannot be read either, so nothing is sent, and
    # once the key is back X is sent before Y.
    # The worker's clock is the test's, so X's retry comes due only inside the
    # outage. On the real clock, a runner that stalled for the retry delay
    # (0.05 s, then 0.5 s) between X's refusal and the outage made the retry
    # due first, and the worker rightly resent X before the outage began.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)  # real seconds between idle scans
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    outage = [False]
    journal = _unreadable_journal(0, lambda record_id: outage[0])
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if len(sends) == 1:
            raise DeliveryNotSent("X's first send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        await until(lambda: bool(worker._blocked_conversations))
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: y["id"] in worker._retry_after)  # Y waits for X's retry
        outage[0] = True
        now[0] += transport_worker.RETRY_DELAY  # X's retry comes due
        await until(lambda: worker._unreadable == {x["id"], y["id"]})  # a scan could not read either
        await asyncio.sleep(0.2)  # a few more retry periods
        assert sends == ["X"]
        outage[0] = False
        await until(lambda: len(sends) == 3)
        await worker.close()
        assert sends == ["X", "X", "Y"]
    asyncio.run(run())


def test_a_redelivered_receipt_a_restore_holds_does_not_hold_the_conversation(monkeypatch):
    # The provider redelivers a message whose receipt a restore holds with a
    # refused reply: it reaches the worker through submit, is not run, and
    # the person's next message is answered without waiting a retry period.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 60)
    journal = _unreadable_journal(1, lambda record_id: False)
    held = next(record_id for _, record_id in journal.store.iter_record_ids(start_after="", limit=10))
    journal.change(journal.get(held), restore_hold=True, delivery="retryable")

    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal)
        handled = []
        real_process = worker._process

        async def process(record_id):
            await real_process(record_id)
            # The state right after, before a scan could tidy it up.
            handled.append((record_id, dict(worker._blocked_conversations), set(worker._retry_after)))

        worker._process = process
        worker.start()
        await asyncio.sleep(0.05)
        await worker.submit(IncomingMessage(user_id="person", sender_id="person", text="saved-0",
                                            channel=Adapter.name, message_id="0"), external_id="0")
        await until(lambda: bool(handled))
        assert handled[0] == (held, {}, set())
        await worker.submit(IncomingMessage(user_id="person", sender_id="person", text="next",
                                            channel=Adapter.name, message_id="n"), external_id="n")
        await until(lambda: order == ["next"])
        await worker.close()
    asyncio.run(run())


def test_a_conversation_waits_behind_a_receipt_that_stays_unreadable_until_the_hold_expires(monkeypatch):
    # X's send is refused, so Y waits behind X; then X cannot be read at all.
    # Y keeps waiting, and its receipt says what it waits behind, until X has
    # been unreadable for UNREADABLE_HOLD_SECONDS (its key is not coming back):
    # then Y is delivered and its receipt records what it went ahead of. The
    # worker scans once or twice a retry period, not back to back.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "sealed": False}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        state["sealed"] = True
        scans = []
        real_window = worker._oldest_window

        def counted():
            scans.append(1)
            return real_window()

        worker._oldest_window = counted
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await asyncio.sleep(0.5)
        # Ten retry periods; back to back, it was over 1,000 scans.
        assert len(scans) <= 15, len(scans)
        hold = journal.store.get(y["id"])["held_behind"]
        assert sends == ["X"] and hold == {"id": x["id"], "created_at": x["created_at"], "unreadable_since": 1000.0}
        assert worker._blocked_conversations
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        await until(lambda: "Y" in sends)
        await worker.close()
        assert sends == ["X", "Y"] and worker._blocked_conversations == {}
        saved = journal.store.get(y["id"])
        assert saved["held_behind"] is None
        assert saved["went_ahead_of"] == {"id": x["id"], "unreadable_since": 1000.0}
    asyncio.run(run())


def test_a_turn_check_reads_only_its_own_conversation():
    # With many replies waiting in other conversations (a channel refusing
    # every send), finding what one message waits behind, and releasing the
    # ones behind a finished message, read only that conversation's waiting
    # receipts. Walking every waiting receipt for each message made a retry
    # round grow with the square of the backlog.
    import time

    class NoFullWalk(dict):
        def _walk(self, *args):
            raise AssertionError("walked every waiting receipt")
        __iter__ = keys = values = items = _walk

    worker = TransportWorker(Adapter(AsyncMock()), account="account", authorize=lambda msg: True,
                             send=AsyncMock())
    later = time.monotonic() + 3600
    retry = NoFullWalk()
    for index in range(1000):
        worker._conversations[f"other-{index}"] = (float(index), f"conversation-{index}")
        dict.__setitem__(retry, f"other-{index}", later)
    worker._conversations["x"] = (5000.0, "c")
    worker._conversations["y"] = (5001.0, "c")
    dict.__setitem__(retry, "x", later)
    dict.__setitem__(retry, "y", later)
    worker._retry_after = retry

    assert worker._waiting_ahead("y", 5001.0, "c") == ("x", None)
    assert worker._waiting_ahead("x", 5000.0, "c") == (None, None)
    worker._release_after("x")
    assert dict.__getitem__(retry, "y") <= time.monotonic()
    assert dict.__getitem__(retry, "other-0") == later
    assert worker._waiting_ahead("y", 5001.0, "c") == (None, None)


def test_a_conversation_continues_once_its_blocking_receipt_is_gone(monkeypatch):
    # X's send is refused, so Y waits behind X; X is then removed (erased or
    # settled elsewhere). Nothing will ever retry X, so Y is delivered.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    journal = _unreadable_journal(0, lambda record_id: False)
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        await until(lambda: bool(worker._blocked_conversations))
        journal.store.delete(x["id"], expected_revision=journal.store.get(x["id"])["revision"])
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await until(lambda: "Y" in sends)
        await worker.close()
        assert sends == ["X", "Y"] and worker._blocked_conversations == {}
    asyncio.run(run())


def test_a_receipt_held_by_a_restore_is_not_run_and_an_unreadable_one_does_not_spin_the_scan(monkeypatch):
    # A restore holds one saved receipt; another cannot be read. The held one
    # is never run, and the worker scans about once a retry period instead of
    # picking the held receipt up again in back-to-back scans.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    poisoned = []
    journal = _unreadable_journal(2, lambda record_id: record_id in poisoned)
    held, sealed = [record_id for _, record_id in journal.store.iter_record_ids(start_after="", limit=10)]
    journal.change(journal.get(held), restore_hold=True)
    poisoned.append(sealed)

    async def run():
        order = []
        async def handler(message):
            order.append(message.text)
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=journal)
        scans = []
        real_window = worker._oldest_window

        def counted():
            scans.append(1)
            return real_window()

        worker._oldest_window = counted
        processed = []
        real_process = worker._process

        async def process(record_id):
            processed.append(record_id)
            return await real_process(record_id)

        worker._process = process
        worker.start()
        await asyncio.sleep(0.5)
        loop = asyncio.get_running_loop()
        started = loop.time()
        await worker.close()
        assert loop.time() - started < 1
        assert order == [] and held not in processed
        assert len(scans) <= 15, len(scans)
    asyncio.run(run())


def test_a_scan_stopped_at_the_safety_ceiling_adds_to_the_unreadable_receipts(monkeypatch):
    # A scan that stops at the ceiling did not reach every receipt, so the
    # receipts it could not read are added to the last complete scan's, not
    # put in their place; the next complete scan replaces them.
    poisoned = []
    journal = _unreadable_journal(4, lambda record_id: record_id in poisoned)
    first = next(record_id for _, record_id in journal.store.iter_record_ids(start_after="", limit=10))
    poisoned.append(first)
    worker = TransportWorker(Adapter(AsyncMock()), account="account", authorize=lambda msg: True,
                             send=AsyncMock(), journal=journal)
    worker._unreadable = frozenset({"chd-read-earlier"})
    monkeypatch.setattr(transport_worker, "MAX_CONFIGURED_RECORDS", 2)
    _selected, more = worker._oldest_window()
    assert more is True and worker._unreadable == {"chd-read-earlier", first}
    monkeypatch.setattr(transport_worker, "MAX_CONFIGURED_RECORDS", 100)
    _selected, more = worker._oldest_window()
    assert more is False and worker._unreadable == {first}


def _saved_older_listed_first(journal, *, person="p"):
    """Save ``older`` then ``newer`` from one person, with message ids chosen so
    the store lists the older message's receipt first."""
    from maverick_channels.delivery import _record_id

    def receipt_id(external_id):
        return _record_id(Adapter.name, "account", external_id)

    older = next(f"older-{n}" for n in range(256) if receipt_id(f"older-{n}") < "chd-4")
    newer = next(f"newer-{n}" for n in range(256) if receipt_id(f"newer-{n}") > receipt_id(older))
    rows = [journal.admit(IncomingMessage(user_id=person, sender_id=person, text=text, channel=Adapter.name,
                                          message_id=external_id), external_id=external_id, account="account")
            for text, external_id in (("older", older), ("newer", newer))]
    assert rows[0]["created_at"] <= rows[1]["created_at"] and rows[0]["id"] < rows[1]["id"]
    return rows


def test_a_newer_message_is_not_sent_first_when_the_key_returns_mid_scan(monkeypatch):
    # Two saved messages from one person; the store lists the older one's
    # receipt first. The at-rest key is unavailable when the scan reads the
    # older receipt and back by the time it reads the newer one. The newer
    # reply used to go out first.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    journal = DeliveryJournal()
    _saved_older_listed_first(journal)
    real_get, outage = journal.get, {"reads_left": 1}

    def get(record_id):
        if outage["reads_left"]:
            outage["reads_left"] -= 1  # the key comes back right after this read
            raise OSError("key briefly unavailable")
        return real_get(record_id)

    journal.get = get
    sends = []

    async def send(message, reply, route):
        sends.append(reply.text)
        return "confirmed"

    async def run():
        async def handler(message):
            return message.text
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal).start()
        await until(lambda: len(sends) == 2)
        await worker.close()
        assert sends == ["older", "newer"]
    asyncio.run(run())


def test_a_newer_message_is_not_sent_first_when_the_key_blinks_before_the_older_is_handled(monkeypatch):
    # The scan reads both receipts and puts the older first; the key is gone
    # only for the worker's next read of the older receipt, just before it is
    # handled. The newer one, read a moment later, used to be sent first.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    journal = DeliveryJournal()
    older, _newer = _saved_older_listed_first(journal)
    real_get, reads = journal.get, []

    def get(record_id):
        if record_id == older["id"]:
            reads.append(record_id)
            if len(reads) == 2:  # the scan's read worked; the next one does not
                raise OSError("key briefly unavailable")
        return real_get(record_id)

    journal.get = get
    sends = []

    async def send(message, reply, route):
        sends.append(reply.text)
        return "confirmed"

    async def run():
        async def handler(message):
            return message.text
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal).start()
        await until(lambda: len(sends) == 2)
        await worker.close()
        assert sends == ["older", "newer"]
    asyncio.run(run())


def test_a_receipt_that_cannot_be_read_holds_only_its_own_conversation(monkeypatch):
    # X's first send is refused, so X waits for a retry and the person's next
    # message Y waits behind it. Then X's receipt cannot be read. Another
    # person's message Z is answered at once; Y keeps waiting, and its receipt
    # says what it waits behind. Once X can be read again, X goes out, then Y.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    state = {"x": None, "sealed": False}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if sends == ["X"]:
            raise DeliveryNotSent("X's first send is refused")
        return "confirmed"

    def held(record_id):
        return (journal.store.get(record_id) or {}).get("held_behind") or {}

    async def run():
        worker = TransportWorker(Adapter(AsyncMock(return_value="answer")), account="account",
                                 authorize=lambda msg: True, send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: x["id"] in worker._retry_after)  # X waits for its retry
        state["sealed"] = True
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await worker.submit(IncomingMessage(user_id="q", sender_id="q", text="Z", channel=Adapter.name,
                                            message_id="z"), external_id="z")
        await until(lambda: "Z" in sends)
        await asyncio.sleep(0.3)  # several retry periods
        assert sends == ["X", "Z"]
        assert held(y["id"])["id"] == x["id"] and held(y["id"])["unreadable_since"] is not None
        state["sealed"] = False
        await until(lambda: len(sends) == 4)
        await worker.close()
        assert sends == ["X", "Z", "X", "Y"] and worker._blocked_conversations == {}
        assert journal.store.get(y["id"])["held_behind"] is None
    asyncio.run(run())


def test_a_restarted_worker_keeps_a_conversation_waiting_behind_an_unreadable_receipt(monkeypatch):
    # Y waits behind X, whose receipt cannot be read, and the worker restarts.
    # The new worker cannot read X either, so it learns from Y's receipt which
    # conversation X holds: Y keeps waiting, and goes out after X once X can
    # be read. The time X became unreadable carries over too.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    state = {"x": None, "sealed": False}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if sends == ["X"]:
            raise DeliveryNotSent("X's first send is refused")
        return "confirmed"

    def held(record_id):
        return (journal.store.get(record_id) or {}).get("held_behind") or {}

    async def run():
        first = TransportWorker(Adapter(AsyncMock(return_value="answer")), account="account",
                                authorize=lambda msg: True, send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await first.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                               message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: x["id"] in first._retry_after)
        state["sealed"] = True
        y = await first.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                               message_id="y"), external_id="y")
        await until(lambda: held(y["id"]).get("unreadable_since") is not None)
        since = held(y["id"])["unreadable_since"]
        await first.close()
        second = TransportWorker(Adapter(AsyncMock(return_value="answer")), account="account",
                                 authorize=lambda msg: True, send=send, journal=journal).start()
        await until(lambda: x["id"] in second._unreadable)
        await asyncio.sleep(0.3)  # several retry periods
        assert sends == ["X"] and second._unreadable_since[x["id"]] == since
        state["sealed"] = False
        await until(lambda: len(sends) == 3)
        await second.close()
        assert sends == ["X", "X", "Y"]
    asyncio.run(run())


def test_more_held_messages_than_one_window_do_not_rescan_back_to_back(monkeypatch):
    # Several of the person's messages wait behind X, whose receipt cannot be
    # read, more than one window holds. Each one waits a retry period: were
    # they due again at once, every scan would report more work and the
    # worker would rescan back to back.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    monkeypatch.setattr(transport_worker, "MAX_PENDING", 2)
    state = {"x": None, "sealed": False}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends = []

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        worker = TransportWorker(Adapter(AsyncMock(return_value="answer")), account="account",
                                 authorize=lambda msg: True, send=send, journal=journal).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: x["id"] in worker._retry_after)
        state["sealed"] = True
        for index in range(4):
            await worker.submit(IncomingMessage(user_id="p", sender_id="p", text=f"Y{index}", channel=Adapter.name,
                                                message_id=f"y{index}"), external_id=f"y{index}")
        await until(lambda: x["id"] in worker._unreadable)
        scans = []
        real_window = worker._oldest_window

        def counted():
            scans.append(1)
            return real_window()

        worker._oldest_window = counted
        await asyncio.sleep(0.5)
        await worker.close()
        assert sends == ["X"]
        # Ten retry periods, two windows of held messages each; due again at
        # once, it was over 800 scans.
        assert len(scans) <= 30, len(scans)
    asyncio.run(run())


class _Status:
    """Records what a worker publishes about its held replies."""

    def __init__(self):
        self.counts, self.started, self.closed = [], False, False

    def start(self):
        self.started = True
        return self

    def update(self, counts):
        self.counts.append(dict(counts))

    def close(self):
        self.closed = True

    @property
    def latest(self):
        return self.counts[-1]


_COUNT_KEYS = {"held", "behind_unreadable", "unreadable", "retrying", "release_at", "went_ahead", "went_ahead_at"}


def test_held_replies_are_published_as_counts_until_the_unreadable_hold_expires(monkeypatch):
    # As the test above: Y waits behind X, which cannot be read, until X has
    # been unreadable for UNREADABLE_HOLD_SECONDS. What the worker publishes
    # for the Channels page and Copilot says so in counts and times only, and
    # then that one reply went out without waiting once it was delivered.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "sealed": False}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends, status = [], _Status()

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        assert status.started
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        state["sealed"] = True
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["behind_unreadable"] == 1)
        # X itself cannot be read, so it is not also counted as waiting for another attempt.
        assert status.latest == {"held": 1, "behind_unreadable": 1, "unreadable": 1, "retrying": 0,
                                 "release_at": 1000.0 + transport_worker.UNREADABLE_HOLD_SECONDS,
                                 "went_ahead": 0, "went_ahead_at": None}
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        await until(lambda: "Y" in sends)
        await until(lambda: status.latest["went_ahead"] == 1)
        assert status.latest["held"] == 0 and status.latest["went_ahead_at"] == wall[0]
        await worker.close()
        assert status.closed
        assert all(set(counts) == _COUNT_KEYS for counts in status.counts)
    asyncio.run(run())


def test_a_reply_that_goes_ahead_is_counted_only_once_it_is_delivered(monkeypatch):
    # As above, but once X's hold expires Y's own first send is refused: Y has
    # not gone out, so nothing is counted until its retried send is delivered.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "sealed": False, "y_refusals": 1}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends, status = [], _Status()

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        if state["y_refusals"]:
            state["y_refusals"] -= 1
            raise DeliveryNotSent("Y's first send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        state["sealed"] = True
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["behind_unreadable"] == 1)
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        await until(lambda: sends.count("Y") == 1)
        # Y, and X, which still cannot be read and no longer holds anything.
        await until(lambda: status.latest["retrying"] == 2)
        assert status.latest["went_ahead"] == 0  # refused: it did not go out
        await until(lambda: sends.count("Y") == 2)
        await until(lambda: status.latest["went_ahead"] == 1)
        assert status.latest["retrying"] == 1  # X still waits
        await worker.close()
    asyncio.run(run())


def test_a_reply_waiting_for_a_refused_one_is_published_without_a_release_time(monkeypatch):
    # X's send is refused once, so Y waits for X's retry. Nothing is
    # unreadable, so the status has no time by which Y goes out regardless;
    # once X is sent, Y follows and nothing is held.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    journal = _unreadable_journal(0, lambda record_id: False)
    sends, status = [], _Status()

    async def send(message, reply, route):
        sends.append(message.text)
        if len(sends) == 1:
            raise DeliveryNotSent("X's first send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                            message_id="x"), external_id="x")
        await until(lambda: bool(worker._blocked_conversations))
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: y["id"] in worker._retry_after and status.counts and status.latest["held"] == 1)
        assert status.latest == {"held": 1, "behind_unreadable": 0, "unreadable": 0, "retrying": 1,
                                 "release_at": None, "went_ahead": 0, "went_ahead_at": None}
        now[0] += transport_worker.RETRY_DELAY
        await until(lambda: sends == ["X", "X", "Y"])
        await until(lambda: status.latest["held"] == 0 and status.latest["retrying"] == 0)
        await worker.close()
    asyncio.run(run())


def _turns(gates):
    """A handler whose reply to a message waits for that text's gate."""
    async def handler(message):
        gate = gates.get(message.text)
        if gate is not None:
            await gate.wait()
        return "answer"
    return handler


def test_the_status_is_current_for_the_whole_of_a_long_reply(monkeypatch):
    # X's send is refused. While W's reply is worked on, Y (X's chat) and Z
    # (another chat) arrive. Y waits behind X, then Z's long reply starts: the
    # status must say Y is held for the whole of Z's reply, not only after it.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    journal = _unreadable_journal(0, lambda record_id: False)
    sends, status = [], _Status()
    gates = {"W": asyncio.Event(), "Z": asyncio.Event()}
    started = []

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        handler = _turns(gates)

        async def watched(message):
            started.append(message.text)
            return await handler(message)
        worker = TransportWorker(Adapter(watched), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                            message_id="x"), external_id="x")
        await until(lambda: bool(worker._blocked_conversations))
        await worker.submit(IncomingMessage(user_id="w", sender_id="w", text="W", channel=Adapter.name,
                                            message_id="w"), external_id="w")
        await until(lambda: "W" in started)
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await worker.submit(IncomingMessage(user_id="z", sender_id="z", text="Z", channel=Adapter.name,
                                            message_id="z"), external_id="z")
        gates["W"].set()
        await until(lambda: "Z" in started)
        await asyncio.sleep(0.05)
        assert status.latest["held"] == 1  # Y waits behind X throughout Z's reply
        gates["Z"].set()
        await worker.close()
    asyncio.run(run())


def test_the_status_says_a_released_reply_is_no_longer_held_while_it_is_answered(monkeypatch):
    # Y waits behind a refused X. X is then sent, so Y is answered: the status
    # must not keep saying Y is held while Y's own long reply is worked on.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    journal = _unreadable_journal(0, lambda record_id: False)
    sends, status, started = [], _Status(), []
    gates = {"Y": asyncio.Event()}

    async def send(message, reply, route):
        sends.append(message.text)
        if len(sends) == 1:
            raise DeliveryNotSent("X's first send is refused")
        return "confirmed"

    async def run():
        handler = _turns(gates)

        async def watched(message):
            started.append(message.text)
            return await handler(message)
        worker = TransportWorker(Adapter(watched), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                            message_id="x"), external_id="x")
        await until(lambda: bool(worker._blocked_conversations))
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["held"] == 1)
        now[0] += transport_worker.RETRY_DELAY
        await until(lambda: "Y" in started)
        await asyncio.sleep(0.05)
        assert sends == ["X", "X"] and status.latest["held"] == 0
        gates["Y"].set()
        await worker.close()
    asyncio.run(run())


def test_a_restarted_worker_reports_every_held_reply_from_its_first_status(monkeypatch):
    # The first worker holds more replies than one window behind a refused X
    # and stops. Each held receipt names what it waits behind, so the next
    # worker's very first status already counts all of them.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    journal = _unreadable_journal(0, lambda record_id: False)
    count = transport_worker.MAX_PENDING + 8

    async def send(message, reply, route):
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        first = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                send=send, journal=journal, status=_Status()).start()
        await asyncio.sleep(0.05)
        await first.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                           message_id="x"), external_id="x")
        await until(lambda: bool(first._blocked_conversations))
        for index in range(count):
            await first.submit(IncomingMessage(user_id="p", sender_id="p", text=f"Y{index}", channel=Adapter.name,
                                               message_id=f"y{index}"), external_id=f"y{index}")
        await until(lambda: len(first._held) == count)
        await first.close()
        status = _Status()
        second = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await until(lambda: bool(status.counts))
        assert status.counts[0]["held"] == count
        await second.close()
    asyncio.run(run())


def test_the_release_time_covers_every_unreadable_reply_ahead_in_the_chat(monkeypatch):
    # In one chat X1's send is refused, so X2 and Y wait behind it. X1 then
    # cannot be read from 1000, and X2 from 5000. Y goes out regardless only
    # once both have been unreadable for UNREADABLE_HOLD_SECONDS, so the status
    # gives 5000 + that, not the earlier 1000 + that.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    sealed = set()
    journal = _unreadable_journal(0, lambda record_id: record_id in sealed)
    status = _Status()

    async def send(message, reply, route):
        raise DeliveryNotSent("every send is refused")

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        ids = {}
        for text in ("X1", "X2", "Y"):
            ids[text] = (await worker.submit(IncomingMessage(user_id="p", sender_id="p", text=text,
                                                             channel=Adapter.name, message_id=text.lower()),
                                             external_id=text.lower()))["id"]
            if text == "X1":
                await until(lambda: bool(worker._blocked_conversations))
        await until(lambda: len(worker._held) == 2)
        sealed.add(ids["X1"])
        await until(lambda: ids["X1"] in worker._unreadable_since)
        wall[0] = 5000.0
        sealed.add(ids["X2"])
        await until(lambda: ids["X2"] in worker._unreadable_since)
        await until(lambda: status.latest["release_at"] == 5000.0 + transport_worker.UNREADABLE_HOLD_SECONDS)
        await worker.close()
    asyncio.run(run())


def test_a_worker_publishes_its_status_by_default_and_removes_it_on_close():
    from maverick_channels import hold_status

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=AsyncMock(return_value="confirmed"), journal=DeliveryJournal()).start()
        await until(lambda: any(record["channel"] == Adapter.name for record in hold_status.records()[0]))
        found, unreadable = hold_status.records()
        assert not unreadable and found[0]["fresh"] and found[0]["held"] == 0
        await worker.close()
        assert hold_status.records() == ([], frozenset())
    asyncio.run(run())


def test_a_restarted_worker_publishes_nothing_until_a_scan_reads_its_receipts(monkeypatch):
    # The first worker holds three replies behind a refused X and stops. The
    # next one starts while the store cannot be listed: it knows nothing yet,
    # so it publishes nothing (the page says it is not reporting) instead of
    # counts that say no reply waits. Once a scan works, all three count.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    journal = _unreadable_journal(0, lambda record_id: False)

    async def send(message, reply, route):
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        first = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                send=send, journal=journal, status=_Status()).start()
        await asyncio.sleep(0.05)
        await first.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                           message_id="x"), external_id="x")
        await until(lambda: bool(first._blocked_conversations))
        for index in range(3):
            await first.submit(IncomingMessage(user_id="p", sender_id="p", text=f"Y{index}", channel=Adapter.name,
                                               message_id=f"y{index}"), external_id=f"y{index}")
        await until(lambda: len(first._held) == 3)
        await first.close()
        listing, broken, attempts = journal.store.iter_record_ids, [True], [0]

        def iter_record_ids(**kwargs):
            attempts[0] += 1
            if broken[0]:
                raise OSError("the store cannot be listed yet")
            return listing(**kwargs)
        journal.store.iter_record_ids = iter_record_ids
        status = _Status()
        second = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await until(lambda: attempts[0] >= 2)  # the failed first scan and its retry
        assert status.counts == []
        broken[0] = False
        await until(lambda: bool(status.counts))
        assert status.counts[0]["held"] == 3
        await second.close()
    asyncio.run(run())


def test_a_worker_restarted_while_no_receipt_can_be_read_publishes_nothing(monkeypatch):
    # As above, but the store lists its receipts and none of them can be read
    # (the receipt key is out while the status key works). A scan that read
    # nothing knows no more than no scan: the worker stays unpublished until
    # one is read, then counts all three.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    outage, reads = [False], [0]

    def failing(record_id):
        reads[0] += 1
        return outage[0]
    journal = _unreadable_journal(0, failing)

    async def send(message, reply, route):
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        first = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                send=send, journal=journal, status=_Status()).start()
        await asyncio.sleep(0.05)
        await first.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                           message_id="x"), external_id="x")
        await until(lambda: bool(first._blocked_conversations))
        for index in range(3):
            await first.submit(IncomingMessage(user_id="p", sender_id="p", text=f"Y{index}", channel=Adapter.name,
                                               message_id=f"y{index}"), external_id=f"y{index}")
        await until(lambda: len(first._held) == 3)
        await first.close()
        outage[0] = True
        status = _Status()
        second = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await until(lambda: len(second._unreadable) == 4)
        before = reads[0]
        await until(lambda: reads[0] >= before + 8)  # two more scans of all four
        assert status.counts == []
        outage[0] = False
        await until(lambda: bool(status.counts))
        assert status.counts[0]["held"] == 3
        await second.close()
    asyncio.run(run())


def test_replies_retried_after_a_failure_or_a_refused_permission_are_counted(monkeypatch):
    # X fails while it is handled and is retried every RETRY_DELAY; Z was
    # admitted but is no longer permitted when handled, and is retried too.
    # Both wait for another attempt, so both count, and Y, in X's chat, is
    # held behind X.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    journal = _unreadable_journal(0, lambda record_id: False)
    status, checks = _Status(), {"Z": 0}

    def authorize(message):
        if message.text != "Z":
            return True
        checks["Z"] += 1
        return checks["Z"] == 1  # admitted, then refused each time it is handled

    class Failing(Adapter):
        async def process_message(self, message, **kwargs):
            if message.text == "X":
                raise OSError("X's attachment cannot be opened")
            return await super().process_message(message, **kwargs)

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Failing(handler), account="account", authorize=authorize,
                                 send=AsyncMock(return_value="confirmed"), journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        await until(lambda: x["id"] in worker._retry_after)
        await until(lambda: status.counts and status.latest["retrying"] == 1)
        assert status.latest["held"] == 0
        await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                            message_id="y"), external_id="y")
        await worker.submit(IncomingMessage(user_id="q", sender_id="q", text="Z", channel=Adapter.name,
                                            message_id="z"), external_id="z")
        await until(lambda: status.latest["held"] == 1 and status.latest["retrying"] == 2)
        await worker.close()
    asyncio.run(run())


def test_a_reply_that_went_ahead_before_a_restart_is_counted_once_delivered_after_it(monkeypatch):
    # Y goes ahead of X's expired hold and its send is refused; the chat
    # service then restarts. The restarted worker cannot read X, so it does
    # not know X's chat, but Y's receipt says it went ahead of X: once Y is
    # delivered it counts as having gone out without waiting.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "sealed": False, "refuse_y": True}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends, first_status, second_status = [], _Status(), _Status()

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X" or (message.text == "Y" and state["refuse_y"]):
            raise DeliveryNotSent("refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        first = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                send=send, journal=journal, status=first_status).start()
        await asyncio.sleep(0.05)
        x = await first.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                               message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(first._blocked_conversations))
        state["sealed"] = True
        y = await first.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                               message_id="y"), external_id="y")
        await until(lambda: first_status.counts and first_status.latest["behind_unreadable"] == 1)
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        await until(lambda: "Y" in sends)
        await until(lambda: first_status.latest["retrying"] == 2)
        assert first_status.latest["went_ahead"] == 0  # refused: it did not go out
        await first.close()
        state["refuse_y"] = False
        second = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=second_status).start()
        await until(lambda: journal.get(y["id"])["delivery"] == "delivered")
        await until(lambda: bool(second_status.counts) and second_status.latest["went_ahead"] == 1)
        assert second_status.latest["went_ahead_at"] is not None
        await second.close()
    asyncio.run(run())


def test_an_irc_reply_that_goes_ahead_is_counted_once_every_line_is_written(monkeypatch):
    # IRC confirms no delivery: a reply whose lines were all written ends as
    # delivery_unknown. One that went ahead of an expired hold went out, so it
    # counts.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "sealed": False}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    status, wire = _Status(), []

    async def send(message, reply, route):
        if message.text == "X":
            raise DeliveryNotSent("X's send is refused")

        async def write():
            wire.append(message.text)
            return "local-wire-write-only"
        await send_chunk("irc-0", message.text, write)  # as IRCChannel._send_chunks
        if delivery_active():
            raise DeliveryUnknown("IRC remote delivery has no acknowledgement")

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="#chan", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        state["sealed"] = True
        y = await worker.submit(IncomingMessage(user_id="#chan", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["behind_unreadable"] == 1)
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        await until(lambda: "Y" in wire)
        await until(lambda: status.latest["went_ahead"] == 1)
        assert journal.get(y["id"])["delivery"] == "delivery_unknown"
        await worker.close()
    asyncio.run(run())


def test_a_reply_that_goes_ahead_stays_counted_through_a_scan_that_cannot_read_it(monkeypatch):
    # Y goes ahead of X's expired hold, but its send is refused. One scan then
    # cannot read Y's receipt. Y is still waiting, so once it is delivered it
    # counts as having gone out without waiting.
    import sys as _sys

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "y": None, "sealed": False, "y_fails": 0, "refuse_y": True}

    def in_scan():
        frame = _sys._getframe()
        while frame is not None:
            if frame.f_code.co_name == "_oldest_window":
                return True
            frame = frame.f_back
        return False

    def failing(record_id):
        if state["sealed"] and record_id == state["x"]:
            return True
        if record_id == state["y"] and state["y_fails"] and in_scan():
            state["y_fails"] -= 1
            return True
        return False
    journal = _unreadable_journal(0, failing)
    sends, status = [], _Status()

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X" or state["refuse_y"]:
            raise DeliveryNotSent("the send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        state["sealed"] = True
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        state["y"] = y["id"]
        await until(lambda: status.counts and status.latest["behind_unreadable"] == 1)
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        await until(lambda: "Y" in sends)
        assert y["id"] in worker._going_ahead
        state["y_fails"] = 1
        await until(lambda: state["y_fails"] == 0 and y["id"] in worker._unreadable)
        await until(lambda: y["id"] not in worker._unreadable)  # the scan has finished with it
        assert y["id"] in worker._going_ahead
        state["refuse_y"] = False
        await until(lambda: journal.get(y["id"])["delivery"] == "delivered")
        await until(lambda: status.latest["went_ahead"] == 1)
        await worker.close()
    asyncio.run(run())


def test_replies_held_through_a_receipt_read_outage_stay_counted_without_a_release_time(monkeypatch):
    # X's send is refused and Y waits behind it. Then no saved receipt can be
    # read while the status can still be saved (a separate key). Both still
    # wait: Y stays counted behind a reply that cannot be read, and since Y
    # cannot be read either, no time is given by which it goes out.
    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    outage = [False]
    journal = _unreadable_journal(0, lambda record_id: outage[0])
    status = _Status()

    async def send(message, reply, route):
        raise DeliveryNotSent("Signal is down")

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        await until(lambda: bool(worker._blocked_conversations))
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["held"] == 1 and status.latest["retrying"] == 1)
        outage[0] = True
        await until(lambda: {x["id"], y["id"]} <= worker._unreadable)
        await until(lambda: status.latest["behind_unreadable"] == 1)
        expected = {"held": 1, "behind_unreadable": 1, "unreadable": 1, "retrying": 0, "release_at": None,
                    "went_ahead": 0, "went_ahead_at": None}
        assert status.latest == expected
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        published = len(status.counts)
        await until(lambda: len(status.counts) > published + 2)  # republished after later scans
        assert status.latest == expected
        await worker.close()
    asyncio.run(run())


def test_a_reply_released_by_the_one_ahead_is_not_said_to_wait_for_it(monkeypatch):
    # Y waits behind X, which cannot be read. X opens again and is sent in a
    # window with Z from another chat, before Y is due. While Z is answered,
    # Y waits only for its turn, not for X to be sent first. W's turn keeps
    # the worker busy while X opens and Z is saved, so no scan picks X alone.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    state = {"x": None, "sealed": False, "refuse_x": True}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends, status, started = [], _Status(), []
    gates = {"W": asyncio.Event(), "Z": asyncio.Event()}

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X" and state["refuse_x"]:
            raise DeliveryNotSent("X's send is refused")
        return "confirmed"

    async def run():
        handler = _turns(gates)

        async def watched(message):
            started.append(message.text)
            return await handler(message)
        worker = TransportWorker(Adapter(watched), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: bool(worker._blocked_conversations))
        state["sealed"] = True
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["behind_unreadable"] == 1)
        await worker.submit(IncomingMessage(user_id="w", sender_id="w", text="W", channel=Adapter.name,
                                            message_id="w"), external_id="w")
        await until(lambda: "W" in started)  # no scan runs while W's reply is worked on
        state["sealed"], state["refuse_x"] = False, False
        await worker.submit(IncomingMessage(user_id="z", sender_id="z", text="Z", channel=Adapter.name,
                                            message_id="z"), external_id="z")
        gates["W"].set()
        await until(lambda: "Z" in started)
        assert journal.get(x["id"])["delivery"] == "delivered"
        assert journal.get(y["id"])["delivery"] != "delivered"
        assert status.latest["held"] == 0
        gates["Z"].set()
        await until(lambda: journal.get(y["id"])["delivery"] == "delivered")
        await worker.close()
    asyncio.run(run())


def test_a_reply_that_went_in_turn_after_all_is_not_counted_as_going_ahead(monkeypatch):
    # Y goes ahead of X's expired hold, but its send is refused. X's key then
    # returns and X is sent before Y's retry, so Y goes out after X after all.
    from types import SimpleNamespace

    monkeypatch.setattr(transport_worker, "RETRY_DELAY", 0.05)
    now = [0.0]
    monkeypatch.setattr(transport_worker, "time", SimpleNamespace(monotonic=lambda: now[0]))
    wall = [1000.0]
    monkeypatch.setattr(transport_worker, "_wall_clock", lambda: wall[0])
    state = {"x": None, "sealed": False, "refuse_x": True, "refuse_y": 1}
    journal = _unreadable_journal(0, lambda record_id: state["sealed"] and record_id == state["x"])
    sends, status = [], _Status()

    async def send(message, reply, route):
        sends.append(message.text)
        if message.text == "X" and state["refuse_x"]:
            raise DeliveryNotSent("X's send is refused")
        if message.text == "Y" and state["refuse_y"]:
            state["refuse_y"] -= 1
            state["sealed"], state["refuse_x"] = False, False  # X's key returns
            raise DeliveryNotSent("Y's first send is refused")
        return "confirmed"

    async def run():
        async def handler(message):
            return "answer"
        worker = TransportWorker(Adapter(handler), account="account", authorize=lambda msg: True,
                                 send=send, journal=journal, status=status).start()
        await asyncio.sleep(0.05)
        x = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="X", channel=Adapter.name,
                                                message_id="x"), external_id="x")
        state["x"] = x["id"]
        await until(lambda: x["id"] in worker._retry_after)
        state["sealed"] = True
        await until(lambda: x["id"] in worker._unreadable)
        y = await worker.submit(IncomingMessage(user_id="p", sender_id="p", text="Y", channel=Adapter.name,
                                                message_id="y"), external_id="y")
        await until(lambda: status.counts and status.latest["behind_unreadable"] == 1)
        wall[0] += transport_worker.UNREADABLE_HOLD_SECONDS
        now[0] += 1.0  # Y's retry is due: it goes ahead of X, and its send is refused
        await until(lambda: journal.get(y["id"])["delivery"] == "delivered")
        # Counted, if at all, once its turn returns: wait for the statuses after it.
        published = len(status.counts)
        await until(lambda: len(status.counts) > published + 1)
        assert journal.get(x["id"])["delivery"] == "delivered"
        assert sends == ["X", "Y", "X", "Y"]  # X was sent before Y's second, delivered send
        assert status.latest["went_ahead"] == 0 and worker._went_ahead == 0
        await worker.close()
    asyncio.run(run())
