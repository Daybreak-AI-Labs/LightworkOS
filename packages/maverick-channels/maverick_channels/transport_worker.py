"""One owned execution worker behind an independently serviced transport."""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque

from .base import IncomingMessage
from .delivery import MAX_CONFIGURED_RECORDS, DeliveryJournal, _digest, reply_withheld

MAX_PENDING = 32
RETRY_DELAY = 30.0
SHUTDOWN_TIMEOUT = 5.0
log = logging.getLogger(__name__)


class TransportWorker:
    """Persist before queueing; overflow stays durable instead of disappearing.

    The bounded in-memory queue is only a wakeup/cache. A recovery scan keeps
    at most MAX_PENDING metadata tuples and loads one source record at a time.
    Scanning the hard-bounded receipt namespace before selecting the oldest
    pending records preserves intake order when overflow/restart has removed
    the in-memory order. Agent work remains strictly serial.
    """
    def __init__(self, channel, *, account, authorize, send, journal=None):
        self.channel, self.account = channel, account
        self.authorize, self.send = authorize, send
        self.journal = journal or DeliveryJournal()
        self.pending = deque()
        self._wake = asyncio.Event()
        self._stop_scan = threading.Event()
        self._generation = 0
        self._overflow = True  # Recover previous accepted inputs before new ones.
        self._closing = False
        self._retry_after = {}
        self._scan_pending = None  # ids still waiting, from the last complete scan
        self._unreadable = frozenset()  # ids the last scans could not read (see _report_unreadable)
        self._blocked_conversations = {}
        self.task = None
        self._scan_task = None
        self.overflow_count = 0

    def start(self, *, task_factory=None):
        if self.task is not None:
            raise RuntimeError("Transport worker already started")
        coro = self._run()
        try:
            self.task = (asyncio.create_task(coro, name="channel-worker:" + self.channel.name)
                         if task_factory is None else task_factory(coro))
            if not isinstance(self.task, asyncio.Task):
                raise TypeError("Transport task factory must return an owned asyncio.Task")
        except BaseException:
            coro.close()
            self.task = None
            raise
        return self

    async def submit(self, message, *, external_id, route=None):
        if self._closing:
            raise RuntimeError("Transport intake is stopping")
        receipt = await self.channel.admit_message(message, external_id=external_id, account=self.account,
            authorize=lambda: not self._closing and self.authorize(message), route=route, journal=self.journal)
        self._generation += 1
        # While a saved receipt cannot be read, new messages go through the
        # ordered scan: if it opens again, it was accepted first.
        if not self._overflow and not self._unreadable and len(self.pending) < MAX_PENDING:
            if receipt["id"] not in self.pending:
                self.pending.append(receipt["id"])
        else:
            self._overflow = True
            self.overflow_count += 1
        self._wake.set()
        return receipt

    def _report_unreadable(self, unreadable, *, complete=True):
        # A complete scan's set replaces the last one; a scan stopped at the
        # safety ceiling only adds to it. Logged when the set changes, not on
        # every scan: while a receipt stays unreadable, every retry period and
        # every new message scans again.
        unreadable = frozenset(unreadable) if complete else self._unreadable | unreadable
        if unreadable and unreadable != self._unreadable:
            log.warning("Channel %s: %d saved receipt(s) in the shared channel store could not be read and were "
                        "skipped; they are read again on later scans", self.channel.name, len(unreadable))
        self._unreadable = unreadable

    def _oldest_window(self):
        selected, waiting, unreadable = [], set(), set()
        self._scan_pending = None
        count = 0
        now = time.monotonic()
        cursor, scanned = "", 0
        while scanned <= MAX_CONFIGURED_RECORDS:
            # Shared storage returns at most 10,000 ids per scan. Keep walking
            # so raising the intake cap cannot hide older pending messages.
            page = list(self.journal.store.iter_record_ids(start_after=cursor, limit=10_000))
            if not page:
                break
            for position, record_id in page:
                # The scan wraps back to the start: a position at or before the
                # cursor ends the pass, even if compaction removed the first one.
                if cursor and position <= cursor:
                    self._scan_pending = frozenset(waiting)
                    self._report_unreadable(unreadable)
                    return [record_id for _, record_id in selected], count > MAX_PENDING
                cursor = position
                scanned += 1
                if self._stop_scan.is_set():
                    return [], False
                try:
                    row = self.journal.get(record_id)
                except Exception:
                    # A receipt that cannot be read now must not stop the
                    # recovery of every other one; it is read again by the
                    # scan after the retry period.
                    unreadable.add(record_id)
                    continue
                # A receipt a restore holds is not run again (as recovery_window).
                if (not row or row.get("restore_hold") or row["channel"] != self.channel.name
                        or row["account_sha256"] != _digest(self.account)
                        or not (row["execution"] == "received" or row["delivery"] in {"ready", "retryable"})):
                    continue
                waiting.add(record_id)
                if self._retry_after.get(record_id, 0) > now:
                    continue
                count += 1
                selected.append((row["created_at"], row["id"]))
                selected.sort()
                del selected[MAX_PENDING:]
        complete = scanned <= MAX_CONFIGURED_RECORDS
        self._report_unreadable(unreadable, complete=complete)
        if not complete:
            log.warning("Channel receipt scan exceeds configured safety ceiling")
        else:
            self._scan_pending = frozenset(waiting)
        return [record_id for _, record_id in selected], count > MAX_PENDING or not complete

    async def _run(self):
        while True:
            if self.pending:
                record_id = self.pending.popleft()
                try:
                    await self._process(record_id)
                except Exception:
                    # Retried by the next scan after RETRY_DELAY, like a refused send.
                    self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
                    log.warning("Channel %s saved transport work requires review", self.channel.name)
                continue
            if self._closing and not self._overflow and not self._wake.is_set():
                return
            if self._overflow or self._wake.is_set():
                self._wake.clear()
                generation = self._generation
                try:
                    self._scan_task = asyncio.create_task(asyncio.to_thread(self._oldest_window),
                                                         name="channel-intake-scan:" + self.channel.name)
                    selected, more = await asyncio.shield(self._scan_task)
                except Exception:
                    log.warning("Channel %s transport recovery scan remains incomplete", self.channel.name)
                    selected, more = [], True
                self.pending.extend(selected)
                if self._scan_pending is not None:
                    self._forget_settled(self._scan_pending)
                self._overflow = more or generation != self._generation
                if self.pending:
                    continue
                if self._closing:
                    return
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=RETRY_DELAY)
            except asyncio.TimeoutError:
                # Rescan only for work waiting on a retry, a scan that did not
                # complete, or a receipt that could not be read (it may open
                # again): an idle worker re-read and decrypted every saved
                # receipt every 30 seconds.
                self._overflow = self._overflow or bool(self._retry_after) or bool(self._unreadable)

    def _forget_settled(self, waiting):
        for record_id in [key for key in self._retry_after if key not in waiting]:
            self._retry_after.pop(record_id)  # finished or removed meanwhile
        # A conversation waits only behind a receipt still waiting to be sent:
        # one that is gone, held by a restore or cannot be read is not retried
        # now, so it no longer holds the person's newer messages (an
        # unreadable one is sent if it opens again).
        for conversation, blocker in list(self._blocked_conversations.items()):
            if blocker not in waiting:
                self._blocked_conversations.pop(conversation)

    async def _process(self, record_id):
        row = await asyncio.to_thread(self.journal.get, record_id)
        # A receipt a restore holds is not run (a redelivered message can
        # bring one here through submit), and does not hold the conversation.
        if not row or not row.get("message") or row.get("restore_hold"):
            return
        message = IncomingMessage(**{key: value for key, value in row["message"].items() if key != "attachments"})
        conversation = (message.user_id, message.sender_id)
        blocked = self._blocked_conversations.get(conversation)
        if blocked and blocked != record_id:
            self._retry_after[record_id] = max(time.monotonic(), self._retry_after.get(blocked, 0))
            return
        if not self.authorize(message):
            self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
            return
        async def send_saved(reply):
            return await self.send(message, reply, row["route"])
        result = await self.channel.process_message(message, external_id=row["external_id"], account=self.account,
            authorize=lambda: self.authorize(message), send=send_saved, receipt=row, journal=self.journal)
        if result["delivery"] == "retryable" and not reply_withheld(result):
            self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
            self._blocked_conversations[conversation] = record_id
        elif result["delivery"] == "retryable":
            # Held back by the source check (task or access changed): retried,
            # but the person's newer messages do not wait behind it.
            self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
            if self._blocked_conversations.get(conversation) == record_id:
                self._blocked_conversations.pop(conversation)
        else:
            self._retry_after.pop(record_id, None)
            if self._blocked_conversations.get(conversation) == record_id:
                self._blocked_conversations.pop(conversation)

    async def close(self):
        self._closing = True
        self._wake.set()
        if self.task is None or self.task is asyncio.current_task():
            return
        done, _ = await asyncio.wait([self.task], timeout=SHUTDOWN_TIMEOUT)
        if self.task not in done:
            self._stop_scan.set()
            self.task.cancel()
            done, _ = await asyncio.wait([self.task], timeout=SHUTDOWN_TIMEOUT)
        if self.task in done:
            try:
                self.task.result()
            except asyncio.CancelledError:
                pass
        else:
            log.warning("Channel %s worker shutdown remains unconfirmed", self.channel.name)
        if self._scan_task is not None and not self._scan_task.done():
            self._stop_scan.set()
            done, _ = await asyncio.wait([self._scan_task], timeout=SHUTDOWN_TIMEOUT)
            if self._scan_task not in done:
                log.warning("Channel %s read-only intake scan exit remains unconfirmed", self.channel.name)
