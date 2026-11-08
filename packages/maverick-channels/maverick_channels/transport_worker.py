"""One owned execution worker behind an independently serviced transport."""
from __future__ import annotations

import asyncio
import logging
import math
import threading
import time
from collections import deque

from . import hold_status
from .base import IncomingMessage
from .delivery import MAX_CONFIGURED_RECORDS, DeliveryJournal, _digest, reply_withheld

MAX_PENDING = 32
RETRY_DELAY = 30.0
SHUTDOWN_TIMEOUT = 5.0
# How long a saved receipt that cannot be read keeps the newer messages of its
# conversation waiting before they go ahead without it: the same limit after
# which delivery surfaces a stalled send or execution claim as unknown.
UNREADABLE_HOLD_SECONDS = 24 * 3600
_wall_clock = time.time  # bound once: tests replace this module's ``time``
log = logging.getLogger(__name__)


def _waiting(row):
    return row["execution"] == "received" or row["delivery"] in {"ready", "retryable"}


def _sent(row):
    """True when the reply went out: delivered, or (IRC, which confirms no
    delivery) every line of it was written to the provider."""
    if row["delivery"] == "delivered":
        return True
    written = [chunk for key, chunk in (row.get("chunks") or {}).items() if key != "reply"]
    return (row["delivery"] == "delivery_unknown" and bool(written)
            and all(chunk.get("state") == "delivered" for chunk in written))


def _conversation(message):
    """A digest naming one conversation: the chat and the person in it."""
    return _digest([message.get("user_id"), message.get("sender_id")])


class _Conversations:
    """Waiting id -> (created_at, conversation), also indexed by conversation,
    so a turn check reads only its own conversation's waiting receipts."""

    def __init__(self):
        self._rows, self._by_conversation = {}, {}

    def __getitem__(self, record_id):
        return self._rows[record_id]

    def get(self, record_id, default=None):
        return self._rows.get(record_id, default)

    def __setitem__(self, record_id, value):
        self.pop(record_id)
        self._rows[record_id] = value
        self._by_conversation.setdefault(value[1], set()).add(record_id)

    def setdefault(self, record_id, value):
        if record_id not in self._rows:
            self[record_id] = value
        return self._rows[record_id]

    def pop(self, record_id, default=None):
        if record_id not in self._rows:
            return default
        value = self._rows.pop(record_id)
        ids = self._by_conversation[value[1]]
        ids.discard(record_id)
        if not ids:
            del self._by_conversation[value[1]]
        return value

    def keep(self, wanted):
        for record_id in [key for key in self._rows if not wanted(key)]:
            self.pop(record_id)

    def in_conversation(self, conversation):
        return tuple(self._by_conversation.get(conversation, ()))


class TransportWorker:
    """Persist before queueing; overflow stays durable instead of disappearing.

    The bounded in-memory queue is only a wakeup/cache. A recovery scan keeps
    at most MAX_PENDING metadata tuples and loads one source record at a time.
    Scanning the hard-bounded receipt namespace before selecting the oldest
    pending records preserves intake order when overflow/restart has removed
    the in-memory order. Agent work remains strictly serial.

    Within one conversation a message is not handled while an earlier one is
    still waiting: for another attempt, or because its saved receipt cannot
    be read (see _waiting_ahead). The worker remembers each waiting receipt's
    conversation from when it could read it, and a message that waits records
    what it waits behind in its own receipt, so a restarted worker that cannot
    read the earlier receipt still knows which conversation it holds. What it
    holds is published as counts for the Channels page and Copilot (see
    hold_status), recomputed after each scan, before each reply is worked on
    and before the worker waits.
    """
    def __init__(self, channel, *, account, authorize, send, journal=None, status=None):
        self.channel, self.account = channel, account
        self.authorize, self.send = authorize, send
        self.journal = journal or DeliveryJournal()
        self._status = status if status is not None else hold_status.Publisher(channel.name)
        self.pending = deque()
        self._wake = asyncio.Event()
        self._stop_scan = threading.Event()
        self._generation = 0
        self._overflow = True  # Recover previous accepted inputs before new ones.
        self._closing = False
        self._retry_after = {}
        self._scan_pending = None  # ids still waiting, from the last complete scan
        self._scan_seen = None  # what the last scan read: see _remember_scan
        self._unreadable = frozenset()  # ids the last scans could not read (see _report_unreadable)
        self._unreadable_since = {}  # id -> wall-clock time it was first found unreadable
        self._conversations = _Conversations()  # waiting id -> (created_at, conversation), from its last read
        self._learned = set()  # ids learned while the current scan runs
        self._held = {}  # id waiting its turn -> the oldest earlier receipt it waits behind
        self._went_ahead, self._went_ahead_at = 0, None
        self._going_ahead = set()  # ids going ahead of an expired hold at their last attempt, not yet sent
        self._retrying = set()  # ids that could not be sent or handled, waiting for another attempt
        self._counted = False  # a scan has read the store: until then nothing is published
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
        try:
            self._status.start()
        except Exception:
            log.warning("Channel %s held chat replies status is unavailable", self.channel.name)
        return self

    async def submit(self, message, *, external_id, route=None):
        if self._closing:
            raise RuntimeError("Transport intake is stopping")
        receipt = await self.channel.admit_message(message, external_id=external_id, account=self.account,
            authorize=lambda: not self._closing and self.authorize(message), route=route, journal=self.journal)
        self._learn(receipt)
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
            log.warning("Channel %s: %d saved receipt(s) in the shared channel store could not be read; they are "
                        "read again on later scans, and newer messages in a conversation this worker knows them "
                        "by wait for them", self.channel.name, len(unreadable))
        self._unreadable = unreadable

    def _learn(self, row):
        """Remember a waiting receipt's conversation while it can be read, so it
        still holds that conversation if it later cannot be."""
        message = row.get("message")
        if (isinstance(message, dict) and not row.get("restore_hold") and _waiting(row)
                and not reply_withheld(row)):
            self._conversations[row["id"]] = (row["created_at"], _conversation(message))
            self._learned.add(row["id"])

    def _oldest_window(self):
        found = {"selected": [], "waiting": {}, "hints": [], "count": 0, "read": False}
        unreadable = set()
        self._scan_pending = self._scan_seen = None
        now = time.monotonic()
        cursor, scanned, wrapped, read_after_failure = "", 0, False, False
        while scanned <= MAX_CONFIGURED_RECORDS and not wrapped:
            # Shared storage returns at most 10,000 ids per scan. Keep walking
            # so raising the intake cap cannot hide older pending messages.
            page = list(self.journal.store.iter_record_ids(start_after=cursor, limit=10_000))
            if not page:
                break
            for position, record_id in page:
                # The scan wraps back to the start: a position at or before the
                # cursor ends the pass, even if compaction removed the first one.
                if cursor and position <= cursor:
                    wrapped = True
                    break
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
                found["read"] = True
                read_after_failure = read_after_failure or bool(unreadable)
                self._consider(row, now, found)
        if read_after_failure:
            # One read failed and a later one worked: the key may have come back
            # during this scan. Read the failed ones again before choosing, or a
            # newer message listed after an older one would be chosen first.
            for record_id in sorted(unreadable):
                if self._stop_scan.is_set():
                    return [], False
                try:
                    row = self.journal.get(record_id)
                except Exception:
                    continue
                found["read"] = True
                unreadable.discard(record_id)
                self._consider(row, now, found)
        complete = wrapped or scanned <= MAX_CONFIGURED_RECORDS
        self._report_unreadable(unreadable, complete=complete)
        # A scan that could read none of the saved receipts knows no more
        # about them than no scan.
        self._scan_seen = (found["waiting"], found["hints"], found["read"] or not unreadable)
        if not complete:
            log.warning("Channel receipt scan exceeds configured safety ceiling")
        else:
            self._scan_pending = found["waiting"]
        return [record_id for _, record_id in found["selected"]], found["count"] > MAX_PENDING or not complete

    def _consider(self, row, now, found):
        """Note a receipt the scan read if it is still waiting, and choose it
        unless it waits for a retry time."""
        # A receipt a restore holds is not run again (as recovery_window).
        if (not row or row.get("restore_hold") or row["channel"] != self.channel.name
                or row["account_sha256"] != _digest(self.account) or not _waiting(row)):
            return
        message = row.get("message")
        # A reply the source check holds back does not hold its conversation.
        known = (None if reply_withheld(row) or not isinstance(message, dict)
                 else (row["created_at"], _conversation(message)))
        found["waiting"][row["id"]] = known
        hold = row.get("held_behind")
        if known and isinstance(hold, dict):
            found["hints"].append((row["id"], hold.get("id"), hold.get("created_at"), known[1],
                                   hold.get("unreadable_since")))
        if self._retry_after.get(row["id"], 0) > now:
            return
        found["count"] += 1
        found["selected"].append((row["created_at"], row["id"]))
        found["selected"].sort()
        del found["selected"][MAX_PENDING:]

    async def _run(self):
        while True:
            if self.pending:
                record_id = self.pending.popleft()
                try:
                    await self._process(record_id)
                except Exception:
                    # Retried by the next scan after RETRY_DELAY, like a refused send.
                    self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
                    self._retrying.add(record_id)
                    log.warning("Channel %s saved transport work requires review", self.channel.name)
                continue
            if self._closing and not self._overflow and not self._wake.is_set():
                return
            if self._overflow or self._wake.is_set():
                self._wake.clear()
                generation = self._generation
                self._learned = set()
                try:
                    self._scan_task = asyncio.create_task(asyncio.to_thread(self._oldest_window),
                                                         name="channel-intake-scan:" + self.channel.name)
                    selected, more = await asyncio.shield(self._scan_task)
                except Exception:
                    log.warning("Channel %s transport recovery scan remains incomplete", self.channel.name)
                    selected, more = [], True
                self.pending.extend(selected)
                self._remember_scan()
                if self._scan_pending is not None:
                    self._forget_settled(self._scan_pending)
                self._publish_status()
                self._overflow = more or generation != self._generation
                if self.pending:
                    continue
                if self._closing:
                    return
            # Published after each scan, before each reply is worked on (see
            # _process) and before waiting: handling a message can end a hold
            # with no scan after it. A held message returns before its reply
            # is worked on, so held replies are not recounted one by one.
            self._publish_status()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=RETRY_DELAY)
            except asyncio.TimeoutError:
                # Rescan only for work waiting on a retry, a scan that did not
                # complete, or a receipt that could not be read (it may open
                # again): an idle worker re-read and decrypted every saved
                # receipt every 30 seconds.
                self._overflow = self._overflow or bool(self._retry_after) or bool(self._unreadable)

    def _remember_scan(self):
        """Take in the conversations the scan read. A message that waits names
        the earlier receipt it waits behind: when this worker cannot read that
        receipt (after a restart it never has), its conversation comes from there.
        It is also counted as held from the first scan, before it is handled again."""
        seen, self._scan_seen = self._scan_seen, None
        if seen is not None:
            waiting, hints, readable = seen
            self._counted = self._counted or readable
            for record_id, known in waiting.items():
                if known:
                    self._conversations[record_id] = known
                else:
                    self._conversations.pop(record_id, None)
            for held_id, record_id, created_at, conversation, since in hints:
                if record_id in self._unreadable or waiting.get(record_id):
                    self._held.setdefault(held_id, record_id)
                if record_id not in self._unreadable or type(created_at) not in (int, float):
                    continue
                self._conversations.setdefault(record_id, (created_at, conversation))
                if type(since) in (int, float):
                    self._unreadable_since[record_id] = min(since, self._unreadable_since.get(record_id, since))
        now = _wall_clock()
        self._unreadable_since = {record_id: self._unreadable_since.get(record_id, now)
                                  for record_id in self._unreadable}

    def _forget_settled(self, waiting):
        for record_id in [key for key in self._retry_after if key not in waiting]:
            self._retry_after.pop(record_id)  # finished or removed meanwhile
        # A receipt that cannot be read right now keeps its marks: it is still
        # waiting, and a mark lost here would not come back when it is read.
        for record_id in [key for key in self._held if key not in waiting and key not in self._unreadable]:
            self._held.pop(record_id)
        self._retrying &= waiting.keys() | self._unreadable
        self._going_ahead &= waiting.keys() | self._unreadable
        # A conversation is remembered only for a receipt still waiting, one
        # that cannot be read (it keeps holding its conversation), or one
        # admitted while the scan ran.
        self._conversations.keep(lambda key: bool(waiting.get(key)) or key in self._unreadable
                                 or key in self._learned)

    def _holds(self, conversation=None):
        """(created_at, id, conversation, expired) for each receipt that newer
        messages of its conversation wait behind: one waiting for another
        attempt (a refused send, a failure, or itself waiting its turn), or one
        that cannot be read. An unreadable one has expired once it has been
        unreadable for UNREADABLE_HOLD_SECONDS: its key is taken not to return.
        Given a conversation, only that conversation's receipts are read."""
        now = _wall_clock()
        others = (set(self._retry_after) | self._unreadable if conversation is None else
                  [other for other in self._conversations.in_conversation(conversation)
                   if other in self._retry_after or other in self._unreadable])
        for other in others:
            known = self._conversations.get(other)
            if known is not None:
                since = self._unreadable_since.get(other)
                expired = (other in self._unreadable and since is not None
                           and now - since >= UNREADABLE_HOLD_SECONDS)
                yield known[0], other, known[1], expired

    @property
    def _blocked_conversations(self):
        """Each conversation that waits, and the oldest receipt it waits behind."""
        held = {}
        for created_at, other, conversation, expired in self._holds():
            if not expired and (conversation not in held or (created_at, other) < held[conversation]):
                held[conversation] = (created_at, other)
        return {conversation: other for conversation, (_, other) in held.items()}

    def _hold_counts(self):
        """What this worker holds, as the counts hold_status publishes: replies
        waiting their turn, those behind a receipt that cannot be read, how
        many such receipts hold them, the time by which every one of those
        goes out regardless, the replies that could not be sent or handled
        and wait for another attempt, and the replies that went out without
        waiting.

        A held reply waits behind each earlier unreadable receipt of its
        conversation until that one has been unreadable for
        UNREADABLE_HOLD_SECONDS, so each conversation's time comes from its
        newest held reply, and each conversation is read once."""
        behind_unreadable, blockers, newest = 0, set(), {}
        for record_id, ahead in self._held.items():
            if ahead not in self._unreadable:
                continue
            behind_unreadable += 1
            blockers.add(ahead)
            if record_id in self._unreadable:
                continue  # it cannot be read itself: no time by which it goes out
            blocker = self._conversations.get(ahead)
            if blocker is None:
                continue
            mine = self._conversations.get(record_id)
            key = (mine[0], record_id) if mine else (math.inf, "")
            if blocker[1] not in newest or key > newest[blocker[1]]:
                newest[blocker[1]] = key
        release = None
        for conversation, key in newest.items():
            for other in self._conversations.in_conversation(conversation):
                since = self._unreadable_since.get(other)
                if other in self._unreadable and since is not None and (self._conversations[other][0], other) < key:
                    due = since + UNREADABLE_HOLD_SECONDS
                    release = due if release is None else max(release, due)
        # One that cannot be read is counted once: as what holds the replies
        # behind it, or else as waiting for another attempt.
        retrying = len(self._retrying - self._held.keys() - blockers)
        return {"held": len(self._held), "behind_unreadable": behind_unreadable, "unreadable": len(blockers),
                "retrying": retrying, "release_at": release, "went_ahead": self._went_ahead,
                "went_ahead_at": self._went_ahead_at}

    def _publish_status(self):
        # Before a scan has read its saved receipts (or found none) this
        # worker knows nothing about what they hold: publishing its empty
        # counts would say no reply waits. Unpublished, the page says it is
        # not reporting.
        if not self._counted:
            return
        try:
            self._status.update(self._hold_counts())
        except Exception:
            log.warning("Channel %s held chat replies status could not be updated", self.channel.name)

    def _waiting_ahead(self, record_id, created_at, conversation):
        """The oldest earlier receipt of this conversation it must wait behind,
        and the oldest it goes ahead of because that one has expired."""
        ahead, passed = [], []
        for other_created_at, other, other_conversation, expired in self._holds(conversation):
            if (other != record_id and other_conversation == conversation
                    and (other_created_at, other) < (created_at, record_id)):
                (passed if expired else ahead).append((other_created_at, other))
        return (min(ahead)[1] if ahead else None), (min(passed)[1] if passed else None)

    async def _note(self, row, **updates):
        """Record a hold in the receipt for the status window and a restarted
        worker; the hold itself does not depend on the write."""
        if all(row.get(key) == value for key, value in updates.items()):
            return row
        try:
            return await asyncio.to_thread(self.journal.change, row, **updates)
        except Exception:
            log.warning("Channel %s could not record a conversation hold in a saved receipt", self.channel.name)
            return row

    async def _in_turn(self, row):
        """The row when no earlier message of its conversation waits; otherwise
        None, after setting its retry time and recording what it waits behind."""
        if not _waiting(row):
            return row
        created_at, conversation = row["created_at"], _conversation(row["message"])
        if not reply_withheld(row):
            self._conversations[row["id"]] = (created_at, conversation)
        ahead, passed = self._waiting_ahead(row["id"], created_at, conversation)
        if ahead is not None:
            # Due with the earlier one's retry, or a retry period from now when
            # it has none (it cannot be read): never due again at once, or a
            # window of held messages would be rescanned back to back.
            now, due = time.monotonic(), self._retry_after.get(ahead, 0)
            self._retry_after[row["id"]] = due if due > now else now + RETRY_DELAY
            since = self._unreadable_since.get(ahead) if ahead in self._unreadable else None
            if since is not None and (row.get("held_behind") or {}).get("unreadable_since") is None:
                log.warning("Channel %s: a message waits behind an earlier one in its conversation whose saved "
                            "receipt cannot be read; it goes out after that one, or without it once that receipt "
                            "has been unreadable for %d hours", self.channel.name, UNREADABLE_HOLD_SECONDS // 3600)
            self._held[row["id"]] = ahead
            self._going_ahead.discard(row["id"])
            await self._note(row, held_behind={"id": ahead, "created_at": self._conversations[ahead][0],
                                               "unreadable_since": since})
            return None
        self._held.pop(row["id"], None)
        if passed is not None:
            went_ahead_of = {"id": passed, "unreadable_since": self._unreadable_since.get(passed)}
            if row.get("went_ahead_of") != went_ahead_of:
                log.warning("Channel %s: a message goes ahead of an earlier one in its conversation whose saved "
                            "receipt has been unreadable for %d hours", self.channel.name,
                            UNREADABLE_HOLD_SECONDS // 3600)
            # Counted once it is sent (see _process), as decided at its last
            # attempt: one held again, or in turn by then, did not go ahead.
            self._going_ahead.add(row["id"])
            return await self._note(row, held_behind=None, went_ahead_of=went_ahead_of)
        # It went ahead at an attempt before a restart of a receipt that still
        # cannot be read (whose chat a restarted worker no longer knows).
        earlier = (row.get("went_ahead_of") or {}).get("id")
        if isinstance(earlier, str) and earlier in self._unreadable:
            self._going_ahead.add(row["id"])
        else:
            self._going_ahead.discard(row["id"])
        return await self._note(row, held_behind=None)

    def _release_after(self, record_id):
        """This receipt no longer holds its conversation: the newer messages
        that waited behind it are due now, and a scan picks them up in order.
        Until then each is counted as waiting behind what is still ahead of it
        in its conversation, if anything."""
        known = self._conversations.pop(record_id, None)
        for other in [key for key, ahead in self._held.items() if ahead == record_id]:
            waited = self._conversations.get(other)
            ahead = self._waiting_ahead(other, *waited)[0] if waited else None
            if ahead is None:
                self._held.pop(other)
            else:
                self._held[other] = ahead
        if known is None:
            return
        now = time.monotonic()
        for other in self._conversations.in_conversation(known[1]):
            waited = self._conversations[other]
            if self._retry_after.get(other, 0) > now and (waited[0], other) > (known[0], record_id):
                self._retry_after[other] = now
                self._overflow = True

    async def _process(self, record_id):
        try:
            row = await asyncio.to_thread(self.journal.get, record_id)
        except Exception:
            # As when a scan cannot read it: it holds its conversation (if this
            # worker knows it) and is read again later.
            self._unreadable = self._unreadable | {record_id}
            self._unreadable_since.setdefault(record_id, _wall_clock())
            raise
        self._unreadable = self._unreadable - {record_id}
        self._unreadable_since.pop(record_id, None)
        # A receipt a restore holds is not run (a redelivered message can
        # bring one here through submit), and does not hold the conversation.
        if not row or not row.get("message") or row.get("restore_hold"):
            self._held.pop(record_id, None)
            self._retrying.discard(record_id)
            self._going_ahead.discard(record_id)
            self._release_after(record_id)
            return
        message = IncomingMessage(**{key: value for key, value in row["message"].items() if key != "attachments"})
        row = await self._in_turn(row)
        if row is None:
            return
        if not self.authorize(message):
            self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
            self._retrying.add(record_id)
            return
        async def send_saved(reply):
            return await self.send(message, reply, row["route"])
        # The status stays as now for as long as this reply is worked on.
        self._publish_status()
        result = await self.channel.process_message(message, external_id=row["external_id"], account=self.account,
            authorize=lambda: self.authorize(message), send=send_saved, receipt=row, journal=self.journal)
        if result["delivery"] == "retryable" and not reply_withheld(result):
            # Refused: retried, and the conversation's newer messages wait for it.
            self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
            self._retrying.add(record_id)
        elif result["delivery"] == "retryable":
            # Held back by the source check (task or access changed): retried,
            # but the person's newer messages do not wait behind it.
            self._retry_after[record_id] = time.monotonic() + RETRY_DELAY
            self._retrying.discard(record_id)
            self._release_after(record_id)
        else:
            self._retry_after.pop(record_id, None)
            self._retrying.discard(record_id)
            if record_id in self._going_ahead:
                self._going_ahead.discard(record_id)
                if _sent(result):
                    self._went_ahead, self._went_ahead_at = self._went_ahead + 1, _wall_clock()
            self._release_after(record_id)

    async def close(self):
        self._closing = True
        self._wake.set()
        try:
            await self._stop_task()
        finally:
            # A stopped worker reports nothing: its held replies are held again
            # when it restarts, and the page says the chat service is not reporting.
            await asyncio.to_thread(self._status.close)

    async def _stop_task(self):
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
