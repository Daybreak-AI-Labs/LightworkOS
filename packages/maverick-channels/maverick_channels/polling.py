"""Bounded durable page admission; provider cursors remain opaque data."""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import re
import time
from dataclasses import dataclass, field


def utc_timestamp() -> str:
    """Current UTC time as an AT-Protocol timestamp (``...Z``). Uses a
    timezone-aware now() -- datetime.utcnow() is deprecated in 3.12+."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_FRAC_RE = re.compile(r"\.(\d+)")


def parse_timestamp(ts: str) -> _dt.datetime | None:
    """Parse an AT-proto ``indexedAt`` into an aware UTC datetime.

    Tolerant of the varying fractional precision AT-proto emits (``...:00Z``,
    ``...:00.123Z``, ``...:00.123456789Z``) and of the trailing ``Z`` that
    ``datetime.fromisoformat`` rejects before Python 3.11. Returns None if the
    value is empty, naive or unparseable so no lexical date guess is needed.

    Why: the startup floor is seeded with 6-digit microseconds, but a raw
    string ``<=`` compares ``"…:00Z"`` as GREATER than ``"…:00.000000Z"``
    (``'Z'`` > ``'.'``), so a boundary-second notification with no/short
    fractional part slips past the "don't backfill history" floor.
    """
    if not isinstance(ts, str):
        return None
    s = ts.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Clamp fractional seconds to microseconds; fromisoformat rejects >6 digits.
    s = _FRAC_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), s, count=1)
    try:
        value = _dt.datetime.fromisoformat(s)
        return value if value.tzinfo is not None else None
    except ValueError:
        return None


MAX_PAGES = 3
MAX_ITEMS_PER_PAGE = 50
POLL_DEADLINE_SECONDS = 15.0
MAX_CYCLE_PAGES = 1024


@dataclass
class PollPage:
    items: list[dict]
    next_cursor: str | None = None
    updates: dict = field(default_factory=dict)
    completed: dict = field(default_factory=dict)


class PollCheckpoint:
    """A page advances only after every eligible input has a durable receipt.

    A partial poll is not a completed range. Re-reading a partly admitted
    page is safe because the inbox identity, not this cursor, owns execution.
    """
    def __init__(self, channel, account):
        from maverick.governed_records import GovernedRecordStore

        self.store = GovernedRecordStore("channel-poll-cursors", "chp", "channel_poll_cursor")
        self.record_id = "chp-" + hashlib.sha256((channel + "\0" + account).encode()).hexdigest()[:56]
        self.channel = channel

    async def load(self, initialize):
        from maverick.channel_recovery import assert_checkpoint_ready
        from maverick.privacy_ops import RecordConflict

        row = await asyncio.to_thread(self.store.get, self.record_id)
        if row is not None:
            assert_checkpoint_ready(row)
            return row
        initial = await asyncio.wait_for(initialize(), timeout=POLL_DEADLINE_SECONDS)
        try:
            return await asyncio.to_thread(self.store.create,
                {"id": self.record_id, "channel": self.channel, "cursor": None, "seen_cursors": [],
                 "status": "idle", **initial}, action="poll_initialized", actor="system:channel", max_records=1000)
        except RecordConflict:
            return await asyncio.to_thread(self.store.get, self.record_id)

    async def change(self, row, **updates):
        return await asyncio.to_thread(self.store.update, row["id"], lambda value: value.update(updates),
            expected_revision=row["revision"], action="poll_checkpoint", actor="system:channel")

    async def drain(self, row, fetch, admit):
        from maverick.channel_recovery import assert_checkpoint_ready

        assert_checkpoint_ready(row)
        admitted = []
        deadline = time.monotonic() + POLL_DEADLINE_SECONDS
        for _ in range(MAX_PAGES):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return admitted
            try:
                page = await asyncio.wait_for(fetch(row), timeout=remaining)
                if not isinstance(page, PollPage) or not isinstance(page.items, list) or len(page.items) > MAX_ITEMS_PER_PAGE:
                    raise ValueError("Provider page exceeded its bounded contract")
                cursor = page.next_cursor
                if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 4096):
                    raise ValueError("Invalid bounded provider continuation")
                for item in page.items:
                    if not isinstance(item, dict):
                        raise ValueError("Provider returned a malformed page item")
                    if await asyncio.wait_for(admit(item, row), timeout=max(0, deadline - time.monotonic())):
                        admitted.append(item)
                seen = [*row["seen_cursors"], hashlib.sha256((row["cursor"] or "").encode()).hexdigest()]
                repeated = cursor is not None and hashlib.sha256(cursor.encode()).hexdigest() in seen
                if repeated or len(seen) >= MAX_CYCLE_PAGES:
                    await self.change(row, **page.updates, cursor=None, seen_cursors=[],
                                      status="incomplete_cursor_cycle" if repeated else "incomplete_cycle_bound")
                    return admitted
                if cursor is None:
                    await self.change(row, **{**page.updates, **page.completed}, cursor=None,
                                      seen_cursors=[], status="idle")
                    return admitted
                row = await self.change(row, **page.updates, cursor=cursor, seen_cursors=seen,
                                        status="incomplete_page_bound")
            except Exception:
                # Keep the last committed continuation. A partially admitted
                # page may be retried, but its execution identities may not.
                from maverick.privacy_ops import RecordConflict

                try:
                    await self.change(row, status="incomplete_error")
                except RecordConflict:
                    pass
                raise
        return admitted
