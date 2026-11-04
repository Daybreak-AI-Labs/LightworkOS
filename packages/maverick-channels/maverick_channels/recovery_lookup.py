"""Bounded read-only checkpoint metadata from configured channel adapters.

Never starts a channel, changes its checkpoint, admits work, or sends a reply.
Only timestamps and stable evidence digests leave this module, never message text.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import sqlite3
import time
from datetime import datetime, timezone

from .polling import parse_timestamp


async def _no_handler(*args, **kwargs):
    raise RuntimeError("Recovery source lookup cannot execute or send work.")


def configured(channel: str, options: dict):
    if not isinstance(options, dict) or options.get("enabled") is not True:
        raise ValueError("This connection is disabled; lookup cannot establish a current checkpoint.")
    allowed = options.get("allowed_user_ids")
    allowed = {str(value) for value in allowed} if allowed is not None else None
    if channel == "imessage":
        from .imessage import iMessageChannel
        return iMessageChannel(_no_handler, allowed_user_ids=allowed)
    if channel == "mastodon":
        from .mastodon import MastodonChannel
        return MastodonChannel(_no_handler, instance=options.get("instance"), access_token=options.get("access_token"), allowed_user_ids=allowed)
    raise ValueError("This source already uses a human date or separate delivery review; automatic position lookup is unavailable.")


def record_identity(channel) -> str:
    account = channel._account()
    value = account if channel.name == "imessage" else channel.name + "\0" + account
    return ("imc-" if channel.name == "imessage" else "chp-") + hashlib.sha256(value.encode()).hexdigest()[:56]


def _candidate(position: str, timestamp: str, source: str, identity: str) -> dict:
    stamp = parse_timestamp(timestamp)
    if stamp is None:
        raise ValueError("The source did not provide a valid checkpoint date; no checkpoint was guessed.")
    observed = stamp.astimezone(timezone.utc).isoformat()
    digest = hashlib.sha256(json.dumps({"source": source, "position": position, "at": observed, "identity": identity}, sort_keys=True).encode()).hexdigest()
    return {"position": position, "source_at": observed, "evidence_reference": "source-lookup:" + source + ":" + digest, "evidence_digest": digest}


def imessage_page(channel, *, minimum: str, before: str | None) -> dict:
    from .imessage import CHAT_DB
    if not re.fullmatch(r"[0-9]{1,19}", minimum) or int(minimum) > 2**63 - 1:
        raise ValueError("The saved position is outside the local source's supported range.")
    if before is not None and (not re.fullmatch(r"[0-9]{1,19}", before) or int(before) > 2**63 - 1):
        raise ValueError("The source page changed; refresh lookup.")
    deadline = time.monotonic() + 5
    # ``with connect()`` only ends a transaction; closing the handle is explicit.
    with contextlib.closing(sqlite3.connect(CHAT_DB.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
        connection.execute("PRAGMA query_only = ON")
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        rows = connection.execute("SELECT ROWID,date,guid FROM message WHERE ROWID >= ? AND (? IS NULL OR ROWID < ?) ORDER BY ROWID DESC LIMIT 51", (int(minimum), int(before) if before else None, int(before) if before else None)).fetchall()
        empty = not rows and minimum == "0" and before is None and connection.execute("SELECT 1 FROM message LIMIT 1").fetchone() is None
    candidates = []
    for rowid, date, guid in rows[:50]:
        if type(date) not in (int, float) or not isinstance(guid, str) or not guid:
            raise ValueError("The local source lacks exact timestamp or message identity evidence.")
        seconds = date / 1_000_000_000 if abs(date) > 1_000_000_000_000 else date
        stamp = datetime.fromtimestamp(978307200 + seconds, timezone.utc).isoformat()
        candidates.append(_candidate(str(rowid), stamp, "imessage", guid))
    if empty:
        candidate = _candidate("0", datetime.now(timezone.utc).isoformat(), "imessage", "confirmed-empty-database")
        candidate["empty_source"] = True
        candidates.append(candidate)
    return {"candidates": candidates, "next_before": str(rows[49][0]) if len(rows) > 50 else None}


async def mastodon_page(channel, *, minimum: str, before: str | None) -> dict:
    from urllib.parse import urlsplit

    import httpx
    origin = urlsplit(channel._base_url)
    if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment:
        raise ValueError("The configured source address is not an approved HTTPS account origin.")
    if not re.fullmatch(r"[0-9]{1,40}", minimum) or (before is not None and not re.fullmatch(r"[0-9]{1,40}", before)):
        raise ValueError("The source position is invalid; refresh recovery.")
    params = {"types[]": "mention", "limit": 50}
    if before:
        params["max_id"] = before
    payload = bytearray()
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        async with client.stream("GET", channel._base_url + "/api/v1/notifications", headers=channel._headers(), params=params) as response:
            response.raise_for_status()
            async for block in response.aiter_bytes():
                if len(payload) + len(block) > 1024 * 1024:
                    raise ValueError("The source response exceeded its read-only lookup bound.")
                payload.extend(block)
    rows = json.loads(payload)
    if not isinstance(rows, list) or len(rows) > 50:
        raise ValueError("The source returned an unsupported page.")
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or any(not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,40}", value) for value in ids):
        raise ValueError("The source page has no exact notification identity.")
    if [int(value) for value in ids] != sorted(set(map(int, ids)), reverse=True) or (before and ids and int(ids[0]) >= int(before)):
        raise ValueError("Source ordering changed. No position was guessed.")
    candidates = [_candidate(row["id"], row.get("created_at", ""), "mastodon", row["id"]) for row in rows if int(row["id"]) >= int(minimum)]
    if not rows and before is None and minimum == "0":
        candidate = _candidate("0", datetime.now(timezone.utc).isoformat(), "mastodon", "confirmed-empty-notification-page")
        candidate["empty_source"] = True
        candidates.append(candidate)
    return {"candidates": candidates, "next_before": ids[-1] if len(rows) == 50 and int(ids[-1]) > int(minimum) else None}


def lookup(channel, *, minimum: str, before: str | None) -> dict:
    if channel.name == "imessage":
        return imessage_page(channel, minimum=minimum, before=before)
    if channel.name == "mastodon":
        async def bounded():
            return await asyncio.wait_for(mastodon_page(channel, minimum=minimum, before=before), timeout=15)
        return asyncio.run(bounded())
    raise ValueError("This source has no read-only position adapter.")
