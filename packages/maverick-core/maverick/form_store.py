"""A bounded append-only store of hosted-form submissions.

A ``form`` event trigger points a public web form (or any POST) at
``/form/<token>``; each submission is appended here under that token, and the
``form`` :class:`~maverick.automation_events.EventSource` polls it so the
submission fires a flow -- the push-to-poll bridge that lets a form be a
first-class trigger without a bespoke inbound queue.

Private NDJSON in the tenant data dir. A submission is one
line ``{"seq", "ts", "fields"}``; ``seq`` is a per-token monotonic counter used
as the poll cursor (deletion-safe, unlike id-walking). Full stores refuse new
submissions instead of silently dropping entries that a trigger has not polled.
"""
from __future__ import annotations

import json
import math
import os
import re

_MAX_FIELDS = 50          # per submission
_MAX_VALUE = 2000         # per field value
_MAX_LINES = 5000         # per form; refuse rather than lose pending events
_MAX_BYTES = 32 * 1024 * 1024
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,120}$")


class FormStoreFull(RuntimeError):
    """The form cannot accept another submission without losing existing data."""


class FormStoreClosed(RuntimeError):
    """A replaced public link cannot accept another submission."""


class FormStoreUnavailable(RuntimeError):
    """Pending submissions cannot be established safely from the stored file."""


def valid_token(token: str) -> bool:
    return isinstance(token, str) and bool(_TOKEN_RE.fullmatch(token))


def storage_key(token: str) -> str:
    """Keep pre-upgrade form files addressable by their original token."""
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", str(token or "").strip())
    return s[:120] or "form"


def _path(token: str):
    from .paths import data_dir
    return data_dir("forms") / f"{storage_key(token)}.ndjson"


def _accepted_marker(p):
    return p.with_name(p.name + ".accepted")


def _closed_marker(p):
    return p.with_name(p.name + ".closed")


def is_closed(token: str) -> bool:
    """Check the durable closure marker without creating a form queue."""
    return _closed_marker(_path(token)).exists()


def close_token(token: str) -> None:
    """Stop a public link under the same lock used by submission append."""
    if not valid_token(token):
        raise ValueError("form token is invalid")
    p = _path(token)
    from .file_lock import atomic_create_bytes, cross_process_lock, ensure_private_directory

    try:
        ensure_private_directory(p.parent)
        with cross_process_lock(p, strict=True):
            if not _closed_marker(p).exists():
                try:
                    atomic_create_bytes(_closed_marker(p), b"closed\n")
                except FileExistsError:
                    pass
    except OSError as exc:
        raise FormStoreUnavailable("form link could not be closed") from exc


def _mark_accepted(p) -> None:
    """Persist that this queue has held work before acknowledging it."""
    marker = _accepted_marker(p)
    if marker.exists():
        return
    from .file_lock import atomic_create_bytes

    try:
        atomic_create_bytes(marker, b"accepted\n")
    except FileExistsError:
        pass


def _bound_fields(fields: dict) -> dict:
    out: dict = {}
    for k, v in (fields or {}).items():
        if len(out) >= _MAX_FIELDS:
            break
        out[str(k)[:200]] = ("" if v is None else str(v))[:_MAX_VALUE]
    return out


def append(token: str, fields: dict, *, ts: float = 0.0) -> int:
    """Append one submission for ``token``; return its ``seq`` (1-based). Fields
    are stringified + bounded. Returns 0 on write failure and raises
    :class:`FormStoreFull` when the bounded store has reached capacity."""
    p = _path(token)
    from .file_lock import cross_process_lock, ensure_private_directory, open_private_append

    try:
        # This is a dedicated Lightwork-owned directory. Harden an older
        # installation's existing directory as well as newly created ones.
        ensure_private_directory(p.parent)
        with cross_process_lock(p, strict=True):
            if _closed_marker(p).exists():
                raise FormStoreClosed("form link was replaced")
            exists = p.exists()
            if _accepted_marker(p).exists() and not exists:
                raise FormStoreUnavailable("form submissions are unavailable")
            count, highest = _state(p) if exists else (0, 0)
            if not count and _accepted_marker(p).exists():
                raise FormStoreUnavailable("form submissions are unavailable")
            if count:
                _mark_accepted(p)  # Initialize pre-upgrade queues under the same lock.
            if count >= _MAX_LINES:
                raise FormStoreFull("form submission limit reached")
            seq = highest + 1
            line = (json.dumps({"seq": seq, "ts": float(ts), "fields": _bound_fields(fields)},
                               separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
            size = p.stat().st_size if p.exists() else 0
            if size + len(line) > _MAX_BYTES:
                raise FormStoreFull("form storage limit reached")
            fd = open_private_append(p, require_private_parent=True)
            with os.fdopen(fd, "ab") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            _mark_accepted(p)
            return seq
    except (OSError, RuntimeError) as exc:
        if isinstance(exc, (FormStoreFull, FormStoreClosed)):
            raise
        return 0


def _validated_rows(p):
    """Reject damage before a reader can acknowledge or append past a row."""
    expected = 1
    with open(p, encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise FormStoreUnavailable("form submissions are damaged") from exc
            if not isinstance(row, dict) or not isinstance(row.get("fields"), dict):
                raise FormStoreUnavailable("form submissions are damaged")
            if type(row.get("seq")) is not int or row["seq"] != expected:
                raise FormStoreUnavailable("form submission sequence is damaged")
            ts = row.get("ts")
            try:
                valid_ts = type(ts) in (int, float) and math.isfinite(ts)
            except OverflowError:
                valid_ts = False
            if not valid_ts:
                raise FormStoreUnavailable("form submissions are damaged")
            expected += 1
            yield row


def _state(p) -> tuple[int, int]:
    """Read count and high-water sequence under the caller's file lock."""
    count = highest = 0
    for row in _validated_rows(p):
        count += 1
        highest = row["seq"]
    return count, highest


def pending(token: str, cursor: str) -> int:
    """Count accepted submissions beyond a trigger's acknowledged cursor.

    Callers must hold the event-trigger registry lock while checking and
    changing a public form's binding.
    """
    if not isinstance(cursor, str) or not cursor.isdecimal():
        raise FormStoreUnavailable("form cursor is unavailable")
    after = int(cursor)
    p = _path(token)
    if not p.exists() and not _accepted_marker(p).exists():
        if after:
            raise FormStoreUnavailable("form submissions are unavailable")
        return 0
    from .file_lock import cross_process_lock

    try:
        with cross_process_lock(p, strict=True):
            if not p.exists():
                raise FormStoreUnavailable("form submissions are unavailable")
            count = highest = 0
            for row in _validated_rows(p):
                highest = row["seq"]
                count += highest > after
            if highest:
                _mark_accepted(p)  # Safely mark a validated pre-upgrade queue.
            elif _accepted_marker(p).exists():
                raise FormStoreUnavailable("form submissions are unavailable")
            if after > highest:
                raise FormStoreUnavailable("form cursor is ahead of submissions")
            return count
    except (OSError, UnicodeError) as exc:
        raise FormStoreUnavailable("form submissions are unavailable") from exc


def since(token: str, cursor: str, *, limit: int | None = None) -> tuple[list[dict], str]:
    """Submissions with ``seq`` greater than ``cursor`` (empty cursor = baseline:
    fire nothing, just record the high-water mark). Returns ``(events, cursor)``
    where each event is the flat ``fields`` dict plus ``_seq``/``_ts``.
    A bounded poll advances only through the returned rows, never the backlog."""
    if limit is not None and limit <= 0:
        raise ValueError("form poll limit must be positive")
    if not isinstance(cursor, str) or (cursor and not cursor.isdecimal()):
        raise FormStoreUnavailable("form cursor is unavailable")
    after = int(cursor) if cursor else None
    p = _path(token)
    if not p.exists() and not _accepted_marker(p).exists():
        if after:
            raise FormStoreUnavailable("form submissions are unavailable")
        # Do not create a lock sidecar on a baseline poll for a new form.
        return [], cursor or "0"
    from .file_lock import cross_process_lock

    try:
        with cross_process_lock(p, strict=True):
            rows = list(_validated_rows(p))
            if rows:
                _mark_accepted(p)  # Safely mark a validated pre-upgrade queue.
            elif _accepted_marker(p).exists():
                raise FormStoreUnavailable("form submissions are unavailable")
    except (OSError, UnicodeError) as exc:
        raise FormStoreUnavailable("form submissions are unavailable") from exc
    if not rows:
        if after:
            raise FormStoreUnavailable("form cursor is ahead of submissions")
        return [], cursor or "0"
    highest = rows[-1]["seq"]
    if after is not None and after > highest:
        raise FormStoreUnavailable("form cursor is ahead of submissions")
    if after is None:
        return [], str(highest)                  # baseline only
    fresh = [r for r in rows if r["seq"] > after]
    if limit is not None:
        fresh = fresh[:limit]
    if not fresh:
        return [], str(highest)
    events = []
    for r in fresh:
        ev = dict(r["fields"])
        ev["_seq"], ev["_ts"] = r["seq"], r["ts"]
        events.append(ev)
    return events, str(fresh[-1]["seq"])


__all__ = ["FormStoreFull", "FormStoreClosed", "FormStoreUnavailable", "append",
           "close_token", "is_closed", "pending", "since", "storage_key", "valid_token"]
