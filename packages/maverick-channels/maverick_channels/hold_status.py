"""Held chat replies as the Channels page and Copilot see them.

Signal and IRC keep each conversation's replies in order: a reply waits while
an earlier one in the same conversation waits for another attempt or cannot
be read (see transport_worker). The worker that holds them runs in the chat
service's process, so each running worker publishes a small sealed status
here: how many replies wait, how many wait behind a reply that cannot be read,
when the earliest of those goes out regardless, and how many went out without
waiting. Counts and times only: no message text, person, chat or saved-reply
name is ever published.

Like the runtime configuration receipts, a status is renewed while its worker
runs and removed when it stops. One that is not renewed is reported as not
current, never as nothing held. Statuses are local to this computer.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import secrets
import threading
import time
from pathlib import Path

FRESH_SECONDS = 100
RENEW_SECONDS = 30
_SCHEMA = 1
_MAX_FILES = 1000
_MAX_BYTES = 65_536
_MAX_COUNT = 10_000_000
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
_COUNTS = ("held", "behind_unreadable", "unreadable", "release_at", "went_ahead", "went_ahead_at")
log = logging.getLogger(__name__)


def _directory():
    from maverick.config import config_path
    return config_path().parent / "channel-holds"


def _count(value):
    return type(value) is int and 0 <= value <= _MAX_COUNT


def _moment(value):
    return value is None or (type(value) in (int, float) and math.isfinite(value) and value >= 0)


def _checked(counts):
    """The six published numbers, or ValueError for anything else."""
    if not isinstance(counts, dict) or set(counts) != set(_COUNTS):
        raise ValueError("Held reply status has unexpected fields")
    if not all(_count(counts[key]) for key in ("held", "behind_unreadable", "unreadable", "went_ahead")):
        raise ValueError("Held reply counts must be whole numbers")
    if not (_moment(counts["release_at"]) and _moment(counts["went_ahead_at"])):
        raise ValueError("Held reply times must be finite")
    # Each unreadable earlier reply holds at least one reply behind it.
    if counts["behind_unreadable"] > counts["held"] or counts["unreadable"] > counts["behind_unreadable"]:
        raise ValueError("Held reply counts do not add up")
    return {key: counts[key] for key in _COUNTS}


class Publisher:
    """One worker's status: written when it changes and renewed every
    ``renew_seconds`` by its own thread, so a worker busy with a long reply
    still reads as current. Writing never raises into the worker."""

    def __init__(self, channel, *, directory=None, clock=time.time, renew_seconds=RENEW_SECONDS):
        if not isinstance(channel, str) or not _NAME.fullmatch(channel):
            raise ValueError("Unknown chat channel")
        self.channel = channel
        self.directory = Path(directory) if directory is not None else _directory()
        self.clock = clock
        self.renew_seconds = renew_seconds
        self.instance = channel + "-" + str(os.getpid()) + "-" + secrets.token_hex(8)
        self.path = self.directory / (self.instance + ".enc")
        self._lock = threading.Lock()
        self._counts = None
        self._changed = threading.Event()
        self._stop = threading.Event()
        self._failing = False
        self._thread = None

    def update(self, counts):
        """Take the worker's current counts; a change is written at once."""
        counts = _checked(counts)
        with self._lock:
            changed, self._counts = counts != self._counts, counts
        if changed:
            self._changed.set()

    def write_now(self):
        """Write the latest counts once. True when the status was saved."""
        with self._lock:
            counts = self._counts
        if counts is None or self._stop.is_set():
            return False
        record = {"schema": _SCHEMA, "channel": self.channel, "instance": self.instance,
                  "seen_at": self.clock(), **counts}
        try:
            from maverick.crypto_at_rest import deployment_key_scope, seal
            from maverick.file_lock import atomic_write_bytes, ensure_private_directory

            ensure_private_directory(self.directory)
            with deployment_key_scope():
                atomic_write_bytes(self.path, seal(json.dumps(record).encode()), mode=0o600)
        except Exception:
            if not self._failing:
                log.warning("Channel %s could not save its held chat replies status for the Channels page; "
                            "it is tried again at each change and every %d seconds", self.channel,
                            int(self.renew_seconds))
            self._failing = True
            return False
        self._failing = False
        return True

    def start(self):
        """Clear statuses left by stopped processes, then publish and renew."""
        try:
            for path in list(self.directory.glob("*.enc"))[:_MAX_FILES]:
                try:
                    if path.stat().st_mtime < time.time() - 7 * 86400:
                        path.unlink()
                except OSError:
                    pass
        except OSError:
            pass
        self._changed.set()

        def renew():
            while not self._stop.is_set():
                self._changed.wait(self.renew_seconds)
                if self._stop.is_set():
                    return
                self._changed.clear()
                self.write_now()

        self._thread = threading.Thread(target=renew, name="channel-hold-status:" + self.channel, daemon=True)
        self._thread.start()
        return self

    def close(self):
        """Stop renewing and remove the status: a stopped worker holds nothing
        it can report, and its saved replies are held again when it restarts."""
        self._stop.set()
        self._changed.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def _parse(blob, now):
    from maverick.crypto_at_rest import deployment_key_scope, unseal

    with deployment_key_scope():
        record = json.loads(unseal(blob))
    if (not isinstance(record, dict) or record.get("schema") != _SCHEMA
            or not isinstance(record.get("channel"), str) or not _NAME.fullmatch(record["channel"])
            or not isinstance(record.get("instance"), str) or type(record.get("seen_at")) not in (int, float)
            or not math.isfinite(record["seen_at"])):
        raise ValueError("invalid held reply status")
    counts = _checked({key: record.get(key) for key in _COUNTS} if set(_COUNTS) <= set(record) else None)
    return {"schema": _SCHEMA, "channel": record["channel"], "instance": record["instance"],
            "seen_at": record["seen_at"], "fresh": 0 <= now - record["seen_at"] < FRESH_SECONDS, **counts}


def records(*, directory=None, now=None):
    """(statuses, unavailable): every status on this computer, each marked
    fresh or not, and whether any could not be read."""
    folder = Path(directory) if directory is not None else _directory()
    now = time.time() if now is None else now
    try:
        paths = list(folder.glob("*.enc"))
    except OSError:
        return [], True
    if len(paths) > _MAX_FILES:
        return [], True
    found, unavailable = [], False
    for path in paths:
        try:
            if path.stat().st_size > _MAX_BYTES:
                raise ValueError("held reply status exceeds limit")
            found.append(_parse(path.read_bytes(), now))
        except FileNotFoundError:
            continue  # its worker stopped while this was read
        except Exception:
            unavailable = True
    return found, unavailable


def summary(enabled, *, directory=None, now=None):
    """What the turned-on chat apps hold, in one state.

    ``off``: no app that holds replies is turned on. ``holding`` or ``clear``:
    the current statuses, added up, with ``not_reporting`` naming any turned-on
    app with no current status. ``stale``: none is current, and ``last_seen``
    is when one was last renewed. ``not_reporting``: none was found.
    ``unavailable``: none could be read. ``unavailable`` is also True beside a
    current answer when another status could not be read."""
    found, unavailable = records(directory=directory, now=now)
    state = {"state": "off", "held": 0, "behind_unreadable": 0, "unreadable": 0, "release_at": None,
             "went_ahead": 0, "went_ahead_at": None, "not_reporting": [], "last_seen": None,
             "unavailable": unavailable}
    enabled = sorted(set(enabled))
    if not enabled:
        return state
    latest = {}
    for record in found:
        channel = record["channel"]
        if channel in enabled and (channel not in latest or record["seen_at"] > latest[channel]["seen_at"]):
            latest[channel] = record
    current = [record for record in latest.values() if record["fresh"]]
    if not current:
        if latest:
            state.update(state="stale", last_seen=max(record["seen_at"] for record in latest.values()))
        else:
            state["state"] = "unavailable" if unavailable else "not_reporting"
        return state
    for key in ("held", "behind_unreadable", "unreadable", "went_ahead"):
        state[key] = sum(record[key] for record in current)
    releases = [record["release_at"] for record in current if record["release_at"] is not None]
    went = [record["went_ahead_at"] for record in current if record["went_ahead_at"] is not None]
    state.update(state="holding" if state["held"] else "clear",
                 release_at=min(releases) if releases else None,
                 went_ahead_at=max(went) if went else None,
                 not_reporting=[channel for channel in enabled
                                if channel not in {record["channel"] for record in current}])
    return state
