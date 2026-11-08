"""Held chat replies as the Channels page and Copilot see them.

Signal and IRC keep each conversation's replies in order: a reply waits while
an earlier one in the same conversation waits for another attempt or cannot
be read (see transport_worker). The worker that holds them runs in the chat
service's process, so each running worker publishes a small sealed status
here: how many replies wait, how many wait behind a reply that cannot be read
and the time by which all of those go out regardless, how many could not be
sent and wait for another attempt, and how many went out without waiting.
Counts and times only: no message text, person, chat or saved-reply name is
ever published.

Like the runtime configuration receipts, a status is renewed while its worker
runs and removed when it stops (a process ended without a chance to stop,
such as on Windows, leaves it behind until the dashboard that started it sees
it end). One that is not renewed is reported as not current, never as nothing
held, and only a sealed status is ever read.
Statuses are local to this computer.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path

FRESH_SECONDS = 100
RENEW_SECONDS = 30
# A status stamped up to this far after the reader's clock is still current:
# a renewal can land between taking the time and reading the file, and two
# clocks can differ slightly. One stamped further ahead counts as no status.
_SKEW = 5
_CLOSE_WAIT = 2
_SCHEMA = 1
_MAX_FILES = 1000
_MAX_BYTES = 65_536
_MAX_COUNT = 10_000_000
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
# Set by the dashboard on a chat service it starts, so it can remove that
# service's statuses, and only those, once the service has ended.
OWNER_ENV = "MAVERICK_CHANNEL_HOLDS_OWNER"
_OWNER = re.compile(r"[0-9a-f]{16}")
_COUNTS = ("held", "behind_unreadable", "unreadable", "retrying", "release_at", "went_ahead", "went_ahead_at")
log = logging.getLogger(__name__)


def _directory():
    from maverick.config import config_path
    return config_path().parent / "channel-holds"


def _count(value):
    return type(value) is int and 0 <= value <= _MAX_COUNT


def _moment(value):
    return value is None or (type(value) in (int, float) and math.isfinite(value) and value >= 0)


def _checked(counts):
    """The published numbers, or ValueError for anything else."""
    if not isinstance(counts, dict) or set(counts) != set(_COUNTS):
        raise ValueError("Held reply status has unexpected fields")
    if not all(_count(counts[key]) for key in ("held", "behind_unreadable", "unreadable", "retrying", "went_ahead")):
        raise ValueError("Held reply counts must be whole numbers")
    if not (_moment(counts["release_at"]) and _moment(counts["went_ahead_at"])):
        raise ValueError("Held reply times must be finite")
    # Each unreadable earlier reply holds at least one reply behind it.
    if counts["behind_unreadable"] > counts["held"] or counts["unreadable"] > counts["behind_unreadable"]:
        raise ValueError("Held reply counts do not add up")
    return {key: counts[key] for key in _COUNTS}


def _app(path):
    """The chat app a status file belongs to, from its name, or ``unknown``."""
    name = path.name.split("-", 1)[0]
    return name if _NAME.fullmatch(name) else "unknown"


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
        owner = os.environ.get(OWNER_ENV, "")
        self.instance = "-".join([channel, *([owner] if _OWNER.fullmatch(owner) else []), str(os.getpid()),
                                  secrets.token_hex(8)])
        self.path = self.directory / (self.instance + ".enc")
        self._lock = threading.Lock()
        self._counts = None
        self._changed = threading.Event()
        self._stop = threading.Event()
        self._failing = False
        self._stamped = None  # seen_at of the last status saved
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
                            int(min(self.renew_seconds, _SKEW)))
            self._failing = True
            return False
        self._failing, self._stamped = False, record["seen_at"]
        if self._stop.is_set():
            # close() stopped waiting for this write and has already removed the status.
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
            return False
        return True

    def _clear_leftovers(self):
        """Remove statuses nobody renews: any a week old, any stamped ahead of
        the clock, and this app's from processes that stopped without removing
        theirs (a renewed one is at most RENEW_SECONDS old). Run at start,
        every FRESH_SECONDS while the worker runs (one left less than
        FRESH_SECONDS before the start is not yet known to be unrenewed) and
        at close. Only a private folder of this module's own is ever cleaned,
        never one another folder stands in for."""
        from maverick.file_lock import ensure_private_directory

        ensure_private_directory(self.directory)
        now = time.time()
        for path in list(self.directory.glob("*.enc"))[:_MAX_FILES]:
            try:
                if self._left_over(path, now):
                    path.unlink()
            except OSError:
                pass

    def _left_over(self, path, now):
        """Whether nobody renews the status at ``path``, judged by the time
        sealed in it: its worker took that from this computer's clock, while
        the file's own time can come from another (a file server's)."""
        if path == self.path:
            return path.lstat().st_mtime < now - 7 * 86400
        try:
            record = _parse(_read(path), now)
        except FileNotFoundError:
            return False  # its worker stopped while this was read
        except Exception:
            # Never read as current, so judged by its file time, and only
            # when it is a week old or this app's.
            changed = path.lstat().st_mtime
            return changed < now - 7 * 86400 or (
                _app(path) == self.channel and not now - FRESH_SECONDS <= changed <= now + _SKEW)
        # One stamped ahead was left before the clock was set back: readers
        # ignore it, and a running worker rewrites its own within seconds.
        return record["ahead"] or record["seen_at"] < now - 7 * 86400 or (
            record["channel"] == self.channel and not record["fresh"])

    def _tidy(self):
        try:
            self._clear_leftovers()
        except OSError:
            pass

    def start(self):
        """Clear statuses left by stopped processes, then publish and renew."""
        self._tidy()
        self._changed.set()

        def renew():
            # Renewed by the age of the last status on this computer's clock,
            # checked every few seconds: a wait alone does not count time
            # asleep, so after a laptop wakes, or the clock is changed, a
            # running worker would read as stopped until the wait ran out.
            tidied = time.monotonic()
            while not self._stop.is_set():
                changed = self._changed.wait(min(self.renew_seconds, _SKEW))
                if self._stop.is_set():
                    return
                age = None if self._stamped is None else self.clock() - self._stamped
                # A failed write is tried again at each check: the last status
                # still reads as current, with counts that may have changed.
                if changed or self._failing or age is None or not 0 <= age < self.renew_seconds:
                    self._changed.clear()
                    self.write_now()
                if time.monotonic() - tidied >= FRESH_SECONDS:
                    tidied = time.monotonic()
                    self._tidy()

        self._thread = threading.Thread(target=renew, name="channel-hold-status:" + self.channel, daemon=True)
        self._thread.start()
        return self

    def close(self):
        """Stop renewing and remove the status: a stopped worker holds nothing
        it can report, and its saved replies are held again when it restarts."""
        self._stop.set()
        self._changed.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=_CLOSE_WAIT)
        self._tidy()
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def _read(path):
    """The file's bytes: a regular file, never followed through a link, and
    never more than the limit (a pipe or device would otherwise never end)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BYTES:
            raise ValueError("held reply status is not a regular file within the limit")
        chunks, left = [], _MAX_BYTES + 1
        while left > 0:
            chunk = os.read(descriptor, left)
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        blob = b"".join(chunks)
        if len(blob) > _MAX_BYTES:
            raise ValueError("held reply status exceeds the limit")
        return blob
    finally:
        os.close(descriptor)


def _parse(blob, now):
    from maverick.crypto_at_rest import deployment_key_scope, is_sealed, unseal

    if not is_sealed(blob):
        raise ValueError("held reply status is not sealed")
    with deployment_key_scope():
        record = json.loads(unseal(blob))
    if (not isinstance(record, dict) or record.get("schema") != _SCHEMA
            or not isinstance(record.get("channel"), str) or not _NAME.fullmatch(record["channel"])
            or not isinstance(record.get("instance"), str) or type(record.get("seen_at")) not in (int, float)
            or not math.isfinite(record["seen_at"])):
        raise ValueError("invalid held reply status")
    counts = _checked({key: record.get(key) for key in _COUNTS} if set(_COUNTS) <= set(record) else None)
    age = now - record["seen_at"]
    return {"schema": _SCHEMA, "channel": record["channel"], "instance": record["instance"],
            "seen_at": record["seen_at"], "fresh": -_SKEW <= age < FRESH_SECONDS, "ahead": age < -_SKEW,
            **counts}


def records(*, directory=None, now=None):
    """(statuses, unreadable): every status on this computer, each marked fresh
    or not, and the apps whose status files could not be read (``unknown``
    when the folder itself could not be listed or a file names no app)."""
    folder = Path(directory) if directory is not None else _directory()
    now = time.time() if now is None else now
    try:
        paths = list(folder.glob("*.enc"))
    except OSError:
        return [], frozenset({"unknown"})
    if len(paths) > _MAX_FILES:
        return [], frozenset({"unknown"})
    found, unreadable = [], set()
    for path in paths:
        try:
            found.append(_parse(_read(path), now))
        except FileNotFoundError:
            continue  # its worker stopped while this was read
        except Exception:
            unreadable.add(_app(path))
    return found, frozenset(unreadable)


def clear_saved_before(moment, *, owner, directory=None):
    """Remove the statuses that the chat service started with ``owner`` (see
    OWNER_ENV) saved before ``moment``, once it has ended: one ended without a
    chance to remove its own (every stop on Windows) would otherwise stand in
    for it until its status is no longer current. Statuses of a chat service
    started some other way are left alone. When a status was saved is the
    time sealed in it, from this computer's clock; the file's own time, which
    can come from another clock, counts only for one that cannot be read.
    Never raises."""
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner):
        return
    try:
        from maverick.file_lock import ensure_private_directory

        directory = Path(directory) if directory is not None else _directory()
        if not directory.is_dir():
            return
        ensure_private_directory(directory)
        for path in list(directory.glob(f"*-{owner}-*.enc"))[:_MAX_FILES]:
            try:
                try:
                    saved = _parse(_read(path), moment)["seen_at"]
                except FileNotFoundError:
                    continue
                except Exception:
                    saved = path.lstat().st_mtime
                if saved <= moment:
                    path.unlink()
            except OSError:
                pass
    except Exception:  # noqa: BLE001 -- best effort: a status left behind still ages out
        log.warning("Held chat replies statuses of the stopped chat service could not be removed")


def summary(enabled, *, directory=None, now=None):
    """What the chat apps hold, in one state.

    ``off``: no app that holds replies is turned on or running. ``holding`` or
    ``clear``: the current statuses, added up. ``reporting`` names the apps
    with a current status, ``not_reporting`` any turned-on app without one,
    and ``running_off`` any app turned off in settings that the chat service
    still runs. ``stale``: no status is current, and ``last_seen`` is when one
    was last renewed. ``not_reporting``: none was found. ``unavailable``: the
    turned-on apps whose status could not be read, in every state; the state
    is ``unavailable`` only when no status, current or old, could be read.
    ``release_at`` is the time by which every reply held behind an unreadable
    one goes out regardless, and ``release_passed`` says it is already past."""
    now = time.time() if now is None else now
    found, unreadable = records(directory=directory, now=now)
    enabled = sorted(set(enabled))
    state = {"state": "off", "held": 0, "behind_unreadable": 0, "unreadable": 0, "retrying": 0,
             "release_at": None, "release_passed": False, "went_ahead": 0, "went_ahead_at": None,
             "reporting": [], "not_reporting": [], "running_off": [], "last_seen": None,
             "unavailable": sorted(name for name in unreadable if name in enabled or name == "unknown")}
    latest = {}
    for record in found:
        channel = record["channel"]
        # A status stamped ahead of this computer's clock (a leftover from
        # before the clock was set back) says nothing about now.
        if record["ahead"]:
            continue
        if channel not in latest or (record["fresh"], record["seen_at"]) > (latest[channel]["fresh"],
                                                                              latest[channel]["seen_at"]):
            latest[channel] = record
    latest = {channel: record for channel, record in latest.items() if channel in enabled or record["fresh"]}
    state["running_off"] = sorted(channel for channel, record in latest.items()
                                  if record["fresh"] and channel not in enabled)
    if not enabled and not state["running_off"]:
        return state
    current = [record for record in latest.values() if record["fresh"]]
    if not current:
        if latest:
            # Every status left is older than FRESH_SECONDS, so this time is in
            # the past and stays the same from one read to the next.
            state.update(state="stale", last_seen=max(record["seen_at"] for record in latest.values()),
                         not_reporting=enabled)
        else:
            state.update(state="unavailable" if state["unavailable"] else "not_reporting", not_reporting=enabled)
        return state
    for key in ("held", "behind_unreadable", "unreadable", "retrying", "went_ahead"):
        state[key] = sum(record[key] for record in current)
    releases = [record["release_at"] for record in current if record["release_at"] is not None]
    went = [record["went_ahead_at"] for record in current if record["went_ahead_at"] is not None]
    reporting = sorted(record["channel"] for record in current)
    state.update(state="holding" if state["held"] or state["retrying"] else "clear",
                 release_at=max(releases) if releases else None,
                 release_passed=bool(releases) and max(releases) <= now,
                 went_ahead_at=max(went) if went else None, reporting=reporting,
                 not_reporting=[channel for channel in enabled if channel not in reporting])
    return state
