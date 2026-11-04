"""Join reported business outcomes and distinct local learning signals.

A reported invoice/payment/renewal result takes precedence over a later local
rating, sign-off or execution verdict for the same episode. Reports remain
reports: this store does not independently authenticate an external business
system or certify the submitted fact. Entry points retain their actor policy.
Without a business report, the latest local signal is the compatibility fallback.
All accepted events remain in append order; reads use the retained bounded tail.
The data-engine join consumes these signals only while [consequence] is enabled.
"""
from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .config import governed_learning_env_flag

log = logging.getLogger(__name__)

_MAX_ROWS = 100_000
_MAX_TAIL_BYTES = 64 * 1024 * 1024
_SOURCES = frozenset({"reported_business", "human_feedback", "execution_verdict"})


class ConsequenceWriteUncertain(RuntimeError):
    """The attempted report may be present; do not automatically submit it again."""


def _discard_torn_tail(fd, end):
    """Drop an unterminated final row left by an interrupted append.

    Readers only ever see newline-terminated rows and the interrupted writer
    never confirmed it, so every visible record is kept. The caller holds the
    journal lock. Returns the new end of the journal.
    """
    keep = end
    while keep > 0:
        start = max(0, keep - 64 * 1024)
        os.lseek(fd, start, os.SEEK_SET)
        newline = os.read(fd, keep - start).rfind(b"\n")
        if newline >= 0:
            keep = start + newline + 1
            break
        keep = start
    os.ftruncate(fd, keep)
    os.fsync(fd)
    if os.fstat(fd).st_size != keep:
        raise OSError("consequence repair could not be verified")
    log.warning("Discarded an incomplete final row from an interrupted consequence journal append")
    return keep


def _append(path, row):
    raw = (json.dumps(row, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
    try:
        end = os.fstat(fd).st_size
        try:
            if end:
                os.lseek(fd, end - 1, os.SEEK_SET)
                if os.read(fd, 1) != b"\n":
                    # Never join a new report onto a torn prior row.
                    end = _discard_torn_tail(fd, end)
        except OSError:
            return False  # Nothing of this report was written.
        try:
            if os.write(fd, raw) != len(raw):
                raise OSError("incomplete consequence append")
            os.fsync(fd)
            return True
        except OSError:
            try:
                os.lseek(fd, end, os.SEEK_SET)
                suffix = os.read(fd, len(raw) + 1)
                if (os.fstat(fd).st_size != end + len(suffix)
                        or len(suffix) > len(raw) or suffix != raw[:len(suffix)]):
                    raise OSError("consequence suffix changed during cleanup")
                os.ftruncate(fd, end)
                os.fsync(fd)
                if os.fstat(fd).st_size != end:
                    raise OSError("consequence cleanup could not be verified")
                return False
            except OSError as error:
                raise ConsequenceWriteUncertain("The report may have been written. Its original outcome is unconfirmed; do not automatically submit it again.") from error
    finally:
        try:
            os.close(fd)
        except OSError as error:
            raise ConsequenceWriteUncertain("The report may have been written. Its original outcome is unconfirmed; do not automatically submit it again.") from error


def _source(kind, source=None):
    if source is not None:
        return source if isinstance(source, str) and source in _SOURCES else None
    # Legacy native local kinds are recognizable; unknown old reports retain
    # compatibility, without claiming they came from an authenticated connector.
    kind = str(kind).strip().lower()
    if kind in {"feedback", "signoff", "edit"}:
        return "human_feedback"
    return "execution_verdict" if kind == "failed" else "reported_business"


def _tail_lines(path, maximum):
    """Read only complete rows from the retained bounded native journal tail."""
    with Path(path).open("rb") as fh:
        end = fh.seek(0, os.SEEK_END)
        start = max(0, end - _MAX_TAIL_BYTES)
        fh.seek(start)
        raw = fh.read(_MAX_TAIL_BYTES)
    if start:
        raw = raw.partition(b"\n")[2]
    limit = min(max(0, maximum), _MAX_ROWS)
    return raw.split(b"\n")[:-1][-limit:] if limit else []


def enabled() -> bool:
    """Whether the default-on data-engine join should prefer real outcomes."""
    _v = governed_learning_env_flag("MAVERICK_CONSEQUENCE")
    if _v is not None:
        return _v
    try:
        from .config import get_consequence

        return bool(get_consequence().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def _clamp(value: float) -> float:
    try:
        number = float(value)
        return max(0.0, min(1.0, number)) if math.isfinite(number) else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


@dataclass
class ConsequenceStore:
    """Append-only classified signals, keyed (goal_id, episode_id).

    Latest business report wins within its class; local signals never replace it.
    The retained read window is the latest max_rows lines, up to 64 MiB. This is
    a learning-signal projection, not a complete-history audit or external proof.
    """

    path: Path | None = None
    max_rows: int = _MAX_ROWS
    _latest: dict = None  # type: ignore[assignment]
    _lock: threading.Lock = None  # type: ignore[assignment]
    _loaded_stamp: tuple | None = None
    _order: int = 0

    def __post_init__(self) -> None:
        if self._lock is None:
            self._lock = threading.Lock()
        if self._latest is None:
            self._latest = {}
        if self.path is not None:
            self._refresh()

    def record(self, goal_id: int, episode_id: int, value: float, *, kind: str = "",
               ts: float | None = None, source: str | None = None) -> bool:
        """Append a classified episode signal; invalid provenance is refused."""
        origin = _source(kind, source)
        try:
            stamp = time.time() if ts is None else float(ts)
        except (TypeError, ValueError, OverflowError):
            return False
        if origin is None or isinstance(ts, bool) or not math.isfinite(stamp) or stamp < 0:
            return False
        key = (int(goal_id), int(episode_id))
        row = {"ts": stamp, "goal_id": key[0], "episode_id": key[1],
               "value": _clamp(value), "kind": str(kind)[:64], "source": origin}
        with self._lock:
            if self.path is None:
                self._accept(row)
                return True
            try:
                from .file_lock import cross_process_lock

                p = Path(self.path)
                with cross_process_lock(p, strict=True):
                    if not _append(p, row):
                        return False
                    # Reload at the next read, outside any caller's world write
                    # transaction. Neither failed appends nor stale worker caches
                    # become an authoritative in-memory result.
                    self._loaded_stamp = ()
                return True
            except ConsequenceWriteUncertain:
                self._loaded_stamp = ()
                raise
            except Exception:  # pragma: no cover -- best-effort
                log.debug("consequence record failed", exc_info=True)
                return False

    def resolve(self, goal_id: int, episode_id: int) -> float | None:
        """Latest reported business result, otherwise the latest local signal."""
        with self._lock:
            if not self._refresh():
                return None
            signals = self._latest.get((int(goal_id), int(episode_id)))
            hit = (signals.get("reported_business") or max(signals.values(), key=lambda item: (item[0], item[1]))) if signals else None
            return hit[2] if hit else None

    def count(self) -> int:
        """Distinct episodes with a signal in the retained learning read window."""
        with self._lock:
            return len(self._latest) if self._refresh() else 0

    def _accept(self, row):
        key = (int(row["goal_id"]), int(row["episode_id"]))
        ts = float(row.get("ts", 0.0))
        source = _source(row.get("kind", ""), row.get("source"))
        if source is None or isinstance(row.get("ts"), bool) or not math.isfinite(ts) or ts < 0:
            return
        value = _clamp(row["value"])
        self._order += 1
        signals = self._latest.setdefault(key, {})
        previous = signals.get(source)
        if previous is None or ts >= previous[0]:
            signals[source] = (ts, self._order, value)

    def _refresh(self):
        if self.path is None:
            return True
        try:
            from .file_lock import cross_process_lock

            path = Path(self.path)
            try:
                info = path.stat()
            except FileNotFoundError:
                self._latest.clear()
                self._loaded_stamp = None
                return True
            stamp = (info.st_ino, info.st_size, info.st_mtime_ns)
            if stamp != self._loaded_stamp:
                with cross_process_lock(path, strict=True):
                    self._load()
                    info = path.stat()
                    self._loaded_stamp = (info.st_ino, info.st_size, info.st_mtime_ns)
            return True
        except (OSError, RuntimeError, ValueError):
            log.debug("consequence read unavailable")
            return False

    def _load(self) -> None:
        lines = _tail_lines(self.path, self.max_rows)
        self._latest.clear()
        self._order = 0
        for line in lines:
            try:
                self._accept(json.loads(line))
            except (KeyError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
                continue


_shared: dict = {}
_shared_lock = threading.Lock()


def shared() -> ConsequenceStore:
    from .paths import data_dir

    path = data_dir("consequences.ndjson")
    with _shared_lock:
        store = _shared.get(path)
        if store is None:
            store = ConsequenceStore(path=path)
            _shared[path] = store
        return store


def reset_shared() -> None:
    with _shared_lock:
        _shared.clear()
    with _shared_corr_lock:
        _shared_corr.clear()


def record_outcome(goal_id: int, episode_id: int, value: float, *, kind: str = "",
                   store: ConsequenceStore | None = None, source: str | None = None) -> bool:
    """Record a reported business result or explicitly classified local signal.

    Source identifies the signal category, not verified external authenticity.
    Omitted source recognizes known legacy local kinds; other direct reports
    remain reported_business. The data-engine join is gated by [consequence].
    """
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("consequence"):
        return False
    return (store or shared()).record(goal_id, episode_id, value, kind=kind, source=source)


def resolve(goal_id: int, episode_id: int, *, store: ConsequenceStore | None = None) -> float | None:
    """Preferred recorded signal for an episode, otherwise None."""
    return (store or shared()).resolve(goal_id, episode_id)


def count(*, store: ConsequenceStore | None = None) -> int:
    """Distinct episodes with a recorded signal in the retained read window."""
    return (store or shared()).count()


def grounded_outcome(goal_id: int, episode_id: int, proxy: float | None, *,
                     store: ConsequenceStore | None = None) -> float | None:
    """Prefer reported business evidence, then local signals, then the proxy.

    A reported result is not independently certified by this join. A no-op
    (returns proxy) unless [consequence] is enabled.
    """
    if not enabled():
        return proxy
    real = resolve(goal_id, episode_id, store=store)
    return real if real is not None else proxy


def record_self_outcome(world, goal_id: int, value: float, *, kind: str,
                        store: ConsequenceStore | None = None) -> bool | None:
    """Record a local first-party signal against a goal's latest episode.

    The single helper for the outcomes Lightwork observes directly -- a human's
    certify/reject, a thumbs-up/down, or the run's own terminal failure -- as
    opposed to :func:`record_outcome`, which a system-of-record connector calls
    with an episode id it already knows. Resolves the episode from ``world``
    (duck-typed: needs ``list_episodes(goal_id=, limit=)``). A no-op returning
    ``False`` when ``[consequence]`` is explicitly disabled, and never raises --
    grounding is best-effort and must not fail the
    action that produced it. None means an append could not be confirmed after
    cleanup failed; callers must not relabel it as a confirmed refusal."""
    try:
        if not enabled():
            return False
        episodes = world.list_episodes(goal_id=goal_id, limit=1)
        if not episodes:
            return False
        source = "human_feedback" if str(kind).strip().lower() in {"feedback", "signoff", "edit"} else "execution_verdict"
        return record_outcome(goal_id, episodes[0].id, float(value), kind=kind, store=store, source=source)
    except ConsequenceWriteUncertain:
        log.warning("Optional local signal may have been written; original outcome unconfirmed for goal %s", goal_id)
        return None
    except Exception:  # pragma: no cover -- grounding is best-effort
        log.debug("self-outcome not recorded for goal %s", goal_id, exc_info=True)
        return False


# ---- outcome correlation: external business key -> the episode that acted ----
#
# The Consequence Engine keys reward on ``(goal_id, episode_id)``, but a system
# of record reports back with only the business key it owns -- ``invoice INV-42
# was paid``, ``ticket 91 reopened``. This store is the join that lets a webhook
# ground an outcome with just that key: the run that acted on the entity links
# the key to its episode, and the outcome ingest resolves the key back. This is
# what makes the marquee "weeks later reality reports back" signal reachable from
# an integration that has never heard of an episode id.

_MAX_LINKS = 100_000


@dataclass
class CorrelationStore(ConsequenceStore):
    """Append-only map ``external key -> (goal_id, episode_id)`` that acted on it.

    The latest link for a key wins (the most recent run to touch the entity owns
    the outcome). Atomic-append, 0600, bounded -- the ``ConsequenceStore`` shape.
    """

    max_rows: int = _MAX_LINKS

    def link(self, key: str, goal_id: int, episode_id: int, *,
             ts: float | None = None) -> bool:
        """Save a link; an uncertain durable write must never invite replay."""
        k = str(key).strip()
        try:
            stamp = time.time() if ts is None else float(ts)
        except (TypeError, ValueError, OverflowError):
            return False
        if not k or len(k) > 256 or isinstance(ts, bool) or not math.isfinite(stamp) or stamp < 0:
            return False
        row = {"ts": stamp, "key": k,
               "goal_id": int(goal_id), "episode_id": int(episode_id)}
        with self._lock:
            if self.path is None:
                self._accept(row)
                return True
            try:
                from .file_lock import cross_process_lock

                p = Path(self.path)
                with cross_process_lock(p, strict=True):
                    if not _append(p, row):
                        return False
                    self._loaded_stamp = ()
                return True
            except ConsequenceWriteUncertain:
                self._loaded_stamp = ()
                raise
            except Exception:  # pragma: no cover -- best-effort
                log.debug("outcome-link record failed", exc_info=True)
                return False

    def resolve(self, key: str) -> tuple[int, int] | None:
        """The (goal_id, episode_id) most recently linked to ``key``, or None."""
        with self._lock:
            if not self._refresh():
                return None
            hit = self._latest.get(str(key).strip())
            return (hit[1], hit[2]) if hit is not None else None

    def count(self) -> int:
        with self._lock:
            return len(self._latest) if self._refresh() else 0

    def _accept(self, row):
        key, ts = str(row["key"]), float(row.get("ts", 0.0))
        if not key.strip() or len(key) > 256 or isinstance(row.get("ts"), bool) or not math.isfinite(ts) or ts < 0:
            return
        previous = self._latest.get(key)
        if previous is None or ts >= previous[0]:
            self._latest[key] = (ts, int(row["goal_id"]), int(row["episode_id"]))

    def _load(self) -> None:
        lines = _tail_lines(self.path, self.max_rows)
        self._latest.clear()
        for raw in lines:
            try:
                self._accept(json.loads(raw))
            except (KeyError, ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
                continue


_shared_corr: dict = {}
_shared_corr_lock = threading.Lock()


def shared_correlation() -> CorrelationStore:
    from .paths import data_dir

    path = data_dir("outcome_links.ndjson")
    with _shared_corr_lock:
        store = _shared_corr.get(path)
        if store is None:
            store = CorrelationStore(path=path)
            _shared_corr[path] = store
        return store


def link_outcome_key(key: str, goal_id: int, episode_id: int, *,
                     store: CorrelationStore | None = None) -> bool:
    """Record that ``key`` (an external business id) was acted on by this episode,
    so a later outcome reported against ``key`` can be grounded. Always harmless."""
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("consequence", "link_outcome_key"):
        return False
    return (store or shared_correlation()).link(key, goal_id, episode_id)


def record_outcome_for_key(key: str, value: float, *, kind: str = "",
                           store: ConsequenceStore | None = None,
                           corr: CorrelationStore | None = None,
                           authorize=None, source: str | None = None) -> bool:
    """Ground a downstream outcome using only the external business ``key``.

    Resolves ``key`` to the episode that acted (via the correlation store) and
    records the grounded reward there. ``authorize(goal_id, episode_id) -> bool``,
    when given, must approve the resolved target first (the caller's access
    check). Returns ``True`` when a correlation existed, was authorized, and the
    outcome was recorded; ``False`` when no run has linked that key yet, or the
    caller may not ground that target."""
    hit = (corr or shared_correlation()).resolve(key)
    if hit is None:
        return False
    goal_id, episode_id = hit
    if authorize is not None and not authorize(goal_id, episode_id):
        return False
    return record_outcome(goal_id, episode_id, value, kind=kind, store=store, source=source)


__all__ = [
    "ConsequenceStore", "ConsequenceWriteUncertain", "enabled", "shared", "reset_shared",
    "record_outcome", "resolve", "grounded_outcome", "count",
    "record_self_outcome",
    "CorrelationStore", "shared_correlation", "link_outcome_key",
    "record_outcome_for_key",
]
