"""Cross-run learning cache: memoize verified sub-results across runs
.

Agents re-derive the same expensive facts every run — "this repo's build
command is ``make -j test``", "service Y's API schema is ...". Each
rediscovery burns tool calls and tokens to land on an answer a previous run
already proved. This cache persists those *verified* sub-results keyed by a
normalized task signature, so the next run (a different process, days later)
starts from the answer instead of the search.

Trust model — only verified results may be stored. ``put`` requires a
``verified_by`` provenance string (e.g. ``"verifier:goal-123"``) naming who
checked the result. That is deliberate friction: caching unverified model
output would let one hallucination poison every future run that hits the key.

SECURITY — never store secrets. The cache file outlives the run, so a leaked
credential in it would too. ``put`` runs both the task and the result through
``maverick.safety.secret_detector.scan`` and REFUSES (``ValueError``) to
store anything containing a detected secret; the caller must redact first or
not cache at all.

Normalization: tasks are lowercased, inner whitespace collapsed, and
punctuation stripped at the edges before hashing (sha256), so
``"Build  the APP."`` and ``"build the app"`` share one entry.

Hygiene: entries expire (default :data:`DEFAULT_TTL_DAYS`), the store is
capped at :data:`MAX_ENTRIES` entries evicted LRU by last use, and writes are
atomic (temp file + rename, mode 0600 — results may describe private
infrastructure).

Default OFF. ``enabled()`` reads ``MAVERICK_LEARNING_CACHE`` (env wins) or
``[memory] learning_cache``. When on, the orchestrator keys each goal by its
owner, title and details: a run starts with the verified answer an earlier
run of that exact task left (framed as untrusted history), and a run whose
answer the checker accepted stores it for next time. The clock is
injectable so TTL behavior is unit-testable.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import string
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from ..config import env_flag
from ..file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)

log = logging.getLogger(__name__)

DEFAULT_TTL_DAYS = 30.0
MAX_ENTRIES = 500
_DAY_SECONDS = 86_400.0
_MAX_SHARED_INSTANCES = 128


def _source_current(entry: dict, owner: str) -> bool:
    """Native recall requires a still-permitted source and its original owner."""
    from ..learning_content import allowed

    return (isinstance(owner, str) and type(entry.get("content_version")) is int
            and entry["content_version"] == 1 and type(entry.get("goal_id")) is int
            and entry["goal_id"] > 0 and allowed(entry, owner=owner))


def enabled() -> bool:
    """Whether the learning cache is on (default OFF).

    ``MAVERICK_LEARNING_CACHE=1`` (env wins) or ``[memory] learning_cache``.
    """
    flag = env_flag("MAVERICK_LEARNING_CACHE")
    if flag is not None:
        return flag
    try:
        from ..config import load_config
        return bool((load_config() or {}).get("memory", {}).get("learning_cache", False))
    except Exception:  # pragma: no cover -- config never blocks a caller
        return False


def normalize(task: str) -> str:
    """Canonical task text: lowercase, collapse whitespace, strip edge punctuation."""
    collapsed = " ".join((task or "").lower().split())
    return collapsed.strip(string.punctuation + string.whitespace)


def task_key(task: str) -> str:
    """Stable sha256 key for a task's normalized signature."""
    return hashlib.sha256(normalize(task).encode("utf-8")).hexdigest()


class LearningCache:
    """JSON-file-backed store of verified task -> result entries.

    ``path`` defaults to ``data_dir("learning_cache.json")`` (tenant-scoped
    under ``~/.maverick``). ``clock`` is injectable for TTL tests;
    ``max_entries`` is the LRU cap.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        max_entries: int = MAX_ENTRIES,
        clock: Callable[[], float] = time.time,
    ):
        if path is None:
            from ..paths import data_dir
            path = data_dir("learning_cache.json")
        self.path = Path(path).expanduser()
        self.max_entries = max(1, int(max_entries))
        self._clock = clock
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._entries: dict[str, dict] = self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> dict[str, dict]:
        try:
            ensure_private_directory(self.path.parent)
            ensure_private_file(self.path, 0o600)
            raw = json.loads(atomic_read_text(self.path))
            entries = raw.get("entries", {})
            if isinstance(entries, dict):
                return {str(k): dict(v) for k, v in entries.items() if isinstance(v, dict)}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            # Fail-open: a corrupt cache costs a re-derivation, never a crash.
            log.warning("learning cache: ignoring unreadable %s (%s)", self.path, exc)
        return {}

    @contextmanager
    def _synced(self) -> Iterator[None]:
        """Hold the thread and cross-process locks and reload from disk, so a
        read-modify-write starts from what other processes have saved instead
        of overwriting their entries with this instance's stale copy."""
        with self._lock, cross_process_lock(self.path):
            self._entries = self._load()
            yield

    def _save_locked(self) -> None:
        """Atomic write (temp + rename), 0600 — entries may be sensitive."""
        try:
            ensure_private_directory(self.path.parent)
            data = json.dumps({"version": 1, "entries": self._entries}, indent=0, sort_keys=True)
            atomic_write_text(self.path, data, mode=0o600)
        except OSError as exc:  # pragma: no cover -- disk trouble never raises out
            log.warning("learning cache: could not persist %s (%s)", self.path, exc)

    def _evict_locked(self) -> None:
        from .eviction import lru_keys_to_evict
        last_used = {k: e.get("last_used", 0.0) for k, e in self._entries.items()}
        for key in lru_keys_to_evict(last_used, self.max_entries):
            del self._entries[key]

    # -- API ----------------------------------------------------------------

    def put(
        self,
        task: str,
        result: str,
        *,
        verified_by: str,
        ttl_days: float = DEFAULT_TTL_DAYS,
        tags: list[str] | None = None,
        source_goal_id: int | None = None,
        source_owner: str | None = None,
    ) -> str:
        """Store a VERIFIED result for ``task``; returns the entry key.

        ``verified_by`` is required provenance (who checked this result).
        Raises ``ValueError`` for missing provenance, a non-positive TTL, or —
        see the module SECURITY note — a task/result containing a detected
        secret.
        """
        if not isinstance(verified_by, str) or not verified_by.strip():
            raise ValueError(
                "verified_by is required: name the verifier that checked this result "
                "(e.g. 'verifier:goal-123')"
            )
        ttl = float(ttl_days)
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("ttl_days must be finite and > 0")
        from ..safety.secret_detector import scan
        found = scan(str(result)) + scan(str(task))
        if found:
            kinds = ", ".join(sorted({m.name for m in found}))
            raise ValueError(
                f"refusing to cache an entry containing detected secret(s): {kinds} "
                "(the cache file outlives the run; redact before storing)"
            )
        now = float(self._clock())
        expires_at = now + ttl * _DAY_SECONDS
        if not math.isfinite(now) or not math.isfinite(expires_at):
            raise ValueError("Learning cache expiry must be finite")
        key = task_key(task)
        entry = {
            "task": normalize(task),
            "result": str(result),
            "verified_by": verified_by.strip(),
            "tags": [str(t) for t in (tags or [])],
            "stored_at": now,
            "expires_at": expires_at,
            "last_used": now,
        }
        bound_source = source_goal_id is not None or source_owner is not None
        if bound_source:
            entry.update(content_version=1, goal_id=source_goal_id, owner=source_owner)
            if not _source_current(entry, source_owner):
                raise ValueError("Learning cache source authority is unavailable")
        with self._synced():
            if bound_source and not _source_current(entry, source_owner):
                raise ValueError("Learning cache source authority changed before saving")
            self._entries[key] = entry
            self._evict_locked()
            self._save_locked()
        return key

    def get(self, task: str, *, source_owner: str | None = None) -> dict | None:
        """Return the entry for ``task`` (TTL-enforced), or ``None``.

        Native task recall must pass its exact owner. Such reads withhold
        unbound legacy results and recheck source permission before delivery.
        Omitting the owner retains the explicit generic maintenance helper.
        """
        key = task_key(task)
        now = float(self._clock())
        with self._synced():
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            from .eviction import is_expired
            expires_at = entry.get("expires_at", 0.0)
            if (type(expires_at) not in (int, float) or not math.isfinite(expires_at)
                    or is_expired(now, expires_at)):
                del self._entries[key]
                self._save_locked()
                self._misses += 1
                return None
            if source_owner is not None and not _source_current(entry, source_owner):
                self._misses += 1
                return None
            entry["last_used"] = now
            self._save_locked()
            if source_owner is not None and not _source_current(entry, source_owner):
                self._misses += 1
                return None
            self._hits += 1
            return dict(entry)

    def invalidate(self, task: str) -> bool:
        """Drop ``task``'s entry (e.g. the fact changed). True if one existed."""
        key = task_key(task)
        with self._synced():
            existed = self._entries.pop(key, None) is not None
            if existed:
                self._save_locked()
            return existed

    def prune(self) -> int:
        """Drop expired entries and enforce the LRU cap; returns entries removed."""
        now = float(self._clock())
        with self._synced():
            from .eviction import is_expired
            before = len(self._entries)
            self._entries = {
                k: e for k, e in self._entries.items()
                if type(expiry := e.get("expires_at", 0.0)) in (int, float)
                and math.isfinite(expiry) and not is_expired(now, expiry)
            }
            self._evict_locked()
            removed = before - len(self._entries)
            if removed:
                self._save_locked()
            return removed

    def stats(self) -> dict:
        """``{entries, hits, misses, path}`` — for the dashboard / tests."""
        with self._lock:
            return {
                "entries": len(self._entries),
                "hits": self._hits,
                "misses": self._misses,
                "path": str(self.path),
            }


_shared: OrderedDict[tuple[str | None, str], LearningCache] = OrderedDict()
_shared_lock = threading.Lock()


def shared() -> LearningCache:
    """Bounded lazy instances for each current exact tenant and data path."""
    from ..paths import current_tenant_id, data_dir

    path = data_dir("learning_cache.json")
    key = (current_tenant_id(), os.path.normcase(os.path.abspath(path)))
    with _shared_lock:
        cache = _shared.get(key)
        if cache is None:
            cache = LearningCache(path)
            _shared[key] = cache
        _shared.move_to_end(key)
        while len(_shared) > _MAX_SHARED_INSTANCES:
            _shared.popitem(last=False)
        return cache


def reset_shared() -> None:
    """Drop all process-wide instances (tests / explicit maintenance)."""
    with _shared_lock:
        _shared.clear()


__all__ = [
    "DEFAULT_TTL_DAYS", "MAX_ENTRIES", "LearningCache",
    "enabled", "normalize", "task_key", "shared", "reset_shared",
]
