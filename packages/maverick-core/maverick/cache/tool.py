"""Tool-output cache: memoize side-effect-free tool calls within a process.

Default OFF. When enabled, the result of a *read-only* tool call — one whose
``Tool.parallel_safe`` is ``True`` (repo_map, read_file, list_dir, dep_graph,
...) — is memoized keyed on ``(tool_name, canonical(args))``. A bounded LRU keeps
memory flat; an optional TTL bounds staleness. Tools that write the workspace,
shell out, send a message, or otherwise have side effects are *never* cached
(``parallel_safe`` is the same invariant the agent loop uses to decide a tool is
safe to run concurrently). Error results (``ERROR: ...``) are never cached so a
transient failure is not pinned.

Enable with ``MAVERICK_TOOL_CACHE=1`` or ``[tools] output_cache = true``. Tune
with ``[tools] output_cache_size`` (entries, default 256) and
``[tools] output_cache_ttl_s`` (seconds, 0 = no expiry, default 0).

**Warm-on-start** (default OFF): with ``[tools] output_cache_snapshot = true``
(or ``MAVERICK_TOOL_CACHE_SNAPSHOT=1``), the cache persists entries to a JSONL
snapshot under ``~/.maverick/`` and reloads the still-fresh ones on the first
lookup of the next process, so a rerun starts with yesterday's repo_map instead
of a cold cache. Entries carry a wall-clock stamp; TTL is re-checked at load.

Thread-safe; lookups/stores never raise into the tool path.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .. import fastjson as _fastjson
from ..paths import data_dir

_DEFAULT_SIZE = 256
_lock = threading.Lock()
_snapshot_lock = threading.RLock()
log = logging.getLogger(__name__)
# key -> (value, stored_at_monotonic, stored_at_epoch)
_store: OrderedDict[str, tuple[str, float, float]] = OrderedDict()
_hits = 0
_misses = 0
_warmed = False
_generation = 0
_epoch: str | None = None


def _sync_epoch() -> str | None:
    """Discard local entries when another worker has invalidated their generation."""
    global _epoch, _generation
    from .epoch import local_epoch
    from .redis_tool import enabled as redis_enabled

    try:
        shared = _shared_backend() if redis_enabled() else None
        token = shared.epoch() if shared is not None else (None if redis_enabled() else local_epoch())
    except Exception:
        token = None
    with _lock:
        if token != _epoch or token is None:
            _store.clear()
            _generation += 1
            _epoch = token
    return token


def _env_true(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _cfg() -> dict:
    try:
        from ..config import load_config
        return (load_config() or {}).get("tools", {}) or {}
    except Exception:  # pragma: no cover -- config never blocks the cache
        return {}


def enabled() -> bool:
    """Whether the tool-output cache is on (default OFF)."""
    if _env_true("MAVERICK_TOOL_CACHE"):
        return True
    return bool(_cfg().get("output_cache", False))


def _maxsize() -> int:
    try:
        n = int(_cfg().get("output_cache_size", _DEFAULT_SIZE))
        return n if n > 0 else _DEFAULT_SIZE
    except (TypeError, ValueError):
        return _DEFAULT_SIZE


def _ttl_s() -> float:
    try:
        return max(0.0, float(_cfg().get("output_cache_ttl_s", 0)))
    except (TypeError, ValueError):
        return 0.0


def snapshot_enabled() -> bool:
    """Whether warm-on-start snapshot persistence is on (default OFF)."""
    if _env_true("MAVERICK_TOOL_CACHE_SNAPSHOT"):
        return True
    return bool(_cfg().get("output_cache_snapshot", False))


def _snapshot_path() -> Path:
    env = os.environ.get("MAVERICK_TOOL_CACHE_SNAPSHOT_PATH", "").strip()
    if env:
        return Path(env).expanduser()
    return data_dir("tool_cache_snapshot.jsonl")


def save_snapshot() -> int:
    """Persist current entries to the snapshot file. Returns entries written.

    Values are stored with their wall-clock stamp so the next process can
    re-apply the TTL. Best-effort: any I/O problem is swallowed (the cache
    must never break the tool path) and 0 is returned.
    """
    with _snapshot_lock:
        return _save_snapshot()


def _save_snapshot() -> int:
    if not snapshot_enabled():
        return 0
    try:
        token = _sync_epoch()
        if token is None:
            return 0
        path = _snapshot_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            rows = [(k, v, epoch) for k, (v, _mono, epoch) in _store.items()]
        tmp: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as fh:
                tmp = Path(fh.name)
                for k, v, epoch in rows:
                    fh.write(_fastjson.dumps({"k": k, "v": v, "t": epoch, "generation": token}) + "\n")
            os.replace(tmp, path)
        finally:
            if tmp is not None:
                tmp.unlink(missing_ok=True)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return len(rows)
    except Exception:  # pragma: no cover -- snapshot is best-effort
        return 0


def warm_on_start() -> int:
    """Load still-fresh snapshot entries into the cache. Returns entries loaded.

    Idempotent per process (the first call wins). TTL is enforced against the
    entry's wall-clock stamp; expired rows are skipped. Capped at the
    configured cache size. Best-effort: a missing/corrupt snapshot loads 0.
    """
    with _snapshot_lock:
        return _warm_on_start()


def _warm_on_start() -> int:
    global _warmed
    with _lock:
        if _warmed:
            return 0
        _warmed = True
    if not (enabled() and snapshot_enabled()):
        return 0
    try:
        token = _sync_epoch()
        if token is None:
            return 0
        path = _snapshot_path()
        if not path.exists():
            return 0
        ttl = _ttl_s()
        now_epoch = time.time()
        now_mono = time.monotonic()
        cap = _maxsize()
        loaded = 0
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = _fastjson.loads(line)
                    if row.get("generation") != token:
                        continue
                    k, v, epoch = str(row["k"]), str(row["v"]), float(row["t"])
                except (ValueError, TypeError, KeyError):
                    continue  # tolerate a corrupt / partial line
                age = max(0.0, now_epoch - epoch)
                if ttl and age > ttl:
                    continue
                with _lock:
                    if len(_store) >= cap:
                        break
                    # Backdate the monotonic stamp so the remaining TTL is right.
                    _store[k] = (v, now_mono - age, epoch)
                    loaded += 1
        return loaded
    except Exception:  # pragma: no cover -- warm is best-effort
        return 0


def cacheable(tool: Any) -> bool:
    """Only side-effect-free (``parallel_safe``) tools may be memoized."""
    # These tools default omitted dates to the current clock. Their verdicts
    # can change while identical arguments remain in an unlimited-TTL cache.
    temporal = {"consent_check", "retention_check", "breach_notification", "coordinated_disclosure"}
    return getattr(tool, "parallel_safe", False) is True and getattr(tool, "name", "") not in temporal


def _key(
    tool_name: str,
    args: dict[str, Any],
    *,
    namespace: str = "",
) -> str:
    try:
        canon = json.dumps(args or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canon = repr(args)
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:24]
    if not namespace:
        # Preserve the legacy key form for direct callers in the shared,
        # unauthenticated namespace and for old warm-cache snapshots.
        return f"{tool_name}:{digest}"
    # Hash the scope before persisting it in the optional warm-cache snapshot:
    # user and tenant identifiers are authorization metadata, not cache data.
    scope = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:24]
    return f"{tool_name}:{scope}:{digest}"


def get_cached(
    tool: Any,
    args: dict[str, Any],
    *,
    namespace: str = "",
) -> tuple[bool, str | None]:
    """Return ``(hit, value)``. ``(False, None)`` when disabled / not cacheable /
    missing / expired."""
    global _hits, _misses
    if not cacheable(tool) or not enabled():
        return (False, None)
    token = _sync_epoch()
    if token is None:
        return (False, None)
    if not _warmed:
        warm_on_start()
    namespace = namespace + "|generation:" + token
    name = getattr(tool, "name", "")
    k = _key(name, args, namespace=namespace)
    ttl = _ttl_s()
    with _lock:
        entry = _store.get(k)
    if entry is None:
        # Shared tier ([tools] output_cache_backend = "redis"): a hit there
        # warms this process too. Same key scope as the local cache.
        with _snapshot_lock:
            shared = _shared_backend()
            hit, value = shared.get(name, args, scope=namespace) if shared else (False, None)
            with _lock:
                if hit and isinstance(value, str):
                    # Redis's existing API returns no age/remaining TTL.
                    # Keep expiring hits in that authoritative tier so warming
                    # cannot restart their lifetime in this process.
                    if not ttl:
                        _store[k] = (value, time.monotonic(), time.time())
                        while len(_store) > _maxsize():
                            _store.popitem(last=False)
                    _hits += 1
                    return (True, value)
                _misses += 1
                return (False, None)
    with _lock:
        entry = _store.get(k)
        if entry is None:
            _misses += 1
            return (False, None)
        value, stored_at, _epoch = entry
        if ttl and (time.monotonic() - stored_at) > ttl:
            del _store[k]
            _misses += 1
            return (False, None)
        _store.move_to_end(k)  # LRU bump
        _hits += 1
        return (True, value)


def store_cached(
    tool: Any,
    args: dict[str, Any],
    value: str,
    *,
    namespace: str = "",
    generation: int | None = None,
) -> None:
    """Memoize a successful, non-error result for a cacheable tool."""
    if not cacheable(tool) or not enabled():
        return
    if not isinstance(value, str) or value.startswith("ERROR:"):
        return
    token = _sync_epoch()
    if token is None:
        return
    namespace = namespace + "|generation:" + token
    name = getattr(tool, "name", "")
    k = _key(name, args, namespace=namespace)
    cap = _maxsize()
    with _snapshot_lock:
        with _lock:
            if generation is not None and generation != _generation:
                return
            _store[k] = (value, time.monotonic(), time.time())
            _store.move_to_end(k)
            while len(_store) > cap:
                _store.popitem(last=False)  # evict least-recently-used
        shared = _shared_backend()
        if shared is not None:
            shared.store(name, args, value, scope=namespace)


def generation() -> int:
    """Capture a cache epoch before executing a read outside the cache."""
    if enabled():
        _sync_epoch()
    with _lock:
        return _generation


_SHARED: dict[str, Any] = {}


def _shared_backend():
    """The Redis tier when ``[tools] output_cache_backend = "redis"`` (the
    environment wins), reused while its address and lifetime stay the same."""
    try:
        from . import redis_tool

        backend = redis_tool.from_config()
    except Exception:  # a cache must never break the tool path
        return None
    if backend is None:
        return None
    fingerprint = f"{backend.url}|{backend.ttl_s}"
    cached = _SHARED.get(fingerprint)
    if cached is None:
        _SHARED.clear()
        _SHARED[fingerprint] = cached = backend
    return cached


def stats() -> dict[str, int]:
    """``{hits, misses, size}`` — for the dashboard / tests."""
    with _lock:
        return {"hits": _hits, "misses": _misses, "size": len(_store)}


def reset() -> None:
    """Clear the cache and counters (tests / a fresh run)."""
    global _hits, _misses, _warmed, _generation
    with _lock:
        _generation += 1
        _store.clear()
        _hits = 0
        _misses = 0
        _warmed = False


def note_side_effect(tool: Any) -> None:
    """Invalidate cached reads after a side-effectful tool ran.

    ``parallel_safe=False`` is the registry's side-effect signal — a write,
    patch, shell command, or message send may have changed what any cached
    read (read_file, repo_map, ...) returned, so the whole store is dropped.
    Conservative over-invalidation is the price of correctness; the LRU
    re-warms on the next reads. Read-only tools leave the cache unchanged.
    Snapshot deletion is serialized with local saves and loads, preventing a
    concurrent save from putting this process's stale snapshot back on disk.
    Generation checks fence other workers and late read publication.
    An unavailable coordinator bypasses reads; a failed shared invalidation is
    logged as an error and still requires operator recovery (a purge) before
    shared caching can be trusted.
    """
    if cacheable(tool):
        return
    global _warmed
    with _snapshot_lock:
        from .epoch import local_epoch

        local_epoch(advance=True)
        shared = _shared_backend()
        if shared is not None and shared.epoch(advance=True) is None:
            log.error(
                "tool cache: could not advance the shared Redis generation after "
                "side-effect tool %r; other workers may serve pre-write results "
                "until the shared cache is purged",
                getattr(tool, "name", "?"),
            )
        purge()
        with _lock:
            _warmed = True
        try:
            _snapshot_path().unlink(missing_ok=True)
        except OSError:
            log.warning("could not invalidate tool-cache snapshot", exc_info=True)
        shared = _shared_backend()
        if shared is not None:
            shared.purge()


def purge(tool_name: str | None = None) -> int:
    """Drop cached entries -- all of them, or just those for ``tool_name``.

    Returns the number of entries removed. Unlike :func:`reset`, the hit/miss
    counters are left intact, so a targeted purge (e.g. after a tool's
    underlying data changed) doesn't throw away the run's hit-rate history.
    """
    global _generation
    with _lock:
        _generation += 1
        if tool_name:
            prefix = f"{tool_name}:"
            keys = [k for k in _store if k.startswith(prefix)]
            for k in keys:
                del _store[k]
            return len(keys)
        n = len(_store)
        _store.clear()
        return n


__all__ = [
    "enabled", "cacheable", "get_cached", "store_cached", "stats", "reset",
    "snapshot_enabled", "save_snapshot", "warm_on_start", "note_side_effect",
    "purge",
]
