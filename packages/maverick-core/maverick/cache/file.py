"""LRU cache for file reads + repo-map lookups.

Saves real money on long runs that re-read the same file repeatedly.
Two layers:

1. ``read_file_cached(path)`` — content cache keyed by (path, mtime,
   size). Bounded LRU; default 64 entries totalling ≤ 8 MiB.
2. ``repo_map_cached(workdir, ...)`` — a per-workdir snapshot of the
   repo-map output (the dir listing + heuristics). Keyed by workdir
   path + filesystem signature. Default 16 entries.

Cache invalidation:
  - Read cache: if file mtime / size changes since the cached read,
    we re-read.
  - Repo-map cache: if any visible file or directory in the recursively
    walked signature changes, we rebuild.

Thread-safe (RLock). Hot path — keep it dumb.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)


# Read cache: max entries + max total bytes.
_MAX_READ_ENTRIES = 64
_MAX_READ_BYTES = 8 * 1024 * 1024  # 8 MiB

_read_cache: OrderedDict[str, tuple[float, int, str, int]] = OrderedDict()
_read_cache_bytes = 0
_read_lock = threading.RLock()


def read_file_cached(
    path: str | os.PathLike,
    encoding: str = "utf-8",
    *,
    errors: str = "replace",
) -> str | None:
    """Return the file contents, served from cache when possible.

    Returns None if the file doesn't exist or can't be read. Errors
    during decode use ``errors`` (default 'replace').
    """
    p = Path(path)
    try:
        stat = p.stat()
    except OSError:
        return None
    mtime = stat.st_mtime
    size = stat.st_size
    cache_key = str(p.resolve())
    with _read_lock:
        cached = _read_cache.get(cache_key)
        if cached is not None and cached[0] == mtime and cached[1] == size:
            _read_cache.move_to_end(cache_key)
            return cached[2]
    # Cache miss — read from disk.
    try:
        text = p.read_text(encoding=encoding, errors=errors)
    except OSError:
        return None
    _put_read(cache_key, mtime, size, text)
    return text


def _put_read(key: str, mtime: float, size: int, text: str) -> None:
    global _read_cache_bytes
    # Account for the encoded byte length, not the code-point count: the
    # _MAX_READ_BYTES cap is a memory budget, and a non-ASCII file holds
    # several bytes per character, so len(text) undercounts and lets the cache
    # grow past its limit. Compute the byte length once here and stash it in
    # the entry so eviction below doesn't have to re-encode. (st_size isn't a
    # safe substitute: errors='replace' can change the decoded text's length.)
    nbytes = len(text.encode("utf-8", "replace"))
    with _read_lock:
        # Evict prior version if present.
        prior = _read_cache.pop(key, None)
        if prior is not None:
            _read_cache_bytes -= prior[3]
        _read_cache[key] = (mtime, size, text, nbytes)
        _read_cache_bytes += nbytes
        # Trim to limits.
        while (
            len(_read_cache) > _MAX_READ_ENTRIES
            or _read_cache_bytes > _MAX_READ_BYTES
        ):
            _, evicted = _read_cache.popitem(last=False)
            _read_cache_bytes -= evicted[3]


def clear_read_cache() -> None:
    """Drop everything in the read cache. Mainly useful in tests."""
    global _read_cache_bytes
    with _read_lock:
        _read_cache.clear()
        _read_cache_bytes = 0


def read_cache_stats() -> dict:
    """For observability: cache size + byte usage."""
    with _read_lock:
        return {
            "entries": len(_read_cache),
            "bytes": _read_cache_bytes,
            "max_entries": _MAX_READ_ENTRIES,
            "max_bytes": _MAX_READ_BYTES,
        }


# ---------- repo_map cache ----------

_MAX_REPO_ENTRIES = 16
_repo_cache: OrderedDict[str, tuple[str, str]] = OrderedDict()
_repo_lock = threading.RLock()


# Directories the repo map omits (its ``_IGNORE_DIRS``); the signature never
# descends into them. Other hidden directories (.hg, .svn, .gradle,
# .ruff_cache, ...) are shown by the map, so they stay visible to invalidation.
_SIG_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    "target", ".pytest_cache", ".mypy_cache", ".tox", ".idea", ".vscode",
    "coverage",
})

#: The repo map renders the top level and the children of top-level
#: directories; hidden entries below that depth never reach the map.
_SIG_HIDDEN_DEPTH = 2


def _sig_entry(entries: list, workdir: Path, path: Path, kind: str, with_mtime: bool) -> None:
    try:
        st = path.lstat()
    except OSError:
        return
    rel = os.path.relpath(path, workdir).replace(os.sep, "/")
    size = st.st_size if kind == "f" else 0
    entries.append((kind, rel, size, st.st_mtime if with_mtime else 0.0))


def _workdir_signature(workdir: Path) -> str:
    """Content-aware signature of ``workdir`` for repo-map cache invalidation.

    Recursively walks visible files and directories (skipping the directories
    the repo map omits) and digests each relative path plus cheap
    metadata. File entries include size+mtime as a proxy for content -- a full
    content hash would be more robust but too slow for a per-call probe; the
    vendor-dir skips keep the walk bounded. Directory entries include mtime so
    directory-only changes that affect the repo map also invalidate the cache.

    Hidden entries are tracked only as deep as the map renders them: a
    top-level hidden directory is listed but its subdirectories are not
    walked, and a deeper hidden directory is recorded by name only. Build
    caches (.gradle, .next, .yarn, ...) therefore cost one listing, not a walk.
    """
    try:
        entries: list[tuple[str, str, int, float]] = []
        for dirpath, dirnames, filenames in os.walk(workdir):
            rel_dir = Path(os.path.relpath(dirpath, workdir))
            # Depth of the entries listed here (1 = top level).
            depth = 1 if str(rel_dir) == "." else len(rel_dir.parts) + 1
            in_hidden = any(p.startswith(".") for p in rel_dir.parts)
            walk: list[str] = []
            for name in dirnames:
                if name in _SIG_SKIP_DIRS:
                    continue
                hidden = in_hidden or name.startswith(".")
                if hidden and depth > _SIG_HIDDEN_DEPTH:
                    continue
                # A hidden directory the map shows only by name is recorded
                # without mtime and not walked: its mtime moves with entries
                # the map never renders.
                descend = not hidden or depth < _SIG_HIDDEN_DEPTH
                _sig_entry(entries, workdir, Path(dirpath) / name, "d", descend)
                if descend:
                    walk.append(name)
            dirnames[:] = walk
            for name in filenames:
                if depth <= _SIG_HIDDEN_DEPTH or not (in_hidden or name.startswith(".")):
                    _sig_entry(entries, workdir, Path(dirpath) / name, "f", True)
        entries.sort()
    except OSError:
        return ""
    digest = hashlib.sha256()
    digest.update(repr(entries).encode())
    return digest.hexdigest()


def repo_map_cached(workdir: str | os.PathLike, builder: Callable[[], str]) -> str:
    """Return a cached repo-map string for ``workdir``, calling ``builder()``
    on cache miss or signature change."""
    p = Path(workdir).resolve()
    key = str(p)
    sig = _workdir_signature(p)
    with _repo_lock:
        cached = _repo_cache.get(key)
        if cached is not None and cached[0] == sig:
            _repo_cache.move_to_end(key)
            return cached[1]
    built = builder()
    with _repo_lock:
        _repo_cache[key] = (sig, built)
        while len(_repo_cache) > _MAX_REPO_ENTRIES:
            _repo_cache.popitem(last=False)
    return built


def clear_repo_cache() -> None:
    with _repo_lock:
        _repo_cache.clear()


__all__ = [
    "read_file_cached",
    "read_cache_stats",
    "clear_read_cache",
    "repo_map_cached",
    "clear_repo_cache",
]
