"""Unified cache-purge surface.

Lightwork keeps a few process-local caches (file reads, repo-map
snapshots) and one on-disk cache (skill embeddings). This module
centralises clearing them so the CLI doesn't need to know each
backend's invalidation API.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

from ..paths import data_dir

log = logging.getLogger(__name__)


_VALID_SCOPES = ("files", "repo_map", "skill_embeddings", "all")


def stats() -> dict:
    """Return current cache sizes for the in-process caches."""
    from .file import read_cache_stats
    out: dict = {"files": read_cache_stats()}
    skill_path = data_dir("skill_embeddings.json")
    if skill_path.exists():
        try:
            out["skill_embeddings"] = {
                "path": str(skill_path),
                "bytes": skill_path.stat().st_size,
            }
        except OSError:
            out["skill_embeddings"] = {"path": str(skill_path), "bytes": -1}
    else:
        out["skill_embeddings"] = {"path": str(skill_path), "bytes": 0}
    return out


def purge(scopes: Iterable[str] = ("all",)) -> dict:
    """Clear one or more cache scopes.

    Valid scopes: ``files``, ``repo_map``, ``skill_embeddings``, ``all``.
    Unknown scopes are ignored with a warning. Returns a per-scope
    report of what was cleared.
    """
    requested = set(scopes) or {"all"}
    unknown = requested - set(_VALID_SCOPES)
    for u in unknown:
        log.warning("cache.purge: unknown scope %r (valid: %s)", u, _VALID_SCOPES)
    requested -= unknown
    if "all" in requested:
        requested = {"files", "repo_map", "skill_embeddings"}

    report: dict = {}

    if "files" in requested:
        from .file import clear_read_cache, read_cache_stats
        before = read_cache_stats()
        clear_read_cache()
        report["files"] = {"cleared_entries": before["entries"], "cleared_bytes": before["bytes"]}

    if "repo_map" in requested:
        from .file import clear_repo_cache
        clear_repo_cache()
        report["repo_map"] = {"cleared": True}

    if "skill_embeddings" in requested:
        path = data_dir("skill_embeddings.json")
        if path.exists():
            try:
                size = path.stat().st_size
                path.unlink()
                report["skill_embeddings"] = {"cleared": True, "bytes": size}
            except OSError as e:
                report["skill_embeddings"] = {"cleared": False, "error": str(e)}
        else:
            report["skill_embeddings"] = {"cleared": False, "reason": "no cache file"}

    return report


__all__ = ["purge", "stats"]
