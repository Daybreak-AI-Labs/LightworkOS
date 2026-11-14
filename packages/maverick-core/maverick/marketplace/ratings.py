"""Marketplace ratings — local ledger.

The catalog indexes carry community aggregates (``rating`` /
``ratings_count`` on :class:`maverick.catalog.CatalogEntry` — display-only,
self-asserted by the index like ``install_count``). This module is the *local*
half: the operator's own star ratings, kept on disk so they

  * annotate ``browse`` output ("your rating: ★★★★"), and
  * can be exported and submitted upstream to an index by PR — the
    self-host-first path to a shared signal (no hosted ratings service).

One JSON file under ``data_dir("marketplace_ratings.json")``; atomic write;
ratings are 1-5 integer stars with an optional short comment.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_VALID_KINDS = ("templates", "skills", "personas", "mcp")


class RatingsLedger:
    def __init__(self, path: Path | None = None):
        if path is None:
            from ..paths import data_dir
            path = data_dir() / "marketplace_ratings.json"
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _cplock(self):
        from ..file_lock import cross_process_lock
        return cross_process_lock(self.path)

    def _save(self, data: dict) -> None:
        # Unique temp + os.replace: a fixed ".tmp" collides between processes.
        from ..file_lock import atomic_write_text
        atomic_write_text(self.path, json.dumps(data, ensure_ascii=False, indent=0))

    def rate(self, kind: str, name: str, stars: int, comment: str = "") -> dict:
        if kind not in _VALID_KINDS:
            raise ValueError(f"kind must be one of {', '.join(_VALID_KINDS)}")
        if not isinstance(stars, int) or isinstance(stars, bool) or not 1 <= stars <= 5:
            raise ValueError("stars must be an integer 1-5")
        name = str(name).strip()
        if not name:
            raise ValueError("name is required")
        entry = {"stars": stars, "comment": str(comment or "")[:280], "at": time.time()}
        # In-process lock + cross-process flock: two processes both load the
        # ledger and the second save clobbers the first's rating otherwise.
        with self._lock, self._cplock():
            data = self._load()
            if not data and self.path.exists():
                # Unreadable or empty ledger: keep the operator's old file
                # aside instead of overwriting it with this one rating.
                self.path.replace(self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}"))
            data.setdefault(kind, {})[name] = entry
            self._save(data)
        return entry

    def my_rating(self, kind: str, name: str) -> dict | None:
        with self._lock:
            return self._load().get(kind, {}).get(str(name).strip())

    def all_ratings(self, kind: str | None = None) -> dict:
        with self._lock:
            data = self._load()
        return data.get(kind, {}) if kind else data

    def export_for_submission(self) -> str:
        """Render the ledger as the JSON fragment an index PR expects:
        ``{kind: {name: stars}}`` (comments stay local)."""
        with self._lock:
            data = self._load()
        out = {
            kind: {name: e["stars"] for name, e in entries.items()}
            for kind, entries in data.items() if entries
        }
        return json.dumps(out, indent=2, sort_keys=True)


def stars_bar(avg: float, count: int = 0) -> str:
    """Render '★★★★☆ (12)' for browse output. 0 ratings -> 'unrated'."""
    if count <= 0 and avg <= 0:
        return "unrated"
    full = int(round(max(0.0, min(5.0, avg))))
    bar = "★" * full + "☆" * (5 - full)
    return f"{bar} ({count})" if count else bar


__all__ = ["RatingsLedger", "stars_bar"]
