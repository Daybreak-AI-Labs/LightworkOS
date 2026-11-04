"""Dashboard UX store: pins, saved views, trace annotations.

Three small per-deployment UX features share one persistence problem — tiny
per-principal records that must survive restarts but don't belong in the
world model's run data:

  * **pinned watch list** — goals a user pinned to the top of the dashboard;
  * **saved dashboard views** — named filter/query-param sets;
  * **annotated traces** — human notes attached to replay-trace steps
    (``goal_id`` + ``seq``), so a reviewer can mark "this is where it went
    wrong" and the next person sees it.

One JSON document under ``data_dir("dashboard", "ux_store-v2.json")`` - tenant-
aware via :func:`maverick.paths.data_dir`, atomic replace on write, owner-only
permissions, thread-safe, bounded (caps below) so it can't grow unbounded.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

MAX_PINS = 200          # per principal
MAX_VIEWS = 50          # per principal
MAX_VIEW_PARAMS = 64     # per saved view
MAX_ANNOTATIONS = 1000  # per goal
MAX_GALLERY = 100       # deployment-wide
_ANON = "_anon"          # principal key when auth is off


def _principal_key(principal: str | None) -> str:
    p = (principal or "").strip()
    return p or _ANON


class UxStore:
    def __init__(self, path: Path | None = None):
        if path is None:
            from .paths import data_dir
            path = data_dir("dashboard") / "ux_store-v2.json"
        self.path = Path(path)
        self._lock = threading.Lock()

    # -- persistence ------------------------------------------------------

    def _load(self, *, strict: bool = False) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("ux_store must be a JSON object")
            for k in ("pins", "views", "annotations", "gallery"):
                data.setdefault(k, {})
                if strict and not isinstance(data[k], dict):
                    raise ValueError("UX storage has an invalid inventory; no empty state is claimed")
            return data
        except FileNotFoundError:
            return {"pins": {}, "views": {}, "annotations": {}, "gallery": {}}
        except (OSError, ValueError):
            if strict:
                raise
            return {"pins": {}, "views": {}, "annotations": {}, "gallery": {}}

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- pinned watch list --------------------------------------------------

    def pin(self, principal: str | None, goal_id: int) -> list[int]:
        key = _principal_key(principal)
        with self._lock:
            data = self._load()
            pins = [int(g) for g in data["pins"].get(key, [])]
            gid = int(goal_id)
            if gid in pins:
                pins.remove(gid)
            pins.insert(0, gid)            # most-recently-pinned first
            data["pins"][key] = pins[:MAX_PINS]
            self._save(data)
            return data["pins"][key]

    def unpin(self, principal: str | None, goal_id: int) -> list[int]:
        key = _principal_key(principal)
        with self._lock:
            data = self._load()
            pins = [int(g) for g in data["pins"].get(key, []) if int(g) != int(goal_id)]
            data["pins"][key] = pins
            self._save(data)
            return pins

    def pins(self, principal: str | None) -> list[int]:
        with self._lock:
            return [int(g) for g in self._load()["pins"].get(_principal_key(principal), [])]

    # -- saved dashboard views ----------------------------------------------

    @staticmethod
    def _view_revision(views: dict) -> str:
        return hashlib.sha256(json.dumps(views, sort_keys=True, ensure_ascii=False,
                                        separators=(",", ":")).encode()).hexdigest()

    def view_snapshot(self, principal: str | None) -> dict:
        """Return one locked view inventory and its compare-and-swap version."""
        with self._lock:
            views = self._load(strict=True)["views"].get(_principal_key(principal), {})
            return {"views": views, "revision": self._view_revision(views)}

    def view_revision(self, principal: str | None) -> str:
        return self.view_snapshot(principal)["revision"]

    def save_view(self, principal: str | None, name: str, params: dict[str, str],
                  *, expected_revision: str | None = None) -> None:
        name = str(name).strip()
        if not name or len(name) > 80:
            raise ValueError("view name must be 1-80 chars")
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        if len(params) > MAX_VIEW_PARAMS:
            raise ValueError(f"too many saved view params (max {MAX_VIEW_PARAMS})")
        clean = {str(k)[:64]: str(v)[:256] for k, v in params.items()}
        key = _principal_key(principal)
        with self._lock:
            data = self._load(strict=expected_revision is not None)
            views = data["views"].setdefault(key, {})
            if expected_revision is not None and expected_revision != self._view_revision(views):
                raise ViewConflict("Saved views changed. Refresh them and review your changes again.")
            if name not in views and len(views) >= MAX_VIEWS:
                raise ValueError(f"too many saved views (max {MAX_VIEWS})")
            views[name] = {"params": clean, "saved_at": time.time()}
            self._save(data)

    def views(self, principal: str | None) -> dict[str, dict[str, Any]]:
        with self._lock:
            return dict(self._load()["views"].get(_principal_key(principal), {}))

    def delete_view(self, principal: str | None, name: str,
                    *, expected_revision: str | None = None) -> bool:
        key = _principal_key(principal)
        with self._lock:
            data = self._load(strict=expected_revision is not None)
            views = data["views"].get(key, {})
            if expected_revision is not None and expected_revision != self._view_revision(views):
                raise ViewConflict("Saved views changed. Refresh them and review removal again.")
            existed = views.pop(str(name).strip(), None) is not None
            if existed:
                self._save(data)
            return existed

    # -- exact-owner My Data inventory/export/erasure ------------------------

    def _owned_navigation(self, data: dict, principal: str) -> dict:
        if not isinstance(principal, str) or not principal or principal != principal.strip() or principal == _ANON:
            raise ValueError("A named exact account is required for owned navigation records")
        pins, views = data["pins"].get(principal, []), data["views"].get(principal, {})
        if (not isinstance(pins, list) or len(pins) > MAX_PINS
                or any(type(value) is not int or value <= 0 for value in pins)
                or not isinstance(views, dict) or len(views) > MAX_VIEWS):
            raise ValueError("Owned navigation records exceed or invalidate the exact inventory")
        material = {"owner": principal, "pins": pins, "views": views}
        version = self._view_revision({"storage": str(self.path.resolve()), **material})
        return {**material, "version": version}

    def owned_navigation_inventory(self, principal: str) -> dict:
        """Content-free review metadata; never expose filters to a reviewer."""
        with self._lock:
            records = self._owned_navigation(self._load(strict=True), principal)
            return {"version": records["version"], "pin_count": len(records["pins"]),
                    "view_count": len(records["views"]), "count": len(records["pins"]) + len(records["views"]),
                    "retained": NAVIGATION_RETAINED}

    def export_owned_navigation(self, principal: str) -> dict:
        """Return only the requesting owner's records, without dereferencing tasks."""
        with self._lock:
            return {**self._owned_navigation(self._load(strict=True), principal),
                    "store": "saved_views_and_pins", "limits": NAVIGATION_RETAINED}

    def erase_owned_navigation(self, principal: str, *, expected_version: str) -> dict:
        """One locked exact-owner mutation after native preservation review.

        The caller owns durable intent and audit receipts. A failed write or
        readback propagates, so its per-store result remains unconfirmed.
        """
        with self._lock:
            data = self._load(strict=True)
            records = self._owned_navigation(data, principal)
            if records["version"] != expected_version:
                raise ViewConflict("Saved views or task pins changed. Review a fresh exact deletion request.")
            data["pins"].pop(principal, None)
            data["views"].pop(principal, None)
            self._save(data)
            after = self._owned_navigation(self._load(strict=True), principal)
            if after["pins"] or after["views"]:
                raise RuntimeError("Owned navigation erasure readback is unconfirmed")
            return {"state": "purged", "removed": len(records["pins"]) + len(records["views"]),
                    "retained": NAVIGATION_RETAINED}

    # -- trace annotations ----------------------------------------------------

    def annotate(self, goal_id: int, seq: int, note: str, *, author: str | None = None) -> dict:
        note = str(note).strip()
        if not note or len(note) > 2000:
            raise ValueError("note must be 1-2000 chars")
        entry = {
            "seq": int(seq),
            "note": note,
            "author": _principal_key(author),
            "at": time.time(),
        }
        gid = str(int(goal_id))
        with self._lock:
            data = self._load()
            notes = data["annotations"].setdefault(gid, [])
            if len(notes) >= MAX_ANNOTATIONS:
                raise ValueError(f"too many annotations on goal {goal_id} (max {MAX_ANNOTATIONS})")
            notes.append(entry)
            self._save(data)
            return entry

    def annotations(self, goal_id: int) -> list[dict]:
        with self._lock:
            notes = self._load()["annotations"].get(str(int(goal_id)), [])
            return sorted(notes, key=lambda n: (n.get("seq", 0), n.get("at", 0)))


    # -- run gallery (deployment-wide curation) -------------------------------

    def gallery_add(self, goal_id: int, *, blurb: str = "", curator: str | None = None) -> dict:
        """Feature a run in the deployment's gallery (idempotent upsert)."""
        blurb = str(blurb or "").strip()
        if len(blurb) > 500:
            raise ValueError("blurb must be <= 500 chars")
        entry = {"blurb": blurb, "curator": _principal_key(curator), "at": time.time()}
        gid = str(int(goal_id))
        with self._lock:
            data = self._load()
            gallery = data["gallery"]
            if gid not in gallery and len(gallery) >= MAX_GALLERY:
                raise ValueError(f"gallery is full (max {MAX_GALLERY})")
            # Dict insertion order is the durable tie-breaker when several
            # curations share one coarse wall-clock tick. Re-inserting an
            # existing goal also moves its recency position forward.
            gallery.pop(gid, None)
            gallery[gid] = entry
            self._save(data)
            return entry

    def gallery_remove(self, goal_id: int) -> bool:
        gid = str(int(goal_id))
        with self._lock:
            data = self._load()
            existed = data["gallery"].pop(gid, None) is not None
            if existed:
                self._save(data)
            return existed

    def gallery(self) -> list[dict]:
        """Featured runs, newest-curated first: [{goal_id, blurb, curator, at}]."""
        with self._lock:
            data = self._load()
        indexed = [
            (index, {"goal_id": int(gid), **entry})
            for index, (gid, entry) in enumerate(data["gallery"].items())
        ]
        indexed.sort(
            key=lambda item: (float(item[1].get("at", 0)), item[0]),
            reverse=True,
        )
        return [entry for _, entry in indexed]


class ViewConflict(ValueError):
    """A reviewed saved-view inventory no longer matches current storage."""


NAVIGATION_RETAINED = (
    "Only this account's saved dashboard filters and pinned task references are included. "
    "Task content, other accounts, page/template favorites, privacy restrictions, "
    "workspace trace annotations, gallery curation and audit evidence remain separate. "
    "Legacy UX files without reliable workspace lineage stay outside this inventory."
)


_shared: dict[Path, UxStore] | None = None
_shared_lock = threading.Lock()


def shared() -> UxStore:
    """Resolve the caller's workspace on every access, preserving its lock."""
    global _shared
    from . import practice
    from .paths import data_dir

    # The previous singleton could write another workspace's records into its
    # first workspace's file. Those rows carry no verifiable workspace lineage;
    # do not silently assign them to that first workspace during an upgrade.
    # Practice tasks are numbered in their own world database, so their pins,
    # views and notes are kept in practice too (maverick.practice).
    path = data_dir("practice" if practice.active() else "dashboard", "ux_store-v2.json").resolve()
    with _shared_lock:
        if _shared is None:
            _shared = {}
        if path not in _shared:
            _shared[path] = UxStore(path=path)
        return _shared[path]


def reset_shared() -> None:
    """Tests / tenant switch."""
    global _shared
    with _shared_lock:
        _shared = None


__all__ = ["UxStore", "shared", "reset_shared", "MAX_PINS", "MAX_VIEWS",
           "MAX_VIEW_PARAMS", "MAX_ANNOTATIONS", "MAX_GALLERY"]
