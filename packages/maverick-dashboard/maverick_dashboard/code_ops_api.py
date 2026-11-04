"""Code page buttons for ``maverick code export`` and ``maverick watch``.

* Download a copy: the vault's own export (a plain clone, outside the vault's
  protection) packed as one download. Administrators only, confirmed, and
  recorded before the copy is made.
* Watch a code project for notes to Lightwork (``# AI: ...`` and the other
  markers ``maverick watch`` finds): a supervised background job per
  workspace and project. It re-reads the project only when its latest
  version changes, keeps at most 200 notes (at most three projects per workspace), stops by itself after eight
  hours or three failed reads, and stops when Lightwork shuts down. Starting
  work from a note runs it exactly like "Build a change": on a private copy of
  the code, under the project's own protection (a project set to "code never
  leaves Lightwork" keeps that policy for the work), with any change waiting
  for approval -- never as an ordinary task.

Every route needs the workspace ``admin`` permission, like the other Code
page actions.
"""
from __future__ import annotations

import contextvars
import dataclasses
import hashlib
import logging
import shutil
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, execution_user_id_from_request, require_permission
from .tools_ops_api import record, same_origin

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/code")

_MAX_EXPORT_BYTES = 500 * 1024 * 1024
_MAX_EXPORT_FILES = 100_000
_MAX_NOTES = 200
_MAX_WATCHERS = 10
_MAX_WATCHERS_PER_WORKSPACE = 3  # one workspace's share of the installation-wide slots
_INTERVAL = 60.0
_MAX_SECONDS = 8 * 3600
_MAX_FAILURES = 3


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = False


def _vault():
    from maverick.codebase import vault
    if not vault.enabled():
        raise HTTPException(503, "Code projects are turned off.")
    return vault


def _repo(name: str):
    vault = _vault()
    try:
        return vault.get(name)
    except vault.VaultError as exc:
        raise HTTPException(404, "That code project was not found.") from exc


# ---- Download a copy (code export) -----------------------------------------

def _zip_tree(folder: Path, out: Path) -> None:
    total = count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(folder.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            total += path.stat().st_size
            if count > _MAX_EXPORT_FILES or total > _MAX_EXPORT_BYTES:
                raise ValueError("too large")
            zf.write(path, str(path.relative_to(folder.parent)))


def _export(name: str) -> str:
    from maverick.codebase import vault
    work = Path(tempfile.mkdtemp(prefix="lw-export-"))
    try:
        copy = vault.export(name, work / "copy" / name)
        # Windows installations can create a private temporary directory but
        # refuse a second open of a file created directly in the temp root.
        # Keep the archive in that private directory until FileResponse ends.
        out = work / "copy.zip"
        _zip_tree(copy, out)
        return str(out)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise


@router.post("/repos/{name}/export")
async def export_repo(name: str, body: ConfirmIn, request: Request) -> FileResponse:
    same_origin(request)
    require_permission(request, "admin")
    _repo(name)
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want to download an unprotected copy.")
    record(request, "code_export", installation=False, repo=name)
    try:
        out = await run_in_threadpool(_export, name)
    except ValueError as exc:
        raise HTTPException(413, "This code project is too large to download from the page.") from exc
    except Exception as exc:  # noqa: BLE001 -- vault errors can carry paths
        raise HTTPException(502, "Lightwork could not make a copy of this code project.") from exc
    return FileResponse(out, media_type="application/zip", filename=f"{name}-copy.zip",
                        background=BackgroundTask(lambda: shutil.rmtree(Path(out).parent, ignore_errors=True)),
                        headers={"Cache-Control": "no-store"})


# ---- Watch a code project for notes (watch) --------------------------------

def _workspace() -> str:
    try:
        from maverick.paths import current_tenant
        return current_tenant() or ""
    except Exception:  # noqa: BLE001 -- an unreadable binding watches nothing shared
        return "?"


class _Watcher:
    """One supervised watch over one code project in one workspace."""

    def __init__(self, workspace: str, repo: str, started_by: str) -> None:
        self.workspace, self.repo, self.started_by = workspace, repo, started_by
        self.stop_event = threading.Event()
        self.state, self.reason = "starting", ""
        self.notes: list[dict[str, Any]] = []
        self.started_at, self.last_scan, self.scans = time.time(), 0.0, 0
        self._head, self._failures = None, 0
        context = contextvars.copy_context()  # keep the workspace the request ran in
        self.thread = threading.Thread(target=context.run, args=(self._run,), daemon=True,
                                       name=f"lightwork-code-watch-{repo}")

    def _run(self) -> None:
        from maverick.codebase import vault
        while not self.stop_event.is_set():
            if time.time() - self.started_at > _MAX_SECONDS:
                self._end("stopped", "Stopped after eight hours. Start it again to keep watching.")
                return
            try:
                head = vault.get(self.repo).head
                if head != self._head:
                    self._scan()
                    self._head = head
                self._failures, self.state = 0, "watching"
            except Exception as exc:  # noqa: BLE001 -- supervised: count and retry
                self._failures += 1
                log.warning("code watch for %s failed to read (%s)", self.repo, type(exc).__name__)
                if self._failures >= _MAX_FAILURES:
                    self._end("failed", "Stopped because the code project could not be read three times in a row.")
                    return
            self.stop_event.wait(_INTERVAL)
        self._end("stopped", "Stopped.")

    def _end(self, state: str, reason: str) -> None:
        self.state, self.reason = state, reason

    def _scan(self) -> None:
        from maverick.codebase import vault
        from maverick.watch_mode import scan_dir
        notes: list[dict[str, Any]] = []
        with vault.checkout(self.repo) as work:
            for match in scan_dir(work):
                if len(notes) >= _MAX_NOTES or self.stop_event.is_set():
                    break
                rel = match.path.relative_to(work)
                text = (match.text or " ".join(match.follow_lines[:4])).strip()[:500]
                task = dataclasses.replace(match, path=rel).to_goal()
                ident = hashlib.sha256(f"{rel}:{match.line_number}:{text}".encode()).hexdigest()[:16]
                notes.append({"id": ident, "file": str(rel)[:300], "line": match.line_number,
                              "note": text, "title": f"{self.repo}: {text[:60] or 'note'}",
                              "task": (f"In the {self.repo} code project.\n" + task)[:4000]})
        self.notes, self.scans, self.last_scan = notes, self.scans + 1, time.time()

    def view(self) -> dict[str, Any]:
        return {"repo": self.repo, "state": self.state, "reason": self.reason,
                "started_at": self.started_at, "last_scan": self.last_scan or None,
                "notes": list(self.notes)}


_lock = threading.Lock()
_watchers: dict[tuple[str, str], _Watcher] = {}
_watch_threads: list[threading.Thread] = []


def _live(w: _Watcher) -> bool:
    return w.thread.is_alive() and not w.stop_event.is_set()


@router.get("/watch")
async def watch_status(request: Request) -> dict:
    require_permission(request, "admin")
    space = _workspace()
    with _lock:
        rows = [w.view() for (ws, _), w in sorted(_watchers.items()) if ws == space]
    return {"watching": rows}


@router.post("/watch/{name}/start", status_code=202)
async def watch_start(name: str, body: ConfirmIn, request: Request) -> dict:
    same_origin(request)
    require_permission(request, "admin")
    _repo(name)
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want Lightwork to watch this code project.")
    key = (_workspace(), name)
    with _lock:
        current = _watchers.get(key)
        if current is not None and _live(current):
            return current.view()
        if sum(1 for (ws, _), w in _watchers.items() if ws == key[0] and _live(w)) >= _MAX_WATCHERS_PER_WORKSPACE:
            raise HTTPException(409, f"This workspace is already watching {_MAX_WATCHERS_PER_WORKSPACE} code "
                                     "projects, the most one workspace can. Stop one first.")
        if sum(1 for w in _watchers.values() if _live(w)) >= _MAX_WATCHERS:
            raise HTTPException(409, "Lightwork is already watching as many code projects as it can. "
                                     "Stop one first.")
    record(request, "code_watch_start", installation=False, repo=name)
    from .auth import caller_principal
    watcher = _Watcher(key[0], name, caller_principal(request) or "local")
    with _lock:
        _watchers[key] = watcher
        _watch_threads[:] = [t for t in _watch_threads if t.is_alive()] + [watcher.thread]
    watcher.thread.start()
    return watcher.view()


@router.post("/watch/{name}/stop")
async def watch_stop(name: str, request: Request) -> dict:
    same_origin(request)
    require_permission(request, "admin")
    key = (_workspace(), name)
    with _lock:
        watcher = _watchers.get(key)
    if watcher is None:
        raise HTTPException(404, "Lightwork is not watching that code project.")
    record(request, "code_watch_stop", installation=False, repo=name)
    watcher.stop_event.set()
    watcher._end("stopped", "Stopped.")
    return watcher.view()


@router.post("/watch/{name}/notes/{note_id}/start", status_code=202)
async def watch_note_start(name: str, note_id: str, body: ConfirmIn, request: Request,
                           bg: BackgroundTasks) -> dict:
    """Start work from one note, on a private copy under the project's protection.

    The note's words come from the server's own reading of the project (the
    page names the note only by its id), and the work runs through the same
    governed path as "Build a change" (``code_actions_api._run_feature``):
    labelled with the project and enforced at its protection, so a project set
    to "code never leaves Lightwork" keeps that policy for this work."""
    same_origin(request)
    require_permission(request, "admin")
    repo = _repo(name)
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want Lightwork to start work on this note.")
    with _lock:
        watcher = _watchers.get((_workspace(), name))
        note = next((dict(n) for n in (watcher.notes if watcher else []) if n["id"] == note_id),
                    None)
    if note is None:
        raise HTTPException(404, "That note was not found. Lightwork may have read the project "
                                 "again since the page was loaded.")
    from .code_actions_api import _provider_missing, _run_feature
    if await run_in_threadpool(_provider_missing):
        raise HTTPException(503, "Set up an AI provider in Settings before asking Lightwork to "
                                 "work on a note.")
    owner = caller_principal(request) or ""
    user_id = execution_user_id_from_request(request)
    if owner and owner != f"user:{user_id}":
        raise HTTPException(403, "A current named execution identity is required.")
    record(request, "code_watch_note_start", installation=False, repo=name, note=note_id,
           protect=repo.protect)
    bg.add_task(_run_feature, name, note["title"], note["task"], None, owner, user_id)
    return {"started": True, "repo": name, "protect": repo.protect}


def stop_watchers(*, timeout: float, wait: bool = True) -> None:
    """Shutdown: stop every watcher, then join them within ``timeout``."""
    with _lock:
        watchers = list(_watchers.values())
    for w in watchers:
        w.stop_event.set()
    if wait:
        deadline = time.monotonic() + max(0.0, float(timeout))
        for w in watchers:
            w.thread.join(max(0.0, deadline - time.monotonic()))


__all__ = ["router", "stop_watchers"]
