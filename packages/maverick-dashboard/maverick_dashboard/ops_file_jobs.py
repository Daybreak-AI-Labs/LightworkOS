"""Background downloads for large exports (whole-organisation data, the
insurance evidence pack).

A request starts the job and returns at once; the page asks for its status
and then downloads the finished file. The work runs in its own thread with
the request's context copied, so the workspace it was started in is the one
it reads. A job belongs to the person and workspace that started it: nobody
else can see its status or download its file. At most one job of a kind runs
per person and workspace, finished files are kept for a short time only, and
the number of jobs held at once is bounded.
"""
from __future__ import annotations

import contextvars
import secrets
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

#: Finished files are removed after this many seconds.
KEEP_SECONDS = 30 * 60
#: Jobs held at once across the installation.
MAX_JOBS = 32

_lock = threading.Lock()
_jobs: dict[str, _Job] = {}


@dataclass
class _Job:
    kind: str
    owner: tuple[str, str]
    filename: str
    media_type: str
    started: float = field(default_factory=time.time)
    state: str = "running"          # running | ready | failed
    message: str = ""
    path: Path | None = None
    workdir: Path | None = None
    finished: float = 0.0


def _expire(now: float) -> None:
    for job_id in [j for j, job in _jobs.items()
                   if job.state != "running" and now - (job.finished or now) > KEEP_SECONDS]:
        job = _jobs.pop(job_id)
        if job.workdir is not None:
            shutil.rmtree(job.workdir, ignore_errors=True)


def start(kind: str, owner: tuple[str, str], filename: str, media_type: str,
          build: Callable[[Path], Path | bytes],
          failure_text: Callable[[Exception], str]) -> str:
    """Start ``build(workdir)`` in the background; it returns the finished
    file (or its bytes). Refuses a second running job of the same kind for
    the same owner, and refuses when too many jobs are held."""
    now = time.time()
    with _lock:
        _expire(now)
        if any(job.kind == kind and job.owner == owner and job.state == "running"
               for job in _jobs.values()):
            raise HTTPException(status_code=409, detail="This download is already being prepared.")
        if len(_jobs) >= MAX_JOBS:
            raise HTTPException(status_code=429, detail="Too many downloads are being prepared. Try again soon.")
        job_id = secrets.token_hex(16)
        job = _Job(kind=kind, owner=owner, filename=filename, media_type=media_type)
        _jobs[job_id] = job

    def run() -> None:
        workdir = Path(tempfile.mkdtemp(prefix="lightwork-export-"))
        try:
            result = build(workdir)
            if isinstance(result, bytes):
                target = workdir / "export"
                target.write_bytes(result)
                result = target
            with _lock:
                job.path, job.workdir, job.state = Path(result), workdir, "ready"
                job.finished = time.time()
        except Exception as exc:  # noqa: BLE001 -- reported to the page in plain words
            shutil.rmtree(workdir, ignore_errors=True)
            with _lock:
                job.state, job.message = "failed", failure_text(exc)
                job.finished = time.time()

    context = contextvars.copy_context()
    threading.Thread(target=context.run, args=(run,), daemon=True,
                     name=f"lightwork-export-{kind}").start()
    return job_id


def _owned(job_id: str, owner: tuple[str, str]) -> _Job:
    with _lock:
        _expire(time.time())
        job = _jobs.get(job_id)
    if job is None or job.owner != owner:
        raise HTTPException(status_code=404, detail="That download is no longer available. Start it again.")
    return job


def status(job_id: str, owner: tuple[str, str]) -> dict:
    job = _owned(job_id, owner)
    return {"state": job.state, "message": job.message, "started": job.started}


def finished_file(job_id: str, owner: tuple[str, str]) -> tuple[Path, str, str]:
    job = _owned(job_id, owner)
    if job.state != "ready" or job.path is None:
        raise HTTPException(status_code=409, detail="The download is not ready yet.")
    return job.path, job.filename, job.media_type


def owner_of(request) -> tuple[str, str]:
    """The person and workspace a job belongs to."""
    from maverick.paths import current_tenant_id

    from .auth import caller_principal

    return (caller_principal(request) or "local", current_tenant_id() or "")


def reset_for_tests() -> None:
    with _lock:
        for job in _jobs.values():
            if job.workdir is not None:
                shutil.rmtree(job.workdir, ignore_errors=True)
        _jobs.clear()


__all__ = ["KEEP_SECONDS", "MAX_JOBS", "finished_file", "owner_of", "reset_for_tests",
           "start", "status"]
