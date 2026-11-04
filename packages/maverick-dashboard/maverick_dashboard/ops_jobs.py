"""Small in-process background jobs for dashboard operations the page polls.

Long operations (model calls, bounded learning, recording imports) never hold
the request: a route starts a job and returns its id, the page asks for the
status. Jobs are private to the person and workspace that started them (a
lookup by anyone else reads as "no such job"), bounded in number, run with
the starting request's context (so the selected workspace carries over) and
forgotten an hour after they finish. The result is whatever the job function
returned; its message must already be written for people.
"""
from __future__ import annotations

import contextvars
import logging
import secrets
import threading
import time
from collections.abc import Callable

log = logging.getLogger(__name__)

MAX_JOBS = 200
MAX_RUNNING_PER_PERSON = 2
KEEP_SECONDS = 3600


class Busy(Exception):
    """Too many jobs are already running for this person."""


class _Store:
    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for key, job in list(self._jobs.items()):
            if job["state"] != "running" and now - job["finished"] > KEEP_SECONDS:
                del self._jobs[key]
        if len(self._jobs) > MAX_JOBS:
            done = sorted((j for j in self._jobs.values() if j["state"] != "running"), key=lambda j: j["finished"])
            for job in done[: len(self._jobs) - MAX_JOBS]:
                self._jobs.pop(job["id"], None)

    def start(self, *, owner: str, tenant: str, kind: str, work: Callable[[], dict], job_id: str | None = None) -> str:
        if job_id is not None and (len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id)):
            raise ValueError("invalid operation job identity")
        now = time.time()
        with self._lock:
            self._prune(now)
            running = sum(1 for j in self._jobs.values()
                          if j["state"] == "running" and j["owner"] == owner and j["tenant"] == tenant)
            if running >= MAX_RUNNING_PER_PERSON or len(self._jobs) >= MAX_JOBS:
                raise Busy
            job_id = job_id or secrets.token_hex(16)
            if job_id in self._jobs:
                raise Busy
            self._jobs[job_id] = {"id": job_id, "kind": kind, "owner": owner, "tenant": tenant,
                                  "state": "running", "started": now, "finished": 0.0, "result": None}

        def run() -> None:
            try:
                result = work()
                state = "done"
            except Exception:  # the job's own code turns expected refusals into results
                log.warning("dashboard job %s failed", kind, exc_info=True)
                result, state = {"message": "This couldn't be finished. Try again in a moment."}, "failed"
            with self._lock:
                job = self._jobs.get(job_id)
                if job is not None:
                    job.update(state=state, result=result, finished=time.time())

        context = contextvars.copy_context()
        threading.Thread(target=context.run, args=(run,), name=f"lightwork-job-{kind}", daemon=True).start()
        return job_id

    def get(self, job_id: str, *, owner: str, tenant: str, kind: str) -> dict | None:
        """Public status. Result keys starting with ``_`` stay on the server."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job["owner"] != owner or job["tenant"] != tenant or job["kind"] != kind:
                return None
            result = job["result"] if job["state"] != "running" else None
            if isinstance(result, dict):
                result = {k: v for k, v in result.items() if not str(k).startswith("_")}
            return {"id": job["id"], "state": job["state"], "started": job["started"], "result": result}

    def private_result(self, job_id: str, *, owner: str, tenant: str, kind: str) -> dict | None:
        """The finished job's full result for server-side follow-up, or None."""
        with self._lock:
            job = self._jobs.get(job_id)
            if (job is None or job["owner"] != owner or job["tenant"] != tenant or job["kind"] != kind
                    or job["state"] != "done" or not isinstance(job["result"], dict)):
                return None
            return job["result"]

    def consume(self, job_id: str, *, owner: str, tenant: str, kind: str) -> dict | None:
        """Take a finished job's full result so it can be used only once."""
        with self._lock:
            job = self._jobs.get(job_id)
            if (job is None or job["owner"] != owner or job["tenant"] != tenant or job["kind"] != kind
                    or job["state"] != "done" or not isinstance(job["result"], dict)):
                return None
            return self._jobs.pop(job_id)["result"]

    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()


JOBS = _Store()


def identity(request) -> tuple[str, str]:
    """(person, workspace) a job belongs to."""
    from maverick.paths import current_tenant_id

    from .auth import caller_principal

    return caller_principal(request) or "local", current_tenant_id() or ""
