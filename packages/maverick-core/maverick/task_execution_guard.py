"""A non-reentrant lease held through execution and finalization.

Handoffs acquire the same lease before closing a source. PostgreSQL uses a
separate session advisory lock, so replicas participate without holding a
world-model transaction across provider calls. No stale-timeout takeover.
"""
from __future__ import annotations

import hashlib
import logging
import os
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .paths import current_tenant_id_strict
from .task_file_recovery import RecoveryConflict, _lease

log = logging.getLogger(__name__)


class TaskBusy(ValueError):
    pass


def _identity(world, goal_id):
    path = getattr(world, "path", None)
    backend = os.path.normcase(str(Path(path).resolve())) if path is not None else "postgres"
    return hashlib.sha256(f"{current_tenant_id_strict()}\0{backend}\0{int(goal_id)}".encode()).digest()


@contextmanager
def lease(world, goal_id):
    with held(world, _identity(world, goal_id), "execution-",
              "This task is still running or finishing. Wait for its safe boundary and review again.",
              "This task is still running or finishing. Review again after it stops."):
        yield


@contextmanager
def held(world, identity: bytes, prefix: str, local_busy: str, shared_busy: str):
    """Hold the lease named by ``identity`` until the block exits, or raise
    :class:`TaskBusy`. A process that dies releases it: the operating system
    drops its file lock and PostgreSQL ends its session."""
    if getattr(world, "path", None) is not None:
        with ExitStack() as stack:
            # Only a conflict taking the lease means busy; one raised by the
            # body keeps its own meaning.
            try:
                stack.enter_context(_lease(prefix + identity.hex()))
            except RecoveryConflict as exc:
                raise TaskBusy(local_busy) from exc
            yield
        return
    from .postgres_io import BoundedConnection, postgres_io_timeout_seconds
    from .world_model_backends.postgres import _connection_kwargs

    # A dedicated bounded connection avoids session-lock ownership leaking
    # into a pooled world-model connection used by unrelated requests.
    key = int.from_bytes(identity[:8], "big", signed=True)
    options = {**_connection_kwargs(world._dsn), "autocommit": True}
    with BoundedConnection.connect(world._dsn, **options,
                                   io_timeout_seconds=postgres_io_timeout_seconds()) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s)", (key,))
            if not cursor.fetchone()[0]:
                raise TaskBusy(shared_busy)
        try:
            yield
        finally:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_unlock(%s)", (key,))
            except Exception:  # closing the session releases the lock anyway
                log.warning("task execution lease: advisory unlock failed", exc_info=True)
