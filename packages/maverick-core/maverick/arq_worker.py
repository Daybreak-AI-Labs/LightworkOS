"""Hardened ARQ worker entry point for authenticated goal dispatch.

Run with::

    arq maverick.arq_worker.WorkerSettings

The producer and worker deliberately import the same strict JSON codec and
Redis settings builder. ARQ's default pickle codec is never enabled here.
"""
from __future__ import annotations

import asyncio
from typing import Any

from arq.connections import RedisSettings
from arq.worker import func

from .queue_dispatcher import (
    JOB_NAME,
    _arq_safe_deserialize,
    _arq_safe_serialize,
    _configured_arq_queue_name,
    _configured_arq_redis_settings,
    _configured_worker_ceilings,
    _require_network_claim_store_configured,
    _require_network_signing_key,
    run_queued_goal,
)


async def _run_queued_goal(
    _ctx: dict[str, Any], payload: dict[str, Any]
) -> str | None:
    """Adapt the synchronous runner to ARQ's required async ``(ctx, ...)`` API."""
    return await asyncio.to_thread(run_queued_goal, payload)


async def _preflight(_ctx: dict[str, Any]) -> None:
    """Refuse to poll jobs unless fleet authentication and replay state exist."""
    _require_network_signing_key()
    _require_network_claim_store_configured()
    _configured_worker_ceilings()


class WorkerSettings:
    """Matching, non-retrying worker configuration for the network queue."""

    functions = [
        func(
            _run_queued_goal,
            name=JOB_NAME,
            keep_result=0,
            max_tries=1,
        )
    ]
    redis_settings = _configured_arq_redis_settings(RedisSettings)
    queue_name = _configured_arq_queue_name()
    on_startup = _preflight
    job_serializer = _arq_safe_serialize
    job_deserializer = _arq_safe_deserialize
    max_tries = 1
    retry_jobs = False
    keep_result = 0
