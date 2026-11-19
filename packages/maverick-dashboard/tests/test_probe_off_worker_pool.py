"""Load-balancer probes answer without borrowing the worker pool.

On the hosted demo a page full of requests waiting on a locked store held the
worker threads; ``/livez`` then queued behind them (13 s measured), because
the shared request path made four worker-pool calls for it: the request
configuration primer, the stored workspace selection, the identity resolver
and the page-visibility check. A probe carries no identity and answers a
redacted payload, so none of that applies to it.
"""
from __future__ import annotations

import asyncio
import threading

import anyio.to_thread
import httpx
import pytest
from maverick_dashboard.app import app


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1")


def test_livez_answers_while_the_worker_pool_is_saturated(home):
    release = threading.Event()

    async def run():
        async with _client() as client:
            assert (await client.get("/livez")).status_code == 200  # routes built
            limiter = anyio.to_thread.current_default_thread_limiter()
            saved = limiter.total_tokens
            limiter.total_tokens = 2
            busy = [asyncio.create_task(anyio.to_thread.run_sync(release.wait, 10)) for _ in range(2)]
            try:
                await asyncio.sleep(0.1)
                assert limiter.borrowed_tokens == 2
                probe = await asyncio.wait_for(client.get("/livez"), 1.0)
                assert probe.status_code == 200 and probe.json() == {"status": "ok"}
            finally:
                release.set()
                await asyncio.gather(*busy)
                limiter.total_tokens = saved

    asyncio.run(run())


@pytest.mark.parametrize(("path", "hops"), [("/livez", 0), ("/readyz", 1), ("/healthz", 2)])
def test_probes_skip_the_per_request_worker_pool_calls(home, monkeypatch, path, hops):
    """/readyz keeps only its deep checks; /healthz also keeps the workspace
    binding its provider verdict reads."""
    calls: list[str] = []
    real = anyio.to_thread.run_sync

    async def counted(func, *args, **kwargs):
        calls.append(getattr(func, "__qualname__", repr(func)))
        return await real(func, *args, **kwargs)

    async def run():
        async with _client() as client:
            await client.get(path)
            monkeypatch.setattr(anyio.to_thread, "run_sync", counted)
            response = await client.get(path)
            monkeypatch.setattr(anyio.to_thread, "run_sync", real)
            return response

    response = asyncio.run(run())
    assert response.status_code in (200, 503)
    assert set(response.json()) == {"status"}  # still redacted
    assert len(calls) == hops, calls
