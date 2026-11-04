"""Real dashboard handlers must let other requests run during slow storage I/O."""
from __future__ import annotations

import asyncio
import threading

import httpx
import pytest
from fastapi import FastAPI
from maverick.paths import current_tenant_id, tenant_scope
from maverick_dashboard import api


@pytest.mark.parametrize("handler", [api.get_spend, api.list_goals])
def test_slow_storage_yields_to_other_requests_and_keeps_scope(monkeypatch, handler):
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    observations = []

    def slow_read(**kwargs):
        observations.append((current_tenant_id(), kwargs["owner"]))
        entered.set()
        try:
            assert release.wait(10), "test storage was never released"
        finally:
            finished.set()
        return []

    class SlowWorld:
        list_goals = staticmethod(slow_read)
        list_episodes = staticmethod(slow_read)

        def total_spend(self, **kwargs):
            return 0.0

    monkeypatch.setattr(api, "_world", SlowWorld)
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: request.headers["X-Owner"])
    app = FastAPI()
    app.add_api_route("/slow", handler)

    @app.get("/probe")
    async def probe():
        return {"storage_finished": finished.is_set()}

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1",
            headers={"Origin": "http://127.0.0.1", "X-Owner": "alice"},
        ) as client:
            with tenant_scope(tenant="client-a"):
                # The timer also lets the pre-fix, event-loop-blocking handler
                # finish, so a regression fails instead of hanging the suite.
                failsafe = threading.Timer(5, release.set)
                failsafe.start()
                slow_request = asyncio.create_task(client.get("/slow"))
                try:
                    assert await asyncio.to_thread(entered.wait, 10)
                    response = await client.get("/probe")
                    assert response.status_code == 200
                    assert response.json() == {"storage_finished": False}
                finally:
                    release.set()
                    failsafe.cancel()
                    slow_response = await slow_request
                assert slow_response.status_code == 200

    asyncio.run(exercise())
    assert observations == [("client-a", "alice")]
