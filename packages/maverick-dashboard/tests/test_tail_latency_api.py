"""GET /api/v1/diag/tail-latency — fat-tailed tools from live latency samples."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_tail_latency_endpoint_empty():
    from maverick import tool_latency
    tool_latency.reset()  # the sample store is process-global; isolate it before
    resp = client.get("/api/v1/diag/tail-latency")
    assert resp.status_code == 200
    assert resp.json() == {"flagged": []}


def test_tail_latency_endpoint_flags_recorded_spike():
    from maverick import tool_latency
    # record a fat tail for a tool: many fast, a few slow
    for _ in range(40):
        tool_latency.record("spiky_tool", 10.0)
    for _ in range(5):
        tool_latency.record("spiky_tool", 200.0)
    resp = client.get("/api/v1/diag/tail-latency?min_count=20&ratio=3.0")
    assert resp.status_code == 200
    flagged = resp.json()["flagged"]
    assert any(r["tool"] == "spiky_tool" for r in flagged)
