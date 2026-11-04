"""GET /api/v1/codec -- live telemetry of what the token-aware codec saves."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import codec_telemetry as ct
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    ct.reset()
    ct.set_token_counter(None)
    yield
    ct.reset()
    ct.set_token_counter(None)


def test_codec_telemetry_empty_by_default():
    body = client.get("/api/v1/codec").json()
    assert body["n_blocks"] == 0
    assert body["tokens_measured"] is False


def test_codec_telemetry_reports_recorded():
    from maverick import codec_telemetry as ct
    ct.set_token_counter(lambda s: len(s.split()))
    ct.record("alpha beta gamma delta", "alpha")     # 4 -> 1 words; bytes shrink too
    body = client.get("/api/v1/codec").json()
    assert body["n_blocks"] == 1
    assert body["byte_savings_pct"] > 0
    assert body["tokens_measured"] is True
    assert body["token_savings_pct"] > 0
