"""Granular redaction UI: preview API + page."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402
from maverick_dashboard.app import app  # noqa: E402


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # Mutating requests must carry a matching Origin (the dashboard CSRF contract).
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


_TEXT = "key AKIAIOSFODNN7EXAMPLE and mail alice@example.com"


def test_preview_all_kinds(client):
    d = client.post("/api/v1/redact/preview", json={"text": _TEXT}).json()
    kinds = {f["kind"] for f in d["findings"]}
    assert "secret:aws_access_key_id" in kinds and "pii:email" in kinds
    assert "AKIA" not in d["redacted"] and "alice@example.com" not in d["redacted"]
    assert d["proven_clean"] is True and d["residual"] == []


def test_granular_kind_selection(client):
    d = client.post("/api/v1/redact/preview",
                    json={"text": _TEXT,
                          "kinds": ["secret:aws_access_key_id"]}).json()
    assert "AKIA" not in d["redacted"]            # selected kind scrubbed
    assert "alice@example.com" in d["redacted"]   # unselected kind kept
    assert d["proven_clean"] is False             # residual disclosed honestly
    assert any("email" in r for r in d["residual"])


def test_clean_text(client):
    d = client.post("/api/v1/redact/preview", json={"text": "nothing here"}).json()
    assert d["findings"] == [] and d["proven_clean"] is True


def test_page_renders(client):
    r = client.get("/redact")
    assert r.status_code == 200 and "/api/v1/redact/preview" in r.text
