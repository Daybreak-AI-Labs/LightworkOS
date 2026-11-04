"""The shield-calibration dashboard endpoint returns the threshold sweep."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


def test_calibration_endpoint_returns_sweep(monkeypatch):
    monkeypatch.delenv("MAVERICK_REDTEAM_CORPUS", raising=False)
    r = client.get("/api/v1/shield/calibration")
    assert r.status_code == 200, r.text
    data = r.json()
    assert set(data["thresholds"]) == {"low", "medium", "high", "critical"}
    assert data["cases"] >= 20
    assert data["rule_hits"]


def test_calibration_endpoint_custom_corpus(monkeypatch, tmp_path):
    corpus = tmp_path / "c.jsonl"
    corpus.write_text('{"id": "a", "text": "rm -rf /", "expected": "block"}\n')
    monkeypatch.setenv("MAVERICK_REDTEAM_CORPUS", str(corpus))
    r = client.get("/api/v1/shield/calibration")
    assert r.status_code == 200 and r.json()["cases"] == 1


def test_calibration_endpoint_bad_corpus_400(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_REDTEAM_CORPUS", str(tmp_path / "missing.jsonl"))
    assert client.get("/api/v1/shield/calibration").status_code == 400
