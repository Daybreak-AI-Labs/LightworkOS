"""Benchmark dashboard: /api/v1/benchmarks + /benchmarks page.

Renders the real continuous-benchmark store (the one the bench_track tool
writes). Empty state is honest; no competitor numbers anywhere.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the continuous-benchmark store at a temp dir."""
    from maverick import continuous_benchmark as cb
    monkeypatch.setattr(cb, "data_dir", lambda *a, **k: tmp_path / "benchmarks")
    return cb


def test_api_empty_state_is_honest(store):
    r = client.get("/api/v1/benchmarks")
    assert r.status_code == 200
    data = r.json()
    assert data["suites"] == []
    assert "no benchmark runs recorded" in data["note"]
    assert "bench_track" in data["note"]


def test_page_empty_state_is_plain_and_offers_a_form(store):
    from test_support.plain_language import developer_terms, visible_text

    r = client.get("/benchmarks")
    assert r.status_code == 200
    assert "No scores recorded yet" in r.text
    assert 'id="bench-record"' in r.text and "Add this score" in r.text
    text = visible_text(r.text)
    for gone in ("bench_track", "history.json", "maverick.", "docs/comparison.md"):
        assert gone not in text
    assert developer_terms(r.text) == []


def test_record_score_appends_to_the_same_history(store):
    cb = store
    c = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    r = c.post("/api/v1/benchmarks/scores", json={"name": "support_quality", "score": 0.8, "note": "march"})
    assert r.status_code == 200, r.text
    assert r.json() == {"name": "support_quality", "runs": 1}
    c.post("/api/v1/benchmarks/scores", json={"name": "support_quality", "score": 0.7})
    rows = cb.load_history(cb._store_path())
    assert [(row["name"], row["score"]) for row in rows] == [("support_quality", 0.8), ("support_quality", 0.7)]
    page = client.get("/benchmarks").text
    assert "Support quality" in page and "70.0%" in page and "Down 10.0%" in page


@pytest.mark.parametrize("body", [
    {"name": "<script>", "score": 1},
    {"name": "ok", "score": "abc"},
    {"name": "", "score": 1},
])
def test_record_score_rejects_bad_input(store, body):
    c = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert c.post("/api/v1/benchmarks/scores", json=body).status_code == 422
    assert store.load_history(store._store_path()) == []


def test_api_groups_history_and_flags_regressions(store):
    cb = store
    history: list[dict] = []
    for s in (0.40, 0.42, 0.45):
        cb.record_result(history, "swe_bench", s, commit="abc")
    for s in (1.0, 1.0, 0.5):  # 50% drop vs baseline -> regression
        cb.record_result(history, "gaia", s)
    cb.save_history(cb._store_path(), history)

    data = client.get("/api/v1/benchmarks").json()
    assert "note" not in data
    by_name = {s["name"]: s for s in data["suites"]}
    assert set(by_name) == {"swe_bench", "gaia"}
    swe = by_name["swe_bench"]
    assert swe["runs"] == 3
    assert swe["latest"] == pytest.approx(0.45)
    assert swe["regressed"] is False
    gaia = by_name["gaia"]
    assert gaia["latest"] == pytest.approx(0.5)
    assert gaia["regressed"] is True
    assert [e["score"] for e in gaia["entries"]] == [1.0, 1.0, 0.5]


def test_api_skips_malformed_rows(store):
    cb = store
    path = cb._store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([
        {"name": "ok", "score": 0.9, "commit": "", "t": 1.0},
        {"name": "bad-no-score"},
        {"score": 1.0},                       # no name
        {"name": "ok", "score": "not-a-number"},
        "not even a dict",
    ]))
    data = client.get("/api/v1/benchmarks").json()
    assert [s["name"] for s in data["suites"]] == ["ok"]
    assert data["suites"][0]["runs"] == 1


def test_page_renders_sparklines_and_comparison_table(store):
    cb = store
    history: list[dict] = []
    for s in (0.40, 0.42, 0.45, 0.44, 0.47):
        cb.record_result(history, "swe_bench", s)
    cb.save_history(cb._store_path(), history)

    r = client.get("/benchmarks")
    assert r.status_code == 200
    assert "Swe bench" in r.text
    assert "<polyline points=" in r.text     # server-side trend sparkline
    assert ">Steady<" in r.text              # verdict badge
    assert "47.0%" in r.text                 # 0..1 scores read as percentages
    # honest framing: this deployment only, no competitor numbers
    assert "this deployment’s own recorded scores only" in r.text
