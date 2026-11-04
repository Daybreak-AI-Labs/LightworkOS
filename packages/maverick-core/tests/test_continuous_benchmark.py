"""Continuous benchmarking."""
from __future__ import annotations

import pytest
from maverick.continuous_benchmark import (
    detect_regression,
    load_history,
    record_result,
    save_history,
)


def test_record_appends():
    h: list = []
    record_result(h, "swe", 0.42, commit="abc")
    record_result(h, "swe", 0.45)
    assert len(h) == 2
    assert h[0]["name"] == "swe" and h[0]["commit"] == "abc"
    assert h[1]["score"] == 0.45


def test_record_rejects_non_numeric():
    with pytest.raises(ValueError):
        record_result([], "x", "not-a-number")


def test_no_regression_when_stable():
    h: list = []
    for _ in range(5):
        record_result(h, "b", 0.80)
    record_result(h, "b", 0.79)
    r = detect_regression(h, "b")
    assert not r["regressed"]


def test_regression_flagged_on_drop():
    h: list = []
    for _ in range(5):
        record_result(h, "b", 0.80)
    record_result(h, "b", 0.60)  # 25% drop
    r = detect_regression(h, "b")
    assert r["regressed"]
    assert r["drop_pct"] > 0.05
    assert r["baseline_mean"] == 0.80


def test_single_run_never_regresses():
    h: list = []
    record_result(h, "b", 0.5)
    assert detect_regression(h, "b") == {
        "regressed": False, "latest": 0.5, "baseline_mean": None,
        "delta": 0.0, "drop_pct": 0.0, "n": 1}


def test_persist_roundtrip(tmp_path):
    h: list = []
    record_result(h, "g", 0.9)
    path = tmp_path / "hist.json"
    save_history(path, h)
    assert load_history(path)[0]["score"] == 0.9
    assert load_history(tmp_path / "nope.json") == []


def test_store_path_resolves_the_active_tenant_at_call_time(tmp_path, monkeypatch):
    """``_store_path()`` (and therefore ``dreaming.benchmark_regressed()``,
    the learning-side canary) must track the ACTIVE tenant at call time, the
    same fix already applied to ``donation._default_outbox()`` -- a module
    constant bound once at import would freeze the benchmark history path
    onto whichever tenant happened to be active during import."""
    from maverick.continuous_benchmark import _store_path
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    tok_a = set_tenant("tenant-a")
    try:
        path_a = _store_path()
    finally:
        reset_tenant(tok_a)

    tok_b = set_tenant("tenant-b")
    try:
        path_b = _store_path()
    finally:
        reset_tenant(tok_b)

    assert path_a != path_b
    assert "tenant-a" in str(path_a)
    assert "tenant-b" in str(path_b)
