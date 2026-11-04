"""Benchmark reproducibility manifests: digests, fail-honest comparability.

Offline: temp history files, no benchmark harness runs.
"""
from __future__ import annotations

import json

import pytest
from maverick import continuous_benchmark as cb
from maverick.benchmark_reproducibility import (
    SCHEMA,
    audit_report,
    build_manifest,
    digest_config,
    digest_inputs,
    enabled,
    env_fingerprint,
    record_with_manifest,
    verify_reproduction,
)
from maverick.file_lock import private_path_is_restricted


@pytest.fixture
def fixtures(tmp_path):
    d = tmp_path / "fixtures"
    d.mkdir()
    (d / "task1.json").write_text('{"q": 1}')
    (d / "task2.json").write_text('{"q": 2}')
    return d


# -------------------------------------------------------------- digests ----

def test_config_digest_is_key_order_free_and_value_sensitive():
    a = digest_config({"model": "x", "n": 3})
    b = digest_config({"n": 3, "model": "x"})
    assert a == b
    assert digest_config({"model": "x", "n": 4}) != a
    assert digest_config(None) == digest_config({})


def test_inputs_digest_tracks_content_and_missing_raises(fixtures, tmp_path):
    d1 = digest_inputs([fixtures])
    assert d1 == digest_inputs([fixtures])  # deterministic
    (fixtures / "task1.json").write_text('{"q": 999}')
    assert digest_inputs([fixtures]) != d1
    with pytest.raises(ValueError, match="not found"):
        digest_inputs([tmp_path / "nope"])


def test_env_fingerprint_presence_only_never_values():
    env = {"MAVERICK_TENANT": "super-secret-tenant", "PATH": "/usr/bin"}
    fp = env_fingerprint(env)
    assert "MAVERICK_TENANT" in fp["present"]
    assert "PYTHONHASHSEED" in fp["absent"]
    assert "PATH" not in fp["present"] and "PATH" not in fp["absent"]
    assert "super-secret-tenant" not in json.dumps(fp)


# ---------------------------------------------------- recording wrapper ----

def test_record_writes_history_via_real_path_plus_manifest(tmp_path, fixtures):
    history = tmp_path / "history.json"
    manifest_path = record_with_manifest(
        "swe-mini", 0.41, commit="abc123", config={"n": 5},
        input_paths=[fixtures], history_path=history, now=1_750_000_000.0)
    # History recorded through continuous_benchmark, schema intact.
    rows = cb.load_history(history)
    assert [(r["name"], r["score"], r["commit"]) for r in rows] == [
        ("swe-mini", 0.41, "abc123")]
    # Manifest next to the result, atomic 0600.
    assert manifest_path is not None
    assert manifest_path.parent == history.parent / "manifests"
    assert private_path_is_restricted(manifest_path)
    assert private_path_is_restricted(manifest_path.parent, 0o700)
    m = json.loads(manifest_path.read_text())
    assert m["schema"] == SCHEMA and m["suite"] == "swe-mini"
    assert m["results"] == {"score": 0.41, "commit": "abc123"}
    assert set(m["host"]) == {"python", "platform", "cpu_count"}
    assert len(m["config_digest"]) == 64 and len(m["inputs_digest"]) == 64


def test_record_never_rewrites_existing_history(tmp_path):
    history = tmp_path / "history.json"
    cb.save_history(history, [{"name": "old", "score": 1.0, "commit": "", "t": 1.0}])
    before = json.loads(history.read_text())[0]
    record_with_manifest("new", 0.5, history_path=history)
    rows = json.loads(history.read_text())
    assert rows[0] == before  # historical row byte-identical
    assert len(rows) == 2
    # And no manifest is back-filled for the historical row.
    manifests = list((tmp_path / "manifests").glob("*.json"))
    assert len(manifests) == 1 and manifests[0].name.startswith("new-")


def test_same_suite_same_millisecond_runs_do_not_collide(tmp_path):
    # Two runs of the same suite at the identical timestamp must not overwrite
    # each other's manifest (the filename now carries a pid+random suffix).
    history = tmp_path / "history.json"
    ts = 1_750_000_000.0
    a = record_with_manifest("s", 0.1, history_path=history, now=ts)
    b = record_with_manifest("s", 0.2, history_path=history, now=ts)
    assert a is not None and b is not None
    assert a != b
    manifests = list((tmp_path / "manifests").glob("*.json"))
    assert len(manifests) == 2


def test_manifest_hook_opt_out(tmp_path, monkeypatch):
    history = tmp_path / "history.json"
    out = record_with_manifest("s", 0.5, history_path=history, write_manifest=False)
    assert out is None
    assert not (tmp_path / "manifests").exists()
    assert len(cb.load_history(history)) == 1  # history still recorded
    # Default is ON; env opt-out flips it.
    monkeypatch.delenv("MAVERICK_BENCH_REPRO", raising=False)
    assert enabled() is True
    monkeypatch.setenv("MAVERICK_BENCH_REPRO", "0")
    assert enabled() is False
    monkeypatch.setenv("MAVERICK_BENCH_REPRO", "1")
    assert enabled() is True


# ---------------------------------------------------------- comparisons ----

def _manifest(fixtures, *, config=None, suite="swe-mini", started=1.0):
    return build_manifest(suite, {"score": 0.4}, config=config or {"n": 1},
                          input_paths=[fixtures], started=started)


def test_identical_runs_are_comparable(fixtures):
    a = _manifest(fixtures)
    b = _manifest(fixtures, started=2.0)
    out = verify_reproduction(a, b)
    assert out["comparable"] and out["differs"] == []
    assert out["verdict"].startswith("comparable")


def test_config_or_inputs_difference_is_never_comparable(fixtures):
    base = _manifest(fixtures)
    other_cfg = _manifest(fixtures, config={"n": 2})
    out = verify_reproduction(base, other_cfg)
    assert not out["comparable"] and out["differs"] == ["config_digest"]
    assert "config_digest differs" in out["verdict"]

    (fixtures / "task1.json").write_text("changed")
    other_inputs = _manifest(fixtures)
    out2 = verify_reproduction(base, other_inputs)
    assert not out2["comparable"] and "inputs_digest" in out2["differs"]

    different_suite = _manifest(fixtures, suite="other")
    out3 = verify_reproduction(base, different_suite)
    assert not out3["comparable"] and "suite" in out3["differs"]

    # Property: ANY digest/suite mismatch forbids comparability.
    for variant in (other_cfg, other_inputs, different_suite):
        assert not verify_reproduction(base, variant)["comparable"]


def test_host_env_differences_are_informational_only(fixtures):
    a = _manifest(fixtures)
    b = json.loads(json.dumps(_manifest(fixtures)))
    b["host"] = {"python": "9.9.9", "platform": "other", "cpu_count": 1}
    out = verify_reproduction(a, b)
    assert out["comparable"]  # same suite+config+inputs
    assert out["informational_differs"] == ["host"]
    assert "host differs" in out["verdict"]


def test_non_manifest_inputs_rejected(fixtures):
    a = _manifest(fixtures)
    for bad in (None, {}, {"schema": "wrong/1"}, "junk"):
        out = verify_reproduction(a, bad)
        assert not out["comparable"] and out["differs"] == ["schema"]


# --------------------------------------------------------------- audits ----

def test_audit_report_flags_mixed_suites(tmp_path, fixtures):
    history = tmp_path / "history.json"
    record_with_manifest("stable", 0.4, config={"n": 1}, input_paths=[fixtures],
                         history_path=history, now=1.0)
    record_with_manifest("stable", 0.42, config={"n": 1}, input_paths=[fixtures],
                         history_path=history, now=2.0)
    record_with_manifest("drifty", 0.4, config={"n": 1}, input_paths=[fixtures],
                         history_path=history, now=3.0)
    record_with_manifest("drifty", 0.9, config={"n": 2}, input_paths=[fixtures],
                         history_path=history, now=4.0)
    (tmp_path / "manifests" / "junk.json").write_text("not json")

    report = audit_report(manifest_dir=tmp_path / "manifests")
    assert report["malformed"] == 1
    assert report["suites"]["stable"] == {
        "runs": 2, "distinct_config_digests": 1,
        "distinct_inputs_digests": 1, "comparable": True}
    drifty = report["suites"]["drifty"]
    assert drifty["runs"] == 2 and drifty["distinct_config_digests"] == 2
    assert drifty["comparable"] is False
