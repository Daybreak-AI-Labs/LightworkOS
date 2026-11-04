"""Artifact identity/recovery; this does not claim trained-model quality."""
from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick_shield import cascade, redteam
from maverick_shield import probe_model as pm


@pytest.fixture
def cache(tmp_path, monkeypatch):
    pm._reset_cache()
    path = tmp_path / "probe.json"
    clock = [100.0]
    monkeypatch.setenv("MAVERICK_SHIELD_PROBE_MODEL", str(path))
    monkeypatch.setattr(pm.time, "monotonic", lambda: clock[0])
    yield path, clock
    pm._reset_cache()


def publish(path, *, bias=0.0, version="v1", **changes):
    artifact = {
        "schema_version": 1, "artifact_version": version,
        "feature_schema": pm.FEATURE_SCHEMA, "bias": bias,
        "weights": {"regex_hit": 2.0}, **changes,
    }
    pending = path.with_suffix(".new")
    pending.write_text(json.dumps(artifact), encoding="utf-8")
    pending.replace(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_same_path_same_mtime_replacement_is_detected_after_refresh(cache):
    path, clock = cache
    first_digest = publish(path, bias=-1, version="v1")
    stamp = path.stat()
    first = pm.configured_probe_model()
    second_digest = publish(path, bias=1, version="v2")
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert pm.configured_probe_model() is first
    clock[0] += pm._REFRESH_SECONDS
    second = pm.configured_probe_model()
    assert second is not first and second.bias == 1.0
    status = pm.configured_probe_status()
    assert status["state"] == "active"
    assert status["active_sha256"] == second_digest != first_digest
    assert status["artifact_version"] == "v2" and status["schema_version"] == 1
    assert str(path) not in json.dumps(status)


def test_negative_cache_expires_and_recovers_without_restart(cache, monkeypatch):
    path, clock = cache
    loads = []
    actual = pm._load_artifact

    def load(location):
        loads.append(location)
        return actual(location)

    monkeypatch.setattr(pm, "_load_artifact", load)
    assert pm.configured_probe_model() is None
    publish(path)
    assert pm.configured_probe_model() is None
    assert len(loads) == 1
    clock[0] += pm._FAILED_REFRESH_SECONDS
    assert pm.configured_probe_model() is not None
    assert len(loads) == 2
    assert pm.configured_probe_status()["state"] == "active"


def test_malformed_replacement_retains_immutable_last_good_and_explicit_status(cache):
    path, clock = cache
    good_digest = publish(path, bias=-1)
    good = pm.configured_probe_model()
    with pytest.raises(TypeError):
        good.weights["regex_hit"] = -100
    path.write_text('{"bias":NaN,"weights":{}}', encoding="utf-8")
    bad_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    clock[0] += pm._REFRESH_SECONDS
    assert pm.configured_probe_model() is good
    status = pm.configured_probe_status()
    assert status["state"] == "stale_rejected"
    assert status["active_sha256"] == good_digest
    assert status["rejected_sha256"] == bad_digest
    publish(path, bias=3, version="repaired")
    clock[0] += pm._FAILED_REFRESH_SECONDS
    assert pm.configured_probe_model().bias == 3.0
    assert pm.configured_probe_status()["state"] == "active"


@pytest.mark.parametrize("changes", [
    {"bias": float("nan")}, {"bias": float("inf")}, {"bias": True},
    {"weights": {"regex_hit": float("-inf")}}, {"weights": []},
    {"threshold": 2}, {"ngram_buckets": -1}, {"ngram_buckets": 1.5},
    {"ngram_buckets": 100_000_000}, {"ngram_sizes": [0]},
    {"ngram_sizes": []}, {"ngram_sizes": [True]},
    {"schema_version": 2}, {"schema_version": True},
    {"feature_schema": "different-feature-contract"}, {"artifact_version": ""},
])
def test_replacement_validation_is_complete_before_publication(cache, changes):
    path, clock = cache
    publish(path)
    good = pm.configured_probe_model()
    publish(path, **changes)
    clock[0] += pm._REFRESH_SECONDS
    assert pm.configured_probe_model() is good
    assert pm.configured_probe_status()["state"] == "stale_rejected"


def test_duplicate_json_fields_and_oversized_files_are_rejected(cache):
    path, _clock = cache
    path.write_text('{"bias":1,"bias":2}', encoding="utf-8")
    assert pm.load_probe_model(path) is None
    path.write_bytes(b" " * (pm._MAX_ARTIFACT_BYTES + 1))
    assert pm.load_probe_model(path) is None


def test_tenant_or_path_change_never_reuses_another_active_model(cache, monkeypatch):
    from maverick import paths

    path, clock = cache
    publish(path, bias=1)
    actor = ["tenant-a"]
    monkeypatch.setattr(paths, "current_tenant_id", lambda: actor[0])
    a = pm.configured_probe_model()
    publish(path, bias=2)
    actor[0] = "tenant-b"
    b = pm.configured_probe_model()
    assert b is not a and b.bias == 2.0
    actor[0] = "tenant-a"
    assert pm.configured_probe_model() is a  # Each tenant has its own refresh state.
    monkeypatch.setenv("MAVERICK_SHIELD_PROBE_MODEL", str(path.with_name("absent.json")))
    assert pm.configured_probe_model() is None
    clock[0] += pm._REFRESH_SECONDS
    assert pm.configured_probe_model() is None


def test_concurrent_refresh_publishes_one_validated_object(cache, monkeypatch):
    path, clock = cache
    publish(path, bias=1)
    pm.configured_probe_model()
    publish(path, bias=2)
    clock[0] += pm._REFRESH_SECONDS
    loads = []
    actual = pm._load_artifact

    def load(location):
        loads.append(location)
        return actual(location)

    monkeypatch.setattr(pm, "_load_artifact", load)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: pm.configured_probe_model(), range(32)))
    assert len(loads) == 1
    assert len({id(model) for model in results}) == 1
    assert results[0].bias == 2.0


def test_cache_entry_count_is_bounded(cache, monkeypatch):
    from maverick import paths

    path, _clock = cache
    publish(path)
    for index in range(pm._MAX_CACHE_ENTRIES + 5):
        monkeypatch.setattr(paths, "current_tenant_id", lambda i=index: f"tenant-{i}")
        assert pm.configured_probe_model() is not None
    assert len(pm._cached) == pm._MAX_CACHE_ENTRIES


def test_fixed_corpus_detector_floor_survives_reloads_and_rejection(cache):
    path, clock = cache
    cases = redteam.load_corpus()
    assert len(cases) >= 20
    baseline = {case.id: cascade.cheap_probe(case.text, model=None) for case in cases}
    for version, bias in (("low", -10), ("high", 10)):
        publish(path, bias=bias, version=version)
        clock[0] += pm._REFRESH_SECONDS
        for case in cases:
            observed = cascade.cheap_probe(case.text)
            floor = baseline[case.id]
            assert 0.0 <= floor.score <= observed.score <= 1.0
            assert not floor.flagged or observed.flagged
    path.write_text("malformed replacement", encoding="utf-8")
    clock[0] += pm._REFRESH_SECONDS
    for case in cases:
        observed = cascade.cheap_probe(case.text)
        assert observed.score >= baseline[case.id].score
    assert pm.configured_probe_status()["state"] == "stale_rejected"


def test_legacy_artifact_has_explicit_schema_zero(cache):
    path, _clock = cache
    path.write_text('{"bias":0,"weights":{"regex_hit":2}}', encoding="utf-8")
    assert pm.configured_probe_model() is not None
    assert pm.configured_probe_status()["schema_version"] == 0
    assert pm.configured_probe_status()["artifact_version"] == "unversioned"
