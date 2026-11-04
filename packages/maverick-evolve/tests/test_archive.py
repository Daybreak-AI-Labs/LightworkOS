from __future__ import annotations

import hashlib
import json
import random

import pytest
from maverick_evolve.archive import Archive, Candidate


def _payload_digest(payload: dict) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_add_and_best():
    a = Archive()
    a.add(Candidate(config={"x": 1}, score=0.5))
    a.add(Candidate(config={"x": 2}, score=0.9))
    assert a.best().config == {"x": 2}


def test_config_identity_uses_complete_sha256():
    config = {"persona": "careful", "fanout": 4}
    expected = hashlib.sha256(
        json.dumps(config, sort_keys=True).encode("utf-8")).hexdigest()
    candidate = Candidate(config=config)

    assert candidate.id == expected
    assert len(candidate.id) == 64
    assert all(ch in "0123456789abcdef" for ch in candidate.id)
    with pytest.raises(ValueError, match="does not match"):
        Candidate(config=config, id=expected[:12])


def test_schema_v2_truncated_ids_migrate_to_full_digest(tmp_path):
    config = {"persona": "legacy", "fanout": 2}
    full_id = hashlib.sha256(
        json.dumps(config, sort_keys=True).encode("utf-8")).hexdigest()
    payload = {
        "capacity": 50,
        "candidates": [{"config": config, "score": 0.75, "id": full_id[:12]}],
    }
    path = tmp_path / "legacy-v2.json"
    path.write_text(json.dumps({
        "schema_version": 2,
        "payload": payload,
        "sha256": _payload_digest(payload),
    }), encoding="utf-8")

    archive = Archive.load(path)
    assert archive.candidates[0].id == full_id
    archive.save(path)
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == 4
    assert migrated["payload"]["candidates"][0]["id"] == full_id
    assert migrated["payload"]["confirmed_candidate_id"] is None


def test_schema_v3_refuses_truncated_or_mismatched_ids():
    config = {"x": 1}
    full_id = hashlib.sha256(
        json.dumps(config, sort_keys=True).encode("utf-8")).hexdigest()
    for bad_id in (full_id[:12], "0" * 64):
        payload = {
            "capacity": 50,
            "candidates": [{"config": config, "score": 0.5, "id": bad_id}],
        }
        envelope = {
            "schema_version": 3,
            "payload": payload,
            "sha256": _payload_digest(payload),
        }
        with pytest.raises(ValueError, match="archive payload is invalid"):
            Archive.from_dict(envelope)


def test_legacy_unenveloped_archive_migrates_missing_or_short_id():
    config = {"x": 1}
    expected = Candidate(config=config).id
    archive = Archive.from_dict({
        "capacity": 2,
        "candidates": [
            {"config": config, "score": 0.2, "id": expected[:12]},
        ],
    })
    assert archive.candidates[0].id == expected


def test_archive_revalidates_mutable_candidate_identity_before_use(tmp_path):
    archive = Archive()
    candidate = Candidate(config={"x": {"nested": 1}}, score=0.5)
    archive.add(candidate)
    candidate.config["x"]["nested"] = 2

    with pytest.raises(ValueError, match="does not match"):
        archive.best()
    with pytest.raises(ValueError, match="does not match"):
        archive.save(tmp_path / "poisoned.json")
    assert not (tmp_path / "poisoned.json").exists()


def test_save_refuses_archive_its_loader_would_reject(tmp_path, monkeypatch):
    import maverick_evolve.archive as archive_module

    archive = Archive()
    archive.add(Candidate(config={"x": "large-enough"}, score=0.5))
    monkeypatch.setattr(archive_module, "_MAX_ARCHIVE_BYTES", 64)
    path = tmp_path / "oversized.json"
    with pytest.raises(ValueError, match="size limit"):
        archive.save(path)
    assert not path.exists()


@pytest.mark.parametrize("config", [
    {"x": float("nan")},
    {"x": float("inf")},
    {1: "non-string-key"},
    {"x": ("tuple",)},
])
def test_candidate_identity_rejects_noncanonical_config(config):
    with pytest.raises(ValueError):
        Candidate(config=config)


def test_archive_rejects_envelope_downgrade_and_duplicate_json_keys(tmp_path):
    with pytest.raises(ValueError, match="legacy archive body is malformed"):
        Archive.from_dict({"payload": {"capacity": 50, "candidates": []}})

    path = tmp_path / "duplicate.json"
    path.write_text('{"capacity":50,"capacity":1,"candidates":[]}', encoding="utf-8")
    with pytest.raises(ValueError, match="cannot be read as JSON"):
        Archive.load(path)


def test_dedup_keeps_higher_score():
    a = Archive()
    a.add(Candidate(config={"x": 1}, score=0.5))
    a.add(Candidate(config={"x": 1}, score=0.8))  # same config id
    assert len(a.candidates) == 1
    assert a.best().score == 0.8


def test_archive_confirmation_tracks_only_the_exact_current_best():
    archive = Archive()
    first = archive.add(Candidate(config={"x": 1}, score=0.5))
    archive.mark_confirmed(first.id)
    assert archive.confirmed_best().id == first.id

    second = archive.add(Candidate(config={"x": 2}, score=0.9))
    assert archive.confirmed_best() is None
    archive.mark_confirmed(second.id)
    assert archive.confirmed_best().id == second.id


def test_archive_refuses_confirmation_of_non_best_candidate():
    archive = Archive()
    lower = archive.add(Candidate(config={"x": 1}, score=0.5))
    archive.add(Candidate(config={"x": 2}, score=0.9))
    with pytest.raises(ValueError, match="current archive best"):
        archive.mark_confirmed(lower.id)


def test_config_distance():
    assert Archive.config_distance({"a": 1}, {"a": 1}) == 0.0
    assert Archive.config_distance({"a": 1}, {"a": 2}) == 1.0
    d = Archive.config_distance({"a": 1, "b": 1}, {"a": 1, "b": 2})
    assert 0.0 < d < 1.0


def test_diverse_picks_best_plus_distant():
    a = Archive()
    a.add(Candidate(config={"k": "aaa"}, score=1.0))   # best
    a.add(Candidate(config={"k": "aaa", "extra": 1}, score=0.9))  # near best
    a.add(Candidate(config={"j": "zzz"}, score=0.8))   # distant
    div = a.diverse(2)
    ids = {c.config.get("k") or c.config.get("j") for c in div}
    assert "aaa" in ids and "zzz" in ids  # best + the distant one, not the near-dup


def test_capacity_eviction_preserves_best():
    a = Archive(capacity=2)
    a.add(Candidate(config={"id": 0}, score=1.0))
    a.add(Candidate(config={"id": 1}, score=0.1))
    a.add(Candidate(config={"id": 2}, score=0.2))
    assert len(a.candidates) <= 2
    assert a.best().config == {"id": 0}


def test_eviction_breaks_distance_ties_by_score():
    """When candidates are mutually equidistant (no shared config keys), the
    greedy diversity pick must break ties by score so eviction never drops a
    stronger candidate for a weaker one."""
    a = Archive(capacity=3)
    a.add(Candidate(config={"a": 1}, score=0.1))
    a.add(Candidate(config={"b": 1}, score=0.9))
    a.add(Candidate(config={"c": 1}, score=0.8))
    a.add(Candidate(config={"d": 1}, score=0.7))  # triggers eviction
    kept = sorted(c.score for c in a.candidates)
    # The stronger 0.7 must survive; the weakest 0.1 is evicted.
    assert kept == [0.7, 0.8, 0.9]


def test_sample_favors_higher_score():
    a = Archive()
    a.add(Candidate(config={"x": 1}, score=1.0))
    a.add(Candidate(config={"x": 2}, score=0.1))
    rng = random.Random(0)
    counts = {1: 0, 2: 0}
    for _ in range(200):
        counts[a.sample(rng).config["x"]] += 1
    # Both lineages stay reachable, but the higher score is sampled more often.
    assert counts[1] > counts[2] and counts[2] >= 0


def test_sample_empty_returns_none():
    assert Archive().sample(random.Random(0)) is None


def test_save_is_atomic_no_temp_residue(tmp_path):
    """save() must write atomically (temp + rename) so a crash mid-write can't
    leave a half-written, unloadable archive. Verify round-trip + no .tmp left."""
    from maverick_evolve.archive import Archive, Candidate

    path = tmp_path / "archive.json"
    arc = Archive()
    arc.add(Candidate(config={"orchestrator": "x"}, score=0.5))
    arc.save(path)
    arc.save(path)  # overwrite an existing file -- the atomic-rename path

    assert path.exists()
    assert not (tmp_path / "archive.json.tmp").exists()  # no leftover temp
    assert list(tmp_path.glob("*.tmp")) == []
    reloaded = Archive.load(path)
    assert len(reloaded.candidates) == len(arc.candidates)


def test_concurrent_saves_leave_a_valid_archive(tmp_path):
    """A fixed ".tmp" collides between two concurrent saves; a unique temp keeps
    each writer's temp private so the file is always a valid, loadable archive."""
    import threading

    from maverick_evolve.archive import Archive, Candidate

    path = tmp_path / "archive.json"
    n = 12

    def worker(i: int):
        arc = Archive()
        arc.add(Candidate(config={"orchestrator": f"v{i}"}, score=0.5))
        arc.save(path)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(Archive.load(path).candidates) >= 1  # valid, loadable
    assert list(tmp_path.glob("*.tmp")) == []
