"""DGM lineage archive: bounded, diversity-aware, lineage-tracking, persistent.

The archive is the DGM's escape from the plateau -- it keeps a diverse population
(including worse ancestors) to branch from. These pin: id/digest stability,
score-ranked update-in-place, diversity eviction that keeps the best, lineage
walking, rolled-back dead ends excluded from best/sample, and round-trip persist.
"""
from __future__ import annotations

import json
import os
import random
import threading

import pytest
from maverick import self_modify_archive as archive_module
from maverick.file_lock import private_path_is_restricted
from maverick.self_modify_archive import (
    ArchivePersistenceError,
    CodeArchive,
    CodeCandidate,
)


def _cand(summary: str, patch: str, score: float, **kw) -> CodeCandidate:
    return CodeCandidate(summary=summary, patch=patch, score=score, **kw)


class TestCodeCandidate:
    def test_id_and_digest_are_derived(self):
        c = _cand("s", "+x", 1.0)
        assert len(c.id) == 32
        assert len(c.patch_sha256) == 64

    def test_same_content_same_id(self):
        assert _cand("s", "+x", 1.0).id == _cand("s", "+x", 2.0).id

    def test_different_patch_different_id(self):
        assert _cand("s", "+x", 1.0).id != _cand("s", "+y", 1.0).id

    def test_different_evidence_scope_has_different_identity(self):
        first = _cand("s", "+x", 1.0, evidence_scope="evaluation-a")
        second = _cand("s", "+x", 1.0, evidence_scope="evaluation-b")
        assert first.id != second.id

    def test_oversized_patch_body_is_dropped_digest_kept(self):
        big = "+" + ("a" * (300 * 1024))
        c = _cand("s", big, 1.0)
        assert c.patch == ""            # body dropped
        assert len(c.patch_sha256) == 64  # digest still pins it

    def test_nonempty_patch_rejects_forged_digest_and_id(self):
        with pytest.raises(ValueError, match="identity mismatch"):
            CodeCandidate(summary="s", patch="+x", patch_sha256="0" * 64)
        with pytest.raises(ValueError, match="identity mismatch"):
            CodeCandidate(summary="s", patch="+x", id="0" * 12)

    def test_improvement(self):
        assert _cand("s", "+x", 0.9, baseline_score=0.4).improvement == 0.5

    @pytest.mark.parametrize(("field", "value"), [
        ("promoted", "false"),
        ("rolled_back", 0),
        ("capability_widens", 1),
        ("samples", True),
        ("samples", "1"),
        ("generation", False),
        ("generation", "2"),
        ("score", True),
        ("created_at", False),
    ])
    def test_deserialization_rejects_coerced_bool_and_int_fields(self, field, value):
        payload = _cand("s", "+x", 1.0).to_dict()
        payload[field] = value
        with pytest.raises(ValueError, match="invalid code candidate record"):
            CodeCandidate.from_dict(payload)

    @pytest.mark.parametrize(("field", "value"), [
        ("promoted", "true"),
        ("rolled_back", 1),
        ("capability_widens", 0),
        ("samples", True),
        ("generation", False),
        ("score", True),
        ("created_at", False),
    ])
    def test_constructor_rejects_bool_int_type_confusion(self, field, value):
        kwargs = {"summary": "s", "patch": "+x", "score": 1.0, field: value}
        with pytest.raises(ValueError, match="invalid code candidate record"):
            CodeCandidate(**kwargs)


class TestArchiveCore:
    def test_add_and_get(self):
        a = CodeArchive()
        c = a.add(_cand("s", "+x", 1.0))
        assert a.get(c.id) is c

    def test_constructor_refuses_secret_bearing_candidate(self):
        secret = "sk-" + ("E" * 24)  # pragma: allowlist secret
        with pytest.raises(ValueError, match="detected secret material"):
            _cand("s", "+" + secret, 1.0)

    def test_add_rescans_mutated_candidate_before_persistence(self):
        candidate = _cand("s", "+clean", 1.0)
        candidate.patch = "sk-" + ("F" * 24)  # pragma: allowlist secret
        archive = CodeArchive()
        with pytest.raises(ValueError, match="detected secret material"):
            archive.add(candidate)
        assert archive.candidates == []

    def test_add_retains_a_canonical_copy_not_the_caller_alias(self):
        candidate = _cand("clean", "+clean", 1.0)
        archive = CodeArchive()

        stored = archive.add(candidate)
        candidate.summary = "sk-" + ("G" * 24)  # pragma: allowlist secret
        candidate.patch = "+changed"

        assert stored is not candidate
        assert archive.best().summary == "clean"
        assert archive.best().patch == "+clean"

    @pytest.mark.parametrize("field", ["summary", "parent_id", "reasons"])
    def test_serialization_rescans_all_mutable_string_metadata(self, field):
        secret = "sk-" + ("H" * 24)  # pragma: allowlist secret
        archive = CodeArchive()
        stored = archive.add(_cand("clean", "+clean", 1.0))
        setattr(stored, field, (secret,) if field == "reasons" else secret)

        with pytest.raises(ValueError, match="detected secret material"):
            archive.to_dict()

    def test_serialization_revalidates_mutated_patch_identity(self):
        archive = CodeArchive()
        stored = archive.add(_cand("clean", "+clean", 1.0))
        stored.patch = "+different"

        with pytest.raises(ValueError, match="identity mismatch"):
            archive.to_dict()

    def test_update_in_place_on_better_score(self):
        a = CodeArchive()
        a.add(_cand("s", "+x", 1.0))
        a.add(_cand("s", "+x", 2.0))          # same id, higher score
        assert len(a.candidates) == 1
        assert a.best().score == 2.0

    def test_better_score_replaces_the_complete_evidence_tuple(self):
        archive = CodeArchive()
        archive.add(_cand(
            "s", "+x", 1.0, baseline_score=0.2, samples=10,
            reasons=("old",), created_at=1.0,
        ))
        archive.add(_cand(
            "s", "+x", 2.0, baseline_score=1.5, samples=3,
            reasons=("new",), capability_widens=True, created_at=2.0,
        ))

        stored = archive.best()
        assert (stored.score, stored.baseline_score, stored.samples) == (2.0, 1.5, 3)
        assert stored.reasons == ("new",)
        assert stored.capability_widens is True
        assert stored.created_at == 2.0

    def test_lower_score_does_not_downgrade(self):
        a = CodeArchive()
        a.add(_cand("s", "+x", 2.0))
        a.add(_cand("s", "+x", 1.0))
        assert a.best().score == 2.0

    def test_best_excludes_rolled_back(self):
        a = CodeArchive()
        a.add(_cand("hi", "+x", 5.0, promoted=True, rolled_back=True))
        a.add(_cand("lo", "+y", 1.0))
        assert a.best().summary == "lo"      # the rolled-back 5.0 is a dead end

    def test_best_none_when_all_rolled_back(self):
        a = CodeArchive()
        a.add(_cand("s", "+x", 5.0, rolled_back=True))
        assert a.best() is None

    def test_mark_promoted_and_rolled_back(self):
        a = CodeArchive()
        c = a.add(_cand("s", "+x", 1.0))
        a.mark_promoted(c.id)
        assert a.get(c.id).promoted is True
        a.mark_rolled_back(c.id)
        assert a.get(c.id).rolled_back is True


class TestLineage:
    def test_ancestry_chain(self):
        a = CodeArchive()
        root = a.add(_cand("root", "+r", 1.0))
        child = a.add(_cand("child", "+c", 2.0, parent_id=root.id))
        grand = a.add(_cand("grand", "+g", 3.0, parent_id=child.id))
        chain = [c.summary for c in a.lineage(grand.id)]
        assert chain == ["grand", "child", "root"]

    def test_broken_parent_link_terminates(self):
        a = CodeArchive()
        c = a.add(_cand("only", "+c", 1.0, parent_id="deadbeef0000"))
        assert [x.summary for x in a.lineage(c.id)] == ["only"]

    def test_cyclic_parent_is_safe(self):
        a = CodeArchive()
        c = a.add(_cand("self", "+c", 1.0))
        c.parent_id = c.id                   # pathological self-cycle
        assert a.lineage(c.id) == [c]


class TestDiversityEviction:
    def test_eviction_keeps_capacity_and_the_best(self):
        a = CodeArchive(capacity=3)
        for i in range(10):
            a.add(_cand(f"s{i}", f"+line_{i} token_{i}", float(i)))
        assert len(a.candidates) == 3
        assert a.best().score == 9.0         # the top scorer survives

    def test_sample_excludes_rolled_back(self):
        a = CodeArchive()
        a.add(_cand("dead", "+x", 100.0, rolled_back=True))
        a.add(_cand("live", "+y", 1.0))
        rng = random.Random(0)
        picks = {a.sample(rng).summary for _ in range(20)}
        assert picks == {"live"}

    def test_sample_none_when_empty(self):
        assert CodeArchive().sample() is None

    def test_patch_distance_identical_is_zero(self):
        c = _cand("s", "+a b c", 1.0)
        assert CodeArchive.patch_distance(c, c) == 0.0

    def test_patch_distance_disjoint_is_one(self):
        d = CodeArchive.patch_distance(
            _cand("s", "+a b c", 1.0), _cand("t", "+x y z", 1.0))
        assert d == 1.0


class TestPersistence:
    def test_round_trip(self, tmp_path):
        a = CodeArchive(capacity=7)
        root = a.add(_cand("root", "+r", 1.0, promoted=True))
        a.add(_cand("child", "+c token", 2.0, parent_id=root.id, samples=8,
                    capability_widens=True, reasons=("network client",)))
        path = tmp_path / "arch.json"
        a.save(path)
        b = CodeArchive.load(path)
        assert b.capacity == 7
        assert len(b.candidates) == 2
        loaded = b.get(root.id)
        assert loaded.promoted is True
        child = next(c for c in b.candidates if c.summary == "child")
        assert child.parent_id == root.id
        assert child.capability_widens is True
        assert child.reasons == ("network client",)

    def test_round_trip_preserves_evidence_scope(self, tmp_path):
        archive = CodeArchive()
        candidate = archive.add(_cand(
            "scoped", "+x", 1.0, evidence_scope="captured-evaluation-a"))
        path = tmp_path / "scoped.json"
        archive.save(path)

        loaded = CodeArchive.load(path).get(candidate.id)
        assert loaded is not None
        assert loaded.evidence_scope == "captured-evaluation-a"
        assert loaded.id == candidate.id

    def test_load_missing_is_fresh(self, tmp_path):
        assert CodeArchive.load(tmp_path / "nope.json").candidates == []

    def test_load_corrupt_is_fresh(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        assert CodeArchive.load(p).candidates == []

    def test_saved_file_is_owner_only(self, tmp_path):
        p = tmp_path / "arch.json"
        CodeArchive().save(p)
        assert private_path_is_restricted(p, 0o600)

    def test_concurrent_saves_merge_lineage_without_lost_updates(self, tmp_path):
        path = tmp_path / "shared.json"
        first = CodeArchive()
        second = CodeArchive()
        first.add(_cand("first", "+first", 1.0))
        second.add(_cand("second", "+second", 2.0))
        barrier = threading.Barrier(2)
        failures = []

        def save(archive):
            try:
                barrier.wait(timeout=5)
                archive.save(path)
            except Exception as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        threads = [
            threading.Thread(target=save, args=(archive,))
            for archive in (first, second)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert failures == []
        assert all(not thread.is_alive() for thread in threads)
        assert {candidate.summary for candidate in CodeArchive.load(path).candidates} == {
            "first", "second",
        }

    def test_merge_preserves_existing_larger_capacity(self, tmp_path):
        path = tmp_path / "shared.json"
        existing = CodeArchive(capacity=5)
        for i in range(4):
            existing.add(_cand(f"existing-{i}", f"+existing-{i}", float(i)))
        existing.save(path)

        stale_small_writer = CodeArchive(capacity=1)
        stale_small_writer.add(_cand("incoming", "+incoming", 10.0))
        stale_small_writer.save(path)

        merged = CodeArchive.load(path)
        assert merged.capacity == 5
        assert {candidate.summary for candidate in merged.candidates} == {
            "existing-0", "existing-1", "existing-2", "existing-3", "incoming",
        }

    def test_save_refuses_symlinked_archive_without_touching_target(self, tmp_path):
        target = tmp_path / "outside.json"
        original = b'{"capacity": 100, "candidates": []}'
        target.write_bytes(original)
        path = tmp_path / "archive.json"
        try:
            path.symlink_to(target)
        except (NotImplementedError, OSError):
            pytest.skip("symlink creation is not available")
        archive = CodeArchive()
        archive.add(_cand("clean", "+clean", 1.0))

        with pytest.raises(ArchivePersistenceError):
            archive.save(path)

        assert target.read_bytes() == original
        assert CodeArchive.load(path).candidates == []

    def test_save_refuses_hardlinked_archive(self, tmp_path):
        target = tmp_path / "outside.json"
        original = b'{"capacity": 100, "candidates": []}'
        target.write_bytes(original)
        path = tmp_path / "archive.json"
        try:
            os.link(target, path)
        except (NotImplementedError, OSError):
            pytest.skip("hard-link creation is not available")
        archive = CodeArchive()
        archive.add(_cand("clean", "+clean", 1.0))

        with pytest.raises(ArchivePersistenceError):
            archive.save(path)

        assert target.read_bytes() == original
        assert CodeArchive.load(path).candidates == []

    def test_save_and_load_refuse_oversized_existing_archive(
        self, tmp_path, monkeypatch,
    ):
        path = tmp_path / "archive.json"
        original = b"x" * 129
        path.write_bytes(original)
        monkeypatch.setattr(archive_module, "_MAX_ARCHIVE_BYTES", 128)
        archive = CodeArchive()
        archive.add(_cand("clean", "+clean", 1.0))

        with pytest.raises(ArchivePersistenceError):
            archive.save(path)

        assert path.read_bytes() == original
        assert CodeArchive.load(path).candidates == []

    def test_save_refuses_to_overwrite_corrupt_existing_evidence(self, tmp_path):
        path = tmp_path / "corrupt.json"
        original = b'{"capacity": 100, "candidates": [{"forged": true}]}'
        path.write_bytes(original)
        archive = CodeArchive()
        archive.add(_cand("clean", "+clean", 1.0))

        with pytest.raises(ArchivePersistenceError):
            archive.save(path)

        assert path.read_bytes() == original

    def test_mutate_after_add_cannot_replace_a_clean_archive_file(self, tmp_path):
        path = tmp_path / "arch.json"
        archive = CodeArchive()
        stored = archive.add(_cand("clean", "+clean", 1.0))
        archive.save(path)
        clean_bytes = path.read_bytes()

        secret = "sk-" + ("I" * 24)  # pragma: allowlist secret
        stored.reasons = (secret,)
        with pytest.raises(ArchivePersistenceError):
            archive.save(path)

        assert path.read_bytes() == clean_bytes
        assert secret not in path.read_text(encoding="utf-8")

    def test_save_failure_is_typed_and_generic(self, tmp_path, monkeypatch):
        archive = CodeArchive()
        archive.add(_cand("clean", "+clean", 1.0))
        monkeypatch.setattr(archive, "to_dict", lambda: (_ for _ in ()).throw(
            OSError("sensitive filesystem detail")))

        with pytest.raises(ArchivePersistenceError) as exc:
            archive.save(tmp_path / "arch.json")

        assert "sensitive filesystem detail" not in str(exc.value)

    def test_load_skips_forged_nonempty_candidate_identity(self, tmp_path):
        path = tmp_path / "arch.json"
        path.write_text(json.dumps({
            "capacity": 5,
            "candidates": [{
                "id": "0" * 12,
                "summary": "clean",
                "patch": "+clean",
                "patch_sha256": "0" * 64,
            }],
        }), encoding="utf-8")

        assert CodeArchive.load(path).candidates == []
