"""The Consequence Engine: record real outcomes, resolve them, and prefer
reality over the proxy -- only when enabled (OFF by default)."""
from __future__ import annotations

import json
import os

import pytest
from maverick import consequence as cq


def test_record_resolve_roundtrip(tmp_path):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    assert store.resolve(1, 7) is None
    store.record(1, 7, 1.0, kind="invoice_paid")
    assert store.resolve(1, 7) == 1.0


def test_latest_event_wins(tmp_path):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    store.record(1, 7, 1.0, kind="renewed", ts=10.0)
    store.record(1, 7, 0.0, kind="churned", ts=20.0)   # reality changed; newest wins
    assert store.resolve(1, 7) == 0.0


def test_value_is_clamped(tmp_path):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    store.record(1, 1, 5.0)
    store.record(1, 2, -3.0)
    assert store.resolve(1, 1) == 1.0 and store.resolve(1, 2) == 0.0


def test_persists_across_reload(tmp_path):
    p = tmp_path / "c.ndjson"
    cq.ConsequenceStore(path=p).record(2, 3, 0.7, kind="graded")
    assert cq.ConsequenceStore(path=p).resolve(2, 3) == 0.7


def test_grounded_outcome_prefers_reality_only_when_enabled(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    store.record(1, 7, 1.0)  # reality says success...

    # disabled (default): keep the proxy
    monkeypatch.setattr("maverick.config.get_consequence", lambda: {"enable": False})
    monkeypatch.delenv("MAVERICK_CONSEQUENCE", raising=False)
    assert cq.grounded_outcome(1, 7, proxy=0.4, store=store) == 0.4

    # enabled: prefer reality where it has landed, else fall back to the proxy
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    assert cq.grounded_outcome(1, 7, proxy=0.4, store=store) == 1.0
    assert cq.grounded_outcome(9, 9, proxy=0.4, store=store) == 0.4   # no real outcome yet


def test_record_outcome_public_entry(tmp_path):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    assert cq.record_outcome(5, 5, 0.9, store=store) is True
    assert cq.resolve(5, 5, store=store) == 0.9


# ---- record_self_outcome (first-party grounding) ---------------------------


class _FakeEpisode:
    def __init__(self, id):
        self.id = id


class _FakeWorld:
    def __init__(self, episodes):
        self._episodes = episodes

    def list_episodes(self, goal_id=None, limit=50):
        return self._episodes[:limit]


def test_record_self_outcome_gated_off_by_default(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setattr("maverick.config.get_consequence", lambda: {"enable": False})
    monkeypatch.delenv("MAVERICK_CONSEQUENCE", raising=False)
    w = _FakeWorld([_FakeEpisode(42)])
    # disabled: no-op returning False, nothing stored
    assert cq.record_self_outcome(w, 7, 0.0, kind="failed", store=store) is False
    assert store.resolve(7, 42) is None


def test_record_self_outcome_grounds_latest_episode_when_enabled(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    w = _FakeWorld([_FakeEpisode(99)])
    assert cq.record_self_outcome(w, 7, 0.0, kind="failed", store=store) is True
    assert store.resolve(7, 99) == 0.0


def test_record_self_outcome_no_episode_is_false(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    assert cq.record_self_outcome(_FakeWorld([]), 7, 1.0, kind="x", store=store) is False


def test_record_self_outcome_never_raises(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")

    class _Boom:
        def list_episodes(self, **_):
            raise RuntimeError("db down")

    assert cq.record_self_outcome(_Boom(), 1, 0.0, kind="x", store=store) is False


# ---- outcome correlation (external business key -> episode) -----------------


def test_correlation_link_and_resolve_roundtrip(tmp_path):
    corr = cq.CorrelationStore(path=tmp_path / "links.ndjson")
    assert corr.resolve("invoice:INV-1") is None
    assert corr.link("invoice:INV-1", 7, 42) is True
    assert corr.resolve("invoice:INV-1") == (7, 42)


def test_correlation_latest_link_wins(tmp_path):
    corr = cq.CorrelationStore(path=tmp_path / "links.ndjson")
    corr.link("ticket:9", 1, 1, ts=10.0)
    corr.link("ticket:9", 2, 2, ts=20.0)   # a later run re-touched the entity
    assert corr.resolve("ticket:9") == (2, 2)


def test_correlation_empty_key_rejected(tmp_path):
    corr = cq.CorrelationStore(path=tmp_path / "links.ndjson")
    assert corr.link("   ", 1, 1) is False
    assert corr.count() == 0


def test_correlation_persists_across_reload(tmp_path):
    p = tmp_path / "links.ndjson"
    cq.CorrelationStore(path=p).link("deal:ACME", 3, 5)
    assert cq.CorrelationStore(path=p).resolve("deal:ACME") == (3, 5)


def test_correlation_native_workers_keep_the_latest_link_and_ignore_torn_rows(tmp_path):
    path = tmp_path / "linked-workers.ndjson"
    first, second = cq.CorrelationStore(path=path), cq.CorrelationStore(path=path)
    assert first.link("invoice:42", 1, 7, ts=10)
    assert second.resolve("invoice:42") == (1, 7)
    assert second.link("invoice:42", 2, 8, ts=20)
    assert first.resolve("invoice:42") == (2, 8)
    assert first.link("invoice:42", 1, 7, ts=15)
    assert first.resolve("invoice:42") == second.resolve("invoice:42") == (2, 8)
    assert not first.link("x" * 257, 3, 9)
    with path.open("ab") as stream:
        stream.write(b'{"key":"invoice:42","goal_id":3,"episode_id":9,"ts":30}')
    assert second.resolve("invoice:42") == (2, 8)
    # The unconfirmed torn row is discarded, not revived, and linking resumes.
    assert first.link("invoice:42", 4, 10, ts=25)
    assert first.resolve("invoice:42") == second.resolve("invoice:42") == (4, 10)
    assert first.count() == second.count() == 1


def test_an_interrupted_append_does_not_stop_later_reports(tmp_path):
    path = tmp_path / "torn.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert store.record(1, 7, 1.0, kind="paid", ts=10)
    complete = path.read_bytes()
    with path.open("ab") as stream:
        stream.write(b'{"episode_id":8,"goal_id":1,"kind":"pa')
    assert store.resolve(1, 7) == 1.0
    assert store.record(1, 8, 0.0, kind="payment_reversed", ts=20)
    assert store.record(1, 9, 1.0, kind="paid", ts=30)
    raw = path.read_bytes()
    assert raw.startswith(complete) and raw.endswith(b"\n")
    assert [json.loads(line)["episode_id"] for line in raw.splitlines()] == [7, 8, 9]
    reloaded = cq.ConsequenceStore(path=path)
    assert (reloaded.resolve(1, 7), reloaded.resolve(1, 8), reloaded.resolve(1, 9)) == (1.0, 0.0, 1.0)
    only_fragment = tmp_path / "fragment.ndjson"
    only_fragment.write_bytes(b'{"episode_id":1,"go')
    assert cq.ConsequenceStore(path=only_fragment).record(2, 3, 1.0, kind="paid", ts=5)
    assert [json.loads(line)["goal_id"] for line in only_fragment.read_bytes().splitlines()] == [2]


def test_correlation_late_write_failure_preserves_prior_binding(tmp_path, monkeypatch):
    path = tmp_path / "linked-late-failure.ndjson"
    store = cq.CorrelationStore(path=path)
    assert store.link("invoice:42", 1, 7)
    original = path.read_bytes()
    native_sync, failures = os.fsync, []
    inode = path.stat().st_ino

    def fail_first_data_sync(fd):
        if os.fstat(fd).st_ino == inode:
            failures.append(fd)
            if len(failures) == 1:
                raise OSError("completed append could not be synced")
        return native_sync(fd)

    monkeypatch.setattr(cq.os, "fsync", fail_first_data_sync)
    assert not store.link("invoice:42", 2, 8)
    assert path.read_bytes() == original
    assert store.resolve("invoice:42") == (1, 7)


def test_record_outcome_for_key_grounds_when_linked(tmp_path):
    cstore = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    corr = cq.CorrelationStore(path=tmp_path / "links.ndjson")
    corr.link("invoice:INV-2", 8, 3)
    # reality reports back with only the business key
    assert cq.record_outcome_for_key("invoice:INV-2", 1.0, kind="paid",
                                     store=cstore, corr=corr) is True
    assert cstore.resolve(8, 3) == 1.0


def test_record_outcome_for_key_unmatched_is_false(tmp_path):
    cstore = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    corr = cq.CorrelationStore(path=tmp_path / "links.ndjson")
    # no run ever linked this key -> nothing grounded
    assert cq.record_outcome_for_key("invoice:UNKNOWN", 1.0, store=cstore, corr=corr) is False


def test_record_outcome_for_key_respects_authorize(tmp_path):
    cstore = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    corr = cq.CorrelationStore(path=tmp_path / "links.ndjson")
    corr.link("invoice:INV-3", 8, 3)
    # authorize denies -> not recorded
    assert cq.record_outcome_for_key("invoice:INV-3", 1.0, store=cstore, corr=corr,
                                     authorize=lambda g, e: False) is False
    assert cstore.resolve(8, 3) is None
    # authorize allows the resolved target -> recorded
    assert cq.record_outcome_for_key("invoice:INV-3", 1.0, store=cstore, corr=corr,
                                     authorize=lambda g, e: (g, e) == (8, 3)) is True
    assert cstore.resolve(8, 3) == 1.0


def test_reset_shared_reresolves_correlation_path(tmp_path, monkeypatch):
    # reset_shared clears the cached singleton so a later call re-resolves the
    # (tenant/HOME-scoped) path -- the isolation seam tests rely on. The NDJSON
    # itself persists on disk, like the ConsequenceStore.
    first = tmp_path / "a"
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: first.joinpath(*p))
    cq.reset_shared()
    cq.shared_correlation().link("k", 1, 1)
    assert cq.shared_correlation().resolve("k") == (1, 1)
    # a fresh home + reset -> a distinct, empty store
    second = tmp_path / "b"
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: second.joinpath(*p))
    cq.reset_shared()
    assert cq.shared_correlation().resolve("k") is None


def test_business_report_survives_feedback_signoff_and_newer_correction(tmp_path):
    path = tmp_path / "classified.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert store.record(1, 7, 1.0, kind="invoice_paid", ts=10)
    assert store.record(1, 7, 0.0, kind="feedback", source="human_feedback", ts=20)
    assert store.record(1, 7, 0.0, kind="signoff", ts=21)
    assert store.resolve(1, 7) == 1.0
    assert cq.ConsequenceStore(path=path).resolve(1, 7) == 1.0
    assert store.record(1, 7, 0.0, kind="invoice_reversed", source="reported_business", ts=30)
    assert store.record(1, 7, 1.0, kind="feedback", source="human_feedback", ts=40)
    assert store.record(1, 7, 1.0, kind="invoice_paid", ts=25)
    assert store.resolve(1, 7) == 0.0
    assert cq.ConsequenceStore(path=path).resolve(1, 7) == 0.0
    assert store.count() == 1
    assert len(path.read_text().splitlines()) == 6


def test_local_fallback_uses_timestamp_and_append_ties_live_and_reloaded(tmp_path):
    path = tmp_path / "local.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert store.record(1, 7, 0.0, kind="failed", source="execution_verdict", ts=10)
    assert store.record(1, 7, 1.0, kind="feedback", source="human_feedback", ts=20)
    assert store.record(1, 7, 0.0, kind="failed", source="execution_verdict", ts=15)
    assert store.resolve(1, 7) == 1.0
    assert cq.ConsequenceStore(path=path).resolve(1, 7) == 1.0
    assert store.record(1, 7, 0.0, kind="failed", source="execution_verdict", ts=20)
    assert store.resolve(1, 7) == 0.0
    assert cq.ConsequenceStore(path=path).resolve(1, 7) == 0.0


def test_legacy_kinds_and_unknown_reports_keep_honest_precedence(tmp_path):
    path = tmp_path / "legacy.ndjson"
    rows = [{"goal_id": 1, "episode_id": 7, "ts": 10, "value": .75, "kind": "renewed"},
            *[{"goal_id": 1, "episode_id": 7, "ts": 20 + index, "value": 0, "kind": kind}
              for index, kind in enumerate(("feedback", "signoff", "edit", "failed"))],
            {"goal_id": 2, "episode_id": 8, "ts": 40, "value": .4, "kind": ""},
            {"goal_id": 1, "episode_id": 7, "ts": 50, "value": 0, "kind": "paid", "source": "externally_verified"},
            {"goal_id": 1, "episode_id": 7, "ts": float("nan"), "value": 0, "kind": "paid"}]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    store = cq.ConsequenceStore(path=path)
    assert store.resolve(1, 7) == .75
    assert store.resolve(2, 8) == .4
    assert store.count() == 2
    assert len(path.read_text().splitlines()) == 8


def test_failed_append_and_invalid_provenance_do_not_change_resolution(tmp_path, monkeypatch):
    path = tmp_path / "failed.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert store.record(1, 7, 1.0, kind="paid", ts=10)
    assert store.resolve(1, 7) == 1.0
    original = path.read_bytes()
    opener = os.open

    def unavailable(filename, *args, **kwargs):
        if str(filename) == str(path):
            raise OSError("synthetic append unavailable")
        return opener(filename, *args, **kwargs)

    monkeypatch.setattr(cq.os, "open", unavailable)
    assert not store.record(1, 7, 0.0, kind="payment_reversed", ts=20)
    assert store.resolve(1, 7) == 1.0
    assert not store.record(1, 7, 0.0, source="verified", ts=30)
    for stamp in (float("nan"), float("inf"), -1, True):
        assert not store.record(1, 7, 0.0, ts=stamp)
    assert store.resolve(1, 7) == 1.0
    assert path.read_bytes() == original


def test_independent_native_workers_refresh_each_others_business_records(tmp_path):
    path = tmp_path / "workers.ndjson"
    first, second = cq.ConsequenceStore(path=path), cq.ConsequenceStore(path=path)
    assert first.record(1, 7, 1.0, kind="paid", ts=10)
    assert second.resolve(1, 7) == 1.0
    assert second.record(1, 7, 0.0, kind="feedback", ts=20)
    assert first.resolve(1, 7) == 1.0
    assert second.record(1, 7, 0.0, kind="payment_reversed", ts=30)
    assert first.resolve(1, 7) == 0.0
    assert first.record(1, 7, 1.0, kind="signoff", ts=40)
    assert second.resolve(1, 7) == 0.0
    assert first.count() == second.count() == 1


def test_self_outcome_cannot_masquerade_as_business_by_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    path = tmp_path / "self.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert cq.record_self_outcome(_FakeWorld([_FakeEpisode(99)]), 7, 1.0, kind="invoice_paid", store=store)
    assert json.loads(path.read_text())["source"] == "execution_verdict"
    assert store.record(7, 99, 0.0, kind="invoice_not_paid", ts=10)
    assert store.resolve(7, 99) == 0.0


def test_complete_append_fsync_failure_removes_only_attempted_suffix(tmp_path, monkeypatch):
    path = tmp_path / "late-failure.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert store.record(1, 7, 1.0, kind="paid", ts=10)
    original = path.read_bytes()
    sync, data_syncs = os.fsync, []
    inode = path.stat().st_ino

    def fail_first_data_sync(fd):
        if os.fstat(fd).st_ino == inode:
            data_syncs.append(fd)
            if len(data_syncs) == 1:
                assert path.read_bytes().startswith(original)
                assert len(path.read_bytes()) > len(original)
                raise OSError("synthetic late fsync failure")
        return sync(fd)

    monkeypatch.setattr(cq.os, "fsync", fail_first_data_sync)
    assert not store.record(1, 7, 0.0, kind="payment_reversed", ts=20)
    assert len(data_syncs) == 2
    assert path.read_bytes() == original
    assert store.resolve(1, 7) == 1.0
    assert cq.ConsequenceStore(path=path).resolve(1, 7) == 1.0


def test_unverified_late_append_cleanup_reports_uncertainty(tmp_path, monkeypatch):
    path = tmp_path / "uncertain.ndjson"
    store = cq.ConsequenceStore(path=path)
    assert store.record(1, 7, 1.0, kind="paid", ts=10)
    assert store.resolve(1, 7) == 1.0
    original, inode = path.read_bytes(), path.stat().st_ino
    sync, truncate = os.fsync, os.ftruncate

    def fail_sync(fd):
        if os.fstat(fd).st_ino == inode:
            raise OSError("synthetic late fsync failure")
        return sync(fd)

    def fail_cleanup(fd, size):
        if os.fstat(fd).st_ino == inode:
            raise OSError("synthetic cleanup unavailable")
        return truncate(fd, size)

    monkeypatch.setattr(cq.os, "fsync", fail_sync)
    monkeypatch.setattr(cq.os, "ftruncate", fail_cleanup)
    with pytest.raises(cq.ConsequenceWriteUncertain, match="may have been written"):
        store.record(1, 7, 0.0, kind="payment_reversed", ts=20)
    assert path.read_bytes().startswith(original)
    assert len(path.read_bytes()) > len(original)
    assert store._loaded_stamp == ()


def test_local_uncertainty_keeps_task_output_and_is_not_confirmed_failure(monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")

    def uncertain(*args, **kwargs):
        raise cq.ConsequenceWriteUncertain("synthetic original write unconfirmed")

    monkeypatch.setattr(cq, "record_outcome", uncertain)
    assert cq.record_self_outcome(_FakeWorld([_FakeEpisode(99)]), 7, 1.0, kind="signoff") is None
