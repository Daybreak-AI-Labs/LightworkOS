"""Temporal memory + Memory Guard provenance on the world-model fact store.

Temporal history is opt-in ([memory] temporal / MAVERICK_TEMPORAL_MEMORY); when
off the live-value path is unchanged. Provenance columns are written regardless,
so trust-aware retrieval governs existing facts the moment the guard turns on.
"""
from __future__ import annotations

import time

from maverick.world_model import SCHEMA_VERSION, WorldModel


def _wm(tmp_path) -> WorldModel:
    return WorldModel(tmp_path / "world.db")


def test_schema_is_current(tmp_path):
    assert _wm(tmp_path).schema_version == SCHEMA_VERSION


def test_overwrite_when_temporal_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_TEMPORAL_MEMORY", raising=False)
    w = _wm(tmp_path)
    w.upsert_fact("k", "v1")
    w.upsert_fact("k", "v2")
    assert w.get_fact("k") == "v2"
    # No history is recorded when temporal is off -- behaviour is unchanged.
    assert w.fact_history("k") == []
    assert w.get_fact("k", as_of=time.time()) is None


def test_temporal_preserves_history(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    w.upsert_fact("hq", "Boston")
    t_mid = time.time()
    time.sleep(0.01)
    w.upsert_fact("hq", "San Francisco")

    # Current value is the latest; the old value is NOT lost.
    assert w.get_fact("hq") == "San Francisco"
    # As-of the instant between the writes, we believed Boston.
    assert w.get_fact("hq", as_of=t_mid) == "Boston"

    hist = w.fact_history("hq")
    assert [h.value for h in hist] == ["San Francisco", "Boston"]
    assert hist[0].valid_to is None       # newest version still open
    assert hist[1].valid_to is not None   # prior version was closed


def test_temporal_unchanged_value_adds_no_version(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    w.upsert_fact("k", "same")
    w.upsert_fact("k", "same")  # confirmation, not a change
    assert len(w.fact_history("k")) == 1


def test_temporal_delete_closes_window(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    w.upsert_fact("k", "v")
    w.delete_fact("k")
    assert w.get_fact("k") is None
    hist = w.fact_history("k")
    assert len(hist) == 1 and hist[0].valid_to is not None  # history survives delete


def test_temporal_delete_window_survives_clock_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    now = [1_000.0]
    monkeypatch.setattr("maverick.world_model.time.time", lambda: now[0])
    w = _wm(tmp_path)

    w.upsert_fact("k", "v")
    now[0] = 999.0
    assert w.delete_fact("k") == 1

    [version] = w.fact_history("k")
    assert version.valid_to is not None
    assert version.valid_to > version.valid_from


def test_temporal_change_after_rollback_reassertion_keeps_valid_window(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    now = [1_000.0]
    monkeypatch.setattr("maverick.world_model.time.time", lambda: now[0])
    w = _wm(tmp_path)

    w.upsert_fact("k", "v1")
    now[0] = 900.0
    w.upsert_fact("k", "v1")  # no new version, rolled-back wall timestamp
    now[0] = 901.0
    w.upsert_fact("k", "v2")

    new, old = w.fact_history("k")
    assert new.valid_from > old.valid_from
    assert old.valid_to == new.valid_from
    assert old.valid_to >= old.valid_from


def test_provenance_stored(tmp_path):
    w = _wm(tmp_path)
    w.upsert_fact("trusted", "ok")  # default = first-party trust (3)
    w.upsert_fact("agentnote", "maybe", source="agent:kv_memory", trust_tier=1)
    meta = w.get_facts_with_trust()
    assert meta["trusted"] == ("ok", 3)
    assert meta["agentnote"] == ("maybe", 1)  # the Memory Guard filters on this


def test_provenance_recorded_even_without_temporal(tmp_path, monkeypatch):
    # Provenance populates regardless of the temporal toggle, so enabling the
    # guard later governs already-stored memory immediately.
    monkeypatch.delenv("MAVERICK_TEMPORAL_MEMORY", raising=False)
    w = _wm(tmp_path)
    w.upsert_fact("a", "x", trust_tier=0)
    assert w.get_facts_with_trust()["a"] == ("x", 0)  # tier stored without temporal
    assert w.get_facts() == {"a": "x"}


def test_erase_purges_fact_history(tmp_path, monkeypatch):
    # GDPR Art.17: delete_facts_matching must hard-purge the temporal history,
    # or erased PII survives in fact_history and via get_fact(as_of=...).
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    k = "user:telegram:u1:addr"
    w.upsert_fact(k, "old place")
    t0 = time.time()
    time.sleep(0.01)
    w.upsert_fact(k, "new place")
    assert len(w.fact_history(k)) == 2          # history accrued

    removed = w.delete_facts_matching("telegram:u1")
    assert removed == [k]
    assert k not in w.get_facts()
    assert w.fact_history(k) == []              # history purged, not just closed
    assert w.get_fact(k, as_of=t0) is None      # erased PII not reconstructable


def test_trust_change_records_new_version(tmp_path, monkeypatch):
    # A re-assertion of the same value by a different-trust source is a distinct
    # belief and gets its own validity window.
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    w.upsert_fact("k", "v", trust_tier=1)       # tool trust
    w.upsert_fact("k", "v", trust_tier=3)       # same value, first-party re-assert
    hist = w.fact_history("k")
    assert [h.trust_tier for h in hist] == [3, 1]
    assert hist[0].valid_to is None and hist[1].valid_to is not None


def test_erase_purges_history_of_already_deleted_key(tmp_path, monkeypatch):
    # A user-scoped fact deleted earlier keeps its value in fact_history (window
    # closed). A later subject-erase must still purge it -- delete_facts_matching
    # works the whole user:<token>: prefix, not just currently-live keys.
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    old = "user:telegram:u9:old"
    cur = "user:telegram:u9:cur"
    w.upsert_fact(old, "old secret")
    w.delete_fact(old)               # window closed, value retained in history
    w.upsert_fact(cur, "current secret")
    assert w.fact_history(old)       # the deleted key still has history

    w.delete_facts_matching("telegram:u9")
    assert w.fact_history(old) == []                  # purged despite being gone
    assert w.fact_history(cur) == []
    assert w.fact_history_matching("telegram:u9") == {}


def test_fact_history_matching_scopes_to_subject(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    w.upsert_fact("user:sms:alice:addr", "A1")
    w.upsert_fact("user:sms:alice:addr", "A2")  # evolves -> 2 versions
    w.upsert_fact("user:sms:bob:addr", "B1")    # different subject
    w.upsert_fact("global", "G")                # unrelated
    hist = w.fact_history_matching("sms:alice")
    assert set(hist) == {"user:sms:alice:addr"}
    assert [v.value for v in hist["user:sms:alice:addr"]] == ["A1", "A2"]  # asc


def test_fact_history_matching_is_case_sensitive(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    lower = "user:sms:alice:addr"
    upper = "user:sms:Alice:addr"
    w.upsert_fact(lower, "lower")
    w.upsert_fact(upper, "upper")

    hist = w.fact_history_matching("sms:alice")
    assert set(hist) == {lower}
    assert [v.value for v in hist[lower]] == ["lower"]


def test_delete_facts_matching_history_purge_is_case_sensitive(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    w = _wm(tmp_path)
    lower = "user:sms:alice:addr"
    upper = "user:sms:Alice:addr"
    w.upsert_fact(lower, "lower")
    w.upsert_fact(upper, "upper")

    assert w.delete_facts_matching("sms:alice") == [lower]
    assert w.fact_history(lower) == []
    assert [v.value for v in w.fact_history(upper)] == ["upper"]
    assert w.get_fact(upper) == "upper"
