"""Locked, backend-portable fact helpers on WorldModel.

kv_memory (and others) must not reach into ``world.conn.execute(... ?)`` directly,
which would bypass the read lock and use SQLite-only ``?`` placeholders. These helpers
are the locked replacements; this pins their behavior, especially LIKE-escaping
so a key/query containing % or _ is matched literally.
"""
from __future__ import annotations

from pathlib import Path

from maverick.world_model import WorldModel


def _wm(tmp_path: Path) -> WorldModel:
    return WorldModel(tmp_path / "world.db")


def test_get_and_delete_fact(tmp_path):
    w = _wm(tmp_path)
    w.upsert_fact("goal:1:color", "blue")
    assert w.get_fact("goal:1:color") == "blue"
    assert w.get_fact("goal:1:missing") is None
    assert w.delete_fact("goal:1:color") == 1
    assert w.get_fact("goal:1:color") is None
    assert w.delete_fact("goal:1:color") == 0  # already gone


def test_list_facts_scoped_by_prefix(tmp_path, monkeypatch):
    # The byte-size assertion is defined on the stored plaintext; under the
    # secure default an unset flag seals values, so opt out explicitly.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    w = _wm(tmp_path)
    w.upsert_fact("goal:1:a", "x")
    w.upsert_fact("goal:1:b", "yy")
    w.upsert_fact("goal:2:c", "zzz")  # different goal -> excluded
    listed = dict(w.list_facts("goal:1:"))
    assert set(listed) == {"goal:1:a", "goal:1:b"}
    assert listed["goal:1:b"] == 2  # value byte size


def test_search_facts_matches_key_or_value(tmp_path):
    w = _wm(tmp_path)
    w.upsert_fact("goal:1:fruit", "apple")
    w.upsert_fact("goal:1:veg", "carrot")
    by_value = w.search_facts("goal:1:", "appl")
    assert [k for k, _ in by_value] == ["goal:1:fruit"]
    by_key = w.search_facts("goal:1:", "veg")
    assert [k for k, _ in by_key] == ["goal:1:veg"]


def test_search_escapes_like_wildcards(tmp_path):
    w = _wm(tmp_path)
    w.upsert_fact("goal:1:k", "a_b")
    w.upsert_fact("goal:1:k2", "axb")
    # "a_b" must match literally, NOT as the LIKE pattern a<any>b (which would
    # also pull in "axb").
    hits = {v for _, v in w.search_facts("goal:1:", "a_b")}
    assert hits == {"a_b"}
    # A bare "%" must not match everything.
    assert w.search_facts("goal:1:", "%") == []


def test_prefix_isolation_is_not_substring(tmp_path):
    w = _wm(tmp_path)
    w.upsert_fact("goal:1:a", "x")
    w.upsert_fact("goal:12:a", "y")  # goal 12, must not leak into goal 1
    listed = dict(w.list_facts("goal:1:"))
    assert set(listed) == {"goal:1:a"}
