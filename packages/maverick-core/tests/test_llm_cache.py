"""Tests for the LLM response cache (maverick.cache.llm)."""
from __future__ import annotations

import time

# --- the LLM cache must not evict the row it just stored ---

def test_llm_cache_keeps_just_stored_entry(tmp_path):
    from maverick.cache.llm import LLMCache

    c = LLMCache(tmp_path / "c.db", max_rows=3)
    for i in range(3):
        c.store(f"k{i}", provider="p", model="m", text=f"t{i}")
        c.lookup(f"k{i}")  # give existing rows hit_count>=1
    c.store("knew", provider="p", model="m", text="new")
    # Under the old hit_count-first eviction this freshly-stored row was
    # deleted in the same call; it must survive now.
    assert c.lookup("knew") is not None


# ---------- llm_cache: row cap eviction ----------

def test_llm_cache_evicts_beyond_max_rows(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db", max_rows=3)
    # Insert 5 distinct keys; cap is 3.
    for i in range(5):
        cache.store(f"k{i}", provider="p", model="m", text=f"v{i}")
    s = cache.stats()
    assert s["entries"] <= 3, f"cap not enforced: {s['entries']} rows"


def test_llm_cache_eviction_is_lru_keeps_newest(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db", max_rows=2)
    cache.store("hot", provider="p", model="m", text="x")
    # hit_count is intentionally NOT the eviction key. A naive LFU policy
    # (ORDER BY hit_count DESC) evicted the just-inserted hit_count=0 row and
    # thrashed to ~0% hit rate under a stream of unique prompts, so eviction
    # is recency-based: keep the newest rows by created_at (see llm_cache.py).
    for _ in range(5):
        cache.lookup("hot")
    cache.store("a", provider="p", model="m", text="x")
    cache.store("b", provider="p", model="m", text="x")
    cache.store("c", provider="p", model="m", text="x")
    # Cap is 2; the two most-recently-stored keys survive, the oldest ("hot")
    # is evicted regardless of its hit_count.
    assert cache.lookup("c") is not None
    assert cache.lookup("b") is not None
    assert cache.lookup("hot") is None
    assert cache.stats()["entries"] == 2


def test_llm_cache_unbounded_when_max_rows_zero(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db", max_rows=0)
    for i in range(20):
        cache.store(f"k{i}", provider="p", model="m", text="x")
    assert cache.stats()["entries"] == 20


# ---------- LLM cache ----------

def test_llm_cache_key_stable():
    from maverick.cache.llm import cache_key
    a = cache_key(provider="anthropic", model="m", system="s",
                  messages=[{"role": "user", "content": "hi"}],
                  tools=[], max_tokens=100)
    b = cache_key(provider="anthropic", model="m", system="s",
                  messages=[{"role": "user", "content": "hi"}],
                  tools=[], max_tokens=100)
    c = cache_key(provider="anthropic", model="m", system="s",
                  messages=[{"role": "user", "content": "bye"}],
                  tools=[], max_tokens=100)
    assert a == b
    assert a != c


def test_llm_cache_lookup_miss_then_hit(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db")
    key = "abc"
    assert cache.lookup(key) is None
    cache.store(key, provider="anthropic", model="m", text="hello there",
                stop_reason="end_turn")
    hit = cache.lookup(key)
    assert hit is not None
    assert hit.text == "hello there"
    assert hit.stop_reason == "end_turn"
    assert hit.hit_count == 1
    # Bump count
    hit2 = cache.lookup(key)
    assert hit2.hit_count == 2


def test_llm_cache_ttl_expires(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db", ttl_seconds=1)
    cache.store("k", provider="p", model="m", text="x")
    assert cache.lookup("k") is not None
    # Lookup with a forced future timestamp drops the row.
    later = time.time() + 60
    assert cache.lookup("k", now=later) is None


def test_llm_cache_stats(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db")
    cache.store("a", provider="p", model="m", text="1")
    cache.store("b", provider="p", model="m", text="2")
    cache.lookup("a")
    s = cache.stats()
    assert s["entries"] == 2
    assert s["hits"] >= 1


def test_llm_cache_purge_expired(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db", ttl_seconds=10)
    cache.store("k", provider="p", model="m", text="x")
    # Force expiration window.
    deleted = cache.purge_expired(now=time.time() + 999)
    assert deleted == 1
    assert cache.lookup("k") is None


def test_llm_cache_clear(tmp_path):
    from maverick.cache.llm import LLMCache
    cache = LLMCache(db_path=tmp_path / "c.db")
    cache.store("a", provider="p", model="m", text="x")
    cache.clear()
    assert cache.lookup("a") is None


def test_llm_cache_enabled_via_env(monkeypatch):
    from maverick.cache import llm as llm_cache
    monkeypatch.setenv("MAVERICK_LLM_CACHE", "1")
    assert llm_cache.enabled() is True
    monkeypatch.setenv("MAVERICK_LLM_CACHE", "0")
    assert llm_cache.enabled() is False
