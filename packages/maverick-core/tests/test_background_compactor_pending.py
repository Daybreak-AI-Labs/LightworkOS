"""The compatibility cache is bounded and starts no background work."""
from __future__ import annotations

from maverick import async_compaction as ac


def test_cache_is_bounded_without_pending_work(monkeypatch):
    monkeypatch.setattr(ac._cc, "_token_counter", False)
    def forbidden_executor(work):
        raise AssertionError("obsolete worker must not start")
    bc = ac.BackgroundCompactor(executor=forbidden_executor)
    for i in range(ac._MAX_KEYS + 50):
        bc.compact_with_precompute(f"key-{i}", [{"role": "user", "content": "x"}],
                                   target_tokens=10)
    assert bc.stats()["cached_keys"] == ac._MAX_KEYS
    assert bc.stats()["pending"] == 0
    assert bc.stats()["retained_feature_bytes"] <= ac._MAX_BYTES


def test_cache_replaces_same_key_and_close_releases_history(monkeypatch):
    monkeypatch.setattr(ac._cc, "_token_counter", False)
    bc = ac.BackgroundCompactor()
    for _ in range(10):
        bc.compact_with_precompute("k", [{"role": "user", "content": "x"}], target_tokens=10)
    assert bc.stats()["cached_keys"] == 1
    bc.close()
    bc.close()
    assert bc.compact_with_precompute("k", [{"role": "user", "content": "x"}],
                                      target_tokens=10) == [{"role": "user", "content": "x"}]
    assert bc.stats() == {"cached_keys": 0, "pending": 0, "retained_feature_bytes": 0}
