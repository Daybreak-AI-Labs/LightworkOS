"""Feature reuse must equal full recomputation with all current evidence."""
from __future__ import annotations

import copy
import re
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import async_compaction as ac
from maverick import context_compactor as cc


@pytest.fixture(autouse=True)
def local_counter(monkeypatch):
    monkeypatch.setattr(cc, "_token_counter", False)


def _history(n=12):
    return [{"role": "system" if i == 0 else "user" if i % 2 else "assistant",
             "content": f"topic_{i} " * 24} for i in range(n)]


def test_advancing_rewritten_rolled_and_changed_query_equal_full_recomputation(monkeypatch):
    prepared = []
    original = cc.prepare_features
    def prepare(text):
        prepared.append(text)
        return original(text)
    monkeypatch.setattr(cc, "prepare_features", prepare)
    compactor = ac.BackgroundCompactor()
    history = _history(14)
    scenarios = [(history[:8], 90, 8), (history[:10], 90, 2),
                 (history[:12], 130, 2), (history[2:14], 90, 2)]
    rewritten = copy.deepcopy(history[2:14])
    rewritten[2]["content"] = "new evidence " * 20
    scenarios.append((rewritten, 90, 1))
    changed_query = copy.deepcopy(rewritten)
    changed_query[-1]["content"] = "topic_6 " * 24
    scenarios.append((changed_query, 250, 0))
    for messages, target, expected_new in scenarios:
        before = len(prepared)
        expected = cc.compact(messages, target_tokens=target).messages
        assert compactor.compact_with_precompute("k", messages, target_tokens=target) == expected
        assert len(prepared) - before == expected_new


def test_changed_query_recovers_evidence_previously_dropped():
    history = [{"role": "user", "content": f"topic_{i} " * 20} for i in range(10)]
    compactor = ac.BackgroundCompactor()
    first = compactor.compact_with_precompute("k", history, target_tokens=240)
    assert history[2] not in first
    history[-1] = {"role": "user", "content": "topic_2 " * 20}
    second = compactor.compact_with_precompute("k", history, target_tokens=240)
    assert history[2] in second
    assert second == cc.compact(history, target_tokens=240).messages


def test_identity_invalidates_tokenizer_and_lexical_strategy(monkeypatch):
    compactor = ac.BackgroundCompactor()
    history = _history()
    compactor.compact_with_precompute("k", history, target_tokens=100)
    monkeypatch.setattr(cc, "_token_counter", lambda text: len(text))
    assert compactor.compact_with_precompute("k", history, target_tokens=100) == (
        cc.compact(history, target_tokens=100).messages)
    monkeypatch.setattr(cc, "_TOKEN_PATTERN", re.compile(r"topic_[02468]"))
    assert compactor.compact_with_precompute("k", history, target_tokens=600) == (
        cc.compact(history, target_tokens=600).messages)


def test_transient_count_failure_is_not_cached(monkeypatch):
    broken = True
    def count(text):
        if broken:
            raise RuntimeError("temporary local tokenizer failure")
        return len(text)
    monkeypatch.setattr(cc, "_token_counter", count)
    compactor = ac.BackgroundCompactor()
    history = _history()
    compactor.compact_with_precompute("k", history, target_tokens=100)
    broken = False
    assert compactor.compact_with_precompute("k", history, target_tokens=500) == (
        cc.compact(history, target_tokens=500).messages)


def test_oversized_history_and_keys_are_not_retained(monkeypatch):
    monkeypatch.setattr(ac, "_MAX_WINDOW_BYTES", 500)
    compactor = ac.BackgroundCompactor()
    history = _history()
    assert compactor.compact_with_precompute("k", history, target_tokens=90) == (
        cc.compact(history, target_tokens=90).messages)
    assert compactor.stats()["cached_keys"] == 0
    monkeypatch.setattr(ac, "_MAX_WINDOW_BYTES", 100_000)
    compactor.compact_with_precompute("k" * 513, history, target_tokens=90)
    assert compactor.stats()["cached_keys"] == 0


def test_storage_bound_applies_across_keys(monkeypatch):
    monkeypatch.setattr(ac, "_MAX_BYTES", 5000)
    compactor = ac.BackgroundCompactor()
    for i in range(20):
        compactor.compact_with_precompute(str(i), _history(2), target_tokens=90)
        assert compactor.stats()["retained_feature_bytes"] <= 5000


def test_tenant_namespaces_do_not_share_entries(monkeypatch):
    compactor = ac.BackgroundCompactor()
    monkeypatch.setattr(ac, "current_tenant_id_strict", lambda: "tenant-a")
    compactor.compact_with_precompute("k", _history(), target_tokens=90)
    monkeypatch.setattr(ac, "current_tenant_id_strict", lambda: "tenant-b")
    compactor.compact_with_precompute("k", _history(), target_tokens=90)
    assert compactor.stats()["cached_keys"] == 2


def test_nested_rewrite_does_not_mutate_cached_snapshot():
    compactor = ac.BackgroundCompactor()
    history = _history()
    history[2]["content"] = [{"type": "text", "text": "old source " * 20}]
    compactor.compact_with_precompute("k", history, target_tokens=90)
    history[2]["content"][0]["text"] = "updated source " * 20
    assert compactor.compact_with_precompute("k", history, target_tokens=200) == (
        cc.compact(history, target_tokens=200).messages)
    cached = next(iter(compactor._cache.values()))
    with pytest.raises(TypeError):
        cached.features["tampered"] = None


def test_concurrent_windows_are_correct_and_context_is_reset():
    compactor = ac.BackgroundCompactor()
    histories = [_history(8 + i % 8) for i in range(32)]
    def compact(history):
        result = compactor.compact_with_precompute("k", history, target_tokens=150)
        assert cc._FEATURES.get() is None
        return result
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(compact, histories))
    assert results == [cc.compact(h, target_tokens=150).messages for h in histories]


def test_context_is_reset_after_compactor_failure(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("local compactor failed")
    monkeypatch.setattr(cc, "compact", broken)
    with pytest.raises(RuntimeError):
        ac.BackgroundCompactor().compact_with_precompute("k", _history(), target_tokens=90)
    assert cc._FEATURES.get() is None
