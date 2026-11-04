"""The catalog never sits on a run's critical path.

Inside ``catalog.cached_first()`` an index is served from the on-disk cache
at any age and refreshed in the background; a missing index counts as empty
for that call and is fetched for the next one. Outside the block, the
blocking fetch-with-cache behaviour is unchanged.
"""
from __future__ import annotations

import json
import threading
import time

import pytest
from maverick import catalog


def _index(entries):
    return {"entries": entries}


def _entry(name="e1"):
    return {"name": name, "summary": "s", "source": "https://x/e1.md",
            "sha256": "0" * 64, "version": "1"}


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog, "_CACHE_DIR", tmp_path / "catalog-cache")
    # No refresh threads leak between tests.
    monkeypatch.setattr(catalog, "_REFRESHING", set())


def _fake_network(monkeypatch, calls, *, data=None):
    """A ``_fetch_index_raw`` stand-in that records synchronous callers."""
    def fetch(url):
        calls.append((threading.current_thread().name, url))
        return data
    monkeypatch.setattr(catalog, "_fetch_index_raw", fetch)


def test_cached_first_serves_a_stale_index_without_waiting(monkeypatch, tmp_path):
    url = "https://a/skills/index.json"
    cache = catalog._cache_path(url)
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps(_index([_entry("stale-but-present")])))
    old = time.time() - 2 * catalog._CACHE_TTL
    import os
    os.utime(cache, (old, old))
    calls: list = []
    _fake_network(monkeypatch, calls)
    with catalog.cached_first():
        entries = catalog.load_catalog("skills", indexes=["https://a"])
    assert [e.name for e in entries] == ["stale-but-present"]
    # The refresh ran, but on its own thread, not the caller's.
    deadline = time.time() + 5
    while not calls and time.time() < deadline:
        time.sleep(0.01)
    assert calls and calls[0][0] != threading.current_thread().name


def test_cached_first_with_no_cache_is_empty_now_and_fetches_for_next_time(monkeypatch):
    calls: list = []
    _fake_network(monkeypatch, calls, data=_index([_entry("later")]))
    with catalog.cached_first():
        assert catalog.load_catalog("skills", indexes=["https://b"]) == []
    deadline = time.time() + 5
    while not calls and time.time() < deadline:
        time.sleep(0.01)
    assert calls == [(calls[0][0], "https://b/skills/index.json")]
    assert calls[0][0] != threading.current_thread().name


def test_cached_first_fresh_cache_schedules_no_refresh(monkeypatch):
    url = "https://c/skills/index.json"
    cache = catalog._cache_path(url)
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps(_index([_entry("fresh")])))
    calls: list = []
    _fake_network(monkeypatch, calls)
    with catalog.cached_first():
        entries = catalog.load_catalog("skills", indexes=["https://c"])
    assert [e.name for e in entries] == ["fresh"]
    time.sleep(0.05)
    assert calls == []


def test_outside_the_block_load_catalog_still_fetches_synchronously(monkeypatch):
    calls: list = []
    _fake_network(monkeypatch, calls, data=_index([_entry("direct")]))
    entries = catalog.load_catalog("skills", indexes=["https://d"])
    assert [e.name for e in entries] == ["direct"]
    assert calls == [(threading.current_thread().name, "https://d/skills/index.json")]


def test_one_background_refresh_per_url_at_a_time(monkeypatch):
    started = threading.Event()
    release = threading.Event()
    calls: list = []

    def slow_fetch(url):
        calls.append(url)
        started.set()
        release.wait(5)
        return None

    monkeypatch.setattr(catalog, "_fetch_index_raw", slow_fetch)
    with catalog.cached_first():
        catalog.load_catalog("skills", indexes=["https://e"])
        assert started.wait(5)
        catalog.load_catalog("skills", indexes=["https://e"])  # refresh already in flight
    release.set()
    time.sleep(0.05)
    assert calls == ["https://e/skills/index.json"]


def test_preflight_search_runs_inside_cached_first(monkeypatch):
    """The self-learning preflight is the latency-sensitive caller."""
    from maverick import self_learning

    seen: list[bool] = []

    def search(need, **kw):
        seen.append(catalog._CACHED_FIRST.get())
        return []

    monkeypatch.setattr(self_learning, "search_capabilities", search)
    monkeypatch.setattr(self_learning, "provider_egress_enabled", lambda: False)
    monkeypatch.setattr(self_learning, "check_learning_halt", lambda *a, **k: None)
    # Preflight searches only once signed skill preparation is ready (trusted
    # publishers, signature checking); that readiness has its own tests.
    monkeypatch.setattr(self_learning, "skill_acquisition_readiness", lambda: {"ready": True})
    monkeypatch.setattr("maverick.skills.load_skills", list)
    import asyncio

    from maverick.budget import Budget
    acquired = asyncio.run(self_learning.preflight(object(), "text my mom", Budget(), None))
    assert acquired == []
    assert seen == [True]
    assert catalog._CACHED_FIRST.get() is False
