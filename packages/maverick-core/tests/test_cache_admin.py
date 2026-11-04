"""cache_admin tool + tool_cache.purge()."""
from __future__ import annotations

import pytest
from maverick.cache import tool as tool_cache
from maverick.tools.cache_admin import cache_admin


class _CacheableTool:
    name = "demo"
    parallel_safe = True  # cacheable() requires side-effect-free


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    tool_cache.reset()
    yield
    tool_cache.reset()


def _seed(name: str, n: int):
    t = _CacheableTool()
    t.name = name
    for i in range(n):
        tool_cache.store_cached(t, {"i": i}, f"val{i}")


def test_purge_by_tool_name():
    _seed("alpha", 3)
    _seed("beta", 2)
    assert tool_cache.stats()["size"] == 5
    assert tool_cache.purge("alpha") == 3
    assert tool_cache.stats()["size"] == 2  # only beta remains
    # purging counters survive (hit-rate history kept)
    assert "hits" in tool_cache.stats()


def test_purge_all():
    _seed("alpha", 3)
    assert tool_cache.purge() == 3
    assert tool_cache.stats()["size"] == 0


def test_tool_stats_op():
    _seed("alpha", 2)
    out = cache_admin().fn({"op": "stats"})
    assert "cache: on" in out and "size: 2" in out and "hit_rate:" in out


def test_tool_purge_op():
    _seed("alpha", 2)
    _seed("beta", 1)
    assert cache_admin().fn({"op": "purge", "tool": "alpha"}) == "purged 2 cached entries for 'alpha'"
    assert cache_admin().fn({"op": "purge"}) == "purged 1 cached entry"
    assert cache_admin().fn({"op": "purge"}) == "purged 0 cached entries"


def test_tool_unknown_op():
    assert cache_admin().fn({"op": "nope"}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "cache_admin" in names


def test_purge_non_string_tool_does_not_crash():
    # A model may pass a non-string 'tool'; must not raise.
    out = cache_admin().fn({"op": "purge", "tool": 5})
    assert out.startswith("purged")
