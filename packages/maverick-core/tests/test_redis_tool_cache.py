"""Redis tool-cache backend against a fake in-memory redis client injected via
sys.modules: hit/miss/store TTL paths, namespace-scoped purge, fail-open on
every redis error (including a missing client package), key parity with
tool_cache._key, and the config wiring. Fully offline."""
from __future__ import annotations

import fnmatch
import sys
import types

from maverick.cache import redis_tool as rtc
from maverick.cache.tool import _key as local_key


class FakeRedisClient:
    def __init__(self):
        self.data: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.setex_calls: list[tuple[str, int]] = []
        self.set_calls: list[str] = []
        self.from_url_kwargs: dict = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value, *, nx=False):
        if nx and key in self.data:
            return None
        self.data[key] = value
        self.set_calls.append(key)

    def setex(self, key, ttl, value):
        self.data[key] = value
        self.ttls[key] = ttl
        self.setex_calls.append((key, ttl))

    def scan_iter(self, match=None, count=None):
        del count  # accepted like the real client; irrelevant to the fake
        for key in list(self.data):
            if match is None or fnmatch.fnmatch(key, match):
                yield key

    def delete(self, *keys):
        removed = 0
        for key in keys:
            if self.data.pop(key, None) is not None:
                removed += 1
        return removed


class BoomClient:
    """Every operation raises, like a dead/unauthed redis."""

    def _boom(self, *a, **k):
        raise ConnectionError("redis is down")

    get = set = setex = delete = _boom

    def scan_iter(self, *a, **k):
        raise ConnectionError("redis is down")


def _install_fake_redis(monkeypatch, client):
    mod = types.ModuleType("redis")

    def from_url(url, **kwargs):
        client.from_url_kwargs = {"url": url, **kwargs}
        return client

    mod.Redis = types.SimpleNamespace(from_url=from_url)
    monkeypatch.setitem(sys.modules, "redis", mod)
    return client


def test_miss_store_hit(monkeypatch):
    client = _install_fake_redis(monkeypatch, FakeRedisClient())
    cache = rtc.RedisToolCache("redis://test:6379/0")
    assert cache.get("repo_map", {"path": "."}) == (False, None)
    cache.store("repo_map", {"path": "."}, "the map")
    assert cache.get("repo_map", {"path": "."}) == (True, "the map")
    stats = cache.stats()
    assert stats["hits"] == 1 and stats["misses"] == 1 and stats["size"] == 1
    assert client.from_url_kwargs["url"] == "redis://test:6379/0"
    # An unreachable Redis must not hang the cache lock (redis-py waits forever by default).
    assert 0 < client.from_url_kwargs["socket_timeout"] <= 5
    assert 0 < client.from_url_kwargs["socket_connect_timeout"] <= 5


def test_ttl_uses_setex_else_set(monkeypatch):
    client = _install_fake_redis(monkeypatch, FakeRedisClient())
    with_ttl = rtc.RedisToolCache(ttl_s=60)
    with_ttl.store("t", {"a": 1}, "v")
    assert client.setex_calls and client.setex_calls[0][1] == 60
    assert not client.set_calls
    no_ttl = rtc.RedisToolCache()
    no_ttl.store("t2", {"a": 1}, "v2")
    assert client.set_calls  # plain SET when no TTL configured


def test_key_parity_with_tool_cache(monkeypatch):
    client = _install_fake_redis(monkeypatch, FakeRedisClient())
    cache = rtc.RedisToolCache(namespace="mvk:toolcache")
    cache.store("read_file", {"path": "a.py", "lines": 5}, "content")
    expected = "mvk:toolcache:" + local_key("read_file", {"path": "a.py", "lines": 5})
    assert list(client.data) == [expected]
    # Canonicalization: arg order doesn't change identity.
    hit, value = cache.get("read_file", {"lines": 5, "path": "a.py"})
    assert (hit, value) == (True, "content")


def test_error_results_never_cached(monkeypatch):
    client = _install_fake_redis(monkeypatch, FakeRedisClient())
    cache = rtc.RedisToolCache()
    cache.store("sh", {"cmd": "x"}, "ERROR: transient failure")
    cache.store("sh", {"cmd": "x"}, 12345)  # non-string
    assert client.data == {}


def test_purge_is_namespace_and_tool_scoped(monkeypatch):
    client = _install_fake_redis(monkeypatch, FakeRedisClient())
    cache = rtc.RedisToolCache()
    cache.store("repo_map", {"p": 1}, "a")
    cache.store("read_file", {"p": 1}, "b")
    client.data["someone-elses:key"] = "do not touch"
    assert cache.purge("repo_map") == 1
    assert cache.get("read_file", {"p": 1})[0] is True
    assert cache.purge() == 1  # the remaining namespaced entry
    assert client.data == {"someone-elses:key": "do not touch"}  # foreign key untouched


def test_redis_errors_fail_open(monkeypatch):
    _install_fake_redis(monkeypatch, BoomClient())
    cache = rtc.RedisToolCache()
    assert cache.get("t", {"a": 1}) == (False, None)  # error -> miss, no raise
    cache.store("t", {"a": 1}, "v")                   # error -> no-op, no raise
    assert cache.purge() == 0
    assert cache.stats() == {"hits": 0, "misses": 1, "size": 0}


def test_missing_redis_package_fails_open(monkeypatch):
    monkeypatch.setitem(sys.modules, "redis", None)  # `import redis` -> ImportError
    cache = rtc.RedisToolCache()
    assert cache.get("t", {}) == (False, None)
    cache.store("t", {}, "v")  # no raise


def test_off_by_default_and_env_wiring(monkeypatch):
    monkeypatch.delenv("MAVERICK_TOOL_CACHE_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_TOOL_CACHE_REDIS_URL", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", lambda *a, **k: {})
    assert rtc.enabled() is False
    assert rtc.from_config() is None
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_BACKEND", "redis")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_REDIS_URL", "redis://envhost:6379/2")
    assert rtc.enabled() is True
    cache = rtc.from_config()
    assert cache is not None and cache.url == "redis://envhost:6379/2"


def test_config_table_wiring(monkeypatch):
    monkeypatch.delenv("MAVERICK_TOOL_CACHE_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_TOOL_CACHE_REDIS_URL", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(
        config_mod, "load_config",
        lambda *a, **k: {"tools": {
            "output_cache_backend": "redis",
            "output_cache_redis_url": "redis://cfg:7000/1",
            "output_cache_ttl_s": 30,
        }},
    )
    assert rtc.enabled() is True
    cache = rtc.from_config()
    assert cache.url == "redis://cfg:7000/1"
    assert cache.ttl_s == 30.0
    # Env beats the config table for the backend choice.
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_BACKEND", "memory")
    assert rtc.enabled() is False


def test_generation_is_shared_and_survives_purge(monkeypatch):
    _install_fake_redis(monkeypatch, FakeRedisClient())
    first, second = rtc.RedisToolCache(), rtc.RedisToolCache()
    epoch = first.epoch()
    assert epoch is not None and second.epoch() == epoch
    first.store("read_file", {}, "old", scope="generation:" + epoch)
    advanced = second.epoch(advance=True)
    assert advanced is not None and advanced != epoch
    assert first.epoch() == advanced
    assert first.get("read_file", {}, scope="generation:" + advanced) == (False, None)
    assert first.purge() == 1
    assert second.epoch() == advanced
    assert second.stats()["size"] == 0


def test_generation_failure_does_not_reuse_local_values(monkeypatch):
    from maverick.cache import tool

    cache = rtc.RedisToolCache()
    cache._cli = FakeRedisClient()
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE_BACKEND", "redis")
    monkeypatch.setattr(tool, "_shared_backend", lambda: cache)
    monkeypatch.setattr(tool, "snapshot_enabled", lambda: False)
    read = types.SimpleNamespace(name="read_file", parallel_safe=True)
    tool.reset()
    try:
        generation = tool.generation()
        tool.store_cached(read, {}, "old", generation=generation)
        assert tool.get_cached(read, {}) == (True, "old")
        cache.epoch(advance=True)  # another worker invalidates the shared tier
        assert tool.get_cached(read, {}) == (False, None)
        tool.store_cached(read, {}, "late old", generation=generation)
        assert tool.get_cached(read, {}) == (False, None)
        tool.store_cached(read, {}, "fresh", generation=tool.generation())
        assert tool.get_cached(read, {}) == (True, "fresh")
        cache._cli = BoomClient()
        assert tool.get_cached(read, {}) == (False, None)
        assert cache.epoch(advance=True) is None
        tool.store_cached(read, {}, "unverified")
        assert tool.stats()["size"] == 0
    finally:
        tool.reset()
