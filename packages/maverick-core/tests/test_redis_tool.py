"""Tests for the Redis tool (maverick.tools.redis_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _install_fake_redis(monkeypatch, **overrides):
    class _Redis:
        def __init__(self, *a, **k):
            for k_, v in overrides.items():
                setattr(self, k_, MagicMock(return_value=v))

        @classmethod
        def from_url(cls, url, **k):
            return cls()

    redis_mod = types.ModuleType("redis")
    redis_mod.Redis = _Redis
    monkeypatch.setitem(sys.modules, "redis", redis_mod)


# ---------- Redis ----------

def test_redis_requires_op():
    from maverick.tools.redis_tool import redis_tool
    assert "op is required" in redis_tool().fn({})


def test_redis_missing_lib(monkeypatch):
    monkeypatch.setitem(sys.modules, "redis", None)
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "get", "key": "x"})
    assert "redis not installed" in out


def test_redis_get_returns_value(monkeypatch):
    _install_fake_redis(monkeypatch, get="hello")
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "get", "key": "greeting"})
    assert "hello" in out


def test_redis_get_nil(monkeypatch):
    _install_fake_redis(monkeypatch, get=None)
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "get", "key": "missing"})
    assert "(nil)" in out


def test_redis_set_with_ttl(monkeypatch):
    _install_fake_redis(monkeypatch, set=True)
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({
        "op": "set", "key": "k", "value": "v", "ttl_seconds": 60, "confirm": True,
    })
    assert "OK" in out and "ttl=60" in out


def test_redis_keys_scan(monkeypatch):
    class _Redis:
        def __init__(self, *a, **k):
            pass

        @classmethod
        def from_url(cls, url, **k):
            return cls()

        def scan(self, cursor=0, match=None, count=200):
            # one batch then done
            if cursor == 0:
                return (0, ["a", "b"])
            return (0, [])

    redis_mod = types.ModuleType("redis")
    redis_mod.Redis = _Redis
    monkeypatch.setitem(sys.modules, "redis", redis_mod)
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "keys", "pattern": "*"})
    assert "a" in out and "b" in out


def test_redis_publish(monkeypatch):
    _install_fake_redis(monkeypatch, publish=3)
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({
        "op": "publish", "channel": "alerts", "message": "x", "confirm": True,
    })
    assert "3 subscriber" in out


def test_redis_mutations_require_confirm(monkeypatch):
    _install_fake_redis(monkeypatch, set=True)
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "set", "key": "k", "value": "v"})
    assert "DRY RUN" in out


def test_redis_requires_explicit_connection(monkeypatch):
    _install_fake_redis(monkeypatch, get="hello")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "get", "key": "greeting"})
    assert "must be set explicitly" in out


class TestRedisClientClosed:
    def test_client_closed_after_run(self, monkeypatch):
        import sys
        import types
        from unittest.mock import MagicMock
        fake_redis = types.ModuleType("redis")
        client = MagicMock()
        client.get.return_value = None
        fake_redis.Redis = MagicMock(return_value=client)
        fake_redis.Redis.from_url = MagicMock(return_value=client)
        monkeypatch.setitem(sys.modules, "redis", fake_redis)
        monkeypatch.setenv("REDIS_URL", "redis://x")
        from maverick.tools.redis_tool import redis_tool
        redis_tool().fn({"op": "get", "key": "k"})
        client.close.assert_called()  # no per-call connection-pool leak


def test_redis_url_client_has_timeouts_and_string_keys_delete_one_key(monkeypatch):
    seen: dict = {}

    class _Redis:
        @classmethod
        def from_url(cls, url, **k):
            seen["kwargs"] = k
            return cls()

        def delete(self, *keys):
            seen["deleted"] = keys
            return len(keys)

        def close(self):
            pass

    redis_mod = types.ModuleType("redis")
    redis_mod.Redis = _Redis
    monkeypatch.setitem(sys.modules, "redis", redis_mod)
    monkeypatch.setenv("REDIS_URL", "redis://localhost")
    from maverick.tools.redis_tool import redis_tool
    out = redis_tool().fn({"op": "delete", "keys": "user:1", "confirm": True})
    assert seen["deleted"] == ("user:1",) and "deleted 1" in out
    assert seen["kwargs"]["socket_timeout"] and seen["kwargs"]["socket_connect_timeout"]
