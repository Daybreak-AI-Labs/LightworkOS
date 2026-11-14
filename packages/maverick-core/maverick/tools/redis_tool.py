"""Redis tool.

Lets the agent talk to a Redis instance for caching, queueing, and
small bits of state.

ops:
  - get(key)
  - set(key, value, ttl_seconds)
  - delete(keys)
  - keys(pattern)                — SCAN-based (no blocking KEYS)
  - lpush(key, values)
  - lrange(key, start, stop)
  - publish(channel, message)
  - info(section)                — server info snapshot

Auth/connection via ``REDIS_URL`` (``redis://[:password@]host:port/db``)
or ``REDIS_HOST`` + ``REDIS_PORT`` + ``REDIS_DB`` + ``REDIS_PASSWORD``.

Requires::

    python -m pip install -e './packages/maverick-core[redis]'
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

from ..fastjson import dumps_compact
from . import Tool

log = logging.getLogger(__name__)


_REDIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["get", "set", "delete", "keys", "lpush",
                     "lrange", "publish", "info"],
        },
        "key": {"type": "string"},
        "keys": {"type": "array", "items": {"type": "string"}},
        "value": {"type": "string"},
        "values": {"type": "array", "items": {"type": "string"}},
        "ttl_seconds": {"type": "integer"},
        "pattern": {"type": "string", "description": "Glob (SCAN pattern)."},
        "start": {"type": "integer"},
        "stop": {"type": "integer"},
        "channel": {"type": "string"},
        "message": {"type": "string"},
        "section": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


# One client (connection pool) is built per _run() and closed in its finally.
# Building a fresh redis.Redis on every _op_* would leak a pool/socket per
# tool call toward the fd / maxclients limit. The
# active client is stashed thread-locally so the _op_* helpers reuse it.
_TL = threading.local()


def _build_client():
    import redis
    url = os.environ.get("REDIS_URL", "").strip()
    if url:
        return redis.Redis.from_url(url, decode_responses=True,
                                    socket_connect_timeout=5, socket_timeout=10)
    if not os.environ.get("REDIS_HOST", "").strip():
        raise ValueError(
            "REDIS_URL (preferred) or REDIS_HOST must be set explicitly"
        )
    return redis.Redis(
        host=os.environ["REDIS_HOST"].strip(),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        db=int(os.environ.get("REDIS_DB", "0")),
        password=os.environ.get("REDIS_PASSWORD") or None,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=10,
    )


def _client():
    cur = getattr(_TL, "client", None)
    return cur if cur is not None else _build_client()


def _op_get(key: str) -> str:
    if not key:
        return "ERROR: get requires key"
    val = _client().get(key)
    return "(nil)" if val is None else str(val)


def _op_set(key: str, value: str, ttl: int) -> str:
    if not key:
        return "ERROR: set requires key"
    r = _client()
    if ttl and ttl > 0:
        r.set(key, value, ex=ttl)
    else:
        r.set(key, value)
    return f"OK (ttl={ttl or 'inf'})"


def _op_delete(keys: list[str]) -> str:
    if not keys:
        return "ERROR: delete requires keys"
    n = _client().delete(*keys)
    return f"deleted {n} key(s)"


def _op_keys(pattern: str) -> str:
    """SCAN-based to avoid blocking large datasets."""
    pat = pattern or "*"
    out: list[str] = []
    cursor = 0
    r = _client()
    while True:
        cursor, batch = r.scan(cursor=cursor, match=pat, count=200)
        out.extend(batch)
        if cursor == 0 or len(out) >= 1000:
            break
    if not out:
        return f"no keys match {pat!r}"
    return "\n".join(f"  {k}" for k in out[:1000])


def _op_lpush(key: str, values: list[str]) -> str:
    if not key or not values:
        return "ERROR: lpush requires key and values"
    n = _client().lpush(key, *values)
    return f"list length: {n}"


def _op_lrange(key: str, start: int, stop: int) -> str:
    if not key:
        return "ERROR: lrange requires key"
    items = _client().lrange(key, start, stop)
    if not items:
        return "(empty)"
    return "\n".join(f"  {i}" for i in items)


def _op_publish(channel: str, message: str) -> str:
    if not channel:
        return "ERROR: publish requires channel"
    n = _client().publish(channel, message)
    return f"delivered to {n} subscriber(s)"


def _op_info(section: str) -> str:
    info = _client().info(section) if section else _client().info()
    return dumps_compact(info)[:3000]


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import redis  # noqa: F401
    except ImportError:
        return (
            "ERROR: redis not installed. "
            "Run: python -m pip install -e './packages/maverick-core[redis]'"
        )
    needs_confirm = {"set", "delete", "lpush", "publish"}
    if op in needs_confirm and args.get("confirm") is not True:
        return (
            f"DRY RUN: op={op!r} would mutate Redis. "
            "Re-run with confirm=true."
        )
    # Build ONE client for this call and close it in finally (no per-op leak).
    try:
        _TL.client = _build_client()
    except Exception as e:
        return f"ERROR: Redis request failed: {type(e).__name__}: {e}"
    try:
        if op == "get":
            return _op_get((args.get("key") or "").strip())
        if op == "set":
            return _op_set(
                (args.get("key") or "").strip(),
                args.get("value") or "",
                int(args.get("ttl_seconds") or 0),
            )
        if op == "delete":
            keys = args.get("keys") or []
            if isinstance(keys, str):
                # A bare string would otherwise be iterated per character.
                keys = [keys]
            return _op_delete([s for s in keys if s])
        if op == "keys":
            return _op_keys((args.get("pattern") or "").strip())
        if op == "lpush":
            return _op_lpush(
                (args.get("key") or "").strip(),
                [str(v) for v in (args.get("values") or [])],
            )
        if op == "lrange":
            return _op_lrange(
                (args.get("key") or "").strip(),
                int(args.get("start") or 0),
                int(args.get("stop") if args.get("stop") is not None else -1),
            )
        if op == "publish":
            return _op_publish(
                (args.get("channel") or "").strip(),
                args.get("message") or "",
            )
        if op == "info":
            return _op_info((args.get("section") or "").strip())
    except Exception as e:
        return f"ERROR: Redis request failed: {type(e).__name__}: {e}"
    finally:
        try:
            _TL.client.close()
        except Exception:
            pass
        _TL.client = None
    return f"ERROR: unknown op {op!r}"


def redis_tool() -> Tool:
    return Tool(
        name="redis",
        description=(
            "Redis client. ops: get / set (with ttl_seconds) / "
            "delete / keys (SCAN by pattern) / lpush + lrange / "
            "publish / info. Connection via REDIS_URL or "
            "REDIS_HOST/PORT/DB/PASSWORD env."
        ),
        input_schema=_REDIS_SCHEMA,
        fn=_run,
    )
