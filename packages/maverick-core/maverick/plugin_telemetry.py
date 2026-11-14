"""Plugin telemetry, opt-in.

Local-only usage counts for third-party plugin tools: which plugin tools
actually get called, how often, and when last — the data an operator needs to
prune the plugin allowlist ("nothing called acme-tools in 90 days") and a
plugin author needs to know their tool earns its keep.

**Local only, nothing leaves the machine.** This writes a JSON tally under
``data_dir("plugin_telemetry.json")`` and is read back by
``maverick plugin stats``. Off by default; opt in via ``[plugins]
telemetry = true`` (env ``MAVERICK_PLUGIN_TELEMETRY``). When off, discovery
does no wrapping and behavior is byte-identical.
"""
from __future__ import annotations

import inspect
import json
import threading
import time
from pathlib import Path

from .config import env_flag
from .file_lock import atomic_write_text, cross_process_lock

_lock = threading.Lock()


def enabled() -> bool:
    _v = env_flag("MAVERICK_PLUGIN_TELEMETRY")
    if _v is not None:
        return _v
    try:
        from .config import load_config
        return bool(((load_config() or {}).get("plugins") or {}).get("telemetry", False))
    except Exception:  # pragma: no cover -- config never blocks a tool call
        return False


def telemetry_path() -> Path:
    from .paths import data_dir
    return data_dir() / "plugin_telemetry.json"


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def record(tool_name: str, dist: str | None = None, *, path: Path | None = None) -> None:
    """Count one invocation of a plugin tool. Best-effort, never raises."""
    try:
        p = path or telemetry_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        # Several processes may count at once: serialize across processes and
        # write through a unique temp file so no tick or tally is lost.
        with _lock, cross_process_lock(p):
            data = _load(p)
            entry = data.setdefault(str(tool_name), {"calls": 0, "dist": dist or ""})
            entry["calls"] = int(entry.get("calls", 0)) + 1
            entry["last_used"] = time.time()
            if dist:
                entry["dist"] = dist
            atomic_write_text(p, json.dumps(data, sort_keys=True), mode=0o600)
    except Exception:  # telemetry must never break a tool call
        pass


def stats(*, path: Path | None = None) -> dict[str, dict]:
    with _lock:
        return _load(path or telemetry_path())


def wrap_factory(name: str, dist: str | None, factory):
    """Wrap a plugin tool factory so each call records one telemetry tick.

    Composes with (runs inside of) the isolation proxy: discovery applies
    this wrapper last so the count covers isolated calls too.
    """
    def wrapped():
        tool = factory()
        inner = tool.fn

        if inspect.isasyncgenfunction(inner):
            async def counted(args):
                record(name, dist)
                async for chunk in inner(args):
                    yield chunk
        elif inspect.iscoroutinefunction(inner):
            async def counted(args):
                record(name, dist)
                return await inner(args)
        else:
            def counted(args):
                record(name, dist)
                return inner(args)

        try:
            tool.fn = counted
        except Exception:
            pass  # frozen Tool object: count nothing rather than break it
        return tool
    return wrapped


__all__ = ["enabled", "record", "stats", "telemetry_path", "wrap_factory"]
