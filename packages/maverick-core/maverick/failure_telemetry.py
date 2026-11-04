"""Default-on local failure-mode telemetry.

When runs fail, *how* they fail is the signal worth having: is it mostly budget
caps, provider auth, timeouts, the shield, sandbox errors? This records a
canonical **failure mode** per failed run to a local JSONL sink, so an operator
can see the distribution and fix the dominant cause instead of guessing.

Local-first and on by default; ``[telemetry] failure_modes = false`` or
``MAVERICK_FAILURE_TELEMETRY=0`` opts out. ``record`` returns immediately when
disabled. No mandatory egress: the JSONL stays on disk; ``summarize`` /
``maverick failures`` read it back.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

# Canonical failure modes (anything else normalizes to "error").
MODES = ("budget", "timeout", "network", "auth", "shield", "sandbox",
         "cancelled", "error")


def _scrub_detail(detail: object) -> str:
    """Redact secrets from a failure detail before it is persisted. The detail
    is often a raw provider exception string (API key / Bearer header in the
    message); scrub it. Fail-safe: telemetry must never break a run."""
    text = str(detail)
    try:
        from .secrets import scrub
        return scrub(text)
    except Exception:  # pragma: no cover -- scrubbing never breaks telemetry
        return ""


def enabled() -> bool:
    try:
        from .config import (
            governed_learning_default,
            governed_learning_env_flag,
            load_config,
        )
        override = governed_learning_env_flag("MAVERICK_FAILURE_TELEMETRY")
        if override is not None:
            return override
        return bool(((load_config() or {}).get("telemetry") or {})
                    .get("failure_modes", governed_learning_default()))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def classify_exception(exc: BaseException) -> str:
    """Map an exception to a canonical failure mode."""
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "budget" in name or "budget" in msg:
        return "budget"
    if "timeout" in name or "timed out" in msg:
        return "timeout"
    if "auth" in name or "unauthor" in msg or "api key" in msg or "401" in msg:
        return "auth"
    if "connection" in name or "network" in msg or name.startswith("connect"):
        return "network"
    if "shield" in name or "shield" in msg:
        return "shield"
    if "sandbox" in name or ("sandbox" in msg and "exec" in msg):
        return "sandbox"
    if "cancel" in name or "cancelled" in msg:
        return "cancelled"
    return "error"


def _path() -> Path:
    from .paths import data_dir
    return data_dir("failure_modes.jsonl")


def record(mode: str, *, goal_id=None, detail: str = "",
           now: float | None = None, path=None) -> bool:
    """Append one failure-mode record (no-op + False when telemetry is off)."""
    if not enabled():
        return False
    from .learning_guard import learning_write_allowed
    if not learning_write_allowed("failure_telemetry"):
        return False
    try:
        p = Path(path) if path is not None else _path()
        from .file_lock import (
            cross_process_lock,
            ensure_private_directory,
            open_private_append,
        )

        if path is None:
            ensure_private_directory(p.parent)
        rec = {
            "ts": now if now is not None else time.time(),
            "mode": mode if mode in MODES else "error",
            "goal_id": goal_id,
            # Scrub before truncating: record_failure feeds the raw exception
            # string here, and provider auth/HTTP errors routinely embed the API
            # key / Bearer header. Truncation is not redaction. scrub first so a
            # secret can't survive by being split across the 200-char cut.
            "detail": _scrub_detail(detail)[:200],
        }
        line = (json.dumps(rec) + "\n").encode("utf-8")
        # Serialize and append directly. Re-reading/replacing the full JSONL on
        # every event made N records O(N^2) bytes of I/O. The append helper
        # creates privately and identity-binds an existing regular file.
        with cross_process_lock(p):
            fd = open_private_append(p)
            try:
                offset = 0
                while offset < len(line):
                    written = os.write(fd, line[offset:])
                    if written <= 0:
                        raise OSError("failure telemetry append made no progress")
                    offset += written
            finally:
                os.close(fd)
        return True
    except Exception:  # pragma: no cover -- telemetry never breaks a run
        return False


def record_failure(exc_or_mode, *, goal_id=None, detail: str = "", **kw) -> bool:
    """Record from an exception (classified) or an explicit mode string."""
    if isinstance(exc_or_mode, str):
        mode = exc_or_mode if exc_or_mode in MODES else "error"
    else:
        mode = classify_exception(exc_or_mode)
        detail = detail or str(exc_or_mode)
    return record(mode, goal_id=goal_id, detail=detail, **kw)


def summarize(path=None) -> dict:
    """Failure-mode distribution from the recorded sink."""
    p = Path(path) if path is not None else _path()
    counts: dict[str, int] = {}
    total = 0
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return {"total": 0, "by_mode": {}}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        m = rec.get("mode", "error")
        counts[m] = counts.get(m, 0) + 1
        total += 1
    return {"total": total,
            "by_mode": dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))}


__all__ = ["enabled", "classify_exception", "record", "record_failure",
           "summarize", "MODES"]
