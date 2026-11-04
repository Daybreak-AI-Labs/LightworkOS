"""When each compliance protection was last checked, and its history.

The control-coverage report (:func:`maverick.compliance.compliance_report`)
is worked out from the live configuration every time it is read. This keeps
what it found: when the check ran, each protection's status and since when,
and every change of status with its time (the newest 500), so the
Compliance page can show freshness and a history over the audit window, and
a protection that breaks shows as failing at the next check.

The dashboard re-checks every hour in the background (its always-on
deadline-alerts thread calls :func:`recheck_if_due`) and on every visit to
the Compliance page.
"""
from __future__ import annotations

import json
import time
from typing import Any

#: The background re-check runs at most this often (Vanta's hourly cadence).
EVERY_SECONDS = 3600
MAX_CHANGES = 500


def _path():
    from .paths import data_dir

    return data_dir("compliance", "control-history.json")


def state() -> dict[str, Any]:
    """``{checked_at, controls: {name: {status, since}}, changes: [...]}``."""
    try:
        value = json.loads(_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return {"checked_at": None, "controls": {}, "changes": []}
    if not isinstance(value, dict) or not isinstance(value.get("controls"), dict):
        return {"checked_at": None, "controls": {}, "changes": []}
    value.setdefault("changes", [])
    return value


def record(checks, *, now: float | None = None) -> dict[str, Any]:
    """Keep the result of one check: freshness, since-when, and any changes."""
    from .file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory

    current = time.time() if now is None else float(now)
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        saved = state()
        controls = dict(saved["controls"])
        changes = list(saved["changes"])
        for check in checks:
            name, status = str(check.control), str(check.status)
            before = controls.get(name)
            if before is None or before.get("status") != status:
                if before is not None:
                    changes.append({"control": name, "from": before.get("status"), "to": status, "at": current})
                controls[name] = {"status": status, "since": current}
        result = {"checked_at": current, "controls": controls, "changes": changes[-MAX_CHANGES:]}
        atomic_write_bytes(path, json.dumps(result, separators=(",", ":")).encode(), mode=0o600)
    return result


def recheck(*, now: float | None = None) -> dict[str, Any]:
    """Run the control-coverage check now and keep what it found."""
    from .compliance import compliance_report

    return record(compliance_report(), now=now)


def recheck_if_due(*, now: float | None = None) -> dict[str, Any] | None:
    """Re-check when the last check is an hour old or more; None otherwise."""
    current = time.time() if now is None else float(now)
    last = state().get("checked_at")
    if isinstance(last, (int, float)) and current - float(last) < EVERY_SECONDS:
        return None
    return recheck(now=current)


__all__ = ["EVERY_SECONDS", "record", "recheck", "recheck_if_due", "state"]
