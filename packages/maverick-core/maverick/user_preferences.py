"""Per-person profile settings: time zone, daily summary choices, email.

Lightwork's sign-in identities (OIDC / SAML / proxy) carry no time zone, so
the person keeps one here. The daily summary (``maverick.daily_digest``)
reads it to send at the right local hour; the My work page lets the person
change it. Store: ``~/.maverick/user-preferences.json`` (0600, locked),
keyed by principal.
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
_EMAIL = re.compile(r"[^@\s<>\"']{1,64}@[^@\s<>\"']{1,190}\.[A-Za-z]{2,24}")
_DEFAULT_TIME_ZONE = "UTC"
FIELDS = ("time_zone", "digest_enabled", "digest_hour", "send_when_empty", "email")


class UserPreferenceError(ValueError):
    """A setting value the page will not accept."""


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "user-preferences.json"


def _locked(path: Path):
    from contextlib import ExitStack

    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import maverick_home

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


def _load() -> dict[str, dict[str, Any]]:
    from .file_lock import atomic_read_text, ensure_private_file

    path = store_path()
    if not path.exists():
        return {}
    ensure_private_file(path)
    try:
        data = json.loads(atomic_read_text(path))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, dict)}


def _write(data: dict[str, Any]) -> None:
    from .file_lock import atomic_write_text

    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True))


def valid_time_zone(name: object) -> bool:
    if not isinstance(name, str) or not name.strip() or len(name) > 64:
        return False
    try:
        from zoneinfo import ZoneInfo

        ZoneInfo(name.strip())
    except Exception:  # noqa: BLE001 -- any lookup failure means "not a zone"
        return False
    return True


def time_zone_choices() -> list[str]:
    """Available zone names for the settings control (falls back to UTC only)."""
    try:
        from zoneinfo import available_timezones

        names = sorted(z for z in available_timezones() if "/" in z or z == "UTC")
    except Exception:  # noqa: BLE001 -- no tzdata: still offer UTC
        names = []
    return names or [_DEFAULT_TIME_ZONE]


def defaults() -> dict[str, Any]:
    try:
        from .config import get_my_work

        section = get_my_work()
    except Exception:  # noqa: BLE001 -- an unreadable config keeps the documented defaults
        section = {}
    return {
        "time_zone": _DEFAULT_TIME_ZONE,
        "digest_enabled": True,
        "digest_hour": int(section.get("digest_hour", 8)),
        "send_when_empty": bool(section.get("send_when_empty", False)),
        "email": "",
        "last_digest_date": "",
    }


def get_preferences(principal: str) -> dict[str, Any]:
    """The person's settings with defaults filled in (never raises)."""
    out = defaults()
    row = _load().get(str(principal or ""), {})
    for key in (*FIELDS, "last_digest_date"):
        if key in row:
            out[key] = row[key]
    if not valid_time_zone(out["time_zone"]):
        out["time_zone"] = _DEFAULT_TIME_ZONE
    return out


def _validate(changes: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in changes.items():
        if key == "time_zone":
            if not valid_time_zone(value):
                raise UserPreferenceError("that time zone is not recognised")
            clean[key] = str(value).strip()
        elif key in ("digest_enabled", "send_when_empty"):
            if not isinstance(value, bool):
                raise UserPreferenceError(f"{key} must be on or off")
            clean[key] = value
        elif key == "digest_hour":
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 23:
                raise UserPreferenceError("the summary hour must be between 0 and 23")
            clean[key] = value
        elif key == "email":
            text = str(value or "").strip().lower()
            if text and not _EMAIL.fullmatch(text):
                raise UserPreferenceError("that does not look like an email address")
            clean[key] = text
        else:
            raise UserPreferenceError(f"unknown setting {key!r}")
    return clean


def set_preferences(principal: str, **changes: Any) -> dict[str, Any]:
    """Save validated changes for ``principal`` and return the new settings."""
    who = str(principal or "").strip()
    if not who:
        raise UserPreferenceError("a person is required")
    clean = _validate(changes)
    with _locked(store_path()):
        data = _load()
        row = dict(data.get(who, {}))
        row.update(clean)
        row["updated_at"] = time.time()
        data[who] = row
        _write(data)
    return get_preferences(who)


def mark_digest_sent(principal: str, local_date: str) -> None:
    """Remember the local date a summary went out so it is sent once a day
    (this also ends any back-off for that day)."""
    with _locked(store_path()):
        data = _load()
        row = dict(data.get(principal, {}))
        row["last_digest_date"] = str(local_date)
        row.pop("digest_retry", None)
        data[principal] = row
        _write(data)


def digest_retry(principal: str) -> dict[str, Any]:
    """The back-off after a summary definitely could not be sent: ``date``,
    ``failures``, ``next_at`` and the channel ``setup`` it failed with ({}
    when there is none)."""
    state = _load().get(str(principal or ""), {}).get("digest_retry")
    return dict(state) if isinstance(state, dict) else {}


def set_digest_retry(principal: str, state: dict[str, Any]) -> None:
    """Save the summary back-off next to ``last_digest_date``."""
    with _locked(store_path()):
        data = _load()
        row = dict(data.get(principal, {}))
        row["digest_retry"] = dict(state)
        data[principal] = row
        _write(data)


def principals_with_preferences() -> list[str]:
    return sorted(_load().keys())


__all__ = [
    "FIELDS",
    "UserPreferenceError",
    "defaults",
    "digest_retry",
    "get_preferences",
    "mark_digest_sent",
    "principals_with_preferences",
    "set_digest_retry",
    "set_preferences",
    "store_path",
    "time_zone_choices",
    "valid_time_zone",
]
