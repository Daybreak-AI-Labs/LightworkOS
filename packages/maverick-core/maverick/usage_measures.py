"""Optional, name-free usage measures for the research kit.

Off unless ``[analytics] usage_measures = true``. When on, this installation
counts two things and nothing else:

* **First result in the first session**: when a signed-in person is
  first seen, and when they first see a finished result of their own task.
  A first result within :data:`FIRST_SESSION_SECONDS` of first being seen
  counts as "in the first session". Reported by access role.
* **AI suggestions**: how often each kind of suggestion is shown,
  used or dismissed, how often one is shown again to the same person after
  they dismissed it, and how often it appeared while they were typing.

Privacy: counts stay in this installation (``~/.maverick/usage-measures.json``,
0600, locked) and are never sent anywhere. People and suggestion texts are
kept only as one-way keyed hashes, used to count each person once and to
notice a dismissed suggestion shown again; reports never read them.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import statistics
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
FIRST_SESSION_SECONDS = 4 * 3600
EVENTS = ("shown", "accepted", "dismissed")
_MAX_PEOPLE = 20000
_MAX_DISMISSED = 200  # per person


def enabled() -> bool:
    """``[analytics] usage_measures``; off unless set to true."""
    try:
        from .config import load_config

        section = (load_config() or {}).get("analytics")
    except Exception:  # noqa: BLE001 -- an unreadable config keeps measuring off
        return False
    return isinstance(section, dict) and section.get("usage_measures") is True


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "usage-measures.json"


def _load() -> dict[str, Any]:
    from .file_lock import atomic_read_text, ensure_private_file

    path = store_path()
    data: Any = {}
    if path.exists():
        ensure_private_file(path)
        try:
            data = json.loads(atomic_read_text(path))
        except (OSError, ValueError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    for key in ("people", "suggestions", "dismissed"):
        if not isinstance(data.get(key), dict):
            data[key] = {}
    if not isinstance(data.get("key"), str) or len(data["key"]) != 64:
        data["key"] = secrets.token_hex(32)
    return data


def _save(data: dict[str, Any]) -> None:
    from .file_lock import atomic_write_text, ensure_private_directory

    ensure_private_directory(store_path().parent)
    atomic_write_text(store_path(), json.dumps(data, sort_keys=True))


def _hash(data: dict[str, Any], value: str) -> str:
    return hmac.new(bytes.fromhex(data["key"]), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _edit(mutate) -> None:
    from .file_lock import cross_process_lock, ensure_private_directory

    ensure_private_directory(store_path().parent)
    with _LOCK, cross_process_lock(store_path()):
        data = _load()
        if mutate(data):
            _save(data)


def note_seen(principal: str, role: str, now: float | None = None) -> None:
    """Remember when this person was first seen, once."""
    who = str(principal or "").strip()
    if not who or not enabled():
        return

    def mutate(data):
        key = _hash(data, who)
        if key in data["people"] or len(data["people"]) >= _MAX_PEOPLE:
            return False
        data["people"][key] = {"role": str(role or "unknown")[:20], "first_seen": now or time.time(),
                               "first_result": None}
        return True
    _edit(mutate)


def note_first_result(principal: str, now: float | None = None) -> bool:
    """Remember when this person first saw a finished result of their own task.
    True once it is on record (now or before); False for someone not yet seen."""
    who = str(principal or "").strip()
    if not who or not enabled():
        return False
    known = []

    def mutate(data):
        row = data["people"].get(_hash(data, who))
        known.append(row is not None)
        if row is None or row.get("first_result") is not None:
            return False
        row["first_result"] = now or time.time()
        return True
    _edit(mutate)
    return bool(known and known[0])


def record_suggestion(principal: str, kind: str, item: str, event: str, *, typing: bool = False) -> None:
    """Count one suggestion shown, used or dismissed."""
    if event not in EVENTS or not enabled():
        return
    kind = "".join(ch for ch in str(kind) if ch.isalnum() or ch in "-_")[:40] or "other"
    who = str(principal or "anonymous")

    def mutate(data):
        counts = data["suggestions"].setdefault(kind, dict.fromkeys((*EVENTS, "reshown", "while_typing"), 0))
        person = _hash(data, who)
        seen = _hash(data, kind + "\n" + str(item)[:500])
        dismissed = data["dismissed"].setdefault(person, [])
        counts[event] = counts.get(event, 0) + 1
        if event == "shown":
            counts["reshown"] += seen in dismissed
            counts["while_typing"] += bool(typing)
        elif event == "dismissed" and seen not in dismissed:
            dismissed.append(seen)
            del dismissed[:-_MAX_DISMISSED]
        return True
    _edit(mutate)


def first_session_report(now: float | None = None) -> list[dict[str, Any]]:
    """Per access role: new people, how many got a first result in their first session, median minutes."""
    data = _load()
    rows: dict[str, list[dict]] = {}
    for row in data["people"].values():
        rows.setdefault(row.get("role") or "unknown", []).append(row)
    report = []
    for role, people in sorted(rows.items()):
        quick = [r["first_result"] - r["first_seen"] for r in people
                 if r.get("first_result") is not None and r["first_result"] - r["first_seen"] <= FIRST_SESSION_SECONDS]
        report.append({"role": role, "people": len(people), "first_session": len(quick),
                       "share": round(100 * len(quick) / len(people)) if people else 0,
                       "median_minutes": round(statistics.median(quick) / 60, 1) if quick else None})
    return report


def suggestion_report() -> list[dict[str, Any]]:
    """Per kind of suggestion: counts, the share dismissed, and whether it needs review."""
    data = _load()
    report = []
    for kind, counts in sorted(data["suggestions"].items()):
        shown = counts.get("shown", 0)
        share = round(100 * counts.get("dismissed", 0) / shown) if shown else 0
        report.append({"kind": kind, **{key: counts.get(key, 0) for key in (*EVENTS, "reshown", "while_typing")},
                       "dismissed_share": share, "review": shown > 0 and share > 50})
    return report


__all__ = ["EVENTS", "FIRST_SESSION_SECONDS", "enabled", "first_session_report", "note_first_result",
           "note_seen", "record_suggestion", "store_path", "suggestion_report"]
