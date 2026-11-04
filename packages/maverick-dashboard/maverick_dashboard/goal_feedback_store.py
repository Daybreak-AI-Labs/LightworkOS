"""Retained workspace feedback compatibility and owner-scoped signal counts.

New customer feedback is saved as an encrypted, exact-answer-bound native
receipt by ``result_feedback_receipts``. This module reads the older workspace
log without claiming its rows identify the currently displayed answer or an
original reviewed operation. Its legacy writer is retained for compatibility;
the reviewed dashboard route does not use it. Counts combine both stores.

A human rating is a feedback signal, not proof of real business performance,
successful training, or the separate governed sign-off required by some work.
"""
from __future__ import annotations

import json
import time

from maverick.ndjson_log import append_row, clamp01
from maverick.paths import data_dir
from maverick.result_feedback_receipts import REASONS

_MAX_ROWS = 5000  # bound the tail we read back; the file itself grows unbounded

# The optional reasons a thumbs-down offers, in display order. Administrators
# see these counts per agent; a person's own written comment stays with them.
REASON_PATTERN = "^(" + "|".join(REASONS) + ")$"
FOLLOW_UP_AFTER = 3  # rejections of one agent's answers before one short question
_FOLLOW_UP_WINDOW = 12 * 3600  # how far back those rejections count, in seconds


def _path():
    # The old deployment-global file has no trustworthy workspace lineage.
    # Never adopt its rows by matching a colliding goal number or owner name.
    return data_dir("dashboard", "goal-feedback-v2.ndjson")


def record(goal_id: int, owner: str, rating: str, *, value: float,
           note: str = "", by: str = "", reason: str = "", agent: str = "") -> dict:
    """Append one feedback row (latest per goal wins on read) and return it.
    ``agent`` is the specialist that answered ("" for the general assistant).
    Never raises."""
    row = {
        "ts": time.time(),
        "goal_id": int(goal_id),
        "owner": str(owner or ""),
        "rating": str(rating),          # "up" | "down" (display), value carries the reward
        "value": clamp01(value),
        "note": str(note)[:500],
        "by": str(by or ""),
        "reason": str(reason) if reason in REASONS else "",
        "agent": str(agent or ""),
    }
    append_row(_path(), row)
    return row


def _read_rows() -> list[dict]:
    path = _path()
    if not path.exists():
        return []
    # Bound both records and bytes when reading the retained workspace log.
    with path.open("rb") as stream:
        end = stream.seek(0, 2)
        start = max(0, end - 4 * 1024 * 1024)
        stream.seek(start)
        raw = stream.read(4 * 1024 * 1024)
    if start:
        raw = raw.partition(b"\n")[2]
    rows = []
    for line in raw.splitlines()[-_MAX_ROWS:]:
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def latest_for_goal(goal_id: int, *, owner: str) -> dict | None:
    """The most recent feedback row for a goal, or ``None``."""
    gid = int(goal_id)
    hit = None
    for r in _read_rows():  # rows are append-order, so the last match is newest
        if r.get("goal_id") == gid and r.get("owner") == owner:
            hit = r
    return hit


def count(*, owner: str | None = None, world=None) -> int:
    """How many distinct goals have human feedback (accumulated human signal).
    ``owner=None`` counts all; a specific owner counts only its own."""
    seen: set[int] = set()
    for r in _read_rows():
        if owner is not None and r.get("owner", "") != owner:
            continue
        try:
            seen.add(int(r.get("goal_id")))
        except (TypeError, ValueError):
            continue
    if world is not None:
        from maverick.result_feedback_receipts import rated_goals
        seen.update(rated_goals(world, owner=owner))
    return len(seen)


def _latest_rows(*, world=None) -> list[dict]:
    """The latest row per (goal, owner): a re-rating replaces the earlier verdict."""
    latest: dict[tuple, dict] = {}
    for row in _read_rows():
        try:
            latest[(int(row.get("goal_id")), str(row.get("owner", "")))] = row
        except (TypeError, ValueError):
            continue
    if world is not None:
        from maverick.result_feedback_receipts import summary_rows
        for row in summary_rows(world):
            latest[(row["goal_id"], row["owner"])] = row
    return list(latest.values())


def rejections(by: str, agent: str, *, since: float, world=None) -> int:
    """How many of ``agent``'s answers ``by`` currently rates down, rated since ``since``."""
    return sum(1 for row in _latest_rows(world=world)
               if row.get("rating") == "down" and str(row.get("by", "")) == by
               and str(row.get("agent", "")) == agent and float(row.get("ts") or 0) >= since)


def should_follow_up(by: str, agent: str, *, previous: dict | None, rating: str, world=None) -> bool:
    """Ask one short question when this new rejection is the third of one agent's
    answers within the window; re-rating or adding a reason never asks again."""
    if rating != "down" or (previous is not None and previous.get("rating") == "down"):
        return False
    since = time.time() - _FOLLOW_UP_WINDOW
    return rejections(by, agent, since=since, world=world) == FOLLOW_UP_AFTER


#: After this many of one agent's answers rated down, offer a person.
HAND_OFF_AFTER = 2


def should_offer_person(by: str, agent: str, *, rating: str, world=None) -> bool:
    """Offer "Get help from a person" once someone has rejected two of one
    agent's or specialist's answers within the window, and on every later
    rejection: the AI has not resolved it, so a person should be one step away."""
    if rating != "down":
        return False
    since = time.time() - _FOLLOW_UP_WINDOW
    return rejections(by, agent, since=since, world=world) >= HAND_OFF_AFTER


def summary_by_agent(*, recent: int = 5, world=None) -> list[dict]:
    """Per-agent counts and recent reasons for administrators. Written
    comments are never included: they stay with the person and their task."""
    agents: dict[str, dict] = {}
    for row in sorted(_latest_rows(world=world), key=lambda item: float(item.get("ts") or 0), reverse=True):
        entry = agents.setdefault(str(row.get("agent", "")), {
            "agent": str(row.get("agent", "")), "up": 0, "down": 0, "reasons": {}, "recent": []})
        if row.get("rating") == "up":
            entry["up"] += 1
        elif row.get("rating") == "down":
            entry["down"] += 1
            reason = row.get("reason")
            if reason in REASONS:
                entry["reasons"][reason] = entry["reasons"].get(reason, 0) + 1
                if len(entry["recent"]) < recent:
                    entry["recent"].append({"reason": reason, "label": REASONS[reason],
                                            "ts": float(row.get("ts") or 0)})
    out = []
    for entry in agents.values():
        entry["reasons"] = [{"reason": key, "label": REASONS[key], "count": count}
                            for key, count in sorted(entry["reasons"].items(),
                                                     key=lambda item: (-item[1], list(REASONS).index(item[0])))]
        out.append(entry)
    return sorted(out, key=lambda entry: (-(entry["up"] + entry["down"]), entry["agent"]))


__all__ = ["FOLLOW_UP_AFTER", "HAND_OFF_AFTER", "REASONS", "REASON_PATTERN", "count", "latest_for_goal",
           "record", "rejections", "should_follow_up", "should_offer_person", "summary_by_agent"]
