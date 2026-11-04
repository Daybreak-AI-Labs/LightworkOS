"""Filter signed audit-reader output before selecting a bounded result page."""
from __future__ import annotations

import hashlib
import json
from collections import deque


def event_cursor(event):
    return hashlib.sha256(json.dumps(event, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def search_events(events, *, matches, person_for, limit, before="", scan_limit=2_000_000):
    from .content_access import audit_metadata

    kept = deque(maxlen=limit)
    kinds, people, agents = set(), set(), set()
    matched, cut, found = 0, False, not before
    for scanned, raw in enumerate(events):
        if scanned >= scan_limit:
            cut = True
            break
        event = audit_metadata(raw)
        cursor = event_cursor(event)
        if cursor == before:
            found = True
            break  # The reader is chronological; this page contains older events.
        if event.get("kind"):
            kinds.add(str(event["kind"]))
        if len(people) < 1000:
            people.add(person_for(event))
        # The agent or specialist that acted, for the "Agent or specialist"
        # filter: an AI action is found by its actor like a person's.
        if (isinstance(event.get("agent"), str) and event["agent"] not in {"", "system"}
                and len(agents) < 1000):
            agents.add(event["agent"])
        if matches(event):
            matched += 1
            kept.append(event)
    rows = list(kept)
    return {"events": rows, "kinds": kinds, "people": people, "agents": agents, "matched": matched,
            "cut": cut, "cursor_found": found,
            "next_cursor": event_cursor(rows[0]) if matched > limit and rows else None}
