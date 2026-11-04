"""Governance that discovers: replay candidate rules, find contradictions.

Rules are data: ``{"id", "action", "modality": "forbid"|"require", "when": {attr: value}}``.
A ``forbid`` rule blocks an event whose ``action`` matches and whose attributes
include every ``when`` pair.

* :func:`replay` scores a rule set on recorded events (``incident`` marks the
  ones that went wrong): incidents stopped, incidents missed, benign friction.
* :func:`better` promotes a candidate only if it misses strictly fewer incidents
  without adding more than ``max_extra_friction`` blocked benign events -- the
  cheap checker that lets a search propose rules without ever trusting one.
* :func:`contradictions` finds pairs of rules that forbid and require the same
  action under conditions that can hold together, with the witnessing condition.
"""
from __future__ import annotations

Rule = dict
Event = dict


def blocks(rules: list[Rule], event: Event) -> bool:
    return any(r["modality"] == "forbid" and r["action"] == event["action"]
               and all(event.get(k) == v for k, v in r.get("when", {}).items())
               for r in rules)


def replay(rules: list[Rule], events: list[Event]) -> dict[str, int]:
    out = {"incidents_stopped": 0, "incidents_missed": 0, "benign_blocked": 0}
    for e in events:
        hit = blocks(rules, e)
        if e.get("incident"):
            out["incidents_stopped" if hit else "incidents_missed"] += 1
        elif hit:
            out["benign_blocked"] += 1
    return out


def better(candidate: list[Rule], current: list[Rule], events: list[Event], *,
           max_extra_friction: int = 0) -> tuple[bool, dict]:
    new, old = replay(candidate, events), replay(current, events)
    ok = (new["incidents_missed"] < old["incidents_missed"]
          and new["benign_blocked"] - old["benign_blocked"] <= max_extra_friction)
    return ok, {"candidate": new, "current": old}


def contradictions(rules: list[Rule], *, limit: int | None = None) -> list[tuple[str, str, dict]]:
    """(forbidding rule, requiring rule, a condition under which both apply).

    ``limit`` stops after that many pairs, so a large rule set with many
    conflicts cannot keep a caller busy listing all of them."""
    requires: dict[object, list[Rule]] = {}
    for r in rules:
        if r["modality"] == "require":
            requires.setdefault(r["action"], []).append(r)
    out = []
    for f in rules:
        if f["modality"] != "forbid":
            continue
        for r in requires.get(f["action"], ()):
            a, b = f.get("when", {}), r.get("when", {})
            if all(a[k] == b[k] for k in a.keys() & b.keys()):
                out.append((f["id"], r["id"], {**a, **b}))
                if limit is not None and len(out) >= limit:
                    return out
    return out
