"""One read-only projection of the immune layer for the dashboard and CLI.

Counts, scores, labels and tool names only: no canary flaws, tool arguments,
recorded tool output or code. Every section degrades to ``available: False``
with a reason instead of failing the whole page.
"""
from __future__ import annotations

import threading
import time
from collections import Counter

_ROSTER_TTL = 600.0
_roster_cache: dict[str, tuple[float, dict]] = {}
_roster_lock = threading.Lock()


def _composition() -> dict:
    """Composition risk of the installed roster at the deployment's settings.
    Cached per tenant (a tenant's own packs are part of its roster): the
    analysis walks every pack (seconds at roster scale)."""
    from ..paths import current_tenant_id
    tenant = current_tenant_id() or ""
    with _roster_lock:
        hit = _roster_cache.get(tenant)
        if hit is not None and time.monotonic() - hit[0] < _ROSTER_TTL:
            return hit[1]
        from . import network
        g = network.roster_graph()
        found = network.findings(g)
        value = {
            "available": True,
            "agents": len(g.agents),
            "by_kind": dict(Counter(f.kind for f in found)),
            "by_sink_risk": dict(Counter(f.sink_risk for f in found)),
            "trifectas": [{"path": list(f.path),
                           "witness": {k: list(v) for k, v in f.witness.items()},
                           "sink_risk": f.sink_risk}
                          for f in found if f.kind == "trifecta"][:50],
        }
        now = time.monotonic()
        for key in [k for k, (at, _) in _roster_cache.items() if now - at >= _ROSTER_TTL]:
            del _roster_cache[key]
        _roster_cache[tenant] = (now, value)
        return value


def _oversight(world) -> dict:
    from . import oversight
    out = {"available": True, "canaries_enabled": oversight.canaries_enabled()}
    for kind in ("canary", "drill"):
        out[kind] = sorted(
            ({"person": person, "class": cls, "caught": s.caught, "missed": s.missed,
              "assured": round(s.assured, 3), "authority": oversight.authority(s)}
             for (person, cls), s in oversight.score(world, kind).items()),
            key=lambda r: (r["class"], r["person"]))
    return out


def _twin() -> dict:
    from . import _ledger, twin
    rows = _ledger.read(twin.replays_path())
    replays = [r for r in rows if r.get("type") != "awareness_probe"][-50:]
    probes = [r for r in rows if r.get("type") == "awareness_probe"][-10:]
    return {"available": True, "recording": twin.recording_enabled(),
            "replays": [{k: r.get(k) for k in (
                "production_goal", "twin_goal", "watched", "production_status", "twin_status",
                "served", "recorded", "unmatched", "result_similarity")}
                | {"approximate": len(r.get("approximate") or [])} for r in replays[::-1]],
            "probes": [{"at": p.get("at"), "goal_count": p.get("goal_count"),
                        "diverged": p.get("diverged"), "blocked": p.get("blocked")}
                       for p in probes[::-1]]}


def _ifc() -> dict:
    from .. import ifc
    from ..config import get_ifc
    from . import _ledger
    rows = _ledger.read(ifc.ledger_path())[-1000:]
    return {"available": True, "mode": get_ifc()["mode"], "events": len(rows),
            "by_outcome": dict(Counter(r["outcome"] for r in rows)),
            "by_tool": dict(Counter(r["tool"] for r in rows).most_common(10)),
            "by_label": dict(Counter(lab for r in rows for lab in r["labels"]).most_common(10)),
            "explicit": sum(1 for r in rows if r.get("explicit")),
            "recent": [{k: r.get(k) for k in ("at", "goal_id", "tool", "labels", "explicit",
                                               "mode", "outcome")} for r in rows[-50:][::-1]]}


def _safe(fn, *args) -> dict:
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 -- one section never breaks the page
        return {"available": False, "reason": type(exc).__name__}


def summary(world=None) -> dict:
    return {
        "schema": "lightwork.immune-summary.v1",
        "composition": _safe(_composition),
        "oversight": _safe(_oversight, world) if world is not None
        else {"available": False, "reason": "no world"},
        "twin": _safe(_twin),
        "ifc": _safe(_ifc),
    }


__all__ = ["summary"]
