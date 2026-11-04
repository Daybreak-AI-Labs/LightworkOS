"""Process introspection tool.

PURE / OFFLINE: it analyzes a *caller-supplied* process snapshot. It never
reads the live OS — no ``psutil``, no ``/proc``. The caller passes a list of
process records and this ranks them and flags orphans (a process whose parent
pid is absent from the snapshot).

ops:
  - parse(snapshot[, top][, by])  — top-N processes by 'rss' or 'cpu', plus
    detected orphans.

``snapshot``: list of {pid, ppid, name, rss_kb, cpu_pct}.
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _parse(snapshot: list[Any], top: int, by: str) -> str:
    procs: list[dict[str, Any]] = []
    pids: set[int] = set()
    for row in snapshot:
        if not isinstance(row, dict):
            return "ERROR: each snapshot row must be an object"
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError):
            return "ERROR: every process needs an integer 'pid'"
        procs.append({
            "pid": pid,
            "ppid": row.get("ppid"),
            "name": str(row.get("name") or "?"),
            "rss_kb": _num(row.get("rss_kb")),
            "cpu_pct": _num(row.get("cpu_pct")),
        })
        pids.add(pid)

    key = "rss_kb" if by == "rss" else "cpu_pct"
    unit = "rss_kb" if by == "rss" else "cpu_pct"
    # Sort by the chosen metric desc; ties broken by pid asc for determinism.
    ranked = sorted(procs, key=lambda p: (-p[key], p["pid"]))[:top]

    # Orphans: ppid is set and not present in the snapshot (pid 0 / None = no
    # parent recorded, i.e. a root, not an orphan).
    orphans: list[dict[str, Any]] = []
    for p in procs:
        ppid_raw = p["ppid"]
        if ppid_raw is None:
            continue
        try:
            ppid = int(ppid_raw)
        except (TypeError, ValueError):
            continue
        if ppid == 0:
            continue
        if ppid not in pids:
            orphans.append({"pid": p["pid"], "name": p["name"], "ppid": ppid})

    lines = [f"OK: {len(procs)} process(es); top {len(ranked)} by {by}"]
    for p in ranked:
        lines.append(
            f"pid={p['pid']} {p['name']} {unit}={_fmt(p[key])}"
        )
    if orphans:
        lines.append(f"orphans: {len(orphans)} (ppid not in snapshot)")
        for o in sorted(orphans, key=lambda o: o["pid"]):
            lines.append(f"orphan pid={o['pid']} {o['name']} ppid={o['ppid']}")
    else:
        lines.append("orphans: 0")
    return "\n".join(lines)


def _fmt(v: float) -> str:
    return str(int(v)) if v == int(v) else str(v)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "parse"):
        return f"ERROR: unknown op {args.get('op')!r} (expected parse)"
    snapshot = args.get("snapshot")
    if not isinstance(snapshot, list):
        return (
            "ERROR: snapshot (array of {pid, ppid, name, rss_kb, cpu_pct}) "
            "is required"
        )
    by = str(args.get("by", "rss")).strip().lower()
    if by not in ("rss", "cpu"):
        return "ERROR: by must be 'rss' or 'cpu'"
    try:
        top = int(args.get("top", 5))
    except (TypeError, ValueError):
        return "ERROR: top must be an integer"
    if top < 1:
        return "ERROR: top must be >= 1"
    if not snapshot:
        return "OK: 0 process(es); top 0 by " + by + "\norphans: 0"
    return _parse(snapshot, top, by)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["parse"]},
        "snapshot": {
            "type": "array",
            "description": "caller-supplied process records (NOT read from the OS)",
            "items": {
                "type": "object",
                "properties": {
                    "pid": {"type": "integer"},
                    "ppid": {"type": "integer"},
                    "name": {"type": "string"},
                    "rss_kb": {"type": "number"},
                    "cpu_pct": {"type": "number"},
                },
                "required": ["pid"],
            },
        },
        "top": {"type": "integer", "description": "how many to return (default 5)"},
        "by": {"type": "string", "enum": ["rss", "cpu"], "description": "ranking metric (default rss)"},
    },
    "required": ["snapshot"],
}


def process_introspect() -> Tool:
    return Tool(
        name="process_introspect",
        description=(
            "Process introspection over a CALLER-SUPPLIED snapshot (offline; "
            "never reads /proc or psutil). op=parse with 'snapshot' (each {pid, "
            "ppid, name, rss_kb, cpu_pct}), optional 'top' (default 5) and 'by' "
            "('rss' or 'cpu', default rss). Returns the top-N processes plus "
            "orphan detection (ppid absent from the snapshot). Deterministic."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
