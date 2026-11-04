"""Plugin version-pinning lockfile.

Pin the exact set of installed plugins so a swarm runs the same code everywhere:
``generate`` emits a deterministic, sorted lockfile (one ``name==version==hash``
line per plugin), and ``verify`` compares an installed set against a lockfile and
reports drift (version/hash mismatches and missing plugins). Pure text;
deterministic; offline. No disk, no network.

ops:
  - generate(plugins=[{name, version, sha256?}]) -> the lockfile string.
  - verify(lockfile, installed=[{name, version, sha256?}]) -> OK or DRIFT.

Line format: ``name==version==sha256`` (the hash field is empty when omitted, so
the line ends ``name==version==``). Lines are sorted by name for stability.
"""
from __future__ import annotations

from typing import Any

from . import Tool

_HEADER = "# maverick plugin lockfile v1"


def _norm(entry: Any) -> tuple[str, str, str] | str:
    """(name, version, sha256) for one entry, or an ERROR string."""
    if not isinstance(entry, dict):
        return "ERROR: each plugin must be an object {name, version, sha256?}"
    name = str(entry.get("name") or "").strip()
    version = str(entry.get("version") or "").strip()
    if not name:
        return "ERROR: plugin entry missing name"
    if not version:
        return f"ERROR: plugin {name!r} missing version"
    sha = str(entry.get("sha256") or "").strip()
    return name, version, sha


def _generate(args: dict[str, Any]) -> str:
    plugins = args.get("plugins")
    if not isinstance(plugins, list):
        return "ERROR: plugins must be an array of {name, version, sha256?}"
    rows: list[tuple[str, str, str]] = []
    for entry in plugins:
        norm = _norm(entry)
        if isinstance(norm, str):
            return norm
        rows.append(norm)
    rows.sort(key=lambda r: r[0])
    lines = [_HEADER]
    lines += [f"{name}=={version}=={sha}" for name, version, sha in rows]
    return "\n".join(lines)


def _parse_lockfile(text: str) -> dict[str, tuple[str, str]]:
    """name -> (version, sha256) for every non-comment, non-blank line."""
    out: dict[str, tuple[str, str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("==")
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        sha = parts[2].strip() if len(parts) >= 3 else ""
        if name:
            out[name] = (version, sha)
    return out


def _verify(args: dict[str, Any]) -> str:
    lockfile = args.get("lockfile")
    installed = args.get("installed")
    if not isinstance(lockfile, str) or not lockfile.strip():
        return "ERROR: lockfile is required"
    if not isinstance(installed, list):
        return "ERROR: installed must be an array of {name, version, sha256?}"

    pinned = _parse_lockfile(lockfile)
    have: dict[str, tuple[str, str]] = {}
    for entry in installed:
        norm = _norm(entry)
        if isinstance(norm, str):
            return norm
        name, version, sha = norm
        have[name] = (version, sha)

    drift: list[str] = []
    for name in sorted(pinned):
        want_v, want_h = pinned[name]
        if name not in have:
            drift.append(f"{name}: missing (pinned {want_v})")
            continue
        got_v, got_h = have[name]
        if got_v != want_v:
            drift.append(f"{name}: version {got_v} != pinned {want_v}")
        elif want_h and got_h != want_h:
            drift.append(f"{name}: sha256 mismatch (pinned {want_h})")
    for name in sorted(have):
        if name not in pinned:
            drift.append(f"{name}: installed but not pinned")

    if drift:
        body = "\n".join(f"- {d}" for d in drift)
        return f"DRIFT: {len(drift)} issue(s)\n{body}"
    return f"OK: {len(pinned)} plugin(s) match the lockfile"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "generate":
        return _generate(args)
    if op == "verify":
        return _verify(args)
    return f"ERROR: unknown op {op!r} (expected generate or verify)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["generate", "verify"]},
        "plugins": {
            "type": "array",
            "description": "for op=generate; each {name, version, sha256?}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "sha256": {"type": "string"},
                },
                "required": ["name", "version"],
            },
        },
        "lockfile": {"type": "string", "description": "lockfile text for op=verify"},
        "installed": {
            "type": "array",
            "description": "for op=verify; each {name, version, sha256?}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "sha256": {"type": "string"},
                },
                "required": ["name", "version"],
            },
        },
    },
    "required": ["op"],
}


def plugin_lockfile() -> Tool:
    return Tool(
        name="plugin_lockfile",
        description=(
            "Pin/verify plugin versions via a deterministic lockfile. "
            "op=generate {plugins:[{name, version, sha256?}]} -> sorted "
            "'name==version==sha256' lines. op=verify {lockfile, installed:[...]} "
            "-> OK or DRIFT listing version/hash mismatches, missing, and "
            "unpinned plugins. Pure text; deterministic; offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
