"""Static concurrency audit: FastAPI ``async def`` route handlers that never
``await`` anything, despite calling synchronous SQLite/world/file/config work
in their body.

FastAPI runs a plain ``def`` route in a worker thread pool automatically, but
an ``async def`` route runs directly on the single event loop thread that
serves *every* request. A route declared ``async def`` that never actually
awaits anything gets neither benefit: it isn't thread-pooled (FastAPI assumes
an ``async def`` handler already yields control when it blocks), and it
blocks the one event loop for however long its synchronous DB/file/config
call takes -- stalling every other in-flight request on the dashboard for
that duration.

This module is the static, offline, AST-only detector (no server, no
network, mirrors :mod:`maverick.a11y_audit`'s "parse the shipped source, no
deps beyond stdlib" design): a route-decorated ``async def`` with zero
``await``/``async for``/``async with`` anywhere in its body, whose body calls
something that looks like synchronous DB/file/config/store work.

``async_route_audit_grandfathered.json`` is empty, so every detected
zero-await blocking handler fails CI. The two-sided ratchet also rejects
stale lock entries; fixing a handler cannot silently leave an exemption.
This static check is a regression guard, not proof that every async path
is free of blocking I/O; runtime concurrency tests cover representative
storage-backed requests and tenant context propagation.

Surfaced as ``python -m maverick.async_route_audit --ci`` (CI gate) and
``--regen`` (rewrite the lock after intentionally fixing or adding entries).
"""
from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

#: FastAPI route-registration method names, matched as the trailing attribute
#: of the decorator call (``@router.get(...)``, ``@app.websocket(...)``, an
#: aliased router, etc.) so it doesn't depend on the router's variable name.
_ROUTE_METHODS = ("get", "post", "put", "delete", "patch", "websocket", "api_route")

#: Call-name prefixes/substrings that indicate synchronous, blocking work in
#: the handler body -- the actual "blocks the loop" signal. A zero-await
#: route that does no I/O at all (pure computation on already-in-memory data)
#: isn't this bug, so "no await" alone is not sufficient to flag.
_BLOCKING_HINTS = (
    "_world", "world", "sqlite3", "open", "load_config", "list_triggers",
    "store", "queue",
    # Synchronous network clients: a catalog index fetch, urllib, httpx.
    "load_catalog", "urlopen", "guarded_urlopen", "urllib", "httpx",
)


@dataclass(frozen=True)
class Finding:
    path: str
    name: str
    lineno: int
    blocking_calls: tuple[str, ...]

    @property
    def key(self) -> str:
        """Identity independent of line number, so an unrelated edit that
        shifts a handler down a few lines is not a spurious lock diff."""
        return f"{self.path}::{self.name}"


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_route_decorator(dec: ast.expr) -> bool:
    name = _dotted(dec.func) if isinstance(dec, ast.Call) else _dotted(dec)
    return any(name.endswith("." + m) for m in _ROUTE_METHODS)


def _blocking_calls(fn: ast.AsyncFunctionDef) -> tuple[str, ...]:
    calls = {_dotted(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)}
    return tuple(sorted(
        c for c in calls
        if c.split(".")[0] in _BLOCKING_HINTS
        or "world" in c.lower() or "_store" in c or "store." in c
    ))


def _scan_file(path: Path, *, rel_to: Path) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []
    rel = path.relative_to(rel_to).as_posix()
    out: list[Finding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.AsyncFunctionDef):
            continue
        if not any(_is_route_decorator(d) for d in fn.decorator_list):
            continue
        yields = any(
            isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith))
            for n in ast.walk(fn)
        )
        if yields:
            continue
        blocking = _blocking_calls(fn)
        if blocking:
            out.append(Finding(path=rel, name=fn.name, lineno=fn.lineno,
                               blocking_calls=blocking))
    return out


def _default_dashboard_root() -> Path | None:
    """Walk up from this file to find the sibling dashboard package -- same
    pattern as :func:`maverick.a11y_audit._default_template_dir`."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "maverick-dashboard" / "maverick_dashboard"
        if cand.is_dir():
            return cand
    return None


def scan(root: Path | None = None) -> list[Finding]:
    """Every zero-await, blocking-call route handler under ``root`` (default:
    the dashboard package), sorted for stable output."""
    root = root or _default_dashboard_root()
    if root is None or not Path(root).is_dir():
        return []
    root = Path(root)
    out: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if "tests" in path.parts or path.name.startswith("test_"):
            continue
        out.extend(_scan_file(path, rel_to=root.parent))
    out.sort(key=lambda f: f.key)
    return out


def lock_path() -> Path:
    """The committed grandfather list, next to this module."""
    return Path(__file__).with_name("async_route_audit_grandfathered.json")


def load_lock() -> dict[str, Finding]:
    path = lock_path()
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = {}
    for entry in raw:
        f = Finding(path=entry["path"], name=entry["name"],
                    lineno=entry.get("lineno", 0),
                    blocking_calls=tuple(entry.get("blocking_calls", ())))
        out[f.key] = f
    return out


def write_lock(root: Path | None = None) -> Path:
    findings = scan(root)
    payload = [
        {"path": f.path, "name": f.name, "lineno": f.lineno,
         "blocking_calls": list(f.blocking_calls)}
        for f in findings
    ]
    path = lock_path()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def problems(root: Path | None = None) -> list[str]:
    """New (un-grandfathered) violations, plus stale lock entries that no
    longer reproduce -- the same two-sided ratchet as
    egress_contract.problems()."""
    current = {f.key: f for f in scan(root)}
    locked = load_lock()
    out: list[str] = []
    for key, f in sorted(current.items()):
        if key not in locked:
            out.append(
                f"{f.path}:{f.lineno} {f.name}() is an async route handler "
                f"with no await that calls {', '.join(f.blocking_calls)} -- "
                "this blocks the dashboard event loop. Make it a plain `def` "
                "(FastAPI thread-pools those automatically), wrap the "
                "blocking call in run_in_threadpool, or add an await/"
                "async-with/async-for that actually yields control. If this "
                "is an intentional, tracked exception, run `python -m "
                "maverick.async_route_audit --regen` and commit the lock.")
    for key in sorted(set(locked) - set(current)):
        f = locked[key]
        out.append(
            f"{f.path} {f.name}() is recorded in "
            f"{lock_path().name} but no longer reproduces -- it was fixed. "
            "Run `--regen` and commit the lock so the grandfather list "
            "actually shrinks.")
    return out


def render(root: Path | None = None) -> str:
    findings = scan(root)
    locked = load_lock()
    new = [f for f in findings if f.key not in locked]
    if not new:
        return (f"async route audit: {len(findings)} known zero-await route "
                f"handler(s) (all grandfathered), 0 new.")
    lines = [f"async route audit: {len(new)} NEW zero-await route handler(s):"]
    for f in sorted(new, key=lambda f: f.key):
        lines.append(f"  {f.path}:{f.lineno} {f.name}() -> "
                     f"{', '.join(f.blocking_calls)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.async_route_audit",
        description="Flag async FastAPI route handlers that block the event "
                    "loop (no await, synchronous DB/file/config work).")
    p.add_argument("--dir", default=None,
                   help="dashboard package directory (default: auto-detected)")
    p.add_argument("--ci", action="store_true", help="exit 1 on any problem")
    p.add_argument("--regen", action="store_true",
                   help="rewrite the grandfather lock from the current scan")
    args = p.parse_args(argv)
    root = Path(args.dir) if args.dir else None

    if args.regen:
        path = write_lock(root)
        print(f"wrote {path}")
        return 0

    # Anti-vacuity: a gate that silently inspected 0 files would report a
    # clean bill of health over nothing checked (see a11y_audit's own note).
    resolved_root = root or _default_dashboard_root()
    inspected = list(resolved_root.rglob("*.py")) if resolved_root else []
    if not inspected:
        print(f"async route audit: ERROR -- inspected 0 files under "
              f"{resolved_root}. The dashboard package is missing, empty, or "
              "--dir is wrong; this is a broken gate, not a pass.",
              file=sys.stderr)
        return 2

    probs = problems(root)
    print(render(root))
    if probs:
        print(f"async route audit: {len(probs)} problem(s):")
        for prob in probs:
            print(f"  - {prob}")
    if args.ci and probs:
        return 1
    return 0


__all__ = [
    "Finding", "scan", "lock_path", "load_lock", "write_lock", "problems",
    "render", "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
