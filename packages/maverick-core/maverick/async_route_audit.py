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
deps beyond stdlib" design). It has two rules:

* ``no-await``: a route-decorated ``async def`` with zero
  ``await``/``async for``/``async with`` anywhere in its body, whose body
  calls something that looks like synchronous DB/file/config/store work or
  renders a page template.
* ``opens-store``: an ``async def`` route that awaits its query in the worker
  pool but first, on the loop, opens a governed SQLite store: a ``*Store``
  constructor, a store factory, ``sqlite3.connect``, or a helper in the same
  module that reaches one. Such a store waits up to its 30 s busy timeout
  for another writer; on the hosted demo the third-party intelligence page's
  thirteen lists did this one after another and the server answered nothing,
  health checks included, for two minutes. The zero-await rule never saw it,
  because each handler did await something afterwards. Handlers registered
  with ``router.add_api_route`` (including ones a local factory returns) are
  routes too.

The analysis follows calls within one module only; it is a heuristic over
names, not a proof.

``async_route_audit_grandfathered.json`` lists the handlers that already did
this when a rule was added, each with the reason it is tolerated; any other
detected handler fails CI, and so does an entry without a reason. The
two-sided ratchet also rejects stale lock entries; fixing a handler cannot
silently leave an exemption.
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


#: Rule names (see the module docstring).
NO_AWAIT = "no-await"
OPENS_STORE = "opens-store"


@dataclass(frozen=True)
class Finding:
    path: str
    name: str
    lineno: int
    blocking_calls: tuple[str, ...]
    rule: str = NO_AWAIT
    reason: str = ""

    @property
    def key(self) -> str:
        """Identity independent of line number, so an unrelated edit that
        shifts a handler down a few lines is not a spurious lock diff."""
        base = f"{self.path}::{self.name}"
        return base if self.rule == NO_AWAIT else f"{base}::{self.rule}"


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
        # Rendering reads the page's settings, permissions and navigation.
        or c.endswith("TemplateResponse")
    ))


def _opens_store(call: str) -> bool:
    """A call that opens a governed SQLite store (and may wait out its busy
    timeout): a ``*Store`` constructor, a store factory, sqlite3.connect."""
    last = call.rsplit(".", 1)[-1]
    return (last.endswith("Store") or last == "factory" or last.endswith("store_for")
            or call == "sqlite3.connect")


def _loop_calls(fn: ast.AST) -> list[ast.Call]:
    """Calls ``fn`` itself evaluates on its thread. An awaited call is handed
    off (its arguments are not), and a nested function or lambda runs only
    when something else calls it."""
    body = fn.body if isinstance(fn.body, list) else [fn.body]
    stack, awaited, out = list(body), set(), []
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            awaited.add(id(node.value))
        if isinstance(node, ast.Call) and id(node) not in awaited:
            out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _bindings(scope: ast.AST) -> dict[str, ast.AST | None]:
    """What each name bound directly in ``scope`` refers to: a local function
    definition, or None for any other binding (a parameter, an import, an
    assignment such as ``authority = partial(run_in_threadpool, ...)``)."""
    out: dict[str, ast.AST | None] = {}
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        a = scope.args
        for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
            if arg is not None:
                out[arg.arg] = None
    body = scope.body if isinstance(scope.body, list) else [scope.body]
    stack = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, node)
            continue
        if isinstance(node, (ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                out.setdefault((alias.asname or alias.name).split(".")[0], None)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            out.setdefault(node.id, None)
        stack.extend(ast.iter_child_nodes(node))
    return out


class _Module:
    """Resolve a called name to this module's function definition."""

    def __init__(self, tree: ast.AST) -> None:
        self.parent: dict[ast.AST, ast.AST] = {}
        self.by_name: dict[str, list[ast.FunctionDef]] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
            if isinstance(node, ast.FunctionDef):
                self.by_name.setdefault(node.name, []).append(node)
        self._bound: dict[ast.AST, dict[str, ast.AST | None]] = {}
        self._opened: dict[ast.AST, bool] = {}

    def _scopes(self, node: ast.AST):
        current = node
        while current is not None:
            if isinstance(current, _SCOPES):
                yield current
            current = self.parent.get(current)

    def targets(self, name: str, at: ast.AST) -> list[ast.AST]:
        """Definitions a bare ``name`` called inside ``at`` may run. A name
        that is a parameter (a router-registration helper is handed its
        module's ``authority``) may be any same-named function here."""
        for scope in self._scopes(at):
            bound = self._bound.setdefault(scope, _bindings(scope))
            if name not in bound:
                continue
            target = bound[name]
            if target is not None:
                return [target]
            is_parameter = isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and any(
                arg.arg == name for arg in (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs))
            return list(self.by_name.get(name, ())) if is_parameter else []
        return []

    def _opens(self, call: ast.Call) -> bool:
        name = _dotted(call.func)
        return _opens_store(name) or (
            isinstance(call.func, ast.Name)
            and any(isinstance(t, ast.FunctionDef) and self.opens_store(t)
                    for t in self.targets(name, call))
        )

    def opens_store(self, fn: ast.AST) -> bool:
        """Whether plain function ``fn`` opens a store, directly or through
        another plain function of this module."""
        if fn not in self._opened:
            self._opened[fn] = False  # a cycle adds nothing
            self._opened[fn] = any(self._opens(call) for call in _loop_calls(fn))
        return self._opened[fn]

    def loop_store_calls(self, handler: ast.AsyncFunctionDef) -> tuple[str, ...]:
        """The calls ``handler`` makes on the loop that open a store."""
        return tuple(sorted({_dotted(c.func) for c in _loop_calls(handler) if self._opens(c)}))


def _registered_handlers(tree: ast.AST) -> list[ast.AsyncFunctionDef]:
    """``async def`` endpoints passed to ``add_api_route``: by name, or as the
    result of a local factory that returns a nested ``async def``."""
    functions: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
    out: list[ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _dotted(node.func).endswith(".add_api_route")):
            continue
        endpoint = node.args[1] if len(node.args) > 1 else next(
            (k.value for k in node.keywords if k.arg == "endpoint"), None)
        if isinstance(endpoint, ast.Name):
            out.extend(f for f in functions.get(endpoint.id, ()) if isinstance(f, ast.AsyncFunctionDef))
        elif isinstance(endpoint, ast.Call):
            for factory in functions.get(_dotted(endpoint.func), ()):
                returned = {r.value.id for r in ast.walk(factory)
                            if isinstance(r, ast.Return) and isinstance(r.value, ast.Name)}
                out.extend(f for f in ast.walk(factory)
                           if isinstance(f, ast.AsyncFunctionDef) and f.name in returned)
    return out


def _scan_file(path: Path, *, rel_to: Path) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return []
    rel = path.relative_to(rel_to).as_posix()
    out: list[Finding] = []
    module = _Module(tree)
    handlers = [fn for fn in ast.walk(tree) if isinstance(fn, ast.AsyncFunctionDef)
                and any(_is_route_decorator(d) for d in fn.decorator_list)]
    handlers += [fn for fn in _registered_handlers(tree) if fn not in handlers]
    for fn in handlers:
        yields = any(
            isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith))
            for n in ast.walk(fn)
        )
        blocking = () if yields else _blocking_calls(fn)
        if blocking:
            out.append(Finding(path=rel, name=fn.name, lineno=fn.lineno,
                               blocking_calls=blocking))
            continue
        opened = module.loop_store_calls(fn)
        if opened:
            out.append(Finding(path=rel, name=fn.name, lineno=fn.lineno,
                               blocking_calls=opened, rule=OPENS_STORE))
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
                    blocking_calls=tuple(entry.get("blocking_calls", ())),
                    rule=entry.get("rule", NO_AWAIT),
                    reason=str(entry.get("reason", "")).strip())
        out[f.key] = f
    return out


def write_lock(root: Path | None = None) -> Path:
    """Rewrite the lock from the current scan, keeping the reason already
    given for each entry that remains. A new entry has none until a person
    writes one; ``problems`` reports it until then."""
    reasons = {key: f.reason for key, f in load_lock().items()}
    findings = scan(root)
    payload = []
    for f in findings:
        entry = {"path": f.path, "name": f.name, "lineno": f.lineno,
                 "blocking_calls": list(f.blocking_calls)}
        if f.rule != NO_AWAIT:
            entry["rule"] = f.rule
        entry["reason"] = reasons.get(f.key, "")
        payload.append(entry)
    path = lock_path()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def _fix_hint(f: Finding) -> str:
    if f.rule == OPENS_STORE:
        return (f"{f.path}:{f.lineno} {f.name}() is an async route handler "
                f"that calls {', '.join(f.blocking_calls)} on the event loop, "
                "which opens a governed SQLite store: it can wait out a 30 s "
                "busy timeout while every other request, /livez included, "
                "waits too. Open the store in the worker pool (`authority = "
                "partial(run_in_threadpool, open_authority)` and `await "
                "authority(request)`, as third_party_intelligence_api does), "
                "or make the handler a plain `def`.")
    return (f"{f.path}:{f.lineno} {f.name}() is an async route handler "
            f"with no await that calls {', '.join(f.blocking_calls)} -- "
            "this blocks the dashboard event loop. Make it a plain `def` "
            "(FastAPI thread-pools those automatically), wrap the "
            "blocking call in run_in_threadpool, or add an await/"
            "async-with/async-for that actually yields control.")


def problems(root: Path | None = None) -> list[str]:
    """New (un-grandfathered) violations, grandfathered ones without a
    reason, plus stale lock entries that no longer reproduce -- the same
    two-sided ratchet as egress_contract.problems()."""
    current = {f.key: f for f in scan(root)}
    locked = load_lock()
    out: list[str] = []
    for key, f in sorted(current.items()):
        if key not in locked:
            out.append(
                _fix_hint(f) + " If this is an intentional, tracked "
                "exception, run `python -m maverick.async_route_audit "
                "--regen`, write its reason in the lock and commit it.")
        elif not locked[key].reason:
            out.append(
                f"{f.path} {f.name}() is recorded in {lock_path().name} "
                "without a reason. Write why it is tolerated in its "
                "\"reason\", or fix it and run `--regen`.")
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
        return (f"async route audit: {len(findings)} known event-loop-blocking "
                f"route handler(s) (all grandfathered), 0 new.")
    lines = [f"async route audit: {len(new)} NEW event-loop-blocking route handler(s):"]
    for f in sorted(new, key=lambda f: f.key):
        lines.append(f"  {f.path}:{f.lineno} {f.name}() [{f.rule}] -> "
                     f"{', '.join(f.blocking_calls)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.async_route_audit",
        description="Flag async FastAPI route handlers that block the event "
                    "loop (no await, synchronous DB/file/config work, or a "
                    "governed store opened before the first await).")
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
    "NO_AWAIT", "OPENS_STORE", "Finding", "scan", "lock_path", "load_lock", "write_lock", "problems",
    "render", "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
