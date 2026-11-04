"""Which modules does production actually reach?

Documentation and capability claims should only name modules that production
can reach. This module answers that structurally: it walks the import graph
from real entry points and classifies every non-test module:

``PRODUCTION``   reachable from the CLI, the dashboard app, or the agent kernel
``CLI_ONLY``     reachable only as a ``python -m`` module main
``CI_ONLY``      reachable only from a CI gate
``TEST_ONLY``    imported only by tests
``UNREACHED``    imported by nothing outside itself

The ledger is committed (``reachability.lock.json``) and CI-ratcheted, so a
module going dark, or a doc naming an unreached one, fails the build instead of
going unnoticed.

CLI: ``python -m maverick.reachability`` prints the classification;
``--ci`` fails on drift; ``--regen`` rewrites the lock.

Import-graph reachability is a *static* over-approximation: it follows
``import`` statements, including deferred ones inside functions, so a module
imported behind a feature flag counts as reachable. That is the honest bias for
this purpose -- it can call something reachable that never runs at runtime, but
it will not call something unreachable that does. Read UNREACHED as "certainly
dead", and PRODUCTION as "on a path that can execute", not "executed".
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import deque
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_ROOT = Path(__file__).resolve().parent
LOCK = PKG_ROOT / "reachability.lock.json"

#: Real entry points, by how the product is actually started.
ENTRY_POINTS = {
    "PRODUCTION": (
        "maverick.cli",              # the `maverick` console script
        "maverick.agent",            # the kernel
        "maverick.orchestrator",     # goal execution
        "maverick_dashboard.app",    # the FastAPI app
        "maverick.mcp_server",       # `maverick mcp`
    ),
}

PACKAGES = ("maverick-core", "maverick-dashboard", "maverick-shield",
            "maverick-channels", "maverick-evolve", "maverick-knowledge",
            "maverick-mcp")


def _module_name(path: Path) -> str | None:
    """Dotted module name for a file inside packages/<pkg>/<top>/..."""
    try:
        rel = path.relative_to(REPO_ROOT / "packages")
    except ValueError:
        return None
    parts = rel.parts
    if len(parts) < 3:
        return None
    mod = list(parts[1:])
    if mod[-1] == "__init__.py":
        mod = mod[:-1]
    else:
        mod[-1] = mod[-1][:-3]
    return ".".join(mod)


def _is_test(path: Path) -> bool:
    return "tests" in path.parts or path.name.startswith("test_")


def all_modules() -> dict[str, Path]:
    """Every non-test module in the workspace, by dotted name."""
    out: dict[str, Path] = {}
    for pkg in PACKAGES:
        base = REPO_ROOT / "packages" / pkg
        if not base.is_dir():
            continue
        # Only immediate import-package roots are source. Recursive scanning
        # from the distribution root also walks ``build/lib`` and unpacked
        # sdists left by packaging tests, classifying copied modules under
        # names such as ``build.lib.maverick.agent``. Besides creating hundreds
        # of false UNREACHED entries, those artifacts vary by local build
        # history, so the committed ledger stops describing the repository.
        source_roots = sorted(
            child
            for child in base.iterdir()
            if child.is_dir() and (child / "__init__.py").is_file()
        )
        for source_root in source_roots:
            for p in sorted(source_root.rglob("*.py")):
                if _is_test(p):
                    continue
                name = _module_name(p)
                if name:
                    out[name] = p
    return out


def _imports_of(path: Path, own: str) -> set[str]:
    """Modules this file imports, absolute and relative, deferred included."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):  # pragma: no cover
        return set()
    pkg_parts = own.split(".")
    # For `from . import x` inside a package module, level 1 means this
    # module's package, which is own minus its last segment for a plain module
    # and own itself for a package __init__.
    is_pkg = path.name == "__init__.py"
    base = pkg_parts if is_pkg else pkg_parts[:-1]

    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                out.add(a.name)
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                anchor = base[: len(base) - (n.level - 1)] if n.level > 1 else base
                prefix = ".".join(anchor)
                mod = f"{prefix}.{n.module}" if n.module else prefix
            else:
                mod = n.module or ""
            if not mod:
                continue
            out.add(mod)
            # `from x import y` may name a submodule rather than an attribute.
            for a in n.names:
                out.add(f"{mod}.{a.name}")
    return out


def build_graph() -> dict[str, set[str]]:
    mods = all_modules()
    graph: dict[str, set[str]] = {}
    for name, path in mods.items():
        graph[name] = {m for m in _imports_of(path, name) if m in mods}
    return graph


def _reach(graph: dict[str, set[str]], roots: tuple[str, ...]) -> set[str]:
    seen: set[str] = set()
    q = deque(r for r in roots if r in graph)
    seen.update(q)
    while q:
        cur = q.popleft()
        for nxt in graph.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return seen


def _has_module_main(path: Path) -> bool:
    try:
        src = path.read_text(encoding="utf-8")
    except OSError:  # pragma: no cover
        return False
    return '__name__ == "__main__"' in src or "__name__ == '__main__'" in src


def _ci_referenced() -> set[str]:
    """Modules named by a CI workflow as `python -m maverick.x`."""
    out: set[str] = set()
    wf = REPO_ROOT / ".github" / "workflows"
    if not wf.is_dir():
        return out
    for f in wf.rglob("*.yml"):
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:  # pragma: no cover
            continue
        for token in text.replace("\n", " ").split():
            if token.startswith("maverick.") and token.count(" ") == 0:
                out.add(token.strip("\"'`,"))
    return out


def _test_referenced(mods: dict[str, Path]) -> set[str]:
    out: set[str] = set()
    for pkg in PACKAGES:
        base = REPO_ROOT / "packages" / pkg / "tests"
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            for imp in _imports_of(p, ""):
                if imp in mods:
                    out.add(imp)
    return out


def classify() -> dict[str, str]:
    mods = all_modules()
    graph = build_graph()
    production = _reach(graph, ENTRY_POINTS["PRODUCTION"])
    ci = _ci_referenced()
    ci_reach = _reach(graph, tuple(m for m in ci if m in graph))
    tested = _test_referenced(mods)

    out: dict[str, str] = {}
    for name, path in sorted(mods.items()):
        if name in production:
            out[name] = "PRODUCTION"
        elif name in ci_reach:
            out[name] = "CI_ONLY"
        elif _has_module_main(path):
            out[name] = "CLI_ONLY"
        elif name in tested:
            out[name] = "TEST_ONLY"
        else:
            out[name] = "UNREACHED"
    return out


def summary(table: dict[str, str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in table.values():
        counts[v] = counts.get(v, 0) + 1
    return dict(sorted(counts.items()))


def load_lock() -> dict[str, str]:
    if not LOCK.exists():
        return {}
    try:
        return json.loads(LOCK.read_text(encoding="utf-8")).get("modules") or {}
    except (OSError, ValueError):  # pragma: no cover
        return {}


def drift(table: dict[str, str], lock: dict[str, str]) -> list[str]:
    """Changes that matter: a module going dark, or newly unreached."""
    problems = []
    RANK = {"PRODUCTION": 4, "CI_ONLY": 3, "CLI_ONLY": 2, "TEST_ONLY": 1,
            "UNREACHED": 0}
    for name, was in sorted(lock.items()):
        now = table.get(name)
        if now is None:
            continue  # deleted modules are fine
        if RANK.get(now, 0) < RANK.get(was, 0):
            problems.append(
                f"{name}: {was} -> {now} (it lost a caller; either restore the "
                "path or accept the demotion with --regen)")
    for name, now in sorted(table.items()):
        if name not in lock and now == "UNREACHED":
            problems.append(
                f"{name}: new module that nothing reaches. Wire it up, or "
                "record it with --regen and do not cite it as capability.")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ci", action="store_true", help="exit non-zero on drift")
    ap.add_argument("--regen", action="store_true", help="rewrite the lock")
    ap.add_argument("--list", metavar="CLASS", help="print modules in a class")
    args = ap.parse_args(argv)

    # Validate the request before the 15-second graph walk, not after it.
    wanted = args.list.upper() if args.list else None
    if wanted is not None and wanted not in {"PRODUCTION", "CI_ONLY", "CLI_ONLY",
                                             "TEST_ONLY", "UNREACHED"}:
        print(f"reachability: unknown class {args.list!r}", file=sys.stderr)
        return 2

    table = classify()
    if not table:
        print("reachability: ERROR -- classified 0 modules; the package roots "
              f"are wrong or missing under {REPO_ROOT}/packages", file=sys.stderr)
        return 2
    counts = summary(table)

    if wanted is not None:
        try:
            for name, cls in sorted(table.items()):
                if cls == wanted:
                    print(name)
        except BrokenPipeError:  # `| head` closes the pipe; not an error
            try:
                sys.stdout.close()
            except BrokenPipeError:
                pass
        return 0

    if args.regen:
        LOCK.write_text(json.dumps({
            "_comment": "Which modules production actually reaches. Regenerate "
                        "with `python -m maverick.reachability --regen`. A "
                        "module listed UNREACHED must not be cited as shipped "
                        "capability in docs or strategy.",
            "counts": counts,
            "modules": table,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"reachability: lock rewritten -- {counts}")
        return 0

    print(f"reachability: {len(table)} modules -- {counts}")
    lock = load_lock()
    if not lock:
        print("reachability: no lock committed; run --regen", file=sys.stderr)
        return 1 if args.ci else 0
    problems = drift(table, lock)
    if not problems:
        return 0
    print(f"\nreachability: {len(problems)} drift problem(s):", file=sys.stderr)
    for p in problems:
        print(f"  {p}", file=sys.stderr)
    return 1 if args.ci else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
