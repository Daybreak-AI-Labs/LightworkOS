"""Cross-repo dependency graph tool.

Parses the Python import graph across one or more repo roots and surfaces the
edges *between* top-level packages — the view that matters when you're trying
to see how several repos (or several packages in a monorepo) actually couple to
each other, and whether that coupling has cycles.

ops:
  - graph(paths)   — package -> package edges (with file counts), plus which
                     edges cross from one given root into another.
  - cycles(paths)  — strongly-connected import cycles among the packages.

Read-only: it walks bounded ``*.py`` files below ``sandbox.workdir`` and
parses them with ``ast`` (no import execution).
"""
from __future__ import annotations

import ast
import os
import stat
from pathlib import Path
from typing import Any

from . import Tool

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", "build", "dist"}
_MAX_ROOTS = 8
_MAX_WALK_DEPTH = 12
_MAX_PY_FILES = 2_000
_MAX_PARSE_BYTES = 1_000_000
_MAX_OUTPUT_ROWS = 1_000


def _safe_roots(sandbox: Any | None, raw_paths: list[str]) -> tuple[list[Path], str | None]:
    """Resolve user roots inside ``sandbox.workdir`` and refuse escapes."""
    if len(raw_paths) > _MAX_ROOTS:
        return [], f"too many paths (max {_MAX_ROOTS})"

    workdir = Path(getattr(sandbox, "workdir", ".")).resolve()
    if not workdir.is_dir():
        return [], f"workdir {workdir} not found"

    roots: list[Path] = []
    for raw in raw_paths:
        candidate = (workdir / raw).resolve()
        try:
            candidate.relative_to(workdir)
        except ValueError:
            return [], f"path {raw!r} escapes the workspace"
        if candidate.is_dir():
            roots.append(candidate)
    return roots, None


def _py_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        try:
            depth = len(base.relative_to(root).parts)
        except ValueError:
            dirnames[:] = []
            continue
        if depth >= _MAX_WALK_DEPTH:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for f in filenames:
            if not f.endswith(".py"):
                continue
            path = base / f
            try:
                st = path.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_PARSE_BYTES:
                continue
            out.append(path)
            if len(out) >= _MAX_PY_FILES:
                return out
    return out


def _top_package(path: Path, root: Path) -> str:
    """First path component of ``path`` relative to ``root`` (the package)."""
    rel = path.relative_to(root)
    parts = rel.parts
    return parts[0] if len(parts) > 1 else path.stem


def _imports(path: Path) -> set[str]:
    try:
        with path.open("rb") as fh:
            raw = fh.read(_MAX_PARSE_BYTES + 1)
        if len(raw) > _MAX_PARSE_BYTES:
            return set()
        tree = ast.parse(raw.decode("utf-8", errors="replace"), filename=str(path))
    # One unparsable file must not fail the whole workspace: deep nesting
    # raises MemoryError/RecursionError, a NUL byte ValueError on 3.11.
    except (SyntaxError, ValueError, MemoryError, RecursionError, OSError):
        return set()
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:  # absolute import only
                mods.add(node.module.split(".")[0])
    return mods


def _build(paths: list[Path]) -> tuple[dict[tuple[str, str], int], dict[str, Path]]:
    """Return (edges: (src_pkg,dst_pkg)->file_count, pkg->owning_root)."""
    pkg_root: dict[str, Path] = {}
    local_pkgs: set[str] = set()
    files_by_root: dict[Path, list[Path]] = {}
    for root in paths:
        files = _py_files(root)
        files_by_root[root] = files
        for f in files:
            pkg = _top_package(f, root)
            local_pkgs.add(pkg)
            pkg_root.setdefault(pkg, root)

    edges: dict[tuple[str, str], int] = {}
    for root, files in files_by_root.items():
        for f in files:
            src = _top_package(f, root)
            for imp in _imports(f):
                if imp in local_pkgs and imp != src:
                    edges[(src, imp)] = edges.get((src, imp), 0) + 1
    return edges, pkg_root


def _cycles(edges: dict[tuple[str, str], int]) -> list[list[str]]:
    """Tarjan SCCs with >1 node (or a self-loop) = import cycles."""
    adj: dict[str, list[str]] = {}
    for (s, d) in edges:
        adj.setdefault(s, []).append(d)
        adj.setdefault(d, [])
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []

    # Iterative Tarjan: the recursive form raised RecursionError on a long
    # import chain (the walk admits 2,000 files per root).
    for root in list(adj):
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            v, i = work.pop()
            if i == 0:
                index[v] = low[v] = len(index)
                stack.append(v)
                on_stack.add(v)
            succ = adj.get(v, [])
            if i > 0:
                low[v] = min(low[v], low[succ[i - 1]])
            while i < len(succ) and succ[i] in index:
                if succ[i] in on_stack:
                    low[v] = min(low[v], index[succ[i]])
                i += 1
            if i < len(succ):
                work.append((v, i + 1))
                work.append((succ[i], 0))
                continue
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1 or (v, v) in edges:
                    sccs.append(sorted(comp))
    return sccs


def _run_factory(sandbox: Any | None):
    def _run(args: dict[str, Any]) -> str:
        op = args.get("op")
        paths_arg = args.get("paths")
        raw_paths = [p for p in paths_arg if isinstance(p, str) and p.strip()] if isinstance(paths_arg, list) else []
        paths, err = _safe_roots(sandbox, raw_paths)
        if err:
            return f"ERROR: {err}"
        if not paths:
            return "ERROR: paths must include at least one existing directory in the workspace"

        edges, pkg_root = _build(paths)
        if op == "graph":
            if not edges:
                return "no inter-package import edges found"
            rows = []
            try:
                cap_raw = int(args.get("max_results") or _MAX_OUTPUT_ROWS)
            except (TypeError, ValueError):
                cap_raw = _MAX_OUTPUT_ROWS
            cap = max(1, min(cap_raw, _MAX_OUTPUT_ROWS))
            for (s, d), n in sorted(edges.items(), key=lambda kv: (-kv[1], kv[0]))[:cap]:
                cross = "  [cross-root]" if pkg_root.get(s) != pkg_root.get(d) else ""
                rows.append(f"{s} -> {d}  ({n} import{'s' if n != 1 else ''}){cross}")
            if len(edges) > cap:
                rows.append(f"... [truncated, {len(edges) - cap} more edges]")
            return "\n".join(rows)
        if op == "cycles":
            cyc = _cycles(edges)[:_MAX_OUTPUT_ROWS]
            if not cyc:
                return "no import cycles among packages"
            return "\n".join(" <-> ".join(c) for c in cyc)
        return f"ERROR: unknown op {op!r}"

    return _run


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["graph", "cycles"]},
        "paths": {
            "type": "array",
            "items": {"type": "string"},
            "description": "one or more repo/package root directories under the workspace to scan",
        },
        "max_results": {
            "type": "integer",
            "description": "maximum graph rows to return (default/cap 1000)",
        },
    },
    "required": ["op", "paths"],
}


def cross_repo_deps(sandbox: Any | None = None) -> Tool:
    return Tool(
        name="cross_repo_deps",
        description=(
            "Cross-repo Python dependency graph. ops: graph (top-level "
            "package -> package import edges with counts; flags edges that "
            "cross from one root into another), cycles (import cycles among "
            "packages). Parses with ast, never executes imports. Paths are "
            "resolved under the workspace."
        ),
        input_schema=_SCHEMA,
        fn=_run_factory(sandbox),
        parallel_safe=False,
    )
