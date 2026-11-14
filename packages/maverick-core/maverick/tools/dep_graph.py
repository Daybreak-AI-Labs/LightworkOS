"""Dependency-graph repo map.

Complements ``repo_map`` (which gives a directory listing) with two
graphs the agent can query:

  - **import_graph**: who imports who (file-level)
  - **symbol_index**: where each function/class is defined (``ast.walk``
    collects methods and nested definitions too, not only top-level ones)

Both are cheap to build on demand from the workspace and dense enough
to fit in 4-8k tokens for repos up to ~100 files.

Currently supports Python. JS/TS/Go/Rust planned (use tree-sitter
queries) but the Python coverage on its own pays for itself on
SWE-bench-class tasks.
"""
from __future__ import annotations

import ast
import logging
import os
import re
import stat
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_DEP_GRAPH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "view": {
            "type": "string",
            "enum": ["import_graph", "symbol_index", "callers", "callees", "summary"],
            "description": "Which view to return.",
        },
        "symbol": {
            "type": "string",
            "description": "For 'callers'/'callees': the function/class name.",
        },
        "module": {
            "type": "string",
            "description": "Filter by python module/file path (e.g. 'src/auth').",
        },
        "max_results": {
            "type": "integer",
            "description": "Cap on returned items (default 200).",
        },
    },
    "required": ["view"],
}


_SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "venv", "__pycache__", ".pytest_cache",
    "node_modules", "dist", "build", ".tox", ".mypy_cache", ".ruff_cache",
    "site-packages",
})

_PY_RE = re.compile(r"\.py$")
_MAX_PARSE_BYTES = 1_000_000


def _walk_py_files(root: Path, *, max_files: int = 2000) -> list[Path]:
    out: list[Path] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for f in files:
            if _PY_RE.search(f):
                out.append(Path(base) / f)
                if len(out) >= max_files:
                    return out
    return out


def _parse_module(path: Path, root: Path) -> dict[str, Any] | None:
    """Return {'rel', 'imports', 'symbols', 'calls'} or None on failure."""
    try:
        st = path.stat(follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    if st.st_size > _MAX_PARSE_BYTES:
        return None

    try:
        with path.open("rb") as fh:
            raw = fh.read(_MAX_PARSE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_PARSE_BYTES:
        return None
    src = raw.decode("utf-8", errors="replace")
    try:
        tree = ast.parse(src, filename=str(path))
    # One unparsable file must not fail the whole index: deep nesting raises
    # MemoryError/RecursionError, a NUL byte ValueError on 3.11.
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None
    # as_posix() so the dep-graph emits forward-slash paths on every platform
    # (the output feeds the LLM, which expects POSIX-style paths, and matches
    # the repo's own import style) -- str() yields backslashes on Windows.
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()

    imports: list[str] = []
    symbols: list[tuple[str, str, int]] = []  # (kind, name, lineno)
    calls: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            # Relative imports keep '.' prefix so callers can
            # disambiguate from absolute imports.
            if node.level:
                mod = ("." * node.level) + mod
            for alias in node.names:
                imports.append(f"{mod}::{alias.name}" if mod else alias.name)
        elif isinstance(node, ast.FunctionDef):
            symbols.append(("def", node.name, node.lineno))
        elif isinstance(node, ast.AsyncFunctionDef):
            symbols.append(("async def", node.name, node.lineno))
        elif isinstance(node, ast.ClassDef):
            symbols.append(("class", node.name, node.lineno))
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                calls.add(f.id)
            elif isinstance(f, ast.Attribute):
                calls.add(f.attr)
    return {
        "rel": rel,
        "imports": imports,
        "symbols": symbols,
        "calls": sorted(calls),
    }


def _build_workspace_index(root: Path) -> dict[str, Any]:
    modules: dict[str, dict[str, Any]] = {}
    for path in _walk_py_files(root):
        parsed = _parse_module(path, root)
        if parsed is None:
            continue
        modules[parsed["rel"]] = parsed
    return modules


def _format_summary(modules: dict[str, dict[str, Any]]) -> str:
    if not modules:
        return "no python files found"
    total = len(modules)
    total_symbols = sum(len(m["symbols"]) for m in modules.values())
    total_imports = sum(len(m["imports"]) for m in modules.values())
    lines = [
        f"python files: {total}",
        f"top-level symbols: {total_symbols}",
        f"import statements: {total_imports}",
        "",
        "## top 10 modules by symbol count",
    ]
    ranked = sorted(modules.items(), key=lambda kv: -len(kv[1]["symbols"]))[:10]
    for rel, m in ranked:
        lines.append(f"  {len(m['symbols']):3d}  {rel}")
    return "\n".join(lines)


def _format_import_graph(modules: dict[str, dict[str, Any]], module_filter: str | None, cap: int) -> str:
    rows: list[str] = []
    for rel, m in modules.items():
        if module_filter and module_filter not in rel:
            continue
        for imp in m["imports"]:
            rows.append(f"{rel}  ->  {imp}")
        if len(rows) >= cap:
            break
    if not rows:
        return "no imports matched"
    return "\n".join(rows[:cap])


def _format_symbol_index(modules: dict[str, dict[str, Any]], module_filter: str | None, cap: int) -> str:
    rows: list[str] = []
    for rel, m in modules.items():
        if module_filter and module_filter not in rel:
            continue
        for kind, name, lineno in m["symbols"]:
            rows.append(f"{rel}:{lineno}  {kind} {name}")
        if len(rows) >= cap:
            break
    if not rows:
        return "no symbols matched"
    return "\n".join(rows[:cap])


def _find_callers(modules: dict[str, dict[str, Any]], symbol: str, cap: int) -> str:
    """Files that call ``symbol``. Cheap heuristic: ast.Call node names."""
    rows: list[str] = []
    for rel, m in modules.items():
        if symbol in m["calls"]:
            rows.append(rel)
        if len(rows) >= cap:
            break
    if not rows:
        return f"no callers found for {symbol!r}"
    return "callers of " + symbol + ":\n  " + "\n  ".join(rows)


def _find_callees(modules: dict[str, dict[str, Any]], symbol: str, cap: int) -> str:
    """All call-targets observed inside files that define ``symbol``."""
    rows: list[str] = []
    for rel, m in modules.items():
        defines = any(name == symbol for _, name, _ in m["symbols"])
        if defines:
            for callee in m["calls"]:
                rows.append(f"{rel}  ->  {callee}")
                if len(rows) >= cap:
                    return "\n".join(rows[:cap])
    if not rows:
        return f"no file defines {symbol!r}"
    return "\n".join(rows)


_VIEWS = frozenset({"summary", "import_graph", "symbol_index", "callers", "callees"})


def _run_dep_graph_factory(sandbox):
    def _run(args: dict[str, Any]) -> str:
        view = args.get("view")
        if not view:
            return "ERROR: view is required"
        if view not in _VIEWS:
            # Refuse before indexing the workspace, not after: the walk is the
            # expensive part and an unknown view can never use it.
            return f"ERROR: unknown view {view!r}"
        module_filter = args.get("module")
        symbol = args.get("symbol")
        cap = max(1, min(int(args.get("max_results") or 200), 1000))
        workdir = Path(getattr(sandbox, "workdir", ".")).resolve()
        if not workdir.exists() or not workdir.is_dir():
            return f"ERROR: workdir {workdir} not found"
        modules = _build_workspace_index(workdir)
        if view == "summary":
            return _format_summary(modules)
        if view == "import_graph":
            return _format_import_graph(modules, module_filter, cap)
        if view == "symbol_index":
            return _format_symbol_index(modules, module_filter, cap)
        if view == "callers":
            if not symbol:
                return "ERROR: 'callers' view requires symbol"
            return _find_callers(modules, symbol, cap)
        if view == "callees":
            if not symbol:
                return "ERROR: 'callees' view requires symbol"
            return _find_callees(modules, symbol, cap)
        return f"ERROR: unknown view {view!r}"
    return _run


def dep_graph(sandbox) -> Tool:
    """Factory: builds the dep_graph tool bound to ``sandbox.workdir``."""
    return Tool(
        name="dep_graph",
        description=(
            "Static dependency / symbol graph over the workspace's Python "
            "files. Views: summary (overview), import_graph (who imports "
            "who), symbol_index (where each symbol lives), callers (which "
            "files call SYMBOL), callees (what SYMBOL's file calls). Use "
            "before refactoring -- shows the blast radius of a rename."
        ),
        input_schema=_DEP_GRAPH_SCHEMA,
        fn=_run_dep_graph_factory(sandbox),
        parallel_safe=True,
    )
