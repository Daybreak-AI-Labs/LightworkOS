"""Semantic-ish code search tool.

Indexes the functions and classes under one or more paths (via ``ast``, no
import execution) and ranks them against a natural-language query using a
zero-dependency lexical scorer over each symbol's name, signature, and
docstring. "Semantic-ish": it understands code *structure* (it searches
symbols, not raw lines) and tolerates word-order/identifier-style differences
(snake/camel are split into words), without needing an embedding model. When a
vector store is wired in elsewhere it can be swapped for true embeddings; this
is the always-available default, mirroring the long-context router's design.

ops:
  - search(paths, query[, k])  — top-k matching symbols as ``file:line  qualname``.

Read-only, ``parallel_safe``.
"""
from __future__ import annotations

import ast
import os
import re
import stat
from pathlib import Path
from typing import Any

from . import Tool

_SKIP = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", "build", "dist"}
_WORD = re.compile(r"[a-z0-9]+")
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES = 2_000
_MAX_DIRS = 5_000


def _words(text: str) -> list[str]:
    # Split identifiers: snake_case and camelCase both become word lists.
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text or "")
    return _WORD.findall(spaced.lower())


def _workspace_root(sandbox: Any = None) -> Path | None:
    workdir = getattr(sandbox, "workdir", None)
    if workdir is None:
        return None
    return Path(workdir).resolve()


def _resolve_path(raw: str, sandbox: Any = None) -> Path:
    root = _workspace_root(sandbox)
    candidate = Path(raw).expanduser()
    if root is not None:
        candidate = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as e:
            raise ValueError(f"path {raw!r} escapes the workspace") from e
    else:
        candidate = candidate.resolve()
    return candidate


def _is_regular_python_file(path: Path) -> bool:
    if path.suffix != ".py":
        return False
    try:
        st = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_size <= _MAX_FILE_BYTES


def _py_files(root: Path) -> list[Path]:
    out: list[Path] = []
    dirs_seen = 0
    for dp, dns, fns in os.walk(root, followlinks=False):
        dirs_seen += 1
        if dirs_seen > _MAX_DIRS:
            break
        dns[:] = [d for d in dns if d not in _SKIP]
        for f in fns:
            path = Path(dp) / f
            if _is_regular_python_file(path):
                out.append(path)
                if len(out) >= _MAX_FILES:
                    return out
    return out


def _signature(node: ast.AST) -> str:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ", ".join(a.arg for a in node.args.args)
    return ""


def _symbols(path: Path) -> list[tuple[str, int, str]]:
    """(qualname, lineno, indexed_text) for each top-level/nested def/class."""
    if not _is_regular_python_file(path):
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, OSError, ValueError, RecursionError, MemoryError):
        # One unparseable file (too deeply nested, a NUL byte) must not abort
        # the whole search.
        return []
    out: list[tuple[str, int, str]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{prefix}{child.name}"
                doc = ast.get_docstring(child) or ""
                text = " ".join([child.name, _signature(child), doc])
                out.append((qual, child.lineno, text))
                visit(child, qual + ".")

    visit(tree, "")
    return out


def _score(query_words: list[str], text_words: list[str]) -> float:
    if not query_words or not text_words:
        return 0.0
    tset = set(text_words)
    hits = sum(1 for q in query_words if q in tset)
    return hits / len(query_words)


def _collect_files(paths: list[str], sandbox: Any = None) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    errors: list[str] = []
    for raw in paths:
        try:
            path = _resolve_path(raw, sandbox)
        except ValueError as e:
            errors.append(str(e))
            continue
        if path.is_dir():
            for file_path in _py_files(path):
                files.append(file_path)
                if len(files) >= _MAX_FILES:
                    return files, errors
        elif _is_regular_python_file(path):
            files.append(path)
            if len(files) >= _MAX_FILES:
                return files, errors
        elif path.exists():
            errors.append(f"path {raw!r} is not a regular .py file or directory")
    return files, errors


def _run(args: dict[str, Any], sandbox: Any = None) -> str:
    if args.get("op") not in (None, "search"):
        return f"ERROR: unknown op {args.get('op')!r}"
    query = str(args.get("query") or "").strip()
    if not query:
        return "ERROR: query is required"
    raw_paths = [p for p in (args.get("paths") or []) if isinstance(p, str)]
    files, errors = _collect_files(raw_paths, sandbox)
    if not files:
        detail = f": {'; '.join(errors[:3])}" if errors else ""
        return f"ERROR: paths must include at least one workspace-confined regular .py file or directory{detail}"
    try:
        k = int(args.get("k", 10))
    except (TypeError, ValueError):
        k = 10
    k = max(1, min(k, 50))

    qwords = _words(query)
    scored: list[tuple[float, str, int, str]] = []
    for f in files:
        for qual, line, text in _symbols(f):
            s = _score(qwords, _words(text))
            if s > 0:
                scored.append((s, str(f), line, qual))

    if not scored:
        return f"no symbols matched {query!r}"
    scored.sort(key=lambda t: (-t[0], t[1], t[2]))
    rows = [f"{s:.2f}  {f}:{line}  {qual}" for s, f, line, qual in scored[:k]]
    return "\n".join(rows)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["search"]},
        "paths": {"type": "array", "items": {"type": "string"},
                  "description": "workspace-confined Python files/dirs to index"},
        "query": {"type": "string", "description": "natural-language description of the code"},
        "k": {"type": "integer", "description": "max results (default 10)"},
    },
    "required": ["query", "paths"],
}


def semantic_code_search(sandbox: Any = None) -> Tool:
    return Tool(
        name="semantic_code_search",
        description=(
            "Search code by intent, not regex. Indexes functions/classes under "
            "the given workspace-confined Python paths (ast; no execution) and "
            "ranks them against a natural-language query over each symbol's "
            "name, signature, and docstring, splitting snake_case/camelCase "
            "into words. Returns top-k 'score  file:line  qualname'. "
            "Zero-dependency lexical default (swap in embeddings via a vector "
            "store elsewhere)."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
        parallel_safe=True,
    )
