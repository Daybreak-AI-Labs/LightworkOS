"""Syntax-safe structural editor for Python.

Refactors that don't break syntax: rename-symbol, add-import,
insert-after-symbol, remove-symbol. Each operation rejects edits that would
leave the file syntactically invalid. Note: ``add/insert/remove`` are AST-driven,
but ``rename-symbol`` is a whole-word *textual* substitution (``\\bname\\b``) —
it is NOT scope-aware, so it also rewrites matching identifiers in unrelated
scopes/strings/comments. Use it for unambiguous, file-local renames.

It supports Python only. The tool is opt-in (agent picks it for refactor-
style work); plain ``str_replace_editor`` is still the go-to for
small targeted patches.

Tree-sitter isn't required — we use Python's stdlib ``ast`` for
parsing and ``ast.unparse()`` (3.9+) for the round-trip. The tool
preserves the original formatting outside the changed region by
operating on lines + AST node offsets rather than fully re-emitting
from the AST.
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Any

from . import Tool
from .fs import read_text_contained, write_text_contained

log = logging.getLogger(__name__)


_AST_EDIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "File to edit (relative to sandbox workdir)."},
        "op": {
            "type": "string",
            "enum": ["rename_symbol", "add_import", "remove_symbol", "insert_after_symbol", "info"],
            "description": "Operation to perform.",
        },
        "old_name": {"type": "string", "description": "For rename_symbol."},
        "new_name": {"type": "string", "description": "For rename_symbol."},
        "import_line": {
            "type": "string",
            "description": "For add_import (e.g. 'from foo import bar'). Idempotent.",
        },
        "symbol": {"type": "string", "description": "For remove_symbol / insert_after_symbol."},
        "code": {"type": "string", "description": "For insert_after_symbol: code block to insert."},
        "dry_run": {
            "type": "boolean",
            "description": "Show the diff but don't write. Default false.",
        },
    },
    "required": ["path", "op"],
}


_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


def _read(sandbox, path: Path) -> str | None:
    # Read through a workspace-contained descriptor (TOCTOU-safe): a ValueError
    # means the resolved path escaped the workspace via a swapped symlink.
    try:
        return read_text_contained(sandbox, path)
    except (ValueError, OSError, UnicodeDecodeError):
        return None


def _parse(src: str) -> ast.Module | None:
    try:
        return ast.parse(src)
    except SyntaxError as e:
        log.warning("ast_edit: source has syntax error: %s", e)
        return None


def _validate(src: str) -> bool:
    """True if ``src`` is syntactically valid Python."""
    try:
        ast.parse(src)
        return True
    except SyntaxError:
        return False


def _info(src: str) -> str:
    """Summary of a file's top-level symbols + imports."""
    tree = _parse(src)
    if tree is None:
        return "ERROR: file does not parse as Python"
    lines: list[str] = []
    imports: list[str] = []
    symbols: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.append(f"import {a.name}" + (f" as {a.asname}" if a.asname else ""))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names = ", ".join(
                a.name + (f" as {a.asname}" if a.asname else "")
                for a in node.names
            )
            imports.append(f"from {'.' * node.level}{mod} import {names}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            symbols.append(f"{kind} {node.name}  (line {node.lineno})")
        elif isinstance(node, ast.ClassDef):
            symbols.append(f"class {node.name}  (line {node.lineno})")
    if imports:
        lines.append("imports:")
        lines.extend(f"  {i}" for i in imports)
        lines.append("")
    if symbols:
        lines.append("symbols:")
        lines.extend(f"  {s}" for s in symbols)
    return "\n".join(lines) or "(no top-level symbols)"


def _rename_symbol(src: str, old: str, new: str) -> str:
    """Whole-word rename across the source. Naive but valid for most cases."""
    if not old or not new:
        raise ValueError("rename_symbol requires old_name and new_name")
    if not _IDENT_RE.fullmatch(new):
        raise ValueError(f"new_name {new!r} is not a valid Python identifier")
    pattern = re.compile(rf"\b{re.escape(old)}\b")
    return pattern.sub(new, src)


def _add_import(src: str, import_line: str) -> str:
    """Insert ``import_line`` after the existing import block. Idempotent."""
    if not import_line.strip():
        raise ValueError("add_import requires non-empty import_line")
    # Idempotency check: line already there?
    for line in src.splitlines():
        if line.strip() == import_line.strip():
            return src
    tree = _parse(src)
    if tree is None:
        raise ValueError("file does not parse")
    # Find the last existing top-level import.
    last_import_line = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import_line = max(last_import_line, node.end_lineno or node.lineno)
    lines = src.splitlines(keepends=True)
    if last_import_line == 0:
        # No imports yet: prepend after any module docstring.
        if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
            insert_idx = (tree.body[0].end_lineno or 1)
        else:
            insert_idx = 0
    else:
        insert_idx = last_import_line
    insert_text = import_line.rstrip("\n") + "\n"
    head = "".join(lines[:insert_idx])
    if head and not head.endswith("\n"):
        head += "\n"  # the anchor line was the last line, with no newline
    return head + insert_text + "".join(lines[insert_idx:])


def _remove_symbol(src: str, symbol: str) -> str:
    """Remove a top-level def / class by name (and any preceding decorators)."""
    if not symbol:
        raise ValueError("remove_symbol requires symbol")
    tree = _parse(src)
    if tree is None:
        raise ValueError("file does not parse")
    target = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
            target = node
            break
    if target is None:
        raise ValueError(f"top-level symbol {symbol!r} not found")
    start = (target.decorator_list[0].lineno if target.decorator_list else target.lineno) - 1
    end = (target.end_lineno or target.lineno)
    lines = src.splitlines(keepends=True)
    return "".join(lines[:start] + lines[end:])


def _insert_after_symbol(src: str, symbol: str, code: str) -> str:
    """Insert ``code`` immediately after the named top-level symbol."""
    if not symbol or not code:
        raise ValueError("insert_after_symbol requires symbol and code")
    tree = _parse(src)
    if tree is None:
        raise ValueError("file does not parse")
    target = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
            target = node
            break
    if target is None:
        raise ValueError(f"top-level symbol {symbol!r} not found")
    end = (target.end_lineno or target.lineno)
    lines = src.splitlines(keepends=True)
    block = code.rstrip("\n") + "\n"
    return "".join(lines[:end]) + "\n" + block + "".join(lines[end:])


_OPS = {
    "rename_symbol":       _rename_symbol,
    "add_import":          _add_import,
    "remove_symbol":       _remove_symbol,
    "insert_after_symbol": _insert_after_symbol,
}


def _resolve_workdir_path(sandbox, rel: str) -> Path:
    """Resolve a sandbox-relative path with traversal guard."""
    base = Path(getattr(sandbox, "workdir", ".")).resolve()
    target = (base / rel).resolve()
    # Refuse paths that escape the workdir.
    try:
        target.relative_to(base)
    except ValueError as e:
        raise ValueError(f"refusing path traversal: {rel!r}") from e
    return target


def _make_run(sandbox):
    def _run(args: dict[str, Any]) -> str:
        op = args.get("op")
        path_arg = str(args.get("path") or "")
        if not op:
            return "ERROR: op is required"
        if not path_arg:
            return "ERROR: path is required"
        try:
            target = _resolve_workdir_path(sandbox, path_arg)
        except ValueError as e:
            return f"ERROR: {e}"
        src = _read(sandbox, target)
        if src is None:
            return f"ERROR: cannot read {path_arg}"
        if op == "info":
            return _info(src)
        fn = _OPS.get(op)
        if fn is None:
            return f"ERROR: unknown op {op!r}"
        try:
            new_src = fn(
                src,
                **{k: v for k, v in {
                    "old": args.get("old_name"),
                    "new": args.get("new_name"),
                    "import_line": args.get("import_line"),
                    "symbol": args.get("symbol"),
                    "code": args.get("code"),
                }.items() if v is not None and k in _fn_kwargs(fn)},
            )
        except (TypeError, ValueError) as e:
            return f"ERROR: {e}"
        if not _validate(new_src):
            return "ERROR: edit would produce invalid Python; rejected."
        if args.get("dry_run"):
            return (
                f"DRY RUN -- would write {len(new_src)} bytes to "
                f"{path_arg} (was {len(src)} bytes; delta {len(new_src) - len(src):+d})"
            )
        try:
            write_text_contained(sandbox, target, new_src)
        except (ValueError, OSError) as e:
            return f"ERROR: write failed: {e}"
        return (
            f"wrote {path_arg}: {len(new_src)} bytes "
            f"(was {len(src)}, delta {len(new_src) - len(src):+d})"
        )
    return _run


def _fn_kwargs(fn) -> set[str]:
    """Return the kwarg names ``fn`` accepts. Used to filter the
    universal args dict down to what each op wants."""
    import inspect
    return set(inspect.signature(fn).parameters.keys()) - {"src"}


def ast_edit(sandbox) -> Tool:
    """Factory: builds the ast_edit tool bound to ``sandbox.workdir``."""
    return Tool(
        name="ast_edit",
        description=(
            "Structural Python edits that won't break syntax. ops: "
            "rename_symbol (whole-word rename), add_import (idempotent), "
            "remove_symbol (drop a top-level def/class + its decorators), "
            "insert_after_symbol (add code right after a named function/"
            "class), info (summary of top-level symbols + imports). "
            "Edits that would leave invalid Python are rejected. Use "
            "dry_run=true to preview without writing."
        ),
        input_schema=_AST_EDIT_SCHEMA,
        fn=_make_run(sandbox),
    )
