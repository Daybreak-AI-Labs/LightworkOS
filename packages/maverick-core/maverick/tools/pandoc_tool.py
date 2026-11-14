"""Pandoc tool — document format conversion.

Auth: none. Requires the ``pandoc`` binary on PATH.

ops:
  - convert(input_path, output_path, from_, to, args)
  - formats()                                    — input/output formats list
  - markdown_to_html(text)                       — string in/out
  - html_to_markdown(text)
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)

_READERS = frozenset({"markdown", "markdown_strict", "commonmark", "commonmark_x", "gfm", "html", "docx", "rst", "latex"})
_WRITERS = frozenset({"markdown", "commonmark", "commonmark_x", "gfm", "html", "html5", "plain", "docx", "rst", "latex"})
_EXTENSIONS = {".md": "markdown", ".markdown": "markdown", ".html": "html", ".htm": "html",
               ".docx": "docx", ".rst": "rst", ".tex": "latex", ".txt": "plain"}
_SAFE_ARGS = frozenset({"--standalone", "--toc", "--number-sections", "--wrap=none", "--wrap=auto", "--wrap=preserve"})


_PANDOC_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["convert", "formats", "markdown_to_html",
                     "html_to_markdown"],
        },
        "input_path": {"type": "string"},
        "output_path": {"type": "string"},
        "from_": {"type": "string"},
        "to": {"type": "string"},
        "text": {"type": "string"},
        "args": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["op"],
}


def _need_pandoc() -> str | None:
    if shutil.which("pandoc"):
        return None
    return "ERROR: pandoc not on PATH. Install pandoc."


def _safe_path(sandbox, user_path: str) -> str:
    if user_path.startswith("-"):
        raise ValueError("paths may not begin with '-'")
    if sandbox is None:
        raise ValueError("document conversion requires a workspace")
    workdir = Path(sandbox.workdir).resolve()
    candidate = (workdir / user_path).resolve()
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        raise ValueError(f"path {user_path!r} escapes the workspace") from e
    return str(candidate)


def _op_convert(args: dict, sandbox) -> str:
    err = _need_pandoc()
    if err:
        return err
    src = (args.get("input_path") or "").strip()
    dst = (args.get("output_path") or "").strip()
    if not src or not dst:
        return "ERROR: convert requires input_path and output_path"
    output_parts = dst.replace("\\", "/").split("/")
    try:
        src = _safe_path(sandbox, src)
        dst = _safe_path(sandbox, dst)
    except ValueError as e:
        return f"ERROR: {e}"
    if any(part.rstrip(" .").casefold() == ".git" for part in (*output_parts, *Path(dst).parts)):
        return "ERROR: refusing to write under .git/"
    # Output names can cause Pandoc to start an external PDF engine even when
    # a different writer is specified. PDF conversion needs a separately
    # isolated worker because TeX can read files referenced by the document.
    if Path(dst).name.rstrip(" .").lower().endswith(".pdf"):
        return "ERROR: PDF conversion requires an isolated document worker"
    source_suffix = Path(src).suffix.lower()
    reader = args.get("from_") or ("markdown" if source_suffix == ".txt" else _EXTENSIONS.get(source_suffix))
    writer = args.get("to") or _EXTENSIONS.get(Path(dst).suffix.lower())
    if not isinstance(reader, str) or reader not in _READERS:
        return "ERROR: unsupported input format; choose a built-in document reader"
    if not isinstance(writer, str) or writer not in _WRITERS:
        return "ERROR: unsupported output format; choose a built-in document writer"
    extra = args.get("args")
    if extra is None:
        extra = []
    if (not isinstance(extra, list) or len(extra) > 16
            or any(not isinstance(item, str) or item not in _SAFE_ARGS for item in extra)):
        return "ERROR: unsupported Pandoc options"
    if writer == "docx":
        return _convert_to_docx(sandbox, src, dst, reader, extra)
    from . import sandbox_run
    # --sandbox stops readers from pulling in other files (rst ``include``,
    # LaTeX ``\input``) and writers from fetching remote resources.
    cmd = ["pandoc", "--sandbox", src, "-o", dst, "-f", reader, "-t", writer, *extra]
    code, _out, stderr = sandbox_run(sandbox, cmd, timeout=120)
    if code != 0:
        return f"ERROR: pandoc ({code}): {stderr.strip()[-300:]}"
    return f"wrote {dst}"


def _is_workspace_image(target: str, bases: tuple[Path, ...], workdir: Path) -> bool:
    normalized = target.replace("\\", "/")
    if ":" in normalized or normalized.startswith("/"):
        return False
    for base in bases:
        try:
            (base / normalized).resolve().relative_to(workdir)
        except ValueError:
            return False
    return True


def _unsafe_image_target(node: Any, bases: tuple[Path, ...], workdir: Path) -> str | None:
    """Return the first image target that is not a relative path inside the workspace."""
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            if item.get("t") == "Image":
                content = item.get("c")
                target = content[2][0] if isinstance(content, list) and len(content) == 3 else None
                if not isinstance(target, str):
                    return "<malformed image>"
                if not _is_workspace_image(target, bases, workdir):
                    return target
            stack.extend(item.values())
    return None


def _convert_to_docx(sandbox, src: str, dst: str, reader: str, extra: list) -> str:
    """Convert to docx without letting the document read or fetch other resources.

    Distribution builds of pandoc read the docx template from data files,
    which ``--sandbox`` forbids, so the docx writer cannot run sandboxed. The
    document is parsed under ``--sandbox`` into pandoc's JSON AST instead;
    images that are not relative workspace paths are refused, and only then
    is the AST written out as docx.
    """
    import json
    import secrets

    from . import sandbox_run
    staging = str(Path(dst).with_name(f".{Path(dst).name}.{secrets.token_hex(16)}.pandoc.json"))
    try:
        code, _out, stderr = sandbox_run(
            sandbox, ["pandoc", "--sandbox", src, "-o", staging, "-f", reader, "-t", "json"], timeout=120,
        )
        if code != 0:
            return f"ERROR: pandoc ({code}): {stderr.strip()[-300:]}"
        try:
            ast = json.loads(Path(staging).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return f"ERROR: pandoc produced no readable document: {type(e).__name__}"
        workdir = Path(sandbox.workdir).resolve()
        bad = _unsafe_image_target(ast, (workdir, Path(src).parent), workdir)
        if bad is not None:
            return f"ERROR: docx output only embeds images by relative workspace path; refused {bad[:200]!r}"
        cmd = ["pandoc", staging, "-o", dst, "-f", "json", "-t", "docx", *extra]
        code, _out, stderr = sandbox_run(sandbox, cmd, timeout=120)
        if code != 0:
            return f"ERROR: pandoc ({code}): {stderr.strip()[-300:]}"
        return f"wrote {dst}"
    finally:
        Path(staging).unlink(missing_ok=True)


def _op_formats(_args: dict, _sandbox) -> str:
    err = _need_pandoc()
    if err:
        return err
    return (
        "supported input formats:\n" + "\n".join(sorted(_READERS)) +
        "\n\nsupported output formats:\n" + "\n".join(sorted(_WRITERS))
    )


def _string_convert(text: str, from_: str, to: str, sandbox) -> str:
    err = _need_pandoc()
    if err:
        return err
    if not text.strip():
        return "ERROR: text is required"
    from . import sandbox_run
    code, out, stderr = sandbox_run(
        sandbox, ["pandoc", "--sandbox", "-f", from_, "-t", to], timeout=60, stdin=text,
    )
    if code != 0:
        return f"ERROR: pandoc ({code}): {stderr.strip()[-300:]}"
    return out


def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        if op == "convert":
            return _op_convert(args, sandbox)
        if op == "formats":
            return _op_formats(args, sandbox)
        if op == "markdown_to_html":
            return _string_convert(args.get("text") or "", "markdown", "html", sandbox)
        if op == "html_to_markdown":
            return _string_convert(args.get("text") or "", "html", "markdown", sandbox)
    except Exception as e:
        return f"ERROR: pandoc failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def pandoc_tool(sandbox=None) -> Tool:
    return Tool(
        name="pandoc",
        description=(
            "Pandoc document conversion. ops: convert (file in/out + "
            "optional from/to/args), formats (list), markdown_to_html "
            "(string), html_to_markdown (string). File conversion accepts "
            "supported built-in formats and basic options; PDF requires an "
            "isolated document worker. Requires pandoc on PATH."
        ),
        input_schema=_PANDOC_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
