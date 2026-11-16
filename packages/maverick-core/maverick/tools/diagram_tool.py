"""Diagramming tool: render Graphviz DOT or Mermaid source to an image.

Feeds the diagram source to the renderer on standard input, through the
sandbox chokepoint, and has it write a workspace-relative file itself:
  - ``dot`` (Graphviz)  -> ``dot -T<fmt> -o ./.out.<random>.<fmt>``
  - ``mermaid`` (mmdc)  -> ``mmdc -i - -o ./.out.<random>.<fmt>``

Nothing is staged on the host: a container backend mounts the workspace at its
own root and cannot see a host temp folder or a host path into the workspace.
The renderer writes a temporary name beside the output, which is moved into
place only when the render succeeds: a failed render leaves an existing
output as it was, and mmdc (which requires a name ending in the format) can
produce an output of any name.

The renderer binaries are host/sandbox tools (not Python deps); when they're not
installed the sandbox command fails and the tool returns an actionable error.
``_argv`` (the command builder) is pure and unit-tested; engine + format are
validated against allowlists so model input can't inject flags.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from . import Tool, sandbox_run
from .ffmpeg_tool import _safe_output_path

_ENGINES = ("dot", "mermaid")
_FORMATS = ("svg", "png", "pdf")

_SCHEMA = {
    "type": "object",
    "properties": {
        "engine": {"type": "string", "enum": list(_ENGINES)},
        "source": {"type": "string", "description": "DOT or Mermaid diagram source"},
        "format": {"type": "string", "enum": list(_FORMATS), "default": "svg"},
        "out": {"type": "string", "description": "output path (default ./diagram.<fmt>)"},
    },
    "required": ["engine", "source"],
}


def _argv(engine: str, outfile: str, fmt: str) -> list[str]:
    """Build the renderer argv (engine + format already validated).

    The source is read from standard input."""
    if engine == "dot":
        return ["dot", f"-T{fmt}", "-o", outfile]
    # mermaid: the format follows the output name's ending.
    return ["mmdc", "-i", "-", "-o", outfile]


def _run(args: dict[str, Any], sandbox) -> str:
    engine = str(args.get("engine") or "").strip().lower()
    if engine not in _ENGINES:
        return f"ERROR: engine must be one of {_ENGINES}"
    source = str(args.get("source") or "")
    if not source.strip():
        return "ERROR: diagram source is required"
    fmt = str(args.get("format") or "svg").strip().lower()
    if fmt not in _FORMATS:
        return f"ERROR: format must be one of {_FORMATS}"

    # Confine the model-supplied destination to the sandbox workspace: an
    # unconfined `out` is an arbitrary host-file write (e.g. ~/.ssh/authorized_keys).
    try:
        out = Path(_safe_output_path(sandbox, args.get("out") or f"diagram.{fmt}"))
    except ValueError as e:
        return f"ERROR: {e}"
    return _render(sandbox, engine, source, fmt, out)


def _move_into_place(staged: Path, out: Path) -> None:
    """Rename ``staged`` to ``out``. Both are names in one folder, so where the
    platform allows it the rename is done against that folder, not by path."""
    if os.rename in os.supports_dir_fd:
        folder = os.open(out.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.replace(staged.name, out.name, src_dir_fd=folder, dst_dir_fd=folder)
        finally:
            os.close(folder)
    else:
        os.replace(staged, out)


def _render(sandbox, engine: str, source: str, fmt: str, out: Path) -> str:
    out.parent.mkdir(parents=True, exist_ok=True)
    staged = out.with_name(f".{out.stem[:40]}.{secrets.token_hex(4)}.{fmt}")
    # Sandbox backends mount the workspace at their own root, not its host path.
    # Prefix the relative name so one beginning with '-' is not an option.
    relative = "./" + staged.relative_to(Path(sandbox.workdir).resolve()).as_posix()
    try:
        code, stdout, stderr = sandbox_run(
            sandbox, _argv(engine, relative, fmt), timeout=60.0, stdin=source)
        if code != 0 or not staged.is_file():
            tail = (stderr or stdout or "").strip()[-400:]
            binary = "dot (graphviz)" if engine == "dot" else "mmdc (mermaid-cli)"
            return (f"ERROR: {engine} render failed (exit {code}); is {binary} "
                    f"installed in the sandbox? {tail}")
        try:
            _move_into_place(staged, out)
        except OSError as e:
            return f"ERROR: could not save the rendered diagram: {e}"
        return f"rendered {engine} diagram -> {out}"
    finally:
        # Never leave a half-written render behind.
        staged.unlink(missing_ok=True)


def diagram_tool(sandbox) -> Tool:
    return Tool(
        name="diagram",
        description=(
            "Render a diagram from source. engine: dot (Graphviz) or mermaid "
            "(mmdc); format: svg/png/pdf. Input: engine, source, format, out. "
            "Renders through the sandbox; needs the renderer binary installed."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )


__all__ = ["diagram_tool", "_argv"]
