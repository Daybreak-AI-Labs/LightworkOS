"""Diagramming tool: render Graphviz DOT or Mermaid source to an image.

Feeds the diagram source to the renderer on standard input, through the
sandbox chokepoint, and has it write the workspace-relative output itself:
  - ``dot`` (Graphviz)  -> ``dot -T<fmt> -o ./out``
  - ``mermaid`` (mmdc)  -> ``mmdc -i - -o ./out``

Nothing is staged on the host: a container backend mounts the workspace at its
own root and cannot see a host temp folder or a host path into the workspace.

The renderer binaries are host/sandbox tools (not Python deps); when they're not
installed the sandbox command fails and the tool returns an actionable error.
``_argv`` (the command builder) is pure and unit-tested; engine + format are
validated against allowlists so model input can't inject flags.
"""
from __future__ import annotations

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
    # mermaid: the format follows the output name unless it is given.
    argv = ["mmdc", "-i", "-", "-o", outfile]
    if not outfile.lower().endswith(f".{fmt}"):
        argv += ["-e", fmt]
    return argv


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
    if engine == "mermaid" and out.suffix.lower().lstrip(".") not in _FORMATS:
        # mmdc refuses any other ending, whatever format is asked for.
        return "ERROR: a mermaid diagram's output name must end with .svg, .png or .pdf"
    return _render(sandbox, engine, source, fmt, out)


def _render(sandbox, engine: str, source: str, fmt: str, out: Path) -> str:
    out.parent.mkdir(parents=True, exist_ok=True)
    # Sandbox backends mount the workspace at their own root, not its host path.
    # Prefix the relative name so one beginning with '-' is not an option.
    relative = "./" + out.relative_to(Path(sandbox.workdir).resolve()).as_posix()
    code, stdout, stderr = sandbox_run(
        sandbox, _argv(engine, relative, fmt), timeout=60.0, stdin=source)
    if code != 0 or not out.exists():
        tail = (stderr or stdout or "").strip()[-400:]
        binary = "dot (graphviz)" if engine == "dot" else "mmdc (mermaid-cli)"
        return (f"ERROR: {engine} render failed (exit {code}); is {binary} "
                f"installed in the sandbox? {tail}")
    return f"rendered {engine} diagram -> {out}"


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
