"""Diagramming tool: render Graphviz DOT or Mermaid source to an image.

Writes the diagram source to a temp file and shells the renderer through the
sandbox chokepoint:
  - ``dot`` (Graphviz)  -> ``dot -T<fmt>``
  - ``mermaid`` (mmdc)  -> ``mmdc -i in.mmd -o out.<fmt>``

The renderer binaries are host/sandbox tools (not Python deps); when they're not
installed the sandbox command fails and the tool returns an actionable error.
``_argv`` (the command builder) is pure and unit-tested; engine + format are
validated against allowlists so model input can't inject flags.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from . import Tool, sandbox_run
from .ffmpeg_tool import _safe_path

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


def _argv(engine: str, infile: str, outfile: str, fmt: str) -> list[str]:
    """Build the renderer argv (engine + format already validated)."""
    if engine == "dot":
        return ["dot", f"-T{fmt}", infile, "-o", outfile]
    # mermaid
    return ["mmdc", "-i", infile, "-o", outfile]


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

    workdir = Path(tempfile.mkdtemp(prefix="mvk-diagram-"))
    ext = "dot" if engine == "dot" else "mmd"
    infile = workdir / f"in.{ext}"
    infile.write_text(source, encoding="utf-8")
    # Confine the model-supplied destination to the sandbox workspace: an
    # unconfined `out` is an arbitrary host-file write (e.g. ~/.ssh/authorized_keys).
    try:
        out = Path(_safe_path(sandbox, args.get("out") or f"diagram.{fmt}"))
    except ValueError as e:
        return f"ERROR: {e}"
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = workdir / f"out.{fmt}"

    code, stdout, stderr = sandbox_run(
        sandbox, _argv(engine, str(infile), str(tmp_out), fmt), timeout=60.0)
    if code != 0 or not tmp_out.exists():
        tail = (stderr or stdout or "").strip()[-400:]
        binary = "dot (graphviz)" if engine == "dot" else "mmdc (mermaid-cli)"
        return (f"ERROR: {engine} render failed (exit {code}); is {binary} "
                f"installed in the sandbox? {tail}")
    import shutil
    shutil.copyfile(tmp_out, out)
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
