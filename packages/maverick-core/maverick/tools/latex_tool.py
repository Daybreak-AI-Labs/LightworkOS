"""LaTeX tool: render math to MathML and full documents to PDF.

Two ops:
  - ``mathml``: convert a LaTeX math expression to MathML via the pure-Python
    ``latex2mathml`` package (optional dep) — no TeX install needed.
  - ``render``: compile a full LaTeX document to PDF by shelling a TeX engine
    (``tectonic`` or ``pdflatex``) through the sandbox chokepoint.

Both degrade with an actionable error when their dependency is missing, per the
optional-dependency knob exemption. ``mathml`` needs ``pip install
maverick-agent[latex]``; ``render`` needs a TeX engine on PATH in the sandbox.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from . import Tool

_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["mathml", "render"], "default": "mathml"},
        "latex": {"type": "string", "description": "LaTeX source (math for mathml, full doc for render)"},
        "engine": {"type": "string", "enum": ["tectonic", "pdflatex"],
                   "description": "TeX engine for render (default tectonic)"},
        "out": {"type": "string", "description": "output PDF path (render op)"},
    },
    "required": ["latex"],
}


def to_mathml(latex: str) -> str:
    """Convert a LaTeX math expression to a MathML string."""
    try:
        from latex2mathml import converter
    except ImportError as e:
        raise RuntimeError(
            "mathml needs the 'latex2mathml' package. Install it with: "
            "python -m pip install -e './packages/maverick-core[latex]'") from e
    try:
        mathml = converter.convert(latex)
        # The converter accepts an incomplete \frac{...} and emits a one-child
        # mfrac, which is invalid MathML and silently loses the denominator.
        root = ET.fromstring(mathml)
        for fraction in root.iter("{http://www.w3.org/1998/Math/MathML}mfrac"):
            if len(fraction) != 2:
                raise ValueError("fraction requires a numerator and denominator")
        return mathml
    except Exception as e:  # noqa: BLE001 -- converter-specific parse errors
        raise RuntimeError(f"invalid LaTeX expression: {type(e).__name__}: {e}") from e


def _render_pdf(latex: str, sandbox, engine: str, out: str) -> str:
    from .document_processing import run_document_job, workspace_path

    eng = engine if engine in ("tectonic", "pdflatex") else "tectonic"
    destination = out or "doc.pdf"
    workspace_path(sandbox, destination)
    result = run_document_job({"operation": "latex", "engine": eng},
                              latex.encode("utf-8"), sandbox, destination=destination)
    return result.replace("wrote ", "rendered PDF -> ", 1)



def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op") or "mathml"
    latex = args.get("latex")
    if not isinstance(latex, str):
        return "ERROR: latex source must be a string"
    if not latex.strip():
        return "ERROR: latex source is required"
    try:
        if op == "mathml":
            return to_mathml(latex)
        if op == "render":
            return _render_pdf(latex, sandbox, args.get("engine") or "tectonic",
                               args.get("out") or "")
    except (RuntimeError, ValueError, OSError) as e:
        return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def latex_tool(sandbox) -> Tool:
    return Tool(
        name="latex",
        description=(
            "Render LaTeX. ops: mathml (math expr -> MathML, pure-Python, needs "
            "maverick-agent[latex]); render (full document -> PDF via tectonic/"
            "pdflatex in the sandbox). Input: latex, op, engine, out."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )


__all__ = ["latex_tool", "to_mathml"]
