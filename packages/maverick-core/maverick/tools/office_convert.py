"""Office-document converter.

LibreOffice headless conversion for the *binary* office formats pandoc can't
take — Word/Excel/PowerPoint/OpenDocument — into PDF / text / HTML / CSV.
``pandoc`` (the sibling tool) handles markup formats; this fills the
docx/xlsx/pptx → pdf gap that a business workflow actually hits.

Auth: none. Requires ``soffice`` and Python UNO in the selected document backend.

ops:
  - convert(input_path, to, outdir?)  — convert to a supported artifact type
  - to_pdf(input_path, outdir?)       — shortcut: PDF export
  - to_text(input_path, outdir?)      — shortcut: text export
  - formats()                         — the common input/output formats

All shell goes through the sandbox chokepoint (CLAUDE.md #4); paths are
confined to the sandbox workdir and may not begin with '-' (option injection).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from . import Tool

log = logging.getLogger(__name__)

_OFFICE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["convert", "to_pdf", "to_text", "formats"],
        },
        "input_path": {"type": "string"},
        "to": {"type": "string",
               "description": "LibreOffice target, e.g. pdf, txt, html, csv, docx"},
        "outdir": {"type": "string",
                   "description": "output directory (defaults to the input's dir)"},
    },
    "required": ["op"],
}

# A LibreOffice convert-to token: a format ('pdf') optionally with an explicit
# filter ('txt:Text'). Must start alnum so it can never be read as a flag.
_TO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 :._-]*$")

_COMMON_INPUTS = ("doc", "docx", "odt", "rtf", "xls", "xlsx", "ods",
                  "ppt", "pptx", "odp", "csv", "html")
_COMMON_OUTPUTS = ("pdf", "txt", "html", "csv", "docx", "odt", "xlsx", "png")






def _op_convert(args: dict, sandbox, to_override: str | None = None) -> str:
    from ..sandbox.workspace_transfer import _read
    from .document_processing import run_document_job, workspace_path

    src = (args.get("input_path") or "").strip()
    target = (to_override or args.get("to") or "").strip()
    if not src:
        return "ERROR: convert requires input_path"
    if not target:
        return "ERROR: convert requires a target format (to)"
    if len(target) > 128 or not _TO_RE.fullmatch(target):
        return f"ERROR: invalid target format {target!r}"
    root, relative = workspace_path(sandbox, src)
    source = Path(relative)
    output_dir = (args.get("outdir") or "").strip() or str(source.parent)
    extension = target.split(":", 1)[0].lower()
    destination = str(Path(output_dir) / (source.stem + "." + extension))
    workspace_path(sandbox, destination)  # reject escapes before execution
    data = _read(root, relative)
    return run_document_job({"operation": "convert", "target": target,
                             "input_suffix": source.suffix.lstrip(".").lower()},
                            data, sandbox, destination=destination)



def _op_formats(_args: dict, _sandbox) -> str:
    return ("common input formats:\n  " + ", ".join(_COMMON_INPUTS) +
            "\n\ncommon output formats:\n  " + ", ".join(_COMMON_OUTPUTS) +
            "\n\n(An explicit LibreOffice filter may follow a supported target, e.g. 'txt:Text'. "
            "Available conversions depend on the document backend's installed components.)")


def _run(args: dict[str, Any], sandbox) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        if op == "convert":
            return _op_convert(args, sandbox)
        if op == "to_pdf":
            return _op_convert(args, sandbox, to_override="pdf")
        if op == "to_text":
            return _op_convert(args, sandbox, to_override="txt")
        if op == "formats":
            return _op_formats(args, sandbox)
    except Exception as e:
        return f"ERROR: libreoffice failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def office_convert(sandbox=None) -> Tool:
    return Tool(
        name="office_convert",
        description=(
            "Convert binary office documents (Word/Excel/PowerPoint/"
            "OpenDocument) via LibreOffice headless. ops: convert "
            "(input_path + to format + optional outdir), to_pdf, to_text, "
            "formats. Requires soffice and Python UNO in the document backend. Use pandoc for "
            "markup formats (md/html/rst)."
        ),
        input_schema=_OFFICE_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )
