"""Jupyter notebook execution tool: run a .ipynb's code cells, capture output.

Extracts the code cells from a notebook (stdlib ``json``), concatenates them into
one script, obtains a one-use human approval, and runs it through the sandbox
chokepoint so execution is confined and the backend is swappable in tests.
No Jupyter kernel required — this runs the notebook's *code* the way the agent
runs any other script. Cell magics (``%``/``!`` lines) are stripped since they're
kernel-only. ``_extract_code`` is the pure, unit-tested core.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any

from . import Tool, sandbox_run

_MAX_NOTEBOOK_BYTES = 16 * 1024 * 1024
_MAX_CODE_BYTES = 64 * 1024
_MAX_TIMEOUT_SECONDS = 600.0


def _read_notebook(path: Path) -> bytes:
    with path.open("rb") as handle:
        contents = handle.read(_MAX_NOTEBOOK_BYTES + 1)
    if len(contents) > _MAX_NOTEBOOK_BYTES:
        raise ValueError("notebook is larger than 16 MiB")
    return contents


def _safe_path(sandbox, user_path: str) -> Path:
    """Resolve ``user_path`` confined to the sandbox workspace.

    Without a sandbox there's no workspace to confine to, so fall back to
    ``expanduser`` (matches pandas_query). With a sandbox wired in, resolve
    under ``sandbox.workdir`` and refuse anything that escapes it -- a
    model-supplied ``~/secret.ipynb`` must not execute outside the workspace.
    """
    if sandbox is None:
        return Path(os.path.expanduser(user_path))
    workdir = Path(sandbox.workdir).resolve()
    candidate = Path(user_path)
    candidate = (workdir / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    candidate.relative_to(workdir)  # raises ValueError if it escapes
    return candidate

_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "path to a .ipynb notebook"},
        "timeout": {"type": "integer", "description": "seconds (default 120)"},
    },
    "required": ["path"],
}


def _extract_code(nb: dict) -> str:
    """Concatenate code-cell source from a parsed notebook, dropping magics."""
    cells = nb.get("cells") or []
    chunks: list[str] = []
    for i, cell in enumerate(cells):
        if cell.get("cell_type") != "code":
            continue
        src = cell.get("source") or []
        if isinstance(src, list):
            src = "".join(src)
        lines = [ln for ln in str(src).splitlines()
                 if not ln.lstrip().startswith(("%", "!"))]
        body = "\n".join(lines).strip()
        if body:
            chunks.append(f"# --- cell {i} ---\n{body}")
    return "\n\n".join(chunks)


def _run(args: dict[str, Any], sandbox) -> str:
    path = str(args.get("path") or "").strip()
    if not path:
        return "ERROR: path is required"
    try:
        p = _safe_path(sandbox, path)
    except ValueError:
        return f"ERROR: path escapes the workspace: {path!r}"
    try:
        if not p.exists():
            return f"ERROR: no such notebook {path!r}"
        notebook_bytes = _read_notebook(p)
        nb = json.loads(notebook_bytes.decode("utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError) as e:
        return f"ERROR: cannot read notebook: {e}"
    code = _extract_code(nb)
    if not code:
        return "(notebook has no executable code cells)"
    code_bytes = code.encode("utf-8")
    if len(code_bytes) > _MAX_CODE_BYTES:
        return "ERROR: executable notebook code exceeds 64 KiB"
    try:
        timeout = float(120 if args.get("timeout") is None else args["timeout"])
    except (TypeError, ValueError):
        return "ERROR: timeout must be a positive number of seconds"
    if not math.isfinite(timeout) or not 1 <= timeout <= _MAX_TIMEOUT_SECONDS:
        return "ERROR: timeout must be between 1 and 600 seconds"

    # Notebook code can mutate files and contact services just like a shell
    # command. Reuse shell's mandatory, fresh, one-use consent boundary even
    # when there is no configured sandbox. Commit the code, source notebook,
    # execution target and timeout; recheck the source before dispatch.
    from ..approval_cards import ApprovalCardError, digest
    from ..safety import (
        ConsentDenied,
        consume_operation_consent,
        require_operation_consent,
    )
    from ..safety.secret_detector import redact
    from ..sandbox.local import LocalBackend

    def target() -> dict[str, str]:
        backend = type(sandbox)
        if sandbox is None:
            isolation = "none (host subprocess)"
        elif isinstance(sandbox, LocalBackend):
            isolation = "local host execution"
        else:
            isolation = "configured sandbox"
        return {
            "backend": f"{backend.__module__}.{backend.__qualname__}",
            "workdir": str(Path(getattr(sandbox, "workdir", Path.cwd())).resolve()),
            "isolation": isolation,
        }

    source_sha256 = hashlib.sha256(notebook_bytes).hexdigest()
    cell_count = sum(cell.get("cell_type") == "code" for cell in nb.get("cells") or [])
    preview_lines = [
        line.strip()[:100] for line in code.splitlines()
        if line.strip() and not line.startswith("# --- cell ")
    ]
    preview, _ = redact(" | ".join(preview_lines[:2]) or "comments only")
    parameters = {
        "notebook": str(p),
        "code_sha256": hashlib.sha256(code_bytes).hexdigest(),
        "timeout_seconds": timeout,
    }

    def current_parameters() -> dict[str, str | float]:
        if hashlib.sha256(_read_notebook(p)).hexdigest() != source_sha256:
            raise ApprovalCardError("the notebook changed after its code was read")
        return parameters

    try:
        permit = require_operation_consent(
            "notebook_exec",
            risk="high",
            scope=f"notebook:{p}",
            detail=(
                f"Run {cell_count} code cells from {p.name} using "
                f"{target()['isolation']} with a {timeout:g}-second limit."
            ),
            provenance="notebook_exec",
            target=target(),
            parameters=parameters,
            parameter_summary=[
                f"First lines (truncated, redacted): {preview}",
                "Full code is committed by SHA-256; open the notebook to review all cells.",
            ],
            known_effects=["Runs the notebook's code cells in the reviewed execution environment."],
            unresolved_assumptions=[
                "Notebook code may modify files or contact services allowed by that environment.",
            ],
            before="The notebook code has not run.",
            after="The notebook code has run once and its effects may persist.",
            irreversible=True,
            target_provider=target,
            parameters_provider=current_parameters,
            input_versions_provider=lambda: {
                "notebook_sha256": hashlib.sha256(_read_notebook(p)).hexdigest(),
            },
            credential_versions_provider=lambda: {
                "kind": "sandbox-runtime",
                "generation_sha256": digest(target()),
            },
            budget_provider=lambda: {"timeout_seconds": timeout},
            allow_auto_approve=False,
            consult_ledger=False,
        )
    except ConsentDenied:
        return "ERROR: notebook execution was not approved; no code was run"
    except (ApprovalCardError, OSError):
        return "ERROR: notebook, execution target, or approval authority changed; review it again"

    try:
        with consume_operation_consent(permit):
            exit_code, stdout, stderr = sandbox_run(
                sandbox, ["python", "-"], stdin=code, timeout=timeout,
            )
    except ApprovalCardError:
        return "ERROR: notebook, execution target, or approval authority changed; review it again"
    parts = [f"exit_code: {exit_code}"]
    if stdout.strip():
        parts.append("stdout:\n" + stdout.rstrip())
    if stderr.strip():
        parts.append("stderr:\n" + stderr.rstrip())
    return "\n".join(parts)


def notebook_exec(sandbox) -> Tool:
    return Tool(
        name="notebook_exec",
        description=(
            "Execute a Jupyter notebook's code cells and capture stdout/stderr. "
            "Concatenates code cells (drops %/! magics) and runs them through the "
            "sandbox — no kernel needed. Input: path to a .ipynb."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, sandbox),
    )


__all__ = ["notebook_exec", "_extract_code"]
