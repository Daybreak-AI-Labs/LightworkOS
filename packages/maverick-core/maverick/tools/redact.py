"""Redaction tool — provably scrub secrets/PII from a blob (offline).

Wraps :mod:`maverick.provable_redaction`: redact to a fixpoint and prove the
output re-scans clean, or report the residual gap. Use before pasting logs /
transcripts / error dumps somewhere they shouldn't carry credentials or PII.

ops:
  - redact(text)   — return the proven-redacted text + the proof status
  - verify(text)   — list any secrets/PII still present ([] == clean)
"""
from __future__ import annotations

from typing import Any

from . import Tool

_REDACT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["redact", "verify"]},
        "text": {"type": "string"},
    },
    "required": ["text"],
}


def _run(args: dict[str, Any]) -> str:
    op = args.get("op") or "redact"
    text = args.get("text")
    if text is None:
        return "ERROR: text is required"
    text = str(text)
    from ..provable_redaction import redact_proven, verify_redacted
    if op == "redact":
        proof = redact_proven(text)
        status = ("PROVEN clean" if proof.proven
                  else f"NOT proven — residual: {', '.join(proof.residual)}")
        return f"[{status}; {proof.passes} pass(es)]\n{proof.redacted}"
    if op == "verify":
        residual = verify_redacted(text)
        if not residual:
            return "clean: no secrets/PII detected"
        return "RESIDUAL: " + ", ".join(residual)
    return f"ERROR: unknown op {op!r}"


def redact_tool() -> Tool:
    return Tool(
        name="redact",
        description=(
            "Provably redact secrets/PII from text. ops: redact (return "
            "fixpoint-redacted text + proof status), verify (list any "
            "secrets/PII still present). Offline; composes the secret + PII "
            "detectors."
        ),
        input_schema=_REDACT_SCHEMA,
        fn=_run,
    )
