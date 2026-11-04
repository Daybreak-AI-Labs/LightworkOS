"""Model card tool — render or validate an LLM model card.

Produce a human-readable model card from structured fields, or validate that a
proposed card carries the required disclosures (model, provider, intended use,
limitations). Deterministic and offline; pure formatting/validation over the
supplied fields. No disk, no network.

ops:
  - render    — format the card; fails if a required field is missing.
  - validate  — list any missing required fields (OK if complete).
"""
from __future__ import annotations

from typing import Any

from . import Tool

_REQUIRED = ["model", "provider", "intended_use", "limitations"]
_OPTIONAL = ["training_cutoff", "eval_scores"]


def _missing(args: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for field in _REQUIRED:
        val = args.get(field)
        if val is None or (isinstance(val, str) and not val.strip()):
            out.append(field)
    return out


def _fmt_scores(scores: Any) -> list[str]:
    lines: list[str] = []
    if isinstance(scores, dict) and scores:
        lines.append("Eval scores:")
        for name in sorted(scores):
            lines.append(f"  - {name}: {scores[name]}")
    return lines


def _render(args: dict[str, Any]) -> str:
    miss = _missing(args)
    if miss:
        return f"ERROR: cannot render, missing required field(s): {', '.join(miss)}"
    lines = [
        f"# Model Card: {str(args['model']).strip()}",
        f"Provider: {str(args['provider']).strip()}",
        f"Intended use: {str(args['intended_use']).strip()}",
        f"Limitations: {str(args['limitations']).strip()}",
    ]
    cutoff = args.get("training_cutoff")
    if cutoff is not None and str(cutoff).strip():
        lines.append(f"Training cutoff: {str(cutoff).strip()}")
    lines.extend(_fmt_scores(args.get("eval_scores")))
    return "OK\n" + "\n".join(lines)


def _validate(args: dict[str, Any]) -> str:
    miss = _missing(args)
    if miss:
        return f"INVALID: missing required field(s): {', '.join(miss)}"
    return f"OK: all required fields present ({', '.join(_REQUIRED)})"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "render":
        return _render(args)
    if op == "validate":
        return _validate(args)
    return f"ERROR: unknown op {op!r} (expected render or validate)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["render", "validate"]},
        "model": {"type": "string", "description": "model name/version"},
        "provider": {"type": "string"},
        "intended_use": {"type": "string"},
        "limitations": {"type": "string"},
        "training_cutoff": {"type": "string", "description": "optional, e.g. 2025-01"},
        "eval_scores": {
            "type": "object",
            "description": "optional benchmark -> score map",
        },
    },
    "required": ["op"],
}


def model_card() -> Tool:
    return Tool(
        name="model_card",
        description=(
            "Render or validate an LLM model card. op=render formats a card from "
            "{model, provider, intended_use, limitations, training_cutoff?, "
            "eval_scores?}; op=validate flags missing required fields. Required: "
            "model, provider, intended_use, limitations. Returns OK / INVALID / "
            "ERROR. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
