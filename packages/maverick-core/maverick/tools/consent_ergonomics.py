"""Consent ergonomics pass.

Turn a raw permission request (action + scopes + data + duration) into a
minimal, plain-language consent prompt a human can actually read, plus a risk
badge (low/med/high) derived from how sensitive the requested scopes are. Flags
over-broad requests (wildcard scopes, far more scopes than the action needs).
Deterministic and offline so the same request always renders the same prompt.

ops:
  - summarize(request)  — request: {action, scopes:[...], data:[...], duration?}.
"""
from __future__ import annotations

import re
from typing import Any

from . import Tool

# Scope keywords (matched on whole atomic TOKENS, not substrings) -> sensitivity.
# The scope is split on every non-alphanumeric char (``:``, ``.``, ``/``, ``_``,
# ``-`` ...), so "delete_all" -> {delete, all} and "send_messages" -> {send,
# messages} match, while a benign "wallet"/"gallery"/"install" does NOT match
# "all" the way the old substring check did. "manage" covers manage_* and "all"
# covers write_all / *_all.
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_HIGH = frozenset({"delete", "admin", "manage", "billing", "payment",
                   "transfer", "export", "all"})
_MED = frozenset({"write", "send", "modify", "update", "create", "share",
                  "contacts", "calendar", "location"})
# Anything else (read/list/view/...) is treated as low.


def _scope_risk(scope: str) -> str:
    s = scope.lower()
    if "*" in s:
        return "high"  # a wildcard scope is over-broad by definition
    tokens = {t for t in _TOKEN_SPLIT.split(s) if t}
    if tokens & _HIGH:
        return "high"
    if tokens & _MED:
        return "med"
    return "low"


def _badge(scopes: list[str]) -> str:
    levels = {_scope_risk(s) for s in scopes}
    if "high" in levels:
        return "high"
    if "med" in levels:
        return "med"
    return "low"


def _summarize(request: dict) -> str:
    action = str(request.get("action", "")).strip()
    if not action:
        return "ERROR: request.action is required"
    scopes = [str(s).strip() for s in (request.get("scopes") or []) if str(s).strip()]
    data = [str(d).strip() for d in (request.get("data") or []) if str(d).strip()]
    duration = str(request.get("duration", "")).strip()

    badge = _badge(scopes) if scopes else "low"

    flags: list[str] = []
    wildcard = [s for s in scopes if "*" in s or s.lower() in ("all", "write_all")]
    if wildcard:
        flags.append(f"over-broad scope(s): {', '.join(sorted(set(wildcard)))}")
    # An action asking for many scopes is a classic over-ask smell.
    if len(scopes) > 5:
        flags.append(f"requests {len(scopes)} scopes (consider least-privilege)")
    if not duration:
        flags.append("no duration set (consent would be open-ended)")

    # Plain-language prompt: one sentence a non-technical user can approve.
    scope_phrase = ", ".join(scopes) if scopes else "no specific permissions"
    prompt = f"Allow {action}? It will be able to: {scope_phrase}."
    if data:
        prompt += f" It will access your: {', '.join(data)}."
    prompt += f" Duration: {duration}." if duration else " Duration: until you revoke it."

    out = [f"CONSENT [{badge.upper()}]", prompt]
    if flags:
        out.append("flags:")
        out.extend("- " + f for f in flags)
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "summarize"):
        return f"ERROR: unknown op {args.get('op')!r}"
    request = args.get("request")
    if not isinstance(request, dict):
        return "ERROR: request (object with action/scopes/data/duration) is required"
    return _summarize(request)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["summarize"]},
        "request": {
            "type": "object",
            "description": "Permission request to summarize",
            "properties": {
                "action": {"type": "string"},
                "scopes": {"type": "array", "items": {"type": "string"}},
                "data": {"type": "array", "items": {"type": "string"}},
                "duration": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    "required": ["request"],
}


def consent_ergonomics() -> Tool:
    return Tool(
        name="consent_ergonomics",
        description=(
            "Render a minimal, plain-language consent prompt from a permission "
            "request. op=summarize with 'request' ({action, scopes, data, "
            "duration?}) returns a one-sentence prompt plus a risk badge "
            "(low/med/high) by scope sensitivity, and flags over-broad scope "
            "requests. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
