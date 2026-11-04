"""OpenTelemetry semantic-conventions mapper.

Rename a span's ad-hoc attribute keys to stable OpenTelemetry semantic-
conventions keys so traces are queryable across tools. The caller supplies a
span ``{kind, attrs}``; this maps every known key via a fixed table, passes
unknown keys through unchanged, and flags them so drift is visible.
Deterministic and offline.

ops:
  - map(span)  — attrs renamed to semconv keys + a list of unknown keys.

span: ``{"kind": str, "attrs": {legacy_key: value, ...}}``.
"""
from __future__ import annotations

import json
from typing import Any

from . import Tool

# Legacy / ad-hoc key -> OpenTelemetry semantic-convention key.
_SEMCONV: dict[str, str] = {
    "http_method": "http.request.method",
    "http_status": "http.response.status_code",
    "http_status_code": "http.response.status_code",
    "http_url": "url.full",
    "http_target": "url.path",
    "http_host": "server.address",
    "net_peer_name": "server.address",
    "net_peer_port": "server.port",
    "db_system": "db.system",
    "db_statement": "db.query.text",
    "db_name": "db.namespace",
    "rpc_method": "rpc.method",
    "rpc_service": "rpc.service",
    "exception_type": "exception.type",
    "exception_message": "exception.message",
    # GenAI / LLM conventions.
    "llm_model": "gen_ai.request.model",
    "llm_provider": "gen_ai.system",
    "llm_prompt_tokens": "gen_ai.usage.input_tokens",
    "llm_completion_tokens": "gen_ai.usage.output_tokens",
    "llm_temperature": "gen_ai.request.temperature",
    "llm_max_tokens": "gen_ai.request.max_tokens",
}


def _map(span: dict) -> str:
    attrs = span.get("attrs")
    if not isinstance(attrs, dict):
        return "ERROR: span.attrs (object) is required"
    kind = str(span.get("kind", ""))

    mapped: dict[str, Any] = {}
    unknown: list[str] = []
    for key in sorted(attrs):
        if key in _SEMCONV:
            mapped[_SEMCONV[key]] = attrs[key]
        else:
            mapped[key] = attrs[key]
            unknown.append(key)

    renamed = sum(1 for k in attrs if k in _SEMCONV)
    unknown_str = "[" + ", ".join(unknown) + "]" if unknown else "[]"
    return (
        f"OK kind={kind or '(none)'} renamed={renamed} unknown={len(unknown)}\n"
        f"  attrs={json.dumps(mapped, sort_keys=True)}\n"
        f"  unknown_keys={unknown_str}"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "map"):
        return f"ERROR: unknown op {args.get('op')!r}"
    span = args.get("span")
    if not isinstance(span, dict):
        return "ERROR: span ({kind, attrs}) is required"
    return _map(span)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["map"]},
        "span": {
            "type": "object",
            "description": "Span to map: {kind, attrs}",
            "properties": {
                "kind": {"type": "string"},
                "attrs": {"type": "object", "description": "Legacy attribute key/value pairs"},
            },
            "required": ["attrs"],
        },
    },
    "required": ["span"],
}


def otel_semconv() -> Tool:
    return Tool(
        name="otel_semconv",
        description=(
            "OpenTelemetry semantic-conventions mapper. op=map with a 'span' "
            "({kind, attrs}); renames known attribute keys to OTel semconv keys "
            "(e.g. http_method->http.request.method, llm_model->"
            "gen_ai.request.model) via a fixed table, passes unknown keys through "
            "and flags them. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
