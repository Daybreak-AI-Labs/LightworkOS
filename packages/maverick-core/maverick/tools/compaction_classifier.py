"""Compaction v6 hybrid strategy picker.

Pick the cheapest compaction strategy that fits a conversation's shape. The
caller supplies coarse features; this applies a documented rule ladder and
returns one of ``truncate | structural | retrieval | summarize`` plus the
reason it fired. Deterministic and offline — no model call.

ops:
  - pick(features)  — strategy + reason.

features:
  - turns            (int)   conversation length in turns
  - tokens           (int)   approximate total tokens
  - has_code         (bool)  transcript contains code blocks
  - has_tool_output  (bool)  transcript contains tool results
  - pinned_ratio     (float) fraction of content pinned (0..1)

Rule ladder (first match wins):
  1. tokens small (< 4000)                       -> truncate   (cheap, nothing to gain)
  2. pinned_ratio high (>= 0.5)                  -> structural  (must preserve refs)
  3. has_code or has_tool_output                 -> structural  (lossless refs matter)
  4. turns large (> 50) and tokens large (>=32k) -> retrieval    (index + fetch on demand)
  5. otherwise                                   -> summarize    (LLM summary of prose)
"""
from __future__ import annotations

from typing import Any

from . import Tool

_SMALL_TOKENS = 4000
_PINNED_HIGH = 0.5
_MANY_TURNS = 50
_BIG_TOKENS = 32000


def _pick(features: dict) -> str:
    try:
        turns = int(features.get("turns", 0))
        tokens = int(features.get("tokens", 0))
    except (TypeError, ValueError):
        return "ERROR: turns and tokens must be integers"
    if turns < 0 or tokens < 0:
        return "ERROR: turns and tokens must be >= 0"
    has_code = bool(features.get("has_code", False))
    has_tool_output = bool(features.get("has_tool_output", False))
    try:
        pinned = float(features.get("pinned_ratio", 0.0))
    except (TypeError, ValueError):
        return "ERROR: pinned_ratio must be a number"
    if not 0.0 <= pinned <= 1.0:
        return "ERROR: pinned_ratio must be in [0, 1]"

    if tokens < _SMALL_TOKENS:
        strat = "truncate"
        reason = f"tokens={tokens} < {_SMALL_TOKENS}: too small to compact, drop oldest"
    elif pinned >= _PINNED_HIGH:
        strat = "structural"
        reason = f"pinned_ratio={pinned:g} >= {_PINNED_HIGH}: preserve pinned refs structurally"
    elif has_code or has_tool_output:
        strat = "structural"
        kinds = [k for k, v in (("code", has_code), ("tool_output", has_tool_output)) if v]
        reason = f"has {'+'.join(kinds)}: keep references lossless"
    elif turns > _MANY_TURNS and tokens >= _BIG_TOKENS:
        strat = "retrieval"
        reason = (
            f"turns={turns} > {_MANY_TURNS} and tokens={tokens} >= {_BIG_TOKENS}: "
            "index and fetch on demand"
        )
    else:
        strat = "summarize"
        reason = "prose-heavy, mid-size: LLM summary"

    return f"STRATEGY {strat}: {reason}"


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "pick"):
        return f"ERROR: unknown op {args.get('op')!r}"
    features = args.get("features")
    if not isinstance(features, dict):
        return (
            "ERROR: features ({turns, tokens, has_code, has_tool_output, "
            "pinned_ratio}) is required"
        )
    return _pick(features)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["pick"]},
        "features": {
            "type": "object",
            "description": "Conversation shape features",
            "properties": {
                "turns": {"type": "integer"},
                "tokens": {"type": "integer"},
                "has_code": {"type": "boolean"},
                "has_tool_output": {"type": "boolean"},
                "pinned_ratio": {"type": "number", "description": "Pinned fraction 0..1"},
            },
        },
    },
    "required": ["features"],
}


def compaction_classifier() -> Tool:
    return Tool(
        name="compaction_classifier",
        description=(
            "Compaction v6 hybrid strategy picker. op=pick with 'features' "
            "({turns, tokens, has_code, has_tool_output, pinned_ratio}); applies "
            "a documented rule ladder to choose truncate | structural | retrieval "
            "| summarize and returns the reason. Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
