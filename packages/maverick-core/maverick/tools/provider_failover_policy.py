"""Provider failover policy engine.

Given a set of upstream providers and a health policy, decide which are eligible
and rank them best-first so the agent loop can pick a primary and an ordered
fallback chain. Deterministic and offline: the caller supplies the providers
(each ``{name, healthy, latency_ms, error_rate}``) and the policy
(``{max_error_rate, max_latency_ms}``); this resolves the ordering.

A provider is eligible when it is healthy AND within both thresholds. Eligible
providers are ranked by (error_rate, latency_ms, name) ascending — lowest error
rate first, then lowest latency, name as a stable tie-breaker. The first ranked
provider is the chosen primary.

ops:
  - order(providers, policy)  — eligible ranking + chosen primary (or NONE).
"""
from __future__ import annotations

from typing import Any

from . import Tool, as_bool


def _parse_provider(p: Any, idx: int) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(p, dict):
        return None, f"ERROR: provider #{idx} must be an object"
    name = p.get("name")
    if not isinstance(name, str) or not name.strip():
        return None, f"ERROR: provider #{idx} needs a non-empty name"
    try:
        latency = float(p.get("latency_ms"))
        error_rate = float(p.get("error_rate"))
    except (TypeError, ValueError):
        return None, f"ERROR: provider {name!r} needs numeric latency_ms and error_rate"
    if latency < 0:
        return None, f"ERROR: provider {name!r} latency_ms must be >= 0"
    if not 0 <= error_rate <= 1:
        return None, f"ERROR: provider {name!r} error_rate must be in [0, 1]"
    return {
        "name": name,
        "healthy": as_bool(p.get("healthy", False)),
        "latency_ms": latency,
        "error_rate": error_rate,
    }, ""


def _order(providers: list, policy: dict) -> str:
    try:
        max_error_rate = float(policy.get("max_error_rate"))
        max_latency_ms = float(policy.get("max_latency_ms"))
    except (TypeError, ValueError):
        return "ERROR: policy needs numeric max_error_rate and max_latency_ms"
    if not 0 <= max_error_rate <= 1:
        return "ERROR: policy.max_error_rate must be in [0, 1]"
    if max_latency_ms < 0:
        return "ERROR: policy.max_latency_ms must be >= 0"

    parsed: list[dict[str, Any]] = []
    for i, p in enumerate(providers):
        prov, err = _parse_provider(p, i)
        if err:
            return err
        parsed.append(prov)

    eligible = [
        p for p in parsed
        if p["healthy"]
        and p["error_rate"] <= max_error_rate
        and p["latency_ms"] <= max_latency_ms
    ]
    eligible.sort(key=lambda p: (p["error_rate"], p["latency_ms"], p["name"]))

    if not eligible:
        return (
            f"NONE no eligible providers (policy: max_error_rate={max_error_rate:g}, "
            f"max_latency_ms={max_latency_ms:g}; evaluated {len(parsed)})"
        )

    primary = eligible[0]["name"]
    ranked = ", ".join(
        f"{p['name']}(err={p['error_rate']:g}, lat={p['latency_ms']:g}ms)"
        for p in eligible
    )
    return (
        f"PRIMARY {primary} ({len(eligible)}/{len(parsed)} eligible)\n"
        f"  ranked: [{ranked}]"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "order"):
        return f"ERROR: unknown op {args.get('op')!r}"
    providers = args.get("providers")
    if not isinstance(providers, list) or not providers:
        return "ERROR: providers (non-empty list of {name, healthy, latency_ms, error_rate}) is required"
    policy = args.get("policy")
    if not isinstance(policy, dict):
        return "ERROR: policy ({max_error_rate, max_latency_ms}) is required"
    return _order(providers, policy)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["order"]},
        "providers": {
            "type": "array",
            "description": "Providers: {name, healthy, latency_ms, error_rate}",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "healthy": {"type": "boolean"},
                    "latency_ms": {"type": "number", "minimum": 0},
                    "error_rate": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "required": ["name", "latency_ms", "error_rate"],
            },
        },
        "policy": {
            "type": "object",
            "description": "Health policy: {max_error_rate, max_latency_ms}",
            "properties": {
                "max_error_rate": {"type": "number", "minimum": 0, "maximum": 1},
                "max_latency_ms": {"type": "number", "minimum": 0},
            },
            "required": ["max_error_rate", "max_latency_ms"],
        },
    },
    "required": ["providers", "policy"],
}


def provider_failover_policy() -> Tool:
    return Tool(
        name="provider_failover_policy",
        description=(
            "Provider failover policy engine. op=order with 'providers' (each "
            "{name, healthy, latency_ms, error_rate}) and a 'policy' "
            "({max_error_rate, max_latency_ms}). Excludes unhealthy or "
            "over-threshold providers, ranks the rest best-first by (error_rate, "
            "latency_ms, name), and names the chosen primary (or NONE). "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
