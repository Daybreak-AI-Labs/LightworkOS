"""Cost-aware router v2, per-role policies.

Pick the cheapest model that still clears a role's quality floor and cost
ceiling. Deterministic and offline: the caller supplies the role, the candidate
models (each ``{model, in_cost, out_cost, quality}``) and a per-role policy map
(``{role: {max_cost?, min_quality?}}``); this resolves the choice and explains
why.

A candidate is eligible when ``quality >= min_quality`` (if set) AND its blended
cost ``in_cost + out_cost`` is ``<= max_cost`` (if set). Among the eligible, the
cheapest blended cost wins; ties break toward higher quality, then model name.

ops:
  - route(role, models, policy)  — chosen model + why (or NONE with the reason).
"""
from __future__ import annotations

from typing import Any

from . import Tool


def _parse_model(m: Any, idx: int) -> tuple[dict[str, Any] | None, str]:
    if not isinstance(m, dict):
        return None, f"ERROR: model #{idx} must be an object"
    name = m.get("model")
    if not isinstance(name, str) or not name.strip():
        return None, f"ERROR: model #{idx} needs a non-empty 'model' name"
    try:
        in_cost = float(m.get("in_cost"))
        out_cost = float(m.get("out_cost"))
        quality = float(m.get("quality"))
    except (TypeError, ValueError):
        return None, f"ERROR: model {name!r} needs numeric in_cost, out_cost, quality"
    if in_cost < 0 or out_cost < 0:
        return None, f"ERROR: model {name!r} costs must be >= 0"
    return {
        "model": name,
        "in_cost": in_cost,
        "out_cost": out_cost,
        "quality": quality,
        "blended": in_cost + out_cost,
    }, ""


def _route(role: str, models: list, policy: dict) -> str:
    role_policy = policy.get(role)
    if role_policy is None:
        role_policy = {}
    if not isinstance(role_policy, dict):
        return f"ERROR: policy[{role!r}] must be an object"

    min_quality: float | None = None
    max_cost: float | None = None
    if role_policy.get("min_quality") is not None:
        try:
            min_quality = float(role_policy.get("min_quality"))
        except (TypeError, ValueError):
            return f"ERROR: policy[{role!r}].min_quality must be a number"
    if role_policy.get("max_cost") is not None:
        try:
            max_cost = float(role_policy.get("max_cost"))
        except (TypeError, ValueError):
            return f"ERROR: policy[{role!r}].max_cost must be a number"

    parsed: list[dict[str, Any]] = []
    for i, m in enumerate(models):
        mod, err = _parse_model(m, i)
        if err:
            return err
        parsed.append(mod)

    eligible = [
        m for m in parsed
        if (min_quality is None or m["quality"] >= min_quality)
        and (max_cost is None or m["blended"] <= max_cost)
    ]
    if not eligible:
        floor = "none" if min_quality is None else f"{min_quality:g}"
        ceil = "none" if max_cost is None else f"{max_cost:g}"
        return (
            f"NONE no model meets role {role!r} (min_quality={floor}, "
            f"max_cost={ceil}; evaluated {len(parsed)})"
        )

    # Cheapest first; tie -> higher quality; then name for stability.
    eligible.sort(key=lambda m: (m["blended"], -m["quality"], m["model"]))
    best = eligible[0]
    floor = "none" if min_quality is None else f"{min_quality:g}"
    ceil = "none" if max_cost is None else f"{max_cost:g}"
    return (
        f"ROUTE {best['model']} for role {role!r} "
        f"(cost={best['blended']:g}, quality={best['quality']:g})\n"
        f"  why: cheapest of {len(eligible)} meeting min_quality={floor}, "
        f"max_cost={ceil}"
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "route"):
        return f"ERROR: unknown op {args.get('op')!r}"
    role = args.get("role")
    if not isinstance(role, str) or not role.strip():
        return "ERROR: role (string) is required"
    models = args.get("models")
    if not isinstance(models, list) or not models:
        return "ERROR: models (non-empty list of {model, in_cost, out_cost, quality}) is required"
    policy = args.get("policy")
    if not isinstance(policy, dict):
        return "ERROR: policy ({role: {max_cost?, min_quality?}}) is required"
    return _route(role, models, policy)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["route"]},
        "role": {"type": "string", "description": "Role to route for, e.g. 'planner'"},
        "models": {
            "type": "array",
            "description": "Candidate models: {model, in_cost, out_cost, quality}",
            "items": {
                "type": "object",
                "properties": {
                    "model": {"type": "string"},
                    "in_cost": {"type": "number", "minimum": 0},
                    "out_cost": {"type": "number", "minimum": 0},
                    "quality": {"type": "number"},
                },
                "required": ["model", "in_cost", "out_cost", "quality"],
            },
        },
        "policy": {
            "type": "object",
            "description": "Per-role policy map: {role: {max_cost?, min_quality?}}",
            "additionalProperties": {
                "type": "object",
                "properties": {
                    "max_cost": {"type": "number"},
                    "min_quality": {"type": "number"},
                },
            },
        },
    },
    "required": ["role", "models", "policy"],
}


def cost_aware_router() -> Tool:
    return Tool(
        name="cost_aware_router",
        description=(
            "Cost-aware router v2 with per-role policies. op=route with 'role', "
            "'models' (each {model, in_cost, out_cost, quality}) and 'policy' "
            "({role: {max_cost?, min_quality?}}). Picks the cheapest model whose "
            "quality clears the role's floor and whose blended cost "
            "(in_cost+out_cost) is within the ceiling; returns the choice and "
            "why (or NONE). Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
