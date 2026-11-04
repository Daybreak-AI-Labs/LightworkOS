"""Provider cost-curve fitter: learn cost ≈ a·in_tok + b·out_tok per provider.

Past runs log (input_tokens, output_tokens, cost); this fits the two per-token
rates by ordinary least squares (closed-form 2×2 normal equations — no numpy/
scipy) so the cost router can *predict* a call's cost before making it. Pure and
dependency-free: ``fit_curve`` / ``predict`` are unit-tested; ``gather`` adapts a
world model's priced episodes, grouped by provider. Falls back to a single
average-rate model when the system is singular (e.g. all rows share a token mix).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CostCurve:
    a: float          # $ per input token
    b: float          # $ per output token
    r2: float         # goodness of fit (0..1)
    n: int            # samples
    basis: str        # "least_squares" | "average" | "none"

    def predict(self, in_tok: float, out_tok: float) -> float:
        return round(max(0.0, self.a * in_tok + self.b * out_tok), 8)


def fit_curve(samples: list[tuple[float, float, float]]) -> CostCurve:
    """Fit ``cost ≈ a·in + b·out`` over ``(in_tok, out_tok, cost)`` rows.

    Uses the closed-form least-squares solution of the 2×2 normal equations.
    With <2 rows or a singular system, falls back to a single average per-token
    rate split evenly across in/out tokens.
    """
    rows = [(float(i), float(o), float(c)) for (i, o, c) in samples
            if c is not None and float(c) >= 0]
    if not rows:
        return CostCurve(0.0, 0.0, 0.0, 0, "none")

    sxx = sum(i * i for i, _, _ in rows)
    syy = sum(o * o for _, o, _ in rows)
    sxy = sum(i * o for i, o, _ in rows)
    sxc = sum(i * c for i, _, c in rows)
    syc = sum(o * c for _, o, c in rows)
    det = sxx * syy - sxy * sxy

    if len(rows) >= 2 and abs(det) > 1e-12:
        a = (syy * sxc - sxy * syc) / det
        b = (sxx * syc - sxy * sxc) / det
        basis = "least_squares"
    else:
        total_tok = sum(i + o for i, o, _ in rows)
        total_cost = sum(c for _, _, c in rows)
        rate = (total_cost / total_tok) if total_tok else 0.0
        a = b = rate
        basis = "average"

    a, b = max(0.0, a), max(0.0, b)  # negative per-token rates are nonsense
    mean_c = sum(c for _, _, c in rows) / len(rows)
    ss_tot = sum((c - mean_c) ** 2 for _, _, c in rows)
    ss_res = sum((c - (a * i + b * o)) ** 2 for i, o, c in rows)
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 1e-12 else 1.0
    return CostCurve(round(a, 10), round(b, 10), round(max(0.0, min(1.0, r2)), 4),
                     len(rows), basis)


def gather(world, *, limit: int = 500) -> dict[str, list[tuple[float, float, float]]]:
    """Build ``{provider: [(in_tok, out_tok, cost), ...]}`` from priced episodes."""
    out: dict[str, list[tuple[float, float, float]]] = {}
    for ep in world.list_episodes(limit=limit):
        cost = getattr(ep, "cost_dollars", 0) or 0
        if cost <= 0:
            continue
        provider = getattr(ep, "provider", None) or "(all)"
        # EpisodeSpend's fields are input_tokens/output_tokens; the old
        # in_tokens/out_tokens getattrs read 0 from every real episode, so the
        # curve fit on all-zero rows and the cost router was never trained.
        out.setdefault(str(provider), []).append((
            float(getattr(ep, "input_tokens", 0) or 0),
            float(getattr(ep, "output_tokens", 0) or 0),
            float(cost),
        ))
    return out


def fit_all(world, *, limit: int = 500) -> dict[str, CostCurve]:
    """Fit one curve per provider from a world model."""
    return {prov: fit_curve(rows) for prov, rows in gather(world, limit=limit).items()}


# --- tool surface ----------------------------------------------------------

_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["fit", "predict"], "default": "fit"},
        "provider": {"type": "string", "description": "provider to predict for (predict op)"},
        "in_tokens": {"type": "integer"},
        "out_tokens": {"type": "integer"},
    },
}


def _run(args: dict, world) -> str:
    import json as _json
    op = args.get("op") or "fit"
    curves = fit_all(world)
    if not curves:
        return "No priced run history yet — can't fit a cost curve."
    if op == "fit":
        return _json.dumps({p: {"per_in_tok": c.a, "per_out_tok": c.b, "r2": c.r2,
                                "n": c.n, "basis": c.basis}
                            for p, c in curves.items()}, indent=2)
    if op == "predict":
        prov = args.get("provider") or next(iter(curves))
        curve = curves.get(prov)
        if curve is None:
            return f"ERROR: no curve for provider {prov!r} (have: {sorted(curves)})"
        est = curve.predict(float(args.get("in_tokens") or 0),
                            float(args.get("out_tokens") or 0))
        return f"{prov}: estimated ${est:.6f}"
    return f"ERROR: unknown op {op!r}"


def cost_curve_tool(world):
    from ..tools import Tool
    return Tool(
        name="cost_curve",
        description=(
            "Fit / query a per-provider cost model (cost ~ a*in_tok + b*out_tok) "
            "from past priced runs. ops: fit (coefficients + R2 per provider), "
            "predict (provider, in_tokens, out_tokens -> estimated cost)."
        ),
        input_schema=_SCHEMA,
        fn=lambda args: _run(args, world),
        parallel_safe=True,
    )


__all__ = ["CostCurve", "fit_curve", "gather", "fit_all", "cost_curve_tool"]
