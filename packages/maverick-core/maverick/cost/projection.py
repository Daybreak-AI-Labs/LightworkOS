"""Token-level cost projection at plan time.

``maverick start --dry-cost`` forecasts a goal's cost from *history*
(:mod:`maverick.cost_forecast`); this module projects a *specific plan's*
cost from its own shape, before a single token is spent. Each step's text is
sized with the same chars/4 heuristic the live billing path uses
(``llm._estimate_call_cost`` and the token preflight), and priced at the
canonical rate of the model the step's role would actually run on
(``llm.model_for_role`` -> versioned pricing provider). The point is a
pre-execution gut check — "this 12-step plan with 3 reflect iterations is
~$4.10 against a $5 cap" — so an over-budget plan gets reshaped *before*
execution instead of dying on ``BudgetExceeded`` halfway through.

These are estimates, not bills. Two documented knobs keep them honest:

* :data:`STEP_OVERHEAD_TOKENS` — flat per-step input overhead (system prompt
  + tool schemas + scaffolding every agent turn carries on top of the step
  text). Override per call via ``overhead_tokens=``.
* :data:`ROLE_OUTPUT_TOKENS` — expected output tokens per role when the
  caller doesn't know better (writer/coder/revisor produce long completions;
  a summarizer doesn't). Override per step via ``expected_output_tokens``.

Pricing resolves through ``budget._lookup_price`` in explicit
``estimate_only`` mode. That permits clearly marked provisional provider
quotes and the documented last-resort Sonnet fallback; the same values cannot
cross the default billing-grade verification gate.

Pure library, default inert: nothing here runs unless called and nothing
dispatches an LLM call, so there is no config knob to flip.
"""
from __future__ import annotations

from dataclasses import dataclass

# The repo-wide chars->tokens heuristic. Same divisor as the token preflight
# and ``llm._estimate_call_cost``, so a plan projection agrees with what the
# live path will later reserve against the budget.
CHARS_PER_TOKEN = 4

# Flat per-step INPUT overhead, in tokens: system prompt + tool schemas +
# conversation scaffolding that ride along with every agent turn regardless of
# the step text. 2k tokens (~8k chars) is a lean single-agent turn; a role
# with a fat tool belt can pass a bigger ``overhead_tokens=`` explicitly.
STEP_OVERHEAD_TOKENS = 2_000

# Default expected OUTPUT tokens per role when ``expected_output_tokens`` is
# not given. The output-heavy set (writer/coder/revisor — the same roles
# cost.router weights output rates for) defaults ~3x the base because their
# value is long completions; a summarizer's whole job is being short.
ROLE_OUTPUT_TOKENS: dict[str, int] = {
    "writer":       3_000,
    "coder":        3_000,
    "revisor":      3_000,
    "orchestrator": 1_500,
    "summarizer":     500,
}

# Output default for roles absent from ROLE_OUTPUT_TOKENS.
DEFAULT_OUTPUT_TOKENS = 1_000

# Role assumed for a plan step that doesn't name one. "researcher" sits on the
# mid (Sonnet) tier in ROLE_MODELS — neither the premium orchestrator rate nor
# the bargain summarizer one — so an untagged step is priced middle-of-road.
DEFAULT_STEP_ROLE = "researcher"

# compare_against_budget thresholds: a projection above TIGHT_FRACTION of the
# budget is TIGHT (these estimates skew low — reflect loops retry, tools
# return more than planned); above the budget itself is OVER.
TIGHT_FRACTION = 0.70

_MTOK = 1_000_000.0


@dataclass(frozen=True)
class StepEstimate:
    role: str
    model: str
    in_tokens: int
    out_tokens: int
    dollars: float


@dataclass(frozen=True)
class PlanProjection:
    steps: list[StepEstimate]      # one entry per step, single iteration
    total_dollars: float           # all steps x iterations
    total_tokens: int              # in+out, all steps x iterations
    by_role: dict[str, float]      # role -> dollars (x iterations)
    iterations: int


@dataclass(frozen=True)
class BudgetVerdict:
    verdict: str            # "OK" | "TIGHT" | "OVER"
    recommendation: str     # one line, human-ready
    projected_dollars: float
    budget_dollars: float | None


def _price_for(model: str) -> tuple[float, float]:
    """Planning-only ``($/Mtok in, $/Mtok out)`` for a model spec.

    A plan projection is explicitly not a bill, so it opts into provisional
    rates and the documented unknown-model fallback. Live accounting calls the
    same resolver without ``estimate_only`` and fails closed unless the rate is
    verified and provenance-carrying.
    """
    from ..budget import _lookup_price
    return _lookup_price(model, estimate_only=True)


def estimate_step(
    role: str,
    text: str,
    *,
    expected_output_tokens: int | None = None,
    overhead_tokens: int | None = None,
) -> StepEstimate:
    """Estimate one plan step's tokens and dollars before running it.

    Input tokens are ``len(text)//4`` (the repo heuristic) plus
    :data:`STEP_OVERHEAD_TOKENS` (or ``overhead_tokens`` when given); output
    tokens come from ``expected_output_tokens`` or the per-role
    :data:`ROLE_OUTPUT_TOKENS` table. The model is whatever
    ``llm.model_for_role`` resolves for the role *right now* (env override >
    config > routers > defaults), so the projection prices the same model the
    run would use.
    """
    from ..llm import model_for_role
    role = (role or DEFAULT_STEP_ROLE).strip() or DEFAULT_STEP_ROLE
    overhead = STEP_OVERHEAD_TOKENS if overhead_tokens is None else max(0, int(overhead_tokens))
    in_tokens = len(text or "") // CHARS_PER_TOKEN + overhead
    if expected_output_tokens is None:
        out_tokens = int(ROLE_OUTPUT_TOKENS.get(role, DEFAULT_OUTPUT_TOKENS))
    else:
        out_tokens = max(0, int(expected_output_tokens))
    model = model_for_role(role)
    in_rate, out_rate = _price_for(model)
    dollars = (in_tokens / _MTOK) * in_rate + (out_tokens / _MTOK) * out_rate
    return StepEstimate(
        role=role, model=model, in_tokens=in_tokens, out_tokens=out_tokens, dollars=dollars,
    )


def project_plan(steps: list[dict], *, iterations: int = 1) -> PlanProjection:
    """Project a whole plan: per-step estimates plus iteration-scaled totals.

    ``steps`` are duck-typed dicts: ``{"role": ..., "text": ...}`` with both
    keys optional (missing role -> :data:`DEFAULT_STEP_ROLE`; a step may also
    carry its own ``expected_output_tokens``). ``iterations`` multiplies every
    total — a plan-execute-reflect loop reruns the plan, so 3 reflect passes
    cost ~3x. ``steps`` in the result stay single-iteration so the per-step
    table reads naturally; only the totals and ``by_role`` are scaled.
    """
    iterations = int(iterations)
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    estimates: list[StepEstimate] = []
    for step in steps or []:
        estimates.append(
            estimate_step(
                step.get("role") or DEFAULT_STEP_ROLE,
                step.get("text", ""),
                expected_output_tokens=step.get("expected_output_tokens"),
            )
        )
    total_dollars = sum(e.dollars for e in estimates) * iterations
    total_tokens = sum(e.in_tokens + e.out_tokens for e in estimates) * iterations
    by_role: dict[str, float] = {}
    for e in estimates:
        by_role[e.role] = by_role.get(e.role, 0.0) + e.dollars * iterations
    return PlanProjection(
        steps=estimates, total_dollars=total_dollars, total_tokens=total_tokens,
        by_role=by_role, iterations=iterations,
    )


def compare_against_budget(projection: PlanProjection, budget_dollars: float | None) -> BudgetVerdict:
    """Verdict for a projection against a dollar cap, plus one recommendation.

    OVER when the projection exceeds the budget (a non-positive budget is OVER
    for any projected spend); TIGHT above :data:`TIGHT_FRACTION` (70%) of it —
    headroom matters because these estimates skew low; OK otherwise.
    """
    total = projection.total_dollars
    if budget_dollars is None:
        return BudgetVerdict(
            verdict="OK", recommendation=(
                f"Projected ${total:.4f}; no task-specific spending limit is configured. "
                "Organization allowances and provider controls still apply."
            ), projected_dollars=total, budget_dollars=None,
        )
    budget = float(budget_dollars)
    if total > budget:
        verdict = "OVER"
        rec = (
            f"Projected ${total:.4f} exceeds the ${budget:.2f} budget by "
            f"${total - budget:.4f} — drop steps, reduce iterations, or raise the cap "
            f"before running."
        )
    elif budget > 0 and total > TIGHT_FRACTION * budget:
        verdict = "TIGHT"
        rec = (
            f"Projected ${total:.4f} is {total / budget:.0%} of the ${budget:.2f} budget — "
            f"estimates skew low, so consider cheaper role models or fewer iterations."
        )
    else:
        verdict = "OK"
        rec = f"Projected ${total:.4f} fits comfortably within the ${budget:.2f} budget."
    return BudgetVerdict(
        verdict=verdict, recommendation=rec,
        projected_dollars=total, budget_dollars=budget,
    )


def render(projection: PlanProjection) -> str:
    """Human-readable per-step table plus totals (labeled as estimates)."""
    lines = [
        "Plan cost projection (chars/4 estimate — not a bill)",
        f"{'#':>3}  {'role':<14} {'model':<30} {'in_tok':>9} {'out_tok':>9} {'$':>9}",
    ]
    for i, e in enumerate(projection.steps, 1):
        lines.append(
            f"{i:>3}  {e.role:<14} {e.model:<30} {e.in_tokens:>9,} "
            f"{e.out_tokens:>9,} {e.dollars:>9.4f}"
        )
    mult = f" x{projection.iterations} iterations" if projection.iterations > 1 else ""
    lines.append(
        f"total{mult}: {projection.total_tokens:,} tokens, ${projection.total_dollars:.4f}"
    )
    for role in sorted(projection.by_role):
        lines.append(f"  {role}: ${projection.by_role[role]:.4f}")
    return "\n".join(lines)


__all__ = [
    "CHARS_PER_TOKEN", "STEP_OVERHEAD_TOKENS", "ROLE_OUTPUT_TOKENS",
    "DEFAULT_OUTPUT_TOKENS", "DEFAULT_STEP_ROLE", "TIGHT_FRACTION",
    "StepEstimate", "PlanProjection", "BudgetVerdict",
    "estimate_step", "project_plan", "compare_against_budget", "render",
]
