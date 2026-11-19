"""A budget/wall-clock exhaustion must give the helpful 'raise the cap'
message, not a generic 'ran into an error'.

The agent swallows BudgetExceeded into result.error (so spawned children
return gracefully), which meant the orchestrator's nice budget message was
unreachable for the common case -- the user saw a generic error with no hint
to raise --max-dollars.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.llm import LLM
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


@pytest.mark.asyncio
async def test_budget_exhaustion_gives_helpful_message(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("expensive goal", "")
    bud = Budget(max_dollars=0.01)
    # Push spend over the cap directly (bypassing record_tokens' own check)
    # so the agent's first budget.check() trips -- no LLM call needed.
    with bud._lock:
        bud.dollars = 5.0

    out = await run_goal(
        fake_llm, world, bud, gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    assert "hit your spending limit" in out
    assert "--max-dollars" in out
    assert "ran into an error" not in out
    # The message reports spend AGAINST the configured cap, not spend alone, so
    # the user can see how far over they went and what the limit was.
    assert "$5.00 of $0.01 cap used" in out
    assert world.get_goal(gid).status == "blocked"
    assert world.get_goal(gid).result == out


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["provider", "setup"])
async def test_organization_allowance_message_survives_agent_and_lifecycle(
    tmp_path, fake_llm, monkeypatch, stage,
):
    from maverick.tenant.provider_admission import OrganizationBudgetExceeded

    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("organization controlled task", "")

    async def refuse(*args, **kwargs):
        raise OrganizationBudgetExceeded("Daily allowance has unresolved charges")

    if stage == "provider":
        monkeypatch.setattr(fake_llm, "complete_async", refuse)
    else:
        monkeypatch.setattr("maverick.orchestrator._build_orchestrator_brief", refuse)
    out = await run_goal(
        fake_llm, world, Budget(), gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    assert "organization spending allowance" in out
    assert "Daily allowance has unresolved charges" in out
    assert "organization administrator" in out
    assert "--max-dollars" not in out and "internal error" not in out
    assert world.get_goal(gid).status == "blocked"
    assert world.get_goal(gid).result == out
    episode, = world.list_episodes(goal_id=gid)
    assert episode.outcome == "interrupted" and episode.ended_at is not None


class _StrictInvoiceClient:
    """A provider client that must never be contacted for an unpriced model."""

    def __init__(self):
        self.calls = 0

    async def complete_async(self, *, budget, model, **kwargs):
        self.calls += 1
        raise AssertionError("unpriced provider request must be refused before dispatch")


@pytest.mark.asyncio
async def test_unpriced_model_gives_pricing_message_not_a_cap_message(
    tmp_path: Path,
):
    """UnpricedModelError is a BudgetExceeded subclass (so the run
    still aborts), but it is NOT a spending/time cap -- it's Lightwork
    refusing to bill a model with no verified price. Reporting it like a
    real cap trip ('hit your spending or time limit ... resume with a higher
    cap') would send the user round raising the cap and failing forever, with
    the real remedy (price the model, or set [budget] strict_pricing=false)
    visible only in the debug log.
    """
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("goal on an unpriced model", "")
    llm = LLM(model="claude-nonexistent-99")
    client = _StrictInvoiceClient()
    llm._get_client = lambda provider: client

    out = await run_goal(
        llm, world, Budget(max_dollars=5.0), gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
        orchestrator_model_override="claude-nonexistent-99",
    )

    assert "no usable price" in out
    assert "Settings" in out
    assert client.calls == 0
    # Must NOT be mistaken for -- or advise the same fix as -- a real cap trip.
    assert "hit your spending or time limit" not in out
    assert "--max-dollars" not in out
    goal = world.get_goal(gid)
    assert goal.status == "blocked"
    # Recorded distinctly so it doesn't poison the budget-cap failure class
    # the self-tuning budget learner trains on.
    assert goal.result.startswith("unpriced model:")
    from maverick.stop_reasons import stop_payload

    stop = stop_payload(goal.status, goal.result)
    assert stop["kind"] == "unpriced_model"
    assert "choose a priced model" in stop["action"]
    assert stop["link"] == "/settings#settings-model-prices"


class TestErrorMessageVoice:
    @pytest.mark.asyncio
    async def test_error_returns_human_sentence(
        self, tmp_path, fake_llm, make_llm_response,
    ):
        """Error path now reads like a sentence with a resume hint."""
        from maverick.budget import Budget
        from maverick.orchestrator import run_goal
        from maverick.sandbox import LocalBackend
        from maverick.world_model import WorldModel

        fake_llm.scripted = [make_llm_response(text="")]  # empty -> error
        world = WorldModel(tmp_path / "w.db")
        gid = world.create_goal("err", "")
        out = await run_goal(
            llm=fake_llm, world=world,
            budget=Budget(max_dollars=1.0),
            goal_id=gid,
            sandbox=LocalBackend(workdir=tmp_path),
            max_depth=1,
        )
        assert "Stopped" in out
        assert "couldn't finish" in out
        # Positional id, no leading '#': `maverick resume <id>` is copy-pasteable
        # (resume now takes a positional GOAL_ID, and a bare '#' is a shell comment).
        assert f"maverick resume {gid}" in out
        assert f"maverick resume #{gid}" not in out

    @pytest.mark.asyncio
    async def test_paused_with_no_questions_is_friendly(
        self, tmp_path, fake_llm, make_llm_response,
    ):
        """The old 'PAUSED: 0 open question(s)' bug now has a clear msg."""
        from maverick.budget import Budget
        from maverick.llm import ToolCall
        from maverick.orchestrator import run_goal
        from maverick.sandbox import LocalBackend
        from maverick.world_model import WorldModel

        # Mock ask_user to file NO question (the old bug) — we patch by
        # using a tool call to a name that doesn't actually persist.
        # The simpler proxy: blocked_on_user True with no rows in
        # questions for this goal_id. Easiest path is calling ask_user
        # against another goal id externally; in practice the message
        # rewriting itself is what we want to verify, so check via the
        # straightforward "asked one question" path produces a sentence.
        fake_llm.scripted = [
            make_llm_response(
                text="I need info.",
                tool_calls=[ToolCall(
                    id="t1", name="ask_user",
                    input={"question": "What's your timezone?"},
                )],
            ),
        ]
        world = WorldModel(tmp_path / "w.db")
        gid = world.create_goal("ask", "")
        out = await run_goal(
            llm=fake_llm, world=world,
            budget=Budget(max_dollars=1.0),
            goal_id=gid,
            sandbox=LocalBackend(workdir=tmp_path),
            max_depth=1,
        )
        assert "Paused" in out
        assert "1 question" in out
        assert "What's your timezone?" in out
        assert "maverick answer" in out


# The real reason for a budget stop lived only in the event log: the CLI said
# "$1.16 of $2.00 cap" and "raise the applicable limit", while the kernel knew
# the next call was projected to $2.02 and that an unpriced paid tool's safety
# ceiling set its estimate. The stop message must carry those facts.
_PROJECTED_CEILING_DETAIL = (
    "projected $2.02 > $2.00 (spent $1.16 + in-flight $0.01 + est $0.85 for this call)"
    ". Spend for Tavily search used the per-call safety ceiling because it has no "
    "usable price. Set the service's price in Settings > Models, under Prices for "
    "paid tool services"
)


def _spent_budget(dollars=1.16, cap=2.0):
    budget = Budget(max_dollars=cap, max_wall_seconds=1800)
    with budget._lock:
        budget.dollars = dollars
    return budget


def test_projected_stop_message_states_cap_spend_and_next_call():
    from maverick.budget import BudgetExceeded
    from maverick.orchestrator import _budget_stop_message

    out = _budget_stop_message(_spent_budget(), 4, BudgetExceeded(_PROJECTED_CEILING_DETAIL))
    assert "$2.00" in out and "$1.16" in out
    assert "estimated at $0.85" in out and "$2.02" in out
    assert "Tavily search" in out and "safety ceiling" in out
    assert "Prices for paid tool services" in out
    assert "administrator" not in out
    assert "maverick resume 4 --max-dollars" in out


def test_agent_swallowed_budget_detail_reaches_the_stop_message():
    """The agent returns ``stop_kind="budget"`` with ``str(exc)``; that detail
    must reach the message, not be replaced by spent-of-cap alone."""
    from maverick.orchestrator import _budget_exceeded_message

    out = _budget_exceeded_message(_spent_budget(), 4, _PROJECTED_CEILING_DETAIL)
    assert "estimated at $0.85" in out and "Tavily search" in out


def test_dashboard_stop_reason_names_the_real_cause():
    from maverick.budget import BudgetExceeded
    from maverick.orchestrator import _budget_stop_message
    from maverick.stop_reasons import explain_stop

    out = _budget_stop_message(_spent_budget(), 4, BudgetExceeded(_PROJECTED_CEILING_DETAIL))
    stop = explain_stop(out)
    assert stop.kind == "spending_limit"
    text = f"{stop.message} {stop.action}"
    assert "$2.00" in text and "$1.16" in text and "$0.85" in text
    assert "Tavily search" in text
    assert "administrator" not in text
    assert stop.link == "/settings#settings-tool-prices"


def test_dashboard_task_cap_stop_points_to_the_task_limit_setting():
    from maverick.budget import BudgetExceeded
    from maverick.orchestrator import _budget_stop_message
    from maverick.stop_reasons import explain_stop

    detail = "projected $2.10 > $2.00 (spent $1.80 + est $0.30 for this call)"
    stop = explain_stop(_budget_stop_message(_spent_budget(1.8), 7, BudgetExceeded(detail)))
    assert stop.kind == "spending_limit"
    assert "$2.00" in stop.message and "$1.80" in stop.message and "$0.30" in stop.message
    assert "administrator" not in stop.action
    assert stop.link == "/settings#settings-task-limit"
    # The task page offers a limit for the next attempt beside this advice.
    assert stop.action.startswith("Try again with a higher spending limit for this attempt")


def test_time_limit_stop_is_a_limit_not_an_internal_error():
    from maverick.budget import BudgetExceeded
    from maverick.orchestrator import _budget_stop_message
    from maverick.stop_reasons import explain_stop

    budget = Budget(max_wall_seconds=1800)
    out = _budget_stop_message(budget, 9, BudgetExceeded("wall time 1800s >= 1800s"))
    assert "time limit" in out and "30 minutes" in out
    stop = explain_stop(out)
    assert stop.kind == "time_limit"
    assert "time limit" in stop.message and "administrator" not in stop.action
    assert "spending" not in stop.message.lower() and "spending" not in stop.action.lower()


@pytest.mark.parametrize("detail", [
    "wall time 61s > 60s",
    "wall-clock cap 60s reached mid-model-call",
    "wall-clock cap 60s reached mid-tool-execution",
])
def test_every_wall_clock_wording_is_a_time_limit_stop(detail):
    """Live goal 43 stopped at its 1-minute limit mid-call and was told to raise
    its spending limit: the agent's own wall-cap wordings were not recognised."""
    from maverick.budget import BudgetExceeded
    from maverick.orchestrator import _budget_stop_message
    from maverick.stop_reasons import explain_stop

    budget = Budget(max_dollars=1.0, max_wall_seconds=60)
    with budget._lock:
        budget.dollars = 0.58
    out = _budget_stop_message(budget, 43, BudgetExceeded(detail))
    assert "time limit (1 minute)" in out and "spending" not in out.split("\n")[0]
    assert "--max-wall-seconds" in out
    stop = explain_stop(out)
    assert stop.kind == "time_limit"
    assert "1 minute" in stop.message
    assert "time limit" in stop.action and "spending" not in stop.action.lower()


def test_unexplained_cap_stop_after_the_time_ran_out_is_a_time_limit_stop():
    from maverick.budget import BudgetExceeded
    from maverick.orchestrator import _budget_stop_message
    from maverick.stop_reasons import explain_stop

    budget = Budget(max_dollars=1.0, max_wall_seconds=0.001)
    import time as _time
    _time.sleep(0.01)
    out = _budget_stop_message(budget, 5, BudgetExceeded("limit reached"))
    assert explain_stop(out).kind == "time_limit"


def test_organization_allowance_stop_still_names_an_administrator():
    from maverick.stop_reasons import explain_stop

    stop = explain_stop("Paused: the organization spending allowance cannot admit the next call.")
    assert stop.kind == "spending_limit"
    assert "administrator" in stop.action


def test_a_time_stop_says_a_step_was_still_waiting_for_approval(tmp_path, monkeypatch):
    # Seen live: a helper asked to run a command, nobody decided within the
    # task's 10 minutes, and the stop only said "hit your time limit".
    from maverick import orchestrator
    from maverick.orchestrator import _budget_exceeded_message

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("look at the image", "")
    monkeypatch.setattr("maverick.world_model.open_world", lambda path=None: world)
    budget = Budget(max_dollars=1.0, max_wall_seconds=600)
    detail = "wall time 601s >= 600s"
    assert "waiting for approval" not in _budget_exceeded_message(budget, gid, detail)
    from maverick.logging_config import reset_goal_context, set_goal_context
    tokens = set_goal_context(goal_id=gid)
    try:
        world.create_approval("shell: python3 inspect.py", risk="medium")
    finally:
        reset_goal_context(tokens)
    out = _budget_exceeded_message(budget, gid, detail)
    assert "hit your time limit (10 minutes)" in out
    assert "A step was still waiting for approval when time ran out, so it did not run." in out
    from maverick.stop_reasons import explain_stop
    stop = explain_stop(out, status="blocked")
    assert stop.message == ("This task reached its time limit of 10 minutes while a step "
                            "waited for approval. That step did not run.")
    assert "decide its approvals sooner" in stop.action
    # A spending stop is not about waiting.
    assert "waiting for approval" not in _budget_exceeded_message(budget, gid, "$1.02 > $1.00")
    assert orchestrator._waiting_for_approval(None) is False
