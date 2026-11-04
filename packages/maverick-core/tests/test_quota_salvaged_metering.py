"""Quota metering on the *salvaged-patch* completion path.

``orchestrator.run_goal`` records each run's spend to the principal's daily
usage ledger via the ``_record_quota_usage`` helper, which every terminal path
calls. The salvaged-patch branch -- the success-ish path inside
``if result.error:`` that returns a usable ``result.final_patch`` despite the
agent erroring (e.g. it hit max_steps but had already written a diff via
str_replace_editor) -- must charge the ledger too, or that spend escapes the
quota accounting. This test pins the metering on that specific branch, so a
future refactor of it cannot silently drop the charge.

Hermetic, mirroring tests/test_quota_enforcement.py (FakeLLM + tmp world db +
LocalBackend + real UsageLedger under the per-test isolated ``~/.maverick``).
The salvaged branch is reached by monkeypatching ``Agent.run`` to return an
``AgentResult`` whose ``error`` is set AND whose ``final_patch`` looks like a
diff -- the exact shape the orchestrator salvages -- the same way the
failed-run tests drive the other error paths. No network.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel

# A minimal-but-valid unified diff: contains both ``diff --git`` and ``--- a/``
# so it satisfies the salvage branch's ``result.final_patch and (...)`` guard.
_SALVAGED_PATCH = (
    "diff --git a/hello.py b/hello.py\n"
    "--- a/hello.py\n"
    "+++ b/hello.py\n"
    "@@ -1 +1 @@\n"
    "-print('hi')\n"
    "+print('hello')\n"
)


@pytest.fixture(autouse=True)
def _clear_quota_env(monkeypatch):
    """Isolate quota state and explicitly estimate the synthetic test model."""
    for env in (
        "MAVERICK_QUOTA_ENFORCE",
        "MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY",
        "MAVERICK_QUOTA_MAX_TOKENS_PER_DAY",
        "MAVERICK_TENANT",
    ):
        monkeypatch.delenv(env, raising=False)
    # ``fake:test`` intentionally has no vendor evidence.  Estimate-only mode
    # is explicit here so the suite exercises quota metering without weakening
    # the strict-by-default production accounting path.
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")


def _spy_record_usage(monkeypatch) -> list[tuple]:
    """Spy on ``quotas.record_usage`` while still hitting the real ledger.

    The orchestrator does ``from . import quotas; quotas.record_usage(...)``,
    so patch the function on the module it resolves (matches
    test_quota_enforcement.py::test_quotas_off_run_proceeds_and_records_usage).
    """
    import maverick.quotas as q
    recorded: list[tuple] = []
    real = q.record_usage
    monkeypatch.setattr(
        q, "record_usage",
        lambda *a, **k: (recorded.append((a, k)), real(*a, **k))[1],
    )
    return recorded


@pytest.mark.asyncio
async def test_salvaged_patch_path_records_usage(
    tmp_path: Path, fake_llm, monkeypatch,
):
    # Drive the salvaged-patch branch: the agent spends paid tokens, then
    # returns an error result that nonetheless carries a usable diff. The
    # orchestrator marks the goal done, returns the patch -- and must charge
    # that spend to the ledger so it doesn't escape the quota accounting.
    from maverick.agent import Agent, AgentResult

    calls = 0

    async def spend_then_salvage(self):
        nonlocal calls
        calls += 1
        self.ctx.budget.record_tokens(120, 40, model="fake:test")
        return AgentResult(
            error="max_steps exceeded",
            final_patch=_SALVAGED_PATCH,
            role=self.role,
            name=self.name,
        )

    monkeypatch.setattr(Agent, "run", spend_then_salvage)
    recorded = _spy_record_usage(monkeypatch)

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("salvage a patch", "trivial")
    budget = Budget(max_dollars=1.0)

    out = await run_goal(
        llm=fake_llm,
        world=world,
        budget=budget,
        goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    # The salvaged patch is returned as-is and the goal is marked done.
    assert out == _SALVAGED_PATCH
    assert world.get_goal(gid).status == "done"
    assert calls == 1

    # Metering fired exactly once on this path, with this run's principal and
    # final budget totals -- the spend that would otherwise escape.
    assert len(recorded) == 1
    (args, _kwargs) = recorded[0]
    assert args[0] == "user:local"
    assert args[1:] == (budget.dollars, budget.input_tokens, budget.output_tokens)


@pytest.mark.asyncio
async def test_salvaged_patch_spend_advances_ledger_and_gates_next_run(
    tmp_path: Path, fake_llm, monkeypatch,
):
    # End-to-end proof: with enforcement on, the salvaged run's token spend must
    # land in the real ledger so a second run is refused by the quota gate
    # instead of spending again. This is the user-visible point of metering the
    # salvaged path -- a "success" that errored still counts against the cap.
    from maverick.agent import Agent, AgentResult
    from maverick.quotas import UsageLedger, over_quota

    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    monkeypatch.setenv("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY", "100")

    calls = 0

    async def spend_then_salvage(self):
        nonlocal calls
        calls += 1
        self.ctx.budget.record_tokens(80, 50, model="fake:test")
        return AgentResult(
            error="max_steps exceeded",
            final_patch=_SALVAGED_PATCH,
            role=self.role,
            name=self.name,
        )

    monkeypatch.setattr(Agent, "run", spend_then_salvage)

    world = WorldModel(path=tmp_path / "world.db")
    gid1 = world.create_goal("salvage then exceed", "trivial")
    out1 = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid1,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert out1 == _SALVAGED_PATCH
    assert world.get_goal(gid1).status == "done"
    usage = UsageLedger().usage("user:local")
    assert usage["in_tokens"] == 80
    assert usage["out_tokens"] == 50
    assert over_quota("user:local") is not None

    # The next run for the same principal is refused before the agent loop.
    gid2 = world.create_goal("try again", "trivial")
    out2 = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid2,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "quota" in out2
    assert world.get_goal(gid2).status == "blocked"
    assert calls == 1  # the second run never reached the (patched) agent


@pytest.mark.asyncio
async def test_primary_path_still_records_usage(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    # Guard the primary FINAL path metering too, so a refactor of the shared
    # helper can't silently drop the normal-completion case while fixing the
    # salvaged one. Mirrors test_quota_enforcement.py's off-by-default case.
    recorded = _spy_record_usage(monkeypatch)

    fake_llm.scripted = [
        make_llm_response(text="FINAL: the answer is 42"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")
    budget = Budget(max_dollars=1.0)

    out = await run_goal(
        llm=fake_llm,
        world=world,
        budget=budget,
        goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "DONE." in out
    assert world.get_goal(gid).status == "done"
    assert len(recorded) == 1
    (args, _kwargs) = recorded[0]
    assert args[0] == "user:local"
    assert args[1:] == (budget.dollars, budget.input_tokens, budget.output_tokens)
