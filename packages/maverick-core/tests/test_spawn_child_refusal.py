"""A helper that ends without an answer still tells its parent what a person
refused, so the parent's answer and its verifier can rely on it."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from maverick.agent import AgentResult, _is_refusal
from maverick.tools.spawn import _run_child_and_report
from maverick.world_model import WorldModel

REJECTED = ("tool=shell -> <tool_output tool='shell' id=ab12>\nERROR: shell command was not "
            "approved: a person rejected it, so no command was run. Do not ask to run it "
            "again.\n</tool_output ab12>")


def _parent_and_child(tmp_path, *, final=None):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("Run hostname", "")
    world.append_event(gid, "researcher-1-854", "observation", REJECTED)
    world.append_event(gid, "analyst-1-111", "observation",
                       "tool=shell -> <tool_output tool='shell' id=cd>\nERROR: shell command was "
                       "not approved: nobody approved it in time\n</tool_output cd>")
    released = []
    ctx = SimpleNamespace(world=world, goal_id=gid, quarantine=None, ifc=None,
                          release_spawns=released.append)
    parent = SimpleNamespace(ctx=ctx, name="orchestrator-0-f")

    async def run():
        return AgentResult(final=final, role="researcher", name="researcher-1-854")

    child = SimpleNamespace(name="researcher-1-854", role="researcher", run=run)
    return world, parent, child


def test_a_helper_with_no_answer_reports_the_refusal_it_got(tmp_path):
    # Seen live: the helper got "a person rejected it" and ended with an empty
    # answer; the parent saw only "finished without final answer: unknown",
    # and the verifier rejected the parent's correct answer as unsupported.
    world, parent, child = _parent_and_child(tmp_path)
    out = asyncio.run(_run_child_and_report(parent, child))
    assert out.startswith("ERROR: child finished without final answer")
    assert "a person rejected it, so no command was run" in out
    assert "nobody approved it in time" not in out  # another helper's refusal
    assert "<tool_output" not in out
    framed = f"<tool_output tool='spawn_subagent' id=ff>\n{out}\n</tool_output ff>"
    assert _is_refusal(framed)  # the parent's verifier counts it as evidence
    world.close()


def test_a_helper_answer_is_returned_unchanged(tmp_path):
    world, parent, child = _parent_and_child(tmp_path, final="The command was not run.")
    assert asyncio.run(_run_child_and_report(parent, child)) == "The command was not run."
    world.close()
