"""run_goal must scan the FINAL answer before returning it.

The shield's output chokepoint must not exist only on the channel server
path (server._handle_message): direct callers -- `maverick start` / `chat` /
`resume` and the dashboard REST API -- would then get run_goal's raw answer
with no scan_output, contradicting docs/safety.md. run_goal scans the prose
summary itself so every caller is covered.

We monkeypatch _build_shield with a sentinel shield that blocks only an
output containing "BLOCKME" (so intermediate tool-output / input scans
still pass) and put the sentinel in the agent's FINAL.
"""
from __future__ import annotations

import types
from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.orchestrator import _safe_exception_text, run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


def _verdict(allowed: bool, reasons):
    return types.SimpleNamespace(allowed=allowed, reasons=reasons, severity="high")


class _SentinelShield:
    """Allows everything except an OUTPUT containing the sentinel."""

    def scan_input(self, text):
        return _verdict(True, [])

    def scan_tool_call(self, *a, **k):
        return _verdict(True, [])

    def scan_output(self, text):
        if "BLOCKME" in (text or ""):
            return _verdict(False, ["test-policy"])
        return _verdict(True, [])


def test_orchestrator_exception_text_redacts_lightwork_capabilities():
    rest_token = "lw-rest-" + "A" * 43
    flow_token = "eyJ" + "B" * 32 + "." + "c" * 64

    result = _safe_exception_text(
        RuntimeError(f"request {rest_token} approval {flow_token}"),
        fallback="run failed",
    )

    assert rest_token not in result
    assert flow_token not in result
    assert "REDACTED:lightwork_agent_token" in result
    assert "REDACTED:lightwork_flow_approval_token" in result


@pytest.mark.asyncio
async def test_run_goal_blocks_flagged_final_answer(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    monkeypatch.setattr(
        "maverick.orchestrator._build_shield", lambda: _SentinelShield(),
    )
    fake_llm.scripted = [
        make_llm_response(text="FINAL: the answer is 42 BLOCKME"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")

    out = await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    assert "Output blocked by Shield" in out
    assert "test-policy" in out
    # The flagged answer text must be withheld, not handed back.
    assert "the answer is 42" not in out


@pytest.mark.asyncio
async def test_run_goal_returns_clean_answer_unblocked(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    # Same shield, but the FINAL has no sentinel -> normal answer flows.
    monkeypatch.setattr(
        "maverick.orchestrator._build_shield", lambda: _SentinelShield(),
    )
    fake_llm.scripted = [
        make_llm_response(text="FINAL: the answer is 42"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")

    out = await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    assert "Output blocked" not in out
    assert "the answer is 42" in out
