"""A Shield block must leave a tamper-evident audit trail.

When Shield blocks a goal's input/brief (orchestrator) or a tool call
(agent), the run stops and a ``shield_block`` audit event
(``EventKind.SHIELD_BLOCK``) must be recorded, so a safety denial leaves a
trace in the tamper-evident log. This pins that the orchestrator input
chokepoint records it.
"""
from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


def _verdict(allowed, reasons):
    return types.SimpleNamespace(allowed=allowed, reasons=reasons, severity="high")


class _InputBlockingShield:
    """Blocks any input containing the sentinel; allows everything else."""

    def scan_input(self, text):
        if "BLOCKME" in (text or ""):
            return _verdict(False, ["test-input-policy"])
        return _verdict(True, [])

    def scan_tool_call(self, *a, **k):
        return _verdict(True, [])

    def scan_output(self, text):
        return _verdict(True, [])


def _audit_events(home: Path):
    events = []
    for p in (home / "audit").glob("*.ndjson"):
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


@pytest.mark.asyncio
async def test_shield_input_block_records_audit_event(tmp_path, monkeypatch, fake_llm):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # The module-level audit writer is a process singleton cached across tests;
    # reset it (monkeypatch restores the originals on teardown) so record()
    # resolves THIS test's isolated audit dir rather than a prior test's writer.
    import maverick.audit.writer as _w
    monkeypatch.setattr(_w, "_default", None)
    monkeypatch.setattr(_w, "_defaults", {})
    monkeypatch.setattr("maverick.orchestrator._build_shield",
                        lambda: _InputBlockingShield())
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("please do BLOCKME right now", "")

    out = await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    assert "BLOCKED" in out

    blocks = [e for e in _audit_events(tmp_path) if e.get("kind") == "shield_block"]
    assert blocks, "shield input block left no shield_block audit event"
    assert blocks[0]["stage"] == "input"
    assert "test-input-policy" in blocks[0]["reason"]
