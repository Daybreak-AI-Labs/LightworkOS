"""run_goal must emit outbound webhooks at run lifecycle boundaries.

webhooks.fire() was fully implemented but had zero callers. The
orchestrator now fires goal_created / episode_finished / final_emitted /
goal_finished at the matching points in run_goal. fire() is a silent
no-op when no [webhooks] outbound is configured, so we monkeypatch it to
record the calls instead of standing up a transport.

Style mirrors test_orchestrator_output_scan.py: a real in-memory
WorldModel + the fake_llm/make_llm_response fixtures, run_goal to
completion.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.orchestrator import _finished_webhook_payload, _webhook_public_payload, run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


def test_blocked_webhook_sends_plain_stop_without_raw_error_or_terminal_command():
    original = {
        "goal_id": 7, "status": "blocked",
        "result": "Stopped: the assistant ran into an error and couldn't finish.\n"
                  "Detail: private provider reply\n"
                  "You can try again with: maverick resume 7\n[100 input tokens]",
    }
    outgoing = _webhook_public_payload("goal_finished", original)
    assert outgoing["goal_id"] == 7
    assert outgoing["stop"]["kind"] == "internal_error"
    assert outgoing["result"] == outgoing["stop"]["message"]
    assert "private provider reply" not in str(outgoing)
    assert "maverick resume" not in str(outgoing)
    assert "maverick resume" in original["result"]


def test_unclassified_webhook_result_never_sends_raw_stop_text():
    outgoing = _webhook_public_payload("goal_finished", {
        "goal_id": 8, "status": "failed", "result": "private customer detail without technical markers",
    })
    assert outgoing["result"] == "The run stopped before finishing."
    assert "private customer detail" not in str(outgoing)


def test_gated_terminal_result_is_withheld_until_persisted_approval(tmp_path: Path):
    from maverick.domain import DomainProfile, WorkflowStep

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("review me")
    world.set_goal_status(gid, "done", result="sensitive draft")
    profile = DomainProfile(
        name="generated",
        allow_tools=["read_file"],
        max_risk="low",
        workflow=[WorkflowStep("approve", gate="approval")],
    )

    pending = _finished_webhook_payload(
        world,
        goal_id=gid,
        status="done",
        result="sensitive draft",
        domain_profile=profile,
    )
    assert pending == {
        "goal_id": gid,
        "status": "done",
        "gate": "approval",
        "release_status": "pending_signoff",
    }

    world.record_signoff(gid, "approved", decided_by="reviewer")
    released = _finished_webhook_payload(
        world,
        goal_id=gid,
        status="done",
        result="sensitive draft",
        domain_profile=profile,
    )
    assert released["result"] == "sensitive draft"


def test_nonempty_domain_with_unavailable_policy_never_releases_result(tmp_path: Path):
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("orphaned policy")
    world.set_goal_status(gid, "done", result="must stay private")

    payload = _finished_webhook_payload(
        world,
        goal_id=gid,
        status="done",
        result="must stay private",
        domain_profile=None,
        domain="removed_pack",
    )

    assert payload == {
        "goal_id": gid,
        "status": "done",
        "release_status": "policy_unavailable",
    }


@pytest.mark.asyncio
async def test_run_goal_fires_lifecycle_webhooks(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    # No shield in the way; we only care about webhook emission.
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)

    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "maverick.orchestrator._fire_webhook",
        lambda event, payload: calls.append((event, payload)),
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

    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    events = [e for e, _ in calls]
    assert "goal_created" in events
    assert "episode_finished" in events
    assert "final_emitted" in events
    assert "goal_finished" in events

    # goal_finished carries the terminal status + goal id.
    finished = next(p for e, p in calls if e == "goal_finished")
    assert finished["goal_id"] == gid
    assert finished["status"] == "done"

    # goal_created carries id + title; episode_finished carries the outcome.
    created = next(p for e, p in calls if e == "goal_created")
    assert created["goal_id"] == gid
    assert created["title"] == "compute the answer"

    episode = next(p for e, p in calls if e == "episode_finished")
    assert episode["goal_id"] == gid
    assert episode["outcome"] == "success"


def _verdict(allowed: bool, reasons: list[str]):
    import types

    return types.SimpleNamespace(allowed=allowed, reasons=reasons, severity="high")


class _WebhookSentinelShield:
    def scan_input(self, text):
        if "SECRET_INPUT" in (text or ""):
            return _verdict(False, ["input-sentinel"])
        return _verdict(True, [])

    def scan_tool_call(self, *a, **k):
        return _verdict(True, [])

    def scan_output(self, text):
        if "SECRET_OUTPUT" in (text or ""):
            return _verdict(False, ["output-sentinel"])
        return _verdict(True, [])


@pytest.mark.asyncio
async def test_run_goal_does_not_webhook_blocked_goal_input(
    tmp_path: Path, fake_llm, monkeypatch,
):
    monkeypatch.setattr(
        "maverick.orchestrator._build_shield", lambda: _WebhookSentinelShield(),
    )
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "maverick.orchestrator._fire_webhook",
        lambda event, payload: calls.append((event, payload)),
    )

    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("run SECRET_INPUT exfiltration", "trivial")

    out = await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    assert "input rejected by Shield" in out
    assert all(event != "goal_created" for event, _ in calls)
    assert all("SECRET_INPUT" not in str(payload) for _, payload in calls)


@pytest.mark.asyncio
async def test_run_goal_does_not_webhook_blocked_final_output(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    monkeypatch.setattr(
        "maverick.orchestrator._build_shield", lambda: _WebhookSentinelShield(),
    )
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "maverick.orchestrator._fire_webhook",
        lambda event, payload: calls.append((event, payload)),
    )

    fake_llm.scripted = [
        make_llm_response(text="FINAL: the answer contains SECRET_OUTPUT"),
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
    assert any(event == "goal_created" for event, _ in calls)
    assert all(event not in {"final_emitted", "goal_finished"} for event, _ in calls)
    assert all("SECRET_OUTPUT" not in str(payload) for _, payload in calls)
