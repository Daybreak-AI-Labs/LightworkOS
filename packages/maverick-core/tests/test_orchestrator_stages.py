"""Lifecycle-stage contracts that must hold before agent work starts."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick import orchestrator


def test_start_limits_stop_before_tenant_admission_when_person_is_over_quota(monkeypatch):
    from maverick import quotas, spending_limits
    from maverick.tenant import registry

    monkeypatch.setattr(quotas, "quotas_enforced", lambda: True)
    monkeypatch.setattr(quotas, "over_quota", lambda principal: "daily cap reached")
    monkeypatch.setattr(spending_limits, "start_refusal", lambda principal: pytest.fail("late check"))
    monkeypatch.setattr(registry, "assert_tenant_active", lambda tenant: pytest.fail("late check"))
    changes = []
    world = SimpleNamespace(set_goal_status=lambda goal_id, status, **kw: changes.append((goal_id, status, kw)))

    reason = orchestrator._check_start_limits(world, SimpleNamespace(), 8, "user:alice")

    assert reason == "daily cap reached"
    assert changes == [(8, "blocked", {"result": "over quota: daily cap reached"})]


def test_start_limits_fail_closed_when_tenant_policy_is_unavailable(monkeypatch):
    from maverick import quotas, spending_limits
    from maverick.tenant import registry

    monkeypatch.setattr(quotas, "quotas_enforced", lambda: False)
    monkeypatch.setattr(spending_limits, "start_refusal", lambda principal: None)

    def fail(_tenant):
        raise RuntimeError("cannot read tenant policy")

    monkeypatch.setattr(registry, "assert_tenant_active", fail)
    changes = []
    world = SimpleNamespace(set_goal_status=lambda goal_id, status, **kw: changes.append((goal_id, status, kw)))

    reason = orchestrator._check_start_limits(world, SimpleNamespace(), 9, "user:alice")

    assert reason.startswith("tenant policy unavailable or inactive:")
    assert changes[0][0:2] == (9, "blocked")
    assert changes[0][2]["result"].startswith("over quota: ")


def test_open_episode_binds_accounting_before_publishing_lifecycle(monkeypatch):
    from maverick import checkpoint

    monkeypatch.setattr(checkpoint, "enabled", lambda: False)
    seen = []
    world = SimpleNamespace(start_episode=lambda goal_id: seen.append(("start", goal_id)) or 17)
    settlement = SimpleNamespace(world=None, episode_id=None, bind_checkpoint=lambda: seen.append(("bind",)))
    lifecycle = SimpleNamespace(episode_id=None)

    episode = orchestrator._open_goal_episode(
        world, SimpleNamespace(), 8, resume=False, resume_episode_id=None,
        settlement=settlement, lifecycle=lifecycle,
    )

    assert episode == 17
    assert seen == [("start", 8), ("bind",)]
    assert settlement.world is world
    assert settlement.episode_id == lifecycle.episode_id == 17


def test_resume_without_checkpoint_requires_unspent_scope_before_execution(monkeypatch):
    from maverick import checkpoint

    monkeypatch.setattr(checkpoint, "enabled", lambda: True)
    checkpointer = SimpleNamespace(orchestrator_for=lambda *a, **kw: None,
                                   latest=lambda *a, **kw: None)
    monkeypatch.setattr(checkpoint, "Checkpointer", lambda world: checkpointer)
    world = SimpleNamespace(start_episode=lambda goal_id: 17)
    settlement = SimpleNamespace(
        world=None, episode_id=None, bind_checkpoint=lambda: None,
        require_unspent_scope=lambda: (_ for _ in ()).throw(RuntimeError("spent")),
    )
    lifecycle = SimpleNamespace(episode_id=None)

    with pytest.raises(RuntimeError, match="spent"):
        orchestrator._open_goal_episode(
            world, SimpleNamespace(), 8, resume=True, resume_episode_id=None,
            settlement=settlement, lifecycle=lifecycle,
        )
    assert lifecycle.episode_id is None


def test_unavailable_domain_cannot_fall_back_to_unrestricted_agent(monkeypatch):
    from maverick import domain

    monkeypatch.setattr(domain, "enabled_domains", dict)
    monkeypatch.setattr(domain, "rejected_workspace_domains", lambda: set())
    monkeypatch.setattr(orchestrator, "_fire_webhook", lambda *a, **kw: None)
    monkeypatch.setattr(orchestrator, "Agent", lambda **kw: pytest.fail("unrestricted fallback"))
    changes = []
    world = SimpleNamespace(set_goal_status=lambda goal_id, status, **kw: changes.append((goal_id, status)))
    lifecycle = SimpleNamespace(end_episode=lambda message, outcome: changes.append((message, outcome)))

    root, profile, refusal = orchestrator._create_root_agent(
        world=world, goal_id=8, ctx=SimpleNamespace(), brief="task", domain="missing",
        resume=False, allowed_suites=None, model_override=None, lifecycle=lifecycle,
    )

    assert root is profile is None
    assert refusal.startswith("no such domain:")
    assert changes[0] == (8, "blocked")
    assert changes[1] == (refusal, "blocked")


def test_output_gate_blocks_before_any_success_publication(monkeypatch):
    from maverick import shield_policy

    monkeypatch.setattr(shield_policy, "shield_required", lambda: False)
    shield = SimpleNamespace(scan_output=lambda text: SimpleNamespace(allowed=False, reasons=["policy"]))
    result = SimpleNamespace(final_patch=None, final="sensitive output")
    changes = []
    world = SimpleNamespace(set_goal_status=lambda goal_id, status, **kw: changes.append((status, kw)))
    lifecycle = SimpleNamespace(end_episode=lambda message, outcome: changes.append((message, outcome)))

    summary, is_patch, refusal = orchestrator._prepare_goal_output(
        result=result, shield=shield, world=world, goal_id=4, brief="brief",
        conversation_id=None, channel=None, root=SimpleNamespace(), lifecycle=lifecycle,
    )

    assert summary == "" and not is_patch
    assert "Output blocked by Shield" in refusal
    assert changes[0][0] == "blocked"
    assert changes[1][1] == "blocked"


def test_cancelled_goal_is_settled_before_agent_output_can_be_published():
    result = SimpleNamespace(stop_kind=None, blocked_on_user=False, error=None)
    world = SimpleNamespace(get_goal=lambda goal_id: SimpleNamespace(status="cancelled"))
    ended = []
    lifecycle = SimpleNamespace(end_episode=lambda message, outcome: ended.append((message, outcome)))

    output = orchestrator._handle_root_result(
        result=result, world=world, goal=SimpleNamespace(), goal_id=4,
        budget=SimpleNamespace(), blackboard=SimpleNamespace(), shield=None,
        channel=None, user_id=None, domain=None, domain_profile=None,
        ctx=SimpleNamespace(), planning_mode=None, lifecycle=lifecycle,
    )

    assert output == "Stopped: this goal was cancelled."
    assert ended == [("cancelled", "interrupted")]
