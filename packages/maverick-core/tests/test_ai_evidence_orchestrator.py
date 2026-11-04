"""End-to-end contracts for the gateway on Lightwork's real output seam."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from maverick import ai_evidence_gateway as gateway
from maverick import orchestrator
from maverick.budget import Budget
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


def _bind_gateway(monkeypatch, tenant: str) -> None:
    monkeypatch.setenv("MAVERICK_EVIDENCE_GATEWAY", "1")
    monkeypatch.setenv("MAVERICK_CLIENT_ID", tenant)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    from maverick import client

    client.reset_client_cache()


def _policy() -> dict:
    return gateway.upsert_policy(
        "default",
        actor="test-policy-admin",
        model_sha256="",
        context_sha256="",
    )


def _final_script(make_llm_response):
    return [
        make_llm_response(text="FINAL: the answer is 42"),
        make_llm_response(
            text=(
                '{"confidence": 0.95, "accepts": true, '
                '"critique": "ok", "issues": []}'
            ),
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]


@pytest.mark.asyncio
async def test_normal_goal_output_is_evidence_ready_before_any_delivery(
    tmp_path: Path,
    monkeypatch,
    fake_llm,
    make_llm_response,
):
    _bind_gateway(monkeypatch, "orchestrator-tenant")
    _policy()
    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("compute the answer", "trivial")

    output = await orchestrator.run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=goal_id,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
        channel="dashboard",
        conversation_id=19,
    )

    goal = world.get_goal(goal_id)
    assert goal is not None
    assert goal.status == "done"
    assert gateway.DEFAULT_DISCLOSURE_TEXT in output
    assert gateway.DEFAULT_DISCLOSURE_TEXT in str(goal.result)
    assert "the answer is 42" in output
    receipts = gateway.list_interaction_receipts(limit=10)
    assert len(receipts) == 1
    assert (
        receipts[0]["signed_receipt"]["tenant_id"]
        == "orchestrator-tenant"
    )
    assert receipts[0]["conversation_sha256"] == hashlib.sha256(
        b"dashboard:19"
    ).hexdigest()
    # Live event feeds are externally visible.  When the gateway is enabled,
    # internal model excerpts remain in memory for agents but their mirrors are
    # withheld until the final receipted output is committed.
    event_content = "\n".join(event.content for event in world.goal_events(goal_id))
    assert "the answer is 42" not in event_content
    assert "evidence-ready result" in event_content


@pytest.mark.asyncio
async def test_disabled_gateway_preserves_legacy_goal_output(
    tmp_path: Path,
    monkeypatch,
    fake_llm,
    make_llm_response,
):
    monkeypatch.setenv("MAVERICK_EVIDENCE_GATEWAY", "0")
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("compute the answer", "trivial")

    output = await orchestrator.run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=goal_id,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "the answer is 42" in output
    assert gateway.DEFAULT_DISCLOSURE_TEXT not in output
    assert world.get_goal(goal_id).status == "done"
    event_content = "\n".join(event.content for event in world.goal_events(goal_id))
    assert "the answer is 42" in event_content


@pytest.mark.asyncio
async def test_first_goal_in_a_tenant_is_delivered_without_operator_setup(
    tmp_path: Path,
    monkeypatch,
    fake_llm,
    make_llm_response,
):
    """The production failure: a tenant whose operator never published a
    policy.  The goal completes disclosed and receipted instead of parking
    on "policy 'default' does not exist"."""
    _bind_gateway(monkeypatch, "fresh-tenant")
    assert gateway.get_policy("default") is None
    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("compute the answer", "trivial")

    output = await orchestrator.run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=goal_id,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
        channel="dashboard",
        conversation_id=20,
    )

    goal = world.get_goal(goal_id)
    assert goal is not None
    assert goal.status == "done"
    assert gateway.DEFAULT_DISCLOSURE_TEXT in output
    assert "the answer is 42" in output
    assert "does not exist" not in str(goal.result)
    assert gateway.get_policy("default")["revision"] == 1
    assert gateway._receipt_ledger().state().total_receipts == 1


@pytest.mark.asyncio
async def test_gateway_refusal_blocks_goal_without_releasing_generated_text(
    tmp_path: Path,
    monkeypatch,
    fake_llm,
    make_llm_response,
):
    _bind_gateway(monkeypatch, "refusal-tenant")
    # A tenant with no policy is provisioned one on first delivery, so a
    # refusal needs the gateway itself to refuse: here the tenant's policy
    # cannot be provisioned (the same state error a mode-locked namespace
    # raises), which must block the goal without releasing the answer.
    def refuse(*args, **kwargs):
        raise gateway.EvidenceGatewayStateError(
            "AI evidence policy tenant mode failed validation"
        )

    monkeypatch.setattr(gateway, "upsert_policy", refuse)
    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    goal_id = world.create_goal("compute the answer", "trivial")

    output = await orchestrator.run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=goal_id,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    goal = world.get_goal(goal_id)
    assert goal is not None
    assert goal.status == "blocked"
    assert "gateway withheld" in output
    assert "the answer is 42" not in output
    assert "the answer is 42" not in str(goal.result)
    event_content = "\n".join(event.content for event in world.goal_events(goal_id))
    assert "the answer is 42" not in event_content
    assert gateway._receipt_ledger().state().total_receipts == 0


def test_output_seam_retry_deduplicates_and_tenants_remain_isolated(
    monkeypatch,
):
    receipt_ids: list[str] = []
    for tenant in ("tenant-alpha", "tenant-beta"):
        _bind_gateway(monkeypatch, tenant)
        _policy()
        first = orchestrator._evidence_ready_goal_output(
            "Generated result.",
            brief="User brief.",
            goal_id=7,
            conversation_id=3,
            channel="chat",
            model="provider:model",
        )
        replay = orchestrator._evidence_ready_goal_output(
            "Generated result.",
            brief="User brief.",
            goal_id=7,
            conversation_id=3,
            channel="chat",
            model="provider:model",
        )
        assert replay == first
        rows = gateway.list_interaction_receipts(limit=10)
        assert len(rows) == 1
        assert rows[0]["signed_receipt"]["tenant_id"] == tenant
        receipt_ids.append(rows[0]["receipt_id"])

    assert receipt_ids[0] != receipt_ids[1]
