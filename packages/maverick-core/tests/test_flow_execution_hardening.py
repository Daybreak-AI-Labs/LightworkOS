"""Regression coverage for durable, fail-closed flow execution boundaries."""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time

import pytest
from maverick.flow import evolution_log, execution, node_outcomes, node_tools, store
from maverick.flow.ir import (
    NODE_ACTION,
    NODE_APPROVAL,
    Flow,
    FlowNode,
    ensure_high_risk_approvals,
)
from maverick.flow.runner import (
    ACTIVE_STATUSES,
    QUARANTINED_STATUSES,
    STATUS_CLAIMED,
    STATUS_INDETERMINATE,
    STATUS_RESUMING,
    STATUS_RUNNING,
)


def _patch_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))


def _noop_agent(brief, data):
    return ("ok", 1.0)


def _approval_binding(run, *, inputs=None):
    from maverick.flow.approvals import paused_operation_binding

    return paused_operation_binding(store.load_run(run.run_id), inputs=inputs)


def _approval_attestation(
    run, *, inputs=None, decision="approved", decided_by="system:direct",
):
    from maverick.flow.approvals import (
        flow_decision_attestation_material,
        paused_operation_binding,
    )
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    current = store.load_run(run.run_id)
    binding = paused_operation_binding(current, inputs=inputs)
    material = flow_decision_attestation_material(
        current,
        inputs=inputs,
        operation_binding_sha256=binding,
        authority_binding_sha256="",
        decision=decision,
        decided_by=decided_by,
    )
    return issue_flow_decision_attestation(
        None,
        material=material,
        expires_at=float(current.human["approval_card"]["expires_at"]),
    )


def test_agent_runner_runtime_type_error_is_never_retried():
    calls = []

    def side_effecting_runner(brief, data, *, wall=None):
        calls.append((brief, wall))
        raise TypeError("runner failed after creating its goal")

    with pytest.raises(TypeError, match="after creating"):
        execution._call_agent(side_effecting_runner, "work", {}, 10)

    assert calls == [("work", 10)]


def test_two_argument_agent_runner_is_detected_before_invocation():
    calls = []

    def two_argument_runner(brief, data):
        calls.append(brief)
        return ("ok", 0.0)

    assert execution._call_agent(two_argument_runner, "work", {}, 10) == ("ok", 0.0)
    assert calls == ["work"]


def test_status_sets_keep_resume_active_and_ambiguity_quarantined():
    assert STATUS_CLAIMED in ACTIVE_STATUSES
    assert STATUS_RESUMING in ACTIVE_STATUSES
    assert STATUS_INDETERMINATE not in ACTIVE_STATUSES
    assert {STATUS_INDETERMINATE} == QUARANTINED_STATUSES


def test_existing_running_fresh_delivery_is_quarantined_without_replay(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="crashed-fresh", name="crashed", start="act", nodes={
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="web_search"),
    })
    store.save_run(store.FlowRun(
        run_id="durable-run", flow_id=flow.id, status=STATUS_RUNNING,
        data={"started": True}, input_data={"started": True},
    ))
    calls: list[str] = []

    run = execution.execute(
        flow,
        run_id="durable-run",
        agent_runner=_noop_agent,
        action_runner=lambda tool, params, data: (calls.append(tool) or "bad", 1.0),
    )

    assert run.status == STATUS_INDETERMINATE
    assert store.load_run("durable-run").status == STATUS_INDETERMINATE
    assert calls == []


def test_claimed_placeholder_is_a_legitimate_first_delivery(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="claimed-fresh", name="claimed", start="act", nodes={
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="web_search"),
    })
    store.save_run(store.FlowRun(
        run_id="claimed-run", flow_id=flow.id, status=STATUS_CLAIMED,
        data={}, input_data={}, dry_run=True,
    ))
    calls: list[str] = []

    run = execution.execute(
        flow,
        run_id="claimed-run",
        agent_runner=_noop_agent,
        action_runner=lambda tool, params, data: (calls.append(tool) or "ok", 1.0),
        record_outcomes=False,
    )

    assert run.status == "completed"
    assert run.dry_run is True
    assert calls == ["web_search"]


def test_flow_revision_round_trips_as_opaque_ir_state():
    flow = Flow(
        id="revision", name="revision", start="n", revision="generation-token",
        nodes={"n": FlowNode(id="n", kind="agent", brief="work")},
    )
    assert flow.copy().revision == "generation-token"
    assert Flow.from_dict(flow.to_dict()).revision == "generation-token"


def test_stale_delete_cannot_remove_a_recreated_flow(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    original = store.save_flow(Flow(
        id="same-id", name="Alice", start="n", owner="user:alice",
        nodes={"n": FlowNode(id="n", kind="agent", brief="old")},
    ))
    assert store.delete_flow(
        original.id,
        expected_version=original.version,
        expected_revision=original.revision,
    )
    replacement = store.save_flow(Flow(
        id="same-id", name="Bob", start="n", owner="user:bob",
        nodes={"n": FlowNode(id="n", kind="agent", brief="new")},
    ))

    with pytest.raises(store.FlowVersionConflict, match="replaced|generation"):
        store.delete_flow(
            original.id,
            expected_version=original.version,
            expected_revision=original.revision,
        )

    current = store.load_flow(original.id)
    assert current is not None
    assert current.owner == "user:bob"
    assert current.revision == replacement.revision != original.revision


def test_recreated_flow_does_not_inherit_prior_generation_learning(
    tmp_path, monkeypatch,
):
    _patch_home(tmp_path, monkeypatch)
    alice = store.save_flow(Flow(
        id="learn-same-id", name="Alice", start="n", owner="user:alice",
        nodes={"n": FlowNode(id="n", kind="agent", brief="old")},
    ))
    for _ in range(6):
        node_outcomes.record(alice.id, "n", "agent", 1.0)
        node_tools.record(alice.id, "n", ["web_search"])
    evolution_log.record_apply(
        alice.id, "n", "agent", "action", alice.version, source="manual")
    assert node_outcomes.stats(alice.id)["n"]["n"] == 6
    assert node_tools.dominant_tool(alice.id, "n") == "web_search"
    assert evolution_log.last_apply(alice.id, "n") is not None

    assert store.delete_flow(
        alice.id,
        expected_version=alice.version,
        expected_revision=alice.revision,
    )
    bob = store.save_flow(Flow(
        id=alice.id, name="Bob", start="n", owner="user:bob",
        nodes={"n": FlowNode(id="n", kind="agent", brief="new")},
    ))

    assert bob.revision != alice.revision
    assert node_outcomes.stats(bob.id) == {}
    assert node_tools.dominant_tool(bob.id, "n") is None
    assert evolution_log.last_apply(bob.id, "n") is None
    store.record_flow_schema(
        bob.id, {"alice_secret": {"type": "string"}}, revision=alice.revision)
    assert store.load_flow_schema(bob.id) == {}


def test_high_risk_action_requires_approval_next_as_its_only_incoming_edge():
    gated = Flow(id="gated", name="gated", start="gate", nodes={
        "gate": FlowNode(id="gate", kind=NODE_APPROVAL, prompt="approve?", next="charge"),
        "charge": FlowNode(id="charge", kind=NODE_ACTION, tool="stripe",
                           params={"confirm": True}),
    })
    assert not [e for e in gated.validate() if "high-risk action" in e]

    bypass_sources = [
        FlowNode(id="src", kind="agent", brief="bypass", next="charge"),
        FlowNode(id="src", kind="branch", condition="ok", if_true="charge"),
        FlowNode(id="src", kind="branch", condition="ok", if_false="charge"),
        FlowNode(id="src", kind="switch", condition="route",
                 cases=[{"value": "x", "to": "charge"}]),
        FlowNode(id="src", kind="agent", brief="bypass", on_error="charge"),
        FlowNode(id="src", kind=NODE_APPROVAL, prompt="expires", on_expire="charge"),
    ]
    for source in bypass_sources:
        flow = gated.copy()
        flow.nodes[source.id] = source
        errors = flow.validate()
        assert any("approval-bypassing incoming edge" in e for e in errors), errors


def test_choice_routing_is_not_authorization_for_a_high_risk_action():
    flow = Flow(id="choice-is-not-consent", name="choice", start="gate", nodes={
        "gate": FlowNode(
            id="gate",
            kind=NODE_APPROVAL,
            prompt="What should happen?",
            choices=["ship", "hold"],
            next="charge",
        ),
        "charge": FlowNode(id="charge", kind=NODE_ACTION, tool="stripe"),
    })

    errors = flow.validate()
    assert any("approval-bypassing incoming edge" in error for error in errors), errors


def test_nested_high_risk_action_requires_a_hoisted_durable_approval():
    inner = Flow(id="inner", name="inner", start="charge", nodes={
        "charge": FlowNode(id="charge", kind=NODE_ACTION, tool="stripe"),
    })
    outer = Flow(id="outer", name="outer", start="loop", nodes={
        "loop": FlowNode(id="loop", kind="foreach", items="rows", body=inner),
    })
    errors = outer.validate()
    assert any("body: high-risk action" in e and "cannot be the flow start" in e
               for e in errors), errors

    governed = ensure_high_risk_approvals(outer)
    gate = governed.node(governed.start)
    assert gate is not None and gate.kind == NODE_APPROVAL
    assert gate.next == "loop"
    assert governed.validate() == []
    # Nested execution cannot pause/resume safely, so authorization is inherited
    # from the durable root rather than inserting a broken approval in the body.
    assert all(n.kind != NODE_APPROVAL
               for n in governed.nodes["loop"].body.nodes.values())


def test_live_execution_rejects_ungated_high_risk_plan_before_side_effect(
    tmp_path, monkeypatch,
):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="unsafe-live", name="unsafe", start="charge", nodes={
        "charge": FlowNode(id="charge", kind=NODE_ACTION, tool="stripe"),
    })
    calls: list[str] = []

    with pytest.raises(ValueError, match="invalid flow execution plan"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (
                calls.append(tool) or "must not run", 1.0),
        )

    assert calls == []


def test_concurrent_resume_executes_downstream_action_once(tmp_path, monkeypatch):
    """At-least-once queue delivery must not duplicate an approved side effect."""
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="resume-race", name="resume race", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve?", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="stripe"),
    })
    store.save_flow(flow)
    paused = execution.execute(
        flow, agent_runner=_noop_agent, action_runner=lambda *a: ("unused", 1.0))
    assert paused.status == "paused_approval"

    entered = threading.Event()
    release = threading.Event()
    calls: list[str] = []

    def action(tool, params, data):
        calls.append(tool)
        entered.set()
        assert release.wait(5), "test did not release the side effect"
        return ("sent", 1.0)

    def resume():
        try:
            return execution.execute(
                flow,
                agent_runner=_noop_agent,
                action_runner=action,
                resume_run_id=paused.run_id,
                 decision="approved",
                 decided_by="system:direct",
                 approval_binding_sha256=_approval_binding(paused),
                 approval_decision_attestation=_approval_attestation(paused),
             ).status
        except execution.FlowNotResumable:
            return "not-resumable"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(resume)
        assert entered.wait(5), "first resume never reached the action"
        second = pool.submit(resume)
        # Give the duplicate delivery a chance to contend for the durable run
        # lock while the first worker is still inside the side effect.
        time.sleep(0.05)
        release.set()
        outcomes = {first.result(timeout=5), second.result(timeout=5)}

    assert outcomes == {"completed", "not-resumable"}
    assert calls == ["stripe"]


def test_core_resume_requires_explicit_actor_and_declared_assignee(
    tmp_path, monkeypatch,
):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="assigned-core", name="assigned", start="gate", nodes={
        "gate": FlowNode(
            id="gate", kind="approval", prompt="approve?", assignee="@alice",
        ),
    })
    store.save_flow(flow)
    paused = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=lambda *args: ("unused", 1.0),
    )

    with pytest.raises(ValueError, match="identity"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda *args: ("unused", 1.0),
            resume_run_id=paused.run_id,
            decision="approved",
        )
    with pytest.raises(ValueError, match="assignee"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda *args: ("unused", 1.0),
            resume_run_id=paused.run_id,
            decision="approved",
            decided_by="user:bob",
        )
    assert store.load_run(paused.run_id).status == "paused_approval"

    completed = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=lambda *args: ("unused", 1.0),
        resume_run_id=paused.run_id,
        decision="approved",
        decided_by="user:alice",
        approval_binding_sha256=_approval_binding(paused),
        approval_decision_attestation=_approval_attestation(
            paused, decided_by="user:alice",
        ),
    )
    assert completed.status == "completed"
    assert completed.decided_by == "user:alice"


@pytest.mark.parametrize("tamper", ["missing_binding", "expired_card", "changed_role"])
def test_direct_core_resume_revalidates_the_persisted_approval_before_effect(
    tmp_path, monkeypatch, tamper,
):
    from copy import deepcopy

    from maverick.approval_cards import ApprovalCardError, digest

    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="direct-approval-guard", name="guard", start="gate", nodes={
        "gate": FlowNode(
            id="gate", kind="approval", prompt="approve deletion?", next="delete",
        ),
        "delete": FlowNode(id="delete", kind=NODE_ACTION, tool="stripe"),
    })
    paused = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=lambda *args: ("unused", 1.0),
    )
    if tamper != "missing_binding":
        current = store.load_run(paused.run_id)
        card = deepcopy(current.human["approval_card"])
        card.pop("binding_sha256")
        if tamper == "expired_card":
            card["expires_at"] = time.time() - 1
        else:
            card["authority"]["role"] = "revoked-role"
        card["binding_sha256"] = digest(card)
        current.human["approval_card"] = card
        store.save_run(current)

    calls: list[str] = []
    binding = "" if tamper == "missing_binding" else _approval_binding(paused)
    with pytest.raises(ApprovalCardError):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (
                calls.append(tool) or "mutated", 1.0
            ),
            resume_run_id=paused.run_id,
            decision="approved",
            decided_by="system:direct",
            approval_binding_sha256=binding,
        )

    assert calls == []
    assert store.load_run(paused.run_id).status == "paused_approval"


def test_direct_core_resume_cannot_manufacture_decision_from_public_binding(
    tmp_path, monkeypatch,
):
    from maverick.approval_cards import ApprovalCardError

    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="direct-permit-guard", name="guard", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve?", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="stripe"),
    })
    paused = execution.execute(
        flow, agent_runner=_noop_agent,
        action_runner=lambda *args: ("unused", 1.0),
    )
    calls: list[str] = []

    with pytest.raises(ApprovalCardError, match="decision attestation"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (
                calls.append(tool) or "mutated", 1.0
            ),
            resume_run_id=paused.run_id,
            decision="approved",
            decided_by="system:direct",
            approval_binding_sha256=_approval_binding(paused),
        )

    assert calls == []
    assert store.load_run(paused.run_id).status == "paused_approval"


def test_direct_core_resume_rechecks_credential_inventory_after_permit(
    tmp_path, monkeypatch,
):
    from maverick.approval_cards import ApprovalCardError

    _patch_home(tmp_path, monkeypatch)
    monkeypatch.setenv("STRIPE_API_KEY", "credential-before")
    flow = Flow(id="credential-rotation", name="guard", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve?", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="stripe"),
    })
    paused = execution.execute(
        flow, agent_runner=_noop_agent,
        action_runner=lambda *args: ("unused", 1.0),
    )
    attestation = _approval_attestation(paused)
    monkeypatch.setenv("STRIPE_API_KEY", "credential-after")
    calls: list[str] = []

    with pytest.raises(ApprovalCardError, match="durable operation"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (
                calls.append(tool) or "mutated", 1.0
            ),
            resume_run_id=paused.run_id,
            decision="approved",
            decided_by="system:direct",
            approval_binding_sha256=_approval_binding(paused),
            approval_decision_attestation=attestation,
        )

    assert calls == []
    assert store.load_run(paused.run_id).status == "paused_approval"


def test_approval_resume_revalidates_inside_effect_fence(tmp_path, monkeypatch):
    import os

    from maverick.flow import approvals
    from maverick.flow.runner import FlowApprovalStale

    _patch_home(tmp_path, monkeypatch)
    monkeypatch.setenv("STRIPE_API_KEY", "credential-before")
    flow = Flow(id="credential-toctou", name="guard", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve?", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="stripe"),
    })
    paused = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=lambda *args: ("unused", 1.0),
    )
    binding = _approval_binding(paused)
    attestation = _approval_attestation(paused)
    real_require = approvals.require_current_paused_operation
    observations: list[tuple[str, str]] = []
    calls = 0

    def rotate_after_validation(*args, **kwargs):
        nonlocal calls
        card = real_require(*args, **kwargs)
        calls += 1
        if calls == 1:
            monkeypatch.setenv("STRIPE_API_KEY", "credential-after")
        return card

    monkeypatch.setattr(
        approvals, "require_current_paused_operation", rotate_after_validation,
    )

    with pytest.raises(FlowApprovalStale, match="changed before execution"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (
                observations.append((tool, os.environ["STRIPE_API_KEY"])) or "mutated",
                1.0,
            ),
            resume_run_id=paused.run_id,
            decision="approved",
            decided_by="system:direct",
            approval_binding_sha256=binding,
            approval_decision_attestation=attestation,
        )

    assert calls == 1
    assert observations == []
    assert store.load_run(paused.run_id).status == "paused_approval"


def test_paused_run_uses_pinned_root_after_edit_and_delete(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    reviewed = Flow(id="pinned-root", name="pinned", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve read?", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="web_search"),
    })
    store.save_flow(reviewed)
    paused = execution.execute(
        reviewed, agent_runner=_noop_agent, action_runner=lambda *a: ("unused", 1.0))
    assert paused.status == "paused_approval"
    assert paused.definition_digest

    changed = Flow(id="pinned-root", name="changed", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="different", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="slack_bot"),
    })
    store.save_flow(changed)
    assert store.delete_flow(reviewed.id) is True

    seen: list[str] = []
    resumed = execution.execute(
        changed,
        agent_runner=_noop_agent,
        action_runner=lambda tool, params, data: (seen.append(tool) or "ok", 1.0),
        resume_run_id=paused.run_id,
        decision="approved",
        decided_by="system:direct",
        approval_binding_sha256=_approval_binding(paused),
        approval_decision_attestation=_approval_attestation(paused),
    )

    assert resumed.status == "completed"
    assert seen == ["web_search"]
    assert resumed.definition_digest == paused.definition_digest


def test_paused_run_uses_pinned_subflow_after_child_edit_and_delete(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    child = Flow(id="pinned-child", name="child", start="act", nodes={
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="web_search"),
    })
    root = Flow(id="pinned-parent", name="parent", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve child?", next="child"),
        "child": FlowNode(id="child", kind="subflow", flow_ref=child.id),
    })
    store.save_flow(child)
    store.save_flow(root)
    paused = execution.execute(
        root, agent_runner=_noop_agent, action_runner=lambda *a: ("unused", 1.0))
    assert paused.status == "paused_approval"
    assert paused.subflow_digests.get(child.id)

    store.save_flow(Flow(id=child.id, name="changed child", start="act", nodes={
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="stripe"),
    }))
    assert store.delete_flow(child.id) is True

    seen: list[str] = []
    resumed = execution.execute(
        root,
        agent_runner=_noop_agent,
        action_runner=lambda tool, params, data: (seen.append(tool) or "ok", 1.0),
        resume_run_id=paused.run_id,
        decision="approved",
        decided_by="system:direct",
        approval_binding_sha256=_approval_binding(paused),
        approval_decision_attestation=_approval_attestation(paused),
    )

    assert resumed.status == "completed"
    assert seen == ["web_search"]


def test_snapshot_rejects_cross_owner_subflow_reference(tmp_path, monkeypatch):
    """Knowing another user's flow id is not authority to execute its graph."""
    _patch_home(tmp_path, monkeypatch)
    child = store.save_flow(Flow(
        id="bob-private", name="Bob private", start="work", owner="user:bob",
        nodes={"work": FlowNode(id="work", kind="agent", brief="private")},
    ))
    parent = store.save_flow(Flow(
        id="alice-parent", name="Alice parent", start="child", owner="user:alice",
        nodes={
            "child": FlowNode(
                id="child", kind="subflow", flow_ref=child.id,
            ),
        },
    ))

    with pytest.raises(store.FlowSnapshotError, match="unavailable"):
        store.snapshot_current_flow_bundle(parent.id)


def test_snapshot_allows_same_owner_subflow_reference(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    child = store.save_flow(Flow(
        id="alice-child", name="Alice child", start="work", owner="user:alice",
        nodes={"work": FlowNode(id="work", kind="agent", brief="work")},
    ))
    parent = store.save_flow(Flow(
        id="alice-parent", name="Alice parent", start="child", owner="user:alice",
        nodes={
            "child": FlowNode(
                id="child", kind="subflow", flow_ref=child.id,
            ),
        },
    ))

    _digest, _version, children = store.snapshot_current_flow_bundle(parent.id)
    assert children[child.id]


def test_legacy_pinned_cross_owner_subflow_is_rejected_on_resume(tmp_path, monkeypatch):
    """Pre-hardening durable manifests do not retain a permanent ACL bypass."""
    _patch_home(tmp_path, monkeypatch)
    child = Flow(
        id="bob-private", name="Bob private", start="act", owner="user:bob",
        nodes={"act": FlowNode(id="act", kind=NODE_ACTION, tool="web_search")},
    )
    root = Flow(
        id="alice-parent", name="Alice parent", start="gate", owner="user:alice",
        revision="alice-generation",
        nodes={
            "gate": FlowNode(
                id="gate", kind=NODE_APPROVAL, prompt="approve?", next="child",
            ),
            "child": FlowNode(id="child", kind="subflow", flow_ref=child.id),
        },
    )
    root_digest = store._store_flow_object(root.to_dict())
    child_digest = store._store_flow_object(child.to_dict())
    store.save_run(store.FlowRun(
        run_id="legacy-cross-owner",
        flow_id=root.id,
        status="paused_approval",
        cursor="gate",
        owner="user:alice",
        definition_digest=root_digest,
        definition_version=root.version,
        definition_revision=root.revision,
        subflow_digests={child.id: child_digest},
    ))
    calls: list[str] = []

    with pytest.raises(store.FlowSnapshotError, match="unavailable"):
        execution.execute(
            root,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (
                calls.append(tool) or "bad", 1.0
            ),
            resume_run_id="legacy-cross-owner",
            decision="approved",
            decided_by="system:direct",
        )
    assert calls == []


def test_pinned_subflow_manifest_cannot_remap_a_flow_id(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    actual = Flow(
        id="actual-child",
        name="actual",
        start="work",
        owner="user:alice",
        nodes={"work": FlowNode(id="work", kind="agent", brief="work")},
    )
    digest = store._store_flow_object(actual.to_dict())
    root = Flow(
        id="root",
        name="root",
        start="child",
        owner="user:alice",
        nodes={
            "child": FlowNode(
                id="child", kind="subflow", flow_ref="claimed-child",
            ),
        },
    )

    with pytest.raises(store.FlowSnapshotError, match="identity mismatch"):
        store.validate_snapshot_bundle_owners(root, {"claimed-child": digest})


def test_pinned_root_snapshot_must_match_durable_flow_id(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    other = Flow(
        id="other",
        name="other",
        start="work",
        owner="user:alice",
        nodes={"work": FlowNode(id="work", kind="agent", brief="work")},
    )
    digest, version, children = store.snapshot_flow_bundle(other)
    store.save_run(store.FlowRun(
        run_id="queued-root-swap",
        flow_id="expected",
        status="queued",
        owner="user:alice",
        definition_digest=digest,
        definition_version=version,
        definition_revision=other.revision,
        subflow_digests=children,
    ))

    with pytest.raises(store.FlowSnapshotError, match="durable run"):
        execution.execute(
            Flow(
                id="expected",
                name="expected",
                start="work",
                owner="user:alice",
                nodes={"work": FlowNode(id="work", kind="agent", brief="work")},
            ),
            agent_runner=_noop_agent,
            action_runner=lambda *_args: ("ok", 1.0),
            run_id="queued-root-swap",
            owner="user:alice",
        )


def test_corrupt_pinned_snapshot_fails_closed_before_side_effect(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="corrupt-plan", name="corrupt", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="approve?", next="act"),
        "act": FlowNode(id="act", kind=NODE_ACTION, tool="stripe"),
    })
    store.save_flow(flow)
    paused = execution.execute(
        flow, agent_runner=_noop_agent, action_runner=lambda *a: ("unused", 1.0))
    snapshot = store._objects_dir() / f"{paused.definition_digest}.json"
    snapshot.write_text('{"id":"tampered"}', encoding="utf-8")

    calls: list[str] = []
    with pytest.raises(store.FlowSnapshotError, match="integrity verification"):
        execution.execute(
            flow,
            agent_runner=_noop_agent,
            action_runner=lambda tool, params, data: (calls.append(tool) or "bad", 1.0),
            resume_run_id=paused.run_id,
            decision="approved",
            decided_by="system:direct",
        )

    assert calls == []
    assert store.load_run(paused.run_id).status == "paused_approval"


def test_high_risk_lost_ack_is_quarantined_without_a_grounded_failure(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="lost-ack", name="lost ack", start="gate", nodes={
        "gate": FlowNode(id="gate", kind=NODE_APPROVAL, prompt="approve?", next="charge"),
        "charge": FlowNode(id="charge", kind=NODE_ACTION, tool="stripe"),
    })
    store.save_flow(flow)
    paused = execution.execute(
        flow, agent_runner=_noop_agent, action_runner=lambda *args: ("unused", 1.0))

    def _lost_ack(*args):
        raise RuntimeError("upstream disconnected after dispatch")

    run = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=_lost_ack,
        resume_run_id=paused.run_id,
        decision="approved",
        decided_by="system:direct",
        approval_binding_sha256=_approval_binding(paused),
        approval_decision_attestation=_approval_attestation(paused),
    )
    assert run.status == STATUS_INDETERMINATE
    assert run.cursor == "charge"
    assert run.nodes["charge"]["status"] == STATUS_INDETERMINATE
    assert run.nodes["charge"].get("outcome") is None


@pytest.mark.parametrize(
    "result",
    [
        "REFUSED (governed): approval was not granted",
        "DRY RUN: would charge; re-run with confirm=true",
    ],
)
def test_high_risk_pre_effect_refusal_is_failed_not_indeterminate(
    tmp_path, monkeypatch, result,
):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="pre-effect-refusal", name="refusal", start="gate", nodes={
        "gate": FlowNode(id="gate", kind=NODE_APPROVAL, prompt="approve?", next="charge"),
        "charge": FlowNode(id="charge", kind=NODE_ACTION, tool="stripe"),
    })
    store.save_flow(flow)
    paused = execution.execute(
        flow, agent_runner=_noop_agent, action_runner=lambda *args: ("unused", 1.0))

    run = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=lambda *args: (result, 0.0),
        resume_run_id=paused.run_id,
        decision="approved",
        decided_by="system:direct",
        approval_binding_sha256=_approval_binding(paused),
        approval_decision_attestation=_approval_attestation(paused),
    )

    assert run.status == "failed"
    assert run.cursor == "charge"
    assert run.status != STATUS_INDETERMINATE


def test_failed_agent_trajectory_is_quarantined_without_replay_proof(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="agent-ambiguous", name="agent", start="work", nodes={
        "work": FlowNode(id="work", kind="agent", brief="update the account"),
    })
    run = execution.execute(
        flow,
        agent_runner=lambda brief, data: ("goal failed after tool call", 0.0),
        action_runner=lambda *args: ("unused", 1.0),
    )
    assert run.status == STATUS_INDETERMINATE
    assert run.cursor == "work"
    assert run.nodes["work"]["status"] == STATUS_INDETERMINATE
    assert run.nodes["work"].get("outcome") is None


def test_persisted_run_errors_are_secret_redacted(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    secret = "ghp_" + "Z" * 36  # pragma: allowlist secret
    run = store.FlowRun(
        run_id="redacted", flow_id="f", status="failed",
        error=f"connector rejected Authorization: Bearer {secret}",
    )
    store.save_run(run)

    loaded = store.load_run("redacted")
    raw = (store._runs_dir() / "redacted.json").read_text(encoding="utf-8")
    assert secret not in raw
    assert secret not in loaded.error
    assert "REDACTED" in loaded.error


def test_secret_bearing_ordinary_data_values_are_redacted_at_rest(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    secret = "ghp_" + "Q" * 36  # pragma: allowlist secret
    run = store.FlowRun(
        run_id="redacted-data", flow_id="f", status="completed",
        data={"result": f"remote said Authorization: Bearer {secret}"},
        input_data={"note": f"token observed: {secret}"},
    )
    store.save_run(run)

    raw = (store._runs_dir() / "redacted-data.json").read_text(encoding="utf-8")
    loaded = store.load_run("redacted-data")
    assert secret not in raw
    assert secret not in loaded.data["result"]
    assert secret not in loaded.input_data["note"]


def test_failed_action_result_is_not_published_as_flow_output(tmp_path, monkeypatch):
    _patch_home(tmp_path, monkeypatch)
    flow = Flow(id="failed-output", name="failed", start="read", nodes={
        "read": FlowNode(
            id="read", kind=NODE_ACTION, tool="web_search",
            output="result", on_error="gate",
        ),
        "gate": FlowNode(id="gate", kind=NODE_APPROVAL, prompt="recover?"),
    })
    run = execution.execute(
        flow,
        agent_runner=_noop_agent,
        action_runner=lambda *args: ("Authorization: Bearer should-not-flow", 0.0),
    )
    assert run.status == "paused_approval"
    assert "result" not in run.data


def test_default_agent_runner_propagates_flow_execution_identity(tmp_path, monkeypatch):
    from maverick import world_model

    world = world_model.WorldModel(tmp_path / "world.db")
    captured = {}

    def fake_run(goal_id, **kwargs):
        captured.update(kwargs)
        world.set_goal_status(goal_id, "done", result="ok")
        return "done"

    monkeypatch.setattr("maverick.runner.run_goal_in_thread", fake_run)
    runner = execution.default_agent_runner(
        world,
        owner="user:alice",
        channel="api",
        user_id="alice",
        allowed_suites=frozenset({"finance"}),
        concurrency_principal="user:alice",
        budget_dollars=1.25,
        budget_wall_seconds=30,
    )

    result, outcome = runner("do work", {}, wall=10)

    assert (result, outcome) == ("ok", 1.0)
    assert callable(captured.pop("usage_observer"))
    assert captured == {
        "max_dollars": 1.25,
        "max_wall_seconds": 10,
        "channel": "api",
        "user_id": "alice",
        "allowed_suites": frozenset({"finance"}),
        "concurrency_principal": "user:alice",
    }


def test_default_action_runner_uses_registry_dict_contract_for_async_tool(monkeypatch):
    """Flow actions share ToolRegistry's authoritative async dispatch contract."""
    from maverick.tools import Tool, ToolRegistry

    seen: list[dict] = []

    async def async_tool(args):
        await asyncio.sleep(0)
        seen.append(dict(args))
        return f"received:{args['value']}"

    registry = ToolRegistry()
    registry.register(Tool(
        name="web_search",
        description="test async action",
        input_schema={"type": "object"},
        fn=async_tool,
    ))
    registry_kwargs = {}

    def fake_registry(*args, **kwargs):
        registry_kwargs.update(kwargs)
        return registry

    monkeypatch.setattr("maverick.tools.base_registry", fake_registry)
    runner = execution.default_action_runner(
        world=None, channel="api", user_id="alice")

    async def call_from_running_loop():
        return runner("web_search", {"value": 7}, {})

    result, outcome = asyncio.run(call_from_running_loop())
    assert (result, outcome) == ("received:7", 1.0)
    assert seen == [{"value": 7}]
    assert registry_kwargs["channel"] == "api"
    assert registry_kwargs["user_id"] == "alice"


@pytest.mark.parametrize(
    "reserved",
    [
        "REFUSED (governed): approval missing",
        "INDETERMINATE (governed): commit receipt missing",
    ],
)
def test_default_action_runner_never_scores_governed_non_success_as_success(
    monkeypatch, reserved,
):
    from maverick.tools import Tool, ToolRegistry

    registry = ToolRegistry()
    registry.register(Tool(
        name="salesforce",
        description="governed connector",
        input_schema={"type": "object"},
        fn=lambda _args: reserved,
    ))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *a, **k: registry)

    result, outcome = execution.default_action_runner(world=None)(
        "salesforce", {"op": "post"}, {},
    )
    assert result == reserved
    assert outcome == 0.0


def test_default_action_runner_preserves_explicit_success_with_error_prefix(monkeypatch):
    from maverick.tool_results import ToolOutcome, ToolResultState
    from maverick.tools import Tool, ToolRegistry

    content = "ERROR: ValueError: ordinary document content"
    registry = ToolRegistry()
    registry.register(Tool(
        name="web_search",
        description="search results",
        input_schema={"type": "object"},
        fn=lambda _args: ToolOutcome(ToolResultState.SUCCEEDED, content).as_text(),
    ))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *a, **k: registry)
    result, outcome = execution.default_action_runner(world=None)("web_search", {}, {})
    assert result == content
    assert outcome == 1.0


def test_redacted_typed_indeterminate_result_is_not_retried(monkeypatch):
    from maverick.flow.runner import run_flow
    from maverick.tool_results import ToolOutcome, ToolResultState
    from maverick.tools import Tool, ToolRegistry

    calls = []
    registry = ToolRegistry()
    registry.register(Tool(
        name="web_search", description="search results", input_schema={"type": "object"},
        fn=lambda _args: calls.append("called") or ToolOutcome(
            ToolResultState.INDETERMINATE, "ERROR: RuntimeError: private details",
        ).as_text(),
    ))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *a, **k: registry)
    action = execution.default_action_runner(world=None)
    node = FlowNode(id="search", kind=NODE_ACTION, tool="web_search", retries=3)
    flow = Flow(id="f", name="Example", start="search", nodes={"search": node})
    result = run_flow(flow, agent_fn=lambda *_args: ("unused", None),
                      action_fn=lambda node, params, data: action(node.tool, params, data))
    assert result.status == "indeterminate"
    assert calls == ["called"]
    assert "private details" not in result.error
