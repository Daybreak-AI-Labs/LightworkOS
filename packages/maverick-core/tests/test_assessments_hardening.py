"""Adversarial flow-surface and assessment-register governance tests."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest
from maverick import assessments as A

SAFE = {
    "kind": "agent", "subject": "calm_bot", "description": "reads",
    "allow_tools": ["read_file"], "deny_tools": [], "max_risk": "low",
    "allow_paths": [], "allow_hosts": [], "mcp_servers": [],
    "knowledge_sources": [], "has_human_gate": True, "steps": 1,
}


@pytest.fixture(autouse=True)
def _isolate_home(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))


@pytest.mark.parametrize("kind", ["foreach", "while", "scope", "parallel"])
def test_nested_high_risk_actions_are_traversed_and_inherit_dominating_gate(kind):
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    body = Flow(
        id=f"{kind}_body", name="body", start="send",
        nodes={"send": FlowNode(id="send", kind="action", tool="email")},
    )
    container = FlowNode(id="container", kind=kind)
    if kind == "parallel":
        container.branches = [body]
    else:
        container.body = body
    if kind == "foreach":
        container.items = "rows"
    if kind == "while":
        container.condition = "continue == true"
    flow_id = f"nested_{kind}"
    save_flow(Flow(
        id=flow_id, name=flow_id, start="approve",
        nodes={
            "approve": FlowNode(
                id="approve", kind="approval", prompt="Approve?", next="container",
            ),
            "container": container,
        },
    ))

    surface = A.flow_surface(flow_id)

    assert surface["allow_tools"] == ["email"]
    assert surface["analysis_complete"] is True
    assert surface["has_human_gate"] is True
    assert surface["approval_gaps"] == []


def test_nested_branch_bypass_and_scope_catch_are_not_waved_through():
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    body = Flow(
        id="bypass_body", name="body", start="send",
        nodes={"send": FlowNode(id="send", kind="action", tool="email")},
    )
    save_flow(Flow(
        id="nested_bypass", name="bypass", start="route",
        nodes={
            "route": FlowNode(
                id="route", kind="branch", condition="ok == true",
                if_true="approve", if_false="container",
            ),
            "approve": FlowNode(
                id="approve", kind="approval", prompt="Approve?", next="container",
            ),
            "container": FlowNode(id="container", kind="scope", body=body),
        },
    ))
    catch_body = Flow(
        id="catch_body", name="catch body", start="lookup",
        nodes={
            "lookup": FlowNode(id="lookup", kind="action", tool="web_search"),
        },
    )
    save_flow(Flow(
        id="catch_bypass", name="catch bypass", start="work",
        nodes={
            "work": FlowNode(
                id="work", kind="scope", body=catch_body,
                next="unrelated_approval", on_error="send",
            ),
            "unrelated_approval": FlowNode(
                id="unrelated_approval", kind="approval", prompt="Unrelated",
            ),
            "send": FlowNode(id="send", kind="action", tool="email"),
        },
    ))

    nested = A.flow_surface("nested_bypass")
    caught = A.flow_surface("catch_bypass")

    assert nested["has_human_gate"] is False
    assert nested["approval_gaps"]
    assert any("container" in gap and "email" in gap for gap in nested["approval_gaps"])
    assert caught["has_human_gate"] is False
    assert any("send" in gap and "email" in gap for gap in caught["approval_gaps"])


def test_pinned_subflows_are_traversed_and_missing_pins_fail_high():
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    save_flow(Flow(
        id="child", name="child", start="lookup",
        nodes={"lookup": FlowNode(id="lookup", kind="action", tool="web_search")},
    ))
    save_flow(Flow(
        id="parent", name="parent", start="child",
        nodes={"child": FlowNode(id="child", kind="subflow", flow_ref="child")},
    ))
    save_flow(Flow(
        id="missing_parent", name="missing", start="child",
        nodes={"child": FlowNode(id="child", kind="subflow", flow_ref="absent")},
    ))

    resolved = A.flow_surface("parent")
    missing = A.flow_surface("missing_parent")

    assert resolved["allow_tools"] == ["web_search"]
    assert resolved["analysis_complete"] is True
    assert resolved["subflow_digests"]["child"]
    assert missing["analysis_complete"] is False
    assert missing["max_risk"] == "high"
    assert missing["unresolved_subflows"] == ["absent"]


def test_parent_gate_dominates_pinned_child_but_child_only_gate_does_not():
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    save_flow(Flow(
        id="gated_child", name="gated child", start="child_approval",
        nodes={
            "child_approval": FlowNode(
                id="child_approval", kind="approval", prompt="Approve child?",
                next="send",
            ),
            "send": FlowNode(id="send", kind="action", tool="email"),
        },
    ))
    save_flow(Flow(
        id="safe_parent", name="safe parent", start="parent_approval",
        nodes={
            "parent_approval": FlowNode(
                id="parent_approval", kind="approval", prompt="Approve parent?",
                next="child",
            ),
            "child": FlowNode(
                id="child", kind="subflow", flow_ref="gated_child",
            ),
        },
    ))
    save_flow(Flow(
        id="child_only_parent", name="child-only", start="child",
        nodes={
            "child": FlowNode(
                id="child", kind="subflow", flow_ref="gated_child",
            ),
        },
    ))

    safe = A.flow_surface("safe_parent")
    child_only = A.flow_surface("child_only_parent")

    assert safe["analysis_complete"] is True
    assert safe["has_human_gate"] is True
    assert safe["approval_gaps"] == []
    # Subflows execute with ctx.nested(): their approval cannot create a
    # persisted pause/resume decision, so only the parent gate is authoritative.
    assert child_only["analysis_complete"] is True
    assert child_only["has_human_gate"] is False
    assert any("send" in gap and "email" in gap for gap in child_only["approval_gaps"])


def test_nested_body_approval_is_non_authoritative_like_the_runtime():
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    body = Flow(
        id="invalid_nested_gate", name="nested", start="approve",
        nodes={
            "approve": FlowNode(
                id="approve", kind="approval", prompt="Cannot pause", next="send",
            ),
            "send": FlowNode(id="send", kind="action", tool="email"),
        },
    )
    save_flow(Flow(
        id="nested_gate_parent", name="nested gate", start="scope",
        nodes={"scope": FlowNode(id="scope", kind="scope", body=body)},
    ))

    surface = A.flow_surface("nested_gate_parent")

    assert surface["analysis_complete"] is False
    assert surface["has_human_gate"] is False
    assert any("send" in gap and "email" in gap for gap in surface["approval_gaps"])


def test_subflow_cycles_and_analysis_resource_limits_fail_high(monkeypatch):
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    save_flow(Flow(
        id="cycle_a", name="a", start="b",
        nodes={"b": FlowNode(id="b", kind="subflow", flow_ref="cycle_b")},
    ))
    save_flow(Flow(
        id="cycle_b", name="b", start="a",
        nodes={"a": FlowNode(id="a", kind="subflow", flow_ref="cycle_a")},
    ))
    cyclic = A.flow_surface("cycle_a")
    assert cyclic["analysis_complete"] is False
    assert cyclic["max_risk"] == "high"
    assert any("cyclic subflow" in error for error in cyclic["analysis_errors"])

    save_flow(Flow(
        id="too_many", name="too many", start="one",
        nodes={
            "one": FlowNode(
                id="one", kind="action", tool="web_search", next="two",
            ),
            "two": FlowNode(id="two", kind="action", tool="web_search"),
        },
    ))
    monkeypatch.setattr(A, "_FLOW_MAX_NODES", 1)
    bounded = A.flow_surface("too_many")
    assert bounded["analysis_complete"] is False
    assert bounded["max_risk"] == "high"
    assert any("node limit" in error for error in bounded["analysis_errors"])

    leaf = Flow(
        id="leaf", name="leaf", start="lookup",
        nodes={"lookup": FlowNode(id="lookup", kind="action", tool="web_search")},
    )
    middle = Flow(
        id="middle", name="middle", start="scope",
        nodes={"scope": FlowNode(id="scope", kind="scope", body=leaf)},
    )
    save_flow(Flow(
        id="too_deep", name="too deep", start="scope",
        nodes={"scope": FlowNode(id="scope", kind="scope", body=middle)},
    ))
    monkeypatch.setattr(A, "_FLOW_MAX_NODES", 100)
    monkeypatch.setattr(A, "_FLOW_MAX_DEPTH", 1)
    deep = A.flow_surface("too_deep")
    assert deep["analysis_complete"] is False
    assert any("depth limit" in error for error in deep["analysis_errors"])


def test_unknown_action_tool_is_incomplete_high_risk_and_ungated():
    from maverick.flow.ir import Flow, FlowNode
    from maverick.flow.store import save_flow

    save_flow(Flow(
        id="unknown_tool", name="unknown", start="mystery",
        nodes={
            "mystery": FlowNode(id="mystery", kind="action", tool="new_plugin_mutate"),
        },
    ))

    surface = A.flow_surface("unknown_tool")

    assert surface["analysis_complete"] is False
    assert surface["max_risk"] == "high"
    assert surface["unresolved_tools"] == ["new_plugin_mutate"]
    assert surface["approval_gaps"]


def test_failed_review_audit_cannot_publish_and_retry_recovers(monkeypatch):
    monkeypatch.setattr(A, "subject_surface", lambda _kind, _name: dict(SAFE))
    created = A.refresh("agent", "calm_bot", now=1.0)
    monkeypatch.setattr(A, "_audit_review", lambda *_args: False)

    with pytest.raises(A.AssessmentAuditError):
        A.record_review(
            "agent", "calm_bot", "security", "accepted", now=2.0,
            expected_revision=created["revision"],
        )

    unchanged = A.get_assessment("agent", "calm_bot")
    assert unchanged["revision"] == created["revision"]
    assert unchanged["status"] == "draft"
    assert unchanged["lenses"]["security"]["status"] == "open"

    monkeypatch.setattr(A, "_audit_review", lambda *_args: True)
    recovered = A.record_review(
        "agent", "calm_bot", "security", "accepted", now=3.0,
        expected_revision=created["revision"],
    )
    assert recovered["revision"] == created["revision"] + 1
    assert recovered["status"] == "in_review"


def test_post_audit_promotion_failure_keeps_retryable_prepare(monkeypatch):
    monkeypatch.setattr(A, "subject_surface", lambda _kind, _name: dict(SAFE))
    created = A.refresh("agent", "calm_bot", now=1.0)
    phases: list[tuple[str, str]] = []

    def audit(*_args, **kwargs):
        phases.append((kwargs["phase"], kwargs["transaction_id"]))
        return True

    monkeypatch.setattr(A, "_audit_review", audit)
    real_write = A._write_register_unlocked
    writes = 0

    def fail_promotion(data, *, expected_register_revision):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("injected promotion failure")
        return real_write(
            data, expected_register_revision=expected_register_revision,
        )

    monkeypatch.setattr(A, "_write_register_unlocked", fail_promotion)
    with pytest.raises(OSError, match="promotion failure"):
        A.record_review(
            "agent", "calm_bot", "security", "accepted", reviewer="ada",
            now=2.0, expected_revision=created["revision"],
        )
    assert [phase for phase, _txn in phases] == ["prepare", "commit_authorized"]
    unchanged = A.get_assessment("agent", "calm_bot")
    assert unchanged["status"] == "draft"
    assert unchanged["revision"] == created["revision"]

    monkeypatch.setattr(A, "_write_register_unlocked", real_write)
    recovered = A.record_review(
        "agent", "calm_bot", "security", "accepted", reviewer="ada",
        now=3.0, expected_revision=created["revision"],
    )
    assert recovered["status"] == "in_review"
    assert recovered["revision"] == created["revision"] + 1
    assert phases[-1][0] == "published"
    assert len({txn for _phase, txn in phases}) == 1


def test_register_serializes_cross_process_writers_and_rejects_stale_cas(
    monkeypatch, tmp_path,
):
    monkeypatch.setattr(A, "subject_surface", lambda _kind, _name: dict(SAFE))
    created = A.refresh("agent", "calm_bot", now=1.0)
    script = (
        "import sys; from maverick import assessments; "
        "result = assessments.add_evidence("
        "'agent', 'calm_bot', 'security', 'Capability envelope', sys.argv[1]); "
        "raise SystemExit(0 if result is not None else 2)"
    )
    env = os.environ.copy()
    env["MAVERICK_HOME"] = str(tmp_path)
    env["HOME"] = str(tmp_path)
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", script, f"evidence-{index}"], env=env,
        )
        for index in range(4)
    ]
    for worker in workers:
        assert worker.wait(timeout=20) == 0

    current = A.get_assessment("agent", "calm_bot")
    finding = next(
        item for item in current["lenses"]["security"]["findings"]
        if item["control"] == "Capability envelope"
    )
    assert sorted(finding["evidence"]) == [f"evidence-{index}" for index in range(4)]
    assert current["revision"] == created["revision"] + 4
    with pytest.raises(A.AssessmentVersionConflict):
        A.add_evidence(
            "agent", "calm_bot", "security", "Capability envelope", "stale",
            expected_revision=created["revision"],
        )
