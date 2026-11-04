"""Native teaching pauses preserve exact effects, approvals and evidence gates."""
from __future__ import annotations

import copy
import time

import pytest
from maverick import audit
from maverick.approval_cards import ApprovalCardError
from maverick.audit.errors import AuditRefused
from maverick.flow import Flow, action_episode_review, execution, recipe_lineage, store
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

from test_support.action_choice_native import (
    APPROVE,
    DOMAIN,
    OPEN,
    OWNER,
    QUEUE,
    SEED_CASES,
    TENANT,
    TOOLS,
    context,
    no_agent,
    permit,
    redeliver,
    start,
)
from test_support.action_choice_native import choice_native as choice_native


def decide(run_id, verdict="approved", *, inputs=None, authenticated=True):
    prior = store.load_run(run_id, owner=OWNER)
    binding = paused_operation_binding(prior, inputs=inputs)
    material = flow_decision_attestation_material(prior, inputs=inputs,
        operation_binding_sha256=binding, authority_binding_sha256="",
        decision=verdict, decided_by=OWNER)
    token = issue_flow_decision_attestation(None, material=material,
        expires_at=float(prior.human["approval_card"]["expires_at"])) if authenticated else None
    return execution.execute(store.load_flow_snapshot(prior.definition_digest), owner=OWNER,
        resume_run_id=run_id, decision=verdict, decided_by=OWNER, inputs=inputs,
        approval_binding_sha256=binding, approval_decision_attestation=token,
        agent_runner=no_agent, action_runner=execution.default_action_runner(None, user_id=OWNER))


@pytest.fixture
def teaching(choice_native):
    env = choice_native
    env.flags["action_recipe_teaching"] = True
    package = recipe_lineage.learn_choice_from_verified_bundles(
        [env.capture(*values) for values in SEED_CASES], trust=env.trust(), expected_tenant=TENANT,
        now=time.time(), allowed_tools=TOOLS, domain=DOMAIN, max_operations=2,
        operators=["le", "lt", "not"], constants=[])
    service = recipe_lineage.RecipeLineageService(permit)
    row = service.admit(context(), package)
    flow = Flow.from_dict(service.draft(context(), row["id"], flow_id="native-teaching-runtime",
        name="Reviewed continuation teaching", teaching=True))
    store.save_flow(flow)
    return env, flow, package


def paused(teaching, values=(3, 8, False), *, data=None):
    env, flow, _ = teaching
    inputs = dict(zip(("amount", "limit", "legacy_eligible"), values, strict=True))
    if data is None:
        first = start(flow, inputs)
    else:
        first = execution.execute(flow, owner=OWNER, data={**data, "input": inputs},
            agent_runner=no_agent, action_runner=execution.default_action_runner(None, user_id=OWNER))
    assert first.status == "paused_approval" and first.cursor == "approval_0"
    before = len(env.business.rows("attempts"))
    run = decide(first.run_id)
    assert run.status == "paused_approval" and run.cursor == "teaching_review", run.error
    assert len(env.business.rows("attempts")) == before + 1
    return run


@pytest.mark.parametrize("values,tool,route", [((3, 8, False), APPROVE, "0"), ((9, 4, True), QUEUE, "1")])
def test_real_prefix_question_and_separate_action_approval(teaching, values, tool, route):
    env, _, _ = teaching
    run = paused(teaching, values)
    question = run.data["_recipe_teaching_question"]
    assert question["observation"] == {"inputs": run.data["input"], "prefix_result": run.data["_recipe_step_0"]}
    assert {option["tool"] for option in question["options"]} == {APPROVE, QUEUE}
    assert all(option["arguments"] == run.data["_recipe_step_0"] for option in question["options"])
    before = copy.deepcopy(env.business.rows("attempts"))
    selected = decide(run.run_id, "route:" + route)
    assert selected.status == "paused_approval" and selected.cursor == "approval_1_" + route, selected.error
    assert env.business.rows("attempts") == before
    assert selected.data["_recipe_next_arguments"] == run.data["_recipe_step_0"]
    assert selected.nodes["teaching_review"]["status"] == "route:" + route
    final = decide(run.run_id)
    assert final.status == "completed", final.error
    assert len(env.business.rows("attempts")) == len(before) + 1
    assert env.business.rows("attempts")[-1]["tool"] == tool
    attempts = copy.deepcopy(env.business.rows("attempts"))
    assert redeliver(run.run_id).status == "completed"
    assert env.business.rows("attempts") == attempts
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
              and event.get("flow_run_id") == run.run_id]
    for status in ("teaching_requested", "teaching_selected", "completed"):
        assert any(event.get("status") == status and event.get("sig") for event in events)
    terminal = [event for event in events if event.get("node_id") == "action_1_" + route]
    assert terminal and all(event.get("recipe_teaching", {}).get("question_sha256") == question["question_sha256"] for event in terminal)


def test_generic_approval_and_unsigned_route_preserve_current_teaching_pause(teaching):
    env, _, _ = teaching
    run = paused(teaching)
    binding = paused_operation_binding(store.load_run(run.run_id))
    before = copy.deepcopy(env.business.rows("attempts"))
    with pytest.raises(ValueError, match="explicit valid approval decision"):
        decide(run.run_id)
    with pytest.raises(ApprovalCardError, match="attestation"):
        decide(run.run_id, "route:0", authenticated=False)
    current = store.load_run(run.run_id)
    assert current.status == "paused_approval" and current.cursor == "teaching_review"
    assert paused_operation_binding(current) == binding
    assert env.business.rows("attempts") == before
    assert decide(run.run_id, "route:0").cursor == "approval_1_0"


def test_rejection_preserves_completed_prefix_without_continuation(teaching):
    env, _, _ = teaching
    run = paused(teaching)
    before = copy.deepcopy(env.business.rows("attempts"))
    rejected = decide(run.run_id, "rejected")
    assert rejected.status == "rejected"
    assert rejected.data["_recipe_step_0"] == run.data["_recipe_step_0"]
    assert env.business.rows("attempts") == before
    assert redeliver(run.run_id).status == "rejected"


def test_untrusted_initial_and_resume_fields_cannot_preselect_teaching_route(teaching):
    env, _, _ = teaching
    forged = {"_recipe_teaching_question": {"schema": "fake"}, "_recipe_teaching_decision": "route:1",
              "_recipe_teaching_selection": {"route": "1", "tool": QUEUE}, "_recipe_choice": {"route": "1"}}
    run = paused(teaching, data=forged)
    assert run.data["_recipe_teaching_question"] != forged["_recipe_teaching_question"]
    assert "_recipe_teaching_decision" not in run.data and "_recipe_teaching_selection" not in run.data
    selected = decide(run.run_id, "route:0", inputs=forged)
    assert selected.status == "paused_approval" and selected.cursor == "approval_1_0", selected.error
    assert selected.data["_recipe_teaching_selection"]["tool"] == APPROVE
    assert decide(run.run_id, inputs=forged).status == "completed"
    assert env.business.rows("attempts")[-1]["tool"] == APPROVE


@pytest.mark.parametrize("stage", ["question", "selection", "terminal"])
def test_feature_withdrawal_after_required_receipt_prevents_terminal_effect(teaching, monkeypatch, stage):
    env, flow, _ = teaching
    first = start(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
    if stage != "question":
        first = decide(first.run_id)
    if stage == "terminal":
        first = decide(first.run_id, "route:0")
    before = len(env.business.rows("attempts"))
    target = {"question": "teaching_requested", "selection": "teaching_selected", "terminal": "selected"}[stage]
    seen = []
    original = audit.record

    def record(*args, **kwargs):
        result = original(*args, **kwargs)
        if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                and kwargs.get("flow_run_id") == first.run_id and kwargs.get("status") == target
                and kwargs.get("step_index") == 1):
            assert result is True
            seen.append(True)
            env.flags["action_recipe_teaching"] = False
        return result

    monkeypatch.setattr(audit, "record", record)
    stopped = decide(first.run_id, "route:0" if stage == "selection" else "approved")
    assert seen and stopped.status in {"failed", "indeterminate"}
    assert len(env.business.rows("attempts")) == before + int(stage == "question")
    assert "_recipe_step_0" in stopped.data and "_recipe_step_1" not in stopped.data


def test_source_review_withdrawal_between_question_and_selection_prevents_effect(teaching):
    env, _, package = teaching
    run = paused(teaching)
    before = copy.deepcopy(env.business.rows("attempts"))
    body = package["bundles"][0]["body"]
    source = body["source"]
    service = action_episode_review.ActionEpisodeReviewService(permit)
    row = service.get(context(), source["flow_id"], source["run_id"])
    service.withdraw(context(), source["flow_id"], source["run_id"], expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], expected_review_sha256=body["review_sha256"],
        rationale="Withdraw teaching parent evidence before decision")
    stopped = decide(run.run_id, "route:0")
    assert stopped.status in {"failed", "indeterminate"}
    assert env.business.rows("attempts") == before


def test_agreement_uses_existing_branch_approval_without_teaching_question(teaching):
    env, flow, _ = teaching
    first = start(flow, {"amount": 2, "limit": 5, "legacy_eligible": True})
    continued = decide(first.run_id)
    assert continued.status == "paused_approval" and continued.cursor == "approval_1_0"
    assert "_recipe_teaching_question" not in continued.data
    assert decide(first.run_id).status == "completed"
    assert env.business.rows("attempts")[-1]["tool"] == APPROVE


def test_teaching_disabled_before_first_action_cannot_commit_prefix(teaching):
    env, flow, _ = teaching
    env.flags["action_recipe_teaching"] = False
    before = copy.deepcopy(env.business.rows("attempts"))
    run = start(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
    assert run.status == "failed" and "feature_disabled" in run.error
    assert env.business.rows("attempts") == before
    assert all(row["tool"] in {OPEN, APPROVE, QUEUE} for row in before)


def test_teaching_request_and_selection_require_literal_receipt_acknowledgement(teaching, monkeypatch):
    env, flow, _ = teaching
    for target in ("teaching_requested", "teaching_selected"):
        first = start(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
        if target == "teaching_selected":
            first = decide(first.run_id)
        before = len(env.business.rows("attempts"))
        original = audit.record
        seen = []

        def record(*args, original=original, first=first, target=target, seen=seen, **kwargs):
            result = original(*args, **kwargs)
            if (args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                    and kwargs.get("flow_run_id") == first.run_id and kwargs.get("status") == target):
                seen.append(True)
                return 1  # Truthy is not the required literal True delivery receipt.
            return result

        with monkeypatch.context() as boundary:
            boundary.setattr(audit, "record", record)
            with pytest.raises(AuditRefused):
                decide(first.run_id, "route:0" if target == "teaching_selected" else "approved")
        stopped = store.load_run(first.run_id)
        # A failed question receipt follows a new effect and quarantines it;
        # a failed selection receipt precedes any new effect and keeps the pause.
        expected_status = "indeterminate" if target == "teaching_requested" else "paused_approval"
        assert seen and stopped.status == expected_status
        assert len(env.business.rows("attempts")) == before + int(target == "teaching_requested")
        assert "_recipe_step_1" not in stopped.data
        attempts = copy.deepcopy(env.business.rows("attempts"))
        assert redeliver(first.run_id).status == expected_status
        assert env.business.rows("attempts") == attempts


def test_run_detail_exposes_complete_verified_question_and_withholds_invalid_preview(teaching, monkeypatch):
    from maverick.flow import payloads
    from maverick_dashboard import api, rbac

    rbac.set_tenant_role(TENANT, OWNER, "operator")

    run = paused(teaching)
    retained = store.load_run(run.run_id)
    # Force the generic display projection to contain no observations at all;
    # the purpose-built teaching review must still expose both exact options.
    with monkeypatch.context() as projection:
        projection.setattr(payloads, "preview", lambda value: {"preview": "omitted"})
        response = api._run_out(retained)
    assert response["approval_card_status"] == "current"
    assert response["data"] == {"preview": "omitted"}
    assert response["teaching_review"] == {"status": "current", "question": run.data["_recipe_teaching_question"]}
    listed = copy.deepcopy(retained)
    listed.metadata_only = True
    assert "teaching_review" not in api._run_out(listed)
    corrupted = copy.deepcopy(retained)
    corrupted.data["_recipe_teaching_question"]["options"][0]["arguments"]["case_id"] = "forged-case"
    rejected = api._run_out(corrupted)
    assert rejected["approval_card_status"] != "current"
    assert rejected.get("teaching_review", {}).get("status") != "current"
