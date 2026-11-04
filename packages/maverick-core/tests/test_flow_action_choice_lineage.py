"""Signed binary learning from actual approved SQLite action executions."""
from __future__ import annotations

import copy
import json
import multiprocessing
import time

import pytest
from maverick import audit, crypto_at_rest
from maverick.flow import Flow, action_choice, action_episode_review, action_recipe, store
from maverick.flow import recipe_lineage as lineage

from test_support.action_choice_native import (
    APPROVE,
    COUNTER_CASES,
    DOMAIN,
    OWNER,
    QUEUE,
    SEED_CASES,
    SOURCE_IDS,
    TENANT,
    TOOLS,
    child_redeliver,
    context,
    permit,
    redeliver,
    resume,
    start,
)
from test_support.action_choice_native import choice_native as choice_native


def learn(env):
    bundles = [env.capture(*values) for values in SEED_CASES]
    return lineage.learn_choice_from_verified_bundles(bundles, trust=env.trust(), expected_tenant=TENANT,
        now=time.time(), allowed_tools=TOOLS, domain=DOMAIN, max_operations=2,
        operators=["le", "lt", "not"], constants=[])


def validate(env, package):
    lineage.validate_package(package, trust=env.trust(), expected_tenant=TENANT, now=time.time())


def rehash(package):
    package.pop("package_sha256")
    package["package_sha256"] = lineage._digest(package)


def admitted_flow(env, package, identity):
    service = lineage.RecipeLineageService(permit)
    row = service.admit(context(), package)
    assert row["status"] == "admitted" and row["audit_status"] == "delivered"
    assert crypto_at_rest.is_sealed_str(service.records.get(row["id"])["sensitive_envelope"])
    flow = Flow.from_dict(service.draft(context(), row["id"], flow_id=identity, name="Native learned choice"))
    assert store.load_flow(identity) is None
    store.save_flow(flow)
    return flow, row


def test_choice_package_rebuild_preserves_signed_batches_seed_grammar_and_counterexamples(choice_native, record_property):
    env = choice_native
    package = learn(env)
    validate(env, package)
    assert package["artifact"]["schema"] == action_recipe.CHOICE_SCHEMA
    assert len(package["bundles"]) == len(package["manifest"]) == 6
    assert {bundle["body"]["source"]["flow_id"] for bundle in package["bundles"]} == set(SOURCE_IDS.values())
    assert all(bundle["body"]["review"]["authenticated"] is True for bundle in package["bundles"])
    assert len(env.business.rows("cases")) == len(env.business.rows("decisions")) == 6
    initial = copy.deepcopy(package)
    decision = action_choice.resolve_choice(package["artifact"],
        {"amount": 3, "limit": 8, "legacy_eligible": False}, [{"case_id": "unseen-case"}])
    assert not decision.applied and decision.reason == "ambiguity"
    for change in (
        lambda p: p["manifest"].pop(),
        lambda p: p["bundles"].pop(),
        lambda p: p["batches"][0].pop(),
        lambda p: p["artifact"]["episodes"][0]["inputs"].update(amount=99),
        lambda p: p["bundles"][0]["body"]["episode"]["steps"][1].update(tool="injected_terminal"),
    ):
        tampered = copy.deepcopy(package)
        change(tampered)
        rehash(tampered)
        with pytest.raises(ValueError):
            validate(env, tampered)
    counters = [env.capture(*values) for values in COUNTER_CASES]
    refined = lineage.refine_package(package, counters, trust=env.trust(), expected_tenant=TENANT, now=time.time())
    validate(env, refined)
    assert package == initial
    assert len(refined["bundles"]) == len(refined["manifest"]) == 8
    assert refined["artifact"]["grammar"] == package["artifact"]["grammar"]
    assert refined["ancestors"] == [{"package_sha256": package["package_sha256"],
                                     "artifact_sha256": package["artifact"]["artifact_sha256"]}]
    assert refined["artifact"]["guard_candidate_count"] < package["artifact"]["guard_candidate_count"]
    # Independent numeric oracle over held-out amounts/limits and both stale flag
    # states. These values are never passed to synthesis or refinement.
    for amount in range(10):
        for limit in range(10):
            for flag in (False, True):
                inputs = {"amount": amount, "limit": limit, "legacy_eligible": flag}
                selected = action_choice.resolve_choice(refined["artifact"], inputs, [{"case_id": "fresh-case"}])
                assert selected.applied and selected.tool == (APPROVE if amount <= limit else QUEUE)
                terminal = action_recipe.resolve_step(refined["artifact"], 1, inputs, [{"case_id": "fresh-case"}])
                assert terminal.applied and terminal.arguments == {"case_id": "fresh-case"}
    altered = copy.deepcopy(refined)
    altered["ancestors"][0]["package_sha256"] = "0" * 64
    rehash(altered)
    with pytest.raises(ValueError, match="parent"):
        validate(env, altered)
    record_property("choice_mathematical_evidence", json.dumps({
        "initial_signed_episodes": 6, "additional_signed_episodes": 2,
        "initial_guard_candidates": package["artifact"]["guard_candidate_count"],
        "refined_guard_candidates": refined["artifact"]["guard_candidate_count"],
        "independent_numeric_cases": 200, "applied": 200, "abstentions": 0, "wrong": 0,
    }, sort_keys=True))


def test_admitted_choice_stale_flag_stops_after_case_commit_and_fresh_process_never_replays(choice_native, record_property):
    env = choice_native
    package = learn(env)
    flow, admission = admitted_flow(env, package, "coincident-native-choice")
    original_cases = len(env.business.rows("cases"))
    original_decisions = len(env.business.rows("decisions"))
    run = start(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
    assert run.status == "paused_approval" and run.cursor == "approval_0"
    stopped = resume(run.run_id)
    assert stopped.status == "indeterminate" and stopped.cursor == "choice"
    assert "_recipe_step_0" in stopped.data and "_recipe_step_1" not in stopped.data
    assert len(env.business.rows("cases")) == original_cases + 1
    assert len(env.business.rows("decisions")) == original_decisions
    assert store.load_flow_snapshot(stopped.definition_digest).recipe_lineage == admission["reference"]
    attempts = env.business.rows("attempts")
    assert redeliver(run.run_id).status == "indeterminate"
    process = multiprocessing.get_context("spawn").Process(target=child_redeliver,
        args=(run.run_id, str(env.business.path), str(env.world_path)))
    process.start()
    process.join(40)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("fresh-process durable redelivery did not finish")
    assert process.exitcode == 0 and env.business.rows("attempts") == attempts
    assert store.load_run(run.run_id).data["_recipe_step_0"] == stopped.data["_recipe_step_0"]
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
              and event.get("flow_run_id") == run.run_id]
    assert any(event.get("status") == "choice_blocked" and event.get("reason") == "ambiguity" for event in events)
    assert all(event.get("sig") for event in events)

    refined = lineage.refine_package(package, [env.capture(*values) for values in COUNTER_CASES],
        trust=env.trust(), expected_tenant=TENANT, now=time.time())
    validate(env, refined)
    new_flow, new_admission = admitted_flow(env, refined, "refined-native-choice")
    completions = []
    for values in [(1, 9, False), (9, 1, True), (6, 6, False), (10, 5, True)]:
        inputs = dict(zip(("amount", "limit", "legacy_eligible"), values, strict=True))
        fresh = start(new_flow, inputs)
        first = resume(fresh.run_id)
        assert first.status == "paused_approval" and first.cursor.startswith("approval_1_")
        final = resume(fresh.run_id)
        assert final.status == "completed"
        case_id = final.data["_recipe_step_0"]["case_id"]
        actual = next(row for row in env.business.rows("decisions") if row["case_id"] == case_id)
        assert actual["tool"] == (APPROVE if values[0] <= values[1] else QUEUE)
        assert final.data["_recipe_step_1"] == ({"approved": True} if actual["tool"] == APPROVE else {"queued": True})
        completions.append((fresh.run_id, case_id))
    assert len({run_id for run_id, _ in completions}) == len({case_id for _, case_id in completions}) == 4
    assert stopped.data["_recipe_step_0"]["case_id"] not in {case_id for _, case_id in completions}
    # Existing quarantined run remains tied to its old package after a new
    # draft is admitted; refinement never repairs/restarts that run in place.
    assert redeliver(run.run_id).status == "indeterminate"
    completed_events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
        if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
        and event.get("flow_run_id") in {run_id for run_id, _ in completions}]
    assert any(new_admission["package_sha256"] in json.dumps(event) for event in completed_events)
    assert any("trust_sha256" in json.dumps(event) for event in completed_events)
    all_events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    calls = [event for event in all_events if event["kind"] == audit.EventKind.TOOL_CALL and event.get("name") in TOOLS]
    results = [event for event in all_events if event["kind"] == audit.EventKind.TOOL_RESULT and event.get("name") in TOOLS]
    assert len(calls) == len(results) == len(env.business.rows("attempts")) == 25
    assert len({event["call_id"] for event in calls}) == 25
    assert {event["call_id"] for event in calls} == {event["call_id"] for event in results}
    assert all(event.get("sig") for event in [*calls, *results])
    record_property("choice_native_evidence", json.dumps({
        "teacher_source_flows": 2, "reviewed_signed_teachers": 8,
        "teacher_native_actions": 16, "ambiguous_committed_prefixes": 1,
        "fresh_completed_runs": 4, "fresh_case_ids": 4,
        "fresh_process_redelivery_exit": process.exitcode, "replayed_actions": 0,
        "native_call_receipts": len(calls), "native_terminal_receipts": len(results),
    }, sort_keys=True))


@pytest.mark.parametrize("revoke", ["review", "key", "review_during_receipt"])
def test_choice_current_signed_authority_is_rechecked_after_prefix_and_approval_pause(choice_native, monkeypatch, revoke):
    env = choice_native
    package = learn(env)
    flow, _ = admitted_flow(env, package, "choice-withdrawal")
    baseline = len(env.business.rows("attempts"))
    run = start(flow, {"amount": 2, "limit": 5, "legacy_eligible": True})
    first = resume(run.run_id)
    assert first.status == "paused_approval"
    assert len(env.business.rows("attempts")) == baseline + 1
    bundle = package["bundles"][0]

    def withdraw():
        service = action_episode_review.ActionEpisodeReviewService(permit)
        body = bundle["body"]
        source = body["source"]
        row = service.get(context(), source["flow_id"], source["run_id"])
        service.withdraw(context(), source["flow_id"], source["run_id"], expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], expected_review_sha256=body["review_sha256"],
            rationale="Withdraw exact reviewed choice evidence between native effects")

    intercepted = []
    if revoke == "key":
        env.flags["action_evidence_revoked_keys"] = [bundle["signature"]["key_id"]]
    elif revoke == "review":
        withdraw()
    else:
        original = audit.record

        def record(*args, **kwargs):
            acknowledged = original(*args, **kwargs)
            if (not intercepted and args and args[0] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                    and kwargs.get("flow_run_id") == run.run_id and kwargs.get("step_index") == 1
                    and kwargs.get("status") == "selected"):
                assert acknowledged is True
                intercepted.append(True)
                withdraw()
            return acknowledged

        monkeypatch.setattr(audit, "record", record)
    final = resume(run.run_id)
    assert final.status == "indeterminate" and final.data["_recipe_step_0"] == first.data["_recipe_step_0"]
    assert "_recipe_step_1" not in final.data and len(env.business.rows("attempts")) == baseline + 1
    assert redeliver(run.run_id).status == "indeterminate"
    assert len(env.business.rows("attempts")) == baseline + 1
    if revoke == "review_during_receipt":
        assert intercepted == [True]
    with pytest.raises((ValueError, PermissionError, action_episode_review.ActionEpisodeConflict)):
        lineage.runtime_reference(flow.recipe_lineage, package["artifact"], owner=OWNER)
