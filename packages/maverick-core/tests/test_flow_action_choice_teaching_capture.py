"""Authenticated teaching capture, portable provenance and real refinement."""
from __future__ import annotations

import copy
import json
import multiprocessing
import time

import pytest
from maverick import audit
from maverick.flow import (
    action_episode_review,
    action_provenance,
    action_recipe_transforms,
    recipe_lineage,
    store,
)
from maverick.flow.action_episodes import TEACHING_FAMILY, capture_plan, teaching_capture_plan
from maverick.flow.approvals import paused_operation_binding

from test_support.action_choice_native import (
    APPROVE,
    INPUT_SCHEMA,
    OWNER,
    QUEUE,
    TENANT,
    TOOL_SCHEMAS,
    TOOLS,
    context,
    redeliver,
    start,
)
from test_support.action_choice_native import choice_native as choice_native
from test_support.action_choice_teaching_native import child_resume, permit, resume
from test_support.action_choice_teaching_native import teaching_native as teaching_native
from test_support.audit_child_process import audit_signing_target


def test_real_human_teaching_capture_signs_distinct_family_and_refines_only_actual_actions(teaching_native, record_property):
    harness = teaching_native
    backend = harness.native.business
    flow = harness.draft("actual-native-teaching")
    with pytest.raises(ValueError, match="branching|straight-line"):
        capture_plan(flow, allowed_tools=TOOLS, no_forms=True)
    assert teaching_capture_plan(flow, allowed_tools=TOOLS)["prefix"][0] == "action_0"
    taught, teaching_runs, snapshots = [], [], []
    for index, (inputs, wanted) in enumerate([
        ({"amount": 3, "limit": 8, "legacy_eligible": False}, APPROVE),
        ({"amount": 9, "limit": 4, "legacy_eligible": True}, QUEUE),
    ]):
        baseline = len(backend.rows("attempts"))
        run = harness.enroll(flow, inputs)
        question_run = resume(run.run_id)
        assert question_run.status == "paused_approval" and question_run.cursor == "teaching_review", question_run.error
        assert len(backend.rows("attempts")) == baseline + 1
        question = question_run.data["_recipe_teaching_question"]
        case_id = question_run.data["_recipe_step_0"]["case_id"]
        assert question["observation"] == {"inputs": inputs, "prefix_result": {"case_id": case_id}}
        option = next(option for option in question["options"] if option["tool"] == wanted)
        assert option["arguments"] == {"case_id": case_id}
        if index == 0:
            process = multiprocessing.get_context("spawn").Process(target=audit_signing_target(child_resume),
                args=(run.run_id, str(backend.path), str(harness.native.world_path), "route:" + option["route"]))
            process.start()
            process.join(45)
            if process.is_alive():
                process.terminate()
                process.join(5)
                pytest.fail("fresh process did not authenticate the native teaching decision")
            assert process.exitcode == 0
            selected = store.load_run(run.run_id, owner=OWNER)
        else:
            selected = resume(run.run_id, decision="route:" + option["route"])
        assert selected.status == "paused_approval" and selected.cursor == "approval_1_" + option["route"]
        assert len(backend.rows("attempts")) == baseline + 1
        final = resume(run.run_id)
        assert final.status == "completed", final.error
        assert len(backend.rows("attempts")) == baseline + 2
        assert backend.rows("decisions")[-1] == {"case_id": case_id, "tool": wanted}
        bundle = harness.export(run.run_id)
        body = bundle["body"]
        assert body["schema"] == action_provenance.TEACHING_SCHEMA
        assert body["source"]["family"] == TEACHING_FAMILY
        assert [step["node_id"] for step in body["steps"]] == ["action_0", "action_1_" + option["route"]]
        assert body["teaching"]["decision_origin"] == "authenticated_human"
        assert body["teaching"]["actor"] == OWNER and body["teaching"]["question"] == question
        assert body["teaching"]["parent_lineage"] == harness.admission["reference"]
        assert body["episode"]["steps"][0]["result"] == {"case_id": case_id}
        assert body["episode"]["steps"][1]["arguments"] == {"case_id": case_id}
        checked = action_provenance.verify_bundle(bundle, trust=harness.native.trust(), expected_tenant=TENANT, now=time.time())
        assert checked["live_status"] == "not_checked"
        assert harness.service.assert_bundle_current(context(), bundle)["live_status"] == "accepted"
        row = harness.service.get(context(), flow.id, run.run_id)
        captured = harness.service.records.get(row["id"])
        invalid_payload = action_episode_review._open(context(), captured)
        other_tool = QUEUE if wanted == APPROVE else APPROVE
        invalid_payload["contract"]["tool_data_schemas"][other_tool]["arguments"]["properties"]["case_id"]["maxLength"] = 1
        with pytest.raises(ValueError, match="declared bounds"):
            action_episode_review._validate_teaching_capture(captured, invalid_payload, final,
                store.load_flow_snapshot(final.definition_digest))
        # Portable validation binds the actual observation and selected action;
        # no caller-provided route/actor/question field is treated as proof.
        for mutate in (
            lambda value: value.update(actor="different-human"),
            lambda value: value.update(route="1" if value["route"] == "0" else "0"),
            lambda value: value["decision_material"].update(operation_binding_sha256="0" * 64),
            lambda value: value["parent_lineage"].update(artifact_sha256="0" * 64),
            lambda value: value["question"]["observation"].update(prefix_result={"case_id": "fabricated-case"}),
        ):
            changed = copy.deepcopy(body["teaching"])
            mutate(changed)
            with pytest.raises(ValueError):
                action_provenance.validate_teaching(changed, source=body["source"], inputs=inputs,
                                                    prefix_result={"case_id": case_id})
        typed_alias = copy.deepcopy(body["teaching"])
        aliased_question = typed_alias["question"]
        aliased_question["observation"]["inputs"]["legacy_eligible"] = int(inputs["legacy_eligible"])
        aliased_question["question_sha256"] = action_recipe_transforms._digest({
            key: value for key, value in aliased_question.items() if key != "question_sha256"})
        typed_alias["question_sha256"] = aliased_question["question_sha256"]
        with pytest.raises(ValueError, match="question commitment"):
            action_provenance.validate_teaching(typed_alias, source=body["source"], inputs=inputs,
                                               prefix_result={"case_id": case_id})
        forged = copy.deepcopy(body["teaching"])
        forged["decision_attestation"]["signature"]["signature"] = "0" * 128
        with pytest.raises(ValueError, match="trusted"):
            action_provenance.verify_teaching_signature(forged, trust=harness.native.trust(), tenant=TENANT)
        downgraded = copy.deepcopy(bundle)
        downgraded["body"]["schema"] = action_provenance.SCHEMA
        with pytest.raises(ValueError):
            action_provenance.verify_bundle(downgraded, trust=harness.native.trust(), expected_tenant=TENANT, now=time.time())
        retained = store.load_run(run.run_id, owner=OWNER)
        changed = copy.deepcopy(retained)
        other_route = "1" if option["route"] == "0" else "0"
        changed.nodes["action_1_" + other_route] = {"status": "done", "outcome": 1.0}
        store.save_run(changed)
        try:
            with pytest.raises(ValueError, match="action trace"):
                harness.service.assert_bundle_current(context(), bundle)
        finally:
            store.save_run(retained)
        before = backend.rows("attempts")
        assert redeliver(run.run_id).status == "completed" and backend.rows("attempts") == before
        taught.append(bundle)
        teaching_runs.append(run.run_id)
        snapshots.append((run.run_id, case_id))
    refined = recipe_lineage.refine_package(harness.package, taught, trust=harness.native.trust(),
        expected_tenant=TENANT, now=time.time())
    recipe_lineage.validate_package(refined, trust=harness.native.trust(), expected_tenant=TENANT, now=time.time())
    assert refined["artifact"]["guard_candidate_count"] == 2 < harness.package["artifact"]["guard_candidate_count"]
    assert {bundle["body"]["schema"] for bundle in refined["bundles"]} == {action_provenance.SCHEMA, action_provenance.TEACHING_SCHEMA}
    assert refined["ancestors"][-1]["package_sha256"] == harness.package["package_sha256"]
    admission = recipe_lineage.RecipeLineageService(permit).admit(context(), refined)
    learned = harness.draft("taught-native-default", teaching=False, package=refined, admission=admission)
    completed = []
    for inputs, expected in [({"amount": 1, "limit": 7, "legacy_eligible": False}, APPROVE),
                             ({"amount": 10, "limit": 6, "legacy_eligible": True}, QUEUE)]:
        run = start(learned, inputs)
        pending = resume(run.run_id)
        assert pending.status == "paused_approval" and pending.cursor.startswith("approval_1_")
        assert "_recipe_teaching_question" not in pending.data
        final = resume(run.run_id)
        assert final.status == "completed"
        case_id = final.data["_recipe_step_0"]["case_id"]
        assert backend.rows("decisions")[-1] == {"case_id": case_id, "tool": expected}
        completed.append((run.run_id, case_id))
    assert len({case_id for _, case_id in [*snapshots, *completed]}) == 4
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    calls = [event for event in events if event["kind"] == audit.EventKind.TOOL_CALL and event.get("name") in TOOLS]
    results = [event for event in events if event["kind"] == audit.EventKind.TOOL_RESULT and event.get("name") in TOOLS]
    assert len(calls) == len(results) == len(backend.rows("attempts")) == 20
    assert {event["call_id"] for event in calls} == {event["call_id"] for event in results}
    assert all(event.get("sig") for event in [*calls, *results])
    record_property("native_teaching", json.dumps({"straight_line_seed_episodes": 6,
        "actual_taught_episodes": 2, "fresh_process_teaching_decisions": 1,
        "new_default_completions": 2, "native_call_receipts": 20, "native_terminal_receipts": 20,
        "replayed_prefixes": 0, "initial_guard_candidates": 3, "refined_guard_candidates": 2}))


def test_agreement_only_teaching_run_executes_but_cannot_export_human_teaching_evidence(teaching_native):
    harness = teaching_native
    flow = harness.draft("agreed-teaching-not-human")
    run = harness.enroll(flow, {"amount": 2, "limit": 5, "legacy_eligible": True})
    first = resume(run.run_id)
    assert first.status == "paused_approval" and first.cursor.startswith("approval_1_")
    assert "_recipe_teaching_question" not in first.data
    completed = resume(run.run_id)
    assert completed.status == "completed"
    row = harness.service.get(context(), flow.id, run.run_id)
    assert row["status"] == "unusable"
    with pytest.raises(action_episode_review.ActionEpisodeConflict):
        harness.service.export(context(), flow.id, run.run_id)


def test_bad_capture_attestation_loses_evidence_without_repeating_actual_work(teaching_native):
    harness = teaching_native
    backend = harness.native.business
    flow = harness.draft("bad-teaching-attestation")
    run = harness.enroll(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
    paused = resume(run.run_id)
    baseline = len(backend.rows("attempts"))
    assert paused.cursor == "teaching_review"
    handle = action_episode_review.load_capture_runtime(flow, paused, resumed=True,
        initial_data=copy.deepcopy(paused.input_data), submitted_inputs={}, from_failure=False,
        expired=False, decision="route:0", decided_by=OWNER, approval_binding_sha256="0" * 64,
        decision_attestation=None)
    assert handle is None
    assert harness.service.get(context(), flow.id, run.run_id)["status"] == "unusable"
    assert resume(run.run_id, decision="route:0").cursor == "approval_1_0"
    assert len(backend.rows("attempts")) == baseline
    assert resume(run.run_id).status == "completed"
    assert len(backend.rows("attempts")) == baseline + 1
    with pytest.raises(action_episode_review.ActionEpisodeConflict):
        harness.service.export(context(), flow.id, run.run_id)


def test_unselected_teaching_option_must_match_retention_contract_before_commit(teaching_native):
    harness = teaching_native
    backend = harness.native.business
    flow = harness.draft("teaching-unselected-retention-bounds")
    run = start(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
    schemas = copy.deepcopy(TOOL_SCHEMAS)
    # The fixture deliberately shares schema objects; narrow this unselected
    # tool independently so the actual prefix/selected action remain valid.
    schemas[QUEUE] = copy.deepcopy(schemas[QUEUE])
    schemas[QUEUE]["arguments"]["properties"]["case_id"]["maxLength"] = 1
    harness.service.enroll(context(), flow.id, run.run_id,
        expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
        allowed_tools=TOOLS, input_schema=INPUT_SCHEMA, tool_data_schemas=schemas,
        retain_until=time.time() + 3600)
    assert resume(run.run_id).cursor == "teaching_review"
    prefix_row = harness.service.get(context(), flow.id, run.run_id)
    assert prefix_row["status"] == "paused" and prefix_row["completed_steps"] == 1
    before = len(backend.rows("attempts"))
    assert resume(run.run_id, decision="route:0").cursor == "approval_1_0"
    row = harness.service.get(context(), flow.id, run.run_id)
    assert row["status"] == "unusable"
    retained = harness.service.records.get(row["id"])
    payload = action_episode_review._open(context(), retained)
    assert payload["teaching"] is None and "teaching_sha256" not in retained
    assert len(backend.rows("attempts")) == before
    assert resume(run.run_id).status == "completed"
    assert len(backend.rows("attempts")) == before + 1
    with pytest.raises(action_episode_review.ActionEpisodeConflict):
        harness.service.export(context(), flow.id, run.run_id)
