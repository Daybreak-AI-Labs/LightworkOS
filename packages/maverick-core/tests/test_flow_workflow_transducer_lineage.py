"""Signed native variable-length evidence and governed transducer admission."""
from __future__ import annotations

import copy
import time

import pytest
from maverick import audit, crypto_at_rest
from maverick.flow import action_episode_review, action_recipe, recipe_lineage, store

from test_support.action_episode_native import ALLOWED
from test_support.action_episode_native import native as native
from test_support.workflow_transducer_native import DOMAIN
from test_support.workflow_transducer_native import workflow_native as workflow_native


def validate(harness, package):
    recipe_lineage.validate_package(package, trust=harness.trust(), expected_tenant=harness.context.tenant,
                                   now=time.time())


def rehash(package):
    package.pop("package_sha256", None)
    package["package_sha256"] = recipe_lineage._digest(package)


def withdraw_first(harness):
    body = harness.package["bundles"][0]["body"]
    flow_id, run_id = body["source"]["flow_id"], body["source"]["run_id"]
    current = harness.service.get(harness.context, flow_id, run_id)
    return harness.service.withdraw(harness.context, flow_id, run_id,
        expected_revision=current["revision"], expected_episode_sha256=current["episode_sha256"],
        expected_review_sha256=body["review_sha256"], rationale="Withdraw actual native transducer training evidence")


def test_complete_native_paths_and_repeated_tool_are_covered_exactly(workflow_native):
    h = workflow_native
    package = h.package
    validate(h, package)
    assert package["artifact"]["schema"] == action_recipe.WORKFLOW_SCHEMA
    assert sorted(len(episode["steps"]) for episode in package["artifact"]["episodes"]) == [2, 2, 3, 3]
    assert h.counts() == 10
    ids = {episode["id"] for episode in package["artifact"]["episodes"]}
    assert ids == {row["episode_id"] for row in package["manifest"]} == set(package["batches"][0])
    for bundle in package["bundles"]:
        body = bundle["body"]
        assert body["review"]["authenticated"] is True
        assert body["review"]["accepted"] is True
        run = store.load_run(body["source"]["run_id"], owner=h.context.resource_owner)
        assert run.status == "completed"
        if len(body["episode"]["steps"]) == 3:
            assert [step["tool"] for step in body["episode"]["steps"]] == [ALLOWED[0], ALLOWED[1], ALLOWED[0]]
        assert len({step["call_id"] for step in body["steps"]}) == len(body["steps"])
    raw = h.lineage.records.get(h.admission["id"])
    assert crypto_at_rest.is_sealed_str(raw["sensitive_envelope"])
    assert h.lineage.get(h.context, h.admission["id"], detail=True)["package"] == package
    assert recipe_lineage.runtime_reference(h.admission["reference"], package["artifact"],
                                           owner=h.context.resource_owner)["current_eligibility"] == "accepted"


def test_refinement_rebuilds_original_signed_batches_and_fixed_grammar_and_cap(workflow_native):
    h = workflow_native
    original = h.learn(h.bundles, max_steps=4, max_operations=1, operators=["if", "not", "le"], constants=[2])
    before = copy.deepcopy(original)
    extra = h.capture("additional-long", repeat=True, quantity=7)
    refined = recipe_lineage.refine_package(original, [extra], trust=h.trust(),
        expected_tenant=h.context.tenant, now=time.time())
    validate(h, refined)
    assert original == before
    assert refined["artifact"]["grammar"] == original["artifact"]["grammar"]
    assert refined["artifact"]["max_steps"] == original["artifact"]["max_steps"] == 4
    assert len(refined["artifact"]["episodes"]) == 5 and h.counts() == 13
    assert refined["ancestors"] == [{"package_sha256": original["package_sha256"],
                                     "artifact_sha256": original["artifact"]["artifact_sha256"]}]
    refined["ancestors"][0]["artifact_sha256"] = "0" * 64
    rehash(refined)
    with pytest.raises(ValueError, match="parent"):
        validate(h, refined)


@pytest.mark.parametrize("change", [
    lambda p: p["manifest"].pop(),
    lambda p: p["batches"][0].pop(),
    lambda p: p["bundles"][0]["body"]["episode"]["steps"].pop(),
    lambda p: p["bundles"][0]["signature"].update(signature="0" * 128),
    lambda p: p["artifact"]["episodes"][0]["inputs"].update(repeat="forged"),
    lambda p: p.update(owner="other-owner"),
])
def test_rehashing_cannot_forge_or_drop_native_transducer_evidence(workflow_native, change):
    h = workflow_native
    changed = copy.deepcopy(h.package)
    change(changed)
    rehash(changed)
    with pytest.raises(ValueError):
        validate(h, changed)
    with pytest.raises((ValueError, PermissionError)):
        h.lineage.admit(h.context, changed)
    assert h.lineage.records.count() == 1 and h.counts() == 10


@pytest.mark.parametrize("change", ["withdraw", "revoke_key"])
def test_current_reference_refuses_withdrawn_or_untrusted_training_source(workflow_native, change):
    h = workflow_native
    if change == "withdraw":
        assert withdraw_first(h)["status"] == "withdrawn"
    else:
        h.flags["action_evidence_revoked_keys"] = [h.package["bundles"][0]["signature"]["key_id"]]
    with pytest.raises((ValueError, action_episode_review.ActionEpisodeConflict)):
        recipe_lineage.runtime_reference(h.admission["reference"], h.package["artifact"], owner=h.context.resource_owner)
    with pytest.raises((ValueError, action_episode_review.ActionEpisodeConflict)):
        h.lineage.get(h.context, h.admission["id"], detail=True)
    assert h.counts() == 10


@pytest.mark.parametrize(("key", "value"), [
    ("action_workflow_learning", False), ("action_workflow_learning", 1),
    ("action_recipe_transforms", False), ("action_recipes", False),
])
def test_workflow_gates_stay_strict_when_general_lineage_requirement_is_off(workflow_native, key, value):
    h = workflow_native
    assert h.flags["require_action_recipe_lineage"] is False
    h.flags[key] = value
    with pytest.raises(PermissionError, match="workflow"):
        h.lineage.admit(h.context, h.package)
    with pytest.raises(PermissionError, match="workflow"):
        recipe_lineage.runtime_reference(h.admission["reference"], h.package["artifact"], owner=h.context.resource_owner)
    with pytest.raises(PermissionError, match="workflow"):
        h.lineage.draft(h.context, h.admission["id"], flow_id="disabled-workflow-draft", name="Disabled")
    assert store.load_flow("disabled-workflow-draft") is None and h.counts() == 10


def test_native_draft_requires_current_package_and_excludes_teaching_marker(workflow_native):
    h = workflow_native
    draft = h.lineage.draft(h.context, h.admission["id"], flow_id="workflow-draft", name="Reviewed workflow")
    assert draft["learned_recipe"] == h.package["artifact"]
    assert draft["recipe_lineage"] == h.admission["reference"]
    assert "recipe_teaching" not in draft
    assert store.load_flow("workflow-draft") is None
    with pytest.raises(ValueError, match="teaching"):
        h.lineage.draft(h.context, h.admission["id"], flow_id="teaching-workflow", name="Unsupported", teaching=True)


def test_schema_adapter_refuses_positional_history_and_requires_named_result_tool(workflow_native):
    h = workflow_native
    artifact = h.package["artifact"]
    episode = artifact["episodes"][0]
    decision = action_recipe.resolve_step(artifact, 0, episode["inputs"], [])
    assert decision.applied is False and decision.reason == "workflow_history_required"
    first = episode["steps"][0]
    action_recipe.validate_result(artifact, 0, first["result"], tool=first["tool"])
    with pytest.raises(ValueError):
        action_recipe.validate_result(artifact, 0, first["result"])
    with pytest.raises(ValueError):
        action_recipe.validate_result(artifact, 0, {"customer_id": "C42", "active": True, "pending": True}, tool=first["tool"])
    from maverick.flow.workflow_transducer import synthesize
    raw = synthesize(artifact["episodes"], allowed_tools=ALLOWED, domain=DOMAIN)
    action_recipe.validate_artifact(raw)
    with pytest.raises(ValueError):
        h.lineage.admit(h.context, raw)


@pytest.mark.parametrize("receipt", [False, 1])
def test_new_transducer_admission_withholds_package_until_literal_true_receipt(workflow_native, monkeypatch, receipt):
    h = workflow_native
    extra = h.capture("pending-long", repeat=True, quantity=8)
    package = recipe_lineage.refine_package(h.package, [extra], trust=h.trust(),
        expected_tenant=h.context.tenant, now=time.time())
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: receipt
                        if kwargs.get("record_type") == "flow_recipe_lineage" else original(*args, **kwargs))
    row = h.lineage.admit(h.context, package)
    assert row["status"] == "audit_pending" and "package" not in row
    assert "package" not in h.lineage.get(h.context, row["id"], detail=True)
    with pytest.raises(recipe_lineage.RecipeLineageAuditPending):
        h.lineage.draft(h.context, row["id"], flow_id="pending-draft", name="Pending")
    monkeypatch.setattr(audit, "record", original)
    recovered = h.lineage.get(h.context, row["id"], detail=True)
    assert recovered["status"] == "admitted" and recovered["package"] == package
    assert h.lineage.admit(h.context, package)["id"] == row["id"] and h.lineage.records.count() == 2
