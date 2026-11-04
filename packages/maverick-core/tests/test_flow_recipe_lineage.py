"""Signed all-example lineage, encrypted admission and live source qualification."""
from __future__ import annotations

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from maverick import audit, crypto_at_rest
from maverick.flow import Flow, action_episode_review, action_recipe, execution, store
from maverick.flow import recipe_lineage as lineage
from maverick.paths import data_dir, tenant_scope

from test_support.action_episode_native import ALLOWED, _calls, _no_agent, _schema
from test_support.action_episode_native import native as native
from test_support.recipe_lineage_native import lineage_native as lineage_native
from test_support.recipe_lineage_native import permit, resume_recipe


def _learn(env, bundles=None, **options):
    bundles = bundles or [env["capture"]("first"), env["capture"]("second")]
    return lineage.learn_from_verified_bundles(bundles, trust=env["trust"](), expected_tenant=env["tenant"],
        now=time.time(), allowed_tools=ALLOWED, **options)


def _validate(env, package):
    lineage.validate_package(package, trust=env["trust"](), expected_tenant=env["tenant"], now=time.time())


def _rehash(package):
    package.pop("package_sha256")
    package["package_sha256"] = lineage._digest(package)


def test_native_signed_examples_exactly_cover_package_and_all_parent_lineage(lineage_native):
    env = lineage_native
    package = _learn(env)
    _validate(env, package)
    assert len(package["manifest"]) == 2
    assert {item["episode_id"] for item in package["manifest"]} == {row["id"] for row in package["artifact"]["episodes"]}
    before = copy.deepcopy(package)
    refined = lineage.refine_package(package, [env["capture"]("third")], trust=env["trust"](),
        expected_tenant=env["tenant"], now=time.time())
    _validate(env, refined)
    assert package == before and len(refined["bundles"]) == 3
    assert refined["ancestors"] == [{"package_sha256": package["package_sha256"],
                                     "artifact_sha256": package["artifact"]["artifact_sha256"]}]
    assert len(_calls(env["journal"])) == 6
    assert all(row["body"]["review"]["authenticated"] is True for row in refined["bundles"])


def test_transformed_refinement_reconstructs_seed_literal_and_old_signed_batches(lineage_native):
    env = lineage_native
    bundles = [env["capture"]("seed-a", quantity=1), env["capture"]("seed-b", quantity=2)]
    episode = bundles[0]["body"]["episode"]
    domain = {"inputs": _schema(episode["inputs"]), "steps": [
        {"arguments": _schema(step["arguments"]), "result": _schema(step["result"])} for step in episode["steps"]]}
    package = _learn(env, bundles, domain=domain, max_operations=1, operators=["max"])
    refined = lineage.refine_package(package, [env["capture"]("counter", quantity=4, output_quantity=4)],
        trust=env["trust"](), expected_tenant=env["tenant"], now=time.time())
    _validate(env, refined)
    assert refined["artifact"]["grammar"] == package["artifact"]["grammar"]
    binding = next(item for item in refined["artifact"]["steps"][1]["bindings"] if item["path"] == ["quantity"])
    assert binding["artifact"]["spec"]["constants"] == [3]
    decision = action_recipe.resolve_step(refined["artifact"], 1,
        {"customer": "fresh-customer", "quantity": 5}, [{"customer_id": "C42", "active": True}])
    assert decision.applied and decision.arguments == {"customer_id": "C42", "quantity": 5}
    changed = copy.deepcopy(refined)
    changed["ancestors"][0]["package_sha256"] = "0" * 64
    _rehash(changed)
    with pytest.raises(ValueError, match="parent"):
        _validate(env, changed)


@pytest.mark.parametrize("change", [
    lambda p: p["bundles"].pop(),
    lambda p: p["manifest"].pop(),
    lambda p: p["bundles"][0]["body"]["episode"]["inputs"].update(customer="forged"),
    lambda p: p["artifact"]["episodes"][0]["inputs"].update(customer="uncovered"),
    lambda p: p["batches"][0].pop(),
    lambda p: p.update(owner="other-owner"),
])
def test_rehashing_cannot_remove_or_replace_verified_training_evidence(lineage_native, change):
    env = lineage_native
    package = _learn(env)
    change(package)
    _rehash(package)
    with pytest.raises(ValueError):
        _validate(env, package)


def test_encrypted_audited_admission_draft_and_native_current_reference(lineage_native):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    row = service.admit(env["ctx"], package)
    assert row["status"] == "admitted" and row["audit_status"] == "delivered"
    assert service.admit(env["ctx"], package)["id"] == row["id"]
    assert service.records.count() == 1
    raw = service.records.get(row["id"])
    assert crypto_at_rest.is_sealed_str(raw["sensitive_envelope"])
    disk = data_dir("flow_recipe_lineage", row["id"] + ".json").read_text(encoding="utf-8")
    assert "customer-first" not in disk and '"bundles"' not in disk and '"artifact"' not in disk
    assert service.get(env["ctx"], row["id"], detail=True)["package"] == package
    draft = service.draft(env["ctx"], row["id"], flow_id="verified-draft", name="Verified action recipe")
    assert draft["learned_recipe"] == package["artifact"] and draft["recipe_lineage"] == row["reference"]
    assert store.load_flow("verified-draft") is None
    lineage.validate_reference(row["reference"], package["artifact"])
    current = lineage.runtime_reference(row["reference"], package["artifact"], owner=env["ctx"].resource_owner)
    assert current["id"] == row["id"] and current["current_eligibility"] == "accepted"
    assert len(_calls(env["journal"])) == 4
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("record_type") == "flow_recipe_lineage"]
    assert len(events) == 1 and events[0]["sig"]
    assert all("customer-first" not in json.dumps(event) and "bundles" not in event for event in events)


@pytest.mark.parametrize("receipt", [False, 1])
def test_audit_pending_exposes_no_content_and_retry_recovers_same_admission(lineage_native, monkeypatch, receipt):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: receipt
                        if kwargs.get("record_type") == "flow_recipe_lineage" else original(*args, **kwargs))
    row = service.admit(env["ctx"], package)
    assert row["status"] == "audit_pending" and "package" not in row
    pending = service.get(env["ctx"], row["id"], detail=True)
    assert pending["status"] == "audit_pending" and "package" not in pending
    with pytest.raises(lineage.RecipeLineageAuditPending):
        service.draft(env["ctx"], row["id"], flow_id="not-exposed", name="No pending draft")
    with pytest.raises(lineage.RecipeLineageAuditPending):
        lineage.runtime_reference(row["reference"], package["artifact"], owner=env["ctx"].resource_owner)
    monkeypatch.setattr(audit, "record", original)
    recovered = service.admit(env["ctx"], package)
    assert recovered["status"] == "admitted" and recovered["id"] == row["id"]
    assert recovered["revision"] == row["revision"] and service.records.count() == 1
    assert service.get(env["ctx"], row["id"], detail=True)["package"] == package


def test_admission_requires_literal_authority_and_human_and_never_trusts_payload_owner(lineage_native):
    env = lineage_native
    package = _learn(env)
    with pytest.raises(PermissionError):
        lineage.RecipeLineageService(lambda *args: 1).admit(env["ctx"], package)
    with pytest.raises(PermissionError):
        lineage.RecipeLineageService(lambda *args: True).admit(replace(env["ctx"], human=False), package)
    with pytest.raises(PermissionError):
        lineage.RecipeLineageService(lambda *args: True).admit(replace(env["ctx"], resource_owner="other"), package)
    assert lineage._RECORDS.count() == 0


def test_current_local_key_revocation_and_source_owner_loss_refuse_existing_reference(lineage_native):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    row = service.admit(env["ctx"], package)
    env["flags"]["action_evidence_revoked_keys"] = [package["bundles"][0]["signature"]["key_id"]]
    with pytest.raises(ValueError, match="trusted"):
        lineage.runtime_reference(row["reference"], package["artifact"], owner=env["ctx"].resource_owner)
    env["flags"]["action_evidence_revoked_keys"] = []
    source = store.load_flow("durable-native-actions")
    source.owner = "new-owner"
    store.save_flow(source)
    with pytest.raises(PermissionError):
        lineage.runtime_reference(row["reference"], package["artifact"], owner=env["ctx"].resource_owner)
    with tenant_scope(tenant="other-tenant"), pytest.raises((LookupError, PermissionError, ValueError)):
        lineage.runtime_reference(row["reference"], package["artifact"], owner=env["ctx"].resource_owner)


def test_expiry_removes_managed_sensitive_package_and_withholds_draft(lineage_native):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    row = service.admit(env["ctx"], package)
    expired = lineage.RecipeLineageService(permit, clock=lambda: package["use_until"])
    status = expired.get(env["ctx"], row["id"], detail=True)
    assert status["status"] == "expired" and "package" not in status
    assert "sensitive_envelope" not in service.records.get(row["id"])
    with pytest.raises(lineage.RecipeLineageConflict):
        expired.draft(env["ctx"], row["id"], flow_id="expired", name="Expired draft")


def test_reference_cannot_substitute_another_artifact_or_plaintext_record(lineage_native):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    row = service.admit(env["ctx"], package)
    changed = {**row["reference"], "artifact_sha256": "0" * 64}
    with pytest.raises(ValueError, match="different"):
        lineage.validate_reference(changed, package["artifact"])
    path = data_dir("flow_recipe_lineage", row["id"] + ".json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["sensitive_envelope"] = json.dumps(package)
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="sealed"):
        service.get(env["ctx"], row["id"], detail=True)


@pytest.mark.parametrize("change", ["none", "withdraw", "revoke_key"])
def test_real_native_recipe_execution_rechecks_lineage_between_persisted_approvals(lineage_native, change):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    row = service.admit(env["ctx"], package)
    flow = Flow.from_dict(service.draft(env["ctx"], row["id"], flow_id="governed-native-recipe", name="Governed native recipe"))
    store.save_flow(flow)
    run = execution.execute(flow, owner=flow.owner, data={"input": {"customer": "fresh-runtime", "quantity": 3}},
        agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"))
    assert run.status == "paused_approval" and len(_calls(env["journal"])) == 4
    first = resume_recipe(run.run_id)
    assert first.status == "paused_approval" and len(_calls(env["journal"])) == 5
    assert first.data["_recipe_step_0"] == {"customer_id": "C42", "active": True}
    if change == "withdraw":
        source = package["bundles"][0]["body"]
        episodes = action_episode_review.ActionEpisodeReviewService(permit)
        current = episodes.get(env["ctx"], source["source"]["flow_id"], source["source"]["run_id"])
        episodes.withdraw(env["ctx"], source["source"]["flow_id"], source["source"]["run_id"],
            expected_revision=current["revision"], expected_episode_sha256=current["episode_sha256"],
            expected_review_sha256=source["review_sha256"], rationale="Withdraw training use before next action")
    elif change == "revoke_key":
        env["flags"]["action_evidence_revoked_keys"] = [package["bundles"][0]["signature"]["key_id"]]
    final = resume_recipe(run.run_id)
    if change == "none":
        assert final.status == "completed" and len(_calls(env["journal"])) == 6
        assert final.data["_recipe_step_1"] == {"updated": True, "revision": 2}
        events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
                  if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION and event.get("flow_run_id") == run.run_id]
        assert events and any(row["package_sha256"] in json.dumps(event) for event in events)
        assert any("trust_sha256" in json.dumps(event) for event in events)
    else:
        assert final.status == "indeterminate" and len(_calls(env["journal"])) == 5
        assert final.data["_recipe_step_0"] == first.data["_recipe_step_0"]
        assert "_recipe_step_1" not in final.data
        repeated = execution.execute(flow, owner=flow.owner, run_id=run.run_id,
            agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"))
        assert repeated.status == "indeterminate" and len(_calls(env["journal"])) == 5


def test_pending_admission_recovers_receipt_but_withholds_later_withdrawn_source(lineage_native, monkeypatch):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False
                        if kwargs.get("record_type") == "flow_recipe_lineage" else original(*args, **kwargs))
    row = service.admit(env["ctx"], package)
    assert row["status"] == "audit_pending"
    source = package["bundles"][0]["body"]
    episodes = action_episode_review.ActionEpisodeReviewService(permit)
    current = episodes.get(env["ctx"], source["source"]["flow_id"], source["source"]["run_id"])
    episodes.withdraw(env["ctx"], source["source"]["flow_id"], source["source"]["run_id"],
        expected_revision=current["revision"], expected_episode_sha256=current["episode_sha256"],
        expected_review_sha256=source["review_sha256"], rationale="Withdraw while admission audit is pending")
    monkeypatch.setattr(audit, "record", original)
    with pytest.raises(action_episode_review.ActionEpisodeConflict):
        service.get(env["ctx"], row["id"], detail=True)
    assert not service.records.get(row["id"]).get("_audit_pending")
    with pytest.raises(action_episode_review.ActionEpisodeConflict):
        service.admit(env["ctx"], package)
    assert service.records.count() == 1


def test_concurrent_same_package_admission_has_one_cas_record_and_one_receipt(lineage_native, monkeypatch):
    env = lineage_native
    package = _learn(env)
    service = lineage.RecipeLineageService(permit)
    original = service.records.create
    rendezvous = threading.Barrier(2)

    def create(*args, **kwargs):
        rendezvous.wait(15)
        return original(*args, **kwargs)

    monkeypatch.setattr(service.records, "create", create)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result(30) for future in [pool.submit(service.admit, env["ctx"], package) for _ in range(2)]]
    assert results[0]["id"] == results[1]["id"] and all(row["status"] == "admitted" for row in results)
    assert service.records.count() == 1 and len(_calls(env["journal"])) == 4
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("record_type") == "flow_recipe_lineage"]
    assert len(events) == 1
