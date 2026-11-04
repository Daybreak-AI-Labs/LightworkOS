"""Actual captured/reviewed native episodes for lineage service qualification."""
from __future__ import annotations

import time

import pytest
from maverick import config
from maverick.flow import action_episode_review, action_provenance, execution, store
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

from test_support.action_episode_native import (
    ALLOWED,
    FLAGS,
    TENANT,
    TOOL_SCHEMAS,
    _context,
    _no_agent,
    _resume,
    _schema,
    _source,
)
from test_support.action_episode_native import native as native


def permit(ctx, capability, resource):
    return ctx == _context() and (
        (capability.startswith("flow.episode.") and resource == "durable-native-actions")
        or capability in {"flow.recipe.admit", "flow.recipe.read", "flow.recipe.detail", "flow.recipe.draft"}
    )


def captured_bundle(tag, *, quantity=3, output_quantity=3):
    service = action_episode_review.ActionEpisodeReviewService(permit)
    ctx = _context()
    source = _source()
    source.nodes["update"].params["quantity"] = output_quantity
    store.save_flow(source)
    inputs = {"customer": "customer-" + tag, "quantity": quantity}
    run = execution.execute(source, owner=source.owner, data={"input": inputs},
        agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"))
    assert run.status == "paused_approval"
    service.enroll(ctx, source.id, run.run_id,
        expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
        allowed_tools=ALLOWED, input_schema=_schema(inputs), tool_data_schemas=TOOL_SCHEMAS,
        retain_until=time.time() + 3600)
    assert _resume(run.run_id).status == "paused_approval"
    assert _resume(run.run_id).status == "completed"
    row = service.get(ctx, source.id, run.run_id)
    row = service.review(ctx, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], accepted=True, rationale="Reviewed actual fixture executions")
    row = service.grant_training(ctx, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], use_until=time.time() + 1800,
        retain_derived_copies=True, rationale="Retain bounded derived examples for local qualification")
    bundle = service.export_signed(ctx, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], expected_grant_sha256=row["grant_sha256"])
    assert set(bundle) == {"body", "signature"}
    return bundle


def resume_recipe(run_id):
    prior = store.load_run(run_id, owner="reviewer")
    source = store.load_flow_snapshot(prior.definition_digest)
    binding = paused_operation_binding(prior)
    material = flow_decision_attestation_material(prior, inputs=None, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="reviewer")
    attestation = issue_flow_decision_attestation(None, material=material,
        expires_at=float(prior.human["approval_card"]["expires_at"]))
    return execution.execute(source, owner="reviewer", resume_run_id=run_id,
        decision="approved", decided_by="reviewer", approval_binding_sha256=binding,
        approval_decision_attestation=attestation, agent_runner=_no_agent,
        action_runner=execution.default_action_runner(None, user_id="reviewer"))


@pytest.fixture
def lineage_native(native, monkeypatch):
    flags = {**FLAGS, "action_recipes": True, "action_recipe_transforms": True,
             "action_recipe_lineage": True, "require_action_recipe_lineage": False,
             "action_evidence_issuer": "native-lineage-qualification", "action_evidence_revoked_keys": []}
    monkeypatch.setattr(config, "get_flows", lambda: dict(flags))
    return {"journal": native, "flags": flags, "ctx": _context(), "tenant": TENANT,
            "capture": captured_bundle,
            "trust": lambda: action_provenance.local_trust(TENANT)}
