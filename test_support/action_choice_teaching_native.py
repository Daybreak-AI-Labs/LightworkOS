"""Native bounded teaching fixtures; every demonstration is an actual run."""
from __future__ import annotations

import copy
import importlib
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from maverick import config, tools, world_model
from maverick.flow import action_episode_review, execution, recipe_flow, recipe_lineage, store
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick.paths import tenant_scope
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

from test_support.action_choice_native import (
    DOMAIN,
    FLAGS,
    INPUT_SCHEMA,
    OWNER,
    SEED_CASES,
    TENANT,
    TOOL_SCHEMAS,
    TOOLS,
    Business,
    context,
    no_agent,
    registry_for,
    start,
)
from test_support.action_choice_native import choice_native as choice_native


def permit(ctx, capability, resource):
    if ctx != context():
        return False
    if capability.startswith("flow.episode."):
        source = store.load_flow(resource)
        return source is not None and source.owner == OWNER
    return capability in {"flow.recipe.admit", "flow.recipe.read", "flow.recipe.detail", "flow.recipe.draft"}


def resume(run_id, *, decision="approved"):
    prior = store.load_run(run_id, owner=OWNER)
    pinned = store.load_flow_snapshot(prior.definition_digest)
    binding = paused_operation_binding(prior)
    material = flow_decision_attestation_material(prior, inputs=None, operation_binding_sha256=binding,
        authority_binding_sha256="", decision=decision, decided_by=OWNER)
    attestation = issue_flow_decision_attestation(None, material=material,
        expires_at=float(prior.human["approval_card"]["expires_at"]))
    return execution.execute(pinned, owner=OWNER, resume_run_id=run_id, decision=decision,
        decided_by=OWNER, approval_binding_sha256=binding, approval_decision_attestation=attestation,
        agent_runner=no_agent, action_runner=execution.default_action_runner(None, user_id=OWNER))


def child_resume(run_id, business_path, world_path, decision):
    business = Business(business_path, create=False)
    registry = registry_for(business)
    risk = importlib.import_module("maverick.safety.tool_risk")
    with (patch.object(config, "get_flows", lambda: {**copy.deepcopy(FLAGS), "action_recipe_teaching": True}),
          patch.object(world_model, "DEFAULT_DB", Path(world_path)),
          patch.object(tools, "base_registry", lambda *args, **kwargs: registry),
          patch.object(risk, "_load_overrides", lambda: dict.fromkeys(TOOLS, "high")),
          tenant_scope(tenant=TENANT)):
        resumed = resume(run_id, decision=decision)
        assert resumed.status == "paused_approval" and resumed.cursor.startswith("approval_1_")


class TeachingHarness:
    def __init__(self, native):
        self.native = native
        self.service = action_episode_review.ActionEpisodeReviewService(permit)
        bundles = [native.capture(*values) for values in SEED_CASES]
        self.package = recipe_lineage.learn_choice_from_verified_bundles(bundles, trust=native.trust(),
            expected_tenant=TENANT, now=time.time(), allowed_tools=TOOLS, domain=DOMAIN,
            max_operations=2, operators=["le", "lt", "not"], constants=[])
        self.admission = recipe_lineage.RecipeLineageService(permit).admit(context(), self.package)

    def draft(self, identity, *, teaching=True, package=None, admission=None):
        package = self.package if package is None else package
        admission = self.admission if admission is None else admission
        flow = recipe_flow.make_flow(package["artifact"], flow_id=identity, name="Native teaching qualification", teaching=teaching)
        flow.owner = OWNER
        flow.recipe_lineage = copy.deepcopy(admission["reference"])
        store.save_flow(flow)
        return flow

    def enroll(self, flow, inputs):
        run = start(flow, inputs)
        assert run.status == "paused_approval" and run.cursor == "approval_0"
        self.service.enroll(context(), flow.id, run.run_id,
            expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)), allowed_tools=TOOLS,
            input_schema=INPUT_SCHEMA, tool_data_schemas=TOOL_SCHEMAS, retain_until=time.time() + 3600)
        return run

    def export(self, run_id):
        run = store.load_run(run_id, owner=OWNER)
        row = self.service.get(context(), run.flow_id, run_id)
        assert row["status"] == "awaiting_review", row
        row = self.service.review(context(), run.flow_id, run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], accepted=True,
            rationale="Reviewed actual human-taught native case and terminal effect")
        row = self.service.grant_training(context(), run.flow_id, run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], use_until=time.time() + 1800,
            retain_derived_copies=True, rationale="Bounded reuse of native human teaching evidence")
        return self.service.export_signed(context(), run.flow_id, run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], expected_grant_sha256=row["grant_sha256"])


@pytest.fixture
def teaching_native(choice_native):
    choice_native.flags["action_recipe_teaching"] = True
    return TeachingHarness(choice_native)
