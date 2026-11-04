"""Complete signed native teachers with two- and three-action paths.

The journal connector performs real local writes. It deliberately has a fixed
customer lookup result; this fixture qualifies trace and authority binding, not
variable external identifier allocation or a live business integration.
"""
from __future__ import annotations

import copy
import time

import pytest
from maverick import config
from maverick.flow import (
    Flow,
    FlowNode,
    action_episode_review,
    action_provenance,
    execution,
    recipe_flow,
    recipe_lineage,
    store,
)
from maverick.flow.approvals import paused_operation_binding

from test_support.action_episode_native import (
    ALLOWED,
    TOOL_SCHEMAS,
    _calls,
    _context,
    _no_agent,
    _schema,
)
from test_support.action_episode_native import native as native
from test_support.recipe_lineage_native import resume_recipe

INPUT_SCHEMA = _schema({"customer": "customer", "quantity": 1, "repeat": True})
DOMAIN = {"inputs": INPUT_SCHEMA, "tools": copy.deepcopy(TOOL_SCHEMAS)}
SEEDS = [("short-a", False, 1), ("short-b", False, 4),
         ("long-a", True, 2), ("long-b", True, 3)]
FLAGS = {"enable": True, "action_recipes": True, "action_recipe_transforms": True,
         "action_recipe_choices": True, "action_workflow_learning": True,
         "action_episode_capture": True, "action_recipe_lineage": True,
         "require_action_recipe_lineage": False,
         "action_evidence_issuer": "native-workflow-qualification", "action_evidence_revoked_keys": []}


def permit(ctx, capability, resource):
    if ctx != _context():
        return False
    if capability.startswith("flow.episode."):
        source = store.load_flow(resource)
        return source is not None and source.owner == ctx.resource_owner
    return capability in {"flow.recipe.admit", "flow.recipe.read", "flow.recipe.detail", "flow.recipe.draft"}


class WorkflowHarness:
    def __init__(self, journal, flags):
        self.journal, self.flags = journal, flags
        self.context = _context()
        self.service = action_episode_review.ActionEpisodeReviewService(permit)
        self.lineage = recipe_lineage.RecipeLineageService(permit)
        self.bundles = [self.capture(tag, repeat=repeat, quantity=quantity) for tag, repeat, quantity in SEEDS]
        self.package = self.learn(self.bundles)
        self.admission = self.lineage.admit(self.context, self.package)

    def trust(self):
        return action_provenance.local_trust(self.context.tenant)

    def calls(self):
        return _calls(self.journal)

    def counts(self):
        return len(self.calls())

    def learn(self, bundles, **options):
        return recipe_lineage.learn_transducer_from_verified_bundles(bundles,
            trust=self.trust(), expected_tenant=self.context.tenant, now=time.time(),
            allowed_tools=ALLOWED, domain=DOMAIN, **options)

    def start(self, flow, inputs):
        return execution.execute(flow, owner=self.context.resource_owner, data={"input": copy.deepcopy(inputs)},
            agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id=self.context.actor))

    def resume(self, run_id):
        return resume_recipe(run_id)

    def draft(self, identity, *, package=None, admission=None):
        package = self.package if package is None else package
        admission = self.admission if admission is None else admission
        flow = recipe_flow.make_flow(package["artifact"], flow_id=identity, name="Native variable-length workflow")
        flow.owner = self.context.resource_owner
        flow.recipe_lineage = copy.deepcopy(admission["reference"])
        store.save_flow(flow)
        return flow

    def capture(self, tag, *, repeat=False, quantity=3):
        inputs = {"customer": "customer-" + tag, "quantity": quantity, "repeat": repeat}
        source = Flow(id="workflow-teacher-" + tag, name="Native complete workflow teacher",
            owner=self.context.resource_owner, start="approve_lookup", nodes={
                "approve_lookup": FlowNode("approve_lookup", "approval", prompt="Review lookup", next="lookup"),
                "lookup": FlowNode("lookup", "action", tool=ALLOWED[0], params={"query": inputs["customer"]},
                                   output="lookup_result", next="approve_update"),
                "approve_update": FlowNode("approve_update", "approval", prompt="Review update", next="update"),
                "update": FlowNode("update", "action", tool=ALLOWED[1],
                                   params={"customer_id": "C42", "quantity": quantity}, output="update_result",
                                   next="approve_recheck" if repeat else None),
            })
        if repeat:
            source.nodes.update({
                "approve_recheck": FlowNode("approve_recheck", "approval", prompt="Review completed update", next="recheck"),
                "recheck": FlowNode("recheck", "action", tool=ALLOWED[0], params={"query": inputs["customer"]},
                                    output="rechecked_result"),
            })
        store.save_flow(source)
        run = self.start(source, inputs)
        assert run.status == "paused_approval"
        self.service.enroll(self.context, source.id, run.run_id,
            expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
            allowed_tools=ALLOWED, input_schema=INPUT_SCHEMA, tool_data_schemas=TOOL_SCHEMAS,
            retain_until=time.time() + 3600)
        for _ in range(3 if repeat else 2):
            run = self.resume(run.run_id)
        assert run.status == "completed", run.error
        row = self.service.get(self.context, source.id, run.run_id)
        assert row["status"] == "awaiting_review", row
        row = self.service.review(self.context, source.id, run.run_id,
            expected_revision=row["revision"], expected_episode_sha256=row["episode_sha256"],
            accepted=True, rationale="Reviewed the complete native two- or three-action trace")
        row = self.service.grant_training(self.context, source.id, run.run_id,
            expected_revision=row["revision"], expected_episode_sha256=row["episode_sha256"],
            use_until=time.time() + 1800, retain_derived_copies=True,
            rationale="Bounded workflow transducer qualification from actual local native execution")
        return self.service.export_signed(self.context, source.id, run.run_id,
            expected_revision=row["revision"], expected_episode_sha256=row["episode_sha256"],
            expected_grant_sha256=row["grant_sha256"])


@pytest.fixture
def workflow_native(native, monkeypatch):
    flags = copy.deepcopy(FLAGS)
    monkeypatch.setattr(config, "get_flows", lambda: copy.deepcopy(flags))
    return WorkflowHarness(native, flags)
