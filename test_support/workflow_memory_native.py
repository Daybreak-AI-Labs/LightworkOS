"""Signed native receipt traces from a local file-backed connector oracle.

The connector really consumes the next scheduled observation and writes a local
journal. The schedule is a deterministic test environment, not a real provider
or independent evidence that summing quantities is a customer's correct policy.
No episode, signature, approval, or native tool result is fabricated after capture.
"""
from __future__ import annotations

import copy
import importlib
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from maverick import config, tools, world_model
from maverick.flow import (
    Flow,
    FlowNode,
    action_episode_review,
    action_provenance,
    execution,
    recipe_lineage,
    store,
)
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick.paths import tenant_scope
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

from test_support.action_episode_native import TENANT, _calls, _context, _no_agent, _schema
from test_support.action_episode_native import native as native
from test_support.workflow_transducer_native import FLAGS as WORKFLOW_FLAGS
from test_support.workflow_transducer_native import permit

TOOL = "memory_receipt"
ALLOWED = [TOOL]
INPUT_SCHEMA = _schema({"target": 5})
INPUT_SCHEMA["properties"]["target"].update(minimum=1, maximum=20)
TOOL_SCHEMAS = {TOOL: {"arguments": copy.deepcopy(INPUT_SCHEMA), "result": _schema({"quantity": 1})}}
TOOL_SCHEMAS[TOOL]["result"]["properties"]["quantity"].update(minimum=1, maximum=10)
DOMAIN = {"inputs": INPUT_SCHEMA, "tools": TOOL_SCHEMAS}
FLAGS = {**WORKFLOW_FLAGS, "action_workflow_memory_learning": True,
         "action_evidence_issuer": "native-memory-qualification"}
# Same target/latest/count/order, but [2,3] finishes while [1,3] continues.
# Other cases vary count, maximum, ordering and overshoot without desired formulas.
SEEDS = [(5, [2, 3]), (5, [1, 3, 1]), (5, [1, 1, 3]),
         (5, [4, 2]), (6, [2, 1, 4]), (8, [3, 1, 4])]


def registry(journal, schedule):
    journal, schedule = Path(journal), Path(schedule)
    result = tools.ToolRegistry(principal="reviewer")

    def perform(arguments):
        plan = json.loads(schedule.read_text(encoding="utf-8"))
        previous = _calls(journal)
        index = len(previous) - plan["start"]
        if not 0 <= index < len(plan["quantities"]):
            raise AssertionError("native receipt schedule exhausted; an extra dispatch occurred")
        observation = {"quantity": plan["quantities"][index]}
        with journal.open("a", encoding="utf-8") as output:
            output.write(json.dumps({"tool": TOOL, "arguments": arguments, "result": observation,
                                     "ordinal": len(previous)}) + "\n")
        return json.dumps(observation)

    result.register(tools.Tool(name=TOOL, description="Local recorded receipt observation",
                              input_schema=TOOL_SCHEMAS[TOOL]["arguments"], fn=perform))
    return result


def decide(run_id, *, decision="approved", inputs=None, authenticated=True, action_runner=None):
    prior = store.load_run(run_id, owner="reviewer")
    binding = paused_operation_binding(prior, inputs=inputs)
    material = flow_decision_attestation_material(prior, inputs=inputs, operation_binding_sha256=binding,
        authority_binding_sha256="", decision=decision, decided_by="reviewer")
    attestation = issue_flow_decision_attestation(None, material=material,
        expires_at=float(prior.human["approval_card"]["expires_at"])) if authenticated else None
    return execution.execute(store.load_flow_snapshot(prior.definition_digest), owner="reviewer",
        resume_run_id=run_id, decision=decision, decided_by="reviewer", inputs=inputs,
        approval_binding_sha256=binding, approval_decision_attestation=attestation,
        agent_runner=_no_agent, action_runner=action_runner or execution.default_action_runner(None, user_id="reviewer"))


def redeliver(run_id):
    prior = store.load_run(run_id, owner="reviewer")
    return execution.execute(store.load_flow_snapshot(prior.definition_digest), owner="reviewer", run_id=run_id,
        agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"))


def child_resume(run_id, journal, schedule, world_path, flags):
    """Spawned worker reconstructs memory from disk; no live parent state crosses."""
    native_registry = registry(journal, schedule)
    risk = importlib.import_module("maverick.safety.tool_risk")
    with (patch.object(config, "get_flows", lambda: copy.deepcopy(flags)),
          patch.object(world_model, "DEFAULT_DB", Path(world_path)),
          patch.object(tools, "base_registry", lambda *args, **kwargs: native_registry),
          patch.object(risk, "_load_overrides", lambda: {TOOL: "high"}), tenant_scope(tenant=TENANT)):
        run = decide(run_id)
        assert run.status in {"paused_approval", "completed"}, run.error


class MemoryHarness:
    def __init__(self, journal, flags):
        self.journal, self.flags = journal, flags
        self.schedule = journal.with_name("memory-schedule.json")
        self.context = _context()
        self.service = action_episode_review.ActionEpisodeReviewService(permit)
        self.lineage = recipe_lineage.RecipeLineageService(permit)
        self.bundles = [self.capture("seed-" + str(index), target, quantities)
                        for index, (target, quantities) in enumerate(SEEDS)]
        self.package = self.learn(self.bundles)
        self.admission = self.lineage.admit(self.context, self.package)

    def calls(self):
        return _calls(self.journal)

    def counts(self):
        return len(self.calls())

    def plan(self, quantities):
        self.schedule.write_text(json.dumps({"start": self.counts(), "quantities": quantities}), encoding="utf-8")

    def trust(self):
        return action_provenance.local_trust(self.context.tenant)

    def learn(self, bundles):
        return recipe_lineage.learn_memory_from_verified_bundles(bundles,
            trust=self.trust(), expected_tenant=self.context.tenant, now=time.time(),
            allowed_tools=ALLOWED, domain=DOMAIN, max_operations=2, operators=["if", "le", "lt"], constants=[0])

    def start(self, flow, target, quantities, *, injected=None):
        self.plan(quantities)
        return execution.execute(flow, owner="reviewer", data={"input": {"target": target}, **(injected or {})},
            agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"))

    def draft(self, identity):
        flow = Flow.from_dict(self.lineage.draft(self.context, self.admission["id"], flow_id=identity,
                                               name="Reviewed cumulative receipt workflow"))
        store.save_flow(flow)
        return flow

    def capture(self, tag, target, quantities):
        # Test oracle determines when this particular reviewed teacher ends.
        assert 2 <= len(quantities) <= 8 and sum(quantities) >= target
        assert all(sum(quantities[:index]) < target for index in range(1, len(quantities)))
        nodes = {}
        for index in range(len(quantities)):
            approval, action = f"review_{index}", f"receipt_{index}"
            nodes[approval] = FlowNode(approval, "approval", prompt="Review receipt collection", next=action)
            nodes[action] = FlowNode(action, "action", tool=TOOL, params={"target": target},
                output=f"received_{index}", next=f"review_{index + 1}" if index + 1 < len(quantities) else None)
        source = Flow(id="memory-teacher-" + tag, name="Complete native receipt teacher", owner="reviewer",
                      start="review_0", nodes=nodes)
        store.save_flow(source)
        run = self.start(source, target, quantities)
        self.service.enroll(self.context, source.id, run.run_id,
            expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)), allowed_tools=ALLOWED,
            input_schema=INPUT_SCHEMA, tool_data_schemas=TOOL_SCHEMAS, retain_until=time.time() + 3600)
        for _ in quantities:
            run = decide(run.run_id)
        assert run.status == "completed", run.error
        row = self.service.get(self.context, source.id, run.run_id)
        assert row["status"] == "awaiting_review", row
        row = self.service.review(self.context, source.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], accepted=True,
            rationale="Reviewed complete native receipt observations and intended continuation")
        row = self.service.grant_training(self.context, source.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], use_until=time.time() + 1800,
            retain_derived_copies=True, rationale="Retain reviewed examples for local memory qualification")
        return self.service.export_signed(self.context, source.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], expected_grant_sha256=row["grant_sha256"])


@pytest.fixture
def memory_native(native, monkeypatch):
    flags = copy.deepcopy(FLAGS)
    monkeypatch.setattr(config, "get_flows", lambda: copy.deepcopy(flags))
    schedule = native.with_name("memory-schedule.json")
    native_registry = registry(native, schedule)
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: native_registry)
    risk = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk, "_load_overrides", lambda: {TOOL: "high"})
    return MemoryHarness(native, flags)
