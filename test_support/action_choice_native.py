"""Real SQLite effects and signed straight-line teachers for binary choices.

Teacher Flows explicitly name a reserved case ID before execution because the
ordinary Flow renderer does not parse an action's JSON result string. The local
connector commits that reservation on open_case. Learned runs have no reservation
and must obtain a newly allocated case ID from the actual prefix result. Neither
reserved IDs, field mappings nor the business decision rule enter synthesis.
"""
from __future__ import annotations

import copy
import importlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from maverick import config, tools, world_model
from maverick.flow import Flow, FlowNode, action_episode_review, action_provenance, execution, store
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick.governed_operations import ServiceContext
from maverick.paths import tenant_scope
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

TENANT = "choice-native-lineage"
OWNER = "choice-reviewer"
OPEN = "choice_open_case"
APPROVE = "choice_approve_case"
QUEUE = "choice_queue_review"
TOOLS = [OPEN, APPROVE, QUEUE]
SOURCE_IDS = {tool: "choice-teacher-" + tool for tool in (APPROVE, QUEUE)}
FLAGS = {"enable": True, "action_recipes": True, "action_recipe_transforms": True,
         "action_recipe_choices": True, "action_episode_capture": True, "action_recipe_lineage": True,
         "require_action_recipe_lineage": True, "action_evidence_issuer": "native-choice-qualification",
         "action_evidence_revoked_keys": []}


def closed(fields):
    return {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False}


INTEGER = {"type": "integer", "minimum": 0, "maximum": 100}
STRING = {"type": "string", "maxLength": 64}
INPUT_SCHEMA = closed({"amount": INTEGER, "limit": INTEGER, "legacy_eligible": {"type": "boolean"}})
TOOL_SCHEMAS = {
    OPEN: {"arguments": closed({"amount": INTEGER, "limit": INTEGER}), "result": closed({"case_id": STRING})},
    APPROVE: {"arguments": closed({"case_id": STRING}), "result": closed({"approved": {"type": "boolean"}})},
    QUEUE: {"arguments": closed({"case_id": STRING}), "result": closed({"queued": {"type": "boolean"}})},
}
DOMAIN = {"inputs": INPUT_SCHEMA, "prefix": TOOL_SCHEMAS[OPEN],
          "branches": {tool: TOOL_SCHEMAS[tool] for tool in (APPROVE, QUEUE)}}
# Fixed before synthesis: includes equality, unequal limits, both directions and
# both truth values. No learner-generated or implementation-selected examples.
SEED_CASES = [(2, 5, True), (7, 8, True), (4, 4, True),
              (5, 3, False), (8, 7, False), (9, 2, False)]
COUNTER_CASES = [(3, 8, False), (9, 4, True)]


def context():
    return ServiceContext(tenant=TENANT, actor=OWNER, resource_owner=OWNER, human=True,
        credential_authority="native_choice_fixture", credential_ref="not_applicable",
        authorization_role="owner", authorization_policy="fixture_owner",
        budget_authority="local_no_provider", workspace_authority="fixture_tenant")


def permit(ctx, capability, resource):
    return ctx == context() and (
        (capability.startswith("flow.episode.") and resource in SOURCE_IDS.values())
        or capability in {"flow.recipe.admit", "flow.recipe.read", "flow.recipe.detail", "flow.recipe.draft"})


def no_agent(*args, **kwargs):
    raise AssertionError("binary native choice must not invoke an agent or replay a prefix")


class Business:
    def __init__(self, path, *, create=True):
        self.path = Path(path)
        self.reserved = None
        if create:
            with self.connect() as db:
                db.executescript("""
                    CREATE TABLE cases(case_id TEXT PRIMARY KEY, amount INTEGER NOT NULL,
                                       limit_value INTEGER NOT NULL);
                    CREATE TABLE decisions(case_id TEXT PRIMARY KEY REFERENCES cases,
                                           tool TEXT NOT NULL);
                    CREATE TABLE attempts(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                                          tool TEXT NOT NULL, arguments TEXT NOT NULL);
                """)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys=ON")
        db.row_factory = sqlite3.Row
        return db

    def rows(self, table):
        assert table in {"cases", "decisions", "attempts"}
        with self.connect() as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def reserve(self):
        assert self.reserved is None
        self.reserved = "case-" + uuid.uuid4().hex
        return self.reserved

    def dispatch(self, tool, arguments):
        expected = {"amount": int, "limit": int} if tool == OPEN else {"case_id": str}
        assert set(arguments) == set(expected)
        assert all(type(arguments[key]) is kind for key, kind in expected.items())
        with self.connect() as db:
            db.execute("INSERT INTO attempts(tool,arguments) VALUES(?,?)", (tool, json.dumps(arguments, sort_keys=True)))
            if tool == OPEN:
                case_id = self.reserved or "case-" + uuid.uuid4().hex
                self.reserved = None
                db.execute("INSERT INTO cases VALUES(?,?,?)", (case_id, arguments["amount"], arguments["limit"]))
                result = {"case_id": case_id}
            else:
                assert tool in (APPROVE, QUEUE)
                db.execute("INSERT INTO decisions VALUES(?,?)", (arguments["case_id"], tool))
                result = {"approved": True} if tool == APPROVE else {"queued": True}
        return json.dumps(result, sort_keys=True)


def registry_for(business):
    registry = tools.ToolRegistry(principal=OWNER)
    for name in TOOLS:
        registry.register(tools.Tool(name=name, description="Local SQLite case decision connector",
            input_schema=copy.deepcopy(TOOL_SCHEMAS[name]["arguments"]),
            fn=lambda args, name=name: business.dispatch(name, args)))
    return registry


def resume(run_id):
    prior = store.load_run(run_id, owner=OWNER)
    source = store.load_flow_snapshot(prior.definition_digest)
    binding = paused_operation_binding(prior)
    material = flow_decision_attestation_material(prior, inputs=None, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by=OWNER)
    attestation = issue_flow_decision_attestation(None, material=material,
        expires_at=float(prior.human["approval_card"]["expires_at"]))
    return execution.execute(source, owner=OWNER, resume_run_id=run_id,
        decision="approved", decided_by=OWNER, approval_binding_sha256=binding,
        approval_decision_attestation=attestation, agent_runner=no_agent,
        action_runner=execution.default_action_runner(None, user_id=OWNER))


def start(flow, inputs):
    return execution.execute(flow, owner=OWNER, data={"input": inputs}, agent_runner=no_agent,
        action_runner=execution.default_action_runner(None, user_id=OWNER))


def redeliver(run_id):
    prior = store.load_run(run_id, owner=OWNER)
    return execution.execute(store.load_flow_snapshot(prior.definition_digest), owner=OWNER,
        run_id=run_id, agent_runner=no_agent,
        action_runner=execution.default_action_runner(None, user_id=OWNER))


def child_redeliver(run_id, business_path, world_path):
    """Fresh interpreter reads immutable snapshot and durable run, not Python state."""
    business = Business(business_path, create=False)
    registry = registry_for(business)
    risk = importlib.import_module("maverick.safety.tool_risk")
    with (patch.object(config, "get_flows", lambda: copy.deepcopy(FLAGS)),
          patch.object(world_model, "DEFAULT_DB", Path(world_path)),
          patch.object(tools, "base_registry", lambda *args, **kwargs: registry),
          patch.object(risk, "_load_overrides", lambda: dict.fromkeys(TOOLS, "high")),
          tenant_scope(tenant=TENANT)):
        redeliver(run_id)


class Harness:
    def __init__(self, business, world_path, flags):
        self.business, self.world_path, self.flags = business, world_path, flags

    def capture(self, amount, limit, legacy_eligible, *, terminal=None):
        # This independent fixture rule picks the demonstrated action; only the
        # resulting tool names are learning labels, never this predicate.
        terminal = terminal or (APPROVE if amount <= limit else QUEUE)
        inputs = {"amount": amount, "limit": limit, "legacy_eligible": legacy_eligible}
        case_id = self.business.reserve()
        source = Flow(id=SOURCE_IDS[terminal], name="Native case teacher", owner=OWNER,
            start="before_open", nodes={
                "before_open": FlowNode("before_open", "approval", prompt="Review opening case", next="open"),
                "open": FlowNode("open", "action", tool=OPEN, params={"amount": amount, "limit": limit},
                                 output="opened", next="before_terminal"),
                "before_terminal": FlowNode("before_terminal", "approval", prompt="Review case decision", next="terminal"),
                "terminal": FlowNode("terminal", "action", tool=terminal, params={"case_id": case_id}, output="decision"),
            })
        store.save_flow(source)
        run = start(source, inputs)
        assert run.status == "paused_approval"
        service = action_episode_review.ActionEpisodeReviewService(permit)
        service.enroll(context(), source.id, run.run_id,
            expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
            allowed_tools=[OPEN, terminal], input_schema=INPUT_SCHEMA,
            tool_data_schemas={tool: TOOL_SCHEMAS[tool] for tool in (OPEN, terminal)},
            retain_until=time.time() + 3600)
        assert resume(run.run_id).status == "paused_approval"
        resumed = resume(run.run_id)
        assert resumed.status == "completed", (resumed.status, getattr(resumed, "error", ""))
        row = service.get(context(), source.id, run.run_id)
        assert row["status"] == "awaiting_review"
        row = service.review(context(), source.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], accepted=True,
            rationale="Reviewed exact native SQLite case and terminal decision")
        row = service.grant_training(context(), source.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], use_until=time.time() + 1800,
            retain_derived_copies=True, rationale="Local bounded binary-choice qualification")
        return service.export_signed(context(), source.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], expected_grant_sha256=row["grant_sha256"])

    def trust(self):
        return action_provenance.local_trust(TENANT)


@pytest.fixture
def choice_native(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    from test_support.audit_child_process import configure_test_audit_signer

    configure_test_audit_signer(monkeypatch)
    # Retained action evidence refuses plaintext; pin encryption at rest so the
    # fixture holds under the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    flags = copy.deepcopy(FLAGS)
    monkeypatch.setattr(config, "get_flows", lambda: copy.deepcopy(flags))
    world_path = tmp_path / "native-choice-world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", world_path)
    business = Business(tmp_path / "native-choice-business.db")
    registry = registry_for(business)
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: registry)
    risk = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk, "_load_overrides", lambda: dict.fromkeys(TOOLS, "high"))
    with tenant_scope(tenant=TENANT):
        yield Harness(business, world_path, flags)
