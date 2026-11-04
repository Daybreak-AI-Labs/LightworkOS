"""Disposable signed-learning journey: actual capture and runtime, local fake actions."""
from __future__ import annotations

import json
import time
from contextvars import ContextVar

from fastapi import HTTPException, Request

FLOW_ID = "browser-signed-learning"
LOOKUP = "browser_learning_lookup"
CREATE = "browser_learning_create"
_ACTIVE = ContextVar("browser_signed_learning_fixture_active", default=False)


def _local_action(tool: str, params: dict, calls: list[str]) -> str:
    if tool not in {LOOKUP, CREATE}:
        raise AssertionError("Only the local synthetic learning actions are available")
    calls.append(tool)
    if tool == LOOKUP:
        return json.dumps({"customer_id": "customer-" + params["query"]})
    return json.dumps({"order_id": "local-order-" + str(len(calls))})


def _instrument_registry(tools, owner: str, calls: list[str]) -> None:
    base_registry = tools.base_registry

    def local_registry(*args, **kwargs):
        registry = base_registry(*args, **kwargs)
        if _ACTIVE.get() and kwargs.get("user_id") == owner:
            for name in (LOOKUP, CREATE):
                registry.register(tools.Tool(name=name, description="Synthetic local browser learning action",
                                             input_schema={"type": "object"},
                                             fn=lambda params, name=name: _local_action(name, params, calls)))
        return registry

    tools.base_registry = local_registry


def _run_fixture(execution, *args, **kwargs):
    token = _ACTIVE.set(True)
    try:
        return execution.execute(*args, **kwargs)
    finally:
        _ACTIVE.reset(token)


def install(app, tenant: str, owner: str) -> None:
    from maverick import tools
    from maverick.flow import Flow, FlowNode, execution, store
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick.flow.capture_schema import suggest_contract
    from maverick.paths import tenant_scope
    from maverick_dashboard.api_flow_action_episodes import _enrollment_info, _service
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    state: dict = {"runs": [], "calls": [], "derived": None, "probe": None}

    _instrument_registry(tools, owner, state["calls"])
    native_action = execution.default_action_runner(None, user_id=owner)

    def no_agent(*_args, **_kwargs):
        raise AssertionError("The synthetic learning journey never calls a model")

    def approve(run_id: str):
        run = store.load_run(run_id, owner=owner)
        binding = paused_operation_binding(run, inputs={})
        material = flow_decision_attestation_material(
            run, inputs={}, operation_binding_sha256=binding, authority_binding_sha256="",
            decision="approved", decided_by=owner,
        )
        token = issue_flow_decision_attestation(
            None, material=material, expires_at=float(run.human["approval_card"]["expires_at"]),
        )
        return _run_fixture(execution,
            store.load_flow_snapshot(run.definition_digest), owner=owner, resume_run_id=run_id,
            inputs={}, decision="approved", decided_by=owner, approval_binding_sha256=binding,
            approval_decision_attestation=token, action_runner=native_action, agent_runner=no_agent,
        )

    def source_flow():
        # One saved definition for both runs: a learning decision needs the
        # reviewed procedure to still be the current one. The runs differ by
        # their input, and the order uses the customer the lookup returned.
        return Flow(id=FLOW_ID, name="Reviewed local procedure", owner=owner,
                    start="approve_lookup", nodes={
            "approve_lookup": FlowNode(id="approve_lookup", kind="approval", prompt="Review lookup", next="lookup"),
            "lookup": FlowNode(id="lookup", kind="action", tool=LOOKUP,
                               params={"query": "{{input.ref}}"}, output="customer", next="approve_create"),
            "approve_create": FlowNode(id="approve_create", kind="approval", prompt="Review order", next="create"),
            "create": FlowNode(id="create", kind="action", tool=CREATE,
                               params={"customer_id": "{{customer.customer_id}}"}, output="order"),
        })

    def result_schema(field: str):
        return {"type": "object", "properties": {field: {"type": "string", "maxLength": 1024}},
                "required": [field], "additionalProperties": False}

    @app.post("/__browser_fixture/signed-learning/setup", include_in_schema=False)
    def setup(request: Request):
        if state["runs"]:
            return {"flow_id": FLOW_ID, "run_ids": list(state["runs"]), "tools": [LOOKUP, CREATE],
                    "calls": len(state["calls"])}
        with tenant_scope(tenant=tenant):
            prior = None
            source = store.save_flow(source_flow())
            for index in range(2):
                run = _run_fixture(execution, source, owner=owner, data={"input": {"ref": f"local-ref-{index}"}},
                                        action_runner=native_action, agent_runner=no_agent)
                if run.status != "paused_approval":
                    raise AssertionError("The source must pause before its first action")
                prepared = _enrollment_info(request, FLOW_ID, run.run_id)
                service, ctx = _service(request, FLOW_ID, human=True)
                contract = suggest_contract(source, run, allowed_tools=prepared["allowed_tools"],
                                            prior_contract=prior, earlier_runs=[])
                contract["tool_data_schemas"][LOOKUP]["result"] = result_schema("customer_id")
                contract["tool_data_schemas"][CREATE]["result"] = result_schema("order_id")
                service.enroll(ctx, FLOW_ID, run.run_id, expected_pause_binding=prepared["expected_pause_binding"],
                               allowed_tools=prepared["allowed_tools"], input_schema=contract["input_schema"],
                               tool_data_schemas=contract["tool_data_schemas"], retain_until=time.time() + 6 * 86400)
                middle = approve(run.run_id)
                if middle.status != "paused_approval":
                    raise AssertionError(f"The first local action stopped at {middle.status}: {middle.error}")
                final = approve(run.run_id)
                if final.status != "completed":
                    raise AssertionError("The locally approved source must complete exactly two actions")
                row = service.get(ctx, FLOW_ID, run.run_id, detail=True)
                if row["status"] != "awaiting_review":
                    raise AssertionError("The completed source must await a separate review")
                service.review(ctx, FLOW_ID, run.run_id, expected_revision=row["revision"],
                               expected_episode_sha256=row["episode_sha256"], accepted=True,
                               rationale="Reviewed actual local inputs and both action results")
                prior = row["evidence"]["contract"]
                state["runs"].append(run.run_id)
        return {"flow_id": FLOW_ID, "run_ids": list(state["runs"]), "tools": [LOOKUP, CREATE],
                "calls": len(state["calls"])}

    @app.post("/__browser_fixture/signed-learning/prepare-probe", include_in_schema=False)
    def prepare_probe(flow_id: str):
        with tenant_scope(tenant=tenant):
            flow = store.load_flow(flow_id)
            if flow is None or flow.owner != owner or not flow.recipe_lineage:
                raise HTTPException(409, "Expected a saved learned flow with bound lineage")
            run = _run_fixture(execution, flow, owner=owner, data={"input": {"ref": "new-local-ref"}},
                                    action_runner=native_action, agent_runner=no_agent)
            if run.status != "paused_approval":
                raise HTTPException(409, "Expected an approval before the learned action")
            state["derived"] = flow_id
            state["probe"] = run.run_id
            return {"run_id": run.run_id, "status": run.status, "calls": len(state["calls"]),
                    "lineage_bound": bool(flow.recipe_lineage)}

    @app.post("/__browser_fixture/signed-learning/continue-probe", include_in_schema=False)
    def continue_probe():
        if not state["probe"]:
            raise HTTPException(409, "Start the local probe before continuing it")
        with tenant_scope(tenant=tenant):
            before = len(state["calls"])
            run = approve(state["probe"])
            return {"status": run.status, "calls_before": before, "calls_after": len(state["calls"]),
                    "run_id": run.run_id}
