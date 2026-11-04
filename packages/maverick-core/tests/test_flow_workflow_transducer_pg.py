"""PostgreSQL evidence/admission with native durable variable-length execution."""
from __future__ import annotations

import copy
import os

import pytest
from maverick import config, governed_records
from maverick.flow import Flow, execution, recipe_lineage, store
from maverick.flow.workflow_recipe_flow import HISTORY
from maverick.governed_records import GovernedRecordStore, PostgresGovernedRecordBackend

from test_support.action_episode_native import ALLOWED, _no_agent
from test_support.action_episode_native import native as native
from test_support.postgres_authority import authority as authority
from test_support.workflow_transducer_native import FLAGS, WorkflowHarness, permit

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


@pytest.fixture
def pg_workflow(native, authority, monkeypatch):
    factory, _, _ = authority
    dsn = factory()._dsn
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)
    flags = copy.deepcopy(FLAGS)
    monkeypatch.setattr(config, "get_flows", lambda: copy.deepcopy(flags))
    try:
        harness = WorkflowHarness(native, flags)

        def independent():
            backend = PostgresGovernedRecordBackend("flow_recipe_lineage", "LRA", dsn=dsn, require_bound_tenant=True)
            records = GovernedRecordStore("flow_recipe_lineage", "LRA", "flow_recipe_lineage",
                                          backend=backend, required_backend="postgres")
            return recipe_lineage.RecipeLineageService(permit, records=records)

        yield harness, independent
    finally:
        governed_records._reset_process_authority_pin_for_testing()


@pytest.mark.parametrize("repeat", [False, True])
def test_pg_admission_and_native_history_survive_every_approval_and_redelivery(pg_workflow, repeat):
    h, factory = pg_workflow
    row = factory().admit(h.context, h.package)
    assert row["id"] == h.admission["id"] and factory().records.count() == 1
    assert factory().get(h.context, row["id"], detail=True)["package"] == h.package
    flow = Flow.from_dict(factory().draft(h.context, row["id"],
        flow_id="pg-workflow-" + str(repeat).lower(), name="PG variable-length workflow"))
    store.save_flow(flow)
    baseline = h.counts()
    run = h.start(flow, {"customer": "pg-fresh-input", "quantity": 9, "repeat": repeat})
    assert run.status == "paused_approval" and h.counts() == baseline
    count = 3 if repeat else 2
    previous = []
    for index in range(count):
        before = store.load_run(run.run_id, owner=h.context.resource_owner)
        assert before.data[HISTORY] == previous and len(previous) == index
        run = h.resume(run.run_id)
        retained = store.load_run(run.run_id, owner=h.context.resource_owner)
        assert h.counts() == baseline + index + 1
        assert retained.data[HISTORY][:-1] == previous
        assert retained.data[HISTORY][-1]["result"] == retained.data[f"_recipe_step_{index}"]
        assert retained.status == ("completed" if index == count - 1 else "paused_approval")
        previous = copy.deepcopy(retained.data[HISTORY])
        assert factory().get(h.context, row["id"])["current_eligibility"] == "accepted"
    assert [step["tool"] for step in previous] == [ALLOWED[0], ALLOWED[1]] + ([ALLOWED[0]] if repeat else [])
    before_calls = h.calls()
    replay = execution.execute(store.load_flow_snapshot(run.definition_digest), owner=h.context.resource_owner,
        run_id=run.run_id, agent_runner=_no_agent,
        action_runner=execution.default_action_runner(None, user_id=h.context.actor))
    assert replay.status == "completed" and replay.data[HISTORY] == previous and h.calls() == before_calls
