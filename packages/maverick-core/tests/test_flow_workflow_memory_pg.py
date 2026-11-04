"""Independent PostgreSQL evidence/admission and native history accumulation."""
from __future__ import annotations

import copy
import importlib
import os

import pytest
from maverick import config, governed_records, tools
from maverick.flow import Flow, recipe_lineage, store
from maverick.flow.workflow_recipe_flow import HISTORY
from maverick.governed_records import GovernedRecordStore, PostgresGovernedRecordBackend

from test_support.postgres_authority import authority as authority
from test_support.workflow_memory_native import (
    FLAGS,
    TOOL,
    MemoryHarness,
    decide,
    redeliver,
    registry,
)
from test_support.workflow_memory_native import native as native
from test_support.workflow_transducer_native import permit

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


@pytest.fixture
def pg_memory(native, authority, monkeypatch):
    factory, _, _ = authority
    dsn = factory()._dsn
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)
    flags = copy.deepcopy(FLAGS)
    monkeypatch.setattr(config, "get_flows", lambda: copy.deepcopy(flags))
    native_registry = registry(native, native.with_name("memory-schedule.json"))
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: native_registry)
    risk = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk, "_load_overrides", lambda: {TOOL: "high"})
    try:
        harness = MemoryHarness(native, flags)

        def independent():
            backend = PostgresGovernedRecordBackend("flow_recipe_lineage", "LRA", dsn=dsn, require_bound_tenant=True)
            records = GovernedRecordStore("flow_recipe_lineage", "LRA", "flow_recipe_lineage",
                                          backend=backend, required_backend="postgres")
            return recipe_lineage.RecipeLineageService(permit, records=records)

        yield harness, independent
    finally:
        governed_records._reset_process_authority_pin_for_testing()


@pytest.mark.parametrize("quantities", [[2, 3], [1, 3, 1]])
def test_pg_signed_history_models_survive_independent_adapters_and_approvals(pg_memory, quantities):
    h, factory = pg_memory
    admission = factory().admit(h.context, h.package)
    assert admission["id"] == h.admission["id"] and factory().records.count() == 1
    assert factory().get(h.context, admission["id"], detail=True)["package"] == h.package
    flow = Flow.from_dict(factory().draft(h.context, admission["id"],
        flow_id="pg-memory-" + str(len(quantities)), name="Native learned receipt memory"))
    store.save_flow(flow)
    before = h.counts()
    run = h.start(flow, 5, quantities)
    assert run.status == "paused_approval" and h.counts() == before, run.error
    previous = []
    for index, quantity in enumerate(quantities):
        assert store.load_run(run.run_id).data[HISTORY] == previous
        run = decide(run.run_id)
        assert run.status == ("completed" if index == len(quantities) - 1 else "paused_approval"), run.error
        assert h.counts() == before + index + 1
        assert run.data[HISTORY][:-1] == previous
        assert run.data[HISTORY][-1] == {"tool": TOOL, "arguments": {"target": 5}, "result": {"quantity": quantity}}
        previous = copy.deepcopy(run.data[HISTORY])
        assert factory().get(h.context, admission["id"])["current_eligibility"] == "accepted"
    assert redeliver(run.run_id).status == "completed" and h.counts() == before + len(quantities)
