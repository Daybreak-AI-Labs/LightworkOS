"""Signed native sources and lineage admission on independent PostgreSQL adapters."""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import audit, governed_records
from maverick.flow import recipe_lineage as lineage
from maverick.governed_records import GovernedRecordStore, PostgresGovernedRecordBackend
from maverick.paths import tenant_scope

from test_support.action_episode_native import ALLOWED, _calls
from test_support.action_episode_native import native as native
from test_support.postgres_authority import authority as authority
from test_support.recipe_lineage_native import lineage_native as lineage_native
from test_support.recipe_lineage_native import permit

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


@pytest.fixture
def pg_lineage(lineage_native, authority, monkeypatch):
    factory, _, _ = authority
    dsn = factory()._dsn
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)
    env = lineage_native

    def independent():
        backend = PostgresGovernedRecordBackend("flow_recipe_lineage", "LRA", dsn=dsn, require_bound_tenant=True)
        records = GovernedRecordStore("flow_recipe_lineage", "LRA", "flow_recipe_lineage",
                                      backend=backend, required_backend="postgres")
        return lineage.RecipeLineageService(permit, records=records)

    with tenant_scope(tenant=env["tenant"]):
        bundles = [env["capture"]("pg-first"), env["capture"]("pg-second")]
        package = lineage.learn_from_verified_bundles(bundles, trust=env["trust"](),
            expected_tenant=env["tenant"], now=time.time(), allowed_tools=ALLOWED)
        yield env, independent, package
    governed_records._reset_process_authority_pin_for_testing()


@pytest.mark.parametrize("receipt", [False, 1])
def test_pg_pending_admission_recovers_across_adapters_without_business_replay(pg_lineage, monkeypatch, receipt):
    env, factory, package = pg_lineage
    before = _calls(env["journal"])
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: receipt
        if kwargs.get("record_type") == "flow_recipe_lineage" else original(*args, **kwargs))
    pending = factory().admit(env["ctx"], package)
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "admitted"
    assert "package" not in pending
    assert "package" not in factory().get(env["ctx"], pending["id"], detail=True)
    with pytest.raises(lineage.RecipeLineageAuditPending):
        factory().draft(env["ctx"], pending["id"], flow_id="pg-draft", name="PG draft")
    monkeypatch.setattr(audit, "record", original)
    recovered = factory().get(env["ctx"], pending["id"], detail=True)
    assert recovered["status"] == "admitted" and recovered["revision"] == pending["revision"]
    assert recovered["package"] == package and recovered["current_eligibility"] == "accepted"
    assert factory().admit(env["ctx"], package)["id"] == pending["id"]
    current = lineage.runtime_reference(recovered["reference"], package["artifact"], owner=env["ctx"].resource_owner)
    assert current["id"] == pending["id"] and len(current["trust_sha256"]) == 64
    assert _calls(env["journal"]) == before
    with tenant_scope(tenant="foreign-lineage-tenant"):
        assert factory().records.get(pending["id"]) is None


def test_pg_concurrent_same_package_has_one_admission_and_one_signed_receipt(pg_lineage):
    env, factory, package = pg_lineage
    barrier = threading.Barrier(2)

    def admit(_):
        barrier.wait(timeout=10)
        return factory().admit(env["ctx"], package)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(admit, [0, 1]))
    assert {row["id"] for row in results} == {results[0]["id"]}
    assert all(row["status"] == "admitted" for row in results)
    assert factory().records.count() == 1
    assert len(_calls(env["journal"])) == 4
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("record_type") == "flow_recipe_lineage"]
    assert len(events) == 1 and events[0]["sig"]
