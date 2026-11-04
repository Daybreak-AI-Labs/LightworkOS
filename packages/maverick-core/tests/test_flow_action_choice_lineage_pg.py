"""Signed binary choice admission and recovery across PostgreSQL adapters."""
from __future__ import annotations

import os
import time

import pytest
from maverick import audit, governed_records
from maverick.flow import recipe_lineage as lineage
from maverick.governed_records import GovernedRecordStore, PostgresGovernedRecordBackend
from maverick.paths import tenant_scope

from test_support.action_choice_native import (
    DOMAIN,
    OWNER,
    SEED_CASES,
    TENANT,
    TOOLS,
    context,
    permit,
)
from test_support.action_choice_native import choice_native as choice_native
from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


@pytest.fixture
def pg_choice_lineage(choice_native, authority, monkeypatch):
    factory, _, _ = authority
    dsn = factory()._dsn
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", dsn)

    def independent():
        backend = PostgresGovernedRecordBackend("flow_recipe_lineage", "LRA", dsn=dsn, require_bound_tenant=True)
        records = GovernedRecordStore("flow_recipe_lineage", "LRA", "flow_recipe_lineage",
                                      backend=backend, required_backend="postgres")
        return lineage.RecipeLineageService(permit, records=records)

    try:
        with tenant_scope(tenant=TENANT):
            bundles = [choice_native.capture(*values) for values in SEED_CASES]
            package = lineage.learn_choice_from_verified_bundles(bundles,
                trust=choice_native.trust(), expected_tenant=TENANT, now=time.time(),
                allowed_tools=TOOLS, domain=DOMAIN, max_operations=2,
                operators=["le", "lt", "not"], constants=[])
            yield choice_native, independent, package
    finally:
        governed_records._reset_process_authority_pin_for_testing()


@pytest.mark.parametrize("receipt", [False, 1])
def test_pg_choice_pending_recovers_current_signed_sources_without_replay(pg_choice_lineage, monkeypatch, receipt):
    env, factory, package = pg_choice_lineage
    before = env.business.rows("attempts")
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: receipt
        if kwargs.get("record_type") == "flow_recipe_lineage" else original(*args, **kwargs))
    pending = factory().admit(context(), package)
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "admitted"
    assert "package" not in pending
    assert "package" not in factory().get(context(), pending["id"], detail=True)
    with pytest.raises(lineage.RecipeLineageAuditPending):
        factory().draft(context(), pending["id"], flow_id="pg-choice-draft", name="PG choice draft")
    monkeypatch.setattr(audit, "record", original)
    recovered = factory().get(context(), pending["id"], detail=True)
    assert recovered["status"] == "admitted" and recovered["revision"] == pending["revision"]
    assert recovered["package"] == package and recovered["current_eligibility"] == "accepted"
    assert factory().admit(context(), package)["id"] == pending["id"]
    current = lineage.runtime_reference(recovered["reference"], package["artifact"], owner=OWNER)
    assert current["id"] == pending["id"] and len(current["trust_sha256"]) == 64
    draft = factory().draft(context(), pending["id"], flow_id="pg-choice-draft", name="PG choice draft")
    assert draft["learned_recipe"] == package["artifact"] and draft["recipe_lineage"] == recovered["reference"]
    assert env.business.rows("attempts") == before and len(before) == 12
    with tenant_scope(tenant="foreign-choice-tenant"):
        assert factory().records.get(pending["id"]) is None
    env.flags["action_evidence_revoked_keys"] = [package["bundles"][0]["signature"]["key_id"]]
    with pytest.raises(ValueError, match="trusted"):
        factory().get(context(), pending["id"], detail=True)
    assert env.business.rows("attempts") == before
