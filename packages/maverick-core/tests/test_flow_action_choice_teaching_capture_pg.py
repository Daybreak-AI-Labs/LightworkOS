"""Native taught evidence commits, signs and recovers on PostgreSQL."""
from __future__ import annotations

import os
import time

import pytest
from maverick import audit, governed_records
from maverick.flow import action_episode_review, action_provenance

from test_support.action_choice_native import TENANT, context
from test_support.action_choice_native import choice_native as choice_native
from test_support.action_choice_teaching_native import TeachingHarness, resume
from test_support.postgres_authority import authority as authority

pytestmark = pytest.mark.skipif(not os.environ.get("MAVERICK_PG_DSN"),
                                reason="dedicated Postgres service unavailable")


def test_pg_teaching_signed_issuance_recovers_without_repeating_native_effect(choice_native, authority, monkeypatch):
    factory, _, _ = authority
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", factory()._dsn)
    choice_native.flags["action_recipe_teaching"] = True
    try:
        harness = TeachingHarness(choice_native)
        flow = harness.draft("pg-native-human-teaching")
        run = harness.enroll(flow, {"amount": 3, "limit": 8, "legacy_eligible": False})
        assert resume(run.run_id).cursor == "teaching_review"
        assert resume(run.run_id, decision="route:0").cursor == "approval_1_0"
        assert resume(run.run_id).status == "completed"
        before = choice_native.business.rows("attempts")
        original = audit.record
        monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False
            if kwargs.get("record_type") == "flow_action_episode" and kwargs.get("action") == "action_episode_evidence_issued"
            else original(*args, **kwargs))
        with pytest.raises(action_episode_review.ActionEpisodeAuditPending):
            harness.export(run.run_id)
        monkeypatch.setattr(audit, "record", original)
        from test_support.action_choice_teaching_native import permit

        independent = action_episode_review.ActionEpisodeReviewService(permit)
        row = independent.get(context(), flow.id, run.run_id)
        assert row["status"] == "accepted" and row["audit_status"] == "delivered"
        bundle = independent.export_signed(context(), flow.id, run.run_id, expected_revision=row["revision"],
            expected_episode_sha256=row["episode_sha256"], expected_grant_sha256=row["grant_sha256"])
        checked = action_provenance.verify_bundle(bundle, trust=choice_native.trust(), expected_tenant=TENANT, now=time.time())
        assert checked["body"]["schema"] == action_provenance.TEACHING_SCHEMA
        assert independent.assert_bundle_current(context(), bundle)["live_status"] == "accepted"
        assert choice_native.business.rows("attempts") == before and len(before) == 14
    finally:
        governed_records._reset_process_authority_pin_for_testing()
