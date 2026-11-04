"""Withdrawal reduces existing training authority without enabling stopped work."""
from __future__ import annotations

from dataclasses import replace

import pytest
from maverick import crypto_at_rest, killswitch
from maverick.flow import action_episode_review as review
from maverick.paths import data_dir

from test_support.action_episode_native import _calls
from test_support.action_episode_native import native as native
from test_support.recipe_lineage_native import lineage_native as lineage_native
from test_support.recipe_lineage_native import permit


def _issued(lineage_native):
    bundle = lineage_native["capture"]("maintenance")
    service = review.ActionEpisodeReviewService(permit)
    ctx = lineage_native["ctx"]
    source = bundle["body"]["source"]
    flow_id, run_id = source["flow_id"], source["run_id"]
    row = service.get(ctx, flow_id, run_id)
    args = {"expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
            "expected_review_sha256": row["review_sha256"], "rationale": "Withdraw this example while stopped."}
    return service, ctx, flow_id, run_id, bundle, args


def test_withdrawal_while_disabled_still_invalidates_previous_signed_bundle_after_reenable(lineage_native):
    service, ctx, flow_id, run_id, bundle, args = _issued(lineage_native)
    flags = lineage_native["flags"]
    flags["action_episode_capture"] = flags["action_recipe_lineage"] = False
    prepared = service.prepare_withdrawal(ctx, flow_id, run_id)
    assert prepared["withdrawal_available"] and "evidence" not in prepared
    result = service.withdraw(ctx, flow_id, run_id, **args)
    assert result["status"] == "withdrawn"
    flags["action_episode_capture"] = flags["action_recipe_lineage"] = True
    with pytest.raises(review.ActionEpisodeConflict):
        service.assert_bundle_current(ctx, bundle)
    assert len(_calls(lineage_native["journal"])) == 2


def test_native_global_halt_allows_only_restrictive_withdrawal(lineage_native):
    service, ctx, flow_id, run_id, _bundle, args = _issued(lineage_native)
    path = data_dir("HALT", tenant=None)
    # The secure test runner isolates HOME and each fixture's data. No application
    # process or real workspace stop state is changed by this temporary file.
    assert not path.exists()
    path.write_text("Synthetic maintenance test stop", encoding="utf-8")
    try:
        with pytest.raises(killswitch.Halted):
            killswitch.check(force_refresh=True, fail_closed=True)
        with pytest.raises(PermissionError):
            service.get(ctx, flow_id, run_id, detail=True)
        assert service.prepare_withdrawal(ctx, flow_id, run_id)["withdrawal_available"]
        assert service.withdraw(ctx, flow_id, run_id, **args)["status"] == "withdrawn"
        with pytest.raises(killswitch.Halted):
            killswitch.check(force_refresh=True, fail_closed=True)
        assert len(_calls(lineage_native["journal"])) == 2
    finally:
        path.unlink()
        killswitch.check(force_refresh=True, fail_closed=True)


def test_maintenance_cannot_turn_an_automated_context_into_a_human_decision(lineage_native):
    service, ctx, flow_id, run_id, _bundle, args = _issued(lineage_native)
    machine = replace(ctx, human=False)
    service.authorize = lambda *_args: True
    with pytest.raises(PermissionError):
        service.prepare_withdrawal(machine, flow_id, run_id)
    with pytest.raises(PermissionError):
        service.withdraw(machine, flow_id, run_id, **args)
    assert service.prepare_withdrawal(ctx, flow_id, run_id)["status"] == "accepted"


def test_authority_revocation_during_sealing_prevents_maintenance_commit(lineage_native, monkeypatch):
    service, ctx, flow_id, run_id, _bundle, args = _issued(lineage_native)
    original = crypto_at_rest.seal_to_str
    original_authorize = service.authorize

    def revoke(*values, **options):
        sealed = original(*values, **options)
        service.authorize = lambda *_args: False
        return sealed

    lineage_native["flags"]["action_episode_capture"] = False
    monkeypatch.setattr(crypto_at_rest, "seal_to_str", revoke)
    with pytest.raises(PermissionError):
        service.withdraw(ctx, flow_id, run_id, **args)
    service.authorize = original_authorize
    result = service.prepare_withdrawal(ctx, flow_id, run_id)
    assert result["status"] == "accepted" and result["revision"] == args["expected_revision"]
