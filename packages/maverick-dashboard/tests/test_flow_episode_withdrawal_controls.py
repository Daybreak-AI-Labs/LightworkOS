"""Native retained-example withdrawal remains available after learning is stopped.

OIDC signature verification is a fixture; storage, review, encryption, native
actions and audit are real isolated local paths. No model or provider is called.
"""
from __future__ import annotations

import copy

import pytest
from maverick import audit, learning_guard

from test_support.action_episode_api import PRIVATE_REF, _accepted, _base
from test_support.action_episode_api import harness as harness


def _reviewed(harness):
    harness.flags.update(action_recipe_lineage=True, action_evidence_issuer="withdrawal-controls",
                         action_evidence_revoked_keys=[])
    _source, run, _old = _accepted(harness)
    response = harness.client.get(_base(run))
    assert response.status_code == 200, response.text
    row = response.json()
    body = {"expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
            "expected_review_sha256": row["review_sha256"], "withdraw": True,
            "rationale": "Stop future use of this retained example."}
    return run, row, body


def _stop(harness, mode):
    if mode == "engine":
        harness.flags["enable"] = False
        harness.monkeypatch.setenv("MAVERICK_FLOWS", "0")
    elif mode == "halt":
        harness.monkeypatch.setattr(learning_guard, "learning_write_allowed", lambda *a, **kw: False)
    else:
        harness.flags[mode] = False


@pytest.mark.parametrize("mode", ["action_episode_capture", "action_recipe_lineage", "engine", "halt"])
def test_owner_can_withdraw_existing_example_after_learning_is_stopped(harness, mode):
    run, row, body = _reviewed(harness)
    calls = copy.deepcopy(harness.calls)
    _stop(harness, mode)
    withdrawn = harness.client.post(_base(run) + "/withdraw", json=body)
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["status"] == "withdrawn"
    assert withdrawn.json()["revision"] == row["revision"] + 1
    assert harness.calls == calls
    repeated = harness.client.post(_base(run) + "/withdraw", json=body)
    assert repeated.status_code == 200 and repeated.json()["revision"] == withdrawn.json()["revision"]


@pytest.mark.parametrize("mode", ["action_episode_capture", "action_recipe_lineage", "engine", "halt"])
def test_fresh_withdrawal_readback_never_enables_training_or_exposes_raw_evidence(harness, mode):
    run, row, body = _reviewed(harness)
    calls = copy.deepcopy(harness.calls)
    _stop(harness, mode)
    prepared = harness.client.get(_base(run) + "/withdrawal")
    assert prepared.status_code == 200, prepared.text
    result = prepared.json()
    assert result["status"] == "accepted" and result["withdrawal_available"] is True
    assert result["revision"] == row["revision"]
    assert result["review_sha256"] == body["expected_review_sha256"]
    assert "evidence" not in result and PRIVATE_REF not in prepared.text
    grant = harness.client.post(_base(run) + "/training-grant", json={
        "expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
        "use_until": row["retain_until"] - 1, "retain_derived_copies": True,
        "rationale": "This positive permission must remain disabled.",
    })
    assert grant.status_code == 403, grant.text
    result = harness.client.post(_base(run) + "/withdraw", json=body)
    assert result.status_code == 200, result.text
    refreshed = harness.client.get(_base(run) + "/withdrawal")
    assert refreshed.status_code == 200 and refreshed.json()["withdrawal_available"] is False
    assert refreshed.json()["status"] == "withdrawn"
    assert harness.calls == calls


def test_stopped_withdrawal_rejects_stale_revision_without_mutating_record(harness):
    run, row, body = _reviewed(harness)
    _stop(harness, "engine")
    body["expected_revision"] -= 1
    response = harness.client.post(_base(run) + "/withdraw", json=body)
    assert response.status_code == 409, response.text
    current = harness.client.get(_base(run) + "/withdrawal").json()
    assert current["status"] == "accepted" and current["revision"] == row["revision"]


def test_stopped_withdrawal_cannot_read_or_change_another_owners_example(harness):
    run, _row, body = _reviewed(harness)
    _stop(harness, "engine")
    for method, suffix, options in [("get", "/withdrawal", {}), ("post", "/withdraw", {"json": body})]:
        response = getattr(harness.client, method)(_base(run) + suffix,
                                                   headers={"Authorization": "Bearer bob"}, **options)
        assert response.status_code in {403, 404}, response.text
        assert PRIVATE_REF not in response.text and "episode_sha256" not in response.text
    current = harness.client.get(_base(run) + "/withdrawal").json()
    assert current["status"] == "accepted"


def test_stopped_withdrawal_requires_an_explicit_human_request(harness):
    run, _row, body = _reviewed(harness)
    _stop(harness, "engine")
    body["withdraw"] = False
    response = harness.client.post(_base(run) + "/withdraw", json=body)
    assert response.status_code == 400
    assert harness.client.get(_base(run) + "/withdrawal").json()["status"] == "accepted"


def test_pending_withdrawal_reports_uncertainty_then_recovers_without_replaying_work(harness):
    run, row, body = _reviewed(harness)
    _stop(harness, "engine")
    calls = copy.deepcopy(harness.calls)
    original = audit.record
    harness.monkeypatch.setattr(audit, "record", lambda *a, **kw: False)
    response = harness.client.post(_base(run) + "/withdraw", json=body)
    assert response.status_code == 503, response.text
    pending = harness.client.get(_base(run) + "/withdrawal")
    assert pending.status_code == 503 and pending.json()["status"] == "audit_pending"
    assert "evidence" not in pending.json() and pending.json().get("withdrawal_available") is not True
    harness.monkeypatch.setattr(audit, "record", original)
    recovered = harness.client.get(_base(run) + "/withdrawal")
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["status"] == "withdrawn"
    assert recovered.json()["withdrawal_available"] is False
    assert recovered.json()["revision"] == row["revision"] + 1
    assert harness.calls == calls
