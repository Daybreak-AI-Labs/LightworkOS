from __future__ import annotations

import json

import pytest

from scripts.acceptance import run_discovery_sensor_test_estate as runner

# Eight concurrent sensor workers on one SQLite store; same reasoning as the
# queue soak -- run alone on the box, not beside a second xdist worker.
pytestmark = pytest.mark.heavy_concurrency


def test_fixed_acceptance_exercises_three_sources_lifecycle_recovery_and_scale():
    report = runner.run_acceptance(synthetic_consent_confirmed=True)

    assert report["status"] == "passed_local_synthetic"
    assert set(report["sources"]) == set(runner.SOURCE_KINDS)
    assert all(row["initial_delivery_passed"] for row in report["sources"].values())
    assert all(row["coverage_complete"] is False for row in report["sources"].values())
    assert all(
        row["coverage_limitations"] == list(runner.COVERAGE_LIMITATIONS)
        for row in report["sources"].values()
    )
    assert report["key_lifecycle"]["hot_rotation_without_agent_restart"] is True
    assert report["key_lifecycle"]["old_key_rejected_after_rotation"] is True
    assert report["revocation_and_recovery"]["passed"] is True
    assert report["outage_and_retry"]["passed"] is True
    assert report["response_loss_idempotency"]["passed"] is True
    assert report["response_loss_idempotency"]["retry_request_count"] == 2
    assert report["response_loss_idempotency"]["unique_observation_delta"] == 1
    tenant_scope = report["tenant_scoped_idempotency"]
    assert tenant_scope["scope"] == "authenticated_tenant_sensor_event_digest"
    assert tenant_scope["same_digest_second_tenant_delivered"] is True
    assert tenant_scope["cross_tenant_unique_observation_delta"] == 1
    assert tenant_scope["same_tenant_sensor_duplicate_status_code"] == 201
    assert tenant_scope["same_tenant_sensor_duplicate_unique_delta"] == 0
    assert tenant_scope["passed"] is True
    scale = report["bounded_concurrent_scale"]
    assert scale["target_observations"] == 1_000
    assert scale["worker_count"] == 8
    assert scale["normalized_observations"] == 1_000
    assert scale["delivered_observations"] == 1_000
    assert scale["unique_observation_delta"] == 1_000
    assert scale["pending_after_drain"] == 0
    assert scale["passed"] is True
    assert report["estate_summary"]["requests_received"] == 1_013
    assert report["estate_summary"]["unique_observations"] == 1_008
    assert report["estate_summary"]["key_ceremony_events"] == 7


def test_acceptance_evidence_is_digest_only_and_truthful_about_external_scope():
    report = runner.run_acceptance(synthetic_consent_confirmed=True)
    encoded = json.dumps(report, sort_keys=True)

    assert report["execution_scope"] == {
        "mode": "in_process_consenting_test_estate",
        "local_synthetic": True,
        "consent_acknowledged": True,
        "network_io_used": False,
        "external_or_customer_estate_run": False,
        "external_credentials_used": False,
        "coverage_complete": False,
    }
    assert report["estate_summary"]["coverage_complete"] is False
    assert report["privacy"]["raw_source_persisted"] is False
    assert report["privacy"]["prohibited_fields_found"] == []
    assert report["privacy"]["estate_privacy_check_passed"] is True
    assert report["privacy"]["queued_payload_privacy_check_passed"] is True
    assert report["privacy"]["network_raw_hostname_absent_from_spool"] is True
    assert report["privacy"]["private_key_material_in_evidence"] is False
    assert runner.CONSENT_REFERENCE not in encoded
    assert "local-synthetic-tenant" not in encoded
    assert "local-synthetic-tenant-two" not in encoded
    assert "api.openai.com" not in encoded
    assert "BEGIN PRIVATE KEY" not in encoded
    unsigned = {key: value for key, value in report.items() if key != "evidence_sha256"}
    assert report["evidence_sha256"] == runner._sha256(unsigned)


def test_runner_requires_explicit_consent_and_cli_writes_report(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="must be acknowledged"):
        runner.run_acceptance(synthetic_consent_confirmed=False)

    expected = {
        "schema": runner.SCHEMA,
        "status": "passed_local_synthetic",
        "evidence_sha256": "a" * 64,
    }
    monkeypatch.setattr(runner, "run_acceptance", lambda **_kwargs: expected)
    output = tmp_path / "acceptance.json"
    assert (
        runner.main(
            [
                "--output",
                str(output),
                "--synthetic-consent-confirmed",
            ]
        )
        == 0
    )
    assert json.loads(output.read_text(encoding="utf-8")) == expected
