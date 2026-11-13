from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import asdict
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.consent_scan_inventory import ConsentScanInventory
from maverick.consent_scanner import SCAN_REPORT_SCHEMA, ScanFinding, ScanReport
from maverick_dashboard import consent_scan_inventory_api

NOW = 1_800_000_000.0
API = "/api/v1/consent/scan-inventory"


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


class FakeScanner:
    def __init__(self) -> None:
        self.outcomes: list[object] = []
        self.calls: list[tuple[object, ...]] = []

    def scan(
        self,
        tenant_id,
        property_id,
        start_urls,
        allowed_origins,
        *,
        limits=None,
        auth_secret_ref=None,
        authenticated_scan_consent=False,
    ):
        self.calls.append(
            (
                tenant_id,
                property_id,
                tuple(start_urls),
                tuple(allowed_origins),
                limits,
                auth_secret_ref,
                authenticated_scan_consent,
            )
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeTrackerAuthority:
    def __init__(self) -> None:
        self.registered: list[dict[str, object]] = []
        self.admitted: list[dict[str, object]] = []

    def register_tracker(
        self,
        tenant_id,
        tracker_id,
        kind,
        vendor_id,
        purpose_ids,
        status,
        *,
        expected_revision,
        idempotency_key,
    ):
        record = {
            "tenant_id": tenant_id,
            "tracker_id": tracker_id,
            "kind": kind,
            "vendor_id": vendor_id,
            "purpose_ids": list(purpose_ids),
            "status": status,
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
        }
        self.registered.append(record)
        return {"revision": expected_revision + 1}

    def admit_scan_observations(
        self,
        tenant_id,
        scan_id,
        observations,
        observed_at,
        source_sha256,
        idempotency_key,
    ):
        record = {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "observations": list(observations),
            "observed_at": observed_at,
            "source_sha256": source_sha256,
            "idempotency_key": idempotency_key,
        }
        self.admitted.append(record)
        return {"accepted": len(record["observations"])}


def _report(
    property_id: str,
    *,
    label: str,
    truncated: bool = False,
    errors: tuple[dict[str, str], ...] = (),
) -> tuple[ScanReport, ScanFinding]:
    tracker_key = hashlib.sha256(f"tracker:{label}".encode()).hexdigest()
    evidence = hashlib.sha256(f"evidence:{label}".encode()).hexdigest()
    finding = ScanFinding(
        finding_id=f"CSF-{tracker_key[:24]}",
        kind="network",
        tracker_key=tracker_key,
        source_page_sha256=hashlib.sha256(b"page").hexdigest(),
        host="tracker.example",
        path_sha256=hashlib.sha256(b"/tag.js").hexdigest(),
        resource_type="script",
        name_sha256=None,
        first_party=False,
        classification="unknown",
        evidence_sha256=evidence,
    )
    body = {
        "schema": SCAN_REPORT_SCHEMA,
        "run_id": f"run-{label}",
        "tenant_sha256": hashlib.sha256(b"tenant-a").hexdigest(),
        "property_id": property_id,
        "started_at": NOW,
        "completed_at": NOW + 1,
        "pages_attempted": 1,
        "pages_captured": 1,
        "page_sha256": (hashlib.sha256(b"page").hexdigest(),),
        "findings": (finding,),
        "errors": errors,
        "truncated": truncated,
        "complete": not truncated and not errors,
    }
    return _signed_report(body), finding


def _signed_report(body: dict[str, object]) -> ScanReport:
    unsigned = ScanReport(**body, report_sha256="")
    canonical = asdict(unsigned)
    canonical.pop("report_sha256")
    return ScanReport(**body, report_sha256=_sha256(canonical))


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[consent_preferences]\n"
        "enable = true\n"
        "[consent_preferences.scanner]\n"
        "enable = true\n"
        "allow_authenticated_scans = false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    clock = Clock()
    scanner = FakeScanner()
    tracker = FakeTrackerAuthority()
    ids = itertools.count(1)
    inventory = ConsentScanInventory(
        tmp_path / "inventory.sqlite3",
        scanner,
        tracker_authority=tracker,
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
        token_factory=lambda: "lease-0123456789abcdefghijklmnop",
        gate=lambda: None,
        authenticated_scan_gate=lambda: False,
    )
    monkeypatch.setattr(
        consent_scan_inventory_api,
        "_inventory",
        lambda _ops, _tenant: inventory,
    )
    app = FastAPI()
    app.include_router(consent_scan_inventory_api.router, prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    yield client, inventory, scanner, tracker, clock, config_path
    config.reset_config_cache()


def _ok(response, expected: int = 200):
    assert response.status_code == expected, response.text
    return response.json()


def _seed_authority(client: TestClient, *, max_attempts: int = 3) -> None:
    _ok(
        client.put(
            f"{API}/properties/primary-web",
            json={
                "origins": ["https://www.example.com"],
                "start_urls": ["https://www.example.com/"],
                "expected_revision": 0,
                "idempotency_key": "property-primary-v1",
            },
        )
    )
    _ok(
        client.put(
            f"{API}/schedules/weekly-primary",
            json={
                "property_id": "primary-web",
                "interval_seconds": 300,
                "next_due_at": NOW,
                "expected_revision": 0,
                "idempotency_key": "schedule-primary-v1",
                "limits": {
                    "max_pages": 10,
                    "max_depth": 2,
                    "page_timeout_seconds": 10,
                    "max_network_events": 100,
                    "settle_milliseconds": 0,
                },
                "authenticated_scan_consent": False,
                "max_attempts": max_attempts,
                "retry_base_seconds": 1,
                "retry_max_seconds": 10,
                "lease_seconds": 60,
                "enabled": True,
            },
        )
    )


def _claim(client: TestClient) -> dict[str, object]:
    _ok(client.post(f"{API}/jobs/enqueue", json={"limit": 10}))
    return _ok(client.post(f"{API}/jobs/claim", json={"limit": 1}))["items"][0]


def test_property_schedule_are_strict_tenant_bound_and_default_off(environment) -> None:
    client, _inventory, _scanner, _tracker, _clock, config_path = environment
    _seed_authority(client)
    assert _ok(client.get(f"{API}/properties"))["items"][0]["property_id"] == "primary-web"
    assert _ok(client.get(f"{API}/schedules"))["items"][0]["schedule_id"] == "weekly-primary"

    extra = client.put(
        f"{API}/properties/other",
        json={
            "tenant_id": "tenant-b",
            "origins": ["https://other.example.com"],
            "start_urls": ["https://other.example.com/"],
            "expected_revision": 0,
            "idempotency_key": "other-v1",
        },
    )
    assert extra.status_code == 422

    config_path.write_text(
        "[consent_preferences]\nenable = true\n[consent_preferences.scanner]\nenable = false\n",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    assert client.get(f"{API}/status").status_code == 403


def test_claim_secret_is_one_time_and_truncated_run_never_claims_completeness(
    environment,
) -> None:
    client, _inventory, scanner, _tracker, _clock, _config = environment
    _seed_authority(client)
    scan_report, _finding = _report("primary-web", label="truncated", truncated=True)
    scanner.outcomes.append(scan_report)
    claim = _claim(client)
    assert claim["lease_token"] == "lease-0123456789abcdefghijklmnop"
    assert "lease_token_sha256" not in claim
    listed = _ok(client.get(f"{API}/jobs"))
    assert "lease_token" not in json.dumps(listed)

    completed = _ok(
        client.post(
            f"{API}/jobs/{claim['job_id']}/run",
            json={"lease_token": claim["lease_token"]},
        )
    )
    assert completed["external_side_effect"] is True
    assert completed["live_acceptance"] is False
    assert completed["report"]["complete"] is False
    assert completed["coverage"] == {
        "coverage_complete": False,
        "truncated": True,
        "errors_present": False,
        "absence_is_proven": False,
    }
    report = _ok(client.get(f"{API}/reports/{completed['report']['report_id']}"))
    assert report["coverage"]["coverage_complete"] is False
    assert report["coverage"]["absence_is_proven"] is False


def test_server_derived_review_evidence_and_two_reviewer_bridge(environment) -> None:
    client, _inventory, scanner, tracker, _clock, _config = environment
    _seed_authority(client)
    scan_report, finding = _report("primary-web", label="reviewed")
    scanner.outcomes.append(scan_report)
    claim = _claim(client)
    completed = _ok(
        client.post(
            f"{API}/jobs/{claim['job_id']}/run",
            json={"lease_token": claim["lease_token"]},
        )
    )
    report_id = completed["report"]["report_id"]
    discoveries = _ok(client.get(f"{API}/properties/primary-web/discoveries"))
    assert discoveries["items"][0]["initial_classification"] == "unknown"
    assert discoveries["unknowns_auto_enforced"] is False
    assert discoveries["after_tracker_key"] is None
    assert discoveries["next_after_tracker_key"] is None
    after = _ok(
        client.get(
            f"{API}/properties/primary-web/discoveries",
            params={"after_tracker_key": finding.tracker_key, "limit": 1},
        )
    )
    assert after["after_tracker_key"] == finding.tracker_key
    assert after["items"] == []
    assert after["truncated"] is False
    assert (
        client.get(
            f"{API}/properties/primary-web/discoveries",
            params={"after_tracker_key": "not-a-digest"},
        ).status_code
        == 422
    )

    people = _two_person_client()
    requested = people.post(
        f"{API}/properties/primary-web/discoveries/{finding.tracker_key}/review-requests",
        headers={"x-test-user": "alice"},
        json={
            "classification": "analytics",
            "registry_action": "approved",
            "report_id": report_id,
            "valid_until": NOW + 86_400,
            "expected_version": 0,
            "tracker_id": "tracker-analytics",
            "vendor_id": "vendor-analytics",
            "purpose_ids": ["analytics"],
            "authority_expected_revision": 0,
        },
    )
    assert requested.status_code == 201, requested.text
    reviewed = _ok(
        people.post(
            f"{API}/review-requests/{requested.json()['request_id']}/approve",
            headers={"x-test-user": "bob"},
        )
    )
    assert reviewed["evidence_sha256"] == finding.evidence_sha256
    assert reviewed["reviewer_sha256"] != reviewed["second_reviewer_sha256"]
    assert reviewed["primary_reviewer_bound_to_request_principal"] is True
    strict = client.post(
        f"{API}/properties/primary-web/discoveries/{finding.tracker_key}/review",
        json={
            "classification": "analytics",
            "registry_action": "observe_only",
            "report_id": report_id,
            "valid_until": NOW + 86_400,
            "expected_version": 1,
            "idempotency_key": "review-forged-evidence",
            "evidence_sha256": "0" * 64,
        },
    )
    assert strict.status_code == 422

    bridged = _ok(
        client.post(
            f"{API}/reports/{report_id}/bridge",
            json={"idempotency_key": "bridge-reviewed-v1", "limit": 100},
        )
    )
    assert bridged["registered_count"] == bridged["admitted_count"] == 1
    assert bridged["unknowns_auto_enforced"] is False
    assert bridged["live_external_acceptance"] is False
    assert tracker.registered[0]["tracker_id"] == "tracker-analytics"


def test_dead_letter_replay_diff_audit_retention_and_status_routes(environment) -> None:
    client, _inventory, scanner, _tracker, clock, _config = environment
    _seed_authority(client, max_attempts=1)
    scanner.outcomes.append(RuntimeError("private scanner detail"))
    failed_claim = _claim(client)
    failed = _ok(
        client.post(
            f"{API}/jobs/{failed_claim['job_id']}/run",
            json={"lease_token": failed_claim["lease_token"]},
        )
    )
    assert failed["job"]["status"] == "dead_letter"
    dead = _ok(client.get(f"{API}/dead-letters"))
    assert dead["items"][0]["job_id"] == failed_claim["job_id"]
    replayed = _ok(
        client.post(
            f"{API}/dead-letters/{failed_claim['job_id']}/replay",
            json={
                "expected_revision": failed["job"]["revision"],
                "idempotency_key": "replay-dead-v1",
            },
        )
    )
    assert replayed["status"] == "queued"

    scanner.outcomes.append(_report("primary-web", label="older")[0])
    claim = _ok(client.post(f"{API}/jobs/claim", json={"limit": 1}))["items"][0]
    older = _ok(
        client.post(
            f"{API}/jobs/{claim['job_id']}/run",
            json={"lease_token": claim["lease_token"]},
        )
    )["report"]
    clock.now += 300
    scanner.outcomes.append(_report("primary-web", label="newer")[0])
    newer_claim = _claim(client)
    newer = _ok(
        client.post(
            f"{API}/jobs/{newer_claim['job_id']}/run",
            json={"lease_token": newer_claim["lease_token"]},
        )
    )["report"]
    diff = _ok(
        client.get(
            f"{API}/reports/diff",
            params={
                "older_report_id": older["report_id"],
                "newer_report_id": newer["report_id"],
                "limit": 100,
            },
        )
    )
    assert diff["absence_is_proven"] is False
    assert diff["added_count"] == diff["removed_count"] == 1

    status = _ok(client.get(f"{API}/status"))
    assert status["unknowns_auto_enforced"] is False
    assert status["live_browser_acceptance"] is False
    assert status["external_scan_execution"] == "explicit_run_endpoint_only"
    assert status["scheduler"]["tenant_bound_metrics_exposed"] is False
    assert set(status["scheduler"]) == {
        "running",
        "configured_enabled",
        "stop_requested",
        "tenant_bound_metrics_exposed",
    }
    assert _ok(client.get(f"{API}/audit"))["events"]
    retention = _ok(
        client.post(
            f"{API}/retention/status",
            json={"before": clock.now + 1_000, "limit": 100},
        )
    )
    assert retention["reports_deleted"] is False
    purged = _ok(
        client.post(
            f"{API}/retention/purge",
            json={"before": clock.now + 1_000, "limit": 100},
        )
    )
    assert purged["classifications_deleted"] == 0
    assert purged["audit_events_deleted"] == 0


def _two_person_client() -> TestClient:
    from types import SimpleNamespace

    from fastapi import Request

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub=request.headers.get("x-test-user", "alice"))
        return await call_next(request)

    app.include_router(consent_scan_inventory_api.router, prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_scan_now_runs_the_worker_protocol_without_exposing_lease_tokens(environment) -> None:
    client, _inventory, scanner, _tracker, _clock, _config = environment
    missing = client.post(f"{API}/properties/primary-web/scan-now")
    assert missing.status_code in {404, 409}
    _seed_authority(client)
    scan_report, _finding = _report("primary-web", label="now")
    scanner.outcomes.append(scan_report)
    ran = client.post(f"{API}/properties/primary-web/scan-now")
    assert ran.status_code == 200, ran.text
    body = ran.json()
    assert body["property_scanned"] is True
    assert body["outcomes"][0]["succeeded"] is True
    assert body["outcomes"][0]["report_id"]
    assert "lease" not in json.dumps(body)
    assert len(scanner.calls) == 1
    # Nothing else is due, so running due scans does nothing more.
    idle = _ok(client.post(f"{API}/jobs/run-due", json={"limit": 5}))
    assert idle["outcomes"] == []
    assert len(scanner.calls) == 1


def test_registry_review_needs_a_different_signed_in_approver(environment) -> None:
    client, _inventory, scanner, _tracker, _clock, _config = environment
    _seed_authority(client)
    scan_report, finding = _report("primary-web", label="two-person")
    scanner.outcomes.append(scan_report)
    ran = _ok(client.post(f"{API}/properties/primary-web/scan-now"))
    report_id = ran["outcomes"][0]["report_id"]
    people = _two_person_client()
    requested = people.post(
        f"{API}/properties/primary-web/discoveries/{finding.tracker_key}/review-requests",
        headers={"x-test-user": "alice"},
        json={
            "classification": "analytics",
            "registry_action": "approved",
            "report_id": report_id,
            "valid_until": NOW + 86_400,
            "expected_version": 0,
            "tracker_id": "tracker-analytics",
            "vendor_id": "vendor-analytics",
            "purpose_ids": ["analytics"],
            "authority_expected_revision": 0,
        },
    )
    assert requested.status_code == 201, requested.text
    request_id = requested.json()["request_id"]
    assert "proposer_sha256" not in requested.text
    listed = people.get(f"{API}/review-requests", headers={"x-test-user": "alice"}).json()
    assert listed["items"][0]["requested_by_me"] is True
    assert people.get(
        f"{API}/review-requests", headers={"x-test-user": "bob"}
    ).json()["items"][0]["requested_by_me"] is False

    self_approval = people.post(
        f"{API}/review-requests/{request_id}/approve", headers={"x-test-user": "alice"}
    )
    assert self_approval.status_code == 409
    approved = people.post(
        f"{API}/review-requests/{request_id}/approve", headers={"x-test-user": "bob"}
    )
    assert approved.status_code == 200, approved.text
    review = approved.json()
    assert review["second_reviewer_independently_authenticated_by_api"] is True
    assert review["reviewer_sha256"] != review["second_reviewer_sha256"]
    assert review["evidence_sha256"] == finding.evidence_sha256
    again = people.post(
        f"{API}/review-requests/{request_id}/approve", headers={"x-test-user": "carol"}
    )
    assert again.status_code == 409
    assert people.get(
        f"{API}/review-requests", headers={"x-test-user": "bob"}
    ).json()["items"][0]["status"] == "approved"


def test_direct_review_never_takes_a_typed_second_reviewer(environment) -> None:
    client, inventory, scanner, _tracker, _clock, _config = environment
    _seed_authority(client)
    scan_report, finding = _report("primary-web", label="direct")
    scanner.outcomes.append(scan_report)
    report_id = _ok(client.post(f"{API}/properties/primary-web/scan-now"))["outcomes"][0][
        "report_id"
    ]
    url = f"{API}/properties/primary-web/discoveries/{finding.tracker_key}/review"
    registry = {
        "classification": "analytics",
        "registry_action": "approved",
        "report_id": report_id,
        "valid_until": NOW + 86_400,
        "expected_version": 0,
        "idempotency_key": "direct-approved-v1",
        "tracker_id": "tracker-analytics",
        "vendor_id": "vendor-analytics",
        "purpose_ids": ["analytics"],
    }
    typed = client.post(
        url,
        json={**registry, "second_reviewer_sha256": hashlib.sha256(b"anyone").hexdigest()},
    )
    assert typed.status_code == 422
    refused = client.post(url, json=registry)
    assert refused.status_code == 409
    assert "review-requests" in refused.json()["detail"]
    assert inventory.list_reviews("tenant-a", "primary-web", finding.tracker_key)["items"] == []

    recorded = _ok(
        client.post(
            url,
            json={
                "classification": "analytics",
                "registry_action": "observe_only",
                "report_id": report_id,
                "valid_until": NOW + 86_400,
                "expected_version": 0,
                "idempotency_key": "direct-observe-v1",
            },
        )
    )
    assert recorded["registry_action"] == "observe_only"
    assert recorded["second_reviewer_sha256"] is None
