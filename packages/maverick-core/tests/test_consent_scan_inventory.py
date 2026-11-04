from __future__ import annotations

import hashlib
import itertools
import json
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pytest
from maverick import config
from maverick.consent_preferences import ConsentPreferenceStore
from maverick.consent_scan_inventory import (
    ConsentScanBridgeError,
    ConsentScanConflict,
    ConsentScanIntegrityError,
    ConsentScanInventory,
    ConsentScanLeaseError,
    ConsentScanNotFound,
    ConsentScanValidationError,
)
from maverick.consent_scanner import (
    SCAN_REPORT_SCHEMA,
    ConsentScanner,
    ConsentScannerConfigError,
    NetworkMetadata,
    PageCapture,
    ScanFinding,
    ScanLimits,
    ScanReport,
)

NOW = 1_800_000_000.0
ORIGIN = "https://shop.example.test"
START_URL = f"{ORIGIN}/"
DIGEST_A = hashlib.sha256(b"reviewer-a").hexdigest()
DIGEST_B = hashlib.sha256(b"reviewer-b").hexdigest()
DIGEST_C = hashlib.sha256(b"review-evidence").hexdigest()


def _sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


class MutableClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _finding(label: str, *, classification: str = "unknown") -> ScanFinding:
    tracker_key = hashlib.sha256(f"tracker:{label}".encode()).hexdigest()
    return ScanFinding(
        finding_id=f"CSF-{tracker_key[:24]}",
        kind="network",
        tracker_key=tracker_key,
        source_page_sha256=hashlib.sha256(f"page:{label}".encode()).hexdigest(),
        host=f"{label}.vendor.test",
        path_sha256=hashlib.sha256(b"/collect").hexdigest(),
        resource_type="fetch",
        name_sha256=None,
        first_party=False,
        classification=classification,
        evidence_sha256=hashlib.sha256(f"evidence:{label}".encode()).hexdigest(),
    )


def _report(
    tenant: str,
    property_id: str,
    run: str,
    findings: tuple[ScanFinding, ...] = (),
    *,
    completed_at: float = NOW,
    truncated: bool = False,
    errors: tuple[dict[str, str], ...] = (),
) -> ScanReport:
    body = {
        "schema": SCAN_REPORT_SCHEMA,
        "run_id": f"CSR-{run}",
        "tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(),
        "property_id": property_id,
        "started_at": completed_at - 1,
        "completed_at": completed_at,
        "pages_attempted": 1,
        "pages_captured": 1 if not errors else 0,
        "page_sha256": [hashlib.sha256(f"page:{run}".encode()).hexdigest()],
        "findings": [asdict(item) for item in findings],
        "errors": list(errors),
        "truncated": truncated,
        "complete": not truncated and not errors,
    }
    return ScanReport(
        schema=SCAN_REPORT_SCHEMA,
        run_id=body["run_id"],
        tenant_sha256=body["tenant_sha256"],
        property_id=property_id,
        started_at=body["started_at"],
        completed_at=completed_at,
        pages_attempted=1,
        pages_captured=body["pages_captured"],
        page_sha256=tuple(body["page_sha256"]),
        findings=findings,
        errors=errors,
        truncated=truncated,
        complete=body["complete"],
        report_sha256=_sha256(body),
    )


class FakeScanner:
    def __init__(self) -> None:
        self.outcomes: list[ScanReport | Exception] = []
        self.calls: list[dict[str, Any]] = []

    def scan(
        self,
        tenant_id: str,
        property_id: str,
        start_urls,
        allowed_origins,
        *,
        limits: ScanLimits | None = None,
        auth_secret_ref: str | None = None,
        authenticated_scan_consent: bool = False,
    ) -> ScanReport:
        self.calls.append(
            {
                "tenant_id": tenant_id,
                "property_id": property_id,
                "start_urls": list(start_urls),
                "allowed_origins": list(allowed_origins),
                "limits": limits,
                "auth_secret_ref": auth_secret_ref,
                "authenticated_scan_consent": authenticated_scan_consent,
            }
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class NoNetworkCollector:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def capture(
        self,
        url,
        *,
        navigation_hosts,
        limits,
        auth_secret_ref,
    ) -> PageCapture:
        del navigation_hosts, limits, auth_secret_ref
        self.calls.append(url)
        return PageCapture(
            final_url=url,
            links=(),
            network=(NetworkMetadata("https://metrics.vendor.test/collect", "fetch"),),
            cookies=(),
            storage_keys=(),
        )


class FakeTrackerAuthority:
    def __init__(self) -> None:
        self.registry_calls: list[dict[str, Any]] = []
        self.admission_calls: list[dict[str, Any]] = []

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
        call = {
            "tenant_id": tenant_id,
            "tracker_id": tracker_id,
            "kind": kind,
            "vendor_id": vendor_id,
            "purpose_ids": list(purpose_ids),
            "status": status,
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
        }
        self.registry_calls.append(call)
        return {**call, "revision": expected_revision + 1}

    def admit_scan_observations(
        self,
        tenant_id,
        scan_id,
        observations,
        observed_at,
        source_sha256,
        idempotency_key,
    ):
        call = {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "observations": list(observations),
            "observed_at": observed_at,
            "source_sha256": source_sha256,
            "idempotency_key": idempotency_key,
        }
        self.admission_calls.append(call)
        return {
            "scan_id": scan_id,
            "admitted": True,
            "admitted_count": len(observations),
            "source_sha256": source_sha256,
        }


@dataclass
class Environment:
    inventory: ConsentScanInventory
    scanner: FakeScanner
    tracker_authority: FakeTrackerAuthority
    clock: MutableClock


@pytest.fixture(autouse=True)
def scanner_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    # Readable config: no unreadable sources (the real function takes
    # include_tenant=, which a bare ``list`` refused when nothing had warmed it).
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: {})
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "scanner": {"enable": True},
            }
        },
    )


@pytest.fixture
def environment(tmp_path: Path) -> Environment:
    clock = MutableClock()
    scanner = FakeScanner()
    tracker_authority = FakeTrackerAuthority()
    identifiers = itertools.count(1)
    tokens = itertools.count(1)
    inventory = ConsentScanInventory(
        tmp_path / "private" / "scan-inventory.sqlite3",
        scanner,
        tracker_authority=tracker_authority,
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(identifiers)}",
        token_factory=lambda: f"lease-token-{next(tokens):012d}",
    )
    return Environment(inventory, scanner, tracker_authority, clock)


def _seed(
    environment: Environment,
    *,
    max_attempts: int = 3,
    retry_base_seconds: int = 10,
    lease_seconds: int = 30,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prop = environment.inventory.upsert_property(
        "tenant-a",
        "property-shop",
        [ORIGIN],
        [START_URL],
        expected_revision=0,
        idempotency_key="property-create",
    )
    schedule = environment.inventory.put_schedule(
        "tenant-a",
        "schedule-daily",
        "property-shop",
        interval_seconds=300,
        next_due_at=environment.clock.value,
        expected_revision=0,
        idempotency_key="schedule-create",
        max_attempts=max_attempts,
        retry_base_seconds=retry_base_seconds,
        retry_max_seconds=100,
        lease_seconds=lease_seconds,
    )
    return prop, schedule


def _enqueue_claim(environment: Environment, worker: str = "worker-a") -> dict[str, Any]:
    queued = environment.inventory.enqueue_due("tenant-a")
    assert len(queued["items"]) == 1
    claimed = environment.inventory.claim_due("tenant-a", worker)
    assert len(claimed["items"]) == 1
    return claimed["items"][0]


def _complete_report(
    environment: Environment,
    report: ScanReport,
    *,
    worker: str = "worker-a",
) -> dict[str, Any]:
    environment.scanner.outcomes.append(report)
    claim = _enqueue_claim(environment, worker)
    result = environment.inventory.run_claim(
        "tenant-a",
        claim["job_id"],
        worker,
        claim["lease_token"],
    )
    assert result["succeeded"] is True
    return result


def test_gates_private_permissions_and_concurrent_schema_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanner = FakeScanner()
    path = tmp_path / "concurrent" / "inventory.sqlite3"

    with ThreadPoolExecutor(max_workers=6) as executor:
        stores = list(
            executor.map(
                lambda _index: ConsentScanInventory(path, scanner),
                range(6),
            )
        )
    assert len(stores) == 6
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    assert stores[0].list_properties("tenant-a") == {
        "items": [],
        "truncated": False,
    }

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"consent_preferences": {"enable": True, "scanner": {"enable": False}}},
    )
    with pytest.raises(ConsentScannerConfigError):
        stores[0].list_properties("tenant-a")


def test_canonical_tenant_ids_accept_spaces_and_preserve_isolation(
    environment: Environment,
) -> None:
    created = environment.inventory.upsert_property(
        "Acme Corp",
        "property-shop",
        [ORIGIN],
        [START_URL],
        expected_revision=0,
        idempotency_key="acme-property-create",
    )

    assert environment.inventory.get_property("Acme Corp", "property-shop") == created
    assert environment.inventory.list_properties("Other Corp") == {
        "items": [],
        "truncated": False,
    }
    with pytest.raises(ConsentScanValidationError, match="tenant_id is invalid"):
        environment.inventory.list_properties("Acme Corp.")
    with pytest.raises(ConsentScanValidationError, match="opaque identifier"):
        environment.inventory.get_property("Acme Corp", "property with spaces")


def test_property_schedule_cas_idempotency_and_exact_origin_boundaries(
    environment: Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prop, schedule = _seed(environment)
    assert prop["revision"] == schedule["revision"] == 1
    assert (
        environment.inventory.upsert_property(
            "tenant-a",
            "property-shop",
            [ORIGIN],
            [START_URL],
            expected_revision=0,
            idempotency_key="property-create",
        )
        == prop
    )
    with pytest.raises(ConsentScanConflict, match="rebound"):
        environment.inventory.upsert_property(
            "tenant-a",
            "property-shop",
            [ORIGIN],
            [f"{ORIGIN}/privacy"],
            expected_revision=0,
            idempotency_key="property-create",
        )
    with pytest.raises(ConsentScanConflict, match="revision"):
        environment.inventory.upsert_property(
            "tenant-a",
            "property-shop",
            [ORIGIN],
            [START_URL],
            expected_revision=0,
            idempotency_key="property-stale",
        )

    for bad_origin in (
        "http://shop.example.test",
        "https://*.example.test",
        "https://shop.example.test/path",
    ):
        with pytest.raises(ConsentScanValidationError):
            environment.inventory.upsert_property(
                "tenant-a",
                "bad-property",
                [bad_origin],
                [START_URL],
                expected_revision=0,
                idempotency_key=f"bad-{hashlib.sha256(bad_origin.encode()).hexdigest()}",
            )
    with pytest.raises(ConsentScanValidationError, match="outside"):
        environment.inventory.upsert_property(
            "tenant-a",
            "bad-start",
            [ORIGIN],
            ["https://outside.example.test/"],
            expected_revision=0,
            idempotency_key="bad-start",
        )
    with pytest.raises(ConsentScanValidationError, match="both"):
        environment.inventory.put_schedule(
            "tenant-a",
            "bad-auth",
            "property-shop",
            interval_seconds=300,
            next_due_at=NOW,
            auth_secret_ref="secret-ref",
            authenticated_scan_consent=False,
            expected_revision=0,
            idempotency_key="bad-auth",
        )
    with pytest.raises(ConsentScanValidationError, match="not enabled"):
        environment.inventory.put_schedule(
            "tenant-a",
            "auth-disabled",
            "property-shop",
            interval_seconds=300,
            next_due_at=NOW,
            auth_secret_ref="secret-ref",
            authenticated_scan_consent=True,
            expected_revision=0,
            idempotency_key="auth-disabled",
        )
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "scanner": {
                    "enable": True,
                    "allow_authenticated_scans": True,
                },
            }
        },
    )
    authenticated = environment.inventory.put_schedule(
        "tenant-a",
        "auth-enabled",
        "property-shop",
        interval_seconds=300,
        next_due_at=NOW,
        auth_secret_ref="secret-ref",
        authenticated_scan_consent=True,
        expected_revision=0,
        idempotency_key="auth-enabled",
    )
    assert authenticated["authenticated_scan_consent"] is True
    assert environment.inventory.list_properties("tenant-b")["items"] == []
    with pytest.raises(ConsentScanNotFound):
        environment.inventory.get_property("tenant-b", "property-shop")


def test_non_ascii_stored_digests_are_refused_not_type_errors(
    environment: Environment,
) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest instead
    # of the idempotency conflict and integrity refusals.
    _seed(environment)
    with sqlite3.connect(environment.inventory.path) as connection:
        connection.execute("DROP TRIGGER consent_scan_idempotency_no_update")
        connection.execute("UPDATE consent_scan_idempotency SET request_sha256 = ?", ("é" * 64,))
        connection.execute("UPDATE consent_scan_properties SET record_sha256 = ?", ("é" * 64,))
    with pytest.raises(ConsentScanConflict, match="rebound"):
        environment.inventory.upsert_property(
            "tenant-a",
            "property-shop",
            [ORIGIN],
            [START_URL],
            expected_revision=0,
            idempotency_key="property-create",
        )
    with pytest.raises(ConsentScanIntegrityError, match="property"):
        environment.inventory.get_property("tenant-a", "property-shop")


def test_due_claim_success_quarantines_unknown_and_preserves_completeness(
    environment: Environment,
) -> None:
    _seed(environment)
    findings = (_finding("analytics"), _finding("ads"))
    report = _report(
        "tenant-a",
        "property-shop",
        "run-one",
        findings,
        truncated=True,
    )
    environment.scanner.outcomes.append(report)
    claim = _enqueue_claim(environment)
    assert environment.inventory.enqueue_due("tenant-a")["items"] == []
    assert claim["attempts"] == 1
    assert claim["lease_token"].encode() not in environment.inventory.path.read_bytes()

    result = environment.inventory.run_claim(
        "tenant-a",
        claim["job_id"],
        "worker-a",
        claim["lease_token"],
    )
    assert result["succeeded"] is True
    assert result["report"]["complete"] is False
    assert result["report"]["truncated"] is True
    assert environment.scanner.calls == [
        {
            "tenant_id": "tenant-a",
            "property_id": "property-shop",
            "start_urls": [START_URL],
            "allowed_origins": [ORIGIN],
            "limits": ScanLimits(),
            "auth_secret_ref": None,
            "authenticated_scan_consent": False,
        }
    ]
    discoveries = environment.inventory.list_discoveries(
        "tenant-a",
        "property-shop",
    )
    assert len(discoveries["items"]) == 2
    assert all(item["initial_classification"] == "unknown" for item in discoveries["items"])
    assert all(item["review"] is None for item in discoveries["items"])
    assert environment.tracker_authority.registry_calls == []
    stored = environment.inventory.get_report(
        "tenant-a",
        result["report"]["report_id"],
    )
    assert stored["scanner_report_sha256"] == report.report_sha256
    assert stored["scanner_report"]["errors"] == []


def test_discovery_listing_has_exact_forward_cursor_pagination(
    environment: Environment,
) -> None:
    _seed(environment)
    findings = (_finding("analytics"), _finding("ads"), _finding("functional"))
    _complete_report(
        environment,
        _report("tenant-a", "property-shop", "cursor-page", findings),
    )

    first = environment.inventory.list_discoveries(
        "tenant-a",
        "property-shop",
        limit=2,
    )
    assert first["after_tracker_key"] is None
    assert first["truncated"] is True
    assert first["next_after_tracker_key"] == first["items"][-1]["tracker_key"]

    second = environment.inventory.list_discoveries(
        "tenant-a",
        "property-shop",
        after_tracker_key=first["next_after_tracker_key"],
        limit=2,
    )
    assert second["after_tracker_key"] == first["next_after_tracker_key"]
    assert second["truncated"] is False
    assert second["next_after_tracker_key"] is None
    combined = first["items"] + second["items"]
    assert [item["tracker_key"] for item in combined] == sorted(
        finding.tracker_key for finding in findings
    )

    with pytest.raises(ConsentScanValidationError, match="after_tracker_key"):
        environment.inventory.list_discoveries(
            "tenant-a",
            "property-shop",
            after_tracker_key="not-a-digest",
        )

    with sqlite3.connect(environment.inventory.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE consent_scan_reports SET scanner_report_sha256 = ?",
                ("0" * 64,),
            )


def test_inventory_executes_real_injected_scanner_without_network(tmp_path: Path) -> None:
    collector = NoNetworkCollector()
    scan_times = iter((NOW, NOW + 1))
    scanner = ConsentScanner(
        collector,
        clock=lambda: next(scan_times),
        id_factory=lambda: "real-injected-run",
        host_is_public=lambda _host: True,
    )
    identifiers = itertools.count(1)
    inventory = ConsentScanInventory(
        tmp_path / "real-scanner" / "inventory.sqlite3",
        scanner,
        clock=MutableClock(NOW + 2),
        id_factory=lambda prefix: f"{prefix}-{next(identifiers)}",
        token_factory=lambda: "lease-token-real-injected-0001",
    )
    inventory.upsert_property(
        "tenant-a",
        "property-shop",
        [ORIGIN],
        [START_URL],
        expected_revision=0,
        idempotency_key="real-property",
    )
    inventory.put_schedule(
        "tenant-a",
        "real-schedule",
        "property-shop",
        interval_seconds=300,
        next_due_at=NOW + 2,
        expected_revision=0,
        idempotency_key="real-schedule",
    )
    inventory.enqueue_due("tenant-a")
    claim = inventory.claim_due("tenant-a", "real-worker")["items"][0]
    result = inventory.run_claim(
        "tenant-a",
        claim["job_id"],
        "real-worker",
        claim["lease_token"],
    )
    assert result["succeeded"] is True
    assert result["report"]["scanner_report"]["findings"][0]["classification"] == ("unknown")
    assert collector.calls == [START_URL]


def test_stale_authority_dead_letters_without_running_scanner(
    environment: Environment,
) -> None:
    _seed(environment)
    queued = environment.inventory.enqueue_due("tenant-a")["items"][0]
    environment.inventory.upsert_property(
        "tenant-a",
        "property-shop",
        [ORIGIN],
        [START_URL, f"{ORIGIN}/privacy"],
        expected_revision=1,
        idempotency_key="property-v2",
    )
    claim = environment.inventory.claim_due("tenant-a", "worker-a")["items"][0]
    assert claim["job_id"] == queued["job_id"]
    result = environment.inventory.run_claim(
        "tenant-a",
        claim["job_id"],
        "worker-a",
        claim["lease_token"],
    )
    assert result["succeeded"] is False
    assert result["job"]["status"] == "dead_letter"
    assert result["job"]["last_error_code"] == "authority_changed"
    assert environment.scanner.calls == []


def test_stale_lease_recovery_rejects_old_worker_and_is_concurrency_safe(
    environment: Environment,
) -> None:
    _seed(environment, max_attempts=3, lease_seconds=30)
    environment.inventory.enqueue_due("tenant-a")
    first = environment.inventory.claim_due("tenant-a", "worker-a")["items"][0]
    environment.clock.value += 31
    recovered = environment.inventory.claim_due("tenant-a", "worker-b")
    assert recovered["recovered_leases"] == 1
    second = recovered["items"][0]
    assert second["attempts"] == 2
    with pytest.raises(ConsentScanLeaseError):
        environment.inventory.run_claim(
            "tenant-a",
            first["job_id"],
            "worker-a",
            first["lease_token"],
        )
    environment.scanner.outcomes.append(
        _report(
            "tenant-a",
            "property-shop",
            "recovered-run",
            completed_at=environment.clock.value,
        )
    )
    assert environment.inventory.run_claim(
        "tenant-a",
        second["job_id"],
        "worker-b",
        second["lease_token"],
    )["succeeded"]

    environment.clock.value += 300
    environment.inventory.enqueue_due("tenant-a")
    with ThreadPoolExecutor(max_workers=2) as executor:
        pages = list(
            executor.map(
                lambda worker: environment.inventory.claim_due("tenant-a", worker),
                ("worker-c", "worker-d"),
            )
        )
    assert sum(len(page["items"]) for page in pages) == 1


def test_retry_backoff_dead_letter_and_bounded_replay(environment: Environment) -> None:
    _seed(environment, max_attempts=2, retry_base_seconds=10)
    environment.scanner.outcomes.extend([RuntimeError("private detail"), ValueError("bad")])
    first = _enqueue_claim(environment)
    failed = environment.inventory.run_claim(
        "tenant-a",
        first["job_id"],
        "worker-a",
        first["lease_token"],
    )
    assert failed["job"]["status"] == "queued"
    assert failed["job"]["last_error_code"] == "RuntimeError"
    assert environment.inventory.claim_due("tenant-a", "worker-a")["items"] == []
    environment.clock.value += 10
    second = environment.inventory.claim_due("tenant-a", "worker-a")["items"][0]
    dead = environment.inventory.run_claim(
        "tenant-a",
        second["job_id"],
        "worker-a",
        second["lease_token"],
    )["job"]
    assert dead["status"] == "dead_letter"
    assert b"private detail" not in environment.inventory.path.read_bytes()

    replay = environment.inventory.replay_dead_letter(
        "tenant-a",
        dead["job_id"],
        expected_revision=dead["revision"],
        idempotency_key="dead-replay",
    )
    assert replay["status"] == "queued"
    assert replay["attempts"] == 0
    assert (
        environment.inventory.replay_dead_letter(
            "tenant-a",
            dead["job_id"],
            expected_revision=dead["revision"],
            idempotency_key="dead-replay",
        )
        == replay
    )
    with pytest.raises(ConsentScanConflict, match="rebound"):
        environment.inventory.replay_dead_letter(
            "tenant-a",
            dead["job_id"],
            expected_revision=replay["revision"],
            idempotency_key="dead-replay",
        )
    environment.scanner.outcomes.append(
        _report(
            "tenant-a",
            "property-shop",
            "after-replay",
            completed_at=environment.clock.value,
        )
    )
    third = environment.inventory.claim_due("tenant-a", "worker-a")["items"][0]
    assert environment.inventory.run_claim(
        "tenant-a",
        third["job_id"],
        "worker-a",
        third["lease_token"],
    )["succeeded"]


def test_report_diffs_are_bounded_and_never_prove_absence(
    environment: Environment,
) -> None:
    _seed(environment)
    first_report = _complete_report(
        environment,
        _report(
            "tenant-a",
            "property-shop",
            "diff-one",
            (_finding("shared"), _finding("removed")),
        ),
    )["report"]
    environment.clock.value += 300
    second_report = _complete_report(
        environment,
        _report(
            "tenant-a",
            "property-shop",
            "diff-two",
            (_finding("shared"), _finding("added")),
            completed_at=environment.clock.value,
            truncated=True,
        ),
    )["report"]
    diff = environment.inventory.diff_reports(
        "tenant-a",
        first_report["report_id"],
        second_report["report_id"],
        limit=1,
    )
    assert diff["added_count"] == diff["removed_count"] == 1
    assert diff["unchanged_count"] == 1
    assert diff["diff_truncated"] is True
    assert diff["older_complete"] is True
    assert diff["newer_complete"] is False
    assert diff["coverage_complete"] is False
    assert diff["absence_is_proven"] is False


def test_four_eyes_review_freshness_and_reviewed_only_bridge(
    environment: Environment,
) -> None:
    _seed(environment)
    analytics = _finding("analytics")
    unknown = _finding("unknown")
    completed = _complete_report(
        environment,
        _report(
            "tenant-a",
            "property-shop",
            "review-run",
            (analytics, unknown),
        ),
    )
    report_id = completed["report"]["report_id"]
    assert environment.tracker_authority.registry_calls == []
    with pytest.raises(ConsentScanValidationError, match="two distinct"):
        environment.inventory.review_tracker(
            "tenant-a",
            "property-shop",
            analytics.tracker_key,
            classification="analytics",
            registry_action="approved",
            tracker_id="tracker-analytics",
            vendor_id="vendor-a",
            purpose_ids=["analytics"],
            reviewer_sha256=DIGEST_A,
            evidence_sha256=DIGEST_C,
            report_id=report_id,
            valid_until=NOW + 100,
            expected_version=0,
            idempotency_key="review-one",
        )
    with pytest.raises(ConsentScanValidationError, match="cannot carry"):
        environment.inventory.review_tracker(
            "tenant-a",
            "property-shop",
            analytics.tracker_key,
            classification="not_a_tracker",
            registry_action="blocked",
            tracker_id="tracker-analytics",
            vendor_id="vendor-a",
            purpose_ids=["analytics"],
            reviewer_sha256=DIGEST_A,
            second_reviewer_sha256=DIGEST_B,
            evidence_sha256=DIGEST_C,
            report_id=report_id,
            valid_until=NOW + 100,
            expected_version=0,
            idempotency_key="review-invalid-not-tracker",
        )
    review = environment.inventory.review_tracker(
        "tenant-a",
        "property-shop",
        analytics.tracker_key,
        classification="analytics",
        registry_action="approved",
        tracker_id="tracker-analytics",
        vendor_id="vendor-a",
        purpose_ids=["analytics"],
        reviewer_sha256=DIGEST_A,
        second_reviewer_sha256=DIGEST_B,
        evidence_sha256=DIGEST_C,
        report_id=report_id,
        valid_until=NOW + 100,
        expected_version=0,
        idempotency_key="review-approved",
    )
    assert review["version"] == 1
    assert (
        environment.inventory.review_tracker(
            "tenant-a",
            "property-shop",
            analytics.tracker_key,
            classification="analytics",
            registry_action="approved",
            tracker_id="tracker-analytics",
            vendor_id="vendor-a",
            purpose_ids=["analytics"],
            reviewer_sha256=DIGEST_A,
            second_reviewer_sha256=DIGEST_B,
            evidence_sha256=DIGEST_C,
            report_id=report_id,
            valid_until=NOW + 100,
            expected_version=0,
            idempotency_key="review-approved",
        )
        == review
    )
    with pytest.raises(ConsentScanConflict, match="rebound"):
        environment.inventory.review_tracker(
            "tenant-a",
            "property-shop",
            analytics.tracker_key,
            classification="advertising",
            registry_action="approved",
            tracker_id="tracker-analytics",
            vendor_id="vendor-a",
            purpose_ids=["analytics"],
            reviewer_sha256=DIGEST_A,
            second_reviewer_sha256=DIGEST_B,
            evidence_sha256=DIGEST_C,
            report_id=report_id,
            valid_until=NOW + 100,
            expected_version=0,
            idempotency_key="review-approved",
        )

    bridge = environment.inventory.bridge_report(
        "tenant-a",
        report_id,
        idempotency_key="bridge-page",
    )
    assert bridge["reviewed_count"] == 1
    assert bridge["skipped_unknown"] == 1
    assert bridge["registered_count"] == bridge["admitted_count"] == 1
    assert environment.tracker_authority.registry_calls[0]["tracker_id"] == ("tracker-analytics")
    observation = environment.tracker_authority.admission_calls[0]["observations"][0]
    assert observation.tracker_id == "tracker-analytics"
    assert observation.evidence_sha256 == analytics.evidence_sha256
    assert (
        environment.inventory.bridge_report(
            "tenant-a",
            report_id,
            idempotency_key="bridge-page",
        )
        == bridge
    )
    assert len(environment.tracker_authority.registry_calls) == 1
    assert all(
        item["initial_classification"] == "unknown"
        for item in environment.inventory.list_discoveries(
            "tenant-a",
            "property-shop",
        )["items"]
    )

    environment.clock.value = NOW + 101
    stale = environment.inventory.bridge_report(
        "tenant-a",
        report_id,
        idempotency_key="bridge-after-expiry",
    )
    assert stale["reviewed_count"] == 0
    assert stale["skipped_stale"] == 1
    assert stale["skipped_unknown"] == 1
    assert len(environment.tracker_authority.registry_calls) == 1
    with pytest.raises(ConsentScanNotFound):
        environment.inventory.bridge_report(
            "tenant-b",
            report_id,
            idempotency_key="cross-tenant",
        )


def test_bridge_failure_is_generic_and_unknowns_are_never_passed(
    environment: Environment,
) -> None:
    _seed(environment)
    finding = _finding("bridge-failure")
    completed = _complete_report(
        environment,
        _report(
            "tenant-a",
            "property-shop",
            "bridge-failure-run",
            (finding,),
        ),
    )
    environment.inventory.review_tracker(
        "tenant-a",
        "property-shop",
        finding.tracker_key,
        classification="analytics",
        registry_action="approved",
        tracker_id="tracker-failing",
        vendor_id="vendor-a",
        purpose_ids=["analytics"],
        reviewer_sha256=DIGEST_A,
        second_reviewer_sha256=DIGEST_B,
        evidence_sha256=DIGEST_C,
        report_id=completed["report"]["report_id"],
        valid_until=NOW + 100,
        expected_version=0,
        idempotency_key="review-failing",
    )

    def fail_registration(*_args, **_kwargs):
        raise RuntimeError("provider secret must not escape")

    environment.tracker_authority.register_tracker = fail_registration
    with pytest.raises(ConsentScanBridgeError, match="bridge failed") as raised:
        environment.inventory.bridge_report(
            "tenant-a",
            completed["report"]["report_id"],
            idempotency_key="bridge-failing",
        )
    assert "provider secret" not in str(raised.value)
    assert environment.tracker_authority.admission_calls == []


def test_reviewed_bridge_interoperates_with_real_consent_tracker_authority(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    scanner = FakeScanner()
    preference_ids = itertools.count(1)
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences" / "consent-preferences.sqlite3",
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(preference_ids)}",
    )
    inventory_ids = itertools.count(1)
    inventory = ConsentScanInventory(
        tmp_path / "inventory" / "scan-inventory.sqlite3",
        scanner,
        tracker_authority=preferences,
        clock=clock,
        id_factory=lambda prefix: f"{prefix}-{next(inventory_ids)}",
        token_factory=lambda: "lease-token-core-bridge-000001",
    )
    inventory.upsert_property(
        "tenant-a",
        "property-shop",
        [ORIGIN],
        [START_URL],
        expected_revision=0,
        idempotency_key="core-property",
    )
    inventory.put_schedule(
        "tenant-a",
        "core-schedule",
        "property-shop",
        interval_seconds=300,
        next_due_at=NOW,
        expected_revision=0,
        idempotency_key="core-schedule",
    )
    finding = _finding("core-bridge")
    scanner.outcomes.append(
        _report(
            "tenant-a",
            "property-shop",
            "core-bridge-run",
            (finding,),
        )
    )
    inventory.enqueue_due("tenant-a")
    claim = inventory.claim_due("tenant-a", "core-worker")["items"][0]
    completed = inventory.run_claim(
        "tenant-a",
        claim["job_id"],
        "core-worker",
        claim["lease_token"],
    )
    report_id = completed["report"]["report_id"]
    inventory.review_tracker(
        "tenant-a",
        "property-shop",
        finding.tracker_key,
        classification="analytics",
        registry_action="approved",
        tracker_id="tracker-core-bridge",
        vendor_id="vendor-core",
        purpose_ids=["analytics"],
        reviewer_sha256=DIGEST_A,
        second_reviewer_sha256=DIGEST_B,
        evidence_sha256=DIGEST_C,
        report_id=report_id,
        valid_until=NOW + 100,
        expected_version=0,
        idempotency_key="core-review",
    )
    bridged = inventory.bridge_report(
        "tenant-a",
        report_id,
        idempotency_key="core-bridge",
    )
    assert bridged["registered_count"] == bridged["admitted_count"] == 1
    trackers = preferences.list_trackers("tenant-a")["trackers"]
    assert trackers[0]["tracker_id"] == "tracker-core-bridge"
    observations = preferences.list_scan_observations("tenant-a", report_id)
    assert observations["observations"][0]["tracker_id"] == "tracker-core-bridge"
    assert observations["observations"][0]["evidence_sha256"] == (finding.evidence_sha256)


def test_retention_and_audit_are_explicit_bounded_and_preserve_evidence(
    environment: Environment,
) -> None:
    _seed(environment, max_attempts=1)
    completed = _complete_report(
        environment,
        _report("tenant-a", "property-shop", "retention-run"),
    )
    report_id = completed["report"]["report_id"]
    environment.clock.value += 100
    due = environment.inventory.retention_due(
        "tenant-a",
        before=environment.clock.value,
        limit=1,
    )
    assert due["reports"][0]["report_id"] == report_id
    assert due["reports_deleted"] is False
    purged = environment.inventory.purge_operational_data(
        "tenant-a",
        before=environment.clock.value,
        limit=1,
    )
    assert purged["reports_deleted"] == 1
    assert purged["classifications_deleted"] == 0
    assert purged["audit_events_deleted"] == 0
    with pytest.raises(ConsentScanNotFound):
        environment.inventory.get_report("tenant-a", report_id)
    audit = environment.inventory.list_audit("tenant-a", limit=1)
    assert len(audit["events"]) == 1
    assert audit["truncated"] is True


def test_report_integrity_rejects_non_unknown_or_tampered_scanner_results(
    environment: Environment,
) -> None:
    _seed(environment, max_attempts=1)
    bad = _report(
        "tenant-a",
        "property-shop",
        "classified-by-scanner",
        (_finding("bad", classification="analytics"),),
    )
    environment.scanner.outcomes.append(bad)
    claim = _enqueue_claim(environment)
    result = environment.inventory.run_claim(
        "tenant-a",
        claim["job_id"],
        "worker-a",
        claim["lease_token"],
    )
    assert result["succeeded"] is False
    assert result["job"]["status"] == "dead_letter"
    assert result["job"]["last_error_code"] == "ConsentScanIntegrityError"
    assert environment.inventory.list_reports("tenant-a")["items"] == []

    environment.clock.value += 300
    environment.inventory.enqueue_due("tenant-a")
    tampered = _report("tenant-a", "property-shop", "tampered")
    tampered = ScanReport(**{**asdict(tampered), "report_sha256": "0" * 64})
    environment.scanner.outcomes.append(tampered)
    next_claim = environment.inventory.claim_due("tenant-a", "worker-a")["items"][0]
    second = environment.inventory.run_claim(
        "tenant-a",
        next_claim["job_id"],
        "worker-a",
        next_claim["lease_token"],
    )
    assert second["succeeded"] is False
    assert second["job"]["last_error_code"] == "ConsentScanIntegrityError"


def _scanner_settings(monkeypatch: pytest.MonkeyPatch, **values: int) -> None:
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"consent_preferences": {"enable": True,
                                         "scanner": {"enable": True, **values}}},
    )


def test_installation_scan_limits_default_and_cap_every_schedule(
    environment: Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maverick.consent_scanner import capped_scan_limits, default_scan_limits

    inventory = environment.inventory
    inventory.upsert_property("tenant-a", "property-shop", [ORIGIN], [START_URL],
                              expected_revision=0, idempotency_key="property-create")
    with pytest.raises(ConsentScanValidationError, match="interval_seconds is required"):
        inventory.put_schedule("tenant-a", "no-interval", "property-shop",
                               interval_seconds=None, next_due_at=NOW,
                               expected_revision=0, idempotency_key="schedule-none")
    _scanner_settings(monkeypatch, max_pages=50, max_depth=2, interval_seconds=3_600)
    assert default_scan_limits().max_pages == 50
    assert capped_scan_limits(ScanLimits(max_pages=10)).max_pages == 10
    defaulted = inventory.put_schedule("tenant-a", "defaulted", "property-shop",
                                       interval_seconds=None, next_due_at=NOW,
                                       expected_revision=0, idempotency_key="schedule-default")
    assert defaulted["interval_seconds"] == 3_600
    assert defaulted["limits"]["max_pages"] == 50 and defaulted["limits"]["max_depth"] == 2
    asked_more = inventory.put_schedule("tenant-a", "asked-more", "property-shop",
                                        interval_seconds=300, next_due_at=NOW,
                                        expected_revision=0, idempotency_key="schedule-more",
                                        limits=ScanLimits(max_pages=5_000, max_depth=9))
    assert asked_more["interval_seconds"] == 3_600
    assert asked_more["limits"]["max_pages"] == 50 and asked_more["limits"]["max_depth"] == 2


def test_installation_shortest_interval_holds_schedules_saved_before_it(
    environment: Environment, monkeypatch: pytest.MonkeyPatch
) -> None:
    _prop, schedule = _seed(environment)  # a 300-second schedule due now
    _scanner_settings(monkeypatch, interval_seconds=7_200)
    queued = environment.inventory.enqueue_due("tenant-a")
    assert len(queued["items"]) == 1
    after = environment.inventory.get_schedule("tenant-a", "schedule-daily")
    assert after["next_due_at"] == schedule["next_due_at"] + 7_200
