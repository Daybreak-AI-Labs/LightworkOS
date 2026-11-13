"""Durable provider-feed runtime coverage for third-party intelligence."""

from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import third_party_intelligence as intelligence
from maverick import third_party_intelligence_providers as providers
from maverick import third_party_intelligence_runtime as runtime

TENANT = "tenant-feed-a"
OTHER_TENANT = "tenant-feed-b"
RAW_SECRET = "provider-secret-never-persisted"
RAW_RECORD = "raw-provider-object-never-persisted"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Transport:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.observed_at = clock() - 10
        self.valid_until = clock() + 600
        self.version = "v1"
        self.error: Exception | None = None
        self.hook = None
        self.calls: list[dict[str, object]] = []

    def get_json(self, **kwargs):
        self.calls.append(kwargs)
        if self.hook is not None:
            hook, self.hook = self.hook, None
            hook()
        if self.error is not None:
            raise self.error
        query = dict(kwargs["query"])
        return {
            "schema": "lightwork.riskrecon-observation-page.v1",
            "tenant_id": query["tenant_id"],
            "provider": query["provider"],
            "source_id": query["source_id"],
            "source_revision": int(query["source_revision"]),
            "source_integrity_sha256": query["source_integrity_sha256"],
            "capability": query["capability"],
            "key_id": query["key_id"],
            "kind": query["kind"],
            "dataset_revision": f"dataset-{self.version}",
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
            "complete": True,
            "incomplete_reason_codes": [],
            "next_cursor": None,
            "records": [
                {
                    "record_id": RAW_RECORD,
                    "observation_sha256": digest(f"observation:{self.version}"),
                    "evidence_sha256": digest(f"evidence:{self.version}"),
                    "citation": {
                        "citation_id": f"citation-{self.version}",
                        "title": "Licensed provider evidence",
                        "uri": "https://api.riskrecon.com/evidence",
                        "pinpoint": f"observation-{self.version}",
                    },
                }
            ],
        }


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.clock = Clock()
        self.intelligence = intelligence.ThirdPartyIntelligenceStore(
            tmp_path / "intelligence.sqlite3",
            config_gate=lambda: None,
            clock=self.clock,
            token_factory=lambda: "i" * 43,
        )
        self.runtime = runtime.ThirdPartyFeedRuntimeStore(
            tmp_path / "feed-runtime.sqlite3",
            config_gate=lambda: None,
            clock=self.clock,
            token_factory=lambda: "r" * 43,
        )
        self.transport = Transport(self.clock)
        self.factory = providers.ThirdPartyProviderFactory(
            transport=self.transport,
            enabled_providers=["riskrecon"],
        )
        self.source = self.intelligence.enroll_source(
            TENANT,
            source_id="source-cyber",
            provider="riskrecon",
            kind="cyber_posture",
            provenance_uri="https://api.riskrecon.com/licensed-feed",
            credential_env="RISKRECON_API_TOKEN",
            license_ref="riskrecon-license-v1",
            rights_basis="Customer-approved licensed monitoring use.",
            purposes=["monitoring"],
            territories=["EU", "US"],
            retention_seconds=86_400,
            actor_ref="source-admin",
            idempotency_key="enroll-cyber-source",
        )
        self.source = self.intelligence.approve_source(
            TENANT,
            self.source.source_id,
            expected_revision=self.source.revision,
            approver_ref="source-counsel",
            approved=True,
            rationale="License, purpose, and territories independently reviewed.",
            idempotency_key="approve-cyber-source",
        )
        self.vendor = self.intelligence.upsert_vendor(
            TENANT,
            vendor_id="vendor-1",
            display_label="Pseudonymous Vendor 1",
            entity_identity_sha256=digest("vendor-1-identity"),
            encrypted_profile_ref="vault-cipher-vendor-1",
            profile_key_ref="kms-key-vendor-1",
            territories=["EU", "US"],
            service_categories=["cloud_service"],
            inherent_risk_level=1,
            criticality=1,
            data_access_level="limited",
            owner_ref="vendor-owner",
            actor_ref="vendor-admin",
            idempotency_key="create-vendor-1",
        )
        self.monitor = self.intelligence.create_monitor(
            TENANT,
            monitor_id="monitor-1",
            vendor_id=self.vendor.vendor_id,
            source_bindings={"cyber_posture": self.source.source_id},
            destination_ref="vendor-alert-sink",
            cadence_seconds=60,
            created_by="monitor-admin",
            idempotency_key="create-monitor-1",
        )

    @staticmethod
    def resolve_credential(
        tenant_id: str,
        credential_env: str,
        provider: str,
        source_id: str,
    ) -> providers.CredentialBinding:
        assert (tenant_id, credential_env, provider, source_id) == (
            TENANT,
            "RISKRECON_API_TOKEN",
            "riskrecon",
            "source-cyber",
        )
        return providers.CredentialBinding("riskrecon-key-v1", RAW_SECRET)

    def enqueue(self, *, maximum_attempts: int = 5, retention_seconds: int = 86_400):
        return self.runtime.enqueue_monitor(
            TENANT,
            self.monitor.monitor_id,
            self.intelligence,
            actor_ref="feed-admin",
            idempotency_key=f"enqueue-{self.intelligence.get_monitor(TENANT, self.monitor.monitor_id).revision}",
            maximum_attempts=maximum_attempts,
            retention_seconds=retention_seconds,
        )

    def run(self, *, backoff: float = 1.0):
        return runtime.run_feed_batch(
            self.runtime,
            self.intelligence,
            self.factory,
            self.resolve_credential,
            tenant_id=TENANT,
            worker_id="feed-worker-1",
            base_backoff_seconds=backoff,
            maximum_backoff_seconds=backoff,
        )


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_runtime_gate_is_exact_and_default_off(monkeypatch) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert runtime.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": True,
                "intelligence": {
                    "enable": True,
                    "providers": {"enabled": True},
                },
            }
        },
    )
    assert runtime.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": True,
                "intelligence": {
                    "enable": True,
                    "providers": {"enable": True},
                },
            }
        },
    )
    assert runtime.enabled() is True


def test_source_provenance_cannot_persist_query_credentials(harness: Harness) -> None:
    marker = "raw-query-credential-never-persisted"
    with pytest.raises(
        intelligence.ThirdPartyIntelligenceValidationError,
        match="query parameters",
    ):
        harness.intelligence.enroll_source(
            TENANT,
            source_id="source-query-secret",
            provider="riskrecon",
            kind="cyber_posture",
            provenance_uri=f"https://api.riskrecon.com/feed?token={marker}",
            credential_env="QUERY_SECRET_TOKEN",
            license_ref="license-query",
            rights_basis="Licensed monitoring use.",
            purposes=["monitoring"],
            territories=["EU", "US"],
            retention_seconds=86_400,
            actor_ref="source-admin",
            idempotency_key="source-query-secret",
        )
    with sqlite3.connect(harness.intelligence.path) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert marker.encode() not in harness.intelligence.path.read_bytes()


def test_baseline_collection_is_minimized_idempotent_and_tenant_bound(
    harness: Harness,
) -> None:
    queued = runtime.enqueue_due_monitors(
        harness.runtime,
        harness.intelligence,
        tenant_id=TENANT,
        actor_ref="feed-scheduler",
    )
    assert len(queued) == 1
    first = queued[0]
    assert (
        runtime.enqueue_due_monitors(
            harness.runtime,
            harness.intelligence,
            tenant_id=TENANT,
            actor_ref="feed-scheduler",
        )
        == queued
    )
    batch = harness.run()
    assert (batch.claimed, batch.completed, batch.retry_pending) == (1, 1, 0)
    receipt = harness.runtime.get_receipt(TENANT, batch.outcomes[0].receipt_id or "")
    assert receipt.changed is False
    assert receipt.alert_id is None
    assert receipt.monitor_revision_after == first.monitor_revision + 1
    assert receipt.source_receipts[0]["source_revision"] == harness.source.revision
    assert receipt.source_receipts[0]["credential_key_id_sha256"] == digest("riskrecon-key-v1")
    assert harness.intelligence.get_monitor(TENANT, "monitor-1").revision == 2
    with pytest.raises(runtime.ThirdPartyFeedRuntimeNotFound):
        harness.runtime.get_job(OTHER_TENANT, first.job_id)
    assert harness.runtime.verify_integrity(TENANT)["receipts"] == 1
    assert harness.intelligence.verify_integrity(TENANT).verified_records > 0

    with sqlite3.connect(harness.runtime.path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert not tables.intersection({"vendors", "risk_decisions", "monitors"})
    with sqlite3.connect(harness.intelligence.path) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    persisted = harness.runtime.path.read_bytes() + harness.intelligence.path.read_bytes()
    assert RAW_SECRET.encode() not in persisted
    assert RAW_RECORD.encode() not in persisted


def test_changed_observation_uses_existing_alert_and_outbox_authority(
    harness: Harness,
) -> None:
    harness.enqueue()
    assert harness.run().completed == 1
    harness.clock.advance(60)
    harness.transport.version = "v2"
    second = harness.enqueue()
    result = harness.run()
    receipt = harness.runtime.get_receipt(TENANT, result.outcomes[0].receipt_id or "")
    assert receipt.changed is True
    assert receipt.alert_id is not None
    assert second.monitor_revision == 2
    alert = harness.intelligence.get_monitoring_alert(TENANT, receipt.alert_id)
    assert alert.observation_sha256 == receipt.observation_sha256
    outbox = harness.intelligence.claim_outbox(
        TENANT,
        worker_id="alert-worker",
        lease_seconds=60,
    )
    assert len(outbox) == 1
    assert outbox[0].alert_id == receipt.alert_id


def test_source_revocation_during_network_io_revokes_job(harness: Harness) -> None:
    job = harness.enqueue()

    def revoke() -> None:
        source = harness.intelligence.get_source(TENANT, harness.source.source_id)
        harness.intelligence.revoke_source(
            TENANT,
            source.source_id,
            expected_revision=source.revision,
            actor_ref="source-counsel",
            rationale="Provider rights revoked during collection.",
            idempotency_key="revoke-during-provider-call",
        )

    harness.transport.hook = revoke
    result = harness.run()
    assert (result.revoked, result.completed) == (1, 0)
    assert result.outcomes[0].error_code == "authority_drift"
    assert harness.runtime.get_job(TENANT, job.job_id).state == "revoked"
    assert harness.intelligence.get_monitor(TENANT, "monitor-1").revision == 1
    assert harness.runtime.verify_integrity(TENANT)["receipts"] == 0


def test_snapshot_source_cas_is_rechecked_inside_commit_transaction(
    harness: Harness,
    monkeypatch,
) -> None:
    original_begin = harness.intelligence._begin
    intercepted = False

    def revoke_before_begin(connection) -> None:
        nonlocal intercepted
        if not intercepted:
            intercepted = True
            monkeypatch.setattr(harness.intelligence, "_begin", original_begin)
            source = harness.intelligence.get_source(TENANT, harness.source.source_id)
            harness.intelligence.revoke_source(
                TENANT,
                source.source_id,
                expected_revision=source.revision,
                actor_ref="source-counsel",
                rationale="Exercise the pre-commit authority race.",
                idempotency_key="revoke-before-snapshot-begin",
            )
        original_begin(connection)

    monkeypatch.setattr(harness.intelligence, "_begin", revoke_before_begin)
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied, match="remain"):
        harness.intelligence.record_source_snapshot(
            TENANT,
            harness.source.source_id,
            snapshot_id="snapshot-race",
            dataset_revision="dataset-race",
            observed_at=harness.clock() - 10,
            valid_until=harness.clock() + 600,
            completeness=1.0,
            record_count=1,
            evidence_sha256=digest("race-evidence"),
            citations=[
                {
                    "citation_id": "citation-race",
                    "title": "Licensed provider evidence",
                    "uri": "https://api.riskrecon.com/evidence",
                    "pinpoint": "race",
                }
            ],
            provenance_uri=harness.source.provenance_uri,
            actor_ref="snapshot-worker",
            idempotency_key="snapshot-race",
            expected_source_revision=harness.source.revision,
            expected_source_integrity_sha256=harness.source.integrity_sha256,
        )
    with pytest.raises(intelligence.ThirdPartyIntelligenceNotFound):
        harness.intelligence.get_source_snapshot(TENANT, "snapshot-race")


def test_retry_dead_letter_and_operator_replay(harness: Harness) -> None:
    job = harness.enqueue(maximum_attempts=2)
    harness.transport.error = TimeoutError("raw upstream details")
    first = harness.run()
    assert first.retry_pending == 1
    assert first.outcomes[0].error_code == "provider_unavailable"
    harness.clock.advance(1)
    second = harness.run()
    assert second.dead_lettered == 1
    dead = harness.runtime.get_job(TENANT, job.job_id)
    assert dead.state == "dead_letter"
    replay = harness.runtime.replay_dead_letter(
        TENANT,
        job.job_id,
        expected_revision=dead.revision,
        actor_ref="feed-operator",
        idempotency_key="replay-job-1",
    )
    assert replay.state == "pending"
    assert (
        harness.runtime.replay_dead_letter(
            TENANT,
            job.job_id,
            expected_revision=dead.revision,
            actor_ref="feed-operator",
            idempotency_key="replay-job-1",
        )
        == replay
    )
    harness.transport.error = None
    assert harness.run().completed == 1


def test_ambiguous_get_retries_but_definitive_protocol_failure_dead_letters(
    harness: Harness,
) -> None:
    first_job = harness.enqueue(maximum_attempts=3)
    harness.transport.error = providers.ThirdPartyProviderTransportError(
        "provider_transport_ambiguous",
        retryable=True,
        ambiguous=True,
    )
    first = harness.run()
    assert first.retry_pending == 1
    assert first.outcomes[0].error_code == "provider_ambiguous"
    assert harness.runtime.get_job(TENANT, first_job.job_id).state == "retry"

    harness.clock.advance(1)
    harness.transport.error = providers.ThirdPartyProviderProtocolError(
        "provider response contract drifted"
    )
    second = harness.run()
    assert second.dead_lettered == 1
    assert second.outcomes[0].error_code == "provider_protocol"
    assert harness.runtime.get_job(TENANT, first_job.job_id).state == "dead_letter"


def test_revoked_deployment_credential_is_terminal_without_provider_io(
    harness: Harness,
) -> None:
    job = harness.enqueue(maximum_attempts=5)

    def revoked(*_args):
        raise providers.ThirdPartyProviderCredentialError(
            "credential_revoked",
            revoked=True,
        )

    result = runtime.run_feed_batch(
        harness.runtime,
        harness.intelligence,
        harness.factory,
        revoked,
        tenant_id=TENANT,
        worker_id="feed-worker-1",
        base_backoff_seconds=1,
        maximum_backoff_seconds=1,
    )
    assert result.revoked == 1
    assert result.outcomes[0].error_code == "credential_revoked"
    assert harness.runtime.get_job(TENANT, job.job_id).state == "revoked"
    assert harness.transport.calls == []


def test_transient_deployment_secret_outage_retries_without_provider_io(
    harness: Harness,
) -> None:
    job = harness.enqueue(maximum_attempts=3)

    def unavailable(*_args):
        raise providers.ThirdPartyProviderCredentialError(
            "credential_resolution_failed",
            retryable=True,
        )

    result = runtime.run_feed_batch(
        harness.runtime,
        harness.intelligence,
        harness.factory,
        unavailable,
        tenant_id=TENANT,
        worker_id="feed-worker-1",
        base_backoff_seconds=1,
        maximum_backoff_seconds=1,
    )
    assert result.retry_pending == 1
    assert result.outcomes[0].error_code == "credential_unavailable"
    assert harness.runtime.get_job(TENANT, job.job_id).state == "retry"
    assert harness.transport.calls == []


def test_leases_exclude_other_workers_and_expired_lease_recovers(harness: Harness) -> None:
    harness.enqueue()
    first = harness.runtime.claim_jobs(
        TENANT,
        worker_id="worker-a",
        lease_seconds=5,
    )
    assert len(first) == 1
    assert (
        harness.runtime.claim_jobs(
            TENANT,
            worker_id="worker-b",
            lease_seconds=5,
        )
        == ()
    )
    harness.clock.advance(5)
    recovered = harness.runtime.claim_jobs(
        TENANT,
        worker_id="worker-b",
        lease_seconds=5,
    )
    assert len(recovered) == 1
    assert recovered[0].attempt == 2
    assert recovered[0].lease_token != first[0].lease_token
    with pytest.raises(runtime.ThirdPartyFeedRuntimeConflict, match="lease"):
        harness.runtime.fail_job(
            TENANT,
            first[0].job_id,
            lease_token=first[0].lease_token or "",
            error_code="stale_worker",
            backoff_seconds=1,
            actor_ref="worker-a",
        )


def test_expired_lease_on_the_last_attempt_dead_letters(harness: Harness) -> None:
    job = harness.enqueue(maximum_attempts=1)
    assert len(harness.runtime.claim_jobs(TENANT, worker_id="worker-a", lease_seconds=5)) == 1
    harness.clock.advance(5)
    assert harness.runtime.claim_jobs(TENANT, worker_id="worker-b", lease_seconds=5) == ()
    stored = harness.runtime.get_job(TENANT, job.job_id)
    assert (stored.state, stored.attempt, stored.last_error_code) == (
        "dead_letter",
        1,
        "attempts_exhausted",
    )


def test_concurrent_enqueue_and_claim_deduplicate_one_monitor_revision(
    harness: Harness,
) -> None:
    def enqueue(_index: int):
        return harness.runtime.enqueue_monitor(
            TENANT,
            harness.monitor.monitor_id,
            harness.intelligence,
            actor_ref="feed-admin",
            idempotency_key="concurrent-enqueue",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs = list(pool.map(enqueue, range(16)))
    assert len({job.job_id for job in jobs}) == 1
    assert len(harness.runtime.list_jobs(TENANT)) == 1

    def claim(index: int):
        return harness.runtime.claim_jobs(
            TENANT,
            worker_id=f"worker-{index}",
            lease_seconds=60,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(claim, range(8)))
    assert sum(len(items) for items in claims) == 1


def test_cross_store_acknowledgement_failure_recovers_idempotently(
    harness: Harness,
    monkeypatch,
) -> None:
    job = harness.enqueue()
    original = harness.runtime.complete_job
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated acknowledgement boundary")
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.runtime, "complete_job", fail_once)
    first = harness.run()
    assert first.retry_pending == 1
    assert harness.intelligence.get_monitor(TENANT, "monitor-1").revision == 2
    harness.clock.advance(1)
    second = harness.run()
    assert second.completed == 1
    assert harness.runtime.get_job(TENANT, job.job_id).state == "completed"
    assert harness.intelligence.get_monitor(TENANT, "monitor-1").revision == 2
    assert calls == 2


def test_retention_purge_and_index_tamper_detection(harness: Harness) -> None:
    job = harness.runtime.enqueue_monitor(
        TENANT,
        harness.monitor.monitor_id,
        harness.intelligence,
        actor_ref="feed-admin",
        idempotency_key="enqueue-retention",
        retention_seconds=60,
    )
    assert harness.run().completed == 1
    harness.clock.advance(60)
    assert harness.runtime.purge_expired(TENANT, cutoff=harness.clock()) == {
        "jobs": 1,
        "receipts": 1,
        "history": 3,
    }
    with pytest.raises(runtime.ThirdPartyFeedRuntimeNotFound):
        harness.runtime.get_job(TENANT, job.job_id)

    other = Harness(harness.runtime.path.parent / "tamper")
    pending = other.enqueue()
    with sqlite3.connect(other.runtime.path) as connection:
        connection.execute(
            "UPDATE feed_jobs SET state='completed' WHERE tenant_id=? AND job_id=?",
            (TENANT, pending.job_id),
        )
        connection.commit()
    with pytest.raises(runtime.ThirdPartyFeedRuntimeIntegrityError, match="binding"):
        other.runtime.verify_integrity(TENANT)
