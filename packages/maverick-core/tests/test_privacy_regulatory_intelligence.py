from __future__ import annotations

import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import privacy_regulatory_intelligence as intelligence


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(
    tmp_path: Path, clock: Clock
) -> intelligence.PrivacyRegulatoryIntelligenceStore:
    return intelligence.PrivacyRegulatoryIntelligenceStore(
        tmp_path / "privacy-regulatory.sqlite3",
        config_gate=lambda: None,
        clock=clock,
        token_factory=lambda: "s" * 43,
    )


def enroll_source(
    store: intelligence.PrivacyRegulatoryIntelligenceStore,
    *,
    tenant: str = "tenant-a",
    source_id: str = "primary-law",
    actor: str = "research-admin",
) -> intelligence.RegulatorySource:
    return store.enroll_source(
        tenant,
        source_id=source_id,
        name="Official privacy authority",
        license_ref="customer-license-2026",
        rights_basis="Customer confirms licensed internal research and sharing rights.",
        allowed_uses=["search", "research", "compare", "alerts", "reports", "share"],
        provenance_uri="https://authority.example/legal-corpus",
        jurisdictions=["EU", "US-CA"],
        authorities=["EU-DPA", "CA-AG"],
        document_types=["law", "regulation", "authority_guidance"],
        languages=["en", "fr"],
        retention_seconds=86_400,
        actor_ref=actor,
        idempotency_key=(
            "enroll-"
            + hashlib.sha256(f"{tenant}:{source_id}".encode()).hexdigest()[:32]
        ),
    )


def approve_source(
    store: intelligence.PrivacyRegulatoryIntelligenceStore,
    *,
    tenant: str = "tenant-a",
    source_id: str = "primary-law",
) -> intelligence.RegulatorySource:
    enrolled = enroll_source(store, tenant=tenant, source_id=source_id)
    return store.approve_source(
        tenant,
        source_id,
        expected_revision=enrolled.revision,
        approver_ref="privacy-counsel",
        rationale="License and provenance reviewed against the customer agreement.",
        approved=True,
        idempotency_key=(
            "approve-"
            + hashlib.sha256(f"{tenant}:{source_id}".encode()).hexdigest()[:32]
        ),
    )


def ingest_document(
    store: intelligence.PrivacyRegulatoryIntelligenceStore,
    *,
    tenant: str = "tenant-a",
    document_id: str = "eu-access-right",
    expected_version: int = 0,
    content: str = (
        "Controllers must respond to a valid access request within the applicable "
        "statutory period. The official authority describes limited extension grounds."
    ),
    jurisdiction: str = "EU",
    authority: str = "EU-DPA",
    publication_date: str = "2025-01-10",
    superseded_date: str | None = None,
    operation: str | None = None,
) -> intelligence.RegulatoryDocument:
    return store.ingest_document(
        tenant,
        document_id=document_id,
        source_id="primary-law",
        title="Access request response period",
        jurisdiction=jurisdiction,
        authority=authority,
        document_type="authority_guidance",
        language="en",
        publication_date=publication_date,
        effective_date="2025-02-01",
        superseded_date=superseded_date,
        citations=[
            {
                "citation_id": f"cite-{document_id}-v{expected_version + 1}",
                "title": "Official authority guidance",
                "uri": "https://authority.example/guidance/access",
                "pinpoint": "Section 4",
            }
        ],
        content=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        expected_latest_version=expected_version,
        actor_ref="research-editor",
        idempotency_key=operation or f"ingest-{document_id}-v{expected_version + 1}",
    )


def test_config_gate_is_exact_and_default_off(monkeypatch) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert intelligence.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "privacy_automation": {
                "enable": True,
                "regulatory_intelligence": {"enabled": True},
            }
        },
    )
    assert intelligence.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "privacy_automation": {
                "enable": True,
                "regulatory_intelligence": {"enable": True},
            }
        },
    )
    assert intelligence.enabled() is True


def test_constructor_requires_gate_and_creates_private_wal_database(tmp_path: Path) -> None:
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceConfigError):
        intelligence.PrivacyRegulatoryIntelligenceStore(
            tmp_path / "blocked.sqlite3",
            config_gate=lambda: (_ for _ in ()).throw(
                intelligence.PrivacyRegulatoryIntelligenceConfigError("disabled")
            ),
        )
    path = tmp_path / "private" / "authority.sqlite3"
    intelligence.PrivacyRegulatoryIntelligenceStore(path, config_gate=lambda: None)
    assert path.is_file()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_unicode_tenant_identity_is_canonical_and_strict_ids_are_isolated(store) -> None:
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    source = enroll_source(store, tenant=decomposed)
    assert source.tenant_id == canonical
    assert store.get_source(canonical, "primary-law") == source
    assert store.list_sources("Other Corp") == ()
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceValidationError):
        store.get_source(canonical, "primary law")


def test_source_rights_require_independent_human_approval_and_idempotency(store) -> None:
    source = enroll_source(store)
    replay = enroll_source(store)
    assert replay == source
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceConflict):
        store.enroll_source(
            "tenant-a",
            source_id="primary-law",
            name="Changed binding",
            license_ref="customer-license-2026",
            rights_basis="Licensed use.",
            allowed_uses=["research"],
            provenance_uri="https://authority.example/legal-corpus",
            jurisdictions=["EU"],
            authorities=["EU-DPA"],
            document_types=["law"],
            languages=["en"],
            retention_seconds=86_400,
            actor_ref="research-admin",
            idempotency_key="enroll-tenant-a-primary-law",
        )
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligencePermissionDenied):
        store.approve_source(
            "tenant-a",
            "primary-law",
            expected_revision=1,
            approver_ref="research-admin",
            rationale="Self approval must fail.",
            approved=True,
            idempotency_key="bad-self-approval",
        )
    content = "Access request timing is governed by primary law."
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligencePermissionDenied):
        store.ingest_document(
            "tenant-a",
            document_id="blocked-document",
            source_id="primary-law",
            title="Blocked",
            jurisdiction="EU",
            authority="EU-DPA",
            document_type="law",
            language="en",
            publication_date="2025-01-01",
            effective_date=None,
            superseded_date=None,
            citations=[
                {
                    "citation_id": "blocked-cite",
                    "title": "Primary law",
                    "uri": "https://authority.example/law",
                    "pinpoint": "Article 1",
                }
            ],
            content=content,
            content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            expected_latest_version=0,
            actor_ref="research-editor",
            idempotency_key="blocked-ingest",
        )
    approved = store.approve_source(
        "tenant-a",
        "primary-law",
        expected_revision=1,
        approver_ref="privacy-counsel",
        rationale="Rights and provenance accepted.",
        approved=True,
        idempotency_key="approve-primary-law",
    )
    assert approved.state == "active"
    assert approved.approved_by == "privacy-counsel"


def test_historical_search_survives_newer_publication(store) -> None:
    approve_source(store)
    ingest_document(store, publication_date="2025-01-10", superseded_date="2025-06-01")
    past = store.search("tenant-a", "access", as_of="2025-03-01")
    ingest_document(store, expected_version=1, publication_date="2025-05-01", content="New access request policy.")
    assert store.search("tenant-a", "access", as_of="2025-03-01") == past
    assert past[0].version == 1
    assert store.search("tenant-a", "access", as_of="2025-01-09") == ()
    # Search is publication-based: forthcoming effective dates are evidence
    # metadata, not permission to hide a publicly available publication.
    assert store.search("tenant-a", "access", as_of="2025-01-10")[0].version == 1
    assert store.search("tenant-a", "access", as_of="2025-05-01")[0].version == 2


def test_immutable_versioning_supersession_and_cas(store) -> None:
    approve_source(store)
    first = ingest_document(store)
    second = ingest_document(
        store,
        expected_version=1,
        content=(
            "Controllers must answer a valid access request within the statutory "
            "period. A documented extension is permitted only under specified grounds."
        ),
        operation="ingest-eu-access-v2",
    )
    assert (first.version, second.version, second.supersedes_version) == (1, 2, 1)
    assert store.get_document("tenant-a", first.document_id, 1) == first
    assert store.list_document_versions("tenant-a", first.document_id) == (first, second)
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceConflict):
        ingest_document(
            store,
            expected_version=1,
            content="Conflicting third version.",
            operation="stale-document-cas",
        )


def test_grounded_search_citations_abstention_and_jurisdiction_comparison(store) -> None:
    approve_source(store)
    ingest_document(store)
    california_content = (
        "A consumer may submit a verified access request. The business follows the "
        "response timing described by the California authority."
    )
    ingest_document(
        store,
        document_id="ca-access-right",
        content=california_content,
        jurisdiction="US-CA",
        authority="CA-AG",
        publication_date="2025-03-01",
    )
    hits = store.search(
        "tenant-a", "access request response", jurisdictions=["EU"], as_of="2026-01-01"
    )
    assert len(hits) == 1
    assert hits[0].citations[0].uri.startswith("https://authority.example/")
    answer = store.research(
        "tenant-a",
        "access request response",
        jurisdictions=["EU"],
        as_of="2026-01-01",
    )
    assert answer.status == "grounded"
    assert answer.citations and answer.evidence
    assert "not legal advice" in answer.disclaimer
    abstention = store.research(
        "tenant-a", "quantum biometric teleportation", as_of="2026-01-01"
    )
    assert abstention.abstained is True
    assert abstention.citations == ()
    assert "No legal conclusion" in abstention.answer
    comparison = store.compare_jurisdictions(
        "tenant-a",
        "access request",
        ["EU", "US-CA"],
        as_of="2026-01-01",
    )
    assert set(comparison.answers) == {"EU", "US-CA"}
    assert all(item.status == "grounded" for item in comparison.answers.values())


def test_source_revocation_removes_content_from_search_and_capability_use(store) -> None:
    source = approve_source(store)
    ingest_document(store)
    assert store.search("tenant-a", "access request", as_of="2026-01-01")
    revoked = store.revoke_source(
        "tenant-a",
        "primary-law",
        expected_revision=source.revision,
        actor_ref="privacy-counsel",
        reason="License terminated.",
        idempotency_key="revoke-primary-law",
    )
    assert revoked.state == "revoked"
    assert store.search("tenant-a", "access request", as_of="2026-01-01") == ()


def test_collections_enforce_acl_share_scope_and_revocation(store, clock) -> None:
    approve_source(store)
    document = ingest_document(store)
    collection = store.create_collection(
        "tenant-a",
        collection_id="access-research",
        title="Access research",
        description="Personalized EU research collection.",
        owner_ref="alice",
        jurisdictions=["EU"],
        idempotency_key="create-access-collection",
    )
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceNotFound):
        store.get_collection("tenant-a", collection.collection_id, principal_ref="bob")
    collection = store.grant_collection_access(
        "tenant-a",
        collection.collection_id,
        principal_ref="bob",
        role="viewer",
        expected_revision=collection.revision,
        actor_ref="alice",
        idempotency_key="grant-bob-view",
    )
    assert store.get_collection(
        "tenant-a", collection.collection_id, principal_ref="bob"
    ).acl["bob"] == "viewer"
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceNotFound):
        store.add_collection_document(
            "tenant-a",
            collection.collection_id,
            document_id=document.document_id,
            version=document.version,
            expected_revision=collection.revision,
            actor_ref="bob",
            idempotency_key="viewer-cannot-edit",
        )
    collection = store.add_collection_document(
        "tenant-a",
        collection.collection_id,
        document_id=document.document_id,
        version=document.version,
        expected_revision=collection.revision,
        actor_ref="alice",
        idempotency_key="add-document",
    )
    share = store.create_share(
        "tenant-a",
        collection.collection_id,
        share_id="share-access-1",
        scopes=["view"],
        expires_at=clock.value + 3_600,
        actor_ref="alice",
        idempotency_key="create-share-access-1",
    )
    assert share.token is not None
    assert store.redeem_share(share.token).collection_id == collection.collection_id
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceNotFound):
        store.redeem_share(share.token, scope="export")
    store.revoke_share("tenant-a", share.share_id, actor_ref="alice")
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceNotFound):
        store.redeem_share(share.token)


def test_saved_query_tracker_alert_outbox_retry_ack_and_revocation(store, clock) -> None:
    approve_source(store)
    document = ingest_document(store)
    subscription = store.create_jurisdiction_tracker(
        "tenant-a",
        subscription_id="eu-access-alerts",
        query="access request",
        jurisdictions=["EU"],
        principal_ref="alice",
        destination_ref="privacy-alert-sink",
        cadence_seconds=300,
        idempotency_key="save-access-alerts",
    )
    assert store.due_subscriptions("tenant-a") == (subscription,)
    advanced = store.advance_subscription(
        "tenant-a",
        subscription.subscription_id,
        expected_revision=subscription.revision,
        actor_ref="scheduler",
    )
    assert advanced.next_run_at == clock.value + 300
    alerts = store.generate_alerts(
        "tenant-a", document.document_id, document.version, actor_ref="scheduler"
    )
    assert len(alerts) == 1
    assert store.generate_alerts(
        "tenant-a", document.document_id, document.version, actor_ref="scheduler"
    ) == alerts
    delivery = store.claim_deliveries(
        "tenant-a", worker_id="delivery-worker", lease_seconds=30
    )[0]
    failed = store.fail_delivery(
        "tenant-a",
        delivery.delivery_id,
        lease_token=delivery.lease_token or "",
        error_code="temporary_outage",
        backoff_seconds=10,
    )
    assert failed.state == "pending" and failed.attempt == 1
    assert store.claim_deliveries("tenant-a", worker_id="delivery-worker") == ()
    clock.advance(10)
    retried = store.claim_deliveries(
        "tenant-a", worker_id="delivery-worker", lease_seconds=30
    )[0]
    delivered = store.acknowledge_delivery(
        "tenant-a", retried.delivery_id, lease_token=retried.lease_token or ""
    )
    assert delivered.state == "delivered"
    revoked = store.revoke_subscription(
        "tenant-a",
        subscription.subscription_id,
        expected_revision=advanced.revision,
        actor_ref="alice",
    )
    assert revoked.state == "revoked"


def test_report_export_is_evidence_backed_bounded_and_idempotent(store) -> None:
    approve_source(store)
    ingest_document(store)
    report = store.export_report(
        "tenant-a",
        report_id="eu-access-report",
        query="access request",
        jurisdictions=["EU"],
        actor_ref="alice",
        idempotency_key="export-access-report",
        retention_seconds=86_400,
    )
    assert report.status == "grounded"
    assert report.evidence and report.citations
    exported = report.export()
    assert exported["schema"] == intelligence.REPORT_SCHEMA
    assert exported["integrity_sha256"] == report.integrity_sha256
    replay = store.export_report(
        "tenant-a",
        report_id="eu-access-report",
        query="access request",
        jurisdictions=["EU"],
        actor_ref="alice",
        idempotency_key="export-access-report",
        retention_seconds=86_400,
    )
    assert replay == report


def test_bounded_retention_purges_expired_content_but_preserves_audit(store, clock) -> None:
    approve_source(store)
    document = ingest_document(store)
    report = store.export_report(
        "tenant-a",
        report_id="retained-report",
        query="access request",
        jurisdictions=["EU"],
        actor_ref="alice",
        idempotency_key="retained-report-export",
        retention_seconds=86_400,
    )
    clock.advance(86_401)
    counts = store.purge_expired("tenant-a", actor_ref="retention-worker")
    assert counts["documents"] == 1
    assert counts["reports"] == 1
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceNotFound):
        store.get_document("tenant-a", document.document_id)
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceNotFound):
        store.get_report("tenant-a", report.report_id)
    assert store.verify_integrity("tenant-a").audit_events > 0


def test_integrity_detects_payload_content_and_audit_tampering(store) -> None:
    approve_source(store)
    document = ingest_document(store)
    original_content = (
        "Controllers must respond to a valid access request within the applicable "
        "statutory period. The official authority describes limited extension grounds."
    )
    baseline = store.verify_integrity("tenant-a")
    assert baseline.verified_records >= 2
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE documents SET content_text='tampered' "
            "WHERE tenant_id=? AND document_id=? AND version=?",
            ("tenant-a", document.document_id, document.version),
        )
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceIntegrityError):
        store.get_document("tenant-a", document.document_id, document.version)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE documents SET content_text=? "
            "WHERE tenant_id=? AND document_id=? AND version=?",
            (original_content, "tenant-a", document.document_id, document.version),
        )
        connection.execute(
            "UPDATE audit_events SET payload_json='{}' "
            "WHERE tenant_id='tenant-a' AND sequence=1"
        )
    with pytest.raises(intelligence.PrivacyRegulatoryIntelligenceIntegrityError):
        store.verify_integrity("tenant-a")


def test_concurrent_collection_cas_allows_exactly_one_writer(store) -> None:
    collection = store.create_collection(
        "tenant-a",
        collection_id="concurrent-collection",
        title="Concurrent collection",
        description="CAS test.",
        owner_ref="alice",
        jurisdictions=["EU"],
        idempotency_key="create-concurrent-collection",
    )

    def grant(index: int) -> str:
        try:
            store.grant_collection_access(
                "tenant-a",
                collection.collection_id,
                principal_ref=f"viewer-{index}",
                role="viewer",
                expected_revision=collection.revision,
                actor_ref="alice",
                idempotency_key=f"concurrent-grant-{index}",
            )
        except intelligence.PrivacyRegulatoryIntelligenceConflict:
            return "conflict"
        return "updated"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(grant, [1, 2]))
    assert sorted(outcomes) == ["conflict", "updated"]
    assert store.verify_integrity("tenant-a").audit_events == 2
