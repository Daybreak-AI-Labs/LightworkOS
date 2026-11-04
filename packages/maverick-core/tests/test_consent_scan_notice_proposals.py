from __future__ import annotations

import copy
import gc
import hashlib
import inspect
import itertools
import json
import sqlite3
from dataclasses import asdict, replace

import pytest
from maverick import consent_scan_notice_proposals as proposal_module
from maverick.consent_scan_inventory import ConsentScanInventory
from maverick.consent_scan_notice_proposals import (
    ConsentScanInventorySnapshotAdapter,
    ConsentScanNoticeProposalStore,
    IncompleteScanApproval,
    InventoryNoticeProposalBinding,
    NoticeProposalConflict,
    NoticeProposalDisabled,
    NoticeProposalIntegrityError,
    NoticeProposalNotFound,
    ReviewedScanDiscovery,
    ReviewedScanSnapshot,
    notice_proposals_enabled,
)
from maverick.consent_scanner import SCAN_REPORT_SCHEMA, ScanFinding, ScanLimits, ScanReport

D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64
D6 = "6" * 64
D7 = "7" * 64
D8 = "8" * 64


class Context:
    def __init__(self) -> None:
        self.now = 1_000.0
        self.actor = "maker-1"
        self.snapshot = self.make_snapshot()

    def make_snapshot(
        self,
        *,
        tenant: str = "tenant-a",
        property_id: str = "web-property",
        report_id: str = "report-1",
        report_sha256: str = D1,
        inventory_revision: int = 1,
        discoveries: tuple[ReviewedScanDiscovery, ...] | None = None,
        complete: bool = True,
        truncated: bool = False,
        valid_until: float = 2_000.0,
        revoked: bool = False,
    ) -> ReviewedScanSnapshot:
        items = discoveries or (
            ReviewedScanDiscovery(
                tracker_key=D4,
                classification="analytics",
                kind="cookie",
                first_party=False,
                resource_type="script",
                review_version=2,
                review_sha256=D5,
                evidence_sha256=D6,
                valid_until=valid_until,
            ),
            ReviewedScanDiscovery(
                tracker_key=D7,
                classification="not_a_tracker",
                kind="network",
                first_party=True,
                resource_type="image",
                review_version=1,
                review_sha256=D8,
                evidence_sha256=D2,
                valid_until=valid_until,
            ),
        )
        classification_sha = ConsentScanNoticeProposalStore.classification_sha256(items)
        return ReviewedScanSnapshot(
            tenant_id=tenant,
            property_id=property_id,
            report_id=report_id,
            report_sha256=report_sha256,
            property_revision=3,
            property_sha256=D2,
            inventory_revision=inventory_revision,
            classification_sha256=classification_sha,
            completed_at=900.0,
            valid_until=valid_until,
            complete=complete,
            truncated=truncated,
            revoked=revoked,
            discoveries=items,
            scanner_report_sha256=D3,
            inventory_sha256=D8,
        )


ADAPTER_NOW = 1_800_000_000.0
ADAPTER_ORIGIN = "https://shop.example.test"
REVIEWER_A = hashlib.sha256(b"reviewer-a").hexdigest()
REVIEWER_B = hashlib.sha256(b"reviewer-b").hexdigest()
REVIEW_EVIDENCE = hashlib.sha256(b"review-evidence").hexdigest()


def _json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


def _inventory_finding(label: str) -> ScanFinding:
    tracker_key = hashlib.sha256(f"tracker:{label}".encode()).hexdigest()
    return ScanFinding(
        finding_id=f"CSF-{tracker_key[:24]}",
        kind="network",
        tracker_key=tracker_key,
        source_page_sha256=hashlib.sha256(f"page:{label}".encode()).hexdigest(),
        host=f"{label}.vendor.test",
        path_sha256=hashlib.sha256(b"/collect?token=secret").hexdigest(),
        resource_type="fetch",
        name_sha256=None,
        first_party=False,
        classification="unknown",
        evidence_sha256=hashlib.sha256(f"finding-evidence:{label}".encode()).hexdigest(),
    )


def _inventory_report(
    tenant: str,
    property_id: str,
    findings: tuple[ScanFinding, ...],
    *,
    truncated: bool = False,
) -> ScanReport:
    body = {
        "schema": SCAN_REPORT_SCHEMA,
        "run_id": "CSR-proposal-adapter",
        "tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(),
        "property_id": property_id,
        "started_at": ADAPTER_NOW - 1,
        "completed_at": ADAPTER_NOW,
        "pages_attempted": 1,
        "pages_captured": 1,
        "page_sha256": [hashlib.sha256(b"adapter-page").hexdigest()],
        "findings": [asdict(item) for item in findings],
        "errors": [],
        "truncated": truncated,
        "complete": not truncated,
    }
    return ScanReport(
        schema=SCAN_REPORT_SCHEMA,
        run_id=body["run_id"],
        tenant_sha256=body["tenant_sha256"],
        property_id=property_id,
        started_at=body["started_at"],
        completed_at=body["completed_at"],
        pages_attempted=1,
        pages_captured=1,
        page_sha256=tuple(body["page_sha256"]),
        findings=findings,
        errors=(),
        truncated=truncated,
        complete=not truncated,
        report_sha256=_json_sha256(body),
    )


class _InventoryScanner:
    def __init__(self, report: ScanReport) -> None:
        self.report = report

    def scan(
        self,
        _tenant_id: str,
        _property_id: str,
        _start_urls,
        _allowed_origins,
        *,
        limits: ScanLimits | None = None,
        auth_secret_ref: str | None = None,
        authenticated_scan_consent: bool = False,
    ) -> ScanReport:
        del limits, auth_secret_ref, authenticated_scan_consent
        return self.report


def _seed_adapter_inventory(
    tmp_path,
    *,
    tenant: str = "Caf\u00e9",
    truncated: bool = False,
    second_finding_unreviewed: bool = False,
):
    property_id = "property-shop"
    primary = _inventory_finding("analytics")
    findings = (
        (primary, _inventory_finding("unreviewed")) if second_finding_unreviewed else (primary,)
    )
    scanner = _InventoryScanner(
        _inventory_report(tenant, property_id, findings, truncated=truncated)
    )
    identifiers = itertools.count(1)
    tokens = itertools.count(1)
    inventory = ConsentScanInventory(
        tmp_path / "inventory" / "scan.sqlite3",
        scanner,
        clock=lambda: ADAPTER_NOW,
        id_factory=lambda prefix: f"{prefix}-{next(identifiers)}",
        token_factory=lambda: f"lease-token-{next(tokens):012d}",
        gate=lambda: None,
    )
    property_result = inventory.upsert_property(
        tenant,
        property_id,
        [ADAPTER_ORIGIN],
        [f"{ADAPTER_ORIGIN}/"],
        expected_revision=0,
        idempotency_key="property",
    )
    inventory.put_schedule(
        tenant,
        "daily",
        property_id,
        interval_seconds=300,
        next_due_at=ADAPTER_NOW,
        expected_revision=0,
        idempotency_key="schedule",
    )
    inventory.enqueue_due(tenant)
    claim = inventory.claim_due(tenant, "worker")["items"][0]
    completed = inventory.run_claim(tenant, claim["job_id"], "worker", claim["lease_token"])
    report = completed["report"]
    inventory.review_tracker(
        tenant,
        property_id,
        primary.tracker_key,
        classification="analytics",
        registry_action="approved",
        reviewer_sha256=REVIEWER_A,
        second_reviewer_sha256=REVIEWER_B,
        evidence_sha256=REVIEW_EVIDENCE,
        report_id=report["report_id"],
        valid_until=ADAPTER_NOW + 1_000,
        expected_version=0,
        idempotency_key="review",
        tracker_id="tracker-analytics",
        vendor_id="vendor-analytics",
        purpose_ids=("analytics",),
    )
    binding = InventoryNoticeProposalBinding(
        tenant_id=tenant,
        property_id=property_id,
        report_id=report["report_id"],
        inventory_revision=7,
    )
    return {
        "inventory": inventory,
        "property": property_result,
        "report": report,
        "primary": primary,
        "binding": binding,
    }


@pytest.fixture
def authority(tmp_path):
    context = Context()
    counters: dict[str, int] = {}

    def new_id(prefix: str) -> str:
        counters[prefix] = counters.get(prefix, 0) + 1
        return f"{prefix}-{counters[prefix]}"

    store = ConsentScanNoticeProposalStore(
        tmp_path / "notice-proposals.sqlite3",
        snapshot_resolver=lambda: context.snapshot,
        actor_resolver=lambda: context.actor,
        signing_key_resolver=lambda _tenant: b"k" * 32,
        clock=lambda: context.now,
        id_factory=new_id,
        gate=lambda: None,
        approval_ttl_seconds=300,
    )
    return context, store


def _approve_and_accept(context, store, proposal, suffix: str):
    context.actor = f"reviewer-{suffix}"
    approval = store.approve(
        proposal["proposal_id"], expected_revision=1, idempotency_key=f"approve-{suffix}"
    )
    context.actor = f"acceptor-{suffix}"
    accepted = store.accept_local(
        proposal["proposal_id"],
        expected_revision=2,
        expected_head_revision=proposal["head_revision"],
        idempotency_key=f"accept-{suffix}",
    )
    return approval, accepted


def test_exact_default_off_gate(monkeypatch) -> None:
    import maverick.config as config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert notice_proposals_enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "scanner": {"enable": True, "notice_proposals": {"enable": True}},
            }
        },
    )
    assert notice_proposals_enabled() is True
    for bad in (
        {
            "consent_preferences": {
                "scanner": {"enable": True, "notice_proposals": {"enable": True}}
            }
        },
        {
            "consent_preferences": {
                "enable": True,
                "scanner": {"notice_proposals": {"enable": True}},
            }
        },
        {
            "consent_preferences": {
                "enable": True,
                "scanner": {"enable": True, "notice_proposals": True},
            }
        },
    ):
        monkeypatch.setattr(config, "load_config", lambda bad=bad: bad)
        assert notice_proposals_enabled() is False


def test_default_gate_is_enforced_at_operation_time(tmp_path, monkeypatch) -> None:
    import maverick.config as config

    context = Context()
    # Accept the keyword form load_global_config uses (include_tenant=False).
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: [])
    monkeypatch.setattr(config, "load_config", dict)
    store = ConsentScanNoticeProposalStore(
        tmp_path / "disabled.sqlite3",
        snapshot_resolver=lambda: context.snapshot,
        actor_resolver=lambda: context.actor,
        signing_key_resolver=lambda _tenant: b"k" * 32,
    )
    with pytest.raises(NoticeProposalDisabled):
        store.propose(expected_revision=0, idempotency_key="disabled")


def test_public_surface_has_no_tenant_content_or_publication_target(authority) -> None:
    _context, store = authority
    parameters = inspect.signature(store.propose).parameters
    assert set(parameters) == {"expected_revision", "idempotency_key"}
    parameters = inspect.signature(store.accept_local).parameters
    assert "tenant_id" not in parameters
    assert "content" not in parameters
    assert "url" not in parameters
    assert "target" not in parameters
    assert store.product_boundaries() == {
        "local_reviewed_scan_proposals": True,
        "structured_metadata_only": True,
        "independent_approval": True,
        "legal_prose_generation": False,
        "automatic_publication": False,
        "network_io": False,
        "provider_write": False,
        "site_mutation": False,
        "notice_publication": False,
        "live_acceptance_verified": False,
    }


def test_deterministic_safe_metadata_and_exact_pins(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    assert proposal["action"] == "desired"
    assert proposal["source_pins"] == {
        "report_id": "report-1",
        "report_sha256": D1,
        "scanner_report_sha256": D3,
        "property_revision": 3,
        "property_sha256": D2,
        "inventory_revision": 1,
        "inventory_sha256": D8,
        "classification_sha256": context.snapshot.classification_sha256,
        "completed_at": 900.0,
        "valid_until": 2_000.0,
    }
    metadata = proposal["metadata"]
    assert metadata["disclosure_count"] == 1
    assert metadata["classification_counts"]["analytics"] == 1
    assert metadata["first_party_count"] == 0
    assert metadata["third_party_count"] == 1
    assert metadata["legal_prose_included"] is False
    assert metadata["disclosures"] == [
        {
            "tracker_key": D4,
            "classification": "analytics",
            "kind": "cookie",
            "first_party": False,
            "resource_type": "script",
            "review_version": 2,
            "review_sha256": D5,
            "evidence_sha256": D6,
            "finding_evidence_sha256": D6,
        }
    ]
    encoded = json.dumps(proposal, sort_keys=True)
    assert "http" not in encoded
    assert "query" not in encoded
    assert "cookie policy text" not in encoded
    assert "secret" not in encoded


def test_incomplete_scan_is_labeled_not_misrepresented(authority) -> None:
    context, store = authority
    context.snapshot = context.make_snapshot(complete=False, truncated=True)
    proposal = store.propose(expected_revision=0, idempotency_key="incomplete")
    assert proposal["metadata"]["scan_complete"] is False
    assert proposal["metadata"]["scan_truncated"] is True


def test_self_approval_is_rejected_and_local_acceptance_never_publishes(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    with pytest.raises(NoticeProposalConflict, match="creator"):
        store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="self")
    approval, accepted = _approve_and_accept(context, store, proposal, "one")
    assert approval["actor_sha256"] != proposal["created_by_sha256"]
    assert accepted == {
        "proposal_id": proposal["proposal_id"],
        "action": "desired",
        "state": "locally_accepted",
        "proposal_revision": 3,
        "head_revision": 2,
        "metadata_sha256": proposal["metadata_sha256"],
        "local_baseline_only": True,
        "published": False,
        "site_mutated": False,
    }


def test_creator_approver_and_acceptor_must_be_separate(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.actor = "reviewer"
    store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="approve")
    with pytest.raises(NoticeProposalConflict, match="approver"):
        store.accept_local(
            proposal["proposal_id"],
            expected_revision=2,
            expected_head_revision=1,
            idempotency_key="approver-accept",
        )
    context.actor = "maker-1"
    with pytest.raises(NoticeProposalConflict, match="creator"):
        store.accept_local(
            proposal["proposal_id"],
            expected_revision=2,
            expected_head_revision=1,
            idempotency_key="creator-accept",
        )
    context.actor = "acceptor"
    assert (
        store.accept_local(
            proposal["proposal_id"],
            expected_revision=2,
            expected_head_revision=1,
            idempotency_key="independent-accept",
        )["state"]
        == "locally_accepted"
    )


def test_idempotency_and_cas_are_exact(authority) -> None:
    context, store = authority
    first = store.propose(expected_revision=0, idempotency_key="same")
    assert store.propose(expected_revision=0, idempotency_key="same") == first
    with pytest.raises(NoticeProposalConflict, match="rebound"):
        store.propose(expected_revision=1, idempotency_key="same")
    with pytest.raises(NoticeProposalConflict, match="revision"):
        store.propose(expected_revision=0, idempotency_key="stale")
    context.actor = "reviewer"
    approved = store.approve(first["proposal_id"], expected_revision=1, idempotency_key="approval")
    assert (
        store.approve(first["proposal_id"], expected_revision=1, idempotency_key="approval")
        == approved
    )
    with pytest.raises(NoticeProposalConflict, match="rebound"):
        store.approve(first["proposal_id"], expected_revision=2, idempotency_key="approval")


def test_stale_report_review_digest_expiry_and_revocation_fail_closed(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.actor = "reviewer"
    context.snapshot = replace(context.snapshot, inventory_revision=2)
    with pytest.raises(NoticeProposalConflict, match="source pins"):
        store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="stale")

    context.snapshot = context.make_snapshot()
    context.snapshot = replace(context.snapshot, classification_sha256=D3)
    with pytest.raises(NoticeProposalIntegrityError, match="classification digest"):
        store.propose(expected_revision=1, idempotency_key="bad-digest")

    context.snapshot = context.make_snapshot(valid_until=context.now)
    with pytest.raises(NoticeProposalConflict, match="expired"):
        store.propose(expected_revision=1, idempotency_key="expired")

    context.snapshot = context.make_snapshot(revoked=True)
    with pytest.raises(NoticeProposalConflict, match="revoked"):
        store.propose(expected_revision=1, idempotency_key="revoked")

    discovery = replace(context.make_snapshot().discoveries[0], revoked=True)
    context.snapshot = context.make_snapshot(discoveries=(discovery,))
    with pytest.raises(NoticeProposalConflict, match="revoked"):
        store.propose(expected_revision=1, idempotency_key="review-revoked")


def test_approval_expiry_and_revoke_block_acceptance(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.actor = "reviewer"
    store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="approve")
    context.now = 1_301.0
    with pytest.raises(NoticeProposalConflict, match="approval window expired"):
        store.accept_local(
            proposal["proposal_id"],
            expected_revision=2,
            expected_head_revision=1,
            idempotency_key="late",
        )

    context.now = 1_000.0
    second_context = Context()
    context.snapshot = second_context.snapshot
    revoked = store.revoke_approval(
        proposal["proposal_id"],
        expected_proposal_revision=2,
        expected_approval_revision=1,
        idempotency_key="revoke",
    )
    assert revoked["revoked_at"] == 1_000.0
    with pytest.raises(NoticeProposalConflict, match="not approved"):
        store.accept_local(
            proposal["proposal_id"],
            expected_revision=3,
            expected_head_revision=1,
            idempotency_key="revoked-accept",
        )


@pytest.mark.parametrize("source_state", ["expired", "revoked"])
def test_source_expiry_or_revocation_after_approval_blocks_acceptance(
    authority, source_state: str
) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.actor = "reviewer"
    store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="approve")
    context.actor = "acceptor"
    if source_state == "expired":
        context.now = 2_001.0
    else:
        context.snapshot = replace(context.snapshot, revoked=True)
    with pytest.raises(NoticeProposalConflict, match="expired|revoked"):
        store.accept_local(
            proposal["proposal_id"],
            expected_revision=2,
            expected_head_revision=1,
            idempotency_key=f"source-{source_state}",
        )


def test_desired_no_change_and_reconcile_lifecycle(authority) -> None:
    context, store = authority
    desired = store.propose(expected_revision=0, idempotency_key="desired")
    _approve_and_accept(context, store, desired, "desired")

    context.actor = "maker-2"
    no_change = store.propose(expected_revision=2, idempotency_key="no-change")
    assert no_change["version"] == 2
    assert no_change["action"] == "no_change"
    _approve_and_accept(context, store, no_change, "no-change")

    changed = replace(
        context.snapshot.discoveries[0],
        classification="advertising",
        review_version=3,
        review_sha256=D3,
    )
    context.snapshot = context.make_snapshot(
        report_id="report-2",
        report_sha256=D3,
        inventory_revision=2,
        discoveries=(changed,),
    )
    context.actor = "maker-3"
    reconcile = store.propose(expected_revision=4, idempotency_key="reconcile")
    assert reconcile["version"] == 3
    assert reconcile["action"] == "reconcile"
    assert reconcile["metadata"]["classification_counts"]["advertising"] == 1


def test_rollback_is_a_new_approved_local_proposal(authority) -> None:
    context, store = authority
    original = store.propose(expected_revision=0, idempotency_key="original")
    _approve_and_accept(context, store, original, "original")
    changed = replace(
        context.snapshot.discoveries[0],
        classification="advertising",
        review_version=3,
        review_sha256=D3,
    )
    context.snapshot = context.make_snapshot(
        report_id="report-2",
        report_sha256=D3,
        inventory_revision=2,
        discoveries=(changed,),
    )
    context.actor = "maker-2"
    reconcile = store.propose(expected_revision=2, idempotency_key="reconcile")
    _approve_and_accept(context, store, reconcile, "reconcile")
    context.actor = "maker-3"
    rollback = store.propose_rollback(
        original["proposal_id"], expected_revision=4, idempotency_key="rollback"
    )
    assert rollback["version"] == 3
    assert rollback["action"] == "rollback"
    assert rollback["metadata_sha256"] == original["metadata_sha256"]
    assert rollback["rollback_target_proposal_id"] == original["proposal_id"]
    replay = store.propose_rollback(
        original["proposal_id"], expected_revision=4, idempotency_key="rollback"
    )
    assert replay == rollback
    _approval, accepted = _approve_and_accept(context, store, rollback, "rollback")
    assert accepted["published"] is False
    assert accepted["metadata_sha256"] == original["metadata_sha256"]


def test_rollback_approval_revalidates_current_source_pins(authority) -> None:
    context, store = authority
    original = store.propose(expected_revision=0, idempotency_key="original")
    _approve_and_accept(context, store, original, "original")
    changed = replace(
        context.snapshot.discoveries[0],
        classification="advertising",
        review_version=3,
        review_sha256=D3,
    )
    context.snapshot = context.make_snapshot(
        report_id="report-2",
        report_sha256=D3,
        inventory_revision=2,
        discoveries=(changed,),
    )
    context.actor = "maker-2"
    reconcile = store.propose(expected_revision=2, idempotency_key="reconcile")
    _approve_and_accept(context, store, reconcile, "reconcile")
    context.actor = "maker-3"
    rollback = store.propose_rollback(
        original["proposal_id"], expected_revision=4, idempotency_key="rollback"
    )
    context.snapshot = replace(context.snapshot, inventory_revision=3)
    context.actor = "rollback-reviewer"
    with pytest.raises(NoticeProposalConflict, match="source pins"):
        store.approve(
            rollback["proposal_id"],
            expected_revision=1,
            idempotency_key="stale-rollback-approval",
        )


def test_signed_export_is_metadata_only_and_detects_tampering(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.actor = "reviewer"
    store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="approve")
    exported = store.export_signed_metadata(proposal["proposal_id"], idempotency_key="export")
    assert store.verify_export(exported) is True
    encoded = json.dumps(exported, sort_keys=True)
    assert "tenant-a" not in encoded
    assert "maker-1" not in encoded
    assert "reviewer" not in encoded
    assert "http" not in encoded
    assert 'legal_prose_generation": false' in encoded
    tampered = copy.deepcopy(exported)
    tampered["payload"]["metadata"]["disclosure_count"] = 99
    assert store.verify_export(tampered) is False


def test_tenant_and_property_isolation_come_only_from_resolver(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.snapshot = context.make_snapshot(tenant="tenant-b")
    with pytest.raises(NoticeProposalNotFound):
        store.get(proposal["proposal_id"])


def test_unicode_tenant_canonicalization_does_not_collapse_distinct_scope(authority) -> None:
    context, store = authority
    context.snapshot = context.make_snapshot(tenant="Caf\u00e9")
    proposal = store.propose(expected_revision=0, idempotency_key="unicode")
    context.snapshot = context.make_snapshot(tenant="Cafe\u0301")
    assert store.get(proposal["proposal_id"])["proposal_id"] == proposal["proposal_id"]
    context.snapshot = context.make_snapshot(tenant="Cafe")
    with pytest.raises(NoticeProposalNotFound):
        store.get(proposal["proposal_id"])
    context.snapshot = context.make_snapshot(property_id="other-property")
    with pytest.raises(NoticeProposalNotFound):
        store.get(proposal["proposal_id"])


def test_integrity_verification_covers_audit_and_signed_exports(authority) -> None:
    context, store = authority
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    context.actor = "reviewer"
    store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="approve")
    store.export_signed_metadata(proposal["proposal_id"], idempotency_key="export")
    counts = store.verify_integrity()
    assert counts == {
        "heads": 1,
        "proposals": 1,
        "approvals": 1,
        "idempotency": 3,
        "exports": 1,
        "audit_events": 3,
    }
    with sqlite3.connect(store._path) as connection:
        connection.execute(
            "UPDATE scan_notice_exports SET signature_sha256=?",
            (D8,),
        )
        connection.commit()
    with pytest.raises(NoticeProposalIntegrityError, match="metadata export"):
        store.verify_integrity()


def test_audit_chain_rejects_mutation_and_forged_append(authority) -> None:
    _context, store = authority
    store.propose(expected_revision=0, idempotency_key="create")
    with sqlite3.connect(store._path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE scan_notice_audit SET payload_sha256=?",
            (D8,),
        )
    with sqlite3.connect(store._path) as connection:
        connection.execute(
            "INSERT INTO scan_notice_audit(tenant,property_id,event_id,event_type,object_id,"
            "payload_sha256,previous_event_sha256,event_sha256,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "tenant-a",
                "web-property",
                "forged",
                "proposal.forged",
                "CSNP-1",
                D1,
                None,
                D2,
                1_000.0,
            ),
        )
        connection.commit()
    with pytest.raises(NoticeProposalIntegrityError, match="audit chain"):
        store.verify_integrity()


def test_resolver_output_cannot_smuggle_unstructured_fields(authority) -> None:
    context, store = authority
    with pytest.raises(TypeError):
        ReviewedScanDiscovery(  # type: ignore[call-arg]
            tracker_key=D4,
            classification="analytics",
            kind="cookie",
            first_party=False,
            resource_type="script",
            review_version=1,
            review_sha256=D5,
            evidence_sha256=D6,
            valid_until=2_000.0,
            raw_url="https://example.test/?token=secret",
        )
    context.snapshot = replace(context.snapshot, discoveries=(object(),))  # type: ignore[arg-type]
    with pytest.raises(NoticeProposalIntegrityError, match="invalid type"):
        store.propose(expected_revision=0, idempotency_key="invalid")


def test_tracker_keys_are_digest_only(authority) -> None:
    context, store = authority
    invalid = replace(context.snapshot.discoveries[0], tracker_key="analytics.example.test")
    context.snapshot = replace(context.snapshot, discoveries=(invalid,))
    with pytest.raises(NoticeProposalIntegrityError, match="invalid authority metadata"):
        store.propose(expected_revision=0, idempotency_key="raw-tracker")


def test_inventory_adapter_re_reads_exact_public_authority_and_emits_no_raw_scan_data(
    tmp_path,
) -> None:
    seeded = _seed_adapter_inventory(tmp_path)
    binding_box = {"value": seeded["binding"]}
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: binding_box["value"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    snapshot = adapter()
    assert snapshot.tenant_id == "Caf\u00e9"
    assert snapshot.property_revision == seeded["property"]["revision"]
    assert snapshot.property_sha256 == seeded["property"]["record_sha256"]
    assert snapshot.report_sha256 == seeded["report"]["record_sha256"]
    assert snapshot.scanner_report_sha256 == seeded["report"]["scanner_report_sha256"]
    assert snapshot.inventory_revision == 7
    assert snapshot.inventory_sha256 is not None
    assert len(snapshot.discoveries) == 1
    discovery = snapshot.discoveries[0]
    assert discovery.tracker_key == seeded["primary"].tracker_key
    assert discovery.finding_evidence_sha256 == seeded["primary"].evidence_sha256
    assert discovery.evidence_sha256 == REVIEW_EVIDENCE
    encoded = json.dumps(asdict(snapshot), sort_keys=True)
    assert "analytics.vendor.test" not in encoded
    assert "/collect" not in encoded
    assert "token=secret" not in encoded
    assert adapter.product_boundaries()["inventory_cursor_pagination"] is True
    assert adapter.product_boundaries()["maximum_exact_discoveries"] == 10_000
    assert adapter.product_boundaries()["global_inventory_revision_available"] is False


def test_inventory_adapter_follows_exact_public_discovery_cursor_pages(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _seed_adapter_inventory(tmp_path, second_finding_unreviewed=True)
    inventory = seeded["inventory"]
    discoveries = inventory.list_discoveries("Café", "property-shop", limit=10)["items"]
    second = next(
        item for item in discoveries if item["tracker_key"] != seeded["primary"].tracker_key
    )
    inventory.review_tracker(
        "Café",
        "property-shop",
        second["tracker_key"],
        classification="functional",
        registry_action="approved",
        reviewer_sha256=REVIEWER_A,
        second_reviewer_sha256=REVIEWER_B,
        evidence_sha256=hashlib.sha256(b"second-review").hexdigest(),
        report_id=seeded["report"]["report_id"],
        valid_until=ADAPTER_NOW + 1_000,
        expected_version=0,
        idempotency_key="review-second",
        tracker_id="tracker-functional",
        vendor_id="vendor-functional",
        purpose_ids=("functional",),
    )
    monkeypatch.setattr(proposal_module, "_INVENTORY_DISCOVERY_PAGE_SIZE", 1)
    adapter = ConsentScanInventorySnapshotAdapter(
        inventory,
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )

    snapshot = adapter()

    assert len(snapshot.discoveries) == 2
    assert [item.tracker_key for item in snapshot.discoveries] == sorted(
        item["tracker_key"] for item in discoveries
    )


def test_inventory_adapter_snapshot_drives_proposal_without_request_authority(tmp_path) -> None:
    seeded = _seed_adapter_inventory(tmp_path)
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    actor = {"value": "maker"}
    store = ConsentScanNoticeProposalStore(
        tmp_path / "adapter-proposals.sqlite3",
        snapshot_resolver=adapter,
        actor_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant: b"z" * 32,
        clock=lambda: ADAPTER_NOW,
        gate=lambda: None,
    )
    proposal = store.propose(expected_revision=0, idempotency_key="adapter-proposal")
    assert proposal["source_pins"]["report_sha256"] == seeded["report"]["record_sha256"]
    assert proposal["source_pins"]["inventory_sha256"] == adapter().inventory_sha256
    assert proposal["metadata"]["disclosures"][0]["tracker_key"] == seeded["primary"].tracker_key


def test_inventory_adapter_rejects_unknown_unreviewed_and_revoked_items(tmp_path) -> None:
    seeded = _seed_adapter_inventory(tmp_path, second_finding_unreviewed=True)
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    with pytest.raises(NoticeProposalConflict, match="unknown or unreviewed"):
        adapter()

    seeded = _seed_adapter_inventory(tmp_path / "revoked")
    review = seeded["inventory"].list_reviews(
        seeded["binding"].tenant_id,
        seeded["binding"].property_id,
        seeded["primary"].tracker_key,
    )["items"][0]
    revoked = {"values": [review["record_sha256"]]}
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=lambda: revoked["values"],
        clock=lambda: ADAPTER_NOW,
    )
    with pytest.raises(NoticeProposalConflict, match="revoked"):
        adapter()


def test_inventory_adapter_rejects_stale_review_and_binding_drift(tmp_path) -> None:
    seeded = _seed_adapter_inventory(tmp_path)
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW + 1_001,
    )
    with pytest.raises(NoticeProposalConflict, match="stale"):
        adapter()

    calls = itertools.count()

    def drifting_binding() -> InventoryNoticeProposalBinding:
        revision = 7 if next(calls) == 0 else 8
        return replace(seeded["binding"], inventory_revision=revision)

    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=drifting_binding,
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    with pytest.raises(NoticeProposalConflict, match="drifted"):
        adapter()


def test_inventory_adapter_rejects_property_revision_drift_after_report(tmp_path) -> None:
    seeded = _seed_adapter_inventory(tmp_path)
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    adapter()
    seeded["inventory"].upsert_property(
        seeded["binding"].tenant_id,
        seeded["binding"].property_id,
        [ADAPTER_ORIGIN],
        [f"{ADAPTER_ORIGIN}/updated"],
        expected_revision=1,
        idempotency_key="property-v2",
    )
    with pytest.raises(NoticeProposalConflict, match="report job is stale"):
        adapter()


def test_inventory_adapter_unicode_tenant_scope_is_canonical_and_isolated(tmp_path) -> None:
    seeded = _seed_adapter_inventory(tmp_path, tenant="Caf\u00e9")
    binding = {"value": replace(seeded["binding"], tenant_id="Cafe\u0301")}
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: binding["value"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    assert adapter().tenant_id == "Caf\u00e9"
    binding["value"] = replace(seeded["binding"], tenant_id="Cafe")
    with pytest.raises(NoticeProposalConflict, match="unavailable"):
        adapter()


def test_inventory_adapter_fails_closed_on_incomplete_without_exact_policy(tmp_path) -> None:
    seeded = _seed_adapter_inventory(tmp_path, truncated=True)
    binding = {"value": seeded["binding"]}
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: binding["value"],
        revoked_review_resolver=tuple,
        clock=lambda: ADAPTER_NOW,
    )
    with pytest.raises(NoticeProposalConflict, match="require an exact reviewed policy"):
        adapter()

    policy = IncompleteScanApproval(
        policy_ref="allow-incomplete-1",
        tenant_sha256=hashlib.sha256("Caf\u00e9".encode()).hexdigest(),
        property_sha256=seeded["property"]["record_sha256"],
        report_sha256=seeded["report"]["record_sha256"],
        reviewer_sha256=REVIEWER_A,
        second_reviewer_sha256=REVIEWER_B,
        valid_until=ADAPTER_NOW + 500,
        policy_sha256=D1,
    )
    policy = replace(
        policy,
        policy_sha256=ConsentScanInventorySnapshotAdapter.incomplete_policy_sha256(policy),
    )
    binding["value"] = replace(seeded["binding"], allow_incomplete=policy)
    snapshot = adapter()
    assert snapshot.complete is False
    assert snapshot.truncated is True
    binding["value"] = replace(binding["value"], allow_incomplete=replace(policy, revoked=True))
    with pytest.raises(NoticeProposalConflict, match="revoked"):
        adapter()


def test_inventory_source_review_drift_or_revocation_after_proposal_blocks_approval(
    tmp_path,
) -> None:
    seeded = _seed_adapter_inventory(tmp_path)
    revoked = {"values": []}
    adapter = ConsentScanInventorySnapshotAdapter(
        seeded["inventory"],
        binding_resolver=lambda: seeded["binding"],
        revoked_review_resolver=lambda: revoked["values"],
        clock=lambda: ADAPTER_NOW,
    )
    actor = {"value": "maker"}
    store = ConsentScanNoticeProposalStore(
        tmp_path / "drift-proposals.sqlite3",
        snapshot_resolver=adapter,
        actor_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant: b"z" * 32,
        clock=lambda: ADAPTER_NOW,
        gate=lambda: None,
    )
    proposal = store.propose(expected_revision=0, idempotency_key="create")
    seeded["inventory"].review_tracker(
        seeded["binding"].tenant_id,
        seeded["binding"].property_id,
        seeded["primary"].tracker_key,
        classification="advertising",
        registry_action="approved",
        reviewer_sha256=REVIEWER_A,
        second_reviewer_sha256=REVIEWER_B,
        evidence_sha256=hashlib.sha256(b"new-evidence").hexdigest(),
        report_id=seeded["binding"].report_id,
        valid_until=ADAPTER_NOW + 1_000,
        expected_version=1,
        idempotency_key="review-v2",
        tracker_id="tracker-analytics",
        vendor_id="vendor-analytics",
        purpose_ids=("advertising",),
    )
    actor["value"] = "reviewer"
    with pytest.raises(NoticeProposalConflict, match="source pins"):
        store.approve(proposal["proposal_id"], expected_revision=1, idempotency_key="stale")

    fresh_proposal = store.propose(expected_revision=1, idempotency_key="fresh")
    current_review = seeded["inventory"].list_reviews(
        seeded["binding"].tenant_id,
        seeded["binding"].property_id,
        seeded["primary"].tracker_key,
    )["items"][0]
    revoked["values"] = [current_review["record_sha256"]]
    actor["value"] = "second-reviewer"
    with pytest.raises(NoticeProposalConflict, match="revoked"):
        store.approve(
            fresh_proposal["proposal_id"],
            expected_revision=1,
            idempotency_key="revoked",
        )


def test_store_connections_close_when_row_setup_fails(tmp_path, monkeypatch) -> None:
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    context = Context()
    store = ConsentScanNoticeProposalStore(
        tmp_path / "notice-proposals.sqlite3",
        snapshot_resolver=lambda: context.snapshot,
        actor_resolver=lambda: context.actor,
        signing_key_resolver=lambda _tenant: b"k" * 32,
        clock=lambda: context.now,
        gate=lambda: None,
    )
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect
    fail_row_setup = {"on": True}

    class _RowSetupFails(sqlite3.Connection):
        def __setattr__(self, name, value):
            if name == "row_factory" and fail_row_setup["on"]:
                raise sqlite3.OperationalError("row setup failed")
            super().__setattr__(name, value)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_RowSetupFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(proposal_module.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            with store._connect():
                pass
        fail_row_setup["on"] = False
        with store._connect() as connection:
            assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        gc.enable()
    assert len(opened) == 2  # the failed setup, the working call
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_shared_setup_failure_is_left_to_the_session_owner(tmp_path, monkeypatch) -> None:
    context = Context()
    store = ConsentScanNoticeProposalStore(
        tmp_path / "notice-proposals.sqlite3",
        snapshot_resolver=lambda: context.snapshot,
        actor_resolver=lambda: context.actor,
        signing_key_resolver=lambda _tenant: b"k" * 32,
        clock=lambda: context.now,
        gate=lambda: None,
    )
    sessions = []

    class _SetupFails:
        def __init__(self):
            self.closes = []
            self.row_factory = None
            sessions.append(self)

        def execute(self, sql, *args):
            raise sqlite3.OperationalError("pragma failed")

        def close(self):
            self.closes.append(True)

    monkeypatch.setattr(proposal_module.consent_storage, "shared", lambda: True)
    monkeypatch.setattr(proposal_module.consent_storage, "connect", lambda path, **kwargs: _SetupFails())
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            with store._connect():
                pass
        assert len(sessions) == 1 and sessions[0].closes == []
    finally:
        gc.enable()
