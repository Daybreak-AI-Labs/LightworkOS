"""Exact projections from installed knowledge stores into APP10."""

from __future__ import annotations

import hashlib
import json

import pytest
from maverick import evidence_graph, fleet_memory
from maverick.knowledge_access import KnowledgeActorAuthority
from maverick.knowledge_content_projection import (
    ExistingKnowledgeContentProjector,
    KnowledgeProjectionUnavailable,
    inspect_existing_source,
    vector_knowledge_source_ref,
    work_discovery_source_ref,
)
from maverick.research_registry import (
    DatasetAdmission,
    DataUseAuthority,
    ResearchAssetRef,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _admission(reference: ResearchAssetRef, source_ref: str, content_sha256: str):
    return DatasetAdmission(
        tenant="tenant-a",
        reference=reference,
        source_ref=source_ref,
        content_sha256=content_sha256,
        license_id="customer-authorized",
        license_evidence_sha256=_sha("license"),
        allowed_purpose="product_research",
        usage_constraints=("tenant_only",),
        provenance_kind="source",
        synthetic_provenance=None,
        data_use_authority=DataUseAuthority(
            tenant="tenant-a",
            decision_id="decision-source",
            decision_sha256=_sha("decision"),
            asset_id="source",
            action="export",
            purpose_codes=("product_research",),
            expires_at=4_102_444_800.0,
            authority_sha256=_sha("authority"),
        ),
        consent_authority=None,
        approval_sha256=_sha("approval"),
    )


def test_evidence_graph_projection_is_exact_current_and_checksum_bound(monkeypatch):
    record = {
        "schema": "lightwork.evidence-graph-node.v1",
        "id": "node-7",
        "status": "approved",
        "freshness": "current",
        "authority_validation": {"checked_at": 1_800_000_000.0},
        "evidence_type": "policy",
        "title": "Approval policy",
        "summary": "Controller approval is required.",
        "observed_at": 1_700_000_000.0,
        "review": {"reviewed_at": 1_700_000_100.0},
    }
    monkeypatch.setattr(evidence_graph, "enabled", lambda: True)
    monkeypatch.setattr(evidence_graph, "get", lambda node_id: dict(record) if node_id == "node-7" else None)

    inspected = inspect_existing_source(
        "tenant-a",
        "catalog:evidence-graph/node-7",
    )
    reference = ResearchAssetRef("dataset", "source", "v1", _sha("manifest"))
    document = ExistingKnowledgeContentProjector()(
        "tenant-a",
        reference,
        _admission(reference, inspected["source_ref"], inspected["content_sha256"]),
    )

    assert document is not None
    assert document.title == "Approval policy"
    assert document.summary == "Controller approval is required."
    assert document.claim_state == "verified"
    assert document.reference == reference

    # Live access-check decorations do not rewrite the immutable content
    # commitment, while persisted source content does.
    record["authority_validation"] = {"checked_at": 1_900_000_000.0}
    assert inspect_existing_source(
        "tenant-a", "catalog:evidence-graph/node-7"
    )["content_sha256"] == inspected["content_sha256"]
    record["summary"] = "Changed source material."
    with pytest.raises(KnowledgeProjectionUnavailable, match="no longer matches"):
        ExistingKnowledgeContentProjector()(
            "tenant-a",
            reference,
            _admission(reference, inspected["source_ref"], inspected["content_sha256"]),
        )


def test_evidence_projection_withholds_noncurrent_or_unapproved_nodes(monkeypatch):
    record = {
        "status": "approved",
        "freshness": "expired",
        "summary": "Must remain absent.",
    }
    monkeypatch.setattr(evidence_graph, "enabled", lambda: True)
    monkeypatch.setattr(evidence_graph, "get", lambda _node_id: dict(record))

    with pytest.raises(KnowledgeProjectionUnavailable, match="not current and approved"):
        inspect_existing_source("tenant-a", "catalog:evidence-graph/node-7")

    record.update(status="draft", freshness="current")
    with pytest.raises(KnowledgeProjectionUnavailable, match="not current and approved"):
        inspect_existing_source("tenant-a", "catalog:evidence-graph/node-7")


def test_fleet_projection_reads_one_private_immutable_record(monkeypatch, tmp_path):
    inbox = tmp_path / "fleet"
    inbox.mkdir()
    record = {
        "task_brief_text": "Reconcile the monthly close.",
        "verifier_critique": "Require controller approval.",
        "ts": 1_700_000_000.0,
    }
    path = inbox / "receipt-7.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(fleet_memory, "enabled", lambda: True)
    monkeypatch.setattr(fleet_memory, "inbox_dir", lambda: inbox)

    inspected = inspect_existing_source(
        "tenant-a",
        "catalog:fleet-memory/receipt-7.json",
    )

    assert inspected["claim_state"] == "inferred"
    assert inspected["summary"] == (
        "Reconcile the monthly close.\n\nRequire controller approval."
    )
    assert len(inspected["content_sha256"]) == 64
    with pytest.raises(KnowledgeProjectionUnavailable, match="was not found"):
        inspect_existing_source(
            "tenant-a",
            "catalog:fleet-memory/missing.json",
        )


@pytest.mark.parametrize(
    "source_ref",
    [
        "catalog:vector/default",
        "catalog:fleet-memory/../outside.json",
        "catalog:work-discovery/raw-session",
    ],
)
def test_unsupported_or_ambiguous_store_references_fail_closed(source_ref):
    with pytest.raises(KnowledgeProjectionUnavailable, match="no installed exact"):
        inspect_existing_source("tenant-a", source_ref)


def _authority(tenant: str, principal: str, action: str = "read"):
    return KnowledgeActorAuthority(
        tenant=tenant,
        principal=principal,
        action=action,
        purpose="product_research",
        authorization_sha256=_sha(f"{tenant}:{principal}:{action}"),
    )


def test_vector_document_projection_uses_exact_order_and_rejects_partial_rows():
    from maverick_knowledge import KnowledgeBase, SqliteVectorStore

    text = "alpha beta gamma delta epsilon zeta eta theta"
    kb = KnowledgeBase(
        store=SqliteVectorStore(":memory:"),
        chunk_size=18,
        chunk_overlap=4,
    )
    assert kb.ingest_text("finance", text, source="quarterly.txt") > 1
    digest = _sha(text)
    source_ref = vector_knowledge_source_ref("finance", digest)
    inspected = inspect_existing_source(
        "tenant-a",
        source_ref,
        knowledge_base=kb,
    )
    reference = ResearchAssetRef("dataset", "source", "v1", _sha("vector manifest"))
    projector = ExistingKnowledgeContentProjector(knowledge_base=kb)
    document = projector.resolve_for_context(
        "tenant-a",
        reference,
        _admission(reference, source_ref, inspected["content_sha256"]),
        _authority("tenant-a", "user:alice"),
    )

    assert document.summary == text
    row = kb.store._db.execute(
        "SELECT id FROM chunks WHERE collection='finance' ORDER BY id LIMIT 1"
    ).fetchone()
    kb.store._db.execute(
        "DELETE FROM chunks WHERE collection='finance' AND id=?", row
    )
    kb.store._db.commit()
    with pytest.raises(KnowledgeProjectionUnavailable, match="cannot be read exactly"):
        projector.resolve_for_context(
            "tenant-a",
            reference,
            _admission(reference, source_ref, inspected["content_sha256"]),
            _authority("tenant-a", "user:alice"),
        )


def test_vector_document_projection_rejects_content_under_a_false_document_hash():
    from maverick_knowledge import KnowledgeBase, SqliteVectorStore

    claimed = _sha("approved original")
    store = SqliteVectorStore(":memory:")
    store.add(
        "finance",
        [
            (
                "crafted",
                "different content",
                [1.0, 0.0],
                {
                    "source": "quarterly.txt",
                    "subject": "",
                    "trust_tier": 1,
                    "sensitivity": "internal",
                    "ingested_by": "user:loader",
                    "ingested_at": 1_700_000_000.0,
                    "document_schema": "lightwork.vector-document-layout.v1",
                    "document_length": len("different content"),
                    "doc_sha256": claimed,
                    "chunk_count": 1,
                    "chunk_index": 0,
                    "chunk_start": 0,
                    "chunk_end": len("different content"),
                },
            )
        ],
    )
    kb = KnowledgeBase(store=store)

    with pytest.raises(KnowledgeProjectionUnavailable, match="cannot be read exactly"):
        inspect_existing_source(
            "tenant-a",
            vector_knowledge_source_ref("finance", claimed),
            knowledge_base=kb,
        )


def test_work_discovery_projection_is_exact_owner_bound_and_consent_bound():
    calls = []

    class Store:
        def governed_candidate_projection(self):
            return {
                "schema": "lightwork.ekko-knowledge-projection.v1",
                "owner_sha256": _sha("owner"),
                "device_sha256": _sha("device"),
                "consent": {
                    "policy_sha256": _sha("policy"),
                    "enrolled_at": 1_700_000_000.0,
                    "valid_until": 1_900_000_000.0,
                },
                "lineage": {"event_count": 2, "event_sha256": _sha("events")},
                "candidates": [
                    {
                        "title": "Prepare recurring report",
                        "occurrences": 2,
                        "evidence": [{"event_ids": ["one", "two"]}],
                    }
                ],
            }

    def factory(tenant, owner, device):
        calls.append((tenant, owner, device))
        return Store()

    source_ref = work_discovery_source_ref("user:alice", "laptop-1")
    inspected = inspect_existing_source(
        "tenant-a",
        source_ref,
        work_discovery_factory=factory,
    )
    reference = ResearchAssetRef("dataset", "source", "v1", _sha("work manifest"))
    admission = _admission(reference, source_ref, inspected["content_sha256"])
    projector = ExistingKnowledgeContentProjector(work_discovery_factory=factory)

    document = projector.resolve_for_context(
        "tenant-a",
        reference,
        admission,
        _authority("tenant-a", "user:alice"),
    )
    assert document.summary == "Prepare recurring report (2 occurrences)"
    assert calls[-1] == ("tenant-a", "user:alice", "laptop-1")
    before = len(calls)
    with pytest.raises(KnowledgeProjectionUnavailable, match="another actor"):
        projector.resolve_for_context(
            "tenant-a",
            reference,
            admission,
            _authority("tenant-a", "user:bob"),
        )
    assert len(calls) == before
    with pytest.raises(KnowledgeProjectionUnavailable, match="requires exact actor"):
        projector("tenant-a", reference, admission)


def test_work_discovery_owner_check_compares_non_ascii_principals():
    # Owners and actors are principal names, which may be any Unicode text: a
    # different actor is refused rather than raising TypeError.
    source_ref = work_discovery_source_ref("user:josé", "laptop-1")
    reference = ResearchAssetRef("dataset", "source", "v1", _sha("work manifest"))
    admission = _admission(reference, source_ref, _sha("work content"))
    projector = ExistingKnowledgeContentProjector(work_discovery_factory=lambda *_: None)

    with pytest.raises(KnowledgeProjectionUnavailable, match="another actor"):
        projector.resolve_for_context(
            "tenant-a",
            reference,
            admission,
            _authority("tenant-a", "user:bob"),
        )
