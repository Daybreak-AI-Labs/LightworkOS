"""Continuous, review-gated control evidence graph."""

from __future__ import annotations

import time

import pytest
from maverick import evidence_graph, security_ops


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)


def test_ingest_is_content_addressed_review_gated_and_secret_safe():
    node = evidence_graph.ingest(
        source="deployment_drill",
        source_id="restore-2026-07-19",
        evidence_type="restore_drill",
        title="Witnessed restore",
        summary="Database and audit chain restored inside the declared RTO.",
        controls=["RES-01", "SOC2:A1.2"],
        attributes={"rto_seconds": 812, "result": "passed"},
        links=[{"relation": "proves", "target_type": "control", "target_id": "RES-01"}],
        actor="operator@example.com",
    )
    assert node["id"].startswith("EGN-")
    assert node["status"] == "pending_review"
    assert node["payload_sha256"]
    assert node["revision"] == 1

    duplicate = evidence_graph.ingest(
        source="deployment_drill",
        source_id="restore-2026-07-19",
        evidence_type="restore_drill",
        title="Witnessed restore",
        summary="Database and audit chain restored inside the declared RTO.",
        controls=["SOC2:A1.2", "RES-01"],
        attributes={"result": "passed", "rto_seconds": 812},
        links=[{"target_id": "RES-01", "target_type": "control", "relation": "proves"}],
        actor="operator@example.com",
    )
    assert duplicate["id"] == node["id"]
    assert duplicate["revision"] == node["revision"]

    with pytest.raises(ValueError, match="sensitive attribute"):
        evidence_graph.ingest(
            source="connector",
            source_id="bad",
            evidence_type="probe",
            title="Unsafe",
            summary="Would store a credential.",
            controls=[],
            attributes={"access_token": "secret-value"},
            actor="operator",
        )

    credential = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # pragma: allowlist secret
    with pytest.raises(ValueError, match="secret material"):
        evidence_graph.ingest(
            source="connector",
            source_id="secret-in-summary",
            evidence_type="probe",
            title="Unsafe",
            summary=f"Probe returned {credential}",
            controls=[],
            attributes={},
            actor="operator",
        )
    with pytest.raises(ValueError, match="secret material"):
        evidence_graph.ingest(
            source="connector",
            source_id="secret-in-value",
            evidence_type="probe",
            title="Unsafe",
            summary="Credential hidden under an innocuous field name.",
            controls=[],
            attributes={"result": credential},
            actor="operator",
        )
    with pytest.raises(ValueError, match="secret material"):
        evidence_graph.ingest(
            source="connector",
            source_id="secret-in-list",
            evidence_type="probe",
            title="Unsafe",
            summary="Credential hidden inside an attribute list.",
            controls=[],
            attributes={"observations": ["safe", credential]},
            actor="operator",
        )


def test_public_ingest_cannot_construct_an_inherited_approval():
    with pytest.raises(TypeError, match="inherited_review"):
        evidence_graph.ingest(
            source="production_evidence",
            source_id="forged",
            evidence_type="tenant_isolation",
            title="Forged approval",
            summary="Caller-constructed review must not confer coverage.",
            controls=["TEN-01"],
            attributes={"result": "passed"},
            actor="operator",
            inherited_review={
                "status": "approved",
                "reviewer": "self",
                "rationale": "self-approved",
                "reviewed_at": time.time(),
                "inherited_from": "not-a-governed-record",
            },
        )
    with pytest.raises(ValueError, match="persisted review binding"):
        evidence_graph._ingest(
            source="production_evidence",
            source_id="forged-private-call",
            evidence_type="tenant_isolation",
            title="Forged approval",
            summary="A plain approval dictionary is not a persisted binding.",
            controls=["TEN-01"],
            attributes={"result": "passed"},
            actor="operator",
            persisted_review={
                "status": "approved",
                "authority_sha256": "a" * 64,
            },
        )
    assert evidence_graph.list_nodes() == []


def test_human_decision_and_freshness_drive_coverage():
    fresh = evidence_graph.ingest(
        source="connector_certification",
        source_id="okta-live",
        evidence_type="connector_probe",
        title="Okta least-privilege probe",
        summary="Read-only system-log probe passed.",
        controls=["IAM-01"],
        attributes={"result": "passed"},
        links=[],
        actor="connector-runner",
        valid_until=time.time() + 3600,
    )
    approved = evidence_graph.decide(
        fresh["id"],
        decision="approved",
        rationale="Reviewed the live probe receipt and credential scope.",
        reviewer="security-reviewer",
        expected_revision=fresh["revision"],
    )
    assert approved is not None

    stale = evidence_graph.ingest(
        source="connector_certification",
        source_id="entra-old",
        evidence_type="connector_probe",
        title="Old Entra probe",
        summary="An expired observation.",
        controls=["IAM-01"],
        attributes={"result": "passed"},
        links=[],
        actor="connector-runner",
        observed_at=time.time() - 3600,
        valid_until=time.time() - 1,
    )
    stale = evidence_graph.decide(
        stale["id"],
        decision="approved",
        rationale="Historically valid, but its freshness window has elapsed.",
        reviewer="security-reviewer",
        expected_revision=stale["revision"],
    )
    assert stale is not None

    report = evidence_graph.coverage_report(["IAM-01", "RES-01"])
    assert report["covered_controls"] == ["IAM-01"]
    assert report["missing_controls"] == ["RES-01"]
    assert report["stale_nodes"] == 1


def test_collect_approved_security_evidence_preserves_review_provenance():
    mapped = security_ops.map_evidence(
        "MFA policy",
        "The approved access-control policy requires phishing-resistant MFA for administrators.",
        submitted_by="grc-analyst",
    )
    approved = security_ops.decide_evidence(
        mapped["id"],
        "approved",
        "Verified against the controlled policy repository.",
        "control-owner",
        mapped["revision"],
    )
    assert approved is not None

    imported = evidence_graph.collect_security_evidence(actor="evidence-collector")
    assert len(imported) == 1
    assert imported[0]["status"] == "approved"
    assert imported[0]["review"]["inherited_from"] == mapped["id"]
    assert imported[0]["review"]["authority_revision"] == approved["revision"]
    assert len(imported[0]["review"]["authority_sha256"]) == 64
    assert imported[0]["source"] == "security_ops"


def test_inherited_security_approval_is_revalidated_for_get_coverage_and_pack():
    mapped = security_ops.map_evidence(
        "MFA policy",
        (
            "The approved access-control policy requires phishing-resistant "
            "MFA for administrators."
        ),
        control_ids=["IAM-02"],
        submitted_by="grc-analyst",
    )
    approved = security_ops.decide_evidence(
        mapped["id"],
        "approved",
        "Verified against the controlled policy repository.",
        "control-owner",
        mapped["revision"],
    )
    assert approved is not None
    projected = evidence_graph.collect_security_evidence(actor="collector")[0]
    assert evidence_graph.get(projected["id"])["status"] == "approved"
    assert evidence_graph.coverage_report(["IAM-02"])["coverage_percent"] == 100.0
    with pytest.raises(ValueError, match="governed source authority"):
        evidence_graph.decide(
            projected["id"],
            decision="approved",
            rationale="A graph-local review must not launder inherited authority.",
            reviewer="graph-reviewer",
            expected_revision=projected["revision"],
        )

    rejected = security_ops.decide_evidence(
        mapped["id"],
        "rejected",
        "The controlled source was withdrawn after the graph projection.",
        "control-owner",
        approved["revision"],
    )
    assert rejected is not None

    current = evidence_graph.get(projected["id"])
    assert current is not None
    assert current["status"] == "authority_stale"
    assert current["freshness"] == "stale"
    assert current["authority_validation"] == {
        "status": "stale",
        "source": "security_ops",
        "record_id": mapped["id"],
        "bound_revision": approved["revision"],
        "reason": "source_not_approved",
        "current_revision": rejected["revision"],
    }
    # Revocation is an effective read-time state.  The historical graph record
    # and its original inherited review remain immutable for audit provenance.
    persisted = evidence_graph._STORE.get(projected["id"])  # noqa: SLF001
    assert persisted is not None
    assert persisted["status"] == "approved"
    assert persisted["review"]["authority_revision"] == approved["revision"]

    coverage = evidence_graph.coverage_report(["IAM-02"])
    assert coverage["coverage_percent"] == 0.0
    assert coverage["covered_controls"] == []
    assert coverage["missing_controls"] == ["IAM-02"]
    assert coverage["approved_current_nodes"] == 0
    assert coverage["stale_nodes"] == 1

    pack = evidence_graph.render_pack(required_controls=["IAM-02"])
    packed = next(node for node in pack["nodes"] if node["id"] == projected["id"])
    assert packed["status"] == "authority_stale"
    assert packed["authority_validation"]["reason"] == "source_not_approved"
    assert pack["coverage"] == coverage

    reapproved = security_ops.decide_evidence(
        mapped["id"],
        "approved",
        "The replacement controlled source was independently verified.",
        "control-owner",
        rejected["revision"],
    )
    assert reapproved is not None
    replacement = evidence_graph.collect_security_evidence(actor="collector")[0]
    assert replacement["id"] != projected["id"]
    old = evidence_graph.get(projected["id"])
    assert old is not None
    assert old["authority_validation"]["reason"] == "source_revision_changed"
    assert evidence_graph.get(replacement["id"])["status"] == "approved"
    recovered = evidence_graph.coverage_report(["IAM-02"])
    assert recovered["coverage_percent"] == 100.0
    assert recovered["approved_current_nodes"] == 1
    assert recovered["stale_nodes"] == 1


def test_inherited_security_approval_binds_the_exact_decision(monkeypatch):
    mapped = security_ops.map_evidence(
        "MFA policy",
        "Phishing-resistant MFA is required for administrators.",
        control_ids=["IAM-02"],
        submitted_by="grc-analyst",
    )
    approved = security_ops.decide_evidence(
        mapped["id"],
        "approved",
        "Verified against the controlled policy repository.",
        "control-owner",
        mapped["revision"],
    )
    assert approved is not None
    projected = evidence_graph.collect_security_evidence(actor="collector")[0]

    changed_decision = {
        **approved,
        "decision": {
            **approved["decision"],
            "rationale": "Changed without a governed revision.",
        },
    }
    monkeypatch.setattr(
        security_ops,
        "get_evidence",
        lambda _evidence_id: changed_decision,
    )
    current = evidence_graph.get(projected["id"])
    assert current is not None
    assert current["status"] == "authority_stale"
    assert current["authority_validation"]["reason"] == "source_decision_changed"


def test_security_projection_rereads_persisted_authority(monkeypatch):
    monkeypatch.setattr(
        security_ops,
        "list_evidence",
        lambda: [{
            "id": "EVD-forged",
            "status": "approved",
            "decision": {
                "decision": "approved",
                "decided_by": "attacker",
                "rationale": "caller-constructed",
                "decided_at": time.time(),
            },
        }],
    )

    assert evidence_graph.collect_security_evidence(actor="collector") == []


def test_render_pack_binds_nodes_edges_and_coverage():
    node = evidence_graph.ingest(
        source="production_evidence",
        source_id="tenant-wall",
        evidence_type="tenant_isolation",
        title="Tenant isolation drill",
        summary="Cross-tenant reads were refused.",
        controls=["TEN-01"],
        attributes={"attempts": 20, "leaks": 0},
        links=[{"relation": "tests", "target_type": "boundary", "target_id": "tenant"}],
        actor="operator",
    )
    node = evidence_graph.decide(
        node["id"],
        decision="approved",
        reviewer="witness",
        rationale="Witnessed test",
        expected_revision=node["revision"],
    )
    assert node is not None
    pack = evidence_graph.render_pack(required_controls=["TEN-01", "IAM-01"])
    assert pack["schema"] == "lightwork.evidence-graph-pack.v1"
    assert pack["graph_sha256"]
    assert pack["coverage"]["covered_controls"] == ["TEN-01"]
    assert pack["nodes"][0]["id"] == node["id"]
    assert pack["signature"]
    ok, reason = evidence_graph.verify_pack(
        pack,
        trusted_pubkey_hex=pack["signature"]["pubkey"],
    )
    assert ok, reason

    tampered = {**pack, "nodes": [{**pack["nodes"][0], "title": "changed"}]}
    ok, reason = evidence_graph.verify_pack(
        tampered,
        trusted_pubkey_hex=pack["signature"]["pubkey"],
    )
    assert ok is False
    assert "digest" in reason


def test_graph_listing_refuses_unbounded_namespace(monkeypatch):
    monkeypatch.setattr(
        evidence_graph._STORE,  # noqa: SLF001 - boundary behavior under test
        "list",
        lambda *, limit=None: [{}] * int(limit or 0),
    )

    with pytest.raises(ValueError, match="10000-node operational limit"):
        evidence_graph.list_nodes()
