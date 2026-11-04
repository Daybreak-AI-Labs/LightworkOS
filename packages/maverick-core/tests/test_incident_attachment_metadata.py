from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from maverick import governed_document_vault as document_vault
from maverick import incident_attachment_metadata as iam
from maverick.paths import tenant_scope


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def test_stock_media_contract_matches_governed_document_vault() -> None:
    assert iam.DEFAULT_MEDIA_TYPES == document_vault.DEFAULT_MEDIA_TYPES


def _fixture_store(tmp_path, monkeypatch, principal_ref=None):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    clock = [time.time()]
    principal = [principal_ref or "incident-principal-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    incident = {
        "kind": "privacy",
        "id": "INC-privacy-one",
        "revision": 3,
        "sha256": _digest("incident-v3"),
        "revoked": False,
    }
    document = {
        "id": "DOC-evidence-one",
        "revision": 7,
        "authority_sha256": _digest("document-authority-v7"),
        "content_sha256": _digest("document-content"),
        "safe_display_name": "incident-report.pdf",
        "media_type": "application/pdf",
        "byte_size": 4_096,
        "download_allowed": True,
    }

    def incident_resolver(tenant, principal_ref, kind, incident_id):
        assert tenant == "alpha"
        return iam.issue_incident_authority(
            tenant_id=tenant,
            principal_ref=principal_ref,
            incident_kind=kind,
            incident_id=incident_id,
            incident_revision=incident["revision"],
            incident_sha256=incident["sha256"],
            revoked=incident["revoked"],
        )

    def document_resolver(tenant, principal_ref, document_id):
        return SimpleNamespace(
            tenant_id=tenant,
            principal_ref=principal_ref,
            document_ref=document_id,
            authority_revision=document["revision"],
            authority_sha256=document["authority_sha256"],
            safe_display_name=document["safe_display_name"],
            media_type=document["media_type"],
            byte_size=document["byte_size"],
            content_sha256=document["content_sha256"],
            download_allowed=document["download_allowed"],
        )

    store = iam.IncidentAttachmentStore(
        tenant_id="alpha",
        principal_ref=principal[0],
        principal_resolver=lambda: principal[0],
        incident_authority_resolver=incident_resolver,
        document_authority_resolver=document_resolver,
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        retention_seconds=3_600,
        attachment_ttl_seconds=600,
        clock=lambda: clock[0],
    )
    return store, clock, principal, incident, document


def _create(store, incident, document, *, key="create-one", redaction="unreviewed"):
    return store.create_attachment(
        "alpha",
        incident_kind=incident["kind"],
        incident_id=incident["id"],
        incident_revision=incident["revision"],
        incident_sha256=incident["sha256"],
        document_id=document["id"],
        document_revision=document["revision"],
        document_authority_sha256=document["authority_sha256"],
        sha256=document["content_sha256"],
        redaction_state=redaction,
        idempotency_key=key,
    )


def test_create_is_closed_authority_bound_and_idempotent(tmp_path, monkeypatch):
    store, _clock, _principal, incident, document = _fixture_store(
        tmp_path, monkeypatch
    )
    with tenant_scope(tenant="alpha"):
        created = _create(store, incident, document)
        replay = _create(store, incident, document)

        assert replay == created
        assert created.attachment_id.startswith("IAT-")
        assert created.incident_revision == 3
        assert created.document_revision == 7
        assert created.safe_display_name == "incident-report.pdf"
        assert created.media_type == "application/pdf"
        assert created.byte_size == 4_096
        assert created.sha256 == document["content_sha256"]
        assert created.revision == 1
        assert store.backend_kind == "local"
        assert store.verify_integrity("alpha")["ok"] is True
        raw = store._records.get(created.attachment_id)  # noqa: SLF001
        assert raw is not None
        encoded = json.dumps(raw).lower()
        assert all(
            forbidden not in encoded
            for forbidden in ("filesystem_path", "object_store_uri", "credential", "raw_bytes")
        )

        with pytest.raises(iam.IncidentAttachmentConflict, match="idempotency"):
            _create(store, incident, document, redaction="pending")


def test_exact_authority_media_and_scope_fail_closed(tmp_path, monkeypatch):
    store, _clock, principal, incident, document = _fixture_store(tmp_path, monkeypatch)
    with tenant_scope(tenant="alpha"):
        with pytest.raises(iam.IncidentAttachmentConflict, match="incident revision"):
            store.create_attachment(
                "alpha",
                incident_kind="privacy",
                incident_id=incident["id"],
                incident_revision=2,
                incident_sha256=incident["sha256"],
                document_id=document["id"],
                document_revision=document["revision"],
                document_authority_sha256=document["authority_sha256"],
                sha256=document["content_sha256"],
                idempotency_key="wrong-incident",
            )
        with pytest.raises(iam.IncidentAttachmentConflict, match="document revision"):
            store.create_attachment(
                "alpha",
                incident_kind="privacy",
                incident_id=incident["id"],
                incident_revision=incident["revision"],
                incident_sha256=incident["sha256"],
                document_id=document["id"],
                document_revision=6,
                document_authority_sha256=document["authority_sha256"],
                sha256=document["content_sha256"],
                idempotency_key="wrong-document",
            )
        document["media_type"] = "application/x-msdownload"
        with pytest.raises(iam.IncidentAttachmentValidationError, match="not allowed"):
            _create(store, incident, document, key="blocked-media")
        document["media_type"] = "application/pdf"
        with pytest.raises(iam.IncidentAttachmentNotFound):
            store.list_for_incident("beta", "privacy", incident["id"])
        principal[0] = "incident-principal-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        with pytest.raises(iam.IncidentAttachmentPermissionDenied):
            store.list_for_incident("alpha", "privacy", incident["id"])


def test_non_ascii_tenant_scope_is_not_found(tmp_path, monkeypatch):
    # Tenant ids may be any Unicode text; another tenant's name is a miss,
    # not a TypeError from the comparison.
    store, _clock, _principal, incident, _document = _fixture_store(tmp_path, monkeypatch)
    with tenant_scope(tenant="alpha"):
        with pytest.raises(iam.IncidentAttachmentNotFound):
            store.list_for_incident("béta", "privacy", incident["id"])


def test_update_rebinds_current_incident_and_document_with_cas(tmp_path, monkeypatch):
    store, _clock, _principal, incident, document = _fixture_store(
        tmp_path, monkeypatch
    )
    with tenant_scope(tenant="alpha"):
        created = _create(store, incident, document)
        incident["revision"] = 4
        incident["sha256"] = _digest("incident-v4")
        document["revision"] = 8
        document["authority_sha256"] = _digest("document-authority-v8")
        document["safe_display_name"] = "redacted-report.pdf"

        assert store.authority_state(created) == "stale"
        updated = store.update_attachment(
            "alpha",
            created.attachment_id,
            expected_revision=created.revision,
            incident_revision=incident["revision"],
            incident_sha256=incident["sha256"],
            document_revision=document["revision"],
            document_authority_sha256=document["authority_sha256"],
            sha256=document["content_sha256"],
            redaction_state="pending",
            idempotency_key="update-one",
        )
        replay = store.update_attachment(
            "alpha",
            created.attachment_id,
            expected_revision=created.revision,
            incident_revision=incident["revision"],
            incident_sha256=incident["sha256"],
            document_revision=document["revision"],
            document_authority_sha256=document["authority_sha256"],
            sha256=document["content_sha256"],
            redaction_state="pending",
            idempotency_key="update-one",
        )
        assert replay == updated
        assert updated.revision == 2
        assert updated.previous_integrity_sha256 == created.integrity_sha256
        assert updated.safe_display_name == "redacted-report.pdf"
        assert updated.redaction_state == "pending"
        assert store.authority_state(updated) == "active"
        assert len(store.history("alpha", created.attachment_id)) == 2

        with pytest.raises(iam.IncidentAttachmentConflict, match="revision"):
            store.update_attachment(
                "alpha",
                created.attachment_id,
                expected_revision=1,
                incident_revision=incident["revision"],
                incident_sha256=incident["sha256"],
                document_revision=document["revision"],
                document_authority_sha256=document["authority_sha256"],
                sha256=document["content_sha256"],
                redaction_state="redacted",
                idempotency_key="stale-update",
            )


def test_expiry_revocation_delete_retention_and_purge(tmp_path, monkeypatch):
    store, clock, _principal, incident, document = _fixture_store(tmp_path, monkeypatch)
    with tenant_scope(tenant="alpha"):
        created = _create(store, incident, document)
        document["download_allowed"] = False
        assert store.authority_state(created) == "revoked"
        document["download_allowed"] = True
        clock[0] += 601
        assert store.authority_state(created) == "expired"

        deleted = store.delete_attachment(
            "alpha",
            created.attachment_id,
            expected_revision=created.revision,
            idempotency_key="delete-one",
        )
        assert deleted.status == "tombstoned"
        assert store.authority_state(deleted) == "tombstoned"
        assert store.list_for_incident("alpha", "privacy", incident["id"]) == ()
        assert store.list_for_incident(
            "alpha", "privacy", incident["id"], include_tombstones=True
        ) == (deleted,)
        assert store.retention_due("alpha") == ()

        clock[0] += 3_601
        assert store.retention_due("alpha") == (deleted,)
        assert store.purge_expired("alpha") == 1
        purged = store.get_attachment("alpha", created.attachment_id)
        assert purged.status == "purged"
        assert purged.safe_display_name is None
        assert purged.sha256 == document["content_sha256"]
        assert store.authority_state(purged) == "purged"

        active = _create(store, incident, document, key="create-retention-expiry")
        clock[0] += 3_601
        assert store.retention_due("alpha") == (active,)
        assert store.purge_expired("alpha") == 1
        assert store.get_attachment("alpha", active.attachment_id).status == "purged"


def test_projection_helper_requires_exact_response_revision(tmp_path, monkeypatch):
    store, _clock, _principal, incident, document = _fixture_store(
        tmp_path, monkeypatch
    )
    with tenant_scope(tenant="alpha"):
        created = _create(store, incident, document)
        response = iam.with_incident_attachment_metadata(
            {"id": incident["id"], "revision": incident["revision"], "status": "open"},
            store=store,
            tenant_id="alpha",
            incident_kind="privacy",
        )
        assert response["attachments"][0]["attachment_id"] == created.attachment_id
        assert response["attachments"][0]["authority_state"] == "active"
        assert response["attachment_metadata"]["incident_sha256"] == incident["sha256"]
        with pytest.raises(iam.IncidentAttachmentConflict, match="response revision"):
            iam.with_incident_attachment_metadata(
                {"id": incident["id"], "revision": 2},
                store=store,
                tenant_id="alpha",
                incident_kind="privacy",
            )


def test_history_tampering_is_withheld(tmp_path, monkeypatch):
    store, _clock, _principal, incident, document = _fixture_store(
        tmp_path, monkeypatch
    )
    with tenant_scope(tenant="alpha"):
        created = _create(store, incident, document)

        def tamper(raw):
            raw["history"][0]["event_sha256"] = "0" * 64

        store._records.update(  # noqa: SLF001
            created.attachment_id,
            tamper,
            expected_revision=created.revision,
            action="test_tamper",
            actor=created.principal_ref,
        )
        with pytest.raises(iam.IncidentAttachmentIntegrityError):
            store.get_attachment("alpha", created.attachment_id)


# ---- legal matters: an uploader's attachments are held like other attachments -----

def _matter_events(monkeypatch):
    """Record the legal-matter control-plane events; every other audit event passes through unchanged."""
    from maverick import audit

    real = audit.audit_event
    recorded: list[tuple[str, dict]] = []

    def record(kind, **payload):
        if payload.get("agent") == "ediscovery":
            recorded.append((payload.get("verb", kind), dict(payload)))
            return True
        return real(kind, **payload)

    monkeypatch.setattr(audit, "audit_event", record)
    return recorded


@pytest.fixture()
def held_store(tmp_path, monkeypatch):
    """An attachment store whose uploader is ``user:alice``, plus a matter ledger for tenant ``alpha``."""
    from maverick import ediscovery

    alice = iam.principal_ref_for_subject("alpha", "user:alice")
    store, clock, principal, incident, document = _fixture_store(tmp_path, monkeypatch, principal_ref=alice)
    ledger = tmp_path / "ledger.sqlite3"
    monkeypatch.setattr(ediscovery, "store_path", lambda tenant=None: ledger)
    events = _matter_events(monkeypatch)
    with tenant_scope(tenant="alpha"):
        yield SimpleNamespace(store=store, clock=clock, incident=incident, document=document,
                              ledger=ledger, events=events, alice=alice)


def _matter(ledger, **overrides):
    from maverick import ediscovery

    values = {"name": "Acme dispute", "description": "", "custodians": ["user:alice"],
              "record_kinds": ["attachments"]}
    values.update(overrides)
    return ediscovery.MatterStore(ledger).create("alpha", actor="auditor", values=values)


def test_principal_reference_is_derived_per_tenant_and_subject() -> None:
    first = iam.principal_ref_for_subject("alpha", "user:alice")
    assert first == iam.principal_ref_for_subject("alpha", "user:alice")
    assert first.startswith("incident-principal-") and len(first) == len("incident-principal-") + 32
    assert iam.principal_ref_for_subject("beta", "user:alice") != first
    assert iam.principal_ref_for_subject("alpha", "user:bob") != first


def test_a_matter_naming_the_uploader_refuses_their_attachment_delete_and_keeps_it(held_store):
    s = held_store
    with tenant_scope(tenant="alpha"):
        created = _create(s.store, s.incident, s.document)
        _matter(s.ledger)
        with pytest.raises(iam.IncidentAttachmentConflict) as refused:
            s.store.delete_attachment("alpha", created.attachment_id,
                                      expected_revision=created.revision, idempotency_key="delete-held")
        assert str(refused.value) == ediscovery_module().LEGAL_HOLD_MESSAGE
        assert s.store.get_attachment("alpha", created.attachment_id).status == "active"
        refusals = [payload for verb, payload in s.events if verb == "ediscovery_erasure_refused"]
        assert refusals and refusals[-1]["attachments"] == 1
        assert "alice" not in json.dumps(refusals) and "incident-report" not in json.dumps(refusals)


def test_a_matter_naming_the_uploader_refuses_their_attachment_rebind_and_keeps_the_binding(held_store):
    s = held_store
    with tenant_scope(tenant="alpha"):
        created = _create(s.store, s.incident, s.document)
        _matter(s.ledger)
        s.incident["revision"] = 4
        s.incident["sha256"] = _digest("incident-v4")
        s.document["revision"] = 8
        s.document["authority_sha256"] = _digest("document-authority-v8")
        s.document["content_sha256"] = _digest("replacement-content")
        s.document["safe_display_name"] = "replacement.pdf"
        with pytest.raises(iam.IncidentAttachmentConflict) as refused:
            s.store.update_attachment(
                "alpha",
                created.attachment_id,
                expected_revision=created.revision,
                incident_revision=4,
                incident_sha256=_digest("incident-v4"),
                document_revision=8,
                document_authority_sha256=_digest("document-authority-v8"),
                sha256=_digest("replacement-content"),
                redaction_state="redacted",
                idempotency_key="rebind-held",
            )
        assert str(refused.value) == ediscovery_module().LEGAL_HOLD_MESSAGE
        kept = s.store.get_attachment("alpha", created.attachment_id)
        assert kept.revision == created.revision
        assert kept.sha256 == created.sha256
        assert kept.safe_display_name == "incident-report.pdf"
        assert kept.redaction_state == created.redaction_state
        assert len(s.store.history("alpha", created.attachment_id)) == 1
        refusals = [payload for verb, payload in s.events if verb == "ediscovery_erasure_refused"]
        assert refusals and refusals[-1]["attachments"] == 1


@pytest.mark.parametrize("overrides", [
    {"date_from": "2001-01-01", "date_to": "2001-01-02"},   # the attachment is outside the dates
    {"custodians": ["user:bob"]},                           # another person is named
    {"record_kinds": ["goals", "chats"]},                   # attachments are not among the kinds
])
def test_a_matter_outside_the_attachment_scope_leaves_the_delete_alone(held_store, overrides):
    s = held_store
    with tenant_scope(tenant="alpha"):
        created = _create(s.store, s.incident, s.document)
        _matter(s.ledger, **overrides)
        deleted = s.store.delete_attachment("alpha", created.attachment_id,
                                            expected_revision=created.revision, idempotency_key="delete-free")
        assert deleted.status == "tombstoned"


def test_a_released_matter_no_longer_refuses_the_attachment_delete(held_store):
    from maverick import ediscovery

    s = held_store
    with tenant_scope(tenant="alpha"):
        created = _create(s.store, s.incident, s.document)
        matter = _matter(s.ledger)
        ediscovery.MatterStore(s.ledger).release("alpha", matter["id"], actor="auditor", expected_revision=1)
        deleted = s.store.delete_attachment("alpha", created.attachment_id,
                                            expected_revision=created.revision, idempotency_key="delete-released")
        assert deleted.status == "tombstoned"


def test_retention_purge_keeps_a_held_attachment_until_the_matter_is_released(held_store):
    from maverick import ediscovery

    s = held_store
    with tenant_scope(tenant="alpha"):
        created = _create(s.store, s.incident, s.document)
        deleted = s.store.delete_attachment("alpha", created.attachment_id,
                                            expected_revision=created.revision, idempotency_key="delete-first")
        matter = _matter(s.ledger)
        s.clock[0] += 3_601
        assert s.store.retention_due("alpha") == (deleted,)
        assert s.store.purge_expired("alpha") == 0
        assert s.store.get_attachment("alpha", created.attachment_id).status == "tombstoned"
        ediscovery.MatterStore(s.ledger).release("alpha", matter["id"], actor="auditor", expected_revision=1)
        assert s.store.purge_expired("alpha") == 1
        assert s.store.get_attachment("alpha", created.attachment_id).status == "purged"


def test_an_unreadable_matter_ledger_refuses_the_attachment_delete(held_store):
    s = held_store
    with tenant_scope(tenant="alpha"):
        created = _create(s.store, s.incident, s.document)
        s.ledger.write_bytes(b"not a matter ledger")
        with pytest.raises(iam.IncidentAttachmentConflict) as refused:
            s.store.delete_attachment("alpha", created.attachment_id,
                                      expected_revision=created.revision, idempotency_key="delete-unverified")
        assert str(refused.value) == ediscovery_module().HOLD_UNVERIFIED_MESSAGE
        assert s.store.get_attachment("alpha", created.attachment_id).status == "active"


def test_matter_scope_and_export_list_the_uploaders_attachment_metadata_only(held_store, tmp_path):
    from maverick import ediscovery, ediscovery_export
    from maverick.world_model import WorldModel

    s = held_store
    with tenant_scope(tenant="alpha"):
        mine = _create(s.store, s.incident, s.document)
        other_store = iam.IncidentAttachmentStore(
            tenant_id="alpha",
            principal_ref=iam.principal_ref_for_subject("alpha", "user:bob"),
            principal_resolver=lambda: iam.principal_ref_for_subject("alpha", "user:bob"),
            incident_authority_resolver=s.store._incident_resolver,
            document_authority_resolver=s.store._document_resolver,
            maintenance_authorizer=lambda: True,
            config_gate=lambda: None,
            clock=lambda: s.clock[0],
        )
        _create(other_store, s.incident, s.document, key="bob-upload")
        matter = _matter(s.ledger, date_from=None, date_to=None)
        with WorldModel(tmp_path / "world.db") as world:
            scope = ediscovery.build_scope(world, matter)
            assert [row.attachment_id for row in scope.incident_attachments] == [mine.attachment_id]
            result = ediscovery_export.export_matter(world, matter, actor="auditor", out_dir=tmp_path / "exports")
        import zipfile

        with zipfile.ZipFile(result["path"]) as archive:
            rows = [json.loads(line) for line in archive.read("attachments.jsonl").splitlines()]
        incident_rows = [row for row in rows if row["record_type"] == "incident_attachment"]
        assert [row["attachment_id"] for row in incident_rows] == [mine.attachment_id]
        assert set(incident_rows[0]) <= {
            "record_type", "attachment_id", "incident_kind", "incident_id", "incident_revision",
            "document_id", "document_revision", "safe_display_name", "media_type", "byte_size", "sha256",
            "redaction_state", "status", "created_at", "updated_at", "tombstoned_at", "purged_at",
            "uploader_ref", "retained_until"}
        assert "uploader_ref" in incident_rows[0] and incident_rows[0]["uploader_ref"] == s.alice


def test_a_matter_scope_lists_incident_attachments_only_in_the_matters_own_workspace(held_store, tmp_path):
    from maverick import ediscovery
    from maverick.world_model import WorldModel

    s = held_store
    with tenant_scope(tenant="alpha"):
        _create(s.store, s.incident, s.document)
        matter = _matter(s.ledger)
    with tenant_scope(tenant="beta"), WorldModel(tmp_path / "world.db") as world:
        with pytest.raises(ediscovery.MatterScopeUnverifiable):
            ediscovery.build_scope(world, matter)
        # An erasure does not list incident attachments, so the workspace check does not apply to it.
        assert ediscovery.build_scope(world, matter, for_erasure=True).incident_attachments == []


def ediscovery_module():
    from maverick import ediscovery

    return ediscovery
