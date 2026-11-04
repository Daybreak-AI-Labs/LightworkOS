from __future__ import annotations

import gc
import sqlite3

import pytest
from maverick import administration_document_access as access
from maverick import governed_document_vault as vault


class Clock:
    def __init__(self, value: float = 1_900_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    clock = Clock()
    config = vault.GovernedDocumentVaultConfig(
        enable=True,
        retention_seconds=60,
        grant_ttl_seconds=30,
        claim_lease_seconds=5,
    )
    authority = vault.GovernedDocumentVault(
        tmp_path / "private" / "vault.sqlite3",
        tenant_id="tenant-a",
        config=config,
        clock=clock,
    )
    return authority, clock


def ingest(store, content: bytes = b"governed evidence"):
    authority, _clock = store
    return authority.ingest(
        content,
        principal_ref="actor-a",
        product_area="privacy_automation",
        record_type="incident_attachment",
        safe_display_name="evidence.pdf",
        media_type="application/pdf",
    )


def claim_for(record, *, principal_ref="principal-a", claim_id="claim-1", now=1_900_000_000.0):
    return access.DeliveryClaim(
        tenant_id="tenant-a",
        principal_ref=principal_ref,
        token_id="token-1",
        claim_id=claim_id,
        document_ref=record.document_ref,
        product_area=record.product_area,
        record_type=record.record_type,
        safe_display_name=record.safe_display_name,
        media_type=record.media_type,
        byte_size=record.byte_size,
        content_sha256=record.content_sha256,
        authority_revision=record.authority_revision,
        authority_sha256=record.authority_sha256,
        grant_expires_at=now + 20,
    )


def test_configuration_is_default_off_and_media_subset_is_closed():
    assert vault.GovernedDocumentVaultConfig.from_mapping({}).enable is False
    with pytest.raises(vault.VaultConfigError, match="media_type_not_approved"):
        vault.GovernedDocumentVaultConfig.from_mapping(
            {
                "governed_document_vault": {
                    "enable": True,
                    "allowed_media_types": ["application/x-executable"],
                }
            }
        )


def test_ingest_seals_bytes_and_resolves_exact_authority(store):
    authority, _clock = store
    record = ingest(store)
    resolved = authority.resolve_authority(
        "tenant-a", "incident-principal-a", record.document_ref
    )

    assert resolved.content_sha256 == record.content_sha256
    assert resolved.authority_revision == 1
    assert resolved.download_allowed is True
    assert authority.context_record_count() == 1
    raw = authority.path.read_bytes()
    assert b"governed evidence" not in raw
    with sqlite3.connect(authority.path) as connection:
        ciphertext = connection.execute(
            "SELECT encrypted_content FROM governed_document_revisions"
        ).fetchone()[0]
    from maverick.crypto_at_rest import is_sealed

    assert is_sealed(bytes(ciphertext)) is True


def test_one_time_grant_streams_content_and_rejects_replay(store):
    authority, _clock = store
    record = ingest(store, b"abcdefgh")
    issued = authority.issue_delivery_grant(claim_for(record))
    payload = authority.consume_delivery_grant(
        issued.grant, principal_ref="principal-a"
    )

    assert b"".join(payload.chunks(4096)) == b"abcdefgh"
    assert payload.media_type == "application/pdf"
    with pytest.raises(vault.VaultConflict, match="replayed"):
        authority.consume_delivery_grant(
            issued.grant, principal_ref="principal-a"
        )


def test_grant_is_principal_bound_and_raw_values_are_not_persisted(store):
    authority, _clock = store
    record = ingest(store)
    issued = authority.issue_delivery_grant(claim_for(record))

    with pytest.raises(vault.VaultPermissionDenied, match="binding"):
        authority.consume_delivery_grant(issued.grant, principal_ref="principal-b")
    persisted = authority.path.read_bytes()
    assert issued.grant.encode() not in persisted
    assert b"principal-a" not in persisted
    assert b"actor-a" not in persisted


def test_revoke_invalidates_authority_and_outstanding_grant(store):
    authority, _clock = store
    record = ingest(store)
    issued = authority.issue_delivery_grant(claim_for(record))
    revoked = authority.revoke(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=record.authority_revision,
    )

    assert revoked.state == "revoked"
    assert revoked.authority_revision == 2
    assert authority.resolve_authority(
        "tenant-a", "principal-a", record.document_ref
    ).download_allowed is False
    with pytest.raises(vault.VaultConflict, match="replayed"):
        authority.consume_delivery_grant(issued.grant, principal_ref="principal-a")


def test_listing_reads_document_heads_once_and_preserves_order_filters_limits(store, monkeypatch):
    authority, clock = store
    records = []
    for index in range(12):
        records.append(ingest(store, f"evidence {index}".encode()))
        clock.advance(1)
    authority.revoke(records[3].document_ref, principal_ref="actor-a", expected_revision=1)
    queries = []
    connect = authority._connect

    def traced_connect(**kwargs):
        connection = connect(**kwargs)
        connection.set_trace_callback(queries.append)
        return connection

    monkeypatch.setattr(authority, "_connect", traced_connect)
    listed = authority.list_documents(state="active", limit=7)
    assert [record.document_ref for record in listed] == [
        record.document_ref for record in reversed(records[5:])
    ]
    head_reads = [query for query in queries if "SELECT" in query.upper()
                  and "FROM GOVERNED_DOCUMENTS" in query.upper()]
    assert len(head_reads) == 1
    assert "BEGIN" in queries and "COMMIT" in queries
    assert [record.document_ref for record in authority.list_documents(state="revoked")] == [
        records[3].document_ref
    ]
    assert len(authority.list_documents()) == 12


def test_listing_ties_are_deterministic_and_tampering_fails_closed(store):
    authority, _clock = store
    records = [ingest(store) for _ in range(3)]
    assert [record.document_ref for record in authority.list_documents()] == sorted(
        record.document_ref for record in records
    )
    with sqlite3.connect(authority.path) as connection:
        connection.execute("UPDATE governed_documents SET safe_display_name='tampered.pdf' WHERE document_ref=?",
                           (records[1].document_ref,))
    with pytest.raises(vault.VaultIntegrityError, match="document_integrity_invalid"):
        authority.list_documents()
    with pytest.raises(vault.VaultIntegrityError, match="document_integrity_invalid"):
        authority.get(records[1].document_ref)


def test_listing_retains_selected_snapshot_while_fresh_authority_observes_revoke(store, monkeypatch):
    authority, _clock = store
    records = [ingest(store) for _ in range(3)]
    validate = authority._validate_document_row
    revoked = False

    def revoke_during_validation(row):
        nonlocal revoked
        if not revoked:
            revoked = True
            authority.revoke(records[-1].document_ref, principal_ref="actor-a", expected_revision=1)
        validate(row)

    monkeypatch.setattr(authority, "_validate_document_row", revoke_during_validation)
    listed = authority.list_documents(state="active")
    assert {record.document_ref for record in listed} == {record.document_ref for record in records}
    assert all(record.state == "active" and record.authority_revision == 1 for record in listed)
    current = authority.resolve_authority("tenant-a", "principal-a", records[-1].document_ref)
    assert current.download_allowed is False
    assert current.authority_revision == 2


def test_claim_recovery_restores_only_an_unexpired_stale_lease(store, monkeypatch):
    authority, clock = store
    record = ingest(store)
    issued = authority.issue_delivery_grant(claim_for(record))
    grant_sha = vault._grant_sha256(issued.grant)  # noqa: SLF001
    now = clock()
    lease_sha = "f" * 64
    with authority._transaction() as connection:  # noqa: SLF001
        row = authority._grant_on(connection, grant_sha)  # noqa: SLF001
        updated = dict(row)
        updated.update(
            state="claimed",
            revision=2,
            claimed_at=now,
            lease_sha256=lease_sha,
            lease_until=now + 5,
        )
        updated.pop("row_sha256")
        connection.execute(
            """UPDATE governed_document_grants SET state='claimed',revision=2,
            claimed_at=?,lease_sha256=?,lease_until=?,row_sha256=? WHERE grant_sha256=?""",
            (
                now,
                lease_sha,
                now + 5,
                vault.canonical_sha256(authority._grant_material(updated)),  # noqa: SLF001
                grant_sha,
            ),
        )
    clock.advance(6)

    assert authority.reconcile() == {"expired": 0, "recovered": 1, "purged": 0}
    assert authority.consume_delivery_grant(
        issued.grant, principal_ref="principal-a"
    ).content == b"governed evidence"


def test_reconcile_limit_is_not_starved_by_non_due_terminal_grants(store):
    authority, clock = store
    record = ingest(store)
    retained = authority.issue_delivery_grant(
        claim_for(record, claim_id="claim-retained", now=clock())
    )
    authority.consume_delivery_grant(
        retained.grant,
        principal_ref="principal-a",
    )
    clock.advance(1)
    due = authority.issue_delivery_grant(
        claim_for(record, claim_id="claim-due", now=clock())
    )
    due_sha = vault._grant_sha256(due.grant)  # noqa: SLF001
    clock.advance(21)

    assert authority.reconcile(limit=1) == {
        "expired": 1,
        "recovered": 0,
        "purged": 0,
    }
    with sqlite3.connect(authority.path) as connection:
        assert connection.execute(
            "SELECT state FROM governed_document_grants WHERE grant_sha256=?",
            (due_sha,),
        ).fetchone()[0] == "expired"


def test_retention_purge_removes_ciphertext_and_leaves_tombstone(store):
    authority, clock = store
    record = ingest(store)
    revoked = authority.revoke(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=1,
    )
    clock.advance(61)
    tombstone = authority.purge_document(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=revoked.authority_revision,
    )

    assert tombstone["schema"] == "lightwork.governed-document-tombstone.v1"
    with pytest.raises(vault.VaultNotFound):
        authority.get(record.document_ref)
    assert authority.context_record_count() == 0
    with sqlite3.connect(authority.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM governed_document_revisions"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM governed_document_tombstones"
        ).fetchone()[0] == 1
    integrity = authority.verify_integrity()
    assert integrity["integrity_anchors"] == 3
    assert integrity["authority_revisions"] == 0


def test_integrity_detects_ciphertext_tampering(store):
    authority, _clock = store
    ingest(store)
    assert authority.verify_integrity()["ok"] is True
    with sqlite3.connect(authority.path) as connection:
        connection.execute(
            "UPDATE governed_document_revisions SET encrypted_content=?",
            (b"tampered",),
        )
        connection.commit()

    with pytest.raises(vault.VaultIntegrityError, match="content_integrity"):
        authority.verify_integrity()


def test_integrity_detects_authority_history_tampering(store):
    authority, _clock = store
    ingest(store)
    assert authority.verify_integrity()["authority_revisions"] == 1
    with sqlite3.connect(authority.path) as connection:
        connection.execute(
            "UPDATE governed_document_authorities SET state='revoked'"
        )
        connection.commit()

    with pytest.raises(vault.VaultIntegrityError, match="authority_integrity"):
        authority.verify_integrity()


def test_integrity_detects_deleted_authority_revision_from_immutable_anchor(store):
    authority, _clock = store
    record = ingest(store)
    authority.revoke(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=1,
    )
    with sqlite3.connect(authority.path) as connection:
        connection.execute(
            "DELETE FROM governed_document_authorities "
            "WHERE document_ref=? AND authority_revision=1",
            (record.document_ref,),
        )
        connection.commit()

    with pytest.raises(vault.VaultIntegrityError, match="authority_completeness"):
        authority.verify_integrity()


def test_integrity_anchor_is_immutable_and_terminal_deletion_is_detected(store):
    authority, _clock = store
    ingest(store)
    with sqlite3.connect(authority.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM governed_document_integrity_anchors WHERE sequence=1"
            )
        connection.rollback()
        connection.execute("DROP TRIGGER governed_document_anchor_no_delete")
        connection.execute(
            "DELETE FROM governed_document_integrity_anchors WHERE sequence=1"
        )
        connection.commit()

    with pytest.raises(vault.VaultIntegrityError, match="completeness_state"):
        authority.verify_integrity()


def test_integrity_detects_tombstone_tampering(store):
    authority, clock = store
    record = ingest(store)
    revoked = authority.revoke(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=record.authority_revision,
    )
    clock.advance(61)
    authority.purge_document(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=revoked.authority_revision,
    )
    assert authority.verify_integrity()["tombstones"] == 1
    with sqlite3.connect(authority.path) as connection:
        connection.execute(
            "UPDATE governed_document_tombstones SET final_content_sha256=?",
            ("f" * 64,),
        )
        connection.commit()

    with pytest.raises(vault.VaultIntegrityError, match="tombstone_integrity"):
        authority.verify_integrity()


def test_integrity_detects_deleted_tombstone_from_purge_anchor(store):
    authority, clock = store
    record = ingest(store)
    revoked = authority.revoke(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=record.authority_revision,
    )
    clock.advance(61)
    authority.purge_document(
        record.document_ref,
        principal_ref="actor-a",
        expected_revision=revoked.authority_revision,
    )
    with sqlite3.connect(authority.path) as connection:
        connection.execute("DELETE FROM governed_document_tombstones")
        connection.commit()

    with pytest.raises(vault.VaultIntegrityError, match="tombstone_completeness"):
        authority.verify_integrity()


def test_operational_probe_requires_existing_intact_writable_vault(store, tmp_path):
    authority, _clock = store
    ingest(store)
    before = authority.verify_integrity(verify_content=False)

    probed = vault.GovernedDocumentVault.operational_probe(
        authority.path,
        tenant_id="tenant-a",
        config=authority.config,
    )

    assert probed == before
    with pytest.raises(vault.VaultConfigError, match="store_unavailable"):
        vault.GovernedDocumentVault.operational_probe(
            tmp_path / "absent.sqlite3",
            tenant_id="tenant-a",
            config=authority.config,
        )


def test_operational_probe_fails_closed_when_write_transaction_is_unavailable(
    store,
    monkeypatch,
):
    authority, _clock = store
    ingest(store)
    connect = sqlite3.connect

    def readonly_only(database, *args, **kwargs):
        if kwargs.get("uri") is not True:
            raise sqlite3.OperationalError("readonly")
        return connect(database, *args, **kwargs)

    monkeypatch.setattr(vault.sqlite3, "connect", readonly_only)
    with pytest.raises(vault.VaultIntegrityError, match="store_invalid"):
        vault.GovernedDocumentVault.operational_probe(
            authority.path,
            tenant_id="tenant-a",
            config=authority.config,
        )


def test_schema_v1_upgrade_backfills_and_seals_completeness_anchors(store):
    authority, clock = store
    ingest(store)
    with sqlite3.connect(authority.path) as connection:
        meta = connection.execute(
            "SELECT tenant_sha256,created_at FROM governed_document_vault_meta"
        ).fetchone()
        legacy_meta = {
            "schema": "lightwork.governed-document-vault-meta.v1",
            "schema_version": 1,
            "tenant_sha256": meta[0],
            "created_at": meta[1],
        }
        connection.execute("DROP TABLE governed_document_integrity_anchors")
        connection.execute("DROP TABLE governed_document_integrity_state")
        connection.execute(
            "UPDATE governed_document_vault_meta "
            "SET schema_version=1,integrity_sha256=?",
            (vault.canonical_sha256(legacy_meta),),
        )
        connection.commit()

    upgraded = vault.GovernedDocumentVault(
        authority.path,
        tenant_id="tenant-a",
        config=authority.config,
        clock=clock,
    )

    assert upgraded.verify_integrity()["integrity_anchors"] == 1
    with sqlite3.connect(authority.path) as connection:
        assert connection.execute(
            "SELECT schema_version FROM governed_document_vault_meta"
        ).fetchone()[0] == 2
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM governed_document_integrity_anchors"
            )


def test_cross_tenant_resolution_fails_closed(store):
    authority, _clock = store
    record = ingest(store)
    with pytest.raises(vault.VaultNotFound):
        authority.resolve_authority(
            "tenant-b", "principal-a", record.document_ref
        )


def test_non_ascii_tenant_resolution_is_not_found_not_type_error(store):
    # Tenant ids may be any Unicode text; another tenant's name is a miss.
    authority, _clock = store
    record = ingest(store)
    with pytest.raises(vault.VaultNotFound):
        authority.resolve_authority(
            "tenant-é", "principal-a", record.document_ref
        )


def test_historical_metadata_window_reaches_past_recent_five_hundred(store):
    authority, clock = store
    oldest = ingest(store)
    for _ in range(500):
        clock.advance(1)
        ingest(store)
    assert oldest.document_ref not in {row.document_ref for row in authority.list_documents(limit=500)}
    page = authority.history_window(offset=500)
    assert [row.document_ref for row in page.rows] == [oldest.document_ref]
    assert page.next_offset is None
    assert authority.history_window(oldest=True).rows[0].document_ref == oldest.document_ref
    exact = authority.history_window(after=oldest.created_at, before=oldest.created_at + 1)
    assert len(exact.rows) == 1
    before = authority.history_window(oldest=True).snapshot
    authority.revoke(oldest.document_ref, principal_ref="actor-a", expected_revision=oldest.authority_revision)
    assert before != authority.history_window(oldest=True).snapshot


def _assert_closed(connections):
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_every_vault_connection_is_closed_when_its_call_returns(tmp_path, monkeypatch):
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    opened = []
    real_connect = sqlite3.connect
    fail_pragma = {"on": True}

    class _PragmaFails(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA foreign_keys=ON" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_PragmaFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(vault.sqlite3, "connect", recording_connect)
    clock = Clock()
    config = vault.GovernedDocumentVaultConfig(
        enable=True,
        retention_seconds=60,
        grant_ttl_seconds=30,
        claim_lease_seconds=5,
    )

    def build():
        return vault.GovernedDocumentVault(
            tmp_path / "private" / "vault.sqlite3",
            tenant_id="tenant-a",
            config=config,
            clock=clock,
        )

    gc.disable()
    try:
        with pytest.raises(vault.VaultIntegrityError):
            build()
        fail_pragma["on"] = False
        before = len(opened)
        authority = build()
        assert len(opened) > before, "__init__"
        _assert_closed(opened[before:])
        before = len(opened)
        record = ingest((authority, clock))
        assert len(opened) > before, "ingest"
        _assert_closed(opened[before:])
        calls = [
            ("get", lambda: authority.get(record.document_ref)),
            ("list_documents", authority.list_documents),
            ("history_window", authority.history_window),
            ("context_record_count", authority.context_record_count),
            ("list_audit", authority.list_audit),
            ("verify_integrity", authority.verify_integrity),
        ]
        for name, call in calls:
            before = len(opened)
            call()
            assert len(opened) > before, name
            _assert_closed(opened[before:])
    finally:
        gc.enable()
    _assert_closed(opened)
