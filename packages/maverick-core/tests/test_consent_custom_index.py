from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from maverick.consent_custom_index import (
    ConsentCustomIndexConflict,
    ConsentCustomIndexIntegrityError,
    ConsentCustomIndexNotFound,
    ConsentCustomIndexStore,
    ConsentCustomIndexValidationError,
    custom_index_enabled,
)

TENANT = "tenant-alpha"
NOW = 2_000_000_000.0
KEY = b"consent-custom-index-test-key-32-bytes-minimum"


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _prepare_source(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE catalogs(
                tenant_id TEXT NOT NULL,catalog_id TEXT NOT NULL,version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                PRIMARY KEY(tenant_id,catalog_id,version)
            );
            CREATE TABLE profile_values(
                tenant_id TEXT NOT NULL,profile_id TEXT NOT NULL,preference_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                PRIMARY KEY(tenant_id,profile_id,preference_id)
            );
            """
        )
        catalog = {
            "tenant_id": TENANT,
            "catalog_id": "catalog-1",
            "version": 1,
            "state": "published",
            "definitions": [
                {
                    "preference_id": "loyalty-tier",
                    "value_type": "single_select",
                }
            ],
        }
        connection.execute(
            "INSERT INTO catalogs VALUES(?,?,?,?,?)",
            (TENANT, "catalog-1", 1, _canonical(catalog), _digest(catalog)),
        )


def _store(path: Path, *, tenant: str = TENANT) -> ConsentCustomIndexStore:
    return ConsentCustomIndexStore(
        path,
        key_resolver=lambda resolved_tenant, version: (
            KEY if resolved_tenant == tenant and version == 1 else b""
        ),
        config_gate=lambda: None,
        principal_resolver=lambda: "admin-1",
        clock=lambda: NOW,
    )


def _write_value(path: Path, profile_id: str, value: str, revision: int = 1) -> None:
    payload = {
        "tenant_id": TENANT,
        "profile_id": profile_id,
        "preference_id": "loyalty-tier",
        "status": "active",
        "value": value,
        "revision": revision,
        "expires_at": None,
    }
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO profile_values VALUES(?,?,?,?,?) "
            "ON CONFLICT(tenant_id,profile_id,preference_id) DO UPDATE SET "
            "payload_json=excluded.payload_json,integrity_sha256=excluded.integrity_sha256",
            (
                TENANT,
                profile_id,
                "loyalty-tier",
                _canonical(payload),
                _digest(payload),
            ),
        )


def test_index_lifecycle_exact_search_staleness_and_rebuild(tmp_path: Path) -> None:
    path = tmp_path / "profiles.sqlite3"
    _prepare_source(path)
    store = _store(path)

    pending = store.create_index(
        TENANT,
        index_id="loyalty-index",
        element_name="loyalty-tier",
        key_version=1,
        retention_seconds=86_400,
        idempotency_key="create-index-0001",
    )
    assert pending.state == "pending"
    assert pending.revision == 1

    _write_value(path, "profile-a", "gold")
    _write_value(path, "profile-b", "gold")
    _write_value(path, "profile-c", "silver")
    ready = store.build_index(
        TENANT,
        "loyalty-index",
        expected_revision=1,
        idempotency_key="build-index-0001",
    )
    assert ready.state == "ready"
    assert ready.entry_count == 3
    assert ready.source_records_sha256 is not None

    first = store.search(TENANT, "loyalty-index", value="gold", limit=1)
    assert first.profile_ids == ("profile-a",)
    assert first.next_cursor == "profile-a"
    second = store.search(
        TENANT,
        "loyalty-index",
        value="gold",
        limit=1,
        cursor=first.next_cursor,
    )
    assert second.profile_ids == ("profile-b",)
    assert second.next_cursor is None

    _write_value(path, "profile-b", "silver", revision=2)
    assert store.get_index(TENANT, "loyalty-index").state == "stale"
    with pytest.raises(ConsentCustomIndexConflict, match="stale"):
        store.search(TENANT, "loyalty-index", value="gold")

    rebuilt = store.build_index(
        TENANT,
        "loyalty-index",
        expected_revision=2,
        idempotency_key="build-index-0002",
    )
    assert rebuilt.revision == 3
    assert store.search(TENANT, "loyalty-index", value="gold").profile_ids == (
        "profile-a",
    )
    assert store.verify_integrity(TENANT)["ok"] is True


def test_index_idempotency_revoke_and_closed_inputs(tmp_path: Path) -> None:
    path = tmp_path / "profiles.sqlite3"
    _prepare_source(path)
    store = _store(path)
    kwargs = {
        "index_id": "loyalty-index",
        "element_name": "loyalty-tier",
        "key_version": 1,
        "retention_seconds": 86_400,
        "idempotency_key": "create-index-0001",
    }
    created = store.create_index(TENANT, **kwargs)
    assert store.create_index(TENANT, **kwargs) == created
    with pytest.raises(ConsentCustomIndexConflict, match="different request"):
        store.create_index(TENANT, **{**kwargs, "retention_seconds": 172_800})
    with pytest.raises(ConsentCustomIndexNotFound):
        store.create_index(
            TENANT,
            index_id="missing-element-index",
            element_name="not-published",
            key_version=1,
            retention_seconds=86_400,
            idempotency_key="create-index-0002",
        )
    with pytest.raises(ConsentCustomIndexValidationError):
        store.search(TENANT, "loyalty-index", value={"free": "form"})

    revoked = store.revoke_index(
        TENANT,
        "loyalty-index",
        expected_revision=1,
        idempotency_key="revoke-index-001",
    )
    assert revoked.state == "revoked"
    with pytest.raises(ConsentCustomIndexConflict, match="not ready"):
        store.search(TENANT, "loyalty-index", value="gold")


def test_integrity_and_tenant_boundaries_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "profiles.sqlite3"
    _prepare_source(path)
    store = _store(path)
    store.create_index(
        TENANT,
        index_id="loyalty-index",
        element_name="loyalty-tier",
        key_version=1,
        retention_seconds=86_400,
        idempotency_key="create-index-0001",
    )
    _write_value(path, "profile-a", "gold")
    store.build_index(
        TENANT,
        "loyalty-index",
        expected_revision=1,
        idempotency_key="build-index-0001",
    )

    with pytest.raises(ConsentCustomIndexNotFound):
        store.get_index("tenant-bravo", "loyalty-index")
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE consent_custom_index_entries SET integrity_sha256=?",
            ("0" * 64,),
        )
    with pytest.raises(ConsentCustomIndexIntegrityError):
        store.verify_integrity(TENANT)


def test_non_ascii_stored_digests_are_refused_not_type_errors(tmp_path: Path) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest instead
    # of the idempotency conflict and integrity refusals.
    path = tmp_path / "profiles.sqlite3"
    _prepare_source(path)
    store = _store(path)
    kwargs = {
        "index_id": "loyalty-index",
        "element_name": "loyalty-tier",
        "key_version": 1,
        "retention_seconds": 86_400,
        "idempotency_key": "create-index-0001",
    }
    store.create_index(TENANT, **kwargs)
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM consent_custom_index_operations").fetchone()
        body = {
            "tenant_id": row["tenant_id"],
            "operation_sha256": row["operation_sha256"],
            "request_sha256": "é" * 64,
            "result_id": row["result_id"],
        }
        connection.execute(
            "UPDATE consent_custom_index_operations SET request_sha256=?,integrity_sha256=?",
            ("é" * 64, _digest(body)),
        )
    with pytest.raises(ConsentCustomIndexConflict, match="different request"):
        store.create_index(TENANT, **kwargs)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE consent_custom_indexes SET integrity_sha256=?", ("é" * 64,))
    with pytest.raises(ConsentCustomIndexIntegrityError):
        store.get_index(TENANT, "loyalty-index")


def test_exact_config_gates() -> None:
    complete = {
        "consent_preferences": {
            "enable": True,
            "profile_data": {
                "enable": True,
                "custom_index": {"enable": True},
            },
        }
    }
    assert custom_index_enabled(complete) is True
    assert custom_index_enabled({}) is False
    complete["consent_preferences"]["profile_data"]["custom_index"]["enable"] = "true"
    assert custom_index_enabled(complete) is False
