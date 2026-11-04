from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from maverick import consent_custom_index as indexes
from maverick_dashboard import consent_custom_index_composition as composition

TENANT = "tenant-a"


def _config(
    *,
    enabled: bool = True,
    profile_enabled: bool = True,
    key_version: int = 1,
    max_indexes: int = 2,
    max_page_size: int = 1,
    retention_seconds: int = 86_400,
) -> dict[str, object]:
    return {
        "consent_preferences": {
            "enable": True,
            "profile_data": {
                "enable": profile_enabled,
                "custom_index": {
                    "enable": enabled,
                    "key_secret_ref": "MAVERICK_CONSENT_CUSTOM_INDEX_KEY",
                    "key_version": key_version,
                    "max_indexes": max_indexes,
                    "max_page_size": max_page_size,
                    "retention_seconds": retention_seconds,
                },
            },
        }
    }


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


def _prepare_source(path: Path, *, second_element: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    definitions = [
        {"preference_id": "loyalty-tier", "value_type": "single_select"}
    ]
    if second_element:
        definitions.append(
            {"preference_id": "support-plan", "value_type": "single_select"}
        )
    catalog = {
        "tenant_id": TENANT,
        "catalog_id": "catalog-1",
        "version": 1,
        "state": "published",
        "definitions": definitions,
    }
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
        connection.execute(
            "INSERT INTO catalogs VALUES(?,?,?,?,?)",
            (TENANT, "catalog-1", 1, _canonical(catalog), _digest(catalog)),
        )


def _write_value(path: Path, profile_id: str, value: str) -> None:
    payload = {
        "tenant_id": TENANT,
        "profile_id": profile_id,
        "preference_id": "loyalty-tier",
        "status": "active",
        "value": value,
        "revision": 1,
        "expires_at": None,
    }
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO profile_values VALUES(?,?,?,?,?)",
            (
                TENANT,
                profile_id,
                "loyalty-tier",
                _canonical(payload),
                _digest(payload),
            ),
        )


def _request(app: FastAPI, subject: str = "user:admin") -> Request:
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/consent/custom-indexes",
            "raw_path": b"/api/v1/consent/custom-indexes",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )
    request.state.principal = SimpleNamespace(principal=subject)
    return request


def test_settings_are_exact_default_off_and_server_owned() -> None:
    assert composition.consent_custom_index_settings({}) is None
    assert composition.consent_custom_index_settings(_config(enabled=False)) is None
    settings = composition.consent_custom_index_settings(_config())
    assert settings == composition.ConsentCustomIndexSettings(
        key_secret_ref="MAVERICK_CONSENT_CUSTOM_INDEX_KEY",
        key_version=1,
        max_indexes=2,
        max_page_size=1,
        retention_seconds=86_400,
    )
    with pytest.raises(composition.ConsentCustomIndexCompositionError, match="require"):
        composition.consent_custom_index_settings(_config(profile_enabled=False))
    invalid = _config()
    invalid["consent_preferences"]["profile_data"]["custom_index"]["raw_key"] = "bad"  # type: ignore[index]
    with pytest.raises(composition.ConsentCustomIndexCompositionError, match="unknown"):
        composition.consent_custom_index_settings(invalid)
    with pytest.raises(composition.ConsentCustomIndexCompositionError, match="max_page"):
        composition.consent_custom_index_settings(_config(max_page_size=501))


def test_install_is_lazy_idempotent_and_does_not_read_secret_or_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    calls = {"config": 0, "path": 0, "secret": 0}

    def no_config(_tenant: str):
        calls["config"] += 1
        raise AssertionError("installation read configuration")

    def no_path(**_kwargs):
        calls["path"] += 1
        raise AssertionError("installation resolved a path")

    def no_secret(**_kwargs):
        calls["secret"] += 1
        raise AssertionError("installation read custody")

    monkeypatch.setattr(composition, "_load_tenant_config", no_config)
    app.state.consent_custom_index_store_path_factory = no_path
    app.state.consent_custom_index_key_resolver = no_secret
    composition.install_consent_custom_index_composition(app)
    seams = (
        "consent_custom_index_store_factory",
        "consent_custom_index_enabled_probe",
        "consent_custom_index_readiness_probe",
        "consent_custom_index_store_path_factory",
        "consent_custom_index_key_resolver",
    )
    first = {name: getattr(app.state, name) for name in seams}
    assert all(callable(value) for value in first.values())
    composition.install_consent_custom_index_composition(app)
    assert {name: getattr(app.state, name) for name in seams} == first
    assert calls == {"config": 0, "path": 0, "secret": 0}


def test_readiness_requires_exact_gates_source_schema_and_key_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = {"config": _config()}
    path = tmp_path / "consent-profile-data.sqlite3"
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: selected["config"],
    )
    app = FastAPI()
    app.state.consent_custom_index_store_path_factory = lambda **_kwargs: path
    composition.install_consent_custom_index_composition(app)

    monkeypatch.delenv("MAVERICK_CONSENT_CUSTOM_INDEX_KEY", raising=False)
    assert app.state.consent_custom_index_enabled_probe(TENANT) is True
    assert app.state.consent_custom_index_readiness_probe(TENANT) is False

    monkeypatch.setenv("MAVERICK_CONSENT_CUSTOM_INDEX_KEY", "k" * 48)
    assert app.state.consent_custom_index_readiness_probe(TENANT) is False
    _prepare_source(path)
    assert app.state.consent_custom_index_readiness_probe(TENANT) is True

    selected["config"] = _config(enabled=False)
    assert app.state.consent_custom_index_enabled_probe(TENANT) is False
    assert app.state.consent_custom_index_readiness_probe(TENANT) is False


def test_runtime_uses_server_key_version_retention_quota_and_page_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(max_indexes=1, max_page_size=1, retention_seconds=86_400)
    path = tmp_path / "consent-profile-data.sqlite3"
    _prepare_source(path, second_element=True)
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: config)
    monkeypatch.setenv("MAVERICK_CONSENT_CUSTOM_INDEX_KEY", "root-secret-" * 4)
    app = FastAPI()
    app.state.consent_custom_index_store_path_factory = lambda **_kwargs: path
    composition.install_consent_custom_index_composition(app)
    request = _request(app)
    principal = composition._principal_ref_from_request(request, TENANT)
    runtime = app.state.consent_custom_index_store_factory(
        tenant_id=TENANT,
        principal_ref=principal,
        request=request,
    )

    pending = runtime.create_index(
        TENANT,
        index_id="loyalty-index",
        element_name="loyalty-tier",
        idempotency_key="create-index-0001",
    )
    assert pending.key_version == 1
    assert 86_300 <= pending.retained_until - pending.created_at <= 86_500
    replay = runtime.create_index(
        TENANT,
        index_id="loyalty-index",
        element_name="loyalty-tier",
        idempotency_key="create-index-0001",
    )
    assert replay == pending
    with pytest.raises(indexes.ConsentCustomIndexConflict, match="quota"):
        runtime.create_index(
            TENANT,
            index_id="support-index",
            element_name="support-plan",
            idempotency_key="create-index-0002",
        )

    _write_value(path, "profile-a", "gold")
    _write_value(path, "profile-b", "gold")
    ready = runtime.build_index(
        TENANT,
        "loyalty-index",
        expected_revision=1,
        idempotency_key="build-index-0001",
    )
    assert ready.state == "ready"
    page = runtime.search(TENANT, "loyalty-index", value="gold", limit=500)
    assert page.profile_ids == ("profile-a",)
    assert page.next_cursor == "profile-a"
    listed, next_cursor = runtime.list_indexes_page(TENANT, limit=500)
    assert len(listed) == 1
    assert next_cursor is None
    assert runtime.verify_integrity(TENANT)["ok"] is True


def test_principal_and_tenant_are_independently_rechecked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "consent-profile-data.sqlite3"
    _prepare_source(path)
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    monkeypatch.setenv("MAVERICK_CONSENT_CUSTOM_INDEX_KEY", "root-secret-" * 4)
    app = FastAPI()
    app.state.consent_custom_index_store_path_factory = lambda **_kwargs: path
    composition.install_consent_custom_index_composition(app)
    request = _request(app)
    with pytest.raises(indexes.ConsentCustomIndexPermissionDenied):
        app.state.consent_custom_index_store_factory(
            tenant_id=TENANT,
            principal_ref="consent-index-admin-attacker",
            request=request,
        )

    principal = composition._principal_ref_from_request(request, TENANT)
    runtime = app.state.consent_custom_index_store_factory(
        tenant_id=TENANT,
        principal_ref=principal,
        request=request,
    )
    request.state.principal = SimpleNamespace(principal="user:changed")
    with pytest.raises(indexes.ConsentCustomIndexPermissionDenied):
        runtime.create_index(
            TENANT,
            index_id="loyalty-index",
            element_name="loyalty-tier",
            idempotency_key="create-index-0001",
        )
    with pytest.raises(composition.ConsentCustomIndexCompositionError):
        runtime.get_index("tenant-b", "loyalty-index")
