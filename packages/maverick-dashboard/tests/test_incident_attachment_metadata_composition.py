from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from maverick import administration_document_access as document_access
from maverick.paths import tenant_scope
from maverick_dashboard import governed_document_vault_composition as vault_composition
from maverick_dashboard import incident_attachment_metadata_composition as composition


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _request(app: FastAPI, subject: str = "operator@example.test") -> Request:
    request = Request(
        {
            "type": "http",
            "app": app,
            "method": "POST",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("127.0.0.1", 80),
            "client": ("testclient", 50000),
            "scheme": "http",
        }
    )
    request.state.principal = SimpleNamespace(sub=subject)
    return request


def _settings() -> composition.IncidentAttachmentSettings:
    return composition.IncidentAttachmentSettings(
        retention_seconds=3_600,
        attachment_ttl_seconds=600,
        max_attachments=100,
        allowed_media_types=("application/pdf",),
    )


def test_settings_are_default_off_and_closed():
    assert composition.incident_attachment_settings({}) is None
    assert composition.incident_attachment_settings(
        {"incident_attachment_metadata": {"enable": False}}
    ) is None
    settings = composition.incident_attachment_settings(
        {"incident_attachment_metadata": {"enable": True}}
    )
    assert settings is not None
    assert settings.max_attachments == 100_000
    assert "application/pdf" in settings.allowed_media_types

    with pytest.raises(composition.IncidentAttachmentCompositionError, match="unknown"):
        composition.incident_attachment_settings(
            {"incident_attachment_metadata": {"enable": True, "bucket": "caller"}}
        )
    with pytest.raises(
        composition.IncidentAttachmentCompositionError,
        match="product allowlist",
    ):
        composition.incident_attachment_settings(
            {
                "incident_attachment_metadata": {
                    "enable": True,
                    "allowed_media_types": ["application/x-msdownload"],
                }
            }
        )


def test_attach_is_lazy_and_preserves_deployment_document_factory(monkeypatch):
    app = FastAPI()
    touched = []

    def document_factory(_tenant, _request):
        touched.append("document")
        return lambda *_args: None

    app.state.administration_document_access_document_resolver_factory = document_factory
    app.state.administration_document_access_enabled_probe = lambda _tenant: True
    app.state.administration_document_access_document_custody_probe = (
        lambda _tenant: True
    )
    app.state.incident_attachment_metadata_custody_probe = lambda _tenant: True
    app.state.governed_document_vault_enabled_probe = lambda _tenant: False
    composition.attach_incident_attachment_metadata_composition(app)

    assert callable(app.state.incident_attachment_metadata_enabled_probe)
    assert callable(app.state.incident_attachment_metadata_readiness_probe)
    assert callable(app.state.incident_attachment_metadata_store_factory)
    assert callable(app.state.incident_attachment_metadata_projection_factory)
    assert (
        app.state.administration_document_access_document_resolver_factory
        is document_factory
    )
    assert touched == []

    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    assert composition.incident_attachment_metadata_readiness(app, "alpha") is True
    assert touched == []


def test_readiness_requires_and_exercises_both_custody_probes(monkeypatch):
    app = FastAPI()
    calls: list[tuple[str, str]] = []

    def document_factory(*_args):
        return lambda *_more: None

    app.state.administration_document_access_document_resolver_factory = (
        document_factory
    )
    app.state.administration_document_access_enabled_probe = lambda _tenant: True
    app.state.administration_document_access_document_custody_probe = (
        lambda tenant: calls.append(("document", tenant)) or True
    )
    app.state.incident_attachment_metadata_custody_probe = (
        lambda tenant: calls.append(("metadata", tenant)) or True
    )
    composition.attach_incident_attachment_metadata_composition(app)
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())

    assert composition.incident_attachment_metadata_readiness(app, "alpha") is True
    assert calls == [("document", "alpha"), ("metadata", "alpha")]

    del app.state.administration_document_access_document_custody_probe
    assert composition.incident_attachment_metadata_readiness(app, "alpha") is False


def test_stock_resolver_readiness_requires_enabled_vault(monkeypatch):
    app = FastAPI()
    app.state.administration_document_access_enabled_probe = lambda _tenant: True
    monkeypatch.setattr(
        vault_composition,
        "_load_tenant_config",
        lambda _tenant: {"governed_document_vault": {"enable": False}},
    )
    vault_composition.attach_governed_document_vault_composition(app)
    composition.attach_incident_attachment_metadata_composition(app)
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())

    assert (
        app.state.administration_document_access_document_resolver_factory
        is app.state.governed_document_vault_stock_document_resolver_factory
    )
    assert composition.incident_attachment_metadata_readiness(app, "alpha") is False


def test_store_factory_binds_existing_incident_and_document_authorities(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    incident_record = {
        "id": "INC-one",
        "revision": 5,
        "status": "open",
        "created_at": 1_800_000_000.0,
        "timeline": [],
    }
    monkeypatch.setattr(
        composition,
        "_load_incident_record",
        lambda tenant, kind, incident_id: dict(incident_record),
    )
    document = document_access.DocumentAuthority(
        tenant_id="alpha",
        principal_ref="placeholder",
        document_ref="DOC-one",
        product_area="privacy_automation",
        record_type="incident-evidence",
        safe_display_name="evidence.pdf",
        media_type="application/pdf",
        byte_size=321,
        content_sha256=_digest("content"),
        authority_revision=9,
        authority_sha256=_digest("document-authority"),
        download_allowed=True,
    )
    app = FastAPI()
    request = _request(app)
    principal = composition.principal_ref_from_request(request, "alpha")

    def document_factory(tenant_id, selected_request):
        assert tenant_id == "alpha" and selected_request is request

        def resolve(tenant, principal_ref, document_ref):
            assert tenant == "alpha" and document_ref == "DOC-one"
            return document_access.DocumentAuthority(
                tenant_id=tenant,
                principal_ref=principal_ref,
                document_ref=document.document_ref,
                product_area=document.product_area,
                record_type=document.record_type,
                safe_display_name=document.safe_display_name,
                media_type=document.media_type,
                byte_size=document.byte_size,
                content_sha256=document.content_sha256,
                authority_revision=document.authority_revision,
                authority_sha256=document.authority_sha256,
                download_allowed=document.download_allowed,
            )

        return resolve

    app.state.administration_document_access_document_resolver_factory = document_factory
    app.state.incident_attachment_metadata_clock = time.time
    store = composition.incident_attachment_metadata_store_factory(
        app,
        tenant_id="alpha",
        principal_ref=principal,
        request=request,
    )
    incident_sha = composition.incident_record_sha256(incident_record)
    with tenant_scope(tenant="alpha"):
        created = store.create_attachment(
            "alpha",
            incident_kind="privacy",
            incident_id="INC-one",
            incident_revision=5,
            incident_sha256=incident_sha,
            document_id="DOC-one",
            document_revision=9,
            document_authority_sha256=document.authority_sha256,
            sha256=document.content_sha256,
            idempotency_key="compose-one",
        )
        response_hook = composition.incident_attachment_projection_factory(
            app,
            tenant_id="alpha",
            principal_ref=principal,
            request=request,
        )
        response = response_hook(incident_record, "privacy")

    assert created.safe_display_name == "evidence.pdf"
    assert created.principal_ref == principal
    assert response["attachments"][0]["attachment_id"] == created.attachment_id
    assert response["attachment_metadata"]["incident_sha256"] == incident_sha


def test_request_and_principal_cannot_be_replayed_across_apps(monkeypatch):
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    first = FastAPI()
    second = FastAPI()
    request = _request(first)
    principal = composition.principal_ref_from_request(request, "alpha")
    second.state.administration_document_access_document_resolver_factory = (
        lambda *_args: lambda *_more: None
    )
    with pytest.raises(composition.IncidentAttachmentCompositionError, match="request"):
        composition.incident_attachment_metadata_store_factory(
            second,
            tenant_id="alpha",
            principal_ref=principal,
            request=request,
        )


def _readiness_app() -> FastAPI:
    app = FastAPI()
    app.state.administration_document_access_document_resolver_factory = (
        lambda *_args: lambda *_more: None
    )
    app.state.administration_document_access_enabled_probe = lambda _tenant: True
    app.state.administration_document_access_document_custody_probe = (
        lambda _tenant: True
    )
    composition.attach_incident_attachment_metadata_composition(app)
    return app


def test_stock_metadata_custody_probe_rejects_corruption_without_repair(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    app = _readiness_app()

    assert composition.incident_attachment_metadata_readiness(app, "alpha") is True
    with tenant_scope(tenant="alpha"):
        from maverick.file_lock import atomic_create_text
        from maverick.paths import data_dir

        record_path = data_dir("incident_attachment_metadata") / "IAT-corrupt.json"
        atomic_create_text(record_path, '{"id":"IAT-corrupt","revision":1}')
    before = record_path.read_bytes()

    assert composition.incident_attachment_metadata_readiness(app, "alpha") is False
    assert record_path.read_bytes() == before
    assert not list(record_path.parent.glob(".readiness-*.tmp"))


def test_stock_metadata_custody_probe_rejects_unwritable_store_without_record(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    from maverick import file_lock

    monkeypatch.setattr(
        file_lock,
        "atomic_create_bytes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("denied")),
    )
    app = _readiness_app()

    assert composition.incident_attachment_metadata_readiness(app, "alpha") is False
    assert not list(tmp_path.rglob("IAT-*.json"))
    assert not list(tmp_path.rglob(".readiness-*.tmp"))


def test_readiness_opens_incident_authorities_and_fails_on_unreadable_store(
    monkeypatch,
):
    monkeypatch.setattr(composition, "settings_for_tenant", lambda _tenant: _settings())
    app = FastAPI()
    app.state.administration_document_access_document_resolver_factory = (
        lambda *_args: lambda *_more: None
    )
    app.state.administration_document_access_enabled_probe = lambda _tenant: True
    app.state.administration_document_access_document_custody_probe = (
        lambda _tenant: True
    )
    app.state.incident_attachment_metadata_custody_probe = lambda _tenant: True
    composition.attach_incident_attachment_metadata_composition(app)
    from maverick import privacy_ops

    monkeypatch.setattr(
        privacy_ops._INCIDENT,  # noqa: SLF001
        "list_bounded",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError("unreadable")),
    )

    assert composition.incident_attachment_metadata_readiness(app, "alpha") is False


def test_uploader_reference_is_the_one_a_legal_matter_names() -> None:
    from maverick import incident_attachment_metadata as iam

    request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(principal="user:alice")))
    uploader = composition.principal_ref_from_request(request, "alpha")
    assert uploader == iam.principal_ref_for_subject("alpha", "user:alice")
    assert uploader != composition.principal_ref_from_request(request, "beta")
