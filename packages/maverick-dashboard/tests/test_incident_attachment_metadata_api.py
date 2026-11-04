from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import incident_attachment_metadata as iam
from maverick.paths import tenant_scope
from maverick_dashboard.incident_attachment_metadata_api import (
    IncidentAttachmentDependencies,
    create_incident_attachment_metadata_router,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _principal_ref(subject: str = "operator@example.test") -> str:
    digest = hashlib.sha256(
        f"lightwork.incident-attachment.identity.v1:alpha:{subject}".encode()
    ).hexdigest()
    return f"incident-principal-{digest[:32]}"


def _projection(attachment_id: str = "IAT-" + "a" * 32) -> dict[str, object]:
    return {
        "schema": iam.PROJECTION_SCHEMA,
        "attachment_id": attachment_id,
        "document_id": "DOC-one",
        "safe_display_name": "report.pdf",
        "media_type": "application/pdf",
        "byte_size": 123,
        "sha256": _digest("content"),
        "redaction_state": "unreviewed",
        "status": "active",
        "authority_state": "active",
        "incident_revision": 4,
        "incident_sha256": _digest("incident"),
        "document_revision": 2,
        "document_authority_sha256": _digest("document-authority"),
        "created_at": 1_800_000_000.0,
        "updated_at": 1_800_000_000.0,
        "expires_at": 1_800_000_600.0,
        "retained_until": 1_900_000_000.0,
        "revision": 1,
        "integrity_sha256": _digest("integrity"),
    }


class _Store:
    tenant_id = "alpha"
    principal_ref = _principal_ref()
    backend_kind = "local"

    def __init__(self):
        self.calls = []
        self.record = SimpleNamespace(
            incident_kind="privacy",
            incident_id="INC-one",
            attachment_id="IAT-" + "a" * 32,
        )

    def create_attachment(self, tenant, **kwargs):
        self.calls.append(("create", tenant, kwargs))
        return self.record

    def update_attachment(self, tenant, attachment_id, **kwargs):
        self.calls.append(("update", tenant, attachment_id, kwargs))
        return self.record

    def delete_attachment(self, tenant, attachment_id, **kwargs):
        self.calls.append(("delete", tenant, attachment_id, kwargs))
        return self.record

    def get_attachment(self, tenant, attachment_id):
        self.calls.append(("get", tenant, attachment_id))
        return self.record

    def list_for_incident(self, tenant, kind, incident_id, **kwargs):
        self.calls.append(("list", tenant, kind, incident_id, kwargs))
        return (self.record,)

    def history(self, tenant, attachment_id):
        self.calls.append(("history", tenant, attachment_id))
        return (
            {
                "schema": iam.HISTORY_SCHEMA,
                "event_type": "created",
                "revision": 1,
                "actor_ref": self.principal_ref,
                "created_at": 1_800_000_000.0,
                "changes_sha256": _digest("changes"),
                "previous_event_sha256": None,
                "event_sha256": _digest("event"),
            },
        )

    def projection(self, record):
        assert record is self.record
        return _projection(record.attachment_id)

    def verify_integrity(self, tenant):
        return {"schema": iam.INTEGRITY_SCHEMA, "ok": True, "tenant": tenant}

    def purge_expired(self, tenant, *, limit):
        self.calls.append(("purge", tenant, limit))
        return 2


def _app(*, enabled=True, ready=True, store=None):
    selected = store or _Store()
    dependencies = IncidentAttachmentDependencies(
        enabled_probe=lambda _tenant: enabled,
        readiness_probe=lambda _tenant: ready,
        store_factory=lambda **_kwargs: selected,
    )
    app = FastAPI()

    @app.middleware("http")
    async def bind_principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub="operator@example.test")
        return await call_next(request)

    app.include_router(
        create_incident_attachment_metadata_router(dependencies),
        prefix="/api/v1",
    )
    return app, selected


def _create_body() -> dict[str, object]:
    return {
        "incident_revision": 4,
        "incident_sha256": _digest("incident"),
        "document_id": "DOC-one",
        "document_revision": 2,
        "document_authority_sha256": _digest("document-authority"),
        "sha256": _digest("content"),
        "redaction_state": "unreviewed",
        "idempotency_key": "create-one",
    }


def test_status_is_explicit_about_default_off_and_external_gaps():
    app, _store = _app(enabled=False, ready=False)
    client = TestClient(app, base_url="http://127.0.0.1")
    with tenant_scope(tenant="alpha"):
        response = client.get(
            "/api/v1/incident-attachments/status",
            headers={"Origin": "http://127.0.0.1"},
        )
    assert response.status_code == 200
    assert response.json() == {
        "schema": "lightwork.incident-attachment-status.v1",
        "enabled": False,
        "configured": True,
        "ready": False,
        "metadata_only": True,
        "object_store_operational": False,
        "relying_workflow_accepted": False,
    }
    assert response.headers["cache-control"].startswith("no-store")


def test_enabled_but_unready_mutation_fails_closed():
    app, _store = _app(enabled=True, ready=False)
    client = TestClient(app, base_url="http://127.0.0.1")
    with tenant_scope(tenant="alpha"):
        response = client.post(
            "/api/v1/incident-attachments/privacy/INC-one",
            json=_create_body(),
            headers={"Origin": "http://127.0.0.1"},
        )
    assert response.status_code == 503
    assert "readiness" in response.json()["detail"]


def test_create_accepts_only_closed_references_and_returns_projection():
    app, store = _app()
    client = TestClient(app, base_url="http://127.0.0.1")
    with tenant_scope(tenant="alpha"):
        rejected = client.post(
            "/api/v1/incident-attachments/privacy/INC-one",
            json={**_create_body(), "safe_display_name": "caller-name.pdf"},
            headers={"Origin": "http://127.0.0.1"},
        )
        response = client.post(
            "/api/v1/incident-attachments/privacy/INC-one",
            json=_create_body(),
            headers={"Origin": "http://127.0.0.1"},
        )
    assert rejected.status_code == 422
    assert response.status_code == 201
    assert response.json()["safe_display_name"] == "report.pdf"
    assert response.json()["authority_state"] == "active"
    assert response.headers["x-content-type-options"] == "nosniff"
    operation, tenant, kwargs = store.calls[-1]
    assert operation == "create" and tenant == "alpha"
    assert kwargs["incident_id"] == "INC-one"
    assert kwargs["document_id"] == "DOC-one"
    assert "safe_display_name" not in kwargs
    assert "path" not in kwargs and "bytes" not in kwargs


def test_get_path_binding_and_history_are_strict():
    app, store = _app()
    client = TestClient(app, base_url="http://127.0.0.1")
    attachment_id = store.record.attachment_id
    with tenant_scope(tenant="alpha"):
        wrong = client.get(
            f"/api/v1/incident-attachments/security/INC-one/{attachment_id}",
            headers={"Origin": "http://127.0.0.1"},
        )
        history = client.get(
            f"/api/v1/incident-attachments/privacy/INC-one/{attachment_id}/history",
            headers={"Origin": "http://127.0.0.1"},
        )
    assert wrong.status_code == 404
    assert history.status_code == 200
    assert history.json()["count"] == 1
    assert history.json()["events"][0]["event_type"] == "created"


def test_core_conflicts_map_to_http_409():
    class ConflictStore(_Store):
        def create_attachment(self, tenant, **kwargs):
            raise iam.IncidentAttachmentConflict("incident revision or digest changed")

    app, _store = _app(store=ConflictStore())
    client = TestClient(app, base_url="http://127.0.0.1")
    with tenant_scope(tenant="alpha"):
        response = client.post(
            "/api/v1/incident-attachments/privacy/INC-one",
            json=_create_body(),
            headers={"Origin": "http://127.0.0.1"},
        )
    assert response.status_code == 409
    assert response.json()["detail"] == "incident revision or digest changed"


def test_the_api_names_the_uploader_with_the_stores_own_reference():
    from maverick_dashboard import incident_attachment_metadata_api as api

    request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(sub="operator@example.test")))
    decomposed = "josé-workspace"  # the store keeps the composed (NFC) form of a tenant name
    composed = "josé-workspace"
    expected = iam.principal_ref_for_subject(composed, "operator@example.test")
    assert api._principal(request, decomposed) == expected
    assert api._principal(request, composed) == expected
    with pytest.raises(HTTPException) as unavailable:  # a trailing dot is not a workspace the store can name
        api._principal(request, "workspace.")
    assert unavailable.value.status_code == 503
