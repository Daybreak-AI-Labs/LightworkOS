from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from maverick_dashboard.incident_attachment_projection import (
    project_incident_record,
    project_incident_records,
)
from starlette.requests import Request


def _request(app: FastAPI) -> Request:
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "https",
            "path": "/api/v1/privacy/incidents",
            "raw_path": b"/api/v1/privacy/incidents",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )
    request.state.principal = SimpleNamespace(principal="operator@example.test")
    return request


def test_disabled_projection_preserves_legacy_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    app = FastAPI()
    app.state.incident_attachment_metadata_enabled_probe = lambda _tenant: False
    record = {"id": "INC-1", "revision": 1, "title": "Example"}

    assert project_incident_record(_request(app), record, "privacy") == record


def test_enabled_projection_uses_server_principal_and_exact_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    app = FastAPI()
    captured: dict[str, object] = {}
    app.state.incident_attachment_metadata_enabled_probe = lambda tenant: tenant == "tenant-a"
    app.state.incident_attachment_metadata_readiness_probe = lambda tenant: tenant == "tenant-a"

    def factory(**kwargs):
        captured.update(kwargs)

        def project(record, kind):
            captured["kind"] = kind
            return {**record, "attachments": [], "attachment_metadata": {"count": 0}}

        return project

    app.state.incident_attachment_metadata_projection_factory = factory
    request = _request(app)
    projected = project_incident_records(
        request,
        [{"id": "SEC-1", "revision": 2}],
        "security",
    )

    assert projected[0]["attachment_metadata"]["count"] == 0
    assert captured["tenant_id"] == "tenant-a"
    assert str(captured["principal_ref"]).startswith("incident-principal-")
    assert captured["request"] is request
    assert captured["kind"] == "security"


def test_enabled_but_unready_projection_is_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    app = FastAPI()
    app.state.incident_attachment_metadata_enabled_probe = lambda _tenant: True
    app.state.incident_attachment_metadata_readiness_probe = lambda _tenant: False
    app.state.incident_attachment_metadata_projection_factory = lambda **_kwargs: None

    with pytest.raises(HTTPException) as caught:
        project_incident_record(
            _request(app),
            {"id": "INC-1", "revision": 1},
            "privacy",
        )

    assert caught.value.status_code == 503
    assert caught.value.detail == "incident attachment authority is not ready"


def test_stale_incident_projection_maps_to_closed_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    app = FastAPI()
    app.state.incident_attachment_metadata_enabled_probe = lambda _tenant: True
    app.state.incident_attachment_metadata_readiness_probe = lambda _tenant: True

    class IncidentAttachmentConflict(RuntimeError):
        pass

    def factory(**_kwargs):
        def project(_record, _kind):
            raise IncidentAttachmentConflict("private stale detail")

        return project

    app.state.incident_attachment_metadata_projection_factory = factory
    with pytest.raises(HTTPException) as caught:
        project_incident_record(
            _request(app),
            {"id": "INC-1", "revision": 1},
            "privacy",
        )

    assert caught.value.status_code == 409
    assert caught.value.detail == "incident attachment authority changed"
    assert "private stale detail" not in str(caught.value.detail)
