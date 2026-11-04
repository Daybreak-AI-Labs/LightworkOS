"""Lazy composition/readiness tests for document access."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import administration_document_access as access
from maverick_dashboard import administration_document_access_composition as composition


def _config(enabled=True):
    return {
        "administration_document_access": {
            "enable": enabled,
            "default_ttl_seconds": 30,
            "max_ttl_seconds": 120,
            "max_uses": 2,
            "delivery_grant_ttl_seconds": 10,
            "retention_seconds": 60,
        }
    }


def _resolver(tenant_id, principal_ref, document_ref):
    return access.DocumentAuthority(
        tenant_id=tenant_id,
        principal_ref=principal_ref,
        document_ref=document_ref,
        product_area="administration",
        record_type="document_attachment",
        safe_display_name="attachment.pdf",
        media_type="application/pdf",
        byte_size=10,
        content_sha256="a" * 64,
        authority_revision=1,
        authority_sha256="b" * 64,
        download_allowed=True,
    )


def _issuer(claim):
    return access.DeliveryGrant(
        grant="composition_grant_" + "x" * 40,
        expires_at=claim.grant_expires_at,
    )


def test_attach_is_lazy_and_readiness_does_not_invoke_external_factories(monkeypatch):
    calls = {"config": 0, "resolver": 0, "issuer": 0}

    def load(_tenant):
        calls["config"] += 1
        return _config()

    monkeypatch.setattr(composition, "_load_tenant_config", load)
    app = FastAPI()

    def resolver_factory(_tenant, _request):
        calls["resolver"] += 1
        return _resolver

    def issuer_factory(_tenant, _request):
        calls["issuer"] += 1
        return _issuer

    app.state.administration_document_access_document_resolver_factory = resolver_factory
    app.state.administration_document_access_delivery_grant_issuer_factory = issuer_factory
    composition.attach_administration_document_access_composition(app)
    assert calls == {"config": 0, "resolver": 0, "issuer": 0}

    readiness = app.state.administration_document_access_readiness_probe(
        "tenant-a",
        SimpleNamespace(),
    )
    assert readiness["configured"] is True
    assert readiness["ready"] is False
    assert readiness["status_probe_opened_store"] is False
    assert readiness["status_probe_invoked_external_dependency"] is False
    assert calls == {"config": 1, "resolver": 0, "issuer": 0}


def test_attached_factory_fails_closed_when_authorities_are_absent(monkeypatch):
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    composition.attach_administration_document_access_composition(app)
    readiness = app.state.administration_document_access_readiness_probe(
        "tenant-a",
        SimpleNamespace(),
    )
    assert readiness["enabled"] is True
    assert readiness["configured"] is False
    with pytest.raises(access.DocumentAccessConfigError, match="resolver_unavailable"):
        app.state.administration_document_access_service_factory(
            "tenant-a",
            "principal.alice",
            SimpleNamespace(),
        )


def test_disabled_attached_factory_checks_gate_before_dependencies(monkeypatch):
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(enabled=False),
    )
    app = FastAPI()
    touched = {"resolver": False}

    def resolver_factory(_tenant, _request):
        touched["resolver"] = True
        return _resolver

    app.state.administration_document_access_document_resolver_factory = resolver_factory
    app.state.administration_document_access_delivery_grant_issuer_factory = (
        lambda _tenant, _request: _issuer
    )
    composition.attach_administration_document_access_composition(app)
    with pytest.raises(access.DocumentAccessConfigError, match="disabled"):
        app.state.administration_document_access_service_factory(
            "tenant-a",
            "principal.alice",
            SimpleNamespace(),
        )
    assert touched["resolver"] is False


def test_direct_builder_produces_ready_runtime_with_bounded_limits(tmp_path):
    def clock():
        return 2_000_000_000.0

    service = composition.build_administration_document_access_service(
        tenant_id="tenant-a",
        principal_ref="principal.alice",
        document_resolver=_resolver,
        delivery_grant_issuer=_issuer,
        config=_config(),
        store_path=tmp_path / "document-access.sqlite3",
        clock=clock,
    )
    status = service.status()
    assert status["enabled"] is True
    assert status["configured"] is True
    assert status["ready"] is True
    assert status["limits"]["raw_document_bytes_persisted"] is False
    assert status["limits"]["document_paths_or_urls_persisted"] is False
    assert status["live_relying_workflow_verified"] is False
    assert status["external_object_store_custody_verified"] is False


def test_direct_builder_does_not_create_store_when_gate_is_off(tmp_path):
    path = tmp_path / "must-not-exist.sqlite3"
    with pytest.raises(access.DocumentAccessConfigError, match="disabled"):
        composition.build_administration_document_access_service(
            tenant_id="tenant-a",
            principal_ref="principal.alice",
            document_resolver=_resolver,
            delivery_grant_issuer=_issuer,
            config=_config(enabled=False),
            store_path=path,
        )
    assert not path.exists()
