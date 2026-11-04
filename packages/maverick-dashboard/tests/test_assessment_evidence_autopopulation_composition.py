from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick_dashboard import assessment_evidence_autopopulation_composition as composition


def _config(*, enabled=True, apply_enabled=True):
    return {
        "ai_evidence_analysis": {"enable": True},
        "assessment_evidence_autopopulation": {
            "enable": enabled,
            "apply_enabled": apply_enabled,
            "retention_seconds": 3_600,
            "max_records": 100,
            "max_evidence_records_per_proposal": 4,
            "max_citations_per_answer": 3,
            "min_confidence_bps": 8_000,
        },
    }


def test_settings_are_closed_default_off_and_dependency_bound():
    settings = composition.assessment_evidence_autopopulation_settings(_config())
    assert settings is not None
    assert settings.core.apply_enabled is True
    assert settings.core.max_evidence_records_per_proposal == 4

    disabled = _config(enabled=False)
    assert composition.assessment_evidence_autopopulation_settings(disabled) is None

    missing_evidence = _config()
    missing_evidence["ai_evidence_analysis"] = {"enable": False}
    with pytest.raises(composition.AssessmentEvidenceCompositionError, match="require"):
        composition.assessment_evidence_autopopulation_settings(missing_evidence)

    unknown = _config()
    unknown["assessment_evidence_autopopulation"]["surprise"] = True
    with pytest.raises(composition.AssessmentEvidenceCompositionError, match="unknown"):
        composition.assessment_evidence_autopopulation_settings(unknown)


def test_install_is_lazy_preserves_overrides_and_readiness_opens_no_store(monkeypatch):
    calls = {"store": 0, "external": 0}
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    app.state.ai_evidence_analysis_enabled_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: True

    def store_factory(*_args):
        calls["store"] += 1
        raise AssertionError("readiness opened store")

    app.state.ai_evidence_analysis_store_factory = store_factory
    def override(*_args):
        return "override"
    app.state.assessment_evidence_autopopulation_enabled_probe = override
    composition.install_assessment_evidence_autopopulation_composition(app)

    assert app.state.assessment_evidence_autopopulation_enabled_probe is override
    assert calls == {"store": 0, "external": 0}
    request = SimpleNamespace(app=app, state=SimpleNamespace())
    monkeypatch.setattr(composition, "_request_for", lambda _app, _request: request)
    monkeypatch.setattr(composition, "_subject", lambda _request: "user:reviewer")
    readiness = app.state.assessment_evidence_autopopulation_readiness_probe(
        "tenant-a", request
    )
    assert readiness["ready"] is True
    assert readiness["status_probe_opened_store"] is False
    assert readiness["status_probe_invoked_external_dependency"] is False
    assert calls["store"] == 0


def test_readiness_fails_closed_when_evidence_dependency_is_not_ready(monkeypatch):
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    app.state.ai_evidence_analysis_enabled_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: False
    app.state.ai_evidence_analysis_store_factory = lambda *_args: object()
    composition.install_assessment_evidence_autopopulation_composition(app)
    request = SimpleNamespace(app=app, state=SimpleNamespace())
    monkeypatch.setattr(composition, "_request_for", lambda _app, _request: request)
    monkeypatch.setattr(composition, "_subject", lambda _request: "user:reviewer")

    readiness = app.state.assessment_evidence_autopopulation_readiness_probe(
        "tenant-a", request
    )

    assert readiness["configured"] is True
    assert readiness["evidence_analysis_enabled"] is True
    assert readiness["evidence_analysis_ready"] is False
    assert readiness["ready"] is False


@pytest.mark.parametrize("resolver_result", [object(), None])
def test_readiness_checks_exact_runtime_mapping_factory_result(
    monkeypatch,
    resolver_result,
):
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    app.state.ai_evidence_analysis_enabled_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_store_factory = lambda *_args: object()
    calls = []

    def mapping_factory(tenant_id, request):
        calls.append((tenant_id, request))
        return resolver_result

    app.state.assessment_evidence_mapping_resolver_factory = mapping_factory
    composition.install_assessment_evidence_autopopulation_composition(app)
    request = SimpleNamespace(app=app, state=SimpleNamespace())
    monkeypatch.setattr(composition, "_request_for", lambda _app, _request: request)
    monkeypatch.setattr(composition, "_subject", lambda _request: "user:reviewer")

    readiness = app.state.assessment_evidence_autopopulation_readiness_probe(
        "tenant-a", request
    )

    assert calls == [("tenant-a", request)]
    assert readiness["mapping_resolver_callable"] is False
    assert readiness["configured"] is False
    assert readiness["ready"] is False


def test_readiness_validates_mapping_and_applier_runtime_seams(monkeypatch):
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    app.state.ai_evidence_analysis_enabled_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_store_factory = lambda *_args: object()
    def resolver(*_args):
        return None

    app.state.assessment_evidence_mapping_resolver_factory = (
        lambda _tenant, _request: resolver
    )
    app.state.assessment_evidence_assessment_applier = object()
    composition.install_assessment_evidence_autopopulation_composition(app)
    request = SimpleNamespace(app=app, state=SimpleNamespace())
    monkeypatch.setattr(composition, "_request_for", lambda _app, _request: request)
    monkeypatch.setattr(composition, "_subject", lambda _request: "user:reviewer")

    not_callable = app.state.assessment_evidence_autopopulation_readiness_probe(
        "tenant-a", request
    )
    assert not_callable["mapping_mode"] == "deployment_authority"
    assert not_callable["mapping_resolver_callable"] is True
    assert not_callable["assessment_applier_callable"] is False
    assert not_callable["configured"] is False
    assert not_callable["ready"] is False

    app.state.assessment_evidence_assessment_applier = lambda **_kwargs: None
    ready = app.state.assessment_evidence_autopopulation_readiness_probe(
        "tenant-a", request
    )
    assert ready["assessment_applier_callable"] is True
    assert ready["configured"] is True
    assert ready["ready"] is True


def test_readiness_fails_closed_when_mapping_factory_raises(monkeypatch):
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    app = FastAPI()
    app.state.ai_evidence_analysis_enabled_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_store_factory = lambda *_args: object()

    def raising_factory(_tenant, _request):
        raise RuntimeError("deployment seam failed")

    app.state.assessment_evidence_mapping_resolver_factory = raising_factory
    composition.install_assessment_evidence_autopopulation_composition(app)
    request = SimpleNamespace(app=app, state=SimpleNamespace())
    monkeypatch.setattr(composition, "_request_for", lambda _app, _request: request)
    monkeypatch.setattr(composition, "_subject", lambda _request: "user:reviewer")

    readiness = app.state.assessment_evidence_autopopulation_readiness_probe(
        "tenant-a", request
    )
    assert readiness["configured"] is False
    assert readiness["ready"] is False


def test_installed_factory_fails_closed_before_store_when_disabled(monkeypatch):
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(enabled=False),
    )
    app = FastAPI()
    touched = {"store": False}
    app.state.ai_evidence_analysis_enabled_probe = lambda _tenant: True
    app.state.ai_evidence_analysis_readiness_probe = lambda _tenant: True

    def store_factory(*_args):
        touched["store"] = True

    app.state.ai_evidence_analysis_store_factory = store_factory
    composition.install_assessment_evidence_autopopulation_composition(app)
    request = SimpleNamespace(app=app, state=SimpleNamespace())
    monkeypatch.setattr(composition, "_request_for", lambda _app, _request: request)
    monkeypatch.setattr(composition, "expected_actor_ref", lambda *_args: "actor")
    with pytest.raises(composition.AssessmentEvidenceCompositionError, match="disabled"):
        app.state.assessment_evidence_autopopulation_service_factory(
            "tenant-a", "actor", request
        )
    assert touched["store"] is False


def test_direct_builder_returns_core_service_without_opening_dependencies():
    touched = {"assessment": 0, "evidence": 0}

    def assessment(_identifier):
        touched["assessment"] += 1
        return None

    def evidence(_identifier):
        touched["evidence"] += 1
        return None

    service = composition.build_assessment_evidence_autopopulation_service(
        tenant_id="tenant-a",
        config=_config(),
        assessment_resolver=assessment,
        evidence_resolver=evidence,
    )
    assert service.settings.apply_enabled is True
    assert touched == {"assessment": 0, "evidence": 0}
