from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick.ai_identity_governance_controls import (
    AgentPrincipalAuthority,
    AgentPrincipalFederationBinding,
    CapabilityRule,
)
from maverick.paths import tenant_scope
from maverick_dashboard import identity_governance_composition as composition
from maverick_dashboard import identity_governance_runtime as runtime


def _section(*, conditional: bool = True, production: bool = True):
    return {
        "enable": True,
        "entra": {"enable": True},
        "purview": {"enable": False},
        "scheduler": {
            "enable": True,
            "providers": {"entra": {"enable": True}},
        },
        "controls": {
            "enable": True,
            "production": {
                "enable": production,
                "mapping_revision": 2,
                "mapping_retention_seconds": 600,
                "max_authority_records": 100,
                "max_observation_age_seconds": 300,
                "max_future_skew_seconds": 30,
                "purview_max_attempts": 3,
                "purview_operation_lease_seconds": 60,
            },
            "change_coupling": {
                "enable": True,
                "dynamic_risk": True,
                "alerts": True,
            },
            "federation": {"enable": True},
            "conditional_access": {"enable": conditional},
            "purview_writeback": {"enable": False},
        },
    }


class Registry:
    def __init__(self, tenant_sha256: str) -> None:
        self.tenant_sha256 = tenant_sha256
        self.authority = AgentPrincipalAuthority(
            tenant_sha256=tenant_sha256,
            principal_ref="prn_" + ("a" * 32),
            authority_binding_sha256="b" * 64,
            revision=1,
        )
        self.binding = AgentPrincipalFederationBinding.bind(
            self.authority,
            provider="entra",
            provider_subject_id="sub_" + ("c" * 32),
        )
        self.rule = CapabilityRule(
            tenant_sha256=tenant_sha256,
            provider="entra",
            permission_id="prm_" + ("d" * 32),
            capabilities=("agent.execute",),
            revision=1,
        )
        self.mappings = {}

    def resolve_authority(self, tenant_sha256, principal_ref):
        if tenant_sha256 == self.tenant_sha256 and principal_ref == self.authority.principal_ref:
            return self.authority
        return None

    def resolve_federation_binding(self, tenant_sha256, principal_ref, provider):
        if (
            tenant_sha256 == self.tenant_sha256
            and principal_ref == self.authority.principal_ref
            and provider == "entra"
        ):
            return self.binding
        return None

    def resolve_purview_asset(self, *_args):
        return None

    def capability_rules(self):
        return (self.rule,)

    def store(self, mapping):
        self.mappings[mapping.mapping_sha256] = mapping
        return True

    def get(self, tenant_sha256, principal_ref, mapping_sha256):
        mapping = self.mappings.get(mapping_sha256)
        if (
            mapping is not None
            and tenant_sha256 == self.tenant_sha256
            and principal_ref == mapping.principal_ref
        ):
            return mapping
        return None

    def status(self):
        return {
            "schema": "lightwork.identity_governance.authority-registry-status.v1",
            "tenant_sha256": self.tenant_sha256,
            "counts": {
                "agent_authority": 1,
                "federation_binding": 1,
                "capability_rule": 1,
                "purview_asset_binding": 0,
                "capability_mapping": 0,
            },
            "purview_authority_ready": False,
            "live_acceptance_verified": False,
        }


class FederationTransport:
    provider = "entra"
    dns_pinned = True
    redirects_followed = False

    def __init__(self, tenant_sha256: str) -> None:
        self.tenant_sha256 = tenant_sha256
        self.calls = 0

    def observe(self, _request):
        self.calls += 1
        raise AssertionError("runtime construction must not perform provider I/O")


class ConditionalTransport(FederationTransport):
    pass


def test_production_settings_are_closed_and_default_off():
    assert composition.production_settings({}).enabled is False
    selected = composition.production_settings(_section())
    assert selected.enabled is True
    assert selected.mapping_revision == 2
    invalid = _section()
    invalid["controls"]["production"]["max_authority_records"] = 0
    with pytest.raises(composition.IdentityGovernanceCompositionError):
        composition.production_settings(invalid)


def test_readiness_never_invokes_provider_factories(monkeypatch):
    calls = []
    app = SimpleNamespace(state=SimpleNamespace())

    def must_not_run(**_kwargs):
        calls.append(True)
        raise AssertionError("readiness must not construct a provider transport")

    app.state.identity_governance_federation_transport_factory = must_not_run
    app.state.identity_governance_conditional_access_transport_factory = must_not_run
    monkeypatch.setattr(
        composition,
        "_registry",
        lambda _tenant, _settings: Registry("e" * 64),
    )
    app.state.identity_governance_control_runtime_factory = lambda *_args: None
    with tenant_scope(tenant="alpha"):
        status = composition.identity_governance_composition_readiness(
            app,
            tenant_id="alpha",
            section=_section(),
        )

    assert calls == []
    assert status["configured"] is False
    assert status["dependencies"]["asset_binding_authority"] is False
    assert status["dependencies"]["dynamic_risk_feature"] is False
    assert status["status_invoked_provider_io"] is False
    assert status["status_resolved_credentials"] is False
    assert status["provider_writes_possible"] is False


def test_runtime_factory_is_fresh_tenant_exact_and_uses_pinned_contracts(monkeypatch):
    app = SimpleNamespace(state=SimpleNamespace())
    built = []

    def federation_factory(**kwargs):
        built.append(("federation", kwargs))
        return FederationTransport(kwargs["tenant_sha256"])

    def conditional_factory(**kwargs):
        built.append(("conditional", kwargs))
        return ConditionalTransport(kwargs["tenant_sha256"])

    app.state.identity_governance_federation_transport_factory = federation_factory
    app.state.identity_governance_conditional_access_transport_factory = conditional_factory
    registries = []

    def registry_factory(_tenant, _settings):
        selected = Registry(composition.scheduler.tenant_binding_sha256(require_explicit=True))
        registries.append(selected)
        return selected

    monkeypatch.setattr(composition, "_registry", registry_factory)
    with tenant_scope(tenant="alpha"):
        first = composition.build_identity_governance_control_runtime(
            app,
            tenant_id="alpha",
            request=object(),
            section=_section(),
        )
        second = composition.build_identity_governance_control_runtime(
            app,
            tenant_id="alpha",
            request=object(),
            section=_section(),
        )
        with pytest.raises(
            composition.IdentityGovernanceCompositionError,
            match="tenant scope does not match",
        ):
            composition.build_identity_governance_control_runtime(
                app,
                tenant_id="beta",
                request=object(),
                section=_section(),
            )

    assert first is not second
    assert len(registries) == 2
    assert first.status()["provider_writes_possible"] is False
    assert first.status()["attachment"] == "lazy_per_request_tenant_runtime_factory"
    assert [name for name, _kwargs in built] == [
        "federation",
        "conditional",
        "federation",
        "conditional",
    ]
    assert all(item[1]["tenant_id"] == "alpha" for item in built)
    assert all(item[1]["provider"] == "entra" for item in built)


def test_scheduler_composition_attaches_durable_handoff_sinks():
    with tenant_scope(tenant="alpha"):
        engine = composition._scheduler_engine(_section())

    assert engine is not None
    callback = engine._change_callback
    assert callback is not None
    assert callback.status()["configured_sinks"] == ["alert", "dynamic_risk"]
    assert callback.status()["risk_score_generated"] is False
    assert callback._sinks["dynamic_risk"].status()["outcome_mode"] == (
        "dynamic_risk_signal_and_score"
    )
    assert callback.status()["asset_binding_resolver_attached"] is True


def test_attach_installs_factories_without_loading_config_or_state(monkeypatch):
    app = SimpleNamespace(state=SimpleNamespace())
    installed = []
    monkeypatch.setattr(
        composition.scheduler,
        "install_composed_engine_factory",
        lambda factory: installed.append(factory),
    )
    monkeypatch.setattr(
        composition,
        "_load_tenant_section",
        lambda _tenant: (_ for _ in ()).throw(
            AssertionError("attach must stay lazy")
        ),
    )

    composition.attach_identity_governance_composition(app)

    assert callable(app.state.identity_governance_control_runtime_factory)
    assert callable(app.state.identity_governance_control_readiness_probe)
    assert callable(app.state.identity_governance_authority_registry_factory)
    assert len(installed) == 1


def test_model_risk_runtime_resolver_prefers_production_factory(monkeypatch):
    from maverick_dashboard import model_risk_api

    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    captured = []
    with tenant_scope(tenant="alpha"):
        tenant_sha256 = composition.scheduler.tenant_binding_sha256(
            require_explicit=True
        )
    selected = runtime.IdentityGovernanceControlRuntime(
        tenant_sha256=tenant_sha256,
        authority_resolver=lambda *_args: None,
        federation_adapters={},
    )
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                identity_governance_control_runtime_factory=(
                    lambda tenant, supplied_request: captured.append(
                        (tenant, supplied_request)
                    )
                    or selected
                )
            )
        )
    )

    resolved = model_risk_api._identity_control_runtime(
        request,
        _section(conditional=False),
    )

    assert resolved is selected
    assert captured == [("alpha", request)]
