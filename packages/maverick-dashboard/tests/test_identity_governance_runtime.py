"""Focused runtime wiring tests for identity-governance connectors."""
from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from maverick.ai_identity_governance_connectors import IdentityGovernanceLimitError
from maverick_dashboard import identity_governance_runtime as runtime


class _Response:
    def __init__(self, body: bytes, *, declared: int | None = None) -> None:
        self.status_code = 200
        self.headers = {"content-type": "application/json", "link": "next"}
        if declared is not None:
            self.headers["content-length"] = str(declared)
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def iter_bytes(self):
        yield self._body


class _Client:
    def __init__(self, response: _Response, calls: list[dict]) -> None:
        self.response = response
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def stream(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


def test_pinned_transport_preserves_closed_request_and_bounded_response(monkeypatch):
    from maverick import enterprise
    from maverick.tools import _ssrf

    calls = []
    response = _Response(b'{"value":[]}', declared=12)
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *_a, **_k: None)
    monkeypatch.setattr(_ssrf, "safe_client", lambda *_a, **_k: _Client(response, calls))

    result = runtime.PinnedIdentityGovernanceHTTPTransport().request(
        "POST",
        "https://account.purview.azure.com/datamap/api/search/query",
        headers={"Authorization": "Bearer transient-secret"},
        json_body={"keywords": None, "limit": 100},
        timeout=12,
        max_response_bytes=1024,
    )
    assert result.final_url == (
        "https://account.purview.azure.com/datamap/api/search/query"
    )
    assert result.body == b'{"value":[]}'
    assert result.headers == {
        "content-type": "application/json",
        "content-length": "12",
        "link": "next",
    }
    assert calls[0]["method"] == "POST"
    assert calls[0]["json"] == {"keywords": None, "limit": 100}


def test_pinned_transport_refuses_oversized_declared_response(monkeypatch):
    from maverick import enterprise
    from maverick.tools import _ssrf

    response = _Response(b"{}", declared=2048)
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *_a, **_k: None)
    monkeypatch.setattr(_ssrf, "safe_client", lambda *_a, **_k: _Client(response, []))
    with pytest.raises(IdentityGovernanceLimitError, match="too_large"):
        runtime.PinnedIdentityGovernanceHTTPTransport().request(
            "GET",
            "https://graph.microsoft.com/v1.0/servicePrincipals",
            headers={},
            json_body=None,
            timeout=12,
            max_response_bytes=1024,
        )


@dataclass
class _Snapshot:
    schema: str = "lightwork.identity_governance.snapshot.v1"
    provider: str = "entra"
    live_acceptance_verified: bool = False
    complete_inventory_claimed: bool = False


class _Adapter:
    provider = "entra"

    def collect(self):
        return _Snapshot()


def test_status_and_collection_never_claim_live_acceptance(monkeypatch):
    monkeypatch.setattr(runtime, "_adapters", lambda _section: (_Adapter(),))
    status = runtime.connector_status({"enable": True})
    assert status["configured_providers"] == ["entra"]
    assert status["live_acceptance_verified"] is False
    assert status["complete_inventory_claimed"] is False
    snapshot = runtime.collect_connector({"enable": True}, "entra")
    assert snapshot["provider"] == "entra"
    assert snapshot["live_acceptance_verified"] is False
    assert snapshot["complete_inventory_claimed"] is False


def _scheduled_section():
    return {
        "enable": True,
        "entra": {
            "enable": True,
            "tenant_id": "raw-tenant@example.invalid",
            "base_url": "https://graph.microsoft.com",
            "credential_secret_ref": "RAW_ENTRA_TOKEN",
        },
        "scheduler": {
            "enable": True,
            "poll_seconds": 60,
            "providers": {"entra": {"enable": True}},
        },
    }


def test_scheduler_metadata_is_removed_only_at_strict_adapter_boundary(monkeypatch):
    captured = []

    def configured(section, **_kwargs):
        captured.append(section)
        return ()

    monkeypatch.setattr(runtime, "configured_connectors", configured)
    runtime._adapters(_scheduled_section())

    assert len(captured) == 1
    assert "scheduler" not in captured[0]
    assert captured[0]["entra"]["credential_secret_ref"] == "RAW_ENTRA_TOKEN"


def _controlled_section():
    section = _scheduled_section()
    section["okta"] = {
        "enable": True,
        "tenant_id": "raw-okta-tenant@example.invalid",
        "base_url": "https://tenant.okta.com",
        "credential_secret_ref": "RAW_OKTA_TOKEN",
    }
    section["purview"] = {
        "enable": True,
        "tenant_id": "raw-purview-tenant@example.invalid",
        "base_url": "https://account.purview.azure.com",
        "credential_secret_ref": "RAW_PURVIEW_TOKEN",
    }
    section["controls"] = {
        "enable": True,
        "change_coupling": {
            "enable": True,
            "dynamic_risk": True,
            "alerts": False,
        },
        "federation": {"enable": True},
        "conditional_access": {"enable": True},
        "purview_writeback": {"enable": True},
    }
    return section


def test_control_metadata_is_removed_at_strict_adapter_boundary(monkeypatch):
    captured = []

    def configured(section, **_kwargs):
        captured.append(section)
        return ()

    monkeypatch.setattr(runtime, "configured_connectors", configured)
    runtime._adapters(_controlled_section())

    assert len(captured) == 1
    assert "scheduler" not in captured[0]
    assert "controls" not in captured[0]
    assert captured[0]["entra"]["credential_secret_ref"] == "RAW_ENTRA_TOKEN"


def test_control_plane_is_default_off_and_reports_no_live_or_write_claims(monkeypatch):
    monkeypatch.setattr(runtime, "_adapters", lambda _section: ())
    disabled = runtime.connector_status({})["control_plane"]
    configured = runtime.connector_status(_controlled_section())["control_plane"]

    assert disabled["enabled"] is False
    assert disabled["default_mode"] == "read_only_off"
    assert configured["configured"] == {
        "change_coupling": True,
        "federation": True,
        "conditional_access": True,
        "purview_writeback": True,
    }
    assert configured["runtime_attached"] is False
    assert configured["contracts_available"]["purview_compensation"] is True
    assert (
        configured["contracts_available"][
            "conditional_access_enforcement_decision"
        ]
        is True
    )
    assert configured["provider_writes"] is False
    assert configured["live_acceptance_verified"] is False


def test_attached_federation_runtime_requires_enrolled_subject_resolver():
    class Adapter:
        provider = "entra"

        def observe(self, *_args, **_kwargs):
            raise AssertionError("construction must not call provider")

        def status(self):
            return {}

    with pytest.raises(TypeError, match="enrolled subject binding resolver"):
        runtime.IdentityGovernanceControlRuntime(
            tenant_sha256="a" * 64,
            authority_resolver=lambda _tenant, _principal: None,
            federation_adapters={"entra": Adapter()},
        )


def test_federation_binding_resolver_is_exact_and_fails_closed():
    from maverick.ai_identity_governance_controls import (
        AgentPrincipalAuthority,
        AgentPrincipalFederationBinding,
        IdentityGovernanceBindingError,
        IdentityGovernanceDeliveryError,
    )

    class Adapter:
        provider = "entra"

        def observe(self, *_args, **_kwargs):
            raise AssertionError("binding admission must not call provider")

        def status(self):
            return {}

    tenant = "a" * 64
    principal = "prn_" + ("b" * 32)
    subject = "sub_" + ("c" * 32)
    authority = AgentPrincipalAuthority(
        tenant_sha256=tenant,
        principal_ref=principal,
        authority_binding_sha256="d" * 64,
        revision=3,
    )

    def bound(
        *,
        selected_tenant=tenant,
        selected_principal=principal,
        selected_provider="entra",
        selected_authority="d" * 64,
        selected_revision=3,
    ):
        selected = AgentPrincipalAuthority(
            tenant_sha256=selected_tenant,
            principal_ref=selected_principal,
            authority_binding_sha256=selected_authority,
            revision=selected_revision,
        )
        return AgentPrincipalFederationBinding.bind(
            selected,
            provider=selected_provider,
            provider_subject_id=subject,
        )

    mismatches = (
        bound(selected_tenant="e" * 64),
        bound(selected_principal="prn_" + ("f" * 32)),
        bound(selected_provider="okta"),
        bound(selected_authority="1" * 64),
        bound(selected_revision=4),
    )
    for mismatch in mismatches:
        attached = runtime.IdentityGovernanceControlRuntime(
            tenant_sha256=tenant,
            authority_resolver=lambda _tenant, _principal: authority,
            federation_binding_resolver=(
                lambda _tenant, _principal, _provider, value=mismatch: value
            ),
            federation_adapters={"entra": Adapter()},
        )
        with pytest.raises(
            IdentityGovernanceBindingError,
            match="federation_subject_binding_mismatch",
        ):
            attached.resolve_federation_binding(authority, "entra", subject)

    unavailable = runtime.IdentityGovernanceControlRuntime(
        tenant_sha256=tenant,
        authority_resolver=lambda _tenant, _principal: authority,
        federation_binding_resolver=lambda _tenant, _principal, _provider: None,
        federation_adapters={"entra": Adapter()},
    )
    with pytest.raises(
        IdentityGovernanceDeliveryError,
        match="federation_subject_binding_unavailable",
    ):
        unavailable.resolve_federation_binding(authority, "entra", subject)

    def failed_resolver(*_args):
        raise RuntimeError("raw-provider-secret-must-not-escape")

    failed = runtime.IdentityGovernanceControlRuntime(
        tenant_sha256=tenant,
        authority_resolver=lambda _tenant, _principal: authority,
        federation_binding_resolver=failed_resolver,
        federation_adapters={"entra": Adapter()},
    )
    with pytest.raises(IdentityGovernanceDeliveryError) as captured:
        failed.resolve_federation_binding(authority, "entra", subject)
    assert str(captured.value) == "federation_subject_binding_unavailable"


def test_provider_write_status_requires_complete_federation_and_mapping_runtime():
    class Adapter:
        provider = "entra"

        def observe(self, *_args, **_kwargs):
            raise AssertionError("status must not call provider")

        def status(self):
            return {}

    class Mapper:
        def map(self, *_args, **_kwargs):
            raise AssertionError("status must not map")

    class Registry:
        def store(self, _mapping):
            raise AssertionError("status must not store")

        def get(self, *_args):
            raise AssertionError("status must not load")

    class Purview:
        def status(self):
            return {
                "runtime_available": True,
                "provider_writes_possible": True,
                "live_acceptance_verified": False,
            }

        def prepare(self, *_args, **_kwargs):
            raise AssertionError("status must not prepare")

        def get_intent(self, *_args, **_kwargs):
            raise AssertionError("status must not load")

        def execute(self, *_args, **_kwargs):
            raise AssertionError("status must not execute")

        def compensate(self, *_args, **_kwargs):
            raise AssertionError("status must not compensate")

    common = {
        "tenant_sha256": "a" * 64,
        "authority_resolver": lambda _tenant, _principal: None,
        "capability_mapping_registry": Registry(),
        "purview_writeback": Purview(),
    }
    without_adapter = runtime.IdentityGovernanceControlRuntime(
        **common,
        federation_adapters={},
        capability_mapper=Mapper(),
    )
    without_mapper = runtime.IdentityGovernanceControlRuntime(
        **common,
        federation_binding_resolver=lambda *_args: None,
        federation_adapters={"entra": Adapter()},
    )

    assert without_adapter.status()["provider_writes_possible"] is False
    assert without_mapper.status()["provider_writes_possible"] is False


def test_conditional_access_and_purview_controls_require_federation():
    for dependent in ("conditional_access", "purview_writeback"):
        section = _controlled_section()
        section["controls"]["federation"] = {"enable": False}
        section["controls"][dependent] = {"enable": True}
        with pytest.raises(
            runtime.IdentityGovernanceConfigError,
            match="identity_control_federation_required",
        ):
            runtime.control_plane_status(section)


def test_explicit_change_coupling_requires_configured_sink_and_tenant(monkeypatch):
    from maverick_dashboard import identity_governance_scheduler as scheduler

    monkeypatch.setattr(
        scheduler,
        "tenant_binding_sha256",
        lambda **_kwargs: "a" * 64,
    )
    section = _controlled_section()
    with pytest.raises(runtime.IdentityGovernanceConfigError, match="sink_unavailable"):
        runtime.build_change_coupler(section)

    coupler = runtime.build_change_coupler(
        section,
        risk_sink=lambda _event: None,
        store=object(),
    )
    assert coupler is not None
    status = coupler.status()
    assert status["configured_sinks"] == ["dynamic_risk"]
    assert status["provider_writes"] is False
    assert status["live_acceptance_verified"] is False


def test_scheduler_factory_receives_only_explicit_control_callback(monkeypatch):
    from maverick_dashboard import identity_governance_scheduler as scheduler

    captured = []

    class Engine:
        def status(self, _section):
            return {}

        def run_configured(self, _section, *, actor):
            del actor

    def factory(**kwargs):
        captured.append(kwargs)
        return Engine()

    monkeypatch.setattr(
        scheduler,
        "tenant_binding_sha256",
        lambda **_kwargs: "b" * 64,
    )
    engine = runtime.build_scheduler(
        _controlled_section(),
        scheduler_factory=factory,
        risk_sink=lambda _event: None,
        change_store=object(),
    )

    assert engine is not None
    assert len(captured) == 1
    assert callable(captured[0]["change_callback"])
    with pytest.raises(runtime.IdentityGovernanceConfigError, match="ambiguous"):
        runtime.build_scheduler(
            _controlled_section(),
            scheduler_factory=factory,
            risk_sink=lambda _event: None,
            change_callback=lambda _event: None,
        )


def test_control_adapter_factories_are_default_off_and_explicit(monkeypatch):
    from maverick_dashboard import identity_governance_scheduler as scheduler

    class ObservationTransport:
        def observe(self, _request):
            raise AssertionError("factory construction must not call provider")

    class WritebackTransport:
        def apply(self, _request):
            raise AssertionError("factory construction must not call provider")

        def compensate(self, _request):
            raise AssertionError("factory construction must not call provider")

    observation_transport = ObservationTransport()
    assert runtime.build_federation_adapter(
        {}, "entra", transport=observation_transport
    ) is None
    assert runtime.build_conditional_access_observer(
        {}, "okta", transport=observation_transport
    ) is None
    assert runtime.build_purview_writeback({}, transport=WritebackTransport()) is None

    monkeypatch.setattr(
        scheduler,
        "tenant_binding_sha256",
        lambda **_kwargs: "c" * 64,
    )
    section = _controlled_section()
    entra = runtime.build_federation_adapter(
        section,
        "entra",
        transport=observation_transport,
    )
    okta_ca = runtime.build_conditional_access_observer(
        section,
        "okta",
        transport=observation_transport,
    )
    purview = runtime.build_purview_writeback(
        section,
        transport=WritebackTransport(),
    )
    assert entra.status()["provider"] == "entra"
    assert entra.status()["provider_writes"] is False
    assert okta_ca.status()["provider_policy_writes"] is False
    assert purview.status()["runtime_available"] is False
    assert purview.status()["provider_writes_possible"] is False

    provider_disabled = _controlled_section()
    provider_disabled.pop("okta")
    with pytest.raises(runtime.IdentityGovernanceConfigError, match="provider_disabled"):
        runtime.build_federation_adapter(
            provider_disabled,
            "okta",
            transport=observation_transport,
        )


def test_controls_require_the_parent_connector_opt_in() -> None:
    section = _controlled_section()
    section["enable"] = False
    with pytest.raises(runtime.IdentityGovernanceConfigError, match="connector_disabled"):
        runtime.control_plane_status(section)


def test_scheduler_factory_is_default_off_and_never_called_when_unconfigured():
    calls = 0

    def factory(**_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("disabled scheduler factory must not run")

    assert runtime.build_scheduler({}, scheduler_factory=factory) is None
    status = runtime.scheduler_status({}, scheduler_factory=factory)
    assert calls == 0
    assert status["enabled"] is False
    assert status["runtime_attached"] is False
    assert status["automatic_start"] is False
    assert status["source_complete"] is False
    assert status["risk_generated"] is False


def test_explicit_scheduler_factory_adds_sanitized_runtime_status(monkeypatch):
    captured = []

    class Engine:
        def run_configured(self, _section, *, actor):
            raise AssertionError(f"status must not collect as {actor}")

        def status(self, _section):
            return {
                "schema": "lightwork.identity_governance.scheduler-runtime-status.v1",
                "enabled": True,
                "providers": [{"provider": "entra", "health": "never_run"}],
                "source_complete": False,
                "live_acceptance_verified": False,
                "complete_inventory_claimed": False,
                "risk_generated": False,
            }

    def factory(**kwargs):
        captured.append(kwargs)
        return Engine()

    monkeypatch.setattr(runtime, "_adapters", lambda _section: (_Adapter(),))
    section = _controlled_section()
    status = runtime.connector_status(section, scheduler_factory=factory)

    continuous = status["continuous_collection"]
    assert captured == [{}]
    assert continuous["enabled"] is True
    assert continuous["configured_providers"] == ["entra"]
    assert continuous["runtime_attached"] is True
    assert continuous["automatic_start"] is False
    assert continuous["provider_writes"] is False
    assert continuous["runtime"]["risk_generated"] is False
    serialized = json.dumps(status, sort_keys=True)
    assert "raw-tenant@example.invalid" not in serialized
    assert "RAW_ENTRA_TOKEN" not in serialized


def test_scheduler_status_rejects_fabricated_completion_or_risk_claims():
    class InvalidEngine:
        def run_configured(self, _section, *, actor):
            del actor

        def status(self, _section):
            return {
                "source_complete": False,
                "live_acceptance_verified": False,
                "complete_inventory_claimed": False,
                "risk_generated": True,
            }

    with pytest.raises(ValueError, match="unsupported claim"):
        runtime.scheduler_status(
            _scheduled_section(),
            scheduler_factory=lambda: InvalidEngine(),
        )
