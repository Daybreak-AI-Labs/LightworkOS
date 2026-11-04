"""Lazy, tenant-exact production composition for identity governance.

Installing this module performs no provider I/O, opens no authority store, and
resolves no credential.  The enabled request path constructs a fresh runtime
for the active tenant from the stock governed authority registry and closed
provider transport contracts.  The browser cannot select a tenant, registry,
store path, provider credential, enrolled subject, binding, or write transport.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from maverick import ai_identity_governance_controls as controls
from maverick.ai_identity_governance_connectors import CONFIG_SECTION
from maverick.paths import canonical_tenant_id, current_tenant_id_strict, tenant_scope

from . import identity_governance_runtime as runtime
from . import identity_governance_scheduler as scheduler


class IdentityGovernanceCompositionError(RuntimeError):
    """The production composition cannot preserve its authority contract."""


@dataclass(frozen=True)
class IdentityGovernanceProductionSettings:
    enabled: bool = False
    mapping_revision: int = 1
    mapping_retention_seconds: int = 86_400
    max_authority_records: int = 10_000
    max_observation_age_seconds: int = 300
    max_future_skew_seconds: int = 30
    purview_max_attempts: int = 3
    purview_operation_lease_seconds: int = 60
    outcome_max_attempts: int = 5
    outcome_retry_base_seconds: int = 30
    outcome_retry_max_seconds: int = 3_600
    outcome_lease_seconds: int = 60
    outcome_signal_validity_seconds: int = 86_400


def _tenant_sha256(tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    current = current_tenant_id_strict()
    if current is None or canonical_tenant_id(current) != tenant:
        raise IdentityGovernanceCompositionError(
            "identity governance runtime tenant scope does not match"
        )
    value = scheduler.tenant_binding_sha256(require_explicit=True)
    if not isinstance(value, str) or len(value) != 64:
        raise IdentityGovernanceCompositionError(
            "identity governance tenant binding is unavailable"
        )
    return value


def _load_tenant_section(tenant_id: str) -> dict[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick.config import config_source_errors, load_config

        with tenant_scope(tenant=tenant):
            config = load_config()
            errors = config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise IdentityGovernanceCompositionError(
            "identity governance configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise IdentityGovernanceCompositionError(
            "identity governance configuration is unavailable"
        )
    section = config.get(CONFIG_SECTION, {})
    if not isinstance(section, Mapping):
        raise IdentityGovernanceCompositionError(
            "identity governance configuration is invalid"
        )
    return dict(section)


def production_settings(section: object) -> IdentityGovernanceProductionSettings:
    """Return the closed, default-off production composition settings."""

    try:
        runtime.control_plane_status(section)
    except Exception as exc:
        raise IdentityGovernanceCompositionError(
            "identity governance control configuration is invalid"
        ) from exc
    if not isinstance(section, Mapping):
        return IdentityGovernanceProductionSettings()
    control_table = section.get("controls")
    if not isinstance(control_table, Mapping):
        return IdentityGovernanceProductionSettings()
    raw = control_table.get("production")
    if not isinstance(raw, Mapping) or raw.get("enable") is not True:
        return IdentityGovernanceProductionSettings()
    return IdentityGovernanceProductionSettings(
        enabled=True,
        mapping_revision=int(raw.get("mapping_revision", 1)),
        mapping_retention_seconds=int(raw.get("mapping_retention_seconds", 86_400)),
        max_authority_records=int(raw.get("max_authority_records", 10_000)),
        max_observation_age_seconds=int(
            raw.get("max_observation_age_seconds", 300)
        ),
        max_future_skew_seconds=int(raw.get("max_future_skew_seconds", 30)),
        purview_max_attempts=int(raw.get("purview_max_attempts", 3)),
        purview_operation_lease_seconds=int(
            raw.get("purview_operation_lease_seconds", 60)
        ),
        outcome_max_attempts=int(raw.get("outcome_max_attempts", 5)),
        outcome_retry_base_seconds=int(
            raw.get("outcome_retry_base_seconds", 30)
        ),
        outcome_retry_max_seconds=int(raw.get("outcome_retry_max_seconds", 3_600)),
        outcome_lease_seconds=int(raw.get("outcome_lease_seconds", 60)),
        outcome_signal_validity_seconds=int(
            raw.get("outcome_signal_validity_seconds", 86_400)
        ),
    )


def _registry(
    tenant_id: str,
    settings: IdentityGovernanceProductionSettings,
) -> controls.IdentityGovernanceAuthorityRegistry:
    tenant = canonical_tenant_id(tenant_id)
    with tenant_scope(tenant=tenant):
        tenant_sha256 = _tenant_sha256(tenant)
        return controls.IdentityGovernanceAuthorityRegistry(
            tenant_sha256=tenant_sha256,
            max_records=settings.max_authority_records,
            mapping_retention_seconds=settings.mapping_retention_seconds,
        )


def _outcome_runtime(
    section: Mapping[str, Any],
) -> runtime.IdentityGovernanceOutcomeRuntime:
    """Build fresh service objects over tenant-private durable stores."""

    from maverick import ai_dynamic_risk, model_risk_assurance
    from maverick.ai_identity_governance_outcomes import (
        IdentityChangeAssetRegistry,
        IdentityChangeOutcomeConsumer,
    )

    settings = production_settings(section)
    if not settings.enabled:
        raise IdentityGovernanceCompositionError(
            "identity governance production composition is disabled"
        )
    tenant_sha256 = scheduler.tenant_binding_sha256(require_explicit=True)
    registry = IdentityChangeAssetRegistry(
        tenant_sha256=tenant_sha256,
        max_records=settings.max_authority_records,
    )
    controls_table = section.get("controls")
    change_table = (
        controls_table.get("change_coupling")
        if isinstance(controls_table, Mapping)
        else None
    )
    consumers: dict[str, object] = {}
    common = {
        "tenant_sha256": tenant_sha256,
        "asset_lookup": model_risk_assurance.get_observation,
        "manifest_resolver": registry.resolve_change,
        "max_records": settings.max_authority_records,
        "max_attempts": settings.outcome_max_attempts,
        "retry_base_seconds": settings.outcome_retry_base_seconds,
        "retry_max_seconds": settings.outcome_retry_max_seconds,
        "lease_seconds": settings.outcome_lease_seconds,
        "signal_validity_seconds": settings.outcome_signal_validity_seconds,
    }
    if isinstance(change_table, Mapping) and change_table.get("enable") is True:
        if change_table.get("dynamic_risk") is True:
            consumers["dynamic_risk"] = IdentityChangeOutcomeConsumer(
                **common,
                sink="dynamic_risk",
                risk_service=ai_dynamic_risk.default_service,
            )
        if change_table.get("alerts") is True:
            consumers["alert"] = IdentityChangeOutcomeConsumer(
                **common,
                sink="alert",
            )
    return runtime.IdentityGovernanceOutcomeRuntime(
        tenant_sha256=tenant_sha256,
        asset_registry=registry,
        consumers=consumers,
    )


def _enabled_providers(section: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        provider
        for provider in ("entra", "okta")
        if isinstance(section.get(provider), Mapping)
        and section[provider].get("enable") is True
    )


def _provider_transport(
    state: Any,
    *,
    attribute: str,
    tenant_id: str,
    tenant_sha256: str,
    provider: str,
    request: Any,
    methods: tuple[str, ...],
) -> object:
    factory = getattr(state, attribute, None)
    if not callable(factory):
        raise IdentityGovernanceCompositionError(
            "identity governance provider transport factory is unavailable"
        )
    try:
        selected = factory(
            tenant_id=tenant_id,
            tenant_sha256=tenant_sha256,
            provider=provider,
            request=request,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise IdentityGovernanceCompositionError(
            "identity governance provider transport is unavailable"
        ) from exc
    if (
        getattr(selected, "tenant_sha256", None) != tenant_sha256
        or getattr(selected, "provider", None) != provider
        or getattr(selected, "dns_pinned", None) is not True
        or getattr(selected, "redirects_followed", None) is not False
        or any(not callable(getattr(selected, method, None)) for method in methods)
    ):
        raise IdentityGovernanceCompositionError(
            "identity governance provider transport authority is invalid"
        )
    return selected


def build_identity_governance_control_runtime(
    app: Any,
    *,
    tenant_id: str,
    request: Any,
    section: Mapping[str, Any] | None = None,
) -> runtime.IdentityGovernanceControlRuntime:
    """Build one non-cacheable runtime for the exact active tenant."""

    tenant = canonical_tenant_id(tenant_id)
    current = current_tenant_id_strict()
    if current is None or canonical_tenant_id(current) != tenant:
        raise IdentityGovernanceCompositionError(
            "identity governance runtime tenant scope does not match"
        )
    selected = dict(section) if section is not None else _load_tenant_section(tenant)
    settings = production_settings(selected)
    if not settings.enabled:
        raise IdentityGovernanceCompositionError(
            "identity governance production composition is disabled"
        )
    state = getattr(app, "state", None)
    if state is None:
        raise IdentityGovernanceCompositionError("dashboard app state is unavailable")
    tenant_sha256 = _tenant_sha256(tenant)
    authority_registry = _registry(tenant, settings)
    providers = _enabled_providers(selected)
    control_status = runtime.control_plane_status(selected)
    configured = control_status.get("configured")
    if not isinstance(configured, Mapping):
        raise IdentityGovernanceCompositionError(
            "identity governance control configuration is invalid"
        )

    federation_adapters: dict[str, object] = {}
    if configured.get("federation") is True:
        if not providers:
            raise IdentityGovernanceCompositionError(
                "identity governance federation has no enabled provider"
            )
        for provider in providers:
            transport = _provider_transport(
                state,
                attribute="identity_governance_federation_transport_factory",
                tenant_id=tenant,
                tenant_sha256=tenant_sha256,
                provider=provider,
                request=request,
                methods=("observe",),
            )
            adapter = runtime.build_federation_adapter(
                selected,
                provider,
                transport=transport,
            )
            if adapter is None:
                raise IdentityGovernanceCompositionError(
                    "identity governance federation adapter is unavailable"
                )
            federation_adapters[provider] = adapter

    capability_mapper: object | None = None
    mapping_registry: object | None = None
    if configured.get("federation") is True:
        capability_mapper = controls.IdentityCapabilityMapper(
            authority_registry.capability_rules(),
            revision=settings.mapping_revision,
            max_observation_age_seconds=settings.max_observation_age_seconds,
            max_future_skew_seconds=settings.max_future_skew_seconds,
        )
        mapping_registry = authority_registry

    conditional_observers: dict[str, object] = {}
    decision_engine: object | None = None
    decision_ledger: object | None = None
    if configured.get("conditional_access") is True:
        for provider in providers:
            transport = _provider_transport(
                state,
                attribute="identity_governance_conditional_access_transport_factory",
                tenant_id=tenant,
                tenant_sha256=tenant_sha256,
                provider=provider,
                request=request,
                methods=("observe",),
            )
            observer = runtime.build_conditional_access_observer(
                selected,
                provider,
                transport=transport,
            )
            if observer is None:
                raise IdentityGovernanceCompositionError(
                    "identity governance conditional-access observer is unavailable"
                )
            conditional_observers[provider] = observer
        decision_engine = controls.ConditionalAccessDecisionEngine(
            max_observation_age_seconds=settings.max_observation_age_seconds,
            max_future_skew_seconds=settings.max_future_skew_seconds,
        )
        from maverick.ai_identity_governance_outcomes import (
            GovernedConditionalAccessDecisionLedger,
        )

        decision_ledger = GovernedConditionalAccessDecisionLedger(
            tenant_sha256=tenant_sha256,
            max_records=settings.max_authority_records,
        )

    purview_writeback: object | None = None
    if configured.get("purview_writeback") is True:
        provider_table = selected.get("purview")
        if not isinstance(provider_table, Mapping) or provider_table.get("enable") is not True:
            raise IdentityGovernanceCompositionError(
                "identity governance Purview provider is disabled"
            )
        registry_status = authority_registry.status()
        if registry_status.get("purview_authority_ready") is not True:
            raise IdentityGovernanceCompositionError(
                "identity governance Purview authority is not enrolled"
            )
        write_transport = _provider_transport(
            state,
            attribute="identity_governance_purview_transport_factory",
            tenant_id=tenant,
            tenant_sha256=tenant_sha256,
            provider="purview",
            request=request,
            methods=("apply", "compensate"),
        )
        purview_writeback = runtime.build_purview_writeback(
            selected,
            principal_resolver=authority_registry.resolve_authority,
            asset_binding_resolver=authority_registry.resolve_purview_asset,
            transport=write_transport,
            max_attempts=settings.purview_max_attempts,
            operation_lease_seconds=settings.purview_operation_lease_seconds,
        )
        if purview_writeback is None:
            raise IdentityGovernanceCompositionError(
                "identity governance Purview writeback is unavailable"
            )

    return runtime.IdentityGovernanceControlRuntime(
        tenant_sha256=tenant_sha256,
        authority_resolver=authority_registry.resolve_authority,
        federation_binding_resolver=(
            authority_registry.resolve_federation_binding
            if federation_adapters
            else None
        ),
        federation_adapters=federation_adapters,
        capability_mapper=capability_mapper,
        capability_mapping_registry=mapping_registry,
        conditional_access_observers=conditional_observers,
        conditional_access_decision_engine=decision_engine,
        conditional_access_decision_ledger=decision_ledger,
        purview_writeback=purview_writeback,
    )


def identity_governance_composition_readiness(
    app: Any,
    *,
    tenant_id: str,
    section: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect config, installed factories, and local authorities only."""

    tenant = canonical_tenant_id(tenant_id)
    selected = dict(section) if section is not None else _load_tenant_section(tenant)
    settings = production_settings(selected)
    base = {
        "schema": "lightwork.identity_governance.production-readiness.v1",
        "enabled": settings.enabled,
        "runtime_factory_installed": callable(
            getattr(
                getattr(app, "state", None),
                "identity_governance_control_runtime_factory",
                None,
            )
        ),
        "status_invoked_provider_io": False,
        "status_resolved_credentials": False,
        "provider_writes_possible": False,
        "live_acceptance_verified": False,
    }
    if not settings.enabled:
        return {
            **base,
            "configured": False,
            "authority_registry": None,
            "dependencies": {},
        }
    state = getattr(app, "state", None)
    if state is None:
        return {
            **base,
            "configured": False,
            "authority_registry": None,
            "dependencies": {"app_state": False},
        }
    registry = _registry(tenant, settings)
    registry_status = registry.status()
    posture = runtime.control_plane_status(selected)
    configured_controls = posture.get("configured", {})
    providers = _enabled_providers(selected)
    dependencies = {
        "federation_transport_factory": (
            configured_controls.get("federation") is not True
            or callable(
                getattr(state, "identity_governance_federation_transport_factory", None)
            )
        ),
        "conditional_access_transport_factory": (
            configured_controls.get("conditional_access") is not True
            or callable(
                getattr(
                    state,
                    "identity_governance_conditional_access_transport_factory",
                    None,
                )
            )
        ),
        "purview_transport_factory": (
            configured_controls.get("purview_writeback") is not True
            or callable(
                getattr(state, "identity_governance_purview_transport_factory", None)
            )
        ),
        "enabled_federation_provider": (
            configured_controls.get("federation") is not True or bool(providers)
        ),
        "purview_authority": (
            configured_controls.get("purview_writeback") is not True
            or registry_status.get("purview_authority_ready") is True
        ),
    }
    change_enabled = configured_controls.get("change_coupling") is True
    outcome_runtime: runtime.IdentityGovernanceOutcomeRuntime | None = None
    if change_enabled:
        try:
            outcome_runtime = _outcome_runtime(selected)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            outcome_runtime = None
        dependencies["asset_outcome_runtime"] = outcome_runtime is not None
        dependencies["asset_binding_authority"] = bool(
            outcome_runtime is not None
            and outcome_runtime.asset_registry.status().get("active_binding_count", 0)
        )
        change_table = (
            selected.get("controls", {}).get("change_coupling")
            if isinstance(selected.get("controls"), Mapping)
            else None
        )
        if isinstance(change_table, Mapping) and change_table.get("dynamic_risk") is True:
            from maverick import ai_dynamic_risk

            dependencies["dynamic_risk_feature"] = ai_dynamic_risk.enabled()
    return {
        **base,
        "configured": all(dependencies.values()),
        "authority_registry": registry_status,
        "dependencies": dependencies,
        "enabled_federation_providers": list(providers),
        "asset_outcomes": (
            outcome_runtime.status() if outcome_runtime is not None else None
        ),
        "provider_writes_possible": False,
        "provider_write_activation": "exact_runtime_transport_validation_required",
    }


def _scheduler_engine(section: object) -> object | None:
    if not isinstance(section, Mapping):
        return None
    settings = production_settings(section)
    if not settings.enabled:
        return None
    control_table = section.get("controls")
    change_table = (
        control_table.get("change_coupling")
        if isinstance(control_table, Mapping)
        else None
    )
    risk_sink: Callable[[Mapping[str, Any]], object] | None = None
    alert_sink: Callable[[Mapping[str, Any]], object] | None = None
    asset_binding_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None
    if isinstance(change_table, Mapping) and change_table.get("enable") is True:
        outcomes = _outcome_runtime(section)
        asset_binding_resolver = outcomes.asset_registry.resolve_change
        if change_table.get("dynamic_risk") is True:
            risk_sink = outcomes.consumer("dynamic_risk")
        if change_table.get("alerts") is True:
            alert_sink = outcomes.consumer("alert")
    return runtime.build_scheduler(
        section,
        risk_sink=risk_sink,
        alert_sink=alert_sink,
        asset_binding_resolver=asset_binding_resolver,
    )


def attach_identity_governance_composition(app: Any) -> None:
    """Install lazy request, readiness, provisioning, and scheduler factories."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")

    existing_runtime = getattr(
        state,
        "identity_governance_control_runtime_factory",
        None,
    )
    if existing_runtime is not None and not callable(existing_runtime):
        raise TypeError("identity governance runtime factory must be callable")
    if existing_runtime is None:

        def runtime_factory(tenant_id: str, request: Any):
            return build_identity_governance_control_runtime(
                app,
                tenant_id=tenant_id,
                request=request,
            )

        state.identity_governance_control_runtime_factory = runtime_factory

    existing_readiness = getattr(
        state,
        "identity_governance_control_readiness_probe",
        None,
    )
    if existing_readiness is not None and not callable(existing_readiness):
        raise TypeError("identity governance readiness probe must be callable")
    if existing_readiness is None:

        def readiness_probe(tenant_id: str):
            return identity_governance_composition_readiness(
                app,
                tenant_id=tenant_id,
            )

        state.identity_governance_control_readiness_probe = readiness_probe

    existing_registry = getattr(
        state,
        "identity_governance_authority_registry_factory",
        None,
    )
    if existing_registry is not None and not callable(existing_registry):
        raise TypeError("identity governance authority registry factory must be callable")
    if existing_registry is None:

        def registry_factory(tenant_id: str):
            section = _load_tenant_section(tenant_id)
            settings = production_settings(section)
            if not settings.enabled:
                raise IdentityGovernanceCompositionError(
                    "identity governance production composition is disabled"
                )
            return _registry(tenant_id, settings)

        state.identity_governance_authority_registry_factory = registry_factory

    existing_outcomes = getattr(
        state,
        "identity_governance_outcome_runtime_factory",
        None,
    )
    if existing_outcomes is not None and not callable(existing_outcomes):
        raise TypeError("identity governance outcome runtime factory must be callable")
    if existing_outcomes is None:

        def outcome_runtime_factory(tenant_id: str):
            tenant = canonical_tenant_id(tenant_id)
            with tenant_scope(tenant=tenant):
                selected = _load_tenant_section(tenant)
                return _outcome_runtime(selected)

        state.identity_governance_outcome_runtime_factory = outcome_runtime_factory

    scheduler.install_composed_engine_factory(_scheduler_engine)


__all__ = [
    "IdentityGovernanceCompositionError",
    "IdentityGovernanceProductionSettings",
    "attach_identity_governance_composition",
    "build_identity_governance_control_runtime",
    "identity_governance_composition_readiness",
    "production_settings",
]
