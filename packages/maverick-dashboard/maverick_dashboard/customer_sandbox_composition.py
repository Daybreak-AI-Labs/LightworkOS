"""Native local composition for the governed customer-sandbox lifecycle."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from typing import Any

from maverick.customer_sandbox_lifecycle import (
    AI_GOVERNANCE_SOURCE_SECTIONS,
    SUPPORTED_SANDBOX_MODULES,
    CustomerSandboxConfigError,
    CustomerSandboxLifecycleStore,
    LocalCustomerSandboxProvisioner,
    SourceTenantConfiguration,
    enabled,
    require_enabled,
)
from maverick.paths import _tenant_namespace_key, data_dir

_AI_GOVERNANCE_SECTIONS = (
    "agent_topology",
    "ai_bank_mrm",
    "ai_benchmark_exchange",
    "ai_business_intake",
    "ai_conformity_workflow",
    "ai_cost_roi",
    "ai_discovery_sensors",
    "ai_dynamic_risk",
    "ai_explainability",
    "ai_identity_governance_connectors",
    "ai_insurability",
    "ai_inventory",
    "ai_literacy",
    "ai_media_provenance",
    "ai_policy_management",
    "ai_regulatory_feed",
    "ai_regulated_verticals",
    "ai_runtime_guardrails",
    "ai_vendor_risk",
    "drift_monitoring",
    "eu_ai_incidents",
    "grc_outbound_sync",
    "policy_packs",
    "portfolio_risk",
    "red_team_assurance",
)

if frozenset(_AI_GOVERNANCE_SECTIONS) != AI_GOVERNANCE_SOURCE_SECTIONS:
    raise RuntimeError("customer sandbox AI projection schema is inconsistent")

_AI_SAFE_NUMERIC_KEYS = frozenset(
    {
        "bins",
        "campaign_ttl_seconds",
        "collector_lookback_days",
        "collector_poll_seconds",
        "embedding_cosine_threshold",
        "evidence_validity_seconds",
        "kl_threshold",
        "max_attempts_per_revision",
        "max_cases",
        "max_response_bytes",
        "min_samples",
        "missing_grace_runs",
        "page_cap",
        "performance_decay_threshold",
        "poll_seconds",
        "psi_threshold",
        "record_cap",
        "retry_attempts",
        "scheduler_poll_seconds",
        "timeout_seconds",
    }
)


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CustomerSandboxConfigError("sandbox_source_authority_invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


def _load_global_authority_config() -> Mapping[str, Any]:
    from maverick import config as config_module

    config = config_module.load_global_config()
    if config_module.config_source_errors(include_tenant=False):
        raise CustomerSandboxConfigError("sandbox_configuration_source_invalid")
    if not isinstance(config, Mapping):
        raise CustomerSandboxConfigError("sandbox_configuration_source_invalid")
    return config


def _load_source_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    from maverick import config as config_module
    from maverick.paths import tenant_scope

    with tenant_scope(tenant=tenant_id):
        config = config_module.load_config()
        if config_module.config_source_errors(include_tenant=True):
            raise CustomerSandboxConfigError("sandbox_source_configuration_invalid")
    if not isinstance(config, Mapping):
        raise CustomerSandboxConfigError("sandbox_source_configuration_invalid")
    return config


def _source_revision(config: Mapping[str, Any]) -> int:
    section = config.get("customer_sandbox_lifecycle")
    value = section.get("source_revision", 1) if isinstance(section, Mapping) else 1
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**31 - 1:
        raise CustomerSandboxConfigError("sandbox_source_revision_invalid")
    return value


def _suite_configuration(config: Mapping[str, Any]) -> dict[str, object]:
    modules: dict[str, object] = {}
    ai_projection: dict[str, object] = {}
    for section_name in _AI_GOVERNANCE_SECTIONS:
        section = config.get(section_name)
        if isinstance(section, Mapping) and "enable" in section:
            projected = {"enable": section.get("enable")}
            projected.update(
                {
                    key: section[key]
                    for key in sorted(_AI_SAFE_NUMERIC_KEYS & set(section))
                }
            )
            if section_name == "ai_vendor_risk" and "portal_enable" in section:
                projected["portal_enable"] = section["portal_enable"]
            ai_projection[section_name] = projected
    # AI governance is physically split across closed ai_* sections.  Export
    # only their gates; connector/provider settings never enter this mapping.
    modules["ai_governance"] = ai_projection or {"enabled": False}
    for module in sorted(SUPPORTED_SANDBOX_MODULES - {"ai_governance"}):
        if module in config:
            modules[module] = config[module]
    return modules


def _source_configuration(tenant_id: str) -> SourceTenantConfiguration:
    from maverick.tenant.registry import TenantRegistryError, get_tenant

    try:
        tenant = get_tenant(tenant_id)
    except TenantRegistryError as exc:
        raise CustomerSandboxConfigError("sandbox_source_tenant_authority_unavailable") from exc
    if tenant is None or not tenant.active:
        raise CustomerSandboxConfigError("sandbox_source_tenant_not_active")
    global_config = _load_global_authority_config()
    require_enabled(global_config)
    config = _load_source_tenant_config(tenant.id)
    # This built-in local composition snapshots only suite configuration.  The
    # core sanitizer independently rejects unsafe nested material before write.
    modules = _suite_configuration(config)
    return SourceTenantConfiguration(
        tenant_id=tenant.id,
        revision=_source_revision(config),
        config_sha256=_canonical_sha256(modules),
        config=modules,
    )


def _production_target_collision(target_sandbox_id: str) -> bool:
    from maverick.tenant.registry import TenantRegistryError, list_tenants

    try:
        target_key = _tenant_namespace_key(target_sandbox_id)
        return any(_tenant_namespace_key(record.id) == target_key for record in list_tenants())
    except TenantRegistryError as exc:
        raise CustomerSandboxConfigError("sandbox_target_tenant_authority_unavailable") from exc


def build_customer_sandbox_store(
    *,
    principal_resolver: Callable[[], str],
    clock: Callable[[], float] = time.time,
    existing_only: bool = False,
) -> CustomerSandboxLifecycleStore:
    if not callable(principal_resolver):
        raise CustomerSandboxConfigError("sandbox_principal_authority_unavailable")

    def gate() -> None:
        require_enabled(_load_global_authority_config())

    def target_collision(target_sandbox_id: str) -> bool:
        return _production_target_collision(target_sandbox_id)

    root = data_dir("customer_sandbox_lifecycle", tenant=None)
    return CustomerSandboxLifecycleStore(
        root / "lifecycle.sqlite3",
        source_resolver=_source_configuration,
        principal_resolver=principal_resolver,
        provisioner=LocalCustomerSandboxProvisioner(
            root / "isolated-sandbox-workspaces",
            existing_only=existing_only,
        ),
        config_gate=gate,
        target_collision_resolver=target_collision,
        clock=clock,
        existing_only=existing_only,
    )


def customer_sandbox_capability_enabled() -> bool:
    """Side-effect-free deployment-global feature probe."""

    return enabled(_load_global_authority_config())


def attach_customer_sandbox_composition(app: Any) -> None:
    """Install a lazy global-authority factory without overriding test/runtime injection."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    if getattr(state, "customer_sandbox_store_factory", None) is not None:
        if getattr(state, "customer_sandbox_capability_probe", None) is None:
            state.customer_sandbox_capability_probe = customer_sandbox_capability_enabled
        return

    def store_factory(
        *,
        principal_ref: str,
        principal_resolver: Callable[[], str],
        **_unused: Any,
    ) -> CustomerSandboxLifecycleStore:
        if not isinstance(principal_ref, str) or not principal_ref:
            raise CustomerSandboxConfigError("sandbox_principal_authority_unavailable")
        if principal_resolver() != principal_ref:
            raise CustomerSandboxConfigError("sandbox_principal_authority_changed")
        existing_only = not customer_sandbox_capability_enabled()
        return build_customer_sandbox_store(
            principal_resolver=principal_resolver,
            existing_only=existing_only,
        )

    state.customer_sandbox_store_factory = store_factory
    state.customer_sandbox_capability_probe = customer_sandbox_capability_enabled


__all__ = [
    "attach_customer_sandbox_composition",
    "build_customer_sandbox_store",
    "customer_sandbox_capability_enabled",
]
