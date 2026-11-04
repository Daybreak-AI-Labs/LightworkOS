"""Runtime wiring for bounded identity/data-governance connector snapshots.

The provider adapters live in :mod:`maverick.ai_identity_governance_connectors`.
This module supplies the production HTTP and secret-resolution seams while
preserving their fixed-host, fixed-operation, no-redirect and bounded-response
contracts. Returned connector values are normalized pseudonymous snapshots.
Optional control factories remain separately configured, default-off, and
unavailable until their credential-owning transports and binding resolvers are
explicitly injected; this module never resolves write credentials itself.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from dataclasses import field as dataclass_field
from types import MappingProxyType
from typing import Any

from maverick.ai_identity_governance_connectors import (
    PROVIDERS,
    BoundedHTTPResponse,
    IdentityGovernanceConfigError,
    IdentityGovernanceLimitError,
    IdentityGovernanceProtocolError,
    configured_connectors,
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
# Legacy compatibility for deployments that have not enabled the shipped
# production composition.  Production requests resolve a fresh tenant-bound
# runtime through ``identity_governance_control_runtime_factory``.
CONTROL_RUNTIME_APP_STATE = "identity_governance_control_runtime"


@dataclass(frozen=True)
class IdentityGovernanceControlRuntime:
    """Explicit startup composition for live identity-control dependencies.

    The shipped composition creates this object lazily for the active request
    tenant.  It never builds the authority from browser input or connector
    credentials.  Exact authorities and mappings come from the tenant's
    governed registry; credential-owning provider transports remain closed,
    independently configured deployment seams.
    """

    tenant_sha256: str
    authority_resolver: Callable[[str, str], object]
    federation_adapters: Mapping[str, object]
    federation_binding_resolver: Callable[[str, str, str], object] | None = None
    capability_mapper: object | None = None
    capability_mapping_registry: object | None = None
    conditional_access_observers: Mapping[str, object] = dataclass_field(
        default_factory=lambda: MappingProxyType({})
    )
    conditional_access_decision_engine: object | None = None
    conditional_access_decision_ledger: object | None = None
    purview_writeback: object | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_sha256, str) or not _SHA256_RE.fullmatch(
            self.tenant_sha256
        ):
            raise ValueError("identity control runtime tenant binding is invalid")
        if not callable(self.authority_resolver):
            raise TypeError("identity control authority resolver must be callable")
        object.__setattr__(
            self,
            "federation_adapters",
            self._closed_provider_map(
                self.federation_adapters,
                label="federation adapter",
                methods=("observe", "status"),
            ),
        )
        if self.federation_binding_resolver is not None and not callable(
            self.federation_binding_resolver
        ):
            raise TypeError(
                "identity control federation binding resolver must be callable"
            )
        if self.federation_adapters and self.federation_binding_resolver is None:
            raise TypeError(
                "identity control federation adapters require an enrolled "
                "subject binding resolver"
            )
        object.__setattr__(
            self,
            "conditional_access_observers",
            self._closed_provider_map(
                self.conditional_access_observers,
                label="conditional-access observer",
                methods=("observe", "status"),
            ),
        )
        for value, label, method in (
            (self.capability_mapper, "capability mapper", "map"),
            (
                self.conditional_access_decision_engine,
                "conditional-access decision engine",
                "decide",
            ),
            (self.purview_writeback, "Purview writeback service", "status"),
        ):
            if value is not None and not callable(getattr(value, method, None)):
                raise TypeError(f"identity control {label} is invalid")
        if self.capability_mapping_registry is not None:
            for method in ("store", "get"):
                if not callable(getattr(self.capability_mapping_registry, method, None)):
                    raise TypeError("identity control capability mapping registry is invalid")
        if self.purview_writeback is not None:
            for method in ("prepare", "get_intent", "execute", "compensate"):
                if not callable(getattr(self.purview_writeback, method, None)):
                    raise TypeError("identity control Purview writeback service is invalid")
        if self.conditional_access_decision_ledger is not None:
            for method in ("record", "get", "list", "revoke", "status"):
                if not callable(
                    getattr(self.conditional_access_decision_ledger, method, None)
                ):
                    raise TypeError(
                        "identity control conditional-access decision ledger is invalid"
                    )

    @staticmethod
    def _closed_provider_map(
        value: Mapping[str, object],
        *,
        label: str,
        methods: tuple[str, ...],
    ) -> Mapping[str, object]:
        if not isinstance(value, Mapping):
            raise TypeError(f"identity control {label} table is invalid")
        selected = dict(value)
        if set(selected) - {"entra", "okta"}:
            raise ValueError(f"identity control {label} provider is unsupported")
        for provider, adapter in selected.items():
            if getattr(adapter, "provider", provider) != provider or any(
                not callable(getattr(adapter, method, None)) for method in methods
            ):
                raise TypeError(f"identity control {label} is invalid")
        return MappingProxyType(selected)

    def resolve_authority(self, principal_ref: str):
        """Resolve an exact pseudonymous authority through the injected registry."""

        from maverick.ai_identity_governance_controls import (
            AgentPrincipalAuthority,
            IdentityGovernanceBindingError,
            IdentityGovernanceDeliveryError,
        )

        try:
            authority = self.authority_resolver(self.tenant_sha256, principal_ref)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise IdentityGovernanceDeliveryError(
                "principal_binding_unavailable"
            ) from None
        if not isinstance(authority, AgentPrincipalAuthority):
            raise IdentityGovernanceDeliveryError("principal_binding_unavailable")
        if (
            authority.tenant_sha256 != self.tenant_sha256
            or authority.principal_ref != principal_ref
        ):
            raise IdentityGovernanceBindingError("principal_binding_mismatch")
        return authority

    def federation_adapter(self, provider: str):
        from maverick.ai_identity_governance_controls import (
            IdentityGovernanceControlConfigError,
        )

        adapter = self.federation_adapters.get(provider)
        if adapter is None:
            raise IdentityGovernanceControlConfigError(
                "federation_runtime_unavailable"
            )
        return adapter

    def resolve_federation_binding(
        self,
        authority: object,
        provider: str,
        requested_subject_id: str,
    ):
        """Resolve an enrolled provider subject without trusting API input.

        ``requested_subject_id`` is only an exact-match assertion from the
        caller. The injected resolver receives the current tenant, authority
        principal and closed provider name; it never receives the caller's
        proposed subject and therefore cannot accidentally act as an echo.
        """

        from maverick.ai_identity_governance_controls import (
            AgentPrincipalAuthority,
            AgentPrincipalFederationBinding,
            IdentityGovernanceBindingError,
            IdentityGovernanceControlConfigError,
            IdentityGovernanceDeliveryError,
        )

        if not isinstance(authority, AgentPrincipalAuthority):
            raise TypeError("identity control authority is invalid")
        resolver = self.federation_binding_resolver
        if resolver is None:
            raise IdentityGovernanceControlConfigError(
                "federation_subject_binding_runtime_unavailable"
            )
        try:
            binding = resolver(
                self.tenant_sha256,
                authority.principal_ref,
                provider,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise IdentityGovernanceDeliveryError(
                "federation_subject_binding_unavailable"
            ) from None
        if not isinstance(binding, AgentPrincipalFederationBinding):
            raise IdentityGovernanceDeliveryError(
                "federation_subject_binding_unavailable"
            )
        if (
            binding.tenant_sha256 != self.tenant_sha256
            or binding.principal_ref != authority.principal_ref
            or binding.provider != provider
            or binding.authority_binding_sha256
            != authority.authority_binding_sha256
            or binding.authority_revision != authority.revision
        ):
            raise IdentityGovernanceBindingError(
                "federation_subject_binding_mismatch"
            )
        if binding.provider_subject_id != requested_subject_id:
            raise IdentityGovernanceBindingError(
                "provider_subject_not_enrolled"
            )
        return binding

    def require_capability_mapper(self):
        from maverick.ai_identity_governance_controls import (
            IdentityGovernanceControlConfigError,
        )

        if self.capability_mapper is None:
            raise IdentityGovernanceControlConfigError(
                "capability_mapping_runtime_unavailable"
            )
        return self.capability_mapper

    def retain_capability_mapping(self, mapping: object) -> None:
        """Admit a safe normalized mapping for exact resumable writeback use."""

        from maverick.ai_identity_governance_controls import (
            IdentityCapabilityMapping,
            IdentityGovernanceBindingError,
            IdentityGovernanceControlConfigError,
            IdentityGovernanceStateError,
        )

        if self.capability_mapping_registry is None:
            raise IdentityGovernanceControlConfigError(
                "capability_mapping_registry_unavailable"
            )
        if not isinstance(mapping, IdentityCapabilityMapping):
            raise TypeError("capability mapping is invalid")
        if mapping.tenant_sha256 != self.tenant_sha256:
            raise IdentityGovernanceBindingError("capability_mapping_tenant_mismatch")
        try:
            stored = self.capability_mapping_registry.store(mapping)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise IdentityGovernanceStateError(
                "capability_mapping_registry_unavailable"
            ) from None
        if stored not in (None, True):
            raise IdentityGovernanceStateError("capability_mapping_registry_invalid")

    def resolve_capability_mapping(self, principal_ref: str, mapping_sha256: str):
        """Resolve a previously admitted mapping without trusting browser claims."""

        from maverick.ai_identity_governance_controls import (
            IdentityCapabilityMapping,
            IdentityGovernanceBindingError,
            IdentityGovernanceControlConfigError,
            IdentityGovernanceStateError,
        )

        if self.capability_mapping_registry is None:
            raise IdentityGovernanceControlConfigError(
                "capability_mapping_registry_unavailable"
            )
        try:
            mapping = self.capability_mapping_registry.get(
                self.tenant_sha256,
                principal_ref,
                mapping_sha256,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise IdentityGovernanceStateError(
                "capability_mapping_registry_unavailable"
            ) from None
        if not isinstance(mapping, IdentityCapabilityMapping):
            raise IdentityGovernanceStateError("capability_mapping_unavailable")
        if (
            mapping.tenant_sha256 != self.tenant_sha256
            or mapping.principal_ref != principal_ref
            or mapping.mapping_sha256 != mapping_sha256
        ):
            raise IdentityGovernanceBindingError("capability_mapping_registry_mismatch")
        return mapping

    def conditional_access_observer(self, provider: str):
        from maverick.ai_identity_governance_controls import (
            IdentityGovernanceControlConfigError,
        )

        observer = self.conditional_access_observers.get(provider)
        if observer is None:
            raise IdentityGovernanceControlConfigError(
                "conditional_access_runtime_unavailable"
            )
        return observer

    def require_conditional_access_decision_engine(self):
        from maverick.ai_identity_governance_controls import (
            IdentityGovernanceControlConfigError,
        )

        if self.conditional_access_decision_engine is None:
            raise IdentityGovernanceControlConfigError(
                "conditional_access_decision_runtime_unavailable"
            )
        return self.conditional_access_decision_engine

    def require_conditional_access_decision_ledger(self):
        from maverick.ai_identity_governance_controls import (
            IdentityGovernanceControlConfigError,
        )

        if self.conditional_access_decision_ledger is None:
            raise IdentityGovernanceControlConfigError(
                "conditional_access_decision_ledger_unavailable"
            )
        return self.conditional_access_decision_ledger

    def require_purview_writeback(self):
        from maverick.ai_identity_governance_controls import (
            IdentityGovernanceControlConfigError,
        )

        if self.purview_writeback is None:
            raise IdentityGovernanceControlConfigError(
                "purview_writeback_runtime_unavailable"
            )
        return self.purview_writeback

    def status(self) -> dict[str, Any]:
        """Describe attachment reality without calling any provider transport."""

        purview_status: Mapping[str, Any] | None = None
        if self.purview_writeback is not None:
            candidate = self.purview_writeback.status()
            if not isinstance(candidate, Mapping):
                raise TypeError("identity control Purview status is invalid")
            purview_status = dict(candidate)
            if purview_status.get("live_acceptance_verified") is not False:
                raise ValueError("identity control runtime contains an unsupported claim")
        return {
            "schema": "lightwork.identity_governance.attached-control-runtime-status.v1",
            "tenant_sha256": self.tenant_sha256,
            "runtime_attached": True,
            "attachment": "lazy_per_request_tenant_runtime_factory",
            "authority_resolver_attached": True,
            "federation_binding_resolver_attached": (
                self.federation_binding_resolver is not None
            ),
            "federation_providers": sorted(self.federation_adapters),
            "capability_mapping_available": self.capability_mapper is not None,
            "capability_mapping_registry_attached": (
                self.capability_mapping_registry is not None
            ),
            "conditional_access_providers": sorted(
                self.conditional_access_observers
            ),
            "conditional_access_decision_available": (
                self.conditional_access_decision_engine is not None
            ),
            "conditional_access_decision_ledger": (
                self.conditional_access_decision_ledger.status()
                if self.conditional_access_decision_ledger is not None
                else None
            ),
            "purview_writeback": purview_status,
            "provider_writes_possible": bool(
                purview_status is not None
                and self.federation_binding_resolver is not None
                and bool(self.federation_adapters)
                and self.capability_mapper is not None
                and self.capability_mapping_registry is not None
                and purview_status.get("runtime_available") is True
                and purview_status.get("provider_writes_possible") is True
            ),
            "raw_identity_retained": False,
            "secrets_retained": False,
            "automatic_approval": False,
            "live_acceptance_verified": False,
        }


@dataclass(frozen=True)
class IdentityGovernanceOutcomeRuntime:
    """Tenant-exact authority and durable consumers used by the scheduler/API."""

    tenant_sha256: str
    asset_registry: object
    consumers: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_sha256, str) or not _SHA256_RE.fullmatch(
            self.tenant_sha256
        ):
            raise ValueError("identity outcome runtime tenant binding is invalid")
        for method in ("resolve_change", "status", "list_bindings", "enroll", "revoke"):
            if not callable(getattr(self.asset_registry, method, None)):
                raise TypeError("identity outcome asset registry is invalid")
        if not isinstance(self.consumers, Mapping) or set(self.consumers) - {
            "dynamic_risk",
            "alert",
        }:
            raise TypeError("identity outcome consumer table is invalid")
        selected = dict(self.consumers)
        for consumer in selected.values():
            for method in ("status", "get", "list", "run_due", "replay", "revoke"):
                if not callable(getattr(consumer, method, None)):
                    raise TypeError("identity outcome consumer is invalid")
        object.__setattr__(self, "consumers", MappingProxyType(selected))

    def consumer(self, sink: str):
        selected = self.consumers.get(sink)
        if selected is None:
            raise IdentityGovernanceConfigError(
                "identity outcome consumer is unavailable"
            )
        return selected

    def status(self) -> dict[str, Any]:
        return {
            "schema": "lightwork.identity_governance.outcome-runtime-status.v1",
            "tenant_sha256": self.tenant_sha256,
            "asset_registry": self.asset_registry.status(),
            "consumers": {
                name: consumer.status()
                for name, consumer in sorted(self.consumers.items())
            },
            "provider_writes": False,
            "live_acceptance_verified": False,
        }


class PinnedIdentityGovernanceHTTPTransport:
    """DNS-pinned, redirect-disabled transport for the closed provider adapters."""

    dns_pinned = True
    redirects_followed = False

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None,
        timeout: float,
        max_response_bytes: int,
    ) -> BoundedHTTPResponse:
        from maverick.enterprise import enterprise_egress_denial
        from maverick.tools._ssrf import BlockedHost, safe_client

        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise IdentityGovernanceProtocolError("connector_method_rejected")
        denial = enterprise_egress_denial(
            url,
            tool="ai_identity_governance_connectors",
        )
        if denial:
            raise IdentityGovernanceProtocolError("connector_egress_denied")
        try:
            with safe_client(url, timeout=timeout, follow_redirects=False) as client:
                with client.stream(
                    method,
                    url,
                    headers=dict(headers),
                    json=dict(json_body) if json_body is not None else None,
                ) as response:
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_size = int(declared)
                        except ValueError:
                            raise IdentityGovernanceProtocolError(
                                "connector_content_length_invalid"
                            ) from None
                        if declared_size < 0 or declared_size > max_response_bytes:
                            raise IdentityGovernanceLimitError(
                                "connector_response_too_large"
                            )
                    chunks: list[bytes] = []
                    observed = 0
                    for chunk in response.iter_bytes():
                        observed += len(chunk)
                        if observed > max_response_bytes:
                            raise IdentityGovernanceLimitError(
                                "connector_response_too_large"
                            )
                        chunks.append(chunk)
                    selected_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            "content-length",
                            "content-type",
                            "link",
                            "retry-after",
                        }
                    }
                    return BoundedHTTPResponse(
                        status_code=int(response.status_code),
                        headers=selected_headers,
                        body=b"".join(chunks),
                        # safe_client never follows redirects; the exact request
                        # URL is therefore the authoritative final URL. Its
                        # internal DNS pin may replace response.url with an IP.
                        final_url=url,
                    )
        except BlockedHost:
            raise IdentityGovernanceProtocolError("connector_ssrf_blocked") from None


def _secret(reference: str) -> str | None:
    from maverick.secret_provider import get_secret

    return get_secret(reference)


def _connector_section(section: object) -> object:
    """Remove runtime-only metadata before strict adapter validation."""

    if not isinstance(section, Mapping) or not ({"scheduler", "controls"} & set(section)):
        return section
    selected = dict(section)
    selected.pop("scheduler", None)
    selected.pop("controls", None)
    return selected


def _control_table(section: object) -> Mapping[str, Any] | None:
    """Validate the closed, default-off identity control configuration."""

    if not isinstance(section, Mapping):
        raise IdentityGovernanceConfigError("identity_control_section_invalid")
    raw = section.get("controls")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise IdentityGovernanceConfigError("identity_controls_invalid")
    allowed = {
        "enable",
        "change_coupling",
        "federation",
        "conditional_access",
        "purview_writeback",
        "production",
    }
    if set(raw) - allowed:
        raise IdentityGovernanceConfigError("identity_control_key_unsupported")
    if not isinstance(raw.get("enable", False), bool):
        raise IdentityGovernanceConfigError("identity_controls_enable_invalid")
    if raw.get("enable") is True and section.get("enable") is not True:
        raise IdentityGovernanceConfigError("identity_controls_connector_disabled")
    shapes = {
        "change_coupling": {"enable", "dynamic_risk", "alerts"},
        "federation": {"enable"},
        "conditional_access": {"enable"},
        "purview_writeback": {"enable"},
        "production": {
            "enable",
            "mapping_revision",
            "mapping_retention_seconds",
            "max_authority_records",
            "max_observation_age_seconds",
            "max_future_skew_seconds",
            "purview_max_attempts",
            "purview_operation_lease_seconds",
            "outcome_max_attempts",
            "outcome_retry_base_seconds",
            "outcome_retry_max_seconds",
            "outcome_lease_seconds",
            "outcome_signal_validity_seconds",
        },
    }
    any_nested_enabled = False
    for name, keys in shapes.items():
        value = raw.get(name)
        if value is None:
            continue
        if not isinstance(value, Mapping) or set(value) - keys:
            raise IdentityGovernanceConfigError("identity_control_shape_invalid")
        for key in keys:
            if key in value and key == "enable" and not isinstance(value[key], bool):
                raise IdentityGovernanceConfigError("identity_control_flag_invalid")
        any_nested_enabled = any_nested_enabled or value.get("enable") is True
    production = raw.get("production")
    if isinstance(production, Mapping):
        integer_bounds = {
            "mapping_revision": (1, 1_000_000),
            "mapping_retention_seconds": (300, 31_622_400),
            "max_authority_records": (1, 10_000),
            "max_observation_age_seconds": (1, 3_600),
            "max_future_skew_seconds": (0, 300),
            "purview_max_attempts": (1, 10),
            "purview_operation_lease_seconds": (5, 300),
            "outcome_max_attempts": (1, 20),
            "outcome_retry_base_seconds": (1, 86_400),
            "outcome_retry_max_seconds": (1, 604_800),
            "outcome_lease_seconds": (1, 3_600),
            "outcome_signal_validity_seconds": (60, 31_622_400),
        }
        for key, (lower, upper) in integer_bounds.items():
            value = production.get(key)
            if (
                value is not None
                and (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not lower <= value <= upper
                )
            ):
                raise IdentityGovernanceConfigError(
                    "identity_control_production_bound_invalid"
                )
    if any_nested_enabled and raw.get("enable") is not True:
        raise IdentityGovernanceConfigError("identity_controls_parent_disabled")
    change = raw.get("change_coupling")
    if isinstance(change, Mapping) and change.get("enable") is True:
        if change.get("dynamic_risk") is not True and change.get("alerts") is not True:
            raise IdentityGovernanceConfigError("identity_change_sink_not_enabled")
    federation = raw.get("federation")
    federation_enabled = (
        isinstance(federation, Mapping) and federation.get("enable") is True
    )
    for dependent in ("conditional_access", "purview_writeback"):
        selected = raw.get(dependent)
        if (
            isinstance(selected, Mapping)
            and selected.get("enable") is True
            and not federation_enabled
        ):
            raise IdentityGovernanceConfigError(
                "identity_control_federation_required"
            )
    return raw


def _control_enabled(section: object, name: str) -> bool:
    table = _control_table(section)
    if table is None or table.get("enable") is not True:
        return False
    selected = table.get(name)
    return isinstance(selected, Mapping) and selected.get("enable") is True


def _require_control_provider(section: object, provider: str) -> None:
    if not isinstance(section, Mapping):
        raise IdentityGovernanceConfigError("identity_control_section_invalid")
    selected = section.get(provider)
    if not isinstance(selected, Mapping) or selected.get("enable") is not True:
        raise IdentityGovernanceConfigError("identity_control_provider_disabled")


def build_change_coupler(
    section: object,
    *,
    risk_sink: Callable[[Mapping[str, Any]], object] | None = None,
    alert_sink: Callable[[Mapping[str, Any]], object] | None = None,
    asset_binding_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    | None = None,
    store: object | None = None,
    clock: Callable[[], float] | None = None,
) -> object | None:
    """Build the explicitly enabled digest-only risk/alert callback."""

    table = _control_table(section)
    if table is None or table.get("enable") is not True:
        return None
    raw = table.get("change_coupling")
    if not isinstance(raw, Mapping) or raw.get("enable") is not True:
        return None
    selected_risk = risk_sink if raw.get("dynamic_risk") is True else None
    selected_alert = alert_sink if raw.get("alerts") is True else None
    if raw.get("dynamic_risk") is True and selected_risk is None:
        raise IdentityGovernanceConfigError("identity_dynamic_risk_sink_unavailable")
    if raw.get("alerts") is True and selected_alert is None:
        raise IdentityGovernanceConfigError("identity_alert_sink_unavailable")
    from maverick.ai_identity_governance_controls import NormalizedIdentityChangeCoupler

    from . import identity_governance_scheduler as scheduler

    kwargs: dict[str, object] = {
        "enable": True,
        "tenant_sha256": scheduler.tenant_binding_sha256(require_explicit=True),
        "risk_sink": selected_risk,
        "alert_sink": selected_alert,
        "asset_binding_resolver": asset_binding_resolver,
    }
    if store is not None:
        kwargs["store"] = store
    if clock is not None:
        kwargs["clock"] = clock
    return NormalizedIdentityChangeCoupler(**kwargs)


def build_federation_adapter(
    section: object,
    provider: str,
    *,
    transport: object,
) -> object | None:
    """Build one enabled Entra/Okta agent-principal observation adapter."""

    if not _control_enabled(section, "federation"):
        return None
    from maverick.ai_identity_governance_controls import (
        EntraAgentPrincipalFederationAdapter,
        OktaAgentPrincipalFederationAdapter,
    )

    factories = {
        "entra": EntraAgentPrincipalFederationAdapter,
        "okta": OktaAgentPrincipalFederationAdapter,
    }
    selected = str(provider or "").strip().lower()
    factory = factories.get(selected)
    if factory is None:
        raise IdentityGovernanceConfigError("identity_federation_provider_unsupported")
    _require_control_provider(section, selected)
    return factory(transport)


def build_conditional_access_observer(
    section: object,
    provider: str,
    *,
    transport: object,
) -> object | None:
    """Build an observation-only conditional-access adapter."""

    if not _control_enabled(section, "conditional_access"):
        return None
    from maverick.ai_identity_governance_controls import ConditionalAccessObserver

    selected = str(provider or "").strip().lower()
    if selected not in {"entra", "okta"}:
        raise IdentityGovernanceConfigError(
            "identity_conditional_access_provider_unsupported"
        )
    _require_control_provider(section, selected)
    return ConditionalAccessObserver(selected, transport)


def build_purview_writeback(
    section: object,
    *,
    principal_resolver: Callable[..., object] | None = None,
    asset_binding_resolver: Callable[..., object] | None = None,
    transport: object | None = None,
    store: object | None = None,
    clock: Callable[[], float] | None = None,
    max_attempts: int = 3,
    operation_lease_seconds: float = 60.0,
) -> object | None:
    """Build the opt-in governed writeback service without resolving secrets."""

    if not _control_enabled(section, "purview_writeback"):
        return None
    _require_control_provider(section, "purview")
    from maverick.ai_identity_governance_controls import (
        GovernedPurviewWritebackService,
    )

    from . import identity_governance_scheduler as scheduler

    kwargs: dict[str, object] = {
        "enable": True,
        "tenant_sha256": scheduler.tenant_binding_sha256(require_explicit=True),
        "principal_resolver": principal_resolver,
        "asset_binding_resolver": asset_binding_resolver,
        "transport": transport,
        "max_attempts": max_attempts,
        "operation_lease_seconds": operation_lease_seconds,
    }
    if store is not None:
        kwargs["store"] = store
    if clock is not None:
        kwargs["clock"] = clock
    return GovernedPurviewWritebackService(**kwargs)


def control_plane_status(section: object) -> dict[str, Any]:
    """Report configuration reality; this function never attaches live seams."""

    table = _control_table(section)
    enabled = bool(table is not None and table.get("enable") is True)
    configured = {
        name: _control_enabled(section, name)
        for name in (
            "change_coupling",
            "federation",
            "conditional_access",
            "purview_writeback",
        )
    }
    production_enabled = _control_enabled(section, "production")
    return {
        "schema": "lightwork.identity_governance.control-plane-status.v1",
        "enabled": enabled,
        "configured": configured,
        "contracts_available": {
            "normalized_change_coupling": True,
            "entra_agent_principal_federation": True,
            "okta_agent_principal_federation": True,
            "identity_to_capability_mapping": True,
            "conditional_access_observation": True,
            "conditional_access_enforcement_decision": True,
            "purview_governed_writeback": True,
            "purview_compensation": True,
        },
        "runtime_attached": False,
        "runtime_attachment": (
            "FastAPI app.state.identity_governance_control_runtime_factory"
            if production_enabled
            else "FastAPI app.state.identity_governance_control_runtime"
        ),
        "production_composition_enabled": production_enabled,
        "activation": (
            "lazy_per_tenant_production_factory"
            if production_enabled
            else "explicit_startup_injection_required"
        ),
        "authoritative_subject_enrollment_required": True,
        "federation_providers": ["entra", "okta"],
        "default_mode": "read_only_off",
        "provider_writes": False,
        "raw_identity_retained": False,
        "secrets_retained": False,
        "live_acceptance_verified": False,
    }


def _adapters(section: object):
    transport = PinnedIdentityGovernanceHTTPTransport()
    transports = dict.fromkeys(PROVIDERS, transport)
    return configured_connectors(
        _connector_section(section),
        transports=transports,
        secret_resolver=_secret,
    )


def build_scheduler(
    section: object,
    *,
    scheduler_factory: Callable[..., object] | None = None,
    store: object | None = None,
    clock: Callable[[], float] | None = None,
    change_callback: Callable[[Mapping[str, Any]], None] | None = None,
    risk_sink: Callable[[Mapping[str, Any]], object] | None = None,
    alert_sink: Callable[[Mapping[str, Any]], object] | None = None,
    asset_binding_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    | None = None,
    change_store: object | None = None,
    attach_control_callback: bool = True,
) -> object | None:
    """Build, but never start, the explicitly configured scheduler engine.

    Missing schedules return ``None`` without invoking the factory.  The
    default engine has no change callback.  A configured coupling is attached
    only when the caller also injects each enabled bounded sink; the callback
    requests downstream assessment and does not fabricate a risk score.
    """

    from . import identity_governance_scheduler as scheduler

    selected = {} if section is None else section
    if not scheduler.configured_schedules(selected):
        return None
    factory = scheduler_factory or scheduler.IdentityGovernanceScheduler
    kwargs: dict[str, object] = {}
    if store is not None:
        kwargs["store"] = store
    if clock is not None:
        kwargs["clock"] = clock
    if not isinstance(attach_control_callback, bool):
        raise TypeError("attach_control_callback must be boolean")
    configured_callback = (
        build_change_coupler(
            selected,
            risk_sink=risk_sink,
            alert_sink=alert_sink,
            asset_binding_resolver=asset_binding_resolver,
            store=change_store,
            clock=clock,
        )
        if attach_control_callback
        else None
    )
    if change_callback is not None and configured_callback is not None:
        raise IdentityGovernanceConfigError("identity_change_callback_ambiguous")
    callback = change_callback if change_callback is not None else configured_callback
    if callback is not None:
        kwargs["change_callback"] = callback
    engine = factory(**kwargs)
    if not callable(getattr(engine, "status", None)) or not callable(
        getattr(engine, "run_configured", None)
    ):
        raise TypeError("identity-governance scheduler factory returned an invalid engine")
    return engine


def scheduler_status(
    section: object,
    *,
    scheduler_factory: Callable[..., object] | None = None,
) -> dict[str, Any]:
    """Expose opt-in schedule reality without starting background work."""

    from . import identity_governance_scheduler as scheduler

    selected = {} if section is None else section
    schedules = scheduler.configured_schedules(selected)
    status: dict[str, Any] = {
        "schema": "lightwork.identity_governance.scheduler-status.v1",
        "enabled": bool(schedules),
        "configured_providers": [item.provider for item in schedules],
        "poll_seconds": (scheduler.scheduler_poll_seconds(selected) if schedules else None),
        "runtime_attached": False,
        "automatic_start": False,
        "activation": "explicit_factory_required",
        "collection_mode": "bounded_read_only_snapshot",
        "source_state": "unavailable",
        "source_complete": False,
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
        "provider_writes": False,
        "risk_generated": False,
    }
    if scheduler_factory is None or not schedules:
        return status
    engine = build_scheduler(
        selected,
        scheduler_factory=scheduler_factory,
        attach_control_callback=False,
    )
    assert engine is not None
    runtime_status = engine.status(selected)
    if not isinstance(runtime_status, Mapping):
        raise TypeError("identity-governance scheduler status must be a table")
    for field in (
        "source_complete",
        "live_acceptance_verified",
        "complete_inventory_claimed",
        "risk_generated",
    ):
        if runtime_status.get(field) is not False:
            raise ValueError("identity-governance scheduler status contains an unsupported claim")
    status["runtime_attached"] = True
    status["runtime"] = dict(runtime_status)
    return status


def connector_status(
    section: object,
    *,
    scheduler_factory: Callable[..., object] | None = None,
) -> dict[str, Any]:
    """Return configuration reality without resolving or disclosing secrets."""

    adapters = _adapters(section)
    configured = [adapter.provider for adapter in adapters]
    return {
        "schema": "lightwork.identity_governance.runtime-status.v1",
        "enabled": bool(configured) or bool(
            isinstance(section, Mapping) and section.get("enable") is True
        ),
        "supported_providers": list(PROVIDERS),
        "configured_providers": configured,
        "transport": {
            "read_only": True,
            "dns_pinned": True,
            "redirects_followed": False,
            "secret_values_exposed": False,
        },
        "continuous_collection": scheduler_status(
            section,
            scheduler_factory=scheduler_factory,
        ),
        "control_plane": control_plane_status(section),
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
    }


def collect_connector(section: object, provider: str) -> dict[str, Any]:
    """Collect one bounded snapshot through the exact configured provider seam."""

    selected = str(provider or "").strip().lower()
    if selected not in PROVIDERS:
        raise ValueError("identity-governance provider is unsupported")
    adapters = {adapter.provider: adapter for adapter in _adapters(section)}
    adapter = adapters.get(selected)
    if adapter is None:
        raise IdentityGovernanceConfigError("connector_disabled")
    return asdict(adapter.collect())


__all__ = [
    "CONTROL_RUNTIME_APP_STATE",
    "IdentityGovernanceControlRuntime",
    "IdentityGovernanceOutcomeRuntime",
    "PinnedIdentityGovernanceHTTPTransport",
    "build_change_coupler",
    "build_conditional_access_observer",
    "build_federation_adapter",
    "build_purview_writeback",
    "build_scheduler",
    "collect_connector",
    "connector_status",
    "control_plane_status",
    "scheduler_status",
]
