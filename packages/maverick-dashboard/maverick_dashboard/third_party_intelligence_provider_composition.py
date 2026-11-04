"""Tenant-exact production composition for third-party intelligence feeds.

Installation performs no provider I/O and resolves no secret.  Each scheduler
or readiness operation rebuilds authority from the active tenant's closed
configuration and current approved source revisions.  The browser cannot
choose a tenant, host, credential reference, transport, or signing key ID.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from maverick.paths import canonical_tenant_id, current_tenant_id_strict, data_dir, tenant_scope
from maverick.third_party_intelligence_providers import (
    ProviderCredentialEnrollment,
    ThirdPartyProviderComposition,
    ThirdPartyProviderConfigError,
    available_provider_concepts,
)

from .third_party_intelligence_scheduler import (
    ThirdPartyFeedScheduler,
    ThirdPartyFeedSchedulerDependencies,
)

_PROVIDER_KEYS = frozenset(
    {
        "enable",
        "enabled_providers",
        "generic_approved_host",
        "iss_corporate_solutions_host",
        "scheduler",
        "supplywisdom_host",
        "timeout_seconds",
    }
)
_KNOWN_PROVIDERS = frozenset(available_provider_concepts())
_NAMED_HOST_KEYS = {
    "supplywisdom": "supplywisdom_host",
    "iss_corporate_solutions": "iss_corporate_solutions_host",
}
_MAX_SOURCE_ENROLLMENTS = 1_000


class ThirdPartyProviderCompositionError(RuntimeError):
    """The tenant's closed provider runtime cannot be composed safely."""


@dataclass(frozen=True, slots=True)
class ThirdPartyProviderSettings:
    enabled_providers: tuple[str, ...]
    generic_approved_host: str | None
    named_provider_hosts: Mapping[str, str]
    timeout_seconds: float


def _require_tenant_scope(tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    current = current_tenant_id_strict()
    if current is None or canonical_tenant_id(current) != tenant:
        raise ThirdPartyProviderCompositionError("provider_tenant_scope_mismatch")
    return tenant


def provider_settings(config: object) -> ThirdPartyProviderSettings | None:
    """Parse the exact provider table; ``None`` means explicitly disabled."""

    if not isinstance(config, Mapping):
        raise ThirdPartyProviderCompositionError("provider_configuration_unavailable")
    root = config.get("third_party_management")
    if root is None:
        return None
    if not isinstance(root, Mapping):
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid")
    root_enabled = root.get("enable", False)
    if type(root_enabled) is not bool:
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid")
    intelligence = root.get("intelligence")
    if intelligence is None:
        return None
    if not isinstance(intelligence, Mapping):
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid")
    intelligence_enabled = intelligence.get("enable", False)
    if type(intelligence_enabled) is not bool:
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid")
    providers = intelligence.get("providers")
    if providers is None:
        return None
    if not isinstance(providers, Mapping) or set(providers) - _PROVIDER_KEYS:
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid")
    enabled = providers.get("enable", False)
    if type(enabled) is not bool:
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid")
    if not (root_enabled and intelligence_enabled and enabled):
        return None
    selected = providers.get("enabled_providers")
    if (
        not isinstance(selected, list)
        or not selected
        or len(selected) > len(_KNOWN_PROVIDERS)
        or any(not isinstance(item, str) or item not in _KNOWN_PROVIDERS for item in selected)
        or len(set(selected)) != len(selected)
    ):
        raise ThirdPartyProviderCompositionError("provider_allowlist_invalid")
    timeout = providers.get("timeout_seconds", 20)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 1 <= float(timeout) <= 120
    ):
        raise ThirdPartyProviderCompositionError("provider_timeout_invalid")
    named_hosts = {
        provider: str(providers[key])
        for provider, key in _NAMED_HOST_KEYS.items()
        if key in providers
    }
    generic_host = providers.get("generic_approved_host")
    if generic_host is not None and not isinstance(generic_host, str):
        raise ThirdPartyProviderCompositionError("provider_host_invalid")
    try:
        # Reuse the core constructor's exact host/enable invariants without
        # retaining this bootstrap object or performing any I/O.
        ThirdPartyProviderComposition(
            enabled_providers=tuple(selected),
            credential_enrollments=(),
            generic_approved_host=generic_host,
            named_provider_hosts=named_hosts,
            timeout_seconds=float(timeout),
        )
    except ThirdPartyProviderConfigError as exc:
        raise ThirdPartyProviderCompositionError("provider_configuration_invalid") from exc
    return ThirdPartyProviderSettings(
        enabled_providers=tuple(selected),
        generic_approved_host=generic_host,
        named_provider_hosts=named_hosts,
        timeout_seconds=float(timeout),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    _require_tenant_scope(tenant_id)
    try:
        from maverick import config as config_module

        loaded = config_module.load_config() or {}
        errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyProviderCompositionError(
            "provider_configuration_unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise ThirdPartyProviderCompositionError("provider_configuration_unavailable")
    return loaded


def _default_intelligence_store_for(tenant_id: str, _request: object = None):
    from maverick.third_party_intelligence import ThirdPartyIntelligenceStore

    tenant = canonical_tenant_id(tenant_id)
    with tenant_scope(tenant=tenant):
        return ThirdPartyIntelligenceStore(
            data_dir(
                "third_party_management",
                "third-party-intelligence.sqlite3",
                tenant=tenant,
            )
        )


def _default_runtime_store_for(tenant_id: str):
    from maverick.third_party_intelligence_runtime import ThirdPartyFeedRuntimeStore

    tenant = canonical_tenant_id(tenant_id)
    with tenant_scope(tenant=tenant):
        return ThirdPartyFeedRuntimeStore(
            data_dir(
                "third_party_management",
                "third-party-intelligence-feed-runtime.sqlite3",
                tenant=tenant,
            )
        )


def _source_key_id(source: Any) -> str:
    encoded = (
        "lightwork.third-party-provider-source-key.v1\x00"
        f"{source.tenant_id}\x00{source.provider}\x00{source.source_id}\x00"
        f"{source.credential_env}\x00{source.revision}\x00{source.integrity_sha256}"
    ).encode()
    return f"tpi-key-{hashlib.sha256(encoded).hexdigest()[:40]}"


def _credential_enrollments(
    store: Any,
    *,
    tenant_id: str,
    settings: ThirdPartyProviderSettings,
) -> tuple[ProviderCredentialEnrollment, ...]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        sources = store.list_sources(tenant, limit=_MAX_SOURCE_ENROLLMENTS)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyProviderCompositionError("provider_source_authority_unavailable") from exc
    if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence):
        raise ThirdPartyProviderCompositionError("provider_source_authority_invalid")
    result: list[ProviderCredentialEnrollment] = []
    seen: set[str] = set()
    for source in sources:
        source_id = getattr(source, "source_id", None)
        if (
            getattr(source, "tenant_id", None) != tenant
            or not isinstance(source_id, str)
            or source_id in seen
        ):
            raise ThirdPartyProviderCompositionError("provider_source_authority_invalid")
        seen.add(source_id)
        if getattr(source, "provider", None) not in settings.enabled_providers:
            continue
        state = getattr(source, "state", None)
        if (
            state not in {"active", "revoked"}
            or getattr(source, "approved_by", None) is None
            or "monitoring" not in getattr(source, "purposes", ())
        ):
            continue
        try:
            result.append(
                ProviderCredentialEnrollment(
                    tenant_id=tenant,
                    provider=source.provider,
                    source_id=source_id,
                    credential_ref=source.credential_env,
                    key_id=_source_key_id(source),
                    revision=source.revision,
                    state=state,
                )
            )
        except ThirdPartyProviderConfigError as exc:
            raise ThirdPartyProviderCompositionError(
                "provider_source_authority_invalid"
            ) from exc
    return tuple(result)


class _LazyTenantProviderFactory:
    def __init__(self, runtime: TenantThirdPartyProviderRuntime) -> None:
        self._runtime = runtime

    def create(self, provider: str, provenance_uri: str):
        tenant = current_tenant_id_strict()
        if tenant is None:
            raise ThirdPartyProviderCompositionError("provider_tenant_scope_missing")
        composition, _sources = self._runtime._composition(tenant, request=None)
        return composition.provider_factory.create(provider, provenance_uri)


class TenantThirdPartyProviderRuntime:
    """Fresh tenant-authority composition plus bounded scheduler lifecycle."""

    def __init__(
        self,
        *,
        intelligence_store_for: Callable[[str, object], Any] = (
            _default_intelligence_store_for
        ),
        runtime_store_for: Callable[[str], Any] = _default_runtime_store_for,
        config_loader: Callable[[str], Mapping[str, Any]] = _load_tenant_config,
        secret_resolver: Callable[[str], str | None] | None = None,
        transport: object | None = None,
        scheduler: ThirdPartyFeedScheduler | None = None,
    ) -> None:
        if not all(
            callable(item)
            for item in (intelligence_store_for, runtime_store_for, config_loader)
        ):
            raise TypeError("provider runtime factories must be callable")
        if secret_resolver is not None and not callable(secret_resolver):
            raise TypeError("provider secret resolver must be callable")
        if transport is not None and not callable(getattr(transport, "get_json", None)):
            raise TypeError("provider transport must implement get_json")
        self._intelligence_store_for = intelligence_store_for
        self._runtime_store_for = runtime_store_for
        self._config_loader = config_loader
        self._secret_resolver = secret_resolver
        self._transport = transport
        self.provider_factory = _LazyTenantProviderFactory(self)
        dependencies = ThirdPartyFeedSchedulerDependencies(
            intelligence_store_for=lambda tenant: self._intelligence_store_for(
                tenant, None
            ),
            runtime_store_for=self._runtime_store_for,
            provider_factory=self.provider_factory,
            credential_resolver=self.resolve_credential,
        )
        self.scheduler = scheduler or ThirdPartyFeedScheduler(dependencies)

    def _composition(
        self,
        tenant_id: str,
        *,
        request: object,
    ) -> tuple[ThirdPartyProviderComposition, int]:
        tenant = _require_tenant_scope(tenant_id)
        settings = provider_settings(self._config_loader(tenant))
        if settings is None:
            raise ThirdPartyProviderCompositionError("provider_runtime_disabled")
        store = self._intelligence_store_for(tenant, request)
        enrollments = _credential_enrollments(
            store,
            tenant_id=tenant,
            settings=settings,
        )
        try:
            composition = ThirdPartyProviderComposition(
                enabled_providers=settings.enabled_providers,
                credential_enrollments=enrollments,
                generic_approved_host=settings.generic_approved_host,
                named_provider_hosts=settings.named_provider_hosts,
                timeout_seconds=settings.timeout_seconds,
                secret_resolver=self._secret_resolver,
                transport=self._transport,
            )
        except ThirdPartyProviderConfigError as exc:
            raise ThirdPartyProviderCompositionError(
                "provider_composition_invalid"
            ) from exc
        return composition, len(enrollments)

    def resolve_credential(
        self,
        tenant_id: str,
        credential_ref: str,
        provider: str,
        source_id: str,
    ):
        composition, _count = self._composition(tenant_id, request=None)
        return composition.credential_resolver(
            tenant_id,
            credential_ref,
            provider,
            source_id,
        )

    def readiness(
        self,
        tenant_id: str,
        *,
        request: object = None,
    ) -> Mapping[str, object]:
        tenant = _require_tenant_scope(tenant_id)
        settings = provider_settings(self._config_loader(tenant))
        if settings is None:
            return {
                "schema": "lightwork.third-party-provider-runtime-readiness.v1",
                "enabled": False,
                "configured": False,
                "configuration_ready": False,
                "ready": False,
                "enabled_providers": [],
                "source_enrollment_count": 0,
                "status_secret_resolution": False,
                "status_provider_network_io": False,
                "licensed_provider_credential_verified": False,
                "live_provider_acceptance_verified": False,
            }
        composition, enrollment_count = self._composition(tenant, request=request)
        core = dict(composition.readiness())
        endpoints = core.pop("resolved_endpoints", {})
        core.update(
            {
                "schema": "lightwork.third-party-provider-runtime-readiness.v1",
                "enabled": True,
                "source_enrollment_count": enrollment_count,
                "resolved_endpoint_count": len(endpoints),
                "endpoint_authorities_returned": False,
                "status_secret_resolution": False,
                "status_provider_network_io": False,
            }
        )
        return core

    def source_readiness(
        self,
        tenant_id: str,
        source_id: str,
        *,
        request: object = None,
        verify_secret: bool = False,
    ) -> Mapping[str, object]:
        tenant = canonical_tenant_id(tenant_id)
        composition, _count = self._composition(tenant, request=request)
        store = self._intelligence_store_for(tenant, request)
        try:
            source = store.get_source(tenant, source_id)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ThirdPartyProviderCompositionError("provider_source_not_found") from exc
        if (
            source.provider not in composition.provider_factory.enabled_providers
            or source.state not in {"active", "revoked"}
            or source.approved_by is None
            or "monitoring" not in source.purposes
        ):
            raise ThirdPartyProviderCompositionError(
                "provider_source_not_approved_for_monitoring"
            )
        result = dict(
            composition.credential_authority.source_readiness(
                tenant_id=tenant,
                credential_ref=source.credential_env,
                provider=source.provider,
                source_id=source.source_id,
                verify_secret=verify_secret,
            )
        )
        result.update(
            {
                "source_id": source.source_id,
                "provider": source.provider,
                "source_revision": source.revision,
                "ready_for_provider_attempt": result.get("ready") is True,
                "provider_network_io": False,
                "live_provider_acceptance_verified": False,
            }
        )
        return result

    def status(self) -> Mapping[str, object]:
        return self.scheduler.status()

    def start(self) -> bool:
        return self.scheduler.start()

    def stop(self, *, timeout: float = 5.0) -> bool:
        return self.scheduler.stop(timeout=timeout)


def _runtime_for_app(app: Any) -> TenantThirdPartyProviderRuntime:
    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    configured_store = getattr(state, "third_party_intelligence_store_factory", None)
    if configured_store is None:

        def configured_store(*, tenant_id: str, request: object = None):
            return _default_intelligence_store_for(tenant_id, request)

        state.third_party_intelligence_store_factory = configured_store
    elif not callable(configured_store):
        raise TypeError("third-party intelligence store factory must be callable")
    runtime_store = getattr(state, "third_party_intelligence_runtime_store_factory", None)
    if runtime_store is None:
        runtime_store = _default_runtime_store_for
        state.third_party_intelligence_runtime_store_factory = runtime_store
    elif not callable(runtime_store):
        raise TypeError("third-party intelligence runtime store factory must be callable")
    secret_resolver = getattr(state, "third_party_intelligence_secret_resolver", None)
    if secret_resolver is not None and not callable(secret_resolver):
        raise TypeError("third-party intelligence secret resolver must be callable")
    transport = getattr(state, "third_party_intelligence_provider_transport", None)
    return TenantThirdPartyProviderRuntime(
        intelligence_store_for=lambda tenant, request: configured_store(
            tenant_id=tenant,
            request=request,
        ),
        runtime_store_for=runtime_store,
        secret_resolver=secret_resolver,
        transport=transport,
    )


def attach_third_party_intelligence_provider_composition(
    app: Any,
    *,
    runtime: TenantThirdPartyProviderRuntime | None = None,
) -> TenantThirdPartyProviderRuntime:
    """Attach lazy composition plus scheduler startup/shutdown to the app."""

    state = getattr(app, "state", None)
    router = getattr(app, "router", None)
    previous = getattr(router, "lifespan_context", None)
    if state is None or router is None or not callable(previous):
        raise TypeError("app must expose state and a lifespan-capable router")
    existing = getattr(state, "third_party_intelligence_provider_runtime", None)
    if existing is not None:
        if runtime is None or existing is runtime:
            return existing
        raise RuntimeError("a third-party provider runtime is already attached")
    selected = runtime or _runtime_for_app(app)

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "third_party_feed", selected, scheduler=selected.scheduler):
                yield

    app.router.lifespan_context = lifespan
    state.third_party_intelligence_provider_runtime = selected
    state.third_party_intelligence_feed_scheduler = selected.scheduler
    return selected


__all__ = [
    "TenantThirdPartyProviderRuntime",
    "ThirdPartyProviderCompositionError",
    "ThirdPartyProviderSettings",
    "attach_third_party_intelligence_provider_composition",
    "provider_settings",
]
