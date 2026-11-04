"""Production composition for the local privacy-notice publication bridge.

The composition is deliberately closed and lazy.  Attaching it opens no
tenant store.  A run is possible only for an explicitly active tenant and an
exact, server-owned notice/consent target binding.  The resolver re-reads the
notice release, obtains two independent exact consent previews, and derives
the property/publication CAS revisions from the tenant-private authorities.

Only Lightwork's local consent publication store is mutated.  This module has
no provider transport, site writer, SDK deployer, or live-acceptance claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from maverick.consent_publishing import ConsentPublishingStore
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from maverick.privacy_notice_governance import (
    NoticeRelease,
    PrivacyNoticeGovernanceStore,
    PublicationIntent,
)
from maverick.privacy_notice_publication_bridge import (
    ConsentPublicationTarget,
    PrivacyNoticePublicationBridge,
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_BINDINGS = 1_000


class PrivacyNoticePublicationCompositionError(RuntimeError):
    """The deployment-owned publication composition is unavailable."""


@dataclass(frozen=True, slots=True)
class PublicationTargetBinding:
    binding_id: str
    tenant_id: str
    notice_id: str
    consent_publication_ref: str
    property_id: str
    rule_group_id: str
    rule_group_version: int
    notice_resource_id: str
    notice_resource_version: int
    authority_sha256: str


@dataclass(frozen=True, slots=True)
class PrivacyNoticePublicationSettings:
    enabled: bool
    scheduler_enabled: bool
    active_tenants: tuple[str, ...]
    bindings: tuple[PublicationTargetBinding, ...]
    poll_seconds: int
    retry_max_seconds: int
    tenant_limit: int
    lease_seconds: int
    retry_delay_seconds: int
    config_sha256: str


@dataclass(frozen=True, slots=True)
class PrivacyNoticePublicationRuntime:
    tenant_id: str
    config_sha256: str
    notice_store: PrivacyNoticeGovernanceStore
    consent_store: ConsentPublishingStore
    bridge: PrivacyNoticePublicationBridge
    local_only: bool = True
    provider_network_io: bool = False
    provider_writes: bool = False
    site_mutation: bool = False
    sdk_deployment: bool = False

    def run_once(self):
        return self.bridge.process_next()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError, RecursionError) as exc:
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice publication configuration is not canonical"
        ) from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise PrivacyNoticePublicationCompositionError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PrivacyNoticePublicationCompositionError(f"{label} is outside its bound")
    return value


def _runtime_section(config: Mapping[str, Any]) -> object:
    privacy = config.get("privacy_automation")
    notice = privacy.get("notice_governance") if isinstance(privacy, Mapping) else None
    return notice.get("publication_runtime") if isinstance(notice, Mapping) else None


def settings_from_config(config: Mapping[str, Any]) -> PrivacyNoticePublicationSettings:
    """Parse the exact closed runtime contract without opening storage."""

    section = _runtime_section(config)
    if section is None:
        material = {"schema": "lightwork.privacy-notice-publication-config.v1", "enable": False}
        return PrivacyNoticePublicationSettings(
            enabled=False,
            scheduler_enabled=False,
            active_tenants=(),
            bindings=(),
            poll_seconds=30,
            retry_max_seconds=300,
            tenant_limit=100,
            lease_seconds=60,
            retry_delay_seconds=60,
            config_sha256=_sha256(material),
        )
    privacy = config.get("privacy_automation")
    notice = privacy.get("notice_governance") if isinstance(privacy, Mapping) else None
    consent = config.get("consent_preferences")
    publishing = consent.get("publishing") if isinstance(consent, Mapping) else None
    if not isinstance(section, Mapping):
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice publication_runtime must be a table"
        )
    allowed = {
        "enable",
        "scheduler_enable",
        "active_tenants",
        "bindings",
        "poll_seconds",
        "retry_max_seconds",
        "tenant_limit",
        "lease_seconds",
        "retry_delay_seconds",
    }
    if set(section) - allowed:
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice publication_runtime contains an unknown key"
        )
    enabled = section.get("enable", False)
    scheduler_enabled = section.get("scheduler_enable", False)
    if type(enabled) is not bool or type(scheduler_enabled) is not bool:
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice publication runtime gates must be boolean"
        )
    if enabled and not (
        isinstance(privacy, Mapping)
        and privacy.get("enable") is True
        and isinstance(notice, Mapping)
        and notice.get("enable") is True
        and isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(publishing, Mapping)
        and publishing.get("enable") is True
    ):
        raise PrivacyNoticePublicationCompositionError(
            "enabled publication runtime requires notice governance and consent publishing"
        )
    if scheduler_enabled and not enabled:
        raise PrivacyNoticePublicationCompositionError(
            "publication scheduler requires publication runtime enablement"
        )
    raw_tenants = section.get("active_tenants", [])
    if (
        not isinstance(raw_tenants, list)
        or len(raw_tenants) > 10_000
        or any(not isinstance(item, str) for item in raw_tenants)
    ):
        raise PrivacyNoticePublicationCompositionError("active_tenants is invalid")
    try:
        active_tenants = tuple(sorted({canonical_tenant_id(item) for item in raw_tenants}))
    except (TypeError, ValueError) as exc:
        raise PrivacyNoticePublicationCompositionError("active_tenants is invalid") from exc
    raw_bindings = section.get("bindings", {})
    if (
        not isinstance(raw_bindings, Mapping)
        or len(raw_bindings) > _MAX_BINDINGS
        or any(not isinstance(key, str) for key in raw_bindings)
    ):
        raise PrivacyNoticePublicationCompositionError("publication bindings are invalid")
    bindings: list[PublicationTargetBinding] = []
    required = {
        "tenant_id",
        "notice_id",
        "consent_publication_ref",
        "property_id",
        "rule_group_id",
        "rule_group_version",
        "notice_resource_id",
        "notice_resource_version",
    }
    for raw_name in sorted(raw_bindings):
        binding_id = _identifier(raw_name, "binding_id")
        raw = raw_bindings[raw_name]
        if not isinstance(raw, Mapping) or set(raw) != required:
            raise PrivacyNoticePublicationCompositionError(
                "each publication binding must contain only the exact required fields"
            )
        try:
            tenant_id = canonical_tenant_id(raw["tenant_id"])
        except (TypeError, ValueError) as exc:
            raise PrivacyNoticePublicationCompositionError(
                "publication binding tenant_id is invalid"
            ) from exc
        body = {
            "binding_id": binding_id,
            "tenant_id": tenant_id,
            "notice_id": _identifier(raw["notice_id"], "notice_id"),
            "consent_publication_ref": _identifier(
                raw["consent_publication_ref"], "consent_publication_ref"
            ),
            "property_id": _identifier(raw["property_id"], "property_id"),
            "rule_group_id": _identifier(raw["rule_group_id"], "rule_group_id"),
            "rule_group_version": _integer(
                raw["rule_group_version"], "rule_group_version", 1, 2**31 - 1
            ),
            "notice_resource_id": _identifier(
                raw["notice_resource_id"], "notice_resource_id"
            ),
            "notice_resource_version": _integer(
                raw["notice_resource_version"],
                "notice_resource_version",
                1,
                2**31 - 1,
            ),
        }
        bindings.append(PublicationTargetBinding(**body, authority_sha256=_sha256(body)))
    identities = [
        (binding.tenant_id, binding.consent_publication_ref) for binding in bindings
    ]
    if len(set(identities)) != len(identities):
        raise PrivacyNoticePublicationCompositionError(
            "tenant consent publication references must be unique"
        )
    if enabled and (not active_tenants or not bindings):
        raise PrivacyNoticePublicationCompositionError(
            "enabled publication runtime requires active tenants and bindings"
        )
    if any(binding.tenant_id not in active_tenants for binding in bindings):
        raise PrivacyNoticePublicationCompositionError(
            "every publication binding tenant must be explicitly active"
        )
    for tenant in active_tenants:
        if not any(binding.tenant_id == tenant for binding in bindings):
            raise PrivacyNoticePublicationCompositionError(
                "every active publication tenant requires an exact binding"
            )
    material = {
        "schema": "lightwork.privacy-notice-publication-config.v1",
        "section": dict(section),
    }
    return PrivacyNoticePublicationSettings(
        enabled=enabled,
        scheduler_enabled=scheduler_enabled,
        active_tenants=active_tenants,
        bindings=tuple(bindings),
        poll_seconds=_integer(section.get("poll_seconds", 30), "poll_seconds", 5, 86_400),
        retry_max_seconds=_integer(
            section.get("retry_max_seconds", 300),
            "retry_max_seconds",
            5,
            86_400,
        ),
        tenant_limit=_integer(section.get("tenant_limit", 100), "tenant_limit", 1, 1_000),
        lease_seconds=_integer(section.get("lease_seconds", 60), "lease_seconds", 1, 3_600),
        retry_delay_seconds=_integer(
            section.get("retry_delay_seconds", 60),
            "retry_delay_seconds",
            0,
            604_800,
        ),
        config_sha256=_sha256(material),
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            loaded = config_module.load_config() or {}
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice tenant configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice tenant configuration is invalid"
        )
    return loaded


def settings_for_tenant(tenant_id: str) -> PrivacyNoticePublicationSettings:
    return settings_from_config(_load_tenant_config(tenant_id))


def _worker_principal(tenant_id: str) -> str:
    digest = hashlib.sha256(
        f"lightwork.privacy-notice-publication.worker.v1:{tenant_id}".encode()
    ).hexdigest()
    return f"png-publication-worker-{digest[:32]}"


def _default_notice_store(tenant_id: str, principal_ref: str) -> PrivacyNoticeGovernanceStore:
    with tenant_scope(tenant=tenant_id):
        return PrivacyNoticeGovernanceStore(
            data_dir(
                "privacy_automation",
                "privacy-notice-governance.sqlite3",
                tenant=tenant_id,
            ),
            principal_resolver=lambda: principal_ref,
        )


def _default_consent_store(tenant_id: str) -> ConsentPublishingStore:
    return ConsentPublishingStore(
        data_dir(
            "consent_preferences",
            "consent-publishing.sqlite3",
            tenant=tenant_id,
        )
    )


def _stores(app: Any, tenant_id: str, principal_ref: str):
    notice_factory = getattr(app.state, "privacy_notice_publication_notice_store_factory", None)
    consent_factory = getattr(app.state, "privacy_notice_publication_consent_store_factory", None)
    if notice_factory is not None and not callable(notice_factory):
        raise PrivacyNoticePublicationCompositionError("notice store factory is invalid")
    if consent_factory is not None and not callable(consent_factory):
        raise PrivacyNoticePublicationCompositionError("consent store factory is invalid")
    notice_store = (
        notice_factory(tenant_id=tenant_id, principal_ref=principal_ref)
        if callable(notice_factory)
        else _default_notice_store(tenant_id, principal_ref)
    )
    consent_store = (
        consent_factory(tenant_id=tenant_id)
        if callable(consent_factory)
        else _default_consent_store(tenant_id)
    )
    if type(notice_store) is not PrivacyNoticeGovernanceStore:
        raise PrivacyNoticePublicationCompositionError("notice store authority is invalid")
    if not isinstance(consent_store, ConsentPublishingStore):
        raise PrivacyNoticePublicationCompositionError("consent store authority is invalid")
    return notice_store, consent_store


class ExactPublicationTargetResolver:
    """Resolve one intent only from verified local authorities and exact config."""

    def __init__(
        self,
        *,
        tenant_id: str,
        settings: PrivacyNoticePublicationSettings,
        notice_store: PrivacyNoticeGovernanceStore,
        consent_store: ConsentPublishingStore,
    ) -> None:
        self._tenant = canonical_tenant_id(tenant_id)
        self._settings = settings
        self._notice = notice_store
        self._consent = consent_store

    def __call__(
        self,
        intent: PublicationIntent,
        release: NoticeRelease,
        rollback_release: NoticeRelease | None,
    ) -> ConsentPublicationTarget:
        selected = rollback_release or release
        candidates = [
            binding
            for binding in self._settings.bindings
            if binding.tenant_id == self._tenant
            and binding.notice_id == selected.notice_id
            and hmac.compare_digest(
                binding.consent_publication_ref,
                selected.consent_publication_ref,
            )
            and binding.property_id == selected.property_id
        ]
        if len(candidates) != 1:
            raise PrivacyNoticePublicationCompositionError(
                "exact publication target binding is unavailable"
            )
        binding = candidates[0]
        reread = self._notice.get_release(
            self._tenant,
            selected.notice_id,
            selected.version,
        )
        if reread != selected:
            raise PrivacyNoticePublicationCompositionError(
                "notice release authority changed during target resolution"
            )
        first = self._consent.preview(
            self._tenant,
            binding.property_id,
            binding.rule_group_id,
            binding.rule_group_version,
        )
        second = self._consent.preview(
            self._tenant,
            binding.property_id,
            binding.rule_group_id,
            binding.rule_group_version,
        )
        if _sha256(first) != _sha256(second):
            raise PrivacyNoticePublicationCompositionError(
                "consent target authority changed during target resolution"
            )
        bundle = second.get("bundle") if isinstance(second, Mapping) else None
        property_snapshot = bundle.get("property") if isinstance(bundle, Mapping) else None
        rule_group = bundle.get("rule_group") if isinstance(bundle, Mapping) else None
        resources = bundle.get("resources") if isinstance(bundle, Mapping) else None
        notices = [
            item
            for item in (resources if isinstance(resources, list) else [])
            if isinstance(item, Mapping)
            and item.get("resource_kind") == "notice"
            and item.get("resource_id") == binding.notice_resource_id
            and item.get("locale") == ""
            and item.get("version") == binding.notice_resource_version
        ]
        if (
            not isinstance(property_snapshot, Mapping)
            or property_snapshot.get("property_id") != binding.property_id
            or isinstance(property_snapshot.get("revision"), bool)
            or not isinstance(property_snapshot.get("revision"), int)
            or not isinstance(rule_group, Mapping)
            or rule_group.get("resource_id") != binding.rule_group_id
            or rule_group.get("version") != binding.rule_group_version
            or len(notices) != 1
            or not hmac.compare_digest(
                str(second.get("bundle_sha256", "")), selected.configuration_sha256
            )
            or not hmac.compare_digest(
                str(rule_group.get("resource_sha256", "")), selected.policy_sha256
            )
            or not isinstance(notices[0].get("payload"), Mapping)
            or not hmac.compare_digest(
                str(notices[0]["payload"].get("document_sha256", "")),
                selected.content_sha256,
            )
        ):
            raise PrivacyNoticePublicationCompositionError(
                "exact publication target authority does not match the notice release"
            )
        history = self._consent.publication_history(
            self._tenant,
            binding.property_id,
            limit=500,
        )
        items = history.get("items") if isinstance(history, Mapping) else None
        truncated = history.get("truncated") if isinstance(history, Mapping) else None
        if not isinstance(items, list) or type(truncated) is not bool:
            raise PrivacyNoticePublicationCompositionError(
                "consent publication history is invalid"
            )
        current_revision = int(items[0]["publication_revision"]) if items else 0
        target_publication_id = None
        if intent.action == "rollback":
            matches = [
                item
                for item in items
                if isinstance(item, Mapping)
                and item.get("property_id") == binding.property_id
                and item.get("property_revision") == property_snapshot["revision"]
                and item.get("action") != "withdraw"
                and hmac.compare_digest(
                    str(item.get("bundle_sha256", "")), selected.configuration_sha256
                )
            ]
            if not matches:
                suffix = " within complete history" if not truncated else " within bounded history"
                raise PrivacyNoticePublicationCompositionError(
                    "exact rollback bundle is unavailable" + suffix
                )
            chosen = min(matches, key=lambda item: int(item["publication_revision"]))
            target_publication_id = _identifier(
                chosen.get("publication_id"), "target_publication_id"
            )
        return ConsentPublicationTarget(
            tenant_id=self._tenant,
            intent_id=intent.intent_id,
            action=intent.action,
            intent_release_sha256=release.definition_sha256,
            notice_id=selected.notice_id,
            selected_release_version=selected.version,
            selected_release_sha256=selected.definition_sha256,
            consent_publication_ref=binding.consent_publication_ref,
            property_id=binding.property_id,
            rule_group_id=binding.rule_group_id,
            rule_group_version=binding.rule_group_version,
            notice_resource_id=binding.notice_resource_id,
            notice_resource_version=binding.notice_resource_version,
            expected_property_revision=int(property_snapshot["revision"]),
            expected_publication_revision=current_revision,
            target_publication_id=target_publication_id,
        )


def build_runtime(app: Any, tenant_id: str) -> PrivacyNoticePublicationRuntime:
    tenant = canonical_tenant_id(tenant_id)
    settings = settings_for_tenant(tenant)
    if not settings.enabled or tenant not in settings.active_tenants:
        raise PrivacyNoticePublicationCompositionError(
            "privacy-notice publication runtime is not enabled for this tenant"
        )
    principal = _worker_principal(tenant)
    notice_store, consent_store = _stores(app, tenant, principal)
    resolver = ExactPublicationTargetResolver(
        tenant_id=tenant,
        settings=settings,
        notice_store=notice_store,
        consent_store=consent_store,
    )
    bridge = PrivacyNoticePublicationBridge(
        notice_store=notice_store,
        consent_store=consent_store,
        tenant_resolver=lambda: tenant,
        target_resolver=resolver,
        lease_seconds=settings.lease_seconds,
        retry_delay_seconds=settings.retry_delay_seconds,
    )
    return PrivacyNoticePublicationRuntime(
        tenant_id=tenant,
        config_sha256=settings.config_sha256,
        notice_store=notice_store,
        consent_store=consent_store,
        bridge=bridge,
    )


def readiness(app: Any, tenant_id: str) -> Mapping[str, object]:
    """Configuration-only readiness; never open a store or process an intent."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        settings = settings_for_tenant(tenant)
        configured = bool(
            settings.enabled
            and tenant in settings.active_tenants
            and any(binding.tenant_id == tenant for binding in settings.bindings)
        )
        valid = True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        settings = None
        configured = False
        valid = False
    return {
        "schema": "lightwork.privacy-notice-publication-readiness.v1",
        "tenant_id": tenant,
        "enabled": bool(settings and settings.enabled),
        "configured": configured,
        "configuration_preflight_ready": configured and valid,
        "executable_ready": False,
        "execution_preflight_required": configured and valid,
        "config_valid": valid,
        "config_sha256": settings.config_sha256 if settings else None,
        "binding_count": (
            sum(binding.tenant_id == tenant for binding in settings.bindings)
            if settings
            else 0
        ),
        "status_opened_tenant_store": False,
        "status_processed_intent": False,
        "local_consent_publication_only": True,
        "provider_network_io": False,
        "provider_writes": False,
        "site_mutation": False,
        "sdk_deployment": False,
        "live_acceptance_verified": False,
    }


def attach_privacy_notice_publication_composition(app: Any) -> None:
    state = app.state
    factories = {
        "privacy_notice_publication_runtime_factory": lambda tenant_id: build_runtime(
            app, tenant_id
        ),
        "privacy_notice_publication_readiness_probe": lambda tenant_id: readiness(
            app, tenant_id
        ),
    }
    for name, value in factories.items():
        current = getattr(state, name, None)
        if current is None:
            setattr(state, name, value)
        elif not callable(current):
            raise TypeError(f"{name} must be callable")


__all__ = [
    "ExactPublicationTargetResolver",
    "PrivacyNoticePublicationCompositionError",
    "PrivacyNoticePublicationRuntime",
    "PrivacyNoticePublicationSettings",
    "PublicationTargetBinding",
    "attach_privacy_notice_publication_composition",
    "build_runtime",
    "readiness",
    "settings_for_tenant",
    "settings_from_config",
]
