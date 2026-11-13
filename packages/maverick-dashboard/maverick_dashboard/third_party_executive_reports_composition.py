"""Stock lazy composition for tenant-bound third-party executive reports.

The composition derives tenant, authenticated principal and dashboard RBAC
role from the request.  It resolves only caller-selected opaque references
against existing Lightwork authorities and projects a closed metric set; raw
profiles, assessment answers, contract custom fields, credentials and portal
tokens never enter report storage.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Request
from maverick import third_party_executive_reports as reports
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

from .auth import (
    _dashboard_token_authenticated,
    anonymous_local_access_allowed,
    caller_role,
)

_STATIC_DASHBOARD_OPERATOR_SUBJECT = "dashboard-static-operator"


class ThirdPartyExecutiveReportsCompositionError(
    reports.ThirdPartyExecutiveReportConfigError
):
    """The deployment cannot construct the reporting authority."""


@dataclass(frozen=True, slots=True)
class ResolvedSource:
    entry: reports.SourceManifestEntry
    metrics: Mapping[str, int]


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_configuration_unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_configuration_unavailable"
        )
    return config


def settings_for_tenant(tenant_id: str) -> reports.ThirdPartyExecutiveReportConfig:
    settings = reports.ThirdPartyExecutiveReportConfig.from_mapping(
        _load_tenant_config(tenant_id)
    )
    if settings.enable is not True:
        raise ThirdPartyExecutiveReportsCompositionError("executive_report_disabled")
    return settings


def third_party_executive_reports_enabled(tenant_id: str) -> bool:
    try:
        return settings_for_tenant(tenant_id).enable is True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_request_authority_unavailable"
        )
    return request


def _subject(request: Request) -> str:
    verified = getattr(request.state, "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if isinstance(subject, str) and subject.strip() and len(subject) <= 512:
        return subject.strip()
    if _dashboard_token_authenticated(request):
        return _STATIC_DASHBOARD_OPERATOR_SUBJECT
    if anonymous_local_access_allowed():
        return "local-operator"
    raise reports.ThirdPartyExecutiveReportPermissionDenied(
        "executive_report_principal_unavailable"
    )


def _report_principal(request: Request, tenant_id: str) -> str:
    digest = hashlib.sha256(
        f"lightwork.third-party-executive-report.identity.v1:{tenant_id}:{_subject(request)}".encode()
    ).hexdigest()
    return f"tper-principal-{digest[:40]}"


def _source_principal(request: Request, tenant_id: str, source: str) -> str:
    subject = _subject(request)
    if source == "lifecycle":
        digest = hashlib.sha256(
            f"lightwork.third-party-lifecycle.identity.v1:{tenant_id}:{subject}".encode()
        ).hexdigest()
        return f"tpl-principal-{digest[:32]}"
    if source == "contract":
        digest = hashlib.sha256(
            f"lightwork.third-party-contract.identity.v1:{tenant_id}:{subject}".encode()
        ).hexdigest()
        return f"contract-principal-{digest[:32]}"
    digest = hashlib.sha256(
        f"lightwork.third-party-collaboration.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"tpc-principal-{digest[:40]}"


def _role(request: Request) -> str:
    selected = caller_role(request)
    if selected is None:
        if _dashboard_token_authenticated(request):
            return "operator"
        if anonymous_local_access_allowed():
            return "admin"
    if selected not in reports.ROLE_VIEWS:
        raise reports.ThirdPartyExecutiveReportPermissionDenied(
            "executive_report_role_unavailable"
        )
    return selected


def _clock_for(app: Any) -> Callable[[], float]:
    configured = getattr(app.state, "third_party_executive_reports_clock", None) or time.time
    if not callable(configured):
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_clock_unavailable"
        )

    def read() -> float:
        try:
            value = configured()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_clock_unavailable"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_clock_unavailable"
            )
        return float(value)

    return read


class ThirdPartyReportSourceResolver:
    """Resolve exact records twice and project only closed aggregate facts."""

    def __init__(self, app: Any, *, tenant_id: str, request: Request) -> None:
        self._app = app
        self._tenant = canonical_tenant_id(tenant_id)
        self._request = _request_for(app, request)

    def _intelligence_store(self):
        from maverick import third_party_intelligence as intelligence

        factory = getattr(self._app.state, "third_party_intelligence_store_factory", None)
        if callable(factory):
            return factory(tenant_id=self._tenant, request=self._request)
        with tenant_scope(tenant=self._tenant):
            return intelligence.ThirdPartyIntelligenceStore(
                data_dir(
                    "third_party_management",
                    "third-party-intelligence.sqlite3",
                    tenant=self._tenant,
                )
            )

    def _lifecycle_store(self):
        from maverick import third_party_lifecycle as lifecycle

        principal = _source_principal(self._request, self._tenant, "lifecycle")
        factory = getattr(self._app.state, "third_party_lifecycle_store_factory", None)
        if callable(factory):
            return factory(
                tenant_id=self._tenant,
                principal_ref=principal,
                principal_resolver=lambda: principal,
                request=self._request,
            )
        with tenant_scope(tenant=self._tenant):
            return lifecycle.ThirdPartyLifecycleStore(
                data_dir(
                    "third_party_management",
                    "third-party-lifecycle.sqlite3",
                    tenant=self._tenant,
                ),
                principal_resolver=lambda: principal,
            )

    def _contract_store(self):
        principal = _source_principal(self._request, self._tenant, "contract")
        factory = getattr(self._app.state, "third_party_contracts_store_factory", None)
        if not callable(factory):
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_contract_source_not_configured"
            )
        return factory(
            tenant_id=self._tenant,
            principal_ref=principal,
            request=self._request,
        )

    def _collaboration_store(self):
        principal = _source_principal(self._request, self._tenant, "collaboration")
        factory = getattr(
            self._app.state, "third_party_collaboration_store_factory", None
        )
        if not callable(factory):
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_collaboration_source_not_configured"
            )
        return factory(
            tenant_id=self._tenant,
            principal_ref=principal,
            principal_resolver=lambda: principal,
            request=self._request,
        )

    @staticmethod
    def _unavailable(
        selector: reports.SourceSelector,
        reason: str,
    ) -> ResolvedSource:
        return ResolvedSource(
            reports.SourceManifestEntry(
                reports.SOURCE_SCHEMA,
                selector.source_kind,
                selector.source_id,
                "unavailable",
                0,
                None,
                0,
                reason,
            ),
            {},
        )

    @staticmethod
    def _available(
        selector: reports.SourceSelector,
        *,
        revision: int,
        digest: str,
        metrics: Mapping[str, int],
    ) -> ResolvedSource:
        return ResolvedSource(
            reports.SourceManifestEntry(
                reports.SOURCE_SCHEMA,
                selector.source_kind,
                selector.source_id,
                "available",
                revision,
                digest,
                1,
                "none",
            ).normalized(),
            dict(metrics),
        )

    def _resolve_available(self, selector: reports.SourceSelector) -> ResolvedSource:
        kind = selector.source_kind
        identifier = selector.source_id
        if kind.startswith("intelligence_"):
            store = self._intelligence_store()
            if kind == "intelligence_vendor":
                record = store.get_vendor(self._tenant, identifier)
                metrics = {
                    "active_vendor_count": int(record.state == "active"),
                    "critical_vendor_count": int(record.criticality >= 5),
                    "high_risk_vendor_count": int(record.inherent_risk_level >= 4),
                }
            else:
                record = store.get_finding(self._tenant, identifier)
                metrics = {
                    "open_finding_count": int(record.disposition == "pending_review"),
                    "critical_finding_count": int(record.severity == "critical"),
                }
            return self._available(
                selector,
                revision=record.revision,
                digest=record.integrity_sha256,
                metrics=metrics,
            )
        if kind.startswith("lifecycle_"):
            store = self._lifecycle_store()
            if kind == "lifecycle_assessment":
                record = store.get_assessment(self._tenant, identifier)
                open_tasks = any(
                    isinstance(task, Mapping) and task.get("status") == "open"
                    for task in record.tasks
                )
                metrics = {
                    "open_assessment_count": int(open_tasks or record.route == "human_review"),
                    "high_risk_assessment_count": int(
                        record.highest_severity in {"high", "critical"}
                    ),
                }
            else:
                record = store.get_lifecycle(self._tenant, identifier)
                metrics = {
                    "active_lifecycle_count": int(record.stage == "active"),
                    "offboarding_lifecycle_count": int(record.stage == "offboarding"),
                }
            return self._available(
                selector,
                revision=record.revision,
                digest=record.integrity_sha256,
                metrics=metrics,
            )
        if kind == "contract_record":
            record = self._contract_store().get_record(self._tenant, identifier)
            metrics = {
                "contract_count": int(record.record_kind == "contract"),
                "active_contract_count": int(
                    record.record_kind == "contract" and record.status == "active"
                ),
                "engagement_count": int(record.record_kind == "engagement"),
                "active_engagement_count": int(
                    record.record_kind == "engagement" and record.status == "active"
                ),
            }
            return self._available(
                selector,
                revision=record.revision,
                digest=record.integrity_sha256,
                metrics=metrics,
            )
        invitation = self._collaboration_store().get_invitation(self._tenant, identifier)
        if not isinstance(invitation, Mapping):
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_collaboration_source_unavailable"
            )
        revision = invitation.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_collaboration_source_unavailable"
            )
        finalization = invitation.get("finalization")
        complete = isinstance(finalization, Mapping) and finalization.get("status") == "finalized"
        safe_digest = reports.canonical_sha256(dict(invitation))
        return self._available(
            selector,
            revision=revision,
            digest=safe_digest,
            metrics={
                "open_collaboration_count": int(invitation.get("status") == "active" and not complete),
                "completed_collaboration_count": int(complete),
            },
        )

    def resolve_one(self, selector: reports.SourceSelector) -> ResolvedSource:
        selected = selector.normalized()
        try:
            first = self._resolve_available(selected)
            second = self._resolve_available(selected)
            if first != second:
                raise reports.ThirdPartyExecutiveReportConflict(
                    "executive_report_source_changed"
                )
            return first
        except ThirdPartyExecutiveReportsCompositionError as exc:
            if "not_configured" in exc.error_code:
                return self._unavailable(selected, "source_not_configured")
            raise
        except reports.ThirdPartyExecutiveReportError:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            from maverick import third_party_collaboration as collaboration
            from maverick import third_party_contracts as contracts
            from maverick import third_party_intelligence as intelligence
            from maverick import third_party_lifecycle as lifecycle

            if isinstance(
                exc,
                (
                    intelligence.ThirdPartyIntelligenceNotFound,
                    lifecycle.ThirdPartyLifecycleNotFound,
                    contracts.ThirdPartyContractNotFound,
                    collaboration.ThirdPartyCollaborationNotFound,
                ),
            ):
                return self._unavailable(selected, "not_found")
            if isinstance(
                exc,
                (
                    intelligence.ThirdPartyIntelligencePermissionDenied,
                    lifecycle.ThirdPartyLifecyclePermissionDenied,
                    contracts.ThirdPartyContractPermissionDenied,
                    collaboration.ThirdPartyCollaborationPermissionDenied,
                ),
            ):
                raise reports.ThirdPartyExecutiveReportPermissionDenied(
                    "executive_report_source_permission_denied"
                ) from exc
            if isinstance(
                exc,
                (
                    intelligence.ThirdPartyIntelligenceIntegrityError,
                    lifecycle.ThirdPartyLifecycleIntegrityError,
                    contracts.ThirdPartyContractIntegrityError,
                    collaboration.ThirdPartyCollaborationIntegrityError,
                ),
            ):
                raise reports.ThirdPartyExecutiveReportIntegrityError(
                    "executive_report_source_integrity_failed"
                ) from exc
            return self._unavailable(selected, "source_unavailable")

    def resolve(
        self,
        selectors: Sequence[reports.SourceSelector],
        *,
        role_view: str,
        captured_at: float,
        max_sources: int,
    ) -> reports.ReportSnapshot:
        if isinstance(selectors, (str, bytes)) or len(selectors) > max_sources:
            raise reports.ThirdPartyExecutiveReportValidationError(
                "executive_report_sources_oversized"
            )
        normalized = tuple(sorted((item.normalized() for item in selectors), key=lambda item: (item.source_kind, item.source_id)))
        keys = [(item.source_kind, item.source_id) for item in normalized]
        if len(set(keys)) != len(keys):
            raise reports.ThirdPartyExecutiveReportValidationError(
                "executive_report_sources_not_canonical"
            )
        resolved = tuple(self.resolve_one(item) for item in normalized)
        totals: Counter[str] = Counter(
            {
                "selected_record_count": len(normalized),
                "available_record_count": sum(item.entry.state == "available" for item in resolved),
                "unavailable_record_count": sum(item.entry.state != "available" for item in resolved),
            }
        )
        for item in resolved:
            totals.update(item.metrics)
        metrics = tuple(
            reports.ReportMetric(metric_id, value)
            for metric_id, value in sorted(totals.items())
        )
        return reports.ReportSnapshot(
            reports.SNAPSHOT_SCHEMA,
            self._tenant,
            role_view,
            tuple(item.entry for item in resolved),
            metrics,
            captured_at,
            False,
        ).normalized(max_sources=max_sources)


class ThirdPartyExecutiveReportRuntime:
    def __init__(
        self,
        *,
        store: reports.ThirdPartyExecutiveReportStore,
        source_resolver: ThirdPartyReportSourceResolver,
        role_view: str,
        clock: Callable[[], float],
        max_sources: int,
    ) -> None:
        self.store = store
        self.source_resolver = source_resolver
        self.role_view = _role_value(role_view)
        self._clock = clock
        self._max_sources = max_sources

    def create_report(
        self,
        *,
        selectors: Sequence[reports.SourceSelector],
        brand: reports.BrandTokens,
        report_id: str | None,
        expected_absent_revision: int,
        idempotency_key: str,
        effect_guard: Callable[[], None] | None = None,
    ) -> reports.ExecutiveReportRecord:
        if self.role_view == "viewer":
            raise reports.ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_viewer_cannot_create"
            )
        captured_at = self._clock()
        snapshot = self.source_resolver.resolve(
            selectors,
            role_view=self.role_view,
            captured_at=captured_at,
            max_sources=self._max_sources,
        )
        return self.store.create_report(
            snapshot=snapshot,
            brand=brand,
            report_id=report_id,
            expected_absent_revision=expected_absent_revision,
            idempotency_key=idempotency_key,
            **({"effect_guard": effect_guard} if effect_guard is not None else {}),
        )


def _role_value(value: object) -> str:
    if not isinstance(value, str) or value not in reports.ROLE_VIEWS:
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_role_unavailable"
        )
    return value


def _build_runtime(
    app: Any,
    *,
    tenant_id: str,
    request: object,
) -> ThirdPartyExecutiveReportRuntime:
    tenant = canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)
    settings = settings_for_tenant(tenant)
    principal = _report_principal(selected, tenant)
    role_view = _role(selected)
    clock = _clock_for(app)

    def principal_resolver() -> str:
        if _report_principal(selected, tenant) != principal:
            raise reports.ThirdPartyExecutiveReportPermissionDenied(
                "executive_report_principal_changed"
            )
        return principal

    def config_gate() -> None:
        if settings_for_tenant(tenant) != settings:
            raise ThirdPartyExecutiveReportsCompositionError(
                "executive_report_configuration_changed"
            )

    path_factory = app.state.third_party_executive_reports_store_path_factory
    path = path_factory(tenant_id=tenant, request=selected)
    if not isinstance(path, (str, Path)):
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_storage_unavailable"
        )
    store = reports.ThirdPartyExecutiveReportStore(
        path,
        tenant_id=tenant,
        principal_resolver=principal_resolver,
        audit_authorizer=lambda: role_view in {"admin", "auditor"},
        maintenance_authorizer=lambda: role_view == "admin",
        config_gate=config_gate,
        config=settings,
        clock=clock,
    )
    resolver_factory = app.state.third_party_executive_reports_source_resolver_factory
    resolver = resolver_factory(tenant_id=tenant, request=selected)
    if not isinstance(resolver, ThirdPartyReportSourceResolver) and not callable(
        getattr(resolver, "resolve", None)
    ):
        raise ThirdPartyExecutiveReportsCompositionError(
            "executive_report_source_resolver_unavailable"
        )
    return ThirdPartyExecutiveReportRuntime(
        store=store,
        source_resolver=resolver,
        role_view=role_view,
        clock=clock,
        max_sources=settings.max_sources,
    )


def install_third_party_executive_reports_composition(app: Any) -> None:
    """Install lazy reporting seams without opening tenant stores."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "third_party_executive_reports_composition_installed"
    if getattr(state, marker, False):
        return
    defaults = {
        "third_party_executive_reports_store_path_factory": (
            lambda *, tenant_id, request: data_dir(
                "third_party_management",
                "executive-reports",
                "reports.sqlite3",
                tenant=canonical_tenant_id(tenant_id),
            )
        ),
        "third_party_executive_reports_source_resolver_factory": (
            lambda *, tenant_id, request: ThirdPartyReportSourceResolver(
                app,
                tenant_id=tenant_id,
                request=request,
            )
        ),
    }
    for name, value in defaults.items():
        existing = getattr(state, name, None)
        if existing is not None and not callable(existing):
            raise TypeError(f"{name} must be callable")
        if existing is None:
            setattr(state, name, value)
    if getattr(state, "third_party_executive_reports_runtime_factory", None) is None:
        state.third_party_executive_reports_runtime_factory = (
            lambda *, tenant_id, request: _build_runtime(
                app,
                tenant_id=tenant_id,
                request=request,
            )
        )
    elif not callable(state.third_party_executive_reports_runtime_factory):
        raise TypeError("third_party_executive_reports_runtime_factory must be callable")

    state.third_party_executive_reports_enabled_probe = (
        lambda tenant_id: third_party_executive_reports_enabled(tenant_id)
    )

    def readiness_probe(tenant_id: str) -> bool:
        try:
            settings_for_tenant(tenant_id)
            return all(
                callable(getattr(state, name, None))
                for name in (
                    "third_party_executive_reports_runtime_factory",
                    "third_party_executive_reports_store_path_factory",
                    "third_party_executive_reports_source_resolver_factory",
                )
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            return False

    state.third_party_executive_reports_readiness_probe = readiness_probe
    setattr(state, marker, True)


__all__ = [
    "ResolvedSource",
    "ThirdPartyExecutiveReportRuntime",
    "ThirdPartyExecutiveReportsCompositionError",
    "ThirdPartyReportSourceResolver",
    "install_third_party_executive_reports_composition",
    "settings_for_tenant",
    "third_party_executive_reports_enabled",
]
