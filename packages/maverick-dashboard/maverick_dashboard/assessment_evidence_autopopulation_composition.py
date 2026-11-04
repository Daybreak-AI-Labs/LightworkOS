"""Lazy production composition for evidence-assisted assessment proposals.

Installation is store-free.  A request-bound factory reuses the mounted AI
Evidence Analysis store, the tenant-scoped assessment authority, and the core
CAS applier only after the feature gate, tenant, principal, and dependency
checks succeed.  Deployments may inject a governed mapping resolver when their
criterion ids do not intentionally equal questionnaire question ids.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from maverick import assessment_evidence_autopopulation as autopop
from maverick.paths import canonical_tenant_id, tenant_scope

_CONFIG_KEYS = frozenset(
    {
        "enable",
        "apply_enabled",
        "retention_seconds",
        "max_records",
        "max_evidence_records_per_proposal",
        "max_citations_per_answer",
        "min_confidence_bps",
    }
)


class AssessmentEvidenceCompositionError(autopop.AssessmentEvidenceConfigError):
    """The deployment-owned assessment-evidence composition is unavailable."""


@dataclass(frozen=True, slots=True)
class AssessmentEvidenceCompositionSettings:
    core: autopop.AssessmentEvidenceSettings


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise AssessmentEvidenceCompositionError(f"{label} is outside its bound")
    return value


def assessment_evidence_autopopulation_settings(
    config: Mapping[str, Any],
) -> AssessmentEvidenceCompositionSettings | None:
    """Parse the exact default-off feature contract."""

    if not isinstance(config, Mapping):
        raise AssessmentEvidenceCompositionError(
            "assessment evidence configuration is unavailable"
        )
    section = config.get("assessment_evidence_autopopulation")
    if section is None:
        return None
    if not isinstance(section, Mapping):
        raise AssessmentEvidenceCompositionError(
            "assessment_evidence_autopopulation must be a table"
        )
    if any(key not in _CONFIG_KEYS for key in section):
        raise AssessmentEvidenceCompositionError(
            "assessment_evidence_autopopulation contains an unknown key"
        )
    enabled = section.get("enable", False)
    apply_enabled = section.get("apply_enabled", False)
    if type(enabled) is not bool or type(apply_enabled) is not bool:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence enable flags must be boolean"
        )
    if enabled is not True:
        return None
    evidence_section = config.get("ai_evidence_analysis")
    if not isinstance(evidence_section, Mapping) or evidence_section.get("enable") is not True:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence proposals require ai_evidence_analysis.enable = true"
        )
    defaults = autopop.AssessmentEvidenceSettings()
    return AssessmentEvidenceCompositionSettings(
        core=autopop.AssessmentEvidenceSettings(
            retention_seconds=_integer(
                section.get("retention_seconds", defaults.retention_seconds),
                "assessment_evidence_autopopulation.retention_seconds",
                60,
                10 * 366 * 86400,
            ),
            max_records=_integer(
                section.get("max_records", defaults.max_records),
                "assessment_evidence_autopopulation.max_records",
                1,
                10_000,
            ),
            max_evidence_records_per_proposal=_integer(
                section.get(
                    "max_evidence_records_per_proposal",
                    defaults.max_evidence_records_per_proposal,
                ),
                "assessment_evidence_autopopulation.max_evidence_records_per_proposal",
                1,
                32,
            ),
            max_citations_per_answer=_integer(
                section.get(
                    "max_citations_per_answer",
                    defaults.max_citations_per_answer,
                ),
                "assessment_evidence_autopopulation.max_citations_per_answer",
                1,
                32,
            ),
            min_confidence_bps=_integer(
                section.get("min_confidence_bps", defaults.min_confidence_bps),
                "assessment_evidence_autopopulation.min_confidence_bps",
                1,
                10_000,
            ),
            apply_enabled=apply_enabled,
        )
    )


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            loaded = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise AssessmentEvidenceCompositionError(
            "assessment evidence configuration is unavailable"
        )
    return loaded


def settings_for_tenant(tenant_id: str) -> AssessmentEvidenceCompositionSettings:
    settings = assessment_evidence_autopopulation_settings(
        _load_tenant_config(tenant_id)
    )
    if settings is None:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence auto-population is disabled"
        )
    return settings


def assessment_evidence_autopopulation_enabled(tenant_id: str) -> bool:
    try:
        return (
            assessment_evidence_autopopulation_settings(
                _load_tenant_config(tenant_id)
            )
            is not None
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _clock_for(app: Any) -> Callable[[], float]:
    selected = getattr(app.state, "assessment_evidence_autopopulation_clock", None)
    if selected is None:
        selected = time.time
    if not callable(selected):
        raise AssessmentEvidenceCompositionError(
            "assessment evidence clock is unavailable"
        )

    def read() -> float:
        try:
            value = selected()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise AssessmentEvidenceCompositionError(
                "assessment evidence clock is unavailable"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise AssessmentEvidenceCompositionError(
                "assessment evidence clock is unavailable"
            )
        return float(value)

    return read


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence request authority is unavailable"
        )
    return request


def _subject(request: Request) -> str:
    from .auth import (
        _dashboard_token_authenticated,
        anonymous_local_access_allowed,
        caller_principal,
    )

    subject = caller_principal(request)
    if isinstance(subject, str) and subject.strip() and len(subject) <= 512:
        return subject.strip()
    if anonymous_local_access_allowed():
        return "authorized-local-operator"
    if _dashboard_token_authenticated(request):
        return "static-dashboard-operator"
    raise AssessmentEvidenceCompositionError(
        "assessment evidence principal authority is unavailable"
    )


def expected_actor_ref(request: Request, tenant_id: str) -> str:
    tenant = canonical_tenant_id(tenant_id)
    digest = hashlib.sha256(
        f"lightwork.assessment-evidence.identity.v1:{tenant}:{_subject(request)}".encode()
    ).hexdigest()
    return f"assessment-evidence-principal-{digest[:40]}"


def _same_snapshot(
    tenant_id: str,
    expected: AssessmentEvidenceCompositionSettings,
) -> None:
    current = settings_for_tenant(tenant_id)
    if current != expected:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence tenant configuration changed"
        )


def build_assessment_evidence_autopopulation_service(
    *,
    tenant_id: str,
    config: Mapping[str, Any],
    assessment_resolver: Callable[[str], Mapping[str, Any] | None],
    evidence_resolver: Callable[[str], Any],
    mapping_resolver: Callable[
        [str, Mapping[str, Any], Sequence[Any], float],
        autopop.AssessmentEvidenceMappingAuthority,
    ] | None = None,
    assessment_applier: Callable[..., autopop.AssessmentApplyResult] = (
        autopop.apply_answers_to_assessment
    ),
    clock: Callable[[], float] = time.time,
    config_gate: Callable[[], None] | None = None,
) -> autopop.AssessmentEvidenceService:
    tenant = canonical_tenant_id(tenant_id)
    settings = assessment_evidence_autopopulation_settings(config)
    if settings is None:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence auto-population is disabled"
        )
    return autopop.AssessmentEvidenceService(
        tenant_id=tenant,
        settings=settings.core,
        assessment_resolver=assessment_resolver,
        evidence_resolver=evidence_resolver,
        mapping_resolver=mapping_resolver,
        assessment_applier=assessment_applier,
        clock=clock,
        config_gate=config_gate,
    )


def _assessment_resolver(tenant_id: str) -> Callable[[str], Mapping[str, Any] | None]:
    tenant = canonical_tenant_id(tenant_id)

    def resolve(assessment_id: str) -> Mapping[str, Any] | None:
        from maverick.assessment import load_saved

        with tenant_scope(tenant=tenant):
            return load_saved(assessment_id)

    return resolve


def _mapping_resolver_for(
    app: Any,
    tenant_id: str,
    request: Request,
) -> Callable[..., autopop.AssessmentEvidenceMappingAuthority] | None:
    factory = getattr(
        app.state,
        "assessment_evidence_mapping_resolver_factory",
        None,
    )
    if factory is None:
        return None
    if not callable(factory):
        raise AssessmentEvidenceCompositionError(
            "assessment evidence mapping resolver is unavailable"
        )
    try:
        resolver = factory(tenant_id, request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence mapping resolver is unavailable"
        ) from exc
    if not callable(resolver):
        raise AssessmentEvidenceCompositionError(
            "assessment evidence mapping resolver is unavailable"
        )
    return resolver


def _service_for(
    app: Any,
    tenant_id: str,
    actor_ref: str,
    request: object,
) -> autopop.AssessmentEvidenceService:
    tenant = canonical_tenant_id(tenant_id)
    selected_request = _request_for(app, request)
    expected_actor = expected_actor_ref(selected_request, tenant)
    if actor_ref != expected_actor:
        raise AssessmentEvidenceCompositionError(
            "assessment evidence principal authority is unavailable"
        )
    settings = settings_for_tenant(tenant)
    evidence_probe = getattr(app.state, "ai_evidence_analysis_enabled_probe", None)
    store_factory = getattr(app.state, "ai_evidence_analysis_store_factory", None)
    if not callable(evidence_probe) or not callable(store_factory):
        raise AssessmentEvidenceCompositionError(
            "AI evidence-analysis composition is unavailable"
        )
    try:
        evidence_enabled = evidence_probe(tenant)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AssessmentEvidenceCompositionError(
            "AI evidence-analysis configuration is unavailable"
        ) from exc
    if evidence_enabled is not True:
        raise AssessmentEvidenceCompositionError(
            "AI evidence-analysis is disabled or unavailable"
        )
    try:
        evidence_store = store_factory(tenant, expected_actor, selected_request)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise AssessmentEvidenceCompositionError(
            "AI evidence-analysis store is unavailable"
        ) from exc
    getter = getattr(evidence_store, "get_released", None)
    if not callable(getter):
        raise AssessmentEvidenceCompositionError(
            "AI evidence-analysis release authority is unavailable"
        )

    def resolve_evidence(analysis_id: str) -> Any:
        with tenant_scope(tenant=tenant):
            return getter(tenant, analysis_id)

    applier = getattr(
        app.state,
        "assessment_evidence_assessment_applier",
        autopop.apply_answers_to_assessment,
    )
    if not callable(applier):
        raise AssessmentEvidenceCompositionError(
            "assessment evidence application authority is unavailable"
        )
    clock = _clock_for(app)
    return autopop.AssessmentEvidenceService(
        tenant_id=tenant,
        settings=settings.core,
        assessment_resolver=_assessment_resolver(tenant),
        evidence_resolver=resolve_evidence,
        mapping_resolver=_mapping_resolver_for(app, tenant, selected_request),
        assessment_applier=applier,
        clock=clock,
        config_gate=lambda: _same_snapshot(tenant, settings),
    )


def assessment_evidence_autopopulation_readiness(
    app: Any,
    tenant_id: str,
    request: object,
) -> Mapping[str, Any]:
    """Side-effect-free readiness with an exact AI Evidence health probe."""

    tenant = canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)
    try:
        settings = settings_for_tenant(tenant)
    except AssessmentEvidenceCompositionError:
        return {
            "schema": "lightwork.assessment-evidence-readiness.v1",
            "enabled": False,
            "configured": False,
            "ready": False,
            "status_probe_opened_store": False,
            "status_probe_invoked_external_dependency": False,
        }
    evidence_probe = getattr(app.state, "ai_evidence_analysis_enabled_probe", None)
    store_factory = getattr(app.state, "ai_evidence_analysis_store_factory", None)
    readiness_probe = getattr(app.state, "ai_evidence_analysis_readiness_probe", None)
    configured = all(
        callable(value) for value in (evidence_probe, store_factory, readiness_probe)
    )
    evidence_enabled = False
    evidence_ready = False
    mapping_mode = "exact_criterion_question_identity"
    mapping_resolver_callable = False
    assessment_applier_callable = False
    if configured:
        try:
            evidence_enabled = evidence_probe(tenant) is True
            evidence_ready = (
                readiness_probe(tenant) is True if evidence_enabled else False
            )
            mapping_resolver = _mapping_resolver_for(app, tenant, selected)
            mapping_resolver_callable = mapping_resolver is None or callable(
                mapping_resolver
            )
            if mapping_resolver is not None:
                mapping_mode = "deployment_authority"
            assessment_applier_callable = callable(
                getattr(
                    app.state,
                    "assessment_evidence_assessment_applier",
                    autopop.apply_answers_to_assessment,
                )
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            evidence_enabled = False
            evidence_ready = False
            mapping_resolver_callable = False
            assessment_applier_callable = False
    configured = (
        configured and mapping_resolver_callable and assessment_applier_callable
    )
    ready = configured and evidence_enabled and evidence_ready
    return {
        "schema": "lightwork.assessment-evidence-readiness.v1",
        "tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(),
        "enabled": True,
        "configured": configured,
        "ready": ready,
        "apply_enabled": settings.core.apply_enabled,
        "evidence_analysis_enabled": evidence_enabled,
        "evidence_analysis_ready": evidence_ready,
        "authenticated_principal_present": bool(_subject(selected)),
        "mapping_mode": mapping_mode,
        "mapping_resolver_callable": mapping_resolver_callable,
        "assessment_applier_callable": assessment_applier_callable,
        "status_probe_opened_store": False,
        "status_probe_invoked_external_dependency": False,
        "live_provider_or_customer_acceptance_verified": False,
    }


def install_assessment_evidence_autopopulation_composition(app: Any) -> None:
    """Install lazy defaults while preserving deployment overrides."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    marker = "assessment_evidence_autopopulation_composition_installed"
    if getattr(state, marker, False):
        return
    defaults = {
        "assessment_evidence_autopopulation_enabled_probe": (
            assessment_evidence_autopopulation_enabled
        ),
        "assessment_evidence_autopopulation_service_factory": (
            lambda tenant_id, actor_ref, request: _service_for(
                app,
                tenant_id,
                actor_ref,
                request,
            )
        ),
        "assessment_evidence_autopopulation_readiness_probe": (
            lambda tenant_id, request: assessment_evidence_autopopulation_readiness(
                app,
                tenant_id,
                request,
            )
        ),
    }
    for name, value in defaults.items():
        if getattr(state, name, None) is None:
            setattr(state, name, value)
    setattr(state, marker, True)


__all__ = [
    "AssessmentEvidenceCompositionError",
    "AssessmentEvidenceCompositionSettings",
    "assessment_evidence_autopopulation_enabled",
    "assessment_evidence_autopopulation_readiness",
    "assessment_evidence_autopopulation_settings",
    "build_assessment_evidence_autopopulation_service",
    "expected_actor_ref",
    "install_assessment_evidence_autopopulation_composition",
    "settings_for_tenant",
]
