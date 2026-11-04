"""Fail-closed production composition for governed candidate promotion.

The dashboard owns identity and current role resolution. Research-run rights,
artifact observations, deployment effects, and policy remain separate trusted
authorities. This module joins them lazily without making a browser request an
authority source or giving a research worker a release credential.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Mapping, Sequence
from typing import Any

from maverick.candidate_promotion import (
    ArtifactCommitment,
    ArtifactObservation,
    CanaryInvariant,
    CandidatePromotions,
    LineageCommitment,
    PromotionAuthority,
    PromotionPolicy,
    PromotionTargetPreset,
    RunPromotionAdmission,
    StudyClaim,
    TrustedStudyAdmission,
)
from maverick.paths import canonical_tenant_id, tenant_scope

from . import rbac, workspace_tenants
from .auth import global_role_for_principal

_ACTIONS = tuple(sorted(("activate", "canary", "reconcile", "review", "rollback", "stage")))
_SECTION_KEYS = frozenset({
    "enable",
    "allowed_targets",
    "review_ttl_seconds",
    "canary_metric",
    "canary_comparison",
    "canary_threshold",
})


class CandidatePromotionCompositionError(RuntimeError):
    """A deployment-owned promotion dependency is absent or malformed."""


def _digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CandidatePromotionCompositionError(
            "candidate promotion policy is not canonical"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _global_config() -> Mapping[str, Any]:
    from maverick import config

    try:
        loaded = config.load_global_config()
        errors = config.config_source_errors(include_tenant=False)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise CandidatePromotionCompositionError(
            "candidate promotion configuration is unavailable"
        ) from exc
    if errors or not isinstance(loaded, Mapping):
        raise CandidatePromotionCompositionError(
            "candidate promotion configuration source is invalid"
        )
    return loaded


def policy_from_config(config: Mapping[str, Any]) -> PromotionPolicy | None:
    """Parse one closed, deployment-global promotion policy."""

    from maverick import config as config_module

    if not isinstance(config, Mapping):
        raise CandidatePromotionCompositionError("candidate promotion config must be a table")
    section = config.get("candidate_promotion", {})
    if not isinstance(section, Mapping):
        raise CandidatePromotionCompositionError("candidate_promotion must be a table")
    if set(section) - _SECTION_KEYS:
        raise CandidatePromotionCompositionError("candidate_promotion key is unsupported")
    if not config_module.candidate_promotion_enabled(dict(config)):
        return None
    if "enable" in section and type(section.get("enable")) is not bool:
        raise CandidatePromotionCompositionError("candidate_promotion.enable must be boolean")
    targets = section.get("allowed_targets", ["installed-lightwork"])
    if (
        isinstance(targets, str | bytes)
        or not isinstance(targets, Sequence)
        or not targets
        or len(targets) > 64
        or any(not isinstance(item, str) for item in targets)
    ):
        raise CandidatePromotionCompositionError(
            "candidate_promotion.allowed_targets must be a bounded list"
        )
    exact_targets = tuple(sorted(set(targets)))
    if len(exact_targets) != len(targets):
        raise CandidatePromotionCompositionError(
            "candidate_promotion.allowed_targets must be unique"
        )
    ttl = section.get("review_ttl_seconds", 3600)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= 604800:
        raise CandidatePromotionCompositionError(
            "candidate_promotion.review_ttl_seconds is outside its bound"
        )
    metric = section.get("canary_metric", "error_rate")
    comparison = section.get("canary_comparison", "at_most")
    threshold = section.get("canary_threshold", 0.05)
    if (
        not isinstance(metric, str)
        or comparison not in {"at_least", "at_most"}
        or isinstance(threshold, bool)
        or not isinstance(threshold, int | float)
        or not math.isfinite(float(threshold))
    ):
        raise CandidatePromotionCompositionError(
            "candidate_promotion canary invariant is invalid"
        )
    material = {
        "targets": exact_targets,
        "review_ttl_seconds": ttl,
        "canary_metric": metric,
        "canary_comparison": comparison,
        "canary_threshold": float(threshold),
    }
    try:
        return PromotionPolicy(
            policy_id="installed-candidate-promotion",
            version="config-" + _digest(material)[:24],
            allowed_targets=exact_targets,
            role_actions=(("release_admin", _ACTIONS),),
            canary_invariants=(
                CanaryInvariant(metric, str(comparison), float(threshold)),
            ),
            review_ttl_seconds=ttl,
        )
    except ValueError as exc:
        raise CandidatePromotionCompositionError(
            "candidate promotion policy is invalid"
        ) from exc


def candidate_promotion_capability_enabled() -> bool:
    """Side-effect-free availability probe for the app status path."""

    try:
        return policy_from_config(_global_config()) is not None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _policy() -> PromotionPolicy:
    policy = policy_from_config(_global_config())
    if policy is None:
        raise CandidatePromotionCompositionError("candidate promotion is disabled")
    return policy


def _authority(tenant: str, principal: str) -> PromotionAuthority:
    """Resolve a named, active global administrator at the effect boundary."""

    from maverick.tenant.registry import assert_tenant_active, get_tenant

    from .scim_groups import active_for_principal
    from .session_revocation import revocation_epoch

    canonical = canonical_tenant_id(tenant)
    if not isinstance(principal, str) or not principal.startswith("user:"):
        raise PermissionError("a named promotion administrator is required")
    with tenant_scope(tenant=canonical):
        if active_for_principal(principal) is False:
            raise PermissionError("promotion administrator is inactive")
        if get_tenant(canonical) is None:
            raise PermissionError("promotion workspace is unavailable")
        assert_tenant_active(canonical)
        selected, generation = workspace_tenants.get_selection_binding(principal)
        if selected != canonical:
            raise PermissionError("promotion workspace selection changed")
        tenant_role = rbac.get_tenant_role(canonical, principal)
        if not tenant_role or not ({"operate", "admin"} & rbac.permissions_for(tenant_role)):
            raise PermissionError("current workspace membership denies promotion")
        global_role = global_role_for_principal(principal)
        global_permissions = sorted(rbac.permissions_for(global_role))
        if "admin" not in global_permissions:
            raise PermissionError("current global administrator authority is required")
        authorization_sha256 = _digest({
            "schema": "lightwork.candidate-promotion-dashboard-authority.v1",
            "tenant": canonical,
            "principal": principal,
            "global_role": global_role,
            "global_permissions": global_permissions,
            "tenant_role": tenant_role,
            "tenant_permissions": sorted(rbac.permissions_for(tenant_role)),
            "selection_generation": generation,
            "credential_epoch": revocation_epoch(principal.removeprefix("user:")),
        })
        return PromotionAuthority(
            tenant=canonical,
            principal=principal,
            role="release_admin",
            actions=_ACTIONS,
            authorization_sha256=authorization_sha256,
            valid_until=time.time() + 3600,
        )


def _run_admission(
    state: Any,
    tenant: str,
    principal: str,
    run_id: str,
    study_resolver: Any,
) -> RunPromotionAdmission:
    from .research_workspace_api import _run_service

    value = _run_service(state).admit_promotion(
        tenant,
        principal,
        run_id,
        trusted_study_resolver=study_resolver,
    )
    if not isinstance(value, Mapping):
        raise CandidatePromotionCompositionError("research run admission is unavailable")
    try:
        lineage = tuple(LineageCommitment(**item) for item in value["lineage"])
        raw_study = value["study_admission"]
        if not isinstance(raw_study, Mapping):
            raise TypeError("study admission must be a mapping")
        study = StudyClaim(**raw_study["study"])
        artifacts = tuple(
            ArtifactCommitment(**item) for item in raw_study["artifacts"]
        )
        study_admission = TrustedStudyAdmission(
            tenant=raw_study["tenant"],
            run_id=raw_study["run_id"],
            run_manifest_sha256=raw_study["run_manifest_sha256"],
            result_sha256=raw_study["result_sha256"],
            output_artifact_sha256=raw_study["output_artifact_sha256"],
            study=study,
            artifacts=artifacts,
            authority_sha256=raw_study["authority_sha256"],
        )
        return RunPromotionAdmission(
            tenant=value["tenant"],
            principal=value["principal"],
            candidate_principal=value["candidate_principal"],
            run_id=value["run_id"],
            run_manifest_sha256=value["run_manifest_sha256"],
            registry_binding_sha256=value["registry_binding_sha256"],
            result_sha256=value["result_sha256"],
            output_artifact_sha256=value["output_artifact_sha256"],
            lineage=lineage,
            authority_sha256=value["authority_sha256"],
            study_admission=study_admission,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CandidatePromotionCompositionError(
            "research run promotion admission is malformed"
        ) from exc


def build_candidate_promotions(state: Any) -> CandidatePromotions:
    """Build the service only when every deployment-owned dependency exists."""

    default_policy = _policy()
    artifact_resolver = getattr(state, "candidate_promotion_artifact_resolver", None)
    adapter = getattr(state, "candidate_promotion_deployment_adapter", None)
    run_admission_resolver = getattr(
        state, "candidate_promotion_run_admission_resolver", None
    )
    study_resolver = getattr(state, "candidate_promotion_study_resolver", None)
    target_preset_resolver = getattr(
        state, "candidate_promotion_target_preset_resolver", None
    )
    completed_runs_resolver = getattr(
        state, "candidate_promotion_completed_runs_resolver", None
    )
    authority_resolver = getattr(state, "candidate_promotion_authority_resolver", None)
    policy_resolver = getattr(state, "candidate_promotion_policy_resolver", None)
    if not callable(artifact_resolver):
        raise CandidatePromotionCompositionError(
            "candidate promotion artifact resolver is unavailable"
        )
    if not callable(run_admission_resolver) and not callable(study_resolver):
        raise CandidatePromotionCompositionError(
            "candidate promotion trusted study resolver is unavailable"
        )
    if not callable(target_preset_resolver):
        raise CandidatePromotionCompositionError(
            "candidate promotion target preset resolver is unavailable"
        )
    required = ("observe", "stage", "activate", "canary", "rollback", "reconcile")
    if any(not callable(getattr(adapter, name, None)) for name in required):
        raise CandidatePromotionCompositionError(
            "candidate promotion deployment adapter is unavailable"
        )

    def resolve_run(tenant: str, principal: str, run_id: str) -> RunPromotionAdmission:
        resolver = run_admission_resolver if callable(run_admission_resolver) else None
        value = (
            resolver(tenant, principal, run_id)
            if resolver is not None
            else _run_admission(state, tenant, principal, run_id, study_resolver)
        )
        if type(value) is not RunPromotionAdmission:
            raise CandidatePromotionCompositionError(
                "research run promotion admission is malformed"
            )
        return value

    def resolve_target_preset(tenant: str, preset_id: str) -> PromotionTargetPreset:
        value = target_preset_resolver(tenant, preset_id)
        if type(value) is not PromotionTargetPreset:
            raise CandidatePromotionCompositionError(
                "candidate promotion target preset is malformed"
            )
        return value

    def completed_runs(tenant: str, principal: str) -> tuple[str, ...]:
        if callable(completed_runs_resolver):
            values = completed_runs_resolver(tenant, principal)
            if isinstance(values, str | bytes) or not isinstance(values, Sequence):
                raise CandidatePromotionCompositionError(
                    "completed research run choices are malformed"
                )
            return tuple(sorted(values))
        from .research_workspace_api import _run_service

        rows = _run_service(state).list(tenant, principal, limit=256)
        if not isinstance(rows, Sequence):
            raise CandidatePromotionCompositionError(
                "completed research run choices are malformed"
            )
        result = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise CandidatePromotionCompositionError(
                    "completed research run choices are malformed"
                )
            if row.get("status") == "completed":
                result.append(row.get("run_id"))
        if any(not isinstance(value, str) for value in result):
            raise CandidatePromotionCompositionError(
                "completed research run choices are malformed"
            )
        return tuple(sorted(result))

    def observe_artifact(tenant: str, source_ref: str) -> ArtifactObservation:
        value = artifact_resolver(tenant, source_ref)
        if type(value) is not ArtifactObservation:
            raise CandidatePromotionCompositionError(
                "candidate promotion artifact observation is malformed"
            )
        return value

    return CandidatePromotions(
        run_admission_resolver=resolve_run,
        artifact_resolver=observe_artifact,
        target_preset_resolver=resolve_target_preset,
        completed_runs_resolver=completed_runs,
        authority_resolver=(authority_resolver if callable(authority_resolver) else _authority),
        policy_resolver=(
            policy_resolver if callable(policy_resolver) else lambda: default_policy
        ),
        deployment_adapter=adapter,
    )


def install_candidate_promotion_composition(app: Any) -> None:
    """Install a lazy factory without overriding explicit test/deployment wiring."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    from .local_flow_promotions import install_local_flow_promotions
    install_local_flow_promotions(state)
    if getattr(state, "candidate_promotions_factory", None) is None:
        state.candidate_promotions_factory = build_candidate_promotions
    if getattr(state, "candidate_promotion_capability_probe", None) is None:
        state.candidate_promotion_capability_probe = candidate_promotion_capability_enabled
    state.candidate_promotion_composition_installed = True


__all__ = [
    "CandidatePromotionCompositionError",
    "build_candidate_promotions",
    "candidate_promotion_capability_enabled",
    "install_candidate_promotion_composition",
    "policy_from_config",
]
