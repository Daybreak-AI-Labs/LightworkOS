"""Read-only release evidence for an improvement pilot.

Only the governed promotion service and deployment-owned adapter may supply a
release binding. A frozen binding is a plan snapshot, not proof that any task
actually ran under either release.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import asdict, dataclass

from maverick.candidate_promotion import DeploymentObservation, PromotionTarget
from maverick.paths import current_tenant_id_strict

from .auth import caller_principal
from .candidate_promotion_api import _service

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PRE_ACTIVATION = frozenset({"awaiting_review", "authorized", "staged"})


@dataclass(frozen=True)
class ReleaseBinding:
    candidate_id: str
    target_id: str
    run_id: str
    baseline_sha256: str
    candidate_sha256: str
    promotion_manifest_sha256: str
    deployment_observation_sha256: str
    observed_at: float
    promotion_revision: int
    promotion_state: str

    def __post_init__(self):
        if any(
            not isinstance(value, str) or _ID.fullmatch(value) is None
            for value in (self.candidate_id, self.target_id, self.run_id)
        ):
            raise ValueError("The candidate release binding is malformed.")
        if any(
            not isinstance(value, str) or _SHA.fullmatch(value) is None
            for value in (
                self.baseline_sha256,
                self.candidate_sha256,
                self.promotion_manifest_sha256,
                self.deployment_observation_sha256,
            )
        ):
            raise ValueError("The candidate release commitment is malformed.")
        if self.baseline_sha256 == self.candidate_sha256:
            raise ValueError("The candidate must differ from the deployed baseline.")
        if (
            self.promotion_state not in _PRE_ACTIVATION
            or isinstance(self.promotion_revision, bool)
            or not isinstance(self.promotion_revision, int)
            or self.promotion_revision < 1
            or isinstance(self.observed_at, bool)
            or not isinstance(self.observed_at, int | float)
            or not math.isfinite(self.observed_at)
            or self.observed_at <= 0
        ):
            raise ValueError("The candidate release state is not ready for planning.")


def _identity(request):
    tenant = current_tenant_id_strict()
    actor = caller_principal(request)
    if not tenant or not isinstance(actor, str) or not actor.startswith("user:"):
        raise PermissionError("Sign in with a named account and select a workspace.")
    return tenant, actor


def _candidate(value, candidate_id):
    manifest = value.get("manifest") if isinstance(value, dict) else None
    target_data = manifest.get("target") if isinstance(manifest, dict) else None
    run = manifest.get("run") if isinstance(manifest, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("candidate_id") != candidate_id
        or value.get("state") not in _PRE_ACTIVATION
        or not isinstance(target_data, dict)
        or not isinstance(run, dict)
    ):
        raise ValueError("Choose a candidate that has not been activated or withdrawn.")
    target = PromotionTarget(**target_data)
    run_id = run.get("run_id")
    candidate_sha = run.get("output_artifact_sha256")
    if (
        not isinstance(run_id, str)
        or not isinstance(candidate_sha, str)
        or _SHA.fullmatch(candidate_sha) is None
    ):
        raise ValueError("The candidate release commitment is unavailable.")
    return manifest, target, run_id, candidate_sha


def choices(request):
    """Return named, pre-activation choices; a later bind rechecks all facts."""
    try:
        tenant, actor = _identity(request)
    except PermissionError:
        detail = "Sign in with a named account and select a workspace to compare releases. You can still plan a normal workflow pilot."
        return {"available": False, "items": [], "detail": detail,
                "readiness": {"status": "sign_in_required", "release_decisions": False,
                              "deployed_release_check": False, "next_action": detail}}
    service = _service(request, required=False)
    adapter = getattr(request.app.state, "candidate_promotion_deployment_adapter", None)
    observer_ready = callable(getattr(adapter, "observe", None))
    if service is None or not observer_ready:
        if service is None and not observer_ready:
            detail = "Release comparisons need release decisions and a deployed-release check connected by an installation administrator. You can still plan a normal workflow pilot."
        elif service is None:
            detail = "Release decisions are not connected. Ask an installation administrator to finish release setup, then check again. You can still plan a normal workflow pilot."
        else:
            detail = "The deployed-release check is not connected. Ask an installation administrator to finish release setup, then check again. You can still plan a normal workflow pilot."
        return {"available": False, "items": [], "detail": detail,
                "readiness": {"status": "setup_required", "release_decisions": service is not None,
                              "deployed_release_check": observer_ready, "next_action": detail}}
    rows = service.list(tenant, actor, limit=256)
    items = []
    for value in rows:
        if value.get("state") not in _PRE_ACTIVATION:
            continue
        try:
            _, target, _, _ = _candidate(value, value["candidate_id"])
        except (KeyError, TypeError, ValueError):
            continue
        items.append({
            "candidate_id": value["candidate_id"],
            "target_id": target.target_id,
            "state": value["state"],
            "created_at": value.get("created_at"),
        })
    detail = ("Choose a candidate. Its deployed baseline is checked again when you freeze the plan."
              if items else "Release setup is connected, but no candidate is waiting for release in this workspace. You can still plan a normal workflow pilot.")
    return {"available": True, "items": items, "partial": len(rows) == 256,
        "detail": detail,
        "readiness": {"status": "ready", "release_decisions": True,
                      "deployed_release_check": True, "next_action": detail}}


def bind(request, candidate_id):
    """Observe the exact current baseline before freezing new pilot cases."""
    tenant, actor = _identity(request)
    service = _service(request)
    value = service.inspect(tenant, actor, candidate_id)
    _, target, run_id, candidate_sha = _candidate(value, candidate_id)
    adapter = getattr(request.app.state, "candidate_promotion_deployment_adapter", None)
    if not callable(getattr(adapter, "observe", None)):
        raise ValueError("The installed deployment connection cannot verify the baseline.")
    observed = adapter.observe(tenant, target.target_id)
    if (
        type(observed) is not DeploymentObservation
        or observed.tenant != tenant
        or observed.target_id != target.target_id
        or observed.active_artifact_sha256 != target.expected_active_sha256
        or observed.state_schema != target.state_schema
        or observed.queued_intent_schema != target.queued_intent_schema
        or observed.rollback_compatible is not True
    ):
        raise ValueError("The deployed release or rollback compatibility changed. Refresh the candidate before planning.")
    return ReleaseBinding(
        candidate_id=candidate_id,
        target_id=target.target_id,
        run_id=run_id,
        baseline_sha256=observed.active_artifact_sha256,
        candidate_sha256=candidate_sha,
        promotion_manifest_sha256=value["manifest_sha256"],
        deployment_observation_sha256=observed.evidence_sha256,
        observed_at=time.time(),
        promotion_revision=value["revision"],
        promotion_state=value["state"],
    )


def status(request, binding):
    """Fresh promotion/deployment read without claiming per-case exposure."""
    tenant, actor = _identity(request)
    result = {
        "binding": asdict(binding),
        "promotion_state": "unavailable",
        "promotion_revision": None,
        "deployment_state": "unavailable",
        "checked_at": None,
        "release_evidence_current": False,
        "case_exposure_verified": False,
        "causal_lift_qualified": False,
        "review_href": "/research#research-promotions",
    }
    try:
        value = _service(request).inspect(tenant, actor, binding.candidate_id)
        result["promotion_state"] = value["state"]
        result["promotion_revision"] = value["revision"]
        if value["manifest_sha256"] != binding.promotion_manifest_sha256:
            result["deployment_state"] = "candidate_changed"
            return result
        target = PromotionTarget(**value["manifest"]["target"])
        adapter = getattr(request.app.state, "candidate_promotion_deployment_adapter", None)
        observed = adapter.observe(tenant, binding.target_id)
        if type(observed) is not DeploymentObservation or observed.tenant != tenant or observed.target_id != binding.target_id:
            return result
        result["checked_at"] = time.time()
        if (
            target.target_id != binding.target_id
            or observed.state_schema != target.state_schema
            or observed.queued_intent_schema != target.queued_intent_schema
            or observed.rollback_compatible is not True
        ):
            result["deployment_state"] = "rollback_unavailable"
            return result
        if observed.active_artifact_sha256 == binding.baseline_sha256:
            result["deployment_state"] = "baseline_active"
        elif observed.active_artifact_sha256 == binding.candidate_sha256:
            result["deployment_state"] = "candidate_active"
        else:
            result["deployment_state"] = "other_release_active"
        result["release_evidence_current"] = True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        # Do not infer a known state from a failed deployment read.
        pass
    return result


__all__ = ["ReleaseBinding", "bind", "choices", "status"]
