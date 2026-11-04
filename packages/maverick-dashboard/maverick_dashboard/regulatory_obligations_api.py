"""Closed operator API for the regulatory compiler (compliance by construction).

Read-only by design: the obligations a deployment enforces are chosen in
config (``[compliance] profiles``, written by the installer wizard), and this
surface shows what those choices compile to, proves the gates are live
(the same anti-vacuity check CI runs), and answers "what happens to this
action" from the compiled policy itself. Nothing here can widen or narrow
enforcement.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Request
from maverick import gateway_constraint_import as gateway_import
from maverick import regulatory_compiler as rc
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission

STATUS_SCHEMA = "lightwork.regulatory-obligations-status.v1"
CHECK_SCHEMA = "lightwork.regulatory-obligations-check.v1"

ProfileKey = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=32,
                           pattern=r"^[a-z][a-z0-9_]{0,31}$"),
]
ActionName = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=64,
                           pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CheckIn(_StrictModel):
    action: ActionName
    profiles: list[ProfileKey] | None = Field(default=None, max_length=16)


class GatewayConstraintPreviewIn(_StrictModel):
    """A non-persistent, closed gateway restriction document for inspection."""

    document: dict[str, object]
    profiles: list[ProfileKey] | None = Field(default=None, max_length=16)


def _known(keys: list[str]) -> list[str]:
    unknown = sorted(k for k in keys if k not in rc.REGULATIONS)
    if unknown:
        raise HTTPException(status_code=404,
                            detail=f"unknown regulation profile(s): {', '.join(unknown)}")
    return keys


def _verification(keys: list[str]) -> dict:
    problems = rc.verify(keys)
    inspected = len(rc.compile_obligations(keys).obligations)
    return {
        "inspected": inspected,
        "problems": problems,
        "sound": inspected > 0 and not problems,
    }


def _status() -> dict:
    active = rc.active_keys()
    described = rc.describe(active)
    library = []
    for key, obligations in rc.REGULATIONS.items():
        library.append({
            "key": key,
            "regulation": obligations[0].regulation if obligations else key,
            "obligations": len(obligations),
            "active": key in active,
        })
    return {
        "schema": STATUS_SCHEMA,
        "active_profiles": active,
        "library": library,
        "obligations": described["obligations"],
        "policy": described["policy"],
        "attenuation": described["attenuation"],
        "verification": _verification(active),
    }


def _profile(key: str) -> dict:
    described = rc.describe([key])
    return {
        "schema": STATUS_SCHEMA,
        "profile": key,
        "active": key in rc.active_keys(),
        "obligations": described["obligations"],
        "policy": described["policy"],
        "attenuation": described["attenuation"],
        "verification": _verification([key]),
    }


def _check(action: str, profiles: list[str] | None) -> dict:
    from maverick.governance import evaluate

    keys = _known(list(profiles)) if profiles is not None else rc.active_keys()
    compiled = rc.compile_obligations(keys)
    verdict = evaluate(action, policy=compiled.policy)
    tags = rc.audit_tags_under(action, verdict.rule, compiled.obligations)
    risk = rc.action_risk(action)
    return {
        "schema": CHECK_SCHEMA,
        "action": action,
        "profiles": keys,
        "classified": risk is not None,
        "risk": risk,
        "decision": verdict.decision.value,
        "rule": verdict.rule,
        "reason": verdict.reason,
        "attenuated": action in compiled.deny_tools,
        "obligation": tags or None,
        "covered_by": sorted(
            o.id for o in compiled.obligations if o.covers(action, risk)),
    }


def _gateway_constraint_preview(
    document: dict[str, object],
    profiles: list[str] | None,
) -> dict:
    keys = _known(list(profiles)) if profiles is not None else rc.active_keys()
    if not keys:
        raise LookupError("no active regulatory profiles are configured")
    return gateway_import.project_gateway_constraints(document, profiles=keys)


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503,
                            detail="regulatory compiler is unavailable") from exc


def create_regulatory_obligations_router() -> APIRouter:
    router = APIRouter(prefix="/regulatory", tags=["regulatory-obligations"])

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        return await _call(_status)

    @router.get("/tools")
    async def tools(request: Request):
        require_permission(request, "view")
        names = await _call(rc.classified_tools)
        return {"items": names, "count": len(names)}

    @router.get("/profiles/{key}")
    async def profile(request: Request, key: ProfileKey):
        require_permission(request, "view")
        _known([key])
        return await _call(_profile, key)

    @router.post("/check")
    async def check(request: Request, body: CheckIn):
        require_permission(request, "view")
        return await _call(_check, body.action, body.profiles)

    @router.post("/profiles/{key}/activate")
    async def activate_profile(request: Request, key: ProfileKey):
        """Turn one more regulation on (global admin). Turning one off stays
        with the installer: this surface can only add enforcement."""

        require_global_permission(request, "admin")
        _known([key])
        from . import settings_store
        from .compliance_controls_api import SIGN_IN_FIRST, sign_in_configured

        # A regulated posture makes the dashboard require sign-in; without a
        # sign-in method configured that would lock every administrator out.
        if not sign_in_configured():
            raise HTTPException(status_code=409, detail=SIGN_IN_FIRST)

        def activate() -> dict:
            current = rc.active_keys()
            if key in current:
                return {"active": True, "message": "This regulation is already on."}
            settings_store.set_compliance_settings(
                {("compliance", "profiles"): [*current, key]}
            )
            now_on = key in rc.active_keys()
            return {
                "active": now_on,
                "message": (
                    "Turned on. Its checks apply to new work from now on."
                    if now_on
                    else "Saved. It takes effect after Lightwork restarts."
                ),
            }

        try:
            return await run_in_threadpool(activate)
        except settings_store.SecuritySuiteConfigUnavailable as exc:
            raise HTTPException(status_code=503, detail="Settings could not be read.") from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503, detail="The regulation could not be turned on."
            ) from exc

    @router.post("/gateway-constraints/preview")
    async def gateway_constraints_preview(
        request: Request,
        body: GatewayConstraintPreviewIn,
    ):
        """Preview an external gateway's restrictions without changing policy."""

        require_permission(request, "view")
        try:
            return await run_in_threadpool(
                _gateway_constraint_preview,
                body.document,
                body.profiles,
            )
        except gateway_import.GatewayConstraintImportError as exc:
            # The closed parser never includes raw provider material in errors.
            raise HTTPException(
                status_code=422,
                detail="gateway constraint import was refused",
            ) from exc
        except LookupError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="gateway constraint preview is unavailable",
            ) from exc

    return router


router = create_regulatory_obligations_router()

__all__ = ["create_regulatory_obligations_router", "router"]
