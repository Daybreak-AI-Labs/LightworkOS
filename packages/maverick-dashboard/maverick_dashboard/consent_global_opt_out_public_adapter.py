"""Isolated public-consent route adapter for Global Opt-Out.

The parent public consent router owns credential parsing, exact origin/service
admission, CORS, rate limits, profile capability resolution, and active
publication/policy resolution.  This adapter receives those server closures;
it does not parse or accept tenant, property, profile, client, origin, service,
publication, or policy selectors from the public request.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from maverick import consent_global_opt_out as opt_out
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .consent_global_opt_out_composition import GlobalOptOutPublicMaterial

_DIGEST = r"^[0-9a-f]{64}$"
_IDEMPOTENCY = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PublicGlobalOptOutSubmitIn(_StrictModel):
    configuration_version: int = Field(ge=1, le=2**31 - 1)
    configuration_sha256: str = Field(pattern=_DIGEST)
    authority_revision: int = Field(ge=1, le=2**31 - 1)
    authority_sha256: str = Field(pattern=_DIGEST)
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=_IDEMPOTENCY,
    )


@dataclass(frozen=True, slots=True)
class GlobalOptOutPublicRouteDependencies:
    """Existing parent-router closures required by the adapter."""

    authenticate: Callable[[Request], Awaitable[Any]]
    profile_authority: Callable[[Request, Any], Awaitable[Any]]
    active_contract: Callable[[Request, Any], Awaitable[Any]]
    rights_intake_material: Callable[[Request, Any], Awaitable[tuple[Any, Any]]]
    public_authority_reauthenticator: Callable[[Request, Any, Any], Callable[[], object]]
    set_private_headers: Callable[[Response, Request, Any], None]

    def __post_init__(self) -> None:
        for value in (
            self.authenticate,
            self.profile_authority,
            self.active_contract,
            self.rights_intake_material,
            self.public_authority_reauthenticator,
            self.set_private_headers,
        ):
            if not callable(value):
                raise TypeError("Global Opt-Out public dependency is not callable")


def global_opt_out_preflight_contracts() -> dict[str, set[str]]:
    """Return the exact resources the parent CORS preflight must admit."""

    return {
        "global-opt-out/configuration": {"GET"},
        "global-opt-out/requests": {"POST"},
    }


def _http_error(exc: opt_out.GlobalOptOutError) -> HTTPException:
    if isinstance(
        exc,
        (opt_out.GlobalOptOutDisabled, opt_out.GlobalOptOutNotConfigured),
    ):
        status = 404
    elif isinstance(
        exc,
        (opt_out.GlobalOptOutAuthorityStale, opt_out.GlobalOptOutConflict),
    ):
        status = 409
    elif isinstance(exc, opt_out.GlobalOptOutValidationError):
        status = 422
    else:
        status = 503
    return HTTPException(
        status_code=status,
        detail={"code": exc.code, "message": str(exc)},
    )


async def _material(
    request: Request,
    authority: Any,
    dependencies: GlobalOptOutPublicRouteDependencies,
) -> GlobalOptOutPublicMaterial:
    stage = "gate"
    try:
        tenant_id = authority.binding.tenant_id
        gate = getattr(request.app.state, "global_opt_out_enabled_probe", None)
        if not callable(gate) or gate(tenant_id) is not True:
            raise opt_out.GlobalOptOutDisabled("Global Opt-Out is disabled")
        stage = "profile"
        profile = await dependencies.profile_authority(request, authority)
        stage = "contract"
        contract = await dependencies.active_contract(request, authority)
        stage = "rights-intake"
        rights_material, rights_profile = await dependencies.rights_intake_material(
            request, authority
        )
        if profile != rights_profile:
            raise opt_out.GlobalOptOutAuthorityStale(
                "public profile authority changed during Global Opt-Out resolution"
            )
        factory = getattr(request.app.state, "global_opt_out_public_material_factory", None)
        if not callable(factory):
            raise opt_out.GlobalOptOutDisabled("Global Opt-Out composition is unavailable")
        stage = "composition"
        value = await run_in_threadpool(
            factory,
            tenant_id=tenant_id,
            initial_client_binding=authority.binding,
            initial_profile_binding=profile,
            active_public_configuration=contract.public_configuration,
            active_policy=contract.policy,
            public_authority_resolver=dependencies.public_authority_reauthenticator(
                request,
                authority,
                profile,
            ),
            rights_intake_material=rights_material,
            request=request,
        )
        if not isinstance(value, GlobalOptOutPublicMaterial):
            raise opt_out.GlobalOptOutDSARUnavailable(
                "Global Opt-Out public material is unavailable"
            )
        return value
    except opt_out.GlobalOptOutError as exc:
        raise _http_error(exc) from exc
    except HTTPException as exc:
        if stage == "contract":
            translated: opt_out.GlobalOptOutError = opt_out.GlobalOptOutAuthorityStale(
                "public consent authority changed"
            )
        elif stage == "rights-intake" and exc.status_code in {404, 409, 503}:
            translated = opt_out.GlobalOptOutDSARUnavailable(
                "privacy-rights intake is unavailable"
            )
        else:
            raise
        raise _http_error(translated) from exc
    except Exception as exc:
        translated = opt_out.GlobalOptOutDSARUnavailable(
            "privacy-rights intake is unavailable"
        )
        raise _http_error(translated) from exc


def attach_consent_global_opt_out_public_routes(
    router: APIRouter,
    dependencies: GlobalOptOutPublicRouteDependencies,
) -> None:
    """Attach two strict routes inside the existing public consent boundary."""

    if not isinstance(router, APIRouter):
        raise TypeError("Global Opt-Out public routes require an API router")
    if not isinstance(dependencies, GlobalOptOutPublicRouteDependencies):
        raise TypeError("Global Opt-Out public route dependencies are invalid")

    @router.get("/global-opt-out/configuration")
    async def get_global_opt_out_configuration(
        request: Request,
        response: Response,
        authority: Any = Depends(dependencies.authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        material = await _material(request, authority, dependencies)
        try:
            value = await run_in_threadpool(
                material.store.get_public_configuration,
                material.authority,
            )
        except opt_out.GlobalOptOutError as exc:
            raise _http_error(exc) from exc
        except Exception as exc:
            error = opt_out.GlobalOptOutIntegrityError(
                "Global Opt-Out configuration is unavailable"
            )
            raise _http_error(error) from exc
        dependencies.set_private_headers(response, request, authority)
        return value

    @router.post("/global-opt-out/requests", status_code=201)
    async def submit_global_opt_out(
        body: PublicGlobalOptOutSubmitIn,
        request: Request,
        response: Response,
        authority: Any = Depends(dependencies.authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        material = await _material(request, authority, dependencies)
        try:
            value = await run_in_threadpool(
                material.store.submit,
                material.authority,
                **body.model_dump(),
            )
        except opt_out.GlobalOptOutError as exc:
            raise _http_error(exc) from exc
        except Exception as exc:
            error = opt_out.GlobalOptOutDSARUnavailable(
                "privacy-rights intake is unavailable"
            )
            raise _http_error(error) from exc
        dependencies.set_private_headers(response, request, authority)
        return value


__all__ = [
    "GlobalOptOutPublicRouteDependencies",
    "PublicGlobalOptOutSubmitIn",
    "attach_consent_global_opt_out_public_routes",
    "global_opt_out_preflight_contracts",
]
