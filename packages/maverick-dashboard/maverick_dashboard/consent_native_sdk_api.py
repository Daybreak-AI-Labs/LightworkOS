"""Public enrollment and signed-dispatch routes for native consent SDKs."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from maverick.consent_native_sdk import (
    ENVELOPE_SCHEMA,
    NativeAttestationVerifier,
    NativeConsentCapacityError,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeConsentDeviceRegistry,
    NativeConsentGateway,
    NativeConsentIntegrityError,
    NativeConsentValidationError,
    NativeEnrollmentEvidence,
    NativeRequestEnvelope,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

_REF = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_DIGEST = r"^[0-9a-f]{64}$"
_SIGNATURE = r"^[0-9a-f]{128}$"
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{1,87384}\Z")
_MAX_REQUEST_BYTES = 256 * 1024
_MAX_ATTESTATION_BYTES = 64 * 1024


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NativeEnrollmentIn(_StrictModel):
    application_ref: str = Field(pattern=_REF)
    tenant_id: str = Field(pattern=_REF)
    application_id: str = Field(min_length=3, max_length=255)
    platform: str = Field(pattern=r"^(android|fireos|ios|roku|tizen|tvos|webos)$")
    install_subject_sha256: str = Field(pattern=_DIGEST)
    public_key_hex: str = Field(pattern=_DIGEST)
    attestation_nonce: str = Field(pattern=_REF)
    attestation_evidence_sha256: str = Field(pattern=_DIGEST)
    attestation_material_b64url: str = Field(min_length=1, max_length=87_384)
    issued_at: float = Field(gt=0)
    expires_at: float = Field(gt=0)
    sdk_version: int = Field(ge=1, le=1_000_000)


class NativeAuthorityRefreshIn(_StrictModel):
    device_id: str = Field(pattern=_REF)
    expected_revision: int = Field(ge=1, le=2**31 - 1)
    application_ref: str = Field(pattern=_REF)
    tenant_id: str = Field(pattern=_REF)
    application_id: str = Field(min_length=3, max_length=255)
    platform: str = Field(pattern=r"^(android|fireos|ios|roku|tizen|tvos|webos)$")
    install_subject_sha256: str = Field(pattern=_DIGEST)
    public_key_hex: str = Field(pattern=_DIGEST)
    attestation_nonce: str = Field(pattern=_REF)
    attestation_evidence_sha256: str = Field(pattern=_DIGEST)
    attestation_material_b64url: str = Field(min_length=1, max_length=87_384)
    issued_at: float = Field(gt=0)
    expires_at: float = Field(gt=0)
    sdk_version: int | None = Field(default=None, ge=1, le=1_000_000)


class NativeEnvelopeIn(_StrictModel):
    schema_: str = Field(alias="schema", pattern=r"^lightwork\.native-consent-envelope\.v1$")
    application_ref: str = Field(pattern=_REF)
    application_authority_sha256: str = Field(pattern=_DIGEST)
    tenant_id: str = Field(pattern=_REF)
    application_id: str = Field(min_length=3, max_length=255)
    platform: str = Field(pattern=r"^(android|fireos|ios|roku|tizen|tvos|webos)$")
    device_id: str = Field(pattern=_REF)
    device_revision: int = Field(ge=1, le=2**31 - 1)
    key_revision: int = Field(ge=1, le=2**31 - 1)
    sdk_version: int = Field(ge=1, le=1_000_000)
    public_client_revision: int = Field(ge=1, le=2**31 - 1)
    public_client_record_sha256: str = Field(pattern=_DIGEST)
    publication_sha256: str = Field(pattern=_DIGEST)
    publication_bundle_sha256: str = Field(pattern=_DIGEST)
    configuration_sha256: str = Field(pattern=_DIGEST)
    policy_id: str = Field(pattern=_REF)
    policy_version: int = Field(ge=1, le=2**31 - 1)
    policy_sha256: str = Field(pattern=_DIGEST)
    standards_contract_sha256: str = Field(pattern=_DIGEST)
    request_id: str = Field(pattern=_REF)
    counter: int = Field(ge=1, le=2**63 - 1)
    issued_at: float = Field(gt=0)
    expires_at: float = Field(gt=0)
    operation: str = Field(pattern=_REF)
    payload: dict[str, Any]
    signature_hex: str = Field(pattern=_SIGNATURE)


@dataclass(frozen=True)
class NativeConsentSDKAPIDependencies:
    gate: Callable[[], bool]
    registry: NativeConsentDeviceRegistry
    attestation_verifier: NativeAttestationVerifier
    gateway: NativeConsentGateway
    rate_limit: Callable[[str, str], None]


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"


async def _preflight(
    request: Request, deps: NativeConsentSDKAPIDependencies, operation: str
) -> None:
    try:
        # The gate reads the application directory from disk for every
        # anonymous request, so it runs on a worker thread, not the event loop.
        if await run_in_threadpool(deps.gate) is not True:
            raise HTTPException(status_code=404, detail="not found")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    if request.query_params:
        raise HTTPException(status_code=401, detail="native consent authority unavailable")
    if request.headers.get("authorization") is not None or request.headers.get("cookie") is not None:
        raise HTTPException(status_code=401, detail="native consent authority unavailable")
    # Browser-based Tizen/webOS adapters send Origin on JSON POSTs. Permit only
    # the exact endpoint origin; the device signature remains the authority and
    # no ambient cookie or bearer credential is accepted.
    origin = request.headers.get("origin")
    endpoint_origin = f"{request.url.scheme}://{request.url.netloc}"
    if origin is not None and origin.rstrip("/") != endpoint_origin.rstrip("/"):
        raise HTTPException(status_code=401, detail="native consent authority unavailable")
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError as exc:
            raise HTTPException(status_code=413, detail="native consent request too large") from exc
        if not 1 <= size <= _MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="native consent request too large")
    try:
        deps.rate_limit(request.client.host if request.client is not None else "unknown", operation)
    except Exception as exc:
        raise HTTPException(
            status_code=429,
            detail="native consent rate limit reached",
            headers={"Retry-After": "60"},
        ) from exc


async def _bounded_model(
    request: Request,
    model: type[_StrictModel],
) -> _StrictModel:
    """Read and validate JSON without allowing framework pre-buffering past the cap."""

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="application/json is required")
    payload = bytearray()
    async for chunk in request.stream():
        if len(payload) + len(chunk) > _MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="native consent request too large")
        payload.extend(chunk)
    if not payload:
        raise HTTPException(status_code=422, detail="native consent request is invalid")
    try:
        return model.model_validate_json(bytes(payload))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="native consent request is invalid") from exc


def _decode_attestation_material(raw: str) -> bytes:
    if not _B64URL_RE.fullmatch(raw):
        raise HTTPException(status_code=422, detail="attestation material is invalid")
    try:
        material = base64.b64decode(
            raw + "=" * ((4 - len(raw) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="attestation material is invalid") from exc
    if not 1 <= len(material) <= _MAX_ATTESTATION_BYTES:
        raise HTTPException(status_code=422, detail="attestation material is invalid")
    return material


def create_consent_native_sdk_router(dependencies: NativeConsentSDKAPIDependencies) -> APIRouter:
    """Create the isolated native SDK router with explicit trust dependencies."""

    deps = dependencies
    router = APIRouter(prefix="/api/v1/public/consent/native", tags=["native-consent"])

    @router.post("/enroll", status_code=201)
    async def enroll(
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        await _preflight(request, deps, "enroll")
        body = await _bounded_model(request, NativeEnrollmentIn)
        if not isinstance(body, NativeEnrollmentIn):
            raise HTTPException(status_code=422, detail="native enrollment is invalid")
        material = _decode_attestation_material(body.attestation_material_b64url)
        values = body.model_dump()
        values.pop("attestation_material_b64url")
        sdk_version = int(values["sdk_version"])
        evidence = NativeEnrollmentEvidence(**values)
        try:
            device = await run_in_threadpool(
                deps.registry.enroll_device,
                evidence,
                verifier=deps.attestation_verifier,
                attestation_material=material,
                sdk_version=sdk_version,
            )
            authority, _revision = await run_in_threadpool(
                deps.registry.get_application,
                evidence.application_ref,
            )
        except NativeConsentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (NativeConsentConflict, NativeConsentDenied) as exc:
            raise HTTPException(status_code=409, detail="native enrollment unavailable") from exc
        except (NativeConsentCapacityError, NativeConsentIntegrityError) as exc:
            raise HTTPException(status_code=503, detail="native enrollment unavailable") from exc
        _private(response)
        return {
            "authority": {**authority.normalized(), "authority_sha256": authority.authority_sha256},
            "device": asdict(device),
        }

    @router.post("/dispatch")
    async def dispatch(
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        await _preflight(request, deps, "dispatch")
        body = await _bounded_model(request, NativeEnvelopeIn)
        if not isinstance(body, NativeEnvelopeIn):
            raise HTTPException(status_code=422, detail="native envelope is invalid")
        if body.schema_ != ENVELOPE_SCHEMA:
            raise HTTPException(status_code=422, detail="native envelope is invalid")
        try:
            receipt = await run_in_threadpool(
                deps.gateway.dispatch,
                NativeRequestEnvelope(**body.model_dump(by_alias=True)),
            )
        except NativeConsentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NativeConsentDenied as exc:
            raise HTTPException(status_code=401, detail="native consent authority unavailable") from exc
        except NativeConsentConflict as exc:
            raise HTTPException(status_code=409, detail="native consent authority changed") from exc
        except (NativeConsentCapacityError, NativeConsentIntegrityError) as exc:
            raise HTTPException(status_code=503, detail="native consent runtime unavailable") from exc
        _private(response)
        # The detached bytes avoid cross-runtime number-serialization drift:
        # native clients verify this exact canonical payload before parsing it.
        signed_payload = base64.urlsafe_b64encode(
            json.dumps(
                dict(receipt.payload),
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).rstrip(b"=").decode("ascii")
        return {
            **dict(receipt.payload),
            "signature_hex": receipt.signature_hex,
            "signed_payload_b64url": signed_payload,
        }

    @router.post("/refresh")
    async def refresh(
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        await _preflight(request, deps, "refresh")
        body = await _bounded_model(request, NativeAuthorityRefreshIn)
        if not isinstance(body, NativeAuthorityRefreshIn):
            raise HTTPException(status_code=422, detail="native refresh is invalid")
        material = _decode_attestation_material(body.attestation_material_b64url)
        values = body.model_dump()
        values.pop("attestation_material_b64url")
        device_id = str(values.pop("device_id"))
        expected_revision = int(values.pop("expected_revision"))
        admitted_sdk_version = values.get("sdk_version")
        evidence = NativeEnrollmentEvidence(**values)
        try:
            device = await run_in_threadpool(
                deps.registry.refresh_device_authority,
                device_id,
                evidence,
                verifier=deps.attestation_verifier,
                attestation_material=material,
                expected_revision=expected_revision,
                admitted_sdk_version=admitted_sdk_version,
            )
            authority, _revision = await run_in_threadpool(
                deps.registry.get_application,
                evidence.application_ref,
            )
        except NativeConsentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except NativeConsentDenied as exc:
            raise HTTPException(status_code=401, detail="native refresh unavailable") from exc
        except NativeConsentConflict as exc:
            raise HTTPException(status_code=409, detail="native refresh unavailable") from exc
        except (NativeConsentCapacityError, NativeConsentIntegrityError) as exc:
            raise HTTPException(status_code=503, detail="native refresh unavailable") from exc
        _private(response)
        return {
            "authority": {**authority.normalized(), "authority_sha256": authority.authority_sha256},
            "device": asdict(device),
        }

    return router


__all__ = [
    "NativeConsentSDKAPIDependencies",
    "NativeAuthorityRefreshIn",
    "NativeEnrollmentIn",
    "NativeEnvelopeIn",
    "create_consent_native_sdk_router",
]
