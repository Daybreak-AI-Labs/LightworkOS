"""Fail-closed extension point for external Rekor-style Trust Receipt anchors.

This module is intentionally a *transport-free adapter*, not a hidden HTTP
client.  A deployment must inject a reviewed client that knows how to submit to
its selected Rekor endpoint and an independently operated inclusion-proof
verifier.  With neither dependency supplied, the adapter makes no network call
and returns an explicit unavailable/refused outcome.

The adapter never turns a successful submission response into an ``anchored``
claim by itself.  It only creates a reference bound to the exact canonical
Trust Receipt v1 core; an external verifier must separately validate that
reference and proof before a caller may assert anchoring.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .trust_receipt_v1_verify import (
    REKOR_ANCHOR_TYPE,
    REKOR_ANCHOR_VERIFICATION,
    ReceiptFormatError,
    canonical_core_bytes,
    receipt_sha256,
    validate_envelope,
)

TRUST_RECEIPT_V1_MEDIA_TYPE = "application/vnd.lightwork.trust-receipt.v1+json"


@dataclass(frozen=True)
class RekorAnchorRequest:
    """Exact content a reviewed transport must bind to its transparency entry."""

    receipt_sha256: str
    receipt_core: bytes
    signature_public_key: str
    signature: str
    media_type: str = TRUST_RECEIPT_V1_MEDIA_TYPE


@dataclass(frozen=True)
class RekorAnchorResponse:
    """Minimum response fields required from an injected Rekor transport."""

    receipt_sha256: str
    entry_uuid: str
    log_id: str
    log_index: int
    integrated_time: int


class RekorAnchorTransport(Protocol):
    """Deployment-owned submission transport; this package provides no default."""

    def submit(self, request: RekorAnchorRequest) -> RekorAnchorResponse:
        """Submit the bound receipt core and return a normalized entry response."""


class RekorInclusionVerifier(Protocol):
    """Independently verify the returned transparency-log inclusion proof."""

    def verify(
        self, request: RekorAnchorRequest, response: RekorAnchorResponse
    ) -> bool:
        """Return true only when a trusted inclusion proof validates."""


@dataclass(frozen=True)
class RekorAnchorOutcome:
    """Submission status, deliberately distinct from an anchored assurance claim."""

    status: str
    anchored: bool
    reason: str
    reference: dict[str, Any] | None = None


def _response_problem(
    response: object, *, expected_receipt_sha256: str
) -> str | None:
    if not isinstance(response, RekorAnchorResponse):
        return "transport returned an object other than RekorAnchorResponse"
    if response.receipt_sha256 != expected_receipt_sha256:
        return "transport response is bound to a different receipt digest"
    for label, value in (("entry_uuid", response.entry_uuid), ("log_id", response.log_id)):
        if not isinstance(value, str) or not value.strip():
            return f"transport response has invalid {label}"
    for label, value in (
        ("log_index", response.log_index),
        ("integrated_time", response.integrated_time),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return f"transport response has invalid {label}"
    return None


def anchor_reference(
    request: RekorAnchorRequest, response: RekorAnchorResponse
) -> dict[str, Any]:
    """Create the non-assertive reference recognized by the v1 verifier.

    The reference says ``external-required`` rather than ``verified``.  Adding
    it to a receipt does not prove Rekor inclusion without a separate,
    independently trusted verifier.
    """
    return {
        "type": REKOR_ANCHOR_TYPE,
        "receipt_sha256": request.receipt_sha256,
        "entry_uuid": response.entry_uuid,
        "log_id": response.log_id,
        "log_index": response.log_index,
        "integrated_time": response.integrated_time,
        "verification": REKOR_ANCHOR_VERIFICATION,
    }


def with_anchor_reference(
    envelope: Mapping[str, Any], reference: Mapping[str, Any]
) -> dict[str, Any]:
    """Return a copy with a bound reference; never mutate the caller's receipt."""
    copied = dict(envelope)
    copied["anchor"] = dict(reference)
    # The protocol verifier owns shape validation.  This early binding check
    # prevents callers from accidentally attaching a response for another
    # receipt before they write the canonical file.
    expected = receipt_sha256(copied)
    if copied["anchor"].get("receipt_sha256") != expected:
        raise ReceiptFormatError("anchor reference is bound to another receipt")
    validate_envelope(copied)
    return copied


class RekorAnchorAdapter:
    """Use injected submission/proof components without providing network I/O.

    ``transport=None`` is the safe default.  It returns ``UNAVAILABLE`` and
    performs no implicit HTTP request.  A valid transport acknowledgement stays
    ``SUBMITTED_UNVERIFIED`` until the separately injected inclusion verifier
    accepts the exact response.  Thus unavailable or unverified Rekor state can
    never silently promote a receipt to an anchored assertion.
    """

    def __init__(
        self,
        transport: RekorAnchorTransport | None = None,
        inclusion_verifier: RekorInclusionVerifier | None = None,
    ) -> None:
        self._transport = transport
        self._inclusion_verifier = inclusion_verifier

    def request_for(self, envelope: Mapping[str, Any]) -> RekorAnchorRequest:
        """Prepare the exact canonical core that a transport must bind."""
        try:
            validate_envelope(envelope)
            core = canonical_core_bytes(envelope)
            signature = envelope["signature"]
            public_key = signature["public_key"]
            signature_value = signature["signature"]
        except (KeyError, TypeError, ReceiptFormatError) as exc:
            raise ReceiptFormatError(
                "cannot prepare a Rekor request from an invalid v1 receipt"
            ) from exc
        if not isinstance(public_key, str) or not isinstance(signature_value, str):
            raise ReceiptFormatError("receipt signature fields are not strings")
        return RekorAnchorRequest(
            receipt_sha256=receipt_sha256(envelope),
            receipt_core=core,
            signature_public_key=public_key,
            signature=signature_value,
        )

    def anchor(
        self, envelope: Mapping[str, Any], *, require_verified: bool = True
    ) -> RekorAnchorOutcome:
        """Submit through injected dependencies or return a fail-closed outcome.

        This method never raises transport/proof failures as a successful
        outcome.  ``require_verified=False`` exposes a normalized pending
        reference for workflow recovery, but still reports ``anchored=False``.
        """
        try:
            request = self.request_for(envelope)
        except ReceiptFormatError as exc:
            return RekorAnchorOutcome("REFUSED", False, str(exc))
        if self._transport is None:
            return RekorAnchorOutcome(
                "UNAVAILABLE",
                False,
                "no Rekor transport is configured; no network request was made",
            )
        try:
            response = self._transport.submit(request)
        except Exception as exc:  # noqa: BLE001 - a transport exception must refuse
            return RekorAnchorOutcome(
                "REFUSED",
                False,
                f"Rekor transport failed closed: {type(exc).__name__}: {exc}",
            )
        problem = _response_problem(response, expected_receipt_sha256=request.receipt_sha256)
        if problem:
            return RekorAnchorOutcome("REFUSED", False, problem)
        reference = anchor_reference(request, response)
        if self._inclusion_verifier is None:
            status = "REFUSED" if require_verified else "SUBMITTED_UNVERIFIED"
            return RekorAnchorOutcome(
                status,
                False,
                "Rekor submission is not an anchored claim without an independently "
                "operated inclusion verifier",
                reference,
            )
        try:
            verified = bool(self._inclusion_verifier.verify(request, response))
        except Exception as exc:  # noqa: BLE001 - proof verifier failures refuse
            return RekorAnchorOutcome(
                "REFUSED",
                False,
                f"Rekor inclusion verifier failed closed: {type(exc).__name__}: {exc}",
                reference,
            )
        if not verified:
            return RekorAnchorOutcome(
                "REFUSED",
                False,
                "Rekor inclusion verifier did not accept the submitted receipt",
                reference,
            )
        return RekorAnchorOutcome(
            "VERIFIED",
            True,
            "independent Rekor inclusion verifier accepted the bound receipt",
            reference,
        )


__all__ = [
    "RekorAnchorAdapter",
    "RekorAnchorOutcome",
    "RekorAnchorRequest",
    "RekorAnchorResponse",
    "RekorAnchorTransport",
    "RekorInclusionVerifier",
    "TRUST_RECEIPT_V1_MEDIA_TYPE",
    "anchor_reference",
    "with_anchor_reference",
]
