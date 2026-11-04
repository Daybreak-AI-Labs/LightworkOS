"""Fail-closed Rekor adapter contract tests (all transports are local fakes)."""
from __future__ import annotations

import json
from pathlib import Path

from maverick import trust_receipt_v1_verify as verifier
from maverick.trust_receipt_rekor import (
    RekorAnchorAdapter,
    RekorAnchorRequest,
    RekorAnchorResponse,
    with_anchor_reference,
)

VECTORS_PATH = Path(__file__).with_name("data") / "trust_receipt_v1_vectors.json"


def _valid_envelope() -> dict:
    vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    raw = vectors["vectors"][0]["envelope_json"].encode("utf-8")
    return verifier.parse_canonical_envelope(raw)


class _Transport:
    def __init__(self, response: RekorAnchorResponse | None = None) -> None:
        self.requests: list[RekorAnchorRequest] = []
        self.response = response

    def submit(self, request: RekorAnchorRequest) -> RekorAnchorResponse:
        self.requests.append(request)
        if self.response is not None:
            return self.response
        return RekorAnchorResponse(
            receipt_sha256=request.receipt_sha256,
            entry_uuid="entry-123",
            log_id="log-abc",
            log_index=17,
            integrated_time=1_777_350_400,
        )


class _AcceptingVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[RekorAnchorRequest, RekorAnchorResponse]] = []

    def verify(self, request: RekorAnchorRequest, response: RekorAnchorResponse) -> bool:
        self.calls.append((request, response))
        return response.receipt_sha256 == request.receipt_sha256


def test_no_transport_is_explicitly_unavailable_without_a_network_request():
    outcome = RekorAnchorAdapter().anchor(_valid_envelope())
    assert outcome.status == "UNAVAILABLE"
    assert not outcome.anchored
    assert outcome.reference is None
    assert "no network request" in outcome.reason


def test_transport_acknowledgement_is_not_an_anchored_claim():
    envelope = _valid_envelope()
    transport = _Transport()
    outcome = RekorAnchorAdapter(transport).anchor(
        envelope,
        require_verified=False,
    )
    assert outcome.status == "SUBMITTED_UNVERIFIED"
    assert not outcome.anchored
    assert len(transport.requests) == 1
    assert outcome.reference is not None
    assert outcome.reference["receipt_sha256"] == verifier.receipt_sha256(envelope)
    assert outcome.reference["verification"] == "external-required"


def test_required_proof_refuses_even_a_well_formed_submission_response():
    outcome = RekorAnchorAdapter(_Transport()).anchor(_valid_envelope())
    assert outcome.status == "REFUSED"
    assert not outcome.anchored
    assert "inclusion verifier" in outcome.reason


def test_mismatched_transport_digest_refuses_closed():
    response = RekorAnchorResponse(
        receipt_sha256="0" * 64,
        entry_uuid="entry-123",
        log_id="log-abc",
        log_index=17,
        integrated_time=1_777_350_400,
    )
    outcome = RekorAnchorAdapter(_Transport(response)).anchor(_valid_envelope())
    assert outcome.status == "REFUSED"
    assert not outcome.anchored
    assert "different receipt" in outcome.reason


def test_malformed_typed_response_is_refused_instead_of_raising():
    response = RekorAnchorResponse(
        receipt_sha256=verifier.receipt_sha256(_valid_envelope()),
        entry_uuid=1,  # type: ignore[arg-type] - exercise an untrusted adapter result
        log_id="log-abc",
        log_index=17,
        integrated_time=1_777_350_400,
    )
    outcome = RekorAnchorAdapter(_Transport(response)).anchor(_valid_envelope())
    assert outcome.status == "REFUSED"
    assert not outcome.anchored
    assert "entry_uuid" in outcome.reason


def test_injected_inclusion_verifier_can_complete_the_explicit_contract():
    envelope = _valid_envelope()
    transport = _Transport()
    inclusion_verifier = _AcceptingVerifier()
    outcome = RekorAnchorAdapter(transport, inclusion_verifier).anchor(envelope)
    assert outcome.status == "VERIFIED"
    assert outcome.anchored
    assert len(inclusion_verifier.calls) == 1
    assert outcome.reference is not None

    with_reference = with_anchor_reference(envelope, outcome.reference)
    trusted = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["trusted_public_key"]
    result = verifier.verify_envelope(
        with_reference,
        trusted_public_keys=[trusted],
        anchor_verifier=lambda anchor, core: anchor["receipt_sha256"]
        == verifier.receipt_sha256(with_reference),
        require_anchor=True,
    )
    assert result.valid and result.anchored


def test_transport_exception_and_invalid_input_are_refused():
    class FailingTransport:
        def submit(self, request: RekorAnchorRequest) -> RekorAnchorResponse:
            raise RuntimeError("offline test failure")

    transport_failure = RekorAnchorAdapter(FailingTransport()).anchor(_valid_envelope())
    assert transport_failure.status == "REFUSED"
    assert "failed closed" in transport_failure.reason

    invalid = _valid_envelope()
    invalid["payload_sha256"] = "0" * 64
    input_failure = RekorAnchorAdapter(_Transport()).anchor(invalid)
    assert input_failure.status == "REFUSED"
    assert "invalid v1 receipt" in input_failure.reason
