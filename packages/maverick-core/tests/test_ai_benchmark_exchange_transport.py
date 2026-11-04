from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from maverick.ai_benchmark_exchange import (
    CONTRIBUTION_EXPORT_SCHEMA,
    METHODOLOGY_NOTICE,
    PRIVACY_NOTICE,
)
from maverick.ai_benchmark_exchange_transport import (
    COORDINATOR_RECEIPT_SCHEMA,
    COORDINATOR_SUBMISSION_PATH,
    COORDINATOR_SUBMISSION_SCHEMA,
    TRUST_ROOT_SCHEMA,
    BenchmarkCoordinatorAmbiguousDelivery,
    BenchmarkCoordinatorClient,
    BenchmarkCoordinatorConfigError,
    BenchmarkCoordinatorConsentError,
    BenchmarkCoordinatorDefinitiveTransportError,
    BenchmarkCoordinatorDisabled,
    BenchmarkCoordinatorIdempotencyConflict,
    BenchmarkCoordinatorProtocolError,
    BenchmarkTrustRootError,
    CoordinatorHTTPResponse,
    CoordinatorTransportLimits,
    Ed25519TrustKey,
    VersionedEd25519TrustRoots,
)

KEY_A = "KEY-" + "a" * 32
KEY_B = "KEY-" + "b" * 32
UNKNOWN_KEY = "KEY-" + "f" * 32
IDEMPOTENCY_KEY = "benchmark-submit-2026-001"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _all_mapping_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                keys.add(key)
            keys.update(_all_mapping_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.update(_all_mapping_keys(nested))
    return keys


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _trust_key(
    key_id: str,
    private_key: Ed25519PrivateKey,
    *,
    introduced_in: int = 1,
    revoked_in: int | None = None,
) -> Ed25519TrustKey:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Ed25519TrustKey(
        key_id=key_id,
        public_key_hex=public_key.hex(),
        introduced_in=introduced_in,
        revoked_in=revoked_in,
    )


def _report_body() -> dict[str, Any]:
    return {
        "schema": "lightwork.ai-benchmark-cohort-report.v1",
        "report_id": "BXR-" + "1" * 32,
        "issued_at": 1_787_889_600.0,
        "metric_code": "eval_pass_rate",
        "numerator": 920,
        "denominator": 1000,
        "period": {"start": "2026-01-01", "end": "2026-12-31"},
        "cohort": {
            "industry_code": "technology",
            "geography_code": "north_america",
            "organization_size_code": "enterprise",
            "model_modality_code": "text",
        },
        "contributor_count": 12,
        "k_anonymity_min": 5,
        "aggregation_method": "pooled_ratio",
        "privacy": {
            "state": "not_dp",
            "epsilon": None,
            "delta": None,
            "noise_mechanism": None,
        },
        "methodology_version": "benchmark-aggregate-v1",
    }


def _signature(
    private_key: Ed25519PrivateKey,
    payload: bytes,
    *,
    key_id: str = KEY_A,
    value: str | None = None,
) -> dict[str, str]:
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": value if value is not None else private_key.sign(payload).hex(),
    }


def _export_package(*, numerator: int = 91) -> dict[str, Any]:
    packet = {
        "schema": CONTRIBUTION_EXPORT_SCHEMA,
        "pseudonymous_contribution_id": "BXC-" + "2" * 32,
        "version": 3,
        "metric_code": "eval_pass_rate",
        "numerator": numerator,
        "denominator": 100,
        "period": {"start": "2026-01-01", "end": "2026-06-30"},
        "cohort": {
            "industry_code": "technology",
            "geography_code": "north_america",
            "organization_size_code": "enterprise",
            "model_modality_code": "text",
        },
        "evidence_bindings": [
            {
                "evidence_id": "MRE-" + "3" * 32,
                "digest": "4" * 64,
            }
        ],
        "content_sha256": "5" * 64,
        "authority_sha256": "6" * 64,
        "approval": {
            "voluntary_opt_in": True,
            "human_approved": True,
            "four_eyes": True,
            "evidence_current": True,
        },
        "methodology": {
            "aggregation_level": "organization",
            "calculation": "bounded_numerator_divided_by_denominator",
            "sampling_basis": "voluntary_opt_in",
        },
        "privacy": {
            "raw_records_included": False,
            "tenant_identity_included": False,
            "customer_identifiers_included": False,
            "anonymity_claim": False,
            "differential_privacy_claim": False,
            "privacy_budget_accounting": "unsupported",
        },
        "limitations": [METHODOLOGY_NOTICE, PRIVACY_NOTICE],
    }
    return {**packet, "packet_sha256": _sha(packet)}


def _receipt(
    package: Mapping[str, Any],
    *,
    idempotency_key: str = IDEMPOTENCY_KEY,
    status: str = "accepted",
    headers: Mapping[str, str] | None = None,
) -> CoordinatorHTTPResponse:
    body = _canonical(
        {
            "schema": COORDINATOR_RECEIPT_SCHEMA,
            "status": status,
            "receipt_id": "BCR-" + "7" * 32,
            "idempotency_key": idempotency_key,
            "packet_sha256": package["packet_sha256"],
            "accepted_at": 1_787_889_600.0,
        }
    )
    response_headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(body)),
    }
    if headers is not None:
        response_headers = dict(headers)
    return CoordinatorHTTPResponse(200, response_headers, body)


Outcome = CoordinatorHTTPResponse | Exception | object | Callable[..., object]


class FakeTransport:
    def __init__(self, *outcomes: Outcome) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
        allow_redirects: bool,
        max_response_bytes: int,
    ) -> object:
        call = {
            "url": url,
            "headers": dict(headers),
            "body": body,
            "timeout": timeout,
            "allow_redirects": allow_redirects,
            "max_response_bytes": max_response_bytes,
        }
        self.calls.append(call)
        if not self.outcomes:
            raise AssertionError("unexpected coordinator request")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome(**call)
        return outcome


def _client(
    transport: FakeTransport,
    *,
    enabled: bool = True,
    limits: CoordinatorTransportLimits | None = None,
) -> BenchmarkCoordinatorClient:
    return BenchmarkCoordinatorClient(
        coordinator_origin="https://benchmark.example.com",
        enabled=enabled,
        transport=transport,
        limits=limits,
    )


def test_ed25519_verifier_binds_canonical_report_to_named_key() -> None:
    private_key = _private_key(1)
    roots = VersionedEd25519TrustRoots(
        version=1,
        keys=(_trust_key(KEY_A, private_key),),
    )
    payload = _canonical(_report_body())
    signature = _signature(private_key, payload)

    assert roots.verify(payload, signature) is True
    assert roots(payload, signature) is True

    changed = _report_body()
    changed["numerator"] = 919
    assert roots.verify(_canonical(changed), signature) is False

    noncanonical = json.dumps(_report_body(), indent=2).encode()
    assert roots.verify(noncanonical, _signature(private_key, noncanonical)) is False


def test_ed25519_verifier_accepts_bounded_base64url_signature() -> None:
    private_key = _private_key(2)
    roots = VersionedEd25519TrustRoots(
        version=1,
        keys=(_trust_key(KEY_A, private_key),),
    )
    payload = _canonical(_report_body())
    encoded = base64.urlsafe_b64encode(private_key.sign(payload)).decode().rstrip("=")

    assert roots.verify(payload, _signature(private_key, payload, value=encoded)) is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda signature: signature.update(key_id=UNKNOWN_KEY),
        lambda signature: signature.update(algorithm="ECDSA-P256-SHA256"),
        lambda signature: signature.update(value="0" * 128),
        lambda signature: signature.update(value="not-a-signature"),
        lambda signature: signature.update(extra="unexpected"),
    ],
)
def test_ed25519_verifier_fails_closed_for_untrusted_or_malformed_signatures(
    mutate: Callable[[dict[str, str]], None],
) -> None:
    private_key = _private_key(3)
    roots = VersionedEd25519TrustRoots(
        version=1,
        keys=(_trust_key(KEY_A, private_key),),
    )
    payload = _canonical(_report_body())
    signature = _signature(private_key, payload)
    mutate(signature)

    assert roots.verify(payload, signature) is False


def test_trust_root_rotation_selects_key_id_and_revocation_is_versioned() -> None:
    private_a = _private_key(4)
    private_b = _private_key(5)
    version_one = VersionedEd25519TrustRoots(
        version=1,
        keys=(_trust_key(KEY_A, private_a),),
    )
    version_two = version_one.advance(
        version=2,
        additions=(_trust_key(KEY_B, private_b, introduced_in=2),),
        revocations=(KEY_A,),
    )
    payload = _canonical(_report_body())

    assert version_one.verify(payload, _signature(private_a, payload)) is True
    assert (
        version_one.verify(
            payload,
            _signature(private_b, payload, key_id=KEY_B),
        )
        is False
    )
    assert version_two.verify(payload, _signature(private_a, payload)) is False
    assert (
        version_two.verify(
            payload,
            _signature(private_b, payload, key_id=KEY_B),
        )
        is True
    )


def test_trust_root_document_round_trip_is_closed_and_immutable() -> None:
    private_key = _private_key(6)
    roots = VersionedEd25519TrustRoots(
        version=1,
        keys=(_trust_key(KEY_A, private_key),),
    )
    document = roots.as_document()

    assert document["schema"] == TRUST_ROOT_SCHEMA
    assert VersionedEd25519TrustRoots.from_document(document) == roots

    toml_compatible = copy.deepcopy(document)
    toml_compatible["keys"][0].pop("revoked_in")
    assert VersionedEd25519TrustRoots.from_document(toml_compatible) == roots

    document["keys"][0]["public_key_hex"] = "0" * 64
    assert roots.as_document()["keys"][0]["public_key_hex"] != "0" * 64


@pytest.mark.parametrize(
    "operation",
    [
        lambda roots, private_key: roots.advance(version=1),
        lambda roots, private_key: roots.advance(version=2, revocations=(UNKNOWN_KEY,)),
        lambda roots, private_key: roots.advance(
            version=2,
            additions=(_trust_key(KEY_A, private_key, introduced_in=2),),
        ),
        lambda roots, private_key: VersionedEd25519TrustRoots.from_document(
            {**roots.as_document(), "unexpected": True}
        ),
        lambda roots, private_key: VersionedEd25519TrustRoots(
            version=1,
            keys=(roots.keys[0], roots.keys[0]),
        ),
    ],
)
def test_trust_root_updates_reject_downgrade_unknown_revocation_and_rebinding(
    operation: Callable[[VersionedEd25519TrustRoots, Ed25519PrivateKey], object],
) -> None:
    private_key = _private_key(7)
    roots = VersionedEd25519TrustRoots(
        version=1,
        keys=(_trust_key(KEY_A, private_key),),
    )

    with pytest.raises(BenchmarkTrustRootError):
        operation(roots, private_key)


def test_coordinator_is_default_off_and_requires_literal_per_call_consent() -> None:
    package = _export_package()
    transport = FakeTransport(_receipt(package))
    disabled = _client(transport, enabled=False)

    with pytest.raises(BenchmarkCoordinatorDisabled, match="disabled"):
        disabled.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )
    enabled = _client(transport)
    with pytest.raises(BenchmarkCoordinatorConsentError, match="literal consent"):
        enabled.submit(
            package,
            explicit_consent=False,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert transport.calls == []


def test_coordinator_sends_only_closed_export_to_fixed_https_path_once() -> None:
    package = _export_package()
    transport = FakeTransport(_receipt(package))
    client = _client(transport)

    receipt = client.submit(
        package,
        explicit_consent=True,
        idempotency_key=IDEMPOTENCY_KEY,
    )
    repeated = client.submit(
        package,
        explicit_consent=True,
        idempotency_key=IDEMPOTENCY_KEY,
    )

    assert receipt == repeated
    assert receipt["limitations"] == {
        "cohort_inclusion_verified": False,
        "anonymity_verified": False,
        "differential_privacy_verified": False,
    }
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://benchmark.example.com" + COORDINATOR_SUBMISSION_PATH
    assert call["allow_redirects"] is False
    assert call["timeout"] == 15.0
    assert call["max_response_bytes"] == 128 * 1024
    assert call["headers"]["Idempotency-Key"] == IDEMPOTENCY_KEY
    assert call["headers"]["X-Lightwork-Explicit-Consent"] == "true"
    assert call["headers"]["Content-Length"] == str(len(call["body"]))
    sent = json.loads(call["body"])
    assert set(sent) == {
        "schema",
        "explicit_consent",
        "idempotency_key",
        "contribution",
    }
    assert sent["schema"] == COORDINATOR_SUBMISSION_SCHEMA
    assert sent["explicit_consent"] is True
    sent_keys = _all_mapping_keys(sent)
    assert "tenant_id" not in sent_keys
    assert "tenant_ref" not in sent_keys
    assert "raw_records" not in sent_keys


@pytest.mark.parametrize(
    "origin",
    [
        "http://benchmark.example.com",
        "https://user:secret@benchmark.example.com",
        "https://benchmark.example.com/other/path",
        "https://benchmark.example.com?next=https://evil.example",
        "https://benchmark.example.com#fragment",
        "https://benchmark.example.com:444",
        "https://localhost",
        "https://localhost.localdomain",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://single-label",
    ],
)
def test_coordinator_rejects_hostile_or_non_origin_destinations(origin: str) -> None:
    with pytest.raises(BenchmarkCoordinatorConfigError):
        BenchmarkCoordinatorClient(
            coordinator_origin=origin,
            enabled=True,
            transport=FakeTransport(),
        )


def test_coordinator_rejects_redirect_without_following_hostile_location() -> None:
    package = _export_package()
    transport = FakeTransport(
        CoordinatorHTTPResponse(
            302,
            {
                "Location": "https://169.254.169.254/latest/meta-data/",
                "Content-Length": "0",
            },
            b"",
        )
    )
    client = _client(transport)

    with pytest.raises(BenchmarkCoordinatorProtocolError, match="redirect"):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert len(transport.calls) == 1
    assert transport.calls[0]["allow_redirects"] is False


@pytest.mark.parametrize(
    "response",
    [
        CoordinatorHTTPResponse(
            200,
            {"Content-Type": "application/json", "Content-Length": "1025"},
            b"{}",
        ),
        CoordinatorHTTPResponse(
            200,
            {"Content-Type": "application/json", "Content-Length": "not-an-int"},
            b"{}",
        ),
        CoordinatorHTTPResponse(
            200,
            {"Content-Type": "application/json", "Content-Length": "2"},
            b"{" + b" " * 1024 + b"}",
        ),
    ],
)
def test_coordinator_rejects_oversized_or_mismatched_response_lengths(
    response: CoordinatorHTTPResponse,
) -> None:
    package = _export_package()
    client = _client(
        FakeTransport(response),
        limits=CoordinatorTransportLimits(max_response_bytes=1024),
    )

    with pytest.raises(BenchmarkCoordinatorProtocolError, match="byte bound|Content-Length"):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )


@pytest.mark.parametrize(
    ("headers", "body", "match"),
    [
        ({"Content-Type": "application/json"}, b"{", "malformed JSON"),
        (
            {"Content-Type": "application/json"},
            b'{"schema":"a","schema":"b"}',
            "malformed JSON",
        ),
        ({"Content-Type": "text/html"}, b"{}", "Content-Type"),
        (
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
            b"{}",
            "encoding",
        ),
        (
            {"Content-Type": "application/json", "content-type": "text/plain"},
            b"{}",
            "repeated",
        ),
    ],
)
def test_coordinator_rejects_malformed_or_ambiguous_response_framing(
    headers: Mapping[str, str],
    body: bytes,
    match: str,
) -> None:
    package = _export_package()
    client = _client(FakeTransport(CoordinatorHTTPResponse(200, headers, body)))

    with pytest.raises(BenchmarkCoordinatorProtocolError, match=match):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt.update(schema="unsupported"),
        lambda receipt: receipt.update(status="maybe"),
        lambda receipt: receipt.update(receipt_id="BCR-invalid"),
        lambda receipt: receipt.update(accepted_at=0.0),
        lambda receipt: receipt.update(extra="unexpected"),
    ],
)
def test_coordinator_rejects_malformed_receipts(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    package = _export_package()
    receipt = {
        "schema": COORDINATOR_RECEIPT_SCHEMA,
        "status": "accepted",
        "receipt_id": "BCR-" + "7" * 32,
        "idempotency_key": IDEMPOTENCY_KEY,
        "packet_sha256": package["packet_sha256"],
        "accepted_at": 1_787_889_600.0,
    }
    mutation(receipt)
    body = _canonical(receipt)
    response = CoordinatorHTTPResponse(
        200,
        {"Content-Type": "application/json", "Content-Length": str(len(body))},
        body,
    )

    with pytest.raises(BenchmarkCoordinatorProtocolError):
        _client(FakeTransport(response)).submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )


@pytest.mark.parametrize("field", ["idempotency_key", "packet_sha256"])
def test_coordinator_rejects_receipt_idempotency_or_packet_mismatch(field: str) -> None:
    package = _export_package()
    receipt = json.loads(_receipt(package).body)
    receipt[field] = "other-key" if field == "idempotency_key" else "8" * 64
    body = _canonical(receipt)
    response = CoordinatorHTTPResponse(
        200,
        {"Content-Type": "application/json", "Content-Length": str(len(body))},
        body,
    )

    with pytest.raises(BenchmarkCoordinatorIdempotencyConflict):
        _client(FakeTransport(response)).submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )


def test_coordinator_rejects_oversized_request_before_transport() -> None:
    package = _export_package()
    transport = FakeTransport(_receipt(package))
    client = _client(
        transport,
        limits=CoordinatorTransportLimits(max_request_bytes=1024),
    )

    with pytest.raises(BenchmarkCoordinatorProtocolError, match="exceeds"):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert transport.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda package: package.update(tenant_id="acme"),
        lambda package: package.update(raw_records=[{"prompt": "secret"}]),
        lambda package: package["privacy"].update(raw_records_included=True),
        lambda package: package["approval"].update(four_eyes=False),
        lambda package: package.update(packet_sha256="0" * 64),
    ],
)
def test_coordinator_rejects_raw_tenant_unapproved_or_tampered_exports(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    package = _export_package()
    mutation(package)
    transport = FakeTransport()
    client = _client(transport)

    with pytest.raises((BenchmarkCoordinatorProtocolError, BenchmarkCoordinatorConsentError)):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert transport.calls == []


def test_timeout_is_one_ambiguous_attempt_and_exact_explicit_retry_succeeds() -> None:
    package = _export_package()
    transport = FakeTransport(TimeoutError("read timed out"), _receipt(package))
    client = _client(transport)

    with pytest.raises(BenchmarkCoordinatorAmbiguousDelivery, match="ambiguous"):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )
    assert len(transport.calls) == 1

    receipt = client.submit(
        package,
        explicit_consent=True,
        idempotency_key=IDEMPOTENCY_KEY,
    )

    assert receipt["status"] == "accepted"
    assert len(transport.calls) == 2
    assert transport.calls[0]["url"] == transport.calls[1]["url"]
    assert transport.calls[0]["headers"] == transport.calls[1]["headers"]
    assert transport.calls[0]["body"] == transport.calls[1]["body"]


def test_ambiguous_attempt_cannot_rebind_idempotency_key() -> None:
    package = _export_package()
    transport = FakeTransport(TimeoutError("read timed out"))
    client = _client(transport)

    with pytest.raises(BenchmarkCoordinatorAmbiguousDelivery):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )
    changed = _export_package(numerator=90)
    with pytest.raises(BenchmarkCoordinatorIdempotencyConflict, match="different content"):
        client.submit(
            changed,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert len(transport.calls) == 1


def test_retryable_status_is_ambiguous_and_never_retried_automatically() -> None:
    package = _export_package()
    transport = FakeTransport(
        CoordinatorHTTPResponse(
            503,
            {"Content-Type": "application/json", "Content-Length": "0"},
            b"",
        )
    )

    with pytest.raises(BenchmarkCoordinatorAmbiguousDelivery, match="retryable status"):
        _client(transport).submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert len(transport.calls) == 1


def test_untyped_injected_transport_response_is_rejected() -> None:
    package = _export_package()
    transport = FakeTransport({"status_code": 200, "body": b"{}"})

    with pytest.raises(BenchmarkCoordinatorProtocolError, match="untyped"):
        _client(transport).submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )


def test_default_transport_checks_enterprise_egress_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = _export_package()
    safe_client_called = False

    def deny_egress(url: str, *, tool: str) -> str:
        assert url.endswith(COORDINATOR_SUBMISSION_PATH)
        assert tool == "ai_benchmark_exchange.coordinator"
        return "denied for test"

    def unsafe_client(*_args: object, **_kwargs: object) -> object:
        nonlocal safe_client_called
        safe_client_called = True
        raise AssertionError("safe client must not run after enterprise denial")

    monkeypatch.setattr("maverick.enterprise.enterprise_egress_denial", deny_egress)
    monkeypatch.setattr("maverick.tools._ssrf.safe_client", unsafe_client)
    client = BenchmarkCoordinatorClient(
        coordinator_origin="https://benchmark.example.com",
        enabled=True,
    )

    with pytest.raises(BenchmarkCoordinatorDefinitiveTransportError, match="denied"):
        client.submit(
            package,
            explicit_consent=True,
            idempotency_key=IDEMPOTENCY_KEY,
        )

    assert safe_client_called is False


def test_successful_receipt_and_inputs_are_defensively_copied() -> None:
    package = _export_package()
    original = copy.deepcopy(package)
    transport = FakeTransport(_receipt(package))
    client = _client(transport)

    first = client.submit(
        package,
        explicit_consent=True,
        idempotency_key=IDEMPOTENCY_KEY,
    )
    first["limitations"]["anonymity_verified"] = True
    package["privacy"]["raw_records_included"] = True
    package.clear()
    second = client.submit(
        original,
        explicit_consent=True,
        idempotency_key=IDEMPOTENCY_KEY,
    )

    assert second["limitations"]["anonymity_verified"] is False
    assert len(transport.calls) == 1
