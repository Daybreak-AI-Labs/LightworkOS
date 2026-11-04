from __future__ import annotations

import gc
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path

import pytest
from maverick.consent_delivery import (
    ConsentChange,
    ConsentDeliveryRevoked,
    ConsentDeliveryStore,
    ConsentDeliveryTransportError,
    DeliveryPreferenceChoice,
    SignedDeliveryRequest,
)
from maverick.consent_delivery_destinations import (
    ADOBE_EXPERIENCE_PLATFORM,
    MARKETO,
    SALESFORCE,
    SNOWFLAKE,
    ConsentDestinationBinding,
    ConsentDestinationConfigError,
    ConsentDestinationConflict,
    ConsentDestinationOperationStore,
    ConsentDestinationProtocolError,
    ConsentDestinationRegistry,
    ConsentDestinationRequestNotSent,
    ConsentDestinationRouterTransport,
    ConsentDestinationTransportAmbiguous,
    DeploymentConsentDestinationCredentialOwner,
    DestinationHTTPResponse,
    DestinationReconciliationProbe,
    DestinationReconciliationResult,
    PinnedConsentDestinationHTTPTransport,
    StockConsentDestinationReconciliationAuthority,
    build_consent_destination_registry,
)

NOW = 1_800_000_000.0


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class _Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self, prefix: str) -> str:
        self.value += 1
        return f"{prefix}-{self.value}"


class _Signer:
    def sign(self, key_id: str, payload: bytes) -> bytes:
        return hmac.new((key_id * 8).encode(), payload, hashlib.sha256).digest()


class _HTTP:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests = []

    def request(self, request):
        self.requests.append(request)
        response = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if callable(response):
            response = response(request)
        if isinstance(response, BaseException):
            raise response
        return response


def _settings(provider: str) -> dict[str, object]:
    return {
        SALESFORCE: {
            "api_version": "v65.0",
            "object_api_name": "Lightwork_Consent_Event__c",
            "external_id_field": "Lightwork_Message_Id__c",
            "payload_digest_field": "Lightwork_Payload_SHA256__c",
        },
        MARKETO: {
            "custom_object_name": "lightworkConsentEvent_c",
            "dedupe_field": "choiceKey",
            "message_id_field": "lightworkMessageId",
            "payload_digest_field": "payloadSha256",
        },
        ADOBE_EXPERIENCE_PLATFORM: {
            "connection_id": "connection-123",
            "flow_id": "flow-123",
            "dataset_id": "dataset-123",
            "schema_id": "https://ns.adobe.com/example/schemas/consent",
            "ims_org_id": "123456@AdobeOrg",
        },
        SNOWFLAKE: {
            "database": "GOVERNANCE",
            "schema": "CONSENT",
            "table": "PREFERENCE_EVENTS",
            "warehouse": "GOVERNANCE_WH",
            "role": "GOVERNANCE_WRITER",
        },
    }[provider]


def _origin(provider: str) -> str:
    return {
        SALESFORCE: "https://tenant.my.salesforce.com",
        MARKETO: "https://123-abc-456.mktorest.com",
        ADOBE_EXPERIENCE_PLATFORM: "https://dcs.adobedc.net",
        SNOWFLAKE: "https://acme-org.snowflakecomputing.com",
    }[provider]


def _credential(provider: str) -> str:
    if provider == ADOBE_EXPERIENCE_PLATFORM:
        return json.dumps(
            {
                "bearer_token": "aep-bearer-token-value",
                "api_key": "aep-api-key",
                "ims_org_id": "123456@AdobeOrg",
                "sandbox_name": "prod",
            }
        )
    return f"{provider}-bearer-token-value"


def _success(provider: str) -> DestinationHTTPResponse:
    if provider == SALESFORCE:
        return DestinationHTTPResponse(204, {}, b"")
    if provider == MARKETO:
        return DestinationHTTPResponse(
            200,
            {"content-type": "application/json"},
            b'{"success":true,"result":[{"status":"updated"}]}',
        )
    if provider == ADOBE_EXPERIENCE_PLATFORM:
        return DestinationHTTPResponse(
            200,
            {"content-type": "application/json"},
            b'{"inletId":"connection-123","xactionId":"transaction-1"}',
        )
    return DestinationHTTPResponse(
        200,
        {"content-type": "application/json"},
        b'{"sqlState":"00000","statementHandle":"handle-123"}',
    )


def _delivery_request(tmp_path: Path, provider: str):
    tenant = "tenant-a"
    destination = f"{provider}-destination"
    origin = _origin(provider)
    store = ConsentDeliveryStore(
        tmp_path / f"delivery-{provider}.sqlite3",
        clock=_Clock(),
        id_factory=_Ids(),
        config_gate=lambda: True,
        origin_validator=lambda _origin: None,
    )
    store.enroll_destination(
        tenant,
        destination_id=destination,
        origin=origin,
        signing_key_id="key-1",
        idempotency_key=f"enroll-{provider}",
        max_attempts=3,
        base_backoff_seconds=1,
        max_backoff_seconds=10,
        default_retention_seconds=3600,
    )
    change = ConsentChange(
        event_id=f"event-{provider}",
        event_kind="preferences_changed",
        profile_id="profile-pseudonym-1",
        profile_revision=7,
        receipt_id="receipt-1",
        receipt_sha256=_digest("receipt"),
        policy_id="privacy-policy",
        policy_version=4,
        policy_sha256=_digest("policy"),
        choices=(
            DeliveryPreferenceChoice(
                purpose_id="analytics",
                action="withdraw",
                channel="web",
                vendor_id="vendor-1",
            ),
        ),
        occurred_at=NOW - 10,
    )
    store.enqueue_change(
        tenant,
        change,
        destination_ids=(destination,),
        idempotency_key=f"enqueue-{provider}",
    )
    claim = store.claim(
        tenant,
        worker_id="worker-1",
        limit=1,
        lease_seconds=120,
    )[0]
    return store, store.build_signed_request(claim, _Signer()), destination


def _router(tmp_path: Path, provider: str, responses: list[object]):
    store, request, destination = _delivery_request(tmp_path, provider)
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id=destination,
        provider_id=provider,
        origin=_origin(provider),
        credential_secret_ref=f"${provider.upper()}_CONSENT_DESTINATION",
        credential_revision=1,
        settings=_settings(provider),
    )
    registry = ConsentDestinationRegistry(
        "tenant-a",
        (binding,),
        enabled=True,
        timeout_seconds=8,
        max_response_bytes=32 * 1024,
    )
    credentials = {binding.credential_name: _credential(provider)}
    http = _HTTP(responses)
    operations = ConsentDestinationOperationStore(
        tmp_path / f"operations-{provider}.sqlite3",
        clock=_Clock(),
    )
    router = ConsentDestinationRouterTransport(
        registry,
        operations,
        destination_authority=store.destination,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            credentials.get,
            reference_present=lambda name: name in credentials,
        ),
        http_transport=http,
    )
    return router, store, request, http, binding


def test_registry_is_closed_tenant_exact_and_secret_reference_only() -> None:
    config = {
        "consent_preferences": {
            "enable": True,
            "delivery": {
                "enable": True,
                "destinations": {
                    "enable": True,
                    "enabled_providers": [SALESFORCE, MARKETO],
                    "timeout_seconds": 8,
                    "max_response_bytes": 32768,
                    SALESFORCE: {
                        "destination_id": "sf",
                        "origin": _origin(SALESFORCE),
                        "credential_secret_ref": "$SALESFORCE_TOKEN",
                        "credential_revision": 1,
                        **_settings(SALESFORCE),
                    },
                    MARKETO: {
                        "destination_id": "marketo",
                        "origin": _origin(MARKETO),
                        "credential_secret_ref": "${MARKETO_TOKEN}",
                        "credential_revision": 2,
                        **_settings(MARKETO),
                    },
                },
            },
        }
    }
    registry = build_consent_destination_registry(config, "tenant-a")
    status = registry.status(
        credential_reference_present=lambda name: name == "SALESFORCE_TOKEN"
    )
    assert status["providers"] == [MARKETO, SALESFORCE]
    assert status["ready"] is False
    assert status["credential_values_resolved"] is False
    assert "SALESFORCE_TOKEN" not in json.dumps(status)
    with pytest.raises(ConsentDestinationConfigError, match="tenant"):
        ConsentDestinationRegistry(
            "tenant-b", (registry.binding("sf"),), enabled=True
        )
    broken = json.loads(json.dumps(config))
    broken["consent_preferences"]["delivery"]["destinations"][SALESFORCE][
        "credential_secret_ref"
    ] = "plaintext-secret"
    with pytest.raises(ConsentDestinationConfigError, match=r"\$ENV"):
        build_consent_destination_registry(broken, "tenant-a")


@pytest.mark.parametrize(
    ("provider", "expected_method", "expected_path"),
    [
        (SALESFORCE, "PATCH", "/services/data/v65.0/sobjects/"),
        (MARKETO, "POST", "/rest/v1/customobjects/"),
        (ADOBE_EXPERIENCE_PLATFORM, "POST", "/collection/connection-123"),
        (SNOWFLAKE, "POST", "/api/v2/statements"),
    ],
)
def test_four_named_contracts_are_exact_bounded_and_replay_no_change(
    tmp_path: Path,
    provider: str,
    expected_method: str,
    expected_path: str,
) -> None:
    router, _store, request, http, binding = _router(
        tmp_path, provider, [_success(provider)]
    )
    first = router.post(request, timeout_seconds=10, max_response_bytes=64 * 1024)
    second = router.post(request, timeout_seconds=10, max_response_bytes=64 * 1024)
    assert 200 <= first.status_code < 300
    assert second.response_sha256 == first.response_sha256
    assert len(http.requests) == 1
    outbound = http.requests[0]
    assert outbound.method == expected_method
    assert outbound.origin == binding.origin
    assert outbound.path.startswith(expected_path)
    assert outbound.timeout_seconds == 8
    assert outbound.max_response_bytes == 32 * 1024
    assert outbound.headers["Authorization"].startswith("Bearer ")
    assert request.message_id.encode() not in outbound.body
    assert b"tenant-a" not in outbound.body
    assert b"bearer-token-value" not in (
        tmp_path / f"operations-{provider}.sqlite3"
    ).read_bytes()
    operation = router.operation_store.operation(
        "tenant-a",
        binding.destination_id,
        hashlib.sha256(request.message_id.encode("utf-8")).hexdigest(),
    )
    assert operation["state"] == "completed"
    assert operation["completed_replay_is_no_change"] is True
    assert operation["raw_provider_payload_returned"] is False
    assert router.operation_store.verify_integrity()["valid"] is True


def test_provider_and_credential_json_reject_duplicate_keys_and_wrong_media_type(
    tmp_path: Path,
) -> None:
    duplicate_response = DestinationHTTPResponse(
        200,
        {"content-type": "application/json"},
        b'{"success":true,"success":false,"result":[{"status":"updated"}]}',
    )
    router, _, request, _, _ = _router(
        tmp_path, MARKETO, [duplicate_response]
    )
    rejected = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert rejected.status_code == 409

    wrong_media_type = DestinationHTTPResponse(
        200,
        {"content-type": "text/plain"},
        b'{"success":true,"result":[{"status":"updated"}]}',
    )
    router, _, request, _, _ = _router(
        tmp_path / "wrong-media", MARKETO, [wrong_media_type]
    )
    rejected = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert rejected.status_code == 409

    router, _, request, http, binding = _router(
        tmp_path / "duplicate-secret",
        ADOBE_EXPERIENCE_PLATFORM,
        [_success(ADOBE_EXPERIENCE_PLATFORM)],
    )
    router._credentials = DeploymentConsentDestinationCredentialOwner(
        lambda _name: (
            '{"bearer_token":"first-token","bearer_token":"second-token",'
            '"api_key":"aep-api-key","ims_org_id":"123456@AdobeOrg",'
            '"sandbox_name":"prod"}'
        ),
        reference_present=lambda name: name == binding.credential_name,
    )
    rejected = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert rejected.status_code == 401
    assert http.requests == []


def test_provider_payload_shapes_preserve_idempotency_and_no_caller_sql(
    tmp_path: Path,
) -> None:
    salesforce, _, sf_request, sf_http, _ = _router(
        tmp_path, SALESFORCE, [_success(SALESFORCE)]
    )
    salesforce.post(sf_request, timeout_seconds=5, max_response_bytes=4096)
    assert sf_request.message_id not in sf_http.requests[0].path
    assert "/lw-message-" in sf_http.requests[0].path

    marketo, _, mk_request, mk_http, _ = _router(
        tmp_path, MARKETO, [_success(MARKETO)]
    )
    marketo.post(mk_request, timeout_seconds=5, max_response_bytes=4096)
    marketo_body = json.loads(mk_http.requests[0].body)
    assert marketo_body["action"] == "createOrUpdate"
    assert marketo_body["input"][0]["lightworkMessageId"].startswith("lw-message-")
    assert marketo_body["input"][0]["lightworkMessageId"] != mk_request.message_id
    assert len(marketo_body["input"][0]["choiceKey"]) == 64
    assert marketo_body["input"][0]["lightworkAction"] == "withdraw"

    aep, _, aep_request, aep_http, _ = _router(
        tmp_path, ADOBE_EXPERIENCE_PLATFORM, [_success(ADOBE_EXPERIENCE_PLATFORM)]
    )
    aep.post(aep_request, timeout_seconds=5, max_response_bytes=4096)
    aep_body = json.loads(aep_http.requests[0].body)
    assert aep_body["body"]["xdmEntity"]["_id"].startswith("lw-message-")
    assert aep_body["body"]["xdmEntity"]["_id"] != aep_request.message_id
    assert aep_body["header"]["flowId"] == "flow-123"
    assert aep_body["header"]["imsOrgId"] == "123456@AdobeOrg"
    assert aep_http.requests[0].headers["x-gw-ims-org-id"] == "123456@AdobeOrg"

    snowflake, _, snow_request, snow_http, _ = _router(
        tmp_path, SNOWFLAKE, [_success(SNOWFLAKE)]
    )
    snowflake.post(snow_request, timeout_seconds=5, max_response_bytes=4096)
    snow_body = json.loads(snow_http.requests[0].body)
    assert snow_body["statement"].startswith(
        'MERGE INTO "GOVERNANCE"."CONSENT"."PREFERENCE_EVENTS"'
    )
    assert snow_request.message_id not in snow_body["statement"]
    assert snow_body["bindings"]["1"]["value"].startswith("lw-message-")
    assert snow_body["bindings"]["1"]["value"] != snow_request.message_id
    assert snow_http.requests[0].query[0][0] == "requestId"


def test_retryable_no_send_and_provider_retry_reuse_same_effect_identity(
    tmp_path: Path,
) -> None:
    router, _, request, http, _ = _router(
        tmp_path,
        SALESFORCE,
        [
            ConsentDestinationRequestNotSent("blocked before send"),
            DestinationHTTPResponse(503, {"retry-after": "2"}, b"unavailable"),
            _success(SALESFORCE),
        ],
    )
    with pytest.raises(ConsentDeliveryTransportError, match="not sent"):
        router.post(request, timeout_seconds=5, max_response_bytes=4096)
    retry = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert retry.status_code == 503
    assert retry.retry_after_seconds == 2
    success = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert success.status_code == 204
    assert len(http.requests) == 3


def _with_attempt(request: SignedDeliveryRequest, attempt: int) -> SignedDeliveryRequest:
    envelope = json.loads(request.body)
    envelope["attempt"] = attempt
    body = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    body_sha256 = hashlib.sha256(body).hexdigest()
    headers = (
        ("Content-Type", "application/json"),
        ("X-Lightwork-Delivery-Id", request.message_id),
        ("X-Lightwork-Key-Id", request.key_id),
        ("X-Lightwork-Body-SHA256", body_sha256),
        ("X-Lightwork-Signature", "v1=AA"),
    )
    authorization_sha256 = hashlib.sha256(
        json.dumps(
            {
                "body_sha256": body_sha256,
                "headers": list(headers),
                "url": request.url,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return SignedDeliveryRequest(
        tenant_id=request.tenant_id,
        message_id=request.message_id,
        destination_id=request.destination_id,
        url=request.url,
        body=body,
        headers=headers,
        key_id=request.key_id,
        body_sha256=body_sha256,
        authorization_sha256=authorization_sha256,
    )


def test_snowflake_async_acceptance_retries_with_same_request_id(
    tmp_path: Path,
) -> None:
    router, _, request, http, _ = _router(
        tmp_path,
        SNOWFLAKE,
        [
            DestinationHTTPResponse(
                202,
                {},
                b'{"statementHandle":"handle-123","statementStatusUrl":"/api/v2/statements/handle-123"}',
            ),
            _success(SNOWFLAKE),
        ],
    )
    pending = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert pending.status_code == 503
    retry_request = _with_attempt(request, 2)
    completed = router.post(
        retry_request,
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert completed.status_code == 200
    assert http.requests[0].query[0] == http.requests[1].query[0]
    assert ("retry", "true") not in http.requests[0].query
    assert ("retry", "true") in http.requests[1].query


class _Probe:
    def __init__(self) -> None:
        self.probes = []

    def inspect(self, probe):
        self.probes.append(probe)
        return DestinationReconciliationResult(
            disposition="applied",
            provider_id=probe.provider_id,
            binding_sha256=probe.binding_sha256,
            message_sha256=probe.message_sha256,
            request_sha256=probe.request_sha256,
            payload_sha256=probe.payload_sha256,
            expected_records=probe.expected_records,
            provider_record_ref=probe.provider_record_ref,
            evidence_sha256=_digest("independent-provider-observation"),
        )


@pytest.mark.parametrize(
    ("provider", "expected_records"),
    [(SALESFORCE, 1), (MARKETO, 2), (SNOWFLAKE, 1)],
)
def test_stock_reconciliation_reads_exact_provider_record_without_raw_custody(
    provider: str,
    expected_records: int,
) -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id=f"{provider}-destination",
        provider_id=provider,
        origin=_origin(provider),
        credential_secret_ref=f"${provider.upper()}_TOKEN",
        credential_revision=1,
        settings=_settings(provider),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    payload_sha256 = _digest("provider-payload")

    def provider_response(request):
        assert request.origin == binding.origin
        assert request.headers["Authorization"].startswith("Bearer ")
        if provider == SALESFORCE:
            assert request.method == "GET"
            if request.path.endswith("/describe"):
                body = json.dumps(
                    {
                        "name": binding.settings["object_api_name"],
                        "queryable": True,
                        "updateable": True,
                        "fields": [
                            {
                                "name": binding.settings["external_id_field"],
                                "externalId": True,
                                "createable": True,
                            },
                            {
                                "name": binding.settings["payload_digest_field"],
                                "createable": True,
                                "updateable": True,
                            },
                        ],
                    }
                ).encode()
                return DestinationHTTPResponse(
                    200,
                    {"content-type": "application/json"},
                    body,
                )
            assert request.query == (
                ("fields", binding.settings["payload_digest_field"]),
            )
            body = json.dumps(
                {binding.settings["payload_digest_field"]: payload_sha256}
            ).encode()
        elif provider == MARKETO:
            assert request.method == "GET"
            if request.path.endswith("/describe.json"):
                body = json.dumps(
                    {
                        "success": True,
                        "result": [
                            {
                                "name": binding.settings["custom_object_name"],
                                "dedupeFields": [binding.settings["dedupe_field"]],
                                "searchableFields": [
                                    [binding.settings["message_id_field"]]
                                ],
                                "fields": [
                                    {"name": binding.settings["dedupe_field"]},
                                    {"name": binding.settings["message_id_field"]},
                                    {"name": binding.settings["payload_digest_field"]},
                                ],
                            }
                        ],
                    }
                ).encode()
                return DestinationHTTPResponse(
                    200,
                    {"content-type": "application/json"},
                    body,
                )
            query = dict(request.query)
            message = query["filterValues"]
            body = json.dumps(
                {
                    "success": True,
                    "result": [
                        {
                            binding.settings["message_id_field"]: message,
                            binding.settings["payload_digest_field"]: payload_sha256,
                        }
                        for _ in range(expected_records)
                    ],
                }
            ).encode()
        else:
            assert request.method == "POST"
            statement = json.loads(request.body)["statement"]
            assert statement.startswith("SELECT PAYLOAD_SHA256")
            assert "MERGE" not in statement
            body = json.dumps(
                {"sqlState": "00000", "data": [[payload_sha256]]}
            ).encode()
        return DestinationHTTPResponse(
            200,
            {"content-type": "application/json"},
            body,
        )

    http = _HTTP([provider_response])
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(provider),
            reference_present=lambda _name: True,
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=provider,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=payload_sha256,
        expected_records=expected_records,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=_digest("ambiguous-dispatch"),
    )

    result = authority.inspect(probe)

    assert result.disposition == "applied"
    assert result.payload_sha256 == payload_sha256
    assert result.expected_records == expected_records
    assert len(http.requests) == (2 if provider in {SALESFORCE, MARKETO} else 1)
    assert _credential(provider) not in repr(http.requests[0])


def test_stock_reconciliation_reports_absent_or_incomplete_without_guessing() -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="salesforce-destination",
        provider_id=SALESFORCE,
        origin=_origin(SALESFORCE),
        credential_secret_ref="$SALESFORCE_TOKEN",
        credential_revision=1,
        settings=_settings(SALESFORCE),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    describe = DestinationHTTPResponse(
        200,
        {"content-type": "application/json"},
        json.dumps(
            {
                "name": binding.settings["object_api_name"],
                "queryable": True,
                "updateable": True,
                "fields": [
                    {
                        "name": binding.settings["external_id_field"],
                        "externalId": True,
                        "createable": True,
                    },
                    {
                        "name": binding.settings["payload_digest_field"],
                        "createable": True,
                        "updateable": True,
                    },
                ],
            }
        ).encode(),
    )
    http = _HTTP(
        [
            describe,
            DestinationHTTPResponse(404, {}, b""),
            describe,
            DestinationHTTPResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(
                    {
                        binding.settings["payload_digest_field"]: _digest(
                            "different-payload"
                        )
                    }
                ).encode(),
            ),
        ]
    )
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(SALESFORCE),
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=SALESFORCE,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=_digest("expected-payload"),
        expected_records=1,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=None,
    )

    assert authority.inspect(probe).disposition == "not_applied"
    assert authority.inspect(probe).disposition == "not_applied"


def test_snowflake_reconciliation_follows_one_exact_async_status_authority() -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="snowflake-destination",
        provider_id=SNOWFLAKE,
        origin=_origin(SNOWFLAKE),
        credential_secret_ref="$SNOWFLAKE_TOKEN",
        credential_revision=1,
        settings=_settings(SNOWFLAKE),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    payload_sha256 = _digest("provider-payload")
    handle = "e4ce975e-f7ff-4b5e-b15e-bf25f59371ae"
    http = _HTTP(
        [
            DestinationHTTPResponse(
                202,
                {"content-type": "application/json"},
                json.dumps(
                    {
                        "sqlState": "00000",
                        "statementHandle": handle,
                        "statementStatusUrl": f"/api/v2/statements/{handle}",
                    }
                ).encode(),
            ),
            DestinationHTTPResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(
                    {"sqlState": "00000", "data": [[payload_sha256]]}
                ).encode(),
            ),
        ]
    )
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(SNOWFLAKE),
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=SNOWFLAKE,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=payload_sha256,
        expected_records=1,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=None,
    )

    assert authority.inspect(probe).disposition == "applied"
    assert len(http.requests) == 2
    assert http.requests[1].method == "GET"
    assert http.requests[1].path == f"/api/v2/statements/{handle}"
    assert http.requests[1].query == ()


def test_snowflake_reconciliation_rejects_redirected_status_authority() -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="snowflake-destination",
        provider_id=SNOWFLAKE,
        origin=_origin(SNOWFLAKE),
        credential_secret_ref="$SNOWFLAKE_TOKEN",
        credential_revision=1,
        settings=_settings(SNOWFLAKE),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    handle = "e4ce975e-f7ff-4b5e-b15e-bf25f59371ae"
    http = _HTTP(
        [
            DestinationHTTPResponse(
                202,
                {"content-type": "application/json"},
                json.dumps(
                    {
                        "statementHandle": handle,
                        "statementStatusUrl": (
                            f"https://attacker.example/api/v2/statements/{handle}"
                        ),
                    }
                ).encode(),
            )
        ]
    )
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(SNOWFLAKE),
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=SNOWFLAKE,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=_digest("payload-1"),
        expected_records=1,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=None,
    )

    with pytest.raises(ConsentDestinationProtocolError, match="status authority"):
        authority.inspect(probe)
    assert len(http.requests) == 1


def test_marketo_reconciliation_requires_live_searchable_field_metadata() -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="marketo-destination",
        provider_id=MARKETO,
        origin=_origin(MARKETO),
        credential_secret_ref="$MARKETO_TOKEN",
        credential_revision=1,
        settings=_settings(MARKETO),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    response = DestinationHTTPResponse(
        200,
        {"content-type": "application/json"},
        json.dumps(
            {
                "success": True,
                "result": [
                    {
                        "name": binding.settings["custom_object_name"],
                        "dedupeFields": [binding.settings["dedupe_field"]],
                        "searchableFields": [["someOtherField"]],
                        "fields": [
                            {"name": binding.settings["dedupe_field"]},
                            {"name": binding.settings["message_id_field"]},
                            {"name": binding.settings["payload_digest_field"]},
                        ],
                    }
                ],
            }
        ).encode(),
    )
    http = _HTTP([response])
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(MARKETO),
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=MARKETO,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=_digest("payload-1"),
        expected_records=2,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=None,
    )

    with pytest.raises(ConsentDestinationProtocolError, match="metadata"):
        authority.inspect(probe)
    assert len(http.requests) == 1


def test_salesforce_reconciliation_requires_external_id_metadata() -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="salesforce-destination",
        provider_id=SALESFORCE,
        origin=_origin(SALESFORCE),
        credential_secret_ref="$SALESFORCE_TOKEN",
        credential_revision=1,
        settings=_settings(SALESFORCE),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    response = DestinationHTTPResponse(
        200,
        {"content-type": "application/json"},
        json.dumps(
            {
                "name": binding.settings["object_api_name"],
                "queryable": True,
                "updateable": True,
                "fields": [
                    {
                        "name": binding.settings["external_id_field"],
                        "externalId": False,
                        "createable": True,
                    },
                    {
                        "name": binding.settings["payload_digest_field"],
                        "createable": True,
                        "updateable": True,
                    },
                ],
            }
        ).encode(),
    )
    http = _HTTP([response])
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(SALESFORCE),
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=SALESFORCE,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=_digest("payload-1"),
        expected_records=1,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=None,
    )

    with pytest.raises(ConsentDestinationProtocolError, match="fields"):
        authority.inspect(probe)
    assert len(http.requests) == 1


def test_stock_aep_reconciliation_fails_closed_without_query_authority() -> None:
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="aep-destination",
        provider_id=ADOBE_EXPERIENCE_PLATFORM,
        origin=_origin(ADOBE_EXPERIENCE_PLATFORM),
        credential_secret_ref="$AEP_TOKEN",
        credential_revision=1,
        settings=_settings(ADOBE_EXPERIENCE_PLATFORM),
    )
    registry = ConsentDestinationRegistry("tenant-a", [binding], enabled=True)
    http = _HTTP([AssertionError("AEP provider I/O must not start")])
    authority = StockConsentDestinationReconciliationAuthority(
        registry,
        credential_owner=DeploymentConsentDestinationCredentialOwner(
            resolver=lambda _name: _credential(ADOBE_EXPERIENCE_PLATFORM),
        ),
        http_transport=http,
    )
    probe = DestinationReconciliationProbe(
        tenant_id="tenant-a",
        destination_id=binding.destination_id,
        provider_id=ADOBE_EXPERIENCE_PLATFORM,
        binding_sha256=binding.authority_sha256,
        message_sha256=_digest("message-1"),
        request_sha256=_digest("request-1"),
        payload_sha256=_digest("payload-1"),
        expected_records=1,
        provider_record_ref="lw-message-readback-record",
        prior_evidence_sha256=None,
    )

    with pytest.raises(ConsentDestinationConfigError, match="query authority"):
        authority.inspect(probe)
    assert http.requests == []


def test_ambiguous_dispatch_requires_bound_reconciliation_before_replay(
    tmp_path: Path,
) -> None:
    base, store, request, http, binding = _router(
        tmp_path,
        MARKETO,
        [ConsentDestinationTransportAmbiguous("connection reset")],
    )
    with pytest.raises(ConsentDeliveryTransportError, match="ambiguous"):
        base.post(request, timeout_seconds=5, max_response_bytes=4096)
    blocked = base.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert blocked.status_code == 409
    items = base.operation_store.ambiguous("tenant-a", binding.destination_id)
    assert len(items) == 1
    assert set(items[0]).isdisjoint({"tenant_id", "destination_id", "message_id"})

    probe = _Probe()
    router = ConsentDestinationRouterTransport(
        base.registry,
        base.operation_store,
        destination_authority=store.destination,
        credential_owner=base._credentials,
        http_transport=http,
        reconciliation_authority=probe,
    )
    result = router.reconcile(
        destination_id=binding.destination_id,
        message_sha256=items[0]["message_sha256"],
        request_sha256=items[0]["request_sha256"],
    )
    assert result["disposition"] == "applied"
    replay = router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert replay.status_code == 204
    assert len(http.requests) == 1
    assert len(probe.probes) == 1


def test_tampered_reconciliation_binding_is_rejected(tmp_path: Path) -> None:
    base, store, request, http, binding = _router(
        tmp_path,
        SALESFORCE,
        [ConsentDestinationTransportAmbiguous("timeout")],
    )
    with pytest.raises(ConsentDeliveryTransportError):
        base.post(request, timeout_seconds=5, max_response_bytes=4096)
    item = base.operation_store.ambiguous("tenant-a", binding.destination_id)[0]

    class BadProbe:
        def inspect(self, probe):
            return DestinationReconciliationResult(
                disposition="applied",
                provider_id=probe.provider_id,
                binding_sha256=_digest("other-binding"),
                message_sha256=probe.message_sha256,
                request_sha256=probe.request_sha256,
                payload_sha256=probe.payload_sha256,
                expected_records=probe.expected_records,
                provider_record_ref=probe.provider_record_ref,
                evidence_sha256=_digest("evidence"),
            )

    router = ConsentDestinationRouterTransport(
        base.registry,
        base.operation_store,
        destination_authority=store.destination,
        credential_owner=base._credentials,
        http_transport=http,
        reconciliation_authority=BadProbe(),
    )
    with pytest.raises(ConsentDestinationConflict, match="exactly bound"):
        router.reconcile(
            destination_id=binding.destination_id,
            message_sha256=item["message_sha256"],
            request_sha256=item["request_sha256"],
        )


def test_delivery_destination_revocation_wins_before_provider_io(tmp_path: Path) -> None:
    router, store, request, http, binding = _router(
        tmp_path, SALESFORCE, [_success(SALESFORCE)]
    )
    authority = store.destination("tenant-a", binding.destination_id)
    store.revoke_destination(
        "tenant-a",
        binding.destination_id,
        expected_revision=authority["revision"],
        idempotency_key="revoke-provider-destination",
    )
    with pytest.raises(ConsentDeliveryRevoked):
        router.post(request, timeout_seconds=5, max_response_bytes=4096)
    assert http.requests == []


def test_destination_revocation_cancels_ambiguous_reconciliation(
    tmp_path: Path,
) -> None:
    base, store, request, http, binding = _router(
        tmp_path,
        SALESFORCE,
        [ConsentDestinationTransportAmbiguous("timeout")],
    )
    with pytest.raises(ConsentDeliveryTransportError):
        base.post(request, timeout_seconds=5, max_response_bytes=4096)
    item = base.operation_store.ambiguous("tenant-a", binding.destination_id)[0]
    authority = store.destination("tenant-a", binding.destination_id)
    store.revoke_destination(
        "tenant-a",
        binding.destination_id,
        expected_revision=authority["revision"],
        idempotency_key="revoke-before-reconcile",
    )
    router = ConsentDestinationRouterTransport(
        base.registry,
        base.operation_store,
        destination_authority=store.destination,
        credential_owner=base._credentials,
        http_transport=http,
        reconciliation_authority=_Probe(),
    )
    with pytest.raises(ConsentDeliveryRevoked, match="revoked"):
        router.reconcile(
            destination_id=binding.destination_id,
            message_sha256=item["message_sha256"],
            request_sha256=item["request_sha256"],
        )
    operation = base.operation_store.operation(
        "tenant-a",
        binding.destination_id,
        item["message_sha256"],
    )
    assert operation["state"] == "revoked"


def test_destination_revocation_during_readback_wins_before_reconciliation_commit(
    tmp_path: Path,
) -> None:
    base, store, request, http, binding = _router(
        tmp_path,
        SALESFORCE,
        [ConsentDestinationTransportAmbiguous("timeout")],
    )
    with pytest.raises(ConsentDeliveryTransportError):
        base.post(request, timeout_seconds=5, max_response_bytes=4096)
    item = base.operation_store.ambiguous("tenant-a", binding.destination_id)[0]

    class RevokingProbe(_Probe):
        def inspect(self, probe):
            authority = store.destination("tenant-a", binding.destination_id)
            store.revoke_destination(
                "tenant-a",
                binding.destination_id,
                expected_revision=authority["revision"],
                idempotency_key="revoke-during-reconcile",
            )
            return super().inspect(probe)

    router = ConsentDestinationRouterTransport(
        base.registry,
        base.operation_store,
        destination_authority=store.destination,
        credential_owner=base._credentials,
        http_transport=http,
        reconciliation_authority=RevokingProbe(),
    )
    with pytest.raises(ConsentDeliveryRevoked, match="during reconciliation"):
        router.reconcile(
            destination_id=binding.destination_id,
            message_sha256=item["message_sha256"],
            request_sha256=item["request_sha256"],
        )
    operation = base.operation_store.operation(
        "tenant-a",
        binding.destination_id,
        item["message_sha256"],
    )
    assert operation["state"] == "revoked"


def test_readiness_does_not_expose_secret_or_claim_live_acceptance(
    tmp_path: Path,
) -> None:
    router, _, _, _, binding = _router(
        tmp_path, ADOBE_EXPERIENCE_PLATFORM, [_success(ADOBE_EXPERIENCE_PLATFORM)]
    )
    status = router.readiness()
    serialized = json.dumps(status)
    assert status["configured"] is True
    assert status["ready"] is False
    assert status["reconciliation_authority_installed"] is False
    assert status["credential_values_resolved"] is False
    assert status["live_provider_acceptance_verified"] is False
    assert status["redirects_followed"] is False
    assert binding.credential_name not in serialized
    assert "aep-bearer-token-value" not in serialized


def test_digest_only_operation_integrity_detects_tampering(tmp_path: Path) -> None:
    router, _, request, _, _ = _router(
        tmp_path, SALESFORCE, [_success(SALESFORCE)]
    )
    router.post(request, timeout_seconds=5, max_response_bytes=4096)
    with sqlite3.connect(router.operation_store.path) as connection:
        connection.execute(
            "UPDATE consent_destination_operations SET state='retryable'"
        )
    with pytest.raises(ConsentDestinationConflict, match="record changed"):
        router.operation_store.verify_integrity()


def test_preparation_lease_blocks_concurrent_dispatch_and_recovers_before_send(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    operations = ConsentDestinationOperationStore(
        tmp_path / "preparation-lease.sqlite3",
        clock=clock,
    )
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="salesforce",
        provider_id=SALESFORCE,
        origin=_origin(SALESFORCE),
        credential_secret_ref="$SALESFORCE_TOKEN",
        credential_revision=1,
        settings=_settings(SALESFORCE),
    )
    assert (
        operations.begin(
            binding,
            message_id="message-1",
            request_sha256=_digest("request-1"),
            payload_sha256=_digest("payload-1"),
            expected_records=1,
            provider_record_ref="lw-message-record-1",
        )
        is None
    )
    with pytest.raises(ConsentDestinationConflict, match="already active"):
        operations.begin(
            binding,
            message_id="message-1",
            request_sha256=_digest("request-1"),
            payload_sha256=_digest("payload-1"),
            expected_records=1,
            provider_record_ref="lw-message-record-1",
        )
    clock.value += 61
    assert (
        operations.begin(
            binding,
            message_id="message-1",
            request_sha256=_digest("request-1"),
            payload_sha256=_digest("payload-1"),
            expected_records=1,
            provider_record_ref="lw-message-record-1",
        )
        is None
    )


def test_pinned_transport_refuses_private_override_before_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="salesforce",
        provider_id=SALESFORCE,
        origin=_origin(SALESFORCE),
        credential_secret_ref="$SALESFORCE_TOKEN",
        credential_revision=1,
        settings=_settings(SALESFORCE),
    )
    request = _router_request(binding)
    with pytest.raises(ConsentDestinationRequestNotSent, match="private-fetch"):
        PinnedConsentDestinationHTTPTransport().request(request)


def test_pinned_transport_passes_no_redirect_flag_and_refuses_redirect_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    seen: dict[str, object] = {}

    class Response:
        status_code = 302
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def iter_bytes(self):
            return iter(())

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def stream(self, method, url, *, headers, content):
            seen.update(method=method, url=url, headers=headers, content=content)
            return Response()

    def safe_client(url, *, timeout, follow_redirects):
        seen.update(
            safe_client_url=url,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )
        return Client()

    monkeypatch.setattr(
        "maverick.enterprise.enterprise_egress_denial",
        lambda _url, *, tool: None,
    )
    monkeypatch.setattr("maverick.tools._ssrf.safe_client", safe_client)
    binding = ConsentDestinationBinding(
        tenant_id="tenant-a",
        destination_id="salesforce",
        provider_id=SALESFORCE,
        origin=_origin(SALESFORCE),
        credential_secret_ref="$SALESFORCE_TOKEN",
        credential_revision=1,
        settings=_settings(SALESFORCE),
    )
    with pytest.raises(ConsentDestinationTransportAmbiguous, match="redirect"):
        PinnedConsentDestinationHTTPTransport().request(_router_request(binding))
    assert seen["follow_redirects"] is False
    assert seen["safe_client_url"] == _origin(SALESFORCE) + (
        "/services/data/v65.0/sobjects/Test__c/Key__c/message-1"
    )


def test_provider_origin_and_settings_are_exact() -> None:
    with pytest.raises(ConsentDestinationConfigError, match="recognized salesforce"):
        ConsentDestinationBinding(
            tenant_id="tenant-a",
            destination_id="salesforce",
            provider_id=SALESFORCE,
            origin="https://attacker.example.com",
            credential_secret_ref="$SALESFORCE_TOKEN",
            credential_revision=1,
            settings=_settings(SALESFORCE),
        )
    settings = _settings(SNOWFLAKE)
    settings["table"] = "PREFERENCE_EVENTS; DROP TABLE USERS"
    with pytest.raises(ConsentDestinationConfigError, match="identifier"):
        ConsentDestinationBinding(
            tenant_id="tenant-a",
            destination_id="snowflake",
            provider_id=SNOWFLAKE,
            origin=_origin(SNOWFLAKE),
            credential_secret_ref="$SNOWFLAKE_TOKEN",
            credential_revision=1,
            settings=settings,
        )


def _router_request(binding: ConsentDestinationBinding):
    from maverick.consent_delivery_destinations import DestinationHTTPRequest

    return DestinationHTTPRequest(
        provider_id=binding.provider_id,
        origin=binding.origin,
        method="POST",
        path="/services/data/v65.0/sobjects/Test__c/Key__c/message-1",
        query=(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer provider-secret-value",
        },
        body=b"{}",
        timeout_seconds=2,
        max_response_bytes=4096,
    )


def test_turning_destinations_off_is_a_clean_off_with_services_still_listed() -> None:
    """Off with installer-chosen services still listed sends nothing and is not an error."""
    config = {
        "consent_preferences": {
            "delivery": {
                "destinations": {
                    "enable": False,
                    "enabled_providers": ["salesforce", "marketo"],
                    # An incomplete table for a listed service does not matter while off.
                    "salesforce": {"destination_id": "sf-main"},
                }
            }
        }
    }
    registry = build_consent_destination_registry(config, "tenant-a")
    status = registry.status()
    assert status["enabled"] is False and status["configured"] is False
    assert status["destinations"] == []
    with pytest.raises(ConsentDestinationConfigError, match="disabled"):
        registry.binding("sf-main")


def test_every_operation_store_connection_closes_when_its_call_returns(tmp_path, monkeypatch):
    # CPython 3.12 keeps an unclosed sqlite3 connection alive until a cyclic GC pass,
    # so GC is disabled here: any connection left open by a call stays open.
    from maverick import consent_delivery_destinations as destinations

    opened = []
    real_connect = sqlite3.connect
    fail_pragma = {"on": True}

    class _PragmaFails(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql == "PRAGMA foreign_keys=ON" and fail_pragma["on"]:
                raise sqlite3.OperationalError("pragma failed")
            return super().execute(sql, *args)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_PragmaFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(destinations.sqlite3, "connect", recording_connect)
    path = tmp_path / "operations.sqlite3"
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            ConsentDestinationOperationStore(path, clock=_Clock())
        fail_pragma["on"] = False
        operations = ConsentDestinationOperationStore(path, clock=_Clock())
        operations.verify_integrity()
    finally:
        gc.enable()
    assert len(opened) >= 2
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_shared_setup_failure_is_left_to_the_session_owner(tmp_path, monkeypatch):
    from maverick import consent_storage

    store = ConsentDestinationOperationStore(tmp_path / "operations.sqlite3", clock=_Clock())
    sessions = []

    class _SetupFails:
        def __init__(self):
            self.closes = []
            self.row_factory = None
            sessions.append(self)

        def execute(self, sql, *args):
            raise sqlite3.OperationalError("pragma failed")

        def close(self):
            self.closes.append(True)

    monkeypatch.setattr(consent_storage, "shared", lambda: True)
    monkeypatch.setattr(consent_storage, "connect", lambda path, **kwargs: _SetupFails())
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            with store._connect():
                pass
        assert len(sessions) == 1 and sessions[0].closes == []
    finally:
        gc.enable()
