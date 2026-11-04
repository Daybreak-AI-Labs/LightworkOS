"""Adversarial contract tests for fixed ServiceNow IRM and Archer transports."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from maverick import grc_vendor_transports as gvt
from maverick.grc_outbound_sync import (
    ExternalReference,
    GRCSystem,
    GRCTransportConflict,
    GRCTransportFailure,
    OutboundRequest,
    SourceKind,
)

_SN_ID = "0123456789abcdef0123456789abcdef"
_SOURCE_DIGEST = "a" * 64
_TENANT_DIGEST = "b" * 64
_SECRET = "super-secret-vendor-token-12345"


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _request(
    target: GRCSystem,
    source_kind: SourceKind,
    operation: str,
    *,
    revision: int = 1,
    reference: ExternalReference | None = None,
) -> OutboundRequest:
    payload: dict[str, object]
    if target is GRCSystem.SERVICENOW_IRM:
        payload = {
            "short_description": f"Governed {source_kind.value}",
            "risk_rating": "high",
            "source": "Lightwork",
        }
    else:
        payload = {
            "record_name": f"Lightwork {source_kind.value}: source-1",
            "risk_rating": "High",
            "source_system": "Lightwork",
        }
    return OutboundRequest(
        target=target,
        operation=operation,
        source_kind=source_kind,
        source_id="source-1",
        source_revision=revision,
        source_digest=_SOURCE_DIGEST,
        tenant_sha256=_TENANT_DIGEST,
        idempotency_key=f"GRC-{target.value}-{source_kind.value}-{revision}",
        payload_sha256=_canonical_digest(payload),
        payload=payload,
        external_reference=reference,
    )


def _http_response(
    status: int = 200,
    payload: object | None = None,
    *,
    headers: Mapping[str, str] | None = None,
) -> gvt.VendorHTTPResponse:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    return gvt.VendorHTTPResponse(status, dict(headers or {}), body)


class _QueueHTTP:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None,
        timeout: float,
        max_response_bytes: int,
    ) -> gvt.VendorHTTPResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "json_body": dict(json_body) if json_body is not None else None,
                "timeout": timeout,
                "max_response_bytes": max_response_bytes,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected vendor HTTP call")
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item(self.calls[-1])
        assert isinstance(item, gvt.VendorHTTPResponse)
        return item


class _HandlerHTTP:
    def __init__(self, handler: Callable[[dict[str, Any]], gvt.VendorHTTPResponse]):
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, object] | None,
        timeout: float,
        max_response_bytes: int,
    ) -> gvt.VendorHTTPResponse:
        call = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "json_body": dict(json_body) if json_body is not None else None,
            "timeout": timeout,
            "max_response_bytes": max_response_bytes,
        }
        self.calls.append(call)
        return self.handler(call)


def _sn_row(
    request: OutboundRequest,
    *,
    revision: str = "7",
    idempotency_key: str | None = None,
    digest: str | None = None,
) -> dict[str, object]:
    return {
        "sys_id": _SN_ID,
        "sys_mod_count": revision,
        "u_lightwork_idempotency_key": (
            request.idempotency_key if idempotency_key is None else idempotency_key
        ),
        "u_lightwork_payload_sha256": request.payload_sha256,
        "u_lightwork_source_revision": request.source_revision,
        "u_lightwork_source_digest": request.source_digest if digest is None else digest,
        "u_lightwork_tenant_sha256": request.tenant_sha256,
    }


def _archer_row(
    request: OutboundRequest,
    *,
    external_id: int = 1234,
    idempotency_key: str | None = None,
    source_revision: int | None = None,
    digest: str | None = None,
) -> dict[str, object]:
    return {
        "Lightwork_GRC_Sync_Id": external_id,
        "Lightwork_Idempotency_Key": (
            request.idempotency_key if idempotency_key is None else idempotency_key
        ),
        "Lightwork_Source_Revision": (
            request.source_revision if source_revision is None else source_revision
        ),
        "Lightwork_Source_Digest": request.source_digest if digest is None else digest,
        "Lightwork_Payload_SHA256": request.payload_sha256,
        "Lightwork_Tenant_SHA256": request.tenant_sha256,
        "Lightwork_Source_Kind": request.source_kind.value,
        "Lightwork_Source_Id": request.source_id,
        "Lightwork_Operation": request.operation,
    }


@pytest.mark.parametrize(
    ("kind", "operation", "table"),
    [
        (SourceKind.FINDING, "servicenow_irm.upsert_issue", "sn_grc_issue"),
        (
            SourceKind.RISK_ACCEPTANCE,
            "servicenow_irm.upsert_risk_response",
            "sn_risk_response_task",
        ),
        (
            SourceKind.AI_INCIDENT,
            "servicenow_irm.upsert_risk_event",
            "sn_risk_advanced_event",
        ),
    ],
)
def test_servicenow_create_uses_only_fixed_irm_table_and_fields(
    kind: SourceKind,
    operation: str,
    table: str,
) -> None:
    request = _request(GRCSystem.SERVICENOW_IRM, kind, operation)
    http = _QueueHTTP(
        [
            _http_response(payload={"result": []}),
            _http_response(201),
            _http_response(payload={"result": [_sn_row(request)]}),
        ]
    )
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
        limits=gvt.VendorTransportLimits(
            timeout_seconds=9,
            max_response_bytes=32_768,
        ),
    )

    result = transport.send(request)

    assert [call["method"] for call in http.calls] == ["GET", "POST", "GET"]
    assert all(f"/api/now/table/{table}" in call["url"] for call in http.calls)
    assert all("evil" not in call["url"] for call in http.calls)
    create = http.calls[1]
    assert create["timeout"] == 9.0
    assert create["max_response_bytes"] == 32_768
    assert create["headers"]["Authorization"] == f"Bearer {_SECRET}"
    assert create["headers"]["Idempotency-Key"] == request.idempotency_key
    assert create["headers"]["X-Lightwork-Payload-SHA256"] == request.payload_sha256
    assert create["json_body"]["u_lightwork_idempotency_key"] == request.idempotency_key
    assert create["json_body"]["u_lightwork_source_digest"] == request.source_digest
    assert create["json_body"]["short_description"] == request.payload["short_description"]
    assert result.external_id == _SN_ID
    assert result.external_revision == "7"
    assert urlsplit(result.external_url).query == ""
    assert "%3Fsys_id%3D" in result.external_url


def test_servicenow_update_preflights_revision_and_recovers_repeat() -> None:
    reference = ExternalReference(_SN_ID, "4")
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
        revision=2,
        reference=reference,
    )
    old = _sn_row(
        request,
        revision="4",
        idempotency_key="GRC-old-revision",
        digest="c" * 64,
    )
    current = _sn_row(request, revision="5")
    http = _QueueHTTP(
        [
            _http_response(payload={"result": old}),
            _http_response(200),
            _http_response(payload={"result": current}),
            _http_response(payload={"result": current}),
        ]
    )
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    first = transport.send(request)
    repeated = transport.send(request)

    assert first == repeated
    assert first.external_revision == "5"
    mutations = [call for call in http.calls if call["method"] == "PATCH"]
    assert len(mutations) == 1
    assert mutations[0]["headers"]["If-Match"] == "4"
    assert f"/{_SN_ID}?" in mutations[0]["url"]


def test_servicenow_timeout_after_create_is_recovered_without_duplicate() -> None:
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    remote: dict[str, object] | None = None
    posts = 0

    def handler(call: dict[str, Any]) -> gvt.VendorHTTPResponse:
        nonlocal posts, remote
        if call["method"] == "GET":
            rows = [] if remote is None else [remote]
            return _http_response(payload={"result": rows})
        posts += 1
        remote = _sn_row(request)
        raise TimeoutError(f"response lost after write {_SECRET}")

    http = _HandlerHTTP(handler)
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    with pytest.raises(GRCTransportFailure) as caught:
        transport.send(request)
    assert caught.value.category == "vendor_transport_timeout"
    assert caught.value.retryable is True
    assert _SECRET not in str(caught.value)
    assert _SECRET not in repr(caught.value)

    recovered = transport.send(request)
    assert recovered.external_id == _SN_ID
    assert posts == 1


def test_servicenow_revision_conflict_stops_before_patch() -> None:
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
        revision=2,
        reference=ExternalReference(_SN_ID, "3"),
    )
    prior = _sn_row(request, revision="4", idempotency_key="GRC-old")
    http = _QueueHTTP([_http_response(payload={"result": prior})])
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    with pytest.raises(GRCTransportConflict) as caught:
        transport.send(request)
    assert caught.value.category == "external_revision_conflict"
    assert [call["method"] for call in http.calls] == ["GET"]


@pytest.mark.parametrize(
    ("status", "category", "retryable", "conflict"),
    [
        (302, "vendor_redirect_rejected", False, False),
        (401, "vendor_authentication_rejected", False, False),
        (404, "vendor_endpoint_missing", False, False),
        (409, "external_revision_conflict", False, True),
        (429, "vendor_rate_limited", True, False),
        (503, "vendor_unavailable", True, False),
    ],
)
def test_vendor_statuses_have_safe_typed_classification(
    status: int,
    category: str,
    retryable: bool,
    conflict: bool,
) -> None:
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    responses = [_http_response(status, {"error": _SECRET})]
    if status == 409:
        responses.append(_http_response(payload={"result": []}))
    http = _QueueHTTP(responses)
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    expected = GRCTransportConflict if conflict else GRCTransportFailure
    with pytest.raises(expected) as caught:
        transport.send(request)
    assert caught.value.category == category
    assert caught.value.retryable is retryable
    assert _SECRET not in str(caught.value)
    assert _SECRET not in repr(caught.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://tenant.example.com",
        "https://user:pass@tenant.example.com",
        "https://tenant.example.com?next=https://evil.example",
        "https://tenant.example.com/#fragment",
        "https://localhost",
        "https://service.local",
        "https://127.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
        "https://tenant.example.com/caller/chosen/path",
    ],
)
def test_servicenow_rejects_hostile_or_non_origin_base_urls(base_url: str) -> None:
    with pytest.raises(gvt.GRCVendorConfigError):
        gvt.ServiceNowIRMTransport(base_url=base_url)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://archer.example.com",
        "https://token@archer.example.com",
        "https://archer.example.com/rsaarcher/contentapi/Evil",
        "https://10.0.0.2/rsaarcher",
        "https://metadata.local/rsaarcher",
    ],
)
def test_archer_rejects_hostile_or_caller_shaped_paths(base_url: str) -> None:
    with pytest.raises(gvt.GRCVendorConfigError):
        gvt.ArcherTransport(base_url=base_url)


def test_config_loader_is_strict_uses_env_and_does_not_resolve_secret() -> None:
    secret_reads = 0

    def resolver(_name: str) -> str:
        nonlocal secret_reads
        secret_reads += 1
        return _SECRET

    transport = gvt.transport_from_config(
        GRCSystem.SERVICENOW_IRM,
        config={
            "grc_outbound_sync": {
                "servicenow_irm": {
                    "credential_secret_ref": "CUSTOM_SN_TOKEN",
                    "timeout_seconds": 7,
                    "max_response_bytes": 4_096,
                }
            }
        },
        environ={"SERVICENOW_INSTANCE_URL": "https://tenant.service-now.com"},
        http=_QueueHTTP([]),
        secret_resolver=resolver,
    )

    assert isinstance(transport, gvt.ServiceNowIRMTransport)
    assert secret_reads == 0
    assert "CUSTOM_SN_TOKEN" in repr(transport)
    assert _SECRET not in repr(transport)

    with pytest.raises(gvt.GRCVendorConfigError) as caught:
        gvt.transport_from_config(
            GRCSystem.ARCHER,
            config={
                "grc_outbound_sync": {
                    "archer": {
                        "base_url": "https://archer.example.com",
                        "token": _SECRET,
                    }
                }
            },
        )
    assert caught.value.category == "vendor_config_unknown_key"
    assert _SECRET not in str(caught.value)


def test_config_loader_normalizes_documented_archer_api_base() -> None:
    transport = gvt.transport_from_config(
        GRCSystem.ARCHER,
        config={"grc_outbound_sync": {}},
        environ={
            "ARCHER_GRC_BASE_URL": "https://archer.example.com/RSAArcher/platformapi",
            "MAVERICK_GRC_ARCHER_SECRET_REF": "CUSTOM_ARCHER_TOKEN",
        },
        http=_QueueHTTP([]),
    )
    rendered = repr(transport)
    assert "https://archer.example.com/RSAArcher" in rendered
    assert "platformapi" not in rendered
    assert "CUSTOM_ARCHER_TOKEN" in rendered


@pytest.mark.parametrize("key", ["base_url", "credential_secret_ref"])
def test_config_loader_rejects_explicit_empty_required_values(key: str) -> None:
    section: dict[str, object] = {
        "base_url": "https://tenant.service-now.com",
        "credential_secret_ref": "SERVICENOW_TOKEN",
    }
    section[key] = ""
    with pytest.raises(gvt.GRCVendorConfigError):
        gvt.transport_from_config(
            GRCSystem.SERVICENOW_IRM,
            config={"grc_outbound_sync": {"servicenow_irm": section}},
            environ={
                "SERVICENOW_INSTANCE_URL": "https://fallback.service-now.com",
                "MAVERICK_GRC_SERVICENOW_SECRET_REF": "FALLBACK_TOKEN",
            },
        )


def test_invalid_or_missing_credentials_never_reach_http() -> None:
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    http = _QueueHTTP([])
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: "bad\r\nX-Evil: yes",
    )
    with pytest.raises(gvt.GRCVendorConfigError) as caught:
        transport.send(request)
    assert caught.value.category == "credential_header_invalid"
    assert http.calls == []

    missing = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: None,
    )
    with pytest.raises(gvt.GRCVendorConfigError) as caught:
        missing.send(request)
    assert caught.value.category == "credential_unavailable"
    assert http.calls == []


@pytest.mark.parametrize(
    ("response", "category"),
    [
        (
            gvt.VendorHTTPResponse(200, {"Content-Length": "999999"}, b"{}"),
            "vendor_response_too_large",
        ),
        (gvt.VendorHTTPResponse(200, {}, b"x" * 4_097), "vendor_response_too_large"),
        (gvt.VendorHTTPResponse(200, {}, b"not-json"), "vendor_response_not_json"),
        # Valid JSON that parses but is not an object gets the precise category.
        (gvt.VendorHTTPResponse(200, {}, b"[1, 2, 3]"), "vendor_response_not_object"),
    ],
)
def test_response_size_and_json_are_bounded(
    response: gvt.VendorHTTPResponse,
    category: str,
) -> None:
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=_QueueHTTP([response]),
        secret_resolver=lambda _name: _SECRET,
        limits=gvt.VendorTransportLimits(max_response_bytes=4_096),
    )
    with pytest.raises(GRCTransportFailure) as caught:
        transport.send(request)
    assert caught.value.category == category


def test_pathological_nesting_is_rejected_on_every_interpreter() -> None:
    """A 1,100-deep array must never be ACCEPTED, but which bounded category
    rejects it is interpreter-dependent: CPython <= 3.11 raises RecursionError
    inside json.loads (mapped to not_json), while 3.12+ parses it and the
    object check refuses it (not_object). Pinning either category alone made
    this test red on the other half of the CI matrix."""
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    response = gvt.VendorHTTPResponse(200, {}, b"[" * 1_100 + b"0" + b"]" * 1_100)
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=_QueueHTTP([response]),
        secret_resolver=lambda _name: _SECRET,
    )
    with pytest.raises(gvt.GRCVendorProtocolError) as caught:
        transport.send(request)
    assert caught.value.category in {
        "vendor_response_not_json",
        "vendor_response_not_object",
    }


def test_untyped_response_and_wrong_operation_fail_closed_before_persistence() -> None:
    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    wrong = _request(
        GRCSystem.ARCHER,
        SourceKind.FINDING,
        "archer.upsert_finding",
    )
    class _UntypedHTTP:
        def __init__(self) -> None:
            self.calls: list[object] = []

        def request(self, *_args: object, **_kwargs: object) -> object:
            self.calls.append(object())
            return object()

    http = _UntypedHTTP()
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://tenant.service-now.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )
    with pytest.raises(gvt.GRCVendorProtocolError) as caught:
        transport.send(wrong)
    assert caught.value.category == "vendor_target_mismatch"
    assert http.calls == []

    with pytest.raises(gvt.GRCVendorProtocolError) as caught:
        transport.send(request)
    assert caught.value.category == "vendor_http_response_untyped"


@pytest.mark.parametrize(
    ("kind", "operation"),
    [
        (SourceKind.FINDING, "archer.upsert_finding"),
        (SourceKind.RISK_ACCEPTANCE, "archer.upsert_risk_acceptance"),
        (SourceKind.AI_INCIDENT, "archer.upsert_ai_incident"),
    ],
)
def test_archer_create_uses_fixed_content_application_and_safe_envelope(
    kind: SourceKind,
    operation: str,
) -> None:
    request = _request(GRCSystem.ARCHER, kind, operation)
    row = _archer_row(request)
    http = _QueueHTTP(
        [
            _http_response(payload={"value": []}),
            _http_response(200),
            _http_response(payload={"value": [row]}),
        ]
    )
    transport = gvt.ArcherTransport(
        base_url="https://archer.example.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
        limits=gvt.VendorTransportLimits(timeout_seconds=8),
    )

    result = transport.send(request)

    assert [call["method"] for call in http.calls] == ["GET", "POST", "GET"]
    expected_path = "/rsaarcher/contentapi/Lightwork_GRC_Sync"
    assert all(urlsplit(call["url"]).path == expected_path for call in http.calls)
    create = http.calls[1]
    assert create["headers"]["Cookie"] == f"ArcherSessionCookie={_SECRET}"
    assert create["headers"]["X-Lightwork-Idempotency-Key"] == request.idempotency_key
    assert create["json_body"]["Lightwork_GRC_Sync_Id"] == 0
    assert create["json_body"]["Lightwork_Operation"] == operation
    assert create["json_body"]["Lightwork_Source_Kind"] == kind.value
    assert create["json_body"]["Lightwork_Source_Digest"] == request.source_digest
    assert json.loads(create["json_body"]["Lightwork_Payload_JSON"]) == request.payload
    assert set(create["json_body"]) == gvt.ARCHER_REQUIRED_FIELDS
    assert result.external_id == "1234"
    assert result.external_revision == f"lw-1-{_SOURCE_DIGEST[:16]}"
    assert urlsplit(result.external_url).query == ""


def test_archer_update_preflights_remote_lightwork_revision_and_recovers_repeat() -> None:
    prior_revision = f"lw-1-{'c' * 16}"
    request = _request(
        GRCSystem.ARCHER,
        SourceKind.FINDING,
        "archer.upsert_finding",
        revision=2,
        reference=ExternalReference("1234", prior_revision),
    )
    prior = _archer_row(
        request,
        idempotency_key="GRC-old",
        source_revision=1,
        digest="c" * 64,
    )
    current = _archer_row(request)
    http = _QueueHTTP(
        [
            _http_response(payload={"value": [prior]}),
            _http_response(200),
            _http_response(payload={"value": [current]}),
            _http_response(payload={"value": [current]}),
        ]
    )
    transport = gvt.ArcherTransport(
        base_url="https://archer.example.com/rsaarcher",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    first = transport.send(request)
    repeated = transport.send(request)

    assert first == repeated
    posts = [call for call in http.calls if call["method"] == "POST"]
    assert len(posts) == 1
    assert posts[0]["json_body"]["Lightwork_GRC_Sync_Id"] == 1234
    first_query = parse_qs(urlsplit(http.calls[0]["url"]).query)
    assert first_query["$filter"] == ["Lightwork_GRC_Sync_Id eq 1234"]


def test_archer_timeout_after_create_recovers_by_unique_idempotency_field() -> None:
    request = _request(
        GRCSystem.ARCHER,
        SourceKind.AI_INCIDENT,
        "archer.upsert_ai_incident",
    )
    remote: dict[str, object] | None = None
    posts = 0

    def handler(call: dict[str, Any]) -> gvt.VendorHTTPResponse:
        nonlocal posts, remote
        if call["method"] == "GET":
            return _http_response(payload={"value": [] if remote is None else [remote]})
        posts += 1
        remote = _archer_row(request)
        raise TimeoutError(f"lost Archer response with {_SECRET}")

    http = _HandlerHTTP(handler)
    transport = gvt.ArcherTransport(
        base_url="https://archer.example.com",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    with pytest.raises(GRCTransportFailure) as caught:
        transport.send(request)
    assert caught.value.category == "vendor_transport_timeout"
    assert _SECRET not in str(caught.value)
    recovered = transport.send(request)
    assert recovered.external_id == "1234"
    assert posts == 1


@pytest.mark.parametrize("vendor", ["servicenow", "archer"])
def test_unique_constraint_race_recovers_matching_remote_record(vendor: str) -> None:
    if vendor == "servicenow":
        request = _request(
            GRCSystem.SERVICENOW_IRM,
            SourceKind.FINDING,
            "servicenow_irm.upsert_issue",
        )
        http = _QueueHTTP(
            [
                _http_response(payload={"result": []}),
                _http_response(409),
                _http_response(payload={"result": [_sn_row(request)]}),
            ]
        )
        transport: Any = gvt.ServiceNowIRMTransport(
            base_url="https://tenant.service-now.com",
            http=http,
            secret_resolver=lambda _name: _SECRET,
        )
    else:
        request = _request(
            GRCSystem.ARCHER,
            SourceKind.FINDING,
            "archer.upsert_finding",
        )
        http = _QueueHTTP(
            [
                _http_response(payload={"value": []}),
                _http_response(409),
                _http_response(payload={"value": [_archer_row(request)]}),
            ]
        )
        transport = gvt.ArcherTransport(
            base_url="https://archer.example.com",
            http=http,
            secret_resolver=lambda _name: _SECRET,
        )

    result = transport.send(request)

    assert result.idempotency_key == request.idempotency_key
    assert [call["method"] for call in http.calls] == ["GET", "POST", "GET"]


def test_archer_conflicting_or_missing_remote_record_stops_before_write() -> None:
    request = _request(
        GRCSystem.ARCHER,
        SourceKind.FINDING,
        "archer.upsert_finding",
        revision=2,
        reference=ExternalReference("1234", "lw-1-deadbeefdeadbeef"),
    )
    conflicting = _archer_row(
        request,
        idempotency_key="GRC-other",
        source_revision=1,
        digest="c" * 64,
    )
    transport = gvt.ArcherTransport(
        base_url="https://archer.example.com",
        http=_QueueHTTP([_http_response(payload={"value": [conflicting]})]),
        secret_resolver=lambda _name: _SECRET,
    )
    with pytest.raises(GRCTransportConflict) as caught:
        transport.send(request)
    assert caught.value.category == "external_revision_conflict"

    missing_http = _QueueHTTP([_http_response(payload={"value": []})])
    missing = gvt.ArcherTransport(
        base_url="https://archer.example.com",
        http=missing_http,
        secret_resolver=lambda _name: _SECRET,
    )
    with pytest.raises(GRCTransportConflict) as caught:
        missing.send(request)
    assert caught.value.category == "external_record_missing"
    assert all(call["method"] == "GET" for call in missing_http.calls)


def test_duplicate_remote_idempotency_rows_fail_closed() -> None:
    request = _request(
        GRCSystem.ARCHER,
        SourceKind.FINDING,
        "archer.upsert_finding",
    )
    row = _archer_row(request)
    transport = gvt.ArcherTransport(
        base_url="https://archer.example.com",
        http=_QueueHTTP([_http_response(payload={"value": [row, row]})]),
        secret_resolver=lambda _name: _SECRET,
    )
    with pytest.raises(GRCTransportConflict) as caught:
        transport.send(request)
    assert caught.value.category == "external_idempotency_not_unique"


def test_secret_is_only_in_transient_header_never_body_link_or_error() -> None:
    request = _request(
        GRCSystem.ARCHER,
        SourceKind.FINDING,
        "archer.upsert_finding",
    )
    http = _QueueHTTP([RuntimeError(f"provider reflected Cookie={_SECRET}")])
    transport = gvt.ArcherTransport(
        base_url="https://archer.example.com",
        credential_secret_ref="MY_ARCHER_SESSION",
        http=http,
        secret_resolver=lambda _name: _SECRET,
    )

    with pytest.raises(GRCTransportFailure) as caught:
        transport.send(request)

    assert caught.value.category == "vendor_transport_exception"
    assert _SECRET not in str(caught.value)
    assert _SECRET not in repr(caught.value)
    assert _SECRET not in repr(transport)
    assert _SECRET not in json.dumps(http.calls[0]["json_body"])
    assert _SECRET in http.calls[0]["headers"]["Cookie"]


def test_default_http_path_uses_shared_ssrf_guard(monkeypatch) -> None:
    from maverick import enterprise
    from maverick.tools import _ssrf

    request = _request(
        GRCSystem.SERVICENOW_IRM,
        SourceKind.FINDING,
        "servicenow_irm.upsert_issue",
    )
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *_a, **_k: None)

    def blocked(_host: str, **_kwargs: bool) -> str:
        raise _ssrf.BlockedHost("resolved to metadata address")

    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", blocked)
    transport = gvt.ServiceNowIRMTransport(
        base_url="https://rebinding.example.com",
        secret_resolver=lambda _name: _SECRET,
    )

    with pytest.raises(GRCTransportFailure) as caught:
        transport.send(request)
    assert caught.value.category == "vendor_ssrf_blocked"
    assert caught.value.retryable is False


def test_required_vendor_fields_are_explicit_and_stable() -> None:
    assert {
        "u_lightwork_idempotency_key",
        "u_lightwork_payload_sha256",
        "u_lightwork_source_revision",
        "u_lightwork_source_digest",
        "u_lightwork_tenant_sha256",
    } == gvt.SERVICENOW_REQUIRED_FIELDS
    assert gvt.ARCHER_APPLICATION_ALIAS == "Lightwork_GRC_Sync"
    assert "Lightwork_Idempotency_Key" in gvt.ARCHER_REQUIRED_FIELDS
    assert "Lightwork_Payload_JSON" in gvt.ARCHER_REQUIRED_FIELDS
    assert "url" not in {field.lower() for field in gvt.ARCHER_REQUIRED_FIELDS}


def test_config_loader_uses_a_saved_key_only_when_the_server_has_none() -> None:
    section = {
        "base_url": "https://tenant.service-now.com",
        "credential": "saved-dashboard-key",  # pragma: allowlist secret
    }
    transport = gvt.transport_from_config(
        GRCSystem.SERVICENOW_IRM,
        config={"grc_outbound_sync": {"servicenow_irm": section}},
        environ={},
        http=_QueueHTTP([]),
        secret_resolver=lambda _name: None,
    )
    assert "saved-dashboard-key" not in repr(transport)
    assert transport._secret_resolver("SERVICENOW_TOKEN") == "saved-dashboard-key"
    server = gvt.transport_from_config(
        GRCSystem.SERVICENOW_IRM,
        config={"grc_outbound_sync": {"servicenow_irm": section}},
        environ={},
        http=_QueueHTTP([]),
        secret_resolver=lambda _name: "server-key",
    )
    assert server._secret_resolver("SERVICENOW_TOKEN") == "server-key"
    with pytest.raises(gvt.GRCVendorConfigError) as caught:
        gvt.transport_from_config(
            GRCSystem.SERVICENOW_IRM,
            config={"grc_outbound_sync": {"servicenow_irm": {**section, "credential": " "}}},
            environ={},
        )
    assert caught.value.category == "credential_invalid"
