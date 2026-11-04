from __future__ import annotations

import json
from dataclasses import replace

import pytest
from maverick.privacy_data_discovery import (
    EnrolledSource,
    PrivacyDataDiscoveryCoordinator,
    PrivacyDataDiscoveryStore,
    ScanLimits,
)
from maverick.privacy_data_discovery_adapters import (
    AWS_S3,
    AZURE_BLOB,
    ENTRA_ASSETS,
    GOOGLE_CLOUD_STORAGE,
    SERVICENOW_CMDB,
    SNOWFLAKE_METADATA,
    AwsS3DiscoveryAdapter,
    AzureBlobDiscoveryAdapter,
    DiscoveryAdapterConfigError,
    DiscoveryAdapterLimits,
    DiscoveryAdapterProtocolError,
    DiscoveryHTTPRequest,
    DiscoveryHTTPResponse,
    DiscoveryTransportError,
    EntraAssetDiscoveryAdapter,
    GoogleCloudStorageDiscoveryAdapter,
    PinnedDiscoveryHTTPTransport,
    ServiceNowCmdbDiscoveryAdapter,
    SnowflakeMetadataDiscoveryAdapter,
    build_stock_discovery_adapter_registry,
    credential_reference_present,
)


class ScriptedTransport:
    def __init__(self, *results):
        self.results = list(results)
        self.requests = []

    def request(self, request):
        self.requests.append(request)
        if not self.results:
            raise AssertionError("unexpected provider request")
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def response(status=200, body=b"{}", headers=None):
    return DiscoveryHTTPResponse(status, headers or {}, body)


def source(provider, kind, resource_ref, *, origin="https://provider.example"):
    return EnrolledSource(
        tenant_id="tenant-a",
        source_id="source-a",
        kind=kind,
        provider=provider,
        origin=origin,
        resource_ref=resource_ref,
        credential_env="DISCOVERY_CREDENTIAL",
        evidence_key_env="DISCOVERY_EVIDENCE_KEY",
        state="active",
        revision=1,
        enrolled_at=1.0,
        updated_at=1.0,
        integrity_sha256="a" * 64,
    )


def adapter_limits(**overrides):
    return replace(
        DiscoveryAdapterLimits(
            timeout_seconds=2,
            max_response_bytes=1024 * 1024,
            page_size=2,
            max_pages=4,
            max_attempts=2,
            max_polls=2,
        ),
        **overrides,
    )


def scan_limits(**overrides):
    return replace(
        ScanLimits(
            max_records=10,
            max_files=10,
            max_bytes=1024 * 1024,
            max_seconds=30,
            max_findings=100,
            max_fields_per_record=64,
            max_record_bytes=64 * 1024,
            max_document_bytes=64 * 1024,
        ),
        **overrides,
    )


def enabled_config(*providers):
    return {
        "privacy_automation": {
            "enable": True,
            "data_discovery": {
                "enable": True,
                "adapters": {
                    "enable": True,
                    "enabled_providers": list(providers),
                    "timeout_seconds": 2,
                    "max_response_bytes": 65536,
                    "page_size": 100,
                    "max_pages": 20,
                    "max_attempts": 2,
                    "max_polls": 3,
                },
            },
        }
    }


def test_registry_is_closed_and_explicitly_enabled() -> None:
    disabled = build_stock_discovery_adapter_registry({})
    assert disabled.enabled is False
    assert disabled.structured == {}
    assert disabled.unstructured == {}

    registry = build_stock_discovery_adapter_registry(
        enabled_config(AWS_S3, SERVICENOW_CMDB),
        transport=ScriptedTransport(),
        sleeper=lambda _seconds: None,
    )
    assert tuple(registry.structured) == (SERVICENOW_CMDB,)
    assert tuple(registry.unstructured) == (AWS_S3,)
    status = registry.status()
    assert status["credential_values_exposed"] is False
    assert status["live_provider_acceptance_verified"] is False
    assert all(item["writes_provider_data"] is False for item in status["descriptors"])

    with pytest.raises(DiscoveryAdapterConfigError):
        build_stock_discovery_adapter_registry(enabled_config("generic_http"))

    unknown = enabled_config(AWS_S3)
    unknown["privacy_automation"]["data_discovery"]["adapters"][  # type: ignore[index]
        "raw_secret"
    ] = "forbidden"
    with pytest.raises(DiscoveryAdapterConfigError, match="unknown key"):
        build_stock_discovery_adapter_registry(unknown)


def test_request_contract_rejects_cross_authority_and_secret_headers() -> None:
    with pytest.raises(DiscoveryAdapterConfigError):
        DiscoveryHTTPRequest(
            provider=AWS_S3,
            origin="https://provider.example/path",
            method="GET",
            path="/bucket",
            query=(),
            credential_env="DISCOVERY_CREDENTIAL",
            deadline=10,
            timeout_seconds=1,
            max_response_bytes=1024,
        )
    with pytest.raises(DiscoveryAdapterConfigError):
        DiscoveryHTTPRequest(
            provider=AWS_S3,
            origin="https://provider.example",
            method="GET",
            path="//evil.example/path",
            query=(),
            credential_env="DISCOVERY_CREDENTIAL",
            deadline=10,
            timeout_seconds=1,
            max_response_bytes=1024,
        )
    with pytest.raises(DiscoveryAdapterConfigError):
        DiscoveryHTTPRequest(
            provider=AWS_S3,
            origin="https://provider.example",
            method="GET",
            path="/bucket",
            query=(),
            credential_env="DISCOVERY_CREDENTIAL",
            deadline=10,
            timeout_seconds=1,
            max_response_bytes=1024,
            headers={"Authorization": "secret"},
        )


def test_credential_presence_checks_name_without_exposing_value(monkeypatch) -> None:
    monkeypatch.setenv("DISCOVERY_CREDENTIAL", "super-secret")
    assert credential_reference_present("DISCOVERY_CREDENTIAL") is True
    assert credential_reference_present("bad-name") is False


def test_production_transport_resolves_secret_only_at_transport_boundary() -> None:
    secret = "provider-bearer-token"
    resolved = []
    transport = PinnedDiscoveryHTTPTransport(
        credential_resolver=lambda name: resolved.append(name) or secret,
        clock=lambda: 1,
    )
    request = DiscoveryHTTPRequest(
        provider=GOOGLE_CLOUD_STORAGE,
        origin="https://storage.googleapis.com",
        method="GET",
        path="/storage/v1/b/customer-data/o",
        query=(),
        credential_env="DISCOVERY_CREDENTIAL",
        deadline=20,
        timeout_seconds=2,
        max_response_bytes=1_024,
    )
    assert resolved == []
    assert secret not in repr(request)
    assert secret not in repr(transport)

    headers = transport._headers(request)
    assert resolved == ["DISCOVERY_CREDENTIAL"]
    assert headers["Authorization"] == f"Bearer {secret}"


def test_adapter_rejects_expired_deadline_before_transport_io() -> None:
    transport = ScriptedTransport(response())
    adapter = GoogleCloudStorageDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(),
        clock=lambda: 21,
        sleeper=lambda _seconds: None,
    )
    with pytest.raises(DiscoveryTransportError, match="provider_deadline_exhausted"):
        list(
            adapter.iter_documents(
                source=source(
                    GOOGLE_CLOUD_STORAGE,
                    "unstructured",
                    "customer-data",
                ),
                credential_env="DISCOVERY_CREDENTIAL",
                limits=scan_limits(),
                deadline=20,
            )
        )
    assert transport.requests == []


def test_s3_lists_heads_and_reads_only_bounded_text() -> None:
    listing = b"""<?xml version="1.0"?>
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <IsTruncated>false</IsTruncated>
      <Contents><Key>folder%2Fpeople.csv</Key><Size>24</Size><ETag>"etag-1"</ETag></Contents>
    </ListBucketResult>"""
    raw = b"email\nalice@example.com\n"
    transport = ScriptedTransport(
        response(body=listing),
        response(headers={"content-type": "text/csv", "content-length": "24"}),
        response(body=raw, headers={"content-type": "text/csv"}),
    )
    adapter = AwsS3DiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    documents = list(
        adapter.iter_documents(
            source=source(AWS_S3, "unstructured", "customer-records"),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    )
    assert len(documents) == 1
    assert documents[0].content == raw
    assert "people" not in documents[0].document_ref
    assert [item.method for item in transport.requests] == ["GET", "HEAD", "GET"]
    assert all("super-secret" not in repr(item) for item in transport.requests)
    assert transport.requests[2].path.endswith("/folder/people.csv")


def test_azure_blob_contract_lists_and_reads_one_object() -> None:
    listing = b"""<EnumerationResults><Blobs><Blob>
      <Name>customers.json</Name><Properties>
      <Content-Length>25</Content-Length><Content-Type>application/json</Content-Type>
      <Etag>"etag-1"</Etag>
      </Properties></Blob></Blobs><NextMarker /></EnumerationResults>"""
    raw = b'{"email":"a@example.com"}'
    transport = ScriptedTransport(response(body=listing), response(body=raw))
    adapter = AzureBlobDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    documents = list(
        adapter.iter_documents(
            source=source(AZURE_BLOB, "unstructured", "customer-data"),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    )
    assert documents[0].media_type == "application/json"
    assert documents[0].content == raw
    assert transport.requests[0].query[0][0] in {"comp", "maxresults", "restype"}
    assert transport.requests[1].path == "/customer-data/customers.json"


def test_gcs_contract_uses_fixed_json_and_download_paths() -> None:
    listing = json.dumps(
        {
            "items": [
                {
                    "name": "folder/customer.txt",
                    "size": "19",
                    "contentType": "text/plain",
                    "generation": "123",
                }
            ]
        }
    ).encode()
    transport = ScriptedTransport(
        response(body=listing),
        response(body=b"bob@example.com\n"),
    )
    adapter = GoogleCloudStorageDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    documents = list(
        adapter.iter_documents(
            source=source(GOOGLE_CLOUD_STORAGE, "unstructured", "customer-data"),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    )
    assert len(documents) == 1
    assert transport.requests[0].path == "/storage/v1/b/customer-data/o"
    assert "%2F" in transport.requests[1].path
    assert dict(transport.requests[1].query) == {
        "alt": "media",
        "ifGenerationMatch": "123",
    }


def test_servicenow_cmdb_reader_paginates_fixed_table_and_fields() -> None:
    first = {"result": [{"sys_id": "1", "name": "Alice laptop"}]}
    second = {"result": [{"sys_id": "2", "ip_address": "203.0.113.9"}]}
    third = {"result": []}
    transport = ScriptedTransport(
        response(body=json.dumps(first).encode()),
        response(body=json.dumps(second).encode()),
        response(body=json.dumps(third).encode()),
    )
    adapter = ServiceNowCmdbDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(page_size=1),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    rows = list(
        adapter.iter_rows(
            source=source(SERVICENOW_CMDB, "structured", "cmdb_ci_computer"),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    )
    assert len(rows) == 2
    assert rows[0].fields == {"name": "Alice laptop"}
    assert all(
        request.path == "/api/now/table/cmdb_ci_computer"
        for request in transport.requests
    )
    assert all(
        "sysparm_fields" in {key for key, _value in request.query}
        for request in transport.requests
    )


def test_entra_reader_validates_next_link_and_reconstructs_request() -> None:
    selected = (
        "id,deviceId,displayName,accountEnabled,operatingSystem,"
        "operatingSystemVersion,approximateLastSignInDateTime,"
        "registrationDateTime,trustType"
    )
    first = {
        "value": [{"id": "device-1", "displayName": "Alice phone"}],
        "@odata.nextLink": (
            "https://graph.microsoft.com/v1.0/devices?"
            f"%24select={selected}&%24top=1&%24skiptoken=next-token"
        ),
    }
    second = {"value": [{"id": "device-2", "displayName": "Bob laptop"}]}
    transport = ScriptedTransport(
        response(body=json.dumps(first).encode()),
        response(body=json.dumps(second).encode()),
    )
    adapter = EntraAssetDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(page_size=1),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    rows = list(
        adapter.iter_rows(
            source=source(
                ENTRA_ASSETS,
                "structured",
                "devices",
                origin="https://graph.microsoft.com",
            ),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    )
    assert len(rows) == 2
    assert dict(transport.requests[1].query)["$skiptoken"] == "next-token"

    bad = ScriptedTransport(
        response(
            body=json.dumps(
                {
                    "value": [],
                    "@odata.nextLink": "https://evil.example/v1.0/devices?$skiptoken=x",
                }
            ).encode()
        )
    )
    with pytest.raises(DiscoveryAdapterProtocolError):
        list(
            EntraAssetDiscoveryAdapter(
                transport=bad,
                limits=adapter_limits(),
                clock=lambda: 1,
                sleeper=lambda _seconds: None,
            ).iter_rows(
                source=source(
                    ENTRA_ASSETS,
                    "structured",
                    "devices",
                    origin="https://graph.microsoft.com",
                ),
                credential_env="DISCOVERY_CREDENTIAL",
                limits=scan_limits(),
                deadline=20,
            )
        )


def test_snowflake_metadata_reader_uses_fixed_read_only_statement() -> None:
    payload = {
        "statementHandle": "123e4567-e89b-42d3-a456-426614174000",
        "resultSetMetaData": {"partitionInfo": [{}]},
        "data": [
            ["CUSTOMER_DB", "PUBLIC", "CUSTOMERS", "EMAIL", "TEXT", "email"]
        ],
    }
    transport = ScriptedTransport(response(body=json.dumps(payload).encode()))
    adapter = SnowflakeMetadataDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    rows = list(
        adapter.iter_rows(
            source=source(
                SNOWFLAKE_METADATA,
                "structured",
                "GOV_WH:CUSTOMER_DB:PUBLIC",
                origin="https://account.snowflakecomputing.com",
            ),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    )
    assert rows[0].fields["column_name"] == "EMAIL"
    request = transport.requests[0]
    assert request.method == "POST"
    assert request.path == "/api/v2/statements"
    assert dict(request.query)["retry"] == "true"
    body = json.loads(request.body)
    assert body["statement"].startswith("SELECT table_catalog")
    assert ";" not in body["statement"]
    assert "DISCOVERY_CREDENTIAL" not in body["statement"]


def test_retry_is_bounded_and_redirect_is_never_followed() -> None:
    listing = json.dumps({"items": []}).encode()
    transport = ScriptedTransport(response(503), response(body=listing))
    sleeps = []
    adapter = GoogleCloudStorageDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(max_attempts=2),
        clock=lambda: 1,
        sleeper=sleeps.append,
    )
    assert list(
        adapter.iter_documents(
            source=source(GOOGLE_CLOUD_STORAGE, "unstructured", "customer-data"),
            credential_env="DISCOVERY_CREDENTIAL",
            limits=scan_limits(),
            deadline=20,
        )
    ) == []
    assert len(transport.requests) == 2
    assert sleeps == [0.25]

    redirect = GoogleCloudStorageDiscoveryAdapter(
        transport=ScriptedTransport(response(302, headers={"location": "https://evil"})),
        limits=adapter_limits(max_attempts=1),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    with pytest.raises(DiscoveryTransportError, match="provider_redirect_rejected"):
        list(
            redirect.iter_documents(
                source=source(
                    GOOGLE_CLOUD_STORAGE,
                    "unstructured",
                    "customer-data",
                ),
                credential_env="DISCOVERY_CREDENTIAL",
                limits=scan_limits(),
                deadline=20,
            )
        )


def test_pagination_bound_fails_instead_of_claiming_completeness() -> None:
    payload = {"items": [], "nextPageToken": "again"}
    adapter = GoogleCloudStorageDiscoveryAdapter(
        transport=ScriptedTransport(response(body=json.dumps(payload).encode())),
        limits=adapter_limits(max_pages=1),
        clock=lambda: 1,
        sleeper=lambda _seconds: None,
    )
    with pytest.raises(
        DiscoveryAdapterProtocolError,
        match="provider_pagination_bound_exhausted",
    ):
        list(
            adapter.iter_documents(
                source=source(
                    GOOGLE_CLOUD_STORAGE,
                    "unstructured",
                    "customer-data",
                ),
                credential_env="DISCOVERY_CREDENTIAL",
                limits=scan_limits(),
                deadline=20,
            )
        )


def test_stock_reader_runs_through_discovery_coordinator_without_raw_persistence(
    tmp_path,
) -> None:
    raw = b'{"email":"private@example.com"}'
    listing = json.dumps(
        {
            "items": [
                {
                    "name": "private.json",
                    "size": str(len(raw)),
                    "contentType": "application/json",
                    "generation": "7",
                }
            ]
        }
    ).encode()
    transport = ScriptedTransport(response(body=listing), response(body=raw))
    adapter = GoogleCloudStorageDiscoveryAdapter(
        transport=transport,
        limits=adapter_limits(),
        clock=lambda: 1000,
        sleeper=lambda _seconds: None,
    )
    store = PrivacyDataDiscoveryStore(
        tmp_path / "discovery.sqlite3",
        config_gate=lambda: None,
        clock=lambda: 1000,
        evidence_key_resolver=lambda _name: b"e" * 32,
    )
    store.enroll_source(
        "tenant-a",
        source_id="gcs-source",
        kind="unstructured",
        provider=GOOGLE_CLOUD_STORAGE,
        origin="https://storage.googleapis.com",
        resource_ref="customer-data",
        credential_env="DISCOVERY_CREDENTIAL",
        evidence_key_env="DISCOVERY_EVIDENCE_KEY",
        actor_ref="operator",
        idempotency_key="enroll-gcs",
    )
    store.enqueue_scan(
        "tenant-a",
        "gcs-source",
        limits=scan_limits(),
        max_attempts=2,
        retention_seconds=3600,
        actor_ref="operator",
        idempotency_key="scan-gcs",
    )
    job = store.claim_jobs("tenant-a", worker_id="worker", lease_seconds=60)[0]
    report = PrivacyDataDiscoveryCoordinator(
        store,
        unstructured_sources={GOOGLE_CLOUD_STORAGE: adapter},
        clock=lambda: 1000,
        credential_ref_present=lambda _name: True,
    ).execute_job(job, worker_id="worker")
    assert report.files_seen == 1
    assert report.findings_count >= 1
    assert report.completeness == "complete_within_declared_bounds"
    assert raw not in store.path.read_bytes()
