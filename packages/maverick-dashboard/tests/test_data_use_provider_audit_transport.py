"""Controlled provider-shaped tests for the shipped audit-log transport."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest
from maverick.data_use_provider_adapters import (
    DataUseProviderProtocolError,
    DataUseProviderRequestNotSent,
    DataUseProviderTransportAmbiguous,
    ProviderBindingStore,
    ProviderHttpResponse,
)
from maverick.data_use_provider_audit import (
    AUDIT_BATCH_SCHEMA,
    DataUseProviderAuditConfigError,
    DataUseProviderAuditPermanent,
    DataUseProviderAuditRetryable,
    ProviderAuditAcceptedWatermark,
    ProviderAuditCredentialLease,
    ProviderAuditCursor,
    ProviderAuditReadRequest,
    ProviderAuditStatementBinding,
    accepted_watermark_sha256,
)
from maverick.paths import canonical_tenant_id
from maverick_dashboard.data_use_provider_audit_transport import (
    NativeProviderAuditTransport,
    build_operator_watermark_authority,
)
from maverick_dashboard.data_use_provider_runtime import PinnedProviderHttpTransport

TENANT = "Acme Café"
AUTHORITY = hashlib.sha256(b"credential-authority").hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(provider: str, *, snowflake_watermark: bool = False) -> dict[str, Any]:
    audit: dict[str, Any] = {
        "enable": True,
        "audit_window_seconds": 14_400,
        "cursor_overlap_seconds": 300,
        "max_pages_per_read": 20,
    }
    if snowflake_watermark:
        audit["snowflake_latency_watermark_seconds"] = 10_800
    return {
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True},
            "enforcement": {"enable": True, "max_attempts": 3},
            "provider_audit": audit,
            provider: {
                "enable": True,
                "origin": (
                    "https://acct1.snowflakecomputing.com"
                    if provider == "snowflake"
                    else "https://adb-123.cloud.databricks.com"
                ),
                "credential_secret_ref": f"${provider.upper()}_CONTROL_TOKEN",
                "credential_revision": 1,
                "timeout_seconds": 5,
                "max_response_bytes": 65_536,
            },
        }
    }


def _store(tmp_path: Path, provider: str) -> tuple[ProviderBindingStore, dict[str, Any]]:
    store = ProviderBindingStore(tmp_path / f"{provider}-bindings.sqlite3", clock=lambda: 100.0)
    common = {
        "asset_id": "customers",
        "schema": "PUBLIC" if provider == "snowflake" else "default",
        "table": "CUSTOMERS" if provider == "snowflake" else "customers",
        "principal": "ANALYST_ROLE" if provider == "snowflake" else "analysts@example.com",
        "compute_id": "GOVERNANCE_WH" if provider == "snowflake" else "warehouse-1",
        "field_map": {"email": "EMAIL" if provider == "snowflake" else "email"},
        "mask_bindings": {
            "hash_sha256": (
                "GOV.POLICY.MASK_SHA256"
                if provider == "snowflake"
                else "governance.policy.mask_sha256"
            )
        },
        "row_filter_bindings": {},
        "catalog_snapshot_sha256": _text_sha(f"{provider}-catalog"),
        "field_inventory_complete": True,
        "credential_key_id": "credential-key-1",
        "credential_revision": 1,
        "credential_authority_sha256": AUTHORITY,
        "expected_revision": 0,
        "idempotency_key": f"enroll-{provider}",
    }
    if provider == "snowflake":
        binding = store.enroll_snowflake(
            TENANT,
            "native-customers",
            origin="https://acct1.snowflakecomputing.com",
            account_or_workspace_id="acct1",
            catalog="APP_DB",
            state_anchor="GOV.TAGS.DATA_USE_STATE",
            **common,
        )
    else:
        binding = store.enroll_databricks(
            TENANT,
            "native-customers",
            origin="https://adb-123.cloud.databricks.com",
            account_or_workspace_id="adb-123",
            catalog="main",
            **common,
        )
    return store, binding


def _object_sha(binding: dict[str, Any]) -> str:
    return _sha(
        {
            key: binding[key]
            for key in (
                "provider_id",
                "account_or_workspace_id",
                "catalog",
                "schema_name",
                "table",
            )
        }
    )


def _request_for_statements(
    binding: dict[str, Any],
    *,
    raw_statement_ids: tuple[str, ...],
    cursor: ProviderAuditCursor | None = None,
    event_limit: int = 100,
    audit_deadline: float = 1_100.0,
) -> ProviderAuditReadRequest:
    selected_cursor = cursor or ProviderAuditCursor(900.0, "0" * 64)
    object_sha = _object_sha(binding)
    control = _text_sha("mask-control")
    statements = tuple(
        ProviderAuditStatementBinding(
            provider_statement_sha256=_text_sha(raw_statement_id),
            change_kind="masking_policy",
            control_sha256=control,
            object_sha256=object_sha,
        )
        for raw_statement_id in raw_statement_ids
    )
    body = {
        "schema": AUDIT_BATCH_SCHEMA,
        "provider_id": binding["provider_id"],
        "binding_id": binding["binding_id"],
        "binding_revision": binding["revision"],
        "binding_sha256": binding["binding_sha256"],
        "operation_idempotency_sha256": _text_sha("operation-idem"),
        "correlation_sha256": _text_sha("correlation"),
        "object_sha256": object_sha,
        "statement_bindings": [asdict(statement) for statement in statements],
        "cursor": asdict(selected_cursor),
        "audit_deadline": audit_deadline,
        "event_limit": event_limit,
    }
    return ProviderAuditReadRequest(
        schema=AUDIT_BATCH_SCHEMA,
        provider_id=binding["provider_id"],
        binding_id=binding["binding_id"],
        binding_revision=binding["revision"],
        binding_sha256=binding["binding_sha256"],
        operation_idempotency_sha256=body["operation_idempotency_sha256"],
        correlation_sha256=body["correlation_sha256"],
        object_sha256=object_sha,
        statement_bindings=statements,
        cursor=selected_cursor,
        audit_deadline=audit_deadline,
        event_limit=event_limit,
        request_sha256=_sha(body),
    )


def _request(binding: dict[str, Any], *, raw_statement_id: str) -> ProviderAuditReadRequest:
    return _request_for_statements(binding, raw_statement_ids=(raw_statement_id,))


def _accepted_watermark(
    binding: dict[str, Any], *, covered_until: float, expires_at: float = 20_000.0
) -> ProviderAuditAcceptedWatermark:
    candidate = ProviderAuditAcceptedWatermark(
        tenant_sha256=_text_sha(canonical_tenant_id(TENANT)),
        watermark_kind=(
            "snowflake_configured_latency"
            if binding["provider_id"] == "snowflake"
            else "databricks_accepted_delivery"
        ),
        provider_id=binding["provider_id"],
        binding_id=binding["binding_id"],
        binding_revision=binding["revision"],
        binding_sha256=binding["binding_sha256"],
        covered_until=covered_until,
        authority_sha256="0" * 64,
        expires_at=expires_at,
        revoked=False,
    )
    return replace(candidate, authority_sha256=accepted_watermark_sha256(candidate))


def _lease(binding: dict[str, Any]) -> ProviderAuditCredentialLease:
    return ProviderAuditCredentialLease(
        authorization="Bearer raw-provider-secret",
        credential_key_id_sha256=binding["credential_key_id_sha256"],
        credential_revision=binding["credential_revision"],
        credential_authority_sha256=binding["credential_authority_sha256"],
        expires_at=20_000.0,
    )


class MockHttp:
    def __init__(self, responses: list[ProviderHttpResponse | BaseException]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def _response(body: dict[str, Any], status: int = 200) -> ProviderHttpResponse:
    return ProviderHttpResponse(
        status,
        {"content-type": "application/json"},
        json.dumps(body).encode(),
    )


def _databricks_manifest(
    *, expected_columns: int, total_rows: int, total_chunks: int = 1
) -> dict[str, Any]:
    return {
        "format": "JSON_ARRAY",
        "schema": {
            "column_count": expected_columns,
            "columns": [{"name": f"column_{index}"} for index in range(expected_columns)],
        },
        "total_row_count": total_rows,
        "total_chunk_count": total_chunks,
        "truncated": False,
    }


def _snowflake_metadata(*partition_counts: int) -> dict[str, Any]:
    return {
        "format": "jsonv2",
        "numRows": str(sum(partition_counts)),
        "rowType": [{"name": f"column_{index}"} for index in range(5)],
        "partitionInfo": [{"rowCount": str(row_count)} for row_count in partition_counts],
    }


def test_snowflake_retries_same_request_and_reads_every_partition_digest_only(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tag = (
        "lw2:"
        + request.correlation_sha256
        + ":masking_policy:"
        + request.statement_bindings[0].control_sha256
        + ":"
        + request.object_sha256
        + ":-"
    )
    row = ["mutation-stmt-1", "1000.000000", tag, "SUCCESS", "true"]
    http = MockHttp(
        [
            _response({}, 503),
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [row],
                    "resultSetMetaData": _snowflake_metadata(1, 1),
                }
            ),
            _response({"statementHandle": "reader-stmt-1", "data": [row]}),
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 13_000.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 13_000.0,
        sleeper=lambda _delay: None,
    )

    batch = transport.read(request, _lease(binding))

    assert len(batch.events) == 1
    assert batch.events[0].query_id_sha256 == _text_sha("mutation-stmt-1")
    assert batch.events[0].object_change_corroborated is True
    assert batch.complete is True
    assert batch.covered_until == request.audit_deadline
    assert batch.watermark is not None
    posts = [call for call in http.calls if call["method"] == "POST"]
    assert len(posts) == 2
    assert posts[1]["url"] == f"{posts[0]['url']}&retry=true"
    assert http.calls[-1]["url"].endswith("/reader-stmt-1?partition=1")
    serialized = json.dumps(asdict(batch), sort_keys=True)
    for raw in (
        "mutation-stmt-1",
        "reader-stmt-1",
        "raw-provider-secret",
        "acct1.snowflakecomputing.com",
        "SELECT q.QUERY_ID",
    ):
        assert raw not in serialized


def test_snowflake_max_http_timeout_fits_built_in_credential_lease(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    config["data_use_governance"]["snowflake"]["timeout_seconds"] = 60
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tag = (
        "lw2:"
        + request.correlation_sha256
        + ":masking_policy:"
        + request.statement_bindings[0].control_sha256
        + ":"
        + request.object_sha256
        + ":-"
    )
    http = MockHttp(
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [["mutation-stmt-1", "1000.000000", tag, "SUCCESS", "true"]],
                    "resultSetMetaData": _snowflake_metadata(1),
                }
            )
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 13_000.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 13_000.0,
    )
    built_in_ttl = replace(_lease(binding), expires_at=13_065.0)

    batch = transport.read(request, built_in_ttl)

    assert batch.complete is True
    assert http.calls[0]["timeout"] == 60


def test_databricks_uses_query_history_chunks_and_access_audit_only_supplementally(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tags = {
        "lw_corr": request.correlation_sha256,
        "lw_kind": "masking_policy",
        "lw_ctrl": request.statement_bindings[0].control_sha256,
        "lw_obj": request.object_sha256,
        "lw_state": "-",
    }
    row = ["mutation-stmt-1", "1000.000000", json.dumps(tags), "FINISHED"]
    http = MockHttp(
        [
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "RUNNING"},
                },
                202,
            ),
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(
                        expected_columns=4, total_rows=2, total_chunks=2
                    ),
                    "result": {
                        "chunk_index": 0,
                        "row_offset": 0,
                        "row_count": 1,
                        "data_array": [row],
                        "next_chunk_index": 1,
                    },
                }
            ),
            _response(
                {
                    "chunk_index": 1,
                    "row_offset": 1,
                    "row_count": 1,
                    "data_array": [row],
                }
            ),
            _response(
                {
                    "statement_id": "reader-access-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(expected_columns=1, total_rows=1),
                    "result": {
                        "chunk_index": 0,
                        "row_offset": 0,
                        "row_count": 1,
                        "data_array": [["1"]],
                    },
                }
            ),
        ]
    )
    delays: list[float] = []
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        databricks_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered
        ),
        clock=lambda: 1_200.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 1_200.0,
        sleeper=delays.append,
    )

    batch = transport.read(request, _lease(binding))

    assert len(batch.events) == 1
    assert batch.events[0].statement_id_sha256 == _text_sha("mutation-stmt-1")
    assert batch.complete is True
    assert batch.watermark is not None
    assert delays == [0.25]
    assert any("/result/chunks/1" in call["url"] for call in http.calls)
    submitted = [json.loads(call["body"]) for call in http.calls if call["method"] == "POST"]
    assert len(submitted) == 2
    assert "system.query.history" in submitted[0]["statement"]
    assert "system.access.audit" in submitted[1]["statement"]
    assert all(item["wait_timeout"] == "0s" for item in submitted)
    assert all(item["format"] == "JSON_ARRAY" for item in submitted)
    assert all(item["disposition"] == "INLINE" for item in submitted)


def test_construction_and_immature_noop_open_no_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    calls = 0
    original = store.get_binding

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "get_binding", counted)
    now = [1_000.0]
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tag = (
        "lw2:"
        + request.correlation_sha256
        + ":masking_policy:"
        + request.statement_bindings[0].control_sha256
        + ":"
        + request.object_sha256
        + ":-"
    )
    http = MockHttp(
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [["mutation-stmt-1", "1000.125000", tag, "SUCCESS", "true"]],
                    "resultSetMetaData": _snowflake_metadata(1),
                }
            )
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: now[0],
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: now[0],
    )
    assert calls == 0

    batch = transport.read(request, _lease(binding))

    assert batch.events == ()
    assert batch.complete is False
    assert http.calls == []
    assert calls >= 1

    now[0] = 13_000.0
    recovered = transport.read(request, _lease(binding))

    assert recovered.complete is True
    assert recovered.events[0].occurred_at == 1_000.125
    assert len(http.calls) == 1


def test_malformed_partition_and_oversized_response_fail_closed(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 13_000.0,
    )
    malformed = MockHttp(
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [],
                    "resultSetMetaData": _snowflake_metadata(*([0] * 21)),
                }
            )
        ]
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=malformed,
        clock=lambda: 13_000.0,
    )
    with pytest.raises(DataUseProviderAuditPermanent, match="provider_partition_invalid"):
        transport.read(request, _lease(binding))

    oversized = MockHttp([ProviderHttpResponse(200, {}, b"{" + b"x" * 70_000 + b"}")])
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=oversized,
        clock=lambda: 13_000.0,
    )
    with pytest.raises(DataUseProviderAuditPermanent, match="provider_response_oversized"):
        transport.read(request, _lease(binding))


def test_snowflake_partition_metadata_and_page_counts_fail_closed(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tag = (
        "lw2:"
        + request.correlation_sha256
        + ":masking_policy:"
        + request.statement_bindings[0].control_sha256
        + ":"
        + request.object_sha256
        + ":-"
    )
    row = ["mutation-stmt-1", "1000.000000", tag, "SUCCESS", "true"]
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 13_000.0,
    )
    cases = [
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [],
                    "resultSetMetaData": _snowflake_metadata(0, 1),
                }
            ),
            _response({"statementHandle": "reader-stmt-1"}),
        ],
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [row],
                    "resultSetMetaData": {
                        **_snowflake_metadata(1),
                        "numRows": "2",
                    },
                }
            )
        ],
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [row],
                    "resultSetMetaData": _snowflake_metadata(2),
                }
            )
        ],
    ]

    for responses in cases:
        transport = NativeProviderAuditTransport(
            tenant_id=TENANT,
            binding_store=store,
            config=config,
            watermark_authority_resolver=operator.resolve,
            http_transport=MockHttp(responses),
            clock=lambda: 13_000.0,
        )
        with pytest.raises(DataUseProviderAuditPermanent, match="provider_partition_invalid"):
            transport.read(request, _lease(binding))


def test_low_level_pinned_transport_refuses_private_override_and_invalid_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PinnedProviderHttpTransport()
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    with pytest.raises(DataUseProviderRequestNotSent, match="private-fetch override"):
        transport.request(
            "GET",
            "https://acct1.snowflakecomputing.com/api/v2/statements/a",
            headers={},
            body=None,
            timeout=5,
            max_response_bytes=4096,
            allow_redirects=False,
        )
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE")
    with pytest.raises(DataUseProviderProtocolError, match="bounds"):
        transport.request(
            "GET",
            "https://acct1.snowflakecomputing.com/api/v2/statements/a",
            headers={},
            body=None,
            timeout=0,
            max_response_bytes=4096,
            allow_redirects=False,
        )


def test_fractional_same_timestamp_page_advances_by_provider_reference_digest(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    raw_ids = tuple(f"mutation-stmt-{index:03d}" for index in range(101))
    first_request = _request_for_statements(
        binding,
        raw_statement_ids=raw_ids,
        event_limit=100,
    )
    tag = (
        "lw2:"
        + first_request.correlation_sha256
        + ":masking_policy:"
        + first_request.statement_bindings[0].control_sha256
        + ":"
        + first_request.object_sha256
        + ":-"
    )
    ordered_ids = sorted(raw_ids, key=_text_sha)
    rows = [[raw_id, "1000.123456", tag, "SUCCESS", "true"] for raw_id in ordered_ids]
    http = MockHttp(
        [
            _response(
                {
                    "statementHandle": "reader-page-1",
                    "data": rows,
                    "resultSetMetaData": _snowflake_metadata(101),
                }
            ),
            _response(
                {
                    "statementHandle": "reader-page-2",
                    "data": [rows[-1]],
                    "resultSetMetaData": _snowflake_metadata(1),
                }
            ),
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 13_000.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 13_000.0,
    )

    first = transport.read(first_request, _lease(binding))
    second_request = _request_for_statements(
        binding,
        raw_statement_ids=raw_ids,
        cursor=first.next_cursor,
        event_limit=100,
    )
    second = transport.read(second_request, _lease(binding))

    assert len(first.events) == 100
    assert first.complete is False
    assert first.watermark is None
    assert first.next_cursor.occurred_at == 1_000.123456
    assert first.next_cursor.event_id_sha256 == _text_sha(ordered_ids[-2])
    assert tuple(event.event_id_sha256 for event in second.events) == (_text_sha(ordered_ids[-1]),)
    assert second.complete is True
    statements = [
        json.loads(call["body"])["statement"] for call in http.calls if call["method"] == "POST"
    ]
    assert "EPOCH_MICROSECOND" in statements[0]
    assert "LIMIT 101" in statements[0]
    assert str(round(first.next_cursor.occurred_at * 1_000_000)) in statements[1]
    assert first.next_cursor.event_id_sha256 in statements[1]


def test_watermark_overcoverage_and_origin_drift_fail_before_network(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    http = MockHttp([])
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered + 1
        ),
        http_transport=http,
        clock=lambda: 13_000.0,
    )

    overcovered = transport.read(request, object())  # type: ignore[arg-type]

    assert overcovered.complete is False
    assert overcovered.events == ()
    assert http.calls == []

    config["data_use_governance"]["snowflake"]["origin"] = "https://acct2.snowflakecomputing.com"
    with pytest.raises(DataUseProviderAuditPermanent, match="provider_binding_changed"):
        transport.read(request, _lease(binding))
    assert http.calls == []


def test_non_ascii_configured_origin_is_origin_drift_not_a_crash(tmp_path: Path) -> None:
    """The origin check admits any hostname under the provider suffix, so a
    hand-edited non-ASCII origin must read as drift like any other change."""
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    http = MockHttp([])
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered + 1
        ),
        http_transport=http,
        clock=lambda: 13_000.0,
    )
    config["data_use_governance"]["snowflake"]["origin"] = "https://accté.snowflakecomputing.com"
    with pytest.raises(DataUseProviderAuditPermanent, match="provider_binding_changed"):
        transport.read(request, _lease(binding))
    assert http.calls == []


def test_transport_rechecks_mutated_audit_gate_before_network(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    http = MockHttp([])
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 13_000.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 13_000.0,
    )
    config["data_use_governance"]["provider_audit"]["enable"] = False

    with pytest.raises(DataUseProviderAuditConfigError, match="disabled"):
        transport.read(
            _request(binding, raw_statement_id="mutation-stmt-1"),
            object(),  # type: ignore[arg-type]
        )

    assert http.calls == []


def test_snowflake_watermark_remains_recoverable_through_retention(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    config["data_use_governance"]["provider_audit"]["retention_seconds"] = 86_400
    covered = 1_100.0
    now = [covered + 10_800 + 7_200]
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: now[0],
    )

    delayed = operator.resolve("snowflake", binding["binding_id"], covered)

    assert delayed is not None
    assert delayed.expires_at == covered + 86_400
    now[0] = covered + 86_400 + 1
    assert operator.resolve("snowflake", binding["binding_id"], covered) is None


def test_snowflake_refuses_lookback_beyond_source_retention(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    config["data_use_governance"]["provider_audit"]["retention_seconds"] = 63_072_000
    now = 31_536_000 + 2_000.0
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: now,
    )
    http = MockHttp([])
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: now,
    )

    batch = transport.read(
        _request(binding, raw_statement_id="mutation-stmt-1"),
        object(),  # type: ignore[arg-type]
    )

    assert operator.resolve("snowflake", binding["binding_id"], 1_100.0) is None
    assert batch.events == ()
    assert batch.complete is False
    assert http.calls == []


def test_watermark_is_rechecked_after_provider_read(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "snowflake")
    config = _config("snowflake", snowflake_watermark=True)
    config["data_use_governance"]["provider_audit"]["retention_seconds"] = 12_000
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tag = (
        "lw2:"
        + request.correlation_sha256
        + ":masking_policy:"
        + request.statement_bindings[0].control_sha256
        + ":"
        + request.object_sha256
        + ":-"
    )
    now = [13_000.0]

    class AdvancingHttp(MockHttp):
        def request(self, method, url, **kwargs):
            response = super().request(method, url, **kwargs)
            now[0] = 13_200.0
            return response

    http = AdvancingHttp(
        [
            _response(
                {
                    "statementHandle": "reader-stmt-1",
                    "data": [["mutation-stmt-1", "1000.000000", tag, "SUCCESS", "true"]],
                    "resultSetMetaData": _snowflake_metadata(1),
                }
            )
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: now[0],
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: now[0],
    )

    batch = transport.read(request, _lease(binding))

    assert len(batch.events) == 1
    assert batch.complete is False
    assert batch.watermark is None


def test_databricks_without_accepted_watermark_reads_nothing_and_needs_no_lease(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    http = MockHttp([])
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        clock=lambda: 1_200.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 1_200.0,
    )

    batch = transport.read(request, object())  # type: ignore[arg-type]

    assert batch.complete is False
    assert batch.events == ()
    assert http.calls == []


@pytest.mark.parametrize(
    ("timeout", "accepted"),
    [(1, False), (4, False), (5, True), (50, True), (51, False), (60, False)],
)
def test_databricks_http_timeout_is_independently_bounded(
    tmp_path: Path,
    timeout: int,
    accepted: bool,
) -> None:
    store, _binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    config["data_use_governance"]["databricks"]["timeout_seconds"] = timeout
    kwargs = {
        "tenant_id": TENANT,
        "binding_store": store,
        "config": config,
        "watermark_authority_resolver": lambda *_args: None,
        "http_transport": MockHttp([]),
    }

    if accepted:
        assert isinstance(NativeProviderAuditTransport(**kwargs), NativeProviderAuditTransport)
    else:
        with pytest.raises(DataUseProviderAuditConfigError, match="timeout"):
            NativeProviderAuditTransport(**kwargs)


@pytest.mark.parametrize(
    ("result_patch", "manifest_patch", "extra_pages", "error_code"),
    [
        ({"next_chunk_index": None}, {"total_chunk_count": 2}, [], "provider_chunk_invalid"),
        (
            {"external_links": [{"external_link": "https://evil.example/result"}]},
            {},
            [],
            "provider_response_malformed",
        ),
        ({}, {"truncated": True}, [], "provider_manifest_invalid"),
        (
            {},
            {"schema": {"column_count": 3, "columns": [{}, {}, {}]}},
            [],
            "provider_manifest_invalid",
        ),
        ({"next_chunk_index": 2}, {"total_chunk_count": 2}, [], "provider_chunk_invalid"),
        (
            {"next_chunk_index": 1},
            {"total_chunk_count": 2, "total_row_count": 2},
            [
                {
                    "chunk_index": 1,
                    "row_offset": 1,
                    "row_count": 1,
                    "data_array": [["unused", "1000", "{}", "FINISHED"]],
                    "next_chunk_index": 1,
                }
            ],
            "provider_manifest_invalid",
        ),
    ],
)
def test_databricks_manifest_and_chunk_ambiguity_fail_closed(
    tmp_path: Path,
    result_patch: dict[str, Any],
    manifest_patch: dict[str, Any],
    extra_pages: list[dict[str, Any]],
    error_code: str,
) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    tags = {
        "lw_corr": request.correlation_sha256,
        "lw_kind": "masking_policy",
        "lw_ctrl": request.statement_bindings[0].control_sha256,
        "lw_obj": request.object_sha256,
        "lw_state": "-",
    }
    row = ["mutation-stmt-1", "1000.000000", json.dumps(tags), "FINISHED"]
    result = {
        "chunk_index": 0,
        "row_offset": 0,
        "row_count": 1,
        "data_array": [row],
        **result_patch,
    }
    manifest = {
        **_databricks_manifest(expected_columns=4, total_rows=1),
        **manifest_patch,
    }
    http = MockHttp(
        [
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": manifest,
                    "result": result,
                }
            ),
            *[_response(page) for page in extra_pages],
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        databricks_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered
        ),
        clock=lambda: 1_200.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 1_200.0,
    )

    with pytest.raises(DataUseProviderAuditPermanent, match=error_code):
        transport.read(request, _lease(binding))


def test_databricks_fractional_end_bound_rejects_tail_event(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request_for_statements(
        binding,
        raw_statement_ids=("mutation-stmt-1",),
        audit_deadline=1_100.25,
    )
    tags = {
        "lw_corr": request.correlation_sha256,
        "lw_kind": "masking_policy",
        "lw_ctrl": request.statement_bindings[0].control_sha256,
        "lw_obj": request.object_sha256,
        "lw_state": "-",
    }
    row = ["mutation-stmt-1", "1100.500000", json.dumps(tags), "FINISHED"]
    http = MockHttp(
        [
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(expected_columns=4, total_rows=1),
                    "result": {
                        "chunk_index": 0,
                        "row_offset": 0,
                        "row_count": 1,
                        "data_array": [row],
                    },
                }
            ),
            _response(
                {
                    "statement_id": "reader-access-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(expected_columns=1, total_rows=1),
                    "result": {
                        "chunk_index": 0,
                        "row_offset": 0,
                        "row_count": 1,
                        "data_array": [["0"]],
                    },
                }
            ),
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        databricks_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered
        ),
        clock=lambda: 1_200.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 1_200.0,
    )

    with pytest.raises(
        DataUseProviderAuditPermanent,
        match="provider_event_outside_accepted_window",
    ):
        transport.read(request, _lease(binding))
    submitted = json.loads(http.calls[0]["body"])["statement"]
    assert "timestamp_micros(1100250000)" in submitted


def test_databricks_accepts_exact_zero_row_manifest_shape(tmp_path: Path) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    http = MockHttp(
        [
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(
                        expected_columns=4,
                        total_rows=0,
                        total_chunks=0,
                    ),
                    "result": {},
                }
            ),
            _response(
                {
                    "statement_id": "reader-access-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(expected_columns=1, total_rows=1),
                    "result": {
                        "chunk_index": 0,
                        "row_offset": 0,
                        "row_count": 1,
                        "data_array": [["0"]],
                    },
                }
            ),
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        databricks_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered
        ),
        clock=lambda: 1_200.0,
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: 1_200.0,
    )

    batch = transport.read(request, _lease(binding))

    assert batch.events == ()
    assert batch.complete is True
    assert batch.watermark is not None


def test_databricks_renews_expiring_credential_between_async_polls(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    now = [1_200.0]

    class AdvancingHttp(MockHttp):
        def request(self, method, url, **kwargs):
            response = super().request(method, url, **kwargs)
            if len(self.calls) == 1:
                now[0] = 1_261.0
            return response

    http = AdvancingHttp(
        [
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "RUNNING"},
                },
                202,
            ),
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(
                        expected_columns=4,
                        total_rows=0,
                        total_chunks=0,
                    ),
                    "result": {},
                }
            ),
            _response(
                {
                    "statement_id": "reader-access-1",
                    "status": {"state": "SUCCEEDED"},
                    "manifest": _databricks_manifest(expected_columns=1, total_rows=1),
                    "result": {
                        "chunk_index": 0,
                        "row_offset": 0,
                        "row_count": 1,
                        "data_array": [["0"]],
                    },
                }
            ),
        ]
    )
    renewals: list[dict[str, str]] = []

    def renew(**scope):
        renewals.append(scope)
        return replace(
            _lease(binding),
            authorization="Bearer renewed-provider-secret",
            expires_at=1_400.0,
        )

    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        databricks_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered
        ),
        clock=lambda: now[0],
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        credential_lease_resolver=renew,
        http_transport=http,
        clock=lambda: now[0],
        sleeper=lambda _delay: None,
    )
    initial = replace(_lease(binding), expires_at=1_260.0)

    batch = transport.read_with_deadline(
        request,
        initial,
        deadline=1_350.0,
    )

    assert batch.complete is True
    assert len(renewals) == 2
    assert http.calls[0]["headers"]["Authorization"] == "Bearer raw-provider-secret"
    assert all(
        call["headers"]["Authorization"] == "Bearer renewed-provider-secret"
        for call in http.calls[1:]
    )


def test_claim_deadline_clips_http_timeout_and_aborts_before_poll(
    tmp_path: Path,
) -> None:
    store, binding = _store(tmp_path, "databricks")
    config = _config("databricks")
    request = _request(binding, raw_statement_id="mutation-stmt-1")
    now = [1_200.0]

    class DeadlineHttp(MockHttp):
        def request(self, method, url, **kwargs):
            response = super().request(method, url, **kwargs)
            now[0] = 1_200.8
            return response

    http = DeadlineHttp(
        [
            _response(
                {
                    "statement_id": "reader-query-1",
                    "status": {"state": "RUNNING"},
                },
                202,
            )
        ]
    )
    operator = build_operator_watermark_authority(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        databricks_resolver=lambda _provider, _binding, covered: _accepted_watermark(
            binding, covered_until=covered
        ),
        clock=lambda: now[0],
    )
    transport = NativeProviderAuditTransport(
        tenant_id=TENANT,
        binding_store=store,
        config=config,
        watermark_authority_resolver=operator.resolve,
        http_transport=http,
        clock=lambda: now[0],
        sleeper=lambda _delay: None,
    )

    with pytest.raises(DataUseProviderAuditRetryable, match="provider_audit_read_deadline"):
        transport.read_with_deadline(request, _lease(binding), deadline=1_201.0)

    assert len(http.calls) == 1
    assert http.calls[0]["timeout"] == pytest.approx(0.75)


def test_pinned_transport_only_passes_valid_same_origin_partition_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import maverick.enterprise as enterprise
    import maverick.tools._ssrf as ssrf

    valid_link = (
        '<https://acct1.snowflakecomputing.com/api/v2/statements/reader-1?partition=2>; rel="next"'
    )

    class FakeResponse:
        status_code = 200

        def __init__(self, link: str) -> None:
            self.headers = {
                "content-type": "application/json",
                "link": link,
                "x-provider-principal": "must-not-pass",
            }

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def iter_bytes():
            yield b"{}"

    responses = [
        FakeResponse(valid_link),
        FakeResponse('<https://evil.example/api/v2/statements/reader-1?partition=2>; rel="next"'),
    ]

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def stream(*_args, **_kwargs):
            return responses.pop(0)

    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *_a, **_k: None)
    monkeypatch.setattr(ssrf, "safe_client", lambda *_a, **_k: FakeClient())
    transport = PinnedProviderHttpTransport()
    request_url = "https://acct1.snowflakecomputing.com/api/v2/statements/reader-1"

    accepted = transport.request(
        "GET",
        request_url,
        headers={},
        body=None,
        timeout=5,
        max_response_bytes=4096,
        allow_redirects=False,
    )
    rejected = transport.request(
        "GET",
        request_url,
        headers={},
        body=None,
        timeout=5,
        max_response_bytes=4096,
        allow_redirects=False,
    )

    assert accepted.headers["link"] == valid_link
    assert "x-provider-principal" not in accepted.headers
    assert "link" not in rejected.headers


def test_pinned_transport_enforces_total_elapsed_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import maverick.enterprise as enterprise
    import maverick.tools._ssrf as ssrf
    import maverick_dashboard.data_use_provider_runtime as runtime_module

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def iter_bytes():
            yield b"{}"

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def stream(*_args, **_kwargs):
            return FakeResponse()

    elapsed = iter((100.0, 106.0))
    monkeypatch.setattr(enterprise, "enterprise_egress_denial", lambda *_a, **_k: None)
    monkeypatch.setattr(ssrf, "safe_client", lambda *_a, **_k: FakeClient())
    monkeypatch.setattr(runtime_module, "_monotonic", lambda: next(elapsed))

    with pytest.raises(DataUseProviderTransportAmbiguous, match="elapsed timeout"):
        PinnedProviderHttpTransport().request(
            "GET",
            "https://acct1.snowflakecomputing.com/api/v2/statements/reader-1",
            headers={},
            body=None,
            timeout=5,
            max_response_bytes=4096,
            allow_redirects=False,
        )
