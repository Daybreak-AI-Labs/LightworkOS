from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

import pytest
from maverick import privacy_rights_source_adapters as adapters
from maverick import privacy_rights_source_worker as worker

PROVIDERS = (
    (
        "microsoft_graph_users",
        "https://graph.microsoft.com",
        {"id": "graph-user-1", "mail": "person@example.test"},
        "/v1.0/users/graph-user-1",
    ),
    (
        "google_workspace_users",
        "https://admin.googleapis.com",
        {"id": "google-user-1", "primaryEmail": "person@example.test"},
        "/admin/directory/v1/users/google-user-1",
    ),
    (
        "salesforce_contacts",
        "https://tenant.salesforce.com",
        {
            "done": True,
            "totalSize": 1,
            "records": [{"Id": "003ABC", "Email": "person@example.test"}],
        },
        "/services/data/v61.0/sobjects/Contact/003ABC",
    ),
    (
        "servicenow_users",
        "https://tenant.service-now.com",
        {"result": [{"sys_id": "abc123", "email": "person@example.test"}]},
        "/api/now/table/sys_user/abc123",
    ),
)


def _body(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


class Transport:
    dns_pinned = True
    redirects_followed = False

    def __init__(self, *items: object) -> None:
        self.items = list(items)
        self.calls: list[dict[str, object]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
        allow_redirects: bool,
    ) -> adapters.HTTPResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
                "max_response_bytes": max_response_bytes,
                "allow_redirects": allow_redirects,
            }
        )
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        status, response_body, response_headers, final_url = item
        return adapters.HTTPResponse(
            status_code=status,
            headers=response_headers,
            body=response_body,
            final_url=url if final_url is None else final_url,
        )


class Custody:
    def __init__(self) -> None:
        self.items: dict[str, tuple[str, str, dict[str, object]]] = {}

    def store(self, **kwargs):
        target_ref = "target:one"
        current = self.items.get(target_ref)
        material = (kwargs["target_id"], kwargs["target_binding_sha256"], kwargs)
        if current is not None and current[:2] != material[:2]:
            raise RuntimeError("target changed")
        self.items[target_ref] = material
        return adapters.MutationTargetReceipt(
            opaque_ref=target_ref,
            target_binding_sha256=kwargs["target_binding_sha256"],
            tenant_bound=True,
            encrypted_at_rest=True,
            retention_enforced=True,
        )

    def resolve(self, **kwargs):
        target_id, digest, stored = self.items[kwargs["target_ref"]]
        assert digest == kwargs["target_binding_sha256"]
        for key in ("tenant_id", "case_id", "source_id", "operation_id", "provider"):
            assert stored[key] == kwargs[key]
        return target_id


def _json_response(
    payload: object,
    *,
    status: int = 200,
    content_type: str = "application/json; charset=utf-8",
    final_url: str | None = None,
) -> tuple[int, bytes, Mapping[str, str], str | None]:
    return status, _body(payload), {"Content-Type": content_type}, final_url


def _empty_response(status: int) -> tuple[int, bytes, Mapping[str, str], None]:
    return status, b"", {}, None


def _adapter(
    provider: str,
    origin: str,
    transport: Transport,
    *,
    sink=None,
    custody=None,
) -> adapters.StockPrivacyRightsSourceAdapter:
    return adapters.StockPrivacyRightsSourceAdapter(
        provider=provider,
        origin=origin,
        transport=transport,
        artifact_sink=sink,
        target_custody=custody or Custody(),
    )


def _execute(adapter, phase: str, *, approved: bool = False):
    if phase == "delete" and approved:
        prepared = adapter.prepare_mutation(
            tenant_id="tenant-a",
            source_id="directory",
            case_id="case-1",
            phase=phase,
            subject_reference="person@example.test",
            credential="transient-token",
            operation_id="operation:123",
        )
        if prepared.status == "not_found":
            return worker.ProviderOutcome(
                status="not_found",
                record_count=0,
                acknowledgement_sha256=prepared.acknowledgement_sha256,
                acknowledgement_ref=prepared.acknowledgement_ref,
                provider_evidence_sha256=prepared.provider_evidence_sha256,
                opaque_ref=prepared.opaque_ref,
                external_side_effect=False,
            )
        return adapter.execute_prepared(
            tenant_id="tenant-a",
            source_id="directory",
            case_id="case-1",
            phase=phase,
            credential="transient-token",
            operation_id="operation:123",
            target_ref=prepared.target_ref,
            target_binding_sha256=prepared.target_binding_sha256,
            destructive_approved=True,
        )
    return adapter.execute(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-1",
        phase=phase,
        subject_reference="person@example.test",
        credential="transient-token",
        operation_id="operation:123",
        destructive_approved=approved,
    )


@pytest.mark.parametrize(("provider", "origin", "payload", "_delete_path"), PROVIDERS)
def test_stock_adapters_discover_one_exact_subject_without_returning_raw_data(
    provider: str,
    origin: str,
    payload: object,
    _delete_path: str,
) -> None:
    transport = Transport(_json_response(payload))
    outcome = _execute(_adapter(provider, origin, transport), "discover")

    assert outcome.status == "complete"
    assert outcome.record_count == 1
    assert outcome.raw_data_returned is False
    assert "person@example.test" not in repr(outcome)
    assert transport.calls[0]["method"] == "GET"
    assert transport.calls[0]["allow_redirects"] is False
    assert transport.calls[0]["max_response_bytes"] == 1_048_576


@pytest.mark.parametrize(("provider", "origin", "payload", "delete_path"), PROVIDERS)
def test_stock_adapters_delete_only_one_canonical_provider_record(
    provider: str,
    origin: str,
    payload: object,
    delete_path: str,
) -> None:
    transport = Transport(_json_response(payload), _empty_response(204))
    outcome = _execute(_adapter(provider, origin, transport), "delete", approved=True)

    assert outcome.status == "complete"
    assert outcome.external_side_effect is True
    assert [call["method"] for call in transport.calls] == ["GET", "DELETE"]
    assert str(transport.calls[1]["url"]).endswith(delete_path)
    assert transport.calls[1]["headers"]["Idempotency-Key"] == "operation:123"


def test_retrieval_body_only_flows_to_bound_encrypted_retention_sink() -> None:
    raw = {"id": "graph-user-1", "mail": "person@example.test"}
    stored: list[dict[str, object]] = []

    class Sink:
        def store(self, **kwargs):
            stored.append(kwargs)
            return adapters.ArtifactReceipt(
                opaque_ref="artifact:one",
                sha256=kwargs["sha256"],
                record_count=kwargs["record_count"],
                tenant_bound=True,
                encrypted_at_rest=True,
                retention_enforced=True,
            )

    transport = Transport(_json_response(raw))
    outcome = _execute(
        _adapter(
            "microsoft_graph_users",
            "https://graph.microsoft.com",
            transport,
            sink=Sink(),
        ),
        "retrieve",
    )

    assert outcome.opaque_ref == "artifact:one"
    assert outcome.raw_data_returned is False
    assert stored[0]["body"] == _body(raw)
    assert stored[0]["tenant_id"] == "tenant-a"
    assert transport.calls[0]["max_response_bytes"] == 8_388_608
    assert "person@example.test" not in repr(outcome)


def test_retrieval_rejects_sink_without_all_storage_guarantees() -> None:
    class UnsafeSink:
        def store(self, **kwargs):
            return adapters.ArtifactReceipt(
                opaque_ref="artifact:unsafe",
                sha256=kwargs["sha256"],
                record_count=kwargs["record_count"],
                tenant_bound=True,
                encrypted_at_rest=False,
                retention_enforced=True,
            )

    adapter = _adapter(
        "microsoft_graph_users",
        "https://graph.microsoft.com",
        Transport(_json_response({"id": "graph-user-1"})),
        sink=UnsafeSink(),
    )
    with pytest.raises(worker.ProviderPermanentError, match="retrieval_sink_invalid"):
        _execute(adapter, "retrieve")


def test_delete_requires_approval_before_any_provider_io() -> None:
    transport = Transport()
    adapter = _adapter(
        "microsoft_graph_users", "https://graph.microsoft.com", transport
    )
    with pytest.raises(worker.ProviderPermanentError, match="delete_not_approved"):
        _execute(adapter, "delete", approved=False)
    assert transport.calls == []


def test_servicenow_subject_cannot_inject_an_encoded_query_clause() -> None:
    transport = Transport()
    adapter = _adapter("servicenow_users", "https://tenant.service-now.com", transport)

    with pytest.raises(worker.ProviderPermanentError, match="subject_invalid"):
        adapter.execute(
            tenant_id="tenant-a",
            source_id="directory",
            case_id="case-1",
            phase="discover",
            subject_reference="person@example.test^ORactive=true",
            credential="transient-token",
            operation_id="operation:123",
            destructive_approved=False,
        )

    assert transport.calls == []


def test_duplicate_subject_match_is_never_deleted() -> None:
    payload = {
        "totalSize": 2,
        "records": [{"Id": "003A"}, {"Id": "003B"}],
    }
    transport = Transport(_json_response(payload))
    adapter = _adapter(
        "salesforce_contacts", "https://tenant.salesforce.com", transport
    )
    with pytest.raises(worker.ProviderPermanentError, match="subject_not_unique"):
        _execute(adapter, "delete", approved=True)
    assert [call["method"] for call in transport.calls] == ["GET"]


@pytest.mark.parametrize("failure", [RuntimeError("socket closed"), None])
def test_uncertain_delete_outcome_is_ambiguous_and_bound_to_original_operation(
    failure: Exception | None,
) -> None:
    mutation = failure if failure is not None else _empty_response(503)
    transport = Transport(
        _json_response({"id": "graph-user-1"}),
        mutation,
    )
    adapter = _adapter(
        "microsoft_graph_users", "https://graph.microsoft.com", transport
    )
    with pytest.raises(worker.ProviderAmbiguousOutcome) as raised:
        _execute(adapter, "delete", approved=True)
    assert raised.value.operation_ref == "operation:123"
    assert len(raised.value.operation_sha256) == 64


@pytest.mark.parametrize(("provider", "origin", "payload", "_delete_path"), PROVIDERS)
def test_verify_delete_retries_while_provider_record_is_present(
    provider: str, origin: str, payload: object, _delete_path: str
) -> None:
    present = _adapter(provider, origin, Transport(_json_response(payload)))
    with pytest.raises(worker.ProviderRetryableError, match="delete_not_observed"):
        _execute(present, "verify_delete")


@pytest.mark.parametrize(
    ("provider", "origin", "response"),
    [
        ("microsoft_graph_users", "https://graph.microsoft.com", _empty_response(404)),
        ("google_workspace_users", "https://admin.googleapis.com", _empty_response(404)),
        (
            "salesforce_contacts",
            "https://tenant.salesforce.com",
            _json_response({"done": True, "totalSize": 0, "records": []}),
        ),
        ("servicenow_users", "https://tenant.service-now.com", _json_response({"result": []})),
    ],
)
def test_verify_delete_completes_on_validated_zero_result_with_bound_evidence(
    provider: str, origin: str, response: object
) -> None:
    transport = Transport(response)
    outcome = _execute(_adapter(provider, origin, transport), "verify_delete")

    assert outcome.status == "not_found"
    assert outcome.record_count == 0
    assert outcome.external_side_effect is False
    assert outcome.raw_data_returned is False
    assert outcome.acknowledgement_sha256 == outcome.provider_evidence_sha256
    status, body, _, _ = response
    evidence = {
        "schema": "lightwork.privacy-rights-lookup-absence.v1",
        "provider": provider,
        "operation_id": "operation:123",
        "lookup_url_sha256": hashlib.sha256(str(transport.calls[0]["url"]).encode()).hexdigest(),
        "response_status": status,
        "response_body_sha256": hashlib.sha256(body).hexdigest(),
        "record_count": 0,
    }
    assert outcome.provider_evidence_sha256 == hashlib.sha256(_body(dict(sorted(evidence.items())))).hexdigest()
    assert "person@example.test" not in repr(outcome)
    assert [call["method"] for call in transport.calls] == ["GET"]


def test_verify_delete_rejects_incomplete_empty_salesforce_page() -> None:
    adapter = _adapter(
        "salesforce_contacts",
        "https://tenant.salesforce.com",
        Transport(_json_response({"done": False, "totalSize": 1, "records": []})),
    )
    with pytest.raises(worker.ProviderPermanentError, match="response_invalid"):
        _execute(adapter, "verify_delete")


@pytest.mark.parametrize(
    ("provider", "origin"),
    [
        ("salesforce_contacts", "https://tenant.salesforce.com"),
        ("servicenow_users", "https://tenant.service-now.com"),
    ],
)
def test_verify_delete_does_not_treat_missing_query_endpoint_as_zero_records(
    provider: str, origin: str
) -> None:
    adapter = _adapter(provider, origin, Transport(_empty_response(404)))
    with pytest.raises(worker.ProviderPermanentError, match="request_rejected"):
        _execute(adapter, "verify_delete")


@pytest.mark.parametrize(
    ("responses", "disposition", "count", "retention_state"),
    [
        (
            (_empty_response(404), _empty_response(404)),
            "applied",
            0,
            "purged",
        ),
        ((_json_response({"id": "graph-user-1"}),), "absent", 1, "active"),
        ((_empty_response(503),), "unknown", 0, "unknown"),
    ],
)
def test_reconciliation_is_read_only_and_never_replays_delete(
    responses: tuple[object, ...],
    disposition: str,
    count: int,
    retention_state: str,
) -> None:
    custody = Custody()
    transport = Transport(_json_response({"id": "graph-user-1"}), *responses)
    adapter = _adapter(
        "microsoft_graph_users",
        "https://graph.microsoft.com",
        transport,
        custody=custody,
    )
    prepared = adapter.prepare_mutation(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-1",
        phase="delete",
        subject_reference="person@example.test",
        credential="transient-token",
        operation_id="operation:123",
    )
    outcome = adapter.reconcile_mutation(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-1",
        phase="delete",
        credential="transient-token",
        operation_id="operation:123",
        target_ref=prepared.target_ref,
        target_binding_sha256=prepared.target_binding_sha256,
    )
    assert outcome.disposition == disposition
    assert outcome.record_count == count
    assert outcome.provider_retention_state == retention_state
    assert outcome.external_side_effect is False
    assert outcome.optimistic_replay_performed is False
    assert "DELETE" not in [call["method"] for call in transport.calls]


def test_mutation_fails_closed_without_deployment_target_custody() -> None:
    transport = Transport(_json_response({"id": "graph-user-1"}))
    adapter = adapters.StockPrivacyRightsSourceAdapter(
        provider="microsoft_graph_users",
        origin="https://graph.microsoft.com",
        transport=transport,
        target_custody=None,
    )
    with pytest.raises(
        worker.ProviderPermanentError,
        match="provider_target_custody_unavailable",
    ):
        adapter.prepare_mutation(
            tenant_id="tenant-a",
            source_id="directory",
            case_id="case-1",
            phase="delete",
            subject_reference="person@example.test",
            credential="transient-token",
            operation_id="operation:123",
        )
    assert transport.calls == []


def test_subject_rekey_or_identifier_reuse_cannot_change_custodied_target() -> None:
    custody = Custody()
    transport = Transport(
        _json_response({"id": "immutable-user-a", "mail": "person@example.test"}),
        _empty_response(404),
        _json_response({"id": "immutable-user-a"}),
    )
    adapter = _adapter(
        "microsoft_graph_users",
        "https://graph.microsoft.com",
        transport,
        custody=custody,
    )
    prepared = adapter.prepare_mutation(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-1",
        phase="delete",
        subject_reference="person@example.test",
        credential="transient-token",
        operation_id="operation:123",
    )
    outcome = adapter.reconcile_mutation(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-1",
        phase="delete",
        credential="transient-token",
        operation_id="operation:123",
        target_ref=prepared.target_ref,
        target_binding_sha256=prepared.target_binding_sha256,
    )

    urls = [str(call["url"]) for call in transport.calls]
    assert "immutable-user-a" in urls[1]
    assert "immutable-user-a" in urls[2]
    assert "person%40example.test" not in urls[1]
    assert "person%40example.test" not in urls[2]
    assert "replacement-user-b" not in "".join(urls)
    assert outcome.disposition == "unknown"
    assert outcome.provider_retention_state == "soft_deleted"


def test_graph_soft_deleted_item_is_retained_and_not_erasure_proof() -> None:
    custody = Custody()
    transport = Transport(
        _json_response({"id": "graph-user-1"}),
        _empty_response(404),
        _json_response({"id": "graph-user-1"}),
    )
    adapter = _adapter(
        "microsoft_graph_users",
        "https://graph.microsoft.com",
        transport,
        custody=custody,
    )
    prepared = adapter.prepare_mutation(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-soft-deleted",
        phase="delete",
        subject_reference="person@example.test",
        credential="transient-token",
        operation_id="operation:soft-delete",
    )
    outcome = adapter.reconcile_mutation(
        tenant_id="tenant-a",
        source_id="directory",
        case_id="case-soft-deleted",
        phase="delete",
        credential="transient-token",
        operation_id="operation:soft-delete",
        target_ref=prepared.target_ref,
        target_binding_sha256=prepared.target_binding_sha256,
    )
    assert outcome.disposition == "unknown"
    assert outcome.provider_retention_state == "soft_deleted"
    assert outcome.record_count == 1


@pytest.mark.parametrize(
    ("provider", "origin"),
    [
        ("microsoft_graph_users", "https://graph.microsoft.com.evil.test"),
        ("google_workspace_users", "http://admin.googleapis.com"),
        ("salesforce_contacts", "https://salesforce.com"),
        ("servicenow_users", "https://service-now.com"),
    ],
)
def test_provider_origins_are_closed_and_exact(provider: str, origin: str) -> None:
    with pytest.raises(worker.PrivacyRightsSourceWorkerConfigError):
        _adapter(provider, origin, Transport())


def test_transport_must_prove_dns_pinning_and_redirect_refusal() -> None:
    transport = Transport()
    transport.dns_pinned = False
    with pytest.raises(worker.PrivacyRightsSourceWorkerConfigError, match="unsafe"):
        _adapter("microsoft_graph_users", "https://graph.microsoft.com", transport)


@pytest.mark.parametrize(
    "response",
    [
        _json_response(
            {"id": "graph-user-1"},
            final_url="https://evil.test/stolen",
        ),
        _json_response(
            {"id": "graph-user-1"},
            content_type="text/html",
        ),
        (200, b'{"id":"one","id":"two"}', {"content-type": "application/json"}, None),
    ],
)
def test_redirect_content_type_and_duplicate_json_are_rejected(response: object) -> None:
    adapter = _adapter(
        "microsoft_graph_users",
        "https://graph.microsoft.com",
        Transport(response),
    )
    with pytest.raises(
        (worker.ProviderPermanentError, worker.PrivacyRightsSourceWorkerProtocolError)
    ):
        _execute(adapter, "discover")


def test_adapter_receipts_are_digest_only() -> None:
    raw = _body({"id": "graph-user-1", "mail": "person@example.test"})
    transport = Transport(
        (200, raw, {"content-type": "application/json"}, None)
    )
    outcome = _execute(
        _adapter(
            "microsoft_graph_users",
            "https://graph.microsoft.com",
            transport,
        ),
        "discover",
    )
    assert outcome.provider_evidence_sha256 == hashlib.sha256(raw).hexdigest()
    assert "person@example.test" not in repr(outcome)
