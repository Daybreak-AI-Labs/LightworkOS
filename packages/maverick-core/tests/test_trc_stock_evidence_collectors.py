from __future__ import annotations

import json
from dataclasses import replace

import pytest
from maverick.trc_continuous_evidence import (
    ContinuousEvidenceStore,
    run_claimed_collection,
)
from maverick.trc_evidence_collectors import CollectionRequest, validate_page
from maverick.trc_stock_evidence_collectors import (
    AWS_CONFIG,
    AWS_SECURITY_HUB,
    AZURE_DEFENDER,
    AZURE_POLICY,
    GCP_SECURITY_COMMAND_CENTER,
    GITHUB_SECURITY,
    OKTA_POSTURE,
    AWSConfigPostureCollector,
    AWSSecurityHubCollector,
    AzureDefenderCollector,
    AzurePolicyPostureCollector,
    GCPSecurityCommandCenterCollector,
    GitHubSecurityCollector,
    OktaPostureCollector,
    PinnedStockEvidenceHTTPTransport,
    ProviderControlBinding,
    StockCollectorCredentialHandle,
    StockCollectorDirectory,
    StockCollectorLimits,
    StockCollectorSource,
    StockEvidenceAccessDenied,
    StockEvidenceConfigurationError,
    StockEvidenceHTTPRequest,
    StockEvidenceHTTPResponse,
    StockEvidenceProtocolError,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class FakeTransport:
    def __init__(self, *responses: StockEvidenceHTTPResponse) -> None:
        self.responses = list(responses)
        self.requests: list[StockEvidenceHTTPRequest] = []

    def request(self, request: StockEvidenceHTTPRequest) -> StockEvidenceHTTPResponse:
        self.requests.append(request)
        return self.responses.pop(0)


def response(value, *, headers=None) -> StockEvidenceHTTPResponse:
    return StockEvidenceHTTPResponse(
        200,
        {"content-type": "application/json", **(headers or {})},
        json.dumps(value, separators=(",", ":")).encode(),
    )


def source(
    provider: str,
    selector: str,
    *,
    origin: str | None = None,
    scope_ref: str | None = None,
    region: str | None = None,
    stream: str | None = None,
    limits: StockCollectorLimits | None = None,
) -> StockCollectorSource:
    defaults = {
        AWS_SECURITY_HUB: (
            "https://securityhub.us-east-1.amazonaws.com",
            "123456789012",
            "us-east-1",
            None,
        ),
        AWS_CONFIG: (
            "https://config.us-east-1.amazonaws.com",
            "123456789012",
            "us-east-1",
            None,
        ),
        AZURE_DEFENDER: (
            "https://management.azure.com",
            "12345678-1234-4123-8123-123456789abc",
            None,
            None,
        ),
        AZURE_POLICY: (
            "https://management.azure.com",
            "12345678-1234-4123-8123-123456789abc",
            None,
            None,
        ),
        GCP_SECURITY_COMMAND_CENTER: (
            "https://securitycenter.googleapis.com",
            "organizations/1234567890",
            None,
            None,
        ),
        GITHUB_SECURITY: (
            "https://api.github.com",
            "lightwork-org",
            None,
            "code_scanning",
        ),
        OKTA_POSTURE: (
            "https://lightwork.okta.com",
            "lightwork-org",
            None,
            "MFA_ENROLL",
        ),
    }
    default_origin, default_scope, default_region, default_stream = defaults[provider]
    return StockCollectorSource(
        tenant_id="tenant-a",
        enrollment_id="stock_enrollment",
        definition_id="stock_definition",
        definition_version=1,
        definition_integrity_sha256=SHA_A,
        collector_key_id="stock_key_v1",
        capability_revision=1,
        provider=provider,
        origin=origin or default_origin,
        scope_ref=scope_ref or default_scope,
        credential_env="LIGHTWORK_STOCK_CREDENTIAL",
        bindings=(ProviderControlBinding("control-a", selector),),
        region=default_region if region is None else region,
        stream=default_stream if stream is None else stream,
        limits=limits or StockCollectorLimits(),
    )


def request(item: StockCollectorSource, *, revision: int = 3) -> CollectionRequest:
    return CollectionRequest(
        tenant_sha256=item.tenant_sha256,
        definition_id=item.definition_id,
        definition_version=item.definition_version,
        definition_integrity_sha256=item.definition_integrity_sha256,
        collector_id=item.collector_id,
        collector_schema_version=1,
        collector_key_id=item.collector_key_id,
        capability_revision=item.capability_revision,
        enrollment_id=item.enrollment_id,
        enrollment_revision=revision,
        enrollment_integrity_sha256=SHA_B,
        asset_scope_sha256=item.asset_scope_sha256,
        control_refs=("control-a",),
        window_started_at=1_799_999_000.0,
        window_ended_at=1_800_000_000.0,
        credential_handle=StockCollectorCredentialHandle(item, revision),
    )


@pytest.mark.parametrize(
    ("item", "collector_type", "payload", "expected_status", "expected_method"),
    (
        (
            source(AWS_SECURITY_HUB, "IAM.1"),
            AWSSecurityHubCollector,
            {
                "Findings": [
                    {
                        "Id": "finding-1",
                        "GeneratorId": "fallback",
                        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                        "Compliance": {"SecurityControlId": "IAM.1", "Status": "FAILED"},
                        "UpdatedAt": "2026-08-30T01:02:03Z",
                    }
                ]
            },
            "failed",
            "POST",
        ),
        (
            source(AWS_CONFIG, "required-tags"),
            AWSConfigPostureCollector,
            {
                "ComplianceByConfigRules": [
                    {
                        "ConfigRuleName": "required-tags",
                        "Compliance": {"ComplianceType": "COMPLIANT"},
                    }
                ]
            },
            "observed",
            "POST",
        ),
        (
            source(AZURE_DEFENDER, "assessment-1"),
            AzureDefenderCollector,
            {
                "value": [
                    {
                        "name": "assessment-1",
                        "properties": {"status": {"code": "Unhealthy"}},
                    }
                ]
            },
            "failed",
            "GET",
        ),
        (
            source(AZURE_POLICY, "policy-ref-1"),
            AzurePolicyPostureCollector,
            {
                "value": [
                    {
                        "policyDefinitionReferenceId": "policy-ref-1",
                        "complianceState": "Compliant",
                        "timestamp": "2026-08-30T01:02:03Z",
                    }
                ]
            },
            "observed",
            "POST",
        ),
        (
            source(GCP_SECURITY_COMMAND_CENTER, "PUBLIC_BUCKET_ACL"),
            GCPSecurityCommandCenterCollector,
            {
                "listFindingsResults": [
                    {
                        "finding": {
                            "name": "organizations/123/sources/1/findings/1",
                            "category": "PUBLIC_BUCKET_ACL",
                            "state": "ACTIVE",
                            "severity": "HIGH",
                            "eventTime": "2026-08-30T01:02:03Z",
                        }
                    }
                ]
            },
            "failed",
            "GET",
        ),
        (
            source(GITHUB_SECURITY, "py/sql-injection"),
            GitHubSecurityCollector,
            [
                {
                    "number": 4,
                    "state": "fixed",
                    "rule": {"id": "py/sql-injection"},
                    "updated_at": "2026-08-30T01:02:03Z",
                }
            ],
            "observed",
            "GET",
        ),
        (
            source(OKTA_POSTURE, "policy-1"),
            OktaPostureCollector,
            [
                {
                    "id": "policy-1",
                    "name": "Require MFA",
                    "status": "ACTIVE",
                    "type": "MFA_ENROLL",
                    "lastUpdated": "2026-08-30T01:02:03Z",
                }
            ],
            "observed",
            "GET",
        ),
    ),
)
def test_all_stock_collectors_return_digest_only_normalized_observations(
    item,
    collector_type,
    payload,
    expected_status,
    expected_method,
):
    transport = FakeTransport(response(payload))
    page = collector_type(transport=transport, clock=Clock()).fetch(request(item), None)

    validate_page(page, expected_controls=("control-a",))
    assert page.terminal is True
    assert page.complete is True
    assert page.items[0].status == expected_status
    assert page.items[0].control_ref == "control-a"
    assert len(page.items[0].evidence_sha256) == 64
    assert len(page.items[0].source_revision_sha256) == 64
    assert transport.requests[0].method == expected_method
    assert transport.requests[0].origin == item.origin
    assert item.scope_ref not in repr(page)
    assert payload not in page.items


def test_gcp_pagination_uses_opaque_transient_cursor_and_cumulative_watermark():
    item = source(GCP_SECURITY_COMMAND_CENTER, "PUBLIC_BUCKET_ACL")
    first = response(
        {
            "listFindingsResults": [
                {
                    "finding": {
                        "category": "PUBLIC_BUCKET_ACL",
                        "state": "ACTIVE",
                        "eventTime": "2026-08-30T01:00:00Z",
                    }
                }
            ],
            "nextPageToken": "raw-provider-token/with+characters=",
        }
    )
    second = response(
        {
            "listFindingsResults": [
                {
                    "finding": {
                        "category": "PUBLIC_BUCKET_ACL",
                        "state": "INACTIVE",
                        "eventTime": "2026-08-30T02:00:00Z",
                    }
                }
            ]
        }
    )
    transport = FakeTransport(first, second)
    collector = GCPSecurityCommandCenterCollector(transport=transport, clock=Clock())
    first_page = collector.fetch(request(item), None)
    assert first_page.terminal is False
    assert first_page.items == ()
    assert first_page.next_cursor is not None
    assert first_page.next_cursor != "raw-provider-token/with+characters="

    final_page = collector.fetch(request(item), first_page.next_cursor)
    assert final_page.terminal is True
    assert final_page.complete is True
    assert final_page.items[0].status == "failed"
    assert dict(transport.requests[1].query)["pageToken"] == (
        "raw-provider-token/with+characters="
    )
    assert first_page.source_revision_sha256 != final_page.source_revision_sha256


def test_page_bound_reports_explicit_truncation_instead_of_completeness():
    item = source(
        GCP_SECURITY_COMMAND_CENTER,
        "PUBLIC_BUCKET_ACL",
        limits=StockCollectorLimits(max_pages=1),
    )
    transport = FakeTransport(
        response({"listFindingsResults": [], "nextPageToken": "more"})
    )
    page = GCPSecurityCommandCenterCollector(
        transport=transport,
        clock=Clock(),
    ).fetch(request(item), None)
    assert page.terminal is True
    assert page.complete is False
    assert page.incomplete_reason == "provider_truncated"
    assert page.items[0].status == "unknown"
    assert page.items[0].reason_code == "provider_signal_absent"


def test_exact_tenant_definition_enrollment_and_scope_binding_precedes_io():
    item = source(AZURE_DEFENDER, "assessment-1")
    transport = FakeTransport(response({"value": []}))
    collector = AzureDefenderCollector(transport=transport, clock=Clock())
    baseline = request(item)
    hostile = (
        replace(baseline, tenant_sha256=SHA_D),
        replace(baseline, definition_integrity_sha256=SHA_D),
        replace(baseline, enrollment_revision=4),
        replace(baseline, asset_scope_sha256=SHA_D),
    )
    for candidate in hostile:
        with pytest.raises(StockEvidenceAccessDenied, match="authority_mismatch"):
            collector.fetch(candidate, None)
    assert transport.requests == []


def test_source_manifests_reject_arbitrary_origins_and_unsupported_operations():
    with pytest.raises(StockEvidenceConfigurationError, match="origin"):
        source(AZURE_DEFENDER, "assessment-1", origin="https://attacker.example")
    with pytest.raises(StockEvidenceConfigurationError, match="Okta origin"):
        source(OKTA_POSTURE, "policy-1", origin="https://okta.attacker.example")
    with pytest.raises(StockEvidenceConfigurationError, match="AWS region"):
        source(AWS_SECURITY_HUB, "IAM.1", region="bad/region")

    with pytest.raises(StockEvidenceConfigurationError, match="GET-only"):
        StockEvidenceHTTPRequest(
            provider=GITHUB_SECURITY,
            origin="https://api.github.com",
            method="POST",
            path="/orgs/lightwork/code-scanning/alerts",
            query=(),
            credential_env="LIGHTWORK_STOCK_CREDENTIAL",
            deadline=1_800_000_100.0,
            timeout_seconds=10,
            max_response_bytes=1024,
            body=b"{}",
        )


def test_cross_origin_continuation_and_replayed_cursor_fail_closed():
    item = source(AZURE_DEFENDER, "assessment-1")
    transport = FakeTransport(
        response(
            {
                "value": [],
                "nextLink": "https://attacker.example/subscriptions/x/providers/y",
            }
        )
    )
    collector = AzureDefenderCollector(transport=transport, clock=Clock())
    with pytest.raises(StockEvidenceProtocolError, match="crossed_scope"):
        collector.fetch(request(item), None)

    gcp = source(GCP_SECURITY_COMMAND_CENTER, "PUBLIC_BUCKET_ACL")
    transport = FakeTransport(
        response({"listFindingsResults": [], "nextPageToken": "next"}),
        response({"listFindingsResults": []}),
    )
    collector = GCPSecurityCommandCenterCollector(transport=transport, clock=Clock())
    page = collector.fetch(request(gcp), None)
    assert page.next_cursor is not None
    collector.fetch(request(gcp), page.next_cursor)
    with pytest.raises(StockEvidenceProtocolError, match="cursor_invalid"):
        collector.fetch(request(gcp), page.next_cursor)


@pytest.mark.parametrize(
    ("body", "headers", "reason"),
    (
        (
            b'{"value":[],"value":[{"name":"assessment-1"}]}',
            {"content-type": "application/json"},
            "duplicate_key",
        ),
        (b'{"value":[]}', {"content-type": "text/html"}, "content_type"),
        (b'{"value":[]}', {}, "content_type"),
    ),
)
def test_provider_json_must_be_unambiguous_and_explicitly_typed(
    body: bytes,
    headers: dict[str, str],
    reason: str,
) -> None:
    item = source(AZURE_DEFENDER, "assessment-1")
    transport = FakeTransport(StockEvidenceHTTPResponse(200, headers, body))
    collector = AzureDefenderCollector(transport=transport, clock=Clock())

    with pytest.raises(StockEvidenceProtocolError, match=reason):
        collector.fetch(request(item), None)


def test_directory_is_scheduler_compatible_and_readiness_never_resolves_secret():
    item = source(AZURE_DEFENDER, "assessment-1")
    transports = []
    credential_checks = []

    def transport_factory(tenant_id):
        assert tenant_id == "tenant-a"
        selected = FakeTransport(response({"value": []}))
        transports.append(selected)
        return selected

    directory = StockCollectorDirectory(
        (item,),
        transport_factory=transport_factory,
        credential_ref_present=lambda name: credential_checks.append(name) or True,
    )
    readiness = directory.readiness("tenant-a")
    assert readiness["ready"] is True
    assert readiness["credential_values_resolved"] is False
    assert readiness["provider_io_performed"] is False
    assert readiness["sources"][0]["source_revision_sha256"] == (
        item.source_revision_sha256
    )
    assert credential_checks == ["LIGHTWORK_STOCK_CREDENTIAL"]
    assert transports == []

    registry = directory.registry_for_tenant("tenant-a")
    assert item.collector_id in registry.capabilities()
    handle = directory.resolve_credential(
        "tenant-a",
        item.enrollment_id,
        7,
        item.credential_profile_sha256,
    )
    assert isinstance(handle, StockCollectorCredentialHandle)
    assert handle.enrollment_revision == 7
    with pytest.raises(StockEvidenceAccessDenied, match="profile_mismatch"):
        directory.resolve_credential("tenant-a", item.enrollment_id, 7, SHA_D)


def test_real_authority_collection_uses_directory_registry_and_resolver(tmp_path):
    clock = Clock()
    actor = ["maker@example.test"]
    store = ContinuousEvidenceStore(
        tmp_path / "continuous.sqlite3",
        tenant_id="tenant-a",
        principal_resolver=lambda: actor[0],
        config_gate=lambda: None,
        clock=clock,
        lease_token_factory=lambda: "lwtrc1." + "x" * 43,
    )
    pending = store.register_definition(
        definition_id="stock_definition",
        version=1,
        collector_id="azure_defender_v1",
        collector_schema_version=1,
        collector_key_id="stock_key_v1",
        capability_revision=1,
        allowed_control_refs=("control-a",),
    )
    actor[0] = "approver@example.test"
    approved = store.approve_definition(
        pending.definition_id,
        pending.version,
        expected_integrity_sha256=pending.integrity_sha256,
    )
    item = replace(
        source(AZURE_DEFENDER, "assessment-1"),
        definition_integrity_sha256=approved.integrity_sha256,
    )
    store.enroll(
        enrollment_id=item.enrollment_id,
        definition_id=item.definition_id,
        definition_version=item.definition_version,
        expected_definition_integrity_sha256=item.definition_integrity_sha256,
        asset_scope_sha256=item.asset_scope_sha256,
        credential_profile_sha256=item.credential_profile_sha256,
        control_refs=("control-a",),
        interval_seconds=60,
        operation_id="enroll_stock_source",
    )
    transport = FakeTransport(
        response(
            {
                "value": [
                    {
                        "name": "assessment-1",
                        "properties": {"status": {"code": "Healthy"}},
                    }
                ]
            }
        )
    )
    directory = StockCollectorDirectory(
        (item,),
        transport_factory=lambda _tenant: transport,
        include_local_soc2=False,
    )
    jobs = store.enqueue_due(limit=1, allowed_collector_ids=(item.collector_id,))
    assert len(jobs) == 1
    claimed = store.claim_jobs(worker_id="stock-worker", limit=1, lease_seconds=60)
    assert len(claimed) == 1
    outcome = run_claimed_collection(
        store,
        claimed[0],
        registry=directory.registry_for_tenant("tenant-a"),
        resolve_credential=directory.resolve_credential,
        allowed_collector_ids=(item.collector_id,),
    )
    assert outcome.job.state == "completed"
    assert outcome.run is not None and outcome.run.complete is True
    assert outcome.observations[0].status == "observed"
    assert len(transport.requests) == 1


def test_pinned_transport_repr_and_request_contract_never_hold_plaintext_secret():
    secret = "super-secret-token-value"
    transport = PinnedStockEvidenceHTTPTransport(
        credential_resolver=lambda _name: secret,
        clock=Clock(),
    )
    item = source(GITHUB_SECURITY, "py/sql-injection")
    call = StockEvidenceHTTPRequest(
        provider=item.provider,
        origin=item.origin,
        method="GET",
        path="/orgs/lightwork-org/code-scanning/alerts",
        query=(("page", "1"),),
        credential_env=item.credential_env,
        deadline=1_800_000_100.0,
        timeout_seconds=10,
        max_response_bytes=1024,
    )
    assert secret not in repr(transport)
    assert secret not in repr(call)
    assert call.url.startswith("https://api.github.com/")
