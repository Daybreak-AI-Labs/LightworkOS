from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest
from maverick.ai_cost_collectors import (
    AICostCollectorConfigError,
    AICostCollectorLimitError,
    AICostCollectorProtocolError,
    AICostCollectorTransportError,
    AWSCostExplorerCollector,
    AzureCostManagementCollector,
    CollectorLimits,
    GCPBillingExportCollector,
    GCPBillingQueryResult,
    OpenAIOrganizationBillingCollector,
    configured_collector_schedule,
    configured_collectors,
)
from maverick.ai_cost_roi import BillingProvider, CollectionRequest

REQUEST = CollectionRequest(
    period_start="2026-01-01T00:00:00Z",
    period_end="2026-01-03T00:00:00Z",
    max_records=10,
)
AWS_ACCOUNT = "123456789012"
AZURE_SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
GCP_ACCOUNT = "ABCDEF-123456-7890AB"


def _aws_group(
    *,
    service: str = "Amazon Bedrock",
    usage_type: str = "USE1-ModelInference",
    cost: str = "2.75",
    currency: str = "USD",
    usage: str = "125",
    unit: str = "requests",
) -> dict[str, Any]:
    return {
        "Keys": [service, usage_type],
        "Metrics": {
            "UnblendedCost": {"Amount": cost, "Unit": currency},
            "UsageQuantity": {"Amount": usage, "Unit": unit},
        },
    }


def _aws_page(
    *,
    start: str = "2026-01-01",
    end: str = "2026-01-02",
    groups: list[dict[str, Any]] | None = None,
    next_token: str = "",
    estimated: bool = False,
) -> dict[str, Any]:
    page: dict[str, Any] = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": start, "End": end},
                "Estimated": estimated,
                "Groups": groups if groups is not None else [_aws_group()],
            }
        ]
    }
    if next_token:
        page["NextPageToken"] = next_token
    return page


class FakeAWSClient:
    def __init__(self, pages: list[Mapping[str, Any]] | None = None, error: Exception | None = None):
        self.pages = list(pages or [])
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def get_cost_and_usage(self, **kwargs: Any) -> Mapping[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.pages.pop(0)


class FakeAWSIdentityClient:
    def __init__(self, account: str = AWS_ACCOUNT, error: Exception | None = None):
        self.account = account
        self.error = error
        self.calls = 0

    def get_caller_identity(self) -> Mapping[str, Any]:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return {"Account": self.account, "Arn": f"arn:aws:iam::{self.account}:role/test"}


def test_aws_collector_is_default_off_without_touching_client() -> None:
    client = FakeAWSClient([_aws_page()])
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        client=client,
        identity_client=FakeAWSIdentityClient(),
    )

    with pytest.raises(AICostCollectorConfigError, match="disabled"):
        collector.collect(REQUEST)

    assert client.calls == []


def test_aws_collector_consumes_all_pages_and_binds_source_and_currency() -> None:
    client = FakeAWSClient(
        [
            _aws_page(next_token="cursor-2"),
            _aws_page(
                start="2026-01-02",
                end="2026-01-03",
                groups=[_aws_group(cost="3.5", currency="EUR", usage="25")],
            ),
        ]
    )
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=client,
        identity_client=FakeAWSIdentityClient(),
        clock=lambda: 1_800_000_000.0,
    )

    batch = collector.collect(REQUEST)

    assert batch.provider is BillingProvider.AWS
    assert batch.source_account_id == AWS_ACCOUNT
    assert len(batch.records) == 2
    assert [row.currency for row in batch.records] == ["USD", "EUR"]
    assert {row.service for row in batch.records} == {"Amazon Bedrock"}
    assert all(row.source_account_id == AWS_ACCOUNT for row in batch.records)
    assert all(row.citation.row_ref == row.source_record_id for row in batch.records)
    assert all(row.citation.sha256 != batch.manifest_citation.sha256 for row in batch.records)
    assert client.calls[0]["TimePeriod"] == {"Start": "2026-01-01", "End": "2026-01-03"}
    assert client.calls[0]["Metrics"] == ["UnblendedCost", "UsageQuantity"]
    assert client.calls[0]["Filter"]["Dimensions"]["Values"] == ["Amazon Bedrock"]
    assert "NextPageToken" not in client.calls[0]
    assert client.calls[1]["NextPageToken"] == "cursor-2"


def test_aws_refuses_estimated_or_cyclic_results() -> None:
    estimated = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient([_aws_page(estimated=True)]),
        identity_client=FakeAWSIdentityClient(),
    )
    with pytest.raises(AICostCollectorProtocolError, match="estimated"):
        estimated.collect(REQUEST)

    cycle = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient(
            [
                _aws_page(next_token="repeat"),
                _aws_page(start="2026-01-02", end="2026-01-03", next_token="repeat"),
            ]
        ),
        identity_client=FakeAWSIdentityClient(),
    )
    with pytest.raises(AICostCollectorProtocolError, match="cycle"):
        cycle.collect(REQUEST)


def test_aws_refuses_a_partial_batch_at_record_cap() -> None:
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient([_aws_page(next_token="more")]),
        identity_client=FakeAWSIdentityClient(),
        limits=CollectorLimits(record_cap=1),
    )

    with pytest.raises(AICostCollectorLimitError, match="partial"):
        collector.collect(REQUEST)


def test_aws_repagination_keeps_batch_and_row_evidence_idempotent() -> None:
    first_day = _aws_page(next_token="next")
    second_day = _aws_page(start="2026-01-02", end="2026-01-03")
    combined = _aws_page()
    combined["ResultsByTime"].append(second_day["ResultsByTime"][0])
    identity = FakeAWSIdentityClient()
    paged = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient([first_day, second_day]),
        identity_client=identity,
        clock=lambda: 1_800_000_000.0,
    ).collect(REQUEST)
    single = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient([combined]),
        identity_client=FakeAWSIdentityClient(),
        clock=lambda: 1_800_000_000.0,
    ).collect(REQUEST)

    assert paged.batch_id == single.batch_id
    assert paged.manifest_citation.sha256 == single.manifest_citation.sha256
    assert [row.payload_sha256 for row in paged.records] == [
        row.payload_sha256 for row in single.records
    ]


def test_aws_sts_identity_must_match_configured_payer() -> None:
    client = FakeAWSClient([_aws_page()])
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=client,
        identity_client=FakeAWSIdentityClient(account="999999999999"),
    )

    with pytest.raises(AICostCollectorProtocolError, match="caller identity"):
        collector.collect(REQUEST)

    assert client.calls == []


def test_aws_timeout_does_not_expose_exception_secret() -> None:
    secret = "aws-secret-value-that-must-not-leak"
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient(error=TimeoutError(secret)),
        identity_client=FakeAWSIdentityClient(),
    )

    with pytest.raises(AICostCollectorTransportError) as caught:
        collector.collect(REQUEST)

    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert secret not in repr(collector.__dict__)


def test_aws_live_path_requires_only_a_named_credential_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
    )

    with pytest.raises(AICostCollectorConfigError, match="AWS_PROFILE"):
        collector.collect(REQUEST)


@dataclass
class FakeAzureResponse:
    status_code: int
    payload: Any
    headers: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        self.headers = dict(self.headers or {})

    def json(self) -> Any:
        return self.payload


class FakeAzureTransport:
    def __init__(self, responses: list[FakeAzureResponse] | None = None, error: Exception | None = None):
        self.responses = list(responses or [])
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Mapping[str, Any],
        timeout: float,
    ) -> FakeAzureResponse:
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "json_body": dict(json_body),
                "timeout": timeout,
            }
        )
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


AZURE_COLUMNS = [
    {"name": "Currency", "type": "String"},
    {"name": "ResourceId", "type": "String"},
    {"name": "PreTaxCost", "type": "Number"},
    {"name": "ServiceName", "type": "String"},
    {"name": "UsageDate", "type": "Number"},
]


def _azure_page(
    rows: list[list[Any]],
    *,
    next_link: str = "",
    partial: bool = False,
) -> FakeAzureResponse:
    properties: dict[str, Any] = {"columns": AZURE_COLUMNS, "rows": rows}
    if next_link:
        properties["nextLink"] = next_link
    if partial:
        properties["isPartial"] = True
    result_id = (
        f"/subscriptions/{AZURE_SUBSCRIPTION}/providers/"
        "Microsoft.CostManagement/Query/result-1"
    )
    return FakeAzureResponse(200, {"id": result_id, "properties": properties})


def _azure_row(
    *,
    date: object = 20260101,
    cost: object = "7.125",
    currency: str = "USD",
    service: str = "Azure OpenAI",
    resource: str = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/ai/providers/Microsoft.CognitiveServices/accounts/prod",
) -> list[Any]:
    return [currency, resource, cost, service, date]


def _azure_next(host: str = "management.azure.com", extra: str = "") -> str:
    path = (
        f"/subscriptions/{AZURE_SUBSCRIPTION}/providers/"
        "Microsoft.CostManagement/Query"
    )
    suffix = f"&{extra}" if extra else ""
    return f"https://{host}{path}?api-version=2025-03-01&$skiptoken=cursor{suffix}"


def test_azure_collector_paginates_only_inside_fixed_subscription_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "azure-token-do-not-persist"
    monkeypatch.setenv("AZURE_COST_MANAGEMENT_TOKEN", secret)
    transport = FakeAzureTransport(
        [
            _azure_page([_azure_row()], next_link=_azure_next()),
            _azure_page([_azure_row(date=20260102, cost="1.25")]),
        ]
    )
    collector = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=transport,
        clock=lambda: 1_800_000_000.0,
    )

    batch = collector.collect(REQUEST)

    assert len(batch.records) == 2
    assert batch.provider is BillingProvider.AZURE
    assert batch.source_account_id == AZURE_SUBSCRIPTION
    assert all(row.currency == "USD" for row in batch.records)
    assert all(row.service == "Azure OpenAI" for row in batch.records)
    assert all(row.usage[0].quantity == "1" for row in batch.records)
    assert transport.calls[0]["url"].startswith(
        f"https://management.azure.com/subscriptions/{AZURE_SUBSCRIPTION}/"
    )
    assert transport.calls[1]["url"] == _azure_next()
    body = transport.calls[0]["json_body"]
    assert body["type"] == "ActualCost"
    assert body["dataset"]["filter"]["dimensions"]["values"] == ["Azure OpenAI"]
    assert secret not in repr(batch)
    assert secret not in batch.manifest_citation.uri
    assert secret not in repr(collector.__dict__)


@pytest.mark.parametrize(
    "next_link",
    [
        _azure_next("evil.example"),
        _azure_next(extra="redirect=https://evil.example"),
        (
            f"https://user:pass@management.azure.com/subscriptions/{AZURE_SUBSCRIPTION}/"
            "providers/Microsoft.CostManagement/Query?api-version=2025-03-01&"
            "$skiptoken=cursor"
        ),
    ],
)
def test_azure_rejects_hostile_or_expanded_next_links(
    monkeypatch: pytest.MonkeyPatch,
    next_link: str,
) -> None:
    monkeypatch.setenv("AZURE_COST_MANAGEMENT_TOKEN", "token")
    transport = FakeAzureTransport([_azure_page([_azure_row()], next_link=next_link)])
    collector = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=transport,
    )

    with pytest.raises(AICostCollectorProtocolError, match="nextLink"):
        collector.collect(REQUEST)

    assert len(transport.calls) == 1


def test_azure_refuses_partial_marker_or_float_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_COST_MANAGEMENT_TOKEN", "token")
    partial = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport([_azure_page([_azure_row()], partial=True)]),
    )
    with pytest.raises(AICostCollectorProtocolError, match="partial"):
        partial.collect(REQUEST)

    inexact = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport([_azure_page([_azure_row(cost=0.1)])]),
    )
    with pytest.raises(AICostCollectorProtocolError, match="exact decimal"):
        inexact.collect(REQUEST)


def test_azure_timeout_is_sanitized_and_missing_token_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "azure-timeout-secret"
    monkeypatch.setenv("AZURE_COST_MANAGEMENT_TOKEN", "token")
    timeout = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport(error=TimeoutError(secret)),
    )
    with pytest.raises(AICostCollectorTransportError) as caught:
        timeout.collect(REQUEST)
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None

    monkeypatch.delenv("AZURE_COST_MANAGEMENT_TOKEN")
    missing = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport([_azure_page([_azure_row()])]),
    )
    with pytest.raises(AICostCollectorConfigError, match="AZURE_COST_MANAGEMENT_TOKEN"):
        missing.collect(REQUEST)


def test_azure_service_scope_and_complete_record_cap_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_COST_MANAGEMENT_TOKEN", "token")
    wrong_scope_page = _azure_page([_azure_row()])
    wrong_scope_page.payload["id"] = (
        "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/providers/"
        "Microsoft.CostManagement/Query/result-1"
    )
    wrong_scope = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport([wrong_scope_page]),
    )
    with pytest.raises(AICostCollectorProtocolError, match="subscription scope"):
        wrong_scope.collect(REQUEST)

    escaped = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport([_azure_page([_azure_row(service="Azure SQL")])]),
    )
    with pytest.raises(AICostCollectorProtocolError, match="service filter"):
        escaped.collect(REQUEST)

    bounded = AzureCostManagementCollector(
        subscription_id=AZURE_SUBSCRIPTION,
        services=("Azure OpenAI",),
        enabled=True,
        transport=FakeAzureTransport([_azure_page([_azure_row()], next_link=_azure_next())]),
        limits=CollectorLimits(record_cap=1),
    )
    with pytest.raises(AICostCollectorLimitError, match="partial"):
        bounded.collect(REQUEST)


def _gcp_row(
    *,
    account: str = GCP_ACCOUNT,
    start: str = "2026-01-01T00:00:00Z",
    end: str = "2026-01-01T01:00:00Z",
    currency: str = "USD",
    service: str = "Vertex AI",
    cost: object = "4.25",
    row_id: str = "gcp-row-1",
) -> dict[str, Any]:
    return {
        "billing_account_id": account,
        "export_row_id": row_id,
        "usage_start_time": start,
        "usage_end_time": end,
        "currency": currency,
        "net_cost": cost,
        "sku_id": "SKU-123",
        "usage_amount": "99",
        "usage_unit": "requests",
        "resource_name": "//aiplatform.googleapis.com/projects/acme-prod/locations/us/models/1",
        "service_description": service,
        "region": "us-central1",
    }


class FakeGCPClient:
    def __init__(self, result: GCPBillingQueryResult | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def query_billing_export(
        self,
        sql: str,
        *,
        parameters: Mapping[str, Any],
        timeout_seconds: float,
        page_size: int,
        page_cap: int,
        record_cap: int,
        max_bytes_billed: int,
    ) -> GCPBillingQueryResult:
        self.calls.append(
            {
                "sql": sql,
                "parameters": dict(parameters),
                "timeout_seconds": timeout_seconds,
                "page_size": page_size,
                "page_cap": page_cap,
                "record_cap": record_cap,
                "max_bytes_billed": max_bytes_billed,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def test_gcp_collector_uses_parameterized_fixed_export_table_and_full_pages() -> None:
    result = GCPBillingQueryResult(
        job_id="job-1",
        pages=((_gcp_row(),), (_gcp_row(start="2026-01-02T00:00:00Z", end="2026-01-02T01:00:00Z", currency="EUR", row_id="gcp-row-2"),)),
        complete=True,
        total_rows=2,
    )
    client = FakeGCPClient(result)
    collector = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=client,
        clock=lambda: 1_800_000_000.0,
    )

    batch = collector.collect(REQUEST)

    assert batch.provider is BillingProvider.GCP
    assert batch.source_account_id == GCP_ACCOUNT
    assert [row.currency for row in batch.records] == ["USD", "EUR"]
    assert all(row.source_account_id == GCP_ACCOUNT for row in batch.records)
    call = client.calls[0]
    assert "`acme-prod.billing_export.gcp_billing_export_resource_v1_ABCDEF_123456_7890AB`" in call["sql"]
    assert "@billing_account_id" in call["sql"]
    assert "@services" in call["sql"]
    assert call["parameters"] == {
        "period_start": REQUEST.period_start,
        "period_end": REQUEST.period_end,
        "billing_account_id": GCP_ACCOUNT,
        "services": ("Vertex AI",),
    }
    assert batch.manifest_citation.uri.startswith("urn:google:cloud-billing-export:")


@pytest.mark.parametrize(
    ("project", "dataset"),
    [
        ("acme-prod`; SELECT 1 --", "billing_export"),
        ("acme-prod", "billing.export"),
        ("https://evil.example", "billing_export"),
    ],
)
def test_gcp_rejects_hostile_table_identifiers(project: str, dataset: str) -> None:
    with pytest.raises(AICostCollectorConfigError):
        GCPBillingExportCollector(
            project_id=project,
            dataset_id=dataset,
            billing_account_id=GCP_ACCOUNT,
            services=("Vertex AI",),
        )


def test_gcp_refuses_incomplete_or_truncated_query_results() -> None:
    incomplete = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=FakeGCPClient(
            GCPBillingQueryResult(
                job_id="job-incomplete",
                pages=((_gcp_row(),),),
                complete=False,
                total_rows=1,
            )
        ),
    )
    with pytest.raises(AICostCollectorProtocolError, match="complete"):
        incomplete.collect(REQUEST)

    truncated = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=FakeGCPClient(
            GCPBillingQueryResult(
                job_id="job-truncated",
                pages=((_gcp_row(),),),
                complete=True,
                total_rows=2,
            )
        ),
    )
    with pytest.raises(AICostCollectorProtocolError, match="partial"):
        truncated.collect(REQUEST)


def test_gcp_enforces_account_service_and_record_bindings() -> None:
    wrong_account = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=FakeGCPClient(
            GCPBillingQueryResult(
                job_id="job-account",
                pages=((_gcp_row(account="AAAAAA-BBBBBB-CCCCCC"),),),
                complete=True,
                total_rows=1,
            )
        ),
    )
    with pytest.raises(AICostCollectorProtocolError, match="billing account"):
        wrong_account.collect(REQUEST)

    wrong_service = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=FakeGCPClient(
            GCPBillingQueryResult(
                job_id="job-service",
                pages=((_gcp_row(service="Cloud SQL"),),),
                complete=True,
                total_rows=1,
            )
        ),
    )
    with pytest.raises(AICostCollectorProtocolError, match="service filter"):
        wrong_service.collect(REQUEST)

    over_cap = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=FakeGCPClient(
            GCPBillingQueryResult(
                job_id="job-cap",
                pages=((_gcp_row(), _gcp_row(row_id="gcp-row-2")),),
                complete=True,
                total_rows=2,
            )
        ),
        limits=CollectorLimits(record_cap=1),
    )
    with pytest.raises(AICostCollectorLimitError, match="record cap"):
        over_cap.collect(REQUEST)

    over_pages = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=FakeGCPClient(
            GCPBillingQueryResult(
                job_id="job-pages",
                pages=((_gcp_row(),), (_gcp_row(row_id="gcp-row-2"),)),
                complete=True,
                total_rows=2,
            )
        ),
        limits=CollectorLimits(page_cap=1),
    )
    with pytest.raises(AICostCollectorLimitError, match="page cap"):
        over_pages.collect(REQUEST)


def test_gcp_timeout_and_credential_references_never_persist_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "gcp-timeout-secret"
    client = FakeGCPClient(error=TimeoutError(secret))
    collector = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
        client=client,
    )
    with pytest.raises(AICostCollectorTransportError) as caught:
        collector.collect(REQUEST)
    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert secret not in repr(collector.__dict__)

    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    live = GCPBillingExportCollector(
        project_id="acme-prod",
        dataset_id="billing_export",
        billing_account_id=GCP_ACCOUNT,
        services=("Vertex AI",),
        enabled=True,
    )
    with pytest.raises(AICostCollectorConfigError, match="GOOGLE_APPLICATION_CREDENTIALS"):
        live.collect(REQUEST)


def test_collectors_reject_non_midnight_or_overlong_periods() -> None:
    non_midnight = CollectionRequest(
        period_start="2026-01-01T01:00:00Z",
        period_end="2026-01-02T01:00:00Z",
    )
    collector = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient([_aws_page()]),
        identity_client=FakeAWSIdentityClient(),
    )
    with pytest.raises(AICostCollectorConfigError, match="midnight"):
        collector.collect(non_midnight)

    long_request = CollectionRequest(
        period_start="2026-01-01T00:00:00Z",
        period_end="2026-01-04T00:00:00Z",
    )
    bounded = AWSCostExplorerCollector(
        payer_account_id=AWS_ACCOUNT,
        services=("Amazon Bedrock",),
        enabled=True,
        client=FakeAWSClient([_aws_page()]),
        identity_client=FakeAWSIdentityClient(),
        limits=CollectorLimits(max_period_days=2),
    )
    with pytest.raises(AICostCollectorLimitError, match="period"):
        bounded.collect(long_request)


def test_openai_collector_is_default_off_and_requires_admin_secret_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-read-or-persisted")
    disabled = OpenAIOrganizationBillingCollector(organization_ref="org-live-test")
    with pytest.raises(AICostCollectorConfigError, match="disabled"):
        disabled.collect(REQUEST)

    enabled = OpenAIOrganizationBillingCollector(
        organization_ref="org-live-test",
        enabled=True,
    )
    with pytest.raises(AICostCollectorConfigError, match="credential reference"):
        enabled.collect(REQUEST)
    assert "must-not-be-read-or-persisted" not in repr(enabled.__dict__)


def test_configured_collectors_and_schedule_are_default_off() -> None:
    assert configured_collectors({}) == ()
    schedule = configured_collector_schedule({})
    assert schedule.poll_seconds == 86400.0
    assert schedule.lookback_days == 1

    configured_but_gated = {
        "enable": False,
        "aws": {
            "enable": True,
            "payer_account_id": AWS_ACCOUNT,
            "services": ["Amazon Bedrock"],
        },
    }
    assert configured_collectors(configured_but_gated) == ()


def test_configured_collectors_share_strict_bounded_limits() -> None:
    section = {
        "enable": True,
        "collector_poll_seconds": 3600,
        "collector_lookback_days": 7,
        "collector_limits": {
            "timeout_seconds": 12,
            "page_cap": 9,
            "record_cap": 500,
            "max_period_days": 10,
            "page_size": 100,
            "max_bytes_billed": 2_000_000,
        },
        "aws": {
            "enable": True,
            "payer_account_id": AWS_ACCOUNT,
            "services": ["Amazon Bedrock"],
            "credential_ref_env": "AWS_BILLING_PROFILE",
        },
        "azure": {
            "enable": True,
            "subscription_id": AZURE_SUBSCRIPTION,
            "services": ["Azure AI Foundry"],
            "token_env": "AZURE_BILLING_TOKEN",
        },
        "gcp": {
            "enable": True,
            "project_id": "acme-prod",
            "dataset_id": "billing_export",
            "billing_account_id": GCP_ACCOUNT,
            "services": ["Vertex AI"],
            "credential_ref_env": "GCP_BILLING_CREDENTIALS",
        },
        "openai": {
            "enable": True,
            "organization_ref": "org-live-test",
            "admin_key_env": "OPENAI_ADMIN_KEY",
        },
    }

    collectors = configured_collectors(section)
    assert tuple(type(collector) for collector in collectors) == (
        AWSCostExplorerCollector,
        AzureCostManagementCollector,
        GCPBillingExportCollector,
        OpenAIOrganizationBillingCollector,
    )
    assert (
        collectors[0].limits
        is collectors[1].limits
        is collectors[2].limits
        is collectors[3].limits
    )
    assert collectors[0].limits == CollectorLimits(
        timeout_seconds=12,
        page_cap=9,
        record_cap=500,
        max_period_days=10,
        page_size=100,
        max_bytes_billed=2_000_000,
    )
    assert configured_collector_schedule(section).lookback_days == 7


@pytest.mark.parametrize(
    "section",
    [
        {"unexpected": True},
        {"aws": {"enable": False, "endpoint_url": "https://example.test"}},
        {"collector_limits": {"unbounded": True}},
    ],
)
def test_configured_factories_reject_unknown_keys(section: dict[str, Any]) -> None:
    with pytest.raises(AICostCollectorConfigError, match="unknown key"):
        configured_collectors(section)
    with pytest.raises(AICostCollectorConfigError, match="unknown key"):
        configured_collector_schedule(section)


@pytest.mark.parametrize(
    "section",
    [
        {"enable": "true"},
        {"aws": {"enable": "true"}},
        {"collector_poll_seconds": True},
        {"collector_poll_seconds": 299},
        {"collector_poll_seconds": 604801},
        {"collector_lookback_days": 0},
        {"collector_lookback_days": 367},
        {
            "collector_lookback_days": 8,
            "collector_limits": {"max_period_days": 7},
        },
    ],
)
def test_configured_factories_reject_invalid_types_and_bounds(
    section: dict[str, Any],
) -> None:
    with pytest.raises((AICostCollectorConfigError, ValueError)):
        configured_collector_schedule(section)


def test_enabled_provider_requires_only_named_configuration_references() -> None:
    with pytest.raises(AICostCollectorConfigError, match="payer_account_id"):
        configured_collectors({"enable": True, "aws": {"enable": True}})
