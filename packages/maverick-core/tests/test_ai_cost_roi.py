"""Focused contract tests for governed enterprise AI cost and ROI evidence."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from maverick import ai_cost_roi as cost
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

START = "2026-08-01T00:00:00Z"
END = "2026-09-01T00:00:00Z"
NOW = 1_800_000_000.0
ASSET = "MAA-0123456789abcdef0123456789abcdef"


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _citation(label: str = "billing-export") -> cost.SourceCitation:
    return cost.SourceCitation(
        uri=f"s3://billing-evidence/{label}.parquet",
        sha256=_hex(label),
        row_ref="row-0001",
    )


def test_feature_gate_is_explicit_and_default_off(_isolate):
    from maverick import config

    assert cost.enabled() is False
    (_isolate / "config.toml").write_text(
        "[ai_cost_roi]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert cost.enabled() is True


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        self.value += 1
        return self.value


class FakeAllocationResolver:
    def resolve(
        self,
        record: cost.NormalizedBillingRecord,
    ) -> tuple[cost.RegistryAllocation, ...]:
        if not record.registry_asset_id:
            return ()
        return (
            cost.RegistryAllocation(
                kind="asset",
                fraction="0.6",
                department="finance",
                owner="model-owner@example.test",
                asset_id=record.registry_asset_id,
                asset_revision=7,
                asset_digest=_hex("registry-snapshot"),
                basis="exact_provider_resource_mapping",
            ),
            cost.RegistryAllocation(
                kind="shared",
                fraction="0.2",
                department="platform",
                owner="platform-finops",
                basis="approved_shared_platform_rule",
            ),
        )


class FakeCollector:
    def __init__(
        self,
        batch: cost.BillingCollection,
        *,
        provider: cost.BillingProvider | None = None,
        collector_id: str | None = None,
    ) -> None:
        self.provider = provider or batch.provider
        self.collector_id = collector_id or batch.collector_id
        self.batch = batch
        self.requests: list[cost.CollectionRequest] = []

    def collect(self, request: cost.CollectionRequest) -> cost.BillingCollection:
        self.requests.append(request)
        return self.batch


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _service(resolver=None) -> cost.AICostROIService:
    return cost.AICostROIService(
        observations=GovernedRecordStore(
            "test_ai_cost_observations",
            "ACO",
            "test_ai_cost_observation",
        ),
        receipts=GovernedRecordStore(
            "test_ai_cost_receipts",
            "ACR",
            "test_ai_cost_receipt",
        ),
        assumptions=GovernedRecordStore(
            "test_ai_roi_assumptions",
            "ARA",
            "test_ai_roi_assumption",
        ),
        allocation_resolver=resolver,
        clock=Clock(),
    )


def _openai(
    *,
    source_id: str = "line-001",
    amount: str = "10.00",
    currency: str = "USD",
    asset_id: str = ASSET,
    correction_of: str = "",
    correction_reason: str = "",
    start: str = START,
    end: str = END,
) -> cost.NormalizedBillingRecord:
    return cost.OpenAIBillingRecord(
        organization_id="org-enterprise",
        line_item_id=source_id,
        usage_start=start,
        usage_end=end,
        currency=currency,
        cost=amount,
        usage_type="input_tokens",
        usage_amount=("-100" if correction_of else "1000"),
        usage_unit="tokens",
        project_id="project-risk-copilot",
        model="governed-model",
        citation=_citation(source_id),
        registry_asset_id=asset_id,
        correction_of_line_item_id=correction_of,
        correction_reason=correction_reason,
    ).normalize()


def _batch(
    *records: cost.NormalizedBillingRecord,
    batch_id: str = "batch-2026-08",
    collected_at: float = NOW,
    start: str = START,
    end: str = END,
) -> cost.BillingCollection:
    first = records[0]
    return cost.BillingCollection(
        provider=first.provider,
        collector_id=f"{first.provider.value}_billing_export_v1",
        source_account_id=first.source_account_id,
        batch_id=batch_id,
        period_start=start,
        period_end=end,
        collected_at=collected_at,
        manifest_citation=_citation(batch_id),
        records=tuple(records),
    )


def _currency(report: dict, currency: str) -> dict:
    return next(row for row in report["currencies"] if row["currency"] == currency)


@pytest.mark.parametrize(
    ("source", "provider", "account", "record_id", "service", "resource"),
    [
        (
            cost.AWSBillingRecord(
                payer_account_id="123456789012",
                line_item_id="aws-line-1",
                usage_start=START,
                usage_end=END,
                currency="usd",
                unblended_cost="1.230000",
                usage_type="BedrockInputTokens",
                usage_amount="100",
                usage_unit="tokens",
                resource_arn="arn:aws:bedrock:us-east-1:123456789012:model/example",
                product_code="AmazonBedrock",
                citation=_citation("aws"),
            ),
            cost.BillingProvider.AWS,
            "123456789012",
            "aws-line-1",
            "AmazonBedrock",
            "arn:aws:bedrock:us-east-1:123456789012:model/example",
        ),
        (
            cost.AzureBillingRecord(
                billing_account_id="azure-billing-account",
                charge_id="azure-charge-1",
                usage_start=START,
                usage_end=END,
                billing_currency="USD",
                cost_in_billing_currency="2.34",
                meter_name="Input Tokens",
                quantity="200",
                unit_of_measure="tokens",
                resource_id="/subscriptions/sub/resourceGroups/ai/providers/model/one",
                service_name="Azure AI Foundry",
                citation=_citation("azure"),
            ),
            cost.BillingProvider.AZURE,
            "azure-billing-account",
            "azure-charge-1",
            "Azure AI Foundry",
            "/subscriptions/sub/resourceGroups/ai/providers/model/one",
        ),
        (
            cost.GCPBillingRecord(
                billing_account_id="ABCDEF-123456",
                export_row_id="gcp-row-1",
                usage_start=START,
                usage_end=END,
                currency="EUR",
                cost="3.45",
                sku_id="vertex-input-tokens",
                usage_amount="300",
                usage_unit="tokens",
                resource_name="projects/p/locations/us/models/one",
                service_description="Vertex AI",
                citation=_citation("gcp"),
            ),
            cost.BillingProvider.GCP,
            "ABCDEF-123456",
            "gcp-row-1",
            "Vertex AI",
            "projects/p/locations/us/models/one",
        ),
        (
            cost.OpenAIBillingRecord(
                organization_id="org-one",
                line_item_id="openai-line-1",
                usage_start=START,
                usage_end=END,
                currency="USD",
                cost="4.56",
                usage_type="output_tokens",
                usage_amount="400",
                usage_unit="tokens",
                project_id="project-one",
                model="governed-model",
                citation=_citation("openai"),
            ),
            cost.BillingProvider.OPENAI,
            "org-one",
            "openai-line-1",
            "OpenAI governed-model",
            "project-one",
        ),
    ],
)
def test_typed_provider_rows_normalize_without_raw_payload_or_credentials(
    source,
    provider,
    account,
    record_id,
    service,
    resource,
):
    row = source.normalize()

    assert row.provider is provider
    assert row.source_account_id == account
    assert row.source_record_id == record_id
    assert row.service == service
    assert row.resource_id == resource
    assert row.period_start == START
    assert row.period_end == END
    assert row.cost in {"1.23", "2.34", "3.45", "4.56"}
    assert row.payload_sha256 == _hex(json.dumps(row.source_payload, sort_keys=True, separators=(",", ":")))
    assert not {
        "authorization",
        "api_key",
        "credential",
        "password",
        "raw_payload",
    }.intersection(row.source_payload)


def test_citation_rejects_signed_urls_and_decimal_float_inputs():
    with pytest.raises(ValueError, match="query"):
        cost.SourceCitation(
            uri="https://billing.example.test/export?sig=secret",
            sha256=_hex("export"),
        )
    with pytest.raises(ValueError, match="exact decimal"):
        cost.UsageQuantity("tokens", 1.5, "tokens")
    with pytest.raises(ValueError, match="exact decimal"):
        replace(_openai(), cost=1.5)


def test_collector_contract_requires_exact_identity_period_and_bound():
    service = _service(FakeAllocationResolver())
    request = cost.CollectionRequest(period_start=START, period_end=END, max_records=2)
    batch = _batch(_openai())
    collector = FakeCollector(batch)

    with tenant_scope(tenant="acme"):
        receipt = service.collect_and_ingest(collector, request, actor="finops-sync")

    assert collector.requests == [request]
    assert receipt["status"] == "complete"
    assert receipt["record_count"] == 1
    assert receipt["manifest_citation"]["sha256"] == _hex("batch-2026-08")
    assert receipt["observation_bindings"][0]["source_payload_sha256"]

    mismatch = FakeCollector(batch, collector_id="different_collector")
    with tenant_scope(tenant="acme"):
        with pytest.raises(cost.AICostProtocolError, match="identity"):
            service.collect_and_ingest(mismatch, request, actor="finops-sync")


def test_allocations_preserve_exact_cost_and_report_shared_and_unallocated():
    service = _service(FakeAllocationResolver())
    with tenant_scope(tenant="acme"):
        receipt = service.ingest(_batch(_openai()), actor="finops-sync")
        observation = service.get_observation(receipt["observation_ids"][0])
        portfolio = service.portfolio_report(period_start=START, period_end=END)
        department = service.department_report(
            "finance",
            period_start=START,
            period_end=END,
        )
        asset = service.asset_report(ASSET, period_start=START, period_end=END)

    assert observation is not None
    assert sum(
        (cost.Decimal(row["allocated_cost"]) for row in observation["allocations"]),
        cost.Decimal(0),
    ) == cost.Decimal("10")
    usd = _currency(portfolio, "USD")
    assert usd["measured_cost"] == "10"
    assert usd["shared_cost"] == "2"
    assert usd["unallocated_cost"] == "2"
    assert _currency(department, "USD")["measured_cost"] == "6"
    assert _currency(asset, "USD")["measured_cost"] == "6"
    assert portfolio["currency_conversion"] == "not_performed"
    assert portfolio["receipt_ids"] == [receipt["id"]]
    assert portfolio["citations"][0]["citation"]["sha256"] == _hex("line-001")


def test_idempotent_overlapping_batches_and_changed_source_line_conflict():
    service = _service(FakeAllocationResolver())
    original = _openai()
    with tenant_scope(tenant="acme"):
        first = service.ingest(_batch(original), actor="finops-sync")
        replay = service.ingest(
            _batch(original, collected_at=NOW + 100),
            actor="finops-sync",
        )
        overlap = service.ingest(
            _batch(original, batch_id="overlap-export"),
            actor="finops-sync",
        )
        observation = service.get_observation(first["observation_ids"][0])
        with pytest.raises(cost.AICostIdempotencyConflict, match="correction"):
            service.ingest(
                _batch(replace(original, cost="11"), batch_id="changed-export"),
                actor="finops-sync",
            )

    assert first["id"] == replay["id"]
    assert first["revision"] == replay["revision"] == 1
    assert overlap["id"] != first["id"]
    assert overlap["observation_ids"] == first["observation_ids"]
    assert observation is not None and observation["revision"] == 1


def test_batch_replay_identity_is_independent_of_provider_row_order():
    service = _service()
    first_row = _openai(source_id="line-a", asset_id="")
    second_row = _openai(source_id="line-b", amount="2", asset_id="")
    with tenant_scope(tenant="acme"):
        first = service.ingest(
            _batch(first_row, second_row, batch_id="unordered-export"),
            actor="finops-sync",
        )
        replay = service.ingest(
            _batch(
                second_row,
                first_row,
                batch_id="unordered-export",
                collected_at=NOW + 50,
            ),
            actor="finops-sync",
        )

    assert replay["id"] == first["id"]
    assert replay["revision"] == first["revision"] == 1


def test_corrections_are_append_only_and_reuse_original_allocations():
    service = _service(FakeAllocationResolver())
    original = _openai()
    correction = _openai(
        source_id="line-001-adjustment-1",
        amount="-1.25",
        correction_of="line-001",
        correction_reason="Provider-issued billing adjustment",
    )
    with tenant_scope(tenant="acme"):
        base_receipt = service.ingest(_batch(original), actor="finops-sync")
        correction_receipt = service.ingest(
            _batch(correction, batch_id="batch-2026-08-adjustment-1"),
            actor="finops-sync",
        )
        report = service.portfolio_report(period_start=START, period_end=END)
        base = service.get_observation(base_receipt["observation_ids"][0])
        adjustment = service.get_observation(correction_receipt["observation_ids"][0])

    usd = _currency(report, "USD")
    assert usd["original_cost"] == "10"
    assert usd["correction_delta"] == "-1.25"
    assert usd["measured_cost"] == "8.75"
    assert adjustment["correction_of_observation_id"] == base["id"]
    assert [row["fraction"] for row in adjustment["allocations"]] == [
        row["fraction"] for row in base["allocations"]
    ]
    assert base["source_cost"] == "10"
    assert base["revision"] == 1


def test_original_and_correction_can_complete_in_one_provider_batch():
    service = _service(FakeAllocationResolver())
    original = _openai()
    correction = _openai(
        source_id="line-001-adjustment-in-batch",
        amount="-2",
        correction_of="line-001",
        correction_reason="Adjustment included in the closed provider export",
    )
    with tenant_scope(tenant="acme"):
        receipt = service.ingest(
            _batch(correction, original, batch_id="closed-export-with-adjustment"),
            actor="finops-sync",
        )
        report = service.portfolio_report(period_start=START, period_end=END)

    assert receipt["record_count"] == 2
    assert _currency(report, "USD")["measured_cost"] == "8"
    assert _currency(report, "USD")["correction_delta"] == "-2"


def test_correction_requires_completed_original_and_exact_period_currency():
    service = _service(FakeAllocationResolver())
    missing = _openai(
        source_id="adjustment",
        amount="-1",
        correction_of="missing-line",
        correction_reason="Provider adjustment",
    )
    with tenant_scope(tenant="acme"):
        with pytest.raises(cost.AICostStateError, match="completed original"):
            service.ingest(_batch(missing), actor="finops-sync")
        service.ingest(_batch(_openai()), actor="finops-sync")
        mismatch = _openai(
            source_id="adjustment-eur",
            amount="-1",
            currency="EUR",
            correction_of="line-001",
            correction_reason="Provider adjustment",
        )
        with pytest.raises(ValueError, match="currency"):
            service.ingest(
                _batch(mismatch, batch_id="mismatched-adjustment"),
                actor="finops-sync",
            )


def test_multi_currency_cost_and_roi_are_never_conflated():
    service = _service(FakeAllocationResolver())
    usd = _openai()
    eur = replace(
        _openai(source_id="line-eur", amount="5", currency="EUR", asset_id=""),
        source_account_id="org-enterprise",
    )
    with tenant_scope(tenant="acme"):
        service.ingest(_batch(usd), actor="finops-sync")
        service.ingest(_batch(eur, batch_id="eur-export"), actor="finops-sync")
        service.upsert_roi_assumption(
            scenario="approved_business_case",
            scope_kind="portfolio",
            period_start=START,
            period_end=END,
            currency="USD",
            assumed_benefit="30",
            methodology="Operator-approved avoided review hours times loaded rate.",
            rationale="The business case uses the approved August workload forecast.",
            citations=(_citation("business-case-usd"),),
            idempotency_key="assumption-usd-v1",
            expected_revision=0,
            actor="portfolio-owner",
        )
        service.upsert_roi_assumption(
            scenario="approved_business_case",
            scope_kind="portfolio",
            period_start=START,
            period_end=END,
            currency="EUR",
            assumed_benefit="8",
            methodology="Operator-authored scenario; no currency conversion.",
            rationale="A separate EUR business case covers the regional workload.",
            citations=(_citation("business-case-eur"),),
            idempotency_key="assumption-eur-v1",
            expected_revision=0,
            actor="portfolio-owner",
        )
        report = service.portfolio_report(
            period_start=START,
            period_end=END,
            scenario="approved_business_case",
        )

    assert [row["currency"] for row in report["currencies"]] == ["EUR", "USD"]
    assert _currency(report, "USD")["measured_cost"] == "10"
    assert _currency(report, "USD")["assumed_benefit"] == "30"
    assert _currency(report, "USD")["benefit_cost_ratio"] == "3"
    assert _currency(report, "USD")["assumption_roi_percent"] == "200"
    assert _currency(report, "EUR")["measured_cost"] == "5"
    assert _currency(report, "EUR")["assumed_benefit"] == "8"
    assert "total" not in report
    assert report["benefit_basis"] == "operator_assumptions_only"


def test_alternative_scenarios_require_explicit_selection():
    service = _service()
    with tenant_scope(tenant="acme"):
        for scenario, benefit in (("optimistic", "100"), ("pessimistic", "10")):
            service.upsert_roi_assumption(
                scenario=scenario, scope_kind="asset", scope_id=ASSET,
                period_start=START, period_end=END, currency="USD", assumed_benefit=benefit,
                methodology="Hours saved multiplied by loaded cost.",
                rationale="Alternative planning assumption, not a measured result.",
                citations=(_citation(scenario),), idempotency_key=scenario,
                expected_revision=0, actor="business-owner",
            )
        with pytest.raises(ValueError, match="select a scenario"):
            service.asset_report(ASSET, period_start=START, period_end=END)
        report = service.asset_report(ASSET, period_start=START, period_end=END, scenario="pessimistic")
    bucket = _currency(report, "USD")
    assert bucket["assumed_benefit"] == "10"
    assert bucket["assumption_bindings"][0]["scenario"] == "pessimistic"


def test_roi_assumption_replay_conflict_and_stale_cas():
    service = _service()
    kwargs = {
        "scenario": "approved_case",
        "scope_kind": "asset",
        "scope_id": ASSET,
        "period_start": START,
        "period_end": END,
        "currency": "USD",
        "assumed_benefit": "100",
        "methodology": "Approved hours avoided times an operator-entered loaded rate.",
        "rationale": "This is a planning assumption, not a measured outcome.",
        "citations": (_citation("roi-case"),),
        "idempotency_key": "roi-v1",
        "expected_revision": 0,
        "actor": "business-owner",
    }
    with tenant_scope(tenant="acme"):
        first = service.upsert_roi_assumption(**kwargs)
        replay = service.upsert_roi_assumption(**kwargs)
        with pytest.raises(cost.AICostIdempotencyConflict):
            service.upsert_roi_assumption(**{**kwargs, "assumed_benefit": "101"})
        with pytest.raises(RecordConflict):
            service.upsert_roi_assumption(
                **{
                    **kwargs,
                    "assumed_benefit": "120",
                    "idempotency_key": "roi-v2",
                    "expected_revision": 0,
                }
            )
        updated = service.upsert_roi_assumption(
            **{
                **kwargs,
                "assumed_benefit": "120",
                "idempotency_key": "roi-v2",
                "expected_revision": first["revision"],
            }
        )

    assert replay["revision"] == first["revision"] == 1
    assert updated["revision"] == 2
    assert updated["prior_payload_sha256"] == first["payload_sha256"]
    assert updated["evidence_class"] == "operator_assumption"


def test_explicit_tenant_and_isolation_apply_to_costs_receipts_and_assumptions():
    service = _service(FakeAllocationResolver())
    with pytest.raises(cost.AICostStateError, match="explicit tenant"):
        service.ingest(_batch(_openai()), actor="finops-sync")

    with tenant_scope(tenant="acme"):
        acme = service.ingest(_batch(_openai()), actor="finops-sync")
        acme_report = service.portfolio_report(period_start=START, period_end=END)

    with tenant_scope(tenant="globex"):
        assert service.list_receipts() == []
        empty = service.portfolio_report(period_start=START, period_end=END)
        globex = service.ingest(_batch(_openai()), actor="finops-sync")
        globex_report = service.portfolio_report(period_start=START, period_end=END)

    with tenant_scope(tenant="acme"):
        assert service.list_receipts()[0]["id"] == acme["id"]

    assert empty["currencies"] == []
    assert _currency(acme_report, "USD")["measured_cost"] == "10"
    assert _currency(globex_report, "USD")["measured_cost"] == "10"
    assert acme["id"] == globex["id"]
    assert acme["tenant_ref"] != globex["tenant_ref"]


def test_partial_source_period_is_excluded_instead_of_prorated():
    service = _service()
    row = _openai(start="2026-08-15T00:00:00Z", end="2026-09-15T00:00:00Z")
    with tenant_scope(tenant="acme"):
        service.ingest(
            _batch(
                row,
                start="2026-08-01T00:00:00Z",
                end="2026-10-01T00:00:00Z",
            ),
            actor="finops-sync",
        )
        report = service.portfolio_report(period_start=START, period_end=END)

    assert report["currencies"] == []
    assert report["partial_period_observations_excluded"] == 1


def test_report_and_allocation_bounds_fail_closed():
    service = _service()
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="row_limit"):
            service.portfolio_report(period_start=START, period_end=END, row_limit=0)

    class ExcessResolver:
        def resolve(self, _record):
            return tuple(
                cost.RegistryAllocation(
                    kind="shared",
                    fraction="0.01",
                    department=f"department-{index}",
                    basis="test-rule",
                )
                for index in range(33)
            )

    bounded = _service(ExcessResolver())
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="exceeds 32"):
            bounded.ingest(_batch(_openai()), actor="finops-sync")


def test_report_revalidates_receipt_digest_and_allocation_reconciliation():
    service = _service(FakeAllocationResolver())
    with tenant_scope(tenant="acme"):
        receipt = service.ingest(_batch(_openai()), actor="finops-sync")
        observation = service.get_observation(receipt["observation_ids"][0])
        assert observation is not None

        def corrupt(row):
            row["source_cost"] = "999"

        service._observations.update(  # noqa: SLF001 - deliberate corruption proof
            observation["id"],
            corrupt,
            expected_revision=observation["revision"],
            action="test_corrupt_ai_cost",
            actor="test",
        )
        with pytest.raises(cost.AICostStateError, match="payload digest"):
            service.portfolio_report(period_start=START, period_end=END)
