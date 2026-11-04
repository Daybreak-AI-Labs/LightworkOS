from __future__ import annotations

import json

import pytest
from maverick.tools.finance_anomaly import finance_anomaly


def _transactions():
    return [
        {
            "transaction_id": "tx-1",
            "amount": "1250.00",
            "currency": "USD",
            "posted_at": "2026-07-22T03:00:00Z",
            "source_system": "erp-ap",
            "source_record_id": "payment/1",
            "counterparty_id": "vendor-1",
            "invoice_id": "INV-9",
        },
        {
            "transaction_id": "tx-2",
            "amount": "1250.00",
            "currency": "USD",
            "posted_at": "2026-07-22T03:05:00Z",
            "source_system": "erp-ap",
            "source_record_id": "payment/2",
            "counterparty_id": "vendor-1",
            "invoice_id": "INV-9",
        },
    ]


def test_tool_scans_and_enqueues_same_stable_cases_as_core(tmp_path, monkeypatch):
    from maverick import governed_records
    from maverick.finance import anomaly_engine
    from maverick.tools import finance_anomaly as tool_module

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setattr(tool_module, "_operations_enabled", lambda: True)

    result = json.loads(finance_anomaly().fn({"transactions": _transactions()}))

    assert result["finding_count"] >= 3
    assert result["enqueued_case_ids"]
    assert result["workspace"] == "/finance"
    report = anomaly_engine.scan_transactions(_transactions())
    expected = anomaly_engine.FinanceAnomalyCaseQueue().enqueue(
        report.findings[0],
        opened_by="agent:finance_anomaly",
    )
    assert expected["id"] in result["enqueued_case_ids"]


def test_tool_is_fail_closed_when_finance_operations_are_disabled(monkeypatch):
    from maverick.tools import finance_anomaly as tool_module

    monkeypatch.setattr(tool_module, "_operations_enabled", lambda: False)
    output = finance_anomaly().fn({"transactions": _transactions()})
    assert output.startswith("ERROR: enable [finance_operations]")


def test_tool_is_registered_and_not_parallel_safe():
    from maverick.tools import base_registry

    class _World:
        pass

    class _Sandbox:
        workdir = "."

    tool = base_registry(world=_World(), sandbox=_Sandbox()).get(
        "scan_finance_anomalies"
    )
    assert tool is not None
    assert tool.parallel_safe is False


def test_tool_config_schema_and_parser_bound_nested_collections():
    from maverick.tools.finance_anomaly import _config, finance_anomaly

    schema = finance_anomaly().input_schema["properties"]["config"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["approval_thresholds"]["maxItems"] == 128
    assert schema["properties"]["business_days"]["maxItems"] == 7

    with pytest.raises(ValueError, match="at most 128"):
        _config({"approval_thresholds": [{}] * 129})
    with pytest.raises(ValueError, match="at most 7"):
        _config({"business_days": list(range(8))})
    with pytest.raises(ValueError, match="contain only"):
        _config({
            "approval_thresholds": [{
                "threshold_id": "ap-1",
                "currency": "USD",
                "amount": "1000",
                "policy_ref": "urn:policy:ap-1",
                "nested": {"unbounded": []},
            }]
        })
