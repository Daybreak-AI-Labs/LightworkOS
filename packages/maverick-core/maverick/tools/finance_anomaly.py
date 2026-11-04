"""Bounded tool bridge from the finance-anomaly agent to the governed queue."""
from __future__ import annotations

import json
from datetime import time
from typing import Any

from . import Tool

_MAX_TOOL_SIGNALS = 100
_MAX_APPROVAL_THRESHOLDS = 128


def _operations_enabled() -> bool:
    from ..finance.anomaly_engine import enabled

    return enabled()


def _config(raw: object):
    from ..finance.anomaly_engine import ApprovalThreshold, FinanceAnomalyConfig

    if raw in (None, {}):
        return FinanceAnomalyConfig()
    if not isinstance(raw, dict):
        raise ValueError("config must be an object")
    values = dict(raw)
    allowed = set(FinanceAnomalyConfig.__dataclass_fields__)
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unsupported config fields: {', '.join(sorted(unknown))}")
    if "approval_thresholds" in values:
        thresholds = values["approval_thresholds"]
        if not isinstance(thresholds, list):
            raise ValueError("approval_thresholds must be a list")
        if len(thresholds) > _MAX_APPROVAL_THRESHOLDS:
            raise ValueError(
                f"approval_thresholds must contain at most {_MAX_APPROVAL_THRESHOLDS} rows"
            )
        allowed_threshold = {"threshold_id", "currency", "amount", "policy_ref"}
        if any(
            not isinstance(row, dict) or set(row) != allowed_threshold
            for row in thresholds
        ):
            raise ValueError(
                "each approval threshold must contain only threshold_id, currency, "
                "amount, and policy_ref"
            )
        values["approval_thresholds"] = tuple(
            ApprovalThreshold(**row) for row in thresholds
        )
    for name in ("business_start", "business_end"):
        if name in values and isinstance(values[name], str):
            if len(values[name]) > 32:
                raise ValueError(f"{name} exceeds 32 characters")
            try:
                values[name] = time.fromisoformat(values[name])
            except ValueError as exc:
                raise ValueError(f"{name} must be an ISO local time") from exc
    if "business_days" in values:
        days = values["business_days"]
        if not isinstance(days, list) or len(days) > 7:
            raise ValueError("business_days must be a list of at most 7 weekdays")
        values["business_days"] = tuple(days)
    return FinanceAnomalyConfig(**values)


def _run(args: dict[str, Any]) -> str:
    if not _operations_enabled():
        return (
            "ERROR: enable [finance_operations] and anomaly_enable before scanning "
            "finance anomalies"
        )
    transactions = args.get("transactions")
    if not isinstance(transactions, list):
        return "ERROR: transactions must be a list"
    try:
        from ..connections import current_principal
        from ..finance.anomaly_engine import (
            FinanceAnomalyCaseQueue,
            FinanceAnomalyInputLimit,
            finding_to_signal,
            scan_transactions,
            with_configured_materiality,
        )

        report = scan_transactions(
            transactions,
            config=with_configured_materiality(_config(args.get("config"))),
        )
        actor = str(current_principal() or "agent:finance_anomaly")
        cases = []
        if args.get("enqueue_findings", True) is True:
            queue = FinanceAnomalyCaseQueue()
            cases = [queue.enqueue(finding, opened_by=actor) for finding in report.findings]
        signals = [finding_to_signal(finding).to_dict() for finding in report.findings]
    except (FinanceAnomalyInputLimit, KeyError, TypeError, ValueError) as exc:
        return f"ERROR: invalid finance anomaly scan: {exc}"
    except Exception:
        return "ERROR: finance anomaly scan failed safely"

    result = {
        "schema": "lightwork.finance-anomaly-tool-result.v1",
        "transactions_scanned": report.transactions_scanned,
        "input_sha256": report.input_sha256,
        "config_sha256": report.config_sha256,
        "scan_sha256": report.scan_sha256,
        "config": report.config,
        "finding_count": len(report.findings),
        "signals": signals[:_MAX_TOOL_SIGNALS],
        "signals_truncated": len(signals) > _MAX_TOOL_SIGNALS,
        "scan_truncated": report.truncated,
        "omitted_findings": report.omitted_findings,
        "evaluations": [row.to_dict() for row in report.evaluations],
        "enqueued_case_ids": [str(row["id"]) for row in cases[:_MAX_TOOL_SIGNALS]],
        "case_ids_truncated": len(cases) > _MAX_TOOL_SIGNALS,
        "workspace": "/finance",
    }
    return json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


_TRANSACTION = {
    "type": "object",
    "properties": {
        "transaction_id": {"type": "string", "minLength": 1, "maxLength": 200},
        "amount": {"type": ["string", "number"]},
        "currency": {"type": "string", "minLength": 3, "maxLength": 3},
        "posted_at": {"type": "string", "minLength": 1, "maxLength": 100},
        "source_system": {"type": "string", "minLength": 1, "maxLength": 128},
        "source_record_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "counterparty_id": {"type": "string", "maxLength": 256},
        "counterparty_name": {"type": "string", "maxLength": 512},
        "invoice_id": {"type": "string", "maxLength": 256},
        "reference": {"type": "string", "maxLength": 512},
        "source_uri": {"type": "string", "maxLength": 2048},
        "source_sha256": {"type": "string", "maxLength": 64},
    },
    "required": [
        "transaction_id", "amount", "currency", "posted_at",
        "source_system", "source_record_id",
    ],
    "additionalProperties": False,
}

_APPROVAL_THRESHOLD = {
    "type": "object",
    "properties": {
        "threshold_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "currency": {"type": "string", "pattern": "^[A-Za-z]{3}$"},
        "amount": {"type": ["string", "number"]},
        "policy_ref": {"type": "string", "minLength": 1, "maxLength": 1024},
    },
    "required": ["threshold_id", "currency", "amount", "policy_ref"],
    "additionalProperties": False,
}

_CONFIG = {
    "type": "object",
    "properties": {
        "max_transactions": {"type": "integer", "minimum": 1, "maximum": 10_000},
        "max_findings": {"type": "integer", "minimum": 1, "maximum": 5_000},
        "duplicate_window_hours": {"type": "integer", "minimum": 1, "maximum": 744},
        "benford_population_eligible": {"type": "boolean"},
        "benford_min_sample": {"type": "integer", "minimum": 50, "maximum": 10_000},
        "benford_min_orders": {"type": "integer", "minimum": 2, "maximum": 10},
        "benford_mad_threshold": {"type": ["string", "number"]},
        "approval_thresholds": {
            "type": "array",
            "maxItems": _MAX_APPROVAL_THRESHOLDS,
            "items": _APPROVAL_THRESHOLD,
        },
        "threshold_near_fraction": {"type": ["string", "number"]},
        "threshold_split_min_fraction": {"type": ["string", "number"]},
        "threshold_window_hours": {"type": "integer", "minimum": 1, "maximum": 744},
        "business_timezone": {"type": "string", "minLength": 1, "maxLength": 128},
        "business_start": {"type": "string", "minLength": 1, "maxLength": 32},
        "business_end": {"type": "string", "minLength": 1, "maxLength": 32},
        "business_days": {
            "type": "array",
            "maxItems": 7,
            "uniqueItems": True,
            "items": {"type": "integer", "minimum": 0, "maximum": 6},
        },
    },
    "additionalProperties": False,
}

_SCHEMA = {
    "type": "object",
    "properties": {
        "transactions": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10_000,
            "items": _TRANSACTION,
        },
        "config": _CONFIG,
        "enqueue_findings": {"type": "boolean", "default": True},
    },
    "required": ["transactions"],
    "additionalProperties": False,
}


def finance_anomaly() -> Tool:
    return Tool(
        name="scan_finance_anomalies",
        description=(
            "Run deterministic duplicate-payment, Benford, approval-threshold, "
            "split-payment, and off-hours rules over bounded cited transactions. "
            "Findings are enqueued in the governed /finance review workspace by default."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=False,
    )


__all__ = ["finance_anomaly"]
