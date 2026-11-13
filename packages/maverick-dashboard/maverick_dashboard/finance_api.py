"""Permission-tiered REST surface for deterministic finance operations.

The router is mounted below ``/api/v1`` by :mod:`maverick_dashboard.api`.
Viewer access is deliberately limited to aggregates and list metadata. Case
evidence, regulatory text, and screening results require tenant ``operate``;
source ingestion and manual GRC cycle execution require global ``admin``.
"""
from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from . import finance_schemas as schemas
from .auth import require_global_permission, require_permission, require_suite

log = logging.getLogger(__name__)

_SUMMARY_SCAN_LIMIT = 50
_QUEUE_PAGE_LIMIT = 25
_AML_LIST_METADATA_LIMIT = 500


def _require_finance_suite(request: Request) -> None:
    require_suite(request, "finance")


router = APIRouter(
    prefix="/finance-operations",
    tags=["finance-operations"],
    dependencies=[Depends(_require_finance_suite)],
)


def _actor(request: Request) -> str:
    from .request_identity import request_actor as _request_actor

    return _request_actor(request)


def _ensure_enabled() -> None:
    from maverick.finance import aml_screening

    if not aml_screening.enabled():
        raise HTTPException(
            status_code=403,
            detail="finance operations are disabled ([finance_operations] enable)",
        )


def _ensure_anomaly_enabled() -> None:
    from maverick.finance.anomaly_engine import enabled

    if not enabled():
        raise HTTPException(status_code=403, detail="finance anomaly scanning is disabled")


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


async def _call(fn: Callable, *args, **kwargs):
    """Run a synchronous core operation with stable, non-leaking failures."""
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except HTTPException:
        raise
    except Exception as exc:
        from maverick.privacy_ops import RecordConflict

        if isinstance(exc, RecordConflict):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if isinstance(exc, KeyError):
            raise HTTPException(status_code=404, detail="no such finance record") from exc
        if isinstance(exc, (TypeError, ValueError)):
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            from maverick.finance.anomaly_engine import (
                FinanceAnomalyError,
                FinanceAnomalyInputLimit,
                FourEyesRequired,
            )

            expected = (FinanceAnomalyError, FinanceAnomalyInputLimit, FourEyesRequired)
        except ImportError:  # pragma: no cover - packaging failure follows 503 path
            expected = ()
        if isinstance(exc, expected):
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        log.exception("finance operation failed")
        raise HTTPException(
            status_code=503,
            detail="finance operation failed safely",
        ) from exc


async def _record_call(fn: Callable, *args, **kwargs) -> dict[str, Any]:
    result = await _call(fn, *args, **kwargs)
    if result is None:
        raise HTTPException(status_code=404, detail="no such finance record")
    return _jsonable(result)


def _regulatory_engine():
    from maverick.finance.regulatory_change import RegulatoryChangeEngine
    from maverick.paths import data_dir

    return RegulatoryChangeEngine(
        data_dir("finance_operations", "regulatory_change.sqlite3")
    )


def _anomaly_queue():
    from maverick.finance.anomaly_engine import FinanceAnomalyCaseQueue

    return FinanceAnomalyCaseQueue()


def _status_counts(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("status") or "unknown") for row in rows).items()))


def _screening_list_metadata(record: Mapping[str, Any]) -> dict[str, Any]:
    """Strip names and aliases: metadata endpoints never return list entries."""
    safe_keys = (
        "id",
        "schema",
        "status",
        "list_kind",
        "source_name",
        "version",
        "fingerprint",
        "content_sha256",
        "parser_version",
        "entry_count",
        "provenance",
        "notice",
        "revision",
        "created_at",
        "updated_at",
    )
    return {key: _jsonable(record[key]) for key in safe_keys if key in record}


def _screening_case_metadata(record: Mapping[str, Any]) -> dict[str, Any]:
    """Project queue metadata without subject names, hits, or rationale text."""

    safe_keys = (
        "id",
        "schema",
        "status",
        "fingerprint",
        "series_fingerprint",
        "generation",
        "previous_case_id",
        "screened_by",
        "rule_version",
        "revision",
        "created_at",
        "updated_at",
    )
    result = {key: _jsonable(record[key]) for key in safe_keys if key in record}
    hits = record.get("hits")
    dispositions = record.get("dispositions")
    result["hit_count"] = len(hits) if isinstance(hits, list) else 0
    result["disposition_count"] = len(dispositions) if isinstance(dispositions, list) else 0
    return result


def _licensing_metadata(pack) -> dict[str, Any]:
    determinations = Counter(row.determination for row in pack.requirements)
    return {
        "vertical": pack.vertical,
        "version": pack.version,
        "as_of": pack.as_of,
        "title": pack.title,
        "methodology": pack.methodology,
        "jurisdictions": len(pack.requirements),
        "determinations": dict(sorted(determinations.items())),
        "content_sha256": pack.content_sha256,
    }


# Viewer-safe overview -----------------------------------------------------


@router.get("/summary")
async def finance_operations_summary(request: Request) -> dict[str, Any]:
    """Counts and readiness only; no entity, transaction, or case text."""
    require_permission(request, "view")
    _ensure_enabled()

    def _summary() -> dict[str, Any]:
        from maverick.finance import aml_screening, control_testing
        from maverick.finance.licensing import load_licensing_pack

        regulatory_counts = _regulatory_engine().alert_status_counts()
        anomaly = _anomaly_queue().case_status_summary(
            scan_limit=_SUMMARY_SCAN_LIMIT,
        )
        list_rows = aml_screening.list_versions(limit=1_001)
        lists = list_rows[:1_000]
        aml_case_rows = aml_screening.list_cases(limit=_QUEUE_PAGE_LIMIT + 1)
        aml_cases = aml_case_rows[:_QUEUE_PAGE_LIMIT]
        cycles = control_testing.cycle_status_summary(
            scan_limit=_SUMMARY_SCAN_LIMIT,
        )
        packs = [
            load_licensing_pack("money_transmitter"),
            load_licensing_pack("insurance_producer"),
        ]
        return {
            "enabled": True,
            "regulatory_alerts": {
                "total": sum(regulatory_counts.values()),
                "by_status": regulatory_counts,
                "count_is_exact": True,
            },
            "licensing_packs": {
                "total": len(packs),
                "jurisdictions": sum(len(pack.requirements) for pack in packs),
            },
            "anomaly_cases": anomaly,
            "aml": {
                "list_versions": len(lists),
                "list_entries": sum(int(row.get("entry_count") or 0) for row in lists),
                "cases": len(aml_cases),
                "cases_by_status": _status_counts(aml_cases),
                "list_version_count_cap": 1_000,
                "case_count_cap": _QUEUE_PAGE_LIMIT,
                "list_versions_truncated": len(list_rows) > 1_000,
                "cases_truncated": len(aml_case_rows) > _QUEUE_PAGE_LIMIT,
            },
            "control_cycles": cycles,
        }

    return await _call(_summary)


# Regulatory change -------------------------------------------------------


@router.get("/regulatory/alerts")
async def regulatory_alerts(
    request: Request,
    status: str | None = Query(
        None,
        pattern=r"^(open|in_review|accepted|dismissed|inactive)$",
    ),
    limit: int = Query(_QUEUE_PAGE_LIMIT, ge=1, le=_QUEUE_PAGE_LIMIT),
    cursor: str | None = Query(None, max_length=512),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()

    def _list():
        return _regulatory_engine().list_alert_summary_page(
            status=status,
            limit=limit,
            cursor=cursor,
        )

    page = await _call(_list)
    return page


@router.get("/regulatory/alerts/{alert_id}")
async def regulatory_alert_detail(request: Request, alert_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()

    def _detail():
        engine = _regulatory_engine()
        alert = engine.get_alert(alert_id)
        if alert is None:
            return None
        return alert, engine.alert_review_history(alert_id, limit=500)

    detail = await _call(_detail)
    if detail is None:
        raise HTTPException(status_code=404, detail="no such regulatory alert")
    alert, history = detail
    return {"alert": _jsonable(alert), "review_history": _jsonable(history)}


@router.post("/regulatory/alerts/{alert_id}/review")
async def review_regulatory_alert(
    request: Request,
    alert_id: str,
    body: schemas.RegulatoryAlertReviewIn,
) -> dict[str, Any]:
    require_permission(request, "operate", api_scope="approvals:decide")
    _ensure_enabled()
    actor = _actor(request)

    def _review():
        return _regulatory_engine().disposition_alert(
            alert_id,
            status=body.status,
            reviewer=actor,
            note=body.note,
            expected_revision=body.expected_revision,
        )

    return _jsonable(await _call(_review))


@router.post("/regulatory/feeds/ingest")
async def ingest_regulatory_feed(
    request: Request,
    body: schemas.RegulatoryFeedIngestIn,
) -> dict[str, Any]:
    """Ingest only caller-supplied bytes and an explicit official source.

    The regime and domain scopes come from the tenant's configuration; the
    body's ``enabled_regimes`` and ``enabled_domains`` are ignored.
    """
    require_global_permission(request, "admin")
    _ensure_enabled()
    actor = _actor(request)

    def _ingest():
        from maverick.config import load_config
        from maverick.finance.regulatory_change import FeedSource

        from maverick_dashboard.finance_scheduler import _scopes, _section

        source = FeedSource(**body.source.model_dump())
        config = load_config() or {}
        enabled_regimes, enabled_domains = _scopes(config, _section(config))
        return _regulatory_engine().ingest(
            source,
            body.payload,
            enabled_regimes=enabled_regimes,
            enabled_domains=enabled_domains,
            acquisition="operator_supplied",
            acquired_by=actor,
        )

    return _jsonable(await _call(_ingest))


# Licensing packs ---------------------------------------------------------


@router.get("/licensing/packs")
async def licensing_packs(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    _ensure_enabled()

    def _packs():
        from maverick.finance.licensing import load_licensing_pack

        return [
            _licensing_metadata(load_licensing_pack("money_transmitter")),
            _licensing_metadata(load_licensing_pack("insurance_producer")),
        ]

    return {"packs": await _call(_packs)}


@router.get("/licensing/packs/{vertical}")
async def licensing_pack_detail(
    request: Request,
    vertical: str,
    version: str | None = Query(None, max_length=64),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance.licensing import load_licensing_pack

    pack = await _call(load_licensing_pack, vertical, version)
    return {"pack": _licensing_metadata(pack)}


@router.get("/licensing/packs/{vertical}/register")
async def licensing_register_projection(
    request: Request,
    vertical: str,
    version: str | None = Query(None, max_length=64),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance.licensing import load_licensing_pack

    pack = await _call(load_licensing_pack, vertical, version)
    return {
        "pack": _licensing_metadata(pack),
        "records": _jsonable(pack.register_records()),
    }


# Finance anomaly screening ----------------------------------------------


@router.post("/anomalies/scan")
async def scan_finance_anomalies(
    request: Request,
    body: schemas.FinanceAnomalyScanIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    _ensure_anomaly_enabled()
    actor = _actor(request)

    def _scan():
        from maverick.finance import anomaly_engine as anomaly

        config_data = body.config.model_dump()
        config_data["approval_thresholds"] = tuple(
            anomaly.ApprovalThreshold(**row.model_dump())
            for row in body.config.approval_thresholds
        )
        config_data["business_days"] = tuple(body.config.business_days)
        config = anomaly.with_configured_materiality(
            anomaly.FinanceAnomalyConfig(**config_data)
        )
        transactions = [
            anomaly.FinanceTransaction.from_mapping(row.model_dump())
            for row in body.transactions
        ]
        report = anomaly.scan_transactions(transactions, config=config)
        cases = []
        if body.enqueue_findings:
            queue = _anomaly_queue()
            cases = [queue.enqueue(finding, opened_by=actor) for finding in report.findings]
        return {"report": report.to_dict(), "cases": cases}

    return await _call(_scan)


@router.get("/anomalies/cases")
async def anomaly_cases(
    request: Request,
    status: str | None = Query(None, pattern=r"^(open|in_review|dispositioned|closed)$"),
    limit: int = Query(_QUEUE_PAGE_LIMIT, ge=1, le=_QUEUE_PAGE_LIMIT),
    cursor: str | None = Query(None, max_length=512),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    page = await _call(
        _anomaly_queue().list_case_summary_page,
        status=status,
        limit=limit,
        cursor=cursor,
    )
    result = page.to_dict()
    result["projection"] = "summary"
    return result


@router.get("/anomalies/cases/{case_id}")
async def anomaly_case_detail(request: Request, case_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    return await _record_call(_anomaly_queue().get, case_id)


@router.post("/anomalies/cases/{case_id}/disposition")
async def disposition_anomaly_case(
    request: Request,
    case_id: str,
    body: schemas.FinanceCaseDispositionIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    queue = _anomaly_queue()
    if await _call(queue.get, case_id) is None:
        raise HTTPException(status_code=404, detail="no such finance anomaly case")
    return await _record_call(
        queue.record_disposition,
        case_id,
        outcome=body.outcome,
        rationale=body.rationale,
        human_actor=_actor(request),
        expected_revision=body.expected_revision,
    )


@router.post("/anomalies/cases/{case_id}/closure")
async def close_anomaly_case(
    request: Request,
    case_id: str,
    body: schemas.FinanceCaseClosureIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    queue = _anomaly_queue()
    if await _call(queue.get, case_id) is None:
        raise HTTPException(status_code=404, detail="no such finance anomaly case")
    return await _record_call(
        queue.close_case,
        case_id,
        rationale=body.rationale,
        human_actor=_actor(request),
        expected_revision=body.expected_revision,
    )


# AML/KYC/watchlist screening --------------------------------------------


@router.get("/aml/lists")
async def aml_list_versions(
    request: Request,
    list_kind: str | None = Query(
        None, pattern=r"^(sanctions|pep|internal_watchlist|kyc)$"
    ),
    limit: int = Query(
        _AML_LIST_METADATA_LIMIT,
        ge=1,
        le=_AML_LIST_METADATA_LIMIT,
    ),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import aml_screening

    rows = await _call(aml_screening.list_versions, list_kind=list_kind, limit=limit)
    return {"lists": [_screening_list_metadata(row) for row in rows]}


@router.get("/aml/lists/{list_id}")
async def aml_list_detail(request: Request, list_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import aml_screening

    row = await _record_call(aml_screening.get_list, list_id)
    return _screening_list_metadata(row)


@router.post("/aml/lists/ingest")
async def ingest_aml_list(
    request: Request,
    body: schemas.AMLListIngestIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _ensure_enabled()
    from maverick.finance import aml_screening

    row = await _record_call(
        aml_screening.ingest_list,
        **body.model_dump(),
        ingested_by=_actor(request),
    )
    return _screening_list_metadata(row)


@router.post("/aml/screen")
async def screen_aml_subject(
    request: Request,
    body: schemas.AMLScreenIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import aml_screening

    return await _call(
        aml_screening.screen_subject,
        body.subject_name,
        screened_by=_actor(request),
        subject_ref=body.subject_ref,
        list_ids=body.list_ids,
    )


@router.get("/aml/cases")
async def aml_cases(
    request: Request,
    status: str | None = Query(
        None,
        pattern=(
            r"^(open|pending_second_review|pending_adjudication_review|"
            r"review_required|cleared|escalated)$"
        ),
    ),
    limit: int = Query(_QUEUE_PAGE_LIMIT, ge=1, le=_QUEUE_PAGE_LIMIT),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import aml_screening

    rows = await _call(
        aml_screening.list_cases,
        status=status,
        limit=limit + 1,
    )
    return {
        "cases": [_screening_case_metadata(row) for row in rows[:limit]],
        "count_cap": limit,
        "truncated": len(rows) > limit,
        "projection": "summary",
        "page_scope": "bounded_first_page",
    }


@router.get("/aml/cases/{case_id}")
async def aml_case_detail(request: Request, case_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import aml_screening

    return await _record_call(aml_screening.get_case, case_id)


@router.post("/aml/cases/{case_id}/disposition")
async def disposition_aml_case(
    request: Request,
    case_id: str,
    body: schemas.AMLCaseDispositionIn,
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import aml_screening

    if await _call(aml_screening.get_case, case_id) is None:
        raise HTTPException(status_code=404, detail="no such AML screening case")
    return await _record_call(
        aml_screening.record_disposition,
        case_id,
        decision=body.decision,
        rationale=body.rationale,
        decided_by=_actor(request),
        expected_revision=body.expected_revision,
    )


# GRC control-testing loop ------------------------------------------------


@router.get("/control-cycles")
async def control_cycles(
    request: Request,
    limit: int = Query(_QUEUE_PAGE_LIMIT, ge=1, le=_QUEUE_PAGE_LIMIT),
    cursor: str | None = Query(None, max_length=512),
) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import control_testing

    return await _call(
        control_testing.list_cycle_summaries,
        limit=limit,
        cursor=cursor,
    )


@router.get("/control-cycles/{cycle_id}")
async def control_cycle_detail(request: Request, cycle_id: str) -> dict[str, Any]:
    require_permission(request, "operate")
    _ensure_enabled()
    from maverick.finance import control_testing

    return await _record_call(control_testing.get_cycle, cycle_id)


@router.post("/control-cycles/{cycle_id}/reconcile")
async def reconcile_control_cycle(request: Request, cycle_id: str) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _ensure_enabled()
    from maverick.finance import control_testing

    return await _record_call(
        control_testing.reconcile_control_cycle,
        cycle_id,
        actor=_actor(request),
    )


@router.post("/control-cycles/trigger")
async def trigger_control_cycle(
    request: Request,
    body: schemas.ControlCycleTriggerIn,
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    _ensure_enabled()
    from maverick.finance import control_testing

    return await _record_call(
        control_testing.run_control_cycle,
        actor=_actor(request),
        **body.model_dump(exclude_none=True),
    )


__all__ = ["router"]
