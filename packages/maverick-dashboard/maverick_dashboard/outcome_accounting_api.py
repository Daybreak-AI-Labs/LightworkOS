"""Read-only in-app projection of complete outcome accounting records."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick import config
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES, default_service
from maverick.outcome_value_reporting import OutcomeValueReporting
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool

from . import outcome_accounting_bridge
from .auth import caller_principal, constant_time_equals, has_permission, require_permission
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/outcome-accounting", tags=["outcome-accounting"])

_EXPORT_ENVELOPE_SCHEMA = "lightwork.outcome-value-export-envelope.v1"
_EXPORT_CANONICALIZATION = "lightwork.canonical-json-tree-f64-utf8hex.v1"
_EXPORT_EXCLUDED_FIELDS = ["context", "export_envelope.digest_sha256"]
_MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
_MANAGED_COST_SOURCE_PREFIXES = (
    "outcome-accounting:", "outcome-pilot:", "provider-cap:",
)


class StrictIn(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, str_strip_whitespace=True, allow_inf_nan=False,
    )


class CoverageDeclarationIn(StrictIn):
    status: Literal["included", "zero", "unknown"]
    note: str = Field(..., min_length=1, max_length=1000)


class BaselineIn(StrictIn):
    expected_revision: int = Field(..., ge=0)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    cost_basis: Literal["estimated", "observed", "unknown"]
    cost_amount: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,17})(\.[0-9]{1,12})?$")
    currency: str | None = Field(None, pattern=r"^[A-Z]{3}$")
    cost_unknown_reason: str | None = Field(None, min_length=1, max_length=1000)
    human_basis: Literal["estimated", "observed", "unknown"]
    human_minutes: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,12})(\.[0-9]{1,6})?$")
    human_unknown_reason: str | None = Field(None, min_length=1, max_length=1000)
    source_ref: str = Field(..., min_length=1, max_length=512)
    evidence_note: str = Field(..., min_length=1, max_length=4000)
    correction_reason: str | None = Field(None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def components_match_basis(self):
        if self.cost_basis == "unknown":
            if self.cost_amount is not None or self.currency is not None or self.cost_unknown_reason is None:
                raise ValueError("Unknown baseline cost requires a reason and no amount or currency.")
        elif self.cost_amount is None or self.currency is None or self.cost_unknown_reason is not None:
            raise ValueError("Known baseline cost requires amount and currency without an unknown reason.")
        if self.human_basis == "unknown":
            if self.human_minutes is not None or self.human_unknown_reason is None:
                raise ValueError("Unknown baseline time requires a reason and no minutes.")
        elif self.human_minutes is None or self.human_unknown_reason is not None:
            raise ValueError("Known baseline time requires minutes without an unknown reason.")
        return self


class CommercialIn(StrictIn):
    expected_revision: int = Field(..., ge=0)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    kind: Literal["renewal", "expansion"]
    stage: Literal["planned", "proposed", "observed", "won", "lost"]
    basis: Literal["estimated", "observed", "unknown"]
    amount: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,17})(\.[0-9]{1,12})?$")
    currency: str | None = Field(None, pattern=r"^[A-Z]{3}$")
    unknown_reason: str | None = Field(None, min_length=1, max_length=1000)
    source_ref: str = Field(..., min_length=1, max_length=512)
    note: str = Field(..., min_length=1, max_length=4000)
    correction_reason: str | None = Field(None, min_length=1, max_length=2000)

    @model_validator(mode="after")
    def amount_matches_basis(self):
        if self.basis == "unknown":
            if self.amount is not None or self.currency is not None or self.unknown_reason is None:
                raise ValueError("Unknown commercial value requires a reason and no amount or currency.")
        elif self.amount is None or self.currency is None or self.unknown_reason is not None:
            raise ValueError("Known commercial value requires amount and currency without an unknown reason.")
        return self


class CostIn(StrictIn):
    expected_revision: int = Field(..., ge=1)
    operation_id: str = Field(..., min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    category: Literal[
        "allocation", "evaluation", "exception", "generation", "human", "inference",
        "other", "retrieval", "review", "rework", "retry", "search", "setup",
        "storage", "support", "update",
    ]
    attempt_state: Literal["cancelled", "failed", "succeeded", "unknown"]
    basis: Literal["estimated", "observed", "unknown"]
    total_relationship: Literal[
        "included_in_current_total", "additional_to_current_total",
    ] = "included_in_current_total"
    amount: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,17})(\.[0-9]{1,12})?$")
    currency: str | None = Field(None, pattern=r"^[A-Z]{3}$")
    unknown_reason: str | None = Field(None, min_length=1, max_length=1000)
    quantity: str | None = Field(None, pattern=r"^(0|[1-9][0-9]{0,17})(\.[0-9]{1,12})?$")
    unit: str | None = Field(None, min_length=1, max_length=32)
    source_ref: str = Field(..., min_length=1, max_length=512)
    evidence_note: str = Field(..., min_length=1, max_length=4000)
    allocation_method: Literal[
        "direct", "equal_share", "operator_estimate", "unattributed", "usage_weighted",
    ] = "direct"
    allocation_assumption: str | None = Field(None, min_length=1, max_length=2000)
    correction_reason: str | None = Field(None, min_length=1, max_length=2000)
    complete_coverage: bool = False
    coverage_declarations: dict[str, CoverageDeclarationIn] | None = None

    @model_validator(mode="after")
    def cost_fields_reconcile(self):
        if self.basis == "unknown":
            if self.amount is not None or self.currency is not None or self.unknown_reason is None:
                raise ValueError("Unknown cost requires a reason and no amount or currency.")
        elif self.amount is None or self.currency is None or self.unknown_reason is not None:
            raise ValueError("Known cost requires amount and currency without an unknown reason.")
        if (self.quantity is None) is not (self.unit is None):
            raise ValueError("Cost quantity and unit must be supplied together.")
        if self.allocation_method != "direct" and self.allocation_assumption is None:
            raise ValueError("A shared or estimated allocation requires its assumption.")
        declarations = self.coverage_declarations
        if declarations is not None and set(declarations) != set(COST_COVERAGE_FAMILIES):
            raise ValueError("Cost coverage must declare every required family exactly once.")
        if self.complete_coverage:
            if self.total_relationship == "included_in_current_total":
                raise ValueError(
                    "Included detail cannot itself declare complete cost coverage."
                )
            if declarations is None:
                raise ValueError("Complete coverage requires every cost-family declaration.")
            if any(row.status == "unknown" for row in declarations.values()):
                raise ValueError("Complete coverage cannot leave a cost family unknown.")
        return self


def _scope(request: Request, *, mutation: bool = False) -> tuple[str | None, str]:
    require_permission(request, "operate" if mutation else "view")
    if (
        config.config_source_errors(include_tenant=True)
        or config.get_features().get("outcome_measurement") is not True
    ):
        raise HTTPException(
            403,
            "Outcome measurement is disabled in Settings or configuration is unavailable.",
        )
    context = context_for(request)
    supplied = request.headers.get("X-Lightwork-Pilot-Context")
    if (mutation or supplied is not None) and not constant_time_equals(supplied or "", context):
        raise HTTPException(
            409,
            "Your account or workspace changed. Reload outcome accounting before continuing.",
        )
    principal = caller_principal(request)
    owner = None if principal is None or has_permission(request, "admin") else principal
    return owner, context


def _values() -> OutcomeValueReporting:
    # Keep tests, tenant selection, and runtime overrides bound to the same
    # accounting authority selected by this API module.
    return OutcomeValueReporting(accounting=default_service)


def _caller_owns(request: Request, record: dict) -> bool:
    """Whether a read may refresh this exact principal-owned record."""

    # Auth-off and static-token dashboard requests intentionally have no named
    # principal; records created through those supported local app modes use
    # the explicit local dashboard owner. Keep that identity narrow so an
    # admin viewing another named principal still cannot mutate their ledger.
    principal = caller_principal(request) or "local:dashboard"
    return record.get("owner_id") == principal


def _require_mutation_owner(request: Request, record: dict) -> None:
    """Keep administrator portfolio access read-only for another principal."""

    if not _caller_owns(request, record):
        raise HTTPException(
            404,
            "Outcome record unavailable in this account and workspace.",
        )


def _source_version(kind: str, record_id: str, body: dict) -> str:
    evidence = {
        key: value for key, value in body.items()
        if key not in {"expected_revision", "operation_id", "correction_reason"}
    }
    encoded = json.dumps(
        [kind, record_id, evidence], sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _operation_request(kind: str, record_id: str, body: dict, actor: str) -> str:
    """Bind an idempotency key to every submitted field, before server derivation."""
    evidence = {
        key: value for key, value in body.items()
        if key not in {"expected_revision", "operation_id"}
    }
    encoded = json.dumps(
        [kind, record_id, actor, evidence],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _utf8_hex(value: str) -> str:
    try:
        return value.encode("utf-8").hex()
    except UnicodeEncodeError as exc:
        raise ValueError("export evidence must contain valid Unicode text") from exc


def _export_canonical_node(value: object) -> list:
    """Project JSON into the language-neutral export digest contract.

    Every node has an explicit type. Text and object keys use lowercase UTF-8
    hex, numbers use their exact IEEE-754 binary64 big-endian bytes, arrays keep
    their order, and object pairs sort by UTF-8 bytes. The resulting tree is
    compact JSON, so Python and browser implementations hash identical bytes.
    """

    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean", "true" if value else "false"]
    if isinstance(value, str):
        return ["string", _utf8_hex(value)]
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_JSON_INTEGER:
            raise ValueError("export evidence contains an unsafe JSON integer")
        return ["number", struct.pack(">d", float(value)).hex()]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("export evidence contains a non-finite number")
        return ["number", struct.pack(">d", value).hex()]
    if isinstance(value, (list, tuple)):
        return ["array", [_export_canonical_node(item) for item in value]]
    if isinstance(value, dict):
        pairs = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("export evidence object keys must be text")
            pairs.append([_utf8_hex(key), _export_canonical_node(item)])
        pairs.sort(key=lambda pair: pair[0])
        return ["object", pairs]
    raise ValueError("export evidence must contain JSON values")


def _export_envelope_digest(report: dict) -> str:
    """Digest the final export, excluding only request context and this digest."""

    unsigned = dict(report)
    unsigned.pop("context", None)
    envelope = unsigned.get("export_envelope")
    if not isinstance(envelope, dict):
        raise ValueError("export evidence is missing its envelope contract")
    unsigned["export_envelope"] = {
        key: value for key, value in envelope.items() if key != "digest_sha256"
    }
    canonical = json.dumps(
        _export_canonical_node(unsigned),
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bind_export_envelope(report: dict) -> dict:
    if "context" in report:
        raise ValueError("request context must be attached after export binding")
    bound = {
        **report,
        "export_envelope": {
            "schema": _EXPORT_ENVELOPE_SCHEMA,
            "digest_algorithm": "SHA-256",
            "digest_encoding": "lowercase-hex",
            "canonicalization": _EXPORT_CANONICALIZATION,
            "node_encoding": "tagged-arrays-null-[tag]-others-[tag,value]",
            "object_encoding": "sorted-[utf8hex-key,node]-pairs",
            "string_encoding": "utf-8-lowercase-hex",
            "number_encoding": "ieee-754-binary64-big-endian-lowercase-hex",
            "object_key_order": "utf-8-byte-lexicographic",
            "array_order": "preserved",
            "serialization": "compact-json-utf-8",
            "excluded_fields": list(_EXPORT_EXCLUDED_FIELDS),
        },
    }
    bound["export_envelope"]["digest_sha256"] = _export_envelope_digest(bound)
    return bound


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        raise
    except LookupError as exc:
        raise HTTPException(404, "Outcome record unavailable in this account and workspace.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Outcome accounting is temporarily unavailable.") from exc


@router.get("")
async def portfolio(
    request: Request,
    response: Response,
    limit: int = Query(100, ge=1, le=200),
    cursor: str = Query("", max_length=64, pattern=r"^[A-Za-z0-9_.:-]*$"),
):
    owner, context = _scope(request)
    response.headers["Cache-Control"] = "private, no-store"
    report = await _call(
        default_service.portfolio_report, owner_id=owner, limit=limit, cursor=cursor,
    )
    for item in report["records"]:
        if not _caller_owns(request, item):
            continue
        await _call(
            outcome_accounting_bridge.reconcile_record,
            request,
            context,
            item["id"],
            service=default_service,
            owner_id=item["owner_id"],
        )
    report = await _call(
        default_service.portfolio_report, owner_id=owner, limit=limit, cursor=cursor,
    )
    return {**report, "context": context}


async def _cohort(
    request: Request, pilot_id: str, *, export: bool = False,
) -> tuple[dict, str]:
    from . import outcome_pilots

    owner, context = _scope(request)
    values = _values()
    pilot = await _call(outcome_pilots.get, pilot_id, context)
    admissions = await _call(
        outcome_accounting_bridge.require_complete_admission,
        pilot,
        service=default_service,
    )
    record_ids = [admissions[case["id"]]["id"] for case in pilot["cases"]]
    contract = f"outcome-pilot:{pilot['id']}:{pilot['plan_version']}"
    report_kwargs = {
        "owner_id": owner,
        "record_ids": record_ids,
        "acceptance_contract_ref": contract,
    }
    report = await _call(values.cohort_report, **report_kwargs)
    # Refresh every manifest-bound source before calculating this exact pilot.
    for item in report["cases"]:
        if not _caller_owns(request, item["outcome"]):
            continue
        await _call(
            outcome_accounting_bridge.reconcile_record,
            request,
            context,
            item["outcome"]["id"],
            service=default_service,
            owner_id=owner,
        )
    function = values.export_report if export else values.cohort_report
    result = await _call(function, **report_kwargs)
    result = {
        **result,
        "pilot_id": pilot["id"],
        "plan_version": pilot["plan_version"],
        "admission_manifest_sha256": pilot["admission_manifest"]["manifest_sha256"],
    }
    return (_bind_export_envelope(result) if export else result), context


@router.get("/cohort")
async def cohort(
    request: Request,
    response: Response,
    pilot_id: str = Query(..., pattern=r"^OPL-[A-Za-z0-9_-]{1,196}$"),
):
    report, context = await _cohort(request, pilot_id)
    response.headers["Cache-Control"] = "private, no-store"
    return {**report, "context": context}


@router.get("/cohort/export")
async def cohort_export(
    request: Request,
    response: Response,
    pilot_id: str = Query(..., pattern=r"^OPL-[A-Za-z0-9_-]{1,196}$"),
):
    report, context = await _cohort(request, pilot_id, export=True)
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Content-Disposition"] = (
        'attachment; filename="lightwork-outcome-value-report.json"'
    )
    return {**report, "context": context}


@router.get("/{record_id}/value")
async def value_record(request: Request, response: Response, record_id: str):
    owner, context = _scope(request)
    response.headers["Cache-Control"] = "private, no-store"
    values = _values()
    outcome = await _call(default_service.report, record_id, owner_id=owner)
    if _caller_owns(request, outcome):
        await _call(
            outcome_accounting_bridge.reconcile_record,
            request,
            context,
            record_id,
            service=default_service,
            owner_id=outcome["owner_id"],
            value_service=values,
        )
    report = await _call(values.case_report, record_id, owner_id=owner)
    return {**report, "context": context}


@router.post("/{record_id}/baseline")
async def record_baseline(
    request: Request, response: Response, record_id: str, body: BaselineIn,
):
    owner, context = _scope(request, mutation=True)
    actor = caller_principal(request) or "local:dashboard"
    values = _values()
    current = await _call(values.case_report, record_id, owner_id=owner)
    _require_mutation_owner(request, current["outcome"])
    baseline = current["baseline"]
    if (
        baseline is not None and body.expected_revision != 0
        and body.correction_reason is None
    ):
        raise HTTPException(422, "Explain why this baseline replaces the current evidence.")
    payload = body.model_dump()
    await _call(
        values.record_baseline,
        record_id,
        **payload,
        actor=actor,
        source_version=_source_version("baseline", record_id, payload),
        correction_of=(
            None if baseline is None or body.expected_revision == 0 else baseline["id"]
        ),
        owner_id=owner,
        _operation_request=_operation_request("baseline", record_id, payload, actor),
    )
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(values.case_report, record_id, owner_id=owner), "context": context}


@router.post("/{record_id}/commercial")
async def record_commercial(
    request: Request, response: Response, record_id: str, body: CommercialIn,
):
    owner, context = _scope(request, mutation=True)
    actor = caller_principal(request) or "local:dashboard"
    values = _values()
    current = await _call(values.case_report, record_id, owner_id=owner)
    _require_mutation_owner(request, current["outcome"])
    payload = body.model_dump()
    collection = current["renewals"] if body.kind == "renewal" else current["expansions"]
    same_source = next((
        row for row in reversed(collection)
        if row["current"] and row["source_ref"] == body.source_ref
    ), None)
    await _call(
        values.record_commercial,
        record_id,
        **payload,
        actor=actor,
        source_version=_source_version("commercial", record_id, payload),
        correction_of=(
            same_source["id"]
            if same_source is not None and body.correction_reason is not None else None
        ),
        owner_id=owner,
        _operation_request=_operation_request("commercial", record_id, payload, actor),
    )
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(values.case_report, record_id, owner_id=owner), "context": context}


@router.post("/{record_id}/costs")
async def record_cost(request: Request, response: Response, record_id: str, body: CostIn):
    owner, context = _scope(request, mutation=True)
    actor = caller_principal(request) or "local:dashboard"
    if body.source_ref.startswith(_MANAGED_COST_SOURCE_PREFIXES):
        raise HTTPException(
            422,
            "This source reference is maintained by Lightwork. Add operator evidence "
            "under a separate source reference.",
        )
    report = await _call(default_service.report, record_id, owner_id=owner)
    _require_mutation_owner(request, report)
    raw = default_service.store.get(record_id)
    retry = raw is not None and body.operation_id in raw.get("operations", {})
    current = next((
        row for row in reversed(report["costs"]["events"])
        if row["current"] and row["source_ref"] == body.source_ref
    ), None)
    if current is not None and body.correction_reason is None and not retry:
        raise HTTPException(422, "Explain why this cost replaces the current source entry.")
    if (
        current is not None
        and current.get("source_assurance") != "operator_assertion"
        and not retry
    ):
        raise HTTPException(
            422,
            "This cost entry is maintained by its source authority and cannot be "
            "replaced by operator-entered evidence.",
        )
    if current is not None and current.get("all_in_total") is True and not retry:
        raise HTTPException(
            422,
            "A current all-in total cannot be replaced by a component detail entry.",
        )
    all_in_totals = [
        row for row in report["costs"]["events"]
        if row["current"] and row.get("all_in_total") is True
        and row.get("aggregation") == "additive" and row.get("amount") is not None
    ]
    included_detail = body.total_relationship == "included_in_current_total"
    if included_detail and not retry:
        if not all_in_totals:
            raise HTTPException(
                422,
                "Included detail requires a current all-in total. Choose Additional cost "
                "when this amount should increase the delivered total.",
            )
        if body.currency is not None and body.currency not in {
            row["currency"] for row in all_in_totals
        }:
            raise HTTPException(
                422,
                "Included detail must use the currency of a current all-in total.",
            )
    payload = body.model_dump()
    await _call(
        default_service.record_cost,
        record_id,
        expected_revision=body.expected_revision,
        operation_id=body.operation_id,
        actor=actor,
        category=body.category,
        attempt_state=body.attempt_state,
        basis=body.basis,
        amount=body.amount,
        currency=body.currency,
        aggregation="informational" if included_detail else "additive",
        quantity=body.quantity,
        unit=body.unit,
        unknown_reason=body.unknown_reason,
        source_ref=body.source_ref,
        source_version=_source_version("cost", record_id, payload),
        correction_of=None if current is None or retry else current["id"],
        correction_reason=body.correction_reason,
        allocation_method=body.allocation_method,
        allocation_assumption=body.allocation_assumption,
        evidence_note=body.evidence_note,
        coverage_declarations=(
            None if body.coverage_declarations is None else {
                key: value.model_dump() for key, value in body.coverage_declarations.items()
            }
        ),
        source_assurance="operator_assertion",
        coverage="complete" if body.complete_coverage else "partial",
        _operation_request=_operation_request("cost", record_id, payload, actor),
    )
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(_values().case_report, record_id, owner_id=owner), "context": context}


@router.get("/{record_id}")
async def record(request: Request, response: Response, record_id: str):
    owner, context = _scope(request)
    response.headers["Cache-Control"] = "private, no-store"
    # Authorize ownership before resolving any pilot or connector identity.
    report = await _call(default_service.report, record_id, owner_id=owner)
    if _caller_owns(request, report):
        report = await _call(
            outcome_accounting_bridge.reconcile_record,
            request,
            context,
            record_id,
            service=default_service,
            owner_id=report["owner_id"],
        )
    return {**report, "context": context}


__all__ = ["router"]
