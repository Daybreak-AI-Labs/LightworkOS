"""Closed operator API for the Agent Control Plane.

Reads (status, roster, ledger) are open to viewers/auditors; the verbs mirror
``maverick control-plane`` and carry the caller's identity on an attempted
control-plane audit row. ``audit_written`` reports acceptance of that row;
signing remains deployment policy. The plane's own gate
(``[control_plane] enable``) is enforced by the core module, so a disabled
deployment answers 403 here.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from maverick import agent_control_plane as acp
from maverick.audit import AuditRefused
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, has_permission, require_permission

Principal = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128,
                      pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$"),
]
OpaquePrincipal = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=512),
]
Reason = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=500)]
ToolName = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=64,
                           pattern=r"^[A-Za-z0-9_.-]{1,64}$"),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra="forbid", strict=True)


class ReasonIn(_StrictModel):
    reason: Reason


class PrincipalIn(_StrictModel):
    principal: OpaquePrincipal


class PrincipalReasonIn(ReasonIn):
    principal: OpaquePrincipal


class AttenuateIn(_StrictModel):
    deny_tools: list[ToolName] = Field(default_factory=list, max_length=64)
    max_risk: str | None = Field(default=None, pattern=r"^(low|medium|high)$")
    max_dollars: float | None = Field(default=None, gt=0, le=1_000_000)
    max_wall_seconds: float | None = Field(default=None, gt=0, le=31_536_000)

    @model_validator(mode="after")
    def require_requested_restriction(self):
        if (
            not self.deny_tools
            and self.max_risk is None
            and self.max_dollars is None
            and self.max_wall_seconds is None
        ):
            raise ValueError("at least one attenuation restriction is required")
        return self


class PrincipalAttenuateIn(AttenuateIn):
    principal: OpaquePrincipal


SelectionText = Annotated[
    str,
    StringConstraints(strict=True, max_length=160),
]
SnapshotDigest = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
]


class BulkSelectIn(_StrictModel):
    """A bounded, tenant-pinned request for an operator-reviewed fleet set."""

    tenant: SelectionText | None = None
    platform: SelectionText | None = None

    @model_validator(mode="after")
    def require_tenant_or_platform(self):
        if self.tenant is None and self.platform is None:
            raise ValueError("selection requires an explicit tenant or platform")
        for field_name, value in (("tenant", self.tenant), ("platform", self.platform)):
            if value is not None and (value != value.strip() or not value.isprintable()):
                raise ValueError(f"{field_name} selection must be exact printable text")
        if self.platform == "":
            raise ValueError("platform selection must be non-empty printable text")
        return self


class BulkSelectionIn(_StrictModel):
    """The exact selection returned by ``/bulk/select``; never a wildcard."""

    schema_name: Literal["lightwork.agent-control-plane-selection.v1"] = Field(
        alias="schema",
    )
    tenant: SelectionText
    platform: SelectionText | None = None
    principals: list[OpaquePrincipal] = Field(min_length=1, max_length=500)
    snapshot_sha256: SnapshotDigest
    captured_at: float = Field(gt=0)

    @model_validator(mode="after")
    def require_canonical_selection(self):
        if self.tenant != self.tenant.strip() or not self.tenant.isprintable():
            raise ValueError("tenant selection must be exact printable text")
        if self.platform is not None and (
            not self.platform
            or self.platform != self.platform.strip()
            or not self.platform.isprintable()
        ):
            raise ValueError("platform selection must be non-empty printable text")
        if self.principals != sorted(set(self.principals)):
            raise ValueError("bulk selection principals must be unique and sorted")
        return self

    def to_core(self) -> acp.BulkSelection:
        return acp.BulkSelection(
            tenant=self.tenant,
            platform=self.platform,
            principals=tuple(self.principals),
            snapshot_sha256=self.snapshot_sha256,
            captured_at=self.captured_at,
        )


class BulkActionIn(_StrictModel):
    selection: BulkSelectionIn
    verb: Literal["suspend", "resume", "contain", "release"]
    reason: Reason | None = None
    release_after_seconds: float | None = Field(
        default=None,
        gt=0,
        le=31 * 24 * 60 * 60,
    )
    idempotency_key: IdempotencyKey | None = None

    @model_validator(mode="after")
    def require_verb_specific_fields(self):
        needs_reason = self.verb in {"suspend", "contain"}
        if needs_reason and self.reason is None:
            raise ValueError(f"bulk {self.verb} requires a reason")
        if not needs_reason and self.reason is not None:
            raise ValueError(f"bulk {self.verb} does not accept a reason")
        if self.release_after_seconds is not None:
            if self.verb != "contain":
                raise ValueError("release_after_seconds applies only to bulk contain")
            if self.idempotency_key is None:
                raise ValueError("time-boxed bulk containment requires idempotency_key")
        elif self.idempotency_key is not None:
            raise ValueError("idempotency_key applies only to time-boxed bulk containment")
        return self


class TimeboxedContainIn(PrincipalReasonIn):
    release_after_seconds: float = Field(gt=0, le=31 * 24 * 60 * 60)
    idempotency_key: IdempotencyKey


def _actor(request: Request) -> str:
    subject = caller_principal(request) or "authorized-local-operator"
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 512:
        raise HTTPException(status_code=401, detail="an authenticated principal is required")
    return subject.strip()


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except AuditRefused:
        # A mutating core verb writes its state before its terminal audit row.
        # Preserve that distinction for ``_mutation_call`` instead of
        # laundering it into an ordinary dependency outage.
        raise
    except acp.ControlPlaneDisabled as exc:
        raise HTTPException(status_code=403, detail="control_plane_disabled") from exc
    except acp.ControlPlaneDependencyError as exc:
        raise HTTPException(
            status_code=503,
            detail="control plane dependency is unavailable",
        ) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except acp.ControlPlaneError as exc:
        raise HTTPException(
            status_code=409,
            detail="control plane operation was refused",
        ) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503,
                            detail="control plane dependency is unavailable") from exc


def _observed_principal_state(principal: str) -> dict:
    """Re-read one principal without exposing incident reasons or exceptions."""

    try:
        row = acp.lookup(principal)
    except Exception:
        return {"observed": False, "current_state": None}
    if row is None:
        return {"observed": True, "current_state": {"present": False}}
    return {
        "observed": True,
        "current_state": {
            "present": True,
            "state": row.state,
            "revoked": bool(row.revoked),
            "contained": bool(row.contained),
            "deny_tools": list(row.deny_tools),
            "max_risk": row.max_risk,
            "max_dollars": row.max_dollars,
            "max_wall_seconds": row.max_wall_seconds,
        },
    }


async def _mutation_call(
    operation: str,
    principal: str,
    function,
    *args,
    **kwargs,
):
    """Run a verb and distinguish post-effect audit refusal from no effect."""

    try:
        return await _call(function, *args, **kwargs)
    except AuditRefused as exc:
        observation = await run_in_threadpool(_observed_principal_state, principal)
        observed = bool(observation["observed"])
        message = (
            "control action may have changed state, but its required audit was "
            "refused; current state was re-read"
            if observed
            else
            "control action may have changed state, but its required audit was "
            "refused; current state could not be confirmed"
        )
        raise HTTPException(
            status_code=503,
            detail={
                "code": "control_action_audit_refused",
                "message": message,
                "operation": operation,
                "principal": principal,
                "applied": "unknown",
                **observation,
            },
        ) from exc


def _bounded_page(source: acp.ControlPlaneSnapshot, offset: int, limit: int) -> dict:
    total = len(source.rows)
    selected_offset = 0 if total == 0 else offset
    if total > 0 and selected_offset >= total:
        selected_offset = ((total - 1) // limit) * limit
    return source.page(offset=selected_offset, limit=limit)


def _snapshot_payload(offset: int, limit: int) -> dict:
    """Build status and one bounded page from exactly one authority scan."""

    source = acp.snapshot()
    return {
        "status": acp.status(source=source),
        "agents": _bounded_page(source, offset, limit),
    }


def _agent_page(offset: int, limit: int) -> dict:
    source = acp.snapshot()
    return _bounded_page(source, offset, limit)


def _page_payload(page: dict, *, reveal_incident_reason: bool) -> dict:
    items = []
    for raw in page.get("items", []):
        item = dict(raw)
        if not reveal_incident_reason:
            item.pop("revoked_reason", None)
        items.append(item)
    offset = int(page["offset"])
    limit = int(page["limit"])
    total = int(page["total"])
    next_value = offset + len(items)
    has_more = next_value < total
    return {
        "captured_at": page.get("captured_at"),
        "items": items,
        "count": len(items),
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
        "next_offset": next_value if has_more else None,
    }


def _result_response(result: acp.ControlResult):
    payload = result.to_dict()
    if result.code == "protected_containment":
        return JSONResponse(status_code=409, content=payload)
    if result.ok:
        return payload
    status_code = 503 if result.code == "dependency_unavailable" else 409
    return JSONResponse(status_code=status_code, content=payload)


async def _bulk_mutation_call(
    operation: str,
    selection: acp.BulkSelection,
    function,
    *args,
    **kwargs,
):
    """Run a fleet verb without laundering an audit refusal into a no-op.

    Bulk operations can have several already-applied rows when their terminal
    audit is refused.  Re-reading a roster cannot reconstruct every outcome,
    so the response intentionally says that a reviewed subset may have changed
    and gives the caller the snapshot digest to reconcile through the ledger.
    """

    try:
        return await _call(function, *args, **kwargs)
    except AuditRefused as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "bulk_control_action_audit_refused",
                "message": (
                    "one or more reviewed control actions may have changed state, "
                    "but the required audit was refused; reconcile from the ledger "
                    "before retrying"
                ),
                "operation": operation,
                "selection_sha256": selection.snapshot_sha256,
                "target_count": len(selection.principals),
                "applied": "unknown",
            },
        ) from exc


def _bulk_result_response(result: acp.BulkControlResult):
    """Preserve per-principal outcomes, including a partial fleet failure."""

    payload = result.to_dict()
    if result.ok:
        return payload
    failure_codes = {item.code for item in result.results if not item.ok}
    # A dependency gap or a per-row exception can leave an earlier restrictive
    # action applied, so expose the body with a retry-safe non-success status.
    status_code = 503 if failure_codes & {"action_error", "dependency_unavailable"} else 409
    return JSONResponse(status_code=status_code, content=payload)


def _timeboxed_result_response(result: acp.TimeboxedContainment):
    payload = result.to_dict()
    inner = result.result
    if inner.ok:
        return payload
    status_code = 503 if inner.code == "dependency_unavailable" else 409
    return JSONResponse(status_code=status_code, content=payload)


def _timebox_projection(records: list[dict]) -> list[dict]:
    """Return operator-safe schedule state, not request or reason digests."""

    visible = (
        "operation_id",
        "principal",
        "tenant",
        "containment_generation",
        "release_at",
        "status",
        "created_at",
        "updated_at",
        "attempts",
        "error_code",
    )
    return [{field: record[field] for field in visible if field in record} for record in records]


def create_agent_control_plane_router() -> APIRouter:  # noqa: C901 - route-local authority gates
    router = APIRouter(prefix="/agent-control-plane", tags=["agent-control-plane"])

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        return await _call(acp.status)

    @router.get("/snapshot")
    async def plane_snapshot(
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=200),
    ):
        require_permission(request, "view")
        payload = await _call(_snapshot_payload, offset, limit)
        payload["agents"] = _page_payload(
            payload["agents"],
            reveal_incident_reason=has_permission(request, "audit"),
        )
        return payload

    @router.get("/agents")
    async def agents(
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=200),
    ):
        require_permission(request, "view")
        page = await _call(_agent_page, offset, limit)
        return _page_payload(
            page,
            reveal_incident_reason=has_permission(request, "audit"),
        )

    @router.post("/bulk/select")
    async def bulk_select(request: Request, body: BulkSelectIn):
        """Materialize an exact roster snapshot before any fleet mutation."""

        require_permission(request, "operate")
        selection = await _call(
            acp.select_bulk,
            tenant=body.tenant,
            platform=body.platform,
        )
        return selection.to_dict()

    @router.post("/bulk/actions")
    async def bulk_actions(request: Request, body: BulkActionIn):
        """Apply one verb only to an exact, still-current reviewed selection."""

        if body.verb in {"contain", "release"}:
            require_permission(request, "admin")
        else:
            require_permission(request, "operate")
        selection = body.selection.to_core()
        result = await _bulk_mutation_call(
            f"bulk-{body.verb}",
            selection,
            acp.bulk_action,
            selection,
            verb=body.verb,
            actor=_actor(request),
            reason=body.reason,
            release_after_seconds=body.release_after_seconds,
            idempotency_key=body.idempotency_key,
        )
        return _bulk_result_response(result)

    @router.get("/timeboxes")
    async def timeboxes(request: Request):
        require_permission(request, "audit")
        records = await _call(acp.timeboxed_containments)
        items = _timebox_projection(records)
        return {"items": items, "count": len(items)}

    @router.post("/timeboxes/sweep")
    async def sweep_timeboxes(request: Request):
        """Run due releases using server time; this cannot advance a clock."""

        require_permission(request, "admin")
        try:
            results = await _call(
                acp.sweep_timeboxed_releases,
                actor=_actor(request),
            )
        except AuditRefused as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "timebox_release_audit_refused",
                    "message": (
                        "a due containment release may have changed state, but its "
                        "required audit was refused; reconcile from the ledger"
                    ),
                    "applied": "unknown",
                },
            ) from exc
        payload = {"items": [result.to_dict() for result in results], "count": len(results)}
        if any(not result.ok for result in results):
            return JSONResponse(status_code=503, content=payload)
        return payload

    # Opaque-principal transport.  Identity-provider subjects can contain
    # slashes, pipes, spaces and Unicode, so new clients keep them out of URL
    # path components.  The restricted legacy ``/agents/{principal}/...``
    # routes below remain available for existing simple principal ids.
    @router.get("/principals/ledger")
    async def opaque_agent_ledger(
        request: Request,
        principal: OpaquePrincipal = Query(...),
        limit: int = Query(default=50, ge=1, le=500),
    ):
        require_permission(request, "audit")
        rows = await _call(acp.ledger, principal, limit=limit)
        return {"principal": principal, "items": rows, "count": len(rows)}

    @router.post("/principals/suspend")
    async def opaque_suspend(request: Request, body: PrincipalReasonIn):
        require_permission(request, "operate")
        result = await _mutation_call(
            "suspend",
            body.principal,
            acp.suspend,
            body.principal,
            reason=body.reason,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/principals/resume")
    async def opaque_resume(request: Request, body: PrincipalIn):
        require_permission(request, "operate")
        result = await _mutation_call(
            "resume",
            body.principal,
            acp.resume,
            body.principal,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/principals/contain")
    async def opaque_contain(request: Request, body: PrincipalReasonIn):
        require_permission(request, "admin")
        result = await _mutation_call(
            "contain",
            body.principal,
            acp.contain,
            body.principal,
            reason=body.reason,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/principals/contain-timeboxed")
    async def opaque_contain_timeboxed(request: Request, body: TimeboxedContainIn):
        require_permission(request, "admin")
        result = await _mutation_call(
            "timeboxed-contain",
            body.principal,
            acp.contain_timeboxed,
            body.principal,
            reason=body.reason,
            release_after_seconds=body.release_after_seconds,
            idempotency_key=body.idempotency_key,
            actor=_actor(request),
        )
        return _timeboxed_result_response(result)

    @router.post("/principals/release")
    async def opaque_release(request: Request, body: PrincipalIn):
        require_permission(request, "admin")
        result = await _mutation_call(
            "release",
            body.principal,
            acp.release,
            body.principal,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/principals/attenuate")
    async def opaque_attenuate(request: Request, body: PrincipalAttenuateIn):
        require_permission(request, "operate")
        result = await _mutation_call(
            "attenuate",
            body.principal,
            acp.attenuate,
            body.principal,
            deny_tools=body.deny_tools,
            max_risk=body.max_risk,
            max_dollars=body.max_dollars,
            max_wall_seconds=body.max_wall_seconds,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.get("/agents/{principal}/ledger")
    async def agent_ledger(request: Request, principal: Principal,
                           limit: int = Query(default=50, ge=1, le=500)):
        require_permission(request, "audit")
        rows = await _call(acp.ledger, principal, limit=limit)
        return {"principal": principal, "items": rows, "count": len(rows)}

    @router.post("/agents/{principal}/suspend")
    async def suspend(request: Request, principal: Principal, body: ReasonIn):
        require_permission(request, "operate")
        result = await _mutation_call(
            "suspend",
            principal,
            acp.suspend,
            principal,
            reason=body.reason,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/agents/{principal}/resume")
    async def resume(request: Request, principal: Principal):
        require_permission(request, "operate")
        result = await _mutation_call(
            "resume",
            principal,
            acp.resume,
            principal,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/agents/{principal}/contain")
    async def contain(request: Request, principal: Principal, body: ReasonIn):
        require_permission(request, "admin")
        result = await _mutation_call(
            "contain",
            principal,
            acp.contain,
            principal,
            reason=body.reason,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/agents/{principal}/release")
    async def release(request: Request, principal: Principal):
        require_permission(request, "admin")
        result = await _mutation_call(
            "release",
            principal,
            acp.release,
            principal,
            actor=_actor(request),
        )
        return _result_response(result)

    @router.post("/agents/{principal}/attenuate")
    async def attenuate(request: Request, principal: Principal, body: AttenuateIn):
        require_permission(request, "operate")
        result = await _mutation_call(
            "attenuate",
            principal,
            acp.attenuate,
            principal,
            deny_tools=body.deny_tools,
            max_risk=body.max_risk, max_dollars=body.max_dollars,
            max_wall_seconds=body.max_wall_seconds, actor=_actor(request))
        return _result_response(result)

    return router


router = create_agent_control_plane_router()

__all__ = ["create_agent_control_plane_router", "router"]
