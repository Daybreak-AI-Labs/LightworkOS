"""Strict admin/auditor API for the local California DROP authority plane.

Every mutation is a durable proposal followed by a second authenticated
principal's approval.  Tenant and actor are server-derived; inputs contain
only bounded references, digests, closed enums and finite timestamps.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from maverick.privacy_drop_management import (
    DROPDSARReceipt,
    DROPManagementConflict,
    DROPManagementError,
    DROPManagementIntegrityError,
    DROPManagementNotFound,
    DROPManagementValidationError,
    DROPRecordAuthority,
)
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import has_global_permission, has_permission, require_global_permission

ClosedRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$",
    ),
]
KeyRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=256,
        pattern=(
            r"^(?:env:[A-Z][A-Z0-9_]{0,127}|"
            r"(?:kms|secret|vault|aws-kms|azure-keyvault|gcp-kms)://"
            r"[A-Za-z0-9][A-Za-z0-9_./:@+\-]{0,239})$"
        ),
    ),
]
Digest = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
TemplateId = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=(
            r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-"
            r"[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
        ),
    ),
]

_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class BrokerProposalIn(_StrictModel):
    action: Literal["enroll_broker", "revoke_broker"]
    broker_ref: ClosedRef
    registration_sha256: Digest | None = None
    evidence_sha256: Digest
    valid_until: float | None = Field(default=None, strict=True, gt=0)
    expected_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    idempotency_key: ClosedRef

    @model_validator(mode="after")
    def closed_action(self):
        if self.action == "enroll_broker":
            if self.registration_sha256 is None or self.valid_until is None:
                raise ValueError("broker enrollment authority is incomplete")
        elif self.registration_sha256 is not None or self.valid_until is not None:
            raise ValueError("broker revocation input is not closed")
        return self


class RecordProposalIn(_StrictModel):
    action: Literal["import_record", "revoke_record"]
    drop_id: int = Field(strict=True, ge=1, le=2_147_483_647)
    broker_ref: ClosedRef | None = None
    broker_registration_sha256: Digest | None = None
    subject_binding_sha256: Digest | None = None
    request_type: Literal["DataDeletion", "OptOut"] | None = None
    template_id: TemplateId | None = None
    language: Annotated[
        str,
        StringConstraints(
            strict=True,
            min_length=2,
            max_length=12,
            pattern=r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$",
        ),
    ] | None = None
    record_revision: int | None = Field(default=None, strict=True, ge=1, le=2_147_483_647)
    valid_until: float | None = Field(default=None, strict=True, gt=0)
    evidence_sha256: Digest
    expected_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    idempotency_key: ClosedRef

    @model_validator(mode="after")
    def closed_action(self):
        import_fields = (
            self.broker_ref,
            self.broker_registration_sha256,
            self.subject_binding_sha256,
            self.request_type,
            self.template_id,
            self.language,
            self.record_revision,
            self.valid_until,
        )
        if self.action == "import_record" and any(value is None for value in import_fields):
            raise ValueError("DROP record import authority is incomplete")
        if self.action == "revoke_record" and any(value is not None for value in import_fields):
            raise ValueError("DROP record revocation input is not closed")
        return self


class OutcomeProposalIn(_StrictModel):
    drop_id: int = Field(strict=True, ge=1, le=2_147_483_647)
    status: Literal["EXEMPTED", "DELETED", "OPTED_OUT", "NOT_FOUND"]
    evidence_sha256: Digest
    evidence_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    observed_at: float = Field(strict=True, gt=0)
    valid_until: float = Field(strict=True, gt=0)
    deletion_verified: bool = Field(default=False, strict=True)
    opt_out_verified: bool = Field(default=False, strict=True)
    search_complete: bool = Field(default=False, strict=True)
    exemption_approved: bool = Field(default=False, strict=True)
    provider_operations_complete: bool = Field(default=False, strict=True)
    expected_version: int = Field(strict=True, ge=0, le=2_147_483_646)
    idempotency_key: ClosedRef


class KeyProposalIn(_StrictModel):
    action: Literal["rotate_key", "retire_key", "revoke_key", "record_key_migration"]
    new_key_ref: KeyRef | None = None
    expected_current_revision: int | None = Field(
        default=None, strict=True, ge=1, le=2_147_483_647
    )
    key_revision: int | None = Field(default=None, strict=True, ge=1, le=2_147_483_647)
    migration_id: ClosedRef | None = None
    from_revision: int | None = Field(default=None, strict=True, ge=1, le=2_147_483_647)
    to_revision: int | None = Field(default=None, strict=True, ge=1, le=2_147_483_647)
    objects_migrated: int | None = Field(default=None, strict=True, ge=0, le=1_000_000)
    remaining_dependencies: int | None = Field(
        default=None, strict=True, ge=0, le=1_000_000
    )
    idempotency_key: ClosedRef

    @model_validator(mode="after")
    def closed_action(self):
        rotation = (self.new_key_ref, self.expected_current_revision)
        retirement = (self.key_revision,)
        migration = (
            self.migration_id,
            self.from_revision,
            self.to_revision,
            self.objects_migrated,
            self.remaining_dependencies,
        )
        if self.action == "rotate_key":
            if any(value is None for value in rotation) or any(
                value is not None for value in retirement + migration
            ):
                raise ValueError("DROP key rotation input is not closed")
        elif self.action in {"retire_key", "revoke_key"}:
            if self.key_revision is None or any(
                value is not None for value in rotation + migration
            ):
                raise ValueError("DROP key retirement input is not closed")
        elif any(value is None for value in migration) or any(
            value is not None for value in rotation + retirement
        ):
            raise ValueError("DROP key migration input is not closed")
        return self


class ApproveProposalIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=1)
    idempotency_key: ClosedRef


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(status_code=409, detail="select an active tenant for DROP authority")
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(request, error_detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.privacy-drop.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"drop-principal-{digest[:32]}"


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _reject_query(request: Request) -> None:
    if request.query_params:
        raise HTTPException(status_code=422, detail="DROP authority query is invalid")


async def _call(function: Callable[..., Any], *args: object, **kwargs: object) -> Any:
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except DROPManagementNotFound as exc:
        raise HTTPException(status_code=404, detail="DROP authority was not found") from exc
    except DROPManagementConflict as exc:
        raise HTTPException(status_code=409, detail="DROP authority state changed") from exc
    except DROPManagementValidationError as exc:
        raise HTTPException(status_code=422, detail="DROP authority input is invalid") from exc
    except DROPManagementIntegrityError as exc:
        raise HTTPException(status_code=503, detail="DROP authority integrity failed") from exc
    except DROPManagementError as exc:
        raise HTTPException(status_code=503, detail="DROP authority is unavailable") from exc
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="DROP authority is unavailable") from exc


def _factories(request: Request, tenant: str):
    enabled = getattr(request.app.state, "privacy_drop_management_enabled_probe", None)
    registry_factory = getattr(request.app.state, "privacy_drop_authority_registry_factory", None)
    key_factory = getattr(
        request.app.state, "privacy_drop_principal_key_authority_factory", None
    )
    proposal_factory = getattr(
        request.app.state, "privacy_drop_authority_proposal_store_factory", None
    )
    store_factory = getattr(request.app.state, "privacy_drop_management_store_factory", None)
    if (
        not callable(enabled)
        or enabled(tenant) is not True
        or not all(
            callable(value)
            for value in (registry_factory, key_factory, proposal_factory, store_factory)
        )
    ):
        raise HTTPException(status_code=503, detail="DROP authority composition is unavailable")
    try:
        registry = registry_factory(tenant_id=tenant, request=request)
        keys = key_factory(tenant_id=tenant, request=request)
        proposals = proposal_factory(tenant_id=tenant, request=request)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="DROP authority composition is unavailable") from exc
    return registry, keys, proposals, store_factory


def _proposal_out(value: object) -> Mapping[str, object]:
    return {
        "proposal_id": value.proposal_id,
        "kind": value.kind,
        "state": value.state,
        "revision": value.revision,
        "payload_sha256": value.payload_sha256,
        "proposer_key_revision": value.proposer_key_revision,
        "result_sha256": value.result_sha256,
        "created_at": value.created_at,
        "updated_at": value.updated_at,
        "retained_until": value.retained_until,
        "integrity_sha256": value.integrity_sha256,
    }


def create_privacy_drop_authority_router() -> APIRouter:  # noqa: C901,PLR0915
    router = APIRouter(prefix="/privacy/drop/authority", tags=["privacy-drop-authority"])

    @router.get("/proposals/{proposal_id}/review")
    async def review_proposal(request: Request, response: Response, proposal_id: ClosedRef):
        from . import auth
        from .action_center_governance_sources import _access
        from .privacy_drop_authority_proposals import _canonical

        _reject_query(request)
        with auth.fresh_configuration():
            context = _access(request, "/privacy/drop")
            tenant = _tenant_id()
            actor = _principal(request, tenant)
            _registry, _keys, store, _factory = _factories(request, tenant)

        def read():
            with store._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM drop_authority_proposals WHERE tenant_id=? AND proposal_id=?",
                    (tenant, proposal_id),
                ).fetchone()
                if row is None:
                    raise DROPManagementNotFound("proposal unavailable")
                retained = store._body(row)
                if retained["state"] != "proposed" or retained["retained_until"] <= store._now():
                    raise DROPManagementConflict("proposal no longer pending")
                payload = json.loads(retained["payload_json"])
                if hashlib.sha256(_canonical(payload)).hexdigest() != retained["payload_sha256"]:
                    raise DROPManagementIntegrityError("proposal contents changed")
                return {
                    "proposal": _proposal_out(store._public(retained)),
                    "proposed_by_you": retained["proposer_ref"] == actor,
                    "contents": payload,
                    "context": context,
                }

        result = await _call(read)
        with auth.fresh_configuration():
            if _access(request, "/privacy/drop") != context or _tenant_id() != tenant:
                raise HTTPException(409, "Your account or workspace changed. Open the current review again.")
        _secure(response)
        return result

    @router.get("/authorities")
    async def authorities(request: Request, response: Response) -> Mapping[str, object]:
        require_global_permission(request, "audit")
        _reject_query(request)
        tenant = _tenant_id()
        registry, _keys, proposals, _store_factory = _factories(request, tenant)
        values = await _call(registry.list_authorities, limit=250)
        proposal_values = await _call(proposals.list_proposals, limit=250)
        _secure(response)
        return {
            "schema": "lightwork.privacy-drop-authority-list.v1",
            "authorities": list(values),
            "proposals": [_proposal_out(value) for value in proposal_values],
            "raw_subject_fields_returned": False,
        }

    @router.get("/overview")
    async def overview(request: Request, response: Response) -> Mapping[str, object]:
        """Everything the DROP page lists on arrival: imported requests with
        their current state, and (for auditors and administrators) brokers and
        changes waiting for a second administrator."""

        can_audit = has_global_permission(request, "audit")
        if not (can_audit or has_permission(request, "operate")):
            raise HTTPException(status_code=403, detail="permission denied")
        _reject_query(request)
        tenant = _tenant_id()
        actor = _principal(request, tenant)
        registry, _keys, proposals, store_factory = _factories(request, tenant)
        records = await _call(registry.list_record_details, limit=250)
        outcomes = await _call(registry.list_authorities, kind="outcome", limit=250)
        store = await _call(store_factory, tenant_id=tenant, actor_ref=actor, request=request)

        def request_state(detail: Mapping[str, object]) -> Mapping[str, object] | None:
            if not detail["usable"]:
                return None
            try:
                authority = registry.resolve_record(drop_id=detail["drop_id"])
                value = store.get_request(authority)
            except DROPManagementNotFound:
                return None
            except DROPManagementConflict:
                return None
            return {
                "status": value.status,
                "revision": value.revision,
                "created_at": value.created_at,
                "updated_at": value.updated_at,
            }

        rows = []
        for detail in records:
            try:
                current = await run_in_threadpool(request_state, detail)
            except DROPManagementError as exc:
                raise HTTPException(status_code=503, detail="DROP authority is unavailable") from exc
            rows.append(
                {
                    **dict(detail),
                    "request": current,
                    "outcomes": [
                        {"status": item["status"], "version": item["version"], "state": item["state"]}
                        for item in outcomes
                        if item.get("drop_id") == detail["drop_id"]
                    ],
                }
            )
        body: dict[str, object] = {
            "schema": "lightwork.privacy-drop-overview.v1",
            "requests": rows,
            "brokers": [],
            "waiting": [],
        }
        if can_audit or has_global_permission(request, "admin"):
            brokers = await _call(registry.list_authorities, kind="broker", limit=250)
            body["brokers"] = [
                {
                    field: item[field]
                    for field in (
                        "broker_ref",
                        "version",
                        "state",
                        "valid_until",
                        "registration_sha256",
                    )
                    if field in item
                }
                for item in brokers
            ]
            body["waiting"] = list(
                await _call(proposals.list_open_summaries, proposer_ref=actor, limit=100)
            )
        _secure(response)
        return body

    @router.get("/revisions")
    async def revisions(request: Request, response: Response) -> Mapping[str, object]:
        require_global_permission(request, "audit")
        _reject_query(request)
        tenant = _tenant_id()
        registry, keys, _proposals, _store_factory = _factories(request, tenant)
        key_values = await _call(keys.list_revisions)
        dependencies = await _call(keys.dependency_counts)
        reconciliation = await _call(registry.reconcile)
        _secure(response)
        return {
            "schema": "lightwork.privacy-drop-authority-revisions.v1",
            "keys": [keys.public_payload(value) for value in key_values],
            "dependency_counts": dependencies,
            "authority_counts": {
                "active_brokers": reconciliation.active_brokers,
                "active_records": reconciliation.active_records,
                "approved_outcomes": reconciliation.approved_outcomes,
            },
            "key_material_returned": False,
        }

    @router.get("/integrity")
    async def integrity(request: Request, response: Response) -> Mapping[str, object]:
        require_global_permission(request, "audit")
        _reject_query(request)
        tenant = _tenant_id()
        registry, keys, proposals, _store_factory = _factories(request, tenant)
        values = await run_in_threadpool(
            lambda: {
                "key_authority": keys.verify_integrity() is True,
                "registry": registry.verify_integrity() is True,
                "proposals": proposals.verify_integrity() is True,
            }
        )
        if not all(values.values()):
            raise HTTPException(status_code=503, detail="DROP authority integrity failed")
        _secure(response)
        return {"schema": "lightwork.privacy-drop-authority-integrity.v1", **values}

    async def propose(
        request: Request,
        response: Response,
        *,
        kind: str,
        payload: Mapping[str, object],
        idempotency_key: str,
    ) -> Mapping[str, object]:
        require_global_permission(request, "admin")
        _reject_query(request)
        tenant = _tenant_id()
        actor = _principal(request, tenant)
        _registry, _keys, proposals, _store_factory = _factories(request, tenant)
        value = await _call(
            proposals.propose,
            kind=kind,
            payload=payload,
            proposer_ref=actor,
            idempotency_key=idempotency_key,
        )
        _secure(response)
        return {"schema": "lightwork.privacy-drop-authority-proposal.v1", **_proposal_out(value)}

    @router.post("/brokers/proposals", status_code=201)
    async def propose_broker(
        request: Request,
        response: Response,
        body: BrokerProposalIn,
    ) -> Mapping[str, object]:
        payload = body.model_dump(exclude={"idempotency_key"}, exclude_none=True)
        return await propose(
            request,
            response,
            kind=body.action,
            payload=payload,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/records/proposals", status_code=201)
    async def propose_record(
        request: Request,
        response: Response,
        body: RecordProposalIn,
    ) -> Mapping[str, object]:
        payload = body.model_dump(exclude={"idempotency_key"}, exclude_none=True)
        return await propose(
            request,
            response,
            kind=body.action,
            payload=payload,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/outcomes/proposals", status_code=201)
    async def propose_outcome(
        request: Request,
        response: Response,
        body: OutcomeProposalIn,
    ) -> Mapping[str, object]:
        payload = body.model_dump(exclude={"idempotency_key"})
        return await propose(
            request,
            response,
            kind="approve_outcome",
            payload=payload,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/keys/proposals", status_code=201)
    async def propose_key(
        request: Request,
        response: Response,
        body: KeyProposalIn,
    ) -> Mapping[str, object]:
        payload = body.model_dump(exclude={"idempotency_key"}, exclude_none=True)
        return await propose(
            request,
            response,
            kind=body.action,
            payload=payload,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/proposals/{proposal_id}/approve")
    async def approve(
        request: Request,
        response: Response,
        proposal_id: ClosedRef,
        body: ApproveProposalIn,
    ) -> Mapping[str, object]:
        require_global_permission(request, "admin")
        _reject_query(request)
        tenant = _tenant_id()
        reviewer = _principal(request, tenant)
        registry, keys, proposals, store_factory = _factories(request, tenant)
        proposal, payload, proposer = await _call(
            proposals.claim_approval,
            proposal_id,
            expected_revision=body.expected_revision,
            reviewer_ref=reviewer,
            idempotency_key=body.idempotency_key,
        )
        apply_key = f"proposal-{proposal.proposal_id}"
        kind = proposal.kind
        result: Mapping[str, object]
        if kind == "enroll_broker":
            value = await _call(
                registry.enroll_broker,
                broker_ref=payload["broker_ref"],
                registration_sha256=payload["registration_sha256"],
                evidence_sha256=payload["evidence_sha256"],
                valid_until=payload["valid_until"],
                expected_version=payload["expected_version"],
                actor_ref=proposer,
                reviewer_ref=reviewer,
                idempotency_key=apply_key,
            )
            result = {"kind": kind, "version": value.version, "state": value.state}
        elif kind == "revoke_broker":
            value = await _call(
                registry.revoke_broker,
                payload["broker_ref"],
                expected_version=payload["expected_version"],
                evidence_sha256=payload["evidence_sha256"],
                actor_ref=proposer,
                reviewer_ref=reviewer,
                idempotency_key=apply_key,
            )
            result = {"kind": kind, "version": value.version, "state": value.state}
        elif kind == "import_record":
            authority = DROPRecordAuthority(
                tenant_id=tenant,
                drop_id=payload["drop_id"],
                broker_registration_sha256=payload["broker_registration_sha256"],
                subject_binding_sha256=payload["subject_binding_sha256"],
                request_type=payload["request_type"],
                template_id=payload["template_id"],
                language=payload["language"],
                record_revision=payload["record_revision"],
                valid_until=payload["valid_until"],
            ).normalized()
            value = await _call(
                registry.import_record,
                authority,
                broker_ref=payload["broker_ref"],
                import_evidence_sha256=payload["evidence_sha256"],
                expected_version=payload["expected_version"],
                actor_ref=proposer,
                reviewer_ref=reviewer,
                idempotency_key=apply_key,
            )
            result = {
                "kind": kind,
                "drop_id": value.drop_id,
                "authority_sha256": value.authority_sha256,
            }
        elif kind == "revoke_record":
            value = await _call(
                registry.revoke_record,
                payload["drop_id"],
                expected_version=payload["expected_version"],
                evidence_sha256=payload["evidence_sha256"],
                actor_ref=proposer,
                reviewer_ref=reviewer,
                idempotency_key=apply_key,
            )
            result = {"kind": kind, "drop_id": value.drop_id}
        elif kind == "approve_outcome":
            authority = await _call(registry.resolve_record, drop_id=payload["drop_id"])
            store = await _call(
                store_factory,
                tenant_id=tenant,
                actor_ref=reviewer,
                request=request,
            )
            record = await _call(store.get_request, authority)
            if record.status != "PENDING":
                raise HTTPException(status_code=409, detail="DROP request is not pending")
            receipt = DROPDSARReceipt(
                tenant_id=tenant,
                drop_id=record.drop_id,
                authority_sha256=record.authority_sha256,
                subject_binding_sha256=authority.subject_binding_sha256,
                request_type=record.request_type,
                request_queue_id=record.request_queue_id,
                request_queue_ref_id=record.request_queue_ref_id,
                internal_case_id=record.internal_case_id,
                created_at=record.created_at,
            ).normalized()
            value = await _call(
                registry.approve_outcome,
                authority,
                receipt,
                status=payload["status"],
                reviewer_ref=reviewer,
                evidence_sha256=payload["evidence_sha256"],
                evidence_revision=payload["evidence_revision"],
                observed_at=payload["observed_at"],
                valid_until=payload["valid_until"],
                deletion_verified=payload["deletion_verified"],
                opt_out_verified=payload["opt_out_verified"],
                search_complete=payload["search_complete"],
                exemption_approved=payload["exemption_approved"],
                provider_operations_complete=payload["provider_operations_complete"],
                expected_version=payload["expected_version"],
                actor_ref=proposer,
                idempotency_key=apply_key,
            )
            result = {"kind": kind, "evidence_binding_sha256": value.evidence_binding_sha256}
        elif kind == "rotate_key":
            value = await _call(
                keys.rotate,
                new_key_ref=payload["new_key_ref"],
                expected_current_revision=payload["expected_current_revision"],
                actor_ref=proposer,
                reviewer_ref=reviewer,
                idempotency_key=apply_key,
            )
            result = {"kind": kind, "revision": value.revision, "state": value.state}
        elif kind in {"retire_key", "revoke_key"}:
            value = await _call(
                keys.retire,
                payload["key_revision"],
                expected_state="previous",
                actor_ref=proposer,
                reviewer_ref=reviewer,
                idempotency_key=apply_key,
                revoke=kind == "revoke_key",
            )
            result = {"kind": kind, "revision": value.revision, "state": value.state}
        elif kind == "record_key_migration":
            value = await _call(
                keys.record_migration,
                migration_id=payload["migration_id"],
                from_revision=payload["from_revision"],
                to_revision=payload["to_revision"],
                objects_migrated=payload["objects_migrated"],
                remaining_dependencies=payload["remaining_dependencies"],
                actor_ref=proposer,
                reviewer_ref=reviewer,
            )
            encoded = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            result = {
                "kind": kind,
                "migration_sha256": hashlib.sha256(encoded).hexdigest(),
            }
        else:  # pragma: no cover - proposal store enforces the closed set
            raise HTTPException(status_code=422, detail="DROP proposal kind is invalid")
        completed = await _call(
            proposals.complete_approval,
            proposal_id,
            result=result,
        )
        _secure(response)
        return {
            "schema": "lightwork.privacy-drop-authority-approval.v1",
            **_proposal_out(completed),
            "applied_result": dict(result),
        }

    return router


router = create_privacy_drop_authority_router()

__all__ = [
    "ApproveProposalIn",
    "BrokerProposalIn",
    "KeyProposalIn",
    "OutcomeProposalIn",
    "RecordProposalIn",
    "create_privacy_drop_authority_router",
    "router",
]
