"""Review one complete approved scan before updating a named Data Use dataset."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from maverick import privacy_data_discovery as discovery_authority
from maverick import privacy_discovery_data_use_bridge as bridge
from maverick.authority_effects import authority_effect_fence
from maverick.file_lock import atomic_read_bytes, atomic_write_bytes, cross_process_lock
from maverick.governed_operations import digest
from maverick.paths import data_dir
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from . import data_use_governance_api as targets
from . import privacy_data_discovery_api as scans
from .draft_api import context_for

PAGE = "/privacy/data-discovery"
router = APIRouter(prefix="/privacy/data-discovery/data-use", tags=["privacy-data-use"])
TOKEN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
SHA = r"^[0-9a-f]{64}$"


class PrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_id: str = Field(pattern=TOKEN)
    asset_id: str = Field(pattern=TOKEN)
    context: str = Field(pattern=SHA)
    inventory: str = Field(pattern=SHA)
    reference: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{15,95}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{15,95}$")
    context: str = Field(pattern=SHA)
    proposal_sha256: str = Field(pattern=SHA)


def _access(request):
    auth.require_principal(request)
    auth.require_global_permission(request, "admin")
    auth.require_page_permission(request, PAGE)
    from .app import require_page_visible

    require_page_visible(request, PAGE)
    if not bridge.enabled():
        raise HTTPException(403, "Allow reviewed findings in Data Use in Settings, and enable data discovery and Data Use first.")
    return scans._authority(request)


def _key(tenant):
    """Automatically provision a stable private key in the existing tenant vault."""
    from maverick.tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

    path = data_dir("privacy_automation", "discovery-data-use-key.sealed", tenant=tenant)
    database = data_dir("privacy_automation", "discovery-data-use.sqlite3", tenant=tenant)
    with cross_process_lock(path, strict=True):
        if not path.exists():
            if database.exists() and database.stat().st_size:
                raise HTTPException(503, "The saved protection key is unavailable. Restore it with this workspace's backup before continuing.")
            value = {"tenant": tenant, "purpose": "privacy-discovery-data-use", "key": secrets.token_hex(32)}
            atomic_write_bytes(path, seal_text_for_tenant(tenant, json.dumps(value)))
        try:
            value = json.loads(unseal_text_for_tenant(tenant, atomic_read_bytes(path)))
            key = bytes.fromhex(value["key"])
            if value["tenant"] != tenant or value["purpose"] != "privacy-discovery-data-use" or len(key) != 32:
                raise ValueError("invalid protected key")
        except Exception as exc:
            raise HTTPException(503, "The saved protection key could not be opened. No dataset was changed.") from exc
        return key


def _services(request):
    ops, tenant, discovery = _access(request)
    target = targets._store(targets._ops(), tenant)
    key = _key(tenant)
    from .request_identity import request_actor as _request_actor

    actor = _request_actor(request)
    service = bridge.PrivacyDiscoveryDataUseBridgeStore(
        data_dir("privacy_automation", "discovery-data-use.sqlite3", tenant=tenant),
        discovery_store=discovery, data_use_store=target,
        principal_resolver=lambda: actor, digest_key_resolver=lambda _tenant: key,
    )
    return ops, tenant, discovery, target, service


def _catalog(request, services):
    ops, tenant, discovery, target, _service = services
    guard = scans._scan_guard(request, ops, tenant, discovery, permission="view")
    guard()
    now = time.time()
    reports = []
    for report in discovery.list_reports(tenant, limit=51)[:50]:
        if (report.completeness != "complete_within_declared_bounds" or report.truncation_reasons
                or report.error_codes or not 0 < report.findings_count <= 2000 or report.retention_until <= now):
            continue
        source = discovery.get_source(tenant, report.source_id)
        if source.state != "active":
            continue
        reports.append({"id": report.report_id, "source_name": source.source_id,
                        "finished_at": report.finished_at, "findings": report.findings_count,
                        "report_pin": report.integrity_sha256, "source_pin": source.integrity_sha256})
    assets = target.list_records(tenant, "asset", limit=500)
    datasets = [{"id": item["asset_id"], "name": item["asset_id"], "pin": item["record_sha256"]}
                for item in assets]
    guard()
    _access(request)
    return {"context": context_for(request), "inventory": digest({"reports": reports, "datasets": datasets}),
            "reports": reports, "datasets": datasets,
            "scope": "Up to the 50 newest retained scans and the first 500 saved Data Use items. Only complete, unexpired scans with findings are offered. Every finding must still have independent approval when you review it."}


def overview(request):
    return _catalog(request, _services(request))


def _proposal_id(reference):
    return "PDDB-" + hashlib.sha256(reference.encode("ascii")).hexdigest()[:32]


def _owned(request, tenant, service, reference):
    proposal = service.get_proposal(tenant, _proposal_id(reference))
    if not hmac.compare_digest(proposal["created_by_sha256"], service._actor_sha256(tenant)):
        raise HTTPException(403, "This review belongs to a different account. Open your own saved review.")
    return proposal


def _guard(request, services, proposal=None):
    ops, tenant, discovery, _target, service = services
    source = proposal["source_snapshot"] if proposal else None
    current = scans._scan_guard(request, ops, tenant, discovery, permission="view",
        source_id=proposal["source_id"] if proposal else None,
        source_sha256=source["source_integrity_sha256"] if source else None)
    expected_context = context_for(request)

    def check():
        current()
        _access(request)
        if context_for(request) != expected_context:
            raise HTTPException(409, "Your account or workspace changed. Open the current controls again.")
        if proposal:
            now = time.time()
            if now >= min(proposal["created_at"] + 300, proposal["retained_until"]):
                raise HTTPException(409, "This review expired. Read its saved outcome before preparing a new review.")
            service._reread_discovery(proposal["source_snapshot"], now)
    return check


def _view(proposal, *, outcome="review", application=None):
    before = proposal["before_context"]
    return {"outcome": outcome, "proposal_sha256": proposal["integrity_sha256"],
            "dataset": proposal["asset_id"], "source": proposal["source_id"],
            "findings": proposal["source_snapshot"]["report_findings_count"],
            "before": list(before["values"]) if before else [],
            "after": list(proposal["desired_context"]["values"]),
            "expires_at": min(proposal["created_at"] + 300, proposal["retained_until"]),
            "completed_at": application["applied_at"] if application else None,
            "changed": application["outcome"] != "no_change" if application else None,
            "scope": "Only this dataset's observed personal-data categories are updated. Business purpose, consent, legal permissions and the scanned system stay unchanged. This scan does not establish coverage of your entire business."}


def _original(request, reference, context):
    services = _services(request)
    _ops, tenant, discovery, _target, service = services
    if context_for(request) != context:
        raise HTTPException(409, "This saved review belongs to a different account or workspace.")
    proposal = _owned(request, tenant, service, reference)
    check = scans._scan_guard(request, _ops, tenant, discovery, permission="view",
        source_id=proposal["source_id"], source_sha256=proposal["source_snapshot"]["source_integrity_sha256"])
    baseline = _guard(request, services)
    baseline()
    application_id = "PDDA-" + hashlib.sha256(proposal["proposal_id"].encode()).hexdigest()[:32]
    try:
        application = service.get_application(tenant, application_id)
    except bridge.DiscoveryDataUseBridgeNotFound:
        application = None
    admitted = service.application_admitted(tenant, proposal["proposal_id"])
    try:
        check()
    except (HTTPException, discovery_authority.PrivacyDataDiscoveryConflict):
        baseline()
        if context_for(request) != context:
            raise HTTPException(409, "Your account or workspace changed. Open the current controls again.") from None
        return {"outcome": "withdrawn", "can_close": not admitted or application is not None,
                "attempted": admitted, "completed": application is not None,
                "message": "The source or saved account changed. This request was not attempted." if not admitted else
                    "The source or saved account changed. The original update has a saved completed result." if application else
                    "The source or saved account changed. An update was attempted but its result remains unconfirmed. Keep this request; do not repeat it."}
    baseline()
    _access(request)
    return _view(proposal, outcome="complete" if application else "unconfirmed" if admitted else "review",
                 application=application)


def _prepare(request, body):
    with authority_effect_fence():
        services = _services(request)
        _ops, tenant, discovery, target, service = services
        guard = _guard(request, services)
        guard()
        catalog = _catalog(request, services)
        if body.context != catalog["context"] or body.inventory != catalog["inventory"]:
            raise HTTPException(409, "The available reports or datasets changed. Refresh the choices before reviewing.")
        if not any(row["id"] == body.report_id for row in catalog["reports"]) or not any(row["id"] == body.asset_id for row in catalog["datasets"]):
            raise HTTPException(409, "Choose an available complete report and a saved dataset.")
        report = discovery.get_report(tenant, body.report_id)
        source = discovery.get_source(tenant, report.source_id)
        source_guard = scans._scan_guard(request, _ops, tenant, discovery, permission="view",
            source_id=source.source_id, source_sha256=source.integrity_sha256)
        source_guard()
        findings = discovery.list_findings(tenant, report_id=report.report_id, limit=2000)
        pins = []
        for finding in findings:
            reviews = discovery.list_reviews(tenant, finding_id=finding.finding_id, limit=1)
            if not reviews:
                raise HTTPException(409, "A second person must approve every finding before this report can update Data Use.")
            review = reviews[0]
            pins.append(bridge.ClassificationPin(finding.finding_id, finding.revision, finding.integrity_sha256,
                review.review_id, review.version, review.integrity_sha256))
        asset = target.get_record(tenant, "asset", body.asset_id)
        context = target.get_context_authority(tenant, body.asset_id, "observed_classification")
        bridge_id = "pddb-" + digest({"asset": body.asset_id, "source": source.source_id})[:32]
        head = service.get_head(tenant, bridge_id)
        proposal = service.propose(tenant, bridge_id, body.asset_id, source.source_id, report.report_id, pins,
            expected_source_revision=source.revision, expected_source_integrity_sha256=source.integrity_sha256,
            expected_report_revision=1, expected_report_integrity_sha256=report.integrity_sha256,
            expected_asset_revision=asset["revision"], expected_asset_record_sha256=asset["record_sha256"],
            expected_context_revision=context["revision"] if context else 0,
            expected_context_record_sha256=context["record_sha256"] if context else None,
            expected_bridge_revision=head["revision"] if head else 0,
            retained_until=report.retention_until, idempotency_key=body.reference)
        _guard(request, services, proposal)()
        return _view(proposal)


def _apply(request, body):
    with authority_effect_fence():
        services = _services(request)
        _ops, tenant, _discovery, _target, service = services
        if context_for(request) != body.context:
            raise HTTPException(409, "Your account or workspace changed. Read the saved outcome in its original workspace.")
        proposal = _owned(request, tenant, service, body.reference)
        if proposal["integrity_sha256"] != body.proposal_sha256:
            raise HTTPException(409, "This confirmation no longer matches the saved review.")
        if service.application_admitted(tenant, proposal["proposal_id"]):
            return _original(request, body.reference, body.context)
        guard = _guard(request, services, proposal)
        guard()
        if not service.admit_application(tenant, proposal["proposal_id"],
                expected_proposal_integrity_sha256=body.proposal_sha256, idempotency_key=body.reference):
            return _original(request, body.reference, body.context)
        service.reconcile(tenant, proposal["proposal_id"], expected_proposal_integrity_sha256=body.proposal_sha256,
            expected_bridge_revision=proposal["expected_bridge_revision"], idempotency_key=body.reference,
            before_write=guard)
        return _original(request, body.reference, body.context)


async def _call(function, *args):
    try:
        return await run_in_threadpool(function, *args)
    except HTTPException:
        raise
    except bridge.DiscoveryDataUseBridgeNotFound as exc:
        raise HTTPException(404, "No saved review was found for this request. No update was repeated.") from exc
    except (bridge.DiscoveryDataUseBridgeConflict, discovery_authority.PrivacyDataDiscoveryConflict) as exc:
        raise HTTPException(409, "The report approvals or dataset changed, expired, or could not confirm an update. Read the saved outcome; do not repeat an uncertain update.") from exc
    except Exception as exc:
        raise HTTPException(503, "The saved review or update could not be verified. Read its saved outcome before trying again.") from exc


@router.get("/choices")
async def choices(request: Request):
    return await _call(overview, request)


@router.post("/prepare")
async def prepare(request: Request, body: PrepareIn):
    return await _call(_prepare, request, body)


@router.post("/apply")
async def apply(request: Request, body: ApplyIn):
    return await _call(_apply, request, body)


@router.get("/original/{reference}")
async def original(request: Request, reference: str, context: str):
    try:
        body = ApplyIn(reference=reference, context=context, proposal_sha256="0" * 64)
    except ValueError as exc:
        raise HTTPException(422, "The saved request reference is invalid.") from exc
    return await _call(_original, request, body.reference, body.context)
