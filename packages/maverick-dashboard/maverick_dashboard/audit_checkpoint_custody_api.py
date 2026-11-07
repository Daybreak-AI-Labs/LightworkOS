"""Independent checkpoint copies: full review, second-person approval and Original.

Only the governed native record admits an upload. All provider calls use the
same freshly resolved owned account and exact reviewed storage configuration.
"""
from __future__ import annotations

import datetime as dt
import re
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import config, connections, crypto_at_rest
from maverick.audit import checkpoint_custody as core
from maverick.audit import checkpoints, worm
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict, data_dir
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import audit_checkpoint_settings as settings
from . import auth, rbac, scim_groups
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/audit/checkpoint-custody", tags=["audit-checkpoints"])
TTL = 600
RECENT = 50


def store():
    return GovernedRecordStore("audit-checkpoint-custody", "ACC", "audit_checkpoint_custody")


class SetupRequired(HTTPException):
    """Independent storage is not set up yet: a refusal for changes, a state for the overview."""

    def __init__(self, detail: str):
        super().__init__(409, detail)


def _authority(request, context=None, *, setup=True):
    with auth.fresh_configuration():
        auth.require_permission(request, "audit")
        auth.require_page_permission(request, "/audit")
        auth.require_global_permission(request, "admin")
        actor = auth.caller_principal(request)
        principal = auth._resolve_principal(request=request)
        if not actor or principal is None or principal.principal != actor:
            raise HTTPException(401, "Sign in with your own installation administrator account to use independent checkpoint storage.")
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Storage settings could not be read. Nothing was changed.")
        if setup and (not connections.enabled() or not crypto_at_rest.at_rest_enabled()):
            raise SetupRequired("Enable Connections and encryption for saved data in Settings before using independent checkpoint storage.")
        current = context_for(request)
        if context is not None and current != context:
            raise HTTPException(409, "Your account or workspace changed. Open the current activity log again.")
        return actor, current


def _target():
    value = worm._worm_cfg()
    bucket, region = str(value.get("bucket") or ""), str(value.get("region") or "")
    prefix = str(value.get("prefix") or "").strip("/")
    if (value.get("provider") not in {"s3", "aws"} or value.get("endpoint_url")
            or str(value.get("mode") or "COMPLIANCE").upper() != "COMPLIANCE"
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket)
            or not re.fullmatch(r"[a-z]{2}-[a-z]+-\d+", region) or region.startswith("cn-")
            or len(prefix) > 512 or (bool(prefix) and any(not segment or segment in {".", ".."} for segment in prefix.split("/")))
            or not re.fullmatch(r"[A-Za-z0-9_./-]*", prefix)):
        raise SetupRequired("Choose Amazon S3, a bucket, region and Compliance retention on the Compliance page. Independent checkpoints require the Amazon service and do not use local folders or custom storage endpoints.")
    try:
        days = int(value.get("retention_days") or 2555)
    except (ValueError, TypeError):
        days = 0
    if not 1 <= days <= 36500:
        raise SetupRequired("Choose a storage retention period between 1 and 36,500 days on the Compliance page.")
    return {"bucket": bucket, "region": region, "prefix": prefix, "mode": "COMPLIANCE"}, days


def _accounts(actor, target):
    origin = "https://" + target["bucket"] + ".s3." + target["region"] + ".amazonaws.com"
    return [{"name": row["name"], "revision": row["revision"]} for row in connections.list_connections(owner=actor)
            if row["connector"] == "aws_s3" and row["has_token"] and row["base_url"].rstrip("/") == origin]


def _source():
    source = core.capture(settings.checkpoint_dir(), keys=settings.trusted_pubkeys())
    if checkpoints.verify_checkpoints(data_dir("audit"), settings.checkpoint_dir(), trusted_pubkeys=settings.trusted_pubkeys()):
        raise HTTPException(409, "The signed checkpoint history does not match the activity log. Check it before preparing an independent copy.")
    return source


def _rows():
    """Complete rotating backend cursor scan; old completions never fill a cap."""
    service, cursor = store(), ""
    while True:
        page = list(service.iter_record_ids(start_after=cursor, limit=100))
        if not page:
            return
        for next_cursor, identifier in page:
            if next_cursor <= cursor:
                return
            row = service.get(identifier)
            if row is None:
                raise HTTPException(409, "A retained copy request disappeared during its inventory. Refresh before continuing.")
            yield row
            cursor = next_cursor
        if len(page) < 100:
            return


def _display(row, actor):
    import json
    history = [json.loads(text) for text in row["source"]["records"]]
    return {"id": row["id"], "revision": row["revision"], "state": row["state"],
            "requested_by": row["actor"], "reviewed_by": row.get("reviewer"),
            "sequence": row["source"]["sequence"], "day": row["source"]["day"],
            "row_count": row["source"]["row_count"], "checkpoint_sha256": row["source"]["checkpoint_sha256"],
            "checkpoint_count": len(row["source"]["records"]), "account": row["account"]["name"],
            "workspace": current_tenant_id_strict() or "This installation",
            "history": [{"sequence": item["checkpoint_sequence"], "day": item["day"],
                         "kind": item["record_type"], "rows": item["row_count"]} for item in history],
            "destination": row["destination"], "retain_until": row["retain_until"], "expires": row["expires"],
            "can_approve": row["state"] == "review" and actor != row["actor"] and time.time() < row["expires"],
            "can_apply": row["state"] == "approved" and actor == row["actor"] and time.time() < row["expires"],
            "can_cancel": row["state"] in {"review", "approved"} and actor == row["actor"],
            "result": row.get("result"), "copy_may_exist": row["state"] in {"dispatching", "unknown", "retained"},
            "statement": "This sends only the complete signed checkpoint prefix, workspace, requesting and reviewing people and retention commitment. Audit entry contents and saved keys are not included. Amazon enforces each version's lock; storage administrator independence and future availability are not proven."}


def state(request):
    actor, context = _authority(request)
    target, days = _target()
    try:
        source, note = _source(), "The complete latest signed checkpoint prefix is ready for review."
    except (core.CustodyRefused, checkpoints.AuditCheckpointError, HTTPException, OSError, RuntimeError):
        source, note = None, "Publish and check a history checkpoint first. Independent history can still be checked if local history is missing or damaged."
    import heapq
    count, pending = 0, []
    for row in _rows():
        count += 1
        priority = 1 if row["state"] in {"review", "approved", "dispatching", "unknown"} else 0
        heapq.heappush(pending, (priority, row["created_at"], row["id"], row))
        if len(pending) > RECENT:
            heapq.heappop(pending)
    rows = [item[-1] for item in sorted(pending)]
    result = {"context": context, "destination": target, "retention_days": days,
              "accounts": _accounts(actor, target), "note": note,
              "source": {key: value for key, value in source.items() if key != "records"} if source else None,
              "requests": [_display(row, actor) for row in rows], "request_count": count,
              "request_scope": "Up to 50 requests, prioritizing pending or uncertain copies, then recent completions. Saved Original references remain readable regardless of this list."}
    result["inventory"] = digest(result)
    _authority(request, context)
    return result


def _row(identifier):
    if not re.fullmatch(r"ACC-[a-f0-9]{32}", identifier):
        raise HTTPException(422, "Choose a saved independent checkpoint request.")
    row = store().get(identifier)
    if row is None:
        raise HTTPException(404, "This checkpoint request is no longer available. Check independent history to read the retained remote commitments.")
    return row


def _current(request, row, *, source=True, owner=True, expiry=True, reviewer=False):
    actor, _context = _authority(request, row["context"] if owner else None)
    if owner and actor != row["actor"]:
        raise HTTPException(403, "Only the person who prepared this copy can apply or recover its original result.")
    target, days = _target()
    if target != row["destination"] or days != row["retention_days"] or digest(settings.load()) != row["key_policy"]:
        raise HTTPException(409, "Storage, retention or trusted signing keys changed. Read the saved outcome before reviewing again.")
    if expiry and time.time() >= row["expires"]:
        raise HTTPException(409, "This review expired. Read its original outcome before preparing another copy.")
    if row["account"] not in _accounts(row["actor"], target):
        raise HTTPException(409, "The saved Amazon account changed or was removed. Its original request will not be repeated.")
    if source and digest(_source()) != row["source_pin"]:
        raise HTTPException(409, "The signed checkpoint prefix changed. Read the original outcome and review the current history.")
    if reviewer:
        person = row.get("reviewer")
        if (not person or person == row["actor"] or scim_groups.active_for_principal(person) is False
                or "admin" not in rbac.permissions_for(auth.global_role_for_principal(person))
                or "audit" not in rbac.permissions_for(auth.role_for_principal(person))):
            raise HTTPException(409, "The independent reviewer's access is no longer current. Nothing further will be copied.")
    return actor


def _transport(request, row, *, effect=False):
    def guard():
        _current(request, row, source=effect, expiry=effect, reviewer=effect)
        if effect and row["state"] == "dispatching":
            saved = _row(row["id"])
            if saved["state"] != "dispatching" or saved["revision"] != row["revision"]:
                raise HTTPException(409, "The admitted request changed before the provider call. Read Original; nothing will be repeated.")
    guard()
    return core.RetainedCheckpoints(row["destination"], row["account"], workspace=current_tenant_id_strict(),
        actor=row["actor"], guard=guard, keys=settings.trusted_pubkeys())


class PrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    inventory: str = Field(pattern=r"^[a-f0-9]{64}$")
    reference: str = Field(pattern=r"^[a-f0-9]{32}$")
    account: str = Field(min_length=1, max_length=64)
    account_revision: str = Field(min_length=1, max_length=64)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_revision: int = Field(ge=1)
    confirm: bool = False


class CheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    account: str = Field(min_length=1, max_length=64)
    account_revision: str = Field(min_length=1, max_length=64)


def prepare(request, body):
    with authority_effect_fence():
        actor, context = _authority(request, body.context)
        identifier = "ACC-" + body.reference
        existing = store().get(identifier)
        if existing:
            if existing["actor"] != actor or existing["context"] != context or existing["account"] != {"name": body.account, "revision": body.account_revision}:
                raise HTTPException(409, "This saved reference belongs to a different review. Read its Original result.")
            return _display(existing, actor)
        current = state(request)
        account = {"name": body.account, "revision": body.account_revision}
        if body.inventory != current["inventory"] or account not in current["accounts"]:
            raise HTTPException(409, "The checkpoint, saved account or storage changed. Refresh and review the current choices.")
        source = _source()
        for row in _rows():
            if (row["destination"] == current["destination"] and row["source_pin"] == digest(source)
                    and (row["state"] in {"dispatching", "unknown"} or row["state"] in {"review", "approved"} and time.time() < row["expires"])):
                raise HTTPException(409, "This exact history already has a pending or uncertain request. Read its Original outcome; do not create another upload.")
        until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=current["retention_days"])).replace(microsecond=0).isoformat()
        value = {"id": identifier, "actor": actor, "context": context, "state": "review", "source": source,
                 "source_pin": digest(source), "destination": current["destination"], "account": account,
                 "retention_days": current["retention_days"], "retain_until": until, "expires": time.time() + TTL,
                 "key_policy": digest(settings.load())}
        row = store().create(value, action="checkpoint_custody_review", actor=actor,
            effect_guard=lambda: _current(request, value))
        if row.get("_audit_pending"):
            raise HTTPException(503, "The review is saved but its activity record is not confirmed. Read Original; no upload was started.")
        return _display(row, actor)


def decide(request, identifier, body, action):
    with authority_effect_fence():
        actor, _context = _authority(request, body.context, setup=action != "cancel")
        row = _row(identifier)
        if action == "cancel":
            if row["actor"] != actor or row["context"] != body.context:
                raise HTTPException(403, "Only the requester can cancel this unstarted copy.")
        else:
            _current(request, row, owner=False)
        def guard():
            if action == "cancel":
                _authority(request, row["context"], setup=False)
            else:
                _current(request, row, owner=False)
        if not body.confirm or row["revision"] != body.expected_revision:
            raise HTTPException(409, "Read and confirm the complete current review before continuing.")
        if action == "approve" and (actor == row["actor"] or row["state"] != "review"):
            raise HTTPException(403, "A different current installation administrator must approve this copy.")
        if action == "cancel" and row["state"] not in {"review", "approved"}:
            raise HTTPException(409, "An admitted upload cannot be cancelled or repeated. Read its Original result.")
        changed = {"state": "approved", "reviewer": actor} if action == "approve" else {"state": "cancelled"}
        result = store().update(identifier, lambda value: value.update(changed), expected_revision=row["revision"],
            action="checkpoint_custody_" + action, actor=actor,
            effect_guard=guard)
        return _display(result, actor)


def original(request, identifier):
    actor, _context = _authority(request, setup=False)
    row = _row(identifier)
    if row["actor"] != actor:
        return _display(row, actor)
    if row["state"] not in {"dispatching", "unknown", "retained"}:
        result = _display(row, actor)
        try:
            _current(request, row, owner=False)
        except HTTPException as exc:
            result["can_apply"] = result["can_approve"] = False
            result["result"] = {"message": "This saved review is no longer current. It has not been sent; the requester can cancel it.", "refusal": exc.detail}
        return result
    try:
        transport = _transport(request, row)
        remote = transport.inventory()
    except HTTPException as exc:
        result = _display(row, actor)
        result["can_apply"] = result["can_approve"] = False
        result["result"] = {"message": "The saved original remains retained, but current account or storage access no longer permits a remote check. No upload was repeated.",
                            "remote_check_available": False, "refusal": exc.detail}
        return result
    match = next((item for item in remote["versions"] if item["payload_sha256"] == row.get("payload_sha256")), None)
    result = _display(row, actor)
    result["state"] = "retained" if match else "unknown"
    result["result"] = {"matching_retained_copy": bool(match), "complete_inventory": True,
                        "retained_until": match["retain_until"] if match else None,
                        "message": "The exact original copy was read with current Compliance retention. No upload was repeated." if match else
                            "The original upload remains unconfirmed. No copy was repeated, even if its latest name is hidden by a deletion marker."}
    return result


def apply(request, identifier, body):
    with authority_effect_fence():
        actor, _context = _authority(request, body.context)
        row = _row(identifier)
        if row["actor"] != actor:
            raise HTTPException(403, "The requester must apply this independently approved copy.")
        if row["state"] in {"dispatching", "unknown", "retained"}:
            raise HTTPException(409, "This upload was already admitted. Read Original; this request cannot be repeated.")
        if row["state"] != "approved" or not body.confirm or row["revision"] != body.expected_revision or row.get("_audit_pending"):
            raise HTTPException(409, "A second administrator must approve the complete current review before you confirm the copy.")
        _current(request, row, reviewer=True)
        payload = core.bundle(row["source"], workspace=current_tenant_id_strict(), actor=actor, reviewer=row["reviewer"],
            destination=row["destination"], retain_until=row["retain_until"])
    transport = _transport(request, row, effect=True)
    remote = transport.inventory()
    local = {index: core.sha(text.encode()) for index, text in enumerate(row["source"]["records"], 1)}
    if any(item["sequence"] > len(local) or local.get(item["sequence"]) != item["checkpoint_sha256"] for item in remote["versions"]):
        raise HTTPException(409, "Independent storage proves a newer or different history. This copy was refused; check independent history.")
    with authority_effect_fence():
        _current(request, row, reviewer=True)
        row = store().update(identifier, lambda value: value.update(state="dispatching", payload_sha256=core.sha(payload)),
            expected_revision=row["revision"], action="checkpoint_custody_admitted", actor=actor,
            effect_guard=lambda: _current(request, row, reviewer=True))
        if row.get("_audit_pending"):
            raise HTTPException(503, "The upload reservation is saved but its audit completion is uncertain. Read Original; no automatic retry will run.")
    # The pre-dispatch reservation is durable before physical provider work.
    # Guards are re-evaluated inside each bounded provider call after waits.
    try:
        transport = _transport(request, row, effect=True)
        locator = transport.upload(payload, row["source"], worm._parse_utc(row["retain_until"]))
        outcome = {"state": "retained", "result": {"matching_retained_copy": True, "locator": locator,
            "message": "The exact version's bytes and Compliance retention were read back from Amazon. This proves provider acceptance, not future availability or independent administration."}}
    except core.CustodyUnconfirmed:
        outcome = {"state": "unknown", "result": {"matching_retained_copy": False,
            "message": "The upload may have happened. Read Original; do not repeat this request."}}
    except Exception:
        outcome = {"state": "unknown", "result": {"matching_retained_copy": False,
            "message": "The admitted copy could not be confirmed under current access. Read Original; no automatic retry will run."}}
    with authority_effect_fence():
        _authority(request, row["context"])
        saved = store().update(identifier, lambda value: value.update(outcome), expected_revision=row["revision"],
            action="checkpoint_custody_outcome", actor=actor, effect_guard=lambda: _authority(request, row["context"]))
    return _display(saved, actor)


def check(request, body):
    actor, context = _authority(request, body.context)
    target, days = _target()
    account = {"name": body.account, "revision": body.account_revision}
    policy = digest(settings.load())

    def guard():
        _authority(request, context)
        if _target() != (target, days) or digest(settings.load()) != policy or account not in _accounts(actor, target):
            raise HTTPException(409, "The storage, saved account, retention or trusted keys changed during verification. No verification result was accepted.")
    guard()
    transport = core.RetainedCheckpoints(target, account, workspace=current_tenant_id_strict(), actor=actor,
        guard=guard, keys=settings.trusted_pubkeys())
    return core.verify_current(transport, data_dir("audit"), settings.checkpoint_dir(), keys=settings.trusted_pubkeys())


async def _call(function, *args):
    try:
        return await run_in_threadpool(function, *args)
    except HTTPException:
        raise
    except (core.CustodyRefused, checkpoints.AuditCheckpointError) as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Independent checkpoint storage or its saved request could not be confirmed. Keep the request and read Original; nothing will automatically retry.") from exc


@router.get("")
async def overview(request: Request):
    try:
        value = await _call(state, request)
    except SetupRequired as exc:
        # Raised only after the administrator checks: an install without
        # storage reads what to set up rather than an error on every visit.
        value = {"setup_required": exc.detail, "context": await run_in_threadpool(context_for, request)}
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.post("/prepare")
async def prepare_copy(request: Request, body: PrepareIn):
    return await _call(prepare, request, body)


@router.post("/check")
async def check_history(request: Request, body: CheckIn):
    return await _call(check, request, body)


@router.get("/{identifier}/original")
async def original_copy(request: Request, identifier: str):
    return JSONResponse(await _call(original, request, identifier), headers={"Cache-Control": "private, no-store"})


@router.post("/{identifier}/{action}")
async def decide_copy(request: Request, identifier: str, action: str, body: DecisionIn):
    if action == "apply":
        return await _call(apply, request, identifier, body)
    if action not in {"approve", "cancel"}:
        raise HTTPException(404, "Choose one of this review's available actions.")
    return await _call(decide, request, identifier, body, action)
