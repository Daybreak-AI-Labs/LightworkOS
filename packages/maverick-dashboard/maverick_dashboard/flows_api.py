"""Workflow HTTP routes, using explicitly configured application services."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from starlette.responses import StreamingResponse

from .api_schemas import (
    FlowApplyIn,
    FlowApprovalPreviewIn,
    FlowChatIn,
    FlowDraftIn,
    FlowDryRunIn,
    FlowPublishIn,
    FlowResumeIn,
    FlowRetireIn,
    FlowRollbackIn,
    FlowRunIn,
    FlowSaveIn,
)
from .flow_dependencies import (
    _dashboard_token_authenticated,
    _event_trigger_allowed_owners,
    _live_tool_index,
    _live_tool_schemas,
    _supervisor,
    auth_genuinely_off,
    bind_request_services,
    caller_principal,
    caller_suites,
    configured_goal_ceiling_dollars,
    execution_user_id_from_request,
    goal_owner_filter,
    require_permission,
    run_in_threadpool,
)

log = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(bind_request_services)])


def _require_flows() -> None:
    from maverick import flow

    if not flow.enabled():
        raise HTTPException(
            status_code=403,
            detail="Workflows are turned off. Ask the person who manages this installation to turn them on.",
            headers={"X-Lightwork-Feature-Off": "workflows"},
        )


def _can_access_flow(request: Request, flow) -> bool:
    """Private definitions are visible only to their exact owner.

    Administration controls policy, not employee content. An auth-off local
    session may inspect only legacy ownerless definitions.
    """
    return flow is not None and getattr(flow, "owner", "") == (caller_principal(request) or "")


def _assert_flow_access(request: Request, flow) -> None:
    if not _can_access_flow(request, flow):
        raise HTTPException(status_code=404, detail="no such flow")


def _flow_publication_fields(flow_id: str) -> dict:
    """Small activation-state projection for authoring/list responses."""
    from maverick.flow import store

    try:
        published = store.load_published_bundle(flow_id)
    except store.FlowSnapshotError as exc:
        raise HTTPException(
            status_code=409, detail="published flow release failed integrity checks"
        ) from exc
    if published is None:
        return {
            "published": False,
            "published_version": None,
            "published_revision": "",
        }
    _flow, release = published
    return {
        "published": True,
        "published_version": int(release["definition_version"]),
        "published_revision": str(release["release_id"]),
    }


def _require_learned_flow_evidence(flow) -> None:
    """Give the same signed-example policy a useful product recovery message."""
    from maverick.flow import recipe_flow

    try:
        recipe_flow.check_persisted_lineage(flow)
    except ValueError as exc:
        if "admitted signed evidence" in str(exc):
            detail = (
                "This learned flow needs approved signed examples before it can be saved, "
                "published, or run. Open Teach this flow, review and allow its source "
                "runs for learning, then build and save a new flow."
            )
        else:
            detail = (
                "This learned flow's evidence is unavailable or invalid. Open Teach this "
                "flow and rebuild it from current signed examples."
            )
        raise HTTPException(status_code=409, detail=detail) from exc


@router.get("/flows")
def list_flows_endpoint(request: Request) -> dict:
    """The saved flow definitions (a summary per flow)."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    return {
        "flows": [
            {
                "id": f.id,
                "name": f.name,
                "nodes": len(f.nodes),
                "single_agent": f.is_single_agent(),
                "schedule": f.schedule,
                "inputs": f.inputs,
                **_flow_publication_fields(f.id),
            }
            for f in store.list_flows()
            if _can_access_flow(request, f)
        ]
    }


@router.post("/flows", status_code=201)
def save_flow_endpoint(request: Request, payload: FlowSaveIn) -> dict:
    """Create or replace a flow definition (validated before it is stored)."""
    return _save_flow_definition(request, payload)


def _save_flow_definition(request, payload, *, effect_guard=None):
    """Shared native save with an optional caller's current-state effect check."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import Flow, store

    try:
        flow = Flow.from_dict(payload.flow)
    except Exception as e:  # a malformed graph
        raise HTTPException(status_code=400, detail=f"invalid flow: {e}") from e
    if not flow.id:
        raise HTTPException(status_code=400, detail="flow needs an 'id'")
    errs = flow.validate()
    if errs:
        raise HTTPException(status_code=400, detail="invalid flow: " + "; ".join(errs[:5]))
    # Stamp ownership: the creator on first save, preserved across later edits so a
    # re-save can't silently transfer ownership. Scheduled (cron) runs attribute to
    # this owner (they have no request principal of their own).
    prior = store.load_flow(flow.id)
    if prior is not None:
        _assert_flow_access(request, prior)
        # Updates are compare-and-swap against what the editor actually loaded,
        # not a fresh server read performed moments before the write. Requiring
        # both the monotonic version and non-reused generation token closes stale
        # tab overwrites and delete+recreate ABA/ownership races.
        if "version" not in payload.flow or "revision" not in payload.flow:
            raise HTTPException(
                status_code=409,
                detail="flow changed or this editor is stale; reload before saving",
            )
    flow.owner = prior.owner if (prior and prior.owner) else (caller_principal(request) or "")
    _require_learned_flow_evidence(flow)
    try:
        def save_current():
            return store.save_flow(
                flow,
                expected_version=(payload.flow.get("version") if prior is not None else 0),
                expected_revision=(payload.flow.get("revision") if prior is not None else ""),
                effect_guard=effect_guard,
            )
        if payload.acquisition is not None:
            from .operator_acquisition import save_acquired
            save_acquired(request, payload.acquisition, payload.acquisition_acceptance, flow, save_current)
        else:
            save_current()
    except store.FlowVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="The flow cannot be saved safely; review its learned examples and try again.") from exc
    return {
        "id": flow.id,
        "nodes": len(flow.nodes),
        "version": flow.version,
        "revision": flow.revision,
        **_flow_publication_fields(flow.id),
    }


@router.post("/flows/{flow_id}/publish")
def publish_flow_endpoint(
    request: Request,
    flow_id: str,
    payload: FlowPublishIn,
) -> dict:
    """Activate one immutable draft revision for real runs/triggers/schedules."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    current = store.load_flow(flow_id)
    if current is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, current)
    _require_learned_flow_evidence(current)
    try:
        release = store.publish_flow(
            flow_id,
            expected_version=payload.version,
            expected_revision=payload.revision,
        )
    except store.FlowVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except store.FlowSnapshotError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="The flow cannot be published safely; review its learned examples and try again.") from exc
    # Make schedule activation responsive to an explicit publish. The periodic
    # reconcile remains the crash/restart repair path.
    from maverick_dashboard import automation_queue

    try:
        automation_queue._reconcile_flow_crons()
    except Exception:
        # Publication already committed. Report that authoritative state and
        # let the periodic reconciler repair scheduling instead of returning a
        # false failure that might induce a duplicate operator retry.
        log.exception("flow cron reconcile failed after publishing %s", flow_id)
    return {
        "id": flow_id,
        "published": True,
        "published_version": int(release["definition_version"]),
        "published_revision": str(release["release_id"]),
    }


@router.post("/flows/{flow_id}/unpublish")
def unpublish_flow_endpoint(
    request: Request,
    flow_id: str,
    payload: FlowRetireIn,
) -> dict:
    """Deactivate a release while retaining its draft and immutable history."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    current = store.load_flow(flow_id)
    if current is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, current)
    try:
        store.unpublish_flow(
            flow_id,
            expected_version=payload.version,
            expected_revision=payload.revision,
            expected_release_id=payload.expected_release_id,
        )
    except store.FlowVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except store.FlowSnapshotError as exc:
        raise HTTPException(status_code=409, detail="The published flow changed or could not be checked. Review it again.") from exc
    from maverick_dashboard import automation_queue

    try:
        automation_queue._reconcile_flow_crons()
    except Exception:
        # The handler re-checks publication before firing, so a stale queued
        # cron is inert while the periodic reconciler repairs cancellation.
        log.exception("flow cron reconcile failed after unpublishing %s", flow_id)
    return {"id": flow_id, "published": False}


_FLOW_DRAFT_TOOLS = (
    "slack_bot",
    "discord_bot",
    "teams",
    "email",
    "gmail",
    "twilio",
    "github_issues",
    "github_actions",
    "jira",
    "linear",
    "gitlab_issues",
    "salesforce",
    "hubspot",
    "stripe",
    "shopify",
    "servicenow",
    "zendesk",
    "notion",
    "confluence",
    "trello",
    "calendar",
    "dropbox",
    "s3",
    "http_fetch",
)


def _flow_tool_catalog(
    *,
    channel: str | None = None,
    user_id: str | None = None,
) -> list[dict]:
    """The curated connector catalog for the designer's action picker + the NL
    drafter's grounding: each tool's name, one-line description, and param names
    (from its input schema). Best-effort -- a tool absent from the live registry
    still appears by name so the picker/drafter can offer it."""
    by_name = {t["name"]: t for t in _live_tool_index(channel=channel, user_id=user_id)}
    out = []
    for name in _FLOW_DRAFT_TOOLS:
        t = by_name.get(name)
        if t is not None:
            out.append(dict(t))
    return out


def _flow_authoring_catalog(
    query: str,
    *,
    include_tools=(),
    channel: str | None = None,
    user_id: str | None = None,
) -> list[dict]:
    """Intent-ranked tools from the FULL live registry for one draft/chat turn.

    Existing action tools are appended only when they still exist in the live
    registry, so a harmless edit can retain a valid current binding while a
    stale/hallucinated legacy action remains fail-closed.
    """
    from maverick.flow.draft import rank_tool_catalog

    live = _live_tool_index(channel=channel, user_id=user_id)
    ranked = rank_tool_catalog(query, live, limit=24)
    by_name = {t["name"]: t for t in live}
    present = {t["name"] for t in ranked}
    for name in sorted({str(n) for n in include_tools if str(n)}):
        item = by_name.get(name)
        if item is not None and name not in present:
            ranked.append(item)
            present.add(name)
    schemas = _live_tool_schemas(channel=channel, user_id=user_id)
    return [{**item, "input_schema": dict(schemas.get(item["name"]) or {})} for item in ranked]


@router.post("/flows/draft")
async def draft_flow_endpoint(request: Request, payload: FlowDraftIn) -> dict:
    """Draft a first-pass flow from a plain-English description (the designer's
    ✨ button). Returns the flow graph (not saved) + any notes; falls back to a
    single agent step if the model can't produce a full graph. The drafter is
    grounded with each connector's description so action nodes name a real tool."""
    require_permission(request, "operate")
    _require_flows()
    from maverick_dashboard._shared import require_provider_or_400

    require_provider_or_400(role="orchestrator")
    from maverick_dashboard.app import check_goal_rate_limit

    check_goal_rate_limit(request, source="flow-authoring")
    from maverick.flow.draft import draft_flow

    user_id = execution_user_id_from_request(request)
    channel = "api" if user_id else None

    def _draft():
        catalog = _flow_authoring_catalog(payload.description, channel=channel, user_id=user_id)
        tool_docs = {t["name"]: t["description"] for t in catalog if t["description"]}
        tool_schemas = {t["name"]: t["input_schema"] for t in catalog}
        return draft_flow(
            payload.description,
            tools=tuple(t["name"] for t in catalog),
            tool_docs=tool_docs,
            tool_schemas=tool_schemas,
            flow_id=payload.flow_id,
        )

    flow, notes = await run_in_threadpool(_draft)
    return {"flow": flow.to_dict(), "notes": notes}


@router.post("/flows/chat")
async def flow_chat_endpoint(request: Request, payload: FlowChatIn) -> dict:
    """One turn of the designer's flow copilot: answer a question about the
    current canvas, or edit it via validated patches (never a whole-graph
    regeneration on a populated canvas). ``run_id`` grounds "why did this
    fail?" / "fix it" turns in that run's real per-node trace. The patched
    graph is returned to the canvas; nothing is saved until the user saves."""
    require_permission(request, "operate")
    _require_flows()
    from maverick_dashboard._shared import require_provider_or_400

    require_provider_or_400(role="orchestrator")
    from maverick_dashboard.app import check_goal_rate_limit

    check_goal_rate_limit(request, source="flow-authoring")
    from maverick.flow import Flow
    from maverick.flow.chat import chat_flow
    from maverick.flow.draft import action_tool_names

    try:
        current = Flow.from_dict(payload.flow) if payload.flow else None
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid flow: {e}") from e
    run = _run_out(_load_owned_run(request, payload.run_id)) if payload.run_id else None
    user_id = execution_user_id_from_request(request)
    channel = "api" if user_id else None

    def _turn():
        catalog = _flow_authoring_catalog(
            payload.message,
            include_tools=action_tool_names(current) if current is not None else (),
            channel=channel,
            user_id=user_id,
        )
        tool_docs = {t["name"]: t["description"] for t in catalog if t["description"]}
        tool_schemas = {t["name"]: t["input_schema"] for t in catalog}
        return chat_flow(
            payload.message,
            flow=current,
            history=payload.history,
            run=run,
            tools=tuple(t["name"] for t in catalog),
            tool_docs=tool_docs,
            tool_schemas=tool_schemas,
        )

    res = await run_in_threadpool(_turn)
    return {
        "reply": res.reply,
        "flow": res.flow.to_dict() if res.flow is not None else None,
        "applied": res.applied,
        "notes": res.notes,
    }


@router.get("/flows/runs")
def list_flow_runs_endpoint(request: Request, flow_id: str = "", limit: int = 50) -> dict:
    """Recent flow runs (owner-scoped). Defined before ``/flows/{flow_id}`` so the
    literal ``runs`` path isn't captured as a flow id."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    owner = goal_owner_filter(request)
    runs = store.list_run_metadata(flow_id=flow_id or None, owner=owner, limit=max(1, min(500, limit)))
    if owner == "":
        from .auth import anonymous_local_access_allowed
        if caller_principal(request) is None and anonymous_local_access_allowed():
            for label in ("operator", "local:dashboard"):
                candidates = store.list_run_metadata(flow_id=flow_id or None, owner=label, limit=max(1, min(500, limit)))
                runs.extend(run for run in candidates if _legacy_local_flow_run(request, run))
            runs.sort(key=lambda run: (run.updated, run.run_id), reverse=True)
            runs = runs[:max(1, min(500, limit))]
    return {"runs": [_run_out(r) for r in runs]}


@router.get("/flows/{flow_id}/schema")
def flow_schema_endpoint(request: Request, flow_id: str) -> dict:
    """The learned output-key shapes for a flow (from real runs): per key, its
    value type and, for objects/arrays-of-objects, the field names -- so the
    designer's data pills can offer nested keys like ``order.total``. Field
    names + types only; no values are ever stored or returned."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    flow = store.load_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, flow)
    return {"schema": store.load_flow_schema(flow_id)}


def _run_out(run) -> dict:
    """A flow run for the API with secret-looking values in its payloads masked,
    so a token a connector put into the run never leaves over HTTP."""
    from maverick.flow.redact import redact

    d = run.to_dict()
    d["data"] = redact(d.get("data") or {})
    d["input_data"] = redact(d.get("input_data") or {})
    # Execution snapshots are private durability state, not an API surface.
    # Definitions may contain literal connector parameters from older/user-made
    # flows, so never echo the pinned graph through run polling or SSE.
    d.pop("definition_digest", None)
    d.pop("release_digest", None)
    d.pop("release_id", None)
    d.pop("definition_version", None)
    d.pop("subflow_digests", None)
    if run.metadata_only:
        d["execution_data_status"] = "not_loaded"
        if run.status == "paused_approval":
            # A listing cannot attest current full-data/connector authority.
            # Detail/preview/resume endpoints still hydrate and verify it.
            d["human"] = {key: value for key, value in (d.get("human") or {}).items()
                          if key != "approval_card"}
            d["approval_binding_sha256"] = ""
            d["approval_card_status"] = "detail_required"
        return d
    if run.status == "paused_approval":
        from maverick.approval_cards import (
            ApprovalCardError,
            require_current_approval_card,
        )

        human = dict(d.get("human") or {})
        try:
            human["approval_card"] = require_current_approval_card(
                (run.human or {}).get("approval_card")
            )
        except ApprovalCardError as exc:
            # Never echo a malformed structured object as though it were safe
            # review content.  The paused run remains inspectable and blocked.
            human.pop("approval_card", None)
            d["approval_card_status"] = (
                "expired" if "expired" in str(exc) else "invalid"
            )
            d["approval_binding_sha256"] = ""
        else:
            from maverick_dashboard import automation_queue as aq

            try:
                human["approval_card"] = aq.current_flow_approval_card(run)
                d["approval_authority"] = aq._flow_approval_authority(run)
                d["approval_binding_sha256"] = aq.flow_approval_binding(run)
            except Exception:
                d["approval_binding_sha256"] = ""
                d["approval_card_status"] = "stale_or_authority_unavailable"
            else:
                d["approval_card_status"] = "current"
        d["human"] = human
        if run.cursor == "teaching_review":
            # The ordinary payload preview may truncate nested options. Expose
            # an exact, validated teaching question only on owned run detail,
            # after approval integrity checks; never bypass secret redaction.
            from maverick.flow import recipe_flow, store

            if d.get("approval_card_status") == "current":
                try:
                    pinned = store.load_flow_snapshot(run.definition_digest)
                    if pinned.recipe_teaching is None:
                        raise ValueError("not a teaching flow")
                    d["teaching_review"] = {"status": "unavailable"}
                    recipe_flow.validate_flow(pinned)
                    question = recipe_flow.validate_teaching_question(pinned.learned_recipe, run.data)
                    safe_question = redact(question)
                    if safe_question != question:
                        d["teaching_review"] = {"status": "redacted"}
                    else:
                        d["teaching_review"] = {"status": "current", "question": safe_question}
                except Exception:
                    # Do not surface raw observations or unverified options.
                    pass
    if getattr(run, "_approval_reviewer_only", False):
        # A named assignee can review the exact delegated card, not the flow
        # owner's execution data, graph, node trace or trigger inputs.
        human = d.get("human") or {}
        if d.get("approval_card_status") != "current":
            human = {key: value for key, value in human.items() if key != "approval_card"}
        return {
            "run_id": run.run_id, "flow_id": run.flow_id,
            "status": run.status, "cursor": run.cursor,
            "updated": run.updated, "resume_at": run.resume_at,
            "human": {key: human[key] for key in (
                "assignee", "choices", "form", "approval_card",
            ) if key in human},
            "approval_card_status": d.get("approval_card_status", "unavailable"),
            "approval_binding_sha256": d.get("approval_binding_sha256", ""),
            "approval_review_only": True,
        }
    return d


def _legacy_local_flow_run(request: Request, run) -> bool:
    """Recognize only demonstrably unowned pre-ownership local checkpoints."""
    from maverick.flow import store

    from .auth import anonymous_local_access_allowed

    if (caller_principal(request) is not None or not anonymous_local_access_allowed()
            or run is None or run.owner not in {"operator", "local:dashboard"}
            or run.execution_user_id or run.execution_channel
            or not run.definition_digest):
        return False
    try:
        definition = store.load_flow_snapshot(run.definition_digest)
        if definition.id != run.flow_id or definition.owner:
            return False
        store.validate_snapshot_bundle_owners(definition, run.subflow_digests)
        return all(run.subflow_digests.values())
    except (store.FlowSnapshotError, OSError, ValueError):
        return False


def _load_owned_run(request: Request, run_id: str, *, allow_assignee: bool = False):
    """A flow run the caller may see, or a 404 (indistinguishable from missing,
    so a run's existence isn't leaked across owners)."""
    from maverick.flow import store

    owner = goal_owner_filter(request)
    run = store.load_run(run_id, owner=owner)
    if run is None and owner == "":
        # The reserved labels were attribution defaults, not employee owners.
        # Never open arbitrary named records or use this under token/SSO auth.
        from .auth import anonymous_local_access_allowed
        if caller_principal(request) is None and anonymous_local_access_allowed():
            for label in ("operator", "local:dashboard"):
                candidate = store.load_run(run_id, owner=label)
                if _legacy_local_flow_run(request, candidate):
                    run = candidate
                    break
    if run is None:
        if allow_assignee:
            from maverick.flow.payloads import FlowPayloadError

            from .flow_approval_inbox import assigned_review_allowed

            try:
                candidate = store.load_run(run_id)
            except (FlowPayloadError, store.FlowSnapshotError, ValueError, TypeError, OSError):
                # A damaged foreign checkpoint cannot establish that this
                # caller is its assignee; keep it indistinguishable from a
                # missing run. The owner-scoped read above still reports the
                # actionable payload failure to the owner.
                raise HTTPException(status_code=404, detail="no such run") from None
            if assigned_review_allowed(request, candidate):
                candidate._approval_reviewer_only = True
                return candidate
        raise HTTPException(status_code=404, detail="no such run")
    return run


@router.get("/flows/runs/{run_id}")
async def get_flow_run_endpoint(request: Request, run_id: str) -> dict:
    require_permission(request, "operate")
    _require_flows()
    return _run_out(_load_owned_run(request, run_id, allow_assignee=True))


def _flow_value_version(run) -> str:
    material = [run.run_id, run.flow_id, run.owner, run.updated, run.data, run.input_data]
    return hashlib.sha256(json.dumps(material, sort_keys=True, ensure_ascii=False,
                                    allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def _flow_value_at(run, scope: str, path: list[int], part: str):
    from maverick.flow.redact import redact

    # Preserve key-based masking before traversing into a selected child.
    value = redact(run.data if scope == "data" else run.input_data, strict=True)
    name = "Information in this run" if scope == "data" else "What it started with"
    for index in path:
        if isinstance(value, dict):
            keys = sorted(value)
            if index >= len(keys):
                raise HTTPException(409, "This saved value changed. Reload the run information.")
            name = keys[index]
            value = value[name]
        elif isinstance(value, list) and index < len(value):
            value, name = value[index], f"Item {index + 1}"
        else:
            raise HTTPException(409, "This saved value changed. Reload the run information.")
    return redact(name, strict=True) if part == "name" else value


def _flow_value_kind(value) -> str:
    return ("object" if isinstance(value, dict) else "list" if isinstance(value, list)
            else "text" if isinstance(value, str) else "scalar")


def _flow_value_page(value, offset: int) -> dict:
    from maverick.flow.redact import redact

    kind = _flow_value_kind(value)
    if kind == "scalar":
        if offset:
            raise HTTPException(422, "This value has no further pages.")
        return {"kind": kind, "text": json.dumps(value, ensure_ascii=False, allow_nan=False),
                "total": 1, "remaining": 0, "next": None}
    total = len(value)
    if offset > total:
        raise HTTPException(422, "Choose a current page of this saved value.")
    end = min(total, offset + (4096 if kind == "text" else 20))
    result = {"kind": kind, "total": total, "remaining": total - end,
              "next": end if end < total else None}
    if kind == "text":
        result["text"] = value[offset:end]
    else:
        keys = sorted(value) if kind == "object" else range(total)
        result["children"] = [{"index": index,
                               "name": redact(str(keys[index]), strict=True)[:256] if kind == "object" else f"Item {index + 1}",
                               "name_complete": kind != "object" or len(redact(str(keys[index]), strict=True)) <= 256,
                               "kind": _flow_value_kind(value[keys[index]])}
                              for index in range(offset, end)]
    return result


@router.get("/flows/runs/{run_id}/values")
def flow_run_values_endpoint(
    request: Request, run_id: str, scope: str = "data", part: str = "value",
    path: list[int] = Query(default=[]), offset: int = Query(default=0, ge=0, le=16777216),
    version: str = "", context: str = "", updated: float | None = None,
) -> dict:
    """Read bounded pages from the owner's complete, verified native checkpoint."""
    from maverick.authority_effects import authority_effect_fence
    from maverick.flow import store
    from maverick.flow.payloads import FlowPayloadError

    from .auth import fresh_configuration
    from .draft_api import context_for

    if (scope not in {"data", "input"} or part not in {"value", "name"}
            or len(path) > 64 or any(index < 0 for index in path)
            or any(value and re.fullmatch(r"[a-f0-9]{64}", value) is None
                   for value in (version, context))):
        raise HTTPException(422, "Choose a current saved value from this run.")
    with authority_effect_fence(), fresh_configuration():
        require_permission(request, "operate")
        _require_flows()
        current_context = context_for(request)
        if context and context != current_context:
            raise HTTPException(409, "Your account or workspace changed. Reopen this run.")
        try:
            run = _load_owned_run(request, run_id)
            current_version = _flow_value_version(run)
            if ((version and version != current_version)
                    or (updated is not None and updated != run.updated)):
                raise HTTPException(409, "The saved values changed. Reload the run information.")
            result = _flow_value_page(_flow_value_at(run, scope, path, part), offset)
            # Formatting is available only for a declared answer in the exact
            # retained definition, never inferred from an arbitrary field name.
            definition = store.load_flow_snapshot(run.definition_digest) if run.definition_digest else None
            result["answer"] = bool(scope == "data" and part == "value" and len(path) == 1
                                    and definition and definition.owner == run.owner
                                    and definition.id == run.flow_id
                                    and definition.is_single_agent()
                                    and any(node.kind == "agent" and node.output == sorted(run.data)[path[0]]
                                            and (run.nodes.get(node.id) or {}).get("status") == "done"
                                            for node in definition.nodes.values()))
            if _flow_value_version(_load_owned_run(request, run_id)) != current_version:
                raise HTTPException(409, "The saved values changed. Reload the run information.")
        except (FlowPayloadError, store.FlowSnapshotError, OSError, ValueError) as exc:
            raise HTTPException(503, "Complete saved values are unavailable. Reopen this run after its retained data is available.") from exc
        require_permission(request, "operate")
        _require_flows()
        if context_for(request) != current_context:
            raise HTTPException(409, "Your account or workspace changed. Reopen this run.")
        return {**result, "context": current_context, "version": current_version,
                "scope": scope, "path": path, "part": part, "offset": offset}


@router.get("/flows/runs/{run_id}/events")
async def flow_run_events_stream(request: Request, run_id: str) -> StreamingResponse:
    """Server-Sent Events stream of a flow run's live state: one snapshot per
    change (keyed on the run's ``updated`` stamp), ending with a terminal event
    when the run completes/fails/rejects or parks on a human/event pause. The
    canvas overlay and the run viewer prefer this over polling; both fall back
    to polling when SSE is unavailable. Same slot cap + lifetime bound as the
    goal-events stream, so open tabs can't exhaust the event loop."""
    import asyncio as _asyncio
    import json as _json

    require_permission(request, "operate")
    _require_flows()
    _load_owned_run(request, run_id, allow_assignee=True)  # 404 before holding a stream slot
    from maverick.flow.payloads import FlowPayloadError

    from ._event_stream import LeasedStreamingResponse, StreamCadence, StreamLease
    from ._shared import _get_sse_semaphore

    sem = _get_sse_semaphore()
    if sem.locked():
        raise HTTPException(
            status_code=503,
            detail="too many concurrent event streams; retry shortly",
            headers={"Retry-After": "5"},
        )
    await sem.acquire()

    lease = StreamLease(sem)
    # completed/failed/rejected are final; a run parked on a human or an
    # external event won't change until someone acts -- close the stream and
    # let the page's actions (approve / resume) drive the next one.
    end_states = (
        "completed",
        "failed",
        "budget_limited",
        "rejected",
        "indeterminate",
        "paused_approval",
        "paused_event",
    )
    async def generate():
        clock = _asyncio.get_running_loop().time
        cadence = StreamCadence(clock(), clock())
        last_stamp = None
        try:
            yield "retry: 3000\n\n"
            cadence.sent(clock())
            while True:
                if cadence.expired(clock()):
                    yield 'event: timeout\ndata: {"detail": "stream lifetime exceeded"}\n\n'
                    return
                # Stop re-reading the run file the moment the client goes away
                # (a closed tab) instead of leaning solely on CancelledError
                # timing -- matches the goal-events stream.
                if await request.is_disconnected():
                    return
                require_permission(request, "operate")
                run = await run_in_threadpool(_load_owned_run, request, run_id, allow_assignee=True)
                if run is None:
                    yield 'event: error\ndata: {"detail": "run vanished"}\n\n'
                    return
                changed = run.updated != last_stamp
                if changed:
                    last_stamp = run.updated
                    payload = _run_out(run)
                    kind = "terminal" if run.status in end_states else "snapshot"
                    yield f"event: {kind}\ndata: {_json.dumps(payload, default=str)}\n\n"
                    cadence.sent(clock())
                    if kind == "terminal":
                        return
                elif cadence.heartbeat_due(clock()):
                    yield ": heartbeat\n\n"
                    cadence.sent(clock())
                cadence.backoff(changed)
                await _asyncio.sleep(cadence.delay(clock()))
        except HTTPException:
            yield 'event: error\ndata: {"detail": "Current workflow access is unavailable. Reopen the run.", "code": "permission_denied"}\n\n'
            return
        except FlowPayloadError:
            yield (
                'event: error\ndata: {"detail": "complete workflow data is unavailable; '
                'restore the checkpoint before resuming", "code": "flow_data_unavailable"}\n\n'
            )
        except _asyncio.CancelledError:
            return
        finally:
            lease.release()

    return LeasedStreamingResponse(
        generate(),
        lease=lease,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/flows/runs/{run_id}/approval-preview")
async def preview_flow_approval_endpoint(
    request: Request,
    run_id: str,
    payload: FlowApprovalPreviewIn,
) -> dict:
    """Bind the currently visible form values before a final approval click."""
    _require_flows()
    run = _load_owned_run(request, run_id, allow_assignee=True)
    if run.status != "paused_approval":
        raise HTTPException(
            status_code=409,
            detail=f"run is not awaiting approval (status {run.status})",
        )
    from .approval_authority import require_approval_authority

    require_approval_authority(
        request,
        action="flow.approval.preview",
        resource=run_id,
    )
    from maverick.approval_cards import digest
    from maverick.flow import store

    from maverick_dashboard import automation_queue as aq

    inputs = dict(payload.inputs or {})
    try:
        aq.current_flow_approval_card(run)
        binding = aq.flow_approval_binding(run, inputs=inputs)
    except store.FlowSnapshotError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "approval_binding_sha256": binding,
        "inputs_sha256": digest(inputs),
    }


@router.post("/flows/runs/{run_id}/resume")
async def resume_flow_run_endpoint(request: Request, run_id: str, payload: FlowResumeIn) -> dict:
    """Resume a paused flow run with a human decision (approve/reject)."""
    _require_flows()
    run = _load_owned_run(request, run_id, allow_assignee=True)
    decision_authority = None
    if run.status == "paused_approval":
        from .approval_authority import require_approval_authority

        decision_authority = require_approval_authority(
            request,
            action="flow.approval.decide",
            resource=run_id,
        )
    else:
        require_permission(request, "operate")
    # Only a paused run may be resumed -- resuming a completed/rejected run would
    # re-run the flow or run a rejected node (409, not a silent no-op).
    from maverick.flow.runner import PAUSED_STATUSES

    if run.status not in PAUSED_STATUSES:
        raise HTTPException(status_code=409, detail=f"run is not paused (status {run.status})")
    decided_by = ""
    if run.status == "paused_approval":
        if not str(payload.decision or "").strip():
            raise HTTPException(
                status_code=400,
                detail="an explicit approval decision is required",
            )
        decided_by = caller_principal(request) or ""
        if not decided_by and auth_genuinely_off():
            decided_by = "local:dashboard"
        if not decided_by:
            raise HTTPException(
                status_code=403,
                detail="an authenticated approver identity is required",
            )
        if not payload.approval_binding_sha256:
            raise HTTPException(
                status_code=409,
                detail="approval changed or was not reviewed; reload the run",
            )
    from maverick.flow import store

    from maverick_dashboard import automation_queue as aq

    try:
        aq.enqueue_flow_resume(
            run.flow_id,
            run_id,
            payload.decision,
            run.owner,
            decided_by=decided_by,
            inputs=dict(payload.inputs or {}),
            approval_binding_sha256=payload.approval_binding_sha256,
            decision_authority=decision_authority,
        )
    except store.FlowSnapshotError as exc:
        if "approver" in str(exc) or "approval decision" in str(exc):
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        detail = str(exc)
        raise HTTPException(
            status_code=409,
            detail=(
                detail
                if "approval" in detail
                else "run release is no longer active"
            ),
        ) from exc
    return {"run_id": run_id, "status": "resuming", "decision": payload.decision}


@router.post("/flows/runs/{run_id}/retry")
def retry_flow_run_endpoint(
    request: Request, run_id: str, from_failure: bool = False,
    budget_limit_dollars: float | None = Query(None, gt=0, allow_inf_nan=False),
) -> dict:
    """Re-run a finished/failed run from scratch with its ORIGINAL trigger inputs
    (a fresh run, so any partial side effects aren't re-driven mid-flow). This is
    the recovery path a dead-lettered run needs -- the run's input_data was kept
    for exactly this.

    ``?from_failure=1`` instead RESUMES a FAILED run in place, re-entering AT the
    node that failed with the data as of the failure -- the pre-failure nodes'
    side effects are not re-driven. Requires the run to be failed with a
    recorded failure cursor (409 otherwise)."""
    require_permission(request, "operate")
    _require_flows()
    run = _load_owned_run(request, run_id)
    # A still-in-flight run (queued/running or parked on ANY pause, including
    # paused_event) must not be retried-from-scratch -- that would spawn a
    # duplicate run alongside the live one. from_failure below is the only path
    # that acts on a failed run.
    from maverick.flow.runner import ACTIVE_STATUSES, QUARANTINED_STATUSES

    if run.status in ACTIVE_STATUSES:
        raise HTTPException(
            status_code=409, detail=f"run is still active (status {run.status}); nothing to retry"
        )
    if run.status in QUARANTINED_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=(
                "run has an indeterminate external-effect boundary; reconcile the "
                "target system before creating any replacement run"
            ),
        )
    from maverick.flow import store

    current_flow = store.load_flow(run.flow_id)
    if current_flow is None:
        raise HTTPException(status_code=404, detail="flow no longer exists")
    _assert_flow_access(request, current_flow)
    from maverick_dashboard import automation_queue as aq

    if from_failure:
        if run.status not in {"failed", "budget_limited"} or not run.cursor:
            raise HTTPException(
                status_code=409,
                detail="only a failed run with a recorded failure node can be "
                "resumed from its failure; use a plain retry instead",
            )
        ceiling = configured_goal_ceiling_dollars()
        if budget_limit_dollars is not None and ceiling is not None and budget_limit_dollars > ceiling:
            raise HTTPException(
                status_code=409,
                detail=f"The run allowance cannot exceed this deployment's per-run ceiling (${ceiling:g}).",
            )
        if run.status == "budget_limited":
            if budget_limit_dollars is None or budget_limit_dollars <= max(
                run.cost_dollars, run.budget_limit_dollars or 0.0,
            ):
                raise HTTPException(
                    status_code=409,
                    detail="Set a larger total run allowance to continue saved work. Organization limits still apply.",
                )
        elif budget_limit_dollars is not None:
            raise HTTPException(status_code=409, detail="Only a budget-held run can change its allowance.")
        try:
            aq.enqueue_flow_resume(
                run.flow_id,
                run_id,
                owner=run.owner,
                from_failure=True,
                budget_limit_dollars=budget_limit_dollars,
            )
        except store.FlowSnapshotError as exc:
            raise HTTPException(
                status_code=409,
                detail="run release is no longer active",
            ) from exc
        return {"run_id": run_id, "status": "resuming", "from_node": run.cursor}
    # Runs written before immutable definition snapshots have no pin fields at
    # all.  A user-requested retry is explicitly a fresh run against the current
    # definition, so migrate that narrow legacy shape by letting the ordinary
    # enqueue path take a new snapshot.  Partially pinned/tampered rows and
    # modern runs from another definition generation still fail closed.
    legacy_unpinned = (
        not run.definition_digest
        and run.definition_version == 0
        and not run.definition_revision
        and not run.subflow_digests
    )
    if not legacy_unpinned and current_flow.revision != run.definition_revision:
        raise HTTPException(
            status_code=409,
            detail=(
                "the flow definition has changed since this run; start a new "
                "run from the current flow instead"
            ),
        )
    identity = {
        "channel": run.execution_channel or None,
        "user_id": run.execution_user_id or None,
        "allowed_suites": (
            frozenset(run.allowed_suites) if run.allowed_suites is not None else None
        ),
    }
    if run.dry_run:
        if legacy_unpinned:
            raise HTTPException(
                status_code=409,
                detail="legacy dry run has no immutable definition to retry safely",
            )
        new_id = aq.enqueue_flow_run(
            run.flow_id,
            dict(run.input_data or {}),
            run.owner,
            origin=f"retry:{run_id}",
            dry_run=True,
            definition_digest=run.definition_digest,
            release_digest=run.release_digest,
            release_id=run.release_id,
            definition_version=run.definition_version,
            definition_revision=run.definition_revision,
            subflow_digests=dict(run.subflow_digests or {}),
            **identity,
        )
    else:
        try:
            published = store.load_published_bundle(run.flow_id)
        except store.FlowSnapshotError as exc:
            raise HTTPException(
                status_code=409,
                detail="published flow release failed integrity checks",
            ) from exc
        if published is None:
            raise HTTPException(
                status_code=409,
                detail="flow is not published; publish a reviewed draft before retrying",
            )
        published_flow, release = published
        _assert_flow_access(request, published_flow)
        new_id = aq.enqueue_published_flow_run(
            run.flow_id,
            dict(run.input_data or {}),
            run.owner,
            origin=f"retry:{run_id}",
            expected_revision=str(release["release_id"]),
            **identity,
        )
    return {"run_id": new_id, "status": "queued", "retried_from": run_id}


@router.get("/flows/tools")
async def flow_tools_endpoint(
    request: Request, q: str = "", category: str = "",
    offset: int = Query(0, ge=0, le=10000), limit: int = Query(50, ge=1, le=200),
) -> dict:
    """The connector/action catalog for the designer's categorized, searchable
    tool picker: name, description, param names, and a coarse ``category``.

    - no ``q``, no ``category``: the curated starter set.
    - ``category`` (no ``q``): a page of live tools in that bucket, with starter
      actions first. ``next_offset`` exposes the remaining authorized actions.
    - ``q``: a substring search over the FULL live registry, optionally narrowed
      to ``category``.

    Every response also carries ``categories`` (the display-ordered bucket names)
    so the picker can offer the filter without a second round-trip. Declared
    before ``/flows/{flow_id}`` so the literal ``tools`` path isn't captured as a
    flow id."""
    require_permission(request, "operate")
    _require_flows()
    from .tool_categories import categories as _cat_names

    q = q.strip().lower()[:80]
    category = category.strip()[:40]
    cats = _cat_names()
    user_id = execution_user_id_from_request(request)
    channel = "api" if user_id else None

    def _filter():
        if not q and not category:
            return _flow_tool_catalog(channel=channel, user_id=user_id)
        out = _live_tool_index(channel=channel, user_id=user_id)
        if category:
            out = [t for t in out if t.get("category") == category]
        if q:
            out = [t for t in out if q in f"{t['name']} {t['description']}".lower()]
            # name-prefix matches first, then name matches, then description-only
            out = sorted(
                out,
                key=lambda t: (
                    not t["name"].lower().startswith(q),
                    q not in t["name"].lower(),
                    t["name"],
                ),
            )
        else:
            starters = {name: index for index, name in enumerate(_FLOW_DRAFT_TOOLS)}
            out = sorted(out, key=lambda t: (starters.get(t["name"], len(starters)), t["name"]))
        return out

    tools = await run_in_threadpool(_filter)
    end = offset + limit
    return {
        "tools": tools[offset:end], "categories": cats, "total": len(tools),
        "next_offset": end if end < len(tools) else None,
    }


_FLOW_GALLERY: tuple[dict, ...] = (
    {
        "id": "",
        "name": "Triage inbound issues",
        "start": "n0",
        "description": "Summarize a new issue, escalate urgent ones, ask before posting.",
        "nodes": [
            {
                "id": "n0",
                "kind": "agent",
                "brief": "Summarize this issue and rate its urgency high/normal: {{title}} — {{body}}",
                "output": "summary",
                "next": "n1",
            },
            {"id": "n1", "kind": "branch", "condition": "urgency == high", "if_true": "n2"},
            {
                "id": "n2",
                "kind": "approval",
                "prompt": "Escalate this to the on-call channel?",
                "next": "n3",
            },
            {"id": "n3", "kind": "action", "tool": "slack_bot", "params": {"text": "{{summary}}"}},
        ],
    },
    {
        "id": "",
        "name": "Daily digest",
        "start": "n0",
        "description": "On a schedule, gather updates and email a one-paragraph digest.",
        "schedule": "0 9 * * *",
        "nodes": [
            {
                "id": "n0",
                "kind": "agent",
                "brief": "Gather yesterday's notable updates and write a one-paragraph digest.",
                "output": "digest",
                "next": "n1_gate",
            },
            {
                "id": "n1_gate",
                "kind": "approval",
                "prompt": "Send this daily digest?",
                "next": "n1",
            },
            {"id": "n1", "kind": "action", "tool": "email", "params": {"body": "{{digest}}"}},
        ],
    },
    {
        "id": "",
        "name": "Process a list with review",
        "start": "n0",
        "description": "Loop items concurrently, then a human signs off on the batch.",
        "nodes": [
            {
                "id": "n0",
                "kind": "foreach",
                "items": "rows",
                "var": "row",
                "concurrent": True,
                "output": "results",
                "next": "n1",
                "body": {
                    "id": "",
                    "name": "per row",
                    "start": "b0",
                    "nodes": [
                        {"id": "b0", "kind": "agent", "brief": "Handle {{row}}", "output": "r"}
                    ],
                },
            },
            {
                "id": "n1",
                "kind": "approval",
                "prompt": "Batch processed — publish the results?",
                "next": "n2",
            },
            {"id": "n2", "kind": "agent", "brief": "Publish the approved results: {{results}}"},
        ],
    },
    {
        "id": "",
        "name": "Wait for a callback",
        "start": "n0",
        "description": "Kick off work, wait for an external system to call back, then finish.",
        "nodes": [
            {
                "id": "n0",
                "kind": "agent",
                "brief": "Submit the request described in {{request}}",
                "output": "submitted",
                "next": "n1",
            },
            {
                "id": "n1",
                "kind": "wait_event",
                "prompt": "Waiting for the provider callback",
                "next": "n2",
            },
            {
                "id": "n2",
                "kind": "agent",
                "brief": "Reconcile the callback payload {{payload}} with {{submitted}}",
                "output": "done",
            },
        ],
    },
)


@router.get("/flows/gallery")
async def flow_gallery_endpoint(request: Request) -> dict:
    """Starter flow graphs for the designer's gallery. Declared before
    ``/flows/{flow_id}`` so the literal path isn't captured as a flow id."""
    require_permission(request, "operate")
    _require_flows()
    return {"flows": [dict(f) for f in _FLOW_GALLERY]}


@router.get("/flows/analytics")
async def flow_analytics_endpoint(request: Request, limit: int = 500) -> dict:
    """Per-flow run analytics over recent runs: volume, success rate, failure
    count, duration p50/p95, and the top recent error messages -- the aggregate
    view a single run page can't give. Owner-scoped. Declared before
    ``/flows/{flow_id}`` so the literal path isn't captured as a flow id."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import analytics

    owner = goal_owner_filter(request)
    # The aggregation reads + parses every run file in the window: keep that
    # off the event loop.
    return await run_in_threadpool(analytics.aggregate, owner=owner, limit=max(1, min(2000, limit)))


@router.get("/flows/insights")
def flow_insights_endpoint(request: Request) -> dict:
    """Proactive automation intelligence across all flows: pending self-rewrite
    proposals and the measured before/after impact of changes already applied --
    so the automations page can surface 'N suggestions to improve your flows'
    without a human opening each one. Read-only. Declared before ``/flows/{flow_id}``
    so the literal ``insights`` path isn't captured as a flow id."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import evolution_log, evolve, store

    flows_out = []
    proposal_count = 0
    for f in store.list_flows():
        if not _can_access_flow(request, f):
            continue
        proposals = [p.to_dict() for p in evolve.maybe_propose(f)]
        changes = []
        for node_id in f.nodes:
            last = evolution_log.last_apply(f.id, node_id)
            if not last:
                continue
            changes.append(
                {
                    "node_id": node_id,
                    "to_kind": last.get("to_kind"),
                    "source": last.get("source"),
                    "impact": evolve.measure(
                        f.id,
                        node_id,
                        float(last.get("ts") or 0.0),
                        before_revision=str(last.get("before_revision") or ""),
                        after_revision=str(last.get("after_revision") or ""),
                    ),
                }
            )
        if proposals or changes:
            flows_out.append(
                {"flow_id": f.id, "name": f.name, "proposals": proposals, "changes": changes}
            )
        proposal_count += len(proposals)
    return {"flows": flows_out, "proposal_count": proposal_count}


@router.post("/flows/dry-run")
def dry_run_flow_draft_endpoint(
    request: Request,
    payload: FlowDryRunIn,
) -> dict:
    """Run exactly the submitted unsaved graph with side-effect-free executors.

    This endpoint intentionally never calls ``save_flow`` or ``publish_flow``.
    It writes only the immutable execution object and durable dry-run row needed
    to execute/watch the test. A schedule present on the draft is inert.
    """
    require_permission(request, "operate")
    _require_flows()
    from uuid import uuid4

    from maverick.flow import Flow, store
    from maverick.flow.ir import coerce_inputs

    try:
        draft = Flow.from_dict(payload.flow)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid flow: {exc}") from exc
    if not draft.id:
        raise HTTPException(status_code=400, detail="flow needs an 'id'")
    prior = store.load_flow(draft.id)
    if prior is not None:
        _assert_flow_access(request, prior)
        draft.owner = prior.owner
        draft.version = int(prior.version) + 1
        draft.revision = prior.revision
    else:
        draft.owner = caller_principal(request) or ""
        draft.version = 1
        # Never accept a client-selected generation token as provenance.
        draft.revision = uuid4().hex
    errors = draft.validate()
    if errors:
        raise HTTPException(status_code=400, detail="invalid flow: " + "; ".join(errors[:5]))
    data, input_errors = coerce_inputs(draft, dict(payload.data or {}))
    if input_errors:
        raise HTTPException(status_code=400, detail="; ".join(input_errors))
    try:
        digest, version, subflows = store.snapshot_flow_bundle(draft)
        from maverick_dashboard import automation_queue as aq

        run_id, deduplicated = aq.enqueue_flow_run_once(
            draft.id,
            data,
            _supervisor(request),
            "",
            origin="manual-dry-run",
            dry_run=True,
            channel="api" if execution_user_id_from_request(request) else None,
            user_id=execution_user_id_from_request(request),
            allowed_suites=caller_suites(request),
            definition_digest=digest,
            definition_version=version,
            definition_revision=draft.revision,
            subflow_digests=subflows,
        )
    except store.FlowSnapshotError as exc:
        raise HTTPException(
            status_code=409,
            detail="draft or its immutable execution plan is unavailable",
        ) from exc
    run = store.load_run(run_id)
    return {
        "run_id": run_id,
        "status": run.status if run else "queued",
        "dry_run": True,
        "deduplicated": deduplicated,
    }


@router.get("/flows/{flow_id}")
def get_flow_endpoint(request: Request, flow_id: str) -> dict:
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    f = store.load_flow(flow_id)
    if f is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, f)
    return {**f.to_dict(), **_flow_publication_fields(flow_id)}


@router.get("/flows/{flow_id}/published")
def get_published_flow_endpoint(request: Request, flow_id: str) -> dict:
    """Review the exact published inputs and capture its publication epoch."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    draft = store.load_flow(flow_id)
    if draft is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, draft)
    try:
        published = store.load_published_bundle(flow_id)
    except store.FlowSnapshotError as exc:
        raise HTTPException(
            status_code=409,
            detail="published flow release failed integrity checks",
        ) from exc
    if published is None:
        raise HTTPException(
            status_code=409,
            detail="flow is not published; publish the reviewed draft before a live run",
        )
    flow, release = published
    _assert_flow_access(request, flow)
    return {
        "flow": flow.to_dict(),
        "release_id": str(release["release_id"]),
        "published": True,
        "published_version": int(release["definition_version"]),
        "published_revision": str(release["release_id"]),
        "published_at": release.get("published_at"),
    }


@router.get("/flows/{flow_id}/retirement")
def flow_retirement_preview_endpoint(request: Request, flow_id: str) -> dict:
    """Show what turning off or deleting a flow would affect before confirmation."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import runner, store
    from maverick.paths import current_tenant_id

    from maverick_dashboard import event_triggers_store, triggers_store

    flow = store.load_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, flow)
    try:
        published = store.load_published_bundle(flow_id)
    except store.FlowSnapshotError as exc:
        raise HTTPException(status_code=409, detail="The published flow could not be checked. Try again before changing it.") from exc
    tenant = current_tenant_id() or ""
    try:
        webhooks = sum(
            t.get("flow") == flow_id and t.get("tenant", "") == tenant
            and t.get("flow_owner", "") == flow.owner
            for t in triggers_store.list_triggers(strict=True)
        )
        linked_events = [
            t for t in event_triggers_store.list_triggers(strict=True)
            if t.get("flow") == flow_id and t.get("tenant", "") == tenant
            and t.get("owner", "") in _event_trigger_allowed_owners(request)
        ]
        pending_forms = sum(
            event_triggers_store.pending_form_submissions(t)
            for t in linked_events if t.get("source") == "form"
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail="Connected starts could not be checked. Try again before changing this flow.") from exc
    active_statuses = {
        runner.STATUS_QUEUED, runner.STATUS_CLAIMED, runner.STATUS_RUNNING,
        runner.STATUS_RESUMING, runner.STATUS_PAUSED_APPROVAL,
        runner.STATUS_PAUSED_DELAY, runner.STATUS_PAUSED_EVENT,
    }
    run_owners = {flow.owner}
    if (not flow.owner and caller_principal(request) is None
            and (_dashboard_token_authenticated(request) or auth_genuinely_off())):
        run_owners.update(("user:local", "operator", "local:dashboard"))
    active_runs = sum(
        1 for owner in run_owners
        for _ in store.iter_run_metadata(
            flow_id=flow_id, owner=owner, statuses=active_statuses
        )
    )
    try:
        published_parents = sum(
            parent.id != flow_id and parent.owner == flow.owner
            and release.get("subflow_digests", {}).get(flow_id) is not None
            for parent, release in store.list_published_bundles()
        )
    except store.FlowSnapshotError as exc:
        raise HTTPException(status_code=409, detail="Related published flows could not be checked. Try again before changing this flow.") from exc
    return {
        "id": flow.id, "name": flow.name, "version": flow.version,
        "revision": flow.revision, "published": published is not None,
        "release_id": str(published[1]["release_id"]) if published else "",
        "scheduled": bool(published and published[0].schedule.strip()),
        "connected_starts": webhooks + len(linked_events),
        "pending_forms": pending_forms,
        "active_runs": active_runs,
        "published_parent_flows": published_parents,
    }


@router.delete("/flows/{flow_id}", status_code=204)
def delete_flow_endpoint(
    request: Request, flow_id: str, response: Response, version: int | None = None,
    revision: str | None = None, expected_release_id: str | None = None,
) -> None:
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store
    from maverick.paths import current_tenant_id

    from maverick_dashboard import event_triggers_store

    f = store.load_flow(flow_id)
    if f is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, f)
    if (version is None) != (revision is None):
        raise HTTPException(status_code=400, detail="include both flow version and revision")
    try:
        # Public form submission holds this registry lock through its release
        # check and append. Retain that order while checking for accepted work
        # and revoking the release so a submission cannot become stranded.
        with event_triggers_store.registry_lock():
            linked_forms = [
                t for t in event_triggers_store.list_triggers(strict=True)
                if t.get("source") == "form" and t.get("flow") == flow_id
                and t.get("tenant", "") == (current_tenant_id() or "")
                and t.get("flow_owner", "") == f.owner
            ]
            if any(event_triggers_store.pending_form_submissions(t) for t in linked_forms):
                raise HTTPException(
                    status_code=409,
                    detail="This flow has received form submissions waiting in Automations. Review them before deleting it.",
                    headers={"X-Lightwork-Pending-Forms": "true"},
                )
            deleted = store.delete_flow(
                flow_id,
                expected_version=f.version if version is None else version,
                expected_revision=f.revision if revision is None else revision,
                expected_release_id=expected_release_id,
            )
    except store.FlowVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except store.FlowSnapshotError as exc:
        raise HTTPException(
            status_code=409,
            detail="flow could not be safely revoked; its draft was not deleted",
        ) from exc
    except (RuntimeError, OSError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Received submissions could not be checked. Open Automations and try again before deleting this flow.",
        ) from exc
    if not deleted:
        raise HTTPException(status_code=409, detail="flow changed while it was being deleted")
    # The private editor recovery slot is separate from definition history.
    # Retire its content after the confirmed delete; report a cleanup failure
    # separately because the flow itself cannot be restored by retrying DELETE.
    try:
        from .draft_api import context_for
        from .draft_store import DraftStore

        slot = hashlib.sha256(f"flow-designer:{flow_id}".encode()).hexdigest()
        drafts = DraftStore(context_for(request))
        copy = drafts.read(slot)
        if copy["payload"] is not None:
            drafts.save(slot, None, expected_revision=copy["revision"],
                        operation_id=secrets.token_hex(16))
        response.headers["X-Lightwork-Recovery-Copy"] = "cleared"
    except Exception:
        log.exception("flow %s deleted but its editor recovery copy could not be cleared", flow_id)
        response.headers["X-Lightwork-Recovery-Copy"] = "needs-review"
    from maverick_dashboard import automation_queue

    try:
        automation_queue._reconcile_flow_crons()
    except Exception:
        # The publication pointer is already gone; periodic reconciliation
        # repairs any remaining scheduled job.
        log.exception("flow cron reconcile failed after deleting %s", flow_id)


@router.post("/flows/{flow_id}/run")
def run_flow_endpoint(request: Request, flow_id: str, payload: FlowRunIn) -> dict:
    """Start the exact active release as a durable live run."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store
    from maverick.flow.ir import coerce_inputs

    draft = store.load_flow(flow_id)
    if draft is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, draft)
    if payload.dry_run:
        raise HTTPException(
            status_code=400,
            detail="submit the unsaved graph to /flows/dry-run for a safe test",
        )
    try:
        published = store.load_published_bundle(flow_id)
    except store.FlowSnapshotError as exc:
        raise HTTPException(
            status_code=409,
            detail="published flow release failed integrity checks",
        ) from exc
    if published is None:
        raise HTTPException(
            status_code=409,
            detail="flow is not published; publish the reviewed draft before a live run",
        )
    flow, release = published
    _assert_flow_access(request, flow)
    _require_learned_flow_evidence(flow)
    expected_release_id = payload.expected_release_id or str(release["release_id"])
    if expected_release_id != str(release["release_id"]):
        raise HTTPException(
            status_code=409,
            detail="published flow release changed since preview; review it before running",
        )
    # Ownership is the employee principal, distinct from audit actor labels.
    owner = caller_principal(request) or ""
    # Validate/coerce the payload against the flow's declared inputs (a no-op when
    # the flow declares none): reject a missing required input or a bad number/date
    # up front, and coerce number/bool/date so a node's condition sees typed values.
    data, input_errs = coerce_inputs(flow, dict(payload.data or {}))
    if input_errs:
        raise HTTPException(status_code=400, detail="; ".join(input_errs))
    # Idempotency: a caller-supplied key dedups a repeat submit (double-click, retry)
    # to the same run instead of firing a second one.
    idem = (payload.idempotency_key or "").strip()
    from maverick_dashboard import automation_queue as aq

    try:
        run_id, deduplicated = aq.enqueue_published_flow_run_once(
            flow_id,
            data,
            owner,
            idem,
            origin="manual",
            channel="api" if execution_user_id_from_request(request) else None,
            user_id=execution_user_id_from_request(request),
            allowed_suites=caller_suites(request),
            expected_revision=expected_release_id,
        )
    except store.FlowSnapshotError as exc:
        # Snapshot internals may include object paths/digests. The caller only
        # needs to know that the definition changed or cannot be pinned safely.
        raise HTTPException(
            status_code=409,
            detail="flow changed or its immutable execution plan is unavailable",
        ) from exc
    run = store.load_run(run_id)
    return {
        "run_id": run_id,
        "status": run.status if run else "queued",
        "dry_run": False,
        "deduplicated": deduplicated,
    }


@router.get("/flows/{flow_id}/proposals")
def flow_proposals_endpoint(request: Request, flow_id: str) -> dict:
    """Self-rewrite proposals for a flow: node-type swaps its grounded per-node
    outcomes justify (harden a reliable agent to an action, soften a flaky action
    to an agent). Proposals only -- never auto-applied."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import evolve, store

    f = store.load_flow(flow_id)
    if f is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, f)
    return {"proposals": [p.to_dict() for p in evolve.maybe_propose(f)]}


def _softening_action_rows(node) -> list[dict]:
    """Complete ordinary fields, with credential masking before presentation."""
    from maverick.flow.redact import redact

    rows = []

    def visit(label, value, depth=0):
        if depth > 12 or len(rows) >= 2048:
            raise HTTPException(409, "This action is too large for a complete replacement review. Edit it in the designer first.")
        if isinstance(value, dict) and value:
            for key, item in value.items():
                visit(label + " · " + str(redact(str(key), strict=True)).replace("_", " "), item, depth + 1)
        elif isinstance(value, list) and value:
            for index, item in enumerate(value):
                visit(label + " · Item " + str(index + 1), item, depth + 1)
        else:
            shown = ("Yes" if value else "No") if isinstance(value, bool) else (
                "Not set" if value is None else "Empty" if value in ({}, []) else str(value))
            rows.append({"label": label, "value": shown})

    try:
        visit("Current action", redact(node.tool, strict=True))
        visit("Current action inputs", redact(node.params, strict=True))
        visit("Answer kept as", redact(node.output, strict=True) or "No saved answer")
        visit("Current extra instructions", redact(node.brief, strict=True) or "None")
    except ValueError as exc:
        raise HTTPException(503, "The action could not be safely displayed. Nothing was changed.") from exc
    return rows


def _softening_review(request: Request, flow, node) -> dict:
    from maverick.governed_operations import digest

    from .draft_api import context_for

    context = context_for(request)
    publication = _flow_publication_fields(flow.id)
    return {"review_context": context,
            "review_binding": digest([context, flow.to_dict(), node.id, publication]),
            "current_action": _softening_action_rows(node), "brief": "",
            "replacement_consequences": [
                "The fixed action and its inputs are removed from this step in a new draft.",
                "The AI task uses only the complete replacement instructions you enter. A step label is not a substitute.",
                "Automatic retries for this step are turned off. Its answer destination stays the same.",
                "No work starts now. The published edition stays unchanged until you separately publish the draft.",
                "A credential value is masked when necessary; never copy credentials into the instructions.",
            ]}


def _save_reviewed_softening(request: Request, source, candidate, payload):
    from maverick.authority_effects import authority_effect_fence
    from maverick.flow import store

    if (payload.replacement_reviewed is not True or not payload.brief.strip()
            or payload.brief.strip() == source.nodes[payload.node_id].label.strip()):
        raise HTTPException(409, "Review the current action and enter complete replacement instructions before changing it to an AI task.")

    def guard():
        require_permission(request, "operate")
        _require_flows()
        current = store.load_flow(source.id)
        if current is None:
            raise HTTPException(404, "no such flow")
        _assert_flow_access(request, current)
        if payload.node_id not in current.nodes:
            raise HTTPException(409, "The selected step changed. Review the current workflow again.")
        review = _softening_review(request, current, current.nodes[payload.node_id])
        if (current.to_dict() != source.to_dict()
                or review["review_context"] != payload.review_context
                or review["review_binding"] != payload.review_binding):
            raise HTTPException(409, "The workflow or current access changed. Your replacement instructions are kept; review the current action again.")

    with authority_effect_fence(), store._definitions_lock():
        guard()
        return store.save_flow(candidate, expected_version=payload.version,
                               expected_revision=payload.revision, effect_guard=guard)


@router.get("/flows/{flow_id}/apply-review")
def flow_apply_review_endpoint(
    request: Request, flow_id: str, node_id: str, tool: str = "",
) -> dict:
    """Current, owner-scoped information for reviewing one suggested rewrite.

    The tool name is only a candidate. Its live registry contract and the
    available flow data are displayed for a person to bind before apply; this
    endpoint never treats tool-name telemetry as parameter evidence.
    """
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import evolve, store

    flow = store.load_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, flow)
    proposal = next(
        (p for p in evolve.maybe_propose(flow) if p.node_id == node_id), None,
    )
    if proposal is None:
        raise HTTPException(status_code=409, detail="This suggestion changed. Refresh the flow.")
    node = flow.nodes[node_id]
    result = {
        "flow_id": flow.id, "flow_name": flow.name,
        "version": flow.version, "revision": flow.revision,
        "node_id": node_id, "node_label": node.label or node_id,
        "from_kind": node.kind, "to_kind": proposal.to_kind,
        "published": bool(_flow_publication_fields(flow.id).get("published")),
        "inferred_tool": proposal.inferred_tool,
        "tool": "", "description": "", "fields": [], "sources": [],
    }
    if proposal.to_kind != "action":
        result.update(_softening_review(request, flow, node))
        return result

    chosen = (tool or proposal.inferred_tool or "").strip()
    if not chosen:
        return result
    user_id = execution_user_id_from_request(request)
    channel = "api" if user_id else None
    catalog = _live_tool_index(channel=channel, user_id=user_id)
    selected = next((entry for entry in catalog if entry["name"] == chosen), None)
    if selected is None:
        if not tool:
            # The learned name is a suggestion, not a binding. Keep the
            # review open so a person can choose a currently available action.
            return result
        raise HTTPException(409, detail="This action is no longer available. Choose a current action.")
    schema = _live_tool_schemas(channel=channel, user_id=user_id).get(chosen) or {}
    properties = schema.get("properties")
    if schema.get("type") != "object" or not isinstance(properties, dict):
        raise HTTPException(409, detail="This action's input contract is unavailable for review.")
    names = list(properties)
    if len(names) > 12:
        raise HTTPException(409, detail="This action has too many settings for the review form.")
    required_names = schema.get("required") or []
    if not isinstance(required_names, list) or not all(isinstance(name, str) for name in required_names):
        raise HTTPException(409, detail="This action's required settings could not be reviewed.")
    required = set(required_names)
    if required - set(names):
        raise HTTPException(409, detail="This action's required settings could not be reviewed.")
    fields = []
    for name in names:
        spec = properties.get(name) or {}
        if not isinstance(spec, dict):
            raise HTTPException(409, detail="This action's settings could not be reviewed.")
        kind = spec.get("type", "string")
        if kind not in {"string", "number", "integer", "boolean"}:
            raise HTTPException(409, detail="This action has complex settings. Configure it in the flow designer.")
        fields.append({
            "name": name, "label": name.replace("_", " ").capitalize(),
            "type": kind, "required": name in required,
            "description": str(spec.get("description") or "")[:200],
        })
    # A value can come from a declared run input or an earlier step's output.
    # Do not offer a downstream result, which cannot exist when this step runs.
    sources = [
        {"key": item["key"], "label": item.get("label") or item["key"], "origin": "input"}
        for item in flow.inputs
        if isinstance(item, dict) and isinstance(item.get("key"), str)
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", item["key"])
    ]
    for prior in flow.nodes.values():
        if (prior.id == node_id or not prior.output
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", prior.output)):
            continue
        pending, seen = [prior.id], set()
        while pending:
            current_id = pending.pop()
            if current_id == node_id:
                sources.append({"key": prior.output, "label": prior.label or prior.output,
                                "origin": "earlier_step"})
                break
            if current_id in seen or current_id not in flow.nodes:
                continue
            seen.add(current_id)
            current = flow.nodes[current_id]
            pending.extend(
                target for target in (current.next, current.if_true, current.if_false, current.on_error)
                if target
            )
    result.update({"tool": chosen, "description": selected.get("description") or "",
                   "fields": fields, "sources": sources})
    candidate = evolve.apply_proposal(flow, node_id, "action", tool=chosen, params={})
    result["approval_added"] = sum(n.kind == "approval" for n in candidate.nodes.values()) > sum(
        n.kind == "approval" for n in flow.nodes.values()
    )
    return result


@router.get("/flows/{flow_id}/signals")
def flow_signals_endpoint(request: Request, flow_id: str) -> dict:
    """The grounded learning signals a flow has accumulated, for display:
    per-node success rate (work nodes), human accept-rate (approval nodes), and
    trigger reliability (the reserved ``__trigger__`` outcome). This is what the
    loop CAPTURED made visible -- "which gates humans keep rejecting", "which
    triggers produce runs that succeed" -- so a builder can act on it."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import execution, node_outcomes, store

    f = store.load_flow(flow_id)
    if f is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, f)
    stats = node_outcomes.stats(flow_id)
    trigger = stats.get(execution.TRIGGER_NODE)
    nodes = {}
    for nid, s in stats.items():
        if nid == execution.TRIGGER_NODE:
            continue
        node = f.nodes.get(nid)
        nodes[nid] = {
            "n": s["n"],
            "mean": s["mean"],
            "kind": s.get("kind"),
            "label": (node.label if node else "") or nid,
        }
    return {
        "nodes": nodes,
        "trigger": ({"n": trigger["n"], "mean": trigger["mean"]} if trigger else None),
    }


@router.post("/flows/{flow_id}/apply")
def apply_flow_proposal_endpoint(
    request: Request, flow_id: str, payload: FlowApplyIn
) -> dict:
    """Apply a self-rewrite: swap a node between agent and action, producing a new
    flow version. This is the step that lets a flow *change itself* -- the applied
    definition is validated before it is saved, the prior version is retained (so
    it can be rolled back), and the apply is logged so its effect can be measured."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import evolution_log, evolve, store

    f = store.load_flow(flow_id)
    if f is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, f)
    if payload.version is None or not payload.revision:
        raise HTTPException(
            status_code=409,
            detail="flow changed or this editor is stale; reload before applying",
        )
    node = f.nodes.get(payload.node_id)
    if node is None:
        raise HTTPException(status_code=404, detail="no such node")
    if node.kind == payload.to_kind:
        raise HTTPException(status_code=400, detail=f"node is already a {payload.to_kind}")
    from_kind = node.kind
    try:
        new_flow = evolve.apply_proposal(
            f,
            payload.node_id,
            payload.to_kind,
            tool=payload.tool,
            params=payload.params,
            brief=payload.brief,
        )
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    errs = new_flow.validate()
    if errs:
        raise HTTPException(
            status_code=400, detail="resulting flow invalid: " + "; ".join(errs[:5])
        )
    try:
        if from_kind == "action" and payload.to_kind == "agent":
            saved = _save_reviewed_softening(request, f, new_flow, payload)
        else:
            saved = store.save_flow(
                new_flow,
                expected_version=payload.version,
                expected_revision=payload.revision,
            )
    except store.FlowVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    evolution_log.record_apply(
        flow_id,
        payload.node_id,
        from_kind,
        payload.to_kind,
        saved.version,
        source="manual",
        before_revision=store.flow_cohort(f),
        after_revision=store.flow_cohort(saved),
    )
    return {
        "id": flow_id,
        "version": saved.version,
        "node_id": payload.node_id,
        "from_kind": from_kind,
        "to_kind": payload.to_kind,
    }


@router.get("/flows/{flow_id}/versions")
def flow_versions_endpoint(request: Request, flow_id: str) -> dict:
    """Every stored version of a flow (newest first), each with a per-kind node
    count -- so the designer can show history and offer a rollback."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    current = store.load_flow(flow_id)
    if current is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, current)

    def _kinds(f) -> dict:
        c: dict[str, int] = {}
        for n in f.nodes.values():
            c[n.kind] = c.get(n.kind, 0) + 1
        return c

    versions = store.list_versions(flow_id)
    versions.reverse()  # newest first
    return {
        "versions": [
            {"version": v.version, "name": v.name, "nodes": len(v.nodes), "kinds": _kinds(v)}
            for v in versions
        ]
    }


@router.post("/flows/{flow_id}/rollback")
def rollback_flow_endpoint(request: Request, flow_id: str, payload: FlowRollbackIn) -> dict:
    """Roll a flow back to a prior version (default: the immediately previous),
    non-destructively -- the restore is itself a new version."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import store

    current = store.load_flow(flow_id)
    if current is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, current)
    if payload.current_version is None or not payload.revision:
        raise HTTPException(
            status_code=409,
            detail="flow changed or this editor is stale; reload before rolling back",
        )
    try:
        restored = store.rollback_flow(
            flow_id,
            payload.version,
            expected_version=payload.current_version,
            expected_revision=payload.revision,
        )
    except store.FlowVersionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if restored is None:
        raise HTTPException(status_code=404, detail="no such version to roll back to")
    return {"id": flow_id, "version": restored.version}


@router.get("/flows/{flow_id}/nodes/{node_id}/impact")
def flow_node_impact_endpoint(request: Request, flow_id: str, node_id: str) -> dict:
    """Whether a node was rewritten and, if so, how its grounded outcomes compare
    before vs. after the change -- the proof that a self-rewrite actually helped."""
    require_permission(request, "operate")
    _require_flows()
    from maverick.flow import evolution_log, evolve, store

    f = store.load_flow(flow_id)
    if f is None:
        raise HTTPException(status_code=404, detail="no such flow")
    _assert_flow_access(request, f)
    if node_id not in f.nodes:
        raise HTTPException(status_code=404, detail="no such node")
    last = evolution_log.last_apply(flow_id, node_id)
    if last is None:
        return {"node_id": node_id, "changed": False, "applied": None, "impact": None}
    impact = evolve.measure(
        flow_id,
        node_id,
        float(last.get("ts") or 0.0),
        before_revision=str(last.get("before_revision") or ""),
        after_revision=str(last.get("after_revision") or ""),
    )
    return {
        "node_id": node_id,
        "changed": True,
        "applied": {
            "from_kind": last.get("from_kind"),
            "to_kind": last.get("to_kind"),
            "version": last.get("version"),
            "ts": last.get("ts"),
            "source": last.get("source"),
        },
        "impact": impact,
    }
