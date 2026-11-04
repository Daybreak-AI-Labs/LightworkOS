"""Named native policy-exception choices and protected, read-only Copilot handoff."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import HTTPException
from maverick import ai_policy_management as policy
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import model_risk_schemas as schemas
from .draft_api import context_for
from .model_risk_api import _human_principal, _require_active_tenant
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, StrictInput

PAGE = "/security/assurance"
DESCRIPTOR = {"scope": "current_page"}


def authority(request, expected=None):
    from .api_flow_operator_review import _workspace_authority
    from .app import require_page_visible

    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    auth.require_global_permission(request, "admin")
    tenant, actor = _require_active_tenant(), _human_principal(request)
    suites, scopes = auth.caller_suites(request), auth.api_key_scopes(request)
    context = digest([context_for(request), _workspace_authority(request, actor, tenant),
                      auth.caller_role(request), sorted(suites) if suites is not None else None,
                      sorted(scopes) if scopes is not None else None])
    if expected is not None and context != expected:
        raise HTTPException(409, "Your account, workspace or access changed. Read the current exception controls again.")
    return actor, context


def catalog(request):
    from maverick import model_risk_assurance, security_ops

    _actor, context = authority(request)
    try:
        service = policy.configured_policy_management()
        policies, exceptions = service.list_policies(), service.list_exceptions()
        controls = []
        for row in security_ops.list_controls():
            identifier = str(row.get("id") or "")
            if (not policy._TOKEN_RE.fullmatch(identifier) or row.get("status") == "retired"
                    or row.get("applicable") is False):
                continue
            controls.append({"value": identifier.lower(), "label": str(row.get("title") or "Unnamed safeguard"),
                             "status": str(row.get("implementation_status") or "unknown"),
                             "owner": str(row.get("owner") or "Unassigned"), "revision": row.get("revision")})
        assets = [{"value": str(row["asset_id"]).lower(), "label": str(row.get("display_name") or "Unnamed AI system")}
                  for row in model_risk_assurance.list_inventory()]
    except (policy.AIPolicyManagementError, OSError, ValueError) as exc:
        raise HTTPException(503, "Current rules and safeguards could not be verified. Your entered work is kept.") from exc
    authority(request, context)
    return {"context": context, "policies": policies, "exceptions": exceptions, "controls": controls, "assets": assets,
            "revision": digest([context, policies, exceptions, controls, assets]),
            "notice": "Current workspace records only. Selecting a recorded safeguard does not prove it is in place. "
                      "A request has no effect until a different administrator approves it; approval expires at the chosen time."}


class OriginalInput(StrictInput):
    context: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: Literal["request", "approve", "close"]
    body: dict[str, Any]
    previous: dict[str, Any] | None = None


def original(request, envelope: OriginalInput):
    """Read retained immutable request fields and the actual lifecycle receipt.

    There is no historical HTTP-response journal in this native service. A
    matching current status alone is insufficient: identity, full requested
    content, human actor and (for changes) the prior revision must agree.
    """
    actor, context = authority(request, envelope.context)
    try:
        if envelope.kind == "request":
            body = schemas.AIPolicyExceptionRequestIn.model_validate(envelope.body).model_dump()
            expected = {**body, "scope": policy._normalize_scope(body["scope"]),
                        "compensating_control_ids": policy._tokens(body["compensating_control_ids"], "safeguards", maximum=128),
                        "reason": policy._text(body["reason"], "reason", 2000), "requester": actor}
            key = body["exception_key"]
        else:
            previous = envelope.previous
            if not isinstance(previous, dict):
                raise ValueError("A retained previous exception is required")
            key = policy._token(previous.get("exception_key"), "exception")
            model = schemas.AIPolicyExceptionApproveIn if envelope.kind == "approve" else schemas.AIPolicyExceptionCloseIn
            body = model.model_validate(envelope.body).model_dump()
            if previous.get("revision") != body["expected_revision"]:
                raise ValueError("The retained previous version does not match")
            expected = {name: previous.get(name) for name in (
                "exception_key", "policy_id", "policy_version", "policy_digest", "scope", "reason",
                "compensating_control_ids", "requester", "requested_at", "expires_at")}
        # Historical recovery remains a pure native read if this feature was
        # turned off. Page, workspace, principal and current permissions still apply.
        row = policy.AIPolicyManagement().get_exception(key)
        authority(request, context)
        if row is None:
            return {"found": False, "confirmed": False, "message": "No matching retained result was found. Nothing was repeated; keep this original lookup."}
        matched = all(row.get(name) == value for name, value in expected.items())
        if envelope.kind == "approve":
            # This native lifecycle has one pending creation (1), one possible
            # approval (2), then an optional close (3). Audit acknowledgement is
            # metadata-only and never increments that logical revision. A later
            # current match cannot prove a fabricated approval from revision 2.
            matched = (matched and previous.get("status") == "pending"
                       and previous.get("approver") is None and previous.get("approved_at") is None
                       and previous.get("closeout") is None and body["expected_revision"] == 1
                       and row.get("approver") == actor and bool(row.get("approved_at"))
                       and row["revision"] in (2, 3))
        elif envelope.kind == "close":
            closeout = row.get("closeout") or {}
            matched = (matched and row["revision"] == body["expected_revision"] + 1
                       and previous.get("status") in ("pending", "approved", "expired")
                       and previous.get("closeout") is None
                       and closeout.get("closed_by") == actor
                       and closeout.get("reason") == policy._text(body["reason"], "reason", 1000))
        if not matched:
            return {"found": True, "confirmed": False, "message": "A retained record exists, but it does not confirm this exact action and person. Nothing was repeated."}
        return {"found": True, "confirmed": True, "record": row,
                "message": "The retained native record confirms this exact request." if envelope.kind == "request" else "The retained native record confirms this action and person.",
                "notice": "This is a read of retained request fields and lifecycle receipts, not a replay of an earlier screen. The displayed status is current."}
    except HTTPException:
        raise
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "This retained original lookup is incomplete or does not match its previous exception. Nothing was repeated.") from exc
    except (policy.AIPolicyManagementError, OSError) as exc:
        raise HTTPException(503, "The original exception result could not be verified. Nothing was repeated.") from exc


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Open the current AI assurance page to review exception controls.")
    state = catalog(request)
    return Snapshot(state["revision"], "Current workspace AI-use rules and exception controls",
                    "Review named safeguards and complete exception details in the protected form. This handoff changes nothing.",
                    {"Rule sets": len(state["policies"]), "Exceptions": len(state["exceptions"]),
                     "Named safeguards available": len(state["controls"]), "Scope": state["notice"]})


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    return Preview(current.summary, native={**current.details, "policy_exception_review": DESCRIPTOR})


def entries():
    return (Adapter("reviews.policy_exception_controls", "Review AI-use exceptions and safeguards", "reviews",
                    PAGE + "#ai-policy-exception-request", (PAGE,), EmptyInput, snapshot, prepare,
                    aliases=("open policy exception controls", "request an AI use exception", "review an AI use exception",
                             "approve an AI use exception", "close an AI use exception", "read original exception result")),)
