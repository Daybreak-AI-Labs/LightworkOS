"""Audited dashboard authorization boundary for human approval decisions."""
from __future__ import annotations

import math
import time

from fastapi import HTTPException, Request
from maverick.approval_cards import ApprovalCardError, digest

_AUTHORITY_ISSUER = object()


class _ApprovalAuthority:
    """Opaque result of one successful dashboard authorization check."""

    __slots__ = ("_issuer", "action", "principal", "resource", "tenant")

    def __init__(
        self,
        issuer: object,
        *,
        principal: str,
        tenant: str,
        action: str,
        resource: str,
    ) -> None:
        if issuer is not _AUTHORITY_ISSUER:
            raise ApprovalCardError("approval authority issuer is invalid")
        self._issuer = issuer
        self.principal = principal
        self.tenant = tenant
        self.action = action
        self.resource = resource


def require_approval_authority(
    request: Request,
    *,
    action: str,
    resource: str,
    tenant: str | None = None,
) -> object:
    """Require approval authority and record a non-sensitive denial when absent."""
    from .auth import api_key_permissions, caller_principal, has_permission

    # This authority also protects flow decisions and reviewed vendor actions
    # whose URL is outside the main approval queue. Explicitly require the
    # decision scope there; a task key must not inherit approval authority
    # just because both scopes belong to the operator RBAC role. Credential
    # minting uses this authority for attribution, not to decide an approval.
    api_scope = None if action == "external_agents.credential_mint" else "approvals:decide"
    allowed = (has_permission(request, "operate", api_scope=api_scope)
               if api_key_permissions(request) is not None
               else has_permission(request, "operate"))
    if allowed:
        if action in {"approval.approve", "approval.deny", "approval.revise", "approval.undo"}:
            from .content_access import require_approval_content
            row = require_approval_content(request, resource)
            actor = caller_principal(request) or "operator"
            if row.claimed_by and row.claimed_by != actor:
                raise HTTPException(409, "Another reviewer holds this claim. Ask them to release it before deciding.")
        from maverick.paths import current_tenant_id_strict

        from .auth import auth_genuinely_off

        principal = str(caller_principal(request) or "").strip()
        if not principal and auth_genuinely_off():
            principal = "local:dashboard"
        if not principal:
            raise HTTPException(
                status_code=403,
                detail="an attributable approval identity is required",
            )
        workspace = (
            str(tenant).strip()
            if tenant is not None
            else str(current_tenant_id_strict() or "local")
        )
        return _ApprovalAuthority(
            _AUTHORITY_ISSUER,
            principal=principal,
            tenant=workspace or "local",
            action=str(action),
            resource=str(resource),
        )
    principal = str(caller_principal(request) or "anonymous")
    from maverick import audit
    from maverick.paths import current_tenant_id_strict

    # audit_event propagates AuditRefused and internally contains ordinary
    # audit failures.  The record contains only a commitment to the resource.
    recorded = audit.audit_event(
        audit.EventKind.CAPABILITY_DENIED,
        agent=principal,
        action=action,
        principal=principal,
        tenant=current_tenant_id_strict() or "",
        resource_sha256=digest({"kind": "approval", "resource": str(resource)}),
        reason="approval_authority_missing",
    )
    if not recorded:
        raise HTTPException(
            status_code=503,
            detail=(
                "approval was denied but its audit receipt is unavailable; "
                "the action remains pending"
            ),
        )
    raise HTTPException(status_code=403, detail="insufficient role for this action")


def _local_flow_authority(*, principal: str, resource: str, tenant: str) -> object:
    """Create local authority only when dashboard authentication is truly off."""

    from .auth import auth_genuinely_off

    if not auth_genuinely_off():
        raise ApprovalCardError(
            "an authenticated dashboard approval authority is required"
        )
    actor = str(principal or "").strip() or "local:dashboard"
    return _ApprovalAuthority(
        _AUTHORITY_ISSUER,
        principal=actor,
        tenant=str(tenant or "local"),
        action="flow.approval.decide",
        resource=str(resource),
    )


def issue_flow_decision_attestation(
    authority: object | None,
    *,
    material: dict,
    expires_at: float,
) -> dict:
    """Sign a decision only after a real dashboard authority check.

    Authentication-off local installations retain their single-user operator
    behavior. Configured deployments cannot substitute a caller-claimed actor
    for the opaque authority returned by :func:`require_approval_authority`.
    """

    if authority is None:
        authority = _local_flow_authority(
            principal=str(material.get("decided_by") or ""),
            resource=str(material.get("run_id") or ""),
            tenant=str(material.get("workspace") or "local"),
        )
    if (
        not isinstance(authority, _ApprovalAuthority)
        or authority._issuer is not _AUTHORITY_ISSUER
        or authority.action not in {
            "flow.approval.decide", "flow.approval-link.decide",
        }
        or authority.resource != str(material.get("run_id") or "")
        or authority.principal != str(material.get("decided_by") or "")
    ):
        raise ApprovalCardError("dashboard approval authority does not match the decision")
    workspace = str(material.get("workspace") or authority.tenant or "local")
    if authority.tenant != workspace:
        raise ApprovalCardError("dashboard approval workspace does not match the decision")
    now = time.time()
    deadline = float(expires_at)
    if not math.isfinite(deadline) or deadline <= now:
        raise ApprovalCardError("flow decision expiry is invalid")
    body = {
        "schema": "lightwork.flow-decision-attestation.v1",
        "principal": authority.principal,
        "tenant": authority.tenant,
        "action": "flow.approval.decide",
        "resource": authority.resource,
        "issued_at": now,
        "expires_at": min(deadline, now + 900.0),
        "material_sha256": digest(material),
    }
    from maverick.audit.signing import sign_detached_digest

    return {**body, "signature": sign_detached_digest(digest(body))}


__all__ = ["issue_flow_decision_attestation", "require_approval_authority"]
