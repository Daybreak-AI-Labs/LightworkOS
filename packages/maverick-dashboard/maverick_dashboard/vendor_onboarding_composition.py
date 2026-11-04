"""Request-bound authority and existing connector composition for onboarding."""
from __future__ import annotations

import os
from dataclasses import dataclass

from fastapi import HTTPException, Request
from maverick import config, connections
from maverick.governed_operations import ServiceContext, digest
from maverick.paths import current_tenant_id_strict, tenant_scope
from maverick.vendor_onboarding_config import VendorOnboardingSettings

from .auth import caller_principal, caller_role, require_permission


def settings() -> VendorOnboardingSettings:
    loaded = config.load_config()
    if config.config_source_errors(include_tenant=True):
        raise ValueError("vendor onboarding configuration is unavailable")
    from maverick.vendor_onboarding_setup import settings as workspace_settings
    if current_tenant_id_strict():
        return workspace_settings(loaded)
    return VendorOnboardingSettings.from_config(loaded)


def _budget_authority(tenant: str) -> str:
    """Digest the tenant controls that may authorize queued provider spend."""
    try:
        from maverick.tenant.registry import get_tenant

        record = get_tenant(tenant)
    except Exception as exc:
        raise HTTPException(503, "Tenant budget authority is unavailable") from exc
    if record is None:
        material = {"schema": "lightwork.tenant-budget.unregistered-local.v1", "tenant": tenant}
    else:
        material = {
            "schema": "lightwork.tenant-budget-authority.v1",
            "tenant": record.id,
            "status": record.status,
            "plan": record.plan,
            "billing_status": record.billing_status,
            "max_daily_dollars": record.max_daily_dollars,
            "feature_overrides": record.feature_overrides,
            "updated_at": record.updated_at,
        }
    try:
        from maverick.runtime_overrides import budget_override

        policy = config.get_budget_overrides()
        if not isinstance(policy, dict) or config.config_source_errors(include_tenant=True):
            raise ValueError("budget configuration is unavailable")
        # Inspect authority without constructing Budget: construction can reserve
        # tenant funds, which must never happen merely to compare an approval.
        material["configured_budget"] = policy
        material["dashboard_dollar_cap"] = budget_override()
        material["environment_dollar_cap"] = os.environ.get("MAVERICK_BUDGET_DOLLARS")
        return "sha256:" + digest(material)
    except Exception as exc:
        raise HTTPException(503, "Budget policy authority is unavailable") from exc


def _role_authority(role: str) -> str:
    """Bind the role's current permission atoms, including custom-role edits."""
    try:
        from . import rbac

        permissions = sorted(rbac.permissions_for(role))
    except Exception as exc:
        raise HTTPException(503, "Workspace role authority is unavailable") from exc
    return "sha256:" + digest({
        "schema": "lightwork.dashboard-role-authority.v1",
        "role": role,
        "permissions": permissions,
    })


def _workspace_authority(request: Request, actor: str, tenant: str, *, source: str | None = None) -> str:
    """Bind navigation state so any later workspace switch invalidates work."""
    source = source or str(getattr(getattr(request, "state", None), "workspace_tenant_source", "") or "operator_floor")
    generation = 0
    if source == "principal_selection":
        from . import workspace_tenants

        selected, generation = workspace_tenants.get_selection_binding(actor)
        if selected != tenant:
            raise HTTPException(409, "Workspace changed; review the action in the active workspace")
    material = {
        "schema": "lightwork.workspace-authority.v1",
        "principal": actor,
        "tenant": tenant,
        "source": source,
        "generation": generation,
    }
    return "sha256:" + digest(material)


def _context(request: Request) -> ServiceContext:
    # Execute constructs the changed caller context once so the domain service
    # can durably retire a stale approval.  The request-local marker is cleared
    # before the service's authorization callback re-resolves this context.
    revalidating = bool(getattr(
        getattr(request, "state", None),
        "_lightwork_vendor_execution_revalidation",
        False,
    ))
    if not revalidating:
        require_permission(request, "operate")
    tenant = current_tenant_id_strict()
    if not tenant:
        raise HTTPException(409, "Select an active tenant")
    actor = caller_principal(request)
    if not actor:
        raise HTTPException(403, "A named authenticated reviewer is required")
    from maverick.tenant.registry import TenantSuspended, assert_tenant_active

    from . import workspace_tenants

    try:
        assert_tenant_active(tenant)
        source = getattr(getattr(request, "state", None), "workspace_tenant_source", "")
        if source == "principal_selection" and not workspace_tenants.principal_can_select(actor, tenant):
            raise HTTPException(403, "Workspace membership is no longer active")
    except TenantSuspended as exc:
        raise HTTPException(403, "Workspace is no longer active") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Workspace membership authority is unavailable") from exc
    role = caller_role(request)
    if not role:
        raise HTTPException(403, "A current workspace role is required")
    enrolled = settings()
    if not enrolled.enable:
        raise HTTPException(409, "Vendor onboarding is disabled")
    with tenant_scope(tenant=tenant):
        ticket = connections.get_connection(enrolled.ticket_connection)
    if not ticket:
        raise HTTPException(503, "Enroll the Jira connection for reviewed task delivery")
    authority = ticket.get("owner")
    if not authority:
        raise HTTPException(403, "Jira connection requires an enrolled authority")
    # Upload-only requests have no Drive dependency. The Drive adapter resolves
    # its named enrollment, same authority and grants at every search/read.
    return ServiceContext(
        tenant=tenant, actor=actor, resource_owner=enrolled.resource_owner,
        credential_authority=authority, credential_ref=enrolled.ticket_connection,
        document_credential_ref=enrolled.document_connection, human=True,
        authorization_role=role, authorization_policy=_role_authority(role),
        budget_authority=_budget_authority(tenant),
        workspace_authority=_workspace_authority(request, actor, tenant),
    )


@dataclass(frozen=True)
class WorkflowBinding:
    service: object
    context: ServiceContext


def bind_request(request: Request) -> WorkflowBinding:
    """Only trusted app composition may replace this factory for offline use."""
    from maverick.vendor_onboarding import VendorOnboardingService
    from maverick.vendor_onboarding_adapters import GoogleDriveEvidence, JiraTickets

    ctx = _context(request)
    enrolled = settings()

    def authorize(candidate: ServiceContext, operation: str, _resource: str) -> bool:
        # Re-resolve current enrollment and RBAC at every sensitive boundary.
        # The service separately revalidates connection generations and sources.
        with tenant_scope(tenant=ctx.tenant):
            current = _context(request)
            if candidate.binding() == current.binding():
                return not candidate.human or current.human
            if (operation not in {"action.execute", "action.approve"}
                    or candidate.actor == current.actor
                    or any(getattr(candidate, field) != getattr(current, field) for field in (
                        "tenant", "resource_owner", "credential_authority", "credential_ref",
                        "document_credential_ref", "budget_authority", "authority_schema",
                    ))):
                return False
            from . import rbac, workspace_tenants
            from .auth import role_for_principal
            from .scim_groups import active_for_principal

            role = role_for_principal(candidate.actor)
            if ("operate" not in rbac.permissions_for(role)
                    or candidate.authorization_role != role
                    or candidate.authorization_policy != _role_authority(role)
                    or active_for_principal(candidate.actor) is False):
                return False
            # A bound second principal has their own role and workspace history.
            # The current request's navigation binding belongs to another actor.
            try:
                selected = (
                    workspace_tenants.principal_can_select(candidate.actor, candidate.tenant)
                    and candidate.workspace_authority == _workspace_authority(
                        request, candidate.actor, candidate.tenant, source="principal_selection",
                    )
                )
            except HTTPException:
                selected = False
            floor = candidate.workspace_authority == _workspace_authority(
                request, candidate.actor, candidate.tenant, source="operator_floor",
            )
            return selected or floor

    return WorkflowBinding(VendorOnboardingService(
        documents=GoogleDriveEvidence(
            safe_read_attempts=enrolled.safe_read_attempts,
            safe_read_backoff_seconds=enrolled.safe_read_backoff_seconds,
        ),
        tickets=JiraTickets(
            safe_read_attempts=enrolled.safe_read_attempts,
            safe_read_backoff_seconds=enrolled.safe_read_backoff_seconds,
        ),
        authorize=authorize,
    ), ctx)


def attach_vendor_onboarding_composition(app) -> None:
    if not hasattr(app.state, "vendor_onboarding_binding_factory"):
        app.state.vendor_onboarding_binding_factory = bind_request
