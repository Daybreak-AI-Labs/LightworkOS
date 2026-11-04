"""Fresh explicit API credentials at a protected effect's admission.

An admitted browser identity is a durable owner, rather than a requirement to
keep its interactive session alive. An explicitly supplied API key is different:
its current owner, lifecycle, scopes and workspace remain the execution grant.
Never retain or publish its bearer while refreshing that grant.
"""
from __future__ import annotations

from fastapi import HTTPException


def refresh_explicit_api_key(request) -> None:
    """Reverify an admitted key without selecting a different identity/tenant.

    Called by the ordinary permission gates, including their native writer and
    provider-admission callbacks. Browser/session requests have no API-key
    state and retain the existing current-owner authorization contract.
    """
    from maverick.paths import current_tenant_id_strict

    from . import auth

    state = getattr(request, "state", None)
    principal = getattr(state, "principal", None)
    claims = getattr(principal, "claims", None) or {}
    key_state = any(getattr(state, name, None) is not None
                    for name in ("api_key_id", "api_key_permissions", "api_key_scopes"))
    if claims.get("via") != "api_key" and not key_state:
        return
    if (claims.get("via") == "scheduled_report"
            and getattr(state, "_scheduled_report_key_authority", None) is not None):
        from .executive_report_schedules import refresh_background_key

        refresh_background_key(request)
        return

    def refuse():
        if state is not None:
            state.api_key_permissions = frozenset()
            state.api_key_scopes = frozenset()
        raise HTTPException(401, "This API credential or its execution authority changed. No further protected action was admitted.",
                            headers={"WWW-Authenticate": "Bearer"})

    original = auth.caller_principal(request)
    key_id = claims.get("api_key_id")
    workspace = claims.get("workspace")
    if (claims.get("via") != "api_key" or not original or not isinstance(key_id, str) or not key_id
            or key_id != getattr(state, "api_key_id", None) or not isinstance(workspace, str)):
        refuse()
    try:
        tenant = current_tenant_id_strict()
        binding = (original, key_id, workspace, tenant)
        admitted = getattr(state, "_execution_api_key_binding", None)
        if admitted is not None and admitted != binding:
            refuse()
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or not authorization[7:]:
            refuse()
        # Reuses revocation/expiry/service-account/scopes verification, owner
        # sign-out epochs and SCIM lifecycle. Its existing last-used write is
        # throttled, and it never logs or stores the supplied clear bearer.
        refreshed = auth._authenticate_api_key(request, authorization[7:])
        refreshed_claims = refreshed.claims or {}
        if (refreshed.principal != original or refreshed_claims.get("api_key_id") != key_id
                or refreshed_claims.get("workspace") != workspace):
            refuse()
        if workspace and workspace != tenant:
            refuse()
        if workspace or getattr(state, "workspace_tenant_source", None) == "principal_selection":
            from maverick.tenant.registry import is_active

            from .workspace_tenants import principal_can_select

            if not tenant or not is_active(tenant) or not principal_can_select(original, tenant):
                refuse()
        # Identity is unchanged; publishing current scopes avoids leaving the
        # initial authenticated principal's metadata at an older scope set.
        state.principal = refreshed
        state._execution_api_key_binding = binding
    except HTTPException:
        state.api_key_permissions = frozenset()
        state.api_key_scopes = frozenset()
        raise
    except Exception:
        refuse()


__all__ = ["refresh_explicit_api_key"]
