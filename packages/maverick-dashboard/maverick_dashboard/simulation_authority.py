"""Request-to-controller binding for named-human research simulation approval."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException, Request
from maverick.oidc import VerifiedPrincipal
from maverick.research_simulator import AuthenticatedHumanIdentityV1


def authenticated_human_identity(request: Request) -> AuthenticatedHumanIdentityV1:
    """Return an exact verified user identity with operator authority.

    Local auth-off and static-token modes intentionally do not qualify: neither
    establishes a named human.  The caller must come from the dashboard's
    verified OIDC, proxy, SAML, or invite-session principal path.
    """
    from .auth import caller_principal, require_permission

    require_permission(request, "operate")
    principal = caller_principal(request)
    verified = getattr(getattr(request, "state", None), "principal", None)
    if (
        type(verified) is not VerifiedPrincipal
        or not principal
        or principal != verified.principal
        or not principal.startswith("user:")
        or not str(verified.sub or "").strip()
    ):
        raise HTTPException(
            status_code=401,
            detail="a verified named-human session is required for research simulation approval",
        )
    context = json.dumps(
        {
            "schema": "maverick.dashboard-human-auth-context.v1",
            "principal": principal,
            "subject": verified.sub,
            "issuer": verified.issuer,
            "audience": verified.audience,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return AuthenticatedHumanIdentityV1(
        principal=principal,
        authentication_context_sha256=hashlib.sha256(context.encode("utf-8")).hexdigest(),
    )


__all__ = ["authenticated_human_identity"]
