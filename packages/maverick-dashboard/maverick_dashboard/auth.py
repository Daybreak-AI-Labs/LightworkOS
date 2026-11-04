"""Dashboard authentication and authorization boundary.

The global FastAPI dependency composes trusted-proxy identity, OIDC bearer and
browser sessions, SAML sessions, local invite sessions, and the static dashboard
bearer. Once any mechanism is configured, missing or invalid identity fails
closed. Principal-less local-operator compatibility is available only when auth
is genuinely off and client binding does not forbid ambient loopback trust.

Importing this module never hard-requires PyJWT: ``maverick.oidc`` lazy-imports
it only when an OIDC token is actually verified.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
from urllib.parse import urlparse

from fastapi import HTTPException, Request, WebSocket
from maverick.config import single_read
from maverick.oidc import (
    OIDCError,
    VerifiedPrincipal,
    oidc_enabled,
    verify_oidc_token,
)
from maverick.proxy_auth import (
    principal_from_proxy,
    proxy_auth_enabled,
    proxy_header_name,
    proxy_trusts,
)
from starlette.concurrency import run_in_threadpool

# Arm the SCIM-group grant resolver (registered on import with
# maverick.suite_grants) so the HTTP gates and the kernel deploy/dispatch
# gates both see group-derived department grants from the first request.
from . import scim_groups  # noqa: F401
from ._request_memo import fresh_configuration, memoized

# Probe/discovery endpoints that must answer without a bearer even when OIDC is
# on (load balancers and k8s liveness/readiness probes
# can't present an ID token). Mirrors the dashboard's existing bearer-auth
# exemptions in ``app._AUTH_EXEMPT`` -- the HMAC-signed webhooks are NOT listed
# here because they carry their own credential and are gated separately.
_OIDC_EXEMPT_PATHS = frozenset(
    {
        "/healthz",
        "/livez",
        "/readyz",
        "/.well-known/agent-card.json",
        "/.well-known/agent.json",
        # Built-in browser-login endpoints must answer without an existing
        # session/bearer -- they ARE the way a browser gets one. They self-gate
        # on login_enabled() (404 when the login flow is off).
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
        "/auth/error",
        "/auth/local-owner",
        "/auth/local-login",
        "/auth/owner-second-factor",
    }
)

# Restricted recovery authenticates each POST with the original owner's
# passphrase and fresh local policy. Exact paths; no general login bypass.
SELF_AUTH_SIGNIN_RECOVERY_PATHS = frozenset({
    "/auth/company-signin-recovery",
    "/auth/company-signin-recovery/lookup",
    "/auth/company-signin-recovery/original",
    "/auth/company-signin-recovery/review",
    "/auth/company-signin-recovery/apply",
    "/auth/company-signin-recovery/cancel",
    "/auth/company-saml-recovery",
    "/auth/company-saml-recovery/lookup",
    "/auth/company-saml-recovery/original",
    "/auth/company-saml-recovery/review",
    "/auth/company-saml-recovery/apply",
    "/auth/company-saml-recovery/cancel",
})

SELF_AUTH_WEBHOOK_PATHS = frozenset(
    {
        "/webhook/start",
        "/webhook/run",
        "/webhook/linear",
        "/webhook/jira",
        "/webhook/github",
        "/webhook/gitlab",
        "/webhook/stripe",
        # Phone providers use their own current check key, native caller
        # authority and durable call original, rather than a dashboard session.
        "/api/v1/channels/voice/receive",
    }
)

# Files the signed-out pages (sign-in, owner setup, invitation, public rights
# form, vendor questionnaire, shared result, sign-in error) load before any
# session exists. Each is public product code or branding and carries no data.
# Exact files only, never a folder: everything else under /static/ stays behind
# sign-in. Both gates (app._AUTH_EXEMPT and this dependency) read this one set.
PUBLIC_STATIC_PATHS = frozenset(
    {
        # The shell stylesheet: without it every signed-out page renders
        # unstyled (system serif font, full-size logo, sideways scrolling).
        "/static/lightwork.css",
        "/static/daybreak-logo.jpg",
        "/static/daybreak-mark.png",
        # The self-hosted fonts lightwork.css references.
        "/static/fonts/manrope-var.woff2",
        "/static/fonts/jbm-400.woff2", "/static/fonts/jbm-500.woff2",
        # The public share page formats its answer with this dependency-free
        # renderer, which builds DOM from text and carries no data.
        "/static/lightwork-markdown.js",
        "/static/lightwork-company-signin-migration.js",
        "/static/lightwork-company-saml-setup.js",
    }
)

_SELF_AUTH_EXEMPT_PATHS = _OIDC_EXEMPT_PATHS | PUBLIC_STATIC_PATHS | frozenset(
    {
        "/a2a/v1",
        # The LLM gateway authenticates every call with its own bearer inside
        # maverick.llm_gateway (same trust-domain rationale as /a2a/v1).
        "/gateway/v1/chat/completions",
        "/gateway/v1/messages",
        "/gateway/v1/otel",
        # A consent platform pushes consent changes with an HMAC signature
        # checked inside maverick.consent_registry; it never holds a dashboard
        # credential. Keep in step with app._AUTH_EXEMPT.
        "/consent/webhook",
    }
) | SELF_AUTH_WEBHOOK_PATHS | SELF_AUTH_SIGNIN_RECOVERY_PATHS


def route_path(connection) -> str:
    """Return the route inside the server's ASGI application mount.

    ASGI servers may retain the mount prefix in ``path``. Only the trusted
    ``root_path`` may remove that leading prefix, at a complete segment;
    forwarded headers and arbitrary matching suffixes never affect admission.
    Connections from older direct callers keep their URL path unchanged.
    """
    scope = getattr(connection, "scope", None)
    if isinstance(scope, dict):
        path = scope.get("path")
        root = scope.get("root_path", "")
    else:
        path, root = None, ""
    if path is None:
        path = getattr(getattr(connection, "url", None), "path", "")
    if not isinstance(path, str):
        return ""
    if isinstance(root, str) and root.startswith("/"):
        root = root.rstrip("/")
        if root and path == root:
            return "/"
        if root and path.startswith(root + "/"):
            return path[len(root):]
    return path


def _self_authenticated_path(path: str) -> bool:
    """Whether a route authenticates itself or bootstraps authentication.

    ``/api/v1/external/`` contains self-authenticating external integrations.
    Each route enforces its own scoped credential: an agent trust-registry
    credential, a signed discovery-sensor identity, or an opaque vendor-portal
    invitation (see ``external_gateway.py``). Those callers have no dashboard
    credential. ``/api/v1/public/consent`` has a separate opaque public-client
    and profile-capability contract. ``/api/v1/public/policies`` resolves an
    opaque stable link and, for private links, a separate bearer capability.
    The trailing slashes matter: the ADMIN surfaces stay under normal dashboard
    authentication."""
    return path in _SELF_AUTH_EXEMPT_PATHS or path.startswith(
        ("/share/", "/scim/", "/form/", "/dsar/response/", "/unsubscribe/", "/saml/",
         "/auth/invite/", "/api/v1/external/",
         "/api/v1/public/consent/", "/api/v1/public/policies/",
         "/api/v1/devices/pairing/", "/rights/", "/api/v1/public/rights/",
         # Public website chat: the publishable key and visitor session are the
         # credentials, checked in public_chat_api. The admin prefix is not listed.
         "/public/chat/v1/")
    )


def _bearer_token(request: Request) -> str:
    """Extract the raw JWT from an ``Authorization: Bearer <jwt>`` header."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return ""


def _dashboard_require_auth_enabled() -> bool:
    """Whether the dashboard's fail-closed require-auth guard is enabled."""
    env = os.environ.get("MAVERICK_DASHBOARD_REQUIRE_AUTH", "").strip().lower()
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return True
    except Exception:
        # An unreadable policy can hide ``require_auth = true``. Treat it as
        # enabled so ambiguity can never re-enable principal-less local admin.
        return True
    if not isinstance(config, dict):
        return True
    if env:
        if env in {"1", "true", "yes", "on"}:
            return True
        if env in {"0", "false", "no", "off"}:
            return False
        # A typo in an authentication-policy override is uncertainty, not an
        # instruction to restore anonymous administrator access.
        return True
    if "dashboard" not in config:
        dashboard = {}
    else:
        dashboard = config["dashboard"]
    if not isinstance(dashboard, dict):
        return True
    configured = dashboard.get("require_auth", False)
    return configured if isinstance(configured, bool) else True


def _saml_policy_configured() -> bool:
    """Whether config contains any SAML identity-policy surface.

    ``saml_enabled`` intentionally reports only a *complete* SP setup so its
    routes can remain inert while an operator fills in the template.  That is
    the wrong predicate for the local-admin compatibility exception: once a
    non-empty legacy ``[auth.saml]`` table exists, incomplete or invalid policy
    must lock anonymous access down. Explicit ``enabled = false`` is a staged
    configuration; it does not replace the installation's current sign-in.
    """
    try:
        from maverick.config import config_source_errors, load_config

        config = load_config() or {}
        if config_source_errors():
            return True
    except Exception:
        return True
    if not isinstance(config, dict):
        return True
    if "auth" not in config:
        return False
    auth = config["auth"]
    if not isinstance(auth, dict):
        return True
    if "saml" not in auth:
        return False
    saml = auth["saml"]
    if isinstance(saml, dict) and saml.get("enabled") is False:
        return False
    return bool(saml) if isinstance(saml, dict) else True


def non_static_auth_configured() -> bool:
    """Whether an identity mechanism besides the static bearer is configured.

    The static operator token and enterprise/browser identity mechanisms are
    alternatives, not mutually exclusive deployment modes. Configuration
    uncertainty reports identity policy as configured so the request reaches
    the global dependency and fails closed unless an identity verifies.
    Answered once per request (see :mod:`._request_memo`).
    """
    return memoized("non_static_auth_configured", _non_static_auth_configured)


def _non_static_auth_configured() -> bool:
    try:
        from .invites import invites_enabled
        from .local_owner import claimed
        from .saml import saml_enabled

        with single_read():
            return any((
                oidc_enabled(),
                proxy_auth_enabled(),
                invites_enabled(),
                saml_enabled(),
                _saml_policy_configured(),
                claimed(),
            ))
    except Exception:
        return True


def _proxy_principal(request: Request) -> VerifiedPrincipal | None:
    """Reverse-proxy SSO: a principal from a forwarded identity header.

    Honored ONLY when proxy auth is enabled AND the request's network peer is a
    trusted upstream (anti-spoofing -- see :mod:`maverick.proxy_auth`). Returns
    ``None`` (fall through to OIDC/loopback) when not applicable.
    """
    if not proxy_auth_enabled():
        return None
    client_host = request.client.host if request.client else ""
    if not proxy_trusts(client_host):
        return None
    value = request.headers.get(proxy_header_name(), "") or ""
    if not value:
        return None
    try:
        return principal_from_proxy(value)
    except ValueError:
        return None


def _invite_session_principal(request: Request) -> VerifiedPrincipal | None:
    """Locally-minted email-invite session identity (no-IdP mode).

    Returns a principal only when ``[dashboard] invites`` is enabled AND the
    ``mvk_session`` cookie verifies against the local session secret; any
    error means None — invites must never break the auth path. Imported
    lazily like :func:`_session_principal` so the gate takes no hard
    dependency on the invites module."""
    try:
        from .invites import local_session_principal
        return local_session_principal(request)
    except Exception:  # pragma: no cover - invites must never break auth
        return None


def _session_principal(request: Request) -> VerifiedPrincipal | None:
    """Built-in browser-login identity: a valid ``mvk_session`` cookie.

    Returns a principal only when the login flow is configured AND the cookie
    verifies (correct HMAC + unexpired). Absent/invalid -> ``None`` so the
    caller falls through to the OIDC bearer path unchanged. Imported lazily so
    the dashboard (and the existing bearer/proxy paths) don't take a hard
    dependency on the login module just to import this gate.
    """
    try:
        from .oidc_login import _principal_from_request_session
    except Exception:  # pragma: no cover - defensive; module should import
        return None
    return _principal_from_request_session(request)


def execution_user_id_from_request(request: Request) -> str | None:
    """Return the Lightwork ``user_id`` for the authenticated HTTP principal.

    ``run_goal`` derives authorization principals as ``user:<user_id>``. The
    verified dashboard principal stores the raw subject on ``sub`` and exposes
    the full role-assignment key as ``principal``; pass only the subject so
    downstream checks evaluate the same ``user:<id>`` identity instead of
    falling back to ``user:local``.
    """
    principal = getattr(getattr(request, "state", None), "principal", None)
    sub = getattr(principal, "sub", "")
    if isinstance(sub, str) and sub:
        return sub
    principal_name = getattr(principal, "principal", "")
    if not isinstance(principal_name, str):
        return None
    if principal_name.startswith("user:") and len(principal_name) > len("user:"):
        return principal_name[len("user:"):]
    return None


# ---------------------------------------------------------------------------
# Owner-scoped multi-tenant authorization (stage 2)
#
# The verified principal is the unit of ownership. Goals/fleets created by a
# caller are stamped with that caller's ``user:<sub>`` string; every read/mutate
# of an owned resource checks the caller against the owner.
#
# Load-bearing invariant: when auth is OFF there is no principal, so
# ``caller_principal`` returns None and EVERY check below is a no-op. The
# dashboard then behaves exactly as it did before this layer existed
# (single-user mode -- one operator owns everything).
# ---------------------------------------------------------------------------


def caller_principal(request: Request) -> str | None:
    """The full ``"user:<sub>"`` identity established on this request.

    ``None`` only means no end-user principal was established; it is not proof
    that auth is off because static-token and self-authenticated requests also
    have no user subject. Authorization helpers must prove the local exception
    through :func:`_authorization_principal` before granting operator semantics.
    """
    principal = getattr(getattr(request, "state", None), "principal", None)
    if principal is None:
        return None
    name = getattr(principal, "principal", "")
    return name if isinstance(name, str) and name else None


def constant_time_equals(supplied: str, expected: str) -> bool:
    """Constant-time equality for text a caller supplied.

    ``hmac.compare_digest`` raises ``TypeError`` for a ``str`` holding any
    non-ASCII character, which turned a crafted header or JSON field into a
    500 instead of the refusal a wrong ASCII value gets. Compare the bytes;
    ``surrogatepass`` keeps a lone surrogate distinct from every real character."""
    from maverick.constant_time import text_equals

    return text_equals(supplied, expected)


def _dashboard_token_authenticated(request) -> bool:
    """Whether this request carries the configured static dashboard bearer."""
    from ._shared import dashboard_token

    expected = dashboard_token()
    if not expected:
        return False
    authorization = request.headers.get("authorization", "")
    supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
    return bool(supplied) and constant_time_equals(supplied, expected)


def auth_genuinely_off() -> bool:
    """Whether the dashboard has no configured authentication mechanism.

    This is deliberately stricter than ``caller_principal(...) is None``:
    HMAC webhook requests are exempt from browser/OIDC authentication, and a
    static dashboard token authenticates the request without establishing an
    end-user principal. Legacy ownerless automations are safe only on a truly
    unauthenticated local deployment. Any unreadable auth configuration denies
    that legacy exception.
    """
    return memoized("auth_genuinely_off", _auth_genuinely_off)


def _auth_genuinely_off() -> bool:
    from ._shared import dashboard_token

    with single_read():
        if dashboard_token() or _dashboard_require_auth_enabled():
            return False
        return not non_static_auth_configured()


def anonymous_local_access_allowed() -> bool:
    """Whether principal-less loopback requests may act as the local operator.

    Having no configured identity mechanism is necessary but not sufficient:
    client-bound/enterprise deployments explicitly disable ambient loopback
    trust. An unreadable binding policy denies the compatibility path.
    Its own configuration reads share one current read, even inside a page
    render (``single_read(fresh=True)``). Outside an authorization boundary
    ``auth_genuinely_off`` is still answered once per request (its memo).
    """
    with single_read(fresh=True):
        if not auth_genuinely_off():
            return False
        try:
            from maverick.client import client_binding_enforced

            return not client_binding_enforced()
        except Exception:
            return False


def _authorization_principal(request: Request) -> str | None:
    """Return the caller or prove that principal-less local access is safe.

    ``None`` is an authorization grant only in genuine auth-off local mode or
    after the static dashboard bearer has authenticated the request. A missing
    proxy/OIDC/session identity must never inherit the legacy local-admin path.

    Principal-less requests recheck current local policy or the static bearer
    at every gate, including after writer waits and in retained workers.
    """
    principal = caller_principal(request)
    if principal is not None:
        return principal
    state = getattr(request, "state", None)
    with fresh_configuration(), single_read(fresh=True):
        if anonymous_local_access_allowed() or _dashboard_token_authenticated(request):
            if state is not None:
                state._anonymous_grant_verified = True
            return None
    raise HTTPException(status_code=401, detail="authenticated identity required")


def durable_automation_owner(request: Request) -> str:
    """Stable owner for a trigger/import that will execute without a request.

    Principal-bearing auth uses that exact principal. Auth-off preserves the
    historical ownerless local mode. A configured static dashboard token has
    no user subject, so the legacy owner remains available for managing
    existing records.
    """
    principal = caller_principal(request)
    if principal:
        return principal
    return "" if anonymous_local_access_allowed() else "user:local"


def require_durable_automation_creator(request: Request) -> str:
    """Resolve the admissible owner once, refusing unidentified automation."""
    principal = caller_principal(request)
    if principal:
        return principal
    if anonymous_local_access_allowed():
        return ""
    raise HTTPException(
        status_code=409,
        detail=("Sign in with a named account to create an automation. "
                "A shared access token cannot provide an owner for future runs."),
    )


def _pin_tenant_from_principal(request: Request, principal: VerifiedPrincipal) -> None:
    """Pin per-user isolation or an authorized workspace selection.

    HTTP middleware runs before FastAPI dependencies populate
    ``request.state.principal``, so tenant pinning must happen here, in the
    authentication dependency, immediately after a principal is established and
    before route handlers choose tenant-scoped world state. The reset token is
    stored on request state for the outer middleware to clean up after the
    response. Workspace selection is a preference, never a grant: inactive
    tenants and tenants without an effective membership remain unbound.
    """
    try:
        from maverick.paths import current_tenant_id, set_tenant, tenant_by_user_enabled

        name = getattr(principal, "principal", "")
        if not isinstance(name, str):
            name = ""
        if not name or getattr(request.state, "tenant_pin_token", None) is not None:
            return
        # A process/env/client binding is an operator floor and always outranks
        # an in-app preference.
        if current_tenant_id() is not None:
            return
        if tenant_by_user_enabled():
            request.state.tenant_pin_token = set_tenant(f"api:{name}")
            request.state.workspace_tenant_source = "principal_isolation"
            return

        from maverick.tenant.registry import is_active

        from . import workspace_tenants

        claims = getattr(principal, "claims", None) or {}
        bound = claims.get("workspace") if claims.get("via") == "api_key" else ""
        # A key bound to a workspace acts only inside it; its owner's browser
        # selection is irrelevant to the key. Membership is still re-checked.
        selected = str(bound or "") or workspace_tenants.get_selection(name)
        if not selected:
            return
        if not is_active(selected) or not workspace_tenants.principal_can_select(
            name, selected
        ):
            if bound:
                # A key acts only inside its workspace. Falling back to the
                # default workspace would run it somewhere it was never given.
                raise HTTPException(
                    status_code=403,
                    detail="This API key's workspace is paused or its owner is no longer a "
                           "member of it. Ask a workspace administrator.",
                )
            request.state.workspace_tenant_denied = selected
            return
        request.state.tenant_pin_token = set_tenant(selected)
        request.state.workspace_tenant_source = "principal_selection"
        request.state.workspace_expected_tenant = selected
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="tenant isolation policy unavailable",
        ) from exc


def is_dashboard_admin(principal: str) -> bool:
    """True iff ``principal`` is a configured (bootstrap) dashboard admin.

    Admins bypass owner scoping AND department scoping (they see and control
    every goal/fleet/department). The roster is the ``[dashboard] admins`` list
    in ``~/.maverick/config.toml`` with an optional ``MAVERICK_DASHBOARD_ADMINS``
    (comma-separated) env override; comparison is exact against the full
    ``"user:<sub>"`` form.

    Single source of truth: delegates to :func:`maverick.suite_grants.is_admin_principal`
    so the dashboard HTTP gates and the kernel deploy/dispatch gates can never
    disagree about who bypasses scoping. NOTE this is the *config-pinned*
    roster, not the effective RBAC role — a user assigned ``admin`` via the
    Users page or a group mapping holds admin *permissions* but remains
    department-scoped (an admin-of-finance administers finance); only the
    config roster is the "never scoped" break-glass set.
    """
    from maverick.suite_grants import is_admin_principal
    return is_admin_principal(principal)


def global_role_for_principal(principal: str | None) -> str | None:
    """The principal's dashboard-wide RBAC role, ignoring tenant memberships.

    Resolution: explicit stored assignment, then the role mapped to the user's
    SCIM groups (``[dashboard] group_roles`` — team membership in the IdP), then
    the configured default. Explicit always beats derived, so an admin can still
    pin an individual without fighting the group mapping."""
    if principal is None:
        return None
    if is_dashboard_admin(principal):
        return "admin"
    from . import rbac
    try:
        stored = rbac.get_stored_role(principal)
        if stored:
            return stored
        from . import scim_groups, strict_reads

        # An unreadable group policy must not turn its fallback viewer into
        # installation-wide authority for a workspace-only account.
        with strict_reads.strict():
            group_role = scim_groups.role_for_principal(principal)
        if group_role:
            return group_role
        # Once workspace membership is in use, an unassigned account is not
        # implicitly entitled to the separate installation-wide namespace. The
        # durable roster remains after revocation, preventing privilege return.
        if rbac.tenant_role_scope_initialized():
            return None
        return rbac.default_role()
    except Exception:
        # A damaged role roster, group-membership source, or config default is
        # deny-all. Falling through to the historical operator default would
        # turn a policy outage into a privilege escalation.
        from . import strict_reads

        if strict_reads.active():
            raise
        return None


def role_for_principal(principal: str | None) -> str | None:
    """The dashboard RBAC role for ``principal``.

    None when auth is off (no principal) -- the signal for every gate to
    disable itself (single-user mode). A config-pinned bootstrap admin
    (:func:`is_dashboard_admin`) is always ``"admin"`` and cannot be demoted via
    the store, so you can't lock yourself out. Otherwise the stored role, or the
    configured default (``viewer``) for an authenticated user with no explicit
    assignment.
    """
    if principal is None:
        return None
    if is_dashboard_admin(principal):
        return "admin"
    from . import rbac
    # Per-tenant membership wins over the global role, but only for the active
    # tenant. No active tenant or no membership -> the global behaviour below,
    # unchanged. Bootstrap admin (above) always wins, so this can't lock admins
    # out of a tenant.
    try:
        from maverick.paths import current_tenant_id
        tid = current_tenant_id()
        if tid:
            tenant_role = rbac.get_tenant_role(tid, principal)
            if tenant_role:
                return tenant_role
            from maverick.paths import tenant_by_user_enabled

            if tenant_by_user_enabled() and tid == f"api:{principal}":
                # Per-user isolation is not a shared workspace membership.
                # Keep its configured default without granting root access.
                from . import strict_reads

                with strict_reads.strict():
                    return global_role_for_principal(principal) or rbac.default_role()
    except Exception:
        # Never replace an unreadable tenant-local demotion with the broader
        # global/default role.
        from . import strict_reads

        if strict_reads.active():
            raise
        return None
    return global_role_for_principal(principal)


def caller_role(request: Request) -> str | None:
    """The RBAC role of the current caller (None when auth is off)."""
    with single_read(fresh=True):  # a gate: the current files, even inside a render
        return role_for_principal(_authorization_principal(request))


def api_key_permissions(request) -> frozenset[str] | None:
    """The permission atoms an API-key bearer may use on this request, or
    ``None`` when the request was not authenticated with an API key.

    Set by :func:`_authenticate_api_key`: the key's scopes capped by its
    owner's current role. Every RBAC gate intersects with it, so a key with
    ``tasks:read`` fails a route that requires ``operate`` even though its
    owner could call it in a browser."""
    value = getattr(getattr(request, "state", None), "api_key_permissions", None)
    return value if isinstance(value, frozenset) else None


def api_key_scopes(request) -> frozenset[str] | None:
    """Verified scope names for this API-key request, or ``None`` otherwise."""
    value = getattr(getattr(request, "state", None), "api_key_scopes", None)
    return value if isinstance(value, frozenset) else None


def _api_key_allows(request, permission: str, *, api_scope: str | None = None) -> bool:
    scoped = api_key_permissions(request)
    if scoped is None:
        return True
    if permission not in scoped:
        return False
    if permission != "operate":
        return True
    scopes = api_key_scopes(request)
    if scopes is None:
        return False
    if "admin" in scopes:
        return True
    if api_scope is None:
        # The approval queue has operator-gated reads as well as decisions and
        # claim/release actions. A task key must not borrow their shared RBAC
        # atom, while an approval key must not operate unrelated task routes.
        path = route_path(request)
        vendor_decision = (path.startswith("/api/v1/vendor-onboarding/cases/")
                           and path.endswith(("/review", "/approve-action")))
        api_scope = (
            "approvals:decide"
            if (path in {"/api/v1/approvals", "/approvals"}
                or path.startswith("/api/v1/approvals/") or vendor_decision)
            else "tasks:write"
        )
    return api_scope in scopes


def require_api_key_scope(request: Request, scope: str) -> None:
    """Check a named action scope for key bearers without changing browser RBAC.

    A decision may have a different role floor (for example, a content owner
    can review their own employee-content request). Keys still need the
    approval scope and their owner's current role must retain ``operate``.
    """
    if api_key_permissions(request) is not None and not _api_key_allows(
        request, "operate", api_scope=scope,
    ):
        raise HTTPException(
            status_code=403,
            detail="This API key does not have a scope that allows this. "
                   "Create a key with the scope you need on your account page.",
        )


def has_permission(request: Request, permission: str, *, api_scope: str | None = None) -> bool:
    """Whether the caller may perform ``permission`` ("admin"/"operate"/"view").

    Auth off -> True (legacy single-user; the local operator owns everything).
    Otherwise gated by the caller's role, and for an API-key bearer also by
    the key's scopes. A gate: it reads the current configuration once, even
    inside a page render (``single_read(fresh=True)``).
    """
    with single_read(fresh=True):
        principal = _authorization_principal(request)
        if principal is None:
            return True
        if not _api_key_allows(request, permission, api_scope=api_scope):
            return False
        from . import rbac
        return permission in rbac.permissions_for(role_for_principal(principal))


def _permission_denied(request: Request, permission: str, *, installation: bool = False,
                       api_scope: str | None = None) -> HTTPException:
    if not _api_key_allows(request, permission, api_scope=api_scope):
        return HTTPException(
            status_code=403,
            detail="This API key does not have a scope that allows this. "
                   "Create a key with the scope you need on your account page.",
        )
    from .access_explanations import denial
    return HTTPException(status_code=403, detail=denial(request, permission, installation=installation))


def require_permission(request: Request, permission: str, *, api_scope: str | None = None) -> None:
    """Raise ``HTTPException(403)`` unless the caller's role grants ``permission``."""
    from .execution_identity import refresh_explicit_api_key
    refresh_explicit_api_key(request)
    # The action override is meaningful only for a key bearer. Preserve the
    # ordinary two-argument role check for browser/session callers.
    allowed = (has_permission(request, permission, api_scope=api_scope)
               if api_scope is not None and api_key_permissions(request) is not None
               else has_permission(request, permission))
    if not allowed:
        raise _permission_denied(request, permission, api_scope=api_scope)


def require_workspace_picker_access(request: Request, *, write: bool = False) -> None:
    """Allow a signed-in principal to select only its own workspace.

    This narrow navigation capability does not grant access to unbound data.
    API keys retain their own view/operate scope checks.
    """
    from .execution_identity import refresh_explicit_api_key

    refresh_explicit_api_key(request)
    principal = _authorization_principal(request)
    if principal is None:
        if write:
            require_personal_write(request)
        else:
            require_permission(request, "view")
        return
    permission = "operate" if write and api_key_permissions(request) is not None else "view"
    if not _api_key_allows(request, permission):
        raise _permission_denied(request, permission)


def require_personal_write(request: Request) -> None:
    """The ``view`` floor for a person's own settings; a key also needs a write scope.

    Everyone signed in changes their own choices at the view floor. A bearer key
    acts as its owner, so a read-only key must not change the owner's account
    (chat links, the daily-summary address, the workspace picker)."""
    require_permission(request, "view")
    if api_key_permissions(request) is not None:
        require_permission(request, "operate")


def has_global_permission(request: Request, permission: str) -> bool:
    """Whether the caller may perform a dashboard-wide control-plane action.

    Tenant memberships are intentionally ignored so a tenant-local admin cannot
    satisfy global admin gates for other tenants or dashboard settings. A gate:
    it reads the current configuration once (``single_read(fresh=True)``).
    """
    with single_read(fresh=True):
        principal = _authorization_principal(request)
        if principal is None:
            return True
        if not _api_key_allows(request, permission):
            return False
        from . import rbac

        return permission in rbac.permissions_for(global_role_for_principal(principal))


def require_global_permission(request: Request, permission: str) -> None:
    """Raise ``HTTPException(403)`` unless the global role grants permission."""
    from .execution_identity import refresh_explicit_api_key
    refresh_explicit_api_key(request)
    if not has_global_permission(request, permission):
        raise _permission_denied(request, permission, installation=True)


def require_page_permission(request: Request, path: str) -> None:
    """Apply a registered page's security floor to a backing API read.

    Page-visibility overrides only control navigation and HTML admission;
    they do not revoke the underlying role permission or API-key scope.
    """
    from . import ui_visibility

    page = ui_visibility.page_for(path)
    if page is None or page["path"] != path:
        raise RuntimeError(f"no exact page security floor for {path}")
    if page.get("scope") == "global":
        require_global_permission(request, page["floor"])
    else:
        require_permission(request, page["floor"])


def caller_suites(request: Request) -> frozenset[str] | None:
    """The department suites the caller may use, or ``None`` for unrestricted.

    Job-function scoping (``maverick_dashboard.suite_grants``), orthogonal to
    the privilege role: it decides WHICH specialists a user works with, not how
    much they may do. ``None`` — auth off, a dashboard admin, or a user with no
    grant (and no configured default) — disables every suite gate, preserving
    single-user behaviour."""
    principal = _authorization_principal(request)
    if principal is None or is_dashboard_admin(principal):
        return None
    from . import suite_grants
    return suite_grants.granted_suites(principal)


class AutomationAuthorizationError(RuntimeError):
    """A request-less automation owner no longer has execution authority."""


def stored_automation_identity(
    owner: str,
) -> tuple[str, str | None, frozenset[str] | None]:
    """Revalidate a durable trigger owner and return its current run identity.

    Trigger possession is not a perpetual grant. Every request-less fire checks
    SCIM lifecycle, current RBAC ``operate`` permission, and the current suite
    floor. Legacy ownerless rows execute only in genuinely auth-off local mode.
    """
    owner = str(owner or "").strip()
    if not owner:
        if anonymous_local_access_allowed():
            return "", None, None
        raise AutomationAuthorizationError("automation owner is unavailable")
    try:
        from .scim_groups import active_for_principal

        if active_for_principal(owner) is False:
            raise AutomationAuthorizationError("automation owner is unavailable")
        from .rbac import permissions_for

        if "operate" not in permissions_for(role_for_principal(owner)):
            raise AutomationAuthorizationError("automation owner is unavailable")
        suites = None
        if not is_dashboard_admin(owner):
            from .suite_grants import granted_suites

            suites = granted_suites(owner)
    except AutomationAuthorizationError:
        raise
    except Exception as exc:
        raise AutomationAuthorizationError(
            "automation authorization policy is unavailable") from exc
    user_id = owner[len("user:"):] if owner.startswith("user:") else ""
    return owner, (user_id or None), suites


def suite_allowed(request: Request, suite: str | None) -> bool:
    """Whether the caller may use department ``suite``.

    ``suite`` is a suite key (``maverick.domain.suite_for``); ``None`` means a
    generic/legacy pack that belongs to no department and is never scoped."""
    allowed = caller_suites(request)
    if suite is None:
        return True
    return allowed is None or suite in allowed


def domain_suites_allowed(request: Request, domain: str | None) -> bool:
    """Honor inherited suites; scoped users cannot read an unavailable pack."""
    if not domain:
        return True
    from maverick.domain import suites_for_domain

    try:
        return all(suite_allowed(request, suite) for suite in suites_for_domain(domain))
    except HTTPException:
        raise
    except Exception as exc:
        # An unreadable pack or grant policy is not evidence of access.  Keep
        # the server error out of customer responses without releasing data.
        raise HTTPException(status_code=503, detail="Access rules for agents and specialists are unavailable right now. Try again in a moment.") from exc


def domain_suites_checker(request: Request):
    """``domain_suites_allowed`` for many packs of one caller within one request.

    A catalogue listing asks the same caller about every pack. The caller's
    grants are read at most once for the listing; each pack then gets the same
    suite test and the same fail-closed error as :func:`domain_suites_allowed`.
    """
    from maverick.domain import suites_for_domain

    grants: list = []  # Read on first need; ``None`` (unrestricted) must stay distinct from unread.

    def allowed(domain: str | None) -> bool:
        if not domain:
            return True
        try:
            for suite in suites_for_domain(domain):
                if not grants:
                    grants.append(caller_suites(request))
                if suite is not None and grants[0] is not None and suite not in grants[0]:
                    return False
            return True
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Access rules for agents and specialists are unavailable right now. Try again in a moment.") from exc

    return allowed


BOARD_SCOPE_DETAIL = (
    "These charts can include work from departments you cannot access. "
    "Ask an administrator to review your access. Your permitted tasks remain available in Chat."
)


def require_unscoped_board(request: Request) -> None:
    """Withhold unfiltered company rollups from department-scoped callers."""
    if caller_suites(request) is not None:
        raise HTTPException(status_code=403, detail=BOARD_SCOPE_DETAIL)


def scope_to_suites(request: Request, items, *, suite_of, keep_none: bool = True):
    """Filter ``items`` to the caller's granted departments (job-function scope).

    ``suite_of(item)`` returns the item's suite key, or ``None`` for a generic /
    department-less item. Unscoped callers (auth off, admin, no grant) get every
    item back unchanged; otherwise an item is kept when its suite is granted, or
    when it is generic and ``keep_none`` is set (packs outside every department
    stay visible). One helper so every catalog surface scopes identically —
    the inline per-surface copies drifted (some kept generics, some didn't)."""
    allowed = caller_suites(request)
    if allowed is None:
        return list(items)
    return [it for it in items
            if (suite_of(it) is None and keep_none) or suite_of(it) in allowed]


def require_suite(request: Request, suite: str | None) -> None:
    """Raise ``HTTPException(403)`` unless the caller may use ``suite``."""
    if not suite_allowed(request, suite):
        raise HTTPException(
            status_code=403, detail="insufficient department access for this action")


def goal_owner_filter(request: Request) -> str | None:
    """The ``owner`` value to pass to ``WorldModel.list_goals``.

    Every named account, including an administrator, lists its own content.
    A separately reviewed read opens a specific record; it never broadens a
    list. Unidentified local/installation credentials list only unowned work.
    """
    principal = _authorization_principal(request)
    return principal or ""


def can_access_goal_principal(principal: str | None, goal) -> bool:
    """Whether ``principal`` may read/mutate ``goal``.

    ``None`` identifies no employee and may access only unowned local work.
    Named callers, including administrators, need exact ownership.
    """
    if goal is None:
        return False
    if principal is None:
        return not getattr(goal, "owner", "")
    return getattr(goal, "owner", "") == principal


def _goal_read_policy(request: Request, goal) -> bool:
    """Whether the caller may read/mutate ``goal``.

    Ownership grants normal access. A named administrator needs an independent
    scoped read approval for another person's content or unowned legacy work.
    A read approval never grants mutation or publishing authority. A current
    department grant is also required for a specialist-owned goal, including
    when the specialist's pack was removed after the goal was created.
    """
    if goal is None or not domain_suites_allowed(request, getattr(goal, "domain", None)):
        return False
    principal = _authorization_principal(request)
    if getattr(request.state, "paired_device_id", None):
        return bool(principal) and getattr(goal, "owner", "") == principal
    if can_access_goal_principal(principal, goal):
        return True
    # A reviewed content read never confers authority to mutate or publish.
    if str(getattr(request, "method", "GET")).upper() not in {"GET", "HEAD"}:
        return False
    from .content_access import may_read_employee_content

    return may_read_employee_content(request, getattr(goal, "owner", ""),
                                     resource_kind="goal", resource_id=str(goal.id))


def can_access_goal(request: Request, goal) -> bool:
    """A copied conversation keeps every original source's current access rules."""
    if not _goal_read_policy(request, goal):
        return False
    from maverick.attachments import AttachmentRejected
    from maverick.chat_message_actions import require_copy_sources
    from maverick.knowledge_task_context import SourceContextUnavailable

    from ._shared import _world

    def authorize(source):
        if not _goal_read_policy(request, source):
            raise PermissionError("A copied source is unavailable to this account.")

    try:
        require_copy_sources(_world(), goal.id, authorize=authorize)
    except (PermissionError, SourceContextUnavailable, AttachmentRejected):
        return False
    return True


def _goal_readable_by(principal: str, goal, grants=None) -> bool:
    """The task page's rules for a read by ``principal`` (the ``view``
    permission the page and its thread require, then
    :func:`_goal_read_policy`: department access, then ownership or a current
    reviewed read grant held by a global administrator), without a request
    and without recording a read. ``grants`` is the task's grant readers
    (or the error reading them) when the caller already read them. Keep in
    step with :func:`_goal_read_policy` (tests compare the two).

    Every rule is checked: one that refuses decides, whatever order the
    sources are read in, and a source that cannot be read only matters when
    no readable rule refuses (it then raises)."""
    from maverick.domain import suites_for_domain

    from . import content_access, rbac, suite_grants

    owner = getattr(goal, "owner", "") or ""

    def department():
        domain = getattr(goal, "domain", None)
        if not domain:
            return True
        suites = None if is_dashboard_admin(principal) else suite_grants.granted_suites(principal)  # as caller_suites
        return suites is None or all(suite is None or suite in suites for suite in suites_for_domain(domain))

    def granted():
        found = grants
        if found is None:
            found = content_access.grant_readers(owner, resource_kind="goal", resource_id=str(goal.id),
                                                 among={principal})
        if isinstance(found, Exception):
            raise found
        return principal in found

    rules = [lambda: "view" in rbac.permissions_for(role_for_principal(principal)), department]
    if owner != principal:
        rules += [lambda: "admin" in rbac.permissions_for(global_role_for_principal(principal)),
                  lambda: scim_groups.active_for_principal(principal) is not False, granted]
    unreadable = None
    for rule in rules:
        try:
            if not rule():
                return False
        except Exception as exc:  # noqa: BLE001 -- only decides if no readable rule refuses
            unreadable = unreadable or exc
    if unreadable is not None:
        raise unreadable
    return True


def goal_readable_by(principal: str, goal, *, grants=None) -> bool:
    """Whether ``principal`` could open ``goal`` now, by the rules
    :func:`can_access_goal` applies to a read from them (copied
    conversations included), for someone to be told about the task.
    ``grants`` is as for :func:`_goal_readable_by`. A source that cannot be
    read denies (it raises inside ``strict_reads.strict()``)."""
    from maverick.attachments import AttachmentRejected
    from maverick.chat_message_actions import require_copy_sources
    from maverick.knowledge_task_context import SourceContextUnavailable

    from ._shared import _world

    unreadable = []

    def authorize(source):
        if source.id == goal.id:
            return  # the task's own rules are checked below, with the grants already read
        try:
            readable = _goal_readable_by(principal, source)
        except Exception as exc:  # noqa: BLE001 -- a later source may still refuse
            unreadable.append(exc)
            return
        if not readable:
            raise PermissionError("A copied source is unavailable to this account.")

    if goal is None or not principal:
        return False
    # The task's own rules and every copied source are each checked, so a
    # refusal from any of them decides even while another cannot be read.
    try:
        if not _goal_readable_by(principal, goal, grants):
            return False
    except Exception as exc:  # noqa: BLE001 -- a copied source may still refuse
        unreadable.append(exc)
    try:
        require_copy_sources(_world(), goal.id, authorize=authorize, defer_errors=True)
    except PermissionError:
        return False
    except (SourceContextUnavailable, AttachmentRejected) as exc:
        # These also wrap outages (an unreachable connector, an unreadable
        # file): a refusal only when nothing else was unreadable.
        if not unreadable:
            return False
        unreadable.append(exc)
    except Exception as exc:  # noqa: BLE001 -- an unreadable access rule is not evidence of access
        unreadable.append(exc)
    if unreadable:
        from . import strict_reads

        if strict_reads.active():
            raise unreadable[0]
        return False
    return True


def assert_goal_access(request: Request, goal) -> None:
    """Raise ``HTTPException(404)`` if the caller may not touch ``goal``.

    404 (not 403) on denial so a cross-tenant probe can't distinguish "exists
    but forbidden" from "does not exist". Callers fetch the goal first (a real
    miss is its own 404) and then gate on this.
    """
    if not can_access_goal(request, goal):
        raise HTTPException(status_code=404, detail="no such goal")


def assert_template_access(request: Request, template) -> None:
    """Private template ownership is separate from policy administration."""
    from maverick.templates import can_read_template
    require_permission(request, "view")
    if not can_read_template(template, caller_principal(request)):
        raise HTTPException(404, "This template is unavailable to your account.")


def _enforce_scim_active(principal: VerifiedPrincipal) -> None:
    """Reject a SCIM-matched principal that has been deprovisioned.

    Revocation epochs terminate credentials minted before deprovisioning, but
    an IdP that mistakenly continues issuing fresh tokens could otherwise give
    the inactive user the dashboard's global default role. The live SCIM roster
    is therefore an authentication gate as well as a group-grant source.
    """
    from .api_keys import is_service_account_subject

    if is_service_account_subject(principal.sub) and (
        (principal.claims or {}).get("via") != "api_key"
    ):
        # A service account holds keys and a role but can never sign in
        # interactively; an IdP subject that merely looks like one is refused.
        raise HTTPException(status_code=401, detail="invalid identity")
    try:
        from .scim_groups import active_for_principal

        active = active_for_principal(principal.principal)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="identity lifecycle policy unavailable",
        ) from exc
    if active is False:
        raise HTTPException(status_code=401, detail="invalid identity")


_BREAK_GLASS_AUDIT_INTERVAL = 3600.0
_break_glass_last_audit: list[float | None] = [None]


def _audit_break_glass(connection) -> None:
    """Record that the static dashboard token authenticated a request.

    The token is the break-glass credential: it has no person behind it and
    no scopes, so its use is audited. One row per process per hour keeps the
    record useful (a script using the token would otherwise write a row per
    call); the row names the path and client of the first use in the window.
    An audit refusal propagates, and a write that was not made (``audit_event``
    returns False) is refused too: a request that cannot be recorded fails.
    """
    import time as _time

    now = _time.monotonic()
    last = _break_glass_last_audit[0]
    if last is not None and now - last < _BREAK_GLASS_AUDIT_INTERVAL:
        return
    from maverick.audit import EventKind, audit_event

    client = connection.client.host if getattr(connection, "client", None) else ""
    path = str(getattr(getattr(connection, "url", None), "path", "") or "")
    if not audit_event(EventKind.BREAK_GLASS_TOKEN_USED, agent="static-dashboard-operator",
                       path=path, client=client or ""):
        raise HTTPException(
            status_code=503,
            detail="The activity record is unavailable, so the dashboard token cannot be used right now.",
        )
    # Start the window only once a row exists: a refused audit leaves it open so
    # the next request is refused too instead of being admitted unrecorded.
    _break_glass_last_audit[0] = now


def _authenticate_api_key(connection, token: str) -> VerifiedPrincipal:
    """Verify a personal / service-account API key and bind its scopes.

    Fails closed with a plain-language 401: unknown, expired, revoked and
    rotated-out keys are refused, as are keys whose owner was deprovisioned
    (SCIM), signed out everywhere (revocation epoch) or whose service account
    is disabled. On success the request carries ``api_key_permissions`` --
    the key's scopes capped by the owner's current role -- which every RBAC
    gate intersects with.
    """
    from . import api_keys

    client = connection.client.host if getattr(connection, "client", None) else ""
    verified, reason = api_keys.verify(token, client_ip=client or "")
    if verified is None:
        # A recognized key whose workspace was revoked, paused or differs from
        # the deployment binding is authenticated but lacks current authority.
        workspace_denied = (reason.startswith("This API key's workspace")
                            or reason.startswith("This API key is bound")
                            or reason.startswith("Workspace-bound API keys"))
        raise HTTPException(status_code=403 if workspace_denied else 401, detail=reason,
                            headers=None if workspace_denied else {"WWW-Authenticate": "Bearer"})
    key = verified.key
    sub = key.owner[len("user:"):]
    principal = VerifiedPrincipal(
        sub=sub, issuer="api-key", audience="",
        claims={"via": "api_key", "api_key_id": key.id, "scopes": list(key.scopes),
                "workspace": key.workspace, "iat": key.created_at},
    )
    if not key.is_service_account:
        from .session_revocation import is_revoked

        if is_revoked(sub, key.created_at):
            raise HTTPException(status_code=401, detail="This API key's owner was signed out everywhere after it was created. Create a new key.",
                                headers={"WWW-Authenticate": "Bearer"})
        _enforce_scim_active(principal)
    if connection is not None:
        connection.state.api_key_permissions = verified.permissions
        connection.state.api_key_scopes = frozenset(key.scopes)
        connection.state.api_key_id = key.id
    return principal


def _api_key_bearer(connection) -> str:
    """The presented bearer when it has the API-key shape, else ``""``."""
    token = _bearer_token(connection)
    if not token:
        return ""
    try:
        from .api_keys import looks_like_key

        return token if looks_like_key(token) else ""
    except Exception:
        return ""


def _resolve_websocket_principal(websocket) -> VerifiedPrincipal | None:
    """Authenticate a WebSocket handshake with the configured mechanisms."""
    if websocket is None:
        if anonymous_local_access_allowed():
            return None
        raise HTTPException(status_code=401, detail="authenticated identity required")

    # Explicit credentials take precedence over ambient proxy/cookie identity.
    # Otherwise an invalid bearer could be ignored and the handshake satisfied
    # by a browser session riding on the same request.
    authorization = websocket.headers.get("authorization", "")
    if authorization:
        if _dashboard_token_authenticated(websocket):
            _audit_break_glass(websocket)
            return None
        if _api_key_bearer(websocket):
            return _authenticate_api_key(websocket, _api_key_bearer(websocket))
        ws_token = _bearer_token(websocket)
        if not ws_token or not oidc_enabled():
            raise HTTPException(status_code=401, detail="invalid bearer credential")
        try:
            ws_principal = verify_oidc_token(ws_token)
        except OIDCError as exc:
            raise HTTPException(status_code=401, detail="invalid OIDC token") from exc
        from .session_revocation import is_revoked
        if is_revoked(ws_principal.sub, ws_principal.claims.get("iat")):
            raise HTTPException(status_code=401, detail="invalid OIDC token")
        _enforce_scim_active(ws_principal)
        return ws_principal

    # Proxy/session identities are valid WebSocket credentials too. Their
    # browser Origin is checked by ``websocket_authorized`` before accept.
    pp = _proxy_principal(websocket)
    if pp is not None:
        _enforce_scim_active(pp)
        return pp
    sp = _session_principal(websocket)
    if sp is not None:
        _enforce_scim_active(sp)
        return sp
    lp = _invite_session_principal(websocket)
    if lp is not None:
        _enforce_scim_active(lp)
        return lp

    if oidc_enabled():
        raise HTTPException(status_code=401, detail="OIDC bearer token required")
    if not anonymous_local_access_allowed():
        raise HTTPException(status_code=401, detail="authenticated identity required")
    return None


def _authenticate_oidc_bearer(request: Request, token: str) -> VerifiedPrincipal:
    """Verify an explicit HTTP OIDC bearer without binding request ContextVars."""
    try:
        principal = verify_oidc_token(token)
    except OIDCError as exc:
        # Opaque 401: never leak which check failed (expiry vs. signature vs.
        # audience) to an unauthenticated caller.
        raise HTTPException(
            status_code=401,
            detail="invalid OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    # Revocation: a bearer issued before the principal's revocation epoch
    # ("log out everywhere" / SCIM deprovision) is rejected even if it verifies.
    from .session_revocation import is_revoked
    if is_revoked(principal.sub, principal.claims.get("iat")):
        raise HTTPException(
            status_code=401, detail="invalid OIDC token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    _enforce_scim_active(principal)
    return principal


def _resolve_principal(
    request: Request = None,  # type: ignore[assignment]
    websocket: WebSocket = None,  # type: ignore[assignment,name-defined]
) -> VerifiedPrincipal | None:
    """Authenticate every non-exempt HTTP or WebSocket request.

    An explicit static/OIDC bearer takes precedence so an invalid credential
    cannot borrow ambient authority. Without one, trusted proxy identity is
    followed by a verified browser or invite session. Missing identity is
    allowed only in genuine local auth-off mode. Probe,
    discovery, login-bootstrap, share, SCIM, SAML, form, and webhook paths carry
    their own narrower credential or are intentionally public bootstrap routes.
    The whole resolution reads the current configuration once
    (``single_read(fresh=True)``).
    """
    with single_read(fresh=True):
        return _resolve_principal_now(request, websocket)


def _resolve_principal_now(request, websocket) -> VerifiedPrincipal | None:
    if request is None:
        return _resolve_websocket_principal(websocket)

    # An explicit bearer is non-ambient API authority. Resolve it before
    # proxy/browser sessions so the middleware's CSRF exemption cannot be
    # triggered by an invalid header and then satisfied by an ambient cookie.
    # Self-authenticated routes keep their own credential contract. A valid
    # static dashboard bearer has local-operator semantics; any other bearer
    # must verify as OIDC or fail instead of falling back to ambient identity.
    self_authenticated = _self_authenticated_path(route_path(request))
    authorization = request.headers.get("authorization", "")
    if not self_authenticated and authorization:
        if _dashboard_token_authenticated(request):
            _audit_break_glass(request)
            return None
        explicit_token = _bearer_token(request)
        if explicit_token.startswith("lwdev1_"):
            from .device_pairing import authenticate
            principal = authenticate(explicit_token, request.method, route_path(request))
            request.state.paired_device_verified = True
            return principal
        if explicit_token and _api_key_bearer(request):
            return _authenticate_api_key(request, explicit_token)
        if explicit_token and oidc_enabled():
            return _authenticate_oidc_bearer(request, explicit_token)
        raise HTTPException(
            status_code=401,
            detail="invalid bearer credential",
            headers={"WWW-Authenticate": "Bearer"},
        )

    pp = _proxy_principal(request)
    if pp is not None:
        _enforce_scim_active(pp)
        return pp

    # OIDC and SAML mint the same signed browser session. Check it before the
    # protocol switches so a SAML-only deployment (and a proxy+session fallback)
    # cannot degrade to an anonymous local operator.
    sp = _session_principal(request)
    if sp is not None:
        _enforce_scim_active(sp)
        return sp

    # Email-invite local sessions use the same cookie name but their own issuer.
    # Accept only a fully verified, unrevoked session before considering any
    # anonymous compatibility path.
    lp = _invite_session_principal(request)
    if lp is not None:
        _enforce_scim_active(lp)
        return lp

    if self_authenticated:
        return None

    if not oidc_enabled():
        # ``None`` may mean local-admin only when *every* auth mechanism is off.
        # Proxy, SAML, invites, require_auth, or an unreadable auth config all
        # turn a missing/invalid identity into a 401 at the global dependency,
        # including routes that happen not to call an RBAC helper themselves.
        if not anonymous_local_access_allowed():
            raise HTTPException(status_code=401, detail="authenticated identity required")
        return None

    token = _bearer_token(request)
    if not token:
        raise HTTPException(
            status_code=401,
            detail="OIDC bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _authenticate_oidc_bearer(request, token)


def _enforce_workspace_policies(connection, principal) -> None:
    """Policies that need the caller's workspace: its allowed addresses and
    its second-factor requirement (the workspace's config overlay is active
    once the tenant is pinned). Sign-in bootstrap and sign-out paths are
    skipped so a refused session can still end itself."""
    path = route_path(connection)
    if _self_authenticated_path(path):
        return
    from .ip_allowlist import BLOCKED_MESSAGE, workspace_allows
    from .mfa_policy import enforce_session_policy

    if not workspace_allows(connection):
        raise HTTPException(status_code=403, detail=BLOCKED_MESSAGE)
    enforce_session_policy(principal)


def _bind_principal(connection, principal):
    """The only phase that mutates request identity or the task's tenant pin."""
    if connection is not None and principal is not None:
        connection.state.principal = principal
        from .device_pairing import bind as bind_device
        if not bind_device(connection, principal):
            _pin_tenant_from_principal(connection, principal)
        _enforce_workspace_policies(connection, principal)
    return principal


def require_principal(
    request: Request = None,  # type: ignore[assignment]
    websocket: WebSocket = None,  # type: ignore[assignment]
) -> VerifiedPrincipal | None:
    """Synchronous compatibility API; binding stays in the caller's context."""
    principal = _resolve_principal(request=request, websocket=websocket)
    return _bind_principal(request if request is not None else websocket, principal)


_OIDC_VERIFY_SLOTS = 8
_OIDC_ADMISSION_SECONDS = 0.25


async def _verify_off_loop(request, websocket):
    connection = request if request is not None else websocket
    explicit = connection is not None and connection.headers.get("authorization", "")
    remote_bearer = (explicit and not _dashboard_token_authenticated(connection)
                     and (request is None or not _self_authenticated_path(route_path(request))))
    if not remote_bearer:
        return await run_in_threadpool(_resolve_principal, request=request, websocket=websocket)
    # Cap potentially remote verification before borrowing a worker. Probes and
    # local/session authentication retain worker capacity during a slow IdP.
    loop = asyncio.get_running_loop()
    limiter = getattr(loop, "_lightwork_oidc_slots", None)
    if limiter is None:
        limiter = asyncio.Semaphore(_OIDC_VERIFY_SLOTS)
        loop._lightwork_oidc_slots = limiter
    try:
        await asyncio.wait_for(limiter.acquire(), timeout=_OIDC_ADMISSION_SECONDS)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=503, detail="identity verification is busy",
                            headers={"Retry-After": "1"}) from exc
    worker = asyncio.create_task(run_in_threadpool(_resolve_principal, request=request, websocket=websocket))

    def finished(task):
        limiter.release()
        if not task.cancelled():
            task.exception()  # retrieve failures when the client left during verification

    worker.add_done_callback(finished)
    # A disconnected request cannot release admission while its resolver thread
    # is still running. It also cannot bind a late identity into another request.
    return await asyncio.shield(worker)


async def require_principal_in_request_context(
    request: Request = None,  # type: ignore[assignment]
    websocket: WebSocket = None,  # type: ignore[assignment]
) -> VerifiedPrincipal | None:
    """Verify off-loop, then bind identity and tenant in the original task.

    Only cryptographic public keys are cached. Session revocation and identity
    lifecycle are checked on every verification; tenant selection/membership is
    resolved at binding, so cached keys never become an authorization grant.
    """
    principal = await _verify_off_loop(request, websocket)
    return _bind_principal(request if request is not None else websocket, principal)


async def require_websocket_principal_in_context(websocket: WebSocket):
    """Bind the verified handshake in its task and reset the pin on every exit."""
    try:
        principal = await require_principal_in_request_context(websocket=websocket)
        yield principal
    finally:
        token = getattr(websocket.state, "tenant_pin_token", None)
        if token is not None:
            try:
                from maverick.paths import reset_tenant

                reset_tenant(token)
            finally:
                websocket.state.tenant_pin_token = None


def websocket_caller_principal(principal: VerifiedPrincipal | None) -> str | None:
    """Return the owner principal established for a WebSocket connection.

    The app-level dependency returns a ``VerifiedPrincipal`` for OIDC-authenticated
    WebSockets but has no ``Request.state`` to persist it on. WebSocket handlers
    pass that dependency result here so owner checks use the same
    ``user:<sub>`` string as HTTP routes. ``None`` preserves auth-off behavior.
    """
    if principal is None:
        return None
    name = getattr(principal, "principal", "")
    return name if isinstance(name, str) and name else None


def _websocket_same_origin(websocket) -> bool:
    """Require a browser WebSocket Origin matching the requested Host."""
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if not origin or not host:
        return False
    return urlparse(origin).netloc == host


def _websocket_loopback_request_host(websocket) -> bool:
    """True when a WebSocket's user-controlled Host names loopback.

    A loopback socket peer is insufficient in auth-off mode: DNS rebinding can
    connect to 127.0.0.1 while preserving an attacker-controlled Host/Origin
    pair that passes the same-origin comparison. Parse the Host independently
    and require the same loopback boundary as HTTP requests.
    """
    raw_host = str(websocket.headers.get("host") or "")
    if (
        not raw_host
        or raw_host != raw_host.strip()
        or any(char in raw_host for char in "/\\@,?#")
    ):
        return False
    try:
        parsed = urlparse(f"//{raw_host}")
        # Accessing ``port`` validates malformed/non-numeric/out-of-range ports.
        _ = parsed.port
        host = (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def websocket_authorized(
    websocket,
    principal: VerifiedPrincipal | None = None,
) -> bool:
    """Auth gate for WebSocket endpoints (the HTTP middleware doesn't run
    for WS connections).

    Verified proxy/cookie principals additionally require same-origin browser
    handshakes (CSWSH defense). Explicit OIDC/static bearers do not rely on
    browser ambient authority. Principal-less handshakes are same-origin,
    loopback-only, and available solely in genuine local auth-off mode.
    """
    import hmac as _hmac

    if principal is not None:
        via = str((principal.claims or {}).get("via") or "")
        # Cookie/proxy credentials ride a browser handshake and therefore need
        # a same-origin check (CSWSH defense). A verified OIDC bearer is explicit
        # request authentication and does not require a browser Origin header.
        return _websocket_same_origin(websocket) if via in {
            "session", "invite", "proxy",
        } else True
    from ._shared import dashboard_token

    expected = dashboard_token()
    if expected:
        auth = websocket.headers.get("authorization", "")
        supplied = auth[7:] if auth.startswith("Bearer ") else ""
        return bool(supplied) and _hmac.compare_digest(expected.encode(), supplied.encode())
    if not anonymous_local_access_allowed():
        return False
    from .app import _PROXY_FORWARD_HEADERS, _is_loopback_client
    host = websocket.client.host if websocket.client else ""
    proxied = any(websocket.headers.get(h) for h in _PROXY_FORWARD_HEADERS)
    return (
        _is_loopback_client(host)
        and _websocket_loopback_request_host(websocket)
        and not proxied
        and _websocket_same_origin(websocket)
    )
