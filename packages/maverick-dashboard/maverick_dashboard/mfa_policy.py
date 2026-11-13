"""Second-factor policy for named sign-in ("Require a second factor").

Reads ``[auth.mfa]`` through :func:`maverick.config.get_auth_mfa` (the
``"auth"`` / ``"mfa"`` tables; keys ``"require"``, ``"step_up_minutes"``,
``"amr_values"``, ``"acr_values"``, ``"saml_authn_contexts"``; environment
``MAVERICK_MFA_REQUIRE`` and ``MAVERICK_MFA_STEP_UP_MINUTES`` win). Off by
default so existing installations are unchanged.

What the policy checks:

* an OIDC ID token proves a second factor when its ``amr`` claim (RFC 8176)
  names one of ``amr_values`` or its ``acr`` claim is one of ``acr_values``;
* a SAML assertion proves it when its ``AuthnContextClassRef`` is one of
  ``saml_authn_contexts``;
* an invitation (passphrase) session and a reverse-proxy identity carry no
  such proof, so with the policy on they are refused sensitive actions and,
  for browser sessions, refused outright with the plain message below.

The browser session records ``mfa`` and ``mfa_at`` (the sign-in time) so the
step-up check (:mod:`step_up`) can ask "how recent was the second factor?".
Nothing here applies without a named sign-in: auth-off local mode and the
static server token have no principal and are never gated.
"""
from __future__ import annotations

import time

from fastapi import HTTPException

MFA_MISSING_MESSAGE = (
    "Your sign-in didn't include a second factor. Sign in again with your "
    "authenticator."
)


def policy() -> dict:
    from maverick.config import get_auth_mfa

    return get_auth_mfa()


def require_mfa() -> bool:
    """Whether named sign-in must include a second factor (fail closed on an
    unreadable policy: uncertainty never turns the requirement off)."""
    try:
        from maverick.config import config_source_errors

        if config_source_errors():
            return True
        require = bool(policy()["require"])
        # The load can be what finds the source unreadable: that stays "on".
        return bool(config_source_errors()) or require
    except Exception:
        return True


def step_up_seconds() -> int:
    try:
        return int(policy()["step_up_minutes"]) * 60
    except Exception:
        from maverick.config import DEFAULT_STEP_UP_MINUTES

        return DEFAULT_STEP_UP_MINUTES * 60


def claims_prove_mfa(claims: dict | None) -> bool:
    """Whether a verified ID token's claims show a second factor was used."""
    if not isinstance(claims, dict):
        return False
    try:
        rules = policy()
    except Exception:
        return False
    amr = claims.get("amr")
    if isinstance(amr, str):
        amr = [amr]
    accepted = {v.lower() for v in rules["amr_values"]}
    if isinstance(amr, (list, tuple)) and any(
        isinstance(m, str) and m.strip().lower() in accepted for m in amr
    ):
        return True
    acr = claims.get("acr")
    return isinstance(acr, str) and acr.strip() in set(rules["acr_values"])


def saml_context_proves_mfa(authn_context: str | None) -> bool:
    """Whether a SAML assertion's authentication context names a second factor."""
    if not isinstance(authn_context, str) or not authn_context.strip():
        return False
    try:
        return authn_context.strip() in set(policy()["saml_authn_contexts"])
    except Exception:
        return False


def principal_mfa(principal) -> tuple[bool, float | None]:
    """``(proved, when)`` for an established principal.

    Browser sessions carry ``mfa``/``mfa_at`` written at sign-in. An explicit
    OIDC bearer is judged from its own claims, dated by ``auth_time`` (or
    ``iat``). Proxy identities and anything else prove nothing.
    """
    claims = getattr(principal, "claims", None) or {}
    via = str(claims.get("via") or "")
    if via in {"session", "invite"}:
        if claims.get("mfa") is not True:
            return False, None
        try:
            return True, float(claims.get("mfa_at"))
        except (TypeError, ValueError):
            return False, None
    if via == "proxy":
        return False, None
    if not claims_prove_mfa(claims):
        return False, None
    when = claims.get("auth_time", claims.get("iat"))
    try:
        return True, float(when)
    except (TypeError, ValueError):
        return True, None


def _issued_by_a_signed_in_person(principal) -> bool:
    """True for an API key or a paired device.

    Neither can present a second factor. Both are issued only from an
    interactive sign-in, which this policy has already checked, so the
    requirement is met when the credential is issued. Without this, turning
    the requirement on would refuse every service account.
    """
    claims = getattr(principal, "claims", None) or {}
    return (claims.get("via") == "api_key"
            or getattr(principal, "issuer", "") == "lightwork:paired-device")


def enforce_session_policy(principal) -> None:
    """Refuse an established named identity that lacks a required second factor.

    Runs after a workspace is chosen, so a workspace's own ``[auth.mfa]``
    overlay applies to its members, and it also catches sessions signed in
    before the requirement was turned on.
    """
    if principal is None or not require_mfa():
        return
    if _issued_by_a_signed_in_person(principal):
        return
    proved, _when = principal_mfa(principal)
    if not proved:
        raise HTTPException(status_code=403, detail=MFA_MISSING_MESSAGE)


def fresh_enough(when: float | None, *, now: float | None = None) -> bool:
    if when is None:
        return False
    current = time.time() if now is None else now
    return 0 <= current - when <= step_up_seconds()


__all__ = [
    "MFA_MISSING_MESSAGE",
    "claims_prove_mfa",
    "enforce_session_policy",
    "fresh_enough",
    "policy",
    "principal_mfa",
    "require_mfa",
    "saml_context_proves_mfa",
    "step_up_seconds",
]
