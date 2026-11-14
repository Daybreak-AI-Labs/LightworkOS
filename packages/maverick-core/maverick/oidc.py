"""OIDC ID-token verification — the P4 SSO foundation for `maverick serve`.

Verifies an OpenID-Connect ID token (a JWT) against a configured issuer and
audience and returns a :class:`VerifiedPrincipal` whose ``principal`` id is
``f"user:{sub}"`` — the same convention the agent loop and capability layer
already use (see :func:`maverick.capability.capability_from_config` and
``agent.py``'s root-grant principal). So a verified SSO user drops straight
into the existing capability/tenant model with no new identity surface.

Security posture (these are load-bearing, not stylistic — get them wrong and
it's an auth bypass):

- The signature-algorithm allowlist is **asymmetric-only** (default
  ``["RS256","ES256"]``). ``none`` and every HMAC alg (``HS256/384/512``) are
  rejected. This defeats the classic *alg-confusion* attack, where an attacker
  re-signs a token with ``HS256`` using the *public* RSA key bytes as the HMAC
  secret; if a verifier accepts HMAC, the public key (which everyone has)
  becomes a forgery key. We never feed a symmetric verification path to PyJWT.
- ``exp``/``iat``/``aud``/``iss``/``sub`` are all *required* and verified
  (``options={"require": [...]}`` plus ``audience=``/``issuer=``). A token
  missing any of them is rejected.
- Signing keys are fetched from the JWKS endpoint keyed by the token header
  ``kid``; a ``kid`` absent from the JWKS is a rejection (no fallback key).
- On ANY failure we raise :class:`OIDCError`. We never return a principal on a
  partial/failed verification — there is no fail-open path to "authenticated".

Off by default. With ``[auth.oidc].enabled`` unset (and no ``MAVERICK_OIDC_*``
env), :func:`oidc_enabled` is False and nothing in the kernel requires a token —
behaviour is unchanged. This mirrors the opt-in pattern in
``capability.capability_enforced`` and ``paths.tenant_by_user_enabled``.

PyJWT (``pyjwt[crypto]``) is an *optional* dependency (extra ``oidc``); the
kernel imports fine without it. It's lazy-imported only when verification
actually runs, with an actionable install hint.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from ._envparse import is_truthy

# Asymmetric signature algorithms only. HMAC (HS*) and "none" are
# deliberately absent and additionally hard-rejected below, regardless of
# config, so a misconfigured `[auth.oidc].algorithms` can never reopen the
# alg-confusion hole.
DEFAULT_ALGORITHMS = ["RS256", "ES256"]
_USER_PRINCIPAL_PREFIX = "user:"
_MAX_PRINCIPAL_LENGTH = 256
MAX_SUBJECT_LENGTH = _MAX_PRINCIPAL_LENGTH - len(_USER_PRINCIPAL_PREFIX)
_ALLOWED_ASYMMETRIC = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
)
class OIDCError(Exception):
    """Raised on any OIDC verification or configuration failure.

    Subclasses :class:`Exception` (not anything that could be mistaken for
    success). Callers MUST treat this as "unauthenticated" — there is no
    code path that both raises this and returns a principal.
    """


def validate_subject(value: object) -> str:
    """Validate and return an exact subject shared by every auth boundary.

    Subjects are opaque after this check. Edge whitespace is rejected rather
    than normalized so no SSO surface can alias two external identities onto a
    downstream store that historically strips its keys.
    """
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_SUBJECT_LENGTH
        or not value.isprintable()
        or value != value.strip()
    ):
        raise ValueError("invalid authenticated subject")
    return value


@dataclass(frozen=True)
class VerifiedPrincipal:
    """A successfully verified OIDC subject, mapped to Lightwork's identity.

    ``principal`` is ``f"user:{sub}"`` so it slots straight into the
    capability/tenant conventions; ``claims`` is the raw verified claim set
    (callers may read ``email``/``name``/etc., but trust only what the IdP
    actually signed)."""

    sub: str
    issuer: str
    audience: str
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def principal(self) -> str:
        return f"{_USER_PRINCIPAL_PREFIX}{self.sub}"


@dataclass(frozen=True)
class OIDCConfig:
    """Resolved ``[auth.oidc]`` settings.

    The ``client_id`` / ``client_secret`` / ``redirect_uri`` / ``session_secret``
    and the optional explicit ``authorization_endpoint`` / ``token_endpoint``
    fields are used ONLY by the built-in browser-login flow
    (:func:`login_enabled`). They are inert for plain bearer-token verification
    (:func:`verify_oidc_token`), which needs only ``issuer``/``audience``/
    ``jwks_uri``.
    """

    enabled: bool = False
    issuer: str = ""
    audience: str = ""
    jwks_uri: str = ""
    algorithms: list[str] = field(default_factory=lambda: list(DEFAULT_ALGORITHMS))
    # Browser authorization-code login (off unless fully configured; see
    # login_enabled()).
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    session_secret: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""


def _env_flag(name: str) -> bool | None:
    """Tri-state env flag: True/False if set to a recognized value, else None
    (meaning "env says nothing; defer to config")."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    return is_truthy(raw)


def _load_oidc_section() -> dict | None:
    """Read the ``[auth.oidc]`` table from config.

    A missing config gives ``{}`` (the kernel runs without one). An unreadable
    config source gives ``None``: the sign-in settings may have been lost, so
    the caller must not read that as "sign-in is off".
    """
    try:
        from .config import config_source_errors, load_config

        auth = (load_config() or {}).get("auth") or {}
        if config_source_errors(include_tenant=True):
            return None
        section = auth.get("oidc") or {}
        return section if isinstance(section, dict) else {}
    except Exception:
        return None


def _normalize_algorithms(value: Any) -> list[str]:
    """Coerce a config/env value into a clean, asymmetric-only alg list.

    Drops anything that isn't an allowlisted asymmetric algorithm — so a
    hand-edited config that adds ``HS256`` or ``none`` silently loses it here,
    and :func:`verify_oidc_token` independently re-checks before calling PyJWT.
    """
    if isinstance(value, str):
        items = [p.strip() for p in value.split(",")]
    elif isinstance(value, (list, tuple)):
        items = [str(p).strip() for p in value]
    else:
        items = []
    algs = [a for a in items if a in _ALLOWED_ASYMMETRIC]
    return algs or list(DEFAULT_ALGORITHMS)


def load_oidc_config() -> OIDCConfig:
    """Resolve OIDC config from ``MAVERICK_OIDC_*`` env then ``[auth.oidc]``.

    Env overrides config per field. ``algorithms`` accepts a comma-separated
    env value or a TOML list; it is always normalized to asymmetric-only.
    The section and both secrets come from one configuration read.
    """
    from .config import single_read

    with single_read():
        return _load_oidc_config()


def _load_oidc_config() -> OIDCConfig:
    loaded = _load_oidc_section()
    section = loaded if loaded is not None else {}

    enabled_env = _env_flag("MAVERICK_OIDC_ENABLED")
    if enabled_env is not None:
        enabled = enabled_env
    elif loaded is None:
        # Unreadable sign-in settings keep sign-in enforced; with no issuer or
        # audience every token then fails verification (deny, not legacy trust).
        enabled = True
    else:
        enabled = bool(section.get("enabled", False))

    issuer = os.environ.get("MAVERICK_OIDC_ISSUER") or str(section.get("issuer", "") or "")
    audience = os.environ.get("MAVERICK_OIDC_AUDIENCE") or str(section.get("audience", "") or "")
    jwks_uri = os.environ.get("MAVERICK_OIDC_JWKS_URI") or str(section.get("jwks_uri", "") or "")

    algs_raw: Any = os.environ.get("MAVERICK_OIDC_ALGORITHMS")
    if algs_raw is None:
        algs_raw = section.get("algorithms")
    algorithms = _normalize_algorithms(algs_raw)

    # Browser-login fields (env overrides config, same as above). These are
    # only consulted by the authorization-code flow; bearer verification
    # ignores them.
    client_id = os.environ.get("MAVERICK_OIDC_CLIENT_ID") or str(
        section.get("client_id", "") or ""
    )
    # OIDC client/session secrets route through the secret provider so a
    # mounted vault file can supply them without putting the secret in the
    # process env; default backend reads env exactly as before.
    from .secret_provider import get_secret
    client_secret = get_secret("MAVERICK_OIDC_CLIENT_SECRET") or str(
        section.get("client_secret", "") or ""
    )
    redirect_uri = os.environ.get("MAVERICK_OIDC_REDIRECT_URI") or str(
        section.get("redirect_uri", "") or ""
    )
    session_secret = get_secret("MAVERICK_OIDC_SESSION_SECRET") or str(
        section.get("session_secret", "") or ""
    )
    authorization_endpoint = os.environ.get(
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT"
    ) or str(section.get("authorization_endpoint", "") or "")
    token_endpoint = os.environ.get("MAVERICK_OIDC_TOKEN_ENDPOINT") or str(
        section.get("token_endpoint", "") or ""
    )

    return OIDCConfig(
        enabled=enabled,
        issuer=issuer.strip(),
        audience=audience.strip(),
        jwks_uri=jwks_uri.strip(),
        algorithms=algorithms,
        client_id=client_id.strip(),
        client_secret=client_secret.strip(),
        redirect_uri=redirect_uri.strip(),
        session_secret=session_secret.strip(),
        authorization_endpoint=authorization_endpoint.strip(),
        token_endpoint=token_endpoint.strip(),
    )


def oidc_enabled() -> bool:
    """Opt-in, off by default. ``MAVERICK_OIDC_ENABLED=1`` or
    ``[auth.oidc] enabled = true`` turns on OIDC ID-token verification for the
    serving surface. Off -> no token is required and behaviour is unchanged.
    When the env does not decide and a config source is unreadable, this is
    True (fail closed): the setting may have been lost with the file."""
    return load_oidc_config().enabled


def login_enabled(config: OIDCConfig | None = None) -> bool:
    """True only when the built-in OIDC *browser-login* flow is fully configured.

    Fail-closed and off by default: the dashboard's ``/auth/login`` /
    ``/auth/callback`` / ``/auth/logout`` routes are registered ONLY when this
    returns True, so a partial/absent config changes nothing (the existing
    bearer gate and reverse-proxy path keep working unchanged).

    Requires ALL of:
      - :func:`oidc_enabled` (the OIDC master switch),
      - ``client_id`` and ``client_secret`` (the OAuth client registered at the provider),
      - ``redirect_uri`` (the registered return address),
      - ``audience`` (the ID-token audience Lightwork will verify),
      - ``session_secret`` (the HMAC key for our signed session cookie), and
      - ``issuer`` (also required when endpoints are entered explicitly, so
        the returned ID token can be verified).
    """
    cfg = config if config is not None else load_oidc_config()
    if not cfg.enabled:
        return False
    if not (cfg.client_id and cfg.client_secret and cfg.redirect_uri
            and cfg.audience and cfg.session_secret):
        return False
    return bool(cfg.issuer)


# Discovery cache: issuer -> {"authorization_endpoint": ..., "token_endpoint":
# ...}. The OIDC discovery document is effectively static, so we fetch it once
# per issuer per process. Keyed by issuer so a config change to a new issuer
# isn't served a stale doc.
_DISCOVERY_CACHE: dict[str, dict[str, str]] = {}


def _discover_endpoints(issuer: str, *, timeout: float = 5.0) -> dict[str, str]:
    """GET ``<issuer>/.well-known/openid-configuration`` and return the
    authorization/token endpoints.

    HTTPS-only and short-timeout. Cached per issuer. Fail-soft in the sense that
    it never returns a partial/garbage result — any failure (non-https issuer,
    network error, malformed JSON, missing/non-https endpoints) raises
    :class:`OIDCError`, which the caller turns into a clean 4xx/5xx without
    leaking internals.
    """
    issuer = (issuer or "").strip()
    if not issuer:
        raise OIDCError("OIDC issuer is not configured for discovery")
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached is not None:
        return cached
    if not issuer.lower().startswith("https://"):
        raise OIDCError("OIDC issuer must be https for discovery")

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        import httpx

        from .governed_http import guarded_redirect_get

        resp = guarded_redirect_get(httpx.get, require_https=True)(
            url, timeout=timeout, follow_redirects=True,
        )
        resp.raise_for_status()
        doc = resp.json()
    except OIDCError:
        raise
    except Exception as e:  # network, timeout, non-2xx, bad JSON
        raise OIDCError(f"OIDC discovery failed: {e}") from e

    if not isinstance(doc, dict):
        raise OIDCError("OIDC discovery document is not a JSON object")
    authorization_endpoint = str(doc.get("authorization_endpoint", "") or "").strip()
    token_endpoint = str(doc.get("token_endpoint", "") or "").strip()
    # The endpoints we will redirect a browser to / POST a client secret to must
    # themselves be https — never downgrade onto a plaintext endpoint a
    # discovery document happens to advertise.
    if not authorization_endpoint.lower().startswith("https://"):
        raise OIDCError("discovered authorization_endpoint is missing or not https")
    if not token_endpoint.lower().startswith("https://"):
        raise OIDCError("discovered token_endpoint is missing or not https")

    resolved = {
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
    }
    _DISCOVERY_CACHE[issuer] = resolved
    return resolved


def resolve_endpoints(config: OIDCConfig | None = None) -> dict[str, str]:
    """Resolve the authorization + token endpoints for the login flow.

    Explicit ``authorization_endpoint`` / ``token_endpoint`` config wins; any
    gap is filled from the issuer's discovery document. Raises
    :class:`OIDCError` if the result can't be fully resolved.
    """
    cfg = config if config is not None else load_oidc_config()
    authorization_endpoint = cfg.authorization_endpoint
    token_endpoint = cfg.token_endpoint
    if not authorization_endpoint or not token_endpoint:
        discovered = _discover_endpoints(cfg.issuer)
        authorization_endpoint = authorization_endpoint or discovered["authorization_endpoint"]
        token_endpoint = token_endpoint or discovered["token_endpoint"]
    if not authorization_endpoint or not token_endpoint:
        raise OIDCError("could not resolve OIDC authorization/token endpoints")
    return {
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
    }


def _require_pyjwt():
    """Lazy-import PyJWT with an actionable error.

    The kernel must run without PyJWT installed; we only need it when actually
    verifying a token, so the import lives here rather than at module top."""
    try:
        import jwt  # noqa: F401
        return jwt
    except ModuleNotFoundError as e:
        raise OIDCError(
            "OIDC verification requires PyJWT, which isn't installed. "
            "Install the optional extra:  python -m pip install -e './packages/maverick-core[oidc]'  "
            "(or  pip install 'pyjwt[crypto]>=2.13.0' )."
        ) from e


def _safe_algorithms(config: OIDCConfig) -> list[str]:
    """The final algorithm allowlist handed to PyJWT.

    Defence in depth: even though config is normalized on load, we filter again
    to asymmetric-only here so no caller-built ``OIDCConfig`` (or future code
    path) can smuggle ``HS*``/``none`` into the verify call. If nothing
    survives, we raise rather than silently fall back — refusing to verify is
    the safe failure."""
    algs = [a for a in config.algorithms if a in _ALLOWED_ASYMMETRIC]
    if not algs:
        raise OIDCError(
            "no asymmetric signing algorithm configured; refusing to verify "
            "(HMAC/none are never accepted for OIDC)"
        )
    return algs


def _resolve_signing_key(
    jwt_mod,
    token: str,
    *,
    signing_key: Any,
    config: OIDCConfig,
):
    """Resolve the verification key.

    Order:
      1. An explicitly injected ``signing_key`` (a PEM/obj key, or a
         ``PyJWKClient``-like object exposing ``get_signing_key_from_jwt``) is
         used directly — this is the test seam, so no network is touched.
      2. Otherwise a bounded policy-keyed resolver supplies a currently fresh
         public key, refreshing once on cold/expired or unknown-kid access.
         Resolution failure becomes :class:`OIDCError`.
    """
    if signing_key is not None:
        # A resolver/JWK-client was injected: let it pick by kid.
        if hasattr(signing_key, "get_signing_key_from_jwt"):
            try:
                return signing_key.get_signing_key_from_jwt(token).key
            except Exception as e:  # PyJWKClientError, key-not-found, ...
                raise OIDCError(f"signing key resolution failed: {e}") from e
        # A raw key object / PEM string was injected (the common test path:
        # the local RSA public key). Use it as-is.
        return signing_key

    if not config.jwks_uri:
        raise OIDCError("OIDC jwks_uri is not configured")
    try:
        from ._oidc_jwks import resolve

        return resolve(jwt_mod, token, config)
    except Exception as e:  # network error, unknown kid, malformed JWKS
        raise OIDCError(f"could not fetch JWKS signing key: {e}") from e


def verify_oidc_token(
    token: str,
    *,
    config: OIDCConfig | None = None,
    signing_key: Any = None,
) -> VerifiedPrincipal:
    """Verify an OIDC ID token and return its :class:`VerifiedPrincipal`.

    Args:
        token: the raw compact JWT (the ``id_token`` from the IdP).
        config: resolved :class:`OIDCConfig`; defaults to :func:`load_oidc_config`.
        signing_key: optional verification key OR a ``PyJWKClient``-like
            resolver. When provided, NO network call is made — this is the test
            seam (mint a token with a local RSA key, inject the public key).
            When ``None``, a :class:`jwt.PyJWKClient` is built from
            ``config.jwks_uri`` and the key is resolved by the token's ``kid``.

    Raises:
        OIDCError: on a missing/invalid token, missing config (issuer/audience),
            an unresolvable ``kid``, a disallowed algorithm, a bad signature, an
            expired token, an audience/issuer mismatch, or any missing required
            claim. NEVER returns on failure — there is no fail-open path.
    """
    cfg = config if config is not None else load_oidc_config()

    if not isinstance(token, str) or not token.strip():
        raise OIDCError("empty or non-string token")
    if not cfg.issuer:
        raise OIDCError("OIDC issuer is not configured")
    if not cfg.audience:
        raise OIDCError("OIDC audience is not configured")

    algorithms = _safe_algorithms(cfg)
    jwt_mod = _require_pyjwt()

    key = _resolve_signing_key(
        jwt_mod, token, signing_key=signing_key, config=cfg
    )

    try:
        claims = jwt_mod.decode(
            token,
            key,
            algorithms=algorithms,
            audience=cfg.audience,
            issuer=cfg.issuer,
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt_mod.InvalidTokenError as e:
        # Covers expiry, aud/iss mismatch, bad signature, disallowed alg
        # (incl. the HS256-with-public-key alg-confusion attempt, which PyJWT
        # rejects because HS256 isn't in `algorithms`), and missing required
        # claims. All collapse to one OIDCError type; its message carries
        # PyJWT's reason (expired, audience, signature) for server logs, so
        # callers must not echo str(exc) to the client.
        raise OIDCError(f"token verification failed: {e}") from e
    except Exception as e:  # defensive: never leak a non-OIDCError to callers
        raise OIDCError(f"token verification failed: {e}") from e

    try:
        sub = validate_subject(claims.get("sub"))
    except ValueError:
        # ``require`` already enforces presence, but it does not give us a
        # bounded, log-safe identity domain. Validate the signed value exactly
        # once at this trust boundary, then preserve it character-for-character
        # as an opaque subject. Never silently strip/case-fold it: padding is
        # rejected because downstream identity stores historically normalize
        # edge whitespace and must not collapse two IdP subjects onto one owner.
        raise OIDCError("token 'sub' claim is missing or invalid") from None

    return VerifiedPrincipal(
        sub=sub,
        issuer=cfg.issuer,
        audience=cfg.audience,
        claims=claims,
    )


__all__ = [
    "OIDCError",
    "OIDCConfig",
    "VerifiedPrincipal",
    "DEFAULT_ALGORITHMS",
    "MAX_SUBJECT_LENGTH",
    "validate_subject",
    "oidc_enabled",
    "login_enabled",
    "load_oidc_config",
    "resolve_endpoints",
    "verify_oidc_token",
]
