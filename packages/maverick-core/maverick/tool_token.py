"""Per-call scoped capability tokens -- "token exchange for every tool call".

Lightwork's capability layer (:mod:`maverick.capability`) binds an agent to a
single, run-long grant. That grant is *static* for the whole run: once an agent
is spawned, every tool call it makes rides on the same broad authority, so one
mid-run compromise (a poisoned tool result that steers the agent, a leaked
in-process handle, an over-eager sub-step) can exercise the *entire* grant
until the run ends.

This module narrows that blast radius the way a zero-trust gateway does: at the
tool-call chokepoint the agent *exchanges* its broad, long-lived grant for a
freshly minted, single-tool-scoped, short-lived, signed token that authorizes
exactly one invocation. The minted token:

  - is attenuated to exactly the one tool being called (never the whole grant),
    so it is useless for any other tool -- least privilege per call;
  - carries a short TTL (default 30s) so a captured token cannot be replayed
    minutes later;
  - carries a unique nonce (``jti``) enforced single-use against an in-process
    replay cache; and
  - is Ed25519-signed with the deployment's existing capability/audit key
    (reused -- no new crypto, no new dependency), so an out-of-process verifier
    (an MCP gateway, a sandbox boundary) can check it offline.

Because the token is an *attenuation* of the agent's effective grant, it can
never authorize a tool the grant did not already permit -- exchange only ever
tightens authority, never broadens it.

Opt-in and fail-open, exactly like capability enforcement: with the feature off
(the default) token exchange is a no-op and behaviour is unchanged. When
verifying a token, signatures are mandatory unless a caller explicitly opts into
local unsigned checks for tests or same-process fallback use.
Enable with ``[capabilities] per_call_tokens = true`` or
``MAVERICK_TOOL_TOKENS=1``. It is only meaningful alongside capability
enforcement -- a token minted from no grant has nothing to scope.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, replace

from ._envparse import coerce_bool, env_bool
from .capability import Capability

_DEFAULT_TTL_SECONDS = 30.0
_DEFAULT_REPLAY_CACHE = 4096


@dataclass(frozen=True)
class ToolToken:
    """A minted, single-tool-scoped, short-lived authorization for one call.

    ``capability`` is the parent grant attenuated to exactly ``{tool}``. The
    token is the unit a verifier checks: tool match, not-expired, single-use
    ``jti``, and (by default) a valid signature over :meth:`signing_bytes`.
    """

    capability: Capability
    tool: str
    jti: str
    issued_at: float
    expires_at: float
    signature: str | None = None
    key_id: str | None = None

    def signing_bytes(self) -> bytes:
        """Canonical, stable bytes an Ed25519 signature is taken over.

        Binds the nonce, validity window, principal, and the *full* scoped
        capability (via its own canonical ``signing_bytes``) together, so a
        verifier that trusts the signature can trust every field at once.
        """
        payload = {
            "tool": self.tool,
            "jti": self.jti,
            "iat": round(self.issued_at, 3),
            "exp": round(self.expires_at, 3),
            "principal": self.capability.principal,
            "cap": self.capability.signing_bytes().decode("utf-8"),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def is_expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at


class _ReplayCache:
    """Thread-safe single-use ledger of seen ``jti`` nonces.

    A token's nonce is recorded on first successful verify; a second verify of
    the same nonce is rejected as a replay. Entries self-evict once expired, and
    the cache is bounded: when every slot holds a still-live nonce, a new token
    is refused rather than evicting a live entry (which would make that nonce
    replayable within its TTL).
    """

    def __init__(self, maxsize: int = _DEFAULT_REPLAY_CACHE):
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}
        self._max = max(1, maxsize)

    def check_and_add(self, jti: str, expires_at: float, now: float) -> bool:
        """Return True if ``jti`` is fresh (and record it); False if a replay."""
        with self._lock:
            expired = [k for k, exp in self._seen.items() if exp <= now]
            for k in expired:
                self._seen.pop(k, None)
            if jti in self._seen:
                return False
            if len(self._seen) >= self._max:
                # Every remaining entry is live: dropping one would let it be
                # replayed, so fail closed and refuse the new token instead.
                return False
            self._seen[jti] = expires_at
            return True


_REPLAY_CACHE = _ReplayCache()


def tool_tokens_enabled() -> bool:
    """Opt-in, off by default. ``MAVERICK_TOOL_TOKENS=1`` or
    ``[capabilities] per_call_tokens = true`` turns on per-call token exchange
    at the tool chokepoint. Meaningful only with capability enforcement on."""
    if env_bool("MAVERICK_TOOL_TOKENS"):
        return True
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("capabilities") or {}
        return coerce_bool(cfg.get("per_call_tokens"))
    except Exception:
        return False


def _ttl_seconds() -> float:
    try:
        from .env_setting import env_or_config

        return max(1.0, float(env_or_config(
            "MAVERICK_TOOL_TOKEN_TTL", "capabilities", "per_call_token_ttl",
            str(_DEFAULT_TTL_SECONDS)) or _DEFAULT_TTL_SECONDS))
    except (TypeError, ValueError):
        return _DEFAULT_TTL_SECONDS


def _deployment_keypair() -> tuple[str, str, str] | None:
    """``(private_hex, public_hex, key_id)`` from the deployment's audit key.

    Reuses the existing Ed25519 audit-signing keypair so per-call tokens add no
    new key material or dependency. Returns ``None`` when ``cryptography`` is
    unavailable -- callers then mint *unsigned* tokens (still scoped + expiring +
    single-use). Verifiers reject those unsigned tokens by default; callers that
    intentionally need same-process fallback must opt in explicitly.
    """
    try:
        from .audit.signing import _have_crypto, _load_or_create_keypair
        if not _have_crypto():
            return None
        priv, pub, key_id = _load_or_create_keypair()
        return priv.hex(), pub.hex(), key_id
    except Exception:
        return None


def mint_tool_token(
    cap: Capability,
    tool: str,
    *,
    ttl: float | None = None,
    now: float | None = None,
    private_key_hex: str | None = None,
    key_id: str | None = None,
) -> ToolToken:
    """Exchange a broad grant for a single-tool, short-lived, signed token.

    The result is ``cap`` attenuated to exactly ``{tool}`` -- it can never
    permit a tool ``cap`` did not. Signs with ``private_key_hex`` when given,
    else the deployment audit key; mints unsigned when no key/crypto is present.
    """
    now = time.time() if now is None else now
    ttl = _ttl_seconds() if ttl is None else ttl
    scoped = cap.attenuate(allow={tool}, principal=cap.principal)
    kid = key_id
    if private_key_hex is None:
        loaded = _deployment_keypair()
        if loaded is not None:
            private_key_hex, _pub, kid = loaded
    token = ToolToken(
        capability=scoped,
        tool=tool,
        jti=secrets.token_urlsafe(16),
        issued_at=now,
        expires_at=now + ttl,
        key_id=kid,
    )
    if private_key_hex is not None:
        from .capability import _have_crypto
        if _have_crypto():
            from cryptography.hazmat.primitives.asymmetric import ed25519
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
            token = replace(token, signature=priv.sign(token.signing_bytes()).hex())
    return token


def verify_tool_token(
    token: ToolToken,
    expected_tool: str,
    *,
    now: float | None = None,
    public_key_hex: str | None = None,
    replay_cache: _ReplayCache | None = None,
    require_signature: bool = True,
) -> bool:
    """Verify a minted token authorizes exactly ``expected_tool``, right now.

    Checks, in order (all must hold): the token is scoped to ``expected_tool``;
    its capability still permits it; it has not expired; its signature verifies
    under the deployment/passed pubkey; and its ``jti`` has not been seen before
    (single-use replay defense). ``require_signature`` defaults to ``True`` so
    exported verifier consumers do not accidentally trust attacker-controlled
    unsigned tokens; set it to ``False`` only for intentional same-process
    fallback checks where the token object did not cross a trust boundary.

    Returns ``False`` (never raises) on any failure.
    """
    now = time.time() if now is None else now
    if token.tool != expected_tool:
        return False
    if not token.capability.permits(expected_tool, now=now):
        return False
    if token.is_expired(now):
        return False
    if token.signature is not None:
        pub = public_key_hex
        if pub is None:
            loaded = _deployment_keypair()
            pub = loaded[1] if loaded is not None else None
        if pub is None:
            return False
        from .audit.signing import _have_crypto, verify_ed25519
        if not _have_crypto():
            return False
        if not verify_ed25519(pub, token.signature, token.signing_bytes()):
            return False
    elif require_signature:
        return False
    cache = _REPLAY_CACHE if replay_cache is None else replay_cache
    return cache.check_and_add(token.jti, token.expires_at, now)


__all__ = [
    "ToolToken",
    "tool_tokens_enabled",
    "mint_tool_token",
    "verify_tool_token",
]
