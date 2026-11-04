"""Platform-native identity verification for external agents.

The external gateway historically authenticated foreign agents with minted
per-surface bearers alone. This module adds the three platform-native schemes
a bring-your-own-agent deployment actually holds credentials for, each pinned
to a single :class:`~maverick.agent_trust.TrustedAgent` registry entry:

* **JWT** (``jwt_issuer`` / ``jwt_audience`` / ``jwks_file``) — an OIDC-style
  ID/access token verified against key material read from a LOCAL file (PEM
  public key or JSON JWKS), or — identity federation — fetched from an
  ``https://`` JWKS endpoint (Microsoft Entra ID, Okta, any OIDC IdP) with a
  bounded timeout and cached keys; the token's ``sub`` must equal the agent
  id exactly, so a token minted for agent A can never authenticate B.
  Authorization never federates: the agent must still hold an active,
  inbound-permitted registry entry here.
* **HMAC** (``hmac_secret_ref``) — the Lightwork webhook signature format
  (``X-Maverick-Timestamp`` + ``X-Maverick-Signature``) verified through
  :func:`maverick.webhooks.verify_signature`; the registry stores a secret
  NAME resolved through ``maverick.secret_provider.get_secret`` at verify
  time, never the secret itself.
* **Ed25519 envelope** (``pubkey``) — a detached signature over a
  domain-separated request digest, with a freshness window and a single-use
  nonce (replay defence mirroring :func:`maverick.handoff.verify_handoff`).

Both signed schemes are SINGLE USE: a valid request is claimed in a durable,
per-agent ledger (:func:`claim_once`) before it authenticates, so the same
bytes cannot be replayed inside their freshness window — including against a
different dashboard worker, which an in-process cache could not prevent.

Pure verifier library: no FastAPI imports, and no network except the one
explicit opt-in above — an ``https://`` value in ``jwks_file`` is a deliberate
operator decision to trust that IdP endpoint. Every function returns
``(TrustedAgent | None, rule)`` and FAILS CLOSED — any error, mismatch, or
missing material yields ``(None, <rule>)``; nothing here ever raises to the
caller. Each resolver re-applies ``is_active()`` and ``permits_inbound()``
itself, so a revoked/expired/outbound-only entry never authenticates.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from pathlib import Path

from .agent_trust import TrustedAgent, load_registry

log = logging.getLogger(__name__)

#: Domain-separated, versioned message prefix for the Ed25519 request scheme,
#: so a request signature can never double as a handoff/approval/federation
#: signature (mirrors ``approval_signing.APPROVAL_MESSAGE_VERSION``).
ENVELOPE_MESSAGE_VERSION = "lightwork-external-request-v1"
ENVELOPE_MAX_AGE_SECONDS = 300.0
ENVELOPE_CLOCK_SKEW_SECONDS = 60.0
HMAC_MAX_AGE_SECONDS = 300
_MAX_NONCE_BYTES = 128  # matches handoff.HANDOFF_MAX_NONCE_BYTES
_MAX_TIMESTAMP_CHARS = 64

#: Per-agent ceiling on remembered replay keys. The ledger is partitioned by
#: agent so a busy (or hostile) agent can only ever saturate its OWN budget —
#: a single global cache would let two chatty agents lock every other agent
#: out of the signed schemes entirely.
_MAX_KEYS_PER_AGENT = 4096


class ReplayStoreError(RuntimeError):
    """The single-use ledger exists but cannot be read or written. Callers
    fail CLOSED — a request whose single-use property cannot be PROVEN is
    refused, exactly like :mod:`maverick_dashboard.saml_replay`."""


def _replay_path():
    """Single-use ledger for the signed schemes, tenant-scoped like the
    enrollment sidecar: ``{agent_id: {key: expires_at}}``.

    On disk rather than in memory because the gateway runs inside the
    dashboard app, which is deployed with MULTIPLE WORKERS — a per-process
    cache would let the same signed request replay successfully on a
    different worker."""
    from .paths import data_dir
    return data_dir("external-replay.json")


def _load_replay() -> dict[str, dict[str, float]]:
    from .file_lock import atomic_read_text, ensure_private_file
    path = _replay_path()
    try:
        ensure_private_file(path)
        raw = atomic_read_text(path)
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise ReplayStoreError(f"replay ledger unreadable: {e}") from e
    if not raw.strip():
        return {}

    def _reject_constant(value: str):
        # NaN/Infinity would never expire, so they can never be trusted as
        # ledger state (the stdlib decoder accepts them by default).
        raise ValueError(f"non-finite number {value!r}")

    try:
        data = json.loads(raw, parse_constant=_reject_constant)
    except (TypeError, ValueError) as e:
        raise ReplayStoreError(f"replay ledger corrupt: {e}") from e
    if not isinstance(data, dict):
        raise ReplayStoreError("replay ledger corrupt: root must be an object")
    out: dict[str, dict[str, float]] = {}
    for agent_id, keys in data.items():
        if not isinstance(keys, dict):
            raise ReplayStoreError(
                f"replay ledger corrupt: {agent_id!r} must map keys to expiries")
        bucket: dict[str, float] = {}
        for key, expiry in keys.items():
            if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
                raise ReplayStoreError(
                    f"replay ledger corrupt: expiry for {key!r} must be a number")
            if not math.isfinite(expiry) or expiry <= 0:
                raise ReplayStoreError(
                    f"replay ledger corrupt: expiry for {key!r} must be finite")
            bucket[str(key)] = float(expiry)
        out[str(agent_id)] = bucket
    return out


def claim_once(agent_id: str, key: str, *, expires_at: float,
               now: float) -> str | None:
    """Claim one single-use key for ``agent_id``; the refusal rule or ``None``.

    First-writer-wins under a cross-process lock, so the claim holds across
    dashboard workers. Expired keys prune on the way past; a per-agent budget
    that is still full after pruning REFUSES rather than evicting a live key
    (evicting one would silently reopen its replay window). Raises
    :class:`ReplayStoreError` when the ledger cannot be read or written — the
    caller turns that into a refusal."""
    from .file_lock import (
        atomic_write_text,
        cross_process_lock,
        ensure_private_directory,
    )
    path = _replay_path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        ledger = _load_replay()
        bucket = {k: v for k, v in (ledger.get(agent_id) or {}).items()
                  if v > now}
        if key in bucket:
            return "replay"
        if len(bucket) >= _MAX_KEYS_PER_AGENT:
            return "replay_budget_full"
        bucket[key] = float(expires_at)
        ledger[agent_id] = bucket
        # Drop agents whose keys have all expired so the file stays bounded
        # by ACTIVE callers, not by every agent ever enrolled.
        ledger = {a: {k: v for k, v in keys.items() if v > now}
                  for a, keys in ledger.items()}
        ledger = {a: keys for a, keys in ledger.items() if keys}
        try:
            atomic_write_text(path, json.dumps(ledger, sort_keys=True),
                              mode=0o600)
        except OSError as e:
            raise ReplayStoreError(f"replay ledger unwritable: {e}") from e
    return None


def _active_inbound(agent: TrustedAgent, now: float | None = None) -> str | None:
    """The rule that disqualifies ``agent`` as an inbound caller, or ``None``."""
    active, why = agent.is_active(now)
    if not active:
        return why
    if not agent.permits_inbound():
        return "direction"
    return None


# -- JWT ---------------------------------------------------------------------

def _aud_matches(claim_aud: object, audience: str) -> bool:
    """Does the UNVERIFIED ``aud`` claim name ``audience``? (Routing only —
    the cryptographic audience check is PyJWT's, inside verify_oidc_token.)"""
    if isinstance(claim_aud, str):
        return claim_aud == audience
    if isinstance(claim_aud, (list, tuple)):
        return any(isinstance(a, str) and a == audience for a in claim_aud)
    return False


class _StaticJWKS:
    """A ``PyJWKClient``-shaped resolver over a static JWKS document.

    Exposes ``get_signing_key_from_jwt`` so :func:`oidc._resolve_signing_key`
    treats it exactly like a JWK client — but the keys come from a local file,
    so no network is ever touched. A ``kid`` absent from the document is a
    rejection (raises; the oidc layer converts it to ``OIDCError``)."""

    def __init__(self, jwt_mod, keys: list[dict]) -> None:
        self._jwt = jwt_mod
        self._keys = keys

    def get_signing_key_from_jwt(self, token: str):
        kid = self._jwt.get_unverified_header(token).get("kid")
        if kid is not None:
            matches = [k for k in self._keys if k.get("kid") == kid]
        elif len(self._keys) == 1:
            matches = list(self._keys)
        else:
            matches = []
        if len(matches) != 1:
            raise ValueError("no unique JWKS key matches the token header")
        return self._jwt.PyJWK.from_dict(matches[0])


#: Fetched JWKS documents per federated endpoint: url -> (expires_at,
#: keys). Cached with a bounded lifespan so IdP key rotation is picked up
#: without a per-request fetch.
_JWKS_CACHE: dict[str, tuple[float, list[dict]]] = {}
_JWKS_FETCH_TIMEOUT_SECONDS = 10
_JWKS_CACHE_LIFESPAN_SECONDS = 300
_JWKS_MAX_BYTES = 1024 * 1024


def _remote_jwks_client(jwt_mod, url: str):
    """A cached static resolver over one https JWKS endpoint, or ``None``.

    Only ``https://`` is ever fetched — a plaintext URL is a refusal, not
    a downgrade — and the fetch goes through the platform's enterprise
    egress policy and SSRF-pinned client, exactly like every other
    operator-configured outbound URL; PyJWT never touches the network
    here. Fetch or parse errors fail closed like an unreadable file."""
    if not url.startswith("https://"):
        return None
    cached = _JWKS_CACHE.get(url)
    now = time.monotonic()
    if cached is not None and cached[0] > now:
        return _StaticJWKS(jwt_mod, cached[1])
    try:
        from .enterprise import enterprise_egress_denial
        from .tools._ssrf import BlockedHost, safe_client

        if enterprise_egress_denial(url, tool="external_identity"):
            return None
        try:
            with safe_client(url, timeout=_JWKS_FETCH_TIMEOUT_SECONDS) as client:
                response = client.get(url)
        except BlockedHost:
            return None
        if response.status_code != 200:
            return None
        text = response.text or ""
        if len(text.encode("utf-8", "ignore")) > _JWKS_MAX_BYTES:
            return None
        document = json.loads(text)
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list) or not keys:
            return None
        keys = [key for key in keys if isinstance(key, dict)]
    except Exception:
        return None
    _JWKS_CACHE[url] = (now + _JWKS_CACHE_LIFESPAN_SECONDS, keys)
    return _StaticJWKS(jwt_mod, keys)


def _signing_key_for(jwt_mod, entry: TrustedAgent):
    """Resolve ``entry.jwks_file`` into a ``verify_oidc_token`` signing key.

    PEM content is handed to PyJWT as-is; a JSON document (JWKS or a single
    JWK) is wrapped in the static resolver above; an ``https://`` value is
    federated key material fetched from the IdP's JWKS endpoint with a
    bounded timeout and cached keys. The material is resolved at VERIFY
    time (like ``grpc_tls._read``) so rotation is a file swap or an IdP-side
    roll. Returns ``None`` on absent/unreadable/junk material — the caller
    fails closed."""
    if not entry.jwks_file:
        return None
    if entry.jwks_file.startswith(("http://", "https://")):
        return _remote_jwks_client(jwt_mod, entry.jwks_file)
    try:
        raw = Path(entry.jwks_file).expanduser().read_bytes()
    except OSError:
        return None
    stripped = raw.strip()
    if not stripped.startswith(b"{"):
        return raw  # PEM public key: PyJWT consumes it directly
    try:
        doc = json.loads(stripped.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None
    if isinstance(doc, dict) and isinstance(doc.get("keys"), list):
        keys = [k for k in doc["keys"] if isinstance(k, dict)]
    elif isinstance(doc, dict) and doc.get("kty"):
        keys = [doc]
    else:
        return None
    return _StaticJWKS(jwt_mod, keys) if keys else None


def verify_agent_jwt(
    token: str, *, registry: dict[str, TrustedAgent] | None = None,
) -> tuple[TrustedAgent | None, str]:
    """Authenticate a platform-issued JWT against the trust registry.

    Routes by the token's UNVERIFIED ``iss``/``aud`` claims to the one entry
    with matching ``jwt_issuer``/``jwt_audience`` (peeking is acceptable for
    routing only, never for trust), then verifies signature, expiry, issuer,
    and audience through :func:`maverick.oidc.verify_oidc_token` with key
    material from the entry's ``jwks_file``. The VERIFIED ``sub`` must equal
    the entry id exactly. Returns ``(agent, "ok")`` or ``(None, rule)``."""
    try:
        return _verify_agent_jwt(token, registry=registry)
    except Exception:
        log.warning("external_identity: JWT verification error (fail-closed)",
                    exc_info=True)
        return None, "verifier_error"


def _verify_agent_jwt(
    token: str, *, registry: dict[str, TrustedAgent] | None,
) -> tuple[TrustedAgent | None, str]:
    if not isinstance(token, str) or not token.strip():
        return None, "no_token"
    from . import oidc
    try:
        jwt_mod = oidc._require_pyjwt()
    except oidc.OIDCError:
        return None, "jwt_unavailable"
    try:
        peek = jwt_mod.decode(token, options={"verify_signature": False})
    except Exception:
        return None, "jwt_malformed"
    reg = load_registry() if registry is None else registry
    iss = peek.get("iss")
    candidates = [
        a for a in reg.values()
        if a.jwt_issuer and a.jwt_audience
        and a.jwt_issuer == iss and _aud_matches(peek.get("aud"), a.jwt_audience)
    ]
    if not candidates:
        return None, "no_matching_entry"
    # Prefer the candidate the token claims to be; entries sharing an issuer/
    # audience are disambiguated by the (verified, below) subject binding.
    entry = next((a for a in candidates if a.id == peek.get("sub")), candidates[0])
    key = _signing_key_for(jwt_mod, entry)
    if key is None:
        return None, "jwks_unavailable"
    cfg = oidc.OIDCConfig(
        enabled=True, issuer=entry.jwt_issuer, audience=entry.jwt_audience)
    try:
        principal = oidc.verify_oidc_token(token, config=cfg, signing_key=key)
    except oidc.OIDCError:
        return None, "jwt_invalid"
    # The subject IS the agent identity: exact equality (verify_oidc_token has
    # already applied validate_subject), so a token for agent A never
    # authenticates agent B.
    if principal.sub != entry.id:
        return None, "subject_mismatch"
    why = _active_inbound(entry)
    if why is not None:
        return None, why
    return entry, "ok"


# -- HMAC --------------------------------------------------------------------

def verify_agent_hmac(
    agent_id_header: str,
    body: bytes,
    timestamp: str,
    signature: str,
    *,
    registry: dict[str, TrustedAgent] | None = None,
) -> tuple[TrustedAgent | None, str]:
    """Authenticate a request signed in the Lightwork webhook HMAC format.

    The caller names itself in a header; the entry's ``hmac_secret_ref`` is
    resolved through the secret provider at verify time and the signature +
    freshness check is :func:`maverick.webhooks.verify_signature` (timestamp-
    bound, constant-time). Returns ``(agent, "ok")`` or ``(None, rule)``."""
    try:
        return _verify_agent_hmac(
            agent_id_header, body, timestamp, signature, registry=registry)
    except Exception:
        log.warning("external_identity: HMAC verification error (fail-closed)",
                    exc_info=True)
        return None, "verifier_error"


def _verify_agent_hmac(
    agent_id_header: str,
    body: bytes,
    timestamp: str,
    signature: str,
    *,
    registry: dict[str, TrustedAgent] | None,
) -> tuple[TrustedAgent | None, str]:
    agent_id = str(agent_id_header or "").strip()
    reg = load_registry() if registry is None else registry
    entry = reg.get(agent_id)
    if entry is None:
        return None, "unknown_agent"
    if not entry.hmac_secret_ref:
        return None, "hmac_not_configured"
    from .secret_provider import get_secret
    secret = get_secret(entry.hmac_secret_ref)
    if not secret:
        return None, "secret_unresolved"
    if not isinstance(body, bytes):
        return None, "bad_body"
    from .webhooks import verify_signature
    sig = str(signature or "")
    if not verify_signature(body, sig, secret,
                            timestamp=str(timestamp or ""),
                            max_age=HMAC_MAX_AGE_SECONDS):
        return None, "bad_signature"
    why = _active_inbound(entry)
    if why is not None:
        return None, why
    # Single-use, keyed by the SIGNATURE itself: it is deterministic over
    # (secret, timestamp, body), so a captured request replayed inside the
    # freshness window presents the identical signature and is refused. The
    # webhook receiver tolerates that ambiguity because a duplicate delivery
    # is harmless there; here the same bytes would re-drive a governed
    # endpoint, so an exact duplicate must not authenticate twice. A genuine
    # retry re-signs with a fresh timestamp.
    try:
        refusal = claim_once(
            agent_id, "hmac:" + hashlib.sha256(sig.encode("utf-8")).hexdigest(),
            expires_at=time.time() + HMAC_MAX_AGE_SECONDS * 2,
            now=time.time())
    except ReplayStoreError:
        log.warning("external_identity: replay ledger unavailable "
                    "(fail-closed)", exc_info=True)
        return None, "replay_store_unavailable"
    if refusal is not None:
        return None, refusal
    return entry, "ok"


# -- Ed25519 request envelope -------------------------------------------------

def envelope_message(agent_id: str, timestamp: str, nonce: str,
                     body: bytes) -> bytes:
    """Canonical signing input for the Ed25519 request scheme.

    ``<version>|<agent_id>|<ts>|<nonce>|`` + the hex SHA-256 of the raw body —
    every field an attacker could swap (identity, freshness, replay key,
    payload) is under the signature, and the version prefix domain-separates
    it from every other Lightwork signature format. Exported so clients build
    byte-identical material."""
    digest = hashlib.sha256(body).hexdigest()
    return (f"{ENVELOPE_MESSAGE_VERSION}|{agent_id}|{timestamp}|{nonce}|".encode()
            + digest.encode())


def verify_agent_envelope(
    agent_id_header: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    signature_hex: str,
    *,
    registry: dict[str, TrustedAgent] | None = None,
    now: float | None = None,
) -> tuple[TrustedAgent | None, str]:
    """Authenticate a detached Ed25519 request signature against the entry's
    pinned ``pubkey``.

    Signature first, then freshness (±60s skew, 300s max age), then the
    single-use nonce — remembered only after a fully-valid request, and
    fail-closed on both replay and cache saturation, mirroring
    :func:`maverick.handoff.verify_handoff`. Returns ``(agent, "ok")`` or
    ``(None, rule)``."""
    try:
        return _verify_agent_envelope(
            agent_id_header, body, timestamp, nonce, signature_hex,
            registry=registry, now=now)
    except Exception:
        log.warning("external_identity: envelope verification error "
                    "(fail-closed)", exc_info=True)
        return None, "verifier_error"


def _envelope_input_error(body: object, timestamp: object, nonce: object,
                          signature_hex: object) -> str | None:
    """Structural screen for the envelope inputs; the rule string, or ``None``."""
    if not isinstance(body, bytes):
        return "bad_body"
    if (not isinstance(nonce, str) or not nonce
            or len(nonce.encode("utf-8", "replace")) > _MAX_NONCE_BYTES):
        return "bad_nonce"
    if (not isinstance(timestamp, str) or not timestamp
            or len(timestamp) > _MAX_TIMESTAMP_CHARS):
        return "bad_timestamp"
    try:
        ts = float(timestamp)
    except ValueError:
        return "bad_timestamp"
    if not math.isfinite(ts):
        return "bad_timestamp"
    if not isinstance(signature_hex, str) or not signature_hex:
        return "bad_signature"
    return None


def _verify_agent_envelope(
    agent_id_header: str,
    body: bytes,
    timestamp: str,
    nonce: str,
    signature_hex: str,
    *,
    registry: dict[str, TrustedAgent] | None,
    now: float | None,
) -> tuple[TrustedAgent | None, str]:
    agent_id = str(agent_id_header or "").strip()
    reg = load_registry() if registry is None else registry
    entry = reg.get(agent_id)
    if entry is None:
        return None, "unknown_agent"
    if not entry.pubkey:
        return None, "no_pinned_key"
    input_error = _envelope_input_error(body, timestamp, nonce, signature_hex)
    if input_error is not None:
        return None, input_error
    ts = float(timestamp)
    from .audit import signing
    if not signing._have_crypto():
        return None, "no_crypto"  # "verified" is meaningless without crypto
    message = envelope_message(agent_id, timestamp, nonce, body)
    if not signing.verify_ed25519(entry.pubkey, signature_hex, message):
        return None, "bad_signature"
    current = time.time() if now is None else float(now)
    if ts > current + ENVELOPE_CLOCK_SKEW_SECONDS:
        return None, "future_ts"
    if current - ts > ENVELOPE_MAX_AGE_SECONDS:
        return None, "stale"
    why = _active_inbound(entry, now=current)
    if why is not None:
        return None, why
    # Claim the nonce only after a fully-valid request, durably so the claim
    # holds across dashboard workers. A ledger failure REFUSES: a request
    # whose single-use property cannot be proven must not authenticate.
    try:
        refusal = claim_once(
            agent_id, f"nonce:{nonce}",
            expires_at=ts + ENVELOPE_MAX_AGE_SECONDS
            + ENVELOPE_CLOCK_SKEW_SECONDS, now=current)
    except ReplayStoreError:
        log.warning("external_identity: replay ledger unavailable "
                    "(fail-closed)", exc_info=True)
        return None, "replay_store_unavailable"
    if refusal is not None:
        return None, refusal
    return entry, "ok"


__all__ = [
    "ENVELOPE_MESSAGE_VERSION",
    "ENVELOPE_MAX_AGE_SECONDS",
    "ENVELOPE_CLOCK_SKEW_SECONDS",
    "HMAC_MAX_AGE_SECONDS",
    "envelope_message",
    "verify_agent_jwt",
    "verify_agent_hmac",
    "verify_agent_envelope",
]
