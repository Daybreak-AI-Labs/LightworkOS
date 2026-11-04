"""Per-tenant OAuth token vault — refresh tokens sealed at rest.

The OAuth helper (:mod:`maverick.tools.oauth_helper`) can capture access/refresh
tokens, but only ever wrote them to a plaintext ``MAVERICK_OAUTH_OUT`` file —
fine for a one-off capture, wrong for a hosted multi-tenant deployment where one
tenant's long-lived refresh token must never sit in cleartext or be readable
across tenants.

This vault stores each provider's token record **sealed under the tenant's own
DEK** (``tenant.kms.seal_text_for_tenant`` — AES-256-GCM envelope, one data key
per tenant) in a tenant-scoped ``oauth/tokens.sealed``. So a token at rest is
encrypted, and a wrapped DEK from one tenant can't open another's vault (the
KMS binds tenant id + purpose into the AEAD context).

It deliberately performs **no network**: refreshing an expired token is done by a
caller-supplied ``refresher`` callable (the OAuth helper already speaks the
token endpoint), and the vault just persists the rotated record. Opt-in and
offline-testable; fails closed if the ``cryptography`` extra is missing rather
than silently degrading to plaintext.
"""
from __future__ import annotations

import json
import math
import time
from collections.abc import Callable

from .file_lock import atomic_read_bytes, atomic_write_bytes, cross_process_lock
from .paths import data_dir
from .tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

# Default clock skew (seconds) treated as "already expired" so a token isn't
# handed out moments before the provider rejects it.
_DEFAULT_SKEW = 60

class OAuthRefreshError(RuntimeError):
    """Authorization must be replaced after an unconfirmed token rotation."""


def _validated_token(record: dict) -> dict:
    if not isinstance(record, dict) or "error" in record:
        raise ValueError("invalid OAuth token response")
    result = dict(record)
    for name in ("access_token", "refresh_token", "token_type"):
        value = result.get(name)
        if name == "access_token" or name in result:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("invalid OAuth token metadata")
    if "scope" in result and not isinstance(result["scope"], str):
        raise ValueError("invalid OAuth scope")
    for name in ("expires_at", "expires_in", "obtained_at"):
        if name not in result:
            continue
        value = result[name]
        if isinstance(value, bool):
            raise ValueError("invalid OAuth expiry")
        try:
            number = float(value)
        except (ValueError, TypeError, OverflowError):
            raise ValueError("invalid OAuth expiry") from None
        if not math.isfinite(number) or number <= 0:
            raise ValueError("invalid OAuth expiry")
        result[name] = number
    result.setdefault("obtained_at", time.time())
    if ("expires_in" in result
            and not math.isfinite(result["obtained_at"] + result["expires_in"])):
        raise ValueError("invalid OAuth expiry")
    result.pop("refresh_state", None)
    result.pop("refresh_attempted_at", None)
    return result


def _expires_at_from(record: dict) -> float | None:
    """Absolute expiry epoch for a record. Honors an explicit ``expires_at``;
    otherwise derives it from ``expires_in`` + ``obtained_at`` (or now)."""
    if record.get("expires_at") is not None:
        try:
            return float(record["expires_at"])
        except (TypeError, ValueError):
            return None
    if record.get("expires_in") is not None:
        try:
            base = float(record.get("obtained_at", time.time()))
            return base + float(record["expires_in"])
        except (TypeError, ValueError):
            return None
    return None


def is_expired(record: dict, *, skew: int = _DEFAULT_SKEW, now: float | None = None) -> bool:
    """Whether ``record``'s access token is expired (or within ``skew`` of it).
    A record with no expiry information is treated as NOT expired."""
    exp = _expires_at_from(record)
    if exp is None:
        return False
    return (now if now is not None else time.time()) >= (exp - skew)


class OAuthVault:
    """Sealed, per-tenant store of OAuth token records keyed by provider.

    One sealed JSON blob per tenant maps ``provider -> record``; a record is the
    provider's token response (``access_token``, ``refresh_token``,
    ``expires_in``/``expires_at``, ``scope``, ...), plus a normalized
    ``obtained_at``. ``tenant_id`` defaults to the active tenant.
    """

    def __init__(self, tenant_id: str | None = "__active__") -> None:
        self._tenant_id = tenant_id

    # -- storage ------------------------------------------------------------
    def _path(self):
        if self._tenant_id == "__active__":
            return data_dir("oauth", "tokens.sealed")
        return data_dir("oauth", "tokens.sealed", tenant=self._tenant_id)

    def _seal_tenant(self) -> str | None:
        # seal_text_for_tenant takes the RAW tenant id: it path-encodes it itself
        # (_kms_config_for -> _tenant_segment) to find the tenant's [kms] overlay
        # and binds it into the AEAD context. Passing the already path-encoded
        # current_tenant() double-encodes -- so a non-slug tenant misses its own
        # BYOK [kms] key (silently sealing under the default DEK) and seals under
        # a different AEAD context than every other tenant-KMS caller. Use the
        # raw id, like current_tenant_id()'s "natural tenant keys" contract.
        if self._tenant_id == "__active__":
            from .paths import current_tenant_id
            return current_tenant_id()
        return self._tenant_id

    def _load(self) -> dict[str, dict]:
        path = self._path()
        if not path.exists():
            return {}
        try:
            raw = unseal_text_for_tenant(self._seal_tenant(), atomic_read_bytes(path))
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}

    def _save(self, data: dict[str, dict]) -> None:
        path = self._path()
        blob = seal_text_for_tenant(self._seal_tenant(), json.dumps(data, sort_keys=True))
        # Unique private temporary file, fsync and atomic publication. The
        # caller owns the stable sidecar lock for its entire read/modify/write.
        atomic_write_bytes(path, blob)

    def _locked(self):
        # This fence also spans provider refresh: after waiting, another
        # process MUST reread the rotated credential (or uncertainty hold).
        return cross_process_lock(self._path(), strict=True)

    # -- public surface -----------------------------------------------------
    def put(self, provider: str, record: dict) -> None:
        """Store/overwrite ``provider``'s token record (sealed). Stamps
        ``obtained_at`` if absent so relative ``expires_in`` stays meaningful."""
        if not provider:
            raise ValueError("provider is required")
        rec = _validated_token(record)
        with self._locked():
            data = self._load()
            data[provider] = rec
            self._save(data)

    def get(self, provider: str) -> dict | None:
        """The stored record for ``provider`` (decrypted), or ``None``."""
        with self._locked():
            return self._load().get(provider)

    def delete(self, provider: str) -> bool:
        """Remove ``provider``'s record. Returns whether one was present."""
        with self._locked():
            data = self._load()
            existed = provider in data
            if existed:
                del data[provider]
                self._save(data)
            return existed

    def providers(self) -> list[str]:
        """Providers with a stored record (sorted)."""
        with self._locked():
            return sorted(self._load())

    def status(self, provider: str, *, now: float | None = None) -> dict | None:
        """A **token-free** health summary for ``provider`` -- safe to return to
        a dashboard. ``None`` when nothing is stored. Never includes the access
        or refresh token itself, only metadata: whether it's expired, its
        absolute expiry, granted scopes, whether a refresh token is on file, and
        when it was obtained."""
        with self._locked():
            record = self._load().get(provider)
        if record is None:
            return None
        return {
            "provider": provider,
            "expired": is_expired(record, now=now),
            "expires_at": _expires_at_from(record),
            "scope": record.get("scope"),
            "has_refresh_token": bool(record.get("refresh_token")),
            "obtained_at": record.get("obtained_at"),
            "reconnect_required": bool(record.get("refresh_state")),
            "refresh_state": record.get("refresh_state", "ready"),
        }

    def access_token(
        self, provider: str, *,
        refresher: Callable[[dict], dict] | None = None,
        skew: int = _DEFAULT_SKEW,
    ) -> str | None:
        """A usable access token for ``provider``.

        If the stored token is still valid, return it. If it's expired (within
        ``skew``) and a ``refresher`` is supplied, call ``refresher(record)``,
        which must return the new token response; the rotated record is sealed
        back to the vault (preserving the existing ``refresh_token`` when the
        provider's response omits it, per the OAuth spec) and its access token
        returned. Returns ``None`` if there is no record, or it's expired and no
        refresher was given."""
        with self._locked():
            data = self._load()
            record = data.get(provider)
            if record is None:
                return None
            if record.get("refresh_state"):
                raise OAuthRefreshError("OAuth refresh outcome is unconfirmed; reconnect this provider.")
            try:
                _validated_token(record)
            except ValueError:
                data[provider] = {**record, "refresh_state": "reconnect_required"}
                self._save(data)
                raise OAuthRefreshError("Stored OAuth authorization is invalid; reconnect this provider.") from None
            if not is_expired(record, skew=skew):
                return record.get("access_token")
            if refresher is None:
                return None
            # A refresh may rotate its credential even if the response is lost
            # or malformed. Persist the hold before dispatch; a process crash
            # cannot turn an uncertain rotation into an automatic second call.
            data[provider] = {**record, "refresh_state": "refresh_in_progress",
                              "refresh_attempted_at": time.time()}
            self._save(data)
            try:
                fresh = _validated_token(refresher(dict(record)))
            except Exception:
                data[provider]["refresh_state"] = "reconnect_required"
                self._save(data)
                raise OAuthRefreshError("OAuth refresh did not confirm usable authorization; reconnect this provider.") from None
            # Providers may omit the refresh token on refresh — keep the old one.
            if "refresh_token" not in fresh and record.get("refresh_token"):
                fresh["refresh_token"] = record["refresh_token"]
            fresh.setdefault("obtained_at", time.time())
            data[provider] = fresh
            self._save(data)
            return fresh.get("access_token")


def enabled() -> bool:
    """Whether the sealed OAuth vault is the active token sink. Off by default;
    ``[oauth] vault`` / ``MAVERICK_OAUTH_VAULT`` turns it on. Never raises."""
    from .config import env_flag
    v = env_flag("MAVERICK_OAUTH_VAULT")
    if v is not None:
        return v
    try:
        from .config import load_config
        return bool((load_config() or {}).get("oauth", {}).get("vault", False))
    except Exception:  # pragma: no cover -- config must never block
        return False


def get_vault(tenant_id: str | None = "__active__") -> OAuthVault:
    """An :class:`OAuthVault` for the given (default: active) tenant."""
    return OAuthVault(tenant_id)


__all__: list[str] = [
    "OAuthVault", "is_expired", "enabled", "get_vault",
]
