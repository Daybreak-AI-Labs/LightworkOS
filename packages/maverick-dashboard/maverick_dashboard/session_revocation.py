"""Per-principal session/bearer revocation epoch.

A leaked ``mvk_session`` cookie or a still-valid OIDC bearer is otherwise good
until its natural expiry (<=12h), with no way for an admin to force-invalidate
it -- and a SCIM-deprovisioned user keeps a live dashboard session. This keeps a
per-principal **revocation epoch** (a UTC timestamp): any credential whose
issued-at (``iat``) predates a principal's epoch is rejected. Bumping the epoch
-- "log out everywhere" or a SCIM deprovision -- invalidates every credential
that principal holds at once, across processes.

Store: ``<maverick_home>/session-revocations.json`` (0600 via atomic_write_text),
mirroring the rbac roster's load-modify-save under a cross-process lock.
"""
from __future__ import annotations

import json
import math
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import maverick_home

_LOCK = threading.Lock()


class RevocationStoreError(RuntimeError):
    """The revocation store exists but can't be read/parsed. Callers fail
    CLOSED (treat credentials as revoked) rather than silently un-revoking the
    whole population by reading a damaged store as 'nothing revoked'."""


def _path() -> Path:
    return maverick_home() / "session-revocations.json"


@contextmanager
def _locked():
    from maverick.authority_effects import authority_effect_fence

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(_path()))
        yield


def _load() -> dict:
    """The epoch map. A genuinely-absent store is empty (no revocations yet);
    a store that EXISTS but is unreadable/corrupt raises ``RevocationStoreError``
    so the revocation check fails closed instead of fail-open."""
    ensure_private_directory(maverick_home())
    try:
        ensure_private_file(_path())
        raw = atomic_read_text(_path())
    except FileNotFoundError:
        return {}
    except OSError as e:  # EIO / EACCES / ENFILE ... -- present but unreadable
        raise RevocationStoreError(f"revocation store unreadable: {e}") from e
    def _reject_constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        data: dict[str, object] = {}
        for key, value in pairs:
            if key in data:
                raise ValueError(f"duplicate principal {key!r}")
            data[key] = value
        return data

    try:
        data = json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object)
    except (TypeError, ValueError) as e:  # corrupt JSON
        raise RevocationStoreError(f"revocation store corrupt: {e}") from e
    if not isinstance(data, dict):
        raise RevocationStoreError(
            "revocation store corrupt: top-level value must be an object"
        )
    validated: dict[str, float] = {}
    for principal, epoch in data.items():
        if not principal or principal != principal.strip() or len(principal) > 1024:
            raise RevocationStoreError("revocation store corrupt: invalid principal")
        if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
            raise RevocationStoreError(
                f"revocation store corrupt: epoch for {principal!r} must be numeric"
            )
        value = float(epoch)
        if not math.isfinite(value) or value <= 0:
            raise RevocationStoreError(
                f"revocation store corrupt: epoch for {principal!r} must be finite and positive"
            )
        validated[principal] = value
    return validated


def revoke_principal(principal: str, *, at: float | None = None) -> None:
    """Invalidate every credential issued to ``principal`` before now.

    Monotonic: an epoch never moves backwards, so a stale concurrent write can't
    un-revoke. A blank principal is a no-op."""
    p = (principal or "").strip()
    if not p:
        return
    try:
        ts = time.time() if at is None else float(at)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("revocation epoch must be a finite positive number") from exc
    if not math.isfinite(ts) or ts <= 0:
        raise ValueError("revocation epoch must be a finite positive number")
    with _locked():
        data = _load()
        data[p] = max(float(data.get(p, 0.0) or 0.0), ts)
        atomic_write_text(_path(), json.dumps(data, indent=2, sort_keys=True))


def revocation_epoch(principal: str) -> float:
    """The earliest issued-at a credential for ``principal`` may carry; 0 = never
    revoked."""
    return float(_load().get((principal or "").strip(), 0.0) or 0.0)


def is_revoked(principal: str, issued_at: float | None) -> bool:
    """True when a credential's ``issued_at`` predates the principal's revocation
    epoch. A credential carrying no ``iat`` under an active epoch is treated as
    revoked -- it can't prove it post-dates the revocation. A damaged store also
    fails CLOSED (revoked): never silently accept a credential because the
    revocation record couldn't be read."""
    try:
        floor = revocation_epoch(principal)
    except RevocationStoreError:
        return True
    if floor <= 0:
        return False
    if issued_at is None:
        return True
    try:
        issued = float(issued_at)
        return not math.isfinite(issued) or issued < floor
    except (OverflowError, TypeError, ValueError):
        return True


__all__ = ["RevocationStoreError", "revoke_principal", "revocation_epoch", "is_revoked"]
