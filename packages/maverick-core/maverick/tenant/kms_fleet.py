"""Operable, resumable fleet KEK rotation.

``kms.rotate_kek_fleet`` is the library primitive; this is the operations layer
behind ``maverick tenant kms-rotate``. It rotates every provisioned tenant's
wrapped DEK from one local KEK to another (the common fleet event: the at-rest
master key / ``MAVERICK_KMS_KEK`` is being rolled), with the properties a
fleet-scale operation needs:

* **Idempotent / resumable.** A tenant whose DEK already unwraps under the new
  KEK is skipped, so a rotation interrupted partway (signal, throttle, crash)
  finishes the rest on a plain re-run -- the on-disk wrapped DEK *is* the
  progress state; no separate manifest to drift.
* **Isolated failures.** One tenant's failure is recorded and never aborts the
  fleet; the report's ``failed`` map is the "do NOT retire the old KEK yet"
  signal.
* **Dry-run.** Probe what each tenant *would* do (rotate / skip / fail) without
  writing, so an operator can preview before committing.

Re-wrap only: no tenant data is re-encrypted (the DEK is unchanged), so the
operation is O(tenants), not O(data).

Cloud/BYOK rotation (each tenant under its own AWS/GCP/Vault/Azure key) uses the
library ``kms.rotate_kek_fleet`` with custom per-tenant resolvers instead.
"""
from __future__ import annotations

from ..crypto_at_rest import EncryptionUnavailable, _decode_injected_key
from . import kms as _kms

_DEK_BYTES = 32


def _local_kms(raw_kek: str) -> _kms.LocalKMS:
    """Build a LocalKMS from a hex/base64 32-byte KEK (same decoder as
    ``MAVERICK_KMS_KEK``)."""
    key = _decode_injected_key(raw_kek)
    if len(key) != _DEK_BYTES:
        raise EncryptionUnavailable(
            f"KEK must decode to {_DEK_BYTES} bytes, got {len(key)}")
    return _kms.LocalKMS(key)


def _tenants_with_dek() -> list[str]:
    from .registry import list_tenants
    return [rec.id for rec in list_tenants()
            if _kms._wrapped_dek_path(rec.id).exists()]


def _would_do(tenant_id: str, old_kms, new_kms) -> str:
    """Dry-run probe: what rotate_kek_idempotent WOULD return for this tenant,
    without writing. ``rotated`` | ``skipped`` | ``error: ...``."""
    path = _kms._wrapped_dek_path(tenant_id)
    context = _kms._tenant_context(tenant_id, b"dek-wrap")
    wrapped = path.read_bytes()
    try:
        if len(new_kms.unwrap(wrapped, context=context)) == _DEK_BYTES:
            return "skipped"
    except Exception:
        pass
    try:
        if len(old_kms.unwrap(wrapped, context=context)) == _DEK_BYTES:
            return "rotated"
        return "error: unwrapped DEK is malformed"
    except Exception as e:
        return f"error: {e}"


def rotate_local_fleet(old_kek: str, new_kek: str, *, dry_run: bool = False) -> dict:
    """Rotate every provisioned tenant's wrapped DEK from ``LocalKMS(old_kek)``
    to ``LocalKMS(new_kek)``. Idempotent/resumable and failure-isolated.

    Returns ``{"total", "rotated":[ids], "skipped":[ids], "failed":{id: reason},
    "dry_run": bool}``. ``rotated``/``skipped`` are *projections* under dry-run.
    """
    old_kms = _local_kms(old_kek)
    new_kms = _local_kms(new_kek)
    rotated: list[str] = []
    skipped: list[str] = []
    failed: dict[str, str] = {}

    for tid in _tenants_with_dek():
        try:
            if dry_run:
                outcome = _would_do(tid, old_kms, new_kms)
            else:
                outcome = _kms.rotate_kek_idempotent(
                    tid, old_kms=old_kms, new_kms=new_kms)
        except Exception as e:  # pragma: no cover -- defensive; per-tenant isolate
            outcome = f"error: {e}"
        if outcome == "rotated":
            rotated.append(tid)
        elif outcome == "skipped":
            skipped.append(tid)
        else:
            failed[tid] = outcome.removeprefix("error: ")

    return {
        "total": len(rotated) + len(skipped) + len(failed),
        "rotated": rotated,
        "skipped": skipped,
        "failed": failed,
        "dry_run": dry_run,
    }


__all__ = ["rotate_local_fleet"]
