"""Partner fleet registry — the client deployments a partner operates.

A partner (an advisory firm running Lightwork agents for its clients) tracks
each client deployment here: name, base URL, an optional bearer token, and
the white-label theme it runs. Probe results (health, latency, version, the
agent's own counted value ledger) are stored alongside so the console shows
live fleet state without a background poller.

The complete registry is tenant-envelope encrypted on disk under the
tenant-aware data dir; atomic writes run under a process lock.  A legacy
``tenants.json`` file is migrated once and removed only after the sealed write
succeeds.  Tokens are opened only for an authenticated server-side probe and
the API never echoes them back out.
"""
from __future__ import annotations

import contextlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from maverick.file_lock import (
    atomic_read_bytes,
    atomic_read_text,
    cross_process_lock,
    ensure_private_file,
)
from maverick.paths import data_dir
from maverick.tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

_LOCK = threading.Lock()


def _path() -> Path:
    return data_dir("partner") / "tenants.sealed"


def _legacy_path() -> Path:
    return data_dir("partner") / "tenants.json"


def _legacy_quarantine_path() -> Path:
    """Fixed name for a migrated plaintext generation awaiting deletion."""
    return data_dir("partner") / "tenants.json.migrated-plaintext"


class PartnerStoreUnavailable(RuntimeError):
    """Partner credential custody could not be read or written safely."""


class PartnerEndpointRejected(ValueError):
    """A partner endpoint was refused by the platform SSRF policy."""


def _admit_base_url(
    base_url: str, *, trusted_test_estate_loopback: bool = False
) -> str:
    """Validate a partner endpoint before it can enter the fleet registry.

    Normal partner endpoints must resolve entirely to public addresses.  The
    explicit test-estate exception delegates to the narrower scoped policy in
    :mod:`maverick.tools._ssrf`: it admits only an exact loopback IP literal,
    never a hostname, RFC1918/link-local address, or DNS answer that can drift
    away from the literal.
    """
    from maverick.tools import _ssrf

    candidate = str(base_url or "").strip()
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname or ""
        # Accessing .port performs urllib's numeric/range validation.
        _ = parsed.port
    except ValueError as exc:
        raise PartnerEndpointRejected("partner base URL is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not host:
        raise PartnerEndpointRejected("partner base URL must be HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise PartnerEndpointRejected("partner base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise PartnerEndpointRejected(
            "partner base URL must not contain a query string or fragment"
        )

    try:
        if trusted_test_estate_loopback:
            with _ssrf.allow_private_hosts([host]):
                _ssrf.resolve_pinned_ip(host)
        else:
            _ssrf.resolve_pinned_ip(host)
    except (_ssrf.BlockedHost, ValueError) as exc:
        raise PartnerEndpointRejected(
            "partner base URL is not admitted by the platform SSRF policy"
        ) from exc
    return candidate.rstrip("/")


def _parse_rows(text: str) -> list[dict]:
    rows = json.loads(text)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("partner registry root must be a list of records")
    return rows


@contextlib.contextmanager
def _transaction() -> Iterator[None]:
    """Serialize one registry read/migrate/mutate/write across every worker."""
    try:
        with _LOCK, cross_process_lock(_path(), strict=True):
            yield
    except PartnerStoreUnavailable:
        raise
    except Exception as exc:
        raise PartnerStoreUnavailable(
            "partner credential registry transaction failed; no records were changed"
        ) from exc


def _read_sealed() -> list[dict]:
    """Open the authoritative authenticated generation or fail closed."""
    from maverick.paths import current_tenant_id

    p = _path()
    try:
        ensure_private_file(p)
        plaintext = unseal_text_for_tenant(current_tenant_id(), atomic_read_bytes(p))
        return _parse_rows(plaintext)
    except PartnerStoreUnavailable:
        raise
    except Exception as exc:
        # Once a sealed generation exists, a plaintext predecessor is never a
        # recovery source: doing so would let stale/tampered data defeat AEAD.
        raise PartnerStoreUnavailable(
            "partner credential registry ciphertext is unavailable or invalid"
        ) from exc


def _remove_plaintext_residual(path: Path, *, quarantine: bool) -> None:
    """Remove one private plaintext residue, quarantining a legacy source once."""
    if not path.exists():
        return
    try:
        ensure_private_file(path)
        path.unlink()
        return
    except FileNotFoundError:
        return
    except Exception as unlink_exc:
        if not quarantine:
            raise PartnerStoreUnavailable(
                "migrated partner plaintext remains quarantined; cleanup will be retried"
            ) from unlink_exc

    pending = _legacy_quarantine_path()
    try:
        # The fixed quarantine name makes the authoritative generation
        # unambiguous.  It remains owner-only and is retried on every access.
        if pending.exists():
            _remove_plaintext_residual(pending, quarantine=False)
        path.replace(pending)
        ensure_private_file(pending)
    except Exception as quarantine_exc:
        raise PartnerStoreUnavailable(
            "legacy partner plaintext could not be removed or quarantined"
        ) from quarantine_exc
    try:
        pending.unlink()
    except FileNotFoundError:
        return
    except Exception as cleanup_exc:
        raise PartnerStoreUnavailable(
            "migrated partner plaintext remains quarantined; cleanup will be retried"
        ) from cleanup_exc


def _cleanup_plaintext_residuals() -> None:
    """Delete every known plaintext predecessor after sealed verification."""
    _remove_plaintext_residual(_legacy_quarantine_path(), quarantine=False)
    _remove_plaintext_residual(_legacy_path(), quarantine=True)


def _read() -> list[dict]:
    p = _path()
    legacy = _legacy_path()
    pending = _legacy_quarantine_path()
    if p.exists():
        rows = _read_sealed()
        _cleanup_plaintext_residuals()
        return rows
    if pending.exists():
        # This state cannot be produced by the ordered migration below: sealed
        # publication always precedes quarantine.  Never resurrect an orphaned
        # plaintext generation whose authenticated successor is missing.
        raise PartnerStoreUnavailable(
            "quarantined partner plaintext exists without its sealed generation"
        )
    if not legacy.exists():
        return []

    try:
        ensure_private_file(legacy)
        rows = _parse_rows(atomic_read_text(legacy, encoding="utf-8"))
    except Exception as exc:
        raise PartnerStoreUnavailable(
            "legacy partner credential registry is unavailable or invalid"
        ) from exc

    # Ordered, restart-safe migration: publish ciphertext, reopen/authenticate
    # it, then remove plaintext. A crash at either boundary is retried safely.
    _write(rows)
    verified = _read_sealed()
    if verified != rows:
        raise PartnerStoreUnavailable(
            "partner credential migration verification did not match its source"
        )
    _cleanup_plaintext_residuals()
    return verified


def _write(rows: list[dict]) -> None:
    # Rows carry per-tenant bearer tokens: seal the ENTIRE JSON document so
    # names/URLs/notes and credentials share one authenticated generation.
    from maverick.file_lock import atomic_write_bytes, ensure_private_directory
    from maverick.paths import current_tenant_id

    p = _path()
    ensure_private_directory(p.parent)
    try:
        blob = seal_text_for_tenant(
            current_tenant_id(), json.dumps(rows, separators=(",", ":"))
        )
        atomic_write_bytes(p, blob, mode=0o600)
    except Exception as exc:
        raise PartnerStoreUnavailable(
            "partner credential registry could not be sealed; no plaintext was written"
        ) from exc


def list_tenants() -> list[dict]:
    with _transaction():
        return _read()


def upsert_tenant(
    *,
    name: str,
    base_url: str,
    token: str = "",
    theme: str = "",
    notes: str = "",
    tenant_id: str = "",
    trusted_test_estate_loopback: bool = False,
) -> dict:
    admitted_base_url = _admit_base_url(
        base_url,
        trusted_test_estate_loopback=trusted_test_estate_loopback,
    )
    with _transaction():
        rows = _read()
        row = next((r for r in rows if r["id"] == tenant_id), None)
        if row is None:
            row = {"id": uuid.uuid4().hex[:10],
                   "created_at": time.time(), "last_check": None}
            rows.append(row)
        row.update(
            {
                "name": name.strip(),
                "base_url": admitted_base_url,
                "token": token,
                "theme": theme.strip(),
                "notes": notes.strip(),
                "trusted_test_estate_loopback": bool(
                    trusted_test_estate_loopback
                ),
            }
        )
        _write(rows)
        return row


def delete_tenant(tenant_id: str) -> bool:
    with _transaction():
        rows = _read()
        kept = [r for r in rows if r["id"] != tenant_id]
        if len(kept) == len(rows):
            return False
        _write(kept)
        return True


def record_check(tenant_id: str, result: dict) -> None:
    with _transaction():
        rows = _read()
        for r in rows:
            if r["id"] == tenant_id:
                r["last_check"] = result
                _write(rows)
                return


def public_row(row: dict) -> dict:
    """The API view: everything except the bearer token."""
    out = {k: v for k, v in row.items() if k != "token"}
    out["has_token"] = bool(row.get("token"))
    return out


__all__ = [
    "PartnerEndpointRejected",
    "PartnerStoreUnavailable",
    "delete_tenant",
    "list_tenants",
    "public_row",
    "record_check",
    "upsert_tenant",
]
