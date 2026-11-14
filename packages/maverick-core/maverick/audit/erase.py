"""Audit-log erase coverage extension.

GDPR Art. 17 right-to-erasure already covers world-model state via
``maverick erase --channel X --user Y``. This module extends that to
the audit log: scrub or tombstone audit events tied to the same user
identity.

Two modes:

  - ``scrub_user(channel, user_id)``: rewrites matching lines to a
    tombstone form, preserving the row count and timestamps but
    removing identifying payload fields. Default behavior.
  - ``delete_user(channel, user_id)``: removes matching lines entirely.
    More aggressive; use when you need the audit log to look like the
    user never existed.

Both walk every `*.ndjson` file in ``~/.maverick/audit/``. They never
modify files mid-write — they write to a temp file and atomically
rename.

Matching: an event matches a user iff it carries STRUCTURED ``channel``
AND ``user_id`` fields both exactly equal to the args. Matching is on the
structured fields only -- never a substring of a serialized value --
because the old ``f"{channel}:{user_id}"`` substring test both
over-deleted (``slack:42`` matched ``slack:4200``) and under-deleted (a
``slack/42`` encoding was never matched). Exact field equality is the
only safe rule.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from ..file_lock import (
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)

log = logging.getLogger(__name__)


def _reset_live_signer(audit_dir: Path) -> None:
    """Drop the live signer's stale chain head after an in-place re-anchor.

    ``_process_file`` re-anchors the signed file on disk, but a long-lived
    ``AuditLog`` singleton still holds the pre-erase ``_last_hash`` in memory.
    Without this, the next same-process ``record()`` chains onto a hash no
    longer in the file -> ``chain_mismatch``. Best-effort + never fatal: an
    erase must complete even if there is no live signer to refresh.
    """
    try:
        from .writer import reset_signer_after_erase

        reset_signer_after_erase(audit_dir)
    # failure-policy: fail_soft_with_audit
    except Exception as e:  # pragma: no cover - defensive
        log.warning("audit erase: could not reset live signer: %s", e)


def _subject_digest(channel: str, user_id: str) -> str:
    """Return a short, non-reversible identifier for erase log messages."""
    return hashlib.sha256(f"{channel}:{user_id}".encode()).hexdigest()[:16]


def _event_matches(event: dict, channel: str, user_id: str) -> bool:
    # Structured-field equality only. A substring test over serialized values
    # both over- and under-matches (see module docstring), so we never fall
    # back to one -- an event with no structured channel/user_id simply does
    # not match.
    from ..privacy import audit_subject_matches

    return audit_subject_matches(event, channel, user_id)


def _tombstone(event: dict, channel: str, user_id: str) -> dict:
    """Replace identifying fields with [REDACTED]. Keep ts + kind."""
    keep = {"v", "ts", "kind", "schema_version"}
    out = {k: v for k, v in event.items() if k in keep}
    out["agent"] = "[REDACTED]"
    out["channel"] = channel  # keep so audit still reports who-was-scrubbed
    out["user_id"] = "[REDACTED]"
    out["erased_at"] = __import__("time").time()
    return out


def _scan_rows(
    original: str, channel: str, user_id: str,
) -> tuple[list[tuple[str, dict | None]], int, bool]:
    """Parse NDJSON lines into rows. Returns (rows, matched, any_signed)."""
    rows: list[tuple[str, dict | None]] = []
    matched = 0
    any_signed = False
    for raw in original.splitlines(keepends=True):
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            rows.append((raw, None))
            continue
        if not isinstance(event, dict):
            # A non-object line (``123``, ``[]``) carries no subject; keep it
            # verbatim like any other unparseable row.
            rows.append((raw, None))
            continue
        if event.get("sig") and event.get("hash") and event.get("key_id"):
            any_signed = True
        if _event_matches(event, channel, user_id):
            matched += 1
        rows.append((raw, event))
    return rows, matched, any_signed


def _verify_signed_chain(path: Path, rows: list[tuple[str, dict | None]]) -> bool:
    """Validate a signed chain before the authorized erase. False = abort."""
    try:
        from .signing import verify_chain

        breaks = verify_chain(path)
    # failure-policy: fail_closed
    except Exception as e:  # pragma: no cover - defensive/crypto missing
        log.warning("audit erase: could not verify %s before rewrite: %s", path, e)
        return False
    if breaks:
        log.warning(
            "audit erase: refusing to rewrite %s; signed chain is not clean (%s)",
            path,
            breaks[0],
        )
        return False
    return True


def _build_parts(
    rows: list[tuple[str, dict | None]],
    channel: str,
    user_id: str,
    *,
    delete: bool,
) -> tuple[list[str], int]:
    """Rebuild NDJSON, tombstoning or dropping matches. Returns (parts, written)."""
    parts: list[str] = []
    written = 0
    for raw, event in rows:
        if event is None:
            parts.append(raw)
            written += 1
            continue
        if not _event_matches(event, channel, user_id):
            parts.append(raw)
            written += 1
            continue
        if delete:
            continue
        parts.append(json.dumps(_tombstone(event, channel, user_id), default=str) + "\n")
        written += 1
    return parts, written


def _process_file(
    path: Path,
    channel: str,
    user_id: str,
    *,
    delete: bool,
    strict: bool = False,
) -> tuple[int, int]:
    """Walk a single audit-log file. Returns (matched, written)."""
    if not path.exists() or path.is_dir():
        return 0, 0
    # An erase is a read-modify-write of the whole file. Held without a lock it
    # races the live signer appending to today's day-file: rows committed
    # between our read and our atomic replace are silently destroyed, and the
    # re-anchor below then re-signs the truncated result so verify_chain
    # reports CLEAN. Measured at 3-4 lost rows per run under a modest concurrent
    # writer. This is the same sidecar-keyed lock AuditSigner.write takes, and
    # it must cover the re-anchor too -- that is a second whole-file rewrite.
    with cross_process_lock(path):
        return _process_file_locked(
            path,
            channel,
            user_id,
            delete=delete,
            strict=strict,
        )


def _process_file_locked(
    path: Path,
    channel: str,
    user_id: str,
    *,
    delete: bool,
    strict: bool = False,
) -> tuple[int, int]:
    """``_process_file`` body, with the file's rewrite lock already held."""
    try:
        ensure_private_directory(path.parent)
        ensure_private_file(path, 0o600)
        raw = atomic_read_bytes(path)
    except OSError as e:
        log.warning("audit erase: %s: %s", path, e)
        if strict:
            raise
        return 0, 0
    # A closed day-file may be at-rest *sealed*. Read its NDJSON via the
    # transparent decryptor (reading raw bytes as UTF-8 would crash on the
    # ciphertext), and remember the sealed state so the rewrite below preserves
    # it instead of silently unsealing a confidential segment to plaintext.
    from ..crypto_at_rest import is_sealed
    from .sealing import segment_text
    was_sealed = is_sealed(raw)
    # fail_soft=False: an authorized Art.17 erasure must FAIL CLOSED on a sealed
    # segment it can't decrypt (rotated/absent key, corruption). The default
    # fail-soft returns "" -> matched=0 -> we'd report a clean erase while the
    # subject's events remain intact inside the still-sealed file. Raising lets
    # the CLI surface the failure so the operator re-runs after fixing the key.
    original = segment_text(path, fail_soft=False)

    rows, matched, any_signed = _scan_rows(original, channel, user_id)

    if matched == 0:
        return 0, len(rows)

    # If this is a signed audit file, validate it before making the authorized
    # erase mutation. Re-anchoring after the rewrite may only bless changes we
    # just made to a previously clean chain, never unrelated old tampering.
    if any_signed and not _verify_signed_chain(path, rows):
        if strict:
            raise RuntimeError(
                "signed audit chain failed pre-erasure integrity verification"
            )
        return 0, len(rows)

    parts, written = _build_parts(rows, channel, user_id, delete=delete)

    # Re-seal the rewritten NDJSON when the source segment was sealed, so an
    # authorized erase scrubs the data without exposing the rest of a
    # confidential day-file as plaintext on disk.
    from .sealing import encode_segment
    new_bytes = encode_segment("".join(parts), sealed=was_sealed)

    try:
        atomic_write_bytes(path, new_bytes, mode=0o600)
        if any_signed:
            try:
                from .signing import reanchor_day_after_erase, reanchor_file

                reanchor_file(path, force=True, preverified=True)
                # The rewrite changed the file's tip hash -> append a fresh
                # superseding tip-ledger anchor so verify_anchors matches the
                # new state (the prior anchor stays, recording the change).
                reanchor_day_after_erase(path.parent, path)
            # failure-policy: fail_soft_with_audit
            except Exception as e:  # pragma: no cover - defensive/crypto missing
                log.warning("audit erase: could not reanchor %s after rewrite: %s", path, e)
                if strict:
                    raise
    except OSError as e:
        log.warning("audit erase: %s: %s", path, e)
        if strict:
            raise
        return 0, 0
    return matched, written


def scrub_user(
    channel: str,
    user_id: str,
    *,
    audit_dir: Path | None = None,
    strict: bool = False,
) -> tuple[int, int]:
    """Replace matching events with tombstones. Returns (matched, scanned).

    ``strict=True`` is reserved for the legal-erasure workflow: unreadable,
    unwritable, integrity-invalid, or unreanchorable segments raise instead of
    being indistinguishable from an observed zero.
    """
    if audit_dir is None:
        # Resolve the SAME (home + active-tenant) audit dir the writer lands
        # events in. A frozen ~/.maverick/audit default would silently skip
        # scrubbing whenever MAVERICK_HOME or a tenant scopes the real dir
        # elsewhere -- an Art. 17 erasure that reports success but scrubs
        # nothing.
        from ..paths import data_dir
        audit_dir = data_dir("audit")
    total_matched = 0
    total_scanned = 0
    if not audit_dir.exists():
        return 0, 0
    for path in sorted(audit_dir.glob("*.ndjson")):
        m, w = _process_file(
            path,
            channel,
            user_id,
            delete=False,
            strict=strict,
        )
        total_matched += m
        total_scanned += w
    if total_matched:
        _reset_live_signer(audit_dir)
    log.info(
        "audit erase (scrub): subject_hash=%s matched=%d scanned=%d",
        _subject_digest(channel, user_id),
        total_matched,
        total_scanned,
    )
    return total_matched, total_scanned


def delete_user(
    channel: str,
    user_id: str,
    *,
    audit_dir: Path | None = None,
) -> tuple[int, int]:
    """Delete matching events entirely. Returns (deleted, scanned)."""
    if audit_dir is None:
        from ..paths import data_dir
        audit_dir = data_dir("audit")
    total_matched = 0
    total_scanned = 0
    if not audit_dir.exists():
        return 0, 0
    for path in sorted(audit_dir.glob("*.ndjson")):
        m, w = _process_file(path, channel, user_id, delete=True)
        total_matched += m
        total_scanned += w
    if total_matched:
        _reset_live_signer(audit_dir)
    log.info(
        "audit erase (delete): subject_hash=%s matched=%d scanned=%d",
        _subject_digest(channel, user_id),
        total_matched,
        total_scanned,
    )
    return total_matched, total_scanned


__all__ = ["scrub_user", "delete_user"]
