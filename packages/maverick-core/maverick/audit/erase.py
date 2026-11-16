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
import io
import json
import logging
import os
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
    # Split exactly as ``verify_chain`` does (on "\n" only), so a row here is
    # the same row the verifier sees: ``splitlines`` would also split on "\r",
    # "\x85" or "\u2028" and disagree with it.
    for raw in io.StringIO(original):
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
        if _arrived_signed(event):
            any_signed = True
        if _event_matches(event, channel, user_id):
            matched += 1
        rows.append((raw, event))
    return rows, matched, any_signed


def _arrived_signed(event: dict | None) -> bool:
    """Whether a row carries its own signature fields; only these are re-signed."""
    return bool(event and event.get("sig") and event.get("hash") and event.get("key_id"))


_RESTORE_DAY = "Restore the day from a backup (`maverick backup restore`)"
_DAY_ANCHOR_BREAKS = frozenset({
    "anchor_tip_mismatch", "anchor_count_mismatch", "anchored_file_deleted", "unreadable_segment",
})


def _chain_problem(path: Path) -> str | None:
    """Operator text for a signed-chain break in ``path``, or None.

    Rows written with signing off (``unsigned``: no hash, sig or key_id) are
    accepted wherever they are: they were never in the chain and the erase
    keeps them out of it. Any other break refuses: erase re-signs only rows
    that verified, never repairs.
    """
    try:
        from .signing import verify_chain

        breaks = [b for b in verify_chain(path) if b.reason != "unsigned"]
    # failure-policy: fail_closed
    except Exception as e:  # pragma: no cover - defensive/crypto missing
        return f"{path.name} could not be checked ({type(e).__name__}); run erase again"
    if not breaks:
        return None
    if all(b.reason == "no_pubkey" for b in breaks):
        return (f"{path.name} has rows signed by a key whose public key is not available "
                "here: put that key's .pub file back in the audit key folder, or pin it "
                "in MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS")
    return (f"{path.name} has signed rows that do not verify "
            f"({', '.join(sorted({b.reason for b in breaks}))}; see `maverick audit verify`); "
            f"erase will not re-sign them. {_RESTORE_DAY}")


def _anchor_problem(path: Path, *, reanchors: bool) -> str | None:
    """Operator text for a tip-ledger break that concerns ``path``, or None.

    A day the ledger already flags (rows removed, added or changed after it
    was anchored) is refused: a new anchor would replace the evidence. When
    the erase would add an anchor (``reanchors``), any break in the ledger
    itself refuses too.
    """
    from .signing import _ensure_anchor_ledger, verify_anchors

    day = path.stem
    try:
        breaks = verify_anchors(path.parent)
    # failure-policy: fail_closed
    except Exception as e:  # pragma: no cover - defensive
        return f"the audit tip ledger could not be checked ({type(e).__name__}); run erase again"
    mine = [b for b in breaks if b.reason in _DAY_ANCHOR_BREAKS
            and (b.detail.startswith(f"{day}:") or b.detail.startswith(f"{day}.ndjson"))]
    if mine:
        return (f"{path.name} no longer matches its tip anchor "
                f"({', '.join(sorted({b.reason for b in mine}))}; see `maverick audit verify`); "
                f"erase will not re-anchor it. {_RESTORE_DAY}")
    ledger = [b for b in breaks if b.reason not in _DAY_ANCHOR_BREAKS]
    if (all(b.reason == "anchor_ledger_missing" for b in ledger)
            and _ensure_anchor_ledger(path.parent)):
        # No ledger was ever written here (signing was turned off before the
        # first day closed, say): there is nothing to restore. The erase goes
        # ahead and adds no anchor, so `audit verify` reports what it did
        # before. A ledger that was once required and is now gone refuses.
        ledger = []
    if reanchors and ledger:
        return ("the audit tip ledger reports a break "
                f"({', '.join(sorted({b.reason for b in ledger}))}; see `maverick audit verify`); "
                "erase will not add to it. Restore anchors.ndjson from a backup "
                "(`maverick backup restore`)")
    return None


def _checkpoint_stores(path: Path) -> tuple[list[Path], list[str] | None, str | None]:
    """Every checkpoint store that may commit to ``path``'s day.

    The default store and the custody store beside the audit folder, and the
    folder an administrator chose. Returns ``(stores, pinned_keys, problem)``;
    a chosen folder that cannot be read is a problem, not a skip.
    """
    from .checkpoint_location import checkpoint_dir, load, settings_path

    stores = [path.parent.parent / "audit-checkpoints",
              path.parent.parent / "unified-audit" / "checkpoints"]
    try:
        settings = load()
    except RuntimeError:
        return [], None, (f"the checkpoint settings file {settings_path()} cannot be read; "
                          "fix or restore it")
    if settings["folder"]:
        chosen = Path(settings["folder"])
        if not chosen.is_dir() or not os.access(chosen, os.R_OK | os.X_OK):
            return [], None, (f"the chosen checkpoint folder {chosen} cannot be read; reconnect "
                              "it, or choose another folder in the audit checkpoint settings")
        stores.append(checkpoint_dir())
    return list(dict.fromkeys(stores)), (settings["keys"] or None), None


def _checkpoint_problem(path: Path) -> str | None:
    """A published checkpoint that requires more rows than the day has.

    Today's open day is never anchored, so its checkpoints are the only
    evidence of a removed row; an erase marker would otherwise bring the
    count back and turn that evidence into a routine prefix change.
    """
    from .checkpoints import verify_checkpoints

    stores, keys, problem = _checkpoint_stores(path)
    if problem:
        return problem
    for store in stores:
        if not store.is_dir():
            continue
        try:
            breaks = verify_checkpoints(path.parent, store, trusted_pubkeys=keys)
        # failure-policy: fail_closed
        except Exception as e:  # pragma: no cover - defensive
            return f"checkpoints in {store} could not be checked ({type(e).__name__}); run erase again"
        if any(b.reason == "audit_tail_truncated" and f"{path.name} " in b.detail for b in breaks):
            return (f"{path.name} has fewer rows than its published checkpoint in {store} (see "
                    f"`maverick audit checkpoint verify`). {_RESTORE_DAY}")
    return None


def _integrity_problem(path: Path, *, any_signed: bool) -> str | None:
    """Why rewriting ``path`` would hide a break ``maverick audit verify`` reports.

    Erase is never a repair: a day whose chain, tip anchor or published
    checkpoint already reports a break is left unchanged.
    """
    problem = (_chain_problem(path) if any_signed else None) or _checkpoint_problem(path)
    if problem:
        return problem
    if any_signed:
        _ensure_anchors(path.parent)
    return _anchor_problem(path, reanchors=any_signed)


def _ensure_anchors(audit_dir: Path) -> None:
    """Anchor completed days first, as a starting audit writer does, before a
    rewrite that will re-anchor: a new install's first completed day then
    has its ledger. Only when signing is on, as the writer does; an erase
    that rewrites nothing never reaches here."""
    try:
        from .writer import _resolve_signing

        if not _resolve_signing(None):
            return
        from .signing import ensure_anchors

        ensure_anchors(audit_dir)
    # failure-policy: fail_soft_with_audit
    except Exception as e:  # pragma: no cover - defensive
        log.warning("audit erase: could not anchor completed days first: %s", e)


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


def _chain_entries(
    rows: list[tuple[str, dict | None]],
    channel: str,
    user_id: str,
    *,
    delete: bool,
) -> list[tuple[str, object]]:
    """The erased day as :func:`signing.resign_rows` input.

    Only rows that arrived with their own signature fields (and verified,
    checked before this) are re-signed. A row that arrived unsigned stays
    out of the chain wherever it is, tombstoned if it is the subject's.
    """
    entries: list[tuple[str, object]] = []
    for raw, event in rows:
        line = raw.rstrip("\n")  # blank and whitespace lines stay where they were
        signed = _arrived_signed(event)
        if event is not None and _event_matches(event, channel, user_id):
            if delete:
                continue
            event = _tombstone(event, channel, user_id)
            line = json.dumps(event, default=str)
        if not signed:
            entries.append(("raw", line))
        else:
            entries.append(("json", event))
    return entries


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
    # erase mutation. Re-signing may only bless changes we just made to a
    # previously clean chain, never unrelated old tampering.
    problem = _integrity_problem(path, any_signed=any_signed)
    if problem:
        log.warning("audit erase: refusing to rewrite %s: %s", path.name, problem)
        if strict:
            raise RuntimeError("audit day failed pre-erasure integrity verification")
        return 0, len(rows)

    parts, written = _build_parts(rows, channel, user_id, delete=delete)
    text = "".join(parts)
    if any_signed:
        # Build the re-signed day in memory and publish it in ONE write. A
        # signer that is unavailable here (an off-host key this process cannot
        # reach, say) raises before anything is written, so an erase never
        # leaves unsigned tombstones inside a signed chain.
        from .signing import _load_or_create_keypair, resign_rows

        try:
            keypair = _load_or_create_keypair()
        # failure-policy: fail_closed
        except Exception as e:
            log.warning("audit erase: no signer to re-sign %s; left unchanged: %s", path, e)
            if strict:
                raise
            return 0, len(rows)
        text, _signed = resign_rows(
            _chain_entries(rows, channel, user_id, delete=delete),
            keypair,
        )

    # Re-seal the rewritten NDJSON when the source segment was sealed, so an
    # authorized erase scrubs the data without exposing the rest of a
    # confidential day-file as plaintext on disk.
    from .sealing import encode_segment
    new_bytes = encode_segment(text, sealed=was_sealed)

    try:
        atomic_write_bytes(path, new_bytes, mode=0o600)
        if any_signed:
            try:
                from .signing import ANCHOR_FILENAME, reanchor_day_after_erase

                if not (path.parent / ANCHOR_FILENAME).exists():
                    # No ledger has ever existed here (``_anchor_problem``
                    # refused a missing one that was required): add none.
                    return matched, written

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


def _day_blocker(path: Path, channel: str, user_id: str) -> str | None:
    """Why the subject's rows in ``path`` could not be erased, or None."""
    from .sealing import segment_text

    try:
        original = segment_text(path, fail_soft=False)
    # failure-policy: fail_closed
    except Exception:
        return (f"{path.name} cannot be read: restore the at-rest encryption key, or restore "
                "the file from a backup (`maverick backup restore`)")
    rows, matched, any_signed = _scan_rows(original, channel, user_id)
    if not matched:
        return None
    problem = _integrity_problem(path, any_signed=any_signed)
    if problem or not any_signed:
        return problem
    try:
        from .signing import _load_or_create_keypair

        _load_or_create_keypair()
    # failure-policy: fail_closed
    except Exception:
        return (f"{path.name} needs the audit signing key, which this process cannot load: "
                "run erase where MAVERICK_AUDIT_SIGNING_KEY or "
                "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED is set")
    return None


def erase_blockers(
    channel: str,
    user_id: str,
    *,
    audit_dir: Path | None = None,
) -> list[str]:
    """Audit days holding the subject that an erase could not rewrite.

    Erasure is all or nothing from the person's view, so the legal-erasure
    workflow checks this before it deletes anything and refuses when the
    list is not empty. Each entry names the day file and the reason.
    """
    if audit_dir is None:
        from ..paths import data_dir
        audit_dir = data_dir("audit")
    if not audit_dir.exists():
        return []
    blockers = []
    for path in sorted(audit_dir.glob("*.ndjson")):
        if path.is_dir():
            continue
        blocker = _day_blocker(path, channel, user_id)
        if blocker:
            blockers.append(blocker)
    return blockers


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


__all__ = ["scrub_user", "delete_user", "erase_blockers"]
