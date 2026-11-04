"""Encrypt closed audit day-files at rest (confidentiality for the audit log).

The audit log is *signed* for tamper-evidence (``signing.py``) but is otherwise
plaintext NDJSON on disk -- a confidentiality gap when the events carry sensitive
action detail. This seals **closed** day-files (any date strictly before today) in
place with AES-256-GCM, leaving the file name unchanged: a sealed segment just
holds the encrypted blob instead of NDJSON, detected on read by the seal magic
header. The **current** day-file is never sealed -- live append + the flock'd
signing writer keep operating on plaintext.

Reads stay transparent: :func:`segment_text` decrypts a sealed segment back to its
NDJSON text, so the readers (``export.iter_audit_events``) and the verifier
(``signing.verify_chain`` / the cross-file tip ledger) work on sealed and
plaintext segments alike -- and the hash-chain still verifies, because sealing
only encrypts the bytes, never the signed rows.

Exposed as ``maverick audit seal``; runs only when at-rest encryption is enabled.
"""
from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path

from ..file_lock import (
    atomic_read_bytes,
    atomic_write_bytes,
    atomic_write_bytes_chunks,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    open_private_read,
)
from .segments import SegmentReadError, sealed_bytes

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def segment_text(path: Path, *, fail_soft: bool = True) -> str:
    """Return an audit day-file's NDJSON text, transparently decrypting a sealed
    segment.

    Export readers use the default fail-soft mode and receive ``""`` on a
    read/decrypt error. Integrity verifiers must pass ``fail_soft=False`` so
    unreadable or undecryptable signed evidence fails closed instead of being
    mistaken for a valid empty chain.
    """
    try:
        path = Path(path)
        ensure_private_directory(path.parent)
        ensure_private_file(path, 0o600)
        raw = atomic_read_bytes(path)
    except OSError as e:
        if fail_soft:
            return ""
        raise SegmentReadError(f"cannot read audit segment {path}: {e}") from e
    from ..crypto_at_rest import is_sealed, unseal
    if is_sealed(raw):
        try:
            return unseal(raw).decode("utf-8")
        # failure-policy: fail_closed
        except Exception as e:
            if fail_soft:
                return ""
            raise SegmentReadError(f"cannot decrypt sealed audit segment {path}: {e}") from e
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        if fail_soft:
            return ""
        raise SegmentReadError(f"cannot decode audit segment {path}: {e}") from e


def encode_segment(text: str, *, sealed: bool) -> bytes:
    """Encode NDJSON ``text`` for storage, re-sealing it when ``sealed``.

    Lets a rewriter (GDPR erase, chain re-anchor) edit a day-file's content and
    write it back in the *same* on-disk representation it had -- so a sealed,
    confidential segment is never silently replaced with plaintext. ``sealed``
    is the caller's observation of the original file (``is_sealed`` of its raw
    bytes); a sealed file can only have been read because encryption is on, so
    ``seal`` is available here."""
    data = text.encode("utf-8")
    if not sealed:
        return data
    return sealed_bytes(text)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Replace ``path`` with ``data`` atomically and privately (0600)."""
    ensure_private_directory(path.parent)
    try:
        # Tighten legacy state before replacement. A missing destination is the
        # normal first-write case: atomic_write_bytes creates its unpublished
        # temp with private custody before publishing it over this path.
        ensure_private_file(path, 0o600)
    except FileNotFoundError:
        pass
    atomic_write_bytes(path, data, mode=0o600)


def _selected_paths(audit_dir, today, expected_sources):
    if expected_sources is None:
        return sorted(audit_dir.glob("*.ndjson"))
    if any(not _DAY_RE.fullmatch(Path(name).stem) or name != Path(name).name
           or not name.endswith(".ndjson") or Path(name).stem >= today for name in expected_sources):
        raise SegmentReadError("reviewed audit selection is invalid")
    return [audit_dir / name for name in sorted(expected_sources)]


def _source_digest(source):
    source.seek(0)
    hasher = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        hasher.update(chunk)
    return hasher.hexdigest()


def _missing_source(audit_dir, expected_sources):
    if audit_dir.exists():
        return False
    if expected_sources:
        raise SegmentReadError("reviewed audit source is missing")
    return True


def seal_closed_segments(audit_dir: Path | None = None, *,
                         today: str | None = None,
                         dry_run: bool = False,
                         expected_sources: Mapping[str, str] | None = None,
                         before_effect: Callable[[str, str], None] | None = None,
                         completed: Callable[[str, str], None] | None = None) -> dict[str, str]:
    """Seal every closed (date < today), not-yet-sealed day-file in place.

    Requires at-rest encryption to be enabled (raises
    :class:`maverick.crypto_at_rest.EncryptionUnavailable` otherwise, so it never
    leaves a half-state). Returns a ``{filename: status}`` report. The current
    day-file, the ``anchors.ndjson`` tip ledger, and already-sealed files are
    skipped.
    """
    import datetime as _dt

    from ..crypto_at_rest import EncryptionUnavailable, at_rest_enabled, is_sealed, seal
    from ..sealed_stream import encode_stream
    if not at_rest_enabled():
        raise EncryptionUnavailable(
            "at-rest encryption is not enabled; set [encryption] at_rest = true "
            "(or MAVERICK_ENCRYPT_AT_REST=1) before sealing audit segments"
        )
    if audit_dir is None:
        from ..paths import data_dir
        audit_dir = data_dir("audit")
    today = today or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")

    report: dict[str, str] = {}
    if _missing_source(audit_dir, expected_sources):
        return report
    paths = _selected_paths(audit_dir, today, expected_sources)
    for p in paths:
        if not _DAY_RE.fullmatch(p.stem):
            continue                              # not a date-named day-file
        if p.stem >= today:
            report[p.name] = "skipped (current)"  # live append stays plaintext
            continue
        try:
            with cross_process_lock(p, strict=True):
                with os.fdopen(open_private_read(p), "rb") as source:
                    already = is_sealed(source.read(8))
                    source_digest = _source_digest(source)
                if expected_sources is not None and source_digest != expected_sources[p.name]:
                    raise SegmentReadError("reviewed audit source changed")
                if already:
                    report[p.name] = "already sealed"
                    continue
                if dry_run:
                    report[p.name] = "would seal"
                    continue
                if before_effect:
                    before_effect(p.name, source_digest)

                def chunks(path=p, expected_digest=source_digest):
                    # Close the source before atomic publication (Windows),
                    # while retaining the stable rewrite lock through rename.
                    with os.fdopen(open_private_read(path), "rb") as source:
                        initial = os.fstat(source.fileno())
                        # Authenticate the exact plaintext consumed by the
                        # streaming encoder before publishing its replacement.
                        class CheckedSource:
                            def __init__(self):
                                self.hasher = hashlib.sha256()
                            def read(self, size=-1):
                                chunk = source.read(size)
                                self.hasher.update(chunk)
                                return chunk
                            def seek(self, offset, whence=os.SEEK_SET):
                                result = source.seek(offset, whence)
                                if offset == 0 and whence == os.SEEK_SET:
                                    self.hasher = hashlib.sha256()
                                return result
                        checked = CheckedSource()
                        yield from encode_stream(checked, seal)
                        if checked.hasher.hexdigest() != expected_digest:
                            raise SegmentReadError("reviewed audit source changed during sealing")
                        final, visible = os.fstat(source.fileno()), path.lstat()
                        if ((initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns)
                                != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
                                or (visible.st_dev, visible.st_ino) != (initial.st_dev, initial.st_ino)):
                            raise SegmentReadError("audit source changed before sealing publication")

                atomic_write_bytes_chunks(p, chunks(), mode=0o600)
                report[p.name] = "sealed"
                if completed:
                    completed(p.name, "sealed")
        except OSError as e:
            report[p.name] = f"error ({e})"
    return report


__all__ = ["SegmentReadError", "segment_text", "encode_segment", "seal_closed_segments"]
