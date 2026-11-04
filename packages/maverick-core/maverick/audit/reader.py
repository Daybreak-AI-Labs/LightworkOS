"""Single source of truth for reading the tamper-evident audit NDJSON log.

Three read-side consumers share the same three steps here instead of each
re-implementing them with ad-hoc globs and filename literals:

  - :mod:`maverick.audit.export` (SIEM export / ``maverick audit export``),
  - :mod:`maverick.dsar` (GDPR Art. 15/20 subject-access export),
  - :mod:`maverick.soc2` (the audit-chain compliance probe).

They drifted apart in ways that were quietly wrong -- ``dsar`` read the
cross-file ``anchors.ndjson`` tip-ledger as if it were a day-file and ignored
at-rest sealing, while ``export`` excluded the ledger and decrypted sealed
segments. This module defines, once:

  - :func:`day_files` -- what counts as a day-file (re-exported from
    :mod:`maverick.audit.signing`, where the ``YYYY-MM-DD`` pattern and the
    :data:`ANCHOR_FILENAME` constant live), so the anchor ledger is excluded the
    same way everywhere; and
  - :func:`iter_events` -- how to turn the selected day-files into event dicts,
    transparently reading plaintext or authenticated sealed frames, and
    recording malformed/unreadable input in a separate coverage report.

Read-only: nothing here ever mutates the log or touches the signing chain.
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
from collections.abc import Iterator
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from .events import is_valid_day
from .segments import ReadReport, SegmentReadError, SegmentSnapshot
from .signing import ANCHOR_FILENAME, day_files  # noqa: F401  (re-exported)

log = logging.getLogger(__name__)

__all__ = ["ANCHOR_FILENAME", "day_files", "event_paths", "iter_events"]


def resolve_audit_dir(tenant: str | None) -> Path:
    """The tenant-aware audit directory (``<data>/audit``).

    Mirrors :class:`maverick.audit.writer.AuditLog`'s own default so a read
    reflects where rows are *currently* written. ``tenant=None`` follows the
    active tenant (env / contextvar), matching the writer and the export CLI.
    """
    from ..paths import data_dir

    return data_dir("audit", tenant=tenant) if tenant else data_dir("audit")


def event_paths(
    *, day: str | None = None, all_days: bool = False,
    since: str | None = None, until: str | None = None,
    tenant: str | None = None,
    audit_dir: Path | None = None,
) -> list[Path]:
    """Return the tenant-aware audit day-files selected for reading.

    Selection precedence: a ``since``/``until`` window (inclusive, over day-file
    dates) wins; then ``all_days`` sweeps every day-file; otherwise a single
    day-file (``day`` or today, UTC) is returned. The cross-file anchor ledger
    is never included (it is not a date-named day-file).
    """
    # Validate the path-forming input first -- before any filesystem check that
    # could otherwise short-circuit (an empty dir) and let a crafted ``day``
    # slip past. (``since``/``until`` are only compared lexically below, never
    # built into a path.)
    if day is not None and not is_valid_day(day):
        raise ValueError(f"invalid audit day {day!r}: expected YYYY-MM-DD")

    root = Path(audit_dir) if audit_dir is not None else resolve_audit_dir(tenant)
    if not root.exists():
        return []
    if not root.is_dir():
        raise NotADirectoryError("audit root is not a directory")

    if since or until:
        # Inclusive [since, until] window over day-file dates. ISO YYYY-MM-DD
        # sorts lexically, so a plain string compare on the file stem works.
        lo = since or "0000-00-00"
        hi = until or "9999-99-99"
        return [p for p in day_files(root) if lo <= p.stem <= hi]
    if all_days:
        return day_files(root)

    # ``day`` was validated up front; default to today (UTC) when unset.
    d = day or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    return [root / f"{d}.ndjson"]


def iter_events(
    *,
    day: str | None = None,
    all_days: bool = False,
    since: str | None = None,
    until: str | None = None,
    tenant: str | None = None,
    audit_dir: Path | None = None,
    strict: bool = False,
    report: ReadReport | None = None,
    verify: bool = False,
) -> Iterator[dict[str, Any]]:
    """Yield audit event dicts from the tenant-aware audit dir.

    Sealing-aware (transparently decrypts an at-rest-sealed segment) and
    fail-soft by default: malformed/unreadable lines are reported separately,
    a missing dir is empty, and the anchor ledger is excluded. ``strict=True`` makes
    an unreadable/decryption failure, malformed JSON line, or non-object row
    raise so a proof-producing caller cannot mistake unreadable evidence for an
    empty log. ``verify=True`` additionally verifies selected segment chains;
    it does not verify anchors or independent checkpoints. See :func:`event_paths`
    for selection precedence. A report is complete only after exhausting iteration.
    """
    from ..crypto_at_rest import EncryptionUnavailable
    from ..file_lock import cross_process_lock
    from ..paths import tenant_scope
    from ..sealed_stream import SealedStreamError
    from .signing import verify_chain

    report = report if report is not None else ReadReport()
    report.verification = "pending" if verify else "not_requested"
    try:
        paths = event_paths(
            day=day, all_days=all_days, since=since, until=until, tenant=tenant,
            audit_dir=audit_dir,
        )
    except OSError as error:
        report.problem(Path("audit"), type(error).__name__)
        report.finished = True
        if verify:
            report.verification = "failed"
        if strict:
            raise SegmentReadError("cannot enumerate audit segments") from error
        log.warning("audit enumeration failed (%s)", type(error).__name__)
        return
    for path in paths:
        if not path.exists() and not (all_days or since or until or strict):
            continue  # a day with no log is empty; disappearing selected files aren't
        report.segments += 1
        before = report.failures
        try:
            # A verified export binds both bounded passes to the same private
            # descriptor under the writer/rewrite lock. Normal reads are fixed
            # snapshots with explicit change detection, without holding up writers.
            with (cross_process_lock(path, strict=True) if verify else nullcontext()):
                with SegmentSnapshot(path, report, tenant=tenant) as snapshot:
                    if verify:
                        with tenant_scope(tenant=snapshot.tenant):
                            breaks = verify_chain(path, lines=snapshot.lines(), max_breaks=64)
                        if breaks:
                            report.verification = "failed"
                            raise SegmentReadError("audit segment signature or chain verification failed")
                    for line_number, line in enumerate(snapshot.lines(), start=1):
                        if not line.strip():
                            continue
                        try:
                            event = json.loads(line)
                            if not isinstance(event, dict):
                                raise ValueError("non-object audit row")
                        except (ValueError, RecursionError) as error:
                            report.problem(path, "invalid_json_object", line_number)
                            if strict:
                                raise SegmentReadError(f"invalid audit JSON at line {line_number}") from error
                            continue
                        report.events += 1
                        yield event
            if before == report.failures:
                report.completed_segments += 1
        except (OSError, UnicodeError, EncryptionUnavailable, SealedStreamError, SegmentReadError) as error:
            report.problem(path, type(error).__name__)
            if verify:
                report.verification = "failed"
            if strict:
                if isinstance(error, SegmentReadError):
                    raise
                raise SegmentReadError(f"cannot completely read audit segment {path.name}") from error
            log.warning("audit read incomplete: %s (%s)", path.name, type(error).__name__)
    if verify and not report.failures:
        report.verification = "segment_chains_verified"
    report.finished = True


def tail_events(path: Path, n: int, *, report: ReadReport | None = None) -> list[dict[str, Any]]:
    """Read a bounded suffix; no claim about unread prefixes or chain proofs."""
    from ..crypto_at_rest import EncryptionUnavailable
    from ..sealed_stream import SealedStreamError

    report = report if report is not None else ReadReport()
    report.scope = "requested_tail"
    out = []
    try:
        if not path.exists():
            return out
        report.segments += 1
        with SegmentSnapshot(path, report) as snapshot:
            for line in snapshot.tail_lines(n):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("non-object audit row")
                except (ValueError, RecursionError):
                    report.problem(path, "invalid_json_object")
                    continue
                out.append(event)
                report.events += 1
        if not report.failures:
            report.completed_segments += 1
    except (OSError, UnicodeError, EncryptionUnavailable, SealedStreamError, SegmentReadError) as error:
        report.problem(path, type(error).__name__)
        log.warning("audit tail incomplete: %s (%s)", path.name, type(error).__name__)
    finally:
        report.finished = True
    return out
