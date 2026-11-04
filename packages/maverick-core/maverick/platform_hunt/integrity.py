"""Fail-closed verification adapter for the signed Lightwork audit chain."""
from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path

from .models import ChainIntegrityStatus


def _safe_label(path: Path) -> str:
    """Return a diagnostic label that cannot disclose a host filesystem path."""
    return path.name or "audit-segment"


_SAFE_BREAK_DETAILS = {
    "no_crypto": "audit signature verification is unavailable",
    "missing_file": "a signed audit segment is missing",
    "unreadable_segment": "a signed audit segment is unreadable",
    "malformed": "a signed audit record is malformed",
    "unsigned": "an audit record is unsigned",
    "chain_mismatch": "an audit chain link does not match",
    "bad_hash": "an audit record hash does not match",
    "no_pubkey": "an audit signing key is unavailable",
    "bad_signature": "an audit record signature is invalid",
    "anchor_ledger_missing": "the cross-file anchor ledger is missing",
    "anchored_file_deleted": "an anchored audit segment is missing",
    "anchor_tip_mismatch": "an audit segment tip does not match its anchor",
    "anchor_count_mismatch": "an audit segment count does not match its anchor",
}


def _safe_break(item) -> tuple[str, str]:
    """Reduce verifier diagnostics to fixed, viewer-safe vocabulary.

    Several low-level verifier details legitimately contain absolute paths or
    operating-system error strings.  Hunter health is exposed over a viewer
    endpoint, so it must retain the forensic category without reflecting those
    host-local details.
    """
    raw_reason = str(getattr(item, "reason", "verification_break"))
    if raw_reason not in _SAFE_BREAK_DETAILS:
        return "verification_break", "signed audit verification failed"
    return raw_reason, _SAFE_BREAK_DETAILS[raw_reason]


def verify_audit_chain(
    paths: Iterable[str | Path],
    *,
    audit_dirs: Iterable[str | Path] = (),
) -> ChainIntegrityStatus:
    """Verify each signed segment and every containing cross-file anchor ledger.

    ``audit_dirs`` lets a caller retain cross-file deletion detection even when
    every selected day file was deleted and ``paths`` is therefore empty.  The
    returned status intentionally contains only basenames and fixed labels; a
    viewer-safe health endpoint must not disclose tenant-local absolute paths.
    """
    from ..audit.signing import verify_anchors, verify_chain

    checked: list[str] = []
    breaks: list[dict] = []
    normalized_paths = tuple(sorted({Path(path) for path in paths}, key=str))
    directories = {Path(path) for path in audit_dirs}
    directories.update(path.parent for path in normalized_paths)
    for raw_path in normalized_paths:
        label = _safe_label(raw_path)
        checked.append(label)
        try:
            found = verify_chain(raw_path)
        except Exception as exc:  # failure-policy: fail_closed
            breaks.append({
                "path": label,
                "line_no": 0,
                "reason": "verification_error",
                "detail": type(exc).__name__,
            })
            continue
        for item in found:
            reason, detail = _safe_break(item)
            breaks.append({
                "path": label,
                "line_no": int(item.line_no),
                "reason": reason,
                "detail": detail,
            })
    for audit_dir in sorted(directories, key=str):
        checked.append("audit-anchors")
        if not audit_dir.exists() or not audit_dir.is_dir():
            breaks.append({
                "path": "audit-anchors",
                "line_no": 0,
                "reason": "audit_directory_missing",
                "detail": "signed audit telemetry is unavailable",
            })
            continue
        try:
            found = verify_anchors(audit_dir)
        except Exception as exc:  # failure-policy: fail_closed
            breaks.append({
                "path": "audit-anchors",
                "line_no": 0,
                "reason": "anchor_verification_error",
                "detail": type(exc).__name__,
            })
            continue
        for item in found:
            reason, detail = _safe_break(item)
            breaks.append({
                "path": "audit-anchors",
                "line_no": int(item.line_no),
                "reason": reason,
                "detail": detail,
            })
    return ChainIntegrityStatus(
        intact=bool(directories) and not breaks,
        paths_checked=tuple(dict.fromkeys(checked)),
        breaks=tuple(breaks),
        checked_at=time.time(),
    )


__all__ = ["verify_audit_chain"]
