"""Export audit events for SIEM ingestion.

Reads the tamper-evident NDJSON audit log and re-emits each event as
either compact JSON (one event per line) or ArcSight CEF, ready to ship
to a SIEM (Splunk, Sentinel, QRadar, ...). Read-only: it never mutates
the log or touches the signing chain.

Event shape and tenant-aware path resolution are reused from the writer
(:class:`maverick.audit.writer.AuditLog`) via :func:`maverick.paths.data_dir`.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import reader

log = logging.getLogger(__name__)

# CEF severity (0-10). Default low; bump for denial/halt/block kinds so a
# SIEM correlation rule can alert on the dangerous ones without parsing
# every field.
_CEF_SEVERITY = {
    "shield_block": 7,
    "capability_denied": 7,
    "egress_blocked": 7,
    "halt": 9,
    "consent_result": 5,
    "secret_redacted": 5,
    "erase": 5,
}
_DEFAULT_SEVERITY = 2


def _audit_version() -> str:
    try:
        from .. import __version__

        return str(__version__)
    # failure-policy: best_effort
    except Exception:
        return "0"


def audit_event_paths(
    *, day: str | None = None, all_days: bool = False,
    since: str | None = None, until: str | None = None,
    tenant: str | None = None,
) -> list[Path]:
    """Return tenant-aware audit day-files selected for export.

    Thin wrapper over :func:`maverick.audit.reader.event_paths` (the single
    day-file-selection definition shared with the DSAR and SOC 2 readers).
    """
    return reader.event_paths(
        day=day, all_days=all_days, since=since, until=until, tenant=tenant,
    )


def validate_export_destination(path: Path, *, tenant: str | None = None) -> None:
    """Keep exports and read receipts outside all evidence in the audit root.

    Selection is not protection: anchors, WORM receipts, locks, checkpoints and
    unselected day files remain authoritative even when this export omits them.
    Reject multiply-linked destinations without walking an unbounded evidence
    tree. The private atomic writer independently checks destination custody.
    """
    root = reader.resolve_audit_dir(tenant).resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved == root or root in resolved.parents:
        raise ValueError("audit output must be outside the protected audit directory")
    try:
        info = path.stat()
    except FileNotFoundError:
        return
    if info.st_nlink != 1:
        raise ValueError("audit output must not alias another file through a hard link")


def iter_audit_events(
    *, day: str | None = None, all_days: bool = False,
    since: str | None = None, until: str | None = None,
    tenant: str | None = None,
    report: reader.ReadReport | None = None,
    verify: bool = False,
    strict: bool = False,
) -> Iterator[dict[str, Any]]:
    """Yield audit event dicts from the tenant-aware audit dir.

    Thin wrapper over :func:`maverick.audit.reader.iter_events`. Selection
    precedence: a ``since``/``until`` window (inclusive, over day-file dates)
    wins; then ``all_days`` sweeps every day-file except the cross-file
    ``anchors.ndjson`` tip-ledger (matching ``audit verify``); otherwise a
    single day-file is read (``day`` or today, UTC). Malformed/unreadable input
    is recorded in ``report``; ``strict`` refuses it. ``verify`` checks selected
    segment chains, separately from anchor/checkpoint assurance.
    """
    return reader.iter_events(
        day=day, all_days=all_days, since=since, until=until, tenant=tenant,
        report=report, verify=verify, strict=strict,
    )


def to_jsonl(event: dict[str, Any]) -> str:
    """A compact, stable JSON line for one event."""
    return json.dumps(event, default=str, sort_keys=True, separators=(",", ":"))


def _cef_escape(value: str) -> str:
    """Escape a CEF extension value: backslash, equals, and newlines."""
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def _cef_header_escape(value: str) -> str:
    """Escape a CEF *header* field: backslash, pipe, and newlines.

    Header fields are ``|``-delimited (extension values are not), so an
    unescaped ``|`` or newline in a header field (e.g. a future/plugin-supplied
    ``kind``) would shift the header columns and corrupt the record.
    """
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace("\r", "\\n")
    )


def to_cef(event: dict[str, Any]) -> str:
    """Render one event as an ArcSight CEF line.

    ``CEF:0|Lightwork|maverick-agent|<version>|<kind>|<kind>|<sev>|<extensions>``
    where extensions are space-separated ``key=value`` of the event's scalar
    fields (CEF-escaped). Non-scalar fields (dicts/lists) are skipped.
    """
    kind = str(event.get("kind", "event"))
    severity = _CEF_SEVERITY.get(kind, _DEFAULT_SEVERITY)
    hk = _cef_header_escape(kind)
    ver = _cef_header_escape(_audit_version())
    header = f"CEF:0|Lightwork|maverick-agent|{ver}|{hk}|{hk}|{severity}|"
    parts = []
    for key, val in event.items():
        if isinstance(val, bool) or isinstance(val, (str, int, float)) or val is None:
            parts.append(f"{_cef_escape(str(key))}={_cef_escape(str(val))}")
    return header + " ".join(parts)
