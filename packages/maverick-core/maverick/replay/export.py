"""Verified, privacy-scrubbed session replay exports.

Replay bundles are evidence products, not best-effort log viewers. Before a
bundle is published, every selected audit day is parsed strictly, any present
signature/hash chain is verified, and the cross-day anchor ledger is checked.
Unsigned legacy logs remain exportable only with an explicit ``unsigned`` proof
status; malformed, forged, mixed signed/unsigned, or otherwise unverifiable
evidence fails closed.
"""
from __future__ import annotations

import html
import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..file_lock import (
    atomic_write_text,
    cross_process_lock,
    ensure_private_file,
    prepare_private_directory,
)
from ..paths import data_dir
from ..safety.pii_detector import redact as _pii_redact
from ..secrets import scrub

log = logging.getLogger(__name__)

MAX_AUDIT_FILES = 3_660
MAX_AUDIT_FILE_BYTES = 64 * 1024 * 1024
MAX_AUDIT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_AUDIT_LINE_BYTES = 2 * 1024 * 1024
MAX_REPLAY_EVENTS = 250_000


class ReplayEvidenceError(RuntimeError):
    """Audit evidence cannot be exported without risking a false proof claim."""


def _sanitize(text: str) -> str:
    """Strip secrets and PII before a bundle leaves the machine."""
    return _pii_redact(scrub(text))[0]


# Compatibility override: existing tests/operators monkeypatch ``_AUDIT_DIR``.
# While untouched, the actual path is resolved for the active tenant per call.
_INITIAL_AUDIT_DIR = data_dir("audit")
_AUDIT_DIR = _INITIAL_AUDIT_DIR


def _audit_dir() -> Path:
    if _AUDIT_DIR is not _INITIAL_AUDIT_DIR:
        return Path(_AUDIT_DIR)
    return data_dir("audit")


_HTML_HEAD_TMPL = (
    '<!doctype html>\n'
    '<html lang="en">\n'
    '<head>\n'
    '<meta charset="utf-8" />\n'
    '<title>Lightwork replay — goal __GOAL__</title>\n'
    '<style>\n'
    '  body { background: #0d1117; color: #e6edf3; '
    'font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; '
    'margin: 0; padding: 2rem; }\n'
    '  h1 { margin: 0 0 1rem; font-size: 1rem; color: #8b949e; '
    'text-transform: uppercase; letter-spacing: .08em; }\n'
    '  .proof { background: #161b22; border: 1px solid #30363d; '
    'border-radius: 6px; padding: .6rem 1rem; margin: 0 0 1rem; }\n'
    '  .ev { background: #161b22; border: 1px solid #30363d; '
    'border-radius: 6px; padding: .75rem 1rem; margin: .5rem 0; }\n'
    '  .ev .meta { color: #8b949e; font-size: 11px; }\n'
    '  .ev pre { margin: .25rem 0 0; white-space: pre-wrap; '
    'word-break: break-word; }\n'
    '  .badge { display: inline-block; padding: .1rem .5rem; '
    'border-radius: 4px; font-size: 11px; '
    'background: rgba(46,160,67,.2); color: #2ea043; margin-right: .5rem; }\n'
    '  .badge.error  { background: rgba(248,81,73,.2); color: #f85149; }\n'
    '  .badge.system { background: rgba(110,118,129,.2); color: #8b949e; }\n'
    '</style>\n'
    '</head>\n'
    '<body>\n'
    '<h1>goal __GOAL__ — __N__ event(s)</h1>\n'
)
_HTML_TAIL = "\n</body></html>\n"


def _render_head(goal_id: int, count: int) -> str:
    return (
        _HTML_HEAD_TMPL.replace("__GOAL__", str(goal_id)).replace("__N__", str(count))
    )


def _iter_audit_files() -> Iterator[Path]:
    from ..audit.signing import day_files

    audit_dir = _audit_dir()
    if not audit_dir.exists():
        return
    if not audit_dir.is_dir():
        raise ReplayEvidenceError("audit evidence root is not a directory")
    yield from day_files(audit_dir)


def _strict_rows(path: Path) -> list[dict]:
    from ..audit.sealing import segment_text

    try:
        ensure_private_file(path)
        disk_size = path.stat().st_size
    except OSError as exc:
        raise ReplayEvidenceError("audit evidence is unavailable") from exc
    if disk_size > MAX_AUDIT_FILE_BYTES:
        raise ReplayEvidenceError("audit evidence file exceeds the replay limit")
    try:
        text = segment_text(path, fail_soft=False)
    except Exception as exc:
        raise ReplayEvidenceError("audit evidence cannot be decoded") from exc
    encoded_size = len(text.encode("utf-8"))
    if encoded_size > MAX_AUDIT_FILE_BYTES:
        raise ReplayEvidenceError("decoded audit evidence exceeds the replay limit")

    rows: list[dict] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise ReplayEvidenceError(
                f"audit evidence contains a blank committed row at line {line_number}"
            )
        if len(line.encode("utf-8")) > MAX_AUDIT_LINE_BYTES:
            raise ReplayEvidenceError(
                f"audit evidence row {line_number} exceeds the replay limit"
            )
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ReplayEvidenceError(
                f"audit evidence contains a malformed row at line {line_number}"
            ) from exc
        if not isinstance(row, dict):
            raise ReplayEvidenceError(
                f"audit evidence row {line_number} is not an object"
            )
        rows.append(row)
        if len(rows) > MAX_REPLAY_EVENTS:
            raise ReplayEvidenceError("audit evidence exceeds the replay event limit")
    return rows


def _break_codes(breaks) -> str:
    codes = sorted({str(item.reason) for item in breaks})
    return ",".join(codes[:8]) or "unknown"


def _verify_files(files: list[Path]) -> tuple[dict[Path, list[dict]], dict]:
    from ..audit.events import is_valid_day
    from ..audit.signing import (
        ANCHOR_FILENAME,
        ANCHOR_MARKER_FILENAME,
        verify_anchors,
        verify_chain,
    )

    if len(files) > MAX_AUDIT_FILES:
        raise ReplayEvidenceError("too many audit day files for one replay")
    if not files:
        return {}, {
            "status": "no_evidence",
            "anchors": "not_applicable",
            "files": [],
        }
    parents = {path.parent for path in files}
    if len(parents) != 1:
        raise ReplayEvidenceError("audit day files do not share one evidence root")
    audit_dir = next(iter(parents))
    if len(set(files)) != len(files) or any(
        path.suffix != ".ndjson" or not is_valid_day(path.stem) for path in files
    ):
        raise ReplayEvidenceError("audit evidence selection contains an invalid day file")

    rows_by_path: dict[Path, list[dict]] = {}
    file_proofs: list[dict] = []
    total_bytes = 0
    total_rows = 0
    statuses: set[str] = set()
    for path in files:
        try:
            total_bytes += path.stat().st_size
        except OSError as exc:
            raise ReplayEvidenceError("audit evidence is unavailable") from exc
        if total_bytes > MAX_AUDIT_TOTAL_BYTES:
            raise ReplayEvidenceError("audit evidence exceeds the total replay limit")
        rows = _strict_rows(path)
        total_rows += len(rows)
        if total_rows > MAX_REPLAY_EVENTS:
            raise ReplayEvidenceError("audit evidence exceeds the replay event limit")
        rows_by_path[path] = rows
        has_proof = any(
            any(field in row for field in ("hash", "sig", "key_id", "prev_hash"))
            for row in rows
        )
        if not rows:
            status = "empty"
        elif not has_proof:
            status = "unsigned"
            statuses.add(status)
        else:
            breaks = verify_chain(path)
            if breaks:
                raise ReplayEvidenceError(
                    "audit day-chain verification failed: " + _break_codes(breaks)
                )
            status = "verified"
            statuses.add(status)
        file_proofs.append({"day": path.stem, "status": status, "rows": len(rows)})

    if len(statuses) > 1:
        raise ReplayEvidenceError(
            "audit evidence mixes signed and unsigned day files"
        )
    overall = next(iter(statuses), "no_evidence")
    if overall == "unsigned" and (audit_dir / "keys").exists():
        # An all-unsigned day beside signing trust material is indistinguishable
        # from a chain whose proof fields were stripped wholesale. Refuse that
        # downgrade rather than blessing it as an ordinary unsigned deployment.
        raise ReplayEvidenceError(
            "unsigned audit evidence conflicts with signing trust material"
        )

    try:
        anchor_breaks = verify_anchors(audit_dir)
    except Exception as exc:
        raise ReplayEvidenceError("cross-day audit anchors are unverifiable") from exc
    if anchor_breaks:
        reasons = {str(item.reason) for item in anchor_breaks}
        unsigned_without_ledger = (
            overall == "unsigned"
            and reasons == {"anchor_ledger_missing"}
            and not (audit_dir / ANCHOR_FILENAME).exists()
            and not (audit_dir / ANCHOR_MARKER_FILENAME).exists()
        )
        if unsigned_without_ledger:
            anchor_status = "unavailable_unsigned"
        else:
            raise ReplayEvidenceError(
                "cross-day audit anchor verification failed: "
                + _break_codes(anchor_breaks)
            )
    elif (audit_dir / ANCHOR_FILENAME).exists():
        anchor_status = "verified"
    else:
        anchor_status = "not_required" if overall == "verified" else "unavailable_unsigned"

    return rows_by_path, {
        "status": overall,
        "anchors": anchor_status,
        "files": file_proofs,
    }


def load_goal_events(
    goal_id: int,
    files: Iterable[Path] | None = None,
) -> tuple[list[dict], dict]:
    """Return matching events plus their verified/explicit proof posture."""
    try:
        target_goal = int(goal_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("goal_id must be an integer") from exc
    selected = list(files) if files is not None else list(_iter_audit_files())
    rows_by_path, proof = _verify_files(selected)
    events: list[dict] = []
    for path in selected:
        for event in rows_by_path.get(path, []):
            raw_goal = event.get("goal_id")
            if raw_goal is None:
                continue
            try:
                matches = int(raw_goal) == target_goal
            except (TypeError, ValueError):
                # Invalid unrelated IDs cannot abort a verified file export.
                continue
            if matches:
                events.append(event)
                if len(events) > MAX_REPLAY_EVENTS:
                    raise ReplayEvidenceError("goal replay exceeds the event limit")
    return events, proof


def _iter_events_for_goal(
    goal_id: int,
    files: Iterable[Path] | None = None,
) -> Iterator[dict]:
    events, _proof = load_goal_events(goal_id, files)
    yield from events


def _kind_class(kind: str) -> str:
    value = (kind or "").lower()
    if "error" in value or "fail" in value or "halt" in value:
        return "error"
    if "system" in value or "config" in value:
        return "system"
    return ""


def _render_event(event: dict) -> str:
    kind = str(event.get("kind") or event.get("event") or "?")
    timestamp = event.get("ts") or event.get("created_at") or ""
    body = {
        key: value
        for key, value in event.items()
        if key
        not in (
            "kind",
            "event",
            "ts",
            "goal_id",
            "hash",
            "prev_hash",
            "sig",
            "key_id",
        )
    }
    body_text = _sanitize(json.dumps(body, indent=2, default=str))
    return (
        '<div class="ev"><div class="meta">'
        f'<span class="badge {_kind_class(kind)}">{html.escape(kind)}</span>'
        f"<span>{html.escape(str(timestamp))}</span></div>"
        f"<pre>{html.escape(body_text)}</pre></div>"
    )


def _render_proof(proof: dict) -> str:
    status = html.escape(str(proof.get("status", "unknown")))
    anchors = html.escape(str(proof.get("anchors", "unknown")))
    file_count = len(proof.get("files") or [])
    return (
        '<div class="proof"><span class="badge system">evidence</span>'
        f"status: {status}; anchors: {anchors}; day files: {file_count}</div>\n"
    )


def _publish_text(out_path: Path, text: str) -> None:
    out_path = Path(out_path)
    prepare_private_directory(out_path.parent)
    with cross_process_lock(out_path, strict=True):
        atomic_write_text(out_path, text, mode=0o600)
        ensure_private_file(out_path)


def export_html(goal_id: int, out_path: Path) -> int:
    """Atomically publish a self-contained replay with proof status."""
    events, proof = load_goal_events(goal_id)
    parts = [_render_head(goal_id, len(events)), _render_proof(proof)]
    if not events:
        parts.append('<p style="color:#8b949e">No events recorded for this goal.</p>')
    parts.extend(_render_event(event) + "\n" for event in events)
    parts.append(_HTML_TAIL)
    _publish_text(Path(out_path), "".join(parts))
    return len(events)


def export_json(goal_id: int, out_path: Path) -> int:
    """Atomically publish matching events and their proof posture as JSON."""
    events, proof = load_goal_events(goal_id)
    payload = _sanitize(
        json.dumps(
            {"goal_id": goal_id, "proof": proof, "events": events},
            indent=2,
            default=str,
        )
    )
    _publish_text(Path(out_path), payload)
    return len(events)


__all__ = [
    "export_html",
    "export_json",
    "load_goal_events",
    "ReplayEvidenceError",
]
