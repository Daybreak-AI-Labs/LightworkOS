"""Hash-chained, append-only replay traces.

Each committed JSONL record carries a monotonic sequence, writer/run identity,
and a SHA-256 link to the prior record. Appends are serialized across processes
and fsync'd. Readers fail closed on a committed record that is malformed or
whose hash or chain link does not match; only one non-newline-terminated
malformed final fragment is tolerated as the residue of a killed writer.

The chain is an unkeyed hash, so it detects accidental corruption and
reordering, not deliberate rewriting: someone who can write the file can
change records and recompute every hash. For tamper evidence use the signed
audit log (``maverick.audit``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..file_lock import (
    atomic_create_bytes,
    atomic_read_bytes,
    cross_process_lock,
    ensure_private_file,
    open_private_append,
    prepare_private_directory,
)

log = logging.getLogger(__name__)

TRACE_VERSION = 2
MAX_TRACE_FILE_BYTES = 16 * 1024 * 1024
MAX_TRACE_RECORD_BYTES = 256 * 1024
MAX_TRACE_RECORDS = 100_000
MAX_TRACE_NESTING = 32
MAX_TRACE_CONTAINER_ITEMS = 4_096
MAX_TRACE_STRING_CHARS = 128 * 1024
MAX_TRACE_ID_CHARS = 128

_RESERVED_FIELDS = frozenset(
    {"trace_version", "seq", "t", "kind", "writer_id", "run_id", "prev_hash", "hash"}
)


class TraceError(RuntimeError):
    """Base class for replay trace failures."""


class TraceCorruptionError(TraceError):
    """A committed trace record is malformed or fails its hash chain."""


class TraceLimitError(TraceError):
    """A trace input exceeds a bounded resource limit."""


@dataclass(frozen=True)
class _ScanResult:
    events: list[dict]
    valid_bytes: int
    partial_tail: bool
    legacy: bool


def _identity(value: str | None, *, prefix: str) -> str:
    if value is None:
        return f"{prefix}-{uuid.uuid4().hex}"
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_TRACE_ID_CHARS
        or not value.isprintable()
    ):
        raise ValueError(
            f"trace {prefix}_id must be 1-{MAX_TRACE_ID_CHARS} printable characters"
        )
    return value


def _safe(value: Any, *, depth: int = 0) -> Any:
    """Coerce to bounded JSON data without silently truncating evidence."""
    if depth > MAX_TRACE_NESTING:
        raise TraceLimitError("trace field nesting exceeds the limit")
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str) and len(value) > MAX_TRACE_STRING_CHARS:
            raise TraceLimitError("trace string field exceeds the limit")
        return value
    if isinstance(value, int):
        if value.bit_length() > 4096:
            raise TraceLimitError("trace integer field exceeds the limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("trace numeric fields must be finite")
        return value
    if isinstance(value, dict):
        if len(value) > MAX_TRACE_CONTAINER_ITEMS:
            raise TraceLimitError("trace mapping exceeds the item limit")
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if len(key) > MAX_TRACE_ID_CHARS or not key.isprintable():
                raise ValueError("trace mapping keys must be bounded printable strings")
            out[key] = _safe(item, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_TRACE_CONTAINER_ITEMS:
            raise TraceLimitError("trace sequence exceeds the item limit")
        return [_safe(item, depth=depth + 1) for item in value]
    text = str(value)
    if len(text) > MAX_TRACE_STRING_CHARS:
        raise TraceLimitError("trace stringified field exceeds the limit")
    return text


def _canonical_bytes(event: dict) -> bytes:
    payload = {key: value for key, value in event.items() if key != "hash"}
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise TraceCorruptionError("trace record is not canonical JSON") from exc


def _record_hash(event: dict) -> str:
    return hashlib.sha256(_canonical_bytes(event)).hexdigest()


def _parse_record(raw: bytes, *, line_number: int) -> dict:
    if len(raw) > MAX_TRACE_RECORD_BYTES:
        raise TraceLimitError(f"trace record {line_number} exceeds the byte limit")
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TraceCorruptionError(f"trace record {line_number} is malformed") from exc
    if not isinstance(obj, dict):
        raise TraceCorruptionError(f"trace record {line_number} must be an object")
    return obj


def _validate_legacy(events: list[dict]) -> None:
    expected = 1
    for line_number, event in enumerate(events, start=1):
        if event.get("seq") != expected:
            raise TraceCorruptionError(
                f"legacy trace sequence is non-monotonic at record {line_number}"
            )
        if not isinstance(event.get("kind"), str) or not event["kind"]:
            raise TraceCorruptionError(f"legacy trace record {line_number} has no kind")
        expected += 1


def _validate_chained(events: list[dict]) -> None:
    expected_seq = 1
    expected_prev = ""
    authoritative_run_id: str | None = None
    for line_number, event in enumerate(events, start=1):
        required = _RESERVED_FIELDS
        if not required.issubset(event):
            raise TraceCorruptionError(
                f"trace record {line_number} is missing integrity fields"
            )
        if event.get("trace_version") != TRACE_VERSION:
            raise TraceCorruptionError(
                f"trace record {line_number} has an unsupported version"
            )
        if event.get("seq") != expected_seq:
            raise TraceCorruptionError(
                f"trace sequence is non-monotonic at record {line_number}"
            )
        if not isinstance(event.get("t"), (int, float)) or not math.isfinite(event["t"]):
            raise TraceCorruptionError(f"trace record {line_number} has an invalid time")
        for field in ("kind", "writer_id", "run_id"):
            value = event.get(field)
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= MAX_TRACE_ID_CHARS
                or not value.isprintable()
            ):
                raise TraceCorruptionError(
                    f"trace record {line_number} has an invalid {field}"
                )
        record_run_id = event["run_id"]
        if authoritative_run_id is None:
            authoritative_run_id = record_run_id
        elif record_run_id != authoritative_run_id:
            raise TraceCorruptionError(
                f"trace record {line_number} changes the authoritative run_id"
            )
        previous = event.get("prev_hash")
        claimed = event.get("hash")
        if not isinstance(previous, str) or previous != expected_prev:
            raise TraceCorruptionError(
                f"trace hash chain breaks at record {line_number}"
            )
        if (
            not isinstance(claimed, str)
            or len(claimed) != 64
            or any(char not in "0123456789abcdef" for char in claimed)
        ):
            raise TraceCorruptionError(
                f"trace record {line_number} has an invalid hash"
            )
        calculated = _record_hash(event)
        if not hmac.compare_digest(calculated, claimed):
            raise TraceCorruptionError(
                f"trace record {line_number} content does not match its hash"
            )
        expected_seq += 1
        expected_prev = claimed


def _scan_trace(path: Path, *, allow_legacy: bool = False) -> _ScanResult:
    if not path.exists():
        return _ScanResult([], 0, False, False)
    ensure_private_file(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TraceCorruptionError("trace file cannot be inspected") from exc
    if size > MAX_TRACE_FILE_BYTES:
        raise TraceLimitError("trace file exceeds the byte limit")
    try:
        content = atomic_read_bytes(path)
    except OSError as exc:
        raise TraceCorruptionError("trace file cannot be read") from exc
    if len(content) > MAX_TRACE_FILE_BYTES:
        raise TraceLimitError("trace file exceeds the byte limit")

    events: list[dict] = []
    valid_bytes = 0
    partial_tail = False
    chunks = content.splitlines(keepends=True)
    for index, chunk in enumerate(chunks):
        line_number = index + 1
        terminated = chunk.endswith(b"\n")
        raw = chunk[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if index == len(chunks) - 1 and not terminated:
            # Writer commits always end in ``\n``. Even a prefix that happens
            # to parse as JSON is not a committed record without that marker.
            partial_tail = True
            break
        if not raw.strip():
            raise TraceCorruptionError(f"trace record {line_number} is blank")
        try:
            event = _parse_record(raw, line_number=line_number)
        except TraceCorruptionError:
            raise
        events.append(event)
        valid_bytes += len(chunk)
        if len(events) > MAX_TRACE_RECORDS:
            raise TraceLimitError("trace file exceeds the record limit")

    proof_presence = [bool(_RESERVED_FIELDS & event.keys() - {"seq", "t", "kind"})
                      for event in events]
    if any(proof_presence) and not all(proof_presence):
        raise TraceCorruptionError("trace mixes legacy and chained records")
    legacy = bool(events) and not any(proof_presence)
    if legacy:
        _validate_legacy(events)
        if not allow_legacy:
            raise TraceCorruptionError(
                "legacy unsigned trace has no per-record integrity proof"
            )
    else:
        _validate_chained(events)
    return _ScanResult(events, valid_bytes, partial_tail, legacy)


def _truncate_partial(path: Path, length: int) -> None:
    """Discard only the uncommitted final fragment under the caller's lock."""
    ensure_private_file(path)
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        visible = path.lstat()
        opened = os.fstat(fd)
        if (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino):
            raise TraceCorruptionError("trace identity changed during recovery")
        os.ftruncate(fd, length)
        os.fsync(fd)
    finally:
        os.close(fd)


class TraceWriter:
    """Append chained events to a private JSONL trace."""

    def __init__(
        self,
        path: str | Path,
        *,
        writer_id: str | None = None,
        run_id: str | None = None,
    ):
        self.path = Path(path)
        self.writer_id = _identity(writer_id, prefix="writer")
        self._run_id_explicit = run_id is not None
        requested_run_id = _identity(run_id, prefix="run")
        self._closed = False
        try:
            prepare_private_directory(self.path.parent)
        except OSError as exc:
            # Callers that treat tracing as optional swallow this, so say why
            # nothing is being recorded.
            log.warning(
                "replay trace is not being recorded: trace folder %s cannot be used (%s)",
                self.path.parent, exc)
            raise
        with cross_process_lock(self.path, strict=True):
            try:
                atomic_create_bytes(self.path, b"")
            except FileExistsError:
                ensure_private_file(self.path)
            scan = _scan_trace(self.path)
            if scan.events:
                authoritative_run_id = scan.events[0]["run_id"]
                if self._run_id_explicit and requested_run_id != authoritative_run_id:
                    raise TraceCorruptionError(
                        "trace run_id does not match the committed run"
                    )
                self.run_id = authoritative_run_id
            else:
                self.run_id = requested_run_id

    def record(self, kind: str, **fields: Any) -> int:
        """Durably append one ordered event and return its sequence number."""
        if self._closed:
            raise ValueError("trace writer is closed")
        if (
            not isinstance(kind, str)
            or not 1 <= len(kind) <= MAX_TRACE_ID_CHARS
            or not kind.isprintable()
        ):
            raise ValueError("trace kind must be a bounded printable string")
        collisions = _RESERVED_FIELDS.intersection(fields)
        if collisions:
            raise ValueError("trace fields may not replace integrity metadata")
        safe_fields = {key: _safe(value) for key, value in fields.items()}

        with cross_process_lock(self.path, strict=True):
            scan = _scan_trace(self.path)
            if scan.legacy:
                raise TraceCorruptionError(
                    "legacy unsigned trace cannot be extended; start a new trace path"
                )
            if scan.partial_tail:
                _truncate_partial(self.path, scan.valid_bytes)
            if scan.events:
                authoritative_run_id = scan.events[0]["run_id"]
                if self._run_id_explicit and self.run_id != authoritative_run_id:
                    raise TraceCorruptionError(
                        "trace run_id does not match the committed run"
                    )
                self.run_id = authoritative_run_id
            previous = scan.events[-1]["hash"] if scan.events else ""
            seq = int(scan.events[-1]["seq"]) + 1 if scan.events else 1
            event = {
                "trace_version": TRACE_VERSION,
                "seq": seq,
                "t": round(time.time(), 6),
                "kind": kind,
                "writer_id": self.writer_id,
                "run_id": self.run_id,
                "prev_hash": previous,
                **safe_fields,
            }
            event["hash"] = _record_hash(event)
            encoded = json.dumps(
                event,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8") + b"\n"
            if len(encoded) > MAX_TRACE_RECORD_BYTES:
                raise TraceLimitError("trace record exceeds the byte limit")
            if scan.valid_bytes + len(encoded) > MAX_TRACE_FILE_BYTES:
                raise TraceLimitError("trace file exceeds the byte limit")
            fd = open_private_append(
                self.path,
                require_private_parent=True,
            )
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("trace append made no progress")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            return seq

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> TraceWriter:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def read_trace(path: str | Path, *, allow_legacy: bool = False) -> list[dict]:
    """Read and verify a bounded trace, tolerating one final partial record.

    Legacy unsigned traces are refused by default because an attacker could
    otherwise strip every v2 integrity field and have forged rows accepted as
    an old file. ``allow_legacy=True`` is an explicit forensic compatibility
    escape hatch; :func:`replay` never enables it.
    """
    p = Path(path)
    if not p.exists():
        return []
    prepare_private_directory(p.parent)
    return list(_scan_trace(p, allow_legacy=allow_legacy).events)


def trace_dir() -> Path | None:
    """The folder run traces are recorded in, or ``None`` when recording is off.

    ``MAVERICK_TRACE_DIR`` always wins. Otherwise ``[replay] record = true``
    (Settings > All settings) turns recording on, into ``[replay] trace_dir``
    or, when that is empty, Lightwork's own ``traces`` folder. With neither
    set nothing is recorded, as before.
    """
    base = os.environ.get("MAVERICK_TRACE_DIR")
    if base:
        return Path(base)
    try:
        from ..config import load_config

        section = (load_config() or {}).get("replay") or {}
    except Exception:  # an unreadable configuration never turns recording on
        return None
    if not isinstance(section, dict) or section.get("record") is not True:
        return None
    folder = str(section.get("trace_dir") or "").strip()
    if folder:
        return Path(folder).expanduser()
    from ..paths import data_dir

    return Path(data_dir("traces"))


def goal_trace_path(goal_id: int) -> Path | None:
    """Where a run of ``goal_id`` records its trace --
    ``<trace folder>/goal-<id>.jsonl`` -- or ``None`` when tracing is off.
    The one naming rule the orchestrator writes by and readers find it by."""
    base = trace_dir()
    if base is None:
        return None
    return base / f"goal-{int(goal_id)}.jsonl"


def replay(path: str | Path, handlers: dict[str, Callable[[dict], Any]]) -> int:
    """Verify and dispatch committed events in their recorded sequence."""
    events = read_trace(path)
    count = 0
    for event in events:
        handler = handlers.get(event.get("kind", "")) or handlers.get("*")
        if handler is not None:
            handler(event)
            count += 1
    return count


__all__ = [
    "TraceWriter",
    "goal_trace_path",
    "read_trace",
    "replay",
    "TraceError",
    "TraceCorruptionError",
    "TraceLimitError",
    "TRACE_VERSION",
    "MAX_TRACE_FILE_BYTES",
    "MAX_TRACE_RECORD_BYTES",
    "MAX_TRACE_RECORDS",
]
