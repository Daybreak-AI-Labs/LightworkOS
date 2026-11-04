"""Segmented, indexed storage for signed AI evidence receipts.

The receipt body and its Ed25519 signature remain the authority.  This module
only changes how those immutable rows are laid out and discovered:

* the historical ``interaction_receipts.ndjson`` file remains segment zero;
* later segments start with a signed header that commits to the prior segment;
* a signed state snapshot commits to the current physical tip and index chain;
* a SQLite identity/ordinal index accelerates idempotency and pagination.

The index is never trusted on its own.  Targeted reads bind an index entry back
to the signed row, while full verification streams every segment and compares
it with every index entry.  Crash reconciliation accepts only an append-only
extension of the last signed state; truncation or divergence fails closed.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import stat
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constant_time import text_equals

SEGMENT_HEADER_SCHEMA = "lightwork.ai-evidence-receipt-segment.v1"
SEGMENT_HEADER_EVENT = "ai_evidence_receipt_segment_opened"
INDEX_STATE_SCHEMA = "lightwork.ai-evidence-receipt-index-state.v1"
INDEX_STATE_EVENT = "ai_evidence_receipt_index_state"

_SEGMENT_RE = re.compile(r"segment-([0-9]{8})\.ndjson\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID_RE = re.compile(r"[0-9a-f]{16}\Z")
_MAX_PHYSICAL_ROWS_PER_SEGMENT = 1_000_001
_INDEX_SCHEMA_VERSION = 1
_CURSOR_VERSION = 1
_TAIL_PROBE_BYTES = 2 * 1024 * 1024


class SegmentedLedgerError(RuntimeError):
    """Segmented receipt evidence cannot be read or advanced safely."""


@dataclass(frozen=True)
class LedgerEntry:
    """One immutable receipt location in global append order."""

    ordinal: int
    identity: str
    row_hash: str
    payload_sha256: str
    segment: int
    line_number: int


@dataclass(frozen=True)
class LedgerState:
    """Authenticated physical/index tip used for bounded fast-path checks."""

    generation: int
    total_receipts: int
    identity_chain_tip: str
    segment_count: int
    active_segment: int
    active_file_row_count: int
    active_segment_receipt_count: int
    active_segment_tip: str
    previous_state_hash: str
    state_hash: str
    updated_at: float


@dataclass(frozen=True)
class LedgerPage:
    """A stable page over an append-only receipt snapshot."""

    entries: tuple[LedgerEntry, ...]
    next_cursor: str | None
    snapshot_total: int


@dataclass(frozen=True)
class _ScanSummary:
    total_receipts: int
    identity_chain_tip: str
    segment_count: int
    active_segment: int
    active_file_row_count: int
    active_segment_receipt_count: int
    active_segment_tip: str
    prefix_identity_chain_tip: str
    prefix_active_tip: str


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256(value: bytes | str | object) -> str:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = _canonical_json(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _estimated_signed_row_bytes(
    event: Mapping[str, Any],
    *,
    chained: bool,
) -> int:
    """Exact encoded row size for AuditSigner's fixed-width signing fields."""

    payload = dict(event)
    payload["prev_hash"] = "0" * 64 if chained else ""
    payload["key_id"] = "0" * 16
    payload["hash"] = "0" * 64
    payload["sig"] = "0" * 128
    return len(
        (
            json.dumps(
                payload,
                default=str,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    )


def _identity_tip(previous: str, entry: LedgerEntry) -> str:
    prior = bytes.fromhex(previous) if previous else b"\0" * 32
    body = _canonical_json(
        {
            "identity": entry.identity,
            "line_number": entry.line_number,
            "ordinal": entry.ordinal,
            "payload_sha256": entry.payload_sha256,
            "row_hash": entry.row_hash,
            "segment": entry.segment,
        }
    ).encode("utf-8")
    return hashlib.sha256(prior + body).hexdigest()


def _fsync_directory(path: Path) -> None:
    """Persist a published pathname on platforms that expose directory fsync."""

    if os.name == "nt":
        return
    descriptor = os.open(
        str(path),
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sqlite_rebuild_artifacts(path: Path) -> tuple[Path, ...]:
    return (
        path,
        Path(f"{path}-journal"),
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
    )


def _iter_strict_rows(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield strict JSON rows without materializing a whole evidence segment."""

    from .file_lock import ensure_private_file

    try:
        ensure_private_file(path, 0o600)
        stream = path.open(encoding="utf-8")
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SegmentedLedgerError(
            f"signed receipt segment is unreadable: {path.name}"
        ) from exc
    try:
        with stream:
            for number, raw in enumerate(stream, start=1):
                if number > _MAX_PHYSICAL_ROWS_PER_SEGMENT:
                    raise SegmentedLedgerError(
                        "signed receipt segment exceeds its physical safety "
                        f"bound: {path.name}"
                    )
                if not raw.strip():
                    raise SegmentedLedgerError(
                        "signed receipt segment contains a blank row: "
                        f"{path.name}:{number}"
                    )
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise SegmentedLedgerError(
                        "signed receipt segment contains malformed JSON: "
                        f"{path.name}:{number}"
                    ) from exc
                if not isinstance(row, dict):
                    raise SegmentedLedgerError(
                        "signed receipt segment contains a non-object row: "
                        f"{path.name}:{number}"
                    )
                yield number, row
    except (OSError, UnicodeError) as exc:
        raise SegmentedLedgerError(
            f"signed receipt segment is unreadable: {path.name}"
        ) from exc


def _verify_chained_row(
    row: dict[str, Any],
    *,
    previous: str,
    public_keys: dict[str, Any],
    registry: Mapping[str, str],
    path_name: str,
    row_ref: str,
) -> None:
    """Verify one signed row's chain link, hash, and Ed25519 signature.

    Shared by the full-segment scan (:func:`_iter_verified_rows`, verifying
    every row from genesis) and the append-time tail check
    (:meth:`SegmentedReceiptLedger._verify_appended_row`, verifying only the
    row just written) so what "verified" means can never quietly drift
    between the two call sites. ``public_keys`` is a same-shape ``key_id ->
    Ed25519PublicKey`` cache at both call sites; a newly-seen key is added to
    it. Raises :class:`SegmentedLedgerError` (using ``path_name``/``row_ref``
    for the message) on any failure.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    key_id = row.get("key_id")
    row_hash = row.get("hash")
    signature = row.get("sig")
    row_previous = row.get("prev_hash")
    if (
        not isinstance(key_id, str)
        or not _KEY_ID_RE.fullmatch(key_id)
        or not isinstance(row_hash, str)
        or not _DIGEST_RE.fullmatch(row_hash)
        or not isinstance(signature, str)
        or len(signature) != 128
        or not isinstance(row_previous, str)
        or (
            row_previous != ""
            and not _DIGEST_RE.fullmatch(row_previous)
        )
        or not hmac.compare_digest(row_previous, previous)
    ):
        raise SegmentedLedgerError(
            f"signed receipt segment failed verification: {path_name} "
            f"(invalid chain row {row_ref})"
        )
    unsigned = {
        key: value
        for key, value in row.items()
        if key not in {"hash", "sig"}
    }
    try:
        expected_hash = hashlib.sha256(
            json.dumps(
                unsigned,
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError) as exc:
        raise SegmentedLedgerError(
            f"signed receipt segment failed verification: {path_name} "
            f"(unhashable row {row_ref})"
        ) from exc
    if not hmac.compare_digest(expected_hash, row_hash):
        raise SegmentedLedgerError(
            f"signed receipt segment failed verification: {path_name} "
            f"(hash mismatch at row {row_ref})"
        )
    try:
        public_key = public_keys.get(key_id)
        if public_key is None:
            public_hex = registry.get(key_id)
            if not isinstance(public_hex, str):
                raise ValueError("unknown signing key")
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_hex)
            )
            public_keys[key_id] = public_key
        public_key.verify(
            bytes.fromhex(signature),
            bytes.fromhex(row_hash),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise SegmentedLedgerError(
            f"signed receipt segment failed verification: {path_name} "
            f"(bad signature at row {row_ref})"
        ) from exc


def _iter_verified_rows(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield one segment while verifying its chain and every signature.

    Keeping verification and consumption in the same pass avoids a time-of-
    check/time-of-use window on the append-only file and halves the I/O cost of
    full assurance scans.  Callers that pin a signed :class:`LedgerState` still
    perform an end-state comparison; a concurrent legitimate append therefore
    causes a retry rather than a false integrity finding.
    """

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    from .audit.signing import trusted_audit_public_keys

    try:
        registry = trusted_audit_public_keys()
    except (OSError, TypeError, ValueError) as exc:
        raise SegmentedLedgerError(
            "audit public-key registry is unavailable"
        ) from exc
    public_keys: dict[str, Ed25519PublicKey] = {}
    previous = ""
    count = 0
    for line_number, row in _iter_strict_rows(path):
        count = line_number
        _verify_chained_row(
            row,
            previous=previous,
            public_keys=public_keys,
            registry=registry,
            path_name=path.name,
            row_ref=str(line_number),
        )
        previous = str(row.get("hash") or "")
        yield line_number, row
    if count == 0:
        raise SegmentedLedgerError(
            f"signed receipt segment is unexpectedly empty: {path.name}"
        )


def _iter_verified_rows_read_only(
    path: Path,
    trusted_public_keys: Mapping[str, str],
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Verify one segment without chmod, lock creation, or trust provisioning."""

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    from .file_lock import private_path_is_restricted

    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not private_path_is_restricted(path, 0o600)
        ):
            raise SegmentedLedgerError(
                f"signed receipt segment is unsafe: {path.name}"
            )
        stream = path.open(encoding="utf-8")
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SegmentedLedgerError(
            f"signed receipt segment is unreadable: {path.name}"
        ) from exc
    public_keys: dict[str, Ed25519PublicKey] = {}
    previous = ""
    count = 0
    try:
        with stream:
            for line_number, raw in enumerate(stream, start=1):
                count = line_number
                if line_number > _MAX_PHYSICAL_ROWS_PER_SEGMENT:
                    raise SegmentedLedgerError(
                        "signed receipt segment exceeds its physical safety "
                        f"bound: {path.name}"
                    )
                if not raw.strip():
                    raise SegmentedLedgerError(
                        "signed receipt segment contains a blank row: "
                        f"{path.name}:{line_number}"
                    )
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise SegmentedLedgerError(
                        "signed receipt segment contains malformed JSON: "
                        f"{path.name}:{line_number}"
                    ) from exc
                if not isinstance(row, dict):
                    raise SegmentedLedgerError(
                        "signed receipt segment contains a non-object row: "
                        f"{path.name}:{line_number}"
                    )
                key_id = row.get("key_id")
                row_hash = row.get("hash")
                signature = row.get("sig")
                row_previous = row.get("prev_hash")
                if (
                    not isinstance(key_id, str)
                    or not _KEY_ID_RE.fullmatch(key_id)
                    or not isinstance(row_hash, str)
                    or not _DIGEST_RE.fullmatch(row_hash)
                    or not isinstance(signature, str)
                    or len(signature) != 128
                    or not isinstance(row_previous, str)
                    or (
                        row_previous != ""
                        and not _DIGEST_RE.fullmatch(row_previous)
                    )
                    or not hmac.compare_digest(row_previous, previous)
                ):
                    raise SegmentedLedgerError(
                        "signed receipt segment failed verification: "
                        f"{path.name} (invalid chain row {line_number})"
                    )
                unsigned = {
                    key: value
                    for key, value in row.items()
                    if key not in {"hash", "sig"}
                }
                expected_hash = hashlib.sha256(
                    json.dumps(
                        unsigned,
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest()
                if not hmac.compare_digest(expected_hash, row_hash):
                    raise SegmentedLedgerError(
                        "signed receipt segment failed verification: "
                        f"{path.name} (hash mismatch at row {line_number})"
                    )
                try:
                    public_key = public_keys.get(key_id)
                    if public_key is None:
                        public_hex = trusted_public_keys.get(key_id)
                        if not isinstance(public_hex, str):
                            raise ValueError("unknown signing key")
                        public_key = Ed25519PublicKey.from_public_bytes(
                            bytes.fromhex(public_hex)
                        )
                        public_keys[key_id] = public_key
                    public_key.verify(
                        bytes.fromhex(signature),
                        bytes.fromhex(row_hash),
                    )
                except (InvalidSignature, TypeError, ValueError) as exc:
                    raise SegmentedLedgerError(
                        "signed receipt segment failed verification: "
                        f"{path.name} (bad signature at row {line_number})"
                    ) from exc
                previous = row_hash
                yield line_number, row
    except (OSError, UnicodeError) as exc:
        raise SegmentedLedgerError(
            f"signed receipt segment is unreadable: {path.name}"
        ) from exc
    if count == 0:
        raise SegmentedLedgerError(
            f"signed receipt segment is unexpectedly empty: {path.name}"
        )


def _signed_snapshot(body: Mapping[str, Any]) -> dict[str, Any]:
    """Sign one replaceable state snapshot with the audit signing authority."""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from .audit.signing import _load_or_create_keypair

    private_bytes, public_bytes, key_id = _load_or_create_keypair()
    if (
        len(private_bytes) != 32
        or len(public_bytes) != 32
        or not _KEY_ID_RE.fullmatch(key_id)
        or hashlib.sha256(public_bytes).hexdigest()[:16] != key_id
    ):
        raise SegmentedLedgerError("audit signing authority is invalid")
    payload = dict(body)
    payload["key_id"] = key_id
    row_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    payload["hash"] = row_hash
    payload["sig"] = (
        Ed25519PrivateKey.from_private_bytes(private_bytes)
        .sign(bytes.fromhex(row_hash))
        .hex()
    )
    return payload


def _verify_snapshot(
    row: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, str] | None = None,
) -> bool:
    from .audit.signing import verify_ed25519

    try:
        key_id = row.get("key_id")
        row_hash = row.get("hash")
        signature = row.get("sig")
        if (
            not isinstance(key_id, str)
            or not _KEY_ID_RE.fullmatch(key_id)
            or not isinstance(row_hash, str)
            or not _DIGEST_RE.fullmatch(row_hash)
            or not isinstance(signature, str)
        ):
            return False
        if trusted_public_keys is None:
            from .audit.signing import trusted_audit_public_keys

            registry = trusted_audit_public_keys()
        else:
            registry = trusted_public_keys
        public_key = registry.get(key_id)
        if not isinstance(public_key, str):
            return False
        unsigned = {
            key: value for key, value in row.items() if key not in {"hash", "sig"}
        }
        expected = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return hmac.compare_digest(expected, row_hash) and verify_ed25519(
            public_key,
            signature,
            bytes.fromhex(row_hash),
        )
    except (OSError, TypeError, ValueError):
        return False


class SegmentedReceiptLedger:
    """Append-only segmented receipt ledger with a signed crash-recovery index."""

    def __init__(
        self,
        legacy_path: Path,
        *,
        tenant_id: str,
        identity_key: str = "receipt_id",
        payload_key: str = "receipt_payload_sha256",
        segment_rows: int = 4_096,
        segment_bytes: int = 64 * 1024 * 1024,
        max_receipts: int = 1_000_000,
    ) -> None:
        if (
            isinstance(segment_rows, bool)
            or not isinstance(segment_rows, int)
            or segment_rows < 1
            or segment_rows > 1_000_000
        ):
            raise ValueError("receipt segment row limit must be between 1 and 1000000")
        if (
            isinstance(segment_bytes, bool)
            or not isinstance(segment_bytes, int)
            or segment_bytes < 1024 * 1024
            or segment_bytes > 1024 * 1024 * 1024
        ):
            raise ValueError(
                "receipt segment byte limit must be between 1048576 and 1073741824"
            )
        if (
            isinstance(max_receipts, bool)
            or not isinstance(max_receipts, int)
            or max_receipts < 1
            or max_receipts > 100_000_000
        ):
            raise ValueError("receipt capacity must be between 1 and 100000000")
        identity_field = str(identity_key)
        payload_field = str(payload_key)
        reserved = {"prev_hash", "key_id", "hash", "sig"}
        if (
            not identity_field
            or not payload_field
            or identity_field == payload_field
            or identity_field in reserved
            or payload_field in reserved
        ):
            raise ValueError(
                "receipt identity and payload fields must be distinct, "
                "non-reserved names"
            )
        self.legacy_path = Path(legacy_path)
        self.tenant_sha256 = _sha256(str(tenant_id).encode("utf-8"))
        self.identity_key = identity_field
        self.payload_key = payload_field
        self.segment_rows = segment_rows
        self.segment_bytes = segment_bytes
        self.max_receipts = max_receipts
        stem = self.legacy_path.stem
        self.segment_dir = self.legacy_path.with_name(f"{stem}.segments")
        self.index_path = self.legacy_path.with_name(f"{stem}.index.sqlite3")
        self.state_path = self.legacy_path.with_name(f"{stem}.index-state.json")
        self.lock_target = self.legacy_path.with_name(
            f"{self.legacy_path.name}.identity-transaction"
        )

    def _segment_path(self, number: int) -> Path:
        if number == 0:
            return self.legacy_path
        return self.segment_dir / f"segment-{number:08d}.ndjson"

    def _numbered_segments(self) -> list[tuple[int, Path]]:
        if not self.segment_dir.exists():
            return []
        from .file_lock import ensure_private_directory

        try:
            ensure_private_directory(self.segment_dir)
            children = list(self.segment_dir.iterdir())
        except OSError as exc:
            raise SegmentedLedgerError(
                "signed receipt segment directory is unreadable"
            ) from exc
        numbered: list[tuple[int, Path]] = []
        for path in children:
            match = _SEGMENT_RE.fullmatch(path.name)
            if match is None:
                # AuditSigner/cross_process_lock owns one durable private
                # sidecar per segment.  It is coordination state, not evidence.
                if (
                    path.name.endswith(".ndjson.lock")
                    and _SEGMENT_RE.fullmatch(path.name[:-5])
                    and stat.S_ISREG(path.lstat().st_mode)
                ):
                    continue
                raise SegmentedLedgerError(
                    f"signed receipt segment directory contains an unexpected "
                    f"entry: {path.name}"
                )
            try:
                info = path.lstat()
            except OSError as exc:
                raise SegmentedLedgerError(
                    f"signed receipt segment cannot be inspected: {path.name}"
                ) from exc
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
            ):
                raise SegmentedLedgerError(
                    f"signed receipt segment is not a regular file: {path.name}"
                )
            numbered.append((int(match.group(1)), path))
        numbered.sort()
        expected = list(range(1, len(numbered) + 1))
        if [number for number, _path in numbered] != expected:
            raise SegmentedLedgerError(
                "signed receipt segment sequence is missing or duplicated"
            )
        return numbered

    def _physical_segments(self) -> list[tuple[int, Path]]:
        segments: list[tuple[int, Path]] = []
        try:
            legacy_nonempty = (
                self.legacy_path.exists() and self.legacy_path.stat().st_size > 0
            )
        except OSError as exc:
            raise SegmentedLedgerError(
                "legacy signed receipt segment is unreadable"
            ) from exc
        if legacy_nonempty:
            segments.append((0, self.legacy_path))
        segments.extend(self._numbered_segments())
        return segments

    def _verify_file(
        self,
        path: Path,
    ) -> tuple[int, dict[str, Any]]:
        """Stream-verify one segment without loading its full contents."""

        count = 0
        last_row: dict[str, Any] | None = None
        for line_number, row in _iter_verified_rows(path):
            count = line_number
            last_row = row
        assert last_row is not None
        return count, last_row

    def _verify_appended_row(
        self,
        path: Path,
        *,
        offset_before: int,
        expected_previous: str,
    ) -> dict[str, Any]:
        """Verify ONLY the row just written at ``offset_before``, not the
        whole segment.

        ``append()`` holds ``cross_process_lock`` for its entire duration and
        has already reconciled ``state`` against the physical file moments
        earlier (``_ensure_ready_locked``), so no other writer could have
        appended between then and now. What remains to prove is narrower than
        "is this whole segment intact": it is "did the single row I just
        asked ``AuditSigner`` to write land correctly, chained to the tip I
        expected". Re-streaming every prior row on every append made a single
        delivery's cost grow with the whole segment (measured 64ms -> 237ms
        across a 4,096-row segment) under a lock that serializes ALL
        governed-output delivery. Full prefix verification is preserved
        everywhere else: crash reconciliation (``_rebuild_locked``/``_scan``)
        and explicit integrity checks still stream and verify every row from
        genesis.

        Reads exactly the bytes written after ``offset_before`` (the file's
        pre-write size), so an arbitrarily large single row is still read in
        full -- unlike the bounded tail probe :meth:`_quick_physical_matches`
        uses for its cheaper "does state look plausible" check, this seam
        needs a definite answer, not a probe.
        """
        from .audit.signing import trusted_audit_public_keys

        try:
            with path.open("rb") as stream:
                stream.seek(offset_before)
                tail_bytes = stream.read()
        except OSError as exc:
            raise SegmentedLedgerError(
                f"signed receipt segment is unreadable after append: {path.name}"
            ) from exc
        if not tail_bytes.endswith(b"\n") or tail_bytes.count(b"\n") != 1:
            raise SegmentedLedgerError(
                "signed receipt segment failed verification: "
                f"{path.name} (malformed row after append)"
            )
        raw = tail_bytes[:-1]
        if not raw.strip():
            raise SegmentedLedgerError(
                "signed receipt segment failed verification: "
                f"{path.name} (blank row after append)"
            )
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SegmentedLedgerError(
                "signed receipt segment failed verification: "
                f"{path.name} (malformed JSON after append)"
            ) from exc
        if not isinstance(row, dict):
            raise SegmentedLedgerError(
                "signed receipt segment failed verification: "
                f"{path.name} (non-object row after append)"
            )
        try:
            registry = trusted_audit_public_keys()
        except (OSError, TypeError, ValueError) as exc:
            raise SegmentedLedgerError(
                "audit public-key registry is unavailable"
            ) from exc
        _verify_chained_row(
            row,
            previous=expected_previous,
            public_keys={},
            registry=registry,
            path_name=path.name,
            row_ref="just-appended",
        )
        return row

    def _scan(
        self,
        *,
        on_entry: Callable[[LedgerEntry], None] | None = None,
        prefix_state: LedgerState | None = None,
        physical_segments: Sequence[tuple[int, Path]] | None = None,
        row_reader: Callable[
            [Path],
            Iterator[tuple[int, dict[str, Any]]],
        ] = _iter_verified_rows,
    ) -> _ScanSummary:
        segments = (
            self._physical_segments()
            if physical_segments is None
            else list(physical_segments)
        )
        total = 0
        identity_chain_tip = ""
        previous_number = 0
        previous_tip = ""
        previous_receipt_count = 0
        prefix_identity_tip = "" if prefix_state is None else "__not_reached__"
        prefix_active_tip = ""
        active_segment = 0
        active_file_rows = 0
        active_receipts = 0
        active_tip = ""
        for segment_number, path in segments:
            header: dict[str, Any] | None = None
            segment_receipts = 0
            file_rows = 0
            segment_tip = ""
            for line_number, row in row_reader(path):
                file_rows = line_number
                segment_tip = str(row.get("hash") or "")
                if (
                    prefix_state is not None
                    and segment_number == prefix_state.active_segment
                    and line_number == prefix_state.active_file_row_count
                ):
                    prefix_active_tip = segment_tip
                if segment_number > 0 and line_number == 1:
                    header = row
                    expected_keys = {
                        "schema",
                        "event",
                        "tenant_sha256",
                        "segment",
                        "previous_segment",
                        "previous_segment_tip",
                        "previous_segment_receipt_count",
                        "previous_total_receipts",
                        "opened_at",
                        "segment_row_limit",
                        "segment_byte_limit",
                        "prev_hash",
                        "key_id",
                        "hash",
                        "sig",
                    }
                    opened_at = header.get("opened_at")
                    if (
                        set(header) != expected_keys
                        or header.get("schema") != SEGMENT_HEADER_SCHEMA
                        or header.get("event") != SEGMENT_HEADER_EVENT
                        or header.get("tenant_sha256") != self.tenant_sha256
                        or header.get("segment") != segment_number
                        or header.get("previous_segment") != previous_number
                        or header.get("previous_segment_tip") != previous_tip
                        or header.get("previous_segment_receipt_count")
                        != previous_receipt_count
                        or header.get("previous_total_receipts") != total
                        or isinstance(opened_at, bool)
                        or not isinstance(opened_at, (int, float))
                        or not math.isfinite(float(opened_at))
                        or float(opened_at) <= 0
                        or isinstance(header.get("segment_row_limit"), bool)
                        or not isinstance(header.get("segment_row_limit"), int)
                        or int(header["segment_row_limit"]) < 1
                        or int(header["segment_row_limit"]) > 1_000_000
                        or isinstance(header.get("segment_byte_limit"), bool)
                        or not isinstance(header.get("segment_byte_limit"), int)
                        or int(header["segment_byte_limit"]) < 1024 * 1024
                        or int(header["segment_byte_limit"])
                        > 1024 * 1024 * 1024
                        or header.get("prev_hash") != ""
                    ):
                        raise SegmentedLedgerError(
                            "signed receipt segment header is invalid: "
                            f"{path.name}"
                        )
                    continue
                if (
                    segment_number == 0
                    and row.get("schema") == SEGMENT_HEADER_SCHEMA
                ):
                    raise SegmentedLedgerError(
                        "legacy receipt segment contains a numbered-segment "
                        "header"
                    )
                identity = row.get(self.identity_key)
                row_hash = row.get("hash")
                payload = row.get(self.payload_key)
                if (
                    not isinstance(identity, str)
                    or not identity
                    or not isinstance(row_hash, str)
                    or not _DIGEST_RE.fullmatch(row_hash)
                    or not isinstance(payload, str)
                    or not _DIGEST_RE.fullmatch(payload)
                ):
                    raise SegmentedLedgerError(
                        f"signed receipt row identity is invalid: "
                        f"{path.name}:{line_number}"
                    )
                total += 1
                segment_receipts += 1
                entry = LedgerEntry(
                    ordinal=total,
                    identity=identity,
                    row_hash=row_hash,
                    payload_sha256=payload,
                    segment=segment_number,
                    line_number=line_number,
                )
                identity_chain_tip = _identity_tip(identity_chain_tip, entry)
                if on_entry is not None:
                    on_entry(entry)
                if prefix_state is not None and total == prefix_state.total_receipts:
                    prefix_identity_tip = identity_chain_tip
            if file_rows == 0:
                raise SegmentedLedgerError(
                    f"signed receipt segment is unexpectedly empty: {path.name}"
                )
            if segment_number > 0:
                if header is None:
                    raise SegmentedLedgerError(
                        f"signed receipt segment has no header: {path.name}"
                    )
                try:
                    segment_size = path.stat().st_size
                except OSError as exc:
                    raise SegmentedLedgerError(
                        f"signed receipt segment size is unavailable: {path.name}"
                    ) from exc
                if (
                    segment_receipts > int(header["segment_row_limit"])
                    or segment_size > int(header["segment_byte_limit"])
                ):
                    raise SegmentedLedgerError(
                        f"signed receipt segment exceeds its authenticated "
                        f"storage bound: {path.name}"
                    )
            active_segment = segment_number
            active_file_rows = file_rows
            active_receipts = segment_receipts
            active_tip = segment_tip
            previous_number = segment_number
            previous_tip = active_tip
            previous_receipt_count = segment_receipts
        if prefix_state is not None and prefix_state.total_receipts == 0:
            prefix_identity_tip = ""
            if prefix_state.active_file_row_count == 0:
                prefix_active_tip = ""
        return _ScanSummary(
            total_receipts=total,
            identity_chain_tip=identity_chain_tip,
            segment_count=len(segments),
            active_segment=active_segment,
            active_file_row_count=active_file_rows,
            active_segment_receipt_count=active_receipts,
            active_segment_tip=active_tip,
            prefix_identity_chain_tip=prefix_identity_tip,
            prefix_active_tip=prefix_active_tip,
        )

    def _state_body(
        self,
        summary: _ScanSummary,
        *,
        generation: int,
        previous_state_hash: str,
    ) -> dict[str, Any]:
        return {
            "schema": INDEX_STATE_SCHEMA,
            "event": INDEX_STATE_EVENT,
            "version": _INDEX_SCHEMA_VERSION,
            "tenant_sha256": self.tenant_sha256,
            "generation": generation,
            "total_receipts": summary.total_receipts,
            "identity_chain_tip": summary.identity_chain_tip,
            "segment_count": summary.segment_count,
            "active_segment": summary.active_segment,
            "active_file_row_count": summary.active_file_row_count,
            "active_segment_receipt_count": (
                summary.active_segment_receipt_count
            ),
            "active_segment_tip": summary.active_segment_tip,
            "segment_row_limit": self.segment_rows,
            "segment_byte_limit": self.segment_bytes,
            "receipt_capacity": self.max_receipts,
            "updated_at": time.time(),
            "prev_hash": previous_state_hash,
        }

    def _write_state(
        self,
        summary: _ScanSummary,
        *,
        generation: int,
        previous_state_hash: str,
    ) -> LedgerState:
        from .file_lock import atomic_write_text, ensure_private_directory

        ensure_private_directory(self.state_path.parent)
        row = _signed_snapshot(
            self._state_body(
                summary,
                generation=generation,
                previous_state_hash=previous_state_hash,
            )
        )
        atomic_write_text(
            self.state_path,
            _canonical_json(row) + "\n",
            mode=0o600,
        )
        return self._parse_state(row)

    def _parse_state(
        self,
        row: Mapping[str, Any],
        *,
        trusted_public_keys: Mapping[str, str] | None = None,
    ) -> LedgerState:
        expected_keys = {
            "schema",
            "event",
            "version",
            "tenant_sha256",
            "generation",
            "total_receipts",
            "identity_chain_tip",
            "segment_count",
            "active_segment",
            "active_file_row_count",
            "active_segment_receipt_count",
            "active_segment_tip",
            "segment_row_limit",
            "segment_byte_limit",
            "receipt_capacity",
            "updated_at",
            "prev_hash",
            "key_id",
            "hash",
            "sig",
        }
        try:
            numeric = (
                row["generation"],
                row["total_receipts"],
                row["segment_count"],
                row["active_segment"],
                row["active_file_row_count"],
                row["active_segment_receipt_count"],
                row["segment_row_limit"],
                row["segment_byte_limit"],
                row["receipt_capacity"],
            )
            updated_at = float(row["updated_at"])
            if (
                set(row) != expected_keys
                or row["schema"] != INDEX_STATE_SCHEMA
                or row["event"] != INDEX_STATE_EVENT
                or row["version"] != _INDEX_SCHEMA_VERSION
                or row["tenant_sha256"] != self.tenant_sha256
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                    for value in numeric
                )
                or row["generation"] < 1
                or not 1 <= row["segment_row_limit"] <= 1_000_000
                or not 1024 * 1024
                <= row["segment_byte_limit"]
                <= 1024 * 1024 * 1024
                or not 1 <= row["receipt_capacity"] <= 100_000_000
                or row["total_receipts"] < row[
                    "active_segment_receipt_count"
                ]
                or (
                    row["active_segment"] == 0
                    and row["active_file_row_count"]
                    != row["active_segment_receipt_count"]
                )
                or (
                    row["active_segment"] > 0
                    and row["active_file_row_count"]
                    != row["active_segment_receipt_count"] + 1
                )
                or (
                    row["segment_count"] == 0
                    and (
                        row["total_receipts"] != 0
                        or row["active_segment"] != 0
                        or row["active_file_row_count"] != 0
                        or row["active_segment_receipt_count"] != 0
                    )
                )
                or (
                    row["segment_count"] > 0
                    and row["active_file_row_count"] == 0
                )
                or not isinstance(row["identity_chain_tip"], str)
                or (
                    row["identity_chain_tip"]
                    and not _DIGEST_RE.fullmatch(row["identity_chain_tip"])
                )
                or not isinstance(row["active_segment_tip"], str)
                or (
                    row["active_segment_tip"]
                    and not _DIGEST_RE.fullmatch(row["active_segment_tip"])
                )
                or not isinstance(row["prev_hash"], str)
                or (
                    row["prev_hash"]
                    and not _DIGEST_RE.fullmatch(row["prev_hash"])
                )
                or (row["total_receipts"] == 0)
                != (row["identity_chain_tip"] == "")
                or (row["segment_count"] == 0)
                != (row["active_segment_tip"] == "")
                or isinstance(row["updated_at"], bool)
                or not isinstance(row["updated_at"], (int, float))
                or not math.isfinite(updated_at)
                or updated_at <= 0
                or not _verify_snapshot(
                    row,
                    trusted_public_keys=trusted_public_keys,
                )
            ):
                raise ValueError("invalid state")
        except (KeyError, TypeError, ValueError) as exc:
            raise SegmentedLedgerError(
                "signed receipt index state failed integrity validation"
            ) from exc
        return LedgerState(
            generation=int(row["generation"]),
            total_receipts=int(row["total_receipts"]),
            identity_chain_tip=str(row["identity_chain_tip"]),
            segment_count=int(row["segment_count"]),
            active_segment=int(row["active_segment"]),
            active_file_row_count=int(row["active_file_row_count"]),
            active_segment_receipt_count=int(
                row["active_segment_receipt_count"]
            ),
            active_segment_tip=str(row["active_segment_tip"]),
            previous_state_hash=str(row["prev_hash"]),
            state_hash=str(row["hash"]),
            updated_at=updated_at,
        )

    def _read_state(self) -> LedgerState | None:
        from .file_lock import ensure_private_file

        try:
            ensure_private_file(self.state_path, 0o600)
            text = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError) as exc:
            raise SegmentedLedgerError(
                "signed receipt index state is unreadable"
            ) from exc
        lines = text.splitlines()
        if len(lines) != 1 or not lines[0].strip():
            raise SegmentedLedgerError(
                "signed receipt index state must contain exactly one row"
            )
        try:
            row = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise SegmentedLedgerError(
                "signed receipt index state contains malformed JSON"
            ) from exc
        if not isinstance(row, dict):
            raise SegmentedLedgerError(
                "signed receipt index state is not an object"
            )
        return self._parse_state(row)

    def _connect_index(self, *, create: bool) -> sqlite3.Connection:
        from .file_lock import ensure_private_directory, ensure_private_file

        ensure_private_directory(self.index_path.parent)
        if not create and not self.index_path.exists():
            raise FileNotFoundError(self.index_path)
        if self.index_path.exists():
            ensure_private_file(self.index_path, 0o600)
        connection = sqlite3.connect(
            str(self.index_path),
            timeout=30.0,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if create:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS receipts (
                        ordinal INTEGER PRIMARY KEY,
                        identity TEXT NOT NULL UNIQUE,
                        row_hash TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        segment INTEGER NOT NULL,
                        line_number INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    """
                )
            ensure_private_file(self.index_path, 0o600)
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        try:
            rows = connection.execute(
                "SELECT key, value FROM metadata"
            ).fetchall()
        except sqlite3.Error as exc:
            raise SegmentedLedgerError(
                "receipt identity index metadata is unreadable"
            ) from exc
        return {str(key): str(value) for key, value in rows}

    @staticmethod
    def _metadata_for_state(state: LedgerState) -> dict[str, str]:
        return {
            "version": str(_INDEX_SCHEMA_VERSION),
            "generation": str(state.generation),
            "total_receipts": str(state.total_receipts),
            "identity_chain_tip": state.identity_chain_tip,
            "active_segment": str(state.active_segment),
            "active_file_row_count": str(state.active_file_row_count),
            "active_segment_tip": state.active_segment_tip,
            "state_hash": state.state_hash,
        }

    @staticmethod
    def _index_shape_matches(
        connection: sqlite3.Connection,
        state: LedgerState,
    ) -> bool:
        """Prove the derivative index has one contiguous row per ordinal."""

        try:
            count, minimum, maximum = connection.execute(
                "SELECT COUNT(*), MIN(ordinal), MAX(ordinal) FROM receipts"
            ).fetchone()
        except (sqlite3.Error, TypeError) as exc:
            raise SegmentedLedgerError(
                "receipt identity index shape is unreadable"
            ) from exc
        if state.total_receipts == 0:
            return count == 0 and minimum is None and maximum is None
        return (
            count == state.total_receipts
            and minimum == 1
            and maximum == state.total_receipts
        )

    def _replace_index(
        self,
        summary_factory: Callable[[Callable[[LedgerEntry], None]], _ScanSummary],
        *,
        generation: int,
        previous_state_hash: str,
    ) -> LedgerState:
        from .file_lock import ensure_private_file

        temp_path = self.index_path.with_name(f"{self.index_path.name}.rebuild")
        for artifact in _sqlite_rebuild_artifacts(temp_path):
            if artifact.exists():
                try:
                    artifact.unlink()
                except OSError as exc:
                    raise SegmentedLedgerError(
                        "stale receipt index rebuild file cannot be removed"
                    ) from exc
        original_path = self.index_path
        self.index_path = temp_path
        try:
            connection = self._connect_index(create=True)
            try:
                connection.execute("BEGIN IMMEDIATE")

                def insert(entry: LedgerEntry) -> None:
                    try:
                        connection.execute(
                            "INSERT INTO receipts "
                            "(ordinal, identity, row_hash, payload_sha256, "
                            "segment, line_number) VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                entry.ordinal,
                                entry.identity,
                                entry.row_hash,
                                entry.payload_sha256,
                                entry.segment,
                                entry.line_number,
                            ),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise SegmentedLedgerError(
                            "signed receipt ledger contains a duplicate identity "
                            "or ordinal"
                        ) from exc

                summary = summary_factory(insert)
                body_state = LedgerState(
                    generation=generation,
                    total_receipts=summary.total_receipts,
                    identity_chain_tip=summary.identity_chain_tip,
                    segment_count=summary.segment_count,
                    active_segment=summary.active_segment,
                    active_file_row_count=summary.active_file_row_count,
                    active_segment_receipt_count=(
                        summary.active_segment_receipt_count
                    ),
                    active_segment_tip=summary.active_segment_tip,
                    previous_state_hash=previous_state_hash,
                    state_hash="",
                    updated_at=time.time(),
                )
                provisional = self._metadata_for_state(body_state)
                provisional["state_hash"] = ""
                connection.executemany(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    provisional.items(),
                )
                connection.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
            ensure_private_file(temp_path, 0o600)
            # The SQLite database is a disposable derivative of the signed
            # physical ledger.  Never let a stale journal from the database
            # being replaced replay against the newly published inode.
            for artifact in _sqlite_rebuild_artifacts(original_path)[1:]:
                if artifact.exists():
                    try:
                        artifact.unlink()
                    except OSError as exc:
                        raise SegmentedLedgerError(
                            "stale receipt index journal cannot be removed"
                        ) from exc
            os.replace(temp_path, original_path)
            _fsync_directory(original_path.parent)
            ensure_private_file(original_path, 0o600)
        finally:
            self.index_path = original_path
            for artifact in _sqlite_rebuild_artifacts(temp_path):
                if artifact.exists():
                    with contextlib.suppress(OSError):
                        artifact.unlink()
        state = self._write_state(
            summary,
            generation=generation,
            previous_state_hash=previous_state_hash,
        )
        connection = self._connect_index(create=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='state_hash'",
                (state.state_hash,),
            )
            connection.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return state

    def _quick_physical_matches(self, state: LedgerState) -> bool:
        segments = self._physical_segments()
        if len(segments) != state.segment_count:
            return False
        if not segments:
            return (
                state.total_receipts == 0
                and state.active_file_row_count == 0
                and state.active_segment_tip == ""
            )
        number, path = segments[-1]
        if number != state.active_segment:
            return False
        # State acquisition is on the receipt append path.  Re-verifying every
        # row in a potentially million-row active segment here would turn a
        # nominally short mutex into an ingestion outage.  The signed state and
        # exact derivative-index shape are checked separately; this bounded
        # tail probe detects ordinary append/truncation/crash drift.  Full
        # assurance verification still streams every signature outside the
        # append lock.
        try:
            size = path.stat().st_size
            if size <= 0:
                return False
            with path.open("rb") as stream:
                start = max(0, size - _TAIL_PROBE_BYTES)
                stream.seek(start)
                tail_bytes = stream.read(_TAIL_PROBE_BYTES)
        except OSError:
            return False
        if not tail_bytes.endswith(b"\n"):
            return False
        rows = tail_bytes.splitlines()
        if start and len(rows) < 2:
            # The final signed row is larger than the bounded probe.  Let the
            # strict reconciliation path inspect this unusual state.
            return False
        try:
            tail = json.loads(rows[-1].decode("utf-8"))
        except (IndexError, UnicodeError, json.JSONDecodeError):
            return False
        return (
            isinstance(tail, dict)
            and str(tail.get("hash") or "") == state.active_segment_tip
        )

    @staticmethod
    def _summary_matches_state(
        summary: _ScanSummary,
        state: LedgerState,
    ) -> bool:
        return (
            summary.total_receipts == state.total_receipts
            and summary.identity_chain_tip == state.identity_chain_tip
            and summary.segment_count == state.segment_count
            and summary.active_segment == state.active_segment
            and summary.active_file_row_count == state.active_file_row_count
            and summary.active_segment_receipt_count
            == state.active_segment_receipt_count
            and summary.active_segment_tip == state.active_segment_tip
        )

    @staticmethod
    def _is_append_extension(
        summary: _ScanSummary,
        state: LedgerState,
    ) -> bool:
        return (
            summary.total_receipts >= state.total_receipts
            and summary.prefix_identity_chain_tip == state.identity_chain_tip
            and summary.prefix_active_tip == state.active_segment_tip
        )

    def _rebuild_locked(
        self,
        *,
        prior_state: LedgerState | None,
    ) -> LedgerState:
        prefix = prior_state

        def factory(
            insert: Callable[[LedgerEntry], None],
        ) -> _ScanSummary:
            return self._scan(on_entry=insert, prefix_state=prefix)

        # First scan without side effects establishes whether the surviving
        # bytes extend the last authenticated state.  A shorter/divergent
        # ledger is tamper state, never "recovered" into a new clean index.
        preview = self._scan(prefix_state=prefix)
        if prior_state is not None and not self._is_append_extension(
            preview,
            prior_state,
        ):
            raise SegmentedLedgerError(
                "signed receipt ledger was truncated or diverged from its "
                "authenticated index state"
            )
        generation = 1 if prior_state is None else prior_state.generation + 1
        previous_hash = "" if prior_state is None else prior_state.state_hash
        return self._replace_index(
            factory,
            generation=generation,
            previous_state_hash=previous_hash,
        )

    def _ensure_ready_locked(self) -> LedgerState:
        state = self._read_state()
        numbered = self._numbered_segments()
        if state is None:
            if numbered:
                raise SegmentedLedgerError(
                    "segmented receipt ledger exists without authenticated "
                    "index state"
                )
            # A lone legacy file is the supported in-place migration path.  Its
            # original signed bytes remain segment zero.
            return self._rebuild_locked(prior_state=None)
        physical_matches = self._quick_physical_matches(state)
        index_matches = False
        try:
            connection = self._connect_index(create=False)
        except (FileNotFoundError, sqlite3.Error, OSError):
            connection = None
        if connection is not None:
            try:
                index_matches = text_equals(
                    _canonical_json(self._metadata(connection)),
                    _canonical_json(self._metadata_for_state(state)),
                ) and self._index_shape_matches(connection, state)
            finally:
                connection.close()
        if physical_matches and index_matches:
            return state
        return self._rebuild_locked(prior_state=state)

    def state(self) -> LedgerState:
        from .file_lock import cross_process_lock

        with cross_process_lock(self.lock_target, strict=True):
            return self._ensure_ready_locked()

    def _validated_entry_rows(
        self,
        entries: tuple[LedgerEntry, ...],
    ) -> dict[int, dict[str, Any]]:
        """Bind indexed entries to verified physical rows, once per segment."""

        by_segment: dict[int, dict[int, list[LedgerEntry]]] = {}
        for entry in entries:
            by_segment.setdefault(entry.segment, {}).setdefault(
                entry.line_number,
                [],
            ).append(entry)
        result: dict[int, dict[str, Any]] = {}
        for segment, pending in by_segment.items():
            path = self._segment_path(segment)
            for line_number, row in _iter_verified_rows(path):
                expected_entries = pending.pop(line_number, ())
                for entry in expected_entries:
                    if (
                        row.get(self.identity_key) != entry.identity
                        or row.get("hash") != entry.row_hash
                        or row.get(self.payload_key)
                        != entry.payload_sha256
                    ):
                        raise SegmentedLedgerError(
                            "receipt identity index does not match its signed row"
                        )
                    result[entry.ordinal] = row
            if pending:
                raise SegmentedLedgerError(
                    "receipt identity index points outside its signed segment"
                )
        return result

    def _load_entry_row(self, entry: LedgerEntry) -> dict[str, Any]:
        return self._validated_entry_rows((entry,))[entry.ordinal]

    @staticmethod
    def _entry_from_sql(row: tuple[Any, ...]) -> LedgerEntry:
        try:
            if len(row) != 6:
                raise ValueError("wrong number of index fields")
            ordinal, identity, row_hash, payload_sha256, segment, line_number = row
            if (
                isinstance(ordinal, bool)
                or not isinstance(ordinal, int)
                or ordinal < 1
                or not isinstance(identity, str)
                or not identity
                or not isinstance(row_hash, str)
                or not _DIGEST_RE.fullmatch(row_hash)
                or not isinstance(payload_sha256, str)
                or not _DIGEST_RE.fullmatch(payload_sha256)
                or isinstance(segment, bool)
                or not isinstance(segment, int)
                or segment < 0
                or isinstance(line_number, bool)
                or not isinstance(line_number, int)
                or line_number < 1
            ):
                raise ValueError("invalid index fields")
            return LedgerEntry(
                ordinal=ordinal,
                identity=identity,
                row_hash=row_hash,
                payload_sha256=payload_sha256,
                segment=segment,
                line_number=line_number,
            )
        except (TypeError, ValueError) as exc:
            raise SegmentedLedgerError(
                "receipt identity index contains an invalid row"
            ) from exc

    def find(self, identity: str) -> dict[str, Any] | None:
        from .file_lock import cross_process_lock

        with cross_process_lock(self.lock_target, strict=True):
            state = self._ensure_ready_locked()
            connection = self._connect_index(create=False)
            try:
                row = connection.execute(
                    "SELECT ordinal, identity, row_hash, payload_sha256, "
                    "segment, line_number FROM receipts WHERE identity=?",
                    (str(identity),),
                ).fetchone()
            except sqlite3.Error as exc:
                raise SegmentedLedgerError(
                    "receipt identity index lookup failed"
                ) from exc
            finally:
                connection.close()
            if row is None:
                physical_match = False

                def locate(entry: LedgerEntry) -> None:
                    nonlocal physical_match
                    if hmac.compare_digest(entry.identity, str(identity)):
                        physical_match = True

                summary = self._scan(on_entry=locate)
                if not self._summary_matches_state(summary, state):
                    raise SegmentedLedgerError(
                        "signed receipt index state diverges from the ledger"
                    )
                if physical_match:
                    raise SegmentedLedgerError(
                        "receipt identity index omits a signed row"
                    )
                return None
            return self._load_entry_row(self._entry_from_sql(row))

    def _new_segment_header(
        self,
        state: LedgerState,
        segment_number: int,
    ) -> dict[str, Any]:
        return {
            "schema": SEGMENT_HEADER_SCHEMA,
            "event": SEGMENT_HEADER_EVENT,
            "tenant_sha256": self.tenant_sha256,
            "segment": segment_number,
            "previous_segment": state.active_segment,
            "previous_segment_tip": state.active_segment_tip,
            "previous_segment_receipt_count": (
                state.active_segment_receipt_count
            ),
            "previous_total_receipts": state.total_receipts,
            "opened_at": time.time(),
            "segment_row_limit": self.segment_rows,
            "segment_byte_limit": self.segment_bytes,
        }

    def _active_limits(self, state: LedgerState) -> tuple[int, int]:
        """Return the active segment's authenticated row/byte ceilings."""

        row_limit = self.segment_rows
        byte_limit = self.segment_bytes
        if state.segment_count and state.active_segment > 0:
            row_iter = _iter_strict_rows(
                self._segment_path(state.active_segment)
            )
            try:
                _line_number, header = next(row_iter)
            except StopIteration as exc:
                raise SegmentedLedgerError(
                    "active signed receipt segment is empty"
                ) from exc
            row_limit = min(row_limit, int(header["segment_row_limit"]))
            byte_limit = min(byte_limit, int(header["segment_byte_limit"]))
        return row_limit, byte_limit

    def _update_index_after_append(
        self,
        entry: LedgerEntry,
        summary: _ScanSummary,
        prior_state: LedgerState,
    ) -> LedgerState:
        connection = self._connect_index(create=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO receipts "
                "(ordinal, identity, row_hash, payload_sha256, segment, "
                "line_number) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entry.ordinal,
                    entry.identity,
                    entry.row_hash,
                    entry.payload_sha256,
                    entry.segment,
                    entry.line_number,
                ),
            )
            provisional = {
                "version": str(_INDEX_SCHEMA_VERSION),
                "generation": str(prior_state.generation + 1),
                "total_receipts": str(summary.total_receipts),
                "identity_chain_tip": summary.identity_chain_tip,
                "active_segment": str(summary.active_segment),
                "active_file_row_count": str(summary.active_file_row_count),
                "active_segment_tip": summary.active_segment_tip,
                "state_hash": "",
            }
            connection.executemany(
                "UPDATE metadata SET value=? WHERE key=?",
                ((value, key) for key, value in provisional.items()),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            with contextlib.suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise SegmentedLedgerError(
                "signed receipt identity is duplicated"
            ) from exc
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        state = self._write_state(
            summary,
            generation=prior_state.generation + 1,
            previous_state_hash=prior_state.state_hash,
        )
        connection = self._connect_index(create=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='state_hash'",
                (state.state_hash,),
            )
            connection.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return state

    def _validate_append_event(
        self,
        event: Mapping[str, Any],
        identity: str,
    ) -> None:
        if (
            any(not isinstance(key, str) for key in event)
            or {"prev_hash", "key_id", "hash", "sig"}.intersection(event)
        ):
            raise ValueError(
                "signed receipt event contains reserved or non-string fields"
            )
        if event.get(self.identity_key) != identity:
            raise ValueError("signed receipt identity does not match its event")
        try:
            # Fail before AuditSigner creates a file if sorting or JSON
            # serialization would make the row unverifiable.
            json.dumps(
                dict(event),
                sort_keys=True,
                default=str,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("signed receipt event is not valid JSON") from exc

    def append(
        self,
        event: Mapping[str, Any],
        *,
        identity: str,
    ) -> tuple[dict[str, Any], str]:
        """Append or idempotently recover one signed receipt."""

        from .audit.signing import AuditSigner
        from .file_lock import cross_process_lock, ensure_private_directory

        identity_value = str(identity)
        self._validate_append_event(event, identity_value)
        with cross_process_lock(self.lock_target, strict=True):
            state = self._ensure_ready_locked()
            connection = self._connect_index(create=False)
            try:
                existing_sql = connection.execute(
                    "SELECT ordinal, identity, row_hash, payload_sha256, "
                    "segment, line_number FROM receipts WHERE identity=?",
                    (identity_value,),
                ).fetchone()
            finally:
                connection.close()
            if existing_sql is not None:
                existing = self._load_entry_row(
                    self._entry_from_sql(existing_sql)
                )
                for key, value in event.items():
                    if existing.get(key) != value:
                        raise SegmentedLedgerError(
                            "signed receipt identity was reused with different "
                            "content"
                        )
                key_id = existing.get("key_id")
                from .audit.signing import trusted_audit_public_keys

                public_key = trusted_audit_public_keys().get(str(key_id or ""))
                if not isinstance(public_key, str):
                    raise SegmentedLedgerError(
                        "signed receipt key is absent from the trust registry"
                    )
                return existing, public_key
            if state.total_receipts >= self.max_receipts:
                raise SegmentedLedgerError(
                    "AI evidence receipt capacity has been reached; delivery "
                    "was withheld before signing"
                )
            active_row_limit, active_byte_limit = self._active_limits(state)
            active_path = self._segment_path(state.active_segment)
            try:
                active_size = active_path.stat().st_size
            except FileNotFoundError:
                active_size = 0
            except OSError as exc:
                raise SegmentedLedgerError(
                    "active signed receipt segment size is unavailable"
                ) from exc
            estimated_row_bytes = _estimated_signed_row_bytes(
                event,
                chained=state.segment_count > 0,
            )
            if estimated_row_bytes > self.segment_bytes:
                raise SegmentedLedgerError(
                    "AI evidence receipt exceeds the configured segment byte "
                    "limit; delivery was withheld before signing"
                )
            has_active_capacity = (
                state.active_segment_receipt_count < active_row_limit
                and active_size + estimated_row_bytes <= active_byte_limit
            )
            if (
                state.segment_count == 0
                or (
                    state.segment_count > 0
                    and has_active_capacity
                )
            ):
                segment_number = state.active_segment
                segment_path = self._segment_path(segment_number)
                new_segment_tip = None
            else:
                segment_number = max(1, state.active_segment + 1)
                segment_path = self._segment_path(segment_number)
                header = self._new_segment_header(state, segment_number)
                new_segment_bytes = _estimated_signed_row_bytes(
                    header,
                    chained=False,
                ) + _estimated_signed_row_bytes(event, chained=True)
                if new_segment_bytes > self.segment_bytes:
                    raise SegmentedLedgerError(
                        "AI evidence receipt cannot fit in an empty signed "
                        "segment; delivery was withheld before signing"
                    )
                ensure_private_directory(self.segment_dir)
                if segment_path.exists():
                    raise SegmentedLedgerError(
                        "next signed receipt segment already exists"
                    )
                header_signer = AuditSigner(segment_path)
                if not header_signer.write(
                    header
                ):
                    raise SegmentedLedgerError(
                        "audit signer refused the receipt segment header"
                    )
                # The header is the new segment's chain root (prev_hash always
                # ""); verifying it here (not just the event row below) means
                # every row this call adds is checked, not only the last one.
                new_segment_tip = self._verify_appended_row(
                    segment_path, offset_before=0, expected_previous="",
                ).get("hash")
            try:
                offset_before_event = segment_path.stat().st_size
            except FileNotFoundError:
                offset_before_event = 0
            except OSError as exc:
                raise SegmentedLedgerError(
                    "signed receipt segment size is unavailable before append"
                ) from exc
            signer = AuditSigner(segment_path)
            if not signer.write(dict(event)):
                raise SegmentedLedgerError("audit signer refused evidence")
            # Verify only the row just written, chained to the tip we
            # already know (this new segment's own header, or the active
            # segment's authenticated tip) -- not the whole segment from
            # genesis. append() holds cross_process_lock start-to-finish and
            # _ensure_ready_locked() already reconciled state against the
            # physical file moments ago, so nothing else could have appended
            # in between; full prefix verification remains the job of crash
            # reconciliation and explicit integrity checks, run outside this
            # lock. See _verify_appended_row for the full reasoning.
            signed = self._verify_appended_row(
                segment_path,
                offset_before=offset_before_event,
                expected_previous=(
                    new_segment_tip if new_segment_tip is not None
                    else state.active_segment_tip
                ),
            )
            line_number = 2 if new_segment_tip is not None else (
                state.active_file_row_count + 1
            )
            try:
                written_size = segment_path.stat().st_size
            except OSError as exc:
                raise SegmentedLedgerError(
                    "signed receipt segment size is unavailable after append"
                ) from exc
            written_receipts = line_number - (1 if segment_number > 0 else 0)
            final_row_limit = (
                active_row_limit
                if segment_number == state.active_segment
                and state.segment_count
                else self.segment_rows
            )
            final_byte_limit = (
                active_byte_limit
                if segment_number == state.active_segment
                and state.segment_count
                else self.segment_bytes
            )
            if (
                written_receipts > final_row_limit
                or written_size > final_byte_limit
            ):
                raise SegmentedLedgerError(
                    "signed receipt segment exceeded its authenticated storage "
                    "bound after append"
                )
            if signed.get(self.identity_key) != identity_value:
                raise SegmentedLedgerError(
                    "signed receipt could not be recovered after append"
                )
            entry = LedgerEntry(
                ordinal=state.total_receipts + 1,
                identity=identity_value,
                row_hash=str(signed.get("hash") or ""),
                payload_sha256=str(signed.get(self.payload_key) or ""),
                segment=segment_number,
                line_number=line_number,
            )
            if (
                not _DIGEST_RE.fullmatch(entry.row_hash)
                or not _DIGEST_RE.fullmatch(entry.payload_sha256)
            ):
                raise SegmentedLedgerError(
                    "signed receipt contains an invalid evidence digest"
                )
            summary = _ScanSummary(
                total_receipts=entry.ordinal,
                identity_chain_tip=_identity_tip(
                    state.identity_chain_tip,
                    entry,
                ),
                segment_count=(
                    state.segment_count
                    if segment_number == state.active_segment
                    and state.segment_count
                    else state.segment_count + 1
                ),
                active_segment=segment_number,
                active_file_row_count=line_number,
                active_segment_receipt_count=(
                    state.active_segment_receipt_count + 1
                    if segment_number == state.active_segment
                    and state.segment_count
                    else 1
                ),
                active_segment_tip=entry.row_hash,
                prefix_identity_chain_tip="",
                prefix_active_tip="",
            )
            self._update_index_after_append(entry, summary, state)
            return signed, signer.public_key_hex

    def _cursor(
        self,
        *,
        snapshot_total: int,
        before: int,
    ) -> str:
        body = {
            "v": _CURSOR_VERSION,
            "tenant": self.tenant_sha256,
            "snapshot_total": snapshot_total,
            "before": before,
        }
        envelope = {
            "body": body,
            "sha256": _sha256(body),
        }
        return base64.urlsafe_b64encode(
            _canonical_json(envelope).encode("utf-8")
        ).decode("ascii").rstrip("=")

    def _decode_cursor(self, value: str) -> tuple[int, int]:
        try:
            raw = str(value)
            if len(raw) > 2_048:
                raise ValueError("cursor is too large")
            raw += "=" * (-len(raw) % 4)
            envelope = json.loads(
                base64.b64decode(
                    raw.encode("ascii"),
                    altchars=b"-_",
                    validate=True,
                ).decode("utf-8")
            )
            body = envelope["body"]
            if (
                not isinstance(envelope, dict)
                or not isinstance(body, dict)
                or set(envelope) != {"body", "sha256"}
                or set(body)
                != {"v", "tenant", "snapshot_total", "before"}
                or envelope["sha256"] != _sha256(body)
                or body["v"] != _CURSOR_VERSION
                or body["tenant"] != self.tenant_sha256
                or isinstance(body["snapshot_total"], bool)
                or not isinstance(body["snapshot_total"], int)
                or body["snapshot_total"] < 0
                or isinstance(body["before"], bool)
                or not isinstance(body["before"], int)
                or body["before"] < 1
            ):
                raise ValueError("invalid cursor")
            return int(body["snapshot_total"]), int(body["before"])
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("receipt cursor is invalid") from exc

    def page(
        self,
        *,
        limit: int,
        cursor: str | None = None,
    ) -> LedgerPage:
        from .file_lock import cross_process_lock

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
            or limit > 10_000
        ):
            raise ValueError("receipt page limit must be between 1 and 10000")
        # The append lock protects only the authenticated state/index read.
        # Signature verification can scan a very large historical segment, so
        # do it after releasing the lock.  If a legitimate append overlaps a
        # file read and produces a transient parse error, retry against the new
        # state instead of publishing false tamper state.
        for attempt in range(3):
            with cross_process_lock(self.lock_target, strict=True):
                state = self._ensure_ready_locked()
                if cursor is None:
                    snapshot_total = state.total_receipts
                    before = snapshot_total + 1
                else:
                    snapshot_total, before = self._decode_cursor(cursor)
                    if snapshot_total > state.total_receipts:
                        raise SegmentedLedgerError(
                            "receipt cursor names evidence beyond the current "
                            "authenticated ledger"
                        )
                connection = self._connect_index(create=False)
                try:
                    rows = connection.execute(
                        "SELECT ordinal, identity, row_hash, payload_sha256, "
                        "segment, line_number FROM receipts "
                        "WHERE ordinal < ? AND ordinal <= ? "
                        "ORDER BY ordinal DESC LIMIT ?",
                        (before, snapshot_total, limit + 1),
                    ).fetchall()
                except sqlite3.Error as exc:
                    raise SegmentedLedgerError(
                        "receipt identity index pagination failed"
                    ) from exc
                finally:
                    connection.close()
            entries = tuple(self._entry_from_sql(row) for row in rows[:limit])
            try:
                # Never return an index-only result.  The physical signed rows
                # still bind to every accelerated lookup.
                self._validated_entry_rows(entries)
            except SegmentedLedgerError:
                current = self.state()
                if (
                    attempt < 2
                    and not hmac.compare_digest(
                        current.state_hash,
                        state.state_hash,
                    )
                ):
                    continue
                raise
            has_more = len(rows) > limit
            next_cursor = (
                self._cursor(
                    snapshot_total=snapshot_total,
                    before=entries[-1].ordinal,
                )
                if has_more and entries
                else None
            )
            return LedgerPage(
                entries=entries,
                next_cursor=next_cursor,
                snapshot_total=snapshot_total,
            )
        raise SegmentedLedgerError(
            "receipt page could not obtain a stable ledger snapshot"
        )

    def iter_entries(
        self,
        *,
        descending: bool = False,
        snapshot_total: int | None = None,
        batch_size: int = 1_000,
        validate_rows: bool = True,
    ) -> Iterator[LedgerEntry]:
        """Stream a pinned append-only view without holding the append lock.

        ``validate_rows`` defaults to true and binds every derivative index
        entry to a verified signed row.  Assurance callers that have already
        completed :meth:`verify_integrity` for the same signed state may set it
        false, provided they compare the end-state hash before publishing.
        """

        from .file_lock import cross_process_lock

        if batch_size < 1 or batch_size > 10_000:
            raise ValueError("receipt stream batch size must be between 1 and 10000")
        with cross_process_lock(self.lock_target, strict=True):
            state = self._ensure_ready_locked()
            ceiling = (
                state.total_receipts
                if snapshot_total is None
                else int(snapshot_total)
            )
            if ceiling < 0 or ceiling > state.total_receipts:
                raise ValueError("receipt stream snapshot is invalid")
        cursor = ceiling + 1 if descending else 0
        while True:
            entries: tuple[LedgerEntry, ...] | None = None
            for attempt in range(3):
                with cross_process_lock(self.lock_target, strict=True):
                    batch_state = self._ensure_ready_locked()
                    if ceiling > batch_state.total_receipts:
                        raise SegmentedLedgerError(
                            "receipt stream snapshot moved beyond the "
                            "authenticated ledger"
                        )
                    connection = self._connect_index(create=False)
                    try:
                        if descending:
                            rows = connection.execute(
                                "SELECT ordinal, identity, row_hash, "
                                "payload_sha256, segment, line_number FROM "
                                "receipts WHERE ordinal < ? AND ordinal <= ? "
                                "ORDER BY ordinal DESC LIMIT ?",
                                (cursor, ceiling, batch_size),
                            ).fetchall()
                        else:
                            rows = connection.execute(
                                "SELECT ordinal, identity, row_hash, "
                                "payload_sha256, segment, line_number FROM "
                                "receipts WHERE ordinal > ? AND ordinal <= ? "
                                "ORDER BY ordinal ASC LIMIT ?",
                                (cursor, ceiling, batch_size),
                            ).fetchall()
                    except sqlite3.Error as exc:
                        raise SegmentedLedgerError(
                            "receipt identity index stream failed"
                        ) from exc
                    finally:
                        connection.close()
                entries = tuple(self._entry_from_sql(row) for row in rows)
                if not entries or not validate_rows:
                    break
                try:
                    self._validated_entry_rows(entries)
                    break
                except SegmentedLedgerError:
                    current = self.state()
                    if (
                        attempt < 2
                        and not hmac.compare_digest(
                            current.state_hash,
                            batch_state.state_hash,
                        )
                    ):
                        continue
                    raise
            assert entries is not None
            if not entries:
                break
            yield from entries
            cursor = entries[-1].ordinal

    def row_for_entry(self, entry: LedgerEntry) -> dict[str, Any]:
        from .file_lock import cross_process_lock

        with cross_process_lock(self.lock_target, strict=True):
            self._ensure_ready_locked()
            return self._load_entry_row(entry)

    def rows(self) -> list[dict[str, Any]]:
        """Compatibility full read.  Assurance code should use ``iter_entries``."""

        from .file_lock import cross_process_lock

        with cross_process_lock(self.lock_target, strict=True):
            self._ensure_ready_locked()
            connection = self._connect_index(create=False)
            try:
                sql_rows = connection.execute(
                    "SELECT ordinal, identity, row_hash, payload_sha256, "
                    "segment, line_number FROM receipts ORDER BY ordinal ASC"
                ).fetchall()
            except sqlite3.Error as exc:
                raise SegmentedLedgerError(
                    "receipt identity index full read failed"
                ) from exc
            finally:
                connection.close()
            entries = tuple(
                self._entry_from_sql(row) for row in sql_rows
            )
            physical = self._validated_entry_rows(entries)
            return [physical[entry.ordinal] for entry in entries]

    def _read_only_state(
        self,
        trusted_public_keys: Mapping[str, str],
    ) -> LedgerState | None:
        from .file_lock import private_path_is_restricted

        if not self.state_path.exists():
            return None
        try:
            info = self.state_path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not private_path_is_restricted(self.state_path, 0o600)
            ):
                raise SegmentedLedgerError(
                    "signed receipt index state path is unsafe"
                )
            text = self.state_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SegmentedLedgerError(
                "signed receipt index state is unreadable"
            ) from exc
        lines = text.splitlines()
        if len(lines) != 1 or not lines[0].strip():
            raise SegmentedLedgerError(
                "signed receipt index state must contain exactly one row"
            )
        try:
            row = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise SegmentedLedgerError(
                "signed receipt index state contains malformed JSON"
            ) from exc
        if not isinstance(row, dict):
            raise SegmentedLedgerError(
                "signed receipt index state is not an object"
            )
        return self._parse_state(
            row,
            trusted_public_keys=trusted_public_keys,
        )

    def _read_only_physical_segments(self) -> list[tuple[int, Path]]:
        from .file_lock import private_path_is_restricted

        segments: list[tuple[int, Path]] = []
        if self.legacy_path.exists():
            try:
                info = self.legacy_path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_size <= 0
                    or not private_path_is_restricted(
                        self.legacy_path,
                        0o600,
                    )
                ):
                    raise SegmentedLedgerError(
                        "legacy signed receipt segment is unsafe"
                    )
            except OSError as exc:
                raise SegmentedLedgerError(
                    "legacy signed receipt segment is unreadable"
                ) from exc
            segments.append((0, self.legacy_path))
        if not self.segment_dir.exists():
            return segments
        try:
            info = self.segment_dir.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or not private_path_is_restricted(self.segment_dir, 0o700)
            ):
                raise SegmentedLedgerError(
                    "signed receipt segment directory is unsafe"
                )
            children = list(self.segment_dir.iterdir())
        except OSError as exc:
            raise SegmentedLedgerError(
                "signed receipt segment directory is unreadable"
            ) from exc
        numbered: list[tuple[int, Path]] = []
        for path in children:
            match = _SEGMENT_RE.fullmatch(path.name)
            if match is None:
                if (
                    path.name.endswith(".ndjson.lock")
                    and _SEGMENT_RE.fullmatch(path.name[:-5])
                ):
                    continue
                raise SegmentedLedgerError(
                    "signed receipt segment directory contains an unexpected "
                    f"entry: {path.name}"
                )
            try:
                entry = path.lstat()
            except OSError as exc:
                raise SegmentedLedgerError(
                    f"signed receipt segment cannot be inspected: {path.name}"
                ) from exc
            if (
                not stat.S_ISREG(entry.st_mode)
                or entry.st_nlink != 1
                or not private_path_is_restricted(path, 0o600)
            ):
                raise SegmentedLedgerError(
                    f"signed receipt segment is unsafe: {path.name}"
                )
            numbered.append((int(match.group(1)), path))
        numbered.sort()
        if [number for number, _path in numbered] != list(
            range(1, len(numbered) + 1)
        ):
            raise SegmentedLedgerError(
                "signed receipt segment sequence is missing or duplicated"
            )
        segments.extend(numbered)
        return segments

    def _read_only_index(self) -> sqlite3.Connection:
        from .file_lock import private_path_is_restricted

        try:
            info = self.index_path.lstat()
        except OSError as exc:
            raise SegmentedLedgerError(
                "receipt identity index is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not private_path_is_restricted(self.index_path, 0o600)
        ):
            raise SegmentedLedgerError("receipt identity index path is unsafe")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self.index_path.resolve().as_uri()}?mode=ro",
                uri=True,
                timeout=5.0,
                isolation_level=None,
            )
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA integrity_check").fetchone() != (
                "ok",
            ):
                raise SegmentedLedgerError(
                    "receipt identity index failed SQLite integrity validation"
                )
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    def verify_integrity_read_only(
        self,
        *,
        trusted_public_keys: Mapping[str, str],
    ) -> tuple[bool, str]:
        """Verify signed state, physical rows, and index without any repair."""

        prior_state: LedgerState | None = None
        for attempt in range(3):
            try:
                state = self._read_only_state(trusted_public_keys)
                if state is None:
                    return (
                        False,
                        "signed receipt ledger has no authenticated index state",
                    )
                prior_state = state
                segments = self._read_only_physical_segments()
                connection = self._read_only_index()
                try:
                    if (
                        not hmac.compare_digest(
                            _canonical_json(self._metadata(connection)),
                            _canonical_json(self._metadata_for_state(state)),
                        )
                        or not self._index_shape_matches(connection, state)
                    ):
                        raise SegmentedLedgerError(
                            "receipt identity index diverges from signed state"
                        )
                    sql_cursor = connection.execute(
                        "SELECT ordinal, identity, row_hash, payload_sha256, "
                        "segment, line_number FROM receipts "
                        "WHERE ordinal <= ? ORDER BY ordinal ASC",
                        (state.total_receipts,),
                    )
                    compared = 0

                    def compare(
                        entry: LedgerEntry,
                        index_cursor: sqlite3.Cursor = sql_cursor,
                    ) -> None:
                        nonlocal compared
                        row = index_cursor.fetchone()
                        expected = (
                            None if row is None else self._entry_from_sql(row)
                        )
                        if expected is None or expected != entry:
                            raise SegmentedLedgerError(
                                "receipt identity index diverges from the "
                                "signed ledger"
                            )
                        compared += 1

                    summary = self._scan(
                        on_entry=compare,
                        prefix_state=state,
                        physical_segments=segments,
                        row_reader=lambda path: (
                            _iter_verified_rows_read_only(
                                path,
                                trusted_public_keys,
                            )
                        ),
                    )
                    if (
                        compared != state.total_receipts
                        or sql_cursor.fetchone() is not None
                        or not self._summary_matches_state(summary, state)
                    ):
                        raise SegmentedLedgerError(
                            "signed receipt ledger or index diverges from "
                            "authenticated state"
                        )
                finally:
                    connection.close()
                current = self._read_only_state(trusted_public_keys)
                if (
                    current is not None
                    and hmac.compare_digest(
                        current.state_hash,
                        state.state_hash,
                    )
                ):
                    return True, ""
            except (
                OSError,
                sqlite3.Error,
                SegmentedLedgerError,
                TypeError,
                ValueError,
            ) as exc:
                if attempt == 2:
                    return False, str(exc) or type(exc).__name__
                try:
                    current = self._read_only_state(trusted_public_keys)
                except (
                    OSError,
                    SegmentedLedgerError,
                    TypeError,
                    ValueError,
                ):
                    return False, str(exc) or type(exc).__name__
                if (
                    prior_state is not None
                    and current is not None
                    and hmac.compare_digest(
                        current.state_hash,
                        prior_state.state_hash,
                    )
                ):
                    return False, str(exc) or type(exc).__name__
        return (
            False,
            "receipt ledger changed during read-only integrity snapshots; "
            "retry when ingestion is quiescent",
        )

    def _verify_integrity_snapshot(
        self,
        state: LedgerState,
    ) -> tuple[bool, str]:
        """Verify one signed prefix without holding the append lock."""

        try:
            cursor = 0
            indexed: deque[LedgerEntry] = deque()

            def next_indexed() -> LedgerEntry | None:
                nonlocal cursor, indexed
                if not indexed:
                    connection = self._connect_index(create=False)
                    try:
                        rows = connection.execute(
                            "SELECT ordinal, identity, row_hash, "
                            "payload_sha256, segment, line_number FROM receipts "
                            "WHERE ordinal > ? AND ordinal <= ? "
                            "ORDER BY ordinal ASC LIMIT 10000",
                            (cursor, state.total_receipts),
                        ).fetchall()
                    finally:
                        connection.close()
                    indexed.extend(self._entry_from_sql(row) for row in rows)
                if not indexed:
                    return None
                entry = indexed.popleft()
                cursor = entry.ordinal
                return entry

            compared = 0

            def compare(entry: LedgerEntry) -> None:
                nonlocal compared
                if entry.ordinal > state.total_receipts:
                    return
                expected = next_indexed()
                if expected is None or expected != entry:
                    raise SegmentedLedgerError(
                        "receipt identity index diverges from the signed ledger"
                    )
                compared += 1

            summary = self._scan(on_entry=compare, prefix_state=state)
            if (
                compared != state.total_receipts
                or next_indexed() is not None
            ):
                raise SegmentedLedgerError(
                    "receipt identity index contains rows absent from the "
                    "signed ledger"
                )
            if not self._is_append_extension(summary, state):
                raise SegmentedLedgerError(
                    "signed receipt ledger was truncated or diverged from its "
                    "authenticated index state"
                )
            return True, ""
        except (
            OSError,
            sqlite3.Error,
            SegmentedLedgerError,
            TypeError,
            ValueError,
        ) as exc:
            return False, str(exc) or type(exc).__name__

    def verify_integrity(
        self,
        *,
        snapshot_state: LedgerState | None = None,
    ) -> tuple[bool, str]:
        """Verify a stable signed snapshot without blocking receipt ingestion.

        When the caller supplies ``snapshot_state``, this verifies exactly that
        authenticated prefix and leaves the end-state comparison to the caller.
        The public no-argument form retries benign concurrent appends and
        returns an explicit indeterminate detail if write churn prevents a
        stable observation.
        """

        if snapshot_state is not None:
            return self._verify_integrity_snapshot(snapshot_state)
        for _attempt in range(3):
            try:
                state = self.state()
            except (
                OSError,
                sqlite3.Error,
                SegmentedLedgerError,
                TypeError,
                ValueError,
            ) as exc:
                return False, str(exc) or type(exc).__name__
            result = self._verify_integrity_snapshot(state)
            try:
                current = self.state()
            except (
                OSError,
                sqlite3.Error,
                SegmentedLedgerError,
                TypeError,
                ValueError,
            ) as exc:
                return False, str(exc) or type(exc).__name__
            if hmac.compare_digest(current.state_hash, state.state_hash):
                return result
        return (
            False,
            "receipt ledger changed during integrity snapshots; retry when "
            "ingestion is quiescent",
        )


__all__ = [
    "INDEX_STATE_SCHEMA",
    "LedgerEntry",
    "LedgerPage",
    "LedgerState",
    "SEGMENT_HEADER_SCHEMA",
    "SegmentedLedgerError",
    "SegmentedReceiptLedger",
]
