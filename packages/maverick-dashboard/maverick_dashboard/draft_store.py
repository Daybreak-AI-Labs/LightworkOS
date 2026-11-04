"""Private encrypted recovery copies; restoring never mutates a live resource."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path

from maverick.crypto_at_rest import is_sealed, seal, unseal
from maverick.file_lock import (
    _windows_extended_path,
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
)
from maverick.paths import data_dir
from maverick.safety.secret_detector import scan

_LOCK = threading.RLock()
_SLOT = re.compile(r"[0-9a-f]{64}\Z")
_SECRET = re.compile(r"(?:^|_)(?:password|passwd|passphrase|secret|credentials|api_key|apikey|token|client_secret|private_key|authorization|cookie)(?:$|_)", re.IGNORECASE)
_ASSIGNMENT = re.compile(r"\b(?:password|passwd|api[_ -]?key|client[_ -]?secret|access[_ -]?token|authorization)\s*[=:]\s*\S+", re.IGNORECASE)
MAX_BYTES = 1024 * 1024
MAX_RECORDS = 2000
MAX_REVISION = 2**31 - 1


class DraftConflict(ValueError):
    """A newer recovery copy must be reviewed before replacing it."""


def validate_payload(payload: dict | None) -> str:
    """Refuse credentials even in nested objects or serialized JSON fields."""
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_BYTES:
        raise ValueError("This draft is too large for recovery storage (1 MiB maximum).")
    pending = [(payload, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if depth > 25 or visited > 20_000:
            raise ValueError("This draft is too complex for recovery storage.")
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"([a-z])([A-Z])", r"\1_\2", key).lower().replace("-", "_")
                reference = normalized.endswith(("_ref", "_env", "_reference", "_id"))
                if _SECRET.search(normalized) and not reference and child not in (None, "", False):
                    raise ValueError("Recovery copies cannot contain passwords, tokens, or credentials. Use saved connection references.")
                pending.append((child, depth + 1))
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            if scan(value) or _ASSIGNMENT.search(value):
                raise ValueError("Recovery copies cannot contain credentials. Remove the credential or use a saved connection reference.")
            if value.lstrip().startswith(("{", "[")):
                try:
                    decoded = json.loads(value)
                except ValueError:
                    pass
                else:
                    pending.append((decoded, depth + 1))
    return encoded


class DraftStore:
    def __init__(self, context: str, *, directory: Path | None = None):
        if not _SLOT.fullmatch(context):
            raise ValueError("invalid draft context")
        self.context = context
        self.directory = directory or data_dir("draft-recovery", context)
        # Atomic publication already supports long Win32 paths. Reads, size
        # checks and existence-based CAS must resolve that exact same file.
        if os.name == "nt":
            self.directory = Path(_windows_extended_path(self.directory))

    def _path(self, slot: str) -> Path:
        if not _SLOT.fullmatch(slot):
            raise ValueError("invalid draft slot")
        return self.directory / (slot + ".draft")

    def _floor(self) -> int:
        path = self.directory / "retention.index"
        if not path.exists():
            return self._erasure_floor()
        if path.stat().st_size > 4096:
            raise ValueError("Recovery retention history could not be verified.")
        raw = atomic_read_bytes(path)
        if len(raw) > 4096 or not is_sealed(raw):
            raise ValueError("Recovery retention history could not be verified.")
        record = json.loads(unseal(raw))
        if (not isinstance(record, dict) or record.get("context") != self.context
                or record.get("schema") != "lightwork.draft-retention.v1"
                or type(record.get("revision_floor")) is not int
                or not 1 <= record["revision_floor"] <= MAX_REVISION):
            raise ValueError("Recovery retention history could not be verified.")
        return max(record["revision_floor"], self._erasure_floor())

    def _erasure_floor(self) -> int:
        path = self.directory / "erasure.index"
        if not path.exists():
            return 0
        raw = atomic_read_bytes(path)
        if len(raw) > 4096 or not is_sealed(raw):
            raise ValueError("Recovery erasure history could not be verified.")
        record = json.loads(unseal(raw))
        if (record.get("context") != self.context or type(record.get("revision_floor")) is not int
                or not 1 <= record["revision_floor"] <= MAX_REVISION):
            raise ValueError("Recovery erasure history could not be verified.")
        return record["revision_floor"]

    def _read(self, path: Path, slot: str, *, floor: int | None = None) -> dict:
        if floor is None:
            floor = self._floor()
        empty = {"context": self.context, "slot": slot, "revision": floor, "payload": None, "updated_at": None}
        if not path.exists():
            return empty
        if path.stat().st_size > MAX_BYTES * 2:
            raise ValueError("Recovery copy is too large to read safely.")
        raw = atomic_read_bytes(path)
        if not is_sealed(raw):
            raise ValueError("Recovery copy encryption could not be verified.")
        result = json.loads(unseal(raw))
        if (not isinstance(result, dict) or result.get("context") != self.context or result.get("slot") != slot
                or type(result.get("revision")) is not int or not 1 <= result["revision"] <= MAX_REVISION
                or "payload" not in result):
            raise ValueError("Recovery copy binding could not be verified.")
        if result["revision"] < self._erasure_floor():
            return empty
        # An interrupted retirement may leave old tombstones on disk. The
        # durable floor takes effect before deletion, so stale tabs remain
        # unable to resurrect them even if cleanup has not completed.
        if result["payload"] is None and result["revision"] < floor and result.get("retention_floor", 0) < floor:
            return empty
        return result

    @staticmethod
    def _public(record: dict) -> dict:
        return {key: record[key] for key in ("context", "slot", "revision", "payload", "updated_at")}

    def read(self, slot: str) -> dict:
        path = self._path(slot)
        ensure_private_directory(self.directory)
        with _LOCK, cross_process_lock(self.directory / "index", strict=True):
            return self._public(self._read(path, slot))

    def _inventory(self) -> tuple[dict, list[tuple[Path, dict]]]:
        floor = self._floor()
        records = []
        for path in self.directory.glob("*.draft"):
            if len(records) >= MAX_RECORDS:
                raise ValueError("Recovery storage exceeds its supported inventory size.")
            slot = path.stem
            self._path(slot)
            records.append((path, self._read(path, slot, floor=floor)))
        records.sort(key=lambda row: row[1]["slot"])
        entries = [{"slot": row["slot"], "revision": row["revision"],
                    "saved": row["payload"] is not None, "updated_at": row["updated_at"]}
                   for _path, row in records]
        version = hashlib.sha256(json.dumps([self.context, floor, entries], sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest()
        discarded = sum(not entry["saved"] for entry in entries)
        return ({"context": self.context, "version": version, "capacity": MAX_RECORDS,
                 "saved": len(entries) - discarded, "discarded": discarded,
                 "available": MAX_RECORDS - len(entries), "records": entries}, records)

    def inventory(self) -> dict:
        """Private metadata only; never return another editor's draft content."""
        ensure_private_directory(self.directory)
        with _LOCK, cross_process_lock(self.directory / "index", strict=True):
            return self._inventory()[0]

    def erase_all(self, *, expected_version: str) -> dict:
        """Retire this exact owner's copies and fence old autosave revisions."""
        ensure_private_directory(self.directory)
        with _LOCK, cross_process_lock(self.directory / "index", strict=True):
            inventory, records = self._inventory()
            if not hmac.compare_digest(expected_version, inventory["version"]):
                raise DraftConflict("Recovery copies changed. Review a fresh deletion scope.")
            floor = max([self._floor(), *(row["revision"] for _, row in records)]) + 1
            if floor >= MAX_REVISION:
                raise ValueError("Recovery revision capacity is exhausted; no copies were removed.")
            atomic_write_bytes(self.directory / "erasure.index", seal(json.dumps(
                {"context": self.context, "revision_floor": floor}).encode()))
            for path, _ in records:
                path.unlink()
            return {"state": "purged", "removed": len(records), "retained": "Content-free revision barrier prevents stale tabs from restoring deleted drafts."}

    def retire_discarded(self, *, expected_version: str) -> dict:
        """Reclaim only discarded copies while durably fencing every old tab."""
        ensure_private_directory(self.directory)
        with _LOCK, cross_process_lock(self.directory / "index", strict=True):
            inventory, records = self._inventory()
            if not hmac.compare_digest(expected_version, inventory["version"]):
                raise DraftConflict("Recovery storage changed. Review the current storage summary before freeing space.")
            discarded = [(path, row) for path, row in records if row["payload"] is None]
            if not discarded:
                return {**inventory, "retired": 0}
            floor = max(self._floor(), *(row["revision"] for _path, row in discarded)) + 1
            if floor >= MAX_REVISION:
                raise ValueError("Recovery revision capacity is exhausted. Existing copies have been kept.")
            record = {"schema": "lightwork.draft-retention.v1", "context": self.context, "revision_floor": floor}
            atomic_write_bytes(self.directory / "retention.index", seal(json.dumps(record).encode()))
            # Publication precedes deletion. If deletion fails or this process
            # exits, the encrypted floor still rejects old revisions.
            for path, _row in discarded:
                path.unlink()
            return {**self._inventory()[0], "retired": len(discarded)}

    def save(self, slot: str, payload: dict | None, *, expected_revision: int, operation_id: str) -> dict:
        encoded = validate_payload(payload)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        path = self._path(slot)
        ensure_private_directory(self.directory)
        with _LOCK, cross_process_lock(self.directory / "index", strict=True):
            record = self._read(path, slot)
            if record.get("operation_id") == operation_id:
                if expected_revision != record["revision"] - 1 or not hmac.compare_digest(record.get("payload_sha256", ""), digest):
                    raise DraftConflict("This retry reference was already used for different draft content.")
                return self._public(record)
            if record["revision"] != expected_revision:
                raise DraftConflict("A newer recovery copy exists. Review it before replacing it.")
            if not path.exists() and len(list(self.directory.glob("*.draft"))) >= MAX_RECORDS:
                raise ValueError("Recovery storage is full. Open Manage recovery storage to free space from discarded copies.")
            if record["revision"] >= MAX_REVISION:
                raise ValueError("Recovery revision capacity is exhausted. This copy has been kept.")
            record = {"context": self.context, "slot": slot, "revision": record["revision"] + 1,
                      "payload": payload, "updated_at": time.time(), "operation_id": operation_id,
                      "payload_sha256": digest, "retention_floor": self._floor()}
            atomic_write_bytes(path, seal(json.dumps(record, ensure_ascii=False, allow_nan=False).encode("utf-8")))
            return self._public(record)
