"""Digest-only, independently retainable references to a native journal prefix.

The file is not an external witness or a signature. Comparison is useful only
when the customer trusts the original file they retained independently of this
installation. Read and replay the immutable journal, never its mutable view.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from copy import copy
from pathlib import Path
from typing import Any

from .self_improvement import PromotionLedgerError

SCHEMA = "lightwork.learning-history-checkpoint.v1"
SCOPE = "native-promotion-journal.v1"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 4096
MAX_FILE_BYTES = 4096
_KEYS = {"schema", "scope", "saved_at", "record_count", "prefix_sha256", "checkpoint_sha256"}


class CheckpointUnavailable(ValueError):
    """The complete supported native source cannot be checked."""


class CheckpointInputError(ValueError):
    """The uploaded reference is not the exact supported file format."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _checksum(body: dict[str, Any]) -> str:
    return hashlib.sha256(b"lightwork.learning-history-checkpoint.v1\0" + _canonical(body)).hexdigest()


def history(ledger: Any) -> dict[str, Any]:
    """Read one bounded complete native journal, with no locks or source writes."""
    if ledger is None or getattr(ledger, "path", None) is None:
        raise CheckpointUnavailable("A checkpoint needs recorded, permanent learning history. There is no supported history here yet.")
    journal = Path(f"{ledger.path}.journal")
    if journal.is_symlink() or not journal.is_file():
        raise CheckpointUnavailable("This history has no supported permanent record. Older files and temporary histories cannot be checkpointed here.")
    try:
        with journal.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_SOURCE_BYTES:
                raise CheckpointUnavailable("This history exceeds the checkpoint limit of 16 MB. Nothing was omitted or changed; ask your administrator for a supported complete-history review.")
            raw = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(raw) > MAX_SOURCE_BYTES:
            raise CheckpointUnavailable("This history exceeds the checkpoint limit of 16 MB. No partial checkpoint was created.")
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise CheckpointUnavailable("Learning history changed while it was being read. Refresh and try again.")
        text = raw.decode("utf-8")
        lines = text.splitlines()
        if len(lines) > MAX_RECORDS:
            raise CheckpointUnavailable("This history exceeds the checkpoint limit of 4,096 stored records. Nothing was omitted or changed; ask your administrator for a supported complete-history review.")
        # The exact bytes we bounded are checked by the existing native replay
        # authority. A shallow copy also isolates its in-memory outbox refresh.
        copy(ledger)._replay_journal_text(text)
        events = [json.loads(line) for line in lines]
    except CheckpointUnavailable:
        raise
    except (OSError, UnicodeError, ValueError, PromotionLedgerError) as exc:
        raise CheckpointUnavailable("The current learning history could not be checked. Its stored checks may not match. Refresh; if this continues, ask your administrator to review it.") from exc
    return {"digests": [event["sha256"] for event in events],
            "adopted_changes": sum(event["event"] in {"promote", "commit"} for event in events),
            "restorations": sum(event["event"] == "rollback" for event in events)}


def build(current: dict[str, Any]) -> dict[str, Any]:
    digests = current["digests"]
    if not digests:
        raise CheckpointUnavailable("There is no recorded learning history to checkpoint yet.")
    body = {"schema": SCHEMA, "scope": SCOPE, "saved_at": time.time(),
            "record_count": len(digests), "prefix_sha256": digests[-1]}
    return {**body, "checkpoint_sha256": _checksum(body)}


def parse(text: str) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CheckpointInputError("This checkpoint file contains repeated fields. Choose the original downloaded file.")
            result[key] = value
        return result

    try:
        if len(text.encode("utf-8")) > MAX_FILE_BYTES:
            raise CheckpointInputError("The checkpoint file must be 4 KB or smaller. Choose the original downloaded checkpoint.")
        value = json.loads(text, object_pairs_hook=unique)
        if not isinstance(value, dict) or set(value) != _KEYS or value["schema"] != SCHEMA or value["scope"] != SCOPE:
            raise CheckpointInputError("Choose a Learning history checkpoint downloaded from Lightwork. A single receipt or another file cannot be checked here.")
        if type(value["record_count"]) is not int or not 1 <= value["record_count"] <= MAX_RECORDS:
            raise CheckpointInputError("This checkpoint has an unsupported record count. Choose the original downloaded file.")
        stamp = value["saved_at"]
        if type(stamp) not in (int, float) or not math.isfinite(stamp) or not 0 <= stamp <= 253402300799:
            raise CheckpointInputError("This checkpoint has an invalid date. Choose the original downloaded file.")
        for key in ("prefix_sha256", "checkpoint_sha256"):
            if not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
                raise CheckpointInputError("This checkpoint is incomplete. Choose the original downloaded file.")
        if _checksum({key: val for key, val in value.items() if key != "checkpoint_sha256"}) != value["checkpoint_sha256"]:
            raise CheckpointInputError("The checkpoint file's own check does not match. It may have changed; choose your original retained file.")
        return value
    except CheckpointInputError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise CheckpointInputError("The checkpoint file could not be read. Choose the original downloaded file.") from exc


def compare(reference: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    digests = current["digests"]
    count = reference["record_count"]
    matches = len(digests) >= count and digests[count - 1] == reference["prefix_sha256"]
    return {"matches": matches, "saved_at": reference["saved_at"], "checked_at": time.time(),
            "saved_records": count, "current_records": len(digests),
            "later_records": len(digests) - count if matches else None,
            "detail": "Every stored record covered by this checkpoint matches the current history. Later records are allowed." if matches else
                      "The saved history does not match this workspace's current history. Earlier records changed, are missing, or the file belongs to another history. Do not rely on this as an unchanged record.",
            "trust": "This comparison depends on the original file you kept independently. The file alone does not prove external custody, who approved a change, or that all real activity was recorded."}
