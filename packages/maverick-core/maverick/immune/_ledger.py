"""Append-only, private, cross-process JSONL ledger shared by the immune layer."""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..file_lock import cross_process_lock, open_private_append


def canonical(obj: object) -> bytes:
    """The one byte form every digest in this package is computed over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def append(path: Path, record: dict) -> None:
    with cross_process_lock(path, strict=True):
        fd = open_private_append(path, require_private_parent=True)
        try:
            os.write(fd, canonical(record) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)


def read(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in text.splitlines() if line.strip()]
