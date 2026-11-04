"""Bounded, tenant-scoped delivery receipts containing no notification content."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)


class DeliveryReceipts:
    def __init__(self, path: Path | None = None):
        if path is None:
            from .paths import data_dir
            path = data_dir("notification-deliveries.json")
        self.path = path

    def _load(self) -> list[dict]:
        try:
            value = json.loads(atomic_read_text(self.path))
        except FileNotFoundError:
            return []
        if not isinstance(value, list) or len(value) > 1000:
            raise ValueError("Delivery history could not be read")
        return value

    def _save(self, rows: list[dict]) -> None:
        threshold = time.time() - 7 * 86400
        rows = [r for r in rows if r["updated_at"] >= threshold]
        atomic_write_text(self.path, json.dumps(rows[-1000:], separators=(",", ":")))

    @staticmethod
    def key(event: str, backend: str) -> str:
        return hashlib.sha256((event + "\0" + backend).encode()).hexdigest()

    def claim(self, event: str, backend: str, *, kind: str = "event", retry: bool = False) -> tuple[str, bool]:
        """Acquire one dispatch; duplicates never resend a queued/accepted item."""
        if kind not in {"event", "test"}:
            raise ValueError("Unknown delivery kind")
        if kind == "test":
            event = str(uuid.UUID(event))
        ident = self.key(event, backend)
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path):
            rows = [row for row in self._load() if row["updated_at"] >= time.time() - 7 * 86400]
            previous = next((row for row in rows if row["id"] == ident), None)
            if previous is not None:
                if not (retry and previous["kind"] == "test" and previous["state"] == "failed"
                        and previous["safe_to_retry"] and previous["attempts"] < 3):
                    return ident, False
                previous.update(state="queued", updated_at=time.time(), attempts=previous["attempts"] + 1,
                                safe_to_retry=False, message="Waiting to send.")
            else:
                if retry:
                    return ident, False
                if len(rows) >= 1000:
                    rows = self._make_room(rows)
                if len(rows) >= 1000:
                    raise ValueError("Delivery history is full; new sends are paused to preserve duplicate protection.")
                rows.append({"id": ident, "backend": backend, "kind": kind, "state": "queued",
                             "request_id": event if kind == "test" else None,
                             "updated_at": time.time(), "created_at": time.time(), "attempts": 1,
                             "safe_to_retry": False, "message": "Waiting to send."})
            self._save(rows)
            return ident, True

    @staticmethod
    def _make_room(rows: list[dict]) -> list[dict]:
        """Drop the oldest event whose send definitely failed and is safe to
        retry (nothing was sent, e.g. no destination configured), so a flood of
        such failures can never pause every other notification. Accepted,
        queued, sending and unknown rows -- and failures that are not safe to
        retry -- are never dropped: they are what duplicate protection rests on."""
        oldest = None
        for row in rows:
            if (row.get("kind") == "event" and row.get("state") == "failed" and row.get("safe_to_retry") is True
                    and (oldest is None or row["updated_at"] < oldest["updated_at"])):
                oldest = row
        return rows if oldest is None else [row for row in rows if row is not oldest]

    def update(self, ident: str, state: str, message: str, *, safe_to_retry: bool = False) -> None:
        with cross_process_lock(self.path):
            rows = self._load()
            record = next((row for row in rows if row["id"] == ident), None)
            if record is None:
                raise ValueError("Delivery receipt no longer exists")
            record.update(state=state, message=message, safe_to_retry=safe_to_retry, updated_at=time.time())
            self._save(rows)

    def recent(self, *, limit: int = 100) -> list[dict]:
        rows = self._load()
        now = time.time()
        out = []
        for row in sorted(rows, key=lambda r: r["updated_at"], reverse=True):
            if row["updated_at"] < now - 7 * 86400:
                continue
            item = dict(row)
            if item["state"] in {"queued", "sending"} and item["updated_at"] < now - 120:
                item.update(state="unknown", message="Delivery was interrupted. Its result is unknown; check the destination before sending again.", safe_to_retry=False)
            out.append(item)
        return out[:min(100, max(1, limit))]
