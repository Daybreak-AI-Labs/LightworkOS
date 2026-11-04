"""Tenant-scoped, server-authored success receipts for finance schedulers."""
from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

_SCHEMA = "lightwork.finance-operations-health.v1"
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_MAX_RECEIPTS = 256
_MAX_FILE_BYTES = 256 * 1024


def _path() -> Path:
    from ..paths import data_dir

    return data_dir("finance_operations", "scheduler_health.json")


def _load(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            raise ValueError("finance operations health receipt is oversized")
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema": _SCHEMA, "receipts": {}}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("finance operations health receipt is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema") != _SCHEMA:
        raise ValueError("finance operations health receipt schema is invalid")
    receipts = value.get("receipts")
    if not isinstance(receipts, dict) or len(receipts) > _MAX_RECEIPTS:
        raise ValueError("finance operations health receipt set is invalid")
    for receipt_id, row in receipts.items():
        if not isinstance(receipt_id, str) or not isinstance(row, dict):
            raise ValueError("finance operations health receipt is invalid")
        succeeded_at = row.get("succeeded_at")
        if (
            isinstance(succeeded_at, bool)
            or not isinstance(succeeded_at, (int, float))
            or not math.isfinite(float(succeeded_at))
            or float(succeeded_at) <= 0
        ):
            raise ValueError("finance operations health timestamp is invalid")
    return value


def _encoded_state(receipts: Mapping[str, Any]) -> str:
    return json.dumps(
        {"schema": _SCHEMA, "receipts": receipts},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _bounded_receipts(
    receipts: dict[str, Any],
    *,
    retained_id: str,
) -> tuple[dict[str, Any], str]:
    """Evict oldest receipts until count and encoded-byte bounds both hold."""

    def _oldest_removable() -> str | None:
        candidates = (
            (receipt_id, row)
            for receipt_id, row in receipts.items()
            if receipt_id != retained_id
        )
        oldest = min(
            candidates,
            key=lambda item: (float(item[1]["succeeded_at"]), item[0]),
            default=None,
        )
        return None if oldest is None else oldest[0]

    while len(receipts) > _MAX_RECEIPTS:
        oldest = _oldest_removable()
        if oldest is None:
            raise ValueError("finance operations health receipt cannot fit its count bound")
        receipts.pop(oldest)

    payload = _encoded_state(receipts)
    while len(payload.encode("utf-8")) > _MAX_FILE_BYTES:
        oldest = _oldest_removable()
        if oldest is None:
            raise ValueError("finance operations health receipt cannot fit its storage bound")
        receipts.pop(oldest)
        payload = _encoded_state(receipts)
    return receipts, payload


def record_success(
    component: str,
    key: str,
    *,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically record one successful scheduled operation for this tenant."""
    component_id = str(component or "").strip()
    operation_key = str(key or "").strip()
    if _KEY.fullmatch(component_id) is None or _KEY.fullmatch(operation_key) is None:
        raise ValueError("finance operations receipt component and key are invalid")
    observed = time.time()
    if not math.isfinite(observed) or observed <= 0:  # pragma: no cover - system clock failure
        raise ValueError("finance operations receipt timestamp is invalid")
    safe_details = dict(details or {})
    encoded_details = json.dumps(
        safe_details,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(encoded_details.encode("utf-8")) > 16 * 1024:
        raise ValueError("finance operations receipt details are oversized")

    from ..file_lock import atomic_write_text, cross_process_lock

    path = _path()
    lock_path = path.with_suffix(path.suffix + ".lock")
    receipt_id = f"{component_id}:{operation_key}"
    with cross_process_lock(lock_path, strict=True):
        state = _load(path)
        receipts = dict(state["receipts"])
        receipts[receipt_id] = {
            "component": component_id,
            "key": operation_key,
            "succeeded_at": observed,
            "details": json.loads(encoded_details),
        }
        receipts, payload = _bounded_receipts(
            receipts,
            retained_id=receipt_id,
        )
        atomic_write_text(path, payload, mode=0o600)
    return dict(receipts[receipt_id])


def success_receipts(*, component: str | None = None) -> list[dict[str, Any]]:
    """Return validated receipts for the active tenant, newest first."""
    from ..file_lock import cross_process_lock

    selected = None if component is None else str(component or "").strip()
    if selected is not None and _KEY.fullmatch(selected) is None:
        raise ValueError("finance operations receipt component is invalid")
    path = _path()
    with cross_process_lock(path.with_suffix(path.suffix + ".lock"), strict=True):
        rows = list(_load(path)["receipts"].values())
    if selected is not None:
        rows = [row for row in rows if row.get("component") == selected]
    return sorted(
        (dict(row) for row in rows),
        key=lambda row: (-float(row["succeeded_at"]), str(row["key"])),
    )


__all__ = ["record_success", "success_receipts"]
