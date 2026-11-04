"""Exact named-owner model-test inventory and reviewed content erasure.

Physical operation IDs survive as tombstones: deleting private route metadata
must never make an old execute request become a new provider request.
"""
from __future__ import annotations

import hashlib
import json
import time

from . import model_tests
from .audit import audit_event
from .authority_effects import authority_effect_fence
from .paths import current_tenant_id_strict


def _context(owner):
    if not isinstance(owner, str) or not owner.startswith("user:"):
        raise ValueError("A named account is required for personal model-test records.")
    raw = json.dumps([current_tenant_id_strict(), "principal", owner], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _revision(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _blocked(row):
    return row.get("state") in {"queued", "executing", "unknown"} or row.get("state") not in {
        "prepared", "cancelled", "refused", "passed", "not_matched", "erased"}


def owned_inventory(owner):
    rows = model_tests.history(_context(owner))
    return {"version": _revision(rows), "count": sum(row.get("state") != "erased" for row in rows),
            "blocked": sum(_blocked(row) for row in rows),
            "retained": "Content-free operation tombstones and separate accounting/audit receipts remain. Unknown provider outcomes need reconciliation before erasure."}


def export_owned(owner):
    return {"checks": [model_tests.public(row) for row in model_tests.history(_context(owner))],
            "limits": "Synthetic test receipts only; no provider response text was saved. Accounting and provider records are separate."}


def erase_owned(owner, *, expected_version, actor, operation_id):
    if not isinstance(operation_id, str) or not 1 <= len(operation_id) <= 128:
        raise ValueError("An exact deletion operation is required.")
    context = _context(owner)
    with authority_effect_fence():
        def mutate(checks):
            rows = list(checks.values())
            if rows and all(row.get("state") == "erased" and row.get("erasure_operation") == operation_id for row in rows):
                return {"status": "unconfirmed" if any(row.get("erasure_audit_pending") for row in rows) else "confirmed", "removed": len(rows)}
            if _revision(rows) != expected_version:
                raise ValueError("Model test history changed. Review a new exact scope.")
            if any(_blocked(row) for row in rows):
                raise ValueError("Reconcile active or unknown model tests before deleting these receipts.")
            if audit_event("personal_model_tests_erasure_started", actor=actor, owner=owner,
                           operation_id=operation_id, count=len(rows)) is not True:
                raise RuntimeError("The deletion audit receipt was not acknowledged.")
            changed = 0
            for row in rows:
                if row.get("state") == "erased":
                    continue
                identity = row["id"]
                row.clear()
                row.update(id=identity, state="erased", erasure_operation=operation_id,
                           erasure_audit_pending=True, erased_at=time.time(),
                           message="Private test metadata was removed; this operation cannot be replayed.")
                changed += 1
            return {"status": "unconfirmed", "removed": changed}
        result = model_tests._edit(context, mutate)
        if result["status"] == "confirmed":
            return result
        try:
            acknowledged = audit_event("personal_model_tests_erased", actor=actor, owner=owner,
                                       operation_id=operation_id, count=result["removed"]) is True
        except Exception:
            acknowledged = False
        if acknowledged:
            def confirm(checks):
                for row in checks.values():
                    if row.get("state") == "erased" and row.get("erasure_operation") == operation_id:
                        row["erasure_audit_pending"] = False
                return {**result, "status": "confirmed"}
            return model_tests._edit(context, confirm)
        return result
