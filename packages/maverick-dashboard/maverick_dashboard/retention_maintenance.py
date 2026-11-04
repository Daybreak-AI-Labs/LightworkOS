"""Ordinary retention review and read-only interruption recovery.

All deletion goes through the existing policy/hold/audit-fenced native runner.
An uncertain store is never dispatched again by response recovery.
"""
from __future__ import annotations

import secrets
import time

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import retention_runs as native
from .auth import caller_principal, constant_time_equals, require_global_permission
from .draft_api import context_for


def authorize(request, expected_context=None):
    require_global_permission(request, "admin")
    context = context_for(request)
    if expected_context is not None and not constant_time_equals(expected_context, context):
        raise HTTPException(409, "Your account or workspace changed. Reopen retention before continuing.")
    return caller_principal(request) or "local administrator", context


def policy(request):
    authorize(request)
    selected, targets = native._scope()
    return {"context": context_for(request), "revision": native._fingerprint(selected, targets),
            "workspaces": [{"name": row["name"], "periods": [{"label": native.STORES[key][1], "days": days}
                for key, days in row["policy"].items()], "blocked": native._broad_blocked(row)} for row in targets]}


def preview(request, expected_context=None, expected_policy=None, operation_id=None):
    from maverick.authority_effects import authority_effect_fence
    from maverick.file_lock import cross_process_lock

    actor, context = authorize(request, expected_context)
    identity = operation_id or secrets.token_hex(16)
    with cross_process_lock(native._path(identity), strict=True), authority_effect_fence():
        authorize(request, context)
        if native._path(identity).exists():
            return view(request, native.read(identity, actor, context=context))
        if expected_policy is not None and policy(request)["revision"] != expected_policy:
            raise HTTPException(409, "The effective periods or preservation holds changed. Review current retention again.")
        from maverick.retention_review_bindings import RetentionReviewChanged

        try:
            receipt = native.preview(actor, context=context, run_id=identity)
        except RetentionReviewChanged as exc:
            raise HTTPException(409, str(exc)) from exc
    return view(request, receipt)


def read(request, identity):
    actor, context = authorize(request)
    return view(request, native.read(identity, actor, context=context))


def history(request):
    actor, context = authorize(request)
    # File-backed receipts are local to this installation. Examine a bounded
    # recent window, and never publish another account/workspace's reviews.
    paths = sorted(native._directory().glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:256]
    records = []
    for path in paths:
        try:
            receipt = native.read(path.stem, actor, context=context)
        except HTTPException as exc:
            if exc.status_code == 404:
                continue
            raise
        records.append({"id": receipt["id"], "created_at": receipt["created_at"], "status": receipt["status"],
                        "workspaces": ", ".join(row["name"] for row in receipt["targets"]),
                        "eligible": sum(step["eligible"] for step in receipt["steps"])})
        if len(records) == 30:
            break
    return {"context": context, "records": records, "coverage": "Your latest 30 reviews in the 256 most recently saved local receipts."}


def view(request, receipt):
    authorize(request, receipt.get("context", ""))
    selected, targets = native._scope()
    current = native._fingerprint(selected, targets) == receipt["policy_revision"]
    fresh = time.time() - receipt["created_at"] <= 600
    ready = receipt["status"] == "review" and current and fresh and not receipt.get("blocked_by_hold") and bool(receipt["steps"])
    public_steps = [{key: value for key, value in step.items() if key != "review_binding"} for step in receipt["steps"]]
    value = {**receipt, "steps": public_steps, "revision": native.revision(receipt), "current_policy": current,
             "can_apply": ready, "review_expired": not fresh and receipt["status"] == "review"}
    steps = receipt["steps"]
    removed = sum(step.get("removed", 0) for step in steps)
    value["removed"] = removed
    value["unresolved"] = receipt["status"] in {"running", "partial"} or any(
        step.get("uncertain_prior") or step.get("audit_record") == "unconfirmed" for step in steps)
    unknown = any(step["status"] in {"running", "unknown"} or step.get("uncertain_prior") or step.get("audit_record") == "unconfirmed" for step in steps)
    value["message"] = (
        f"Deletion completed. {removed} removals were confirmed. Completed deletions cannot be undone."
        if receipt["status"] == "completed" else
        f"The original deletion needs attention. {removed} removals are confirmed; other outcomes or activity records remain unconfirmed. Checking this receipt does not repeat deletion."
        if unknown else
        f"The original deletion stopped. {removed} removals are confirmed. Blocked stores were not deleted. Preview again for a new decision; checking this receipt does not repeat deletion."
        if value["unresolved"] else
        "This saved review is historical because its workspace policy or preservation holds changed. Preview again before deleting."
        if not current else
        "This review expired. Preview again before deleting." if not fresh else
        "Recorded preservation holds block deletion. The records owner must resolve them; confirmation cannot override them."
        if receipt.get("blocked_by_hold") else
        "No deletion periods are active. Choose periods above, save them, then preview again."
        if not steps else
        "Review these effective periods and eligible counts. No records have been deleted by this review."
    )
    return value


def apply(request, identity, *, confirm_holds, expected_context=None, expected_revision=None, operation_id=None):
    actor, context = authorize(request, expected_context)
    before = native.read(identity, actor, context=context)
    # Older API callers can keep their reviewed-run contract; new UI and
    # Copilot supply exact version and operation references automatically.
    expected_revision = expected_revision or native.revision(before)
    operation_id = operation_id or secrets.token_hex(16)
    result = native.apply(identity, actor, confirm_holds=confirm_holds, retry=False,
        authorize=lambda: authorize(request, context), context=context,
        expected_revision=expected_revision, operation_id=operation_id)
    value = view(request, result)
    value["own_execution"] = result.get("execution_id") == operation_id
    return value


def catalog_revision(value):
    return digest(value)
