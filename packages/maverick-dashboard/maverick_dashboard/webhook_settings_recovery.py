"""Private publication evidence for recovering one reviewed signing-key change.

Recovery checks an exact prepared local publication, never republishes credentials.
Only random identities and non-secret state labels enter the existing activity log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone

from maverick import config
from maverick.crypto_at_rest import (
    deployment_key_scope,
    seal_bound,
    seal_to_str,
    unseal_bound,
    unseal_from_str,
)
from maverick.file_lock import atomic_write_bytes, ensure_private_directory, ensure_private_file
from maverick.paths import tenant_scope

from . import settings_store
from . import webhook_settings as native

_ID = re.compile(r"[a-f0-9]{32}\Z")
_PURPOSE = "lightwork.webhook-change-recovery.v1"
_MAX_BYTES = 65536
_MAX_PENDING = 128
_RECENT = 64


def _directory():
    path = config.dashboard_overrides_path().parent / "webhook-change-recovery"
    if path.is_symlink():
        raise native.WebhookSettingsUnavailable("The saved change history cannot be checked safely. Contact your installation administrator.")
    return path


def _path(identity):
    if not isinstance(identity, str) or _ID.fullmatch(identity) is None:
        raise native.WebhookSettingsConflict("Choose one of your saved signing-secret changes.")
    return _directory() / (identity + ".enc")


def _binding(identity):
    return _PURPOSE + ":" + str(_directory().absolute()) + ":" + identity


def _save(row):
    raw = json.dumps(row, sort_keys=True, allow_nan=False).encode("utf-8")
    if len(raw) > _MAX_BYTES:
        raise native.WebhookSettingsUnavailable("This change is too large to retain safely. No new setting was saved.")
    ensure_private_directory(_directory())
    with tenant_scope(tenant=None), deployment_key_scope():
        blob = seal_bound(raw, _binding(row["id"]))
    atomic_write_bytes(_path(row["id"]), blob)


def _load(identity):
    path = _path(identity)
    if not path.exists():
        raise native.WebhookSettingsConflict("This saved change is no longer available. Refresh the recent change history.")
    if path.is_symlink() or path.stat().st_size > _MAX_BYTES * 2:
        raise native.WebhookSettingsUnavailable("The saved change cannot be checked safely. Nothing was repeated.")
    with tenant_scope(tenant=None), deployment_key_scope():
        raw = unseal_bound(ensure_private_file(path).read_bytes(), _binding(identity))
    row = json.loads(raw)
    if (not isinstance(row, dict) or row.get("id") != identity or row.get("purpose") != _PURPOSE
            or type(row.get("revision")) is not int or row["revision"] < 1
            or row.get("state") not in {"prepared", "reviewed", "completed"}):
        raise native.WebhookSettingsUnavailable("The saved change cannot be verified. Nothing was repeated.")
    return row


def _rows():
    directory = _directory()
    if not directory.exists():
        return []
    names = []
    for path in directory.iterdir():
        if path.name.endswith(".enc"):
            names.append(path.stem)
            if len(names) > _MAX_PENDING + _RECENT + 1:
                raise native.WebhookSettingsUnavailable("The saved change history exceeds its safe reading limit. Contact your installation administrator.")
    return [_load(identity) for identity in names]


def prepare(before, cleaned, action, principal, operation_id, prepared_text):
    """Called inside the native settings lock, before any activity or publication."""
    rows = _rows()
    completed = sorted((row for row in rows if row["state"] == "completed"), key=lambda row: row["created"], reverse=True)
    for row in completed[_RECENT - 1:]:
        _path(row["id"]).unlink()
    if sum(row["state"] != "completed" for row in rows) >= _MAX_PENDING:
        raise native.WebhookSettingsUnavailable("Too many signing-secret changes still need review. Resolve your saved changes here before making another change.")
    # atomic_write_text uses platform newline conversion; retain the exact
    # expected bytes privately, including fresh authenticated secret ciphertext.
    publication = hashlib.sha256(prepared_text.replace("\n", os.linesep).encode("utf-8")).hexdigest()
    row = {"purpose": _PURPOSE, "id": operation_id, "actor": principal,
           "context": native._public(before, principal)["context"], "action": action,
           "created": time.time(), "revision": 1, "state": "prepared", "before": before,
           "publication": publication, "target": cleaned if action == "set" else before["fallback"],
           "target_outbound": cleaned if action == "set" else before["outbound_fallback"]}
    _save(row)
    return row


def reviewed(row):
    row = dict(row, state="reviewed", revision=row["revision"] + 1)
    _save(row)
    return row


def completed(row, after, outcome):
    """Only after an accepted native activity outcome; discard private material."""
    row = {key: value for key, value in row.items() if key not in {"before", "publication", "target", "target_outbound"}}
    row.update(state="completed", revision=row["revision"] + 1, finished=time.time(), outcome=outcome,
               configured=bool(after["value"]), outbound_configured=bool(after["outbound"]), source=after["source"])
    _save(row)
    return row


def _outcome(row, current):
    if row["state"] == "completed":
        return row["outcome"]
    before = row["before"]
    if current == before:
        return "previous_state"
    publication = native._file_identity(config.dashboard_overrides_path())["sha256"]
    if (row["state"] == "reviewed" and current["authority"] == before["authority"]
            and publication == row["publication"] and current["value"] == row["target"]
            and current["outbound"] == row["target_outbound"]
            and current["dashboard_set"] is (row["action"] == "set") and current["storage_writable"]):
        return "reviewed_change"
    raise native.WebhookSettingsConflict("The active settings or their owner changed after this review. This attempt cannot be confirmed from the current state. No secret was saved again; review the active source before making a new change.")


def _plain(row, current, principal):
    available, explanation, outcome = True, "", ""
    if row["context"] != native._public(current, principal)["context"]:
        available, explanation = False, "Select the original workspace to review this change."
    elif row["state"] != "completed":
        try:
            outcome = _outcome(row, current)
        except native.WebhookSettingsConflict as exc:
            available, explanation = False, str(exc)
    status = "Saved change needs outcome review" if row["state"] != "completed" else (
        "Reviewed change verified" if row["outcome"] == "reviewed_change" else "Previous settings verified; change not confirmed")
    when = datetime.fromtimestamp(row["created"], timezone.utc).strftime("%b %d, %Y at %H:%M:%S UTC")
    value = {"id": row["id"], "revision": row["revision"], "completed": available and row["state"] == "completed", "label": ("Save new signing secret" if row["action"] == "set" else "Remove app-saved signing secret") + " · " + when,
             "status": status, "can_reconcile": available and row["state"] != "completed", "explanation": explanation,
             "summary": ("The exact reviewed local change is active. Add a verified current-state check to its activity history without saving the secret again. An earlier completion entry may already exist if its saved receipt was interrupted." if outcome == "reviewed_change" else
                         "The exact previous settings are active. Add a current-state check recording this attempt as not confirmed; this does not prove that a brief intermediate change never occurred." if outcome == "previous_state" else
                         "This is a historical activity outcome. The active settings may have changed since then.")}
    if value["can_reconcile"]:
        with deployment_key_scope():
            value["review"] = seal_to_str(json.dumps({"purpose": _PURPOSE, "id": row["id"], "actor": principal,
                "revision": row["revision"], "context": row["context"], "current": current["fingerprint"], "expires": time.time() + 600}, sort_keys=True))
    return value


def choices(*, principal, authorize):
    with settings_store._locked(strict=True):
        authorize()
        current = native._stable_snapshot()
        rows = [_plain(row, current, principal) for row in sorted(_rows(), key=lambda row: row["created"], reverse=True) if row["actor"] == principal]
        authorize()
        return {"records": rows, "detail": "Check interrupted changes without saving or sending a secret again. Each confirmed recovery adds a new verified observation to the original activity history. Recent completed records are historical; pending changes remain available to their original account."}


def reconcile(identity, token, *, principal, authorize):
    with settings_store._locked(strict=True):
        authorize()
        row, current = _load(identity), native._stable_snapshot()
        if row["actor"] != principal or row["context"] != native._public(current, principal)["context"]:
            raise native.WebhookSettingsConflict("This saved change is unavailable to the current account and workspace.")
        if row["state"] == "completed":
            return {"record": _plain(row, current, principal), "detail": "The saved verified check is already recorded. No setting or activity row was repeated by this request; this receipt is historical."}
        try:
            if not isinstance(token, str) or len(token) > 4096:
                raise ValueError("invalid review")
            with deployment_key_scope():
                review = json.loads(unseal_from_str(token))
            expected = {"purpose": _PURPOSE, "id": identity, "actor": principal, "revision": row["revision"],
                        "context": row["context"], "current": current["fingerprint"], "expires": review["expires"]}
            if review["expires"] <= time.time() or not hmac.compare_digest(native._digest(review), native._digest(expected)):
                raise ValueError("stale review")
        except Exception as exc:
            raise native.WebhookSettingsConflict("The saved change or active settings changed. Refresh and review this check again.") from exc
        outcome = _outcome(row, current)
        authorize()
        if native._stable_snapshot() != current:
            raise native.WebhookSettingsConflict("The settings changed during this check. Refresh and review again.")
        # This is verified current-state evidence, not retroactive proof of what
        # happened while the process was unavailable. Never call settings _write.
        try:
            native._record(principal, row["action"], row["before"], current, identity,
                           "reconciled_active" if outcome == "reviewed_change" else "reconciled_previous")
        except native.WebhookSettingsUnavailable as exc:
            raise native.WebhookSettingsUnavailable("The activity outcome was not accepted. Active settings were left untouched and this saved change still needs completion. Refresh before trying another check.") from exc
        row = completed(row, current, outcome)
        return {"record": _plain(row, current, principal), "detail": (
            "The exact reviewed change is currently active. A new verified state check was added to its original activity history. No secret was saved again and no outside system was contacted." if outcome == "reviewed_change" else
            "The exact previous settings are currently active. A new verified state check records this attempt as not confirmed. No secret was saved again. This cannot establish whether a brief intermediate change occurred.")}
