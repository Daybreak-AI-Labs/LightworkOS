"""Private local handoff of an already reviewed administrator maintenance grant.

No operation is executed here. Browser authorization and final native confirmation
remain separate; the grant never needs to enter a clipboard or a native webview.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from . import installation_recovery as recovery
from .constant_time import text_equals


def _review_digest(release: dict) -> str:
    return hashlib.sha256(json.dumps(release, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _release(value: dict) -> dict:
    if not isinstance(value, dict) or not recovery._VERSION.fullmatch(str(value.get("version", ""))):
        raise recovery.MaintenanceError("The native release review is incomplete.")
    if any(not re.fullmatch(r"[a-f0-9]{64}", str(value.get(key, ""))) for key in ("runtime_sha256", "installer_sha256")):
        raise recovery.MaintenanceError("The release needs exact application and installer identities.")
    signature = value.get("signature")
    if not isinstance(signature, str) or not signature or len(signature) > 16384:
        raise recovery.MaintenanceError("The release signature is incomplete.")
    return {key: value[key] for key in ("version", "runtime_sha256", "installer_sha256", "signature")}


def save_review(release: dict) -> dict:
    """Native read/review only; a feed cannot authorize maintenance."""
    selected = _release(release)
    with recovery._locked():
        record = {"schema": 1, "target": recovery._target(), "id": secrets.token_hex(16),
                  "kind": "native-release-review", "release": selected,
                  "release_sha256": _review_digest(selected), "expires_at": time.time() + 1800}
        recovery._write(recovery._store() / "native-review.json", record)
        return public_review(record)


def public_review(record: dict) -> dict:
    return {key: record[key] for key in ("id", "release", "release_sha256", "expires_at")}


def current_review() -> dict | None:
    try:
        path = recovery._store() / "native-review.json"
        if not path.exists():
            return None
        record = recovery._read(path)
        if record.get("kind") != "native-release-review" or record.get("expires_at", 0) <= time.time():
            return None
        return public_review(record)
    except (OSError, ValueError, KeyError, TypeError, recovery.MaintenanceError):
        # An unreadable or foreign review is no review. The Install & updates
        # panel must still list and retire recovery points, and authorizing an
        # upgrade fails closed ("expired or changed").
        return None


def reviewed_release(identifier: str) -> dict:
    record = current_review()
    if record is None or not text_equals(str(record["id"]), str(identifier)):
        raise recovery.MaintenanceError("The exact native release review expired or changed. Check for updates again and review the new target.")
    return _release(record["release"])


def publish(authorization: str, *, actor_label: str) -> dict:
    """Only the authenticated recovery route calls this after administrator consent."""
    with recovery._locked():
        _, grant = recovery._grant(authorization)
        if grant["operation"] == "upgrade" and not grant.get("reviewed_new"):
            raise recovery.MaintenanceError("A native handoff requires an exact reviewed release.")
        payload = {"schema": 1, "target": recovery._target(), "kind": "maintenance-handoff",
                   "id": grant["id"], "authorization": authorization,
                   "actor": grant["actor"], "actor_label": str(actor_label)[:200],
                   "operation": grant["operation"], "old_version": grant["old_version"],
                   "new_version": grant["old_version"] if grant["operation"] == "rollback" else (grant.get("reviewed_new") or {}).get("version"),
                   "expires_at": grant["expires_at"], "scope": "All local workspaces and shared administration on this installation"}
        recovery._write(recovery._store() / "native-handoff.json", payload)
        return {key: value for key, value in payload.items() if key not in {"authorization", "actor", "schema", "target"}}


def inspect_handoff() -> dict:
    """Secret-bearing result goes only over the bounded native helper pipe."""
    with recovery._locked():
        path = recovery._store() / "native-handoff.json"
        if not path.exists():
            raise recovery.MaintenanceError("No native handoff is ready. Review this exact action as an administrator in Workspace recovery.")
        payload = recovery._read(path)
        _, grant = recovery._grant(payload.get("authorization"))
        if payload.get("kind") != "maintenance-handoff" or any(payload.get(key) != grant.get(key) for key in ("id", "actor", "operation", "old_version", "expires_at")):
            raise recovery.MaintenanceError("The maintenance handoff no longer matches its administrator approval.")
        return payload
