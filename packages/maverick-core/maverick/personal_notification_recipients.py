"""Explicit recipient enrollment, scoped to the current tenant and encrypted."""
from __future__ import annotations

import hashlib
import json
import logging
import time

from .crypto_at_rest import seal, unseal
from .file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
from .paths import current_tenant_id_strict, data_dir

log = logging.getLogger(__name__)


def _path():
    return data_dir("personal-notifications", "recipients.enc")


def _read():
    try:
        state = json.loads(unseal(_path().read_bytes()).decode())
    except FileNotFoundError:
        return {"tenant": current_tenant_id_strict(), "recipients": {}}
    if (not isinstance(state, dict) or state.get("tenant") != current_tenant_id_strict()
            or not isinstance(state.get("recipients"), dict) or len(state["recipients"]) > 1000):
        raise ValueError("Personal alert recipients could not be verified.")
    return state


def enroll(principal: str) -> None:
    if not isinstance(principal, str) or not principal.startswith("user:") or len(principal) > 256:
        raise ValueError("Personal alerts require a named account.")
    path = _path()
    ensure_private_directory(path.parent)
    with cross_process_lock(path):
        state = _read()
        if principal in state["recipients"]:
            return
        if len(state["recipients"]) >= 1000:
            raise ValueError("Personal alert enrollment is full. Ask an administrator to review inactive accounts.")
        state["recipients"][principal] = {"enrolled_at": time.time(), "observed_at": None}
        atomic_write_bytes(path, seal(json.dumps(state).encode()), mode=0o600)


def enroll_task_owner(principal: str) -> None:
    """Observe new named-account work without requiring the owner to open a page.

    Goal creation must remain available if optional alerts are misconfigured.
    The observer rechecks current membership before reading any private work.
    """
    if not isinstance(principal, str) or not principal.startswith("user:") or len(principal) > 256:
        return
    try:
        from . import config, experience_preferences
        from .personal_identity import principal_current
        from .personal_notifications import personal_alerts_on

        if (config.config_source_errors(include_tenant=True)
                or not experience_preferences.enabled()
                or not personal_alerts_on(config.load_config().get("notifications"))
                or not principal_current(principal)):
            return
        enroll(principal)
    except Exception as exc:
        # Never log the owner, task, path, or credential-bearing exception text.
        log.warning("Personal task alert enrollment unavailable (%s)", type(exc).__name__)


def principals() -> list[str]:
    return sorted(_read()["recipients"])


def observed(principal: str) -> None:
    path = _path()
    with cross_process_lock(path):
        state = _read()
        if principal not in state["recipients"]:
            return
        state["recipients"][principal]["observed_at"] = time.time()
        atomic_write_bytes(path, seal(json.dumps(state).encode()), mode=0o600)


def status(principal: str) -> dict:
    value = _read()["recipients"].get(principal, {})
    return {"enrolled_at": value.get("enrolled_at"), "last_observed_at": value.get("observed_at")}


def withdraw(principal: str) -> None:
    """Stop enrollment on current identity revocation; explicit reopen can reenroll."""
    path = _path()
    with cross_process_lock(path):
        state = _read()
        if state["recipients"].pop(principal, None) is None:
            return
        atomic_write_bytes(path, seal(json.dumps(state).encode()), mode=0o600)
    # Exact account key only; no directory-wide deletion or credential changes.
    inbox = data_dir("personal-notifications", hashlib.sha256(principal.encode()).hexdigest() + ".enc")
    with cross_process_lock(inbox):
        inbox.unlink(missing_ok=True)
    from .personal_notification_delivery import remove_personal_history
    remove_personal_history(principal)
