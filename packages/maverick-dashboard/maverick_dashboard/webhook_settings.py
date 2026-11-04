"""Effective webhook settings, with reviewed generations and secret-free receipts.

Deployment sources retain their existing precedence. This service owns only the
dashboard overlay; it cannot migrate a process manager or mounted vault. External
files do not share our lock: verify before/after, roll back a rejected local write,
and make no cross-process-manager transaction or remote sender readiness claim.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import stat
import uuid
from collections.abc import Callable
from pathlib import Path

from maverick import config, secret_provider, webhooks
from maverick.crypto_at_rest import (
    deployment_key_scope,
    is_sealed_str,
    seal_to_str,
    unseal_from_str,
)

from . import settings_store

_PURPOSE = "lightwork.webhook-settings.v1"
_MAX_SOURCE_BYTES = 4 * 1024 * 1024
_SOURCE_LABELS = {
    "none": "No signing secret is active.",
    "dashboard": "Managed here in Lightwork.",
    "config": "A saved installation setting is active. You can replace it here.",
    "external_secret": "Managed by your installation's secret service or startup settings.",
    "operator": "Managed by your installation's deployment settings.",
    "tenant": "Managed by this workspace's deployment settings.",
}


class WebhookSettingsConflict(RuntimeError):
    """Reviewed authority or effective ownership changed."""


class WebhookSettingsUnavailable(RuntimeError):
    """A trustworthy current state or confirmed local write is unavailable."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _file_identity(path: Path) -> dict:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except FileNotFoundError:
        if path.is_symlink():
            raise WebhookSettingsUnavailable("A secret-service link is unavailable. Refresh status or contact your installation administrator.") from None
        return {"path": str(path.absolute()), "sha256": None}
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_SOURCE_BYTES:
        raise WebhookSettingsUnavailable("A webhook settings source cannot be checked safely. Contact your installation administrator.")
    with resolved.open("rb") as handle:
        raw = handle.read(_MAX_SOURCE_BYTES + 1)
    if len(raw) > _MAX_SOURCE_BYTES:
        raise WebhookSettingsUnavailable("A webhook settings source is too large to check safely. Contact your installation administrator.")
    return {"path": str(path.absolute()), "target": str(resolved), "sha256": hashlib.sha256(raw).hexdigest()}


def _layers() -> list[tuple[str, Path]]:
    result = [("config", config.config_path()), ("dashboard", config.dashboard_overrides_path())]
    operator = os.environ.get(config.CONFIG_OVERLAY_ENV)
    if operator:
        result.append(("operator", Path(operator).expanduser()))
    tenant = config.tenant_config_path()
    if tenant is not None:
        result.append(("tenant", tenant))
    return result


def _snapshot() -> dict:
    """Private snapshot. Secrets and unkeyed hashes never leave this module."""
    config.reset_config_cache()
    layers = _layers()
    files = [(source, _file_identity(path)) for source, path in layers]
    files.append(("installer_environment", _file_identity(config.config_path().parent / ".env")))
    config.load_config()  # includes installer environment and authenticated unsealing
    value = fallback = None
    source = fallback_source = "none"
    dashboard_set = False
    for name, path in layers:
        loaded = config._load_config_file(path, interpolate=name != "tenant")
        section = loaded.get("webhooks", {})
        if not isinstance(section, dict):
            raise WebhookSettingsUnavailable("Webhook settings could not be read safely. Refresh status before making a change.")
        if "secret" in section:
            candidate = section["secret"]
            if not isinstance(candidate, str):
                raise WebhookSettingsUnavailable("Webhook settings could not be read safely. Contact your installation administrator.")
            value, source = webhooks._expand_env(candidate), name
            if name != "dashboard":
                fallback, fallback_source = value, source
            else:
                dashboard_set = True
    if config.config_source_errors():
        raise WebhookSettingsUnavailable("Webhook settings could not be read safely. Contact your installation administrator.")
    backend = secret_provider._backend()
    directory = secret_provider._secrets_dir() if backend == "file" else None
    if directory is not None:
        files.extend(("secret_mount", _file_identity(directory / name)) for name in (
            "MAVERICK_WEBHOOK_SECRET", "maverick_webhook_secret",
        ))
    external = secret_provider.get_secret("MAVERICK_WEBHOOK_SECRET")
    outbound, outbound_fallback = value, fallback
    if external:
        value = fallback = external
        outbound = outbound_fallback = external
        source = fallback_source = "external_secret"
    # This panel manages the legacy outbound credential; inbound control
    # requests use their independently configured startup secret.
    observed = external or webhooks._load_config_outbound()[1]
    if observed != value or webhooks._load_config_outbound()[1] != outbound or files[:len(layers)] != [(name, _file_identity(path)) for name, path in layers]:
        raise WebhookSettingsConflict("Webhook settings changed while they were being checked. Refresh status and review again.")
    material = {"files": files, "value": value, "source": source,
                "external": external, "backend": backend, "directory": str(directory),
                "fallback": fallback, "fallback_source": fallback_source,
                "outbound": outbound, "outbound_fallback": outbound_fallback}
    authority = dict(material, files=[row for row in files if row[0] != "dashboard"])
    # The effective value changes when our overlay changes; external identity
    # instead binds the fallback and exact non-dashboard sources.
    authority.pop("value")
    authority.pop("source")
    authority.pop("outbound")
    return {"fingerprint": _digest(material), "authority": _digest(authority),
            "value": value, "source": source, "dashboard_set": dashboard_set,
            "storage_writable": not config.dashboard_overrides_path().is_symlink(),
            "fallback": fallback, "fallback_source": fallback_source,
            "outbound": outbound, "outbound_fallback": outbound_fallback}


def _stable_snapshot() -> dict:
    first, second = _snapshot(), _snapshot()
    if first != second:
        raise WebhookSettingsConflict("Webhook settings changed while they were being checked. Refresh status and review again.")
    return second


def _public(snapshot: dict, principal: str) -> dict:
    with deployment_key_scope():
        token = seal_to_str(json.dumps({"purpose": _PURPOSE, "principal": principal,
                                       "fingerprint": snapshot["fingerprint"]}, sort_keys=True))
    source = snapshot["source"]
    return {"schema": 1, "configured": bool(snapshot["value"]), "source": source,
            "context": _digest([_PURPOSE, principal, str(config.dashboard_overrides_path().absolute()),
                                str(config.tenant_config_path())]),
            "outbound_configured": bool(snapshot["outbound"]),
            "ownership": _SOURCE_LABELS[source], "storage_writable": snapshot["storage_writable"],
            "can_set": snapshot["storage_writable"] and source in {"none", "config", "dashboard"},
            "can_remove": snapshot["storage_writable"] and snapshot["dashboard_set"], "app_copy_present": snapshot["dashboard_set"],
            "remove_keeps_configured": bool(snapshot["fallback"]),
            "remove_keeps_outbound_configured": bool(snapshot["outbound_fallback"]),
            "expected_generation": token}


def state(*, principal: str, authorize: Callable[[], None]) -> dict:
    try:
        with settings_store._locked(strict=True):
            authorize()
            snapshot = _stable_snapshot()
            authorize()
            return _public(snapshot, principal)
    except (WebhookSettingsConflict, WebhookSettingsUnavailable):
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise WebhookSettingsUnavailable("Webhook settings are unavailable. Refresh status before making a change.") from exc


def _check_generation(token: str, snapshot: dict, principal: str) -> None:
    try:
        if not isinstance(token, str) or len(token) > 4096 or not is_sealed_str(token):
            raise ValueError("invalid generation")
        with deployment_key_scope():
            reviewed = json.loads(unseal_from_str(token))
        expected = {"purpose": _PURPOSE, "principal": principal, "fingerprint": snapshot["fingerprint"]}
        if not hmac.compare_digest(_digest(reviewed), _digest(expected)):
            raise ValueError("stale generation")
    except Exception as exc:
        raise WebhookSettingsConflict("Webhook settings changed or this review expired. Refresh status and review the change again.") from exc


def rotate(*, secret: str, action: str, expected_generation: str,
           principal: str, authorize: Callable[[], None]) -> dict:
    if action not in {"set", "remove"} or not isinstance(secret, str) or len(secret) > 4096:
        raise ValueError("Enter a signing secret of no more than 4,096 characters.")
    cleaned = secret.strip()
    if action == "set" and (not cleaned or cleaned.startswith(("${", "MVKAR1:"))):
        raise ValueError("Enter a new signing secret, then review and save it.")
    if action == "remove" and cleaned:
        raise ValueError("Clear the new secret field before removing the saved copy.")
    try:
        with settings_store._locked(strict=True):
            authorize()
            before = _stable_snapshot()
            _check_generation(expected_generation, before, principal)
            if not before["storage_writable"]:
                raise WebhookSettingsConflict("The app's settings use a linked installation location. Nothing was saved. Ask your installation administrator to make this location directly writable before changing secrets here.")
            if action == "set" and before["source"] not in {"none", "config", "dashboard"}:
                raise WebhookSettingsConflict(
                    "Your installation controls the active secret. Nothing was saved. Ask its administrator to arrange a transfer of control; this page cannot change that secret service."
                )
            if action == "remove" and not before["dashboard_set"]:
                raise WebhookSettingsConflict("There is no app-saved secret to remove. Refresh status.")
            return _commit(before, cleaned, action, principal, authorize)
    except (WebhookSettingsConflict, WebhookSettingsUnavailable):
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise WebhookSettingsUnavailable("The change could not be confirmed. Refresh status before trying again.") from exc


def _commit(before: dict, cleaned: str, action: str, principal: str,
            authorize: Callable[[], None]) -> dict:
    path = config.dashboard_overrides_path()
    existed = path.exists()
    raw = path.read_bytes() if existed else None
    mode = stat.S_IMODE(path.stat().st_mode) if existed else None
    data = settings_store._load_overlay_for_update()
    settings_store._unseal_overlay(copy.deepcopy(data))
    if action == "set":
        data.setdefault("webhooks", {})["secret"] = cleaned
    else:
        data.get("webhooks", {}).pop("secret", None)
    authorize()
    if _stable_snapshot() != before:
        raise WebhookSettingsConflict("Webhook settings changed. Refresh status and review again.")
    operation_id = uuid.uuid4().hex
    from . import webhook_settings_recovery as recovery

    # Seal once before publication, so recovery can identify the exact bytes
    # intended by this review rather than guessing from a matching secret.
    prepared_text = settings_store._dump(data)
    data = settings_store._tomllib().loads(prepared_text)
    prepared_text = settings_store._dump(data)
    journal = recovery.prepare(before, cleaned, action, principal, operation_id, prepared_text)
    _record(principal, action, before, None, operation_id, "reviewed")
    journal = recovery.reviewed(journal)
    try:
        settings_store._write(data)
        authorize()
        after = _stable_snapshot()
        expected = cleaned if action == "set" else before["fallback"]
        expected_outbound = cleaned if action == "set" else before["outbound_fallback"]
        if after["authority"] != before["authority"] or after["value"] != expected or after["outbound"] != expected_outbound:
            raise WebhookSettingsConflict("The change did not become active. The app's previous settings were restored. Refresh status.")
        result = _public(after, principal)
        _record(principal, action, before, after, operation_id, "confirmed")
    except Exception:
        try:
            settings_store._restore_provider_overlay(path=path, existed=existed,
                previous_bytes=raw, previous_mode=mode)
        except Exception as exc:
            raise WebhookSettingsUnavailable("The change could not be confirmed or restored. Refresh status and contact your installation administrator before trying again.") from exc
        raise
    result["result"] = "active" if action == "set" else "app_copy_removed"
    try:
        recovery.completed(journal, after, "reviewed_change")
    except Exception:
        # The accepted outcome already exists. Keep its pending journal for
        # exact-state readback; do not roll back an audit-confirmed publication.
        result["history_pending"] = True
    result["operation_id"] = operation_id
    return result


def _record(principal: str, action: str, before: dict, after: dict | None,
            operation_id: str, phase: str) -> None:
    """Link reviewed intent to verified outcome; never record secret material."""
    from maverick.audit import AuditRefused, EventKind, audit_event

    try:
        accepted = audit_event(
            EventKind.SETTING_CHANGED, agent="dashboard", _global=True,
            actor=principal, section="webhooks", key="secret", action=action,
            operation_id=operation_id, phase=phase,
            old="set" if before["value"] else "not set",
            new=("set" if after["value"] else "not set") if after else "unconfirmed",
            old_source=before["source"],
            new_source=after["source"] if after else "unconfirmed",
            source="settings",
        )
    except AuditRefused as exc:
        raise WebhookSettingsUnavailable(
            "The activity record refused this change. No new setting was kept.") from exc
    if not accepted:
        raise WebhookSettingsUnavailable(
            "The activity record could not confirm this change. Refresh status before trying again.")
