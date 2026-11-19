"""The name and verified email a person's sign-in reports, by sign-in.

People read as people in approvals, settings history and the Activity log
(:mod:`person_names`), not as "Google account". Company sign-in (OIDC) keeps
here, at every sign-in, only two facts the identity provider sent in the
verified ID token: the email when the provider marks it verified, and the
display name. Nothing else from the token is kept, and a sign-in that sends
neither removes the record.

Store: ``<maverick_home>/account-profiles.json`` (0600), one installation-wide
file keyed by sign-in, written atomically under a cross-process lock and
sealed with the deployment key when at-rest encryption is on. Bounded to
``_MAX_ENTRIES`` by last sign-in. It grants nothing: it only names people
where they are already shown. My data exports it and its reviewed deletion
erases it; deleting the account in the company directory (SCIM) erases it too.

``[auth] remember_account_names`` (``MAVERICK_REMEMBER_ACCOUNT_NAMES``),
default on: off stops recording and naming; kept records stay exportable and
erasable.
"""
from __future__ import annotations

import json
import os
import threading
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path

from maverick.file_lock import atomic_write_bytes, cross_process_lock, ensure_private_directory
from maverick.paths import maverick_home

_MAX_ENTRIES = 50_000
_MAX_TEXT = 200
_LOCK = threading.Lock()
_FALSE = {"0", "false", "no", "off"}


def _path() -> Path:
    return maverick_home() / "account-profiles.json"


def enabled() -> bool:
    raw = os.environ.get("MAVERICK_REMEMBER_ACCOUNT_NAMES", "").strip().lower()
    if raw:
        return raw not in _FALSE
    try:
        from maverick.config import config_source_errors, load_global_config

        if config_source_errors(include_tenant=False):
            return False  # unreadable settings: collect nothing
        value = (load_global_config().get("auth") or {}).get("remember_account_names", True)
    except Exception:  # noqa: BLE001 -- unreadable settings: collect nothing
        return False
    return value is not False


@contextmanager
def _locked():
    ensure_private_directory(maverick_home())
    with _LOCK, cross_process_lock(_path()):
        yield


def _read() -> dict[str, dict]:
    from maverick import crypto_at_rest

    try:
        raw = _path().read_bytes()
    except FileNotFoundError:
        return {}
    if crypto_at_rest.is_sealed(raw):
        with crypto_at_rest.deployment_key_scope():
            raw = crypto_at_rest.unseal(raw)
    data = json.loads(raw.decode("utf-8"))
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, dict):
        raise ValueError("The account name record is not readable.")
    return profiles


def _write(profiles: dict[str, dict]) -> None:
    from maverick import crypto_at_rest

    if len(profiles) > _MAX_ENTRIES:
        newest = sorted(profiles, key=lambda key: profiles[key].get("at", 0), reverse=True)[:_MAX_ENTRIES]
        profiles = {key: profiles[key] for key in newest}
    payload = json.dumps({"schema": 1, "profiles": profiles}, sort_keys=True).encode("utf-8")
    if crypto_at_rest.deployment_at_rest_enabled():
        with crypto_at_rest.deployment_key_scope():
            payload = crypto_at_rest.seal(payload)
    atomic_write_bytes(_path(), payload, mode=0o600)


def _text(value: object) -> str:
    """One readable line: no control or format characters, bounded."""
    if not isinstance(value, str):
        return ""
    kept = "".join(" " if unicodedata.category(char).startswith(("C", "Z")) else char for char in value)
    return " ".join(kept.split())[:_MAX_TEXT]


def from_claims(claims: dict) -> dict[str, str]:
    """The verified email and display name in verified ID-token claims."""
    from .oidc_login import _oidc_permission_email

    name = _text(claims.get("name")) or _text(" ".join(
        _text(claims.get(key)) for key in ("given_name", "family_name")))
    return {"email": _oidc_permission_email(claims), "name": name}


def record_sign_in(principal: str, claims: dict) -> None:
    """Keep what this sign-in reported; a sign-in with neither removes it."""
    if not isinstance(principal, str) or not principal.startswith("user:") or not enabled():
        return
    current = from_claims(claims or {})
    with _locked():
        profiles = _read()
        before = profiles.get(principal)
        if not (current["email"] or current["name"]):
            if before is None:
                return
            profiles.pop(principal)
        else:
            if before and {key: before.get(key) for key in current} == current \
                    and time.time() - float(before.get("at", 0)) < 86_400:
                return  # unchanged and recent: no write on every sign-in
            profiles[principal] = {**current, "at": time.time()}
        _write(profiles)


def get(principal: str) -> dict | None:
    with _locked():
        found = _read().get(principal)
    return dict(found) if found else None


def names() -> dict[str, str]:
    """Display name, else verified email, per sign-in (empty when turned off)."""
    if not enabled():
        return {}
    with _locked():
        profiles = _read()
    return {key: row.get("name") or row.get("email") for key, row in profiles.items()
            if row.get("name") or row.get("email")}


def erase(principals) -> int:
    """Remove these sign-ins' records; returns how many were removed."""
    wanted = {str(principal) for principal in principals if principal}
    with _locked():
        profiles = _read()
        removed = [key for key in wanted if key in profiles]
        if removed:
            for key in removed:
                profiles.pop(key)
            _write(profiles)
    return len(removed)
