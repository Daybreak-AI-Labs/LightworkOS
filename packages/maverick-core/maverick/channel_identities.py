"""Identity linking: a chat account (Slack member, Teams user, email
address) -> the Lightwork person it belongs to.

A decision or a question from a chat app is only attributable when the chat
account is tied to a Lightwork principal (``user:<sub>``). Two ways to link:

* an administrator maps the account on the Users page (``method="admin"``);
* the person asks for a one-time code on their My work page and sends it
  from the chat app (``/lightwork link <code>``; ``method="code"``). Codes
  are stored hashed, last 15 minutes and work once.

Store: ``~/.maverick/channel-identities.json`` (0600, cross-process
locked, the same shape of store as the dashboard roster). Every link and
unlink is written to the audit log.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

CHANNELS = ("slack", "teams", "email")
CODE_TTL_SECONDS = 15 * 60
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # pragma: allowlist secret -- no 0/O/1/I look-alikes
_EXTERNAL_ID = re.compile(r"[^\s\"'<>{}]{1,254}")
_LOCK = threading.RLock()


class ChannelIdentityError(ValueError):
    """A link request that cannot be honoured (bad input or a taken account)."""


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "channel-identities.json"


def _key(channel: str, external_id: str) -> str:
    return f"{channel}:{external_id}"


def _clean_channel(channel: object) -> str:
    name = str(channel or "").strip().lower()
    if name not in CHANNELS:
        raise ChannelIdentityError("channel must be one of: " + ", ".join(CHANNELS))
    return name


def _clean_external(channel: str, external_id: object) -> str:
    value = str(external_id or "").strip()
    if channel == "email":
        value = value.lower()
    if not _EXTERNAL_ID.fullmatch(value):
        raise ChannelIdentityError("the chat account id is missing or malformed")
    return value


def _clean_principal(principal: object) -> str:
    value = str(principal or "").strip()
    if not value or len(value) > 512 or any(c.isspace() for c in value):
        raise ChannelIdentityError("a Lightwork person is required")
    return value


def _locked(path: Path):
    from contextlib import ExitStack

    from .file_lock import cross_process_lock, ensure_private_directory
    from .paths import maverick_home

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


def _load() -> dict[str, Any]:
    from .file_lock import atomic_read_text, ensure_private_file

    path = store_path()
    if not path.exists():
        return {"links": {}, "codes": {}}
    ensure_private_file(path)
    try:
        data = json.loads(atomic_read_text(path))
    except (OSError, ValueError) as exc:
        raise ChannelIdentityError(f"the chat account store is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise ChannelIdentityError("the chat account store is corrupt")
    links = data.get("links")
    codes = data.get("codes")
    return {
        "links": links if isinstance(links, dict) else {},
        "codes": codes if isinstance(codes, dict) else {},
    }


def _write(data: dict[str, Any]) -> None:
    from .file_lock import atomic_write_text

    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True))


def _audit(kind: str, *, channel: str, external_id: str, principal: str,
           actor: str, method: str) -> None:
    from . import audit

    audit.audit_event(
        kind, agent=actor or "system", channel=channel, external_id=external_id,
        principal=principal, actor=actor or "", method=method,
    )


def principal_for(channel: str, external_id: str) -> str | None:
    """The Lightwork person behind a chat account, or ``None`` when unlinked."""
    try:
        name = _clean_channel(channel)
        ext = _clean_external(name, external_id)
    except ChannelIdentityError:
        return None
    row = _load()["links"].get(_key(name, ext))
    if not isinstance(row, dict):
        return None
    principal = row.get("principal")
    return principal if isinstance(principal, str) and principal else None


def links_for(principal: str) -> list[dict[str, Any]]:
    """Every chat account linked to ``principal`` (newest first)."""
    rows = []
    for key, row in _load()["links"].items():
        if not isinstance(row, dict) or row.get("principal") != principal:
            continue
        channel, _, external_id = key.partition(":")
        rows.append({
            "channel": channel, "external_id": external_id,
            "linked_at": float(row.get("linked_at") or 0),
            "linked_by": str(row.get("linked_by") or ""),
            "method": str(row.get("method") or ""),
        })
    rows.sort(key=lambda r: -r["linked_at"])
    return rows


def all_links() -> dict[str, list[dict[str, Any]]]:
    """``{principal: [links]}`` for the Users page."""
    out: dict[str, list[dict[str, Any]]] = {}
    for key, row in _load()["links"].items():
        if not isinstance(row, dict) or not isinstance(row.get("principal"), str):
            continue
        channel, _, external_id = key.partition(":")
        out.setdefault(row["principal"], []).append({
            "channel": channel, "external_id": external_id,
            "linked_at": float(row.get("linked_at") or 0),
        })
    return out


def link(channel: str, external_id: str, principal: str, *, actor: str,
         method: str = "admin") -> dict[str, Any]:
    """Tie a chat account to a person. A chat account belongs to ONE person;
    linking it again to somebody else is refused (unlink first)."""
    name = _clean_channel(channel)
    ext = _clean_external(name, external_id)
    who = _clean_principal(principal)
    key = _key(name, ext)
    with _locked(store_path()):
        data = _load()
        existing = data["links"].get(key)
        if isinstance(existing, dict) and existing.get("principal") not in (None, who):
            raise ChannelIdentityError(
                "that chat account is already linked to a different person")
        # Granting access is audited first: if the deployment's audit policy
        # refuses (AuditRefused), no unaudited link is left behind.
        _audit("channel_identity_linked", channel=name, external_id=ext, principal=who,
               actor=actor, method=method)
        data["links"][key] = {
            "principal": who, "linked_at": time.time(),
            "linked_by": str(actor or ""), "method": method,
        }
        _write(data)
    return {"channel": name, "external_id": ext, "principal": who}


def unlink(channel: str, external_id: str, *, actor: str,
           expected_principal: str | None = None) -> bool:
    """Cut a chat account loose. With ``expected_principal`` only that person's
    own link is removed (the My work page); without it, an administrator's."""
    name = _clean_channel(channel)
    ext = _clean_external(name, external_id)
    key = _key(name, ext)
    with _locked(store_path()):
        data = _load()
        row = data["links"].get(key)
        if not isinstance(row, dict):
            return False
        if expected_principal is not None and row.get("principal") != expected_principal:
            return False
        principal = str(row.get("principal") or "")
        del data["links"][key]
        _write(data)
    _audit("channel_identity_unlinked", channel=name, external_id=ext,
           principal=principal, actor=actor, method="admin" if expected_principal is None else "self")
    return True


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _normalize_code(code: object) -> str:
    return "".join(ch for ch in str(code or "").upper() if ch.isalnum())


def issue_link_code(principal: str, channel: str, *, now: float | None = None,
                    ttl_seconds: int = CODE_TTL_SECONDS) -> dict[str, Any]:
    """Make a one-time code the person sends from the chat app. Only its hash
    is stored; a newer code for the same person+channel replaces the old one."""
    who = _clean_principal(principal)
    name = _clean_channel(channel)
    current = time.time() if now is None else float(now)
    code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))
    with _locked(store_path()):
        data = _load()
        codes = {
            digest: row for digest, row in data["codes"].items()
            if isinstance(row, dict) and float(row.get("expires_at") or 0) > current
            and not (row.get("principal") == who and row.get("channel") == name)
        }
        codes[_hash_code(code)] = {
            "principal": who, "channel": name, "expires_at": current + ttl_seconds,
        }
        data["codes"] = codes
        _write(data)
    return {"code": code, "channel": name, "expires_at": current + ttl_seconds}


def redeem_link_code(channel: str, external_id: str, code: str, *,
                     now: float | None = None) -> str | None:
    """Link ``external_id`` on ``channel`` to the person who issued ``code``.
    Returns the principal, or ``None`` for a wrong, expired or used code."""
    name = _clean_channel(channel)
    ext = _clean_external(name, external_id)
    current = time.time() if now is None else float(now)
    digest = _hash_code(_normalize_code(code))
    with _locked(store_path()):
        data = _load()
        row = data["codes"].get(digest)
        if (not isinstance(row, dict) or row.get("channel") != name
                or float(row.get("expires_at") or 0) <= current):
            return None
        who = str(row.get("principal") or "")
        existing = data["links"].get(_key(name, ext))
        if isinstance(existing, dict) and existing.get("principal") not in (None, who):
            return None
        # Audited before the code is spent and the link exists: a refusal
        # leaves the code redeemable and no unaudited link behind.
        _audit("channel_identity_linked", channel=name, external_id=ext, principal=who,
               actor=who, method="code")
        del data["codes"][digest]
        data["links"][_key(name, ext)] = {
            "principal": who, "linked_at": current, "linked_by": who, "method": "code",
        }
        _write(data)
    return who


__all__ = [
    "CHANNELS",
    "CODE_TTL_SECONDS",
    "ChannelIdentityError",
    "all_links",
    "issue_link_code",
    "link",
    "links_for",
    "principal_for",
    "redeem_link_code",
    "store_path",
    "unlink",
]
