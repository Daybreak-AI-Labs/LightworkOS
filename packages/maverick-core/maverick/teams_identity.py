"""Link Microsoft Teams accounts to Lightwork users.

The Teams channel only ever sees a Microsoft Entra object id (``aadObjectId``)
for the person who wrote a message or pressed a card button. Before that
person can decide an approval, an administrator maps that id (or the user
principal name they type on the Channels page) to a Lightwork user, or the
person redeems a one-time code in chat that an administrator issued for them.

Records live in ``~/.maverick/teams-identities.json`` (0600, same shape of
protection as the RBAC roster). The file holds no secrets: codes are stored
as SHA-256 digests and expire after fifteen minutes.

Shape::

    {"links": {"<teams id>": {"principal": "user:alice", "approver": true,
                               "upn": "alice@example.com", "linked_by": "...",
                               "linked_at": 1.0, "conversation": {...}}},
     "codes": {"<sha256>": {"principal": "user:alice", "approver": true,
                            "expires_at": 1.0, "issued_by": "..."}}}

``conversation`` is the last personal-chat reference the channel saw for the
person (service URL, conversation id, tenant id) so an approval card can be
posted to them proactively.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

CODE_TTL_SECONDS = 15 * 60
MAX_LINKS = 5000
_LOCK = threading.Lock()
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-@._")


class TeamsIdentityError(ValueError):
    """A link request the store refuses, with a plain sentence."""


def store_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / "teams-identities.json"


def normalize_teams_id(value: object) -> str:
    """Lower-case and trim an Entra object id or user principal name."""
    text = str(value or "").strip().lower()
    if not text or len(text) > 320 or any(ch not in _ID_CHARS for ch in text):
        raise TeamsIdentityError(
            "Enter the person's Microsoft Entra object ID or their sign-in address "
            "(user principal name), such as alice@example.com."
        )
    return text


def normalize_principal(value: object) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 300 or text != text.strip() or any(ch.isspace() for ch in text):
        raise TeamsIdentityError("Choose the Lightwork user to link.")
    return text if ":" in text else f"user:{text}"


def _load() -> dict:
    from .file_lock import atomic_read_text, ensure_private_directory, ensure_private_file

    path = store_path()
    ensure_private_directory(path.parent)
    if not path.exists():
        return {"links": {}, "codes": {}}
    ensure_private_file(path)
    try:
        data = json.loads(atomic_read_text(path))
    except (OSError, ValueError) as exc:
        raise TeamsIdentityError(f"Teams identity links are unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise TeamsIdentityError("Teams identity links are corrupt")
    links = data.get("links") if isinstance(data.get("links"), dict) else {}
    codes = data.get("codes") if isinstance(data.get("codes"), dict) else {}
    return {"links": links, "codes": codes}


def _write(data: dict) -> None:
    from .file_lock import atomic_write_text

    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True))


def _prune_codes(data: dict, now: float) -> None:
    data["codes"] = {
        digest: row for digest, row in data["codes"].items()
        if isinstance(row, dict) and float(row.get("expires_at") or 0) > now
    }


def _code_digest(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def link(teams_id: object, principal: object, *, approver: bool = False,
         actor: str = "", upn: str = "") -> dict:
    """Map a Teams account to a Lightwork user. Re-linking replaces the record."""
    key = normalize_teams_id(teams_id)
    who = normalize_principal(principal)
    with _LOCK:
        data = _load()
        if key not in data["links"] and len(data["links"]) >= MAX_LINKS:
            raise TeamsIdentityError("Too many Teams links; remove some first.")
        previous = data["links"].get(key) if isinstance(data["links"].get(key), dict) else {}
        row = {
            "principal": who,
            "approver": bool(approver),
            "upn": str(upn or previous.get("upn") or "").strip().lower(),
            "linked_by": str(actor or ""),
            "linked_at": time.time(),
        }
        if isinstance(previous.get("conversation"), dict):
            row["conversation"] = previous["conversation"]
        data["links"][key] = row
        _write(data)
    _audit("teams_identity_linked", actor, teams_id=key, principal=who, approver=bool(approver))
    return dict(row)


def unlink(teams_id: object, *, actor: str = "") -> bool:
    key = normalize_teams_id(teams_id)
    with _LOCK:
        data = _load()
        removed = data["links"].pop(key, None) is not None
        if removed:
            _write(data)
    if removed:
        _audit("teams_identity_unlinked", actor, teams_id=key)
    return removed


def list_links() -> list[dict]:
    """Every link, oldest first, without conversation references."""
    with _LOCK:
        data = _load()
    out = []
    for key, row in data["links"].items():
        if not isinstance(row, dict):
            continue
        out.append({"teams_id": key, "principal": str(row.get("principal") or ""),
                    "approver": bool(row.get("approver")), "upn": str(row.get("upn") or ""),
                    "linked_by": str(row.get("linked_by") or ""),
                    "linked_at": float(row.get("linked_at") or 0),
                    "can_be_reached": isinstance(row.get("conversation"), dict)})
    out.sort(key=lambda item: item["linked_at"])
    return out


def _find(data: dict, ids: list[str]) -> tuple[str, dict] | None:
    for candidate in ids:
        row = data["links"].get(candidate)
        if isinstance(row, dict):
            return candidate, row
    for key, row in data["links"].items():
        if isinstance(row, dict) and row.get("upn") and row["upn"] in ids:
            return key, row
    return None


def _candidates(*ids: object) -> list[str]:
    out = []
    for value in ids:
        try:
            out.append(normalize_teams_id(value))
        except TeamsIdentityError:
            continue
    return out


def principal_for(*ids: object) -> str | None:
    """The linked Lightwork user for any of ``ids`` (object id or UPN), or None."""
    ids = _candidates(*ids)
    if not ids:
        return None
    with _LOCK:
        found = _find(_load(), ids)
    return str(found[1].get("principal") or "") or None if found else None


def link_for(*ids: object) -> dict | None:
    ids = _candidates(*ids)
    if not ids:
        return None
    with _LOCK:
        found = _find(_load(), ids)
    if not found:
        return None
    key, row = found
    return {"teams_id": key, **row}


def remember_conversation(teams_id: object, conversation: dict) -> None:
    """Store the personal-chat reference the channel last saw for a linked person."""
    keys = _candidates(teams_id)
    if not keys or not isinstance(conversation, dict):
        return
    ref = {k: str(conversation.get(k) or "")[:2048]
           for k in ("service_url", "conversation_id", "tenant_id", "user_id")}
    if not ref["service_url"] or not ref["conversation_id"]:
        return
    with _LOCK:
        data = _load()
        row = data["links"].get(keys[0])
        if not isinstance(row, dict):
            return
        if row.get("conversation") != ref:
            row["conversation"] = ref
            _write(data)


def approver_links() -> list[dict]:
    """Links marked as approvers (with their last conversation, when known)."""
    with _LOCK:
        data = _load()
    return [{"teams_id": key, **row} for key, row in data["links"].items()
            if isinstance(row, dict) and row.get("approver")]


def issue_link_code(principal: object, *, approver: bool = False, actor: str = "") -> str:
    """A one-time code the person sends in chat as ``link <code>``. Shown once."""
    who = normalize_principal(principal)
    code = secrets.token_hex(4).upper()
    now = time.time()
    with _LOCK:
        data = _load()
        _prune_codes(data, now)
        if len(data["codes"]) >= 200:
            raise TeamsIdentityError("Too many unused link codes; wait for some to expire.")
        data["codes"][_code_digest(code)] = {"principal": who, "approver": bool(approver),
                                             "expires_at": now + CODE_TTL_SECONDS,
                                             "issued_by": str(actor or "")}
        _write(data)
    _audit("teams_link_code_issued", actor, principal=who, approver=bool(approver))
    return code


def redeem_link_code(code: object, teams_id: object, *, upn: str = "",
                     conversation: dict | None = None) -> str | None:
    """Link the Teams account that typed ``code``. Returns the principal, or None."""
    text = str(code or "").strip()
    if not 6 <= len(text) <= 16:
        return None
    key = normalize_teams_id(teams_id)
    now = time.time()
    with _LOCK:
        data = _load()
        _prune_codes(data, now)
        row = data["codes"].pop(_code_digest(text), None)
        if not isinstance(row, dict):
            _write(data)
            return None
        record = {"principal": row["principal"], "approver": bool(row.get("approver")),
                  "upn": str(upn or "").strip().lower(),
                  "linked_by": str(row.get("issued_by") or ""), "linked_at": now}
        if isinstance(conversation, dict):
            record["conversation"] = conversation
        data["links"][key] = record
        _write(data)
    _audit("teams_identity_linked", str(row.get("issued_by") or ""), teams_id=key,
           principal=row["principal"], approver=bool(row.get("approver")), via="link_code")
    return str(row["principal"])


def _audit(action: str, actor: str, **fields) -> None:
    try:
        from . import audit

        audit.audit_event(audit.EventKind.CONSENT_RESULT, agent=actor or "system",
                          action=action, channel="teams", **fields)
    except Exception:  # noqa: BLE001 -- a link never fails because the log is down
        import logging

        logging.getLogger(__name__).warning("teams identity audit failed", exc_info=True)


__all__ = ["TeamsIdentityError", "approver_links", "issue_link_code", "link", "link_for",
           "list_links", "normalize_principal", "normalize_teams_id", "principal_for",
           "redeem_link_code", "remember_conversation", "store_path", "unlink"]
