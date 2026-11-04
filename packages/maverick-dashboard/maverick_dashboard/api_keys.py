"""Personal and service-account API keys: a scoped, expiring bearer for
scripts and integrations.

A key is ``<prefix><43 random url-safe chars>`` (``lwk_...`` by default). It is
shown ONCE at creation; only its SHA-256 is stored, exactly like share links
(``world_model.create_share_link``) and invites (``invites._hash``). A key
carries a set of **scopes** -- a small readable vocabulary mapped onto the
four RBAC permission atoms every ``require_permission`` call site gates on --
and can never exceed its owner's role: the atoms it grants are capped by
``rbac.permissions_for(role_for_principal(owner))`` at creation AND on every
request (a demoted owner's keys shrink with them).

**Service accounts** are principals that cannot sign in interactively but hold
keys and a role. They reuse the existing principal/role model: a service
account ``billing-sync`` is the principal ``user:svc:billing-sync`` with a role
in the ordinary RBAC roster; ``auth`` refuses that subject on every
interactive path (OIDC, proxy, browser and invite sessions) so only a key
can act as it.

Store: ``~/.maverick/dashboard-api-keys.json`` (0600), one global
control-plane file like ``dashboard-users.json`` and ``dashboard-invites.json``.
Keys are looked up during authentication, BEFORE the request's workspace
(tenant) is pinned, so they cannot live in a per-tenant world database; the
identity control plane in this product is a global file store for that reason.
Every read-modify-write holds ``cross_process_lock`` (multiple dashboard
workers). A damaged store raises :class:`ApiKeyStoreError` and every reader
fails closed (no key authenticates).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

SERVICE_ACCOUNT_SUBJECT_PREFIX = "svc:"

# Scope vocabulary -> RBAC permission atom. The atom is still capped by the
# owner's current role. For operator actions, ``auth`` also checks the actual
# key scope: approval decisions and their queue require ``approvals:decide``;
# other operator routes require ``tasks:write``. Every scope implies ``view``
# (every role grants it; a caller who cannot view has no working API).
# ``admin`` grants every atom, like the admin role.
SCOPES: dict[str, tuple[str, str]] = {
    "tasks:read": ("view", "Read information available to your viewer role"),
    "tasks:write": ("operate", "Run tasks and use other operator actions outside the approval queue"),
    "approvals:decide": ("operate", "Review the shared approval queue and decide queued or paused workflow approvals"),
    "audit:read": ("audit", "Read viewer information and audit-gated records"),
    "settings:write": ("admin", "Use administrator-gated controls, but not operator or audit controls"),
    "admin": ("admin", "Use all viewer, operator, audit and administrator controls"),
}

_LABEL_MAX = 80
_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
_LAST_USED_WRITE_INTERVAL = 60.0
EXPIRY_WARNING_DAYS = 7

_STORE_LOCK = threading.Lock()
# key id -> last time last_used was persisted (rate-limits the write).
_last_used_written: dict[str, tuple[float, str]] = {}


class ApiKeyStoreError(RuntimeError):
    """The key store exists but cannot be trusted; readers fail closed."""


class ApiKeyError(ValueError):
    """A plain-language refusal for the API/page to show."""


@dataclass(frozen=True)
class ApiKey:
    id: str
    label: str
    owner: str            # principal, e.g. user:alice or user:svc:billing-sync
    prefix: str           # the key's first characters, safe to display
    scopes: tuple[str, ...]
    created_at: float
    expires_at: float
    created_by: str
    workspace: str = ""
    last_used_at: float | None = None
    last_used_ip: str = ""
    revoked_at: float | None = None
    grace_until: float | None = None   # after a rotation: the old key's end
    replaced_by: str = ""
    rotated_from: str = ""

    @property
    def is_service_account(self) -> bool:
        return is_service_account_principal(self.owner)

    def status(self, now: float | None = None) -> str:
        now = time.time() if now is None else now
        if self.revoked_at is not None:
            return "revoked"
        if now >= self.expires_at:
            return "expired"
        if self.grace_until is not None:
            return "replaced" if now >= self.grace_until else "rotating"
        if self.expires_at - now <= EXPIRY_WARNING_DAYS * 86400:
            return "expiring"
        return "active"

    def usable(self, now: float | None = None) -> bool:
        return self.status(now) in {"active", "expiring", "rotating"}

    def to_public(self, now: float | None = None) -> dict:
        return {
            "id": self.id, "label": self.label, "owner": self.owner,
            "service_account": self.is_service_account, "prefix": self.prefix,
            "scopes": list(self.scopes), "workspace": self.workspace,
            "created_at": self.created_at, "expires_at": self.expires_at,
            "created_by": self.created_by, "last_used_at": self.last_used_at,
            "last_used_ip": self.last_used_ip, "revoked_at": self.revoked_at,
            "grace_until": self.grace_until, "replaced_by": self.replaced_by,
            "rotated_from": self.rotated_from, "status": self.status(now),
        }


@dataclass(frozen=True)
class ServiceAccount:
    slug: str
    description: str
    created_by: str
    created_at: float
    disabled_at: float | None = None
    keys: tuple[ApiKey, ...] = field(default=())

    @property
    def principal(self) -> str:
        return service_account_principal(self.slug)

    def to_public(self) -> dict:
        return {
            "slug": self.slug, "principal": self.principal,
            "description": self.description, "created_by": self.created_by,
            "created_at": self.created_at, "disabled_at": self.disabled_at,
        }


# ---- settings ---------------------------------------------------------------

def settings() -> dict:
    from maverick.config import api_key_settings

    return api_key_settings()


def enabled() -> bool:
    return settings()["enabled"] is True


def key_prefix() -> str:
    return str(settings()["prefix"])


def looks_like_key(bearer: str) -> bool:
    """Whether a bearer has the configured key shape (cheap, no store read)."""
    if not bearer or not enabled():
        return False
    prefix = key_prefix()
    return bearer.startswith(prefix) and len(bearer) >= len(prefix) + 32


# ---- principals ------------------------------------------------------------

def service_account_principal(slug: str) -> str:
    return f"user:{SERVICE_ACCOUNT_SUBJECT_PREFIX}{slug}"


def is_service_account_subject(sub: str | None) -> bool:
    return isinstance(sub, str) and sub.startswith(SERVICE_ACCOUNT_SUBJECT_PREFIX)


def is_service_account_principal(principal: str | None) -> bool:
    return isinstance(principal, str) and principal.startswith(
        "user:" + SERVICE_ACCOUNT_SUBJECT_PREFIX)


# ---- scopes ----------------------------------------------------------------

def atoms_for_scopes(scopes) -> frozenset[str]:
    """The RBAC atoms a scope set grants (before the owner's cap)."""
    atoms = {"view"}
    for scope in scopes:
        atom = SCOPES.get(scope)
        if atom is None:
            raise ApiKeyError(f"unknown scope {scope!r}")
        if scope == "admin":
            from .rbac import PERMISSION_ATOMS
            atoms.update(PERMISSION_ATOMS)
        else:
            atoms.add(atom[0])
    return frozenset(atoms)


def owner_permissions(owner: str) -> frozenset[str]:
    """The atoms the owner's CURRENT role grants (the cap on every key)."""
    from . import rbac
    from .auth import role_for_principal

    try:
        return rbac.permissions_for(role_for_principal(owner))
    except Exception:
        return frozenset()


def scopes_available_to(owner: str) -> list[str]:
    """The scopes this owner may put on a key: those inside its role."""
    allowed = owner_permissions(owner)
    return [s for s, (atom, _help) in SCOPES.items()
            if atom in allowed and (s != "admin" or "admin" in allowed)]


def effective_permissions(key_scopes, owner: str) -> frozenset[str]:
    """What a key may do right now: its scopes, capped by its owner's role."""
    try:
        return atoms_for_scopes(key_scopes) & owner_permissions(owner)
    except ApiKeyError:
        return frozenset()


def _validate_scopes(scopes, owner: str) -> tuple[str, ...]:
    if not isinstance(scopes, (list, tuple)) or not scopes:
        raise ApiKeyError("choose at least one scope")
    cleaned: list[str] = []
    for scope in scopes:
        if not isinstance(scope, str) or scope not in SCOPES:
            raise ApiKeyError("that scope does not exist")
        if scope not in cleaned:
            cleaned.append(scope)
    allowed = owner_permissions(owner)
    for scope in cleaned:
        atom = SCOPES[scope][0]
        if atom not in allowed:
            raise ApiKeyError(
                f"the scope {scope} is more than this key's owner is allowed to do; "
                "a key can never do more than the person or service account that owns it"
            )
    return tuple(s for s in SCOPES if s in cleaned)


# ---- store ------------------------------------------------------------------

def store_path() -> Path:
    from maverick.paths import maverick_home

    return maverick_home() / "dashboard-api-keys.json"


def _locked(path: Path):
    from contextlib import ExitStack

    from maverick.authority_effects import authority_effect_fence
    from maverick.file_lock import cross_process_lock, ensure_private_directory
    from maverick.paths import maverick_home

    ensure_private_directory(maverick_home())
    ensure_private_directory(path.parent)
    with ExitStack() as stack:
        # Effects hold this fence while freshly verifying their explicit key.
        # Lifecycle changes must take the same fence before the key lock; a
        # service-account change can subsequently enter the RBAC writer too.
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_STORE_LOCK)
        stack.enter_context(cross_process_lock(path))
        return stack.pop_all()


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _decode_json(raw: str) -> object:
    def _reject_constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs):
        out: dict = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object)
    except (TypeError, ValueError) as exc:
        raise ApiKeyStoreError(f"API key store corrupt: {exc}") from exc


def _number(rec: dict, name: str, key_id: str, *, optional: bool = False) -> float | None:
    value = rec.get(name)
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ApiKeyStoreError(f"API key store corrupt: invalid {name} for {key_id!r}")
    return float(value)


def _text(rec: dict, name: str, key_id: str, *, limit: int = 512, allow_empty: bool = True) -> str:
    value = rec.get(name, "")
    if not isinstance(value, str) or len(value) > limit or (not allow_empty and not value):
        raise ApiKeyStoreError(f"API key store corrupt: invalid {name} for {key_id!r}")
    return value


def _validate_key(key_id: object, rec: object) -> dict:
    if not isinstance(key_id, str) or not key_id or not isinstance(rec, dict):
        raise ApiKeyStoreError("API key store corrupt: invalid key record")
    if rec.get("id") != key_id:
        raise ApiKeyStoreError(f"API key store corrupt: id mismatch for {key_id!r}")
    sha = rec.get("secret_sha256")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ApiKeyStoreError(f"API key store corrupt: invalid digest for {key_id!r}")
    scopes = rec.get("scopes")
    if not isinstance(scopes, list) or any(not isinstance(s, str) or s not in SCOPES for s in scopes):
        raise ApiKeyStoreError(f"API key store corrupt: invalid scopes for {key_id!r}")
    clean = {
        "id": key_id,
        "label": _text(rec, "label", key_id, limit=_LABEL_MAX, allow_empty=False),
        "owner": _text(rec, "owner", key_id, allow_empty=False),
        "prefix": _text(rec, "prefix", key_id, limit=32, allow_empty=False),
        "secret_sha256": sha,
        "scopes": list(scopes),
        "workspace": _text(rec, "workspace", key_id, limit=128),
        "created_at": _number(rec, "created_at", key_id),
        "expires_at": _number(rec, "expires_at", key_id),
        "created_by": _text(rec, "created_by", key_id),
        "last_used_at": _number(rec, "last_used_at", key_id, optional=True),
        "last_used_ip": _text(rec, "last_used_ip", key_id, limit=64),
        "revoked_at": _number(rec, "revoked_at", key_id, optional=True),
        "grace_until": _number(rec, "grace_until", key_id, optional=True),
        "replaced_by": _text(rec, "replaced_by", key_id, limit=64),
        "rotated_from": _text(rec, "rotated_from", key_id, limit=64),
    }
    return clean


def _validate_account(slug: object, rec: object) -> dict:
    if not isinstance(slug, str) or not _SLUG_RE.match(slug) or not isinstance(rec, dict):
        raise ApiKeyStoreError("API key store corrupt: invalid service account")
    return {
        "slug": slug,
        "description": _text(rec, "description", slug, limit=200),
        "created_by": _text(rec, "created_by", slug),
        "created_at": _number(rec, "created_at", slug),
        "disabled_at": _number(rec, "disabled_at", slug, optional=True),
    }


def _load() -> dict:
    from maverick.file_lock import (
        atomic_read_text,
        ensure_private_directory,
        ensure_private_file,
    )
    from maverick.paths import maverick_home

    p = store_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    if not p.exists():
        return {"keys": {}, "service_accounts": {}, "issuance_requests": {}}
    try:
        ensure_private_file(p)
        data = _decode_json(atomic_read_text(p))
    except ApiKeyStoreError:
        raise
    except (OSError, ValueError) as exc:
        raise ApiKeyStoreError(f"API key store unreadable or corrupt: {exc}") from exc
    if not isinstance(data, dict):
        raise ApiKeyStoreError("API key store corrupt: top-level value must be an object")
    keys = data.get("keys", {})
    accounts = data.get("service_accounts", {})
    if not isinstance(keys, dict) or not isinstance(accounts, dict):
        raise ApiKeyStoreError("API key store corrupt: keys and service_accounts must be objects")
    return {
        "keys": {k: _validate_key(k, v) for k, v in keys.items()},
        "service_accounts": {k: _validate_account(k, v) for k, v in accounts.items()},
        "issuance_requests": _issuance_records(data.get("issuance_requests", {})),
    }


def _write(data: dict, *, effect_guard: Callable[[], None] | None = None) -> None:
    from maverick.file_lock import atomic_write_text

    kwargs = {"effect_guard": effect_guard} if effect_guard is not None else {}
    atomic_write_text(store_path(), json.dumps(data, indent=2, sort_keys=True), **kwargs)


def _to_key(rec: dict) -> ApiKey:
    return ApiKey(
        id=rec["id"], label=rec["label"], owner=rec["owner"], prefix=rec["prefix"],
        scopes=tuple(rec["scopes"]), created_at=rec["created_at"],
        expires_at=rec["expires_at"], created_by=rec["created_by"],
        workspace=rec["workspace"], last_used_at=rec["last_used_at"],
        last_used_ip=rec["last_used_ip"], revoked_at=rec["revoked_at"],
        grace_until=rec["grace_until"], replaced_by=rec["replaced_by"],
        rotated_from=rec["rotated_from"],
    )


def _audit(kind, **payload) -> bool:
    from maverick.audit import audit_event

    actor = payload.get("actor") or "local"
    return audit_event(kind, agent=actor, **payload)


def _audit_with_rollback(kind, rollback, **payload) -> bool:
    from maverick.audit import AuditRefused

    try:
        return _audit(kind, **payload)
    except AuditRefused:
        try:
            rollback()
        except Exception as rollback_exc:
            raise ApiKeyStoreError(
                "audit refused an API key change and the store rollback failed"
            ) from rollback_exc
        raise


# ---- key lifecycle ----------------------------------------------------------

def _expiry(expires_in_days: object, now: float) -> float:
    conf = settings()
    days = conf["default_days"] if expires_in_days in (None, "") else expires_in_days
    if isinstance(days, bool) or not isinstance(days, (int, float)) or not math.isfinite(days):
        raise ApiKeyError("expiry must be a number of days")
    days = int(days)
    if days < 1:
        raise ApiKeyError("a key must last at least one day")
    if days > conf["max_days"]:
        raise ApiKeyError(f"a key may last at most {conf['max_days']} days on this installation")
    return now + days * 86400.0


def _validate_label(label: object) -> str:
    text = str(label or "").strip()
    if not text:
        raise ApiKeyError("give the key a name so you can tell it apart later")
    if len(text) > _LABEL_MAX or not text.isprintable():
        raise ApiKeyError(f"the name must be printable and at most {_LABEL_MAX} characters")
    return text


def _validate_workspace(workspace: object, owner: str) -> str:
    text = str(workspace or "").strip()
    if not text:
        return ""
    if len(text) > 128:
        raise ApiKeyError("that workspace name is too long")
    from maverick.tenant.registry import is_active

    from . import workspace_tenants

    if not is_active(text):
        raise ApiKeyError("that workspace does not exist or is not active")
    if not workspace_tenants.principal_can_select(owner, text):
        raise ApiKeyError("the key's owner is not a member of that workspace")
    return text


def _mint(prefix: str) -> tuple[str, str]:
    secret = prefix + secrets.token_urlsafe(32)
    return secret, secret[: len(prefix) + 8]


def _issuance_records(rows):
    if not isinstance(rows, dict) or len(rows) > 10000:
        raise ApiKeyStoreError("Access-key request history is unavailable or exceeds its limit")
    fields = {"operation", "actor", "context", "binding", "action", "state", "key_id", "recorded_at"}
    for operation, row in rows.items():
        if (not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation) or not isinstance(row, dict)
                or set(row) != fields or row["operation"] != operation or row["action"] not in ("create", "rotate", "revoke")
                or row["state"] not in ("started", "written", "confirmed") or (row["state"] != "started" and not row["key_id"])
                or (row["state"] == "started" and row["key_id"])):
            raise ApiKeyStoreError("Access-key request history contains an invalid record")
        for key, pattern in (("context", r"[a-f0-9]{64}"), ("binding", r"[a-f0-9]{64}"), ("key_id", r"(?:[a-f0-9]{16})?")):
            if not isinstance(row[key], str) or not re.fullmatch(pattern, row[key]):
                raise ApiKeyStoreError("Access-key request history contains invalid verification material")
        _text(row, "actor", operation, allow_empty=False)
        _number(row, "recorded_at", operation)
    return rows


def issuance_original(operation: str) -> dict | None:
    with _locked(store_path()):
        row = _load()["issuance_requests"].get(operation)
        return dict(row) if row else None


def _issuance_begin(data, reviewed, guard):
    if reviewed is None:
        if guard is not None:
            guard(data)
        return
    operation = reviewed["operation"]
    if operation in data["issuance_requests"]:
        raise ApiKeyError("This original request is already retained. Read its outcome; nothing will be issued again.")
    if len(data["issuance_requests"]) >= 10000:
        raise ApiKeyError("The retained access-key request history is full. Nothing was changed.")
    if guard is None:
        raise ApiKeyError("A complete current review is required for this request")
    guard(data)
    row = {**reviewed, "state": "started", "key_id": "", "recorded_at": time.time()}
    _issuance_records({operation: row})
    data["issuance_requests"][operation] = row
    _write(data)
    if not _audit(_kind("API_KEY_CHANGED"), action="request_reviewed", request=operation, actor=row["actor"], change=row["action"]):
        raise ApiKeyStoreError("The reviewed activity could not be confirmed. No access key was changed.")
    guard(data)


def _issuance_written(data, reviewed, key_id):
    if reviewed is not None:
        data["issuance_requests"][reviewed["operation"]].update(state="written", key_id=key_id, recorded_at=time.time())


def _issuance_confirm(data, reviewed, audited):
    if reviewed is not None and audited:
        data["issuance_requests"][reviewed["operation"]]["state"] = "confirmed"
        _write(data)


def create_key(*, label, scopes, owner: str, created_by: str,
               expires_in_days=None, workspace="", reviewed_request: dict | None = None,
               effect_guard: Callable[[dict], None] | None = None) -> tuple[ApiKey, str]:
    """Mint a key for ``owner``. Returns ``(key, secret)``; the secret is shown
    once and never stored."""
    if not enabled():
        raise ApiKeyError("API keys are turned off on this installation")
    owner = str(owner or "").strip()
    if not owner.startswith("user:") or len(owner) <= len("user:"):
        raise ApiKeyError("a key needs an owner")
    now = time.time()
    label_text = _validate_label(label)
    scope_set = _validate_scopes(scopes, owner)
    expires_at = _expiry(expires_in_days, now)
    ws = _validate_workspace(workspace, owner)
    rec = {
        "id": secrets.token_hex(8), "label": label_text, "owner": owner,
        "scopes": list(scope_set),
        "workspace": ws, "created_at": now, "expires_at": expires_at,
        "created_by": created_by or "", "last_used_at": None, "last_used_ip": "",
        "revoked_at": None, "grace_until": None, "replaced_by": "", "rotated_from": "",
    }
    with _locked(store_path()):
        data = _load()
        if is_service_account_principal(owner):
            slug = owner[len("user:" + SERVICE_ACCOUNT_SUBJECT_PREFIX):]
            account = data["service_accounts"].get(slug)
            if account is None or account["disabled_at"] is not None:
                raise ApiKeyError("that service account does not exist or is disabled")
        _issuance_begin(data, reviewed_request, effect_guard)
        secret, prefix = _mint(key_prefix())
        rec.update(prefix=prefix, secret_sha256=_hash(secret))
        prior = json.loads(json.dumps(data))
        data["keys"][rec["id"]] = rec
        _issuance_written(data, reviewed_request, rec["id"])
        if effect_guard is not None:
            effect_guard(prior)
        _write(data, effect_guard=(lambda: effect_guard(prior)) if effect_guard is not None else None)
        audited = _audit_with_rollback(
            _kind("API_KEY_CHANGED"), lambda: _write(prior), action="created",
            key_id=rec["id"], prefix=prefix, owner=owner, scopes=list(scope_set),
            workspace=ws, expires_at=expires_at, actor=created_by or "",
        )
        _issuance_confirm(data, reviewed_request, audited)
    return _to_key(rec), secret


def _kind(name: str):
    from maverick.audit import EventKind

    return getattr(EventKind, name)


def get_key(key_id: str) -> ApiKey | None:
    rec = _load()["keys"].get(str(key_id or ""))
    return _to_key(rec) if rec else None


def list_keys(*, owner: str | None = None) -> list[ApiKey]:
    """Keys newest first; ``owner`` narrows to that principal's keys."""
    keys = [_to_key(r) for r in _load()["keys"].values()]
    if owner is not None:
        keys = [k for k in keys if k.owner == owner]
    return sorted(keys, key=lambda k: k.created_at, reverse=True)


def rotate_key(key_id: str, *, actor: str, reviewed_request: dict | None = None,
               effect_guard: Callable[[dict], None] | None = None) -> tuple[ApiKey, str]:
    """Mint a replacement with the same name, scopes, owner and workspace. The
    old secret keeps working for the configured grace period, then stops."""
    if not enabled():
        raise ApiKeyError("API keys are turned off on this installation")
    now = time.time()
    grace_hours = settings()["rotation_grace_hours"]
    with _locked(store_path()):
        data = _load()
        old = data["keys"].get(str(key_id or ""))
        if old is None:
            raise ApiKeyError("that key does not exist")
        if not _to_key(old).usable(now) or old["grace_until"] is not None:
            raise ApiKeyError("only a working key can be rotated; create a new one instead")
        # The owner's role may have shrunk since the key was made: the new
        # key gets only the scopes the owner may still hold.
        scopes = tuple(s for s in old["scopes"] if SCOPES[s][0] in owner_permissions(old["owner"]))
        if not scopes:
            raise ApiKeyError("the key's owner no longer holds any of its scopes")
        lifetime_days = max(1, int(round((old["expires_at"] - old["created_at"]) / 86400)))
        expires_at = _expiry(min(lifetime_days, settings()["max_days"]), now)
        _issuance_begin(data, reviewed_request, effect_guard)
        secret, prefix = _mint(key_prefix())
        new = dict(old)
        new.update({
            "id": secrets.token_hex(8), "prefix": prefix, "secret_sha256": _hash(secret),
            "scopes": list(scopes), "created_at": now, "expires_at": expires_at,
            "created_by": actor or "", "last_used_at": None, "last_used_ip": "",
            "revoked_at": None, "grace_until": None, "replaced_by": "",
            "rotated_from": old["id"],
        })
        prior = json.loads(json.dumps(data))
        old["grace_until"] = min(now + grace_hours * 3600.0, old["expires_at"])
        old["replaced_by"] = new["id"]
        data["keys"][new["id"]] = new
        _issuance_written(data, reviewed_request, new["id"])
        if effect_guard is not None:
            effect_guard(prior)
        _write(data, effect_guard=(lambda: effect_guard(prior)) if effect_guard is not None else None)
        audited = _audit_with_rollback(
            _kind("API_KEY_CHANGED"), lambda: _write(prior), action="rotated",
            key_id=new["id"], prefix=prefix, owner=new["owner"], scopes=list(scopes),
            workspace=new["workspace"], expires_at=expires_at, actor=actor or "",
            rotated_from=old["id"], grace_until=old["grace_until"],
        )
        _issuance_confirm(data, reviewed_request, audited)
    return _to_key(new), secret


def revoke_key(key_id: str, *, actor: str, reviewed_request: dict | None = None,
               effect_guard: Callable[[dict], None] | None = None) -> ApiKey:
    with _locked(store_path()):
        data = _load()
        rec = data["keys"].get(str(key_id or ""))
        if rec is None:
            raise ApiKeyError("that key does not exist")
        if rec["revoked_at"] is not None:
            return _to_key(rec)
        _issuance_begin(data, reviewed_request, effect_guard)
        prior = json.loads(json.dumps(data))
        rec["revoked_at"] = time.time()
        _issuance_written(data, reviewed_request, rec["id"])
        if effect_guard is not None:
            effect_guard(prior)
        _write(data, effect_guard=(lambda: effect_guard(prior)) if effect_guard is not None else None)
        audited = _audit_with_rollback(
            _kind("API_KEY_CHANGED"), lambda: _write(prior), action="revoked",
            key_id=rec["id"], prefix=rec["prefix"], owner=rec["owner"],
            scopes=list(rec["scopes"]), workspace=rec["workspace"],
            expires_at=rec["expires_at"], actor=actor or "",
        )
        _issuance_confirm(data, reviewed_request, audited)
    return _to_key(rec)


def expiring_soon(keys, *, within_days: int = EXPIRY_WARNING_DAYS,
                  now: float | None = None) -> list[ApiKey]:
    """Working keys that stop within ``within_days`` (for the page's warning)."""
    now = time.time() if now is None else now
    horizon = now + within_days * 86400
    return [k for k in keys if k.usable(now) and k.expires_at <= horizon]


# ---- verification -----------------------------------------------------------

@dataclass(frozen=True)
class Verified:
    key: ApiKey
    permissions: frozenset[str]


def verify(secret: str, *, client_ip: str = "", now: float | None = None) -> tuple[Verified | None, str]:
    """Resolve a presented key. Returns ``(Verified, "")`` or ``(None, reason)``
    where ``reason`` is a plain sentence safe to show the caller.

    Lookup is by the secret's SHA-256 (the clear text is never stored) and the
    stored digest is compared in constant time. Expired, revoked and replaced
    keys are refused; a disabled service account's keys are refused. On
    success ``last_used`` is recorded at most once a minute per key (or when
    the caller's address changes) so a busy script does not rewrite the store
    on every call. An unreadable store refuses every key.
    """
    now = time.time() if now is None else now
    if not looks_like_key(secret):
        return None, "This is not an API key."
    digest = _hash(secret)
    try:
        data = _load()
    except ApiKeyStoreError:
        return None, "API keys are unavailable right now. Ask an administrator."
    rec = None
    for candidate in data["keys"].values():
        if hmac.compare_digest(candidate["secret_sha256"], digest):
            rec = candidate
            break
    if rec is None:
        return None, "This API key is not recognised."
    key = _to_key(rec)
    status = key.status(now)
    if status == "revoked":
        return None, "This API key was revoked."
    if status == "expired":
        return None, "This API key has expired. Create a new one on your account page."
    if status == "replaced":
        return None, "This API key was rotated and its grace period is over. Use the new key."
    if key.is_service_account:
        slug = key.owner[len("user:" + SERVICE_ACCOUNT_SUBJECT_PREFIX):]
        account = data["service_accounts"].get(slug)
        if account is None or account["disabled_at"] is not None:
            return None, "The service account that owns this key is disabled."
    # Authentication runs before principal-scoped tenant pinning. Resolve the
    # same workspace selection that the request will use, while retaining a
    # process/client tenant floor and checking every membership at use time.
    from maverick.paths import current_tenant_id, tenant_by_user_enabled, tenant_scope
    from maverick.tenant.registry import is_active

    from . import workspace_tenants

    try:
        active = current_tenant_id()
        if active:
            if key.workspace and key.workspace != active:
                return None, "This API key is bound to a different workspace."
            if key.workspace and (not is_active(active) or not workspace_tenants.principal_can_select(key.owner, active)):
                return None, "This API key's workspace is unavailable or its membership was revoked."
            permissions = effective_permissions(key.scopes, key.owner)
        elif tenant_by_user_enabled():
            if key.workspace:
                return None, "Workspace-bound API keys are unavailable in per-user isolation mode."
            with tenant_scope(tenant=f"api:{key.owner}"):
                permissions = effective_permissions(key.scopes, key.owner)
        else:
            selected = key.workspace or workspace_tenants.get_selection(key.owner)
            if selected:
                if not is_active(selected) or not workspace_tenants.principal_can_select(key.owner, selected):
                    return None, "This API key's workspace is unavailable or its membership was revoked."
                with tenant_scope(tenant=selected):
                    permissions = effective_permissions(key.scopes, key.owner)
            else:
                permissions = effective_permissions(key.scopes, key.owner)
    except Exception:
        return None, "This API key's workspace authority is unavailable."
    if not permissions:
        return None, "This API key's owner no longer holds any of its scopes."
    _touch(key.id, client_ip, now)
    return Verified(key=key, permissions=permissions), ""


def _touch(key_id: str, client_ip: str, now: float) -> None:
    last = _last_used_written.get(key_id)
    if last is not None and now - last[0] < _LAST_USED_WRITE_INTERVAL and last[1] == client_ip:
        return
    _last_used_written[key_id] = (now, client_ip)
    try:
        with _locked(store_path()):
            data = _load()
            rec = data["keys"].get(key_id)
            if rec is None:
                return
            rec["last_used_at"] = now
            rec["last_used_ip"] = str(client_ip or "")[:64]
            _write(data)
    except (ApiKeyStoreError, OSError):
        # Recording use is best-effort; the key already verified.
        _last_used_written.pop(key_id, None)


# ---- service accounts -------------------------------------------------------

def list_service_accounts() -> list[ServiceAccount]:
    data = _load()
    keys_by_owner: dict[str, list[ApiKey]] = {}
    for rec in data["keys"].values():
        keys_by_owner.setdefault(rec["owner"], []).append(_to_key(rec))
    out = []
    for rec in data["service_accounts"].values():
        principal = service_account_principal(rec["slug"])
        out.append(ServiceAccount(
            slug=rec["slug"], description=rec["description"], created_by=rec["created_by"],
            created_at=rec["created_at"], disabled_at=rec["disabled_at"],
            keys=tuple(sorted(keys_by_owner.get(principal, []), key=lambda k: k.created_at, reverse=True)),
        ))
    return sorted(out, key=lambda a: a.slug)


def get_service_account(slug: str) -> ServiceAccount | None:
    return next((a for a in list_service_accounts() if a.slug == slug), None)


def create_service_account(slug, role, *, description="", actor: str) -> ServiceAccount:
    """Register a service account and give it ``role`` in the ordinary RBAC
    roster (so the Users page, group mappings and every gate see it as a
    normal principal that simply cannot sign in)."""
    from . import rbac

    if not enabled():
        raise ApiKeyError("API keys are turned off on this installation")
    text = str(slug or "").strip().lower()
    if not _SLUG_RE.match(text):
        raise ApiKeyError("a service account name is 2 to 40 lowercase letters, digits or dashes, starting with a letter")
    if not rbac.is_known_role(role):
        raise ApiKeyError("that role does not exist")
    desc = str(description or "").strip()
    if len(desc) > 200 or not desc.isprintable():
        raise ApiKeyError("the description must be printable and at most 200 characters")
    principal = service_account_principal(text)
    now = time.time()
    with _locked(store_path()):
        data = _load()
        if text in data["service_accounts"]:
            raise ApiKeyError("a service account with that name already exists")
        prior = json.loads(json.dumps(data))
        data["service_accounts"][text] = {
            "slug": text, "description": desc, "created_by": actor or "",
            "created_at": now, "disabled_at": None,
        }
        _write(data)
        # Recorded before the role exists: a refused row rolls back the one store,
        # and no role is left on the roster for an account that was never created.
        _audit_with_rollback(
            _kind("SERVICE_ACCOUNT_CHANGED"), lambda: _write(prior), action="created",
            account=text, role=role, actor=actor or "",
        )
        try:
            rbac.set_role(principal, role, actor=actor)
        except Exception:
            _write(prior)
            raise
    return ServiceAccount(slug=text, description=desc, created_by=actor or "", created_at=now)


def disable_service_account(slug: str, *, actor: str) -> ServiceAccount:
    """Disable an account: every key it holds stops working at once and its
    role assignment is removed."""
    from . import rbac

    text = str(slug or "").strip().lower()
    principal = service_account_principal(text)
    now = time.time()
    with _locked(store_path()):
        data = _load()
        rec = data["service_accounts"].get(text)
        if rec is None:
            raise ApiKeyError("that service account does not exist")
        if rec["disabled_at"] is None:
            prior = json.loads(json.dumps(data))
            rec["disabled_at"] = now
            for key in data["keys"].values():
                if key["owner"] == principal and key["revoked_at"] is None:
                    key["revoked_at"] = now
            _write(data)
            _audit_with_rollback(
                _kind("SERVICE_ACCOUNT_CHANGED"), lambda: _write(prior), action="disabled",
                account=text, actor=actor or "",
            )
        # Outside the first-disable branch so a retry finishes a removal that failed
        # after the account was already marked disabled (removing twice is harmless).
        rbac.remove_user(principal, actor=actor)
    return get_service_account(text)  # type: ignore[return-value]


__all__ = [
    "SCOPES", "SERVICE_ACCOUNT_SUBJECT_PREFIX", "EXPIRY_WARNING_DAYS",
    "ApiKey", "ApiKeyError", "ApiKeyStoreError", "ServiceAccount", "Verified",
    "settings", "enabled", "key_prefix", "looks_like_key",
    "service_account_principal", "is_service_account_subject",
    "is_service_account_principal", "atoms_for_scopes", "owner_permissions",
    "scopes_available_to", "effective_permissions", "store_path",
    "create_key", "get_key", "list_keys", "rotate_key", "revoke_key",
    "expiring_soon", "verify", "list_service_accounts", "get_service_account",
    "create_service_account", "disable_service_account",
]
