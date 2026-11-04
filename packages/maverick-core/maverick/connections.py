"""Named SaaS connections -- a first-class, sealed alternative to env-var creds.

An enterprise connector resolves ``<NAME>_BASE_URL`` / ``<NAME>_TOKEN`` from the
environment. That's fine for an operator but a non-starter for a citizen user
who can't touch env vars. A *connection* stores those same two values under a
name (``salesforce`` / ``salesforce-eu``), sealed at rest with the tenant's KMS
key exactly like the OAuth vault, so a connector can be wired from the dashboard
without shell access.

Standard/local resolution keeps legacy env precedence. Authenticated enterprise
execution requires a saved connection whose owner/access grants admit the
current principal; operator-global env credentials are deliberately unavailable
at that boundary.

Gated behind :func:`enabled` (``[connections] enable`` / ``MAVERICK_CONNECTIONS``);
off by default. Token values are sealed and never returned by the listing API --
only ``has_token`` is surfaced.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import re
import threading
import time
import uuid
from collections.abc import Iterator, Sequence

from .paths import data_dir
from .tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

# A reviewed mutation can compose an impact check and a store helper under
# the same transaction. The OS sidecar lock is reentrant as well.
_lock = threading.RLock()
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ACCESS = frozenset({"owner", "tenant"})
_MAX_PRINCIPAL_LENGTH = 256
_runtime_principal: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "maverick_connection_principal", default=None,
)


class ConnectionVersionConflict(RuntimeError):
    """The credential changed after a caller began an operation on it."""


class ConnectionStoreUnavailable(RuntimeError):
    """The sealed connection registry could not be authenticated or read safely."""


def deployment_override() -> bool | None:
    from .config import env_flag
    override = env_flag("MAVERICK_CONNECTIONS")
    return override if override is not None else env_flag("LIGHTWORK_CONNECTIONS")


def enabled() -> bool:
    override = deployment_override()
    if override is not None:
        return override
    try:
        from .config import load_config
        return bool((load_config().get("connections") or {}).get("enable", False))
    except Exception:  # pragma: no cover -- config never gates a read to a crash
        return False


def _path():
    return data_dir("connections", "connections.sealed")


def _load() -> dict[str, dict]:
    from .file_lock import atomic_read_bytes, cross_process_lock, ensure_private_file
    from .paths import current_tenant_id

    path = _path()
    try:
        # Permission verification checks the file identity across syscalls.
        # A legitimate atomic credential rotation must not replace that inode
        # between verification and read. The writer's sidecar lock is reentrant
        # for callers already inside the credential mutation transaction.
        with cross_process_lock(path, strict=True):
            ensure_private_file(path)
            raw = unseal_text_for_tenant(current_tenant_id(), atomic_read_bytes(path))
        data = json.loads(raw)
        if (
            not isinstance(data, dict)
            or any(
                not isinstance(name, str) or not isinstance(record, dict)
                for name, record in data.items()
            )
        ):
            raise ValueError("connection registry root must be an object")
    except FileNotFoundError:
        # Absence is the sole legitimate empty-store state. Every other read or
        # authentication failure may conceal live credentials and must prevent
        # a later load/modify/save from replacing them.
        return {}
    except Exception as exc:
        raise ConnectionStoreUnavailable(
            "connection credential registry is unavailable; no records were changed"
        ) from exc
    return data


def _save(data: dict[str, dict]) -> None:
    from .file_lock import atomic_write_bytes, ensure_private_directory
    from .paths import current_tenant_id

    path = _path()
    blob = seal_text_for_tenant(current_tenant_id(), json.dumps(data, sort_keys=True))
    ensure_private_directory(path.parent)
    atomic_write_bytes(path, blob, mode=0o600)


@contextlib.contextmanager
def _mutation_lock() -> Iterator[None]:
    """Serialize credential read-modify-write across threads and processes."""
    from .file_lock import cross_process_lock

    path = _path()
    with _lock, cross_process_lock(path, strict=True):
        yield


def normalize_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", (name or "").strip().lower()).strip("-")[:64]


def _valid_principal(value: object) -> bool:
    """Whether ``value`` is in the bounded opaque principal domain."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= _MAX_PRINCIPAL_LENGTH
        and value.isprintable()
    )


def _require_principal(value: object) -> str:
    if not _valid_principal(value):
        raise ValueError("connection principals must be 1-256 printable characters")
    return value


def _normalize_principals(values: Sequence[str] | None) -> tuple[str, ...]:
    out: list[str] = []
    for raw in values or ():
        principal = _require_principal(raw)
        if principal not in out:
            out.append(principal)
    return tuple(out)


@contextlib.contextmanager
def bind_principal(principal: str | None) -> Iterator[None]:
    """Bind the authenticated principal allowed to consume saved credentials.

    Tool registries establish this context at the dispatch boundary.  A
    ContextVar is required because synchronous connector functions execute in
    ``asyncio.to_thread`` and concurrent runs must never borrow one another's
    identity.
    """
    if principal is None or principal == "":
        value = None
    else:
        value = _require_principal(principal)
    token = _runtime_principal.set(value)
    try:
        yield
    finally:
        _runtime_principal.reset(token)


def current_principal() -> str | None:
    """Authenticated identity at the connector credential-use boundary."""
    return _runtime_principal.get()


def set_connection(name: str, *, connector: str | None = None,
                   base_url: str | None = None,
                   token: str | None = None, owner: str | None = None,
                   expected_owner: str | None = None,
                   access: str | None = None,
                   allowed_principals: Sequence[str] | None = None,
                   expected_revision: str | None = None,
                   require_revision: bool = False) -> dict:
    """Create or patch a named connection (sealed). ``connector`` is the tool
    name it credentials (e.g. ``salesforce``); ``name`` may differ so one tool
    can have several accounts. Raises ValueError on an unusable name.

    ``expected_owner`` (when not None) makes the overwrite conditional UNDER THE
    STORE LOCK: replacing an existing connection owned by someone else raises
    PermissionError -- the owner check and the write are one atomic step, so an
    API-layer read-then-write can't race a concurrent create (mirrors
    :func:`delete_connection`'s in-store owner enforcement).

    Omitted optional fields preserve an existing record, so rotating only a
    token cannot silently erase its connector, URL, owner, access policy, or
    grants.  API callers set ``require_revision`` and must supply the public
    ``revision`` returned by the preceding read; the compare and write happen
    under the same cross-process lock.
    """
    slug = normalize_name(name)
    if not _NAME_RE.match(slug):
        raise ValueError("connection name must be a slug (a-z, 0-9, -, _)")
    access_value = None if access is None else str(access).strip().lower()
    if access_value is not None and access_value not in _ACCESS:
        raise ValueError("connection access must be 'owner' or 'tenant'")
    grants = (
        None
        if allowed_principals is None
        else _normalize_principals(allowed_principals)
    )
    owner_value = None
    if owner is not None:
        owner_value = "" if owner == "" else _require_principal(owner)
    with _mutation_lock():
        data = dict(_load())
        existing = data.get(slug)
        if (expected_owner is not None and existing is not None
                and existing.get("owner", "") != expected_owner):
            raise PermissionError("a connection with that name already exists")
        if existing is None and expected_revision is not None:
            raise ConnectionVersionConflict("connection no longer exists")
        if isinstance(existing, dict):
            current_revision = str(existing.get("revision") or "")
            if require_revision and not expected_revision:
                raise ConnectionVersionConflict(
                    "expected_revision is required when updating a connection"
                )
            if (
                expected_revision is not None
                and current_revision != str(expected_revision)
            ):
                raise ConnectionVersionConflict(
                    "connection changed since it was read"
                )
        existing_oauth = (existing or {}).get("oauth")
        if existing_oauth and token is None:
            if ((connector is not None and normalize_name(connector) != existing["connector"])
                    or (base_url is not None and str(base_url).strip().rstrip("/") != existing["base_url"])
                    or (owner_value is not None and owner_value != existing["owner"])):
                raise ValueError("Reconnect this account before changing its provider, destination or owner.")
        rec = {
            "name": slug,
            "connector": (
                normalize_name(connector) or slug
                if connector is not None
                else str((existing or {}).get("connector") or slug)
            ),
            "base_url": (
                str(base_url).strip().rstrip("/")
                if base_url is not None
                else str((existing or {}).get("base_url") or "")
            ),
            "token": (
                str(token)
                if token is not None
                else str((existing or {}).get("token") or "")
            ),
            "created": float((existing or {}).get("created") or time.time()),
            "owner": (
                owner_value
                if owner_value is not None
                else str((existing or {}).get("owner") or "")
            ),
            "access": (
                access_value
                if access_value is not None
                else str((existing or {}).get("access") or "owner")
            ),
            "allowed_principals": (
                list(grants)
                if grants is not None
                else list((existing or {}).get("allowed_principals") or [])
            ),
            # A new generation invalidates every prior readiness assertion.
            "revision": uuid.uuid4().hex,
        }
        if rec["connector"] == "aws_s3" and token is not None:
            try:
                credential = json.loads(token)
            except (TypeError, ValueError) as exc:
                raise ValueError("Enter the AWS access key, secret key and storage region together.") from exc
            if (not isinstance(credential, dict) or not isinstance(credential.get("region"), str)
                    or re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", credential["region"]) is None):
                raise ValueError("Enter a valid AWS storage region, such as us-east-1.")
        if existing_oauth and token is None:
            rec["oauth"] = dict(existing_oauth)
        if existing:
            # Preserve the evidence of the old generation. Its revision stays
            # unchanged so no consumer can mistake it for current readiness.
            if existing.get("last_test"):
                rec["last_test"] = dict(existing["last_test"])
            if existing.get("test_history"):
                rec["test_history"] = list(existing["test_history"])
            if existing.get("capability_receipts"):
                rec["capability_receipts"] = list(existing["capability_receipts"])
        data[slug] = rec
        _save(data)
    return _public(rec)


def get_connection(name: str) -> dict | None:
    """The full sealed record (INCLUDING the token) for internal resolution."""
    rec = _load().get(normalize_name(name))
    # Never expose the freshly decrypted store object itself: an internal
    # caller must not mutate credential state without the locked sealed write.
    return dict(rec) if isinstance(rec, dict) else None


def delete_connection(
    name: str, owner: str | None = None, *, expected_revision: str | None = None,
) -> bool:
    """Remove the reviewed generation under the same lock as credential writes.

    Explicit local/programmatic callers may omit the revision for legacy
    unconditional removal. Authenticated dashboard callers must supply it.
    """
    slug = normalize_name(name)
    with _mutation_lock():
        data = dict(_load())
        rec = data.get(slug)
        if rec is None or (owner is not None and rec.get("owner", "") != owner):
            return False
        if expected_revision is not None and rec.get("revision") != expected_revision:
            raise ConnectionVersionConflict("Connection changed; reload Connections and review removal again.")
        del data[slug]
        _save(data)
    return True


def _public(rec: dict) -> dict:
    """A record safe to return over the API -- the token is never included, only
    whether one is set."""
    access = str(rec.get("access") or ("owner" if rec.get("owner") else "tenant"))
    last_test = rec.get("last_test") if isinstance(rec.get("last_test"), dict) else None
    from .connection_oauth import public_status
    result = {
        "name": rec.get("name", ""), "connector": rec.get("connector", ""),
        "base_url": rec.get("base_url", ""), "has_token": bool(rec.get("token")),
        "created": float(rec.get("created") or 0.0), "owner": rec.get("owner", ""),
        "access": access,
        "allowed_principals": list(rec.get("allowed_principals") or []),
        "revision": str(rec.get("revision") or ""),
        "last_test": dict(last_test) if last_test is not None else None,
        "test_history": [dict(item) for item in rec.get("test_history", []) if isinstance(item, dict)],
        "capability_receipts": [dict(item) for item in rec.get("capability_receipts", []) if isinstance(item, dict)],
    }
    status = public_status(rec)
    if status is not None:
        result["oauth"] = status
    return result


def list_connections(owner: str | None = None) -> list[dict]:
    out = [_public(r) for r in _load().values() if isinstance(r, dict)]
    if owner is not None:
        out = [c for c in out if c.get("owner", "") == owner]
    out.sort(key=lambda c: (c["created"], c["name"]))
    return out


def _may_use(rec: dict, principal: str | None) -> bool:
    """Whether ``principal`` may consume this credential record.

    Legacy ownerless records remain tenant-shared.  Legacy owned records become
    owner-only, closing the historical cross-principal fallback without a data
    migration.  An absent principal is the local/operator path and may use only
    ownerless tenant records; it can never silently borrow an authenticated
    user's credential.
    """
    raw_owner = rec.get("owner")
    if raw_owner is None or raw_owner == "":
        owner = ""
    elif _valid_principal(raw_owner):
        owner = raw_owner
    else:
        return False
    if principal is not None and not _valid_principal(principal):
        return False
    raw_grants = rec.get("allowed_principals") or []
    if not isinstance(raw_grants, list) or any(
        not _valid_principal(p) for p in raw_grants
    ):
        return False
    grants = set(raw_grants)
    access = str(rec.get("access") or ("owner" if owner else "tenant")).strip().lower()
    if principal is not None and (principal == owner or principal in grants):
        return True
    if access == "tenant":
        return principal is not None or not owner
    return principal is None and not owner


def resolve_named(name: str, *, expected_revision: str, connector: str, origin: str) -> dict:
    """Resolve one pinned connection for the current authenticated principal.

    There is no environment or first-matching-connector fallback. Consumers
    must call at each network request, not cache the returned credential.
    """
    from urllib.parse import urlsplit

    def exact_origin(value):
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or parsed.port not in (None, 443)):
            raise PermissionError("connection requires an exact HTTPS origin")
        return "https://" + parsed.hostname.lower()

    if not enabled() or not _NAME_RE.fullmatch(name) or not expected_revision:
        raise PermissionError("named connection is unavailable")
    principal = current_principal()
    if not principal:
        raise PermissionError("saved connection requires a named authenticated principal")
    from .template_connections import selected
    pin = selected(connector, principal)
    if pin is not None and (pin["name"] != name or pin["revision"] != expected_revision):
        raise PermissionError("This task selected a different account or saved revision.")
    record = get_connection(name)
    if not record or not _may_use(record, principal) or not record.get("token"):
        raise PermissionError("named connection access is unavailable or denied")
    if record.get("revision") != expected_revision:
        raise ConnectionVersionConflict("saved connection changed; select its current version")
    if record.get("connector") != connector or exact_origin(record.get("base_url", "")) != exact_origin(origin):
        raise PermissionError("saved connection provider or origin does not match the enrolled source")
    from .connection_oauth import renew
    return renew(record, actor=principal)


def resolve(connector: str, *, principal: str | None = None) -> tuple[str, str] | None:
    """(base_url, token) for the first connection credentialing ``connector``,
    or None. Used as a FALLBACK by the connector layer only when the env var is
    unset, so it never overrides an operator's environment."""
    if not enabled():
        return None
    slug = normalize_name(connector)
    if principal is None:
        caller = _runtime_principal.get()
    elif principal == "":
        caller = None
    else:
        caller = _require_principal(principal)
    # a connection named exactly after the connector wins; else the first one
    # whose "connector" field points at it AND whose use grant admits the
    # authenticated caller.  Sort the fallback so selection is deterministic.
    from .template_connections import selected
    pin = selected(slug, caller)
    data = _load()
    rec = data.get(pin["name"] if pin else slug)
    if pin is not None and (not rec or rec.get("revision") != pin["revision"] or not _may_use(rec, caller)):
        raise PermissionError("Selected account changed before credential resolution.")
    if pin is None and (not isinstance(rec, dict) or not _may_use(rec, caller)):
        rec = next((r for _, r in sorted(data.items())
                    if isinstance(r, dict) and r.get("connector") == slug
                    and _may_use(r, caller)), None)
    if not rec or not rec.get("token"):
        return None
    if rec.get("oauth"):
        from .connection_oauth import renew
        rec = renew(rec, actor=caller)
    prefix = str((rec.get("oauth") or {}).get("api_prefix") or "")
    if prefix and (rec.get("base_url") != "https://api.atlassian.com" or not re.fullmatch(r"/ex/jira/[0-9a-f-]{36}", prefix)):
        raise PermissionError("Saved account destination is invalid")
    return (str(rec.get("base_url") or "") + prefix, str(rec.get("token")))


def record_test_result(
    name: str,
    *,
    reachable: bool,
    authenticated: bool,
    status: int | None = None,
    expected_owner: str | None = None,
    expected_revision: str | None = None,
    outcome: str | None = None,
) -> dict:
    """Persist a bounded, non-secret readiness receipt for a connection.

    The receipt is invalidated whenever credentials are replaced.  It is useful
    to authoring/preflight code without retaining response bodies or headers.
    """
    slug = normalize_name(name)
    with _mutation_lock():
        data = dict(_load())
        rec = data.get(slug)
        if not isinstance(rec, dict):
            raise KeyError(slug)
        if expected_owner is not None and rec.get("owner", "") != expected_owner:
            raise PermissionError("connection is not owned by this principal")
        if (
            expected_revision is not None
            and str(rec.get("revision") or "") != str(expected_revision)
        ):
            raise ConnectionVersionConflict(
                "connection changed while its readiness probe was running"
            )
        updated = dict(rec)
        if isinstance(rec.get("last_test"), dict):
            updated["test_history"] = (list(rec.get("test_history", [])) + [dict(rec["last_test"])])[-100:]
        updated["last_test"] = {
            "tested_at": time.time(),
            "reachable": bool(reachable),
            "authenticated": bool(authenticated),
            "status": int(status) if status is not None else None,
            "revision": str(rec.get("revision") or ""),
            "capability": "service-address authentication check; task access is not checked",
            "outcome": outcome if outcome in {
                "authenticated", "access_unverified", "sign_in_refused",
                "blocked_by_policy", "unreachable", "address_missing",
            } else ("authenticated" if authenticated else "access_unverified" if reachable else "unreachable"),
        }
        data[slug] = updated
        _save(data)
    return _public(updated)


def replace_from_staged(name: str, replacement: str, *, owner: str | None,
                        expected_revision: str, replacement_revision: str) -> dict:
    """Copy reviewed API-key bytes without exposing them to a client.

    Both records and the fresh authentication receipt are checked under one
    credential-store lock. Existing sharing remains explicit and unchanged.
    OAuth accounts use their own consent flow, never this key-copy operation.
    """
    with _mutation_lock():
        records = _load()
        target, staged = records.get(normalize_name(name)), records.get(normalize_name(replacement))
        expected_owner = owner or ""
        if (not target or not staged or target["name"] == staged["name"]
                or (target.get("owner") or "") != expected_owner
                or (staged.get("owner") or "") != expected_owner):
            raise PermissionError("Choose two different connections owned by your account.")
        if target.get("revision") != expected_revision or staged.get("revision") != replacement_revision:
            raise ConnectionVersionConflict("A connection changed. Review the replacement again.")
        if target.get("oauth") or staged.get("oauth"):
            raise ValueError("Reconnect renewable accounts through their provider consent flow.")
        if target.get("connector") != staged.get("connector") or target.get("base_url") != staged.get("base_url"):
            raise ValueError("A staged key replacement must use the same adapter and service address.")
        receipt = staged.get("last_test") or {}
        if (receipt.get("revision") != staged["revision"] or receipt.get("authenticated") is not True
                or not 0 <= time.time() - float(receipt.get("tested_at") or 0) <= 86400):
            raise ValueError("Verify the staged credential's authentication within the last day before switching it.")
        updated = dict(target)
        updated["token"] = staged["token"]
        updated["revision"] = uuid.uuid4().hex
        history = list(target.get("test_history", []))
        if target.get("last_test"):
            history.append(dict(target["last_test"]))
        updated["test_history"] = history[-100:]
        updated["last_test"] = {**receipt, "revision": updated["revision"],
                                "staged_name": staged["name"], "staged_revision": staged["revision"]}
        records[updated["name"]] = updated
        _save(records)
        return _public(updated)


__all__ = [
    "enabled", "set_connection", "get_connection", "delete_connection",
    "list_connections", "resolve", "normalize_name", "bind_principal",
    "current_principal",
    "record_test_result", "ConnectionVersionConflict", "ConnectionStoreUnavailable",
]
