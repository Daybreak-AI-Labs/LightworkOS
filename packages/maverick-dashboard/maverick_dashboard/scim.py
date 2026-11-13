"""SCIM 2.0 user provisioning (RFC 7643/7644).

Enterprise IdPs (Okta, Azure AD/Entra, OneLogin) provision and deprovision
users via SCIM. This exposes the standard ``/scim/v2`` surface so an admin can
wire Lightwork as a SCIM app and have user lifecycle flow automatically:
creating a SCIM user provisions a backing **tenant** (the product's isolation
unit), and deprovisioning (``active=false`` or DELETE) suspends/removes it.

Auth is a static bearer (``MAVERICK_SCIM_TOKEN``) the IdP sends on every call —
SCIM has no OIDC/session, so these routes carry their own credential and are
exempt from the dashboard-token middleware and the OIDC gate (the app wires the
``/scim/`` exemptions). OFF by default: with no token set, every route 404s, so
mounting the router is inert until an operator opts in.

State lives in ``<home>/scim_users.json`` (atomic 0600 write), keeping the full
SCIM core attributes (id/userName/externalId/name/emails/active) so a round-trip
with the IdP is faithful, and linking each user to a registry tenant.

Groups: the ``/Groups`` resource stores IdP-pushed group membership
(``<home>/scim_groups.json``). ``scim_groups.py`` maps those groups to
dashboard roles and department grants via ``[dashboard] group_roles`` /
``group_suites``, so access flows from Okta/Entra team membership instead of
per-user hand assignment.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
import time
import uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from maverick.constant_time import text_equals
from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import maverick_home

router = APIRouter(prefix="/scim/v2", tags=["scim"])

_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


# --------------------------------------------------------------------------
# Enable / auth
# --------------------------------------------------------------------------
def _scim_secrets() -> list[str]:
    """Configured SCIM bearer secret(s).

    ``MAVERICK_SCIM_TOKEN`` may hold a single token (legacy) or a
    **comma-separated set** so a rotation can keep the old and new token both
    valid for a grace window. Each entry is either a literal token or a
    ``sha256:<hex>`` digest, so the plaintext secret need not sit in the process
    environment. Order does not matter; all are checked constant-time.

    Routed through the secret provider so a mounted vault file can supply
    the token; default backend reads ``MAVERICK_SCIM_TOKEN`` from env as before."""
    from maverick.secret_provider import get_secret
    raw = get_secret("MAVERICK_SCIM_TOKEN", "") or ""
    if not raw.strip():
        # The dashboard's sealed ``[dashboard] scim_token`` (All settings).
        from ._shared import dashboard_setting

        raw = str(dashboard_setting("MAVERICK_SCIM_TOKEN", "scim_token", "") or "")
    return [s.strip() for s in raw.split(",") if s.strip()]


def scim_enabled() -> bool:
    """SCIM is active only when at least one IdP bearer is configured."""
    return bool(_scim_secrets())


def _token_matches(token: str, secret: str) -> bool:
    """Constant-time match of a presented bearer against one configured secret,
    supporting a ``sha256:<hex>`` hashed secret."""
    if secret.startswith("sha256:"):
        want = secret[len("sha256:"):].strip().lower()
        got = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return text_equals(got, want)
    return text_equals(token, secret)


def _scim_error(status: int, detail: str, *, scim_type: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"schemas": [_ERROR_SCHEMA], "detail": detail, "status": str(status)}
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(body, status_code=status, media_type="application/scim+json")


def _authorize(request: Request) -> JSONResponse | None:
    """None when the caller is authorized; a SCIM error response otherwise.

    Disabled (no token) -> 404 so the surface stays invisible until opted in.
    Wrong/absent bearer -> 401. Constant-time token compare."""
    secrets = _scim_secrets()
    if not secrets:
        return _scim_error(404, "SCIM is not enabled")
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    # Compare on bytes: hmac.compare_digest(str, str) raises TypeError on any
    # non-ASCII (>U+007F) codepoint, which would 500 this auth gate (the sole
    # gate for the IdP provisioning surface) on a crafted bearer -- a DoS /
    # info-leak amplifier. The channel verifiers compare the same way.
    # Any configured secret may match (rotation grace window); each compare is
    # constant-time.
    if not (token and any(_token_matches(token, s) for s in secrets)):
        from .auth_metrics import record_auth_failure
        record_auth_failure("scim_bad_token")
        return _scim_error(401, "invalid or missing SCIM bearer token")
    return None


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------
_USERS_LOCK = threading.Lock()
_MAX_STORE_CHARS = 4 * 1024 * 1024
_MAX_RECORDS = 100_000
_MAX_ID_CHARS = 1024
_MAX_TEXT_CHARS = 16_384
_MAX_TIMESTAMP = 253_402_300_799.0  # 9999-12-31T23:59:59Z
_MAX_PAGE = 200  # advertised as filter.maxResults in ServiceProviderConfig
_GROUP_AUDIT_OUTBOX_SCHEMA = "lightwork.scim-group-audit-outbox.v1"
_GROUP_AUDIT_INLINE_MEMBER_LIMIT = 128
_GROUP_AUDIT_OUTBOX_MAX_CHARS = (_MAX_STORE_CHARS * 3) + (256 * 1024)
_GROUP_AUDIT_OPERATIONS = frozenset({"create", "replace", "patch", "delete"})
_USER_FIELDS = frozenset({
    "id", "userName", "externalId", "displayName", "givenName",
    "familyName", "email", "active", "created_at", "updated_at",
})
_GROUP_FIELDS = frozenset({
    "id", "displayName", "externalId", "members", "created_at", "updated_at",
})


class ScimStoreError(RuntimeError):
    """A present SCIM authorization store cannot be trusted.

    Missing files retain the bootstrap meaning "no provisioned resources".
    A file that exists but is unreadable, malformed, or schema-invalid must
    never be interpreted as empty: doing so can discard deprovisioning state or
    let group-derived authorization fall through to permissive defaults.
    """


class ScimAuditPendingError(ScimStoreError):
    """A SCIM access mutation is durable but not yet audit-acknowledged.

    The active group store remains at the prior revision. The caller receives
    503 and may retry; the stable outbox identity makes a retry safe even when
    the first append succeeded but its acknowledgement was lost.
    """


def _store_path() -> Path:
    return maverick_home() / "scim_users.json"


def _locked_users():
    """Serialize the entire user-store load/modify/save across all workers."""
    from maverick.authority_effects import authority_effect_fence

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_USERS_LOCK)
        stack.enter_context(cross_process_lock(_store_path()))
        return stack.pop_all()


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite number {value!r}")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _read_store(
    path: Path,
    kind: str,
    *,
    max_chars: int = _MAX_STORE_CHARS,
) -> dict | None:
    """Read strict JSON, distinguishing a missing store from a damaged one."""
    try:
        ensure_private_directory(maverick_home())
        ensure_private_file(path)
        raw = atomic_read_text(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ScimStoreError(f"SCIM {kind} store unreadable: {e}") from e
    if len(raw) > max_chars:
        raise ScimStoreError(f"SCIM {kind} store exceeds the size limit")
    try:
        decoded = json.loads(
            raw,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_strict_json_object,
        )
    except (RecursionError, TypeError, ValueError) as e:
        raise ScimStoreError(f"SCIM {kind} store corrupt: {e}") from e
    if not isinstance(decoded, dict):
        raise ScimStoreError(
            f"SCIM {kind} store corrupt: top-level value must be an object"
        )
    return decoded


def _clean_string(
    record: dict,
    field: str,
    *,
    required: bool = False,
    limit: int = _MAX_TEXT_CHARS,
) -> str:
    value = record.get(field)
    if not isinstance(value, str):
        raise ScimStoreError(f"SCIM record field {field!r} must be a string")
    if (
        value != value.strip()
        or len(value) > limit
        or (required and not value)
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ScimStoreError(f"SCIM record field {field!r} is invalid")
    return value


def _timestamp(record: dict, field: str) -> int | float:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScimStoreError(f"SCIM record field {field!r} must be a timestamp")
    try:
        valid = math.isfinite(value) and 0 <= value <= _MAX_TIMESTAMP
    except (OverflowError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ScimStoreError(f"SCIM record field {field!r} is invalid")
    return value


def _validated_users(raw: dict) -> dict[str, dict]:
    if set(raw) != {"users"}:
        raise ScimStoreError("SCIM user store corrupt: unexpected top-level fields")
    records = raw.get("users")
    if not isinstance(records, list) or len(records) > _MAX_RECORDS:
        raise ScimStoreError("SCIM user store corrupt: 'users' must be a bounded list")
    users: dict[str, dict] = {}
    usernames: set[str] = set()
    external_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ScimStoreError("SCIM user store corrupt: every user must be an object")
        if set(record) != _USER_FIELDS:
            raise ScimStoreError("SCIM user store corrupt: unexpected user fields")
        uid = _clean_string(record, "id", required=True, limit=_MAX_ID_CHARS)
        if len(uid) != 32 or any(char not in "0123456789abcdef" for char in uid):
            raise ScimStoreError("SCIM user store corrupt: invalid internal user id")
        username = _clean_string(record, "userName", required=True)
        external_id = _clean_string(record, "externalId", limit=_MAX_ID_CHARS)
        for field in ("displayName", "givenName", "familyName", "email"):
            _clean_string(record, field)
        if not isinstance(record.get("active"), bool):
            raise ScimStoreError("SCIM user store corrupt: 'active' must be a boolean")
        _timestamp(record, "created_at")
        _timestamp(record, "updated_at")
        username_key = username.casefold()
        if uid in users or username_key in usernames:
            raise ScimStoreError("SCIM user store corrupt: duplicate user identity")
        if external_id and external_id in external_ids:
            # One IdP identity matching multiple users would union their groups.
            raise ScimStoreError("SCIM user store corrupt: duplicate externalId")
        if uid in external_ids or (external_id and external_id in users):
            # group_names_for_principal treats both fields as authoritative.
            # A collision across their namespaces would match two records and
            # union otherwise unrelated group memberships.
            raise ScimStoreError(
                "SCIM user store corrupt: authoritative identity collision"
            )
        users[uid] = dict(record)
        usernames.add(username_key)
        if external_id:
            external_ids.add(external_id)
    return users


def _load() -> dict[str, dict]:
    raw = _read_store(_store_path(), "user")
    return {} if raw is None else _validated_users(raw)


def _save(users: dict[str, dict]) -> None:
    if not isinstance(users, dict) or any(not isinstance(k, str) for k in users):
        raise ScimStoreError("SCIM users must be an object keyed by id")
    payload = {"users": [users[k] for k in sorted(users)]}
    validated = _validated_users(payload)
    if set(validated) != set(users) or any(
        not isinstance(k, str) or validated[k].get("id") != k for k in users
    ):
        raise ScimStoreError("SCIM user store keys do not match record ids")
    ensure_private_directory(maverick_home())
    atomic_write_text(_store_path(), json.dumps(payload, indent=2, sort_keys=True))


# --------------------------------------------------------------------------
# SCIM <-> store mapping
# --------------------------------------------------------------------------
def _primary_email(resource: dict) -> str:
    emails = resource.get("emails") or []
    if isinstance(emails, list):
        for e in emails:
            if isinstance(e, dict) and e.get("primary") and e.get("value"):
                return str(e["value"]).strip()
        for e in emails:
            if isinstance(e, dict) and e.get("value"):
                return str(e["value"]).strip()
    return ""


def _coerce_active(value: Any) -> bool:
    """Coerce a SCIM ``active`` value to bool (POST, PUT and PATCH share it).

    Some IdPs (notably Azure AD) send ``active`` as the STRING ``"False"``.
    ``bool("False")`` is True, so a plain ``bool()`` here would leave a user
    active on a string-boolean PUT/POST deprovision -- a deprovisioning bypass.
    Treat only a real bool True or the string "true" (any case) as active.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _record_from_resource(resource: dict, *, uid: str, created: float | None = None) -> dict:
    """Normalize an incoming SCIM User into our stored record."""
    name = resource.get("name") if isinstance(resource.get("name"), dict) else {}
    given_name = str(name.get("givenName") or "").strip()
    family_name = str(name.get("familyName") or "").strip()
    now = time.time()
    return {
        "id": uid,
        "userName": str(resource.get("userName") or "").strip(),
        "externalId": str(resource.get("externalId") or "").strip(),
        "displayName": str(resource.get("displayName")
                            or " ".join(p for p in [given_name, family_name] if p)
                            or "").strip(),
        "givenName": given_name,
        "familyName": family_name,
        "email": _primary_email(resource),
        "active": _coerce_active(resource.get("active", True)),
        "created_at": float(created if created is not None else now),
        "updated_at": now,
    }


def _to_scim(rec: dict) -> dict:
    """Render a stored record as a SCIM User resource."""
    res: dict[str, Any] = {
        "schemas": [_USER_SCHEMA],
        "id": rec["id"],
        "userName": rec.get("userName", ""),
        "active": bool(rec.get("active", True)),
        "meta": {
            "resourceType": "User",
            "created": _iso(rec.get("created_at")),
            "lastModified": _iso(rec.get("updated_at")),
            "location": f"/scim/v2/Users/{rec['id']}",
        },
    }
    if rec.get("externalId"):
        res["externalId"] = rec["externalId"]
    if rec.get("displayName"):
        res["displayName"] = rec["displayName"]
    if rec.get("givenName") or rec.get("familyName"):
        res["name"] = {"givenName": rec.get("givenName", ""),
                       "familyName": rec.get("familyName", "")}
    if rec.get("email"):
        res["emails"] = [{"value": rec["email"], "primary": True}]
    return res


def _iso(ts: float | None) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(float(ts or 0.0), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _rejected_record(users: dict[str, dict], rec: dict) -> JSONResponse | None:
    """A SCIM error when ``_save`` would refuse ``rec``; None when it would not.

    Routes call this before any lifecycle side effect (tenant create/suspend,
    identity retirement, session revocation), so an invalid request is refused
    with nothing changed instead of failing after access was already altered.
    """
    uid = rec["id"]
    external_id = rec["externalId"]
    if external_id and any(
        other_uid != uid and external_id in (other.get("externalId"), other_uid)
        for other_uid, other in users.items()
    ):
        return _scim_error(
            409,
            f"externalId {external_id!r} already exists",
            scim_type="uniqueness",
        )
    candidate = {**users, uid: rec}
    try:
        _validated_users({"users": [candidate[k] for k in sorted(candidate)]})
    except ScimStoreError as e:
        return _scim_error(400, str(e), scim_type="invalidValue")
    return None


# --------------------------------------------------------------------------
# Tenant linkage (provisioning and deprovisioning both fail closed)
# --------------------------------------------------------------------------
def _provision_tenant(uid: str, display_name: str, username: str = "") -> None:
    """Create the tenant before the SCIM identity is made active.

    The old best-effort helper swallowed every registry failure, allowing POST
    to commit and return an active SCIM user with no isolation boundary behind
    it. A randomly generated SCIM id must not already name a tenant; treating
    that condition as an error also avoids attaching an identity to unrelated
    pre-existing state after an (extremely unlikely) id collision.
    """
    from maverick.tenant import registry

    if registry.get_tenant(uid) is not None:
        raise RuntimeError("SCIM tenant id already exists")
    # A refusal does not prove ownership of this UUID: another provisioner may
    # have reserved it after the read above. Core creates its private namespace
    # before publication. Preserve ambiguous state for operator review; only
    # compensate after this call returned successfully and a later SCIM step
    # failed. A retry chooses a new UUID, never adopts retained state.
    # Only a typed pre-publication name refusal is safe to retry. An arbitrary
    # failure might have committed a tenant; never adopt or delete that state.
    base = display_name.strip() or username.strip() or uid
    user = username.strip()
    if len(user) > 80:
        user = user[:79].rstrip() + "…"
    qualifier = f" ({user})" if user and base.casefold() != username.casefold() else ""

    def bounded(suffix: str) -> str:
        available = 200 - len(suffix)  # Workspace editor's visible-name limit.
        if len(base) <= available:
            return base + suffix
        return base[:available - 1].rstrip() + "…" + suffix

    candidates = [bounded("")]
    if qualifier:
        candidates.append(bounded(qualifier))
    for label in candidates:
        try:
            registry.create_tenant(uid, display_name=label)
        except registry.DuplicateWorkspaceName:
            continue
        return
    for number in range(2, 1001):
        try:
            registry.create_tenant(uid, display_name=bounded(f"{qualifier} #{number}"))
        except registry.DuplicateWorkspaceName:
            continue
        return
    raise registry.DuplicateWorkspaceName("No distinct SCIM workspace name is available")


def _rollback_provisioned_tenant(uid: str) -> None:
    """Best-effort compensation after a later SCIM create step fails."""
    try:
        from maverick.tenant import registry

        registry.delete_tenant(uid, purge=True)
    except Exception:  # pragma: no cover - preserve the original create failure
        pass


def _identity_values(rec: dict) -> list[str]:
    return [str(rec.get(key) or "") for key in
            ("externalId", "userName", "email", "id")]


def _revoke_user_sessions(rec: dict) -> None:
    """Kill any live dashboard session/bearer for a deprovisioned SCIM user, so
    deprovisioning ends current access, not just future logins.

    The OIDC session subject is IdP-specific, so revoke every plausible
    identifier: ``externalId`` is the usual OIDC ``sub`` for Okta/Entra, plus
    ``userName`` / ``email`` / our internal ``id``. revoke_principal is a no-op
    for a blank value, so over-revoking spare identifiers is harmless.

    Pairwise-``sub`` IdPs (Entra) issue an OIDC ``sub`` that appears in no SCIM
    attribute, so the direct revokes above can't reach the live session. The
    subject directory closes that gap: it recorded this user's ``sub`` against
    its stable identifiers at login, so we look the ``sub`` up by the SCIM
    record's identifiers and revoke it too."""
    ids = _identity_values(rec)
    from .session_revocation import revoke_principal
    for value in ids:
        revoke_principal(value)
    # Reach a pairwise/per-app sub recorded at login under these identifiers.
    # An unreadable directory/revocation store aborts deprovisioning so the IdP
    # retries; acknowledging success without terminating those credentials is
    # an access-control failure, not a best-effort telemetry miss.
    from .subject_directory import subs_for
    for sub in subs_for(ids):
        revoke_principal(sub)


def _retire_user_identity(rec: dict) -> None:
    """Revoke live credentials and persist a deny tombstone for fresh ones."""
    _revoke_user_sessions(rec)
    from .subject_directory import retire

    retire(_identity_values(rec))


def _reinstate_user_identity(rec: dict) -> None:
    """Clear a tombstone only after an active SCIM record is durable."""
    from .subject_directory import reinstate

    # Direct subjects may equal any SCIM identifier, but a pairwise-sub bridge
    # is authorization-sensitive and may only be revived through the IdP's
    # immutable externalId (or our internal id), never an unverified email/UPN
    # claim that happens to match userName/email.
    reinstate(
        _identity_values(rec),
        linked_identifiers=[str(rec.get("externalId") or ""), rec["id"]],
    )


def _set_tenant_active(uid: str, active: bool, rec: dict | None = None) -> None:
    if not active and rec is not None:
        _retire_user_identity(rec)
    from maverick.tenant import registry
    if registry.get_tenant(uid) is None:
        if active:
            raise RuntimeError("cannot activate a SCIM user without a tenant")
        return
    (registry.resume_tenant if active else registry.suspend_tenant)(uid)


def _delete_tenant(uid: str, rec: dict | None = None) -> None:
    if rec is not None:
        # Write the durable deny decision before removing either the tenant or
        # SCIM record. If a later step fails, authentication still fails closed
        # and the IdP can safely retry the DELETE.
        _retire_user_identity(rec)
    from maverick.tenant import registry
    registry.delete_tenant(uid)
    # Keep the hashed identifier -> pairwise-sub binding. It contains no raw
    # identifier and is needed both to enforce the tombstone and to reactivate
    # that exact pairwise subject if the IdP explicitly provisions it again.


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
async def _json_body(request: Request) -> dict:
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def _list_response(request: Request, resources: list[dict]) -> JSONResponse:
    """One page of ``resources``: 1-based ``startIndex`` + ``count``, with a
    page never larger than the advertised ``filter.maxResults``."""
    try:
        start = max(1, int(request.query_params.get("startIndex", "1")))
    except ValueError:
        start = 1
    try:
        count = int(request.query_params.get("count", str(_MAX_PAGE)))
    except ValueError:
        count = _MAX_PAGE
    count = min(max(0, count), _MAX_PAGE)
    page = resources[start - 1: start - 1 + count]
    body = {
        "schemas": [_LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": start,
        "itemsPerPage": len(page),
        "Resources": page,
    }
    return JSONResponse(body, media_type="application/scim+json")


@router.get("/ServiceProviderConfig")
async def service_provider_config(request: Request):
    if (err := _authorize(request)) is not None:
        return err
    cfg = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": _MAX_PAGE},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken", "name": "OAuth Bearer Token",
            "description": "Authentication via a static bearer token.",
        }],
    }
    return JSONResponse(cfg, media_type="application/scim+json")


@router.get("/ResourceTypes")
async def resource_types(request: Request):
    if (err := _authorize(request)) is not None:
        return err
    rt = [{
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User", "name": "User", "endpoint": "/Users",
        "schema": _USER_SCHEMA,
    }, {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group", "name": "Group", "endpoint": "/Groups",
        "schema": _GROUP_SCHEMA,
    }]
    return JSONResponse(rt, media_type="application/scim+json")


@router.get("/Users")
async def list_users(request: Request):
    if (err := _authorize(request)) is not None:
        return err
    users = _load()
    resources = [_to_scim(u) for u in (users[k] for k in sorted(users))]

    # Minimal filter support: `userName eq "value"` (the IdP existence probe).
    flt = request.query_params.get("filter", "").strip()
    if flt:
        match = _parse_username_eq(flt)
        if match is None:
            return _scim_error(400, f"unsupported filter: {flt}", scim_type="invalidFilter")
        resources = [r for r in resources if r.get("userName", "").lower() == match.lower()]
    return _list_response(request, resources)


@router.post("/Users")
async def create_user(request: Request):
    if (err := _authorize(request)) is not None:
        return err
    resource = await _json_body(request)
    username = str(resource.get("userName") or "").strip()
    if not username:
        return _scim_error(400, "userName is required", scim_type="invalidValue")
    uid = uuid.uuid4().hex
    rec = _record_from_resource(resource, uid=uid)
    with _locked_users():
        users = _load()
        # Check and commit under one cross-worker critical section; otherwise
        # simultaneous IdP retries can both pass uniqueness and lose a write.
        if any(u.get("userName", "").casefold() == username.casefold()
               for u in users.values()):
            return _scim_error(
                409,
                f"userName {username!r} already exists",
                scim_type="uniqueness",
            )
        # Refuse a duplicate externalId or an invalid value before a tenant
        # exists; creating and then purging one leaves its id reserved.
        if (err := _rejected_record(users, rec)) is not None:
            return err
        try:
            _provision_tenant(uid, rec["displayName"] or username, username)
        except Exception:
            return _scim_error(500, "tenant provisioning failed")
        try:
            if not rec["active"]:
                _set_tenant_active(uid, False, rec)
            users[uid] = rec
            _save(users)
        except Exception:
            _rollback_provisioned_tenant(uid)
            return _scim_error(500, "SCIM user provisioning failed")
        if rec["active"]:
            try:
                # A previous hard DELETE may have left a durable tombstone for
                # these IdP identifiers/pairwise subjects. Clear it only after
                # both tenant and active SCIM record are durable.
                _reinstate_user_identity(rec)
            except Exception:
                # Keep denial authoritative if the retirement ledger cannot be
                # updated, and compensate the newly created resource so an IdP
                # retry is not trapped behind a uniqueness conflict.
                users.pop(uid, None)
                try:
                    _save(users)
                except Exception:
                    pass
                _rollback_provisioned_tenant(uid)
                return _scim_error(500, "identity lifecycle update failed")
    return JSONResponse(_to_scim(rec), status_code=201, media_type="application/scim+json")


@router.get("/Users/{uid}")
async def get_user(uid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    rec = _load().get(uid)
    if rec is None:
        return _scim_error(404, f"user {uid} not found")
    return JSONResponse(_to_scim(rec), media_type="application/scim+json")


@router.put("/Users/{uid}")
async def replace_user(uid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    resource = await _json_body(request)
    with _locked_users():
        users = _load()
        existing = users.get(uid)
        if existing is None:
            return _scim_error(404, f"user {uid} not found")
        rec = _record_from_resource(
            resource, uid=uid, created=existing.get("created_at")
        )
        # userName is immutable in practice; keep it if the PUT omits it.
        if not rec["userName"]:
            rec["userName"] = existing.get("userName", "")
        # Live sessions and API keys belong to the stored externalId. A PUT
        # that omits it must not drop that subject from deactivation.
        if not rec["externalId"]:
            rec["externalId"] = existing.get("externalId", "")
        if any(
            other_uid != uid
            and other.get("userName", "").casefold() == rec["userName"].casefold()
            for other_uid, other in users.items()
        ):
            return _scim_error(
                409,
                f"userName {rec['userName']!r} already exists",
                scim_type="uniqueness",
            )
        if (err := _rejected_record(users, rec)) is not None:
            return err
        was_active = bool(existing.get("active", True))
        if not rec["active"] and _identity_values(existing) != _identity_values(rec):
            # The PUT renamed an identifier while deactivating: retire the
            # stored identifiers too, or their sessions would stay valid.
            try:
                _retire_user_identity(existing)
            except Exception:
                return _scim_error(500, "identity lifecycle update failed")
        if rec["active"] != was_active:
            try:
                _set_tenant_active(uid, rec["active"], rec)
            except Exception:
                return _scim_error(500, "tenant lifecycle update failed")
        elif not rec["active"]:
            try:
                _retire_user_identity(rec)
            except Exception:
                return _scim_error(500, "identity lifecycle update failed")
        users[uid] = rec
        _save(users)
        if rec["active"]:
            try:
                _reinstate_user_identity(rec)
            except Exception:
                return _scim_error(500, "identity lifecycle update failed")
    return JSONResponse(_to_scim(rec), media_type="application/scim+json")


@router.patch("/Users/{uid}")
async def patch_user(uid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    body = await _json_body(request)
    with _locked_users():
        users = _load()
        rec = users.get(uid)
        if rec is None:
            return _scim_error(404, f"user {uid} not found")
        was_active = bool(rec.get("active", True))
        applied = _apply_patch(rec, body)
        if applied is None:
            return _scim_error(
                400, "unsupported PATCH operation", scim_type="invalidValue"
            )
        rec["userName"] = str(rec.get("userName") or "").strip()
        if not rec["userName"]:
            return _scim_error(400, "userName is required", scim_type="invalidValue")
        if any(
            other_uid != uid
            and other.get("userName", "").casefold() == rec["userName"].casefold()
            for other_uid, other in users.items()
        ):
            return _scim_error(
                409,
                f"userName {rec['userName']!r} already exists",
                scim_type="uniqueness",
            )
        rec["updated_at"] = time.time()
        # Validate before the lifecycle side effects below: a request refused
        # after them left the tenant suspended behind an ``active`` record.
        if (err := _rejected_record(users, rec)) is not None:
            return err
        if bool(rec.get("active", True)) != was_active:
            try:
                _set_tenant_active(uid, bool(rec.get("active", True)), rec)
            except Exception:
                return _scim_error(500, "tenant lifecycle update failed")
        elif not bool(rec.get("active", True)):
            try:
                _retire_user_identity(rec)
            except Exception:
                return _scim_error(500, "identity lifecycle update failed")
        users[uid] = rec
        _save(users)
        if bool(rec.get("active", True)):
            try:
                _reinstate_user_identity(rec)
            except Exception:
                return _scim_error(500, "identity lifecycle update failed")
    return JSONResponse(_to_scim(rec), media_type="application/scim+json")


@router.delete("/Users/{uid}")
async def delete_user(uid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    with _locked_users():
        users = _load()
        if uid not in users:
            return _scim_error(404, f"user {uid} not found")
        rec = users.get(uid)
        try:
            _delete_tenant(uid, rec)
        except Exception:
            return _scim_error(500, "tenant deletion failed")
        del users[uid]
        _save(users)
    return JSONResponse(None, status_code=204)


# --------------------------------------------------------------------------
# Groups (RFC 7643 §4.2): the IdP pushes group membership so access can be
# managed by team, not per user. Stored in <home>/scim_groups.json; the
# role/department mapping over these groups lives in scim_groups.py.
# --------------------------------------------------------------------------
def _groups_path() -> Path:
    return maverick_home() / "scim_groups.json"


# Serializes a group-store load-modify-save; cross_process_lock extends it
# across dashboard workers. Group membership drives role/department access
# (scim_groups.py), so a lost update here silently grants or withholds access
# — the same hazard the rbac/suite-grants stores guard against.
_GROUPS_LOCK = threading.Lock()


def _locked_groups():
    from maverick.authority_effects import authority_effect_fence

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_GROUPS_LOCK)
        stack.enter_context(cross_process_lock(_groups_path()))
        return stack.pop_all()


def _validated_groups(raw: dict) -> dict[str, dict]:
    if set(raw) != {"groups"}:
        raise ScimStoreError("SCIM group store corrupt: unexpected top-level fields")
    records = raw.get("groups")
    if not isinstance(records, list) or len(records) > _MAX_RECORDS:
        raise ScimStoreError("SCIM group store corrupt: 'groups' must be a bounded list")
    groups: dict[str, dict] = {}
    display_names: set[str] = set()
    external_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ScimStoreError("SCIM group store corrupt: every group must be an object")
        if set(record) != _GROUP_FIELDS:
            raise ScimStoreError("SCIM group store corrupt: unexpected group fields")
        gid = _clean_string(record, "id", required=True, limit=_MAX_ID_CHARS)
        if len(gid) != 32 or any(char not in "0123456789abcdef" for char in gid):
            raise ScimStoreError("SCIM group store corrupt: invalid internal group id")
        display_name = _clean_string(record, "displayName", required=True)
        external_id = _clean_string(record, "externalId", limit=_MAX_ID_CHARS)
        members = record.get("members")
        if not isinstance(members, list) or len(members) > _MAX_RECORDS:
            raise ScimStoreError(
                "SCIM group store corrupt: 'members' must be a bounded list"
            )
        clean_members: list[str] = []
        seen_members: set[str] = set()
        for member in members:
            if (
                not isinstance(member, str)
                or member != member.strip()
                or not member
                or len(member) > _MAX_ID_CHARS
                or len(member) != 32
                or any(char not in "0123456789abcdef" for char in member)
                or member in seen_members
            ):
                raise ScimStoreError("SCIM group store corrupt: invalid member id")
            clean_members.append(member)
            seen_members.add(member)
        _timestamp(record, "created_at")
        _timestamp(record, "updated_at")
        name_key = display_name.casefold()
        if gid in groups or name_key in display_names:
            # displayName is the authorization-mapping key and must be unique.
            raise ScimStoreError("SCIM group store corrupt: duplicate group identity")
        if external_id and external_id in external_ids:
            raise ScimStoreError("SCIM group store corrupt: duplicate externalId")
        groups[gid] = {**record, "members": clean_members}
        display_names.add(name_key)
        if external_id:
            external_ids.add(external_id)
    return groups


def _load_groups() -> dict[str, dict]:
    raw = _read_store(_groups_path(), "group")
    return {} if raw is None else _validated_groups(raw)


def _group_store_payload(groups: dict[str, dict]) -> dict[str, list[dict]]:
    if not isinstance(groups, dict) or any(not isinstance(k, str) for k in groups):
        raise ScimStoreError("SCIM groups must be an object keyed by id")
    payload = {"groups": [groups[k] for k in sorted(groups)]}
    validated = _validated_groups(payload)
    if set(validated) != set(groups) or any(
        validated[k].get("id") != k for k in groups
    ):
        raise ScimStoreError("SCIM group store keys do not match record ids")
    return payload


def _save_groups(groups: dict[str, dict]) -> None:
    payload = _group_store_payload(groups)
    ensure_private_directory(maverick_home())
    atomic_write_text(_groups_path(), json.dumps(payload, indent=2, sort_keys=True))


def _group_state_digest(groups: dict[str, dict]) -> str:
    payload = _group_store_payload(groups)
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _group_audit_outbox_path() -> Path:
    """Deployment-global SCIM authority outbox.

    The group store itself is deployment-global because one SCIM IdP provisions
    the tenant roster. Keeping the outbox beside it prevents an ambient tenant
    context from splitting one mutation across tenant audit namespaces.
    """
    return maverick_home() / "scim_groups.audit-outbox.json"


def _authority_snapshot(record: dict | None) -> dict | None:
    if record is None:
        return None
    return {
        "displayName": str(record.get("displayName") or ""),
        "members": sorted(set(record.get("members") or [])),
    }


def _validated_authority_snapshot(value: object, label: str) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"displayName", "members"}:
        raise ScimStoreError(f"SCIM group audit outbox has invalid {label} snapshot")
    display_name = value.get("displayName")
    members = value.get("members")
    if (
        not isinstance(display_name, str)
        or not display_name
        or display_name != display_name.strip()
        or len(display_name) > _MAX_TEXT_CHARS
        or not isinstance(members, list)
        or len(members) > _MAX_RECORDS
    ):
        raise ScimStoreError(f"SCIM group audit outbox has invalid {label} snapshot")
    if any(
        not isinstance(member, str)
        or len(member) != 32
        or any(char not in "0123456789abcdef" for char in member)
        for member in members
    ):
        raise ScimStoreError(
            f"SCIM group audit outbox has invalid {label} member identity"
        )
    if members != sorted(members) or len(set(members)) != len(members):
        raise ScimStoreError(f"SCIM group audit outbox has invalid {label} snapshot")
    return {"displayName": display_name, "members": list(members)}


def _member_set_commitment(
    event_id: str,
    label: str,
    members: list[str],
) -> str:
    canonical = json.dumps(
        {
            "schema": "lightwork.scim-group-member-set.v1",
            "event_id": event_id,
            "label": label,
            "members": members,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _member_set_payload(
    event_id: str,
    label: str,
    members: set[str],
) -> dict[str, object]:
    ordered = sorted(members)
    inline = (
        ordered
        if len(ordered) <= _GROUP_AUDIT_INLINE_MEMBER_LIMIT
        else None
    )
    return {
        f"{label}_count": len(ordered),
        f"{label}_members": inline,
        f"{label}_members_sha256": _member_set_commitment(
            event_id,
            label,
            ordered,
        ),
    }


def _group_audit_payload(
    *,
    event_id: str,
    operation: str,
    group_id: str,
    occurred_at: float,
    old_authority: dict | None,
    new_authority: dict | None,
) -> dict[str, object]:
    old_members = set((old_authority or {}).get("members") or [])
    new_members = set((new_authority or {}).get("members") or [])
    added = new_members - old_members
    removed = old_members - new_members
    payload: dict[str, object] = {
        "scim_group_event_id": event_id,
        "occurred_at": occurred_at,
        "actor": "scim",
        "principal": f"scim-group:{group_id}",
        "field": "scim_group_authority",
        "tenant": "",
        "scope": "deployment",
        "operation": operation,
        "group_id": group_id,
        "old_name": (old_authority or {}).get("displayName"),
        "new_name": (new_authority or {}).get("displayName"),
    }
    payload.update(_member_set_payload(event_id, "added", added))
    payload.update(_member_set_payload(event_id, "removed", removed))
    payload.update(_member_set_payload(event_id, "old", old_members))
    payload.update(_member_set_payload(event_id, "new", new_members))
    return payload


def _group_audit_outbox_record(
    prior: dict[str, dict],
    target: dict[str, dict],
    *,
    operation: str,
    group_id: str,
) -> dict[str, object]:
    if operation not in _GROUP_AUDIT_OPERATIONS:
        raise ScimStoreError("unsupported SCIM group audit operation")
    old_authority = _authority_snapshot(prior.get(group_id))
    new_authority = _authority_snapshot(target.get(group_id))
    if (
        (operation == "create" and (old_authority is not None or new_authority is None))
        or (operation == "delete" and (old_authority is None or new_authority is not None))
        or (
            operation in {"replace", "patch"}
            and (old_authority is None or new_authority is None)
        )
    ):
        raise ScimStoreError("SCIM group audit operation does not match its state")
    event_id = f"scim-group-{uuid.uuid4().hex}"
    occurred_at = time.time()
    event = _group_audit_payload(
        event_id=event_id,
        operation=operation,
        group_id=group_id,
        occurred_at=occurred_at,
        old_authority=old_authority,
        new_authority=new_authority,
    )
    return {
        "schema": _GROUP_AUDIT_OUTBOX_SCHEMA,
        "event_id": event_id,
        "operation": operation,
        "occurred_at": occurred_at,
        "prior_sha256": _group_state_digest(prior),
        "target_sha256": _group_state_digest(target),
        "old_authority": old_authority,
        "new_authority": new_authority,
        "event": event,
        "target": _group_store_payload(target),
    }


def _validated_group_audit_outbox(
    raw: dict,
    current: dict[str, dict],
) -> tuple[dict[str, object], dict[str, dict]]:
    fields = {
        "schema",
        "event_id",
        "operation",
        "occurred_at",
        "prior_sha256",
        "target_sha256",
        "old_authority",
        "new_authority",
        "event",
        "target",
    }
    if set(raw) != fields or raw.get("schema") != _GROUP_AUDIT_OUTBOX_SCHEMA:
        raise ScimStoreError("SCIM group audit outbox has an invalid schema")
    event_id = raw.get("event_id")
    operation = raw.get("operation")
    occurred_at = raw.get("occurred_at")
    prior_sha256 = raw.get("prior_sha256")
    target_sha256 = raw.get("target_sha256")
    if (
        not isinstance(event_id, str)
        or not event_id.startswith("scim-group-")
        or len(event_id) != 43
        or any(char not in "0123456789abcdef" for char in event_id[11:])
        or operation not in _GROUP_AUDIT_OPERATIONS
        or isinstance(occurred_at, bool)
        or not isinstance(occurred_at, (int, float))
        or not math.isfinite(occurred_at)
        or not 0 <= occurred_at <= _MAX_TIMESTAMP
        or not isinstance(prior_sha256, str)
        or len(prior_sha256) != 64
        or any(char not in "0123456789abcdef" for char in prior_sha256)
        or not isinstance(target_sha256, str)
        or len(target_sha256) != 64
        or any(char not in "0123456789abcdef" for char in target_sha256)
    ):
        raise ScimStoreError("SCIM group audit outbox metadata is invalid")
    target_raw = raw.get("target")
    if not isinstance(target_raw, dict):
        raise ScimStoreError("SCIM group audit outbox target is invalid")
    target = _validated_groups(target_raw)
    if _group_state_digest(target) != target_sha256:
        raise ScimStoreError("SCIM group audit outbox target digest is invalid")

    event = raw.get("event")
    if not isinstance(event, dict):
        raise ScimStoreError("SCIM group audit outbox event is invalid")
    group_id = event.get("group_id")
    if (
        not isinstance(group_id, str)
        or len(group_id) != 32
        or any(char not in "0123456789abcdef" for char in group_id)
    ):
        raise ScimStoreError("SCIM group audit outbox group identity is invalid")
    old_authority = _validated_authority_snapshot(
        raw.get("old_authority"),
        "old",
    )
    new_authority = _validated_authority_snapshot(
        raw.get("new_authority"),
        "new",
    )
    if (
        (operation == "create" and (old_authority is not None or new_authority is None))
        or (operation == "delete" and (old_authority is None or new_authority is not None))
        or (
            operation in {"replace", "patch"}
            and (old_authority is None or new_authority is None)
        )
    ):
        raise ScimStoreError(
            "SCIM group audit operation does not match its authority snapshots"
        )
    expected_event = _group_audit_payload(
        event_id=event_id,
        operation=str(operation),
        group_id=group_id,
        occurred_at=float(occurred_at),
        old_authority=old_authority,
        new_authority=new_authority,
    )
    if event != expected_event:
        raise ScimStoreError("SCIM group audit outbox event does not match its state")
    if _authority_snapshot(target.get(group_id)) != new_authority:
        raise ScimStoreError("SCIM group audit outbox target group is inconsistent")

    current_sha256 = _group_state_digest(current)
    if current_sha256 not in {prior_sha256, target_sha256}:
        raise ScimStoreError(
            "SCIM group state diverged from its pending audit transaction"
        )
    if current_sha256 == prior_sha256:
        if _authority_snapshot(current.get(group_id)) != old_authority:
            raise ScimStoreError("SCIM group audit outbox prior group is inconsistent")
        changed = {
            candidate
            for candidate in set(current) | set(target)
            if current.get(candidate) != target.get(candidate)
        }
        if changed != {group_id}:
            raise ScimStoreError(
                "SCIM group audit outbox changes more than one group"
            )
    normalized = dict(raw)
    normalized["occurred_at"] = float(occurred_at)
    normalized["old_authority"] = old_authority
    normalized["new_authority"] = new_authority
    normalized["event"] = expected_event
    return normalized, target


def _load_group_audit_outbox(
    current: dict[str, dict],
) -> tuple[dict[str, object], dict[str, dict]] | None:
    raw = _read_store(
        _group_audit_outbox_path(),
        "group audit outbox",
        max_chars=_GROUP_AUDIT_OUTBOX_MAX_CHARS,
    )
    if raw is None:
        return None
    return _validated_group_audit_outbox(raw, current)


def _emit_group_audit_event(event: dict[str, object]) -> bool:
    """Deliver one deployment-global, append-once SCIM authority event."""
    from maverick.audit import EventKind, audit_event

    return audit_event(
        EventKind.ACCESS_GRANT_CHANGED,
        agent="scim",
        _global=True,
        **event,
    )


def _flush_group_audit_outbox() -> bool:
    """Acknowledge then publish one staged SCIM group mutation.

    The active group file remains unchanged until the append-once event returns
    True. The outbox survives every uncertain outcome, so a retry converges
    safely whether the first append failed, was refused, or succeeded just
    before the process lost its acknowledgement.
    """
    current = _load_groups()
    loaded = _load_group_audit_outbox(current)
    if loaded is None:
        return True
    pending, target = loaded
    try:
        acknowledged = _emit_group_audit_event(dict(pending["event"]))
    except Exception as exc:
        raise ScimAuditPendingError(
            "SCIM group access audit is pending; mutation was not published"
        ) from exc
    if acknowledged is not True:
        raise ScimAuditPendingError(
            "SCIM group access audit was not acknowledged; mutation was not published"
        )

    target_sha256 = str(pending["target_sha256"])
    if _group_state_digest(current) != target_sha256:
        try:
            _save_groups(target)
        except Exception as exc:
            try:
                published = _group_state_digest(_load_groups()) == target_sha256
            except Exception:
                published = False
            if not published:
                raise ScimAuditPendingError(
                    "SCIM group access audit was acknowledged; publication is pending"
                ) from exc
    if _group_state_digest(_load_groups()) != target_sha256:
        raise ScimAuditPendingError(
            "SCIM group access audit was acknowledged; publication is unverified"
        )
    try:
        _group_audit_outbox_path().unlink(missing_ok=True)
    except OSError as exc:
        # State is effective only after acknowledgement, but keep the 503
        # ambiguity explicit until the durable retry marker can be retired.
        raise ScimAuditPendingError(
            "SCIM group mutation committed; audit cleanup is pending"
        ) from exc
    return True


def _save_groups_with_audit(
    groups: dict[str, dict],
    prior: dict[str, dict],
    *,
    operation: str,
    group_id: str,
) -> None:
    """Stage one group revision, append one batch event, then publish it."""
    if _group_audit_outbox_path().exists():
        raise ScimAuditPendingError(
            "a prior SCIM group audit transaction requires recovery"
        )
    pending = _group_audit_outbox_record(
        prior,
        groups,
        operation=operation,
        group_id=group_id,
    )
    # Validate the exact persisted form before it becomes the recovery
    # authority. This also proves the event and target bind to the prior state.
    _validated_group_audit_outbox(pending, prior)
    atomic_write_text(
        _group_audit_outbox_path(),
        json.dumps(pending, indent=2, sort_keys=True),
    )
    _flush_group_audit_outbox()


def _load_effective_groups() -> dict[str, dict]:
    """Load the published authorization state and validate any retry marker."""
    groups = _load_groups()
    _load_group_audit_outbox(groups)
    return groups


def _group_name_taken(groups: dict[str, dict], name: str, exclude_gid: str) -> bool:
    """True iff a DIFFERENT group already holds ``name`` (case-insensitive).

    displayName is the key the [dashboard] group_roles / group_suites mapping
    tables resolve on, so two groups sharing a name would let one group's
    members silently inherit the other's mapped role/departments. Create
    enforces this; rename (PUT/PATCH) must too."""
    folded = (name or "").strip().casefold()
    return any(gid != exclude_gid and g.get("displayName", "").casefold() == folded
               for gid, g in groups.items())


def _member_ids(value) -> list[str]:
    """Normalize a SCIM ``members`` value to a list of member ids (user uids)."""
    out: list[str] = []
    if isinstance(value, list):
        for m in value:
            if isinstance(m, dict) and m.get("value"):
                out.append(str(m["value"]))
            elif isinstance(m, str) and m.strip():
                out.append(m.strip())
    return sorted(set(out))


def _rejected_members(rec: dict) -> JSONResponse | None:
    """A 400 when a member is not a SCIM user id (the store refuses those)."""
    if all(
        len(member) == 32 and all(char in "0123456789abcdef" for char in member)
        for member in rec["members"]
    ):
        return None
    return _scim_error(
        400, "members must be SCIM user ids", scim_type="invalidValue"
    )


def _group_from_resource(resource: dict, *, gid: str,
                         created: float | None = None) -> dict:
    now = time.time()
    return {
        "id": gid,
        "displayName": str(resource.get("displayName") or "").strip(),
        "externalId": str(resource.get("externalId") or "").strip(),
        "members": _member_ids(resource.get("members")),
        "created_at": float(created if created is not None else now),
        "updated_at": now,
    }


def _to_scim_group(rec: dict) -> dict:
    res: dict[str, Any] = {
        "schemas": [_GROUP_SCHEMA],
        "id": rec["id"],
        "displayName": rec.get("displayName", ""),
        "members": [{"value": m, "$ref": f"/scim/v2/Users/{m}"}
                    for m in rec.get("members", [])],
        "meta": {
            "resourceType": "Group",
            "created": _iso(rec.get("created_at")),
            "lastModified": _iso(rec.get("updated_at")),
            "location": f"/scim/v2/Groups/{rec['id']}",
        },
    }
    if rec.get("externalId"):
        res["externalId"] = rec["externalId"]
    return res


@router.get("/Groups")
async def list_groups(request: Request):
    if (err := _authorize(request)) is not None:
        return err
    groups = _load_effective_groups()
    resources = [_to_scim_group(g) for g in (groups[k] for k in sorted(groups))]
    flt = request.query_params.get("filter", "").strip()
    if flt:
        match = _parse_attr_eq(flt, "displayName")
        if match is None:
            return _scim_error(400, f"unsupported filter: {flt}",
                               scim_type="invalidFilter")
        resources = [r for r in resources
                     if r.get("displayName", "").lower() == match.lower()]
    return _list_response(request, resources)


@router.post("/Groups")
async def create_group(request: Request):
    if (err := _authorize(request)) is not None:
        return err
    resource = await _json_body(request)
    display = str(resource.get("displayName") or "").strip()
    if not display:
        return _scim_error(400, "displayName is required", scim_type="invalidValue")
    gid = uuid.uuid4().hex
    rec = _group_from_resource(resource, gid=gid)
    if (err := _rejected_members(rec)) is not None:
        return err
    try:
        with _locked_groups():
            _flush_group_audit_outbox()
            groups = _load_groups()
            if _group_name_taken(groups, display, gid):
                return _scim_error(409, f"group {display!r} already exists",
                                   scim_type="uniqueness")
            prior = copy.deepcopy(groups)
            groups[gid] = rec
            _save_groups_with_audit(
                groups,
                prior,
                operation="create",
                group_id=gid,
            )
    except ScimAuditPendingError:
        return _scim_error(
            503,
            "group access audit was not acknowledged; mutation is pending",
        )
    return JSONResponse(_to_scim_group(rec), status_code=201,
                        media_type="application/scim+json")


@router.get("/Groups/{gid}")
async def get_group(gid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    rec = _load_effective_groups().get(gid)
    if rec is None:
        return _scim_error(404, f"group {gid} not found")
    return JSONResponse(_to_scim_group(rec), media_type="application/scim+json")


@router.put("/Groups/{gid}")
async def replace_group(gid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    resource = await _json_body(request)
    try:
        with _locked_groups():
            _flush_group_audit_outbox()
            groups = _load_groups()
            existing = groups.get(gid)
            if existing is None:
                return _scim_error(404, f"group {gid} not found")
            rec = _group_from_resource(resource, gid=gid,
                                       created=existing.get("created_at"))
            if not rec["displayName"]:
                rec["displayName"] = existing.get("displayName", "")
            if (err := _rejected_members(rec)) is not None:
                return err
            # Rename must honor the same case-insensitive uniqueness as create, or
            # two groups share the mapping key.
            if _group_name_taken(groups, rec["displayName"], gid):
                return _scim_error(409, f"group {rec['displayName']!r} already exists",
                                   scim_type="uniqueness")
            prior = copy.deepcopy(groups)
            groups[gid] = rec
            _save_groups_with_audit(
                groups,
                prior,
                operation="replace",
                group_id=gid,
            )
    except ScimAuditPendingError:
        return _scim_error(
            503,
            "group access audit was not acknowledged; mutation is pending",
        )
    return JSONResponse(_to_scim_group(rec), media_type="application/scim+json")


@router.patch("/Groups/{gid}")
async def patch_group(gid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    body = await _json_body(request)
    try:
        with _locked_groups():
            _flush_group_audit_outbox()
            groups = _load_groups()
            rec = groups.get(gid)
            if rec is None:
                return _scim_error(404, f"group {gid} not found")
            prior = copy.deepcopy(groups)
            old_name = rec.get("displayName", "")
            if _apply_group_patch(rec, body) is None:
                return _scim_error(400, "unsupported PATCH operation",
                                   scim_type="invalidValue")
            if not isinstance(rec.get("displayName"), str) or not rec[
                "displayName"
            ].strip():
                return _scim_error(
                    400,
                    "displayName is required",
                    scim_type="invalidValue",
                )
            if (rec.get("displayName", "") != old_name
                    and _group_name_taken(groups, rec.get("displayName", ""), gid)):
                return _scim_error(409, f"group {rec['displayName']!r} already exists",
                                   scim_type="uniqueness")
            if (err := _rejected_members(rec)) is not None:
                return err
            rec["updated_at"] = time.time()
            groups[gid] = rec
            _save_groups_with_audit(
                groups,
                prior,
                operation="patch",
                group_id=gid,
            )
    except ScimAuditPendingError:
        return _scim_error(
            503,
            "group access audit was not acknowledged; mutation is pending",
        )
    return JSONResponse(_to_scim_group(rec), media_type="application/scim+json")


@router.delete("/Groups/{gid}")
async def delete_group(gid: str, request: Request):
    if (err := _authorize(request)) is not None:
        return err
    try:
        with _locked_groups():
            _flush_group_audit_outbox()
            groups = _load_groups()
            rec = groups.get(gid)
            if rec is None:
                return _scim_error(404, f"group {gid} not found")
            prior = copy.deepcopy(groups)
            del groups[gid]
            # Deleting a mapped group revokes its members' group-derived access.
            _save_groups_with_audit(
                groups,
                prior,
                operation="delete",
                group_id=gid,
            )
    except ScimAuditPendingError:
        return _scim_error(
            503,
            "group access audit was not acknowledged; mutation is pending",
        )
    return JSONResponse(None, status_code=204)


def _apply_group_patch(rec: dict, body: dict) -> bool | None:
    """Apply a SCIM Group PatchOp in place: the Okta/Azure member-sync shapes.

    Supported ops: replace ``displayName``; add / remove / replace ``members``
    (including the ``members[value eq "<uid>"]`` remove-one path form). Returns
    True on success, None if nothing applicable was found."""
    import re
    if _PATCH_SCHEMA not in (body.get("schemas") or []):
        return None
    ops = body.get("Operations") or body.get("operations") or []
    if not isinstance(ops, list):
        return None
    applied = False
    members = set(rec.get("members", []))
    for op in ops:
        if not isinstance(op, dict):
            continue
        verb = str(op.get("op", "")).lower()
        path = str(op.get("path") or "").strip()
        value = op.get("value")
        one = re.fullmatch(r'members\[\s*value\s+eq\s+"([^"]*)"\s*\]', path,
                           re.IGNORECASE)
        if verb == "remove" and one:
            members.discard(one.group(1))
            applied = True
        elif path.lower() == "members" or (not path and isinstance(value, list)):
            ids = _member_ids(value)
            if verb == "add":
                members.update(ids)
                applied = True
            elif verb == "remove":
                # Clear-all ONLY when no value is supplied (RFC 7644 §3.5.2.2).
                # A value that is PRESENT but yields no parseable ids (a single
                # dict, a display-only member, an empty list) must remove
                # nothing, not wipe the whole group — the alternative silently
                # revokes every member's group-derived access.
                if value is None:
                    members = set()
                else:
                    members -= set(ids)
                applied = True
            elif verb == "replace":
                members = set(ids)
                applied = True
        elif (verb in ("replace", "add")
              and path.lower() == "displayname"
              and isinstance(value, str) and value.strip()):
            rec["displayName"] = value.strip()
            applied = True
        elif (verb in ("replace", "add") and not path
              and isinstance(value, dict)
              and isinstance(value.get("displayName"), str)):
            rec["displayName"] = value["displayName"].strip()
            applied = True
    rec["members"] = sorted(members)
    return True if applied else None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _parse_attr_eq(flt: str, attr: str) -> str | None:
    """Parse ``<attr> eq "value"`` -> value (case-insensitive op). None if the
    filter isn't that exact, supported shape (the IdP existence probe)."""
    import re
    m = re.fullmatch(rf'\s*{re.escape(attr)}\s+eq\s+"([^"]*)"\s*', flt,
                     re.IGNORECASE)
    return m.group(1) if m else None


def _parse_username_eq(flt: str) -> str | None:
    """Parse ``userName eq "value"`` -> value. None for any other filter."""
    return _parse_attr_eq(flt, "userName")


def _apply_patch(rec: dict, body: dict) -> bool | None:
    """Apply a SCIM PatchOp in place. Supports the common Okta/Azure shape:
    replace ``active`` (and a few core scalars). Returns True on success, None if
    nothing applicable was found."""
    if _PATCH_SCHEMA not in (body.get("schemas") or []):
        return None
    ops = body.get("Operations") or body.get("operations") or []
    if not isinstance(ops, list):
        return None
    applied = False
    for op in ops:
        if not isinstance(op, dict):
            continue
        if str(op.get("op", "")).lower() not in ("replace", "add"):
            continue
        path = str(op.get("path") or "").strip()
        value = op.get("value")
        if path:
            applied = _patch_path(rec, path, value) or applied
        elif isinstance(value, dict):
            # No path: value is an attribute bag (Azure sends this form).
            for k, v in value.items():
                applied = _patch_path(rec, k, v) or applied
    return True if applied else None


def _patch_path(rec: dict, path: str, value: Any) -> bool:
    p = path.lower()
    if p == "active":
        rec["active"] = _coerce_active(value)
        return True
    if p == "displayname":
        rec["displayName"] = str(value or "").strip()
        return True
    if p == "username":
        rec["userName"] = str(value or "")
        return True
    return False


__all__ = ["ScimStoreError", "router", "scim_enabled"]
