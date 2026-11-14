"""Caller-bound HTTP session, subscription and task ownership contracts."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import OrderedDict
from dataclasses import dataclass

_SESSION_BINDING_KEY = secrets.token_bytes(32)
_MAX_RESOURCE_SESSIONS_PER_CALLER = 32


@dataclass(frozen=True)
class _MCPAuthorization:
    """Authenticated HTTP caller plus its non-bypassable tool ceiling.

    ``caller_identity`` is empty for the legacy shared bearer because that
    credential cannot distinguish individual callers.  When Agent Trust is
    enforced, the shared bearer is nevertheless admitted as the explicit
    surface principal ``mcp`` and carries that entry's capability.  A
    per-agent bearer always carries its own registry capability, even when the
    trust plane's default-deny admission switch is disengaged: authenticating
    *as* a scoped agent must never discard the scope attached to that token.
    """

    caller_identity: str
    trust_principal: str
    capability: object | None
    credential_kind: str
    credential_fingerprint: str


@dataclass
class _ResourceSession:
    """Resource-subscription state bound to one authenticated credential."""

    caller_scope: str
    subscriptions: set[str]


def _caller_scope(caller: _MCPAuthorization) -> str:
    """Opaque session scope for one authenticated principal + credential."""
    material = "\0".join((
        "mcp-caller-v1",
        caller.credential_kind,
        caller.trust_principal,
        caller.credential_fingerprint,
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _quota_scope(caller: _MCPAuthorization) -> str:
    """Stable per-principal quota scope, independent of token/session churn."""
    material = "\0".join((
        "mcp-quota-v1",
        caller.credential_kind,
        caller.trust_principal,
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _task_owner(sid: str, caller_scope: str) -> str:
    """Bind task ownership to both the unguessable session and its caller."""
    material = f"mcp-task-owner-v1\0{caller_scope}\0{sid}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _request_owner(sid: str | None, caller_scope: str) -> str:
    """Scope request ids to an initialized client, else to the credential.

    An initialized client's session id keeps two clients sharing one
    credential apart. A sessionless request falls back to the credential
    scope: the socket peer is not a client identity (a cancel may arrive on
    another TCP connection, and a reverse proxy multiplexes clients).
    """
    return _task_owner(sid or "<without-session>", caller_scope)


def _mint_session_id(caller_scope: str) -> str:
    """Mint a self-authenticating process-local session for this caller."""
    nonce = secrets.token_urlsafe(24)
    mac = hmac.new(
        _SESSION_BINDING_KEY,
        f"mcp-session-v1\0{caller_scope}\0{nonce}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{nonce}.{mac}"


def _supplied_session_id(
    request,
    caller_scope: str,
) -> str | None:
    """Return a valid caller-bound session without consulting any LRU state."""
    supplied = (
        request.headers.get("Mcp-Session-Id")
        or request.cookies.get("maverick_mcp_session")
    )
    if not supplied or len(supplied) > 128:
        return None
    try:
        nonce, presented_mac = supplied.rsplit(".", 1)
    except ValueError:
        return None
    if (
        not 20 <= len(nonce) <= 64
        or not all(char.isalnum() or char in "_-" for char in nonce)
        or len(presented_mac) != 64
        or not all(char in "0123456789abcdef" for char in presented_mac)
    ):
        return None
    expected_mac = hmac.new(
        _SESSION_BINDING_KEY,
        f"mcp-session-v1\0{caller_scope}\0{nonce}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return supplied if hmac.compare_digest(presented_mac, expected_mac) else None


def _resource_session_id(
    sid: str | None,
    resource_sessions: OrderedDict[str, _ResourceSession],
    caller_scope: str,
) -> str | None:
    """Return ``sid`` only when its evictable subscription state exists."""
    session = resource_sessions.get(sid) if sid else None
    if session is None or not hmac.compare_digest(
        session.caller_scope,
        caller_scope,
    ):
        return None
    resource_sessions.move_to_end(sid)
    return sid


def _session_plan(
    *,
    supplied_sid: str | None,
    resource_sid: str | None,
    caller_scope: str,
    method: str,
    is_task_request: bool,
) -> tuple[str | None, str | None, bool, str | None]:
    """Plan response, resource persistence, and task ownership independently."""
    response_sid = supplied_sid
    if response_sid is None and (
        is_task_request or method in {"initialize", "resources/subscribe"}
    ):
        response_sid = _mint_session_id(caller_scope)
    if method == "resources/subscribe" and resource_sid is None:
        resource_sid = response_sid
    should_persist_resource = resource_sid is not None
    task_owner = (
        _task_owner(response_sid, caller_scope)
        if is_task_request and response_sid is not None else None
    )
    return response_sid, resource_sid, should_persist_resource, task_owner


def _store_session(
    resource_sessions: OrderedDict[str, _ResourceSession],
    sid: str,
    caller_scope: str,
    subscriptions: set[str],
    *, max_sessions: int,
) -> None:
    existing = resource_sessions.get(sid)
    if existing is not None and not hmac.compare_digest(
        existing.caller_scope, caller_scope
    ):
        # A stolen/colliding id must never overwrite another caller's state.
        return
    resource_sessions[sid] = _ResourceSession(caller_scope, subscriptions)
    resource_sessions.move_to_end(sid)
    caller_sessions = [
        key for key, session in resource_sessions.items()
        if hmac.compare_digest(session.caller_scope, caller_scope)
    ]
    # Sessionless subscriptions must spend this caller's own LRU allowance.
    # Also reclaim its older entries when the shared store is full, preserving
    # the newly used session before considering another caller's oldest entry.
    excess = max(
        0,
        len(caller_sessions) - _MAX_RESOURCE_SESSIONS_PER_CALLER,
        len(resource_sessions) - max_sessions,
    )
    for key in caller_sessions[:min(excess, len(caller_sessions) - 1)]:
        del resource_sessions[key]
    while len(resource_sessions) > max_sessions:
        resource_sessions.popitem(last=False)
