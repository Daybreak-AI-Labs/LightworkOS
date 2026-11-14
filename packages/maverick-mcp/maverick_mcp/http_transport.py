"""Streamable HTTP transport for Lightwork's MCP server (spec 2025-11-25).

The stdio JSON-RPC transport in `server.py` works great for desktop
clients (Claude Desktop, Cursor) that spawn Lightwork as a subprocess.
For hosted Lightwork — VPS deployments, multi-tenant setups, MCP
gateways like Composio / MintMCP / Cloudflare — clients need an HTTP
endpoint.

This module ships a single POST endpoint that accepts JSON-RPC
requests. When the client sends ``Accept: text/event-stream``, the
response is a Server-Sent Events stream (MCP 2025-11-25 Streamable
HTTP): for a long-running request the server emits
``notifications/progress`` events while the work runs, then the final
JSON-RPC response, then closes. Without that Accept header it returns a
single blocking ``application/json`` response, exactly as before.

Server-initiated ``sampling`` (the server asking the client's LLM to
complete) is not supported: it needs a bidirectional channel.

Usage::

    MAVERICK_MCP_TOKEN=secret maverick mcp --http --port 8771

Security:
  - Every HTTP request needs a bearer token: the shared token
    (MAVERICK_MCP_TOKEN or ``[mcp] token``) or a per-caller
    ``[agent_trust] mcp_token``. With neither configured, every request
    is refused with 401.
  - Per the 2025-11-25 spec, server runs as an OAuth resource server;
    it checks a bearer token and does not implement the full OAuth flow.
  - All requests are routed through the same MCPServer.handle_*
    dispatch as stdio, so the security audit you do on the stdio
    side covers HTTP too.

Spec deprecation note: major clients are retiring the older SSE-only
transport; Streamable HTTP is the transport this server ships.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import threading
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from functools import partial
from urllib.parse import urlparse

from .http_sessions import (
    _SESSION_BINDING_KEY as _SESSION_BINDING_KEY,
)
from .http_sessions import (
    _caller_scope,
    _MCPAuthorization,
    _quota_scope,
    _request_owner,
    _resource_session_id,
    _ResourceSession,
    _session_plan,
    _supplied_session_id,
)
from .http_sessions import (
    _mint_session_id as _mint_session_id,
)
from .http_sessions import (
    _store_session as _store_session_impl,
)
from .http_sessions import (
    _task_owner as _task_owner,
)
from .protocol import METHOD_HANDLERS
from .settings import mcp_setting

log = logging.getLogger(__name__)

_MAX_PROGRESS_TOKEN_CHARS = 128
_DEFAULT_MAX_PROGRESS_EVENTS = 240
_DEFAULT_MAX_RESOURCE_SESSIONS = 1024
# Match TaskStore's maximum accepted TTL (7 days): a cookie-only MCP client
# must retain its caller-bound session for the entire lifetime of a valid task.
_SESSION_COOKIE_MAX_AGE = 7 * 24 * 60 * 60
_LOOPBACK_PEERS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


try:
    from fastapi import FastAPI, Header, HTTPException, Request, Response
    from fastapi.responses import JSONResponse, StreamingResponse
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False
    FastAPI = Header = HTTPException = Request = Response = None  # type: ignore
    JSONResponse = StreamingResponse = None  # type: ignore


# JSON-RPC requests are small control messages. Cap the body so an
# (authenticated) client can't force the server to buffer an arbitrarily
# large payload in memory before dispatch. Override via MAVERICK_MCP_MAX_BODY.
def _max_body_bytes() -> int:
    try:
        return max(1024, int(mcp_setting("max_body_bytes", str(2 * 1024 * 1024))))
    except ValueError:
        return 2 * 1024 * 1024


def _max_resource_sessions() -> int:
    try:
        configured = mcp_setting("max_resource_sessions", str(_DEFAULT_MAX_RESOURCE_SESSIONS))
        return max(1, int(configured))
    except ValueError:
        return _DEFAULT_MAX_RESOURCE_SESSIONS


async def _read_limited_json(request, http_exc):
    """Read + parse the JSON body with a hard size cap.

    Rejects oversized requests via Content-Length up front, then streams with
    the same cap so a chunked/lengthless request can't bypass it.
    """
    cap = _max_body_bytes()
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) > cap:
                raise http_exc(status_code=413, detail="request body too large")
        except ValueError:
            raise http_exc(status_code=400, detail="invalid Content-Length") from None
    buf = bytearray()
    async for chunk in request.stream():
        buf.extend(chunk)
        if len(buf) > cap:
            raise http_exc(status_code=413, detail="request body too large")
    try:
        return json.loads(buf or b"{}")
    except (ValueError, UnicodeDecodeError):
        raise http_exc(status_code=400, detail="body must be valid JSON") from None


def _normalized_origin(origin: str) -> str | None:
    """Return a canonical Origin value, or None when malformed/unsupported."""
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        return None
    try:
        parsed_port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed_port}" if parsed_port is not None else ""
    return f"{parsed.scheme}://{host}{port}"


def _origin_host_is_loopback(origin: str) -> bool:
    parsed = urlparse(origin)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _allowed_origins() -> set[str]:
    """Explicit Origin values allowed for browser requests.

    Comma-separated list in MAVERICK_MCP_ALLOWED_ORIGINS (e.g. a gateway's
    public origin). Localhost/loopback Origins are also allowed for local
    browser clients. The request Host header is intentionally not trusted:
    DNS rebinding makes Host attacker-controlled for this defense.
    """
    raw = mcp_setting("allowed_origins", "") or ""
    return {
        normalized
        for origin in raw.split(",")
        if (normalized := _normalized_origin(origin.strip()))
    }


def _is_origin_allowed(request) -> bool:
    """DNS-rebinding defense for the loopback HTTP transport.

    A browser page on any site can POST no-cors to http://127.0.0.1:8771,
    and DNS rebinding lets an attacker's hostname resolve to loopback. The
    bearer token is still the primary gate, but the Origin layer rejects
    browser requests unless they come from an explicit allowlist or from a
    literal localhost/loopback Origin.

    Requests with no Origin header (native MCP clients, curl, server-to-
    server) are allowed — like the dashboard, the Origin check only ever
    constrains browser-issued cross-origin requests; non-browser callers
    omit Origin and are gated by the bearer token instead.
    """
    origin = request.headers.get("origin")
    if not origin:
        return True
    normalized = _normalized_origin(origin)
    if not normalized:
        return False
    if _origin_host_is_loopback(normalized):
        return True
    return normalized in _allowed_origins()


def _is_loopback_request(request) -> bool:
    """True when the request's peer is loopback/in-process.

    Mirrors the dashboard: decides only the cookie ``Secure`` flag, so a
    real (non-loopback) deployment never sends the session cookie over
    plain HTTP, while loopback dev over http still works.
    """
    host = request.client.host if request.client else ""
    return host in _LOOPBACK_PEERS


def _http_tasks_enabled() -> bool:
    """Whether async MCP tasks are offered over the HTTP transport.

    Opt-in (default off): each HTTP caller gets an opaque MCP session id and
    task records are bound to that session, so tasks/list, tasks/get,
    tasks/result, and tasks/cancel only operate on the caller's own tasks.
    Set MAVERICK_MCP_HTTP_TASKS=1 to enable.
    """
    return (mcp_setting("http_tasks", "") or "").strip().lower() in (
        "1", "true", "yes", "on")


def _needs_policy_principal(method: str, is_task_request: bool) -> bool:
    return is_task_request or method in {
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/subscribe",
    }


def _task_request_flags(
    *,
    enabled: bool,
    method: str,
    params: dict,
) -> tuple[bool, bool]:
    is_create = (
        enabled
        and method == "tools/call"
        and isinstance(params.get("task"), dict)
    )
    is_request = enabled and (method.startswith("tasks/") or is_create)
    return is_request, is_create


# --- per-caller request rate limiting (sliding 60s window) -------------------
_RATE_LOCK = threading.Lock()
_RATE_HITS: dict[str, deque] = {}
# Cap the number of tracked callers so a long-running server facing many
# distinct IPs/tokens can't grow this map without bound. When exceeded, idle
# buckets (no hits inside the window) are swept; memory stays ~O(active callers).
_RATE_MAX_KEYS = 8192
_AUTH_FAILURE_LOCK = threading.Lock()
_AUTH_FAILURES: dict[str, deque] = {}
_AUTH_FAILURE_LIMIT = 30
# Fingerprints of bearers that already failed from a peer, most recent last.
# Once the peer's failure budget is spent, a repeat of one of these is refused
# before verification; a bearer never seen failing (the legitimate client that
# shares the peer address behind a proxy or NAT) is still verified, so an
# attacker's guesses can only lock out the attacker's own guesses.
_AUTH_FAILED_BEARERS: dict[str, deque] = {}
_AUTH_FAILED_BEARERS_PER_PEER = 64


def _authenticate_bearer(peer: str, authorization: str | None):
    """Resolve the caller for ``authorization`` from ``peer`` or raise.

    Per-peer failure accounting: once the peer's budget is spent, a bearer
    that already failed from it is refused before verification and every
    further failure is a 429; a bearer that has not failed is still verified,
    because one peer address is shared by every client behind a proxy or NAT.
    """
    fingerprint = _bearer_fingerprint(authorization)
    exhausted = not _auth_failure_budget(peer)
    if exhausted and _bearer_known_failed(peer, fingerprint):
        raise HTTPException(status_code=429, detail="authentication rate limit exceeded",
                            headers={"Retry-After": "60"})
    caller = _authorization_for_bearer(authorization)
    if caller is None:
        _auth_failure_budget(peer, failed=True)
        _remember_failed_bearer(peer, fingerprint)
        if exhausted:
            raise HTTPException(status_code=429, detail="authentication rate limit exceeded",
                                headers={"Retry-After": "60"})
        raise HTTPException(status_code=401, detail="invalid bearer")
    return caller


def _bearer_fingerprint(authorization: str | None) -> str:
    import hashlib

    return hashlib.sha256((authorization or "").encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _bearer_known_failed(host: str, fingerprint: str) -> bool:
    with _AUTH_FAILURE_LOCK:
        return fingerprint in _AUTH_FAILED_BEARERS.get(host, ())


def _remember_failed_bearer(host: str, fingerprint: str) -> None:
    with _AUTH_FAILURE_LOCK:
        seen = _AUTH_FAILED_BEARERS.get(host)
        if seen is None:
            if len(_AUTH_FAILED_BEARERS) >= _RATE_MAX_KEYS:
                # Keep only peers that still hold a live failure budget entry.
                for key in list(_AUTH_FAILED_BEARERS):
                    if key not in _AUTH_FAILURES:
                        del _AUTH_FAILED_BEARERS[key]
                if len(_AUTH_FAILED_BEARERS) >= _RATE_MAX_KEYS:
                    return
            seen = _AUTH_FAILED_BEARERS.setdefault(
                host, deque(maxlen=_AUTH_FAILED_BEARERS_PER_PEER))
        if fingerprint not in seen:
            seen.append(fingerprint)


def _auth_failure_budget(host: str, *, failed: bool = False) -> bool:
    """Bound failed bearer attempts independently of authenticated quotas."""
    now = time.monotonic()
    cutoff = now - 60.0
    with _AUTH_FAILURE_LOCK:
        events = _AUTH_FAILURES.get(host)
        if events is None:
            if len(_AUTH_FAILURES) >= _RATE_MAX_KEYS:
                for key, hits in list(_AUTH_FAILURES.items()):
                    if not hits or hits[-1] <= cutoff:
                        del _AUTH_FAILURES[key]
                if len(_AUTH_FAILURES) >= _RATE_MAX_KEYS:
                    return False
            if not failed:
                return True
            events = _AUTH_FAILURES.setdefault(host, deque())
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= _AUTH_FAILURE_LIMIT:
            return False
        if failed:
            events.append(now)
        return True


def _rate_limit_per_min() -> int:
    """Requests/minute allowed per caller. Default 600; 0 disables. An authed
    caller can otherwise spam goal-spawning RPCs with unbounded concurrency."""
    try:
        return max(0, int(mcp_setting("rate_limit", "600")))
    except ValueError:
        return 600


def _rate_key(authorization: str | None, request) -> str:
    """Bucket by bearer token (hashed) when present, else by client IP."""
    if authorization and authorization.startswith("Bearer "):
        tok = authorization[len("Bearer "):].strip()
        return "tok:" + hashlib.sha256(tok.encode("utf-8")).hexdigest()[:16]
    host = getattr(getattr(request, "client", None), "host", None) or "?"
    return "ip:" + str(host)


def _rate_ok(key: str) -> bool:
    """True if ``key`` is under its per-minute budget (and records the hit)."""
    limit = _rate_limit_per_min()
    if limit <= 0:
        return True
    now = time.monotonic()
    with _RATE_LOCK:
        cutoff = now - 60.0
        dq = _RATE_HITS.setdefault(key, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        # Sweep idle buckets when the map grows large, so stale callers don't
        # leak. Keep the current key even if momentarily empty.
        if len(_RATE_HITS) > _RATE_MAX_KEYS:
            for k in [k for k, d in _RATE_HITS.items()
                      if k != key and (not d or d[-1] < cutoff)]:
                del _RATE_HITS[k]
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def _authorization_for_bearer(
    authorization: str | None,
) -> _MCPAuthorization | None:
    """Authenticate one network caller and resolve its tool authority.

    Returns an authorization context, or ``None`` on any authentication,
    admission, or trust-policy failure.  The context keeps both identity and
    capability intact through HTTP dispatch; reducing it to the old identity
    string is the authorization bypass this boundary is designed to prevent.

    Unlike stdio, HTTP requests are network-reachable; token auth is
    therefore mandatory. Two accepted credentials: the shared
    ``MAVERICK_MCP_TOKEN`` and a per-caller ``[agent_trust] mcp_token`` (real
    per-caller identity). On top of authentication, when the Agent Trust Plane
    is engaged the caller must be a permitted inbound agent — a per-caller token
    gates on its own entry, a shared-token caller on the surface-wide ``"mcp"``
    entry — so engaging the plane default-denies MCP instead of leaving it open
    on the shared bearer. No-op (auth only) when disengaged.
    """
    expected = mcp_setting("token")
    given = ""
    if authorization and authorization.startswith("Bearer "):
        given = authorization[len("Bearer "):].strip()
    if not given:
        return None
    try:
        from maverick import agent_trust

        # One snapshot for token resolution, admission, and capability.  A
        # second config read here would create a TOCTOU window where identity
        # came from one registry revision and authority from another.
        enforced, registry = agent_trust.load_trust_state()
        agent = agent_trust.agent_for_token(given, "mcp", registry=registry)
    except Exception as e:  # fail closed at a network tool-execution boundary
        log.error("MCP trust plane unavailable; refusing inbound caller: %s", e)
        return None

    shared = bool(
        expected and hmac.compare_digest(expected.encode(), given.encode())
    )
    if agent is None and not shared:
        return None

    principal = agent.id if agent is not None else "mcp"
    decision = agent_trust.decide_inbound(
        principal,
        registry=registry,
        enforced=enforced,
    )
    if decision.denied:
        agent_trust.record_denied(principal, decision, direction="inbound")
        return None

    # A keyed, process-local digest can be retained for session ownership and
    # queued-task rotation checks without retaining/logging a reusable bearer.
    from .authorization import credential_fingerprint
    fingerprint = credential_fingerprint(given)

    if agent is not None:
        # Per-agent authentication is itself an explicit scoped credential.
        # Keep that scope even when default-deny admission is disengaged (in
        # which case decide_inbound deliberately returns capability=None).
        capability = decision.capability or agent.capability()
        return _MCPAuthorization(
            caller_identity=agent.id,
            trust_principal=agent.id,
            capability=capability,
            credential_kind="agent",
            credential_fingerprint=fingerprint,
        )

    # Shared bearer compatibility is explicit: unrestricted only while the
    # trust plane is disengaged; when enforced, the required ``mcp`` registry
    # entry supplies the capability that tools/list and tools/call must honor.
    return _MCPAuthorization(
        caller_identity="",
        trust_principal="mcp",
        capability=decision.capability,
        credential_kind="shared",
        credential_fingerprint=fingerprint,
    )


def _check_bearer(authorization: str | None) -> tuple[bool, str]:
    """Back-compatible authentication probe returning ``(ok, identity)``.

    HTTP request handling uses :func:`_authorization_for_bearer` so the
    capability is not discarded.  This wrapper remains for callers/tests that
    only need the historical authentication result.
    """
    caller = _authorization_for_bearer(authorization)
    if caller is None:
        return False, ""
    return True, caller.caller_identity


def _result_envelope(request_id, result: dict) -> dict:
    from .protocol import result_envelope

    return result_envelope(request_id, result)


def _error_envelope(request_id, exc: Exception) -> dict:
    from .execution import ExecutionCancelled, RequestAdmissionError
    from .protocol import ProtocolError as _ProtocolError
    from .tasks import TaskError
    # Both _ProtocolError and TaskError carry an explicit JSON-RPC (code,
    # message); preserve them so a task error (e.g. -32602 task not found)
    # reaches the HTTP client with the same wire code the stdio path produces.
    if isinstance(exc, (_ProtocolError, TaskError)):
        code, message = exc.code, exc.message
    elif isinstance(exc, ExecutionCancelled):
        code, message = -32800, "request cancelled; prior effects may be unknown"
    elif isinstance(exc, RequestAdmissionError):
        code, message = -32602, str(exc)
    else:
        # Scrub the message before it reaches the HTTP client: a raw exception's
        # args can carry secrets (DSNs, tokens, credentialed URLs). The stdio
        # dispatch path (server._dispatch) already scrubs the same class of
        # error; mirror it so both transports withhold the same internal detail.
        try:
            from maverick.secrets import scrub
            detail = scrub(f"{type(exc).__name__}: {exc}")
        except Exception:  # pragma: no cover - scrub must never mask the error
            detail = type(exc).__name__
        code, message = -32603, f"internal error: {detail}"
    from .protocol import error_envelope

    return error_envelope(request_id, code, message)


def _sse(obj: dict) -> str:
    """Format a JSON-RPC message as one SSE event."""
    return f"data: {json.dumps(obj)}\n\n"


def _heartbeat_seconds() -> float:
    """Progress-heartbeat cadence for SSE streams. Override via
    MAVERICK_MCP_SSE_HEARTBEAT (seconds)."""
    try:
        return max(0.01, float(mcp_setting("sse_heartbeat", "15")))
    except ValueError:
        return 15.0


def _max_progress_events() -> int:
    """Maximum number of progress events sent on one SSE response."""
    try:
        return max(0, int(mcp_setting("sse_max_progress_events",
                                      str(_DEFAULT_MAX_PROGRESS_EVENTS))))
    except ValueError:
        return _DEFAULT_MAX_PROGRESS_EVENTS


def _progress_token(params: dict, http_exc):
    """Return a bounded MCP progressToken or reject unsafe values.

    Progress tokens are echoed in every progress notification, so keep them
    scalar and small enough that heartbeats cannot amplify large request data.
    """
    meta = params.get("_meta") or {}
    if not isinstance(meta, dict):
        raise http_exc(status_code=400, detail="params._meta must be a JSON object")
    token = meta.get("progressToken")
    if token is None:
        return None
    if isinstance(token, bool) or not isinstance(token, (str, int, float)):
        raise http_exc(
            status_code=400,
            detail="params._meta.progressToken must be a string or number",
        )
    if len(str(token)) > _MAX_PROGRESS_TOKEN_CHARS:
        raise http_exc(
            status_code=400,
            detail=(
                "params._meta.progressToken must be "
                f"{_MAX_PROGRESS_TOKEN_CHARS} characters or fewer"
            ),
        )
    return token


def _sse_stream(
    *,
    server,
    method: str,
    params: dict,
    task_owner: str | None,
    task_quota_owner: str | None = None,
    caller_identity: str | None = None,
    caller_capability=None,
    subscriptions: set,
    request_id,
    should_persist_session: bool,
    sid: str | None,
    store_session,
    caller_trust_principal: str | None = None,
    caller_credential_kind: str | None = None,
    caller_credential_fingerprint: str | None = None,
    execution_owner: str = "stdio",
    execution_quota_owner: str | None = None,
):
    """Async SSE generator: progress heartbeats, then the final JSON-RPC result.

    Factored out of ``mcp_endpoint`` so the streaming branch's control flow does
    not inflate the endpoint's complexity. Behavior is identical.
    """
    progress_token = _progress_token(params, HTTPException)
    max_progress_events = _max_progress_events()

    async def _dispatch_with_updates():
        with server.resource_update_scope(subscriptions):
            kwargs = {
                "task_owner": task_owner,
                "caller_identity": caller_identity,
            }
            if task_quota_owner is not None:
                kwargs["task_quota_owner"] = task_quota_owner
            if caller_capability is not None:
                kwargs["caller_capability"] = caller_capability
            if caller_trust_principal is not None:
                kwargs.update({
                    "caller_trust_principal": caller_trust_principal,
                    "caller_credential_kind": caller_credential_kind,
                    "caller_credential_fingerprint": caller_credential_fingerprint,
                })
            result = await _dispatch_async(server, method, params, execution_owner=execution_owner, request_id=request_id, execution_quota_owner=execution_quota_owner, **kwargs)
            updates = server.drain_resource_updates()
            return result, updates

    async def _stream():
        task = asyncio.create_task(_dispatch_with_updates())
        interval = _heartbeat_seconds()
        progress = 0
        try:
            while not task.done():
                done, _pending = await asyncio.wait({task}, timeout=interval)
                if task in done:
                    break
                if progress_token is not None and progress < max_progress_events:
                    progress += 1
                    yield _sse({
                        "jsonrpc": "2.0", "method": "notifications/progress",
                        "params": {"progressToken": progress_token, "progress": progress, "message": "working"},
                    })
            try:
                result, updates = task.result()
            except Exception as e:
                yield _sse(_error_envelope(request_id, e))
            else:
                if should_persist_session and sid is not None:
                    store_session(sid, subscriptions)
                yield _sse(_result_envelope(request_id, result))
                for uri in updates:
                    yield _sse({
                        "jsonrpc": "2.0", "method": "notifications/resources/updated",
                        "params": {"uri": uri},
                    })
        finally:
            # Cancels the owning async wrapper, which requests cooperative stop
            # but retains the real worker slot until it exits. Detached MCP
            # tasks have their own handles and survive this connection closing.
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    return _stream()


def _store_session(resource_sessions, sid, caller_scope, subscriptions) -> None:
    _store_session_impl(
        resource_sessions, sid, caller_scope, subscriptions,
        max_sessions=_max_resource_sessions(),
    )


def _attach_session(response, sid: str | None, request):
    if sid is None:
        return response
    response.headers["Mcp-Session-Id"] = sid
    response.set_cookie(
        "maverick_mcp_session",
        sid,
        max_age=_SESSION_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=not _is_loopback_request(request),
    )
    return response


@asynccontextmanager
async def _app_lifespan(server, _app):
    try:
        yield
    finally:
        server.shutdown()


def build_app(server) -> FastAPI:
    """Wrap an MCPServer instance in a Streamable HTTP transport.

    `server` is an instance of `maverick_mcp.server.MCPServer`. We
    reuse its handle_* methods 1:1; this module is just the transport.
    """
    if not _HAVE_FASTAPI:
        raise ImportError(
            "fastapi not installed; install maverick-mcp-server[http] to enable "
            "the streamable HTTP transport"
        )

    app = FastAPI(
        title="Lightwork MCP HTTP",
        description=(
            "MCP 2025-11-25 streamable HTTP transport. POST a JSON-RPC "
            "request; receive a JSON-RPC response or an SSE stream."
        ),
        version="0.2.0",
        lifespan=partial(_app_lifespan, server),
    )

    from maverick import a2a
    a2a.mount(app)

    # Offer async tasks over HTTP when opted in (MAVERICK_MCP_HTTP_TASKS). The
    # store lives on this server instance, so task records are bound to the
    # caller's opaque MCP session id before the client polls
    # tasks/get|result|cancel|list on later POSTs. Off by default -> task field
    # ignored and tasks/* return -32601, exactly as before.
    server._tasks_enabled = _http_tasks_enabled()

    # One MCPServer handles the whole HTTP app, but state is per authenticated
    # MCP client. Caller-bound signed session ids authorize task ownership
    # without depending on this map; only resource subscriptions live in the
    # capped LRU below. Evicting an idle subscription therefore cannot orphan a
    # still-valid task, while ignored resource ids cannot grow memory forever.
    resource_sessions: OrderedDict[str, _ResourceSession] = OrderedDict()
    app.state.resource_sessions = resource_sessions

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        authorization: str | None = Header(None),
    ):
        if not _is_origin_allowed(request):
            raise HTTPException(
                status_code=403,
                detail="cross-origin request blocked (set MAVERICK_MCP_ALLOWED_ORIGINS to allow)",
            )
        # Use the connection peer, never an untrusted forwarded header; see
        # _authenticate_bearer for the per-peer failure budget.
        peer = str(getattr(getattr(request, "client", None), "host", None) or "unknown")
        caller = _authenticate_bearer(peer, authorization)
        caller_identity = caller.caller_identity
        caller_scope = _caller_scope(caller)
        quota_scope = _quota_scope(caller)
        # Per-caller rate limit (after auth so unauthenticated probes can't
        # exhaust a victim's budget). Returns 429 over the per-minute cap.
        if not _rate_ok(_rate_key(authorization, request)):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        # Opt-in, consent-gated client-language analytics (off by default; no-op
        # and never raises when disabled). Feeds the language-bindings decision.
        try:
            from maverick.mcp_analytics import record_client
            record_client(request.headers.get("user-agent"))
        except Exception:  # pragma: no cover -- analytics never blocks a request
            pass
        # Bounded read (size cap) + parse; rejects oversized / malformed /
        # non-object bodies with a clean error instead of a 500.
        body = await _read_limited_json(request, HTTPException)
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object")
        # Match the stdio transport: a JSON-RPC notification is a message with
        # NO id key. An explicit `"id": null` is a request still owed a reply,
        # so it must NOT be treated as a notification.
        is_notification = "id" not in body
        request_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params", {}) or {}
        if not isinstance(params, dict):
            raise HTTPException(status_code=400, detail="params must be a JSON object")
        accepts_sse = "text/event-stream" in (request.headers.get("accept") or "")
        supplied_sid = _supplied_session_id(request, caller_scope)
        resource_sid = _resource_session_id(
            supplied_sid,
            resource_sessions,
            caller_scope,
        )
        subscriptions = (
            resource_sessions[resource_sid].subscriptions
            if resource_sid is not None else set()
        )
        is_task_request, is_task_create = _task_request_flags(
            enabled=server._tasks_enabled,
            method=method,
            params=params,
        )
        needs_policy_principal = _needs_policy_principal(method, is_task_request)
        # Task ownership is validated by a self-authenticating session and is
        # intentionally independent of the evictable resource-subscription
        # LRU. Resource subscriptions reuse that session when available but do
        # not become the authority for later tasks/get|result|cancel|list.
        (
            response_sid,
            resource_sid,
            should_persist_session,
            task_owner,
        ) = _session_plan(
            supplied_sid=supplied_sid,
            resource_sid=resource_sid,
            caller_scope=caller_scope,
            method=method,
            is_task_request=is_task_request,
        )
        execution_owner = _request_owner(request, response_sid, caller_scope)

        # Streamable HTTP: when the client accepts SSE and this is a real
        # request (not a fire-and-forget notification), stream progress
        # while the work runs, then the final JSON-RPC response. Dispatch
        # always goes to a worker thread -- the swarm tools call
        # run_goal_sync() -> asyncio.run, which can't run inline under
        # FastAPI's loop.
        if accepts_sse and not is_notification:
            # Streamable HTTP path: progress events while the work runs, then
            # the final JSON-RPC response, on one SSE stream.
            stream = _sse_stream(
                server=server,
                method=method,
                params=params,
                task_owner=task_owner,
                task_quota_owner=(quota_scope if is_task_create else None),
                caller_identity=caller_identity,
                caller_capability=caller.capability,
                subscriptions=subscriptions,
                request_id=request_id,
                should_persist_session=should_persist_session,
                sid=resource_sid,
                store_session=lambda s, subs: _store_session(
                    resource_sessions, s, caller_scope, subs
                ),
                caller_trust_principal=(
                    caller.trust_principal if needs_policy_principal else None
                ),
                caller_credential_kind=(
                    caller.credential_kind if needs_policy_principal else None
                ),
                caller_credential_fingerprint=(
                    caller.credential_fingerprint if needs_policy_principal else None
                ),
                execution_owner=execution_owner,
                execution_quota_owner=quota_scope,
            )
            response = StreamingResponse(stream, media_type="text/event-stream")
            return _attach_session(response, response_sid, request)

        # Blocking JSON path (default). Dispatch runs in a worker thread
        # for the same asyncio.run reason as above.
        async def _dispatch_for_session():
            with server.resource_update_scope(subscriptions):
                kwargs = {
                    "task_owner": task_owner,
                    "caller_identity": caller_identity,
                }
                if caller.capability is not None:
                    kwargs["caller_capability"] = caller.capability
                if needs_policy_principal:
                    kwargs.update({
                        "caller_trust_principal": caller.trust_principal,
                        "caller_credential_kind": caller.credential_kind,
                        "caller_credential_fingerprint": caller.credential_fingerprint,
                    })
                if is_task_create:
                    kwargs.update({
                        "task_quota_owner": quota_scope,
                    })
                return await _dispatch_async(server, method, params, execution_owner=execution_owner, request_id=request_id, execution_quota_owner=quota_scope, **kwargs)

        try:
            result = await _wait_json_dispatch(request, _dispatch_for_session())
        except Exception as e:
            if is_notification:
                # 204 must carry no body; JSONResponse({}) writes "{}" which
                # strict proxies (e.g. Cloudflare) reject as a protocol violation.
                return _attach_session(
                    Response(status_code=204),
                    response_sid,
                    request,
                )
            return _attach_session(
                JSONResponse(_error_envelope(request_id, e)),
                response_sid,
                request,
            )

        if should_persist_session and resource_sid is not None:
            _store_session(
                resource_sessions,
                resource_sid,
                caller_scope,
                subscriptions,
            )

        if is_notification:
            # 204 must carry no body (see above).
            return _attach_session(Response(status_code=204), response_sid, request)
        return _attach_session(
            JSONResponse(_result_envelope(request_id, result)),
            response_sid,
            request,
        )

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "transport": "http"}

    return app


async def _wait_json_dispatch(request, coroutine):
    """Observe disconnect after body consumption; retain underlying ownership."""
    work = asyncio.create_task(coroutine)

    async def disconnected():
        while True:
            message = await request.receive()
            if message["type"] == "http.disconnect":
                return
            await asyncio.sleep(0)

    closed = asyncio.create_task(disconnected())
    try:
        done, _ = await asyncio.wait({work, closed}, return_when=asyncio.FIRST_COMPLETED)
        if closed in done and not work.done():
            work.cancel()
            raise asyncio.CancelledError
        return await work
    finally:
        closed.cancel()
        if not work.done():
            work.cancel()
        await asyncio.gather(work, closed, return_exceptions=True)


def _dispatch_owned(server, method, params, kwargs):
    if kwargs.get("caller_credential_kind") is not None:
        context = server._task_execution_context(
            caller_identity=kwargs.get("caller_identity"),
            trust_principal=kwargs.get("caller_trust_principal"),
            credential_kind=kwargs.get("caller_credential_kind"),
            credential_fingerprint=kwargs.get("caller_credential_fingerprint"),
            capability=kwargs.get("caller_capability"),
        )
        kwargs = dict(kwargs, caller_capability=server._refresh_task_capability(context))
    return _dispatch(server, method, params, **kwargs)


async def _dispatch_async(server, method, params, *, execution_owner, request_id, execution_quota_owner=None, **kwargs):
    """Wait without reserving a thread; isolate effectful request workers."""
    if method == "notifications/cancelled":
        server._requests.cancel(execution_owner, params.get("requestId"))
        return {}
    if method == "tasks/result":
        from maverick.fleet_memory import bind_caller

        result_kwargs = {"task_owner": kwargs.get("task_owner")}
        if kwargs.get("caller_capability") is not None or kwargs.get("caller_trust_principal") is not None:
            result_kwargs.update({
                "caller_identity": kwargs.get("caller_identity"),
                "caller_trust_principal": kwargs.get("caller_trust_principal"),
                "caller_credential_kind": kwargs.get("caller_credential_kind"),
                "caller_credential_fingerprint": kwargs.get("caller_credential_fingerprint"),
                "capability": kwargs.get("caller_capability"),
            })

        async def result():
            with bind_caller(kwargs.get("caller_identity")):
                return await server.handle_tasks_result_async(params, **result_kwargs)

        return await server._requests.run_async(execution_owner, request_id, result, quota_owner=execution_quota_owner)
    if method == "tools/call":
        return await server._requests.run(execution_owner, request_id, lambda: _dispatch_owned(server, method, params, kwargs), quota_owner=execution_quota_owner)
    # Control requests never queue behind the bounded tool workers or a result
    # waiter. Their short synchronous authority checks retain the existing path.
    return await asyncio.to_thread(_dispatch, server, method, params, **kwargs)


_METHOD_MAP = dict(METHOD_HANDLERS)


def _dispatch(
    server,
    method: str,
    params: dict,
    *,
    task_owner: str | None = None,
    task_quota_owner: str | None = None,
    caller_identity: str | None = None,
    caller_capability=None,
    caller_trust_principal: str | None = None,
    caller_credential_kind: str | None = None,
    caller_credential_fingerprint: str | None = None,
) -> dict:
    """Route a JSON-RPC method to the corresponding handle_* method.

    ``caller_identity`` (the authenticated per-caller agent id, ``""`` for the
    shared bearer) is bound for the duration of the handler so fleet-memory
    tools cannot act AS another rostered agent. Bound here -- inside the worker
    thread both dispatch paths funnel through -- so it cannot leak across
    concurrent requests (the ContextVar is set in this thread's context copy).
    """
    if method == "notifications/initialized":
        return {}
    if method == "ping":
        return {}
    handler_name = _METHOD_MAP.get(method)
    if not handler_name:
        from .protocol import ProtocolError as _ProtocolError
        raise _ProtocolError(-32601, f"method not found: {method}")
    handler = getattr(server, handler_name)
    from maverick.fleet_memory import bind_caller
    with bind_caller(caller_identity):
        if method == "tools/call":
            if caller_capability is None and caller_trust_principal is None:
                return handler(params, task_owner=task_owner)
            return handler(
                params,
                task_owner=task_owner,
                task_quota_owner=task_quota_owner,
                caller_identity=caller_identity,
                caller_trust_principal=caller_trust_principal,
                caller_credential_kind=caller_credential_kind,
                caller_credential_fingerprint=caller_credential_fingerprint,
                capability=caller_capability,
            )
        if method == "tools/list":
            if caller_capability is None and caller_trust_principal is None:
                return handler(params)
            return handler(
                params,
                caller_trust_principal=caller_trust_principal,
                capability=caller_capability,
            )
        if method in {
            "resources/list",
            "resources/read",
            "resources/subscribe",
        }:
            if caller_capability is None:
                if caller_trust_principal is None:
                    return handler(params)
                if method == "resources/list":
                    return handler(
                        params,
                        caller_trust_principal=caller_trust_principal,
                    )
                return handler(
                    params,
                    caller_identity=caller_identity,
                    caller_trust_principal=caller_trust_principal,
                )
            if method == "resources/list":
                return handler(
                    params,
                    caller_trust_principal=caller_trust_principal,
                    capability=caller_capability,
                )
            return handler(
                params,
                caller_identity=caller_identity,
                caller_trust_principal=caller_trust_principal,
                capability=caller_capability,
            )
        if method.startswith("tasks/"):
            if caller_capability is None and caller_trust_principal is None:
                return handler(params, task_owner=task_owner)
            kwargs = {
                "task_owner": task_owner,
                "caller_identity": caller_identity,
                "caller_trust_principal": caller_trust_principal,
                "capability": caller_capability,
            }
            if method == "tasks/result":
                kwargs.update({
                    "caller_credential_kind": caller_credential_kind,
                    "caller_credential_fingerprint": caller_credential_fingerprint,
                })
            return handler(
                params,
                **kwargs,
            )
        return handler(params)


def serve(host: str = "127.0.0.1", port: int = 8771) -> None:
    """Run the HTTP transport on host:port. Blocking."""
    from maverick.deployment import require_enterprise_or_die

    from .server import MCPServer

    require_enterprise_or_die()
    # build_app() raises a friendly "install maverick-mcp-server[http]" error
    # if fastapi is missing -- do it BEFORE importing uvicorn so the user
    # sees that hint, not a bare ModuleNotFoundError on uvicorn.
    server = MCPServer()
    app = build_app(server)
    try:
        import uvicorn
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "uvicorn not installed; install maverick-mcp-server[http] to enable "
            "the streamable HTTP transport"
        ) from e
    log.info("MCP Streamable HTTP transport on http://%s:%d/mcp", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info", proxy_headers=False)
