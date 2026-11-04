"""Self-authenticating integrations for agents, sensors, and vendor invitees.

Agents that run on OTHER platforms (Agentforce, Bedrock, Copilot Studio,
LangChain, custom runtimes) call these routes to be governed and accounted by
Lightwork while doing their work elsewhere:

* ``POST /api/v1/external/screen``     — ask before acting (trust ceilings,
  budget cutoff, Shield input scan, approval floor).
* ``POST /api/v1/external/runs``       — report a completed run; it lands as
  a first-class Operating Record goal owned by ``agent:<id>``.
* ``GET  /api/v1/external/approvals/{id}`` — poll a parked high-risk action.
* ``GET  /api/v1/external/openapi.json``  — the importable description of the
  agent routes (drops into Agentforce External Services / Bedrock action
  groups as-is).
* ``POST /api/v1/external/discovery/observations`` — admit a bounded,
  tenant-scoped observation from a registered Ed25519 discovery sensor.
* ``GET/POST /api/v1/external/ai-vendor/...`` — issue a questionnaire to an
  invited vendor and accept one complete, explicitly attested response.

Each route authenticates with a credential scoped to its integration family:
an external-agent trust entry, a registered signed discovery-sensor identity,
or a one-time vendor-portal invitation — NOT the dashboard session/bearer. The
``/api/v1/external/`` prefix is
therefore registered as self-authenticating (see ``auth.py`` and the
dashboard-token middleware in ``app.py``), same pattern as ``/a2a/v1`` and
the HMAC webhooks: an external platform has no dashboard credential, and
pressuring operators to share one across two trust domains would be worse.
Each route family self-gates on its own configuration, so including the router
unconditionally is inert.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
from collections import deque
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import model_risk_schemas as schemas

log = logging.getLogger("maverick.dashboard.external_gateway")

router = APIRouter(prefix="/api/v1/external", tags=["external-agents"])

# Per-caller request throttles (window: 60s). Budgets gate dollars; these
# gate volume, so a misbehaving or looping agent cannot hammer the gateway.
# Keyed by verified agent id — except the unauthenticated schema route,
# which keys by client address.
_RATE_LIMITS = {"screen": 120, "runs": 60, "approvals": 120, "openapi": 30,
                "heartbeat": 240, "memory": 60, "execute": 30,
                "executions": 120, "red_team": 120, "runtime": 120,
                "discovery_sensor": 240, "vendor_portal": 60}
_RATE_BUCKET_CAP = 10_000
_MAX_RED_TEAM_HTTP_BODY_BYTES = 2 * 1024 * 1024
_MAX_RUNTIME_HTTP_BODY_BYTES = 512 * 1024
_MAX_DISCOVERY_SENSOR_HTTP_BODY_BYTES = 64 * 1024
_MAX_VENDOR_PORTAL_HTTP_BODY_BYTES = 128 * 1024
_rate_times: dict[tuple[str, str], deque[float]] = {}
_rate_lock = threading.Lock()


def _rate_limit(key: str, action: str) -> None:
    now = time.monotonic()
    limit = _RATE_LIMITS[action]
    bucket = (action, key)
    with _rate_lock:
        if bucket not in _rate_times and len(_rate_times) >= _RATE_BUCKET_CAP:
            for candidate, window in tuple(_rate_times.items()):
                while window and now - window[0] >= 60:
                    window.popleft()
                if not window:
                    _rate_times.pop(candidate, None)
            if len(_rate_times) >= _RATE_BUCKET_CAP:
                raise HTTPException(
                    status_code=429,
                    detail="gateway rate-limit capacity reached",
                    headers={"Retry-After": "60"})
        window = _rate_times.setdefault(bucket, deque())
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"rate limit reached for {action} "
                       f"({limit}/minute); slow down and retry",
                headers={"Retry-After": "60"})
        window.append(now)


class ExternalRunIn(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    outcome: str = Field(max_length=20)
    summary: str = Field(default="", max_length=4000)
    steps: list[str] = Field(default_factory=list, max_length=50)
    cost_dollars: float = Field(default=0.0, ge=0, le=1_000_000)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0)
    department: str = Field(default="", max_length=100)
    # Send a stable key per logical run and retries become exactly-once:
    # a replay returns the original goal instead of double-counting.
    idempotency_key: str = Field(default="", max_length=128)


class ExternalScreenIn(BaseModel):
    tool: str = Field(min_length=1, max_length=128)
    detail: str = Field(default="", max_length=4000)
    risk: str = Field(default="", max_length=10)


class ExternalMemoryIngestIn(BaseModel):
    kind: str = Field(pattern="^(success|failure|lesson)$")
    goal_text: str = Field(min_length=1, max_length=2000)
    reflection: str = Field(default="", max_length=2000)
    tools_used: list[str] = Field(default_factory=list, max_length=16)
    domain: str = Field(default="", max_length=100)


class ExternalMemoryRecallIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    domain: str = Field(default="", max_length=100)


class ExternalRunStartIn(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    summary: str = Field(default="", max_length=4000)
    department: str = Field(default="", max_length=100)


class ExternalRunFinishIn(BaseModel):
    outcome: str = Field(max_length=20)
    summary: str = Field(default="", max_length=4000)
    steps: list[str] = Field(default_factory=list, max_length=50)
    cost_dollars: float = Field(default=0.0, ge=0, le=1_000_000)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0)
    idempotency_key: str = Field(default="", max_length=128)


# Deliberately permissive: the core adjudicates connector/op/path/body and
# answers with typed verdict rules (connector_not_enabled, bad_op, bad_path,
# bad_body, body_too_large...); pre-rejecting here would replace those
# readable verdicts with a 422. Only basic JSON types are enforced.
class ExternalExecuteIn(BaseModel):
    connector: str
    op: str
    path: str
    body: dict | None = None
    preview: bool = False
    detail: str = ""
    goal_id: int | None = None
    # A write park is itself durable state (an approval plus execution slot).
    # Supplying a stable key lets a caller recover an ambiguous HTTP response
    # without creating a second approval for the same logical request.
    idempotency_key: str = Field(
        default="",
        max_length=128,
        pattern=r"^(?:[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127})?$",
    )
    # When the runtime plane is on, the enforced connector path requires this
    # exact current Model Risk binding. Legacy deployments (plane off) remain
    # byte-for-byte compatible.
    runtime_asset_id: str | None = Field(
        None,
        pattern=r"^MAA-[0-9a-f]{32}$",
    )
    runtime_asset_revision: int | None = Field(None, ge=1)
    runtime_asset_version_digest: str | None = Field(
        None,
        pattern=r"^(?:sha256:)?[0-9a-f]{64}$",
    )


class ExternalExecuteCommitIn(BaseModel):
    connector: str
    op: str
    path: str
    body: dict | None = None
    detail: str = ""
    goal_id: int | None = None
    runtime_asset_id: str | None = Field(
        None,
        pattern=r"^MAA-[0-9a-f]{32}$",
    )
    runtime_asset_revision: int | None = Field(None, ge=1)
    runtime_asset_version_digest: str | None = Field(
        None,
        pattern=r"^(?:sha256:)?[0-9a-f]{64}$",
    )


class ExternalRedTeamResultIn(BaseModel):
    """Transient target output; core persists commitments, never this text."""

    case_id: str = Field(min_length=1, max_length=64)
    target_artifact_sha256: str = Field(pattern=r"^(?:sha256:)?[0-9a-f]{64}$")
    runner_instance_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
    )
    lease_token: str = Field(pattern=r"^rtl1\.[0-9a-f]{64}$")
    response: str = ""
    tool_calls: list[str | dict] = Field(default_factory=list, max_length=64)
    tool_trace_status: str = Field(
        default="unavailable",
        pattern="^(complete|unavailable)$",
    )
    transport_status: str = Field(
        default="completed",
        pattern="^(completed|timeout|error|cancelled)$",
    )


class ExternalDiscoveryObservationIn(BaseModel):
    """Closed machine-sensor payload; the signed body selects its tenant."""

    model_config = ConfigDict(extra="forbid")

    tenant_ref: str = Field(min_length=1, max_length=256)
    sensor_revision: int = Field(ge=1)
    config_sha256: str = Field(pattern=r"^(?:sha256:)?[0-9a-fA-F]{64}$")
    event_sha256: str = Field(pattern=r"^(?:sha256:)?[0-9a-fA-F]{64}$")
    observed_at: float = Field(gt=0)
    ai_service_code: str = Field(min_length=1, max_length=64)
    ai_product_code: str = Field(min_length=1, max_length=64)
    provider_code: str = Field(min_length=1, max_length=64)
    domain_category: str = Field(min_length=1, max_length=64)
    deployment_type: str = Field(min_length=1, max_length=64)
    environment_code: str = Field(min_length=1, max_length=64)
    context_codes: list[str] = Field(default_factory=list, max_length=16)


class ExternalVendorPortalSubmissionIn(BaseModel):
    """Closed vendor-attestation request; all answers are revalidated in core."""

    model_config = ConfigDict(extra="forbid", strict=True)

    answers: dict[str, object] = Field(min_length=1, max_length=32)
    respondent_ref: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9_.:-]{0,127}$",
    )
    attested: bool
    idempotency_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
    )


def _gate() -> None:
    """Self-gate: 404 while the plane is off (the route doesn't exist for
    this deployment)."""
    from maverick import external_agents as xa
    if not xa.enabled():
        raise HTTPException(status_code=404, detail="not found")


def _looks_like_jwt(token: str) -> bool:
    """Route an Authorization bearer: exactly three dot-separated segments
    whose first decodes to a JSON object is a JWT for the platform-identity
    verifier; everything else stays on the minted-bearer path. Minted tokens
    (``lw-rest-<urlsafe>``) can never contain a dot, so no collision."""
    if token.count(".") != 2:
        return False
    header = token.split(".", 1)[0]
    try:
        raw = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        return isinstance(json.loads(raw), dict)
    except ValueError:
        return False


async def _require_agent(request: Request) -> str:
    """Dependency: resolve the caller to its enrolled agent id — solved
    BEFORE the body model, so an unauthenticated caller gets 401, never a
    422 that leaks the request schema.

    Resolution order: the Ed25519 request envelope (agent-id + timestamp +
    nonce + signature headers), the webhook-format HMAC (agent-id +
    timestamp + signature), a platform JWT on the Authorization header, then
    the minted per-agent ``rest`` bearer. The credential is the identity: no
    session, no CSRF surface, no fallback to the dashboard credential. Every
    refusal is the same generic 401 (so a rotated credential reads as
    "re-authenticate" and the reply never says whether the id exists or
    which stage refused); the precise rule goes to the server log only."""
    _gate()
    from maverick import external_identity
    from maverick.agent_trust import AgentTrustError, agent_for_token, load_trust_state
    try:
        # ONE trust snapshot per request (the grpc server pattern), so a
        # registry edit mid-request cannot split the auth decision.
        _, registry = load_trust_state()
    except AgentTrustError as e:
        log.warning("external gateway: trust state unreadable (fail-closed)")
        raise HTTPException(status_code=401,
                            detail="invalid credentials") from e
    agent_hdr = request.headers.get("x-lightwork-agent-id", "")
    from maverick.webhooks import read_signature_headers

    try:
        hmac_sig, ts = read_signature_headers(request.headers)
    except ValueError as exc:
        raise HTTPException(status_code=401,
                            detail="conflicting webhook authentication headers") from exc
    nonce = request.headers.get("x-lightwork-nonce", "")
    envelope_sig = request.headers.get("x-lightwork-request-signature", "")
    if agent_hdr and ts and nonce and envelope_sig:
        scheme = "envelope"
        # Starlette caches the body, so the endpoint model still parses it.
        body = await request.body()
        agent, rule = external_identity.verify_agent_envelope(
            agent_hdr, body, ts, nonce, envelope_sig, registry=registry)
    elif agent_hdr and ts and hmac_sig:
        scheme = "hmac"
        body = await request.body()
        agent, rule = external_identity.verify_agent_hmac(
            agent_hdr, body, ts, hmac_sig, registry=registry)
    else:
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else ""
        if not token:
            raise HTTPException(status_code=401,
                                detail="missing credentials")
        if _looks_like_jwt(token):
            scheme = "jwt"
            agent, rule = external_identity.verify_agent_jwt(
                token, registry=registry)
        else:
            scheme = "bearer"
            agent = agent_for_token(token, "rest", registry=registry)
            rule = "ok" if agent is not None else "invalid_token"
            if agent is not None and (agent.pubkey or agent.jwt_issuer
                                      or agent.hmac_secret_ref):
                # [external_agents] require_signed: an agent enrolled with a
                # strong credential must present it — its bearer alone no
                # longer authenticates. Token-only agents are unaffected.
                from maverick.config import get_external_agents
                if get_external_agents().get("require_signed"):
                    agent, rule = None, "require_signed"
    if agent is None:
        log.info("external gateway: %s auth refused (%s)", scheme, rule)
        raise HTTPException(status_code=401, detail="invalid credentials")
    from maverick import external_agents as xa
    xa.note_seen(agent.id)  # throttled credential-audit stamp
    return agent.id


async def _cache_limited_red_team_body(request: Request) -> None:
    """Bound signed and bearer request bodies before auth or model parsing."""

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="invalid Content-Length",
            ) from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if declared > _MAX_RED_TEAM_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_RED_TEAM_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    request._body = bytes(body)  # noqa: SLF001 - cache for auth and FastAPI parsing


async def _require_red_team_agent(request: Request) -> str:
    _gate()
    await _cache_limited_red_team_body(request)
    return await _require_agent(request)


async def _require_runtime_agent(request: Request) -> str:
    """Bound transient runtime bodies before verifying signed agent auth."""

    _gate()
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if declared > _MAX_RUNTIME_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_RUNTIME_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    request._body = bytes(body)  # noqa: SLF001 - cache for auth and model parsing
    return await _require_agent(request)


async def _cache_limited_discovery_sensor_body(request: Request) -> bytes:
    """Cache a bounded signed body before selecting its tenant trust floor."""

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if declared > _MAX_DISCOVERY_SENSOR_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_DISCOVERY_SENSOR_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    request._body = bytes(body)  # noqa: SLF001 - cache for signature and parsing
    return request._body  # noqa: SLF001 - exact cached signature authority


def _require_registered_external_tenant(tenant: str, *, detail: str = "invalid credentials") -> None:
    """Reject unknown tenants before any tenant-scoped storage is opened."""
    from maverick.paths import implicit_tenant_id
    from maverick.tenant.registry import _registry_path, assert_tenant_active, get_tenant

    try:
        record = get_tenant(tenant)
        legacy_default = (record is None and not _registry_path().exists()
                          and implicit_tenant_id() == tenant)
        if (record is None and not legacy_default) or (record is not None and not record.active):
            raise ValueError("unknown or inactive tenant")
        assert_tenant_active(tenant)
    except Exception as exc:
        log.info("external gateway: tenant admission refused (%s)", type(exc).__name__)
        raise HTTPException(status_code=401, detail=detail) from None


async def _require_discovery_sensor(
    request: Request,
) -> AsyncIterator[tuple[str, str]]:
    """Verify a tenant-bound Ed25519 sensor identity and durable nonce claim.

    Tenant selection comes from the signed body. The selected tenant's trust
    registry must contain a currently active inbound agent with a pinned key
    and the explicit ai_discovery_observation capability. Only the Ed25519
    envelope is accepted on this route; bearer, JWT, and HMAC fallback are
    intentionally unavailable.
    """

    from maverick import ai_discovery_sensors as discovery

    if not discovery.enabled():
        raise HTTPException(status_code=404, detail="not found")
    body = await _cache_limited_discovery_sensor_body(request)
    try:
        decoded = json.loads(body)
        tenant_value = decoded.get("tenant_ref") if isinstance(decoded, dict) else None
        from maverick.paths import canonical_tenant_id, reset_tenant, set_tenant

        tenant = canonical_tenant_id(tenant_value)
    except (TypeError, UnicodeError, ValueError):
        raise HTTPException(status_code=401, detail="invalid credentials") from None

    _require_registered_external_tenant(tenant)
    tenant_token = set_tenant(tenant)
    try:
        from maverick import external_identity
        from maverick.agent_trust import AgentTrustError, load_trust_state
        from maverick.paths import TenantNamespaceCollision, TenantPolicyError

        try:
            _, registry = load_trust_state()
        except (AgentTrustError, TenantNamespaceCollision, TenantPolicyError) as exc:
            log.warning(
                "discovery sensor ingress: tenant trust state unreadable"
            )
            raise HTTPException(
                status_code=401, detail="invalid credentials"
            ) from exc
        agent_id = request.headers.get("x-lightwork-agent-id", "")
        timestamp = request.headers.get("x-maverick-timestamp", "")
        nonce = request.headers.get("x-lightwork-nonce", "")
        signature = request.headers.get("x-lightwork-request-signature", "")
        if not all((agent_id, timestamp, nonce, signature)):
            raise HTTPException(status_code=401, detail="invalid credentials")
        agent, rule = external_identity.verify_agent_envelope(
            agent_id,
            body,
            timestamp,
            nonce,
            signature,
            registry=registry,
        )
        if (
            agent is None
            or "ai_discovery_observation" not in agent.allow_tools
        ):
            log.info(
                "discovery sensor ingress: signed identity refused (%s)",
                rule if agent is None else "missing_sensor_capability",
            )
            raise HTTPException(status_code=401, detail="invalid credentials")
        yield agent.id, tenant
    finally:
        reset_tenant(tenant_token)


async def _cache_limited_vendor_portal_body(request: Request) -> None:
    if request.method == "GET":
        return
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid Content-Length") from None
        if declared < 0:
            raise HTTPException(status_code=400, detail="invalid Content-Length")
        if declared > _MAX_VENDOR_PORTAL_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_VENDOR_PORTAL_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
    request._body = bytes(body)  # noqa: SLF001 - bounded cache for model parsing


async def _require_vendor_portal(
    request: Request,
) -> AsyncIterator[tuple[str, dict]]:
    """Authenticate one opaque invitation without dashboard or agent fallback."""

    from maverick import ai_vendor_portal as portal

    tenant_value = request.headers.get("x-lightwork-tenant", "")
    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if (
        not separator
        or scheme.lower() != "vendorportal"
        or not token
        or len(token) > 96
    ):
        raise HTTPException(status_code=401, detail="invalid invitation")
    try:
        from maverick.paths import canonical_tenant_id, reset_tenant, set_tenant

        tenant = canonical_tenant_id(tenant_value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="invalid invitation") from None
    _require_registered_external_tenant(tenant, detail="invalid invitation")
    client = request.client.host if request.client else "unknown"
    throttle_key = hashlib.sha256(
        f"{client}\0{tenant}".encode()
    ).hexdigest()
    _rate_limit(throttle_key, "vendor_portal")
    await _cache_limited_vendor_portal_body(request)
    tenant_token = set_tenant(tenant)
    try:
        from maverick.paths import TenantNamespaceCollision, TenantPolicyError
        if not portal.enabled():
            raise HTTPException(status_code=404, detail="not found")
        try:
            questionnaire = portal.questionnaire_for_token(token)
        except portal.AIVendorPortalAuthError as exc:
            raise HTTPException(
                status_code=401, detail="invalid invitation"
            ) from exc
        except portal.AIVendorPortalConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except portal.AIVendorPortalConfigError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        except portal.AIVendorPortalStateError as exc:
            raise HTTPException(
                status_code=503,
                detail="vendor response authority is unavailable",
            ) from exc
        except (TenantNamespaceCollision, TenantPolicyError):
            raise HTTPException(status_code=401, detail="invalid invitation") from None
        yield token, questionnaire
    finally:
        reset_tenant(tenant_token)


def _shield():
    """The deployment's Shield instance for input scanning, or ``None``.

    Kernel rule: the platform never *requires* agent-shield. Screening
    degrades to the redaction + injection-tripwire layer when it is absent;
    when it IS present, a scanner error denies (enforced in core)."""
    try:
        from maverick_shield import Shield
        return Shield()
    except Exception:
        return None


@router.post("/runs", status_code=201)
async def external_run_report(
    payload: ExternalRunIn, agent_id: str = Depends(_require_agent),
) -> dict:
    """Ingest one completed external run onto the Operating Record."""
    _rate_limit(agent_id, "runs")
    from maverick import external_agents as xa
    try:
        out = xa.record_run(agent_id, payload.model_dump(), shield=_shield())
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    return {"ok": True, **out}


@router.post("/runs/start", status_code=201)
async def external_run_start(
    payload: ExternalRunStartIn, agent_id: str = Depends(_require_agent),
) -> dict:
    """Open a LIVE run: the goal is visible on the Operating Record while
    the work happens, and the reply names the heartbeat interval the agent
    must honor or the run is reclaimed."""
    _rate_limit(agent_id, "runs")
    from maverick import external_agents as xa
    try:
        out = xa.start_run(agent_id, payload.model_dump(), shield=_shield())
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    return {"ok": True, **out}


@router.post("/runs/{goal_id}/heartbeat")
async def external_run_heartbeat(
    goal_id: int, agent_id: str = Depends(_require_agent),
) -> dict:
    """Keep a live run alive and learn whether to continue — ``continue:
    false`` is the kill switch reaching mid-flight work."""
    _rate_limit(agent_id, "heartbeat")
    from maverick import external_agents as xa
    return xa.heartbeat(agent_id, goal_id)


@router.post("/runs/{goal_id}/finish")
async def external_run_finish(
    goal_id: int, payload: ExternalRunFinishIn,
    agent_id: str = Depends(_require_agent),
) -> dict:
    """Close a live run with its outcome, steps, and cost."""
    _rate_limit(agent_id, "runs")
    from maverick import external_agents as xa
    try:
        out = xa.finish_run(agent_id, goal_id, payload.model_dump(),
                            shield=_shield())
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e
    return {"ok": True, **out}


@router.post("/screen")
async def external_screen(
    payload: ExternalScreenIn, agent_id: str = Depends(_require_agent),
) -> dict:
    """Decide a proposed action before the external agent takes it."""
    _rate_limit(agent_id, "screen")
    from maverick import external_agents as xa
    return xa.screen(agent_id, payload.tool, detail=payload.detail,
                     risk=payload.risk or None, shield=_shield())


@router.post("/runtime/evaluate")
async def external_runtime_evaluate(
    payload: schemas.AIRuntimeGuardrailIn,
    agent_id: str = Depends(_require_runtime_agent),
) -> dict:
    """Apply policy, Shield, and redaction before third-party content is released."""

    _rate_limit(agent_id, "runtime")
    from maverick import ai_runtime_guardrails as runtime

    if not runtime.enabled():
        raise HTTPException(status_code=404, detail="not found")
    # Reuse the dashboard authority resolver: callers cannot self-assert policy
    # facts.  It verifies the exact current observation and derives context from
    # a current approved declaration.
    from .model_risk_api import _runtime_authority

    binding, policy_context = await _runtime_authority(runtime, payload)
    try:
        result = runtime.default_service.evaluate(runtime.RuntimeGuardrailInput(
            stage=payload.stage,
            content=payload.content,
            asset=binding,
            policy_context=policy_context,
            action_name=payload.action_name,
            action_arguments=payload.action_arguments,
            known_prompt=payload.known_prompt,
        ))
        normalized_risk = runtime.dynamic_risk_receipt(result)
    except runtime.RuntimeGuardrailsInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except runtime.RuntimeGuardrailsError as exc:
        raise HTTPException(
            status_code=503,
            detail="runtime guardrail evaluation is unavailable",
        ) from exc
    return {
        "decision": result.decision,
        "receipt": result.receipt,
        "redacted_content": result.redacted_content,
        "dynamic_risk_receipt": normalized_risk,
        "dynamic_risk_signal_recorded": False,
        "raw_content_persisted": False,
    }


@router.post("/memory/ingest", status_code=201)
async def external_memory_ingest(
    payload: ExternalMemoryIngestIn, agent_id: str = Depends(_require_agent),
) -> dict:
    """Deposit one experience record into the governed learning plane —
    the REST twin of the MCP fleet-ingest tool, for platforms that only
    speak HTTPS. Vendor provenance comes from the enrollment, never the
    caller. Refusals carry the plane's own reason (roster, scope, Shield)."""
    _rate_limit(agent_id, "memory")
    from maverick import external_agents as xa
    ok, reason = xa.memory_ingest(agent_id, payload.model_dump(),
                                  shield=_shield())
    if not ok:
        raise HTTPException(status_code=403, detail=reason)
    return {"ok": True}


@router.post("/memory/recall")
async def external_memory_recall(
    payload: ExternalMemoryRecallIn, agent_id: str = Depends(_require_agent),
) -> dict:
    """Governed memory read: department-scoped lessons for the asking agent.
    An empty context with a reason is a refusal, not an error — the caller
    proceeds without memory."""
    _rate_limit(agent_id, "memory")
    from maverick import external_agents as xa
    context, reason = xa.memory_recall(agent_id, payload.query,
                                       domain=payload.domain or None,
                                       shield=_shield())
    return {"context": context, "reason": reason}


@router.get("/approvals/{approval_id}")
async def external_approval_status(
    approval_id: int,
    binding_sha256: str = Query(default="", max_length=64),
    agent_id: str = Depends(_require_agent),
) -> dict:
    """Poll a parked approval (the human decides in the dashboard queue)."""
    _rate_limit(agent_id, "approvals")
    from maverick import external_agents as xa
    try:
        out = xa.approval_status(
            agent_id,
            approval_id,
            expected_binding_sha256=binding_sha256,
        )
    except xa.ApprovalBindingMismatch as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    log.debug("external approval poll by %s: %s", agent_id, out["status"])
    return out


@router.post(
    "/discovery-sensors/{sensor_id}/observations",
    status_code=201,
)
async def external_discovery_sensor_observation(
    sensor_id: str,
    payload: ExternalDiscoveryObservationIn,
    sensor_authority: tuple[str, str] = Depends(_require_discovery_sensor),
) -> dict:
    """Admit one exact signed observation from an approved machine sensor."""

    from maverick import ai_discovery_sensors as discovery

    agent_id, tenant = sensor_authority
    _rate_limit(f"{tenant}:{agent_id}", "discovery_sensor")
    service = discovery.default_service()
    try:
        sensor = service.get_sensor(sensor_id)
        if (
            sensor is None
            or sensor.get("status") != "active"
            or sensor.get("sensor_name") != agent_id
            or sensor.get("sensor_type") != payload.domain_category
        ):
            raise HTTPException(
                status_code=403,
                detail="sensor identity is not authorized for this binding",
            )
        observation = discovery.NormalizedDiscoveryObservation(
            event_sha256=payload.event_sha256,
            observed_at=payload.observed_at,
            ai_service_code=payload.ai_service_code,
            ai_product_code=payload.ai_product_code,
            provider_code=payload.provider_code,
            domain_category=payload.domain_category,
            deployment_type=payload.deployment_type,
            environment_code=payload.environment_code,
            context_codes=tuple(payload.context_codes),
        )
        result = service.ingest_observation(
            sensor_id,
            sensor_revision=payload.sensor_revision,
            config_sha256=payload.config_sha256,
            observation=observation,
        )
    except HTTPException:
        raise
    except discovery.AIDiscoverySensorsBindingError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except discovery.AIDiscoverySensorsIdempotencyConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except discovery.AIDiscoverySensorsConfigError as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    except discovery.AIDiscoverySensorsStateError as exc:
        raise HTTPException(
            status_code=503,
            detail="discovery sensor authority is unavailable",
        ) from exc
    return {
        "observation": result,
        "machine_authenticated": True,
        "sensor_agent_id": agent_id,
    }


@router.get("/ai-vendor/questionnaire")
async def external_ai_vendor_questionnaire(
    response: Response,
    authority: tuple[str, dict] = Depends(_require_vendor_portal),
) -> dict:
    """Return one invitation's exact digest-bound questionnaire."""

    _token, questionnaire = authority
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return questionnaire


@router.post("/ai-vendor/submissions", status_code=201)
async def external_ai_vendor_submission(
    payload: ExternalVendorPortalSubmissionIn,
    response: Response,
    authority: tuple[str, dict] = Depends(_require_vendor_portal),
) -> dict:
    """Consume one invitation with a complete vendor-attested response."""

    from maverick import ai_vendor_portal as portal

    token, _questionnaire = authority
    try:
        submitted = portal.submit_response(
            token,
            answers=payload.answers,
            respondent_ref=payload.respondent_ref,
            attested=payload.attested,
            idempotency_key=payload.idempotency_key,
        )
    except portal.AIVendorPortalAuthError as exc:
        raise HTTPException(status_code=401, detail="invalid invitation") from exc
    except portal.AIVendorPortalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (portal.AIVendorPortalConfigError, portal.AIVendorPortalStateError) as exc:
        raise HTTPException(
            status_code=503,
            detail="vendor response authority is unavailable",
        ) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {
        "submission_id": submitted["submission_id"],
        "invitation_id": submitted["invitation_id"],
        "vendor": submitted["vendor"],
        "status": submitted["status"],
        "response_sha256": submitted["response_sha256"],
        "submitted_at": submitted["submitted_at"],
        "notice": submitted["notice"],
    }


async def _external_execute_runtime_gate(payload: ExternalExecuteIn):
    """Enforce the runtime plane on the connector effect chokepoint when on."""

    from maverick import ai_runtime_guardrails as runtime

    if not runtime.enabled():
        try:
            from maverick.config import config_source_errors, load_config

            errors = config_source_errors()
            config = load_config()
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="runtime guardrail configuration is unavailable",
            ) from exc
        if errors or not isinstance(config, dict):
            raise HTTPException(
                status_code=503,
                detail="runtime guardrail configuration is unreadable",
            )
        section = config.get("ai_runtime_guardrails")
        if isinstance(section, dict) and section.get("enable") is True:
            raise HTTPException(
                status_code=503,
                detail="runtime guardrails are enabled but unavailable",
            )
        return None
    if (
        payload.runtime_asset_id is None
        or payload.runtime_asset_revision is None
        or payload.runtime_asset_version_digest is None
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "runtime_asset_id, runtime_asset_revision, and "
                "runtime_asset_version_digest are required while runtime "
                "guardrails are enabled"
            ),
        )
    try:
        runtime_input = schemas.AIRuntimeGuardrailIn(
            stage="action",
            content=payload.detail,
            asset_id=payload.runtime_asset_id,
            asset_revision=payload.runtime_asset_revision,
            asset_version_digest=payload.runtime_asset_version_digest,
            action_name=f"{payload.connector}.{payload.op}",
            action_arguments={
                "connector": payload.connector,
                "op": payload.op,
                "path": payload.path,
                "body": payload.body,
                "preview": payload.preview,
                "goal_id": payload.goal_id,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="runtime action is malformed") from exc
    from .model_risk_api import _runtime_authority

    binding, policy_context = await _runtime_authority(runtime, runtime_input)
    try:
        return runtime.default_service.evaluate(runtime.RuntimeGuardrailInput(
            stage="action",
            content=payload.detail,
            asset=binding,
            policy_context=policy_context,
            action_name=f"{payload.connector}.{payload.op}",
            action_arguments=runtime_input.action_arguments,
        ))
    except runtime.RuntimeGuardrailsInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except runtime.RuntimeGuardrailsError as exc:
        raise HTTPException(
            status_code=503,
            detail="runtime guardrail evaluation is unavailable",
        ) from exc


def _runtime_execution_context_sha256(payload: ExternalExecuteIn) -> str:
    """Bind a parked approval to its gateway-verified runtime authority."""

    material = {
        "asset_id": payload.runtime_asset_id,
        "asset_revision": payload.runtime_asset_revision,
        "asset_version_digest": (
            payload.runtime_asset_version_digest or ""
        ).lower().removeprefix("sha256:"),
        "detail": payload.detail,
        "goal_id": payload.goal_id,
    }
    return hashlib.sha256(json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _runtime_authority_fingerprint(
    payload: ExternalExecuteIn,
    result: object | None,
) -> str:
    """Commit to the full request and stable fields of one runtime decision."""

    request = payload.model_dump(mode="json")
    if result is None:
        runtime: dict[str, object] = {"state": "disabled"}
    else:
        decision = getattr(result, "decision", None)
        receipt = getattr(result, "receipt", None)
        if not isinstance(decision, str) or not isinstance(receipt, dict):
            raise ValueError("runtime authority result is malformed")
        stable_receipt = dict(receipt)
        # Re-evaluation necessarily has a new observation time. Every
        # authority-bearing field (asset binding, policy digest, decision,
        # categories, rules, controls, and input/output commitments) remains.
        stable_receipt.pop("evaluated_at", None)
        runtime = {
            "state": "enabled",
            "decision": decision,
            "receipt": stable_receipt,
        }
    material = {"request": request, "runtime": runtime}
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def _fresh_runtime_gate(payload):
    from .auth import fresh_configuration

    with fresh_configuration():
        return await _external_execute_runtime_gate(payload)


class _EnforcementObserver:
    """Bind native physical attempt custody to current authenticated sources."""

    def __init__(self, payload, result, agent_id):
        from maverick import agent_trust
        from maverick.paths import current_tenant_id_strict

        self.payload = payload.model_dump_json()
        self.result = result
        self.agent_id = agent_id
        self.tenant = current_tenant_id_strict()
        self.agent = agent_trust.load_registry_strict().get(agent_id)
        from maverick import runtime_enforcement_records as records

        self.expected = records.digest([_runtime_authority_fingerprint(payload, result), self.sources()])
        self.identifier = None
        if self.agent is None or not self.agent.is_active()[0] or self.tenant is None:
            raise HTTPException(409, "Current safeguard account authority is unavailable.")

    def sources(self):
        from maverick import model_risk_assurance as assurance

        asset = self.result.receipt["asset_binding"]["asset_id"]
        observation, declaration = assurance.get_observation(asset), assurance.get_declaration(asset)
        if (observation is None or declaration is None or observation.get("_audit_pending")
                or declaration.get("_audit_pending")
                or not assurance._DEFAULT._declaration_is_current(declaration, observation)):
            raise HTTPException(409, "The AI system's current reviewed safeguards are unavailable.")
        return [observation, declaration]

    def identity(self):
        from maverick import agent_trust
        from maverick.paths import current_tenant_id_strict

        from .auth import fresh_configuration

        with fresh_configuration():
            current = agent_trust.load_registry_strict().get(self.agent_id)
            if (current != self.agent or current is None or not current.is_active()[0]
                    or current_tenant_id_strict() != self.tenant):
                raise HTTPException(409, "The safeguard account or workspace changed.")

    def current(self):
        from anyio import from_thread
        from maverick import runtime_enforcement_records as records

        self.identity()
        payload = ExternalExecuteIn.model_validate_json(self.payload)
        result = from_thread.run(_fresh_runtime_gate, payload)
        current = records.digest([_runtime_authority_fingerprint(payload, result), self.sources()])
        if not hmac.compare_digest(current, self.expected):
            raise HTTPException(409, "The current safeguard sources changed before admission.")
        self.identity()

    def __call__(self, phase, status):
        from maverick import runtime_enforcement_records as records

        actor = "agent:" + self.agent_id
        if phase == "prepare":
            self.identifier = records.capture(self.result, actor=actor, request_sha256=self.expected,
                status=status, effect_guard=self.current)
        elif phase == "outcome" and self.identifier is not None:
            records.finish(self.identifier, status=status, actor=actor, effect_guard=self.identity)
        else:
            raise ValueError("Unknown native enforcement phase")

    def refuse(self):
        self("prepare", "refused")


def _runtime_revalidation_callback(
    payload: ExternalExecuteIn,
    initial_result: object | None,
):
    """Return a worker-safe callback that re-runs current runtime authority."""

    frozen_payload = payload.model_dump_json()
    expected = _runtime_authority_fingerprint(payload, initial_result)

    def revalidate() -> bool:
        # The core provider boundary runs in Starlette's AnyIO worker. Schedule
        # the async authority resolver back on the request loop while the core
        # retains its cross-process effect fence in the worker thread.
        from anyio import from_thread

        current_payload = ExternalExecuteIn.model_validate_json(frozen_payload)
        current = from_thread.run(_fresh_runtime_gate, current_payload)
        if current is not None and getattr(current, "decision", None) != "allow":
            return False
        actual = _runtime_authority_fingerprint(current_payload, current)
        return hmac.compare_digest(actual, expected)

    return revalidate


@router.post("/execute")
async def external_execute(
    payload: ExternalExecuteIn, agent_id: str = Depends(_require_agent),
) -> dict:
    """Perform one outbound action on the agent's behalf through a governed
    connector — the enforcement tier above /screen. Reads run immediately;
    writes park a digest-bound approval to commit later; every decision
    comes back as a typed verdict, never an exception."""
    _rate_limit(agent_id, "execute")
    from maverick import external_agents as xa
    request_body = payload.model_dump(exclude={
        "runtime_asset_id",
        "runtime_asset_revision",
        "runtime_asset_version_digest",
    })
    runtime_result = await _external_execute_runtime_gate(payload)
    observer = _EnforcementObserver(payload, runtime_result, agent_id) if runtime_result is not None and not payload.preview else None
    if runtime_result is not None and runtime_result.decision != "allow":
        try:
            if observer is not None:
                await run_in_threadpool(observer.refuse)
        except Exception as exc:
            raise HTTPException(503, "Safeguard refusal activity could not be confirmed. No action was sent.") from exc
        return {
            "allowed": False,
            "rule": "runtime_guardrail",
            "reason": (
                "runtime policy or content controls did not authorize this "
                "connector action; no external effect occurred"
            ),
            "status": runtime_result.decision,
            "requires_approval": runtime_result.decision in {"review", "restrict"},
            "runtime_guardrail": {
                "decision": runtime_result.decision,
                "receipt": runtime_result.receipt,
                "enforcement_record": observer.identifier if observer is not None else None,
            },
        }
    if runtime_result is not None:
        request_body["_runtime_context_sha256"] = (
            _runtime_execution_context_sha256(payload)
        )
    outcome = await run_in_threadpool(
        xa.execute,
        agent_id,
        request_body,
        shield=_shield(),
        enforcement_observer=observer,
        runtime_revalidator=_runtime_revalidation_callback(
            payload, runtime_result
        ),
    )
    if runtime_result is not None:
        outcome = {
            **outcome,
            "runtime_guardrail": {
                "decision": runtime_result.decision,
                "receipt": runtime_result.receipt,
                "enforcement_record": observer.identifier if observer is not None else None,
            },
        }
    return outcome


@router.get("/executions/{execution_id}")
async def external_execution_status(
    execution_id: str, agent_id: str = Depends(_require_agent),
) -> dict:
    """Poll a parked execution (ledger status joined with the approval
    decision) so the agent knows when to re-send the request and commit."""
    _rate_limit(agent_id, "executions")
    from maverick import external_agents as xa
    try:
        return xa.execute_status(agent_id, execution_id)
    except xa.ExternalAgentsError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/executions/{execution_id}/commit")
async def external_execution_commit(
    execution_id: str, payload: ExternalExecuteCommitIn,
    agent_id: str = Depends(_require_agent),
) -> dict:
    """Commit one approved execution: a digest-bound replay of the identical
    request. Shares the execute rate bucket — a commit can fire a write."""
    _rate_limit(agent_id, "execute")
    from maverick import external_agents as xa
    runtime_payload = ExternalExecuteIn(**payload.model_dump())
    runtime_result = await _external_execute_runtime_gate(runtime_payload)
    observer = _EnforcementObserver(runtime_payload, runtime_result, agent_id) if runtime_result is not None else None
    if runtime_result is not None and runtime_result.decision != "allow":
        try:
            if observer is not None:
                await run_in_threadpool(observer.refuse)
        except Exception as exc:
            raise HTTPException(503, "Safeguard refusal activity could not be confirmed. No action was sent.") from exc
        return {
            "allowed": False,
            "rule": "runtime_guardrail",
            "reason": (
                "current runtime policy or content controls did not authorize "
                "this approved connector action; no external effect occurred"
            ),
            "status": runtime_result.decision,
            "requires_approval": runtime_result.decision in {"review", "restrict"},
            "runtime_guardrail": {
                "decision": runtime_result.decision,
                "receipt": runtime_result.receipt,
                "enforcement_record": observer.identifier if observer is not None else None,
            },
        }
    request_body = payload.model_dump(exclude={
        "runtime_asset_id",
        "runtime_asset_revision",
        "runtime_asset_version_digest",
    })
    if runtime_result is not None:
        request_body["_runtime_context_sha256"] = (
            _runtime_execution_context_sha256(runtime_payload)
        )
    outcome = await run_in_threadpool(
        xa.execute_commit,
        agent_id,
        execution_id,
        request_body,
        shield=_shield(),
        enforcement_observer=observer,
        runtime_revalidator=_runtime_revalidation_callback(
            runtime_payload, runtime_result
        ),
    )
    if runtime_result is not None:
        outcome = {
            **outcome,
            "runtime_guardrail": {
                "decision": runtime_result.decision,
                "receipt": runtime_result.receipt,
                "enforcement_record": observer.identifier if observer is not None else None,
            },
        }
    return outcome


@router.get("/red-team/{campaign_id}/cases")
async def external_red_team_cases(
    campaign_id: str,
    runner_instance_id: str = Query(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
    ),
    limit: int = Query(1, ge=1, le=12),
    lease_seconds: int = Query(120, ge=30, le=900),
    agent_id: str = Depends(_require_red_team_agent),
) -> dict:
    """Atomically lease probes to one instance of the enrolled agent."""

    _rate_limit(agent_id, "red_team")
    from maverick import red_team_assurance as rta
    try:
        return rta.lease_cases_for_agent(
            campaign_id,
            external_agent_id=agent_id,
            runner_instance_id=runner_instance_id,
            limit=limit,
            lease_seconds=lease_seconds,
        )
    except rta.RedTeamDisabled as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    except rta.RedTeamStateError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/red-team/{campaign_id}/results", status_code=201)
async def external_red_team_result(
    campaign_id: str,
    payload: ExternalRedTeamResultIn,
    agent_id: str = Depends(_require_red_team_agent),
) -> dict:
    """Evaluate raw target output transiently and commit bounded metrics."""

    _rate_limit(agent_id, "red_team")
    from maverick import red_team_assurance as rta
    from maverick.privacy_ops import RecordConflict
    try:
        row = rta.submit_result(
            campaign_id,
            external_agent_id=agent_id,
            **payload.model_dump(),
        )
    except rta.RedTeamDisabled as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    except rta.RedTeamStateError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (RecordConflict, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "ok": True,
        "result_id": row["id"],
        "case_id": row["case_id"],
        "outcome": row["outcome"],
        "response_commitment": row["response_commitment"],
    }


#: Hand-maintained on purpose: FastAPI's generated schema spans the whole
#: dashboard; external platforms need exactly these three operations, with
#: nothing to leak. Served without auth like /openapi.json (pure shape, no
#: data) so an operator can import it before any credential exists.
_OPENAPI: dict = {
    "openapi": "3.0.3",
    "info": {
        "title": "Lightwork External Agent Gateway",
        "version": "1",
        "description": (
            "Governance and run accounting for agents built on other "
            "platforms. Authenticate every call with the per-agent rest "
            "bearer minted on the Lightwork /external-agents page."),
    },
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
        },
    },
    "security": [{"bearer": []}],
    "paths": {
        "/api/v1/external/screen": {
            "post": {
                "operationId": "screenAction",
                "summary": "Ask before acting: is this action within my "
                           "ceilings, budget, and approval floor?",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object", "required": ["tool"],
                        "properties": {
                            "tool": {"type": "string",
                                     "description": "Action/tool name"},
                            "detail": {"type": "string",
                                       "description": "What will be done"},
                            "risk": {"type": "string",
                                     "enum": ["low", "medium", "high"]},
                        }}}}},
                "responses": {"200": {"description": "Decision", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "allowed": {"type": "boolean"},
                            "rule": {"type": "string"},
                            "reason": {"type": "string"},
                            "requires_approval": {"type": "boolean"},
                            "approval_id": {"type": "integer"},
                        }}}}}},
            },
        },
        "/api/v1/external/runs": {
            "post": {
                "operationId": "reportRun",
                "summary": "Report a completed run for the Operating Record",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object", "required": ["title", "outcome"],
                        "properties": {
                            "title": {"type": "string"},
                            "outcome": {"type": "string",
                                        "enum": ["success", "failure"]},
                            "summary": {"type": "string"},
                            "steps": {"type": "array",
                                      "items": {"type": "string"}},
                            "cost_dollars": {"type": "number"},
                            "input_tokens": {"type": "integer"},
                            "output_tokens": {"type": "integer"},
                            "tool_calls": {"type": "integer"},
                            "duration_seconds": {"type": "number"},
                            "department": {"type": "string"},
                            "idempotency_key": {
                                "type": "string",
                                "description": "Stable key per logical run; "
                                               "retries return the original "
                                               "record instead of "
                                               "double-counting."},
                        }}}}},
                "responses": {"201": {"description": "Recorded", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "ok": {"type": "boolean"},
                            "goal_id": {"type": "integer"},
                            "over_budget": {"type": "boolean"},
                        }}}}}},
            },
        },
        "/api/v1/external/runs/start": {
            "post": {
                "operationId": "startRun",
                "summary": "Open a LIVE run (visible while working; "
                           "heartbeat required)",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object", "required": ["title"],
                        "properties": {
                            "title": {"type": "string"},
                            "summary": {"type": "string"},
                            "department": {"type": "string"},
                        }}}}},
                "responses": {"201": {"description": "Opened", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "ok": {"type": "boolean"},
                            "goal_id": {"type": "integer"},
                            "heartbeat_seconds": {
                                "type": "number",
                                "description": "Recommended maximum interval between beats. "
                                               "It leaves margin before stale-run recovery."},
                        }}}}}},
            },
        },
        "/api/v1/external/runs/{goal_id}/heartbeat": {
            "post": {
                "operationId": "heartbeatRun",
                "summary": "Keep a live run alive; continue=false is the "
                           "kill switch — stop working when you see it",
                "parameters": [{"name": "goal_id", "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}}],
                "responses": {"200": {"description": "Liveness", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "continue": {"type": "boolean"},
                            "reason": {"type": "string"},
                        }}}}}},
            },
        },
        "/api/v1/external/runs/{goal_id}/finish": {
            "post": {
                "operationId": "finishRun",
                "summary": "Close a live run with outcome, steps, and cost",
                "parameters": [{"name": "goal_id", "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}}],
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object", "required": ["outcome"],
                        "properties": {
                            "outcome": {"type": "string",
                                        "enum": ["success", "failure"]},
                            "summary": {"type": "string"},
                            "steps": {"type": "array",
                                      "items": {"type": "string"}},
                            "cost_dollars": {"type": "number"},
                            "input_tokens": {"type": "integer"},
                            "output_tokens": {"type": "integer"},
                            "tool_calls": {"type": "integer"},
                            "duration_seconds": {"type": "number"},
                            "idempotency_key": {"type": "string"},
                        }}}}},
                "responses": {"200": {"description": "Closed", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "ok": {"type": "boolean"},
                            "goal_id": {"type": "integer"},
                            "over_budget": {"type": "boolean"},
                            "over_wall": {"type": "boolean"},
                        }}}}}},
            },
        },
        "/api/v1/external/memory/ingest": {
            "post": {
                "operationId": "memoryIngest",
                "summary": "Deposit an experience record into the governed "
                           "learning plane (fleet memory)",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "required": ["kind", "goal_text"],
                        "properties": {
                            "kind": {"type": "string",
                                     "enum": ["success", "failure",
                                              "lesson"]},
                            "goal_text": {"type": "string"},
                            "reflection": {"type": "string"},
                            "tools_used": {"type": "array",
                                           "items": {"type": "string"}},
                            "domain": {"type": "string"},
                        }}}}},
                "responses": {"201": {"description": "Deposited", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}}}}}}},
            },
        },
        "/api/v1/external/memory/recall": {
            "post": {
                "operationId": "memoryRecall",
                "summary": "Read governed memory scoped to this agent's "
                           "permitted departments",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object", "required": ["query"],
                        "properties": {
                            "query": {"type": "string"},
                            "domain": {"type": "string"},
                        }}}}},
                "responses": {"200": {"description": "Context", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "context": {"type": "string"},
                            "reason": {"type": "string"},
                        }}}}}},
            },
        },
        "/api/v1/external/approvals/{approval_id}": {
            "get": {
                "operationId": "approvalStatus",
                "summary": "Poll a parked high-risk action",
                "parameters": [
                    {"name": "approval_id", "in": "path",
                     "required": True, "schema": {"type": "integer"}},
                    {"name": "binding_sha256", "in": "query",
                     "required": False,
                     "description": "Binding returned by /screen; a stale "
                                    "binding is rejected.",
                     "schema": {"type": "string", "maxLength": 64}},
                ],
                "responses": {"200": {"description": "Status", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "approval_id": {"type": "integer"},
                            "status": {"type": "string"},
                            "risk": {"type": "string"},
                            "action": {"type": "string"},
                            "approval_binding_sha256": {"type": "string"},
                            "target_sha256": {"type": "string"},
                            "parameters_sha256": {"type": "string"},
                            "inputs": {"type": "object"},
                            "credentials": {"type": "object"},
                            "expires_at": {"type": "number"},
                        }}}}}},
            },
        },
        "/api/v1/external/execute": {
            "post": {
                "operationId": "executeAction",
                "summary": "Perform one action through a governed connector "
                           "(reads run now; writes park a digest-bound "
                           "approval)",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "required": ["connector", "op", "path"],
                        "properties": {
                            "connector": {"type": "string",
                                          "description": "Enabled governed "
                                                         "connector name"},
                            "op": {"type": "string",
                                   "enum": ["get", "post", "put", "patch",
                                            "delete"]},
                            "path": {"type": "string"},
                            "body": {"type": "object"},
                            "preview": {
                                "type": "boolean",
                                "description": "Describe the write without "
                                               "performing it (no side "
                                               "effect)."},
                            "detail": {"type": "string",
                                       "description": "What will be done"},
                            "goal_id": {
                                "type": "integer",
                                "description": "Bind the effect to one of "
                                               "this agent's live runs."},
                            "idempotency_key": {
                                "type": "string",
                                "maxLength": 128,
                                "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
                                "description": "Stable logical-operation key; "
                                               "an exact write-park replay "
                                               "returns the original execution."},
                            "runtime_asset_id": {
                                "type": "string",
                                "pattern": "^MAA-[0-9a-f]{32}$",
                                "description": "Required when the runtime "
                                               "guardrail plane is enabled."},
                            "runtime_asset_revision": {
                                "type": "integer", "minimum": 1},
                            "runtime_asset_version_digest": {
                                "type": "string",
                                "pattern": "^(?:sha256:)?[0-9a-f]{64}$"},
                        }}}}},
                "responses": {"200": {"description": "Verdict", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "allowed": {"type": "boolean"},
                            "rule": {"type": "string"},
                            "reason": {"type": "string"},
                            "status": {"type": "string"},
                            "result": {"type": "string"},
                            "requires_approval": {"type": "boolean"},
                            "approval_id": {"type": "integer"},
                            "execution_id": {"type": "string"},
                            "duplicate": {"type": "boolean"},
                            "expires_at": {"type": "number"},
                            "preview": {"type": "string"},
                            "request_sha256": {"type": "string"},
                        }}}}}},
            },
        },
        "/api/v1/external/executions/{execution_id}": {
            "get": {
                "operationId": "executionStatus",
                "summary": "Poll a parked execution; commit once its "
                           "approval is granted",
                "parameters": [{"name": "execution_id", "in": "path",
                                "required": True,
                                "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Status", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "execution_id": {"type": "string"},
                            "status": {"type": "string"},
                            "approval_id": {"type": "integer"},
                            "connector": {"type": "string"},
                            "op": {"type": "string"},
                            "expires_at": {"type": "number"},
                            "approval_status": {"type": "string"},
                        }}}}}},
            },
        },
        "/api/v1/external/executions/{execution_id}/commit": {
            "post": {
                "operationId": "commitExecution",
                "summary": "Commit an approved execution by re-sending the "
                           "byte-identical request",
                "parameters": [{"name": "execution_id", "in": "path",
                                "required": True,
                                "schema": {"type": "string"}}],
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "required": ["connector", "op", "path"],
                        "properties": {
                            "connector": {"type": "string"},
                            "op": {"type": "string",
                                   "enum": ["get", "post", "put", "patch",
                                            "delete"]},
                            "path": {"type": "string"},
                            "body": {"type": "object"},
                            "detail": {
                                "type": "string",
                                "description": "Exact transient action detail "
                                               "used when the write was parked."},
                            "goal_id": {
                                "type": "integer",
                                "description": "Exact live-run binding used "
                                               "when the write was parked."},
                            "runtime_asset_id": {
                                "type": "string",
                                "pattern": "^MAA-[0-9a-f]{32}$",
                                "description": "Required when runtime "
                                               "guardrails are enabled."},
                            "runtime_asset_revision": {
                                "type": "integer", "minimum": 1},
                            "runtime_asset_version_digest": {
                                "type": "string",
                                "pattern": "^(?:sha256:)?[0-9a-f]{64}$"},
                        }}}}},
                "responses": {"200": {"description": "Verdict", "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "allowed": {"type": "boolean"},
                            "rule": {"type": "string"},
                            "reason": {"type": "string"},
                            "status": {"type": "string"},
                            "result": {"type": "string"},
                            "execution_id": {"type": "string"},
                        }}}}}},
            },
        },
        "/api/v1/external/runtime/evaluate": {
            "post": {
                "operationId": "evaluateRuntimeContent",
                "summary": "Evaluate transient prompt, output, or action content "
                           "against current governed policy and local guardrails",
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object",
                        "required": [
                            "stage", "asset_id", "asset_revision",
                            "asset_version_digest",
                        ],
                        "properties": {
                            "stage": {"type": "string",
                                      "enum": ["prompt", "output", "action"]},
                            "content": {"type": "string", "maxLength": 65536},
                            "asset_id": {"type": "string",
                                         "pattern": "^MAA-[0-9a-f]{32}$"},
                            "asset_revision": {"type": "integer", "minimum": 1},
                            "asset_version_digest": {
                                "type": "string",
                                "pattern": "^(?:sha256:)?[0-9a-f]{64}$",
                            },
                            "action_name": {"type": "string"},
                            "action_arguments": {"type": "object"},
                            "known_prompt": {"type": "string"},
                        }}}}},
                "responses": {"200": {"description": "Guardrail decision and "
                                                     "digest-only receipts",
                                        "content": {"application/json": {
                                            "schema": {"type": "object"}}}}},
            },
        },
        "/api/v1/external/red-team/{campaign_id}/cases": {
            "get": {
                "operationId": "pullRedTeamCases",
                "summary": "Atomically lease synthetic assurance probes to "
                           "one enrolled-agent runner",
                "parameters": [
                    {"name": "campaign_id", "in": "path", "required": True,
                     "schema": {"type": "string"}},
                    {"name": "runner_instance_id", "in": "query",
                     "required": True, "schema": {
                         "type": "string", "minLength": 1, "maxLength": 128,
                         "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$",
                     }},
                    {"name": "limit", "in": "query", "required": False,
                     "schema": {"type": "integer", "minimum": 1,
                                "maximum": 12, "default": 1}},
                    {"name": "lease_seconds", "in": "query",
                     "required": False, "schema": {
                         "type": "integer", "minimum": 30, "maximum": 900,
                         "default": 120,
                     }},
                ],
                "responses": {"200": {"description": "Pending probes",
                                        "content": {"application/json": {
                                            "schema": {"type": "object"}}}}},
            },
        },
        "/api/v1/external/red-team/{campaign_id}/results": {
            "post": {
                "operationId": "submitRedTeamResult",
                "summary": "Submit transient target output; Lightwork keeps "
                           "only a keyed commitment and bounded detector metrics",
                "parameters": [{"name": "campaign_id", "in": "path",
                                "required": True,
                                "schema": {"type": "string"}}],
                "requestBody": {"required": True, "content": {
                    "application/json": {"schema": {
                        "type": "object", "required": [
                            "case_id", "target_artifact_sha256",
                            "runner_instance_id", "lease_token",
                        ],
                        "properties": {
                            "case_id": {"type": "string"},
                            "target_artifact_sha256": {
                                "type": "string",
                                "pattern": "^(?:sha256:)?[0-9a-f]{64}$",
                            },
                            "runner_instance_id": {
                                "type": "string",
                                "pattern": "^[A-Za-z0-9]"
                                           "[A-Za-z0-9_.:@/-]{0,127}$",
                            },
                            "lease_token": {
                                "type": "string",
                                "pattern": "^rtl1\\.[0-9a-f]{64}$",
                            },
                            "response": {"type": "string"},
                            "tool_calls": {"type": "array",
                                           "items": {"oneOf": [
                                               {"type": "string"},
                                               {"type": "object"},
                                           ]}},
                            "tool_trace_status": {
                                "type": "string",
                                "enum": ["complete", "unavailable"],
                                "default": "unavailable",
                            },
                            "transport_status": {
                                "type": "string",
                                "enum": ["completed", "timeout", "error",
                                         "cancelled"],
                            },
                        }}}}},
                "responses": {"201": {"description": "Committed result",
                                        "content": {"application/json": {
                                            "schema": {"type": "object"}}}}},
            },
        },
    },
}


@router.get("/openapi.json")
async def external_openapi(request: Request) -> dict:
    """The importable gateway description (Agentforce External Services /
    Bedrock action groups consume this file directly). No bearer required —
    pure shape, no data, and the operator needs it before credentials exist —
    but it still 404s while the plane is off."""
    from maverick import external_agents as xa
    if not xa.enabled():
        raise HTTPException(status_code=404, detail="not found")
    client = request.client.host if request.client else "unknown"
    _rate_limit(client, "openapi")
    document = {**_OPENAPI, "paths": dict(_OPENAPI["paths"])}
    try:
        from maverick import red_team_assurance as rta

        red_team_enabled = rta.enabled()
    except Exception:
        red_team_enabled = False
    if not red_team_enabled:
        document["paths"].pop(
            "/api/v1/external/red-team/{campaign_id}/cases",
            None,
        )
        document["paths"].pop(
            "/api/v1/external/red-team/{campaign_id}/results",
            None,
        )
    return document
