"""Tenant-bound admin and opaque public APIs for stable policy links.

The administrative router never accepts a tenant identifier.  The public
router resolves a high-entropy stable link ID through a private global registry
and therefore does not expose tenant or policy selectors.  Private bearer
capabilities are passed directly to the core authority, returned only on mint
or rotation, and never written by this module.

This is a local control plane.  It performs no network I/O and is not evidence
of customer, browser, storage, recovery, or scale acceptance.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_CAPABILITY_PATTERN = r"^[A-Za-z0-9_-]{32,256}$"
_ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,47}$"
_MAX_BODY_BYTES = 320 * 1024
_MAX_PUBLIC_RESPONSE_BYTES = 272 * 1024
_REGISTRY_SCHEMA = "lightwork.policy-public-link-registry.v1"
_PUBLIC_DETAIL = "policy link is unavailable"

OpaqueId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_ID_PATTERN,
    ),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    ),
]
Digest = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=64,
        max_length=64,
        pattern=_DIGEST_PATTERN,
    ),
]
Capability = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=32,
        max_length=256,
        pattern=_CAPABILITY_PATTERN,
    ),
]
ErrorCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=48,
        pattern=_ERROR_CODE_PATTERN,
    ),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ArtifactIn(_StrictModel):
    policy_id: OpaqueId
    version: int = Field(ge=1, le=2**31 - 1)
    title: str = Field(min_length=1, max_length=1024)
    body_text: str = Field(min_length=1, max_length=256 * 1024)
    approval_mode: Literal["none", "approval", "four_eyes"]
    idempotency_key: IdempotencyKey


class ReviewIn(_StrictModel):
    decision: Literal["approve", "reject"]
    idempotency_key: IdempotencyKey
    rationale_sha256: Digest | None = None


class LinkIn(_StrictModel):
    policy_id: OpaqueId
    visibility: Literal["public", "private"]
    idempotency_key: IdempotencyKey


class PublishIn(_StrictModel):
    version: int = Field(ge=1, le=2**31 - 1)
    expected_pointer_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    expires_at: float | None = Field(default=None, gt=0, lt=100_000_000_000.0)


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class PublicationScheduleIn(_StrictModel):
    version: int = Field(ge=1, le=2**31 - 1)
    scheduled_for: float = Field(gt=0, lt=100_000_000_000.0)
    expected_pointer_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    expires_at: float | None = Field(default=None, gt=0, lt=100_000_000_000.0)
    max_attempts: int = Field(default=3, ge=1, le=20)


class ExpiryScheduleIn(_StrictModel):
    version: int = Field(ge=1, le=2**31 - 1)
    scheduled_for: float = Field(gt=0, lt=100_000_000_000.0)
    expected_pointer_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    max_attempts: int = Field(default=3, ge=1, le=20)


class RevocationScheduleIn(_StrictModel):
    scheduled_for: float = Field(gt=0, lt=100_000_000_000.0)
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey
    max_attempts: int = Field(default=3, ge=1, le=20)


class ClaimBatchIn(_StrictModel):
    limit: int = Field(default=20, ge=1, le=100)
    lease_seconds: float = Field(default=60.0, gt=0, le=3600.0)


class ClaimAuthorityIn(_StrictModel):
    action: Literal["publish", "expire", "revoke"]
    link_id: OpaqueId
    target_version: int | None = Field(default=None, ge=1, le=2**31 - 1)
    scheduled_for: float = Field(gt=0, lt=100_000_000_000.0)
    expires_at: float | None = Field(default=None, gt=0, lt=100_000_000_000.0)
    expected_revision: int = Field(ge=0, le=2**31 - 1)
    attempt: int = Field(ge=1, le=20)
    lease_token: Capability


class FailClaimIn(ClaimAuthorityIn):
    error_code: ErrorCode
    retryable: bool
    retry_after_seconds: float = Field(default=60.0, gt=0, le=86_400.0)


class RunDueIn(_StrictModel):
    limit: int = Field(default=20, ge=1, le=100)
    lease_seconds: float = Field(default=60.0, gt=0, le=3600.0)
    approval_retry_seconds: float = Field(default=60.0, gt=0, le=86_400.0)


class RetentionIn(_StrictModel):
    before: float = Field(gt=0, lt=100_000_000_000.0)
    limit: int = Field(default=100, ge=1, le=500)


class PublicLinkRegistryError(RuntimeError):
    """The opaque global link registry is unavailable or inconsistent."""


class PublicPolicyLinkRegistry:
    """Private link-ID-to-tenant resolver with canonical row digests.

    The registry deliberately stores no policy content, bearer capability, or
    capability digest.  Its only purpose is selecting the tenant-isolated core
    database after an opaque public link ID is presented.
    """

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._initialize()

    @staticmethod
    def _identifier(value: object, label: str) -> str:
        if not isinstance(value, str) or re.fullmatch(_ID_PATTERN, value) is None:
            raise PublicLinkRegistryError(f"{label} is invalid")
        return value

    @staticmethod
    def _digest(link_id: str, tenant_id: str, created_at: float) -> str:
        canonical = json.dumps(
            {
                "schema": _REGISTRY_SCHEMA,
                "link_id": link_id,
                "tenant_id": tenant_id,
                "created_at": created_at,
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()

    @contextlib.contextmanager
    def _connect(self):
        from maverick.file_lock import ensure_private_directory, ensure_private_file

        ensure_private_directory(self.path.parent)
        if not self.path.exists():
            try:
                descriptor = os.open(
                    self.path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        ensure_private_file(self.path, 0o600)
        connection = sqlite3.connect(
            str(self.path),
            timeout=10.0,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS public_policy_link_registry ("
                "link_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
                "created_at REAL NOT NULL, record_sha256 TEXT NOT NULL)"
            )

    def bind(self, link_id: str, tenant_id: str) -> dict[str, Any]:
        """Idempotently bind one globally opaque link to one exact tenant."""

        link = self._identifier(link_id, "link_id")
        tenant = self._identifier(tenant_id, "tenant_id")
        now = float(self._clock())
        if not 0 < now < 100_000_000_000.0:
            raise PublicLinkRegistryError("registry clock is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT * FROM public_policy_link_registry WHERE link_id=?",
                    (link,),
                ).fetchone()
                if existing is not None:
                    self._verify_row(existing)
                    if not hmac.compare_digest(str(existing["tenant_id"]), tenant):
                        raise PublicLinkRegistryError(
                            "opaque link is already bound to another tenant"
                        )
                    connection.execute("COMMIT")
                    return {
                        "link_id": link,
                        "bound": True,
                        "idempotent_replay": True,
                    }
                digest = self._digest(link, tenant, now)
                connection.execute(
                    "INSERT INTO public_policy_link_registry("
                    "link_id,tenant_id,created_at,record_sha256) VALUES(?,?,?,?)",
                    (link, tenant, now, digest),
                )
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return {"link_id": link, "bound": True, "idempotent_replay": False}

    def _verify_row(self, row: Mapping[str, Any]) -> None:
        expected = self._digest(
            str(row["link_id"]),
            str(row["tenant_id"]),
            float(row["created_at"]),
        )
        if not hmac.compare_digest(expected, str(row["record_sha256"])):
            raise PublicLinkRegistryError("public policy registry integrity failed")

    def resolve(self, link_id: str) -> str:
        """Resolve an opaque link without exposing tenant data to the caller."""

        link = self._identifier(link_id, "link_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM public_policy_link_registry WHERE link_id=?",
                (link,),
            ).fetchone()
        if row is None:
            raise PublicLinkRegistryError("public policy link was not found")
        self._verify_row(row)
        return str(row["tenant_id"])

    def verify_binding(self, link_id: str, tenant_id: str) -> dict[str, Any]:
        tenant = self._identifier(tenant_id, "tenant_id")
        resolved = self.resolve(link_id)
        if not hmac.compare_digest(resolved, tenant):
            raise PublicLinkRegistryError("public policy link binding changed")
        return {"link_id": link_id, "binding_status": "verified"}

    def verify_tenant(self, tenant_id: str) -> dict[str, Any]:
        """Verify all opaque registry bindings for one tenant only."""

        tenant = self._identifier(tenant_id, "tenant_id")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM public_policy_link_registry WHERE tenant_id=? "
                "ORDER BY link_id",
                (tenant,),
            ).fetchall()
        for row in rows:
            self._verify_row(row)
        return {"binding_status": "verified", "binding_count": len(rows)}


class PublicPolicyRateLimitExceeded(RuntimeError):
    """The bounded public retrieval rate was exceeded."""


class PublicPolicyRateLimiter:
    """Small in-process public-link limiter with bounded key cardinality."""

    def __init__(
        self,
        *,
        per_key: int = 60,
        global_limit: int = 20_000,
        window_seconds: float = 60.0,
        max_keys: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(per_key, global_limit, max_keys) < 1 or window_seconds <= 0:
            raise ValueError("rate limiter bounds must be positive")
        self.per_key = per_key
        self.global_limit = global_limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}
        self._global: deque[float] = deque()

    @staticmethod
    def _trim(events: deque[float], cutoff: float) -> None:
        while events and events[0] <= cutoff:
            events.popleft()

    def check(self, key: str) -> None:
        now = float(self._clock())
        cutoff = now - self.window_seconds
        with self._lock:
            self._trim(self._global, cutoff)
            if key not in self._events and len(self._events) >= self.max_keys:
                for values in self._events.values():
                    self._trim(values, cutoff)
                stale = [name for name, values in self._events.items() if not values]
                for name in stale[: max(1, len(self._events) - self.max_keys + 1)]:
                    self._events.pop(name, None)
                if len(self._events) >= self.max_keys:
                    raise PublicPolicyRateLimitExceeded(
                        "public policy rate limit cardinality reached"
                    )
            events = self._events.setdefault(key, deque())
            self._trim(events, cutoff)
            if len(self._global) >= self.global_limit or len(events) >= self.per_key:
                raise PublicPolicyRateLimitExceeded("public policy rate limit reached")
            events.append(now)
            self._global.append(now)


def _public_policy_rate_limiter() -> PublicPolicyRateLimiter:
    try:
        limit = int(os.environ.get("MAVERICK_PUBLIC_POLICY_GLOBAL_RATE", "20000"))
    except ValueError:
        limit = 20_000
    return PublicPolicyRateLimiter(global_limit=max(1, min(limit, 100_000)))


def _default_tenant_resolver() -> str | None:
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict()


def _default_store_for(tenant_id: str):
    from maverick.paths import data_dir
    from maverick.policy_publication_links import PolicyPublicationStore

    return PolicyPublicationStore(
        data_dir(
            "tech_risk_compliance",
            "policy-publication-links.sqlite3",
            tenant=tenant_id,
        )
    )


def _default_registry_factory() -> PublicPolicyLinkRegistry:
    from maverick.paths import data_dir

    return PublicPolicyLinkRegistry(
        data_dir(
            "policy_publication_links",
            "public-link-registry.sqlite3",
            tenant=None,
        )
    )


def _default_actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    subject = getattr(principal, "sub", None) or "local-operator"
    digest = hashlib.sha256(f"policy-publication\0{subject}".encode()).hexdigest()
    return f"operator-{digest[:40]}"


@dataclass(frozen=True)
class PolicyPublicationDependencies:
    """Injectable local dependencies; no dependency performs network I/O."""

    tenant_resolver: Callable[[], str | None] = _default_tenant_resolver
    store_for: Callable[[str], Any] = _default_store_for
    registry_factory: Callable[[], PublicPolicyLinkRegistry] = (
        _default_registry_factory
    )
    actor_resolver: Callable[[Request], str] = _default_actor
    rate_limiter: PublicPolicyRateLimiter | None = None


def _request_body_bound(request: Request) -> None:
    raw = request.headers.get("content-length")
    if raw is None:
        return
    try:
        length = int(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid Content-Length") from exc
    if length < 0 or length > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="request body is too large")


def _stable_path(link_id: str) -> str:
    return f"/api/v1/public/policies/{link_id}"


def _link_response(result: Mapping[str, Any]) -> dict[str, Any]:
    link_id = str(result["link_id"])
    return {
        **result,
        "stable_path": _stable_path(link_id),
        "private_bearer_required": result.get("visibility") == "private",
        "raw_capability_persisted": False,
    }


def _claim_response(claim: Any) -> dict[str, Any]:
    body = asdict(claim)
    body.pop("tenant_id", None)
    body.pop("worker_id", None)
    return {**body, "lease_token_returned_once": True}


def _request_context_sha256(request: Request, link_id: str, output_format: str) -> str:
    client_host = request.client.host if request.client is not None else "unknown"
    context = {
        "schema": "lightwork.policy-public-request-context.v1",
        "link_id": link_id,
        "format": output_format,
        "method": request.method,
        "client_sha256": hashlib.sha256(client_host.encode()).hexdigest(),
        "user_agent_sha256": hashlib.sha256(
            request.headers.get("user-agent", "")[:1024].encode()
        ).hexdigest(),
    }
    encoded = json.dumps(context, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _bearer(request: Request) -> str | None:
    raw = request.headers.get("authorization")
    if raw is None:
        return None
    if len(raw) > 320 or not raw.startswith("Bearer ") or raw.count(" ") != 1:
        raise HTTPException(status_code=404, detail=_PUBLIC_DETAIL)
    value = raw.removeprefix("Bearer ")
    if re.fullmatch(_CAPABILITY_PATTERN, value) is None:
        raise HTTPException(status_code=404, detail=_PUBLIC_DETAIL)
    return value


def _worker_id(request: Request, actor: str) -> str:
    digest = hashlib.sha256(f"policy-worker\0{actor}".encode()).hexdigest()
    return f"worker-{digest[:40]}"


def create_policy_publication_routers(  # noqa: C901 - explicit route assembly
    dependencies: PolicyPublicationDependencies | None = None,
) -> tuple[APIRouter, APIRouter]:
    """Create separately mountable authenticated-admin and public routers."""

    deps = dependencies or PolicyPublicationDependencies(
        rate_limiter=_public_policy_rate_limiter()
    )
    limiter = deps.rate_limiter or _public_policy_rate_limiter()
    admin = APIRouter(
        prefix="/policy-publication-links",
        tags=["policy-publication-links"],
    )
    public = APIRouter(prefix="/public/policies", tags=["public-policy-links"])

    def authority():
        tenant = deps.tenant_resolver()
        if tenant is None:
            raise HTTPException(
                status_code=409,
                detail="select an active tenant before managing policy links",
            )
        try:
            return tenant, deps.store_for(tenant), deps.registry_factory()
        except Exception as exc:
            from maverick import policy_publication_links as ops

            if isinstance(exc, ops.PolicyPublicationConfigError):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "policy links are disabled; enable tech_risk_compliance "
                        "and tech_risk_compliance.policy_publication_links"
                    ),
                ) from exc
            raise HTTPException(
                status_code=503,
                detail="policy publication authority unavailable",
            ) from exc

    async def call(function, *args, **kwargs) -> Any:
        from maverick import policy_publication_links as ops

        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.PolicyPublicationNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (
            ops.PolicyPublicationConflict,
            ops.PolicyPublicationApprovalRequired,
            ops.PolicyPublicationLeaseLost,
        ) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.PolicyPublicationValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.PolicyPublicationIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="policy publication integrity validation failed",
            ) from exc
        except ops.PolicyPublicationConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.PolicyPublicationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except PublicLinkRegistryError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    def actor(request: Request) -> str:
        return deps.actor_resolver(request)

    def claim_from_body(
        ops: Any,
        request: Request,
        tenant: str,
        job_id: str,
        body: ClaimAuthorityIn,
    ) -> Any:
        worker = _worker_id(request, actor(request))
        return ops.PublicationClaim(
            tenant_id=tenant,
            job_id=job_id,
            action=body.action,
            link_id=body.link_id,
            target_version=body.target_version,
            scheduled_for=body.scheduled_for,
            expires_at=body.expires_at,
            expected_revision=body.expected_revision,
            attempt=body.attempt,
            worker_id=worker,
            lease_token=body.lease_token,
        )

    @admin.post("/artifacts", status_code=201)
    async def create_artifact(request: Request, body: ArtifactIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.publish_artifact,
            tenant,
            author_id=actor(request),
            **body.model_dump(),
        )

    @admin.get("/artifacts")
    async def list_artifacts(
        request: Request,
        limit: int = Query(default=200, ge=1, le=500),
    ) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, _registry = authority()
        return await call(store.list_artifacts, tenant, limit=limit)

    @admin.get("/links")
    async def list_links(
        request: Request,
        limit: int = Query(default=200, ge=1, le=500),
    ) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, _registry = authority()
        result = await call(store.list_links, tenant, limit=limit)
        return {
            **result,
            "items": [
                {**item, "stable_path": _stable_path(str(item["link_id"]))}
                for item in result["items"]
            ],
        }

    @admin.get("/jobs")
    async def list_jobs(
        request: Request,
        limit: int = Query(default=200, ge=1, le=500),
    ) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, _registry = authority()
        return await call(store.list_jobs, tenant, limit=limit)

    @admin.get("/artifacts/{policy_id}/versions/{version}")
    async def artifact_status(
        request: Request,
        policy_id: ObjectPath,
        version: int = ApiPath(ge=1, le=2**31 - 1),
    ) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, _registry = authority()
        return await call(
            store.artifact_status,
            tenant,
            policy_id=policy_id,
            version=version,
        )

    @admin.post("/artifacts/{policy_id}/versions/{version}/reviews")
    async def review_artifact(
        request: Request,
        body: ReviewIn,
        policy_id: ObjectPath,
        version: int = ApiPath(ge=1, le=2**31 - 1),
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.approve_artifact,
            tenant,
            policy_id=policy_id,
            version=version,
            reviewer_id=actor(request),
            **body.model_dump(),
        )

    @admin.post("/links", status_code=201)
    async def create_link(request: Request, body: LinkIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, registry = authority()
        result = await call(
            store.create_link,
            tenant,
            created_by=actor(request),
            **body.model_dump(),
        )
        try:
            await run_in_threadpool(registry.bind, str(result["link_id"]), tenant)
        except PublicLinkRegistryError as exc:
            raise HTTPException(
                status_code=503,
                detail="stable public path registry unavailable",
            ) from exc
        return _link_response(result)

    @admin.post("/links/{link_id}/bind-public-path")
    async def bind_public_path(
        request: Request,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        tenant, store, registry = authority()
        result = await call(store.get_link, tenant, link_id=link_id)
        bound = await run_in_threadpool(registry.bind, link_id, tenant)
        return {**bound, "stable_path": _stable_path(link_id), "link": result}

    @admin.get("/links/{link_id}")
    async def get_link(request: Request, link_id: ObjectPath) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, registry = authority()
        result = await call(store.get_link, tenant, link_id=link_id)
        registry_status: str
        try:
            await run_in_threadpool(registry.verify_binding, link_id, tenant)
            registry_status = "verified"
        except PublicLinkRegistryError:
            registry_status = "unbound_or_invalid"
        return {**_link_response(result), "public_registry_status": registry_status}

    @admin.post("/links/{link_id}/publish")
    async def publish_link(
        request: Request,
        body: PublishIn,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.publish_version,
            tenant,
            link_id=link_id,
            actor_id=actor(request),
            **body.model_dump(),
        )

    @admin.post("/links/{link_id}/rotate-capability")
    async def rotate_capability(
        request: Request,
        body: RevisionIn,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        result = await call(
            store.rotate_private_capability,
            tenant,
            link_id=link_id,
            actor_id=actor(request),
            **body.model_dump(),
        )
        return {
            **result,
            "raw_capability_persisted": False,
            "stable_path": _stable_path(link_id),
        }

    @admin.post("/links/{link_id}/revoke")
    async def revoke_link(
        request: Request,
        body: RevisionIn,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.revoke_link,
            tenant,
            link_id=link_id,
            actor_id=actor(request),
            **body.model_dump(),
        )

    @admin.post("/links/{link_id}/schedules/publication", status_code=201)
    async def schedule_publication(
        request: Request,
        body: PublicationScheduleIn,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.schedule_publication,
            tenant,
            link_id=link_id,
            scheduled_by=actor(request),
            **body.model_dump(),
        )

    @admin.post("/links/{link_id}/schedules/expiry", status_code=201)
    async def schedule_expiry(
        request: Request,
        body: ExpiryScheduleIn,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.schedule_expiry,
            tenant,
            link_id=link_id,
            scheduled_by=actor(request),
            **body.model_dump(),
        )

    @admin.post("/links/{link_id}/schedules/revocation", status_code=201)
    async def schedule_revocation(
        request: Request,
        body: RevocationScheduleIn,
        link_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.schedule_revocation,
            tenant,
            link_id=link_id,
            scheduled_by=actor(request),
            **body.model_dump(),
        )

    @admin.post("/jobs/claim")
    async def claim_jobs(request: Request, body: ClaimBatchIn) -> dict[str, Any]:
        require_global_permission(request, "operate")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        worker = _worker_id(request, actor(request))
        claims = await call(
            store.claim_due_jobs,
            tenant,
            worker_id=worker,
            **body.model_dump(),
        )
        return {
            "claims": [_claim_response(claim) for claim in claims],
            "lease_tokens_persisted_raw": False,
        }

    @admin.post("/jobs/{job_id}/apply")
    async def apply_job(
        request: Request,
        body: ClaimAuthorityIn,
        job_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "operate")
        _request_body_bound(request)
        from maverick import policy_publication_links as ops

        tenant, store, _registry = authority()
        claim = claim_from_body(ops, request, tenant, job_id, body)
        return await call(store.apply_claim, claim)

    @admin.post("/jobs/{job_id}/fail")
    async def fail_job(
        request: Request,
        body: FailClaimIn,
        job_id: ObjectPath,
    ) -> dict[str, Any]:
        require_global_permission(request, "operate")
        _request_body_bound(request)
        from maverick import policy_publication_links as ops

        tenant, store, _registry = authority()
        claim = claim_from_body(ops, request, tenant, job_id, body)
        return await call(
            store.fail_claim,
            claim,
            error_code=body.error_code,
            retryable=body.retryable,
            retry_after_seconds=body.retry_after_seconds,
        )

    @admin.post("/jobs/run-due")
    async def run_due(request: Request, body: RunDueIn) -> dict[str, Any]:
        require_global_permission(request, "operate")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        outcomes = await call(
            store.run_due_jobs,
            tenant,
            worker_id=_worker_id(request, actor(request)),
            **body.model_dump(),
        )
        return {
            "outcomes": list(outcomes),
            "network_side_effect": False,
            "live_acceptance": False,
        }

    @admin.get("/audit")
    async def audit_events(
        request: Request,
        after_sequence: int = Query(default=0, ge=0, le=2**31 - 1),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, _registry = authority()
        events = await call(
            store.list_audit,
            tenant,
            after_sequence=after_sequence,
            limit=limit,
        )
        return {"events": list(events), "bounded_limit": limit}

    @admin.get("/access")
    async def access_events(
        request: Request,
        after_sequence: int = Query(default=0, ge=0, le=2**31 - 1),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, _registry = authority()
        events = await call(
            store.list_access_events,
            tenant,
            after_sequence=after_sequence,
            limit=limit,
        )
        return {"events": list(events), "raw_capabilities_logged": False}

    @admin.post("/retention/access")
    async def purge_access(request: Request, body: RetentionIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.purge_access_events,
            tenant,
            **body.model_dump(),
        )

    @admin.post("/retention/content")
    async def purge_content(request: Request, body: RetentionIn) -> dict[str, Any]:
        require_global_permission(request, "admin")
        _request_body_bound(request)
        tenant, store, _registry = authority()
        return await call(
            store.purge_unreferenced_content,
            tenant,
            **body.model_dump(),
        )

    @admin.get("/integrity")
    async def integrity(request: Request) -> dict[str, Any]:
        require_global_permission(request, "audit")
        tenant, store, registry = authority()
        result = await call(store.verify_integrity, tenant)
        registry_result = await call(registry.verify_tenant, tenant)
        return {
            **result,
            "public_registry": registry_result,
            "local_storage_only": True,
            "live_external_acceptance": False,
        }

    @public.get("/{link_id}")
    async def retrieve_policy(
        request: Request,
        link_id: ObjectPath,
        output_format: Literal["html", "text"] = Query(
            default="html",
            alias="format",
        ),
    ) -> Response:
        from .ip_allowlist import client_ip
        # Only configured trusted proxies may supply a forwarded client. Use
        # one budget across link IDs so changing IDs cannot evade the limit.
        client = client_ip(request)
        limiter_key = hashlib.sha256(str(client or "unknown").encode()).hexdigest()
        try:
            limiter.check(limiter_key)
        except PublicPolicyRateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail="public policy rate limit reached",
                headers={"Retry-After": "60"},
            ) from exc
        capability = _bearer(request)
        try:
            registry = deps.registry_factory()
            tenant = await run_in_threadpool(registry.resolve, link_id)
            store = deps.store_for(tenant)
            result = await run_in_threadpool(
                store.retrieve,
                tenant,
                link_id=link_id,
                output_format=output_format,
                bearer_capability=capability,
                request_context_sha256=_request_context_sha256(
                    request,
                    link_id,
                    output_format,
                ),
            )
        except Exception as exc:
            from maverick import policy_publication_links as ops

            if isinstance(
                exc,
                (
                    PublicLinkRegistryError,
                    ops.PolicyPublicationAccessDenied,
                    ops.PolicyPublicationNotFound,
                    ops.PolicyPublicationValidationError,
                ),
            ):
                raise HTTPException(status_code=404, detail=_PUBLIC_DETAIL) from exc
            if isinstance(exc, ops.PolicyPublicationConfigError):
                raise HTTPException(status_code=404, detail=_PUBLIC_DETAIL) from exc
            raise HTTPException(
                status_code=503,
                detail="policy retrieval authority unavailable",
            ) from exc
        content = result.get("content")
        if not isinstance(content, str):
            raise HTTPException(
                status_code=503,
                detail="policy retrieval authority unavailable",
            )
        encoded = content.encode("utf-8")
        if len(encoded) > _MAX_PUBLIC_RESPONSE_BYTES:
            raise HTTPException(
                status_code=503,
                detail="policy response exceeds the public byte bound",
            )
        content_type = str(result.get("content_type", ""))
        expected_type = {
            "html": "text/html; charset=utf-8",
            "text": "text/plain; charset=utf-8",
        }[output_format]
        if content_type != expected_type:
            raise HTTPException(
                status_code=503,
                detail="policy retrieval authority unavailable",
            )
        etag = str(result.get("etag", ""))
        if re.fullmatch(_DIGEST_PATTERN, etag) is None:
            raise HTTPException(
                status_code=503,
                detail="policy retrieval authority unavailable",
            )
        return Response(
            content=encoded,
            media_type=expected_type,
            headers={
                "Cache-Control": "private, no-store, max-age=0",
                "Content-Security-Policy": (
                    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
                ),
                "ETag": f'"{etag}"',
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "X-Lightwork-Artifact-SHA256": str(result["artifact_sha256"]),
                "X-Lightwork-Policy-Version": str(result["version"]),
            },
        )

    return admin, public


router, public_router = create_policy_publication_routers()

__all__ = [
    "PolicyPublicationDependencies",
    "PublicLinkRegistryError",
    "PublicPolicyLinkRegistry",
    "PublicPolicyRateLimitExceeded",
    "PublicPolicyRateLimiter",
    "create_policy_publication_routers",
    "public_router",
    "router",
]
