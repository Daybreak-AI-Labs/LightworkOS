"""Deployment composition for the third-party collaboration portal.

The API module intentionally accepts only an opaque public portal reference.
This composition binds that reference to the active tenant registry with a
deployment-custodied HMAC key, constructs tenant-isolated collaboration stores,
and supplies a bounded external-request limiter.  The routing key and stores
are resolved lazily: importing or attaching this module performs no secret,
tenant-registry, configuration, or SQLite read.
"""

from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import math
import os
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from itertools import islice
from typing import Any

from fastapi import HTTPException, Request
from maverick import third_party_collaboration as collaboration
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from starlette.concurrency import run_in_threadpool

from .third_party_collaboration_api import ExternalPortalAuthority

ROUTING_KEY_ENV = "MAVERICK_THIRD_PARTY_PORTAL_ROUTING_KEY"
_PORTAL_PREFIX = "tpcp_"
_PORTAL_RE = re.compile(r"tpcp_[A-Za-z0-9_-]{43}\Z")
_CREDENTIAL_RE = re.compile(r"[0-9a-f]{64}\Z")
_EXTERNAL_PATH_RE = re.compile(
    r"/api/v1/external/third-party-collaboration/"
    r"(?P<portal>tpcp_[A-Za-z0-9_-]{43})/(?P<action>contract|draft|finalize|evidence)\Z"
)
_ACTIONS = frozenset({"contract", "draft", "finalize", "evidence"})
_MAX_ACTIVE_TENANTS = 10_000
_MAX_ROUTING_KEY_BYTES = 4_096
_ROUTING_REVISION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class ThirdPartyCollaborationCompositionError(collaboration.ThirdPartyCollaborationConfigError):
    """The deployment cannot construct a trustworthy portal authority."""


class ThirdPartyCollaborationRateLimitExceeded(HTTPException):
    """A bounded public-portal request bucket is exhausted."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(
            status_code=429,
            detail="third-party collaboration rate limit exceeded",
            headers={"Retry-After": str(max(1, retry_after))},
        )


@dataclass(frozen=True, slots=True)
class ThirdPartyCollaborationRoutingKeyring:
    """Current routing key plus a bounded explicit verification-only grace set."""

    revision: str
    current: bytes | str
    previous: tuple[bytes | str, ...] = ()


@dataclass(frozen=True, slots=True)
class ThirdPartyCollaborationRateLimitPolicy:
    """Sliding-window limits for the unauthenticated edge of the portal."""

    window_seconds: float = 60.0
    deployment_action_limit: int = 3_000
    source_action_limit: int = 180
    global_portal_action_limit: int = 600
    source_portal_action_limit: int = 60
    credential_portal_action_limit: int = 120
    max_buckets: int = 4_096

    def normalized(self) -> ThirdPartyCollaborationRateLimitPolicy:
        window = self.window_seconds
        if (
            isinstance(window, bool)
            or not isinstance(window, (int, float))
            or not 1.0 <= float(window) <= 3_600.0
        ):
            raise ThirdPartyCollaborationCompositionError(
                "portal rate-limit window is outside its bound"
            )
        limits = (
            self.deployment_action_limit,
            self.source_action_limit,
            self.global_portal_action_limit,
            self.source_portal_action_limit,
            self.credential_portal_action_limit,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1_000_000
            for value in limits
        ):
            raise ThirdPartyCollaborationCompositionError(
                "portal rate-limit ceiling is outside its bound"
            )
        if (
            isinstance(self.max_buckets, bool)
            or not isinstance(self.max_buckets, int)
            or not 5 <= self.max_buckets <= 100_000
        ):
            raise ThirdPartyCollaborationCompositionError(
                "portal rate-limit bucket bound is outside its bound"
            )
        return ThirdPartyCollaborationRateLimitPolicy(
            window_seconds=float(window),
            deployment_action_limit=self.deployment_action_limit,
            source_action_limit=self.source_action_limit,
            global_portal_action_limit=self.global_portal_action_limit,
            source_portal_action_limit=self.source_portal_action_limit,
            credential_portal_action_limit=self.credential_portal_action_limit,
            max_buckets=self.max_buckets,
        )


@dataclass(frozen=True, slots=True)
class _ExternalRequestContext:
    portal_ref: str
    path_action: str
    source_sha256: str
    portal_known: bool
    valid: bool


_REQUEST_CONTEXT: contextvars.ContextVar[_ExternalRequestContext | None] = contextvars.ContextVar(
    "third_party_collaboration_external_request_context",
    default=None,
)


def _routing_key_bytes(value: object) -> bytes:
    if isinstance(value, str):
        if value != value.strip():
            raise ThirdPartyCollaborationCompositionError(
                "portal routing key must not contain surrounding whitespace"
            )
        try:
            key = value.encode("utf-8")
        except UnicodeError as exc:
            raise ThirdPartyCollaborationCompositionError(
                "portal routing key encoding is invalid"
            ) from exc
    elif isinstance(value, bytes):
        key = value
    else:
        raise ThirdPartyCollaborationCompositionError("portal routing key authority is unavailable")
    if not 32 <= len(key) <= _MAX_ROUTING_KEY_BYTES:
        raise ThirdPartyCollaborationCompositionError(
            "portal routing key must contain between 32 and 4096 bytes"
        )
    return key


def _environment_routing_key() -> bytes:
    value = os.environ.get(ROUTING_KEY_ENV)
    if value is None:
        raise ThirdPartyCollaborationCompositionError("portal routing key authority is unavailable")
    return _routing_key_bytes(value)


# Where the dashboard keeps a rotated keyring: [third_party_portal]
# routing_keyring, sealed with the deployment key in the dashboard overlay
# (see portal_routing_key_api). Previous keys carry an "until" time.
KEYRING_SECTION = "third_party_portal"
KEYRING_KEY = "routing_keyring"
MAX_PREVIOUS_KEYS = 2


def _configured_routing_key() -> bytes | ThirdPartyCollaborationRoutingKeyring:
    """The portal routing key: MAVERICK_THIRD_PARTY_PORTAL_ROUTING_KEY wins;
    otherwise the keyring rotated on the dashboard, whose previous keys are
    still accepted for verification until their grace period ends."""
    if os.environ.get(ROUTING_KEY_ENV):
        return _environment_routing_key()
    from maverick.config import load_global_config

    section = (load_global_config() or {}).get(KEYRING_SECTION) or {}
    ring = section.get(KEYRING_KEY) if isinstance(section, dict) else None
    if not isinstance(ring, dict) or not isinstance(ring.get("current"), str):
        raise ThirdPartyCollaborationCompositionError("portal routing key authority is unavailable")
    now = time.time()
    previous = []
    for item in ring.get("previous") or []:
        until = item.get("until") if isinstance(item, dict) else None
        if (isinstance(until, (int, float)) and not isinstance(until, bool) and until > now
                and isinstance(item.get("key"), str)):
            previous.append(item["key"])
    return ThirdPartyCollaborationRoutingKeyring(
        revision=str(ring.get("revision") or ""), current=ring["current"],
        previous=tuple(previous[:MAX_PREVIOUS_KEYS]))


def _resolve_routing_key_material(
    resolver: Callable[[], bytes | str | ThirdPartyCollaborationRoutingKeyring],
) -> tuple[str, tuple[bytes, ...]]:
    if not callable(resolver):
        raise ThirdPartyCollaborationCompositionError("portal routing key resolver is unavailable")
    try:
        value = resolver()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyCollaborationCompositionError(
            "portal routing key authority is unavailable"
        ) from exc
    if isinstance(value, ThirdPartyCollaborationRoutingKeyring):
        if (
            not isinstance(value.revision, str)
            or _ROUTING_REVISION_RE.fullmatch(value.revision) is None
        ):
            raise ThirdPartyCollaborationCompositionError("portal routing key revision is invalid")
        if not isinstance(value.previous, tuple) or len(value.previous) > 2:
            raise ThirdPartyCollaborationCompositionError(
                "portal routing key grace set is outside its bound"
            )
        keys = tuple(_routing_key_bytes(item) for item in (value.current, *value.previous))
        digests = {hashlib.sha256(key).digest() for key in keys}
        if len(digests) != len(keys):
            raise ThirdPartyCollaborationCompositionError(
                "portal routing key grace set contains duplicates"
            )
        return value.revision, keys
    key = _routing_key_bytes(value)
    return hashlib.sha256(key).hexdigest(), (key,)


def _resolve_routing_key(
    resolver: Callable[[], bytes | str | ThirdPartyCollaborationRoutingKeyring],
) -> bytes:
    _revision, keys = _resolve_routing_key_material(resolver)
    return keys[0]


def derive_third_party_collaboration_portal_ref(
    tenant_id: str,
    routing_key: bytes | str,
) -> str:
    """Derive a stable opaque reference without embedding the tenant id."""

    tenant = canonical_tenant_id(tenant_id)
    key = _routing_key_bytes(routing_key)
    digest = hmac.new(
        key,
        b"lightwork.third-party-collaboration.portal-ref.v1\x00" + tenant.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"{_PORTAL_PREFIX}{encoded}"


def _default_tenant_registry() -> Iterable[Any]:
    from maverick.tenant.registry import list_tenants

    return list_tenants()


def _record(record: object) -> tuple[str, bool]:
    if isinstance(record, Mapping):
        tenant_id = record.get("id")
        active_value = record.get("active")
        if active_value is None and "status" in record:
            active_value = record.get("status") == "active"
    else:
        tenant_id = getattr(record, "id", None)
        active_value = getattr(record, "active", None)
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ThirdPartyCollaborationCompositionError("tenant registry contains an invalid record")
    if type(active_value) is not bool:
        raise ThirdPartyCollaborationCompositionError("tenant registry contains an invalid status")
    return canonical_tenant_id(tenant_id), active_value


def _active_tenants(resolver: Callable[[], Iterable[Any]]) -> tuple[str, ...]:
    if not callable(resolver):
        raise ThirdPartyCollaborationCompositionError("tenant registry authority is unavailable")
    try:
        records = resolver()
        if isinstance(records, (str, bytes, Mapping)):
            raise TypeError("tenant registry must return records")
        material = tuple(islice(iter(records), _MAX_ACTIVE_TENANTS + 1))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyCollaborationCompositionError(
            "tenant registry authority is unavailable"
        ) from exc
    if len(material) > _MAX_ACTIVE_TENANTS:
        raise ThirdPartyCollaborationCompositionError(
            "tenant registry exceeds the portal resolver bound"
        )
    active: list[str] = []
    seen: set[str] = set()
    for item in material:
        tenant, is_active = _record(item)
        if tenant in seen:
            raise ThirdPartyCollaborationCompositionError(
                "tenant registry contains duplicate identities"
            )
        seen.add(tenant)
        if is_active:
            active.append(tenant)
    return tuple(active)


def _same_tenant(left: str, right: str) -> bool:
    left_sha = hashlib.sha256(left.encode("utf-8")).digest()
    right_sha = hashlib.sha256(right.encode("utf-8")).digest()
    return hmac.compare_digest(left_sha, right_sha)


def _assert_active_tenant(
    tenant_id: str,
    registry_resolver: Callable[[], Iterable[Any]],
) -> str:
    tenant = canonical_tenant_id(tenant_id)
    matched = False
    for active in _active_tenants(registry_resolver):
        matched = _same_tenant(tenant, active) or matched
    if not matched:
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration tenant is not active"
        )
    return tenant


def _load_tenant_policy(
    tenant_id: str,
) -> collaboration.ThirdPartyCollaborationPolicy:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration configuration is unavailable"
        ) from exc
    if source_errors or not isinstance(config, Mapping):
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration configuration source is invalid"
        )
    if not collaboration.enabled(config):
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration portal is disabled"
        )
    try:
        policy = collaboration.load_policy(config)
    except collaboration.ThirdPartyCollaborationError:
        raise
    except Exception as exc:
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration policy is unavailable"
        ) from exc
    if not isinstance(policy, collaboration.ThirdPartyCollaborationPolicy):
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration policy authority is invalid"
        )
    return policy


def build_third_party_collaboration_store(
    *,
    tenant_id: str,
    principal_resolver: Callable[[], str | None],
    registry_resolver: Callable[[], Iterable[Any]] = _default_tenant_registry,
    policy: collaboration.ThirdPartyCollaborationPolicy | None = None,
) -> collaboration.ThirdPartyCollaborationStore:
    """Build one explicitly tenant-bound store from the current exact policy."""

    if not callable(principal_resolver):
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration principal authority is unavailable"
        )
    tenant = _assert_active_tenant(tenant_id, registry_resolver)
    selected_policy = policy if policy is not None else _load_tenant_policy(tenant)
    if not isinstance(selected_policy, collaboration.ThirdPartyCollaborationPolicy):
        raise ThirdPartyCollaborationCompositionError(
            "third-party collaboration policy authority is invalid"
        )

    def gate() -> None:
        _assert_active_tenant(tenant, registry_resolver)
        if _load_tenant_policy(tenant) != selected_policy:
            raise ThirdPartyCollaborationCompositionError(
                "third-party collaboration policy changed during construction"
            )

    return collaboration.ThirdPartyCollaborationStore(
        data_dir(
            "third_party_management",
            "third-party-collaboration.sqlite3",
            tenant=tenant,
        ),
        lifecycle_path=data_dir(
            "third_party_management",
            "third-party-lifecycle.sqlite3",
            tenant=tenant,
        ),
        config_gate=gate,
        principal_resolver=principal_resolver,
        policy=selected_policy,
    )


class _LazyTenantCollaborationStore:
    """Open the tenant store only inside the API's worker-thread operation."""

    def __init__(
        self,
        *,
        tenant_id: str,
        principal_resolver: Callable[[], str | None],
        registry_resolver: Callable[[], Iterable[Any]],
        builder: Callable[..., Any],
    ) -> None:
        self._tenant_id = canonical_tenant_id(tenant_id)
        self._principal_resolver = principal_resolver
        self._registry_resolver = registry_resolver
        self._builder = builder
        self._store: Any | None = None
        self._store_policy: collaboration.ThirdPartyCollaborationPolicy | None = None
        self._lock = threading.Lock()

    def _authority(self) -> Any:
        _assert_active_tenant(self._tenant_id, self._registry_resolver)
        policy = _load_tenant_policy(self._tenant_id)
        if self._store is not None and self._store_policy == policy:
            return self._store
        with self._lock:
            policy = _load_tenant_policy(self._tenant_id)
            if self._store is None or self._store_policy != policy:
                self._store = self._builder(
                    tenant_id=self._tenant_id,
                    principal_resolver=self._principal_resolver,
                    registry_resolver=self._registry_resolver,
                    policy=policy,
                )
                self._store_policy = policy
        return self._store

    def _invoke(self, operation: str, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        tenant = canonical_tenant_id(tenant_id)
        if not _same_tenant(tenant, self._tenant_id):
            raise collaboration.ThirdPartyCollaborationPermissionDenied(
                "collaboration tenant authority changed"
            )
        function = getattr(self._authority(), operation, None)
        if not callable(function):
            raise ThirdPartyCollaborationCompositionError(
                "third-party collaboration store contract is unavailable"
            )
        return function(self._tenant_id, *args, **kwargs)

    def issue_invitation(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("issue_invitation", tenant_id, *args, **kwargs)

    def get_invitation(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("get_invitation", tenant_id, *args, **kwargs)

    def list_invitations(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("list_invitations", tenant_id, *args, **kwargs)

    def rotate_invitation(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("rotate_invitation", tenant_id, *args, **kwargs)

    def revoke_invitation(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("revoke_invitation", tenant_id, *args, **kwargs)

    def request_follow_up(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("request_follow_up", tenant_id, *args, **kwargs)

    def reopen_follow_up(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("reopen_follow_up", tenant_id, *args, **kwargs)

    def set_legal_hold(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("set_legal_hold", tenant_id, *args, **kwargs)

    def purge_expired(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("purge_expired", tenant_id, *args, **kwargs)

    def verify_integrity(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("verify_integrity", tenant_id, *args, **kwargs)

    def contract_for_token(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("contract_for_token", tenant_id, *args, **kwargs)

    def save_draft(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("save_draft", tenant_id, *args, **kwargs)

    def finalize_submission(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("finalize_submission", tenant_id, *args, **kwargs)

    def measure_evidence(self, tenant_id: str, *args: Any, **kwargs: Any) -> Any:
        return self._invoke("measure_evidence", tenant_id, *args, **kwargs)


class ThirdPartyCollaborationExternalRateLimiter:
    """Bounded source/global/credential sliding-window portal limiter."""

    def __init__(
        self,
        *,
        policy: ThirdPartyCollaborationRateLimitPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
        trusted_client_address_resolver: Callable[[Request], str] | None = None,
        portal_ref_validator: Callable[[str], bool] | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("rate-limit clock must be callable")
        if trusted_client_address_resolver is not None and not callable(
            trusted_client_address_resolver
        ):
            raise TypeError("trusted client-address resolver must be callable")
        if portal_ref_validator is not None and not callable(portal_ref_validator):
            raise TypeError("portal-ref validator must be callable")
        self._policy = (policy or ThirdPartyCollaborationRateLimitPolicy()).normalized()
        self._clock = clock
        self._trusted_client_address_resolver = trusted_client_address_resolver
        self._portal_ref_validator = portal_ref_validator
        self._buckets: OrderedDict[tuple[str, ...], deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)

    def _source(self, request: Request) -> str:
        resolver = self._trusted_client_address_resolver
        if resolver is None:
            client = request.client
            value = client.host if client is not None else "unavailable"
        else:
            try:
                value = resolver(request)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise ThirdPartyCollaborationRateLimitExceeded(1) from exc
        if not isinstance(value, str) or not value or value != value.strip() or len(value) > 255:
            raise ThirdPartyCollaborationRateLimitExceeded(1)
        return value

    def prepare_request_context(self, request: Request) -> _ExternalRequestContext | None:
        """Resolve bounded peer/routing metadata; middleware runs this off-loop."""

        match = _EXTERNAL_PATH_RE.fullmatch(request.url.path)
        if match is None:
            return None
        valid = True
        try:
            source = self._source(request)
        except ThirdPartyCollaborationRateLimitExceeded:
            source = "unavailable"
            valid = False
        source_sha256 = hashlib.sha256(
            b"lightwork.third-party-collaboration.source.v1\x00" + source.encode("utf-8")
        ).hexdigest()
        portal_ref = match.group("portal")
        validator = self._portal_ref_validator
        try:
            portal_known = True if validator is None else validator(portal_ref) is True
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            portal_known = False
        return _ExternalRequestContext(
            portal_ref=portal_ref,
            path_action=match.group("action"),
            source_sha256=source_sha256,
            portal_known=portal_known,
            valid=valid,
        )

    def request_context(self, request: Request):
        """Synchronous helper for non-ASGI adapters and focused tests."""

        return _BoundRequestContext(self.prepare_request_context(request))

    def _prune(self, now: float) -> None:
        cutoff = now - self._policy.window_seconds
        empty: list[tuple[str, ...]] = []
        for key, events in self._buckets.items():
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                empty.append(key)
        for key in empty:
            self._buckets.pop(key, None)

    def __call__(self, credential_sha256: str, action: str) -> None:
        if (
            not isinstance(credential_sha256, str)
            or _CREDENTIAL_RE.fullmatch(credential_sha256) is None
        ):
            raise ThirdPartyCollaborationRateLimitExceeded(1)
        context = _REQUEST_CONTEXT.get()
        if (
            context is None
            or not context.valid
            or action not in _ACTIONS
            or context.path_action != action
            or _PORTAL_RE.fullmatch(context.portal_ref) is None
        ):
            raise ThirdPartyCollaborationRateLimitExceeded(1)
        try:
            raw_now = self._clock()
            if isinstance(raw_now, bool):
                raise TypeError("rate-limit clock returned a boolean")
            now = float(raw_now)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ThirdPartyCollaborationRateLimitExceeded(1) from exc
        if not math.isfinite(now):
            raise ThirdPartyCollaborationRateLimitExceeded(1)
        known_portal = context.portal_known
        base_keys_and_limits = (
            (
                ("deployment", action),
                self._policy.deployment_action_limit,
            ),
            (
                ("source-deployment", context.source_sha256, action),
                self._policy.source_action_limit,
            ),
        )
        portal_keys_and_limits = (
            (
                ("global", context.portal_ref, action),
                self._policy.global_portal_action_limit,
            ),
            (
                ("source", context.source_sha256, context.portal_ref, action),
                self._policy.source_portal_action_limit,
            ),
            (
                ("credential", credential_sha256, context.portal_ref, action),
                self._policy.credential_portal_action_limit,
            ),
        )
        keys_and_limits = (
            base_keys_and_limits + portal_keys_and_limits if known_portal else base_keys_and_limits
        )
        with self._lock:
            self._prune(now)
            retry_after = 1
            for key, limit in keys_and_limits:
                events = self._buckets.get(key)
                if events is not None and len(events) >= limit:
                    retry_after = max(
                        1,
                        math.ceil(events[0] + self._policy.window_seconds - now),
                    )
                    raise ThirdPartyCollaborationRateLimitExceeded(retry_after)
            new_keys = sum(key not in self._buckets for key, _limit in keys_and_limits)
            if len(self._buckets) + new_keys > self._policy.max_buckets:
                raise ThirdPartyCollaborationRateLimitExceeded(int(self._policy.window_seconds))
            for key, _limit in keys_and_limits:
                events = self._buckets.setdefault(key, deque())
                events.append(now)
                self._buckets.move_to_end(key)


class _BoundRequestContext:
    def __init__(self, context: _ExternalRequestContext | None) -> None:
        self._context = context
        self._token: contextvars.Token[_ExternalRequestContext | None] | None = None

    def __enter__(self) -> None:
        self._token = _REQUEST_CONTEXT.set(self._context)

    def __exit__(self, *_args: Any) -> None:
        if self._token is not None:
            _REQUEST_CONTEXT.reset(self._token)


class ThirdPartyCollaborationRateLimitContextMiddleware:
    """Bind trusted ASGI peer metadata without trusting forwarding headers."""

    def __init__(
        self,
        app: Any,
        *,
        limiter: ThirdPartyCollaborationExternalRateLimiter,
    ) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        context = await run_in_threadpool(self.limiter.prepare_request_context, request)
        with _BoundRequestContext(context):
            await self.app(scope, receive, send)


class _PortalRoutingAuthority:
    """Short-lived active-roster index with bounded tenant-store reuse."""

    def __init__(
        self,
        *,
        routing_key_resolver: Callable[[], bytes | str | ThirdPartyCollaborationRoutingKeyring],
        registry_resolver: Callable[[], Iterable[Any]],
        store_builder: Callable[..., Any],
        clock: Callable[[], float] = time.monotonic,
        cache_seconds: float = 5.0,
        max_cached_stores: int = 1_024,
    ) -> None:
        if not callable(clock):
            raise TypeError("portal routing clock must be callable")
        if (
            isinstance(cache_seconds, bool)
            or not isinstance(cache_seconds, (int, float))
            or not 0.1 <= float(cache_seconds) <= 60.0
        ):
            raise TypeError("portal routing cache lifetime is outside its bound")
        if (
            isinstance(max_cached_stores, bool)
            or not isinstance(max_cached_stores, int)
            or not 1 <= max_cached_stores <= _MAX_ACTIVE_TENANTS
        ):
            raise TypeError("portal store-cache bound is outside its bound")
        self._routing_key_resolver = routing_key_resolver
        self._registry_resolver = registry_resolver
        self._store_builder = store_builder
        self._clock = clock
        self._cache_seconds = float(cache_seconds)
        self._max_cached_stores = max_cached_stores
        self._key_revision_sha256 = ""
        self._keys: tuple[bytes, ...] = ()
        self._expires_at = 0.0
        self._portal_index: dict[str, str] = {}
        self._stores: OrderedDict[str, _LazyTenantCollaborationStore] = OrderedDict()
        self._lock = threading.RLock()

    def _now(self) -> float:
        try:
            raw = self._clock()
            if isinstance(raw, bool):
                raise TypeError("portal routing clock returned a boolean")
            value = float(raw)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ThirdPartyCollaborationCompositionError(
                "portal routing clock is unavailable"
            ) from exc
        if not math.isfinite(value):
            raise ThirdPartyCollaborationCompositionError("portal routing clock is unavailable")
        return value

    def _snapshot(self) -> tuple[tuple[bytes, ...], dict[str, str]]:
        revision, keys = _resolve_routing_key_material(self._routing_key_resolver)
        revision_sha256 = hashlib.sha256(
            revision.encode("utf-8")
            + b"\x00"
            + b"".join(hashlib.sha256(key).digest() for key in keys)
        ).hexdigest()
        now = self._now()
        with self._lock:
            if revision_sha256 == self._key_revision_sha256 and now < self._expires_at:
                return self._keys, self._portal_index
            tenants = _active_tenants(self._registry_resolver)
            portal_index: dict[str, str] = {}
            for tenant in tenants:
                for key in keys:
                    portal_ref = derive_third_party_collaboration_portal_ref(tenant, key)
                    if portal_ref in portal_index:
                        raise ThirdPartyCollaborationCompositionError(
                            "portal routing authority contains a collision"
                        )
                    portal_index[portal_ref] = tenant
            active = set(tenants)
            for tenant in tuple(self._stores):
                if tenant not in active:
                    self._stores.pop(tenant, None)
            self._keys = keys
            self._key_revision_sha256 = revision_sha256
            self._portal_index = portal_index
            self._expires_at = now + self._cache_seconds
            return self._keys, self._portal_index

    def _tenant_for_ref(self, portal_ref: str) -> str | None:
        if not isinstance(portal_ref, str) or _PORTAL_RE.fullmatch(portal_ref) is None:
            return None
        keys, portal_index = self._snapshot()
        tenant = portal_index.get(portal_ref)
        if tenant is None:
            return None
        matched = False
        for key in keys:
            expected = derive_third_party_collaboration_portal_ref(tenant, key)
            matched = hmac.compare_digest(portal_ref, expected) or matched
        return tenant if matched else None

    def is_active_ref(self, portal_ref: str) -> bool:
        return self._tenant_for_ref(portal_ref) is not None

    def resolve(self, portal_ref: str, _request: Request) -> ExternalPortalAuthority:
        tenant = self._tenant_for_ref(portal_ref)
        if tenant is None:
            raise ThirdPartyCollaborationCompositionError(
                "third-party collaboration portal is unavailable"
            )
        with self._lock:
            store = self._stores.get(tenant)
            if store is None:
                if len(self._stores) >= self._max_cached_stores:
                    self._stores.popitem(last=False)
                store = _LazyTenantCollaborationStore(
                    tenant_id=tenant,
                    principal_resolver=lambda: "portal-authority",
                    registry_resolver=self._registry_resolver,
                    builder=self._store_builder,
                )
                self._stores[tenant] = store
            self._stores.move_to_end(tenant)
        return ExternalPortalAuthority(tenant_id=tenant, store=store)


def _state_callable(state: Any, name: str, label: str) -> Callable[..., Any] | None:
    value = getattr(state, name, None)
    if value is not None and not callable(value):
        raise TypeError(f"{label} must be callable")
    return value


def _selected_callable(
    *,
    explicit: Callable[..., Any] | None,
    state: Any,
    name: str,
    default: Callable[..., Any] | None,
    label: str,
) -> Callable[..., Any] | None:
    injected = _state_callable(state, name, label)
    if explicit is not None:
        if not callable(explicit):
            raise TypeError(f"{label} must be callable")
        return explicit
    return injected if injected is not None else default


def attach_third_party_collaboration_composition(
    app: Any,
    *,
    routing_key_resolver: Callable[[], bytes | str | ThirdPartyCollaborationRoutingKeyring]
    | None = None,
    tenant_registry_resolver: Callable[[], Iterable[Any]] | None = None,
    trusted_client_address_resolver: Callable[[Request], str] | None = None,
    rate_limit_policy: ThirdPartyCollaborationRateLimitPolicy | None = None,
    rate_limit_clock: Callable[[], float] = time.monotonic,
    routing_clock: Callable[[], float] = time.monotonic,
    routing_cache_seconds: float = 5.0,
    max_cached_external_stores: int = 1_024,
    store_builder: Callable[..., Any] = build_third_party_collaboration_store,
) -> None:
    """Install lazy tenant stores, opaque routing, and bounded edge limiting."""

    state = getattr(app, "state", None)
    if state is None:
        raise TypeError("app must expose state")
    if not callable(store_builder):
        raise TypeError("third-party collaboration store builder must be callable")

    key_resolver = _selected_callable(
        explicit=routing_key_resolver,
        state=state,
        name="third_party_collaboration_routing_key_resolver",
        default=_configured_routing_key,
        label="third-party collaboration routing-key resolver",
    )
    registry_resolver = _selected_callable(
        explicit=tenant_registry_resolver,
        state=state,
        name="third_party_collaboration_tenant_registry_resolver",
        default=_default_tenant_registry,
        label="third-party collaboration tenant registry",
    )
    client_address_resolver = _selected_callable(
        explicit=trusted_client_address_resolver,
        state=state,
        name="third_party_collaboration_trusted_client_address_resolver",
        default=None,
        label="trusted client-address resolver",
    )
    if key_resolver is None or registry_resolver is None:
        raise TypeError("third-party collaboration deployment resolver is unavailable")

    def ref_for_tenant(tenant_id: str) -> str:
        tenant = _assert_active_tenant(tenant_id, registry_resolver)
        _load_tenant_policy(tenant)
        return derive_third_party_collaboration_portal_ref(
            tenant,
            _resolve_routing_key(key_resolver),
        )

    def current_portal_ref() -> str:
        from maverick.paths import current_tenant_id_strict

        tenant = current_tenant_id_strict()
        if tenant is None:
            raise ThirdPartyCollaborationCompositionError(
                "select an active tenant before resolving the portal reference"
            )
        return ref_for_tenant(tenant)

    existing_store_factory = _state_callable(
        state,
        "third_party_collaboration_store_factory",
        "third-party collaboration store factory",
    )
    if existing_store_factory is None:

        def store_factory(
            *,
            tenant_id: str,
            principal_ref: str,
            principal_resolver: Callable[[], str | None],
            **_unused: Any,
        ) -> _LazyTenantCollaborationStore:
            if not isinstance(principal_ref, str) or not principal_ref:
                raise ThirdPartyCollaborationCompositionError(
                    "third-party collaboration principal authority is unavailable"
                )
            if not callable(principal_resolver) or principal_resolver() != principal_ref:
                raise ThirdPartyCollaborationCompositionError(
                    "third-party collaboration principal authority changed"
                )
            tenant = _assert_active_tenant(tenant_id, registry_resolver)
            _load_tenant_policy(tenant)

            def pinned_principal() -> str | None:
                current = principal_resolver()
                return principal_ref if current == principal_ref else None

            return _LazyTenantCollaborationStore(
                tenant_id=tenant,
                principal_resolver=pinned_principal,
                registry_resolver=registry_resolver,
                builder=store_builder,
            )

        state.third_party_collaboration_store_factory = store_factory

    existing_portal_resolver = _state_callable(
        state,
        "third_party_collaboration_portal_resolver",
        "third-party collaboration portal resolver",
    )
    routing_authority = getattr(
        state,
        "third_party_collaboration_routing_authority",
        None,
    )
    if routing_authority is None:
        routing_authority = _PortalRoutingAuthority(
            routing_key_resolver=key_resolver,
            registry_resolver=registry_resolver,
            store_builder=store_builder,
            clock=routing_clock,
            cache_seconds=routing_cache_seconds,
            max_cached_stores=max_cached_external_stores,
        )
        state.third_party_collaboration_routing_authority = routing_authority
    elif not isinstance(routing_authority, _PortalRoutingAuthority):
        raise TypeError("third-party collaboration routing authority is invalid")
    if existing_portal_resolver is None:
        state.third_party_collaboration_portal_resolver = routing_authority.resolve
    existing_ref_resolver = _state_callable(
        state,
        "third_party_collaboration_portal_ref_for_tenant",
        "third-party collaboration portal-ref resolver",
    )
    if existing_ref_resolver is None:
        state.third_party_collaboration_portal_ref_for_tenant = ref_for_tenant
    existing_current_ref = _state_callable(
        state,
        "third_party_collaboration_current_portal_ref",
        "third-party collaboration current portal-ref resolver",
    )
    if existing_current_ref is None:
        state.third_party_collaboration_current_portal_ref = current_portal_ref

    limiter = _state_callable(
        state,
        "third_party_collaboration_rate_limit",
        "third-party collaboration rate limiter",
    )
    if limiter is None:
        limiter = ThirdPartyCollaborationExternalRateLimiter(
            policy=rate_limit_policy,
            clock=rate_limit_clock,
            trusted_client_address_resolver=client_address_resolver,
            portal_ref_validator=routing_authority.is_active_ref,
        )
        state.third_party_collaboration_rate_limit = limiter
    if isinstance(limiter, ThirdPartyCollaborationExternalRateLimiter) and not getattr(
        state,
        "third_party_collaboration_rate_limit_context_attached",
        False,
    ):
        add_middleware = getattr(app, "add_middleware", None)
        if not callable(add_middleware):
            raise TypeError("app must support ASGI middleware")
        add_middleware(
            ThirdPartyCollaborationRateLimitContextMiddleware,
            limiter=limiter,
        )
        state.third_party_collaboration_rate_limit_context_attached = True


__all__ = [
    "ROUTING_KEY_ENV",
    "ThirdPartyCollaborationCompositionError",
    "ThirdPartyCollaborationExternalRateLimiter",
    "ThirdPartyCollaborationRateLimitContextMiddleware",
    "ThirdPartyCollaborationRateLimitExceeded",
    "ThirdPartyCollaborationRateLimitPolicy",
    "ThirdPartyCollaborationRoutingKeyring",
    "attach_third_party_collaboration_composition",
    "build_third_party_collaboration_store",
    "derive_third_party_collaboration_portal_ref",
]
