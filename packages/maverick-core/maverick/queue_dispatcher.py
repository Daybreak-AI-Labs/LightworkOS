"""Authenticated queue-backed goal dispatch.

``QueueDispatcher`` is the control-plane/data-plane split for goal execution.
Every dispatch is a versioned, expiring envelope whose HMAC covers the complete
security context: goal/conversation ids and cost limits, depth, channel/user identity,
concurrency principal, capability, tenant, message id, nonce, and timestamps.
Workers authenticate and validate the immutable envelope snapshot before they
interpret any of those fields.

There are deliberately two transport modes:

* ``local`` (the backwards-compatible constructor default) uses a random
  process-only key.  It works for injected in-memory/SQLite test brokers in the
  same process, but an envelope that crosses a process boundary cannot verify.
* ``network`` requires a >= 32-byte ``MAVERICK_QUEUE_SIGNING_KEY`` (or
  ``[queue] signing_key``) shared by the producer and workers.  Network jobs
  must also carry an explicit tenant and are durably consumed before dispatch.

The durable consume is intentionally at-most-once.  A crash after the claim
burns that envelope; an operator must submit a fresh signed job to retry.  This
prefers preventing duplicate spend/side effects over automatic replay.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlsplit

from .constant_time import text_equals

if TYPE_CHECKING:
    from .runner import DispatchObservation, ExecutionHandle

log = logging.getLogger(__name__)

JOB_NAME = "maverick.run_goal"
QUEUED_STATUS = "queued"

ENVELOPE_VERSION = 2
_AUTH_LOCAL = "local-process"
_AUTH_SHARED = "shared-hmac"
_QUEUE_SIG_FIELD = "sig"
_LOCAL_SIGNING_KEY = secrets.token_bytes(32)
_MIN_NETWORK_KEY_BYTES = 32
_DEFAULT_ENVELOPE_TTL_SECONDS = 15 * 60
_MAX_ENVELOPE_TTL_SECONDS = 24 * 60 * 60
_MAX_FUTURE_SKEW_SECONDS = 60
_MAX_ENVELOPE_BYTES = 128 * 1024
_MAX_ARQ_CODEC_BYTES = 192 * 1024
_MAX_ARQ_JSON_DEPTH = 32
_MAX_ARQ_JSON_NODES = 20_000
_ARQ_CODEC_PREFIX = b"maverick-arq-json-v1\n"
_MAX_TEXT_BYTES = 4096
_MAX_ALLOWED_SUITES = 256
_NETWORK_CLAIM_CHANNEL = "maverick.queue.dispatch.v1"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_HEX_SIG_RE = re.compile(r"^[0-9a-f]{64}$")
_QUEUE_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

_ENVELOPE_FIELDS = frozenset(
    {
        "version",
        "job_name",
        "auth_mode",
        "message_id",
        "nonce",
        "issued_at",
        "expires_at",
        "tenant",
        "goal_id",
        "conversation_id",
        "max_dollars",
        "max_wall_seconds",
        "max_depth",
        "channel",
        "user_id",
        "capability",
        "concurrency_principal",
        "allowed_suites",
        _QUEUE_SIG_FIELD,
    }
)


class QueueSecurityError(RuntimeError):
    """An authenticated queue boundary requirement was not satisfied."""


class QueueReplayError(QueueSecurityError):
    """A network dispatch envelope was already consumed."""


def _queue_signing_key() -> str | None:
    """Return the configured shared queue key without ever logging it."""
    env = os.environ.get("MAVERICK_QUEUE_SIGNING_KEY", "").strip()
    if env:
        return env
    try:
        from .config import load_config

        value = ((load_config() or {}).get("queue") or {}).get("signing_key")
        return str(value).strip() or None if value else None
    except Exception:  # pragma: no cover - config lookup never weakens checks
        return None


def _require_network_signing_key() -> str:
    key = _queue_signing_key()
    if not key:
        raise QueueSecurityError(
            "network queue dispatch requires MAVERICK_QUEUE_SIGNING_KEY "
            "(or [queue] signing_key) on producers and workers"
        )
    if len(key.encode("utf-8")) < _MIN_NETWORK_KEY_BYTES:
        raise QueueSecurityError(
            "network queue signing key must contain at least 32 UTF-8 bytes"
        )
    return key


def _require_network_claim_store_configured() -> None:
    from .world_model_backends import is_postgres_configured

    if not is_postgres_configured():
        raise QueueSecurityError(
            "network queue dispatch requires the shared Postgres world model "
            "for fleet-wide at-most-once claims"
        )


def _configured_envelope_ttl_seconds() -> int:
    raw: Any = os.environ.get("MAVERICK_QUEUE_ENVELOPE_TTL_SECONDS", "").strip()
    if not raw:
        try:
            from .config import load_config

            raw = ((load_config() or {}).get("queue") or {}).get(
                "envelope_ttl_seconds"
            )
        except Exception:  # pragma: no cover - use the safe default
            raw = None
    if raw in (None, ""):
        return _DEFAULT_ENVELOPE_TTL_SECONDS
    try:
        ttl = int(raw)
    except (TypeError, ValueError) as exc:
        raise QueueSecurityError("queue envelope TTL must be an integer") from exc
    if not 1 <= ttl <= _MAX_ENVELOPE_TTL_SECONDS:
        raise QueueSecurityError(
            "queue envelope TTL must be between 1 and 86400 seconds"
        )
    return ttl


def _key_bytes(key: str | bytes) -> bytes:
    return key if isinstance(key, bytes) else key.encode("utf-8")


def _canonical_body(payload: dict[str, Any]) -> bytes:
    body = {key: value for key, value in payload.items() if key != _QUEUE_SIG_FIELD}
    try:
        encoded = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise QueueSecurityError("queue envelope is not canonical JSON") from exc
    if len(encoded) > _MAX_ENVELOPE_BYTES:
        raise QueueSecurityError("queue envelope exceeds the 128 KiB limit")
    return encoded


def _envelope_sig(payload: dict[str, Any], key: str | bytes) -> str:
    return hmac.new(_key_bytes(key), _canonical_body(payload), hashlib.sha256).hexdigest()


def _sign_envelope(payload: dict[str, Any], key: str | bytes) -> dict[str, Any]:
    signed = dict(payload)
    signed[_QUEUE_SIG_FIELD] = _envelope_sig(signed, key)
    return signed


def _snapshot_payload(raw: Any) -> dict[str, Any]:
    """Take a bounded JSON snapshot so verification and use cannot race."""
    if not isinstance(raw, dict):
        raise QueueSecurityError("queued dispatch envelope must be a mapping")
    try:
        wire = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise QueueSecurityError("queued dispatch envelope is not valid JSON") from exc
    if len(wire) > _MAX_ENVELOPE_BYTES:
        raise QueueSecurityError("queue envelope exceeds the 128 KiB limit")
    try:
        snapshot = json.loads(wire.decode("utf-8"))
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise QueueSecurityError("queued dispatch envelope is not valid JSON") from exc
    if not isinstance(snapshot, dict):  # defensive; JSON object above guarantees it
        raise QueueSecurityError("queued dispatch envelope must be an object")
    return snapshot


def _capability_sig(payload: dict[str, Any], key: str | bytes) -> str:
    """HMAC a standalone capability grant (also used by the gRPC path)."""
    body = {k: payload[k] for k in sorted(payload) if k != _QUEUE_SIG_FIELD}
    msg = json.dumps(
        body, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hmac.new(_key_bytes(key), msg, hashlib.sha256).hexdigest()


def _serialize_capability(
    capability: Any | None,
    *,
    signing_key: str | bytes | None = None,
) -> dict[str, Any] | None:
    """Return a JSON-safe representation of an explicit capability grant."""
    if capability is None:
        return None

    from .capability import Capability

    if not isinstance(capability, Capability):
        raise TypeError(
            "queue dispatch requires capability to be a maverick.capability.Capability"
        )
    payload = {
        "principal": capability.principal,
        "allow_tools": sorted(capability.allow_tools),
        "deny_tools": sorted(capability.deny_tools),
        "max_risk": capability.max_risk,
        "expires_at": capability.expires_at,
        "allow_paths": sorted(capability.allow_paths),
        "allow_hosts": sorted(capability.allow_hosts),
    }
    if capability.ancestors:
        payload["ancestors"] = list(capability.ancestors)
    key = _queue_signing_key() if signing_key is None else signing_key
    if key:
        payload[_QUEUE_SIG_FIELD] = _capability_sig(payload, key)
    return payload


def _validate_capability_payload(raw: Any, *, require_sig: bool) -> None:
    if not isinstance(raw, dict):
        raise QueueSecurityError("queued capability payload must be an object")
    required = {
        "principal",
        "allow_tools",
        "deny_tools",
        "max_risk",
        "expires_at",
        "allow_paths",
        "allow_hosts",
    }
    optional = {"ancestors", _QUEUE_SIG_FIELD}
    if not required <= set(raw) or set(raw) - required - optional:
        raise QueueSecurityError("queued capability fields are missing or invalid")
    principal = raw["principal"]
    if (
        not isinstance(principal, str)
        or not principal.strip()
        or len(principal.encode("utf-8")) > _MAX_TEXT_BYTES
    ):
        raise QueueSecurityError("queued capability principal is invalid")
    for field in (
        "allow_tools",
        "deny_tools",
        "allow_paths",
        "allow_hosts",
        "ancestors",
    ):
        values = raw.get(field, [])
        if (
            not isinstance(values, list)
            or len(values) > 4096
            or any(
                not isinstance(item, str)
                or "\x00" in item
                or len(item.encode("utf-8")) > _MAX_TEXT_BYTES
                for item in values
            )
        ):
            raise QueueSecurityError(f"queued capability {field} is invalid")
    max_risk = raw["max_risk"]
    if max_risk is not None and not isinstance(max_risk, str):
        raise QueueSecurityError("queued capability max_risk is invalid")
    expires_at = raw["expires_at"]
    if expires_at is not None and (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(float(expires_at))
    ):
        raise QueueSecurityError("queued capability expiry is invalid")
    sig = raw.get(_QUEUE_SIG_FIELD)
    if require_sig and (
        not isinstance(sig, str) or _HEX_SIG_RE.fullmatch(sig) is None
    ):
        raise QueueSecurityError("queued capability signature is missing or invalid")


def _deserialize_capability(
    raw: Any,
    *,
    signing_key: str | bytes | None = None,
) -> Any | None:
    """Rehydrate and independently authenticate a capability grant."""
    if raw is None:
        return None
    key = _queue_signing_key() if signing_key is None else signing_key
    _validate_capability_payload(raw, require_sig=key is not None)
    if key:
        sig = raw.get(_QUEUE_SIG_FIELD)
        expected = _capability_sig(raw, key)
        if not (isinstance(sig, str) and hmac.compare_digest(sig, expected)):
            raise QueueSecurityError(
                "queued capability signature missing or invalid; refusing grant"
            )

    from .capability import Capability

    try:
        return Capability(
            principal=raw["principal"],
            allow_tools=frozenset(raw["allow_tools"]),
            deny_tools=frozenset(raw["deny_tools"]),
            max_risk=raw["max_risk"],
            expires_at=raw["expires_at"],
            allow_paths=frozenset(raw["allow_paths"]),
            allow_hosts=frozenset(raw["allow_hosts"]),
            ancestors=tuple(raw.get("ancestors") or ()),
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise QueueSecurityError("queued capability is invalid") from exc


def _worker_capability(
    capability: Any | None,
    *,
    channel: str | None = None,
    user_id: str | None = None,
) -> Any | None:
    """Attenuate the authenticated grant by this worker's local policy."""
    from .capability import capability_enforced, capability_from_config

    if not capability_enforced():
        return capability
    local = capability_from_config(
        principal=f"user:{user_id or 'local'}", channel=channel, user_id=user_id
    )
    # The producer is not allowed to disable an enabled worker policy by
    # omitting the optional grant. An absent grant means "apply the worker's
    # configured ceiling", not "run unrestricted". An explicit grant can only
    # narrow that ceiling further.
    if capability is None:
        return local
    return local.intersect(capability, principal=local.principal)


def _configured_worker_ceilings() -> tuple[float | None, float | None, int]:
    """Return worker-local budget/depth ceilings independent of producers."""
    from .runner import (
        DEFAULT_MAX_DEPTH,
        configured_goal_ceiling_dollars,
        configured_goal_ceiling_wall_seconds,
    )

    cfg = _queue_redis_config()

    def _float_limit(
        env_name: str, config_name: str, default: float | None,
    ) -> float | None:
        raw: Any = os.environ.get(env_name)
        if raw is None or not raw.strip():
            raw = cfg.get(config_name, default)
        if raw is None:
            return None
        if isinstance(raw, bool):
            raise QueueSecurityError(f"queue worker {config_name} is invalid")
        try:
            value = float(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise QueueSecurityError(f"queue worker {config_name} is invalid") from exc
        if not math.isfinite(value) or value < 0:
            raise QueueSecurityError(f"queue worker {config_name} is invalid")
        return value

    dollars = _float_limit(
        "MAVERICK_QUEUE_WORKER_MAX_DOLLARS",
        "worker_max_dollars",
        configured_goal_ceiling_dollars(),
    )
    wall = _float_limit(
        "MAVERICK_QUEUE_WORKER_MAX_WALL_SECONDS",
        "worker_max_wall_seconds",
        configured_goal_ceiling_wall_seconds(),
    )
    depth_raw: Any = os.environ.get("MAVERICK_QUEUE_WORKER_MAX_DEPTH")
    if depth_raw is None or not depth_raw.strip():
        depth_raw = cfg.get("worker_max_depth", DEFAULT_MAX_DEPTH)
    try:
        depth = int(depth_raw)
    except (TypeError, ValueError, OverflowError) as exc:
        raise QueueSecurityError("queue worker worker_max_depth is invalid") from exc
    if isinstance(depth_raw, bool) or not 1 <= depth <= 64:
        raise QueueSecurityError("queue worker worker_max_depth is invalid")
    return dollars, wall, depth


def _worker_execution_limits(
    envelope: dict[str, Any],
) -> tuple[float | None, float | None, int]:
    from .runner import clamp_task_limit

    dollars_ceiling, wall_ceiling, depth_ceiling = _configured_worker_ceilings()
    requested_dollars = envelope["max_dollars"]
    requested_wall = envelope["max_wall_seconds"]
    return (
        clamp_task_limit(requested_dollars, dollars_ceiling),
        clamp_task_limit(requested_wall, wall_ceiling),
        min(depth_ceiling, envelope["max_depth"]),
    )


def _valid_optional_text(value: Any, field: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise QueueSecurityError(f"queue envelope {field} must be a string or null")
    if "\x00" in value or len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise QueueSecurityError(f"queue envelope {field} is invalid or too long")


def _valid_optional_number(value: Any, field: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QueueSecurityError(f"queue envelope {field} must be numeric or null")
    if not math.isfinite(float(value)) or float(value) < 0:
        raise QueueSecurityError(f"queue envelope {field} must be finite and non-negative")


def _valid_optional_positive_int(value: Any, field: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise QueueSecurityError(
            f"queue envelope {field} must be a positive integer or null"
        )


def _valid_allowed_suites(value: Any) -> None:
    """Validate the tri-state department grant in its canonical wire form.

    ``None`` means unrestricted, while ``[]`` means deny every department.
    A sorted, duplicate-free list is required so every grant has exactly one
    signed representation and workers never broaden malformed input while
    coercing it to a set.
    """
    if value is None:
        return
    if not isinstance(value, list) or len(value) > _MAX_ALLOWED_SUITES:
        raise QueueSecurityError(
            "queue envelope allowed_suites must be null or a bounded list"
        )
    if any(
        not isinstance(suite, str)
        or not suite
        or "\x00" in suite
        or len(suite.encode("utf-8")) > _MAX_TEXT_BYTES
        for suite in value
    ):
        raise QueueSecurityError("queue envelope allowed_suites entries are invalid")
    if value != sorted(set(value)):
        raise QueueSecurityError("queue envelope allowed_suites is not canonical")

    from .suite_grants import known_suites

    if not set(value) <= known_suites():
        raise QueueSecurityError("queue envelope allowed_suites contains an unknown suite")


def _validate_envelope(payload: dict[str, Any], *, now: float | None = None) -> None:
    if frozenset(payload) != _ENVELOPE_FIELDS:
        raise QueueSecurityError("queue envelope fields do not match version 2")
    if payload["version"] != ENVELOPE_VERSION:
        raise QueueSecurityError("unsupported queue envelope version")
    if payload["job_name"] != JOB_NAME:
        raise QueueSecurityError("queue envelope job name is invalid")
    if payload["auth_mode"] not in {_AUTH_LOCAL, _AUTH_SHARED}:
        raise QueueSecurityError("queue envelope auth mode is invalid")
    if not isinstance(payload["sig"], str) or not _HEX_SIG_RE.fullmatch(payload["sig"]):
        raise QueueSecurityError("queue envelope signature format is invalid")
    for field in ("message_id", "nonce"):
        value = payload[field]
        if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
            raise QueueSecurityError(f"queue envelope {field} is invalid")

    issued_at = payload["issued_at"]
    expires_at = payload["expires_at"]
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
    ):
        raise QueueSecurityError("queue envelope timestamps must be integers")
    current = time.time() if now is None else float(now)
    if issued_at > current + _MAX_FUTURE_SKEW_SECONDS:
        raise QueueSecurityError("queue envelope was issued too far in the future")
    if expires_at <= current:
        raise QueueSecurityError("queue envelope has expired")
    if expires_at <= issued_at:
        raise QueueSecurityError("queue envelope expiry must follow issuance")
    if expires_at - issued_at > _MAX_ENVELOPE_TTL_SECONDS:
        raise QueueSecurityError("queue envelope lifetime exceeds 24 hours")

    tenant = payload["tenant"]
    if not isinstance(tenant, str):
        raise QueueSecurityError("queue envelope tenant must be a string")
    if payload["auth_mode"] == _AUTH_SHARED and not tenant:
        raise QueueSecurityError("network queue envelopes require an explicit tenant")
    if tenant:
        # Public path resolution validates encoding/length without touching disk.
        from .paths import data_dir

        data_dir("jobs.db", tenant=tenant)

    goal_id = payload["goal_id"]
    if isinstance(goal_id, bool) or not isinstance(goal_id, int) or goal_id <= 0:
        raise QueueSecurityError("queue envelope goal_id must be a positive integer")
    _valid_optional_positive_int(payload["conversation_id"], "conversation_id")
    max_depth = payload["max_depth"]
    if (
        isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or not 1 <= max_depth <= 64
    ):
        raise QueueSecurityError("queue envelope max_depth must be between 1 and 64")
    _valid_optional_number(payload["max_dollars"], "max_dollars")
    _valid_optional_number(payload["max_wall_seconds"], "max_wall_seconds")
    _valid_optional_text(payload["channel"], "channel")
    _valid_optional_text(payload["user_id"], "user_id")
    _valid_optional_text(payload["concurrency_principal"], "concurrency_principal")
    _valid_allowed_suites(payload["allowed_suites"])
    capability = payload["capability"]
    if capability is not None:
        _validate_capability_payload(capability, require_sig=True)


def _verify_envelope(raw: Any) -> dict[str, Any]:
    """Authenticate an immutable snapshot, then validate its semantic schema."""
    payload = _snapshot_payload(raw)
    auth_mode = payload.get("auth_mode")
    if auth_mode == _AUTH_LOCAL:
        key: str | bytes = _LOCAL_SIGNING_KEY
    elif auth_mode == _AUTH_SHARED:
        key = _require_network_signing_key()
    else:
        raise QueueSecurityError("queue envelope auth mode is missing or invalid")
    signature = payload.get(_QUEUE_SIG_FIELD)
    expected = _envelope_sig(payload, key)
    if not (
        isinstance(signature, str)
        and text_equals(signature, expected)
    ):
        raise QueueSecurityError("queue envelope signature is missing or invalid")
    _validate_envelope(payload)
    capability = payload["capability"]
    if capability is not None:
        cap_sig = capability.get(_QUEUE_SIG_FIELD)
        expected_cap_sig = _capability_sig(capability, key)
        if not (
            isinstance(cap_sig, str)
            and hmac.compare_digest(cap_sig, expected_cap_sig)
        ):
            raise QueueSecurityError(
                "queued capability signature missing or invalid; refusing grant"
            )
    return payload


def _payload(
    goal_id: int,
    *,
    conversation_id: int | None,
    max_dollars: float | None,
    max_wall_seconds: float | None,
    max_depth: int,
    channel: str | None,
    user_id: str | None,
    capability: Any | None,
    concurrency_principal: str | None,
    allowed_suites: frozenset[str] | None,
    auth_mode: str,
    signing_key: str | bytes,
    ttl_seconds: int,
) -> dict[str, Any]:
    """Build and authenticate the complete dispatch envelope."""
    from .paths import current_tenant_id

    now = int(time.time())
    envelope = {
        "version": ENVELOPE_VERSION,
        "job_name": JOB_NAME,
        "auth_mode": auth_mode,
        "message_id": secrets.token_urlsafe(24),
        "nonce": secrets.token_urlsafe(24),
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "tenant": current_tenant_id() or "",
        "goal_id": int(goal_id),
        "conversation_id": conversation_id,
        "max_dollars": max_dollars,
        "max_wall_seconds": max_wall_seconds,
        "max_depth": max_depth,
        "channel": channel,
        "user_id": user_id,
        "capability": _serialize_capability(capability, signing_key=signing_key),
        "concurrency_principal": concurrency_principal,
        # The caller's department grant must survive the queue boundary, or a
        # suite-scoped goal would run unscoped on the worker (run_queued_goal
        # already deserializes this key).
        "allowed_suites": (sorted(allowed_suites)
                           if allowed_suites is not None else None),
    }
    signed = _sign_envelope(envelope, signing_key)
    _validate_envelope(signed, now=now)
    return signed


def _network_claim_id(envelope: dict[str, Any]) -> str:
    """Opaque stable id for one signed message-id/nonce pair."""
    raw = (
        f"{envelope['version']}\x00{envelope['message_id']}\x00{envelope['nonce']}"
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _claim_network_envelope_once(envelope: dict[str, Any]) -> bool:
    """Atomically claim an envelope in the fleet-shared Postgres world.

    Remote goal workers already require the producer and every worker to share
    the canonical world model.  Requiring its Postgres backend here turns the
    existing tenant-aware ``processed_messages`` uniqueness constraint into a
    cross-process/cross-host replay barrier.  Per-host SQLite is deliberately
    rejected for network mode because it cannot provide fleet-wide exclusion.
    """
    _require_network_claim_store_configured()

    try:
        from .world_model import close_world_if_owned, open_world

        world = open_world()
    except Exception:
        raise QueueSecurityError(
            "network queue replay-claim store is unavailable; refusing dispatch"
        ) from None
    try:
        return bool(
            world.mark_message_processed(
                _NETWORK_CLAIM_CHANNEL,
                _network_claim_id(envelope),
                goal_id=envelope["goal_id"],
            )
        )
    except Exception:
        raise QueueSecurityError(
            "network queue replay claim failed; refusing dispatch"
        ) from None
    finally:
        close_world_if_owned(world)


class QueueDispatcher:
    """Enqueue goals using an authenticated local or network transport."""

    def __init__(
        self,
        enqueue: Callable[[str, dict], Any],
        *,
        transport: str = "local",
        envelope_ttl_seconds: int | None = None,
    ) -> None:
        if transport not in {"local", "network"}:
            raise ValueError("queue transport must be 'local' or 'network'")
        if transport == "local" and getattr(enqueue, "_maverick_network_broker", False):
            raise QueueSecurityError(
                "a network broker requires QueueDispatcher(..., transport='network')"
            )
        self._enqueue = enqueue
        self._auth_mode = _AUTH_SHARED if transport == "network" else _AUTH_LOCAL
        if transport == "network":
            self._signing_key = _require_network_signing_key()
            _require_network_claim_store_configured()
        else:
            self._signing_key = _LOCAL_SIGNING_KEY
        ttl = (
            _configured_envelope_ttl_seconds()
            if envelope_ttl_seconds is None
            else int(envelope_ttl_seconds)
        )
        if not 1 <= ttl <= _MAX_ENVELOPE_TTL_SECONDS:
            raise QueueSecurityError(
                "queue envelope TTL must be between 1 and 86400 seconds"
            )
        self._ttl_seconds = ttl

    def submit(
        self,
        goal_id: int,
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        max_depth: int | None = None,
        conversation_id: int | None = None,
        channel: str | None = None,
        user_id: str | None = None,
        capability: Any | None = None,
        concurrency_principal: str | None = None,
        allowed_suites: frozenset[str] | None = None,
    ) -> str | None:
        return self._submit(
            goal_id, max_dollars=max_dollars, max_wall_seconds=max_wall_seconds,
            max_depth=max_depth, conversation_id=conversation_id, channel=channel,
            user_id=user_id, capability=capability,
            concurrency_principal=concurrency_principal, allowed_suites=allowed_suites,
            observed=False,
        )

    def submit_observed(
        self,
        goal_id: int,
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        max_depth: int | None = None,
        conversation_id: int | None = None,
        channel: str | None = None,
        user_id: str | None = None,
        capability: Any | None = None,
        concurrency_principal: str | None = None,
        allowed_suites: frozenset[str] | None = None,
    ) -> DispatchObservation:
        return self._submit(
            goal_id, max_dollars=max_dollars, max_wall_seconds=max_wall_seconds,
            max_depth=max_depth, conversation_id=conversation_id, channel=channel,
            user_id=user_id, capability=capability,
            concurrency_principal=concurrency_principal, allowed_suites=allowed_suites,
            observed=True,
        )

    def submit_handle(self, goal_id: int, **kwargs: Any) -> ExecutionHandle:
        """Return the signed submission evidence without acquiring a lease."""
        from .runner import _submission_handle

        return _submission_handle(
            goal_id, lambda: self.submit_observed(goal_id, **kwargs), owner="queue",
        )

    def _submit(
        self, goal_id: int, *, max_dollars: float | None,
        max_wall_seconds: float | None, max_depth: int | None,
        conversation_id: int | None, channel: str | None, user_id: str | None,
        capability: Any | None, concurrency_principal: str | None,
        allowed_suites: frozenset[str] | None, observed: bool,
    ) -> str | DispatchObservation:
        from .runner import DEFAULT_MAX_DEPTH, DispatchObservation, DispatchState, observe_dispatch

        try:
            payload = _payload(
                goal_id, conversation_id=conversation_id, max_dollars=max_dollars,
                max_wall_seconds=max_wall_seconds,
                max_depth=DEFAULT_MAX_DEPTH if max_depth is None else max_depth,
                channel=channel, user_id=user_id, capability=capability,
                concurrency_principal=concurrency_principal, allowed_suites=allowed_suites,
                auth_mode=self._auth_mode, signing_key=self._signing_key,
                ttl_seconds=self._ttl_seconds,
            )
        except Exception as exc:
            if not observed:
                raise
            log.warning("queue preflight rejected goal #%s (%s)", goal_id, type(exc).__name__)
            return DispatchObservation(goal_id, DispatchState.NOT_ACCEPTED, "error",
                                       owner="queue", reason="queue_preflight")
        try:
            self._enqueue(JOB_NAME, payload)
        except Exception as exc:
            if not observed:
                raise
            # The broker may have committed before an acknowledgement was
            # lost. Keep its signed message identity for reconciliation.
            log.warning("queue outcome unknown for goal #%s (%s)", goal_id, type(exc).__name__)
            return DispatchObservation(goal_id, DispatchState.UNKNOWN, "error",
                                       owner="queue", receipt_id=payload["message_id"],
                                       reason="queue_acknowledgement_unknown")
        log.info(
            "queued goal #%s as authenticated message %s",
            goal_id,
            payload["message_id"],
        )
        if observed:
            return observe_dispatch(goal_id, QUEUED_STATUS, owner="queue",
                                    receipt_id=payload["message_id"])
        return QUEUED_STATUS


def run_queued_goal(payload: dict) -> str | None:
    """Authenticate, consume, and execute one queued goal.

    Network envelopes are semantically validated and attenuated before their
    durable claim. The claim is then never released: broker redelivery and
    concurrent workers cannot repeat spend, while a post-claim crash requires
    a fresh signed submission.
    """
    envelope = _verify_envelope(payload)

    from .paths import current_tenant_id, tenant_scope

    tenant = envelope["tenant"]
    if not tenant and current_tenant_id() is not None:
        # ``tenant_scope(tenant=None)`` is intentionally a no-op for legacy
        # callers.  Refuse instead of letting a signed shared-root local job
        # drift into whichever tenant became active after it was enqueued.
        raise QueueSecurityError(
            "shared-root local queue envelope cannot run inside a tenant scope"
        )
    with tenant_scope(tenant=tenant or None):
        if tenant:
            try:
                from .tenant.registry import assert_tenant_active, tenant_over_quota

                assert_tenant_active(tenant)
                quota_reason = tenant_over_quota(tenant)
            except Exception as exc:
                raise QueueSecurityError(
                    f"queued tenant policy unavailable or inactive: {tenant!r}"
                ) from exc
            if quota_reason:
                raise QueueSecurityError(quota_reason)
        channel = envelope["channel"]
        user_id = envelope["user_id"]
        capability_key: str | bytes = (
            _LOCAL_SIGNING_KEY
            if envelope["auth_mode"] == _AUTH_LOCAL
            else _require_network_signing_key()
        )
        capability = _worker_capability(
            _deserialize_capability(
                envelope["capability"], signing_key=capability_key
            ),
            channel=channel,
            user_id=user_id,
        )
        max_dollars, max_wall_seconds, max_depth = _worker_execution_limits(envelope)
        concurrency_principal = (
            envelope["concurrency_principal"]
            if envelope["auth_mode"] == _AUTH_LOCAL
            else f"queue:{tenant}"
        )

        if envelope["auth_mode"] == _AUTH_SHARED:
            claimed = _claim_network_envelope_once(envelope)
        else:
            from .job_queue import JobQueue

            claimed = JobQueue().claim_dispatch_envelope(
                envelope["message_id"],
                envelope["nonce"],
                expires_at=envelope["expires_at"],
            )
        if not claimed:
            raise QueueReplayError(
                "queue dispatch envelope was already consumed; "
                "submit a fresh signed job to retry"
            )

        from .runner import LocalThreadDispatcher
        return LocalThreadDispatcher().submit(
            envelope["goal_id"],
            conversation_id=envelope["conversation_id"],
            max_dollars=max_dollars,
            max_wall_seconds=max_wall_seconds,
            max_depth=max_depth,
            channel=channel,
            user_id=user_id,
            concurrency_principal=concurrency_principal,
            capability=capability,
            allowed_suites=(
                None
                if envelope["allowed_suites"] is None
                else frozenset(envelope["allowed_suites"])
            ),
        )


def _arq_exception_text(exc: BaseException) -> str:
    """Return a bounded, inert representation for an arq failure result."""
    text = f"{type(exc).__name__}: {exc}"
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= _MAX_TEXT_BYTES:
        return text
    return raw[:_MAX_TEXT_BYTES].decode("utf-8", errors="ignore") + "..."


def _validate_arq_json_value(value: Any) -> None:
    """Accept only a small, finite JSON tree before it reaches arq.

    arq's serializer is also used for result records, so tuples and exceptions
    can occur even though the authenticated dispatch envelope itself is plain
    JSON.  Exceptions become inert text; every other non-JSON object is denied.
    """
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_ARQ_JSON_NODES:
            raise QueueSecurityError("arq record has too many JSON values")
        if depth > _MAX_ARQ_JSON_DEPTH:
            raise QueueSecurityError("arq record exceeds the JSON nesting limit")
        if current is None or isinstance(current, (str, bool, int)):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise QueueSecurityError("arq record contains a non-finite number")
            continue
        if isinstance(current, BaseException):
            continue
        if isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise QueueSecurityError("arq record object keys must be strings")
            stack.extend((item, depth + 1) for item in current.values())
            continue
        raise QueueSecurityError(
            f"arq record contains unsupported type {type(current).__name__}"
        )


def _arq_json_default(value: Any) -> str:
    if isinstance(value, BaseException):
        return _arq_exception_text(value)
    raise TypeError(f"unsupported arq JSON value: {type(value).__name__}")


def _arq_safe_serialize(value: Any) -> bytes:
    """Serialize arq jobs/results without executable object reconstruction."""
    _validate_arq_json_value(value)
    try:
        body = json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
            default=_arq_json_default,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise QueueSecurityError("arq record is not strict JSON") from exc
    encoded = _ARQ_CODEC_PREFIX + body
    if len(encoded) > _MAX_ARQ_CODEC_BYTES:
        raise QueueSecurityError("arq record exceeds the 192 KiB limit")
    return encoded


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise QueueSecurityError(f"arq record repeats JSON key {key!r}")
        obj[key] = value
    return obj


def _check_json_nesting(body: bytes) -> None:
    """Reject deep JSON before the recursive stdlib decoder sees it."""
    depth = 0
    in_string = False
    escaped = False
    for byte in body:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ or {
            depth += 1
            if depth > _MAX_ARQ_JSON_DEPTH:
                raise QueueSecurityError("arq record exceeds the JSON nesting limit")
        elif byte in (0x5D, 0x7D):  # ] or }
            depth -= 1
            if depth < 0:
                raise QueueSecurityError("arq record has invalid JSON nesting")
    if in_string or depth != 0:
        raise QueueSecurityError("arq record has invalid JSON framing")


def _arq_safe_deserialize(raw: bytes) -> dict[str, Any]:
    """Decode only our bounded, versioned JSON codec; old pickle is rejected."""
    if not isinstance(raw, bytes):
        raise QueueSecurityError("arq record must be bytes")
    if len(raw) > _MAX_ARQ_CODEC_BYTES:
        raise QueueSecurityError("arq record exceeds the 192 KiB limit")
    if not raw.startswith(_ARQ_CODEC_PREFIX):
        raise QueueSecurityError("arq record does not use the safe JSON codec")
    body = raw[len(_ARQ_CODEC_PREFIX):]
    _check_json_nesting(body)

    def _reject_constant(value: str) -> Any:
        raise QueueSecurityError(f"arq record contains invalid number {value!r}")

    try:
        decoded = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_constant,
        )
    except QueueSecurityError:
        raise
    except (UnicodeError, TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise QueueSecurityError("arq record is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise QueueSecurityError("arq record must be a JSON object")
    _validate_arq_json_value(decoded)
    return decoded


def _redis_host_is_loopback(host: Any) -> bool:
    if isinstance(host, tuple) and len(host) == 2 and isinstance(host[0], str):
        host = host[0]
    if isinstance(host, (list, tuple, set, frozenset)):
        return bool(host) and all(_redis_host_is_loopback(item) for item in host)
    if not isinstance(host, str):
        return False
    normalized = host.strip().lower()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if normalized in {"localhost", "localhost.", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _redis_tls_verified(settings: Any) -> bool:
    if not bool(getattr(settings, "ssl", False)):
        return False
    cert_reqs = getattr(settings, "ssl_cert_reqs", "required")
    if isinstance(cert_reqs, str):
        cert_verified = cert_reqs.strip().lower() in {
            "required",
            "cert_required",
        }
    else:
        cert_verified = cert_reqs == ssl.CERT_REQUIRED
    if not cert_verified:
        return False
    return bool(getattr(settings, "ssl_check_hostname", False))


def _validate_redis_transport(settings: Any) -> None:
    """Require verified TLS for Redis unless the endpoint is process-local."""
    if getattr(settings, "unix_socket_path", None):
        return
    host = getattr(settings, "host", None)
    if _redis_host_is_loopback(host) or _redis_tls_verified(settings):
        return

    from ._envparse import env_bool

    if env_bool("MAVERICK_ALLOW_INSECURE_QUEUE_REDIS"):
        log.warning(
            "allowing insecure non-loopback queue Redis transport because "
            "MAVERICK_ALLOW_INSECURE_QUEUE_REDIS is explicitly enabled"
        )
        return
    raise QueueSecurityError(
        "refusing non-loopback queue Redis without verified TLS; configure "
        "RedisSettings(ssl=True, ssl_cert_reqs='required', "
        "ssl_check_hostname=True) or, only for an "
        "isolated development network, set MAVERICK_ALLOW_INSECURE_QUEUE_REDIS=1"
    )


def _queue_redis_config() -> dict[str, Any]:
    try:
        from .config import load_config

        raw = (load_config() or {}).get("queue") or {}
    except Exception as exc:
        raise QueueSecurityError("queue Redis configuration is unreadable") from exc
    if not isinstance(raw, dict):
        raise QueueSecurityError("[queue] configuration must be a mapping")
    return raw


def _configured_arq_redis_settings(redis_settings_cls: Any) -> Any:
    """Build matching producer/worker Redis settings from one strict source.

    Credentials may be embedded in the DSN, so errors are deliberately generic
    and no settings object or DSN is logged. ``rediss://`` always forces system
    certificate verification and hostname checking; query parameters cannot
    weaken either control.
    """
    cfg = _queue_redis_config()
    dsn = (
        os.environ.get("MAVERICK_QUEUE_REDIS_DSN", "").strip()
        or str(cfg.get("redis_dsn") or "").strip()
    )
    if not dsn:
        settings = redis_settings_cls()
        _validate_redis_transport(settings)
        return settings

    try:
        parsed = urlsplit(dsn)
        scheme = parsed.scheme.lower()
        if scheme not in {"redis", "rediss", "unix"}:
            raise ValueError("unsupported scheme")
        if scheme == "unix":
            socket_path = unquote(parsed.path)
            if not socket_path:
                raise ValueError("missing Unix socket path")
            settings = redis_settings_cls()
            settings.unix_socket_path = socket_path
            db_values = parse_qs(parsed.query).get("db")
            if db_values:
                settings.database = int(db_values[0])
        else:
            settings = redis_settings_cls.from_dsn(dsn)
    except Exception:
        raise QueueSecurityError("queue Redis DSN is invalid") from None

    if scheme == "rediss":
        settings.ssl = True
        settings.ssl_cert_reqs = "required"
        settings.ssl_check_hostname = True

    ca_certs = (
        os.environ.get("MAVERICK_QUEUE_REDIS_CA_CERTS", "").strip()
        or str(cfg.get("redis_ca_certs") or "").strip()
    )
    certfile = (
        os.environ.get("MAVERICK_QUEUE_REDIS_CERTFILE", "").strip()
        or str(cfg.get("redis_certfile") or "").strip()
    )
    keyfile = (
        os.environ.get("MAVERICK_QUEUE_REDIS_KEYFILE", "").strip()
        or str(cfg.get("redis_keyfile") or "").strip()
    )
    if bool(certfile) != bool(keyfile):
        raise QueueSecurityError(
            "queue Redis client certificate and key must be configured together"
        )
    if ca_certs:
        settings.ssl_ca_certs = ca_certs
    if certfile:
        settings.ssl_certfile = certfile
        settings.ssl_keyfile = keyfile

    _validate_redis_transport(settings)
    return settings


def _configured_arq_queue_name() -> str:
    """Return a deployment-scoped ARQ queue name shared by producer/workers."""
    cfg = _queue_redis_config()
    namespace = (
        os.environ.get("MAVERICK_QUEUE_NAMESPACE", "").strip()
        or str(cfg.get("namespace") or "").strip()
    )
    if not namespace:
        raise QueueSecurityError(
            "network queue requires MAVERICK_QUEUE_NAMESPACE "
            "(or [queue] namespace) to isolate deployments"
        )
    if not _QUEUE_NAMESPACE_RE.fullmatch(namespace):
        raise QueueSecurityError(
            "queue namespace must be 1-64 letters, digits, dots, dashes, or underscores"
        )
    return f"maverick:queue:{namespace}"


def arq_enqueue(redis_settings: Any | None = None) -> Callable[[str, dict], None]:
    """Return an arq/Redis enqueue callable with fail-closed transport checks."""
    try:
        import asyncio

        from arq import create_pool
        from arq.connections import RedisSettings
    except ImportError as exc:  # pragma: no cover - optional queue extra
        raise ImportError(
            "queue backend needs the queue extra from the same reviewed "
            "Lightwork checkout; public-index lookup is disabled"
        ) from exc

    settings = (
        redis_settings
        if redis_settings is not None
        else _configured_arq_redis_settings(RedisSettings)
    )
    _validate_redis_transport(settings)
    queue_name = _configured_arq_queue_name()

    def _enqueue(job_name: str, payload: dict) -> None:  # pragma: no cover - Redis
        async def _go() -> None:
            pool = await create_pool(
                settings,
                job_serializer=_arq_safe_serialize,
                job_deserializer=_arq_safe_deserialize,
                default_queue_name=queue_name,
            )
            try:
                job_id = hashlib.sha256(
                    f"{payload.get('message_id', '')}\x00{payload.get('nonce', '')}".encode()
                ).hexdigest()
                try:
                    expires_in = int(payload["expires_at"]) - int(time.time())
                except (KeyError, TypeError, ValueError, OverflowError) as exc:
                    raise QueueSecurityError(
                        "queue envelope expiry is missing or invalid"
                    ) from exc
                if expires_in <= 0:
                    raise QueueSecurityError("queue envelope expired before enqueue")
                queued = await pool.enqueue_job(
                    job_name,
                    payload,
                    _job_id=f"maverick-{job_id}",
                    _expires=expires_in,
                )
                if queued is None:
                    raise QueueReplayError(
                        "queue broker already contains this dispatch identity"
                    )
            finally:
                await pool.close()

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(_go())
        else:
            # The Dispatcher contract is synchronous, but a channel or ASGI
            # integration may call it from an active event loop. Run the
            # broker coroutine in its own thread instead of nesting
            # ``asyncio.run`` (which raises and can also leak the coroutine).
            with ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="maverick-arq-enqueue",
            ) as executor:
                executor.submit(asyncio.run, _go()).result()

    # Prevent callers from accidentally wrapping this known network broker in
    # the process-local compatibility mode.
    _enqueue._maverick_network_broker = True  # type: ignore[attr-defined]
    return _enqueue


class _FailClosedQueueDispatcher:
    """Installed on a selected-but-insecure broker instead of falling local."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def submit(self, *_args: Any, **_kwargs: Any) -> str | None:
        raise QueueSecurityError(
            f"configured network queue is unavailable or insecure: {self._reason}"
        )

    def submit_observed(self, goal_id: int, **_kwargs: Any) -> DispatchObservation:
        from .runner import DispatchObservation, DispatchState

        return DispatchObservation(goal_id, DispatchState.NOT_ACCEPTED, "error",
                                   owner="queue", reason="queue_unavailable")

    def submit_handle(self, goal_id: int, **kwargs: Any) -> ExecutionHandle:
        from .runner import _submission_handle

        return _submission_handle(
            goal_id, lambda: self.submit_observed(goal_id, **kwargs), owner="queue",
        )


def install_from_config() -> bool:
    """Install the configured queue, failing closed when a network setup is bad."""
    from .runner import set_dispatcher

    try:
        from .config import load_config

        queue_cfg = (load_config() or {}).get("queue") or {}
        if not isinstance(queue_cfg, dict):
            raise QueueSecurityError("[queue] configuration must be a mapping")
        backend = str(queue_cfg.get("backend") or "").strip().lower()
    except Exception as exc:
        reason = "queue configuration is unreadable"
        set_dispatcher(_FailClosedQueueDispatcher(reason))
        if isinstance(exc, QueueSecurityError):
            raise
        raise QueueSecurityError(reason) from exc
    if backend and backend != "arq":
        reason = f"unsupported queue backend {backend!r}"
        set_dispatcher(_FailClosedQueueDispatcher(reason))
        raise QueueSecurityError(reason)
    if backend == "arq":
        try:
            # Check authentication before importing/connecting to the broker.
            _require_network_signing_key()
            _require_network_claim_store_configured()
            dispatcher = QueueDispatcher(arq_enqueue(), transport="network")
        except Exception as exc:
            # server.py logs and continues on optional integration errors.  Pin
            # a rejecting dispatcher first so "continue" cannot silently turn
            # an explicitly configured network deployment into local execution.
            set_dispatcher(_FailClosedQueueDispatcher(str(exc)))
            raise
        set_dispatcher(dispatcher)
        log.info("installed authenticated arq queue dispatcher")
        return True
    return False


__all__ = [
    "JOB_NAME",
    "QUEUED_STATUS",
    "ENVELOPE_VERSION",
    "QueueDispatcher",
    "QueueSecurityError",
    "QueueReplayError",
    "run_queued_goal",
    "arq_enqueue",
    "install_from_config",
]
