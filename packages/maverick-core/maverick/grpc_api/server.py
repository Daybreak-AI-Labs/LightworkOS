"""gRPC binding for :class:`~maverick.grpc_api.service.GoalService`.

A thin protobuf shim: it maps the generated request/response messages onto the
transport-agnostic service and back. Everything here is behind the ``[grpc]``
extra (``grpcio`` + ``grpcio-tools``) and lazy — importing this module never
requires grpc; only :func:`serve` and :func:`_servicer` do.

Stubs are generated on demand from the bundled ``maverick.proto`` into this
package (``maverick_pb2`` / ``maverick_pb2_grpc``) so no generated code is
checked in. With the ``[grpc]`` extra installed, ``serve()`` just works.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import threading
import time
from collections import deque
from concurrent import futures
from pathlib import Path

log = logging.getLogger(__name__)

_PROTO = Path(__file__).with_name("maverick.proto")
_DEFAULT_ADDR = "127.0.0.1:50051"
_TOKEN_ENV = "MAVERICK_GRPC_BEARER_TOKEN"
_AUTH_HEADER = "authorization"
_BEARER_PREFIX = "bearer "


def _require_grpc():
    try:
        import grpc  # noqa: F401
    except ImportError as e:
        raise ImportError(
                "grpc not installed. Run from a reviewed Lightwork checkout: "
                "python -m pip install -e './packages/maverick-core[grpc]'"
        ) from e
    return __import__("grpc")


def _load_stubs():
    """Import the generated pb2 modules, generating them first if absent."""
    try:
        from . import maverick_pb2, maverick_pb2_grpc  # type: ignore
        return maverick_pb2, maverick_pb2_grpc
    except ImportError:
        from ..grpc_stubs import guard_runtime_generation
        guard_runtime_generation("maverick.proto")
        _generate_stubs()
        from . import maverick_pb2, maverick_pb2_grpc  # type: ignore
        return maverick_pb2, maverick_pb2_grpc


def _generate_stubs() -> None:
    """Compile maverick.proto into this package using grpc_tools.protoc."""
    try:
        from grpc_tools import protoc
    except ImportError as e:
        raise ImportError(
            "grpcio-tools not installed (needed to generate stubs). "
            "Run from a reviewed Lightwork checkout: "
            "python -m pip install -e './packages/maverick-core[grpc]'"
        ) from e
    out = str(_PROTO.parent)
    rc = protoc.main([
        "protoc",
        f"-I{out}",
        f"--python_out={out}",
        f"--grpc_python_out={out}",
        str(_PROTO),
    ])
    if rc != 0:  # pragma: no cover -- only on a broken protoc toolchain
        raise RuntimeError(f"protoc failed to generate gRPC stubs (rc={rc})")


def _configured_bearer_token() -> str:
    """``MAVERICK_GRPC_BEARER_TOKEN``, else the sealed ``[grpc] token`` the
    dashboard's All settings page keeps."""
    token = os.getenv(_TOKEN_ENV, "")
    if token.strip():
        return token
    try:
        from ..config import load_config
        value = ((load_config() or {}).get("grpc") or {}).get("token")
    except Exception:
        return ""
    return value if isinstance(value, str) else ""


def _resolve_bearer_token(bearer_token: str | None = None) -> str:
    token = (bearer_token if bearer_token is not None else _configured_bearer_token()).strip()
    if not token:
        raise ValueError(
            "Lightwork gRPC requires a bearer token. Set "
            f"{_TOKEN_ENV} or pass --bearer-token, and send it as "
            "metadata: authorization: Bearer <token>."
        )
    return token


def _metadata_bearer_token(context) -> str | None:
    metadata = context.invocation_metadata() or ()
    for key, value in metadata:
        if key.lower() != _AUTH_HEADER:
            continue
        value = str(value).strip()
        if value.lower().startswith(_BEARER_PREFIX):
            return value[len(_BEARER_PREFIX):].strip()
    return None


def _abort(context, code, details: str):
    context.abort(code, details)
    raise PermissionError(details)


def _require_authorized(context, bearer_token: str):
    agent = _authorize_caller(context, bearer_token)
    _trust_capability(context, agent)
    return agent


def _agent_owner(agent) -> str | None:
    """Object owner for a per-agent token; ``None`` for the operator token.

    The shared bearer is the backwards-compatible administrative principal and
    may access every goal in the active client/tenant floor.  Per-agent tokens
    are least-privilege principals and may access only ``agent:<id>`` goals.
    """
    if agent is None:
        return None
    return f"agent:{agent.id}"


def _execution_identity(
    agent, *, channel: str | None, user_id: str | None,
) -> tuple[str | None, str | None]:
    """Bind execution context to an authenticated per-agent identity.

    ``channel`` and ``user_id`` select capability policy and user-scoped learned
    context.  They therefore cannot remain caller assertions for a per-agent
    token.  The shared operator token is trusted to forward those fields for the
    cross-host dispatcher and keeps the historical behavior.
    """
    if agent is None:
        return channel, user_id
    return "grpc", str(agent.id)


def _execution_budget(
    agent,
    *,
    max_dollars: float | None,
    max_wall_seconds: float | None,
) -> tuple[float | None, float | None]:
    """Clamp a per-agent request to its registry budget ceilings.

    Protobuf floats can carry NaN/Infinity.  Normalize those (and non-positive
    sentinel values) to "unspecified" before clamping, otherwise NaN can survive
    ``min`` and later be replaced by a larger generic Budget default.  The
    shared operator keeps its historical pass-through semantics.
    """
    if agent is None:
        return max_dollars, max_wall_seconds

    def _finite_positive(value: float | None) -> float | None:
        if value is None:
            return None
        parsed = float(value)
        return parsed if math.isfinite(parsed) and parsed > 0 else None

    from ..agent_trust import clamp_budget

    return clamp_budget(
        agent,
        max_dollars=_finite_positive(max_dollars),
        max_wall_seconds=_finite_positive(max_wall_seconds),
    )


def _execution_depth(requested: int | None) -> int:
    """Clamp remote recursion to a worker-owned ceiling.

    ``RunGoal.max_depth`` is an untrusted protobuf integer.  Passing it through
    lets an authenticated caller request an exponentially large swarm.  The
    worker therefore owns the ceiling (defaulting to the normal runner depth),
    with an absolute implementation bound matching the queue worker.
    """
    from ..runner import DEFAULT_MAX_DEPTH

    default = min(64, max(1, int(DEFAULT_MAX_DEPTH)))
    ceiling = _grpc_int_setting("MAVERICK_GRPC_MAX_DEPTH", "max_depth", default)
    ceiling = min(64, max(1, ceiling or default))
    try:
        value = int(requested) if requested is not None and int(requested) > 0 else default
    except (TypeError, ValueError, OverflowError):
        value = default
    return min(ceiling, max(1, value))


def _stream_deadline(requested: float | None) -> float:
    """Return a finite server-owned deadline for an episode stream.

    A zero protobuf value previously meant "forever", allowing a handful of
    authenticated clients to pin every gRPC worker on non-terminal goals.  A
    caller can reconnect with ``since_id`` after the deadline.
    """
    ceiling = min(
        3600.0,
        _grpc_float_setting(
            "MAVERICK_GRPC_STREAM_MAX_SECONDS", "stream_max_seconds", 300.0
        ),
    )
    try:
        value = float(requested) if requested is not None else ceiling
    except (TypeError, ValueError, OverflowError):
        value = ceiling
    if not math.isfinite(value) or value <= 0:
        value = ceiling
    return min(value, ceiling)


# --- per-caller request rate limiting (sliding 60s window) -------------------
_GRPC_RATE_LOCK = threading.Lock()
_GRPC_RATE_HITS: dict[str, deque] = {}
# Hard-bound the tracked-caller map: idle buckets are swept first, and if every
# bucket is still fresh the least-recently-active ones are evicted, so a
# long-running server can't leak one entry per distinct agent/peer forever
# (even under a flood of short-lived connections from many ephemeral ports).
_GRPC_RATE_MAX_KEYS = 8192


def _grpc_rate_limit_per_min() -> int:
    """Requests/minute per caller. Default 600; 0 disables. Complements
    maximum_concurrent_rpcs (in-flight cap) with a request-rate cap."""
    raw = os.environ.get("MAVERICK_GRPC_RATE_LIMIT")
    if raw is None or raw.strip() == "":
        try:
            from ..config import load_config
            raw = ((load_config() or {}).get("grpc") or {}).get("rate_limit", 600)
        except Exception:
            raw = 600
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 600


def _grpc_peer_caller(peer: str) -> str:
    """Return a stable caller key from a gRPC peer string.

    TCP peer strings include the client's ephemeral source port
    (for example ``ipv4:10.0.0.7:50001``), so hashing the full peer lets the
    same caller receive a fresh rate-limit bucket on every reconnect. Strip the
    port for IP transports while preserving the transport prefix. Non-IP peers
    (for example Unix sockets) are left unchanged.
    """
    if peer.startswith("ipv4:"):
        host, sep, _port = peer[5:].rpartition(":")
        if sep and host:
            return "ipv4:" + host
    if peer.startswith("ipv6:"):
        rest = peer[5:]
        if rest.startswith("["):
            end = rest.find("]")
            if end > 0:
                return "ipv6:" + rest[: end + 1]
        host, sep, _port = rest.rpartition(":")
        if sep and host:
            return "ipv6:" + host
    return peer


def _grpc_rate_key(context, agent) -> str:
    """Bucket by per-caller agent id when present, else by hashed peer address."""
    if agent is not None and getattr(agent, "id", None):
        return "agent:" + str(agent.id)
    peer = ""
    try:
        peer = _grpc_peer_caller(context.peer() or "")
    except Exception:  # pragma: no cover - context always has peer() in practice
        peer = ""
    return "peer:" + hashlib.sha256(peer.encode("utf-8")).hexdigest()[:16]


def _grpc_rate_ok(key: str) -> bool:
    limit = _grpc_rate_limit_per_min()
    if limit <= 0:
        return True
    now = time.monotonic()
    with _GRPC_RATE_LOCK:
        cutoff = now - 60.0
        dq = _GRPC_RATE_HITS.setdefault(key, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(_GRPC_RATE_HITS) > _GRPC_RATE_MAX_KEYS:
            for k in [k for k, d in _GRPC_RATE_HITS.items()
                      if k != key and (not d or d[-1] < cutoff)]:
                del _GRPC_RATE_HITS[k]
            # Idle sweep alone can't bound the map when every bucket is fresh
            # (e.g. one client opening many short-lived connections from many
            # ephemeral ports). Fall back to evicting the least-recently-active
            # buckets so the map is hard-capped regardless of activity.
            if len(_GRPC_RATE_HITS) > _GRPC_RATE_MAX_KEYS:
                victims = sorted(
                    (k for k in _GRPC_RATE_HITS if k != key),
                    key=lambda k: (_GRPC_RATE_HITS[k][-1]
                                   if _GRPC_RATE_HITS[k] else 0.0),
                )
                for k in victims[:len(_GRPC_RATE_HITS) - _GRPC_RATE_MAX_KEYS]:
                    del _GRPC_RATE_HITS[k]
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def _authorize_caller(context, bearer_token: str):
    """Authorize a caller and return its identity.

    Accepts EITHER the configured shared operator bearer (returns ``None`` — the
    shared principal) OR a per-caller ``[agent_trust] grpc_token`` (returns the
    resolved :class:`TrustedAgent`). Aborts UNAUTHENTICATED when neither matches,
    so per-caller tokens are first-class without weakening the shared-bearer path.
    Applies a per-caller request-rate limit after auth (RESOURCE_EXHAUSTED).
    """
    supplied = _metadata_bearer_token(context)
    identity = None  # None == the shared operator principal
    authorized = False
    if supplied and bearer_token and hmac.compare_digest(
        supplied.encode(), bearer_token.encode()
    ):
        authorized = True
    elif supplied:
        try:
            from ..agent_trust import agent_for_token
            agent = agent_for_token(supplied, "grpc")
        except Exception:  # pragma: no cover - never break auth on a read error
            agent = None
        if agent is not None:
            identity = agent
            authorized = True
    if not authorized:
        _abort(context, _grpc_code().UNAUTHENTICATED, "missing or invalid bearer token")
    if not _grpc_rate_ok(_grpc_rate_key(context, identity)):
        _abort(context, _grpc_code().RESOURCE_EXHAUSTED, "rate limit exceeded")
    return identity


def _trust_capability(context, agent):
    """Agent Trust Plane gate for an inbound gRPC RPC. Returns the capability
    ceiling to intersect into goal execution (``None`` when disengaged). Aborts
    PERMISSION_DENIED when the caller isn't a permitted inbound agent.

    A per-caller token gates on that agent's entry; a shared-operator-bearer
    caller gates on the surface-wide ``"grpc"`` entry — so engaging the plane
    default-denies the gRPC goal API instead of leaving it open on the bearer."""
    try:
        from .. import agent_trust
        enforced, registry = agent_trust.load_trust_state()
    except Exception as e:  # pragma: no cover - exercised via monkeypatched seam
        # This is an inbound remote-control boundary, not an optional model
        # enhancement. If trust state is unreadable we cannot prove admission,
        # so deny instead of silently collapsing to bearer-only access.
        log.error("gRPC trust plane: could not load trust state; refusing RPC: %s", e)
        _abort(context, _grpc_code().UNAVAILABLE, "agent trust policy unavailable")
    # Treat only the literal boolean False as a disengaged plane. A malformed
    # or future loader result such as ``None`` must not become a remote-control
    # bypass through ordinary falsey coercion.
    if type(enforced) is not bool or not isinstance(registry, dict):
        log.error(
            "gRPC trust plane: invalid trust-state result; refusing RPC "
            "(enforced_type=%s, registry_type=%s)",
            type(enforced).__name__,
            type(registry).__name__,
        )
        _abort(context, _grpc_code().UNAVAILABLE, "agent trust policy unavailable")
    if enforced is False:
        # A per-agent bearer authenticates a registry entry even when the
        # optional trust plane is disengaged. Its tool ceiling is still an
        # explicit restriction on that credential, not an optional policy.
        return agent.capability() if agent is not None else None
    agent_id = agent.id if agent is not None else "grpc"
    try:
        decision = agent_trust.decide_inbound(
            agent_id, registry=registry, enforced=True,
        )
        if not isinstance(decision, agent_trust.TrustDecision):
            raise TypeError("agent trust decision has an invalid type")
        denied = decision.denied
        reason = decision.reason
        capability = decision.capability
    except Exception as e:  # pragma: no cover - exercised via monkeypatched seam
        log.error(
            "gRPC trust plane: admission decision failed; refusing RPC: %s", e,
        )
        _abort(context, _grpc_code().UNAVAILABLE, "agent trust policy unavailable")
    if denied:
        try:
            agent_trust.record_denied(agent_id, decision, direction="inbound")
        except Exception as e:  # denial must survive an unavailable audit sink
            log.error(
                "gRPC trust plane: could not record denied admission for %r: %s",
                agent_id,
                e,
            )
        _abort(context, _grpc_code().PERMISSION_DENIED, reason)
    return capability


def _capability_from_json(raw: str):
    if not raw:
        return None
    from ..queue_dispatcher import QueueSecurityError, _deserialize_capability

    try:
        return _deserialize_capability(json.loads(raw))
    except QueueSecurityError as exc:
        raise ValueError(str(exc)) from None


def _rpc_capability(
    capability,
    *,
    channel: str | None = None,
    user_id: str | None = None,
    principal: str | None = None,
):
    """Attenuate an RPC-supplied grant by the worker's local policy.

    The bearer token authenticates access to the gRPC API; it is not proof that
    ``capability_json`` is a trusted, least-privilege grant.  When capability
    enforcement is enabled, intersect the received grant with the same local
    policy a root worker agent would derive if no explicit grant were supplied.
    This preserves legitimate delegated restrictions while ensuring external
    callers can only narrow, never broaden, the worker's configured policy.
    """
    from ..capability import Capability, capability_enforced, capability_from_config

    if not capability_enforced():
        if principal:
            # A per-agent bearer already established this execution identity.
            # Carry it on an all-tools root grant even when policy enforcement
            # is off; intersecting an optional wire grant preserves every
            # caller restriction while preventing principal spoofing.
            identity = Capability(principal=principal)
            return (
                identity
                if capability is None
                else identity.intersect(capability, principal=principal)
            )
        return capability

    supplied_principal = (
        getattr(capability, "principal", "") or ""
        if capability is not None
        else ""
    )
    # The shared operator token has no per-agent identity of its own.  A fleet
    # dispatch sends the same already-canonical opaque principal in both the
    # capability and user-id fields (for example ``agent:acme.coder``); preserve
    # that agreement so the worker can satisfy the goal's durable execution
    # binding.  A disagreement is still caller-controlled ambiguity and falls
    # back to the historical ``user:<user_id>`` identity, while an authenticated
    # per-agent bearer (``principal``) always wins over both wire fields.
    forwarded_principal = (
        supplied_principal
        if supplied_principal and supplied_principal == (user_id or "")
        else f"user:{user_id or 'local'}"
    )
    local_principal = principal or forwarded_principal
    local = capability_from_config(
        principal=local_principal,
        channel=channel,
        user_id=user_id,
    )
    if capability is None:
        # An omitted wire grant means "no additional caller restriction", not
        # "bypass the worker's policy".  Always install the worker-owned
        # capability when enforcement is enabled.
        return local
    return local.intersect(capability, principal=local_principal)


def _servicer(service, pb2, pb2_grpc, *, bearer_token: str | None = None):
    """Build a MaverickServicer bound to ``service`` (a GoalService)."""
    bearer_token = _resolve_bearer_token(bearer_token)

    class MaverickServicer(pb2_grpc.MaverickServicer):
        def StartGoal(self, request, context):
            agent = _authorize_caller(context, bearer_token)
            trust_cap = _trust_capability(context, agent)
            max_dollars, max_wall_seconds = _execution_budget(
                agent,
                max_dollars=request.max_dollars or None,
                max_wall_seconds=request.max_wall_seconds or None,
            )
            channel, user_id = _execution_identity(
                agent,
                channel=request.channel or None,
                user_id=request.user_id or None,
            )
            # StartGoal has no wire capability field, but it still executes on
            # this worker and must receive the local capability floor.  When
            # the trust plane supplies a caller ceiling, local policy
            # intersects it rather than replacing either side.
            capability = _rpc_capability(
                trust_cap,
                channel=channel,
                user_id=user_id,
                principal=_agent_owner(agent),
            )
            try:
                goal_id = service.start_goal(
                    request.title,
                    request.description,
                    max_dollars=max_dollars,
                    max_wall_seconds=max_wall_seconds,
                    channel=channel,
                    user_id=user_id,
                    capability=capability,
                    owner=_agent_owner(agent) or "",
                )
            except ValueError as e:
                context.abort(_grpc_code().INVALID_ARGUMENT, str(e))
            return pb2.StartGoalResponse(goal_id=goal_id)

        def StreamEpisode(self, request, context):
            agent = _require_authorized(context, bearer_token)
            stream = service.stream_episode(
                request.goal_id,
                since_id=request.since_id,
                max_seconds=_stream_deadline(request.max_seconds or None),
                expected_owner=_agent_owner(agent),
            )
            try:
                for ev in stream:
                    if not context.is_active():  # client hung up
                        return
                    yield pb2.Event(
                        id=ev.id, goal_id=ev.goal_id, agent=ev.agent,
                        kind=ev.kind, content=ev.content, ts=ev.ts,
                    )
            finally:
                # GoalService holds one backend handle for the stream.  Do not
                # rely on CPython refcounting to finalize its generator when a
                # client disconnects; alternate runtimes may otherwise retain
                # a Postgres connection/pool until an arbitrary GC cycle.
                close = getattr(stream, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:  # pragma: no cover -- preserve RPC status
                        log.debug("gRPC episode stream close failed", exc_info=True)

        def Cancel(self, request, context):
            agent = _require_authorized(context, bearer_token)
            return pb2.CancelResponse(cancelled=service.cancel(
                request.goal_id, expected_owner=_agent_owner(agent),
            ))

        def GetStatus(self, request, context):
            agent = _require_authorized(context, bearer_token)
            st = service.status(
                request.goal_id, expected_owner=_agent_owner(agent),
            )
            if st is None:
                return pb2.GoalStatus(goal_id=request.goal_id, found=False)
            return pb2.GoalStatus(
                goal_id=st.goal_id, status=st.status,
                result=st.result or "", found=True,
            )

        def RunGoal(self, request, context):
            agent = _authorize_caller(context, bearer_token)
            trust_cap = _trust_capability(context, agent)
            max_dollars, max_wall_seconds = _execution_budget(
                agent,
                max_dollars=request.max_dollars or None,
                max_wall_seconds=request.max_wall_seconds or None,
            )
            channel, user_id = _execution_identity(
                agent,
                channel=request.channel or None,
                user_id=request.user_id or None,
            )
            try:
                capability = _rpc_capability(
                    _capability_from_json(request.capability_json),
                    channel=channel,
                    user_id=user_id,
                    principal=_agent_owner(agent),
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                context.abort(_grpc_code().INVALID_ARGUMENT, str(e))
                raise
            # Intersect the caller's trust-plane ceiling (narrow-only) on top of
            # any RPC-supplied / locally-derived grant.
            if trust_cap is not None:
                capability = (trust_cap if capability is None
                              else capability.intersect(
                                  trust_cap,
                                  principal=_agent_owner(agent) or "grpc",
                              ))
            st = service.run_goal(
                request.goal_id,
                max_dollars=max_dollars,
                max_wall_seconds=max_wall_seconds,
                channel=channel,
                user_id=user_id,
                max_depth=_execution_depth(request.max_depth or None),
                capability=capability,
                expected_execution_principal=_agent_owner(agent),
            )
            if st is None:
                return pb2.GoalStatus(goal_id=request.goal_id, found=False)
            return pb2.GoalStatus(
                goal_id=st.goal_id, status=st.status,
                result=st.result or "", found=True,
            )

    return MaverickServicer()


def _grpc_code():
    import grpc
    return grpc.StatusCode


def _grpc_int_setting(env: str, key: str, default: int | None) -> int | None:
    """An int gRPC server setting from ``env`` or ``[grpc] <key>`` (env wins)."""
    raw = os.environ.get(env)
    if raw is None:
        try:
            from ..config import load_config
            val = ((load_config() or {}).get("grpc") or {}).get(key)
            raw = None if val is None else str(val)
        except Exception:
            raw = None
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def _grpc_float_setting(env: str, key: str, default: float) -> float:
    """A finite positive float gRPC setting from env/config (env wins)."""
    raw = os.environ.get(env)
    if raw is None:
        try:
            from ..config import load_config
            val = ((load_config() or {}).get("grpc") or {}).get(key)
            raw = None if val is None else str(val)
        except Exception:
            raw = None
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    return value if math.isfinite(value) and value > 0 else default


def serve(
    address: str = _DEFAULT_ADDR,
    *,
    service=None,
    max_workers: int | None = None,
    bearer_token: str | None = None,
):
    """Start a blocking gRPC server on ``address``. Returns the server handle.

    With ``block=False`` semantics omitted for simplicity: callers that want
    non-blocking use the returned server's ``stop()``. The default service runs
    real goals; tests pass a service wired to fakes.

    ``max_workers`` defaults to ``MAVERICK_GRPC_MAX_WORKERS`` / ``[grpc]
    max_workers`` (then 8). ``MAVERICK_GRPC_MAX_CONCURRENT`` / ``[grpc]
    max_concurrent_rpcs`` caps in-flight RPCs (explicit RESOURCE_EXHAUSTED
    backpressure instead of unbounded executor queueing); it defaults to the
    worker count.
    """
    # Fail closed: a client-bound deployment must not serve unbound.
    from ..client import require_client_binding
    require_client_binding()
    runtime_uses_saved_arguments = max_workers is None and bearer_token is None
    bearer_token = _resolve_bearer_token(bearer_token)
    grpc = _require_grpc()
    pb2, pb2_grpc = _load_stubs()
    if service is None:
        from .service import GoalService
        service = GoalService()
    if max_workers is None:
        max_workers = _grpc_int_setting("MAVERICK_GRPC_MAX_WORKERS", "max_workers", 8)
    max_concurrent = _grpc_int_setting(
        "MAVERICK_GRPC_MAX_CONCURRENT", "max_concurrent_rpcs", max_workers)
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        maximum_concurrent_rpcs=max_concurrent,
    )
    pb2_grpc.add_MaverickServicer_to_server(
        _servicer(service, pb2, pb2_grpc, bearer_token=bearer_token), server
    )
    # TLS when configured; fail closed if required (client-bound/enterprise).
    from ..grpc_tls import bind_port
    secure = bind_port(server, address, "grpc")
    server.start()
    from ..runtime_configuration import start as start_runtime_receipt
    # The blocking watcher stops the heartbeat as soon as the native server
    # terminates, including callers using the returned server.stop() handle.
    if runtime_uses_saved_arguments and callable(getattr(server, "wait_for_termination", None)):
        runtime_receipt = start_runtime_receipt("grpc")
        if runtime_receipt is not None:
            def stopped():
                try:
                    server.wait_for_termination()
                finally:
                    runtime_receipt.close()
            threading.Thread(target=stopped, name="grpc-configuration-receipt", daemon=True).start()
    log.info("Lightwork gRPC API listening on %s (%s)", address,
             "TLS" if secure else "plaintext")
    return server


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser("maverick-grpc", description="Lightwork gRPC API server")
    ap.add_argument("--address", default=_DEFAULT_ADDR, help="host:port to bind")
    ap.add_argument("--max-workers", type=int, default=None,
                    help="thread pool size (default: MAVERICK_GRPC_MAX_WORKERS "
                         "/ [grpc] max_workers, then 8)")
    ap.add_argument(
        "--bearer-token",
        default=None,
        help=f"bearer token required from clients (or set {_TOKEN_ENV})",
    )
    args = ap.parse_args(argv)
    # The two expected startup errors are operator-config, not crashes: a
    # missing bearer token (fail-closed auth default) and a missing grpcio
    # extra. Both already carry a one-line, actionable message -- print it and
    # exit non-zero instead of dumping a traceback.
    try:
        server = serve(
            args.address, max_workers=args.max_workers,
            bearer_token=args.bearer_token,
        )
    except (ValueError, ImportError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(grace=2.0)
    return 0


__all__ = ["serve", "main"]
