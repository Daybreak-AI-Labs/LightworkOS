"""gRPC dispatch.

Move goal execution to a remote Lightwork worker over gRPC: a
:class:`GrpcDispatcher` implements the :class:`maverick.runner.Dispatcher`
protocol by calling the worker's ``RunGoal`` RPC (added to
``grpc_api/maverick.proto``), which runs an **existing** goal row to
completion and returns its terminal status — the same contract as the local
thread dispatcher, so no caller changes.

The legacy ``RunGoal`` wire schema cannot carry department-suite grants.
Therefore a non-``None`` ``allowed_suites`` value (including the explicit
deny-all empty set) is rejected locally before any RPC instead of widening the
grant on the worker. Unrestricted ``None`` remains backwards compatible.

Deployment contract (same as the arq QueueDispatcher): the API process and
the worker must **share the world DB** (the Postgres backend) — the RPC
carries only the goal id, not the goal. The worker is just
``python -m maverick.grpc_api`` on the other host.

Opt-in::

    [grpc_dispatch]
    target = "worker-host:50051"
    # token = "..."        # must match the worker's [grpc] token, if set
    # timeout_s = 0         # 0 = no client deadline (long-horizon runs)

Behind the same ``[grpc]`` extra as the server. TLS/mTLS is configured in the
``[grpc]`` section (``tls``, ``tls_ca``, ``tls_client_cert``/``tls_client_key``)
and used for the dial when present; with ``[grpc] tls_required = true`` the
dispatcher refuses to dial in the clear. The legacy interface returns ``None``
when no status is available; a timeout can leave remote effects unknown.
"""
from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .runner import DispatchObservation, ExecutionHandle

log = logging.getLogger(__name__)

_DEFAULT_PORT = 50051


def _cfg() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("grpc_dispatch") or {}
    except Exception:  # pragma: no cover -- config never blocks dispatch
        return {}


def configured_target() -> str:
    """``host:port`` of the remote worker (empty = gRPC dispatch off)."""
    env = os.environ.get("MAVERICK_GRPC_DISPATCH_TARGET", "").strip()
    if env:
        return env
    return str(_cfg().get("target") or "").strip()


class GrpcDispatcher:
    """Dispatcher that executes goals on a remote worker via ``RunGoal``."""

    def __init__(
        self,
        target: str | None = None,
        *,
        token: str | None = None,
        timeout_s: float | None = None,
        stub_factory: Any | None = None,
    ):
        self.target = (target or configured_target()).strip()
        if not self.target:
            raise ValueError("gRPC dispatch needs a target (host:port)")
        if ":" not in self.target:
            self.target = f"{self.target}:{_DEFAULT_PORT}"
        cfg = _cfg()
        self.token = token if token is not None else str(cfg.get("token") or "") or None
        if timeout_s is None:
            try:
                timeout_s = float(cfg.get("timeout_s", 0) or 0)
            except (TypeError, ValueError):
                timeout_s = 0.0
        self.timeout_s = timeout_s if timeout_s and timeout_s > 0 else None
        # Test seam: stub_factory() -> (stub, pb2). Default builds a real
        # channel lazily so importing this module never requires grpcio.
        self._stub_factory = stub_factory

    def _build_stub(self):
        if self._stub_factory is not None:
            return self._stub_factory()
        import grpc

        from .grpc_tls import (
            TlsConfigError,
            channel_credentials,
            insecure_channel_allowed,
            tls_required,
        )
        # Dial the worker's goal API ([grpc] section) over TLS when configured,
        # mirroring the federation client. The bearer token + goal payloads must
        # not cross the wire in the clear: fail closed when TLS is required.
        creds = channel_credentials("grpc")
        if creds is None and not insecure_channel_allowed(self.target):
            raise TlsConfigError(
                f"refusing to dial non-loopback gRPC worker {self.target!r} "
                "without TLS; configure [grpc] TLS or explicitly set "
                "MAVERICK_ALLOW_INSECURE_GRPC=1 for a trusted private network"
            )
        if creds is not None:
            channel = grpc.secure_channel(self.target, creds)
        elif tls_required("grpc"):
            raise RuntimeError(
                f"refusing to dial gRPC worker {self.target!r} without TLS: "
                "[grpc] tls is required but not configured")
        else:
            channel = grpc.insecure_channel(self.target)  # legacy single-host dev
        from .grpc_api.server import _load_stubs  # compiled-on-demand stubs
        pb2, pb2_grpc = _load_stubs()
        return pb2_grpc.MaverickStub(channel), pb2

    def _metadata(self) -> list[tuple[str, str]]:
        if self.token:
            return [("authorization", f"Bearer {self.token}")]
        return []

    @staticmethod
    def _capability_json(capability: Any | None) -> str:
        """Serialize an explicit capability grant for the remote worker."""
        if capability is None:
            return ""
        from .queue_dispatcher import _serialize_capability

        return json.dumps(_serialize_capability(capability), separators=(",", ":"))

    def submit(
        self,
        goal_id: int,
        *,
        max_dollars: float | None = None,
        max_wall_seconds: float | None = None,
        max_depth: int = 3,
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
        max_depth: int = 3,
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
        """Retain this RPC's result without claiming a remote control handle."""
        from .runner import _submission_handle

        return _submission_handle(
            goal_id, lambda: self.submit_observed(goal_id, **kwargs), owner="grpc",
        )

    def _submit(
        self, goal_id: int, *, max_dollars: float | None,
        max_wall_seconds: float | None, max_depth: int | None,
        conversation_id: int | None, channel: str | None, user_id: str | None,
        capability: Any | None, concurrency_principal: str | None,
        allowed_suites: frozenset[str] | None, observed: bool,
    ) -> str | None | DispatchObservation:
        from .runner import DispatchObservation, DispatchState, observe_dispatch

        # Never forward the caller-selected scheduler lane across this trust
        # boundary. A per-agent bearer remains authoritative for execution;
        # the shared operator path instead verifies the matching capability /
        # user-id identity against the goal's durable execution binding.
        # Conversation ownership is not yet represented in the gRPC contract;
        # forwarding a raw row id would let a per-agent caller select another
        # owner's history. Queue dispatch authenticates this field, while gRPC
        # deliberately omits it until the worker can authorize the association.
        del concurrency_principal, conversation_id
        if allowed_suites is not None:
            log.warning(
                "gRPC dispatch of goal %s refused: the legacy RunGoal wire "
                "schema cannot preserve an allowed_suites grant",
                goal_id,
            )
            if observed:
                return DispatchObservation(goal_id, DispatchState.NOT_ACCEPTED, None,
                                           owner="grpc", reason="grpc_suite_grant")
            return None
        if max_depth is None:
            from .runner import DEFAULT_MAX_DEPTH
            max_depth = DEFAULT_MAX_DEPTH
        try:
            stub, pb2 = self._build_stub()
        except Exception as e:  # missing extra / bad target
            log.warning("gRPC dispatch unavailable (%s); goal %s not started", e, goal_id)
            if observed:
                return DispatchObservation(goal_id, DispatchState.NOT_ACCEPTED, None,
                                           owner="grpc", reason="grpc_preflight")
            return None
        try:
            request = pb2.RunGoalRequest(
                goal_id=int(goal_id),
                max_dollars=float(max_dollars or 0),
                max_wall_seconds=float(max_wall_seconds or 0),
                channel=channel or "",
                user_id=user_id or "",
                max_depth=int(max_depth),
                capability_json=self._capability_json(capability),
            )
        except Exception:
            if not observed:
                raise
            return DispatchObservation(goal_id, DispatchState.NOT_ACCEPTED, None,
                                       owner="grpc", reason="grpc_request_invalid")
        try:
            status = stub.RunGoal(
                request, timeout=self.timeout_s, metadata=self._metadata(),
            )
        except Exception as e:  # worker down / deadline / auth
            log.warning("gRPC dispatch of goal %s failed: %s", goal_id, e)
            if observed:
                return DispatchObservation(goal_id, DispatchState.UNKNOWN, None,
                                           owner="grpc", reason="grpc_response_unknown")
            return None
        if not getattr(status, "found", False):
            log.warning(
                "gRPC worker has no goal %s — are the API and worker sharing "
                "the world DB ([world_model] backend = 'postgres')?", goal_id)
            if observed:
                return DispatchObservation(goal_id, DispatchState.UNKNOWN, None,
                                           owner="grpc", reason="grpc_status_unknown")
            return None
        result = str(status.status or "") or None
        return observe_dispatch(goal_id, result, owner="grpc") if observed else result


def install_from_config() -> bool:
    """Install the GrpcDispatcher when ``[grpc_dispatch] target`` is set.

    Mirrors ``queue_dispatcher.install_from_config``: returns True when
    installed. Never raises — a bad config logs and leaves the local
    dispatcher in place.
    """
    target = configured_target()
    if not target:
        return False
    try:
        from .runner import set_dispatcher
        set_dispatcher(GrpcDispatcher(target))
        log.info("goal dispatch -> gRPC worker at %s", target)
        return True
    except Exception:  # pragma: no cover -- never break startup on config
        log.exception("gRPC dispatcher install failed (running in-process)")
        return False


__all__ = ["GrpcDispatcher", "configured_target", "install_from_config"]
