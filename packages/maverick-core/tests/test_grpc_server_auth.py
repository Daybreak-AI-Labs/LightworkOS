"""Authentication checks for the gRPC protobuf shim."""
from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from maverick.capability import Capability
from maverick.grpc_api import server as grpc_server
from maverick.grpc_api.service import EventDTO, GoalService, GoalStatusDTO


class _Codes:
    UNAUTHENTICATED = "UNAUTHENTICATED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNAVAILABLE = "UNAVAILABLE"


class _Pb2Grpc:
    class MaverickServicer:
        pass


class _Pb2:
    @dataclass
    class StartGoalResponse:
        goal_id: int

    @dataclass
    class CancelResponse:
        cancelled: bool

    @dataclass
    class GoalStatus:
        goal_id: int
        status: str = ""
        result: str = ""
        found: bool = True

    @dataclass
    class Event:
        id: int
        goal_id: int
        agent: str
        kind: str
        content: str
        ts: float


class _Context:
    def __init__(self, metadata=()):
        self._metadata = metadata
        self.aborted = None

    def invocation_metadata(self):
        return self._metadata

    def is_active(self):
        return True

    def abort(self, code, details):
        self.aborted = (code, details)
        raise PermissionError(details)


class _Service:
    def __init__(self):
        self.calls = []

    def start_goal(self, *args, **kwargs):
        self.calls.append(("start_goal", args, kwargs))
        return 7

    def stream_episode(self, *args, **kwargs):
        self.calls.append(("stream_episode", args, kwargs))
        yield EventDTO(1, 2, "agent", "kind", "content", 3.0)

    def cancel(self, *args, **kwargs):
        self.calls.append(("cancel", args, kwargs))
        return True

    def status(self, *args, **kwargs):
        self.calls.append(("status", args, kwargs))
        return GoalStatusDTO(2, "done", "ok")

    def run_goal(self, *args, **kwargs):
        self.calls.append(("run_goal", args, kwargs))
        return GoalStatusDTO(args[0], "done", "ok")


def test_serve_requires_configured_bearer_token(monkeypatch):
    monkeypatch.delenv("MAVERICK_GRPC_BEARER_TOKEN", raising=False)

    with pytest.raises(ValueError, match="requires a bearer token"):
        grpc_server.serve()


@pytest.mark.parametrize("method_name", ["StartGoal", "StreamEpisode", "Cancel", "GetStatus"])
def test_rpc_methods_reject_missing_bearer_token(monkeypatch, method_name):
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    request = SimpleNamespace(
        title="run", description="", max_dollars=1.0, max_wall_seconds=60.0,
        channel="prod", user_id="victim", goal_id=2, since_id=0, max_seconds=1.0,
    )
    context = _Context()
    call = getattr(servicer, method_name)

    with pytest.raises(PermissionError, match="missing or invalid bearer token"):
        result = call(request, context)
        if method_name == "StreamEpisode":
            list(result)

    assert context.aborted == (_Codes.UNAUTHENTICATED, "missing or invalid bearer token")
    assert svc.calls == []


def test_authorized_calls_reach_all_rpc_methods(monkeypatch):
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    context = _Context((("authorization", "Bearer secret"),))

    start_request = SimpleNamespace(
        title="run", description="", max_dollars=1.0,
        max_wall_seconds=60.0, channel="prod", user_id="user",
    )
    goal_request = SimpleNamespace(goal_id=2, since_id=0, max_seconds=1.0)

    assert servicer.StartGoal(start_request, context).goal_id == 7
    assert list(servicer.StreamEpisode(goal_request, context))[0].content == "content"
    assert servicer.Cancel(goal_request, context).cancelled is True
    assert servicer.GetStatus(goal_request, context).result == "ok"
    assert [call[0] for call in svc.calls] == [
        "start_goal", "stream_episode", "cancel", "status",
    ]
    # The shared operator bearer is the backwards-compatible admin scope: it
    # preserves forwarded execution identity and passes expected_owner=None.
    assert svc.calls[0][2]["owner"] == ""
    assert svc.calls[0][2]["channel"] == "prod"
    assert svc.calls[0][2]["user_id"] == "user"
    assert svc.calls[0][2]["max_dollars"] == 1.0
    assert svc.calls[0][2]["max_wall_seconds"] == 60.0
    for call in svc.calls[1:]:
        assert call[2]["expected_owner"] is None


def test_per_agent_token_binds_owner_and_execution_identity(monkeypatch):
    from maverick import agent_trust
    from maverick.agent_trust import TrustedAgent

    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    registry = {
        "alice": TrustedAgent(
            id="alice", grpc_token="alice-secret", direction="inbound",
            max_dollars=2.0, max_wall_seconds=120.0,
            allow_tools=frozenset({"read_file"}), max_risk="low",
        ),
    }
    monkeypatch.setattr(agent_trust, "load_registry", lambda cfg=None: registry)
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (False, registry))

    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="operator-secret")
    context = _Context((("authorization", "Bearer alice-secret"),))

    start_request = SimpleNamespace(
        title="run", description="", max_dollars=99.0,
        max_wall_seconds=999.0, channel="private", user_id="victim",
    )
    goal_request = SimpleNamespace(goal_id=2, since_id=0, max_seconds=1.0)
    run_request = SimpleNamespace(
        goal_id=2, max_dollars=1.5, max_wall_seconds=30.0,
        channel="private", user_id="victim", max_depth=0,
        capability_json="",
    )

    assert servicer.StartGoal(start_request, context).goal_id == 7
    assert list(servicer.StreamEpisode(goal_request, context))
    assert servicer.Cancel(goal_request, context).cancelled is True
    assert servicer.GetStatus(goal_request, context).found is True
    assert servicer.RunGoal(run_request, context).found is True

    calls = {name: kwargs for name, _args, kwargs in svc.calls}
    assert calls["start_goal"]["owner"] == "agent:alice"
    assert calls["start_goal"]["capability"].principal == "agent:alice"
    assert calls["start_goal"]["channel"] == "grpc"
    assert calls["start_goal"]["user_id"] == "alice"
    assert calls["start_goal"]["max_dollars"] == 2.0
    assert calls["start_goal"]["max_wall_seconds"] == 120.0
    assert calls["stream_episode"]["expected_owner"] == "agent:alice"
    assert calls["cancel"]["expected_owner"] == "agent:alice"
    assert calls["status"]["expected_owner"] == "agent:alice"
    assert calls["run_goal"]["expected_execution_principal"] == "agent:alice"
    assert calls["run_goal"]["capability"].principal == "agent:alice"
    for method in ("start_goal", "run_goal"):
        grant = calls[method]["capability"]
        assert grant.permits("read_file")
        assert not grant.permits("shell")
        assert grant.max_risk == "low"
    assert calls["run_goal"]["channel"] == "grpc"
    assert calls["run_goal"]["user_id"] == "alice"
    # A caller may voluntarily request a stricter budget than the registry cap.
    assert calls["run_goal"]["max_dollars"] == 1.5
    assert calls["run_goal"]["max_wall_seconds"] == 30.0


def test_per_agent_nonfinite_budget_falls_back_to_registry_ceiling():
    from maverick.agent_trust import TrustedAgent

    agent = TrustedAgent(
        id="alice", max_dollars=2.0, max_wall_seconds=120.0,
    )
    assert grpc_server._execution_budget(
        agent, max_dollars=float("nan"), max_wall_seconds=float("inf"),
    ) == (2.0, 120.0)


def test_remote_depth_and_stream_duration_are_worker_bounded(monkeypatch):
    monkeypatch.setenv("MAVERICK_GRPC_MAX_DEPTH", "4")
    monkeypatch.setenv("MAVERICK_GRPC_STREAM_MAX_SECONDS", "30")

    assert grpc_server._execution_depth(1_000_000) == 4
    assert grpc_server._execution_depth(2) == 2
    assert grpc_server._stream_deadline(float("inf")) == 30.0
    assert grpc_server._stream_deadline(5.0) == 5.0



@pytest.mark.parametrize("method_name", ["StreamEpisode", "Cancel", "GetStatus"])
def test_read_and_control_rpcs_enforce_trust_plane(monkeypatch, method_name):
    from maverick import agent_trust
    from maverick.agent_trust import TrustedAgent

    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    registry = {
        "outbound": TrustedAgent(
            id="outbound", grpc_token="agent-secret", direction="outbound"
        )
    }
    monkeypatch.setattr(agent_trust, "load_trust_state", lambda: (True, registry))
    monkeypatch.setattr(agent_trust, "load_registry", lambda cfg=None: registry)

    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    request = SimpleNamespace(goal_id=2, since_id=0, max_seconds=1.0)
    # A shared-operator-bearer caller passes authentication; with the trust plane
    # engaged the read/control RPC must still go through the gate, which
    # default-denies the "grpc" surface when it isn't registered (an outbound
    # per-caller token would instead fail authentication outright -- see
    # agent_for_token -- so the shared bearer is what actually reaches the gate).
    context = _Context((("authorization", "Bearer secret"),))
    call = getattr(servicer, method_name)

    with pytest.raises(PermissionError, match="not in the trust registry"):
        result = call(request, context)
        if method_name == "StreamEpisode":
            list(result)

    assert context.aborted[0] == _Codes.PERMISSION_DENIED
    assert "not in the trust registry" in context.aborted[1]
    assert svc.calls == []

def test_run_goal_intersects_rpc_capability_with_local_policy(monkeypatch):
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    import maverick.capability as capability_mod
    import maverick.queue_dispatcher as queue_dispatcher

    local = Capability(
        principal="user:victim",
        deny_tools=frozenset({"shell"}),
        max_risk="medium",
        allow_paths=frozenset({"/safe/*"}),
        allow_hosts=frozenset({"good.example"}),
    )
    monkeypatch.setattr(capability_mod, "capability_enforced", lambda: True)
    monkeypatch.setattr(capability_mod, "capability_from_config", lambda **kw: local)
    monkeypatch.setattr(queue_dispatcher, "_queue_signing_key", lambda: None)
    supplied = queue_dispatcher._serialize_capability(
        Capability(principal="user:attacker")
    )

    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    context = _Context((("authorization", "Bearer secret"),))
    request = SimpleNamespace(
        goal_id=2, max_dollars=0, max_wall_seconds=0, channel="prod",
        user_id="victim", max_depth=0,
        capability_json=json.dumps(supplied),
    )

    assert servicer.RunGoal(request, context).status == "done"

    call = svc.calls[-1]
    assert call[0] == "run_goal"
    cap = call[2]["capability"]
    assert cap.principal == "user:victim"
    assert cap.deny_tools == frozenset({"shell"})
    assert cap.max_risk == "medium"
    assert cap.allow_paths == frozenset({"/safe/*"})
    assert cap.allow_hosts == frozenset({"good.example"})


@pytest.mark.parametrize(
    ("wire_principal", "found"),
    [
        ("agent:acme.coder", True),
        ("agent:acme.researcher", False),
    ],
)
def test_shared_operator_fleet_dispatch_preserves_exact_bound_agent(
    monkeypatch,
    wire_principal,
    found,
):
    """The shared worker token keeps an agreed opaque agent identity.

    This crosses the protobuf servicer and real GoalService binding/claim seam:
    the human resource owner remains visible, the exact pre-bound fleet agent
    can execute, and a different agent cannot adopt the row.
    """
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    monkeypatch.setattr(grpc_server, "_trust_capability", lambda *_args: None)
    import maverick.capability as capability_mod
    import maverick.queue_dispatcher as queue_dispatcher

    policy_principals = []

    def _local_policy(**kwargs):
        policy_principals.append(kwargs["principal"])
        return Capability(
            principal=kwargs["principal"],
            deny_tools=frozenset({"shell"}),
            max_risk="medium",
        )

    monkeypatch.setattr(capability_mod, "capability_enforced", lambda: True)
    monkeypatch.setattr(capability_mod, "capability_from_config", _local_policy)
    monkeypatch.setattr(queue_dispatcher, "_queue_signing_key", lambda: None)

    goal = SimpleNamespace(
        id=7,
        status="pending",
        result=None,
        owner="user:dana",
        execution_principal="agent:acme.coder",
    )
    dispatches = []

    class _World:
        def get_goal(self, goal_id):
            return goal if goal_id == goal.id else None

        def bind_goal_execution_principal(self, goal_id, principal):
            if goal_id != goal.id or (
                goal.execution_principal
                and goal.execution_principal != principal
            ):
                return False
            goal.execution_principal = principal
            return True

        def claim_goal_for_run(self, goal_id, *, expected_owner=None):
            if (
                goal_id != goal.id
                or goal.status != "pending"
                or (expected_owner is not None and goal.owner != expected_owner)
            ):
                return False
            goal.status = "active"
            return True

        def close(self):
            return None

    def _dispatch(goal_id, **kwargs):
        dispatches.append((goal_id, kwargs["capability"].principal))
        goal.status = "done"
        goal.result = "finished"

    service = GoalService(world_factory=_World, dispatch=_dispatch)
    servicer = grpc_server._servicer(
        service,
        _Pb2,
        _Pb2Grpc,
        bearer_token="operator-secret",
    )
    supplied = queue_dispatcher._serialize_capability(
        Capability(principal=wire_principal),
    )
    request = SimpleNamespace(
        goal_id=7,
        max_dollars=0,
        max_wall_seconds=0,
        channel="fleet",
        user_id=wire_principal,
        max_depth=0,
        capability_json=json.dumps(supplied),
    )

    response = servicer.RunGoal(
        request,
        _Context((("authorization", "Bearer operator-secret"),)),
    )

    assert response.found is found
    assert policy_principals == [wire_principal]
    assert goal.owner == "user:dana"
    assert goal.execution_principal == "agent:acme.coder"
    if found:
        assert response.status == "done"
        assert dispatches == [(7, "agent:acme.coder")]
    else:
        assert goal.status == "pending"
        assert dispatches == []


def test_authenticated_agent_overrides_matching_wire_principal(monkeypatch):
    import maverick.capability as capability_mod

    seen = []
    monkeypatch.setattr(capability_mod, "capability_enforced", lambda: True)

    def _local_policy(**kwargs):
        seen.append(kwargs["principal"])
        return Capability(principal=kwargs["principal"])

    monkeypatch.setattr(capability_mod, "capability_from_config", _local_policy)

    capability = grpc_server._rpc_capability(
        Capability(principal="agent:bob"),
        user_id="agent:bob",
        principal="agent:alice",
    )

    assert seen == ["agent:alice"]
    assert capability.principal == "agent:alice"


def test_run_goal_omitted_capability_still_installs_local_policy(monkeypatch):
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    import maverick.capability as capability_mod

    local = Capability(
        principal="user:victim",
        allow_tools=frozenset({"read_file"}),
        deny_tools=frozenset({"shell"}),
        max_risk="low",
    )
    monkeypatch.setattr(capability_mod, "capability_enforced", lambda: True)
    monkeypatch.setattr(capability_mod, "capability_from_config", lambda **kw: local)

    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    context = _Context((("authorization", "Bearer secret"),))
    request = SimpleNamespace(
        goal_id=2, max_dollars=0, max_wall_seconds=0, channel="prod",
        user_id="victim", max_depth=0, capability_json="",
    )

    assert servicer.RunGoal(request, context).status == "done"
    cap = svc.calls[-1][2]["capability"]
    assert cap is local
    assert cap.permits("read_file")
    assert not cap.permits("shell")


def test_start_goal_intersects_trust_ceiling_with_local_policy(monkeypatch):
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    import maverick.capability as capability_mod

    local = Capability(
        principal="user:victim",
        allow_tools=frozenset({"read_file", "shell"}),
        deny_tools=frozenset({"shell"}),
        max_risk="medium",
    )
    trust = Capability(
        principal="agent:remote",
        allow_tools=frozenset({"read_file"}),
        max_risk="high",
    )
    monkeypatch.setattr(capability_mod, "capability_enforced", lambda: True)
    monkeypatch.setattr(capability_mod, "capability_from_config", lambda **kw: local)
    monkeypatch.setattr(grpc_server, "_trust_capability", lambda context, agent: trust)

    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    context = _Context((("authorization", "Bearer secret"),))
    request = SimpleNamespace(
        title="run", description="", max_dollars=0,
        max_wall_seconds=0, channel="prod", user_id="victim",
    )

    assert servicer.StartGoal(request, context).goal_id == 7
    cap = svc.calls[-1][2]["capability"]
    assert cap.principal == "user:victim"
    assert cap.allow_tools == frozenset({"read_file"})
    assert cap.max_risk == "medium"
    assert cap.permits("read_file")
    assert not cap.permits("shell")


def test_run_goal_rejects_malformed_capability_json(monkeypatch):
    monkeypatch.setattr(grpc_server, "_grpc_code", lambda: _Codes)
    svc = _Service()
    servicer = grpc_server._servicer(svc, _Pb2, _Pb2Grpc, bearer_token="secret")
    context = _Context((("authorization", "Bearer secret"),))
    request = SimpleNamespace(
        goal_id=2, max_dollars=0, max_wall_seconds=0, channel="prod",
        user_id="victim", max_depth=0, capability_json='{"principal":',
    )

    with pytest.raises(PermissionError):
        servicer.RunGoal(request, context)

    assert context.aborted[0] == _Codes.INVALID_ARGUMENT
    assert svc.calls == []
