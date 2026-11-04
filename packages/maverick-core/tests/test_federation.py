"""Federated swarm protocol: peers config, hello/delegate/status over a fake
transport, shared-token auth (fail-closed), capability narrowing on accept,
and the matching audit rows both halves of a delegation record."""
from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace
from uuid import uuid4

import pytest
from maverick import federation
from maverick import federation_admission as admission
from maverick.capability import Capability
from maverick.federation import (
    PROTOCOL,
    FederationAuthError,
    FederationError,
    FederationNode,
    FederationService,
    Peer,
    load_peers,
)
from maverick.grpc_api.service import GoalService
from maverick.paths import data_dir
from maverick.world_model import WorldModel

# ---- fakes ----------------------------------------------------------------


class _Recorder:
    """Audit seam capturing rows shaped like AuditEvent.to_dict() output
    (payload spread at top level)."""

    def __init__(self):
        self.rows = []

    def __call__(self, kind, *, agent="system", goal_id=None, **payload):
        self.rows.append({"kind": kind, "agent": agent, "goal_id": goal_id, **payload})
        return True


class _Goals(GoalService):
    """Native durable admission/status with a synchronous model-free dispatcher."""

    def __init__(self):
        self.started = []
        self.path = data_dir().parent / f"test-federation-{uuid4().hex}" / "world.db"
        super().__init__(world_factory=lambda: WorldModel(self.path),
                         dispatch=self._run, spawn=lambda fn: fn())

    def _run(self, goal_id, **kw):
        with WorldModel(self.path) as world:
            admission.require_execution(
                world, goal_id, capability=kw["capability"],
                max_dollars=kw["max_dollars"],
                max_wall_seconds=kw["max_wall_seconds"], consume=True,
            )
            goal = world.get_goal(goal_id)
            self.started.append({"title": goal.title, "description": goal.description,
                                 "owner": goal.owner, **kw})
            world.set_goal_status(goal_id, "done", result=f"did: {goal.title}")


def _service(**kw):
    """Node B's serve half; node A authenticates with token "tok"."""
    kw.setdefault("node", "B")
    kw.setdefault("peers", [Peer("A", "a.internal:50061", "tok")])
    kw.setdefault("local_grant", None)  # enforcement off unless a test injects
    kw.setdefault("goal_service", _Goals())
    kw.setdefault("record", _Recorder())
    return FederationService(**kw)


def _node(service, *, token="tok", **kw):
    """Node A's client half, wired straight to ``service`` — a
    FederationService satisfies the transport seam (call(method, payload))."""
    kw.setdefault("node", "A")
    kw.setdefault("peers", [Peer("B", "b.internal:50061", token)])
    kw.setdefault("record", _Recorder())
    kw.setdefault("transport_factory", lambda peer: service)
    return FederationNode(**kw)


# ---- peers config ---------------------------------------------------------


def test_load_peers_parses_config():
    cfg = {"federation": {"peers": [
        {"name": "edge-1", "target": "edge-1.internal:50061", "token": "s3cret"},
        {"name": "edge-2", "target": "edge-2.internal:50061"},
    ]}}
    peers = load_peers(cfg)
    assert [p.name for p in peers] == ["edge-1", "edge-2"]
    assert peers[0].target == "edge-1.internal:50061"
    assert peers[0].token == "s3cret"
    assert peers[1].token == ""  # token optional in config; can't authenticate


def test_load_peers_forgiving_on_malformed():
    cfg = {"federation": {"peers": [
        "junk", 42,
        {"name": "", "target": "x:1"},          # blank name
        {"name": "no-target"},                  # missing target
        {"name": "dup", "target": "x:1"},
        {"name": "dup", "target": "y:1"},       # duplicate: first wins
        {"name": "coerced", "target": "z:1", "token": 123},
    ]}}
    peers = load_peers(cfg)
    assert [(p.name, p.target) for p in peers] == [("dup", "x:1"), ("coerced", "z:1")]
    assert peers[1].token == "123"
    assert load_peers({"federation": {"peers": "nope"}}) == []
    assert load_peers({"federation": "nope"}) == []
    assert load_peers({}) == []


def test_duplicate_peer_tokens_are_ambiguous_and_cannot_authenticate():
    peers = load_peers({"federation": {"peers": [
        {"name": "a", "target": "a:1", "token": "shared"},
        {"name": "b", "target": "b:1", "token": "shared"},
    ]}})

    assert [peer.token for peer in peers] == ["", ""]
    assert federation._match_token(
        [Peer("a", "a:1", "shared"), Peer("b", "b:1", "shared")],
        "shared",
    ) is None


def test_a_lone_surrogate_token_matches_no_peer():
    # A peer's JSON auth_token can carry a lone surrogate; it authenticates nobody.
    assert federation._match_token([Peer("a", "a:1", "secret-a")], "\ud800") is None


def test_disabled_by_default_and_env_opt_in(monkeypatch):
    monkeypatch.delenv("MAVERICK_FEDERATION_ENABLED", raising=False)
    assert federation.federation_enabled() is False
    with pytest.raises(RuntimeError, match="disabled"):
        federation.serve()  # the gate fires before any grpc import
    monkeypatch.setenv("MAVERICK_FEDERATION_ENABLED", "1")
    assert federation.federation_enabled() is True


# ---- hello (discovery) ----------------------------------------------------


def test_hello_returns_parsed_agent_card():
    card = _node(_service()).hello("B")
    assert card["name"] == "Lightwork"
    assert card["url"].endswith("/a2a/v1")
    assert {s["id"] for s in card["skills"]} >= {"execute-goal"}


def test_hello_refuses_wrong_token_fail_closed():
    with pytest.raises(FederationAuthError, match="invalid token"):
        _node(_service(), token="wrong").hello("B")


def test_hello_refuses_non_conformant_card():
    bad = SimpleNamespace(call=lambda method, payload: {
        "node": "B", "protocol": PROTOCOL,
        "agent_card_json": json.dumps({"name": "shady"}),  # missing url/skills/...
    })
    node = _node(None, transport_factory=lambda peer: bad)
    with pytest.raises(ValueError, match="non-conformant"):
        node.hello("B")


def test_hello_refuses_protocol_mismatch():
    other = SimpleNamespace(call=lambda method, payload: {
        "node": "B", "protocol": "maverick-federation/999", "agent_card_json": "{}",
    })
    node = _node(None, transport_factory=lambda peer: other)
    with pytest.raises(FederationError, match="maverick-federation/1"):
        node.hello("B")


def test_unknown_peer_and_unknown_method_refused():
    svc = _service()
    with pytest.raises(FederationError, match="unknown federation peer"):
        _node(svc).hello("ghost")
    with pytest.raises(FederationError, match="unknown federation method"):
        svc.call("Nope", {})


# ---- delegate (round trip + reciprocity) ----------------------------------


def test_delegate_round_trip_records_reciprocal_halves():
    rec_a, rec_b = _Recorder(), _Recorder()
    goals = _Goals()
    svc_b = _service(goal_service=goals, record=rec_b)
    node_a = _node(svc_b, record=rec_a)

    out = node_a.delegate("B", "Summarize the logs", "last 24h",
                          requested_tools={"read_file"}, correlation_id="corr-1")
    assert out.accepted is True and out.goal_id == 1 and out.peer == "B"
    assert goals.started[0]["title"] == "Summarize the logs"

    # Both halves carry the shared peer/direction/correlation fields.
    (a_row,), (b_row,) = rec_a.rows, rec_b.rows
    assert (a_row["peer_node"], a_row["direction"], a_row["correlation_id"]) == \
        ("B", "sent", "corr-1")
    assert (b_row["peer_node"], b_row["direction"], b_row["correlation_id"]) == \
        ("A", "received", "corr-1")
    assert b_row["goal_id"] == 1 and b_row["accepted"] is True

    # Status flows back over the same seam.
    assert node_a.status("B", out.goal_id) == ("done", "did: Summarize the logs")


def test_correlation_id_autogenerated_and_shared():
    rec_a, rec_b = _Recorder(), _Recorder()
    svc_b = _service(record=rec_b)
    out = _node(svc_b, record=rec_a).delegate("B", "task")
    assert out.correlation_id  # generated when the caller didn't supply one
    assert rec_a.rows[0]["correlation_id"] == out.correlation_id
    assert rec_b.rows[0]["correlation_id"] == out.correlation_id


def test_delegate_requires_correlation_id_server_side():
    svc = _service()
    reply = svc.call("DelegateGoal", {
        "goal_title": "t", "auth_token": "tok", "correlation_id": "",
    })
    assert reply["accepted"] is False
    assert "correlation_id" in reply["reason"]


# ---- auth (fail-closed) ----------------------------------------------------


def test_delegate_wrong_token_fail_closed():
    rec_b = _Recorder()
    goals = _Goals()
    svc_b = _service(goal_service=goals, record=rec_b)
    out = _node(svc_b, token="wrong").delegate("B", "task", correlation_id="c")
    assert out.accepted is False and out.goal_id is None
    assert "unauthorized" in out.reason
    assert goals.started == []  # never reached goal creation
    # The refusal row is deliberately unattributed (no spoofable peer name),
    # so it never pairs with another node's half.
    assert "peer_node" not in rec_b.rows[0]


def test_delegate_missing_token_fail_closed():
    goals = _Goals()
    # Even the peer entry having an empty token must never authenticate.
    svc_b = _service(peers=[Peer("A", "a:1", "")], goal_service=goals)
    out = _node(svc_b, token="").delegate("B", "task", correlation_id="c")
    assert out.accepted is False and "unauthorized" in out.reason
    assert goals.started == []


def test_status_requires_token():
    with pytest.raises(FederationAuthError):
        _service().call("GoalStatus", {"goal_id": 1, "auth_token": "wrong"})


def test_status_owner_scoped_across_peers():
    """A peer may only poll goals IT delegated. Peer B presenting its own valid
    token must not read peer A's delegated goal (status or result) — it gets
    "unknown", indistinguishable from a non-existent id."""
    goals = _Goals()
    svc = _service(peers=[Peer("A", "a:1", "tok-a"), Peer("B", "b:1", "tok-b")],
                   goal_service=goals)
    # A delegates a goal -> owner "federation:A", goal_id 1.
    out = svc.call("DelegateGoal", {
        "goal_title": "A's secret task", "correlation_id": "ca",
        "auth_token": "tok-a"})
    assert out["accepted"] is True and out["goal_id"] == 1

    # A can read its own goal.
    mine = svc.call("GoalStatus", {"goal_id": 1, "auth_token": "tok-a"})
    assert mine["status"] == "done" and "A's secret task" in mine["result"]

    # B (valid token, different peer) is denied — no status, no result leak.
    theirs = svc.call("GoalStatus", {"goal_id": 1, "auth_token": "tok-b"})
    assert theirs == {"status": "unknown", "result": ""}


# ---- capability narrowing on accept ----------------------------------------


def test_delegate_refused_when_local_grant_lacks_tool():
    goals = _Goals()
    rec_b = _Recorder()
    grant = Capability(principal="root", allow_tools=frozenset({"read_file"}))
    svc_b = _service(local_grant=grant, goal_service=goals, record=rec_b)
    out = _node(svc_b).delegate("B", "task", requested_tools={"read_file", "shell"},
                                correlation_id="c3")
    assert out.accepted is False and "shell" in out.reason
    assert goals.started == []
    # The refusal is still a recorded, reciprocable cross-swarm event.
    assert rec_b.rows[0]["peer_node"] == "A"
    assert rec_b.rows[0]["accepted"] is False and rec_b.rows[0]["direction"] == "received"


def test_delegate_accepted_within_local_grant_passes_narrowed_capability():
    goals = _Goals()
    grant = Capability(principal="root",
                       allow_tools=frozenset({"read_file", "http_fetch"}))
    svc_b = _service(local_grant=grant, goal_service=goals)
    out = _node(svc_b).delegate("B", "task", requested_tools={"read_file"})
    assert out.accepted is True and out.goal_id == 1
    capability = goals.started[0]["capability"]
    assert capability.principal == "federation:A"
    assert capability.allow_tools == frozenset({"read_file"})
    assert capability.permits("read_file") is True
    assert capability.permits("http_fetch") is False


def test_delegate_empty_title_refused_in_band():
    out = _node(_service()).delegate("B", "   ", correlation_id="c4")
    assert out.accepted is False and "title" in out.reason


# ---- deadline -------------------------------------------------------------


def test_deadline_plumbed_to_goal_service():
    goals = _Goals()
    svc_b = _service(goal_service=goals)
    out = _node(svc_b).delegate("B", "task", deadline_ms=2500)
    assert out.accepted is True
    assert goals.started[0]["max_wall_seconds"] == 2.5
    assert goals.started[0]["channel"] == "federation"
    assert goals.started[0]["user_id"] == "federation:A"


def test_no_deadline_uses_first_install_wall_cap():
    goals = _Goals()
    _node(_service(goal_service=goals)).delegate("B", "task")
    assert goals.started[0]["max_wall_seconds"] == 1800.0


# ---- gRPC binding (thin adapter; no grpcio needed) --------------------------


class _Pb2Grpc:
    class MaverickFederationServicer:
        pass


class _Pb2:
    @dataclass
    class PeerInfo:
        node: str
        protocol: str
        agent_card_json: str

    @dataclass
    class DelegateResult:
        accepted: bool
        goal_id: int
        reason: str
        outcome_state: str = ""
        audit_state: str = ""
        execution_state: str = ""

    @dataclass
    class StatusReply:
        status: str
        result: str


class _Context:
    def __init__(self):
        self.aborted = None

    def abort(self, code, details):
        self.aborted = (code, details)
        raise PermissionError(details)


def test_grpc_servicer_maps_messages_over_the_dict_seam():
    svc_b = _service()
    servicer = federation._servicer(svc_b, _Pb2, _Pb2Grpc)

    info = servicer.Hello(
        SimpleNamespace(node="A", protocol=PROTOCOL, auth_token="tok"), _Context())
    assert info.protocol == PROTOCOL
    assert json.loads(info.agent_card_json)["name"] == "Lightwork"

    result = servicer.DelegateGoal(SimpleNamespace(
        goal_title="t", goal_description="", correlation_id="c5",
        requested_tools=["read_file"], max_risk="", deadline_ms=0,
        auth_token="tok"), _Context())
    assert result.accepted is True and result.goal_id == 1 and result.reason == ""

    status = servicer.GoalStatus(
        SimpleNamespace(goal_id=1, auth_token="tok"), _Context())
    assert status.status == "done" and status.result == "did: t"


def test_grpc_servicer_aborts_unauthenticated(monkeypatch):
    monkeypatch.setattr(
        federation, "_grpc_code",
        lambda: SimpleNamespace(UNAUTHENTICATED="UNAUTHENTICATED"))
    servicer = federation._servicer(_service(), _Pb2, _Pb2Grpc)
    context = _Context()
    with pytest.raises(PermissionError, match="invalid token"):
        servicer.Hello(
            SimpleNamespace(node="A", protocol=PROTOCOL, auth_token="bad"), context)
    assert context.aborted[0] == "UNAUTHENTICATED"
