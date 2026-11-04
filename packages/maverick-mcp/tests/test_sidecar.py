"""Focused contract tests for the governed external-MCP sidecar."""
from __future__ import annotations

import json

import pytest
from maverick_mcp.sidecar import (
    BudgetDecision,
    GateDecision,
    GovernedMCPGateway,
    SidecarCallBudget,
    SidecarConfig,
    SidecarConfigError,
    build_app,
)


class _Upstream:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def call(self, tool, arguments, request_id):
        self.calls.append((tool, dict(arguments), request_id))
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": "reviewed result"}]},
        }


class _BlockingShield:
    def __init__(self, blocked_text: str) -> None:
        self.blocked_text = blocked_text

    def scan_input(self, text: str):
        return type("Verdict", (), {"blocked": self.blocked_text in text})()


def _config(**overrides) -> SidecarConfig:
    raw = {
        "enable": True,
        "upstream_url": "https://mcp.example.test/mcp",
        "require_shield": False,
        "tools": {
            "search": {
                "risk": "low",
                "description": "A reviewed search endpoint",
                "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
                "obligation_tags": ["reviewed-search"],
            }
        },
    }
    raw.update(overrides)
    return SidecarConfig.from_mapping(raw)


def _gateway(config: SidecarConfig | None = None, **overrides):
    upstream = overrides.pop("upstream", _Upstream())
    audits: list[dict] = []

    def _audit(phase: str, **payload) -> bool:
        audits.append({"phase": phase, **payload})
        return True

    gateway = GovernedMCPGateway(
        config or _config(),
        upstream=upstream,
        trust_decider=overrides.pop(
            "trust_decider",
            lambda _principal, _action, _risk: GateDecision(
                True, "allow", "trusted", capability=object()
            ),
        ),
        policy_decider=overrides.pop(
            "policy_decider",
            lambda _action, _risk, capability: GateDecision(
                True, "allow", "policy passed", capability=capability, profiles=()
            ),
        ),
        halt_checker=overrides.pop("halt_checker", lambda: None),
        egress_checker=overrides.pop("egress_checker", lambda _url, _action: None),
        shield_factory=overrides.pop("shield_factory", lambda: None),
        auditor=overrides.pop("auditor", _audit),
        token_resolver=overrides.pop("token_resolver", lambda token: "alpha" if token == "good" else None),
        **overrides,
    )
    return gateway, upstream, audits


def _call(name: str = "search", arguments: dict | None = None, request_id: int = 7) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {"query": "quarterly report"}},
    }


@pytest.mark.parametrize("kind", ["json", "sse", "progress", "split", "cr", "multiline"])
def test_http_upstream_decodes_advertised_formats(monkeypatch, kind):
    from types import SimpleNamespace

    from maverick_mcp.sidecar import HttpMCPUpstream

    monkeypatch.setattr("maverick.enterprise.enterprise_egress_denial", lambda *a, **kw: None)
    result = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "résult"}]}}
    data = json.dumps(result, ensure_ascii=False).encode()
    if kind != "json":
        data = b"data: " + data + b"\r\n\r\n"
    if kind == "progress":
        data = b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n' + data
    if kind == "cr":
        data = data.replace(b"\r\n", b"\r")
    if kind == "multiline":
        data = data.replace(b'"id": 7,', b'"id": 7,\r\ndata:')
    chunks = [data[i:i+1] for i in range(len(data))] if kind == "split" else [data]
    response = SimpleNamespace(status_code=200, headers={"content-type": "application/json" if kind == "json" else "text/event-stream"},
                               iter_bytes=lambda **kw: iter(chunks))
    calls = []

    def post(*args, **kwargs):
        calls.append(kwargs)
        return response

    config = _config()
    assert HttpMCPUpstream(config, client=SimpleNamespace(post=post)).call(config.tools[0], {}, 7) == result
    assert len(calls) == 1


@pytest.mark.parametrize("data", [b'data: {"jsonrpc":"2.0","id":8,"result":{}}\n\n',
    b'data: {"jsonrpc":"2.0","id":7,"result":{}}\n', b'data: \xff\n\n', b"x" * 129])
def test_http_upstream_never_replays_invalid_or_incomplete_sse(monkeypatch, data):
    from types import SimpleNamespace

    from maverick_mcp.sidecar import HttpMCPUpstream, SidecarUpstreamError

    monkeypatch.setattr("maverick.enterprise.enterprise_egress_denial", lambda *a, **kw: None)
    monkeypatch.setattr("maverick_mcp.sidecar._MAX_RESPONSE_BYTES", 128)
    calls = []

    def post(*args, **kwargs):
        calls.append(1)
        return SimpleNamespace(status_code=200, headers={"content-type": "text/event-stream"}, content=data)

    config = _config()
    with pytest.raises(SidecarUpstreamError):
        HttpMCPUpstream(config, client=SimpleNamespace(post=post)).call(config.tools[0], {}, 7)
    assert calls == [1]


def test_sidecar_admits_only_manifested_tool_and_audits_closed_metadata():
    gateway, upstream, audits = _gateway()

    result = gateway.handle_rpc("alpha", _call())

    assert result["result"]["content"][0]["text"] == "reviewed result"
    assert len(upstream.calls) == 1
    assert {row["phase"] for row in audits} == {"screened", "terminal"}
    screen = next(row for row in audits if row["phase"] == "screened")
    assert screen["tool"] == "mcp_sidecar__search"
    assert screen["upstream_tool"] == "search"
    assert screen["declared_obligation_tags"] == ["reviewed-search"]
    assert len(screen["request_sha256"]) == 64
    assert "quarterly report" not in json.dumps(audits, sort_keys=True)


def test_sidecar_refuses_an_unbound_upstream_tool_before_egress():
    gateway, upstream, audits = _gateway()

    result = gateway.handle_rpc("alpha", _call("unreviewed"))

    assert result["error"]["data"]["rule"] == "unbound_tool"
    assert upstream.calls == []
    assert audits[-1]["allowed"] is False


def test_sidecar_rechecks_trust_and_refuses_revoked_principal_before_egress():
    gateway, upstream, _audits = _gateway(
        trust_decider=lambda _principal, _action, _risk: GateDecision(
            False, "revoked", "external agent credential is revoked"
        )
    )

    result = gateway.handle_rpc("alpha", _call())

    assert result["error"]["data"]["rule"] == "revoked"
    assert upstream.calls == []


def test_sidecar_returns_human_approval_requirement_without_proxying():
    gateway, upstream, _audits = _gateway(
        policy_decider=lambda _action, _risk, capability: GateDecision(
            False,
            "require_human_min_risk",
            "reviewed policy requires human approval",
            capability=capability,
            requires_human=True,
            profiles=("eu_ai_act",),
        )
    )

    result = gateway.handle_rpc("alpha", _call())

    assert result["error"]["data"]["rule"] == "human_approval_required"
    assert upstream.calls == []


def test_sidecar_refuses_shield_blocked_arguments_without_proxying():
    gateway, upstream, _audits = _gateway(
        _config(require_shield=True), shield_factory=lambda: _BlockingShield("danger")
    )

    result = gateway.handle_rpc("alpha", _call(arguments={"query": "danger"}))

    assert result["error"]["data"]["rule"] == "shield"
    assert upstream.calls == []


def test_sidecar_rechecks_halt_after_budget_reservation_before_egress():
    checks = {"count": 0}

    def _halt_check():
        checks["count"] += 1
        if checks["count"] == 2:
            raise RuntimeError("halted")

    gateway, upstream, _audits = _gateway(halt_checker=_halt_check)

    result = gateway.handle_rpc("alpha", _call())

    assert result["error"]["data"]["rule"] == "halted"
    assert upstream.calls == []
    assert checks["count"] == 2


def test_sidecar_durable_budget_refuses_second_call(tmp_path):
    config = _config(max_calls_per_window=1)
    private_dir = tmp_path / "sidecar-private"
    budget = SidecarCallBudget(config, path=private_dir / "budget.json")
    gateway, upstream, _audits = _gateway(config, budget=budget)

    first = gateway.handle_rpc("alpha", _call(request_id=1))
    second = gateway.handle_rpc("alpha", _call(request_id=2))

    assert "result" in first
    assert second["error"]["data"]["rule"] == "budget_exhausted"
    assert len(upstream.calls) == 1


def test_sidecar_http_surface_requires_per_agent_bearer_and_serves_manifest():
    fastapi = pytest.importorskip("fastapi")
    del fastapi
    from fastapi.testclient import TestClient

    config = _config(allowed_origins=["http://testserver"])
    gateway, _upstream, _audits = _gateway(config)
    client = TestClient(build_app(gateway), headers={"Origin": "http://testserver"})

    denied = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    listed = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers={"Authorization": "Bearer good"},
    )

    assert denied.status_code == 401
    assert listed.status_code == 200
    assert listed.json()["result"]["tools"][0]["name"] == "search"


def test_sidecar_config_requires_https_except_loopback_and_rejects_unknown_keys():
    with pytest.raises(SidecarConfigError, match="https"):
        _config(upstream_url="http://mcp.example.test/mcp")
    with pytest.raises(SidecarConfigError, match="unknown keys"):
        _config(unreviewed=True)


def test_budget_decision_shape_is_stable():
    decision = BudgetDecision(True, "budget_reserved", "reserved", remaining=9)
    assert decision.allowed and decision.remaining == 9
