"""End-to-end authorization tests for network-reachable MCP tools.

These tests intentionally cross the HTTP bearer boundary.  A unit test of
``Capability.permits`` would not catch the original defect: authentication
resolved the right TrustedAgent, then HTTP dispatch discarded its capability.
"""
from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402
from maverick import agent_trust  # noqa: E402
from maverick.agent_trust import TrustedAgent  # noqa: E402
from maverick_mcp.http_transport import build_app  # noqa: E402
from maverick_mcp.server import MCPServer  # noqa: E402
from maverick_mcp.tasks import TaskStore  # noqa: E402


def test_failed_authentication_budget_is_per_peer(monkeypatch):
    from maverick_mcp import http_transport

    monkeypatch.setattr(http_transport, "_AUTH_FAILURES", {})
    for _ in range(http_transport._AUTH_FAILURE_LIMIT):
        assert http_transport._auth_failure_budget("192.0.2.1", failed=True)
    assert not http_transport._auth_failure_budget("192.0.2.1")
    assert http_transport._auth_failure_budget("192.0.2.2")


def test_auth_failure_capacity_does_not_leave_new_peers_unlimited(monkeypatch):
    from maverick_mcp import http_transport

    monkeypatch.setattr(http_transport, "_AUTH_FAILURES", {})
    monkeypatch.setattr(http_transport, "_RATE_MAX_KEYS", 1)
    assert http_transport._auth_failure_budget("192.0.2.1", failed=True)
    assert not http_transport._auth_failure_budget("192.0.2.2")


def _client(
    monkeypatch,
    *,
    registry: dict[str, TrustedAgent],
    token: str,
    shared: bool = False,
    enforced: bool = True,
    tasks: bool = False,
) -> tuple[TestClient, MCPServer, dict[str, str]]:
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    if shared:
        monkeypatch.setenv("MAVERICK_MCP_TOKEN", token)
    else:
        monkeypatch.delenv("MAVERICK_MCP_TOKEN", raising=False)
    if tasks:
        monkeypatch.setenv("MAVERICK_MCP_HTTP_TASKS", "1")
    else:
        monkeypatch.delenv("MAVERICK_MCP_HTTP_TASKS", raising=False)
    monkeypatch.setattr(
        agent_trust,
        "load_trust_state",
        lambda: (enforced, registry),
    )
    server = MCPServer()
    server._shield = None
    client = TestClient(build_app(server))
    return client, server, {"Authorization": f"Bearer {token}"}


def _rpc(client: TestClient, headers: dict[str, str], method: str, params=None):
    return client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {},
        },
    ).json()


def _tool_names(body: dict) -> set[str]:
    return {tool["name"] for tool in body["result"]["tools"]}


def test_failed_bearer_attempts_are_throttled_before_authentication(monkeypatch):
    from maverick_mcp import http_transport

    monkeypatch.setattr(http_transport, "_AUTH_FAILURES", {})
    client, _, _ = _client(monkeypatch, registry={}, token="known", shared=True)
    for _ in range(http_transport._AUTH_FAILURE_LIMIT):
        assert client.post("/mcp", headers={"Authorization": "Bearer wrong"}, json={}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer wrong"}, json={}).status_code == 429


def test_per_agent_fleet_recall_enforces_scope_when_global_trust_is_off(monkeypatch, tmp_path):
    from maverick import dreaming, fleet_memory, reflexion

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLEET_MEMORY", "1")
    assert fleet_memory.register_agent("reader", "copilot")
    reader = TrustedAgent(id="reader", mcp_token="reader-token", direction="inbound",
                          data_scopes=frozenset({"sales"}))
    client, _, headers = _client(monkeypatch, registry={"reader": reader},
                                 token="reader-token", enforced=False)
    monkeypatch.setattr(reflexion, "recall", lambda *args, **kwargs: [
        (1.0, SimpleNamespace(domain="finance", reflection="finance secret")),
        (1.0, SimpleNamespace(domain="sales", reflection="sales lesson")),
    ])
    monkeypatch.setattr(reflexion, "format_context", lambda hits, **kwargs: " ".join(
        item.reflection for _, item in hits))
    monkeypatch.setattr(dreaming, "recall_insights", lambda *args, **kwargs: [])
    params = {"name": "maverick_fleet_recall", "arguments": {
        "agent_id": "reader", "vendor": "copilot", "query": "work", "domain": "sales",
    }}
    allowed = _rpc(client, headers, "tools/call", params)
    assert "sales lesson" in json.dumps(allowed)
    assert "finance secret" not in json.dumps(allowed)
    params["arguments"]["domain"] = "finance"
    denied = _rpc(client, headers, "tools/call", params)
    assert "finance secret" not in json.dumps(denied)
    assert "scope" in json.dumps(denied).lower()


def test_low_risk_agent_cannot_list_or_invoke_mutating_tools(monkeypatch):
    reader = TrustedAgent(
        id="reader",
        mcp_token="reader-token",
        direction="inbound",
        max_risk="low",
    )
    client, server, headers = _client(
        monkeypatch,
        registry={"reader": reader},
        token="reader-token",
    )
    invoked: list[tuple[str, str | None]] = []

    def _dispatch(name, _arguments):
        invoked.append((name, __import__("maverick.fleet_memory").fleet_memory._caller.get()))
        return "ok"

    server._dispatch_tool = _dispatch
    server._structured_result = lambda _name: None

    listed = _tool_names(_rpc(client, headers, "tools/list"))
    assert {
        "maverick_status",
        "maverick_skills_list",
        "maverick_fleet_recall",
        "maverick_facts_get",
    } <= listed
    assert {
        "maverick_start",
        "maverick_resume",
        "maverick_answer",
        "maverick_skill_install",
        "maverick_fact_set",
        "maverick_fleet_ingest",
    }.isdisjoint(listed)

    allowed = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert allowed["result"]["isError"] is False
    assert invoked == [("maverick_status", "reader")]

    denied = _rpc(
        client,
        headers,
        "tools/call",
        {
            "name": "maverick_fact_set",
            "arguments": {"key": "backdoor", "value": "enabled"},
        },
    )
    assert denied["error"]["code"] == -32602
    assert invoked == [("maverick_status", "reader")]


def test_agent_allowlist_and_denylist_both_filter_and_enforce(monkeypatch):
    scoped = TrustedAgent(
        id="scoped",
        mcp_token="scoped-token",
        allow_tools=frozenset({"maverick_status", "maverick_fact_set"}),
        deny_tools=frozenset({"maverick_fact_set"}),
        max_risk="high",
    )
    client, _server, headers = _client(
        monkeypatch,
        registry={"scoped": scoped},
        token="scoped-token",
    )

    assert _tool_names(_rpc(client, headers, "tools/list")) == {"maverick_status"}
    for denied_name, arguments in (
        ("maverick_fact_set", {"key": "x", "value": "y"}),
        ("maverick_skills_list", {}),
    ):
        denied = _rpc(
            client,
            headers,
            "tools/call",
            {"name": denied_name, "arguments": arguments},
        )
        assert denied["error"]["code"] == -32602


def test_enforced_shared_bearer_uses_explicit_mcp_capability(monkeypatch):
    surface = TrustedAgent(
        id="mcp",
        allow_tools=frozenset({"maverick_status"}),
        max_risk="low",
    )
    client, _server, headers = _client(
        monkeypatch,
        registry={"mcp": surface},
        token="shared-token",
        shared=True,
        enforced=True,
    )

    assert _tool_names(_rpc(client, headers, "tools/list")) == {"maverick_status"}
    denied = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_start", "arguments": {"title": "escape"}},
    )
    assert denied["error"]["code"] == -32602


def test_disengaged_shared_bearer_remains_explicitly_unscoped(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="legacy-shared",
        shared=True,
        enforced=False,
    )

    listed = _tool_names(_rpc(client, headers, "tools/list"))
    assert "maverick_status" in listed
    assert "maverick_start" in listed
    assert "maverick_fact_set" in listed
    invoked = []
    server._dispatch_tool = lambda name, _arguments: invoked.append(name) or "ok"
    server._structured_result = lambda _name: None
    allowed = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert allowed["result"]["isError"] is False
    assert invoked == ["maverick_status"]


def test_disengaged_shared_bearer_honors_mcp_principal_revocation(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="legacy-shared",
        shared=True,
        enforced=False,
        tasks=True,
    )
    from maverick import revocation

    monkeypatch.setattr(
        revocation,
        "revoked_principal",
        lambda principals: "mcp" if "mcp" in principals else None,
    )
    invoked = []
    server._dispatch_tool = lambda name, _arguments: invoked.append(name) or "ok"

    assert _rpc(client, headers, "tools/list")["result"]["tools"] == []
    denied = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert denied["error"] == {
        "code": -32602,
        "message": "unknown tool: 'maverick_status'",
    }
    denied_task = _rpc(
        client,
        headers,
        "tools/call",
        {
            "name": "maverick_start",
            "arguments": {"title": "must-not-run"},
            "task": {"ttl": 60_000},
        },
    )
    assert denied_task["error"] == {
        "code": -32602,
        "message": "unknown tool: 'maverick_start'",
    }
    assert invoked == []
    assert server._tasks is None


def test_low_risk_agent_cannot_start_or_resume_async_task(monkeypatch):
    reader = TrustedAgent(
        id="reader",
        mcp_token="reader-token",
        max_risk="low",
    )
    client, server, headers = _client(
        monkeypatch,
        registry={"reader": reader},
        token="reader-token",
        tasks=True,
    )

    for name, arguments in (
        ("maverick_start", {"title": "mutate"}),
        ("maverick_resume", {"goal_id": 1}),
    ):
        denied = _rpc(
            client,
            headers,
            "tools/call",
            {
                "name": name,
                "arguments": arguments,
                "task": {"ttl": 60_000},
            },
        )
        assert denied["error"]["code"] == -32602

    # Authorization occurs before task-store creation, so no denied task can
    # race into the executor and run in the background.
    assert server._tasks is None


def test_start_and_resume_attenuate_internal_goal_run(monkeypatch):
    delegated = TrustedAgent(
        id="delegated",
        mcp_token="delegated-token",
        allow_tools=frozenset({
            "maverick_start",
            "maverick_resume",
            "read_file",
        }),
        max_risk="high",
    )
    client, _server, headers = _client(
        monkeypatch,
        registry={"delegated": delegated},
        token="delegated-token",
    )

    from maverick import connections, llm, orchestrator, sandbox, world_model

    class _World:
        def create_goal(self, _title, _description, *, owner=""):
            assert owner == "agent:delegated"
            return 17

        def get_goal(self, goal_id):
            assert goal_id == 17
            return SimpleNamespace(id=17, owner="agent:delegated")

    seen = []

    def _run_goal(_llm, _world, _budget, goal_id, **kwargs):
        seen.append((
            goal_id,
            kwargs["capability"],
            connections.current_principal(),
        ))
        return "done"

    monkeypatch.setattr(world_model, "WorldModel", _World)
    monkeypatch.setattr(llm, "LLM", lambda: object())
    monkeypatch.setattr(sandbox, "build_sandbox", lambda: object())
    monkeypatch.setattr(orchestrator, "run_goal_sync", _run_goal)

    started = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_start", "arguments": {"title": "bounded run"}},
    )
    resumed = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_resume", "arguments": {"goal_id": 17}},
    )

    assert started["result"]["isError"] is False
    assert resumed["result"]["isError"] is False
    assert [goal_id for goal_id, _capability, _principal in seen] == [17, 17]
    for _goal_id, capability, principal in seen:
        assert capability.principal == "agent:delegated"
        assert capability.permits("read_file")
        assert not capability.permits("write_file")
        assert principal == "agent:delegated"


def test_transport_agent_id_cannot_alias_a_user_principal():
    assert MCPServer._connector_principal(
        "user:alice",
        "user:alice",
        SimpleNamespace(principal="agent:user:alice"),
    ) == "agent:user:alice"
    # A trusted in-process caller can still deliberately carry a user grant;
    # only Agent Trust transport ids are forced into the agent namespace.
    assert MCPServer._connector_principal(
        None,
        None,
        SimpleNamespace(principal="user:alice"),
    ) == "user:alice"


def test_authenticated_mcp_goal_cannot_borrow_ambient_connector_credentials(
    monkeypatch,
    tmp_path,
):
    """The HTTP identity must reach the actual agent registry/connector seam."""
    delegated = TrustedAgent(
        id="delegated",
        mcp_token="delegated-token",
        allow_tools=frozenset({"maverick_start"}),
        max_risk="high",
    )
    client, server, headers = _client(
        monkeypatch,
        registry={"delegated": delegated},
        token="delegated-token",
    )

    from maverick import connections, llm, orchestrator, sandbox, world_model
    from maverick.tools import Tool, _rest_connector, base_registry

    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    monkeypatch.setenv("ACME_BASE_URL", "https://ambient.acme.invalid")
    monkeypatch.setenv("ACME_TOKEN", "ambient-acme-token")
    monkeypatch.setenv("DENIED_BASE_URL", "https://ambient.denied.invalid")
    monkeypatch.setenv("DENIED_TOKEN", "ambient-denied-token")
    monkeypatch.setattr(connections, "data_dir", lambda *parts: tmp_path.joinpath(*parts))
    monkeypatch.setattr(
        connections,
        "seal_text_for_tenant",
        lambda _tenant, value: value.encode("utf-8"),
    )
    monkeypatch.setattr(
        connections,
        "unseal_text_for_tenant",
        lambda _tenant, value: value.decode("utf-8"),
    )
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: True)
    allowed = SimpleNamespace(allowed=True, reasons=[])
    server._shield = SimpleNamespace(
        scan_input=lambda _payload: allowed,
        scan_output=lambda _payload: allowed,
    )
    connections.set_connection(
        "acme",
        connector="acme",
        base_url="https://saved.acme.invalid",
        token="saved-acme-token",
        owner="agent:delegated",
    )
    connections.set_connection(
        "denied",
        connector="denied",
        base_url="https://other.denied.invalid",
        token="other-agent-token",
        owner="agent:other",
    )

    class _World:
        def create_goal(self, _title, _description, *, owner=""):
            assert owner == "agent:delegated"
            return 23

    observed = {}
    ambient_calls = []

    def _run_goal(_llm, world, _budget, _goal_id, **kwargs):
        # This is the same registry assembly seam used by Agent. It must copy
        # the HTTP-bound connector principal even though MCP has no dashboard
        # ``user_id`` to pass into the orchestrator.
        registry = base_registry(
            world,
            kwargs["sandbox"],
            _include_generated_tools=False,
        )
        observed["registry_principal"] = registry._principal
        registry.register(Tool(
            name="asana",
            description="legacy connector that would read process credentials",
            input_schema={"type": "object", "properties": {}},
            fn=lambda _args: ambient_calls.append(True) or "ambient borrowed",
        ))
        registry.register(Tool(
            name="authorized_probe",
            description="resolve the caller's saved connector",
            input_schema={"type": "object", "properties": {}},
            fn=lambda _args: repr(_rest_connector._env_config(
                "acme", "ACME_BASE_URL", "ACME_TOKEN",
            )),
        ))

        def _denied_probe(_args):
            try:
                return repr(_rest_connector._env_config(
                    "denied", "DENIED_BASE_URL", "DENIED_TOKEN",
                ))
            except RuntimeError as exc:
                return f"blocked: {exc}"

        registry.register(Tool(
            name="denied_probe",
            description="attempt to resolve another principal's connector",
            input_schema={"type": "object", "properties": {}},
            fn=_denied_probe,
        ))
        observed["ambient"] = asyncio.run(registry.run("asana", {}))
        observed["authorized"] = asyncio.run(
            registry.run("authorized_probe", {}),
        )
        observed["denied"] = asyncio.run(registry.run("denied_probe", {}))
        return "done"

    monkeypatch.setattr(world_model, "WorldModel", _World)
    monkeypatch.setattr(llm, "LLM", lambda: object())
    monkeypatch.setattr(sandbox, "build_sandbox", lambda: object())
    monkeypatch.setattr(orchestrator, "run_goal_sync", _run_goal)

    result = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_start", "arguments": {"title": "scoped run"}},
    )

    assert result["result"]["isError"] is False, result
    assert observed["registry_principal"] == "agent:delegated"
    assert observed["ambient"].startswith("REFUSED (credentials)")
    assert ambient_calls == []
    assert "https://saved.acme.invalid" in observed["authorized"]
    assert "saved-acme-token" in observed["authorized"]
    assert "ambient-acme-token" not in observed["authorized"]
    assert observed["denied"].startswith("blocked: ")
    assert "principal-authorized" in observed["denied"]
    assert "ambient-denied-token" not in observed["denied"]
    assert "other-agent-token" not in observed["denied"]


def test_authorized_task_carries_identity_and_capability_to_worker(monkeypatch):
    runner = TrustedAgent(
        id="runner",
        mcp_token="runner-token",
        allow_tools=frozenset({"maverick_start"}),
        max_risk="high",
    )
    client, server, headers = _client(
        monkeypatch,
        registry={"runner": runner},
        token="runner-token",
        tasks=True,
    )
    seen = {}

    def _run(name, arguments, context=None):
        seen.update(name=name, arguments=arguments, context=context)
        return {"isError": False, "content": [{"type": "text", "text": "done"}]}

    server._task_runner = _run
    created = _rpc(
        client,
        headers,
        "tools/call",
        {
            "name": "maverick_start",
            "arguments": {"title": "authorized"},
            "task": {"ttl": 60_000},
        },
    )
    task_id = created["result"]["task"]["taskId"]
    result = _rpc(client, headers, "tasks/result", {"taskId": task_id})

    assert result["result"]["isError"] is False
    assert seen["context"].caller_identity == "runner"
    assert seen["context"].capability.permits("maverick_start")
    assert not seen["context"].capability.permits("maverick_fact_set")
    assert seen["context"].credential_fingerprint != "runner-token"
    assert "runner-token" not in repr(seen["context"])


def test_authorized_task_rebinds_connector_principal_in_fresh_worker(monkeypatch):
    runner = TrustedAgent(
        id="runner",
        mcp_token="runner-token",
        allow_tools=frozenset({"maverick_start"}),
        max_risk="high",
    )
    client, server, headers = _client(
        monkeypatch,
        registry={"runner": runner},
        token="runner-token",
        tasks=True,
    )
    from maverick import connections

    seen = []

    def _dispatch(_worker, name, _arguments, *, capability=None):
        seen.append((
            name,
            connections.current_principal(),
            getattr(capability, "principal", None),
        ))
        return "done"

    monkeypatch.setattr(MCPServer, "_dispatch_tool", _dispatch)
    created = _rpc(
        client,
        headers,
        "tools/call",
        {
            "name": "maverick_start",
            "arguments": {"title": "background scoped run"},
            "task": {"ttl": 60_000},
        },
    )
    task_id = created["result"]["task"]["taskId"]
    result = _rpc(client, headers, "tasks/result", {"taskId": task_id})

    assert result["result"]["isError"] is False
    assert seen == [("maverick_start", "agent:runner", "agent:runner")]
    server._task_store().shutdown()


def test_mcp_goal_objects_are_private_and_foreign_ids_are_not_an_oracle(
    monkeypatch,
    tmp_path,
):
    registry = {
        agent_id: TrustedAgent(
            id=agent_id,
            mcp_token=f"{agent_id}-token",
            allow_tools=frozenset({
                "maverick_start",
                "maverick_status",
                "maverick_resume",
                "maverick_answer",
            }),
            max_risk="high",
        )
        for agent_id in ("alpha", "bravo")
    }
    client, _server, _ = _client(
        monkeypatch,
        registry=registry,
        token="alpha-token",
    )
    alpha_headers = {"Authorization": "Bearer alpha-token"}
    bravo_headers = {"Authorization": "Bearer bravo-token"}

    from maverick import llm, orchestrator, sandbox, world_model

    real_world = world_model.WorldModel
    db = tmp_path / "mcp-owned-goals.db"
    monkeypatch.setattr(
        world_model,
        "WorldModel",
        lambda *_args, **_kwargs: real_world(db),
    )
    monkeypatch.setattr(llm, "LLM", lambda: object())
    monkeypatch.setattr(sandbox, "build_sandbox", lambda: object())
    run_goal_ids = []
    monkeypatch.setattr(
        orchestrator,
        "run_goal_sync",
        lambda _llm, _world, _budget, goal_id, **_kwargs:
            run_goal_ids.append(goal_id) or f"ran {goal_id}",
    )

    def _start(headers, title):
        body = _rpc(
            client,
            headers,
            "tools/call",
            {"name": "maverick_start", "arguments": {"title": title}},
        )
        assert body["result"]["isError"] is False
        return body["result"]["structuredContent"]["goal_id"]

    alpha_goal = _start(alpha_headers, "alpha private plan")
    bravo_goal = _start(bravo_headers, "bravo private plan")
    world = world_model.WorldModel()
    assert world.get_goal(alpha_goal).owner == "agent:alpha"
    assert world.get_goal(bravo_goal).owner == "agent:bravo"
    alpha_question = world.ask("alpha secret question", goal_id=alpha_goal)
    bravo_question = world.ask("bravo secret question", goal_id=bravo_goal)

    alpha_status = _rpc(
        client,
        alpha_headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )["result"]
    assert "alpha private plan" in alpha_status["content"][0]["text"]
    assert "bravo private plan" not in alpha_status["content"][0]["text"]
    assert {g["id"] for g in alpha_status["structuredContent"]["goals"]} == {
        alpha_goal,
    }
    assert {
        q["id"] for q in alpha_status["structuredContent"]["open_questions"]
    } == {alpha_question}

    alpha_resource = _rpc(
        client,
        alpha_headers,
        "resources/read",
        {"uri": "maverick://goals"},
    )
    resource_goals = json.loads(
        alpha_resource["result"]["contents"][0]["text"],
    )
    assert {goal["id"] for goal in resource_goals} == {alpha_goal}

    run_goal_ids.clear()
    foreign_resume = _rpc(
        client,
        bravo_headers,
        "tools/call",
        {"name": "maverick_resume", "arguments": {"goal_id": alpha_goal}},
    )
    missing_resume = _rpc(
        client,
        bravo_headers,
        "tools/call",
        {"name": "maverick_resume", "arguments": {"goal_id": 987_654_321}},
    )
    assert foreign_resume["error"] == missing_resume["error"] == {
        "code": -32602,
        "message": "goal not found",
    }
    assert run_goal_ids == []

    foreign_answer = _rpc(
        client,
        bravo_headers,
        "tools/call",
        {
            "name": "maverick_answer",
            "arguments": {"question_id": alpha_question, "answer": "stolen"},
        },
    )
    missing_answer = _rpc(
        client,
        bravo_headers,
        "tools/call",
        {
            "name": "maverick_answer",
            "arguments": {"question_id": 987_654_321, "answer": "stolen"},
        },
    )
    assert foreign_answer["error"] == missing_answer["error"] == {
        "code": -32602,
        "message": "question not found",
    }
    assert {q.id for q in world.open_questions(alpha_goal)} == {alpha_question}

    own_answer = _rpc(
        client,
        bravo_headers,
        "tools/call",
        {
            "name": "maverick_answer",
            "arguments": {"question_id": bravo_question, "answer": "approved"},
        },
    )
    assert own_answer["result"]["isError"] is False
    assert world.open_questions(bravo_goal) == []

    world.set_goal_status(alpha_goal, "blocked")
    world.set_goal_status(bravo_goal, "blocked")
    default_resume = _rpc(
        client,
        bravo_headers,
        "tools/call",
        {"name": "maverick_resume", "arguments": {}},
    )
    assert default_resume["result"]["isError"] is False
    assert run_goal_ids == [bravo_goal]


def test_async_mcp_start_and_resume_preserve_goal_object_scope(
    monkeypatch,
    tmp_path,
):
    registry = {
        agent_id: TrustedAgent(
            id=agent_id,
            mcp_token=f"{agent_id}-token",
            allow_tools=frozenset({"maverick_start", "maverick_resume"}),
            max_risk="high",
        )
        for agent_id in ("alpha", "bravo")
    }
    client, server, _ = _client(
        monkeypatch,
        registry=registry,
        token="alpha-token",
        tasks=True,
    )
    alpha_headers = {"Authorization": "Bearer alpha-token"}
    bravo_headers = {"Authorization": "Bearer bravo-token"}
    from maverick import llm, orchestrator, sandbox, world_model

    real_world = world_model.WorldModel
    db = tmp_path / "mcp-owned-task-goals.db"
    monkeypatch.setattr(
        world_model,
        "WorldModel",
        lambda *_args, **_kwargs: real_world(db),
    )
    monkeypatch.setattr(llm, "LLM", lambda: object())
    monkeypatch.setattr(sandbox, "build_sandbox", lambda: object())
    run_goal_ids = []
    monkeypatch.setattr(
        orchestrator,
        "run_goal_sync",
        lambda _llm, _world, _budget, goal_id, **_kwargs:
            run_goal_ids.append(goal_id) or f"ran {goal_id}",
    )

    created = _rpc(
        client,
        alpha_headers,
        "tools/call",
        {
            "name": "maverick_start",
            "arguments": {"title": "async alpha private"},
            "task": {"ttl": 60_000},
        },
    )
    start_task = created["result"]["task"]["taskId"]
    started = _rpc(client, alpha_headers, "tasks/result", {"taskId": start_task})
    alpha_goal = started["result"]["structuredContent"]["goal_id"]
    assert world_model.WorldModel().get_goal(alpha_goal).owner == "agent:alpha"

    def _resume_task(goal_id):
        body = _rpc(
            client,
            bravo_headers,
            "tools/call",
            {
                "name": "maverick_resume",
                "arguments": {"goal_id": goal_id},
                "task": {"ttl": 60_000},
            },
        )
        task_id = body["result"]["task"]["taskId"]
        return _rpc(client, bravo_headers, "tasks/result", {"taskId": task_id})

    run_goal_ids.clear()
    foreign = _resume_task(alpha_goal)
    missing = _resume_task(987_654_321)
    assert foreign["result"]["isError"] is True
    assert missing["result"]["isError"] is True
    assert foreign["result"]["content"] == missing["result"]["content"]
    assert run_goal_ids == []
    server._task_store().shutdown()


def test_global_capability_revocation_hides_and_denies_mcp_tools(monkeypatch):
    runner = TrustedAgent(
        id="runner",
        mcp_token="runner-token",
        allow_tools=frozenset({"maverick_status"}),
        max_risk="low",
    )
    client, server, headers = _client(
        monkeypatch,
        registry={"runner": runner},
        token="runner-token",
    )
    from maverick import revocation

    revoked = False

    def _revoked_principal(_principals):
        return "agent:runner" if revoked else None

    monkeypatch.setattr(revocation, "revoked_principal", _revoked_principal)
    invoked = []
    server._dispatch_tool = lambda name, _arguments: invoked.append(name) or "ok"
    server._structured_result = lambda _name: None

    before = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert before["result"]["isError"] is False
    assert invoked == ["maverick_status"]

    revoked = True
    assert "maverick_status" not in _tool_names(
        _rpc(client, headers, "tools/list")
    )
    after = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert after["error"]["code"] == -32602
    assert invoked == ["maverick_status"]


def test_stolen_session_id_cannot_read_cancel_or_list_another_callers_tasks(
    monkeypatch,
):
    registry = {
        agent_id: TrustedAgent(
            id=agent_id,
            mcp_token=f"{agent_id}-token",
            allow_tools=frozenset({"maverick_start", "maverick_status"}),
            max_risk="high",
        )
        for agent_id in ("alpha", "bravo")
    }
    client, server, _ = _client(
        monkeypatch,
        registry=registry,
        token="alpha-token",
        tasks=True,
    )
    server._task_runner = lambda _name, _arguments, context=None: {
        "isError": False,
        "content": [{"type": "text", "text": "alpha-result"}],
    }
    alpha_headers = {"Authorization": "Bearer alpha-token"}
    created = client.post(
        "/mcp",
        headers=alpha_headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "maverick_start",
                "arguments": {"title": "alpha-only"},
                "task": {"ttl": 60_000},
            },
        },
    )
    assert created.status_code == 200
    alpha_sid = created.headers["Mcp-Session-Id"]
    task_id = created.json()["result"]["task"]["taskId"]
    bravo_headers = {
        "Authorization": "Bearer bravo-token",
        "Mcp-Session-Id": alpha_sid,
    }

    for method in ("tasks/get", "tasks/result", "tasks/cancel"):
        body = _rpc(client, bravo_headers, method, {"taskId": task_id})
        assert body["error"] == {"code": -32602, "message": "task not found"}
    listed = _rpc(client, bravo_headers, "tasks/list")
    assert listed["result"]["tasks"] == []

    # The legitimate caller still owns and can retrieve the task after every
    # adversarial operation above.
    alpha_result = _rpc(
        client,
        {**alpha_headers, "Mcp-Session-Id": alpha_sid},
        "tasks/result",
        {"taskId": task_id},
    )
    assert alpha_result["result"]["content"][0]["text"] == "alpha-result"
    server._task_store().shutdown()


def test_stolen_session_id_cannot_unsubscribe_another_callers_resource(
    monkeypatch,
):
    registry = {
        agent_id: TrustedAgent(
            id=agent_id,
            mcp_token=f"{agent_id}-token",
            allow_tools=frozenset({"maverick_start", "maverick_status"}),
            max_risk="high",
        )
        for agent_id in ("alpha", "bravo")
    }
    client, server, _ = _client(
        monkeypatch,
        registry=registry,
        token="alpha-token",
    )
    alpha_headers = {"Authorization": "Bearer alpha-token"}
    subscribed = client.post(
        "/mcp",
        headers=alpha_headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/subscribe",
            "params": {"uri": "maverick://goals"},
        },
    )
    alpha_sid = subscribed.headers["Mcp-Session-Id"]

    _rpc(
        client,
        {
            "Authorization": "Bearer bravo-token",
            "Mcp-Session-Id": alpha_sid,
        },
        "resources/unsubscribe",
        {"uri": "maverick://goals"},
    )
    server._dispatch_tool = lambda _name, _arguments, **_kwargs: "started"
    response = client.post(
        "/mcp",
        headers={
            **alpha_headers,
            "Mcp-Session-Id": alpha_sid,
            "Accept": "text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "maverick_start",
                "arguments": {"title": "notify alpha"},
            },
        },
    )
    assert "notifications/resources/updated" in response.text
    assert "maverick://goals" in response.text


def test_queued_task_intersects_frozen_capability_with_current_trust(monkeypatch):
    registry = {
        "runner": TrustedAgent(
            id="runner",
            mcp_token="runner-token",
            allow_tools=frozenset({"maverick_start"}),
            max_risk="high",
        )
    }
    client, server, headers = _client(
        monkeypatch,
        registry=registry,
        token="runner-token",
        tasks=True,
    )
    started = threading.Event()
    release = threading.Event()
    executed = []

    def _tool_start(_worker, arguments, *, capability=None):
        title = arguments["title"]
        executed.append(title)
        if title == "blocker":
            started.set()
            assert release.wait(timeout=5)
        return title

    monkeypatch.setattr(MCPServer, "_tool_start", _tool_start)
    server._tasks = TaskStore(
        lambda name, arguments: server._task_runner(name, arguments),
        context_runner=server._task_runner,
        max_workers=1,
        result_block_ms=5_000,
    )
    try:
        blocker = _rpc(
            client,
            headers,
            "tools/call",
            {
                "name": "maverick_start",
                "arguments": {"title": "blocker"},
                "task": {"ttl": 60_000},
            },
        )
        assert "task" in blocker["result"]
        assert started.wait(timeout=2)

        victim = _rpc(
            client,
            headers,
            "tools/call",
            {
                "name": "maverick_start",
                "arguments": {"title": "must-not-run"},
                "task": {"ttl": 60_000},
            },
        )
        victim_id = victim["result"]["task"]["taskId"]

        # Narrow the principal while its second task is still queued. The
        # frozen creation grant allowed start; the current registry does not.
        registry["runner"] = TrustedAgent(
            id="runner",
            mcp_token="runner-token",
            allow_tools=frozenset({"maverick_status"}),
            max_risk="low",
        )
        release.set()
        result = _rpc(client, headers, "tasks/result", {"taskId": victim_id})
        assert result["error"] == {"code": -32602, "message": "task not found"}
        victim_task = server._task_store()._tasks[victim_id]
        assert victim_task.done.wait(timeout=2)
        assert victim_task.status == "failed"
        assert executed == ["blocker"]
    finally:
        release.set()
        server._task_store().shutdown()


def test_queued_shared_task_rechecks_mcp_principal_revocation(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="legacy-shared",
        shared=True,
        enforced=False,
        tasks=True,
    )
    from maverick import revocation

    revoked = False
    monkeypatch.setattr(
        revocation,
        "revoked_principal",
        lambda principals: "mcp" if revoked and "mcp" in principals else None,
    )
    started = threading.Event()
    release = threading.Event()
    executed = []

    def _tool_start(_worker, arguments, *, capability=None):
        title = arguments["title"]
        executed.append(title)
        if title == "blocker":
            started.set()
            assert release.wait(timeout=5)
        return title

    monkeypatch.setattr(MCPServer, "_tool_start", _tool_start)
    server._tasks = TaskStore(
        lambda name, arguments: server._task_runner(name, arguments),
        context_runner=server._task_runner,
        max_workers=1,
        result_block_ms=5_000,
    )
    try:
        blocker = _rpc(
            client,
            headers,
            "tools/call",
            {
                "name": "maverick_start",
                "arguments": {"title": "blocker"},
                "task": {"ttl": 60_000},
            },
        )
        assert "task" in blocker["result"]
        assert started.wait(timeout=2)

        victim = _rpc(
            client,
            headers,
            "tools/call",
            {
                "name": "maverick_start",
                "arguments": {"title": "must-not-run"},
                "task": {"ttl": 60_000},
            },
        )
        victim_id = victim["result"]["task"]["taskId"]

        revoked = True
        release.set()
        victim_task = server._task_store()._tasks[victim_id]
        assert victim_task.done.wait(timeout=2)
        assert victim_task.status == "failed"
        assert executed == ["blocker"]
    finally:
        release.set()
        server._task_store().shutdown()


def test_task_management_rechecks_current_capability_and_revocation(monkeypatch):
    registry = {
        "runner": TrustedAgent(
            id="runner",
            mcp_token="runner-token",
            allow_tools=frozenset({"maverick_start", "maverick_status"}),
            max_risk="high",
        )
    }
    client, server, headers = _client(
        monkeypatch,
        registry=registry,
        token="runner-token",
        tasks=True,
    )
    server._task_runner = lambda _name, _arguments, context=None: {
        "isError": False,
        "content": [{"type": "text", "text": "sensitive-result"}],
    }
    created = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "maverick_start",
                "arguments": {"title": "governed"},
                "task": {"ttl": 60_000},
            },
        },
    )
    task_id = created.json()["result"]["task"]["taskId"]
    sid = created.headers["Mcp-Session-Id"]
    task_headers = {**headers, "Mcp-Session-Id": sid}

    def _assert_task_hidden():
        for method in ("tasks/get", "tasks/result", "tasks/cancel"):
            body = _rpc(client, task_headers, method, {"taskId": task_id})
            assert body["error"] == {"code": -32602, "message": "task not found"}
        assert _rpc(client, task_headers, "tasks/list")["result"]["tasks"] == []

    # A principal that may no longer invoke the underlying tool may no longer
    # inspect its status/result or operate on the task through a stale grant.
    registry["runner"] = TrustedAgent(
        id="runner",
        mcp_token="runner-token",
        allow_tools=frozenset({"maverick_status"}),
        max_risk="low",
    )
    _assert_task_hidden()

    # Restoring the trust entry is insufficient while its capability principal
    # is globally revoked; all task-management paths consult that kill switch.
    registry["runner"] = TrustedAgent(
        id="runner",
        mcp_token="runner-token",
        allow_tools=frozenset({"maverick_start", "maverick_status"}),
        max_risk="high",
    )
    from maverick import revocation

    monkeypatch.setattr(
        revocation,
        "revoked_principal",
        lambda _principals: "agent:runner",
    )
    _assert_task_hidden()
    server._task_store().shutdown()


@pytest.mark.parametrize("policy_change", ["rotate", "revoke", "narrow"])
def test_task_result_reloads_authority_after_blocking_wait(
    monkeypatch,
    policy_change,
):
    registry = {
        "runner": TrustedAgent(
            id="runner",
            mcp_token="old-token",
            allow_tools=frozenset({"maverick_start"}),
            max_risk="high",
        )
    }
    client, server, headers = _client(
        monkeypatch,
        registry=registry,
        token="old-token",
        tasks=True,
    )
    release = threading.Event()
    runner_started = threading.Event()

    def _runner(_name, _arguments, context=None):
        runner_started.set()
        assert release.wait(timeout=5)
        return {
            "isError": False,
            "content": [{"type": "text", "text": "sensitive-result"}],
        }

    server._task_runner = _runner
    created = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "maverick_start",
                "arguments": {"title": "governed"},
                "task": {"ttl": 60_000},
            },
        },
    )
    task_id = created.json()["result"]["task"]["taskId"]
    task_headers = {
        **headers,
        "Mcp-Session-Id": created.headers["Mcp-Session-Id"],
    }
    task = server._task_store()._tasks[task_id]
    assert runner_started.wait(timeout=2)

    # Observe the exact point after the request's initial authorization check
    # has passed and tasks/result is blocked waiting for terminal state.
    waiting = threading.Event()
    original_done = task.done

    class _ObservedDone:
        def set(self):
            original_done.set()

        def wait(self, timeout=None):
            waiting.set()
            return original_done.wait(timeout)

        async def wait_async(self, timeout=None):
            waiting.set()
            return await original_done.wait_async(timeout)

    task.done = _ObservedDone()
    box = {}

    def _fetch_result():
        box["response"] = client.post(
            "/mcp",
            headers=task_headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tasks/result",
                "params": {"taskId": task_id},
            },
        )

    fetch = threading.Thread(target=_fetch_result)
    fetch.start()
    try:
        assert waiting.wait(timeout=2)
        if policy_change == "rotate":
            registry["runner"] = TrustedAgent(
                id="runner",
                mcp_token="new-token",
                allow_tools=frozenset({"maverick_start"}),
                max_risk="high",
            )
        elif policy_change == "revoke":
            registry["runner"] = TrustedAgent(
                id="runner",
                mcp_token="old-token",
                allow_tools=frozenset({"maverick_start"}),
                max_risk="high",
                revoked=True,
            )
        else:
            registry["runner"] = TrustedAgent(
                id="runner",
                mcp_token="old-token",
                allow_tools=frozenset({"maverick_status"}),
                max_risk="low",
            )
        release.set()
        fetch.join(timeout=5)
        assert not fetch.is_alive()
        assert box["response"].json()["error"] == {
            "code": -32602,
            "message": "task not found",
        }
        assert task.status == "completed"
    finally:
        release.set()
        fetch.join(timeout=5)
        server._task_store().shutdown()


def test_unscoped_shared_task_and_resources_honor_mcp_principal_revocation(
    monkeypatch,
):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
        tasks=True,
    )
    server._task_runner = lambda _name, _arguments, context=None: {
        "isError": False,
        "content": [{"type": "text", "text": "shared-result"}],
    }
    created = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "maverick_start",
                "arguments": {"title": "shared"},
                "task": {"ttl": 60_000},
            },
        },
    )
    task_id = created.json()["result"]["task"]["taskId"]
    task_headers = {
        **headers,
        "Mcp-Session-Id": created.headers["Mcp-Session-Id"],
    }
    from maverick import revocation

    monkeypatch.setattr(
        revocation,
        "revoked_principal",
        lambda principals: "mcp" if "mcp" in principals else None,
    )
    assert _rpc(client, task_headers, "tasks/list")["result"]["tasks"] == []
    hidden = _rpc(client, task_headers, "tasks/get", {"taskId": task_id})
    assert hidden["error"] == {"code": -32602, "message": "task not found"}
    assert _rpc(client, headers, "resources/list")["result"]["resources"] == []
    denied_read = _rpc(
        client,
        headers,
        "resources/read",
        {"uri": "maverick://goals"},
    )
    assert denied_read["error"]["code"] == -32602
    server._task_store().shutdown()


def test_resources_use_explicit_read_capabilities_and_revocation(monkeypatch):
    reader = TrustedAgent(
        id="reader",
        mcp_token="reader-token",
        allow_tools=frozenset({"maverick_status"}),
        max_risk="low",
    )
    client, _server, headers = _client(
        monkeypatch,
        registry={"reader": reader},
        token="reader-token",
    )
    from maverick import revocation, world_model

    class _World:
        def __init__(self, *_args, **_kwargs):
            pass

        def list_goals(self, *, owner=None):
            assert owner == "agent:reader"
            return []

    monkeypatch.setattr(world_model, "WorldModel", _World)
    revoked = False
    monkeypatch.setattr(
        revocation,
        "revoked_principal",
        lambda _principals: "agent:reader" if revoked else None,
    )

    listed = _rpc(client, headers, "resources/list")["result"]["resources"]
    assert [resource["uri"] for resource in listed] == ["maverick://goals"]
    assert "result" in _rpc(
        client,
        headers,
        "resources/read",
        {"uri": "maverick://goals"},
    )
    assert "error" in _rpc(
        client,
        headers,
        "resources/read",
        {"uri": "maverick://skills"},
    )
    assert "result" in _rpc(
        client,
        headers,
        "resources/subscribe",
        {"uri": "maverick://goals"},
    )
    assert "error" in _rpc(
        client,
        headers,
        "resources/subscribe",
        {"uri": "maverick://skills"},
    )

    revoked = True
    assert _rpc(client, headers, "resources/list")["result"]["resources"] == []
    for method in ("resources/read", "resources/subscribe"):
        body = _rpc(
            client,
            headers,
            method,
            {"uri": "maverick://goals"},
        )
        assert body["error"]["code"] == -32602


def test_task_access_survives_resource_session_lru_eviction(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_MAX_RESOURCE_SESSIONS", "1")
    registry = {
        agent_id: TrustedAgent(
            id=agent_id,
            mcp_token=f"{agent_id}-token",
            allow_tools=frozenset({"maverick_start", "maverick_status"}),
            max_risk="high",
        )
        for agent_id in ("alpha", "bravo")
    }
    client, server, _ = _client(
        monkeypatch,
        registry=registry,
        token="alpha-token",
        tasks=True,
    )
    server._task_runner = lambda _name, _arguments, context=None: {
        "isError": False,
        "content": [{"type": "text", "text": "durable-task-result"}],
    }
    alpha_headers = {"Authorization": "Bearer alpha-token"}
    created = client.post(
        "/mcp",
        headers=alpha_headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "maverick_start",
                "arguments": {"title": "survive lru"},
                "task": {"ttl": 60_000},
            },
        },
    )
    alpha_sid = created.headers["Mcp-Session-Id"]
    task_id = created.json()["result"]["task"]["taskId"]
    alpha_task_headers = {**alpha_headers, "Mcp-Session-Id": alpha_sid}

    # Reuse Alpha's task session for a resource subscription, then force that
    # evictable subscription entry out with Bravo's independent session.
    assert "result" in _rpc(
        client,
        alpha_task_headers,
        "resources/subscribe",
        {"uri": "maverick://goals"},
    )
    client.cookies.clear()
    bravo_subscribe = client.post(
        "/mcp",
        headers={"Authorization": "Bearer bravo-token"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/subscribe",
            "params": {"uri": "maverick://goals"},
        },
    )
    assert bravo_subscribe.status_code == 200
    assert alpha_sid not in client.app.state.resource_sessions

    result = _rpc(
        client,
        alpha_task_headers,
        "tasks/result",
        {"taskId": task_id},
    )
    assert result["result"]["content"][0]["text"] == "durable-task-result"
    server._task_store().shutdown()


def test_task_quota_is_stable_across_sessions_for_same_principal(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_MAX_TASKS_PER_OWNER", "1")
    registry = {
        agent_id: TrustedAgent(
            id=agent_id,
            mcp_token=f"{agent_id}-token",
            allow_tools=frozenset({"maverick_start"}),
            max_risk="high",
        )
        for agent_id in ("alpha", "bravo")
    }
    client, server, _ = _client(
        monkeypatch,
        registry=registry,
        token="alpha-token",
        tasks=True,
    )
    release = threading.Event()

    def _run(_name, _arguments, context=None):
        release.wait(timeout=5)
        return {"isError": False, "content": [{"type": "text", "text": "done"}]}

    server._task_runner = _run

    def _create(token: str, title: str):
        return client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "maverick_start",
                    "arguments": {"title": title},
                    "task": {"ttl": 60_000},
                },
            },
        ).json()

    try:
        assert "task" in _create("alpha-token", "alpha-one")["result"]
        # Drop the cookie so this request receives a distinct MCP session. Its
        # task owner differs, but the stable principal quota key is unchanged.
        client.cookies.clear()
        second = _create("alpha-token", "alpha-two")
        assert second["error"] == {
            "code": -32602,
            "message": "too many active tasks for this caller",
        }
        client.cookies.clear()
        assert "task" in _create("bravo-token", "bravo-one")["result"]
    finally:
        release.set()
        if server._tasks is not None:
            server._task_store().shutdown()


def test_enterprise_shield_floor_ignores_disable_override(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )
    from maverick import enterprise

    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "0")
    monkeypatch.setattr(enterprise, "enterprise_enabled", lambda: True)
    server._shield = None

    def _must_not_dispatch(_name, _arguments):
        raise AssertionError("enterprise MCP dispatched without Shield")

    server._dispatch_tool = _must_not_dispatch
    body = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert body["result"]["isError"] is True
    assert "required but unavailable" in body["result"]["content"][0]["text"]


def test_required_shield_scrubs_and_scans_resource_output(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1")
    from maverick import world_model

    raw_secret = "sk-abcdefghijklmnopqrstuvwxyz123456"  # pragma: allowlist secret

    class _World:
        def __init__(self, *_args, **_kwargs):
            pass

        def list_goals(self, *, owner=None):
            assert owner == "agent:mcp"
            return [
                SimpleNamespace(
                    id=7,
                    status="active",
                    title=f"sensitive {raw_secret}",
                )
            ]

    monkeypatch.setattr(world_model, "WorldModel", _World)
    scanned = []

    class _AllowingShield:
        def scan_output(self, text):
            scanned.append(text)
            return SimpleNamespace(allowed=True, reasons=[])

    server._shield = _AllowingShield()
    allowed = _rpc(
        client,
        headers,
        "resources/read",
        {"uri": "maverick://goals"},
    )
    text = allowed["result"]["contents"][0]["text"]
    assert raw_secret not in text
    assert "[REDACTED:openai_key]" in text
    assert scanned == [text]

    class _RejectingShield:
        def scan_output(self, _text):
            return SimpleNamespace(
                allowed=False,
                reasons=[f"sensitive span: {raw_secret}"],
            )

    server._shield = _RejectingShield()
    denied = _rpc(
        client,
        headers,
        "resources/read",
        {"uri": "maverick://goals"},
    )
    assert denied["error"] == {
        "code": -32603,
        "message": "resource output blocked by safety policy",
    }
    assert raw_secret not in str(denied)


def test_tool_exception_is_scrubbed_bounded_and_shield_scanned(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1")
    raw_secret = "sk-abcdefghijklmnopqrstuvwxyz123456"  # pragma: allowlist secret
    scanned = []

    class _Shield:
        def scan_input(self, _text):
            return SimpleNamespace(allowed=True, reasons=[])

        def scan_output(self, text):
            scanned.append(text)
            return SimpleNamespace(allowed=True, reasons=[])

    server._shield = _Shield()

    def _crash(_name, _arguments):
        raise RuntimeError(raw_secret + ("x" * 2_000))

    server._dispatch_tool = _crash
    body = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    detail = body["result"]["content"][0]["text"]
    assert body["result"]["isError"] is True
    assert raw_secret not in detail
    assert "[REDACTED:openai_key]" in detail
    assert len(detail) <= 500
    assert scanned == [detail]

    class _RejectingShield(_Shield):
        def scan_output(self, _text):
            return SimpleNamespace(
                allowed=False,
                reasons=[f"sensitive span: {raw_secret}"],
            )

    server._shield = _RejectingShield()
    denied = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    denied_text = denied["result"]["content"][0]["text"]
    assert denied_text == "Output blocked by safety policy"
    assert raw_secret not in denied_text


def test_required_shield_scan_exception_blocks_remote_output(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1")

    class _BrokenShield:
        def scan_input(self, _text):
            return SimpleNamespace(allowed=True, reasons=[])

        def scan_output(self, _text):
            raise RuntimeError("scanner unavailable")

    server._shield = _BrokenShield()
    server._dispatch_tool = lambda _name, _arguments: "must-not-cross-boundary"
    server._structured_result = lambda _name: None

    body = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert body["result"]["isError"] is True
    text = body["result"]["content"][0]["text"]
    assert "safety shield scan error" in text
    assert "must-not-cross-boundary" not in text


def test_required_shield_input_exception_prevents_goal_start(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1")

    class _BrokenInputShield:
        def scan_input(self, _text):
            raise RuntimeError("scanner unavailable")

        def scan_output(self, _text):
            return SimpleNamespace(allowed=True, reasons=[])

    server._shield = _BrokenInputShield()

    from maverick import world_model

    def _must_not_create_world(*_args, **_kwargs):
        raise AssertionError("goal creation reached after failed required scan")

    monkeypatch.setattr(world_model, "WorldModel", _must_not_create_world)
    body = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_start", "arguments": {"title": "unsafe"}},
    )
    assert body["result"]["isError"] is True
    assert "safety shield scan error" in body["result"]["content"][0]["text"]


def test_required_missing_shield_blocks_before_tool_dispatch(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1")
    server._shield = None

    def _must_not_dispatch(_name, _arguments):
        raise AssertionError("tool dispatched without required Shield")

    server._dispatch_tool = _must_not_dispatch
    body = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert body["result"]["isError"] is True
    assert "required but unavailable" in body["result"]["content"][0]["text"]


def test_local_dev_shield_exception_remains_fail_open(monkeypatch):
    client, server, headers = _client(
        monkeypatch,
        registry={},
        token="shared-token",
        shared=True,
        enforced=False,
    )

    class _BrokenShield:
        def scan_output(self, _text):
            raise RuntimeError("scanner unavailable")

    server._shield = _BrokenShield()
    server._dispatch_tool = lambda _name, _arguments: "local-result"
    server._structured_result = lambda _name: None

    body = _rpc(
        client,
        headers,
        "tools/call",
        {"name": "maverick_status", "arguments": {}},
    )
    assert body["result"]["isError"] is False
    assert body["result"]["content"][0]["text"] == "local-result"


def test_unreadable_enforced_trust_state_rejects_http_request(monkeypatch):
    monkeypatch.setenv("MAVERICK_MCP_TOKEN", "shared-token")

    def _broken_state():
        raise OSError("trust registry unavailable")

    monkeypatch.setattr(agent_trust, "load_trust_state", _broken_state)
    response = TestClient(build_app(MCPServer())).post(
        "/mcp",
        headers={"Authorization": "Bearer shared-token"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert response.status_code == 401


def test_exhausted_peer_budget_never_locks_out_a_valid_bearer(monkeypatch):
    """Many clients share one egress address behind a proxy or NAT, and the
    transport deliberately ignores forwarded headers. An attacker's failed
    guesses from that address must not turn into a 429 for a valid token."""
    from maverick_mcp import http_transport

    monkeypatch.setattr(http_transport, "_AUTH_FAILURES", {})
    monkeypatch.setattr(http_transport, "_AUTH_FAILED_BEARERS", {})
    client, _, _ = _client(monkeypatch, registry={}, token="known", shared=True, enforced=False)
    wrong = {"Authorization": "Bearer wrong"}
    for _ in range(http_transport._AUTH_FAILURE_LIMIT):
        assert client.post("/mcp", headers=wrong, json={}).status_code == 401
    # The repeated wrong bearer is refused before verification.
    assert client.post("/mcp", headers=wrong, json={}).status_code == 429
    # A different wrong bearer from the same peer is still refused (429, not 401).
    assert client.post("/mcp", headers={"Authorization": "Bearer other"}, json={}).status_code == 429
    # The valid bearer from the same peer gets through to the protocol layer.
    ok = client.post("/mcp", headers={"Authorization": "Bearer known"}, json={})
    assert ok.status_code != 429, ok.text
    assert ok.status_code != 401
