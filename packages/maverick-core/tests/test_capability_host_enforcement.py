"""Capability layer: host resource-scope enforcement at the tool chokepoint.

A capability whose ``allow_hosts`` is non-empty restricts which network hosts
the known network tools (http_fetch/browser/oidc/oauth_helper) may reach: the host is parsed from
the tool's URL argument and denied if it matches no ``allow_hosts`` glob.
Default-open: an empty ``allow_hosts`` (the common case, and the only state
reachable without opting into capability enforcement) is a no-op, so normal
behaviour is unchanged.

Mirrors ``tests/test_capability_path_enforcement.py``'s ``_agent(tmp_path)`` +
``_run_tool`` setup; hermetic (no real LLM, no network).
"""

import pytest
from maverick.capability import Capability
from maverick.tools import Tool


def _agent(tmp_path):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False,
    )
    return Agent(ctx=ctx, role="coder", brief="b")


def _spy_tool(name: str, calls: list, url_key: str = "url") -> Tool:
    """A fake network-shaped tool that records its calls instead of hitting net."""
    return Tool(
        name=name,
        description="spy",
        fn=lambda args: calls.append(args.get(url_key)) or "ran",
        input_schema={
            "type": "object",
            "properties": {url_key: {"type": "string"}},
        },
    )


@pytest.mark.asyncio
async def test_view_image_respects_host_and_path_scopes(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(
        principal="agent:coder-1", allow_hosts=frozenset({"images.example.com"}),
        allow_paths=frozenset({"allowed/*"}),
    )
    calls = []
    agent.tools.register(_spy_tool("view_image", calls, url_key="source"))
    assert "DENIED" in await agent._run_tool("view_image", {"source": "https://evil.com/a.png"})
    assert "DENIED" in await agent._run_tool("view_image", {"source": "private/a.png"})
    assert "DENIED" in await agent._run_tool("view_image", {"source": "data:secret.png"})
    assert "DENIED" in await agent._run_tool("view_image", {"source": "HTTP:secret.png"})
    assert "DENIED" in await agent._run_tool("view_image", {"source": "https://images.example.com/a.png"})
    assert "DENIED" in await agent._run_tool("view_image", {"source": "allowed/a.png"})
    assert not calls


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name,params", [
    ("view_image", {"source": "secret.png "}),
    ("pandoc", {"op": "convert", "input_path": "secret.png ", "output_path": "allowed.html"}),
    ("imagemagick", {"op": "identify", "input_path": "secret.png "}),
    ("ffmpeg", {"op": "info", "input_path": "secret.png "}),
])
async def test_media_path_scope_uses_same_whitespace_normalization_as_tool(tmp_path, tool_name, params):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1", allow_paths=frozenset({"secret.png ", "allowed.html"}))
    calls = []
    agent.tools.register(_spy_tool(tool_name, calls, url_key="source"))
    assert "DENIED" in await agent._run_tool(tool_name, params)
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["pandoc", "imagemagick", "ffmpeg"])
async def test_media_output_path_must_be_within_capability(tmp_path, tool_name):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1", allow_paths=frozenset({"allowed/*"}))
    calls = []
    agent.tools.register(_spy_tool(tool_name, calls, url_key="input_path"))
    result = await agent._run_tool(tool_name, {"op": "convert", "input_path": "allowed/a.md",
                                              "output_path": "private/output.html"})
    assert "DENIED" in result and calls == []


@pytest.mark.asyncio
async def test_host_outside_scope_denied_and_tool_not_run(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    # Register a fake http_fetch so a permitted call would be observable; the
    # denied call must NOT reach it.
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {"url": "https://evil.com/x"})
    assert "DENIED by capability" in out
    assert "agent:coder-1" in out
    assert "evil.com" in out
    assert calls == []  # the network tool did not run


@pytest.mark.asyncio
async def test_oidc_token_url_outside_scope_denied_and_tool_not_run(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("oidc", calls, url_key="token_url"))

    out = await agent._run_tool("oidc", {"token_url": "https://evil.com/token"})
    assert "DENIED by capability" in out
    assert "evil.com" in out
    assert calls == []


@pytest.mark.asyncio
async def test_websocket_host_outside_scope_is_denied(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1", allow_hosts=frozenset({"safe.example"}))
    calls = []
    agent.tools.register(_spy_tool("websocket", calls))
    assert "DENIED" in await agent._run_tool("websocket", {"url": "wss://evil.example/socket"})
    assert calls == []


@pytest.mark.asyncio
async def test_oauth_helper_token_url_outside_scope_denied_and_tool_not_run(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("oauth_helper", calls, url_key="token_url"))

    out = await agent._run_tool("oauth_helper", {"token_url": "https://evil.com/token"})
    assert "DENIED by capability" in out
    assert calls == []


@pytest.mark.asyncio
async def test_host_inside_scope_permitted(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {"url": "https://api.example.com/x"})
    assert "DENIED" not in out
    assert calls == ["https://api.example.com/x"]  # passed the gate and ran


@pytest.mark.parametrize("name", ["openapi_runner", "teams", "web_archive", "ocr", "huggingface", "learn_capability", "wikipedia", "slack_bot", "youtube"])
def test_unscoped_network_tool_is_refused_with_host_restrictions(tmp_path, name):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_hosts=frozenset({"*.example.com"}))
    assert "DENIED" in agent._capability_host_denial(name, {}, capability)
    assert agent._capability_host_denial(name, {}, None) is None


def test_remote_pdf_is_refused_even_with_leading_whitespace(tmp_path):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_hosts=frozenset({"*.example.com"}))
    assert "DENIED" in agent._capability_host_denial(
        "read_pdf", {"source": " https://elsewhere.example/a.pdf"}, capability,
    )


@pytest.mark.parametrize("name", ["read_file", "ask_user", "compute", "ast_edit"])
def test_local_tool_remains_available_with_host_restrictions(tmp_path, name):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_hosts=frozenset({"*.example.com"}))
    assert agent._capability_host_denial(name, {"path": "file.txt"}, capability) is None


def test_discovery_name_is_not_trusted_without_bound_tool_identity(tmp_path):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_hosts=frozenset({"*.example.com"}))
    assert "DENIED" in agent._capability_host_denial("find_tools", {}, capability)


@pytest.mark.asyncio
async def test_unclassified_tool_is_denied_for_restricted_hosts(tmp_path):
    # An unclassified tool might make network calls through hidden inputs.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("not_a_net_tool", calls))

    out = await agent._run_tool("not_a_net_tool", {"url": "https://evil.com/x"})
    assert "DENIED" in out
    assert not calls


@pytest.mark.asyncio
async def test_no_allow_hosts_is_no_host_denial(tmp_path):
    # Default grant (empty allow_hosts == all): no host denial.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1")  # no allow_hosts
    calls: list = []
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {"url": "https://evil.com/x"})
    assert "DENIED" not in out
    assert calls == ["https://evil.com/x"]


@pytest.mark.asyncio
async def test_unrestricted_capability_none_is_no_host_denial(tmp_path):
    # capability is None == enforcement off entirely.
    agent = _agent(tmp_path)
    agent.capability = None
    calls: list = []
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {"url": "https://evil.com/x"})
    assert "DENIED" not in out
    assert calls == ["https://evil.com/x"]


@pytest.mark.asyncio
async def test_missing_url_arg_fails_soft(tmp_path):
    # Fail-soft: a network tool called without its url arg must not crash on the
    # host check -- it falls through to the tool's own validation.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {})  # no "url"
    assert "DENIED by capability" not in out
    assert calls == [None]  # reached the tool


@pytest.mark.asyncio
async def test_malformed_url_fails_soft(tmp_path):
    # Fail-soft: a URL with no parseable host (relative path) must not be
    # denied and must not crash -- the check is skipped and the tool runs.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {"url": "not a url"})
    assert "DENIED by capability" not in out
    assert calls == ["not a url"]  # reached the tool


@pytest.mark.asyncio
async def test_url_that_raises_on_parse_fails_soft(tmp_path):
    # Fail-soft: a URL that makes urlsplit() raise (bad IPv6 literal) must not
    # crash the gate -- the check is skipped and the tool runs.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(_spy_tool("http_fetch", calls))

    out = await agent._run_tool("http_fetch", {"url": "http://[::1"})
    assert "DENIED by capability" not in out
    assert calls == ["http://[::1"]  # reached the tool


@pytest.mark.asyncio
async def test_host_denial_is_audited(tmp_path, monkeypatch):
    import maverick.audit
    from maverick.audit import EventKind
    calls = []
    monkeypatch.setattr(maverick.audit, "record",
                        lambda kind, **kw: calls.append((kind, kw)) or True)
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    await agent._run_tool("browser",
                          {"action": "navigate", "url": "https://evil.com/x"})
    denied = [kw for k, kw in calls if k == EventKind.CAPABILITY_DENIED]
    assert denied, "host denial was not written to the audit log"
    assert denied[0]["tool"] == "browser"
    assert denied[0]["principal"] == "agent:coder-1"
    assert denied[0]["reason"] == "host_scope_unavailable"


@pytest.mark.asyncio
async def test_browser_is_refused_until_subrequests_enforce_host_scope(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_hosts=frozenset({"*.example.com"}))
    calls: list = []
    agent.tools.register(Tool(
        name="browser",
        description="spy browser",
        fn=lambda args: calls.append(args) or "ran",
        input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
    ))

    out = await agent._run_tool("browser", {
        "action": "navigate",
        "url": "https://api.example.com/x",
    })
    assert "DENIED" in out
    assert not calls


@pytest.mark.parametrize("cap", [None, Capability(principal="agent:coder")])
@pytest.mark.asyncio
async def test_model_cannot_supply_reserved_host_scope(tmp_path, cap):
    agent = _agent(tmp_path)
    agent.capability = cap
    captured = []
    agent.tools.register(Tool(name="database", description="spy database",
                              fn=lambda args: captured.append(args) or "ran",
                              input_schema={"type": "object"}))
    original = {"sql": "SELECT 1", "_capability_allow_hosts": ["*"], "_capability_other": True}
    assert "ran" in await agent._run_tool("database", original)
    assert captured == [{"sql": "SELECT 1"}]
    assert original["_capability_allow_hosts"] == ["*"]


@pytest.mark.asyncio
async def test_model_host_scope_cannot_expand_a_real_grant(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder", allow_hosts=frozenset({"*.example.com"}))
    captured = []
    agent.tools.register(Tool(name="database", description="spy database",
                              fn=lambda args: captured.append(args) or "ran",
                              input_schema={"type": "object"}))
    args = {"sql": "SELECT 1", "_capability_allow_hosts": ["*"]}
    scoped = agent._with_capability_host_scope("database", args, agent.capability)
    assert scoped["_capability_allow_hosts"] == ("*.example.com",)
    result = await agent._run_tool("database", args)
    assert "no verified host scope" in result
    assert captured == []


@pytest.mark.asyncio
async def test_registry_rejects_caller_supplied_internal_host_scope():
    from maverick.tools import ToolRegistry

    registry = ToolRegistry()
    captured = []
    registry.register(Tool(name="database", description="spy", input_schema={"type": "object"},
                           fn=lambda args: captured.append(args) or "ran"))
    assert await registry.run("database", {"sql": "SELECT 1", "_capability_allow_hosts": ["*"]}) == "ran"
    assert captured == [{"sql": "SELECT 1"}]


@pytest.mark.asyncio
async def test_database_model_url_cannot_forge_a_host_grant(tmp_path, monkeypatch):
    from maverick.tools.database_tool import database_tool

    monkeypatch.setenv("MAVERICK_DATABASE_ALLOW_URL_ARG", "0")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    agent = _agent(tmp_path)
    agent.capability = None
    agent.tools.register(database_tool())
    result = await agent._run_tool("database", {
        "op": "query", "sql": "SELECT 1", "url": "postgresql://db.example.test/db",
        "_capability_allow_hosts": ["*"],
    })
    assert "DENIED" in result
    assert "requires either a capability allow_hosts grant" in result
