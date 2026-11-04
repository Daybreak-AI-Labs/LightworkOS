"""Physical connector retries, accounting, mutation uncertainty and admission."""
from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import httpx
import pytest
from maverick import connector_attempts as attempts
from maverick import tool_reliability
from maverick.budget import Budget, BudgetExceeded, UsageAccountingError
from maverick.tools import Tool, ToolRegistry, _ssrf
from maverick.tools._rest_connector import make_graphql_tool, make_rest_tool


@pytest.fixture
def connector(monkeypatch):
    monkeypatch.setenv("BOUNDED_URL", "https://connector.example")
    monkeypatch.setenv("BOUNDED_TOKEN", "test-credential")
    monkeypatch.setattr(attempts, "configured_limits", lambda: attempts.ConnectorLimits())
    monkeypatch.setattr(tool_reliability.retry_classifier, "next_delay", lambda *_a, **_k: 0)
    return make_rest_tool(name="bounded_connector", base_url_env="BOUNDED_URL",
                          token_env="BOUNDED_TOKEN", description="Fixture connector")


def transport(monkeypatch, responses):
    requests = []

    def handler(request):
        requests.append(request)
        result = responses[min(len(requests) - 1, len(responses) - 1)]
        if isinstance(result, Exception):
            raise result
        status, body, headers = result
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
            headers = {"content-type": "application/json", **headers}
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))

    @contextmanager
    def client(_url, **_kwargs):
        with httpx.Client(transport=httpx.MockTransport(handler)) as instance:
            yield instance

    monkeypatch.setattr(_ssrf, "safe_client", client)
    return requests


def invoke(tool, args):
    registry = ToolRegistry()
    registry.register(tool)
    return asyncio.run(registry.run(tool.name, args))


def test_mixed_connector_safe_get_retries_429_with_retry_after_and_budget(connector, monkeypatch):
    requests = transport(monkeypatch, [(429, b"never expose this", {"retry-after": "2"}),
                                       (200, {"ok": True}, {})])
    waits = []

    async def sleep(delay):
        waits.append(delay)

    monkeypatch.setattr(tool_reliability.asyncio, "sleep", sleep)
    budget = Budget(max_tool_calls=2)
    budget.record_tool_call()  # Agent owns the initial logical invocation.
    with attempts.bind_tool_budget(budget):
        result = invoke(connector, {"op": "get", "path": "/items"})
    assert json.loads(result) == {"ok": True}
    assert type(result) is str
    assert len(requests) == budget.tool_calls == 2
    assert waits == [2.0]
    assert requests[0].headers["authorization"] == requests[1].headers["authorization"]


def test_retry_cannot_exceed_agent_tool_budget(connector, monkeypatch):
    requests = transport(monkeypatch, [(503, b"", {})])
    budget = Budget(max_tool_calls=1)
    budget.record_tool_call()
    with attempts.bind_tool_budget(budget), pytest.raises(BudgetExceeded):
        invoke(connector, {"op": "get", "path": "/items"})
    assert len(requests) == 1


def test_each_retry_reenters_configured_rate_limit(connector, monkeypatch):
    from maverick.safety.rate_limiter import apply_to_registry

    requests = transport(monkeypatch, [(429, b"", {}), (200, {"ok": True}, {})])
    registry = ToolRegistry()
    registry.register(connector)
    apply_to_registry(registry, {connector.name: (1, 60)})
    result = asyncio.run(registry.run(connector.name, {"op": "get", "path": "/items"}))
    assert result.startswith("ERROR: rate limit exceeded")
    assert len(requests) == 1


def test_real_agent_dispatch_binds_its_existing_budget_to_connector_retry(connector, monkeypatch, tmp_path):
    from maverick.agent import Agent
    from maverick.world_model import WorldModel

    requests = transport(monkeypatch, [(503, b"", {})])
    budget = Budget(max_tool_calls=1)
    budget.record_tool_call()
    registry = ToolRegistry()
    registry.register(connector)
    # The dispatch guard reads the goal's handoff/cancel state from the world.
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("connector retry", "")
    obj = SimpleNamespace(ctx=SimpleNamespace(budget=budget, goal_id=goal_id, world=world), tools=registry,
                          _HALT_POLL_SECONDS=0.01, _audit_tool_event=lambda *_a, **_k: True)
    obj._await_wall_clock_guarded = Agent._await_wall_clock_guarded.__get__(obj)
    with pytest.raises(BudgetExceeded):
        asyncio.run(Agent._run_dispatched_tool(
            obj, connector.name, {"op": "get", "path": "/items"}, shield=None,
            quarantine=None, call_id="fixture", call_commitment="fixture", principal=None))
    world.close()
    assert len(requests) == 1


@pytest.mark.parametrize("response", [(401, b"secret", {}), (403, b"secret", {}),
                                       (200, b"{broken", {"content-type": "application/json"}),
                                       (200, b"{broken", {"content-type": "Application/Json"}),
                                       (429, b"secret", {"retry-after": "120"})])
def test_terminal_or_excessive_delay_does_not_retry(connector, monkeypatch, response):
    requests = transport(monkeypatch, [response])
    result = invoke(connector, {"op": "get", "path": "/items"})
    assert result.startswith("ERROR:")
    assert "secret" not in result
    assert len(requests) == 1


def test_attempt_limit_exhaustion_retains_sanitized_class(connector, monkeypatch):
    requests = transport(monkeypatch, [(503, b"private backend diagnostic", {})])
    result = invoke(connector, {"op": "get", "path": "/items"})
    assert len(requests) == 3
    assert result == "ERROR: get (503): upstream request failed"


@pytest.mark.parametrize("failure", [httpx.ReadError("test-credential"),
                                      httpx.RemoteProtocolError("test-credential"),
                                      (503, b"test-credential", {})])
def test_ambiguous_mutation_is_one_physical_attempt(connector, monkeypatch, failure):
    requests = transport(monkeypatch, [failure])
    result = connector.fn({"op": "post", "path": "/items", "confirm": True})
    assert isinstance(result, attempts.ConnectorResult)
    assert result.startswith("INDETERMINATE:")
    assert result.attempt.outcome_unknown and result.attempt.dispatch_may_have_happened
    assert not result.attempt.retryable
    assert "test-credential" not in result
    assert len(requests) == 1
    # Registry also preserves the uncertainty and never schedules a replay.
    invoke(connector, {"op": "post", "path": "/items", "confirm": True})
    assert len(requests) == 2


@pytest.mark.parametrize("document", ["query { items { id } }", "{ items { id } }",
                                       "query One { x } query Two { y }"])
def test_graphql_document_is_not_an_independently_verified_read(connector, monkeypatch, document):
    gql = make_graphql_tool(name="bounded_graphql", base_url_env="BOUNDED_URL",
                            token_env="BOUNDED_TOKEN", description="Fixture GraphQL")
    requests = transport(monkeypatch, [(429, b"secret", {"retry-after": "0"})])
    assert invoke(gql, {"op": "query", "query": document}).startswith("ERROR:")
    assert len(requests) == 1


def test_graphql_errors_never_retry_or_echo_error_body(connector, monkeypatch):
    gql = make_graphql_tool(name="bounded_graphql", base_url_env="BOUNDED_URL",
                            token_env="BOUNDED_TOKEN", description="Fixture GraphQL")
    requests = transport(monkeypatch, [(200, {"data": {"x": 1}, "errors": ["secret"]}, {})])
    result = invoke(gql, {"op": "query", "query": "query { x }"})
    assert result == "ERROR: graphql (200): upstream request failed"
    assert len(requests) == 1


@pytest.mark.parametrize("change", ["args", "credentials", "registration", "acl"])
def test_retry_revalidates_original_request_and_authority(connector, monkeypatch, change):
    requests = transport(monkeypatch, [(429, b"", {}), (200, {"ok": True}, {})])
    registry = ToolRegistry()
    registry.register(connector)
    args = {"op": "get", "path": "/items"}

    async def sleep(_delay):
        if change == "args":
            args["path"] = "/other"
        elif change == "credentials":
            monkeypatch.setenv("BOUNDED_TOKEN", "rotated")
        elif change == "registration":
            registry.register(replace(connector, fn=lambda _args: "unexpected"))
        else:
            monkeypatch.setattr(registry, "_tool_access_error", lambda _name: "ERROR: access revoked")

    monkeypatch.setattr(tool_reliability.asyncio, "sleep", sleep)
    result = asyncio.run(registry.run(connector.name, args))
    if change == "args":
        # The registry snapshots top-level arguments, so the retry uses the
        # original path even if the caller mutates its own dictionary.
        assert result == '{"ok": true}'
        assert len(requests) == 2
        assert all(request.url.path == "/items" for request in requests)
        return
    assert result.startswith("ERROR:")
    assert len(requests) == 1


def test_dry_run_and_revision_guard_stay_before_network(connector, monkeypatch):
    requests = transport(monkeypatch, [(200, {"ok": True}, {"etag": '"v2"'})])
    assert invoke(connector, {"op": "post", "path": "/items"}).startswith("DRY RUN:")
    assert invoke(connector, {"op": "put", "path": "/items", "confirm": True}).startswith("ERROR:")
    assert not requests
    result = invoke(connector, {"op": "put", "path": "/items", "confirm": True,
                               "if_match": '"v1"', "response_format": "metadata"})
    assert json.loads(result)["headers"]["etag"] == '"v2"'
    assert requests[0].headers["if-match"] == '"v1"'


@pytest.mark.parametrize("status", [204, 205])
def test_valid_no_content_response_stays_compatible(connector, monkeypatch, status):
    requests = transport(monkeypatch, [(status, b"", {"content-type": "application/json"})])
    assert invoke(connector, {"op": "post", "path": "/items", "confirm": True}) == '""'
    assert len(requests) == 1


@pytest.mark.parametrize("error_type", [BudgetExceeded, UsageAccountingError])
def test_control_error_from_connector_never_becomes_a_tool_result(connector, monkeypatch, error_type):
    original = error_type("stop")
    requests = transport(monkeypatch, [original])
    with pytest.raises(error_type) as raised:
        invoke(connector, {"op": "get", "path": "/items"})
    assert raised.value is original
    assert len(requests) == 1


def test_foreign_attempt_record_cannot_opt_unknown_tool_into_retry():
    count = 0

    def fn(_args):
        nonlocal count
        count += 1
        return attempts.ConnectorResult("ERROR: rate limit", attempts.ConnectorAttempt(
            request_id="foreign", attempt=1, operation="safe_read", error_class="rate_limit"))

    assert invoke(Tool("unknown_tool", "fixture", {}, fn), {}).startswith("ERROR:")
    assert count == 1


def test_attempt_records_are_immutable_and_do_not_retain_request_values(connector, monkeypatch):
    transport(monkeypatch, [(200, {"ok": True}, {})])
    result = connector.fn({"op": "get", "path": "/items"})
    with pytest.raises(AttributeError):
        result.attempt = None
    with pytest.raises(FrozenInstanceError):
        result.attempt.status_code = 503
    assert "test-credential" not in repr(result.attempt)


def test_cached_success_contains_only_public_result(connector, monkeypatch):
    from maverick.cache import tool as cache

    cache.reset()
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "1")
    requests = transport(monkeypatch, [(200, {"ok": True}, {})])
    read_tool = make_rest_tool(name=connector.name, base_url_env="BOUNDED_URL",
                              token_env="BOUNDED_TOKEN", description="Fixture read",
                              read_only=True, allowed_read_paths=("/items",))
    # Factories retain their existing conservative cache eligibility. Exercise
    # the registry boundary with this independently reviewed fixture opted in.
    read_tool = replace(read_tool, parallel_safe=True)
    registry = ToolRegistry()
    registry.register(read_tool)
    try:
        first = asyncio.run(registry.run(read_tool.name, {"path": "/items"}))
        second = asyncio.run(registry.run(read_tool.name, {"path": "/items"}))
        assert type(first) is type(second) is str
        assert first == second == '{"ok": true}'
        assert len(requests) == 1
    finally:
        cache.reset()


def test_graphql_missing_data_is_not_a_success(connector, monkeypatch):
    gql = make_graphql_tool(name="bounded_graphql", base_url_env="BOUNDED_URL",
                            token_env="BOUNDED_TOKEN", description="Fixture GraphQL")
    requests = transport(monkeypatch, [(200, {"unexpected": "secret"}, {})])
    result = invoke(gql, {"op": "query", "query": "query { x }"})
    assert result.startswith("INDETERMINATE:")
    assert "secret" not in result and len(requests) == 1


@pytest.mark.parametrize("value", ["NaN", "inf", "bad\r\nheader", "x" * 129])
def test_untrusted_retry_after_is_not_retained(value):
    assert attempts.retry_after_seconds(value) is None
