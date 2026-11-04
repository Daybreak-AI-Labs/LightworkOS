"""Metadata-only catalog, first-use single-flight and guarded execution parity."""
from __future__ import annotations

import asyncio
import copy
import inspect
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from maverick.governed_tools import apply_governed_connectors, wrap_connector_tool
from maverick.tools import Tool, ToolRegistry, base_registry
from maverick.tools._lazy import LazyTool, LazyToolConstructionError, ToolDescriptor, search_tokens
from maverick.tools.enterprise_connectors import (
    enterprise_connector_descriptors,
    enterprise_connectors,
)


def _descriptor(name="synthetic", *, schema=None):
    return ToolDescriptor(name=name, description="Synthetic tool", input_schema=schema or {"type": "object"},
                          factory_module="maverick.tools._rest_connector", factory_name="make_rest_tool",
                          factory_kwargs={})


def _built(descriptor, fn):
    return Tool(descriptor.name, descriptor.description, copy.deepcopy(descriptor.input_schema), fn,
                parallel_safe=descriptor.parallel_safe, strict=descriptor.strict)


def test_entire_raw_catalog_matches_eager_schema_and_order():
    from maverick.tools import _rest_connector as engine
    from maverick.tools.enterprise_connectors import _GRAPHQL_SPECS, _READ_SPECS, _SPECS
    eager = ([engine.make_rest_tool(**s) for s in _SPECS]
             + [engine.make_graphql_tool(**s) for s in _GRAPHQL_SPECS]
             + [engine.make_rest_tool(read_only=True, **s) for s in _READ_SPECS])
    lazy = enterprise_connectors()
    assert len(lazy) == len(eager)
    assert [t.to_anthropic() for t in lazy] == [t.to_anthropic() for t in eager]
    assert all(t._executor._tool is None for t in lazy)
    assert [(t.parallel_safe, t.strict) for t in lazy] == [(t.parallel_safe, t.strict) for t in eager]


def test_base_discovery_builds_no_enterprise_executor(tmp_path, monkeypatch):
    from maverick.sandbox import LocalBackend
    from maverick.tools import _rest_connector as engine
    from maverick.tools.find_tools import find_tools
    names = {d.name for d in enterprise_connector_descriptors()}
    built = []
    original = engine.make_rest_tool

    def counted(**kwargs):
        if kwargs["name"] in names:
            built.append(kwargs["name"])
        return original(**kwargs)

    monkeypatch.setattr(engine, "make_rest_tool", counted)
    monkeypatch.setattr(engine, "make_graphql_tool", lambda **kw: pytest.fail("GraphQL constructed"))
    registry = base_registry(SimpleNamespace(), LocalBackend(workdir=tmp_path),
                             _include_generated_tools=False)
    assert built == []
    registry.enable_deferred({"read_file", "find_tools"})
    registry.register(find_tools(registry))
    before = registry.to_anthropic()
    assert "zendesk" in registry.get("find_tools").fn({"query": "Zendesk Support"})
    assert registry.to_anthropic() is not before
    assert any(t["name"] == "zendesk" for t in registry.to_anthropic())
    assert built == []
    # Missing path returns locally before any credential or HTTP access.
    assert "path is required" in asyncio.run(registry.run("zendesk", {"op": "get"}))
    assert built == ["zendesk"]
    asyncio.run(registry.run("zendesk", {"op": "get"}))
    assert built == ["zendesk"]


def test_metadata_is_shared_immutable_and_deepcopy_remains_editable():
    first, second = enterprise_connectors(), enterprise_connectors()
    assert first[0].descriptor is second[0].descriptor
    assert first[0].input_schema is second[0].input_schema
    with pytest.raises(TypeError, match="immutable"):
        first[0].input_schema["properties"]["op"]["enum"].append("unsafe")
    with pytest.raises(TypeError, match="immutable"):
        first[0].descriptor.factory_kwargs["token_env"] = "WRONG_TOKEN"
    editable = copy.deepcopy(first[0].input_schema)
    editable["properties"]["op"]["enum"].append("synthetic")
    assert "synthetic" not in second[0].input_schema["properties"]["op"]["enum"]
    assert json.loads(json.dumps(first[0].to_anthropic())) == first[0].to_anthropic()


def test_concurrent_resolution_builds_once_and_instances_do_not_share_executor():
    descriptor = _descriptor()
    constructed = []
    barrier = threading.Barrier(8)

    def factory():
        constructed.append(object())
        return _built(descriptor, lambda args: str(args["n"]))

    tool = LazyTool(descriptor, factory=factory)

    def invoke(n):
        barrier.wait(timeout=5)
        return tool.fn({"n": n})

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sorted(pool.map(invoke, range(8))) == [str(n) for n in range(8)]
    assert len(constructed) == 1
    other = LazyTool(descriptor, factory=factory)
    assert other.fn({"n": 9}) == "9"
    assert len(constructed) == 2
    assert tool._executor._tool is not other._executor._tool


def test_construction_failure_is_safe_stable_and_not_repeated():
    descriptor = _descriptor()
    attempts = []

    def factory():
        attempts.append(1)
        raise RuntimeError("secret synthetic credential must not appear")

    tool = LazyTool(descriptor, factory=factory)
    registry = ToolRegistry()
    registry.register(tool)
    results = [asyncio.run(registry.run(tool.name, {})) for _ in range(2)]
    assert results[0] == results[1]
    assert "LazyToolConstructionError" in results[0]
    assert "credential" not in results[0]
    assert attempts == [1]
    registry.register(LazyTool(descriptor, factory=lambda: _built(descriptor, lambda _: "recovered")))
    assert asyncio.run(registry.run(tool.name, {})) == "recovered"


def test_concurrent_construction_failure_is_single_flight():
    attempts = []
    barrier = threading.Barrier(8)

    def factory():
        attempts.append(1)
        raise ValueError("synthetic-secret")

    tool = LazyTool(_descriptor(), factory=factory)

    def invoke(_):
        barrier.wait(timeout=5)
        with pytest.raises(LazyToolConstructionError) as error:
            tool.fn({})
        return str(error.value)

    with ThreadPoolExecutor(max_workers=8) as pool:
        failures = list(pool.map(invoke, range(8)))
    assert len(set(failures)) == 1
    assert "synthetic-secret" not in failures[0]
    assert attempts == [1]


@pytest.mark.parametrize("stop_name", ["budget", "killswitch"])
def test_control_flow_stops_propagate_and_are_not_cached_as_factory_errors(stop_name):
    from maverick.budget import BudgetExceeded
    from maverick.killswitch import Halted
    stop = BudgetExceeded if stop_name == "budget" else Halted
    signal = BudgetExceeded("stop") if stop_name == "budget" else Halted("stop", "test")
    descriptor = _descriptor()
    attempts = []

    def factory():
        attempts.append(1)
        if len(attempts) == 1:
            raise signal
        return _built(descriptor, lambda _: "recovered")

    registry = ToolRegistry()
    registry.register(LazyTool(descriptor, factory=factory))
    with pytest.raises(stop):
        asyncio.run(registry.run(descriptor.name, {}))
    assert asyncio.run(registry.run(descriptor.name, {})) == "recovered"
    assert attempts == [1, 1]


def test_hidden_authorized_tool_remains_callable_without_activation():
    descriptor = _descriptor()
    built = []

    def factory():
        built.append(1)
        return _built(descriptor, lambda _: "ok")

    registry = ToolRegistry()
    registry.register(LazyTool(descriptor, factory=factory))
    registry.enable_deferred(set())
    assert registry.to_anthropic() == []
    assert asyncio.run(registry.run(descriptor.name, {})) == "ok"
    assert built == [1]
    assert registry.to_anthropic() == []


@pytest.mark.parametrize("change", ["name", "description", "input_schema", "parallel_safe", "strict"])
def test_factory_metadata_mismatch_never_invokes_executor(change):
    descriptor = _descriptor()
    calls = []
    result = _built(descriptor, lambda args: calls.append(args))
    setattr(result, change, True if change in {"parallel_safe", "strict"} else "different")
    tool = LazyTool(descriptor, factory=lambda: result)
    with pytest.raises(LazyToolConstructionError):
        tool.fn({})
    assert calls == []


@pytest.mark.parametrize("kind", ["sync", "async", "generator", "async_generator"])
def test_dispatch_and_streaming_contracts_match_eager(kind):
    descriptor = _descriptor()

    def sync(args):
        return "ab"

    async def coroutine(args):
        return "ab"

    def generator(args):
        yield "a"
        yield "b"

    async def async_generator(args):
        yield "a"
        yield "b"

    fn = {"sync": sync, "async": coroutine, "generator": generator,
          "async_generator": async_generator}[kind]
    outputs = []
    for tool in (_built(descriptor, fn), LazyTool(descriptor, factory=lambda: _built(descriptor, fn))):
        registry = ToolRegistry()
        chunks = []
        registry.set_chunk_listener(lambda name, chunk, chunks=chunks: chunks.append((name, chunk)))
        registry.register(tool)
        outputs.append((asyncio.run(registry.run(tool.name, {})), chunks))
    assert outputs[0] == outputs[1]
    assert outputs[0][0] == "ab"


def test_denied_tool_is_neither_discovered_activated_nor_constructed():
    descriptor = _descriptor("secret_connector")
    tool = LazyTool(descriptor, factory=lambda: pytest.fail("denied factory constructed"))
    registry = ToolRegistry()
    registry.register(tool)
    registry.enable_deferred(set())
    registry.set_acl(denied={tool.name})
    assert registry.activate([tool.name]) == []
    assert registry.deferred_tools() == []
    assert registry.exposed() == []
    assert "denied" in asyncio.run(registry.run(tool.name, {}))


@pytest.mark.parametrize("governed", [False, True])
def test_search_tokens_reuse_same_lexical_scoring_without_factory(governed):
    from maverick.tools.find_tools import _score, _tokens
    tool = enterprise_connectors()[0]
    if governed:
        tool = wrap_connector_tool(tool)
    query = {"support", "zendesk", "get", "governed", "human"}
    expected = (len(query & _tokens(f"{tool.name} {tool.description}"))
                + 2 * len(query & _tokens(tool.name)))
    before = search_tokens.cache_info().hits
    assert _score(query, tool) == _score(query, tool) == expected
    assert search_tokens.cache_info().hits >= before + 2
    assert tool._executor._tool is None


def test_governance_eligibility_and_metadata_do_not_construct_factory():
    descriptor = next(d for d in enterprise_connector_descriptors() if d.name == "zendesk")
    registry = ToolRegistry(principal="user:a")
    registry.register(LazyTool(descriptor, factory=lambda: pytest.fail("discovery constructed factory")))
    assert apply_governed_connectors(registry, goal_id=12) == ["zendesk"]
    wrapped = registry.get("zendesk")
    assert isinstance(wrapped, LazyTool)
    assert "transaction-receipted" in wrapped.description
    assert wrapped.fn.__module__ == "maverick.tools._rest_connector"
    assert wrapped.input_schema == descriptor.input_schema


def test_governed_write_refusal_does_not_invoke_connector(monkeypatch):
    from maverick.tools import _rest_connector as engine
    monkeypatch.delenv("MAVERICK_GOVERNED_APPROVER", raising=False)
    monkeypatch.setattr("maverick.config.get_governed_connectors", lambda: {"approver": ""})
    calls = []
    monkeypatch.setattr(engine, "_rest_execute", lambda *a, **kw: calls.append(a) or "sent")
    descriptor = next(d for d in enterprise_connector_descriptors() if d.name == "zendesk")
    lazy = wrap_connector_tool(LazyTool(descriptor), actor="user:a", goal_id=12, enterprise=True)
    result = lazy.fn({"op": "post", "path": "/tickets", "body": {}, "confirm": True})
    assert result.startswith("REFUSED (governed)")
    assert calls == []


def test_lazy_governed_write_retains_receipts_approval_and_actor_goal_binding(monkeypatch):
    from maverick import governed_actions
    from maverick.safety import consent
    from maverick.tools import _rest_connector as engine
    receipts = []
    calls = []
    monkeypatch.setattr(consent, "require_consent", lambda *a, **kw: SimpleNamespace(
        granted=True, source="dashboard", actor="user:reviewer"))
    monkeypatch.setattr(governed_actions, "record_tool_lineage",
                        lambda *a, **kw: receipts.append((a, kw)) or True)
    monkeypatch.setattr(engine, "_rest_execute", lambda *a, **kw: calls.append((a, kw)) or "created")
    descriptor = next(d for d in enterprise_connector_descriptors() if d.name == "zendesk")
    wrapped = wrap_connector_tool(LazyTool(descriptor), actor="user:owner", goal_id=12, enterprise=True)
    assert wrapped.fn({"op": "post", "path": "/tickets", "body": {"subject": "test"}}) == "created"
    assert len(calls) == 1
    assert [kwargs["phase"] for _, kwargs in receipts] == ["PREPARE", "COMMIT"]
    assert all(args[0] == 12 and kwargs["actor"] == "user:owner" for args, kwargs in receipts)
    assert all(kwargs["approver"] == "user:reviewer" and kwargs["strict"] for _, kwargs in receipts)


def test_resolved_governance_preserves_real_callable_provenance_and_binding(monkeypatch):
    from maverick import governed_tools
    descriptor = next(d for d in enterprise_connector_descriptors() if d.name == "zendesk")
    lazy = wrap_connector_tool(LazyTool(descriptor), actor="user:a", goal_id=12, enterprise=True)
    eager = wrap_connector_tool(descriptor.construct(), actor="user:a", goal_id=12, enterprise=True)
    resolved = lazy._executor.resolve()
    assert resolved.to_anthropic() == eager.to_anthropic()
    assert (resolved.fn.__module__, resolved.fn.__qualname__) == (eager.fn.__module__, eager.fn.__qualname__)
    assert resolved.fn.__qualname__ == "wrap_connector_tool.<locals>._fn"
    left = inspect.getclosurevars(resolved.fn).nonlocals
    right = inspect.getclosurevars(eager.fn).nonlocals
    left_receipt = inspect.getclosurevars(left["_receipt"]).nonlocals
    right_receipt = inspect.getclosurevars(right["_receipt"]).nonlocals
    assert left_receipt["actor"] == right_receipt["actor"] == "user:a"
    assert left_receipt["goal_id"] == right_receipt["goal_id"] == 12
    assert left["strict"] is right["strict"] is True
    monkeypatch.setattr("maverick.connections.list_connections", list)
    assert (governed_tools._connector_credential_versions(left["tool"])
            == governed_tools._connector_credential_versions(right["tool"]))
    other = wrap_connector_tool(LazyTool(descriptor), actor="user:b", goal_id=99, enterprise=True)
    assert other.descriptor is lazy.descriptor
    other_locals = inspect.getclosurevars(other._executor.resolve().fn).nonlocals
    other_receipt = inspect.getclosurevars(other_locals["_receipt"]).nonlocals
    assert other_receipt["actor"] == "user:b"
    assert other_receipt["goal_id"] == 99
    assert other_locals["tool"] is not left["tool"]


@pytest.mark.parametrize(
    ("user_id", "ambient", "expected"),
    [
        (None, "user:network", "user:network"),
        ("  ", "user:network", "user:network"),
        (" alice ", "user:network", "user:alice"),
        ("user:bob", "user:network", "user:bob"),
        (None, None, "anonymous"),
    ],
)
def test_base_registry_retains_resolved_principal(tmp_path, user_id, ambient, expected):
    from maverick.connections import bind_principal, current_principal
    from maverick.sandbox import LocalBackend

    with bind_principal(ambient):
        registry = base_registry(SimpleNamespace(), LocalBackend(workdir=tmp_path),
                                 user_id=user_id, _include_generated_tools=False)
    registry.register(Tool("capture_principal", "Capture principal", {"type": "object"},
                           lambda _: current_principal() or "anonymous"))
    assert asyncio.run(registry.run("capture_principal", {})) == expected


def test_registry_instances_bind_current_principal_and_tenant_per_call(monkeypatch):
    from maverick.connections import current_principal
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick.tools import _rest_connector as engine
    seen = []
    monkeypatch.setattr(engine, "_rest_execute", lambda *a, **kw: seen.append(
        (current_principal(), current_tenant_id())) or "ok")
    descriptor = next(d for d in enterprise_connector_descriptors() if d.name == "zendesk")
    registries = [ToolRegistry(principal=p) for p in ("user:a", "user:b")]
    for registry in registries:
        registry.register(LazyTool(descriptor))
        apply_governed_connectors(registry)
    for tenant, registry in zip(("tenant-a", "tenant-b", "tenant-a"),
                                (registries[0], registries[1], registries[0]), strict=True):
        token = set_tenant(tenant)
        try:
            assert asyncio.run(registry.run("zendesk", {"op": "get", "path": "/tickets"})) == "ok"
        finally:
            reset_tenant(token)
    assert seen == [("user:a", "tenant-a"), ("user:b", "tenant-b"), ("user:a", "tenant-a")]


def test_configured_rate_limit_blocks_before_unused_factory():
    from maverick.safety.rate_limiter import apply_to_registry
    descriptor = _descriptor()
    built = []

    def factory():
        built.append(1)
        return _built(descriptor, lambda _: "ok")

    registry = ToolRegistry()
    registry.register(LazyTool(descriptor, factory=factory))
    apply_to_registry(registry, limits={descriptor.name: (1, 3600.0)})
    assert built == []
    assert asyncio.run(registry.run(descriptor.name, {})) == "ok"
    assert "rate limit exceeded" in asyncio.run(registry.run(descriptor.name, {}))
    assert built == [1]
