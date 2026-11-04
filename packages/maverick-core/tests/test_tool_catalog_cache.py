"""ToolRegistry.to_anthropic() is memoized but stays correct across mutations."""
from __future__ import annotations

from maverick.tools import Tool, ToolRegistry


def _tool(name: str) -> Tool:
    return Tool(name=name, description=f"d {name}", input_schema={"type": "object"}, fn=lambda a: "")


def test_cache_returns_stable_payload_and_memoizes():
    reg = ToolRegistry()
    reg.register(_tool("a"))
    reg.register(_tool("b"))
    first = reg.to_anthropic()
    second = reg.to_anthropic()
    assert first is second  # memoized (same object)
    assert {t["name"] for t in first} == {"a", "b"}


def test_register_invalidates_cache():
    reg = ToolRegistry()
    reg.register(_tool("a"))
    before = reg.to_anthropic()
    reg.register(_tool("c"))
    after = reg.to_anthropic()
    assert after is not before
    assert {t["name"] for t in after} == {"a", "c"}


def test_activate_and_acl_invalidate_cache():
    reg = ToolRegistry()
    for n in ("find_tools", "core1", "extra"):
        reg.register(_tool(n))
    reg.enable_deferred({"core1"})
    exposed = {t["name"] for t in reg.to_anthropic()}
    assert exposed == {"core1", "find_tools"}  # 'extra' deferred
    reg.activate(["extra"])
    assert "extra" in {t["name"] for t in reg.to_anthropic()}  # invalidated + revealed

    # ACL change also invalidates.
    reg2 = ToolRegistry()
    reg2.register(_tool("x"))
    reg2.register(_tool("y"))
    _ = reg2.to_anthropic()
    reg2.set_acl(denied={"y"})
    reg2.register(_tool("z"))  # ACL applies on (re)register
    names = {t["name"] for t in reg2.to_anthropic()}
    assert "z" in names


def test_activate_unknown_name_keeps_cache():
    reg = ToolRegistry()
    reg.register(_tool("find_tools"))
    reg.register(_tool("core1"))
    reg.enable_deferred({"core1"})
    payload = reg.to_anthropic()
    reg.activate(["does_not_exist"])  # no-op -> cache should survive
    assert reg.to_anthropic() is payload
