"""Request-scoped MCP state remains isolated across concurrent clients."""
import asyncio

from maverick_mcp.session import (
    current_pending_updates,
    current_structured_override,
    current_subscriptions,
    resource_update_scope,
    set_scoped_structured_override,
)


def test_nested_resource_scopes_restore_outer_state():
    default = {"default"}
    assert current_subscriptions(default) is default
    assert set_scoped_structured_override({"ignored": True}) is False
    with resource_update_scope({"outer"}):
        pending = current_pending_updates()
        pending.append("outer-update")
        assert set_scoped_structured_override({"owner": "outer"}) is True
        with resource_update_scope({"inner"}):
            assert current_subscriptions(default) == {"inner"}
            assert current_pending_updates() == []
            assert current_structured_override({"default": True}) is None
            set_scoped_structured_override({"owner": "inner"})
        assert current_subscriptions(default) == {"outer"}
        assert current_pending_updates() == ["outer-update"]
        assert current_structured_override(None) == {"owner": "outer"}
    assert current_pending_updates() is None
    assert current_structured_override({"default": True}) == {"default": True}


def test_parallel_requests_and_thread_handoff_keep_their_own_state():
    async def one(name):
        with resource_update_scope({name}):
            set_scoped_structured_override({"owner": name})
            current_pending_updates().append(name + "-update")
            await asyncio.sleep(0)
            return await asyncio.to_thread(
                lambda: (current_subscriptions(set()), current_pending_updates()[:],
                         current_structured_override(None))
            )

    async def parallel():
        return await asyncio.gather(one("alice"), one("bob"))

    assert asyncio.run(parallel()) == [
        ({"alice"}, ["alice-update"], {"owner": "alice"}),
        ({"bob"}, ["bob-update"], {"owner": "bob"}),
    ]
