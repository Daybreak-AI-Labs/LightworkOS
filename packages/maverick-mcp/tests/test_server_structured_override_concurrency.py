"""Concurrency stress test for the MCP server's per-request structured-override.

HTTP reuses ONE ``MCPServer`` across concurrent clients, so the structured
result a side-effectful tool stashes (``_structured_override``) must stay
isolated per request. Isolation is provided by the ``_STRUCTURED_OVERRIDE_CTX``
ContextVar that ``resource_update_scope`` activates; outside a scope (stdio:
one server : one client) the property falls back to a shared instance attr.

This pins that isolation under real thread concurrency — the structured-override
ContextVar path is the hazard in splitting ``mcp/server.py`` TOOLS. It is a
characterization test: it passes on the current design and fails loudly if a
refactor reintroduces the shared-attribute leak.
"""
from __future__ import annotations

import threading

from maverick_mcp.server import MCPServer


def test_structured_override_isolated_across_concurrent_threads():
    """32 concurrent scopes each stash a unique result; none may read another's.

    A barrier forces every thread to WRITE before any thread READS, so a shared
    mutable slot would surface as a thread reading the last writer's value
    instead of its own. Passing proves the ContextVar isolates per thread.
    """
    server = MCPServer()
    n = 32
    results: dict[int, object] = {}
    errors: list[BaseException] = []
    ready = threading.Barrier(n)

    def worker(i: int) -> None:
        try:
            with server.resource_update_scope(set()):
                server._structured_override = {"req": i}
                ready.wait(timeout=10)  # all set before any read
                results[i] = server._structured_override
        except BaseException as exc:  # noqa: BLE001 -- surface any thread failure
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not errors, errors
    # Each worker reads back exactly its own value — no cross-thread leak.
    assert results == {i: {"req": i} for i in range(n)}


def test_structured_override_scope_does_not_clobber_instance_attr():
    """The stdio (no-scope) instance attr and a per-request scope are disjoint.

    A scope starts clean (None), routes writes to the ContextVar, and on exit
    leaves the shared instance attribute exactly as it was — so an HTTP request
    can never overwrite the stdio fallback (or a sibling request's) slot.
    """
    server = MCPServer()
    server._structured_override = {"x": 1}  # stdio path -> instance attr
    assert server._structured_override == {"x": 1}

    with server.resource_update_scope(set()):
        assert server._structured_override is None  # scope starts clean
        server._structured_override = {"y": 2}
        assert server._structured_override == {"y": 2}

    # Instance attr untouched by the scope.
    assert server._structured_override == {"x": 1}


def test_structured_override_nested_scopes_restore_outer():
    """Nested scopes (defensive: a scope opened within a scope) restore the
    outer request's value on exit — the ContextVar token reset is correct."""
    server = MCPServer()
    with server.resource_update_scope(set()):
        server._structured_override = {"level": "outer"}
        with server.resource_update_scope(set()):
            assert server._structured_override is None
            server._structured_override = {"level": "inner"}
            assert server._structured_override == {"level": "inner"}
        # Inner scope exited -> outer value restored, not leaked/lost.
        assert server._structured_override == {"level": "outer"}
