"""Tests for the kv_memory tool (maverick.tools.kv_memory)."""
from __future__ import annotations

from pathlib import Path

import pytest

# ---------- kv_memory ----------

@pytest.fixture
def world_with_goal(tmp_path):
    from maverick.world_model import WorldModel
    w = WorldModel(Path(tmp_path) / "wm.sqlite")
    gid = w.create_goal("test goal", "for kv_memory tests")
    yield w, gid
    w.close()


def test_kv_memory_set_get_round_trip(world_with_goal):
    from maverick.tools.kv_memory import kv_memory
    world, gid = world_with_goal
    tool = kv_memory(world, gid)
    assert "set 'key1'" in tool.fn({"op": "set", "key": "key1", "value": "v1"})
    assert tool.fn({"op": "get", "key": "key1"}) == "v1"


def test_kv_memory_missing_key_returns_sentinel(world_with_goal):
    from maverick.tools.kv_memory import kv_memory
    world, gid = world_with_goal
    out = kv_memory(world, gid).fn({"op": "get", "key": "nope"})
    assert "no fact stored" in out


def test_kv_memory_upsert(world_with_goal):
    from maverick.tools.kv_memory import kv_memory
    world, gid = world_with_goal
    tool = kv_memory(world, gid)
    tool.fn({"op": "set", "key": "k", "value": "first"})
    tool.fn({"op": "set", "key": "k", "value": "second"})
    assert tool.fn({"op": "get", "key": "k"}) == "second"


def test_kv_memory_list(world_with_goal):
    from maverick.tools.kv_memory import kv_memory
    world, gid = world_with_goal
    tool = kv_memory(world, gid)
    tool.fn({"op": "set", "key": "a", "value": "1"})
    tool.fn({"op": "set", "key": "b", "value": "22"})
    out = tool.fn({"op": "list"})
    assert "a" in out and "b" in out


def test_kv_memory_search(world_with_goal):
    from maverick.tools.kv_memory import kv_memory
    world, gid = world_with_goal
    tool = kv_memory(world, gid)
    tool.fn({"op": "set", "key": "auth.password", "value": "secret"})
    tool.fn({"op": "set", "key": "auth.user", "value": "alice"})
    tool.fn({"op": "set", "key": "config.port", "value": "8080"})
    out = tool.fn({"op": "search", "query": "auth"})
    assert "auth.password" in out
    assert "auth.user" in out
    assert "config.port" not in out


def test_kv_memory_delete(world_with_goal):
    from maverick.tools.kv_memory import kv_memory
    world, gid = world_with_goal
    tool = kv_memory(world, gid)
    tool.fn({"op": "set", "key": "k", "value": "v"})
    out = tool.fn({"op": "delete", "key": "k"})
    assert "deleted 1" in out
    assert "no fact stored" in tool.fn({"op": "get", "key": "k"})


def test_kv_memory_requires_active_goal():
    from maverick.tools.kv_memory import kv_memory
    out = kv_memory(world=None, goal_id=None).fn({"op": "get", "key": "x"})
    assert "ERROR" in out and "active goal" in out
