"""Bounded-growth / DoS-hardening regressions from the red-team audit:
the blackboard and the A2A in-memory task store must not grow without limit,
and runtime-override tool names are re-validated on read.
"""
from __future__ import annotations

import asyncio


def test_blackboard_caps_entries(monkeypatch):
    from maverick.blackboard import Blackboard
    monkeypatch.setattr(Blackboard, "_MAX_ENTRIES", 5)
    b = Blackboard()
    for i in range(20):
        b.post("agent", "observation", f"entry-{i}")
    assert len(b.entries) == 5
    # The most recent entries are the ones retained.
    assert b.entries[-1].content == "entry-19"
    assert b.entries[0].content == "entry-15"


def test_a2a_task_store_is_bounded(monkeypatch):
    import maverick.a2a_tasks as a2a
    monkeypatch.setattr(a2a, "_MAX_TASKS", 3)

    def _runner(text, *, max_dollars, max_wall, max_depth):
        return "ok"

    eng = a2a.TaskEngine(runner=_runner)
    ids = []
    for i in range(10):
        t = asyncio.run(eng.send(
            {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": f"g{i}"}],
                    "messageId": f"bounded-growth-{i}",
                }
            }
        ))
        ids.append(t["id"])
    assert len(eng._tasks) == 3  # capped
    # The oldest were evicted; the newest survive.
    assert ids[-1] in eng._tasks
    assert ids[0] not in eng._tasks


def test_runtime_overrides_rejects_invalid_security_names(tmp_path, monkeypatch):
    import maverick.runtime_overrides as ro
    import pytest

    override = tmp_path / "runtime-overrides.toml"
    override.write_text(
        '[security]\n'
        'denied_tools = ["shell", "BAD NAME", "../escape", "ok_tool"]\n'
    )
    monkeypatch.setattr(ro, "OVERRIDES_PATH", override)
    ro._announced.clear()
    # Silently dropping a malformed denial could re-enable a protected tool.
    with pytest.raises(ro.RuntimeOverridesSecurityError):
        ro.denied_tools()


def test_runtime_override_notice_caches_are_bounded(tmp_path, monkeypatch):
    import maverick.runtime_overrides as ro

    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    ro._announced.clear()
    for index in range(ro._ANNOUNCED_LIMIT + 20):
        ro.set_allowed_models([])
        ro.disable_tool(f"bounded{index}")
        ro.enable_tool(f"bounded{index}")
    assert len(ro._announced) <= ro._ANNOUNCED_LIMIT
    assert len(ro._last_known_good) <= ro._LKG_LIMIT
