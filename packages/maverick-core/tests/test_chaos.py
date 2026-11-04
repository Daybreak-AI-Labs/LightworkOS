"""Tests for the chaos fault-injection harness (maverick.chaos)."""
from __future__ import annotations

# ---------- chaos: concurrent roll() doesn't tear the RNG ----------

def test_chaos_roll_is_thread_safe_smoke():
    import threading

    from maverick.chaos import ChaosController, ChaosInjected, maybe_fail
    c = ChaosController()
    c.set(active=True, seed=1, sandbox_exec_fail_pct=50)
    errors: list[str] = []

    def _hammer():
        for _ in range(200):
            try:
                maybe_fail("sandbox_exec")
            except ChaosInjected:
                pass
            except Exception as e:  # a torn RNG read would land here
                errors.append(repr(e))

    threads = [threading.Thread(target=_hammer) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    c.disable()
    assert not errors, f"concurrent roll() raised: {errors[:3]}"


# ---------- chaos harness ----------

def test_chaos_disabled_is_noop():
    from maverick.chaos import ChaosController, maybe_fail
    c = ChaosController()
    c.disable()
    # No exception, no state change.
    maybe_fail("sandbox_exec")
    maybe_fail("tool_dispatch")


def test_chaos_active_block_injects_then_restores():
    from maverick.chaos import ChaosController, ChaosInjected
    c = ChaosController()
    c.disable()
    seen_fail = False
    with c.active(sandbox_exec_fail_pct=100, seed=42):
        try:
            from maverick.chaos import maybe_fail
            maybe_fail("sandbox_exec")
        except ChaosInjected:
            seen_fail = True
    assert seen_fail
    # Restored — should not fail outside the block.
    from maverick.chaos import maybe_fail
    maybe_fail("sandbox_exec")


def test_chaos_state_is_deterministic_with_seed():
    from maverick.chaos import ChaosController, ChaosInjected, maybe_fail
    c = ChaosController()
    c.set(active=True, seed=42, sandbox_exec_fail_pct=50)
    results = []
    for _ in range(20):
        try:
            maybe_fail("sandbox_exec")
            results.append(False)
        except ChaosInjected:
            results.append(True)
    # Replay with the same seed -> same outcomes.
    c.set(active=True, seed=42, sandbox_exec_fail_pct=50)
    results2 = []
    for _ in range(20):
        try:
            maybe_fail("sandbox_exec")
            results2.append(False)
        except ChaosInjected:
            results2.append(True)
    c.disable()
    assert results == results2


def test_chaos_unknown_stage_is_ignored():
    from maverick.chaos import ChaosController, maybe_fail
    c = ChaosController()
    c.set(active=True, sandbox_exec_fail_pct=100)
    # An unknown stage never fails.
    maybe_fail("nonexistent_stage")
    c.disable()


def test_chaos_env_parses_rates(monkeypatch):
    monkeypatch.setenv("MAVERICK_CHAOS", "sandbox:30,tool:10,llm:5")
    monkeypatch.setenv("MAVERICK_CHAOS_SEED", "7")
    # Clear the singleton so the env is re-read.
    import maverick.chaos as chaos_mod
    chaos_mod._singleton = None
    try:
        c = chaos_mod.get()
        assert c.state.active is True
        assert c.state.rates == {
            "sandbox_exec": 30, "tool_dispatch": 10,
            "llm_call": 5, "http_fetch": 0,
        }
    finally:
        c.disable()
        chaos_mod._singleton = None


def test_chaos_propagates_through_local_sandbox(tmp_path):
    """LocalBackend.exec honors the chaos dial."""
    from maverick.chaos import ChaosController, ChaosInjected
    from maverick.sandbox.local import LocalBackend
    backend = LocalBackend(workdir=tmp_path, timeout=2.0)
    c = ChaosController()
    with c.active(sandbox_exec_fail_pct=100, seed=1):
        try:
            backend.exec("true")
        except ChaosInjected:
            return
    raise AssertionError("expected ChaosInjected")


def test_chaos_propagates_through_tool_dispatcher():
    import asyncio

    from maverick.chaos import ChaosController
    from maverick.tools import Tool, ToolRegistry

    reg = ToolRegistry()
    reg.register(Tool(
        name="echo",
        description="echo",
        input_schema={"type": "object", "properties": {}},
        fn=lambda args: "ok",
    ))
    c = ChaosController()
    with c.active(tool_dispatch_fail_pct=100, seed=1):
        result = asyncio.run(reg.run("echo", {}))
    # ToolRegistry.run catches its own exceptions and returns
    # "ERROR: ...". Chaos goes through the same path.
    assert "ERROR" in result
    assert "ChaosInjected" in result or "chaos" in result
