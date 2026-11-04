"""Tests for lifecycle hooks (maverick.hooks): entry-point loading, matching,
blocking and error isolation.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

# ---------- hooks: load_from_entry_points ----------

def test_hooks_load_from_entry_points_empty(monkeypatch, tmp_path):
    """No matching entry points -> 0 hooks registered, no errors."""
    from maverick.hooks import clear, load_from_entry_points
    clear()
    monkeypatch.delenv("MAVERICK_PLUGINS_ALLOW", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nonexistent.toml"))
    n = load_from_entry_points()
    assert n == 0  # must not raise


def test_hooks_load_from_entry_points_registers_specs(monkeypatch):
    """An entry-point factory returning HookSpec objects gets registered."""
    from maverick.hooks import (
        HookEvent,
        HookSpec,
        clear,
        installed,
        load_from_entry_points,
    )
    clear()
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")

    def _register() -> list[HookSpec]:
        return [
            HookSpec(event=HookEvent.PRE_TOOL_USE, matcher="*", callable=lambda ctx: True),
            HookSpec(event=HookEvent.POST_TOOL_USE, matcher="shell", callable=lambda ctx: None),
        ]

    class _FakeEP:
        name = "fake_plugin"
        def load(self):
            return _register

    with patch("importlib.metadata.entry_points", return_value=[_FakeEP()]):
        n = load_from_entry_points()

    assert n == 2
    names = [(s.event, s.matcher) for s in installed()]
    assert (HookEvent.PRE_TOOL_USE, "*") in names
    assert (HookEvent.POST_TOOL_USE, "shell") in names


def test_hooks_load_from_entry_points_accepts_tuples(monkeypatch):
    """Factory returning (event, callable) tuples works too."""
    from maverick.hooks import HookEvent, clear, installed, load_from_entry_points
    clear()
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")

    def _register():
        return [
            (HookEvent.SESSION_START, lambda ctx: True),
        ]

    class _FakeEP:
        name = "fake_plugin"
        def load(self):
            return _register

    with patch("importlib.metadata.entry_points", return_value=[_FakeEP()]):
        n = load_from_entry_points()

    assert n == 1
    assert any(s.event == HookEvent.SESSION_START for s in installed())


def test_hooks_load_from_entry_points_isolates_broken_plugin(monkeypatch):
    """A plugin that raises on load() doesn't disable other plugins."""
    from maverick.hooks import HookEvent, HookSpec, clear, installed, load_from_entry_points
    clear()
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")

    class _BrokenEP:
        name = "broken"
        def load(self):
            raise RuntimeError("plugin import failed")

    class _GoodEP:
        name = "good"
        def load(self):
            return lambda: [HookSpec(event=HookEvent.PRE_TOOL_USE, matcher="*", callable=lambda ctx: True)]

    with patch("importlib.metadata.entry_points", return_value=[_BrokenEP(), _GoodEP()]):
        n = load_from_entry_points()

    # Broken plugin contributed 0; good plugin contributed 1.
    assert n == 1
    assert len(installed()) == 1


def test_hooks_load_from_entry_points_isolates_broken_factory_call(monkeypatch):
    """A factory that raises when called doesn't crash the loader."""
    from maverick.hooks import HookEvent, HookSpec, clear, installed, load_from_entry_points
    clear()
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")

    def _broken_factory():
        raise ValueError("factory crashed")

    def _good_factory():
        return [HookSpec(event=HookEvent.POST_TOOL_USE, matcher="*", callable=lambda ctx: None)]

    class _BrokenEP:
        name = "broken"
        def load(self):
            return _broken_factory

    class _GoodEP:
        name = "good"
        def load(self):
            return _good_factory

    with patch("importlib.metadata.entry_points", return_value=[_BrokenEP(), _GoodEP()]):
        n = load_from_entry_points()

    assert n == 1
    assert len(installed()) == 1


def test_hooks_load_from_entry_points_ignores_invalid_items(monkeypatch):
    """Items that aren't HookSpec / (event, fn) get warned + dropped."""
    from maverick.hooks import HookEvent, HookSpec, clear, installed, load_from_entry_points
    clear()
    monkeypatch.setenv("MAVERICK_PLUGINS_ALLOW", "*")

    def _register():
        return [
            "garbage string",
            42,
            HookSpec(event=HookEvent.PRE_TOOL_USE, matcher="ok", callable=lambda ctx: True),
            (HookEvent.STOP,),  # malformed tuple
        ]

    class _FakeEP:
        name = "fake"
        def load(self):
            return _register

    with patch("importlib.metadata.entry_points", return_value=[_FakeEP()]):
        n = load_from_entry_points()

    # Only the valid HookSpec entry registers.
    assert n == 1
    assert len(installed()) == 1


# ---------- Hooks lifecycle ----------

class TestHooks:
    def teardown_method(self):
        from maverick import hooks
        hooks.clear()

    @pytest.mark.asyncio
    async def test_pre_tool_use_callable_can_block(self):
        from maverick import hooks
        from maverick.hooks import HookContext, HookEvent
        hooks.register(
            HookEvent.PRE_TOOL_USE,
            lambda ctx: False,  # block everything
            matcher="*",
        )
        ctx = HookContext(event=HookEvent.PRE_TOOL_USE, tool_name="shell")
        allowed = await hooks.dispatch(ctx)
        assert allowed is False

    @pytest.mark.asyncio
    async def test_post_tool_use_cannot_block(self):
        """Post* hooks observe; they never block."""
        from maverick import hooks
        from maverick.hooks import HookContext, HookEvent
        hooks.register(HookEvent.POST_TOOL_USE, lambda ctx: False)
        ctx = HookContext(event=HookEvent.POST_TOOL_USE, tool_name="shell",
                          tool_result="ok")
        allowed = await hooks.dispatch(ctx)
        assert allowed is True

    @pytest.mark.asyncio
    async def test_matcher_glob(self):
        from maverick import hooks
        from maverick.hooks import HookContext, HookEvent
        seen: list[str] = []
        hooks.register(
            HookEvent.PRE_TOOL_USE,
            lambda ctx: seen.append(ctx.tool_name) or True,
            matcher="shell*",
        )
        await hooks.dispatch(HookContext(event=HookEvent.PRE_TOOL_USE,
                                         tool_name="shell"))
        await hooks.dispatch(HookContext(event=HookEvent.PRE_TOOL_USE,
                                         tool_name="shell_alias"))
        await hooks.dispatch(HookContext(event=HookEvent.PRE_TOOL_USE,
                                         tool_name="read_file"))
        assert seen == ["shell", "shell_alias"]

    @pytest.mark.asyncio
    async def test_hook_exception_is_isolated(self):
        """A buggy hook must not take down the agent (no exception propagates)."""
        from maverick import hooks
        from maverick.hooks import HookContext, HookEvent

        def bad(ctx):
            raise RuntimeError("oops")

        hooks.register(HookEvent.PRE_TOOL_USE, bad)
        # The exception is caught (the agent doesn't crash). PRE_TOOL_USE is a
        # blocking gate, so a hook that errors now fails CLOSED -- the action is
        # denied rather than silently allowed past a broken guard.
        allowed = await hooks.dispatch(HookContext(
            event=HookEvent.PRE_TOOL_USE, tool_name="shell",
        ))
        assert allowed is False

    @pytest.mark.asyncio
    async def test_async_callable_hook(self):
        from maverick import hooks
        from maverick.hooks import HookContext, HookEvent

        async def async_hook(ctx):
            return True

        hooks.register(HookEvent.PRE_TOOL_USE, async_hook)
        allowed = await hooks.dispatch(HookContext(
            event=HookEvent.PRE_TOOL_USE, tool_name="x",
        ))
        assert allowed is True

    @pytest.mark.asyncio
    async def test_shell_hook_blocks_on_nonzero_exit(self, tmp_path):
        """A shell command exiting non-zero blocks PreToolUse.

        Portable across Unix + Windows. Uses a python -c
        one-liner instead of a #!/bin/sh script (Windows has no
        /bin/sh interpreter).
        """
        import sys

        from maverick import hooks
        from maverick.hooks import HookContext, HookEvent
        py = sys.executable
        hooks.register(
            HookEvent.PRE_TOOL_USE,
            f'"{py}" -c "import sys; sys.exit(1)"',
            matcher="dangerous_*",
        )
        allowed = await hooks.dispatch(HookContext(
            event=HookEvent.PRE_TOOL_USE,
            tool_name="dangerous_shell",
        ))
        assert allowed is False
