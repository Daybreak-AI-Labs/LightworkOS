"""Blocking (Pre*) hooks are a guardrail: a TIMEOUT, a missing binary, or an
exception must all fail CLOSED -- an attacker who can slow, delete/rename, or
crash a guard hook (e.g. via a model-influenced tool arg) would otherwise
bypass it. Hooks must not be handed the kernel's secret env. Post* hooks have
nothing to block, so they stay fail-open.
"""
import shlex
import sys

import pytest
from maverick import hooks
from maverick.hooks import HookContext, HookEvent


@pytest.fixture(autouse=True)
def _clean_registry():
    hooks.clear()
    yield
    hooks.clear()


async def _dispatch(event, **fields):
    return await hooks.dispatch(HookContext(event=event, **fields))


@pytest.mark.asyncio
async def test_blocking_hook_times_out_fails_closed():
    # A PreToolUse hook that sleeps past its timeout must BLOCK the action.
    hooks.register(
        HookEvent.PRE_TOOL_USE,
        f"{sys.executable} -c 'import time; time.sleep(5)'",
        matcher="*", timeout_ms=100,
    )
    allowed = await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell")
    assert allowed is False


@pytest.mark.asyncio
async def test_post_hook_timeout_stays_fail_open():
    # PostToolUse can't block; a slow one must not wedge the run.
    import sys
    hooks.register(
        HookEvent.POST_TOOL_USE,
        f"{sys.executable} -c 'import time; time.sleep(5)'",
        matcher="*", timeout_ms=100,
    )
    allowed = await _dispatch(HookEvent.POST_TOOL_USE, tool_name="write_file")
    assert allowed is True


@pytest.mark.asyncio
async def test_blocking_missing_binary_fails_closed():
    # A blocking hook whose binary is missing never vetted the action -- an
    # attacker who deletes/renames/chmod-x's the guard must not disarm it.
    hooks.register(
        HookEvent.PRE_TOOL_USE, "/nonexistent/guardrail", matcher="*",
    )
    allowed = await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell")
    assert allowed is False


@pytest.mark.asyncio
async def test_post_missing_binary_stays_fail_open():
    # Post* hooks have nothing to block; a missing one just doesn't run.
    hooks.register(HookEvent.POST_TOOL_USE, "/nonexistent/x", matcher="*")
    allowed = await _dispatch(HookEvent.POST_TOOL_USE, tool_name="write_file")
    assert allowed is True


@pytest.mark.asyncio
async def test_blocking_callable_exception_fails_closed():
    # A guard callable that raises (e.g. on a model-influenced tool arg) hasn't
    # vetted the action, so a blocking hook must block rather than wave it.
    def _raise(ctx):
        raise RuntimeError("hook bug")

    hooks.register(HookEvent.PRE_TOOL_USE, _raise, matcher="*")
    allowed = await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell")
    assert allowed is False


@pytest.mark.asyncio
async def test_post_callable_exception_stays_fail_open():
    def _raise(ctx):
        raise RuntimeError("boom")

    hooks.register(HookEvent.POST_TOOL_USE, _raise, matcher="*")
    allowed = await _dispatch(HookEvent.POST_TOOL_USE, tool_name="x")
    assert allowed is True


@pytest.mark.asyncio
async def test_hook_env_omits_secrets(tmp_path, monkeypatch):
    # A hook must not receive the kernel's provider keys / tokens.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")  # pragma: allowlist secret
    monkeypatch.setenv("SOME_API_TOKEN", "tok-should-not-leak")  # pragma: allowlist secret
    monkeypatch.setenv("PLAIN_SETTING", "keep-me")
    out = tmp_path / "env.txt"
    script = tmp_path / "dump_env.py"
    script.write_text(
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "Path(sys.argv[1]).write_text(\n"
        "    ''.join(f'{key}={value}\\n' for key, value in os.environ.items()),\n"
        "    encoding='utf-8',\n"
        ")\n",
        encoding="utf-8",
    )
    command = shlex.join([sys.executable, str(script), str(out)])
    hooks.register(HookEvent.POST_TOOL_USE, command, matcher="*", timeout_ms=5000)
    await _dispatch(HookEvent.POST_TOOL_USE, tool_name="x")
    dumped = out.read_text(encoding="utf-8")
    assert "sk-ant-should-not-leak" not in dumped  # pragma: allowlist secret
    assert "tok-should-not-leak" not in dumped  # pragma: allowlist secret
    # Non-secret vars + the hook metadata still pass through.
    assert "keep-me" in dumped
    assert "MAVERICK_HOOK_EVENT=PostToolUse" in dumped
