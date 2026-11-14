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


def _config_file(tmp_path, monkeypatch, text):
    from maverick import config
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    config.reset_config_cache()
    return path


@pytest.mark.asyncio
async def test_unreadable_config_without_hooks_allows(tmp_path, monkeypatch):
    _config_file(tmp_path, monkeypatch, "[budget\nmax_dollars = 1\n")
    hooks.load_from_config()
    assert await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell") is True


@pytest.mark.asyncio
async def test_unreadable_hooks_config_blocks_until_fixed(tmp_path, monkeypatch):
    path = _config_file(tmp_path, monkeypatch, (
        "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"shell\"\n"
        "command = \"/bin/false\"\n[broken\n"))
    hooks.load_from_config()
    ctx = HookContext(event=HookEvent.PRE_TOOL_USE, tool_name="read_file")
    assert await hooks.dispatch(ctx) is False
    assert "hooks configuration could not be read" in ctx.block_reason
    assert str(path) in ctx.block_reason
    assert await _dispatch(HookEvent.POST_TOOL_USE, tool_name="shell") is True

    # Fixed on disk: the block lifts without a restart and the hooks load.
    path.write_text("[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"shell\"\n"
                    "command = \"/bin/false\"\n", encoding="utf-8")
    assert await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="read_file") is True
    assert await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell") is False


@pytest.mark.asyncio
async def test_malformed_entry_does_not_drop_later_guard(monkeypatch):
    import maverick.config as cfg

    monkeypatch.setattr(cfg, "config_source_errors", lambda **_k: {})
    monkeypatch.setattr(cfg, "load_config", lambda: {"hooks": [
        {"event": "PostToolUse", "command": "true", "timeout_ms": "5s"},
        "not-a-table",
        {"event": "PreToolUse", "matcher": "shell", "command": "/bin/false"},
    ]})
    hooks.load_from_config()
    assert await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell") is False


@pytest.mark.asyncio
async def test_shell_hook_gets_extra_and_expands_home_in_arguments(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "gate.py").write_text(
        "import json, sys\n"
        "sys.exit(0 if json.load(sys.stdin)['extra'].get('prompt') == 'ok' else 1)\n"
    )
    hooks.register(HookEvent.USER_PROMPT_SUBMIT,
                   f"{shlex.quote(sys.executable)} ~/gate.py")
    assert await _dispatch(HookEvent.USER_PROMPT_SUBMIT, extra={"prompt": "ok"}) is True
    assert await _dispatch(HookEvent.USER_PROMPT_SUBMIT, extra={"prompt": "no"}) is False


def test_concurrent_ensure_loaded_waits_for_the_first_load(monkeypatch):
    import asyncio
    import threading

    started = threading.Event()

    def slow_load():
        started.set()
        threading.Event().wait(0.2)
        hooks.register(HookEvent.PRE_TOOL_USE, lambda _c: False)

    monkeypatch.setattr(hooks, "load_from_config", slow_load)
    monkeypatch.setattr(hooks, "load_from_entry_points", lambda: None)
    first = threading.Thread(target=lambda: asyncio.run(hooks.ensure_loaded()))
    first.start()
    started.wait(5)

    async def second():
        await hooks.ensure_loaded()
        return await _dispatch(HookEvent.PRE_TOOL_USE, tool_name="shell")

    assert asyncio.run(second()) is False
    first.join(5)
