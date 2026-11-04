"""Real local fixture children only: no Codex login, models or network."""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import pytest
from maverick import owned_process
from maverick.owned_process import OwnedProcess, ProcessOutputLimit, run_owned
from maverick.providers import codex_cli_provider as codex
from maverick.run_outcome import owned_task, task_stop


def _command(code):
    return [sys.executable, "-I", "-u", "-c", code]


async def _wait(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline
        await asyncio.sleep(0.005)


@pytest.fixture
def children(monkeypatch):
    actual = owned_process.OwnedProcess
    captured = []

    def capture(*args, **kwargs):
        child = actual(*args, **kwargs)
        captured.append(child)
        return child

    monkeypatch.setattr(owned_process, "OwnedProcess", capture)
    yield captured
    for child in captured:
        child.close()


def _assert_reaped(children):
    assert children
    for child in children:
        assert child.proc.poll() is not None
        assert all(not thread.is_alive() for thread in child._threads)


@pytest.mark.asyncio
async def test_utf8_bounded_pipes_and_stdin_eof(children):
    response = await run_owned(
        _command("import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.buffer.write('測定'.encode())"),
        input="Answer → café 日本", deadline=time.monotonic() + 5, env=dict(os.environ),
    )
    assert response.stdout == "Answer → café 日本"
    assert response.stderr == "測定"
    assert response.returncode == 0
    _assert_reaped(children)


@pytest.mark.asyncio
@pytest.mark.parametrize("pipe", ["stdout", "stderr"])
async def test_output_overflow_terminates_without_buffer_growth(children, pipe):
    with pytest.raises(ProcessOutputLimit):
        await run_owned(
            _command(f"import sys;\nwhile True: sys.{pipe}.buffer.write(b'x'*16384)"),
            input="", deadline=time.monotonic() + 5, env=dict(os.environ),
            stdout_limit=32768, stderr_limit=32768,
        )
    _assert_reaped(children)


@pytest.mark.asyncio
async def test_blocked_stdin_deadline_reaps_owned_writer(children):
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        await run_owned(
            _command("import time; time.sleep(60)"), input="x" * 2_000_000,
            deadline=start + 0.3, env=dict(os.environ),
        )
    assert time.monotonic() - start < 2
    _assert_reaped(children)


def _alive(pid):
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:
                return False
            raise ctypes.WinError(error)
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A descendant that has exited can remain a zombie when the container's
    # PID 1 does not reap orphaned processes. It cannot execute any more work.
    # Direct children are separately checked by _assert_reaped above.
    if sys.platform.startswith("linux"):
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
            if state == "Z":
                return False
        except (FileNotFoundError, ProcessLookupError):
            return False
        except (IndexError, OSError):
            pass
    return True


@pytest.mark.asyncio
@pytest.mark.parametrize("parent_exits", [False, True])
async def test_cancel_or_success_terminates_descendants_and_preserves_unrelated_process(children, tmp_path, parent_exits):
    import subprocess

    unrelated = subprocess.Popen(_command("import time; time.sleep(60)"))
    marker = tmp_path / "descendant.pid"
    code = (
        "import subprocess,sys,time,pathlib; "
        "p=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(60)']); "
        f"pathlib.Path({str(marker)!r}).write_text(str(p.pid)); "
        + ("sys.exit(0)" if parent_exits else "time.sleep(60)")
    )
    try:
        task = asyncio.create_task(run_owned(
            _command(code), input="", deadline=time.monotonic() + 5, env=dict(os.environ),
        ))
        await _wait(lambda: marker.exists() and bool(marker.read_text()))
        descendant = int(marker.read_text())
        if parent_exits:
            assert (await task).returncode == 0
        else:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        await _wait(lambda: not _alive(descendant))
        assert unrelated.poll() is None
        _assert_reaped(children)
    finally:
        unrelated.kill()
        unrelated.wait(timeout=5)


@pytest.mark.asyncio
async def test_repeated_cancellation_joins_cleanup_without_blocking_loop(children, monkeypatch):
    real_close = OwnedProcess.aclose
    entered = asyncio.Event()

    async def slow_close(self):
        entered.set()
        await asyncio.sleep(0.1)
        await real_close(self)

    monkeypatch.setattr(OwnedProcess, "aclose", slow_close)
    task = asyncio.create_task(run_owned(
        _command("import time; time.sleep(60)"), input="",
        deadline=time.monotonic() + 5, env=dict(os.environ),
    ))
    await _wait(lambda: bool(children))
    task.cancel()
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    _assert_reaped(children)


@pytest.mark.asyncio
async def test_provider_cancellation_does_not_run_detached_complete_or_claim_zero_usage(monkeypatch, tmp_path, children):
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "auth.json").write_text("{}")
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setattr(codex.shutil, "which", lambda _: sys.executable)
    client = codex.CodexCLIClient()
    paths = []

    def command(*args):
        paths.append(args[args.index("--output-last-message") + 1])
        return _command("import sys,time; sys.stdin.buffer.read(); time.sleep(60)")

    monkeypatch.setattr(client, "_launch_cmd", command)
    task = owned_task(client.complete_async("system", [{"role": "user", "content": "hello"}]))
    await _wait(lambda: bool(children))
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task
    assert task_stop(task, caught.value).usage_status == "unknown"
    from pathlib import Path
    assert paths and not Path(paths[0]).parent.exists()
    _assert_reaped(children)
    assert not any(t.name == "owned-sync-adapter" for t in threading.enumerate())


@pytest.mark.asyncio
async def test_active_budget_stop_keeps_original_exception_and_reaps(children):
    from maverick.budget import Budget, BudgetExceeded

    budget = Budget(max_wall_seconds=.1)
    with pytest.raises(BudgetExceeded):
        await run_owned(
            _command("import time; time.sleep(60)"), input="", check=budget.check,
            deadline=time.monotonic() + 5, env=dict(os.environ),
        )
    _assert_reaped(children)


@pytest.mark.asyncio
async def test_last_message_limit_fails_without_a_completed_usage_receipt(monkeypatch, tmp_path, children):
    from maverick.budget import UsageAccountingError

    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "auth.json").write_text("{}")
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setattr(codex.shutil, "which", lambda _: sys.executable)
    monkeypatch.setattr(codex, "LAST_MESSAGE_BYTES", 128)
    client = codex.CodexCLIClient()

    def command(*args):
        path = args[args.index("--output-last-message") + 1]
        return _command(f"import pathlib,sys; sys.stdin.buffer.read(); pathlib.Path({path!r}).write_bytes(b'x'*129)")

    monkeypatch.setattr(client, "_launch_cmd", command)
    with pytest.raises(UsageAccountingError) as caught:
        await client.complete_async("s", [])
    assert caught.value.usage_status == "unknown"
    _assert_reaped(children)


@pytest.mark.asyncio
async def test_actual_agent_guard_cleans_up_cli_on_wall_stop(monkeypatch, tmp_path, children):
    from types import SimpleNamespace

    from maverick.agent import Agent
    from maverick.budget import Budget, BudgetExceeded

    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "auth.json").write_text("{}")
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setattr(codex.shutil, "which", lambda _: sys.executable)
    client = codex.CodexCLIClient()
    monkeypatch.setattr(client, "_launch_cmd", lambda *_: _command("import time; time.sleep(60)"))
    budget = Budget(max_wall_seconds=.15)
    agent = SimpleNamespace(ctx=SimpleNamespace(budget=budget, llm=client), _HALT_POLL_SECONDS=.01)
    agent._await_wall_clock_guarded = Agent._await_wall_clock_guarded.__get__(agent)
    with pytest.raises(BudgetExceeded):
        await Agent._complete_guarded(agent, system="s", messages=[], budget=budget)
    _assert_reaped(children)


@pytest.mark.asyncio
async def test_cleanup_reporting_failure_cannot_replace_original_stop(monkeypatch, children):
    from maverick.budget import BudgetExceeded

    original = BudgetExceeded("stop")
    real_close = OwnedProcess.aclose

    async def close_then_fail(self):
        await real_close(self)
        raise OSError("fixture cleanup reporting failure")

    def check():
        if children:
            raise original

    monkeypatch.setattr(OwnedProcess, "aclose", close_then_fail)
    with pytest.raises(BudgetExceeded) as caught:
        await run_owned(
            _command("import time; time.sleep(60)"), input="", check=check,
            deadline=time.monotonic() + 5, env=dict(os.environ),
        )
    assert caught.value is original and original.cleanup_incomplete
    _assert_reaped(children)


@pytest.mark.skipif(sys.platform != "linux" or shutil.which("setsid") is None,
                    reason="setsid escape is a Linux process-group behaviour")
def test_a_descendant_that_escapes_the_group_with_our_pipe_does_not_turn_success_into_timeout():
    import asyncio
    import threading
    import time

    from maverick.owned_process import run_owned
    start = time.monotonic()
    result = asyncio.run(run_owned(["sh", "-c", "setsid sleep 78 &"], input="",
                                   deadline=time.monotonic() + 6,
                                   env={"PATH": os.environ["PATH"]}))
    assert result.returncode == 0 and time.monotonic() - start < 3
    assert not [t for t in threading.enumerate() if t.name.startswith("owned-child")]
