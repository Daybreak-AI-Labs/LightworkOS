"""`maverick serve` stops on SIGTERM as on Ctrl-C, so its channels close
cleanly, then ends as SIGTERM always ended it."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Windows ends a process without a signal it can handle")

_CHILD = textwrap.dedent("""
    import asyncio, pathlib, sys, time

    import maverick.deployment as deployment
    import maverick.runner as runner
    import maverick.server as server_mod
    from maverick.cli import main

    marks = pathlib.Path(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else ""

    def goal():
        # A local goal: it runs on the goal threads for as long as it takes.
        (marks / "goal").write_text("")
        time.sleep(60)

    def work():
        # Channel work on a thread (a voice note being transcribed, a send
        # with no timeout): cancelling its await does not stop the thread.
        (marks / "thread").write_text("")
        time.sleep(60)

    class Server:
        max_depth = None

        async def run(self):
            try:
                if mode == "goal":
                    asyncio.get_running_loop().run_in_executor(runner._goal_executor, goal)
                (marks / "started").write_text("")
                if mode == "thread":
                    await asyncio.to_thread(work)
                await asyncio.Event().wait()
            finally:
                # Where Server.run closes every channel; closing takes a moment.
                (marks / "closing").write_text("")
                await asyncio.sleep(0.5)
                (marks / "closed").write_text("")

        async def stop(self):
            pass

    deployment.require_enterprise_or_die = lambda: None
    server_mod.build_from_config = lambda **_kwargs: Server()
    main(["serve"])
""")


def _wait_for(path, child, deadline):
    while not path.exists():
        assert child.poll() is None, child.stdout.read().decode(errors="replace")
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        time.sleep(0.02)


@pytest.fixture
def serve(tmp_path):
    children = []

    def start(*, ignore_sigint=False, mode="", no_output=False):
        marks = tmp_path / "marks"
        marks.mkdir()
        script = tmp_path / "child.py"
        script.write_text(_CHILD)
        env = {**os.environ, "HOME": str(tmp_path), "MAVERICK_HOME": str(tmp_path / "home")}
        disposition = signal.SIG_IGN if ignore_sigint else signal.SIG_DFL

        def prepare():
            signal.signal(signal.SIGINT, disposition)
            if no_output:  # started with its output closed: Python has no sys.stdout or sys.stderr
                os.close(1)
                os.close(2)
        child = subprocess.Popen(
            [sys.executable, str(script), str(marks), *([mode] if mode else [])], env=env, cwd=tmp_path,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            # Ctrl-C is set either way: a script's background job, so a test
            # run started as one too, starts with it ignored.
            preexec_fn=prepare)
        children.append(child)
        _wait_for(marks / (mode or "started"), child, time.monotonic() + 60)
        return child, marks

    yield start
    for child in children:  # a failed wait never leaves a server running
        if child.poll() is None:
            child.kill()
            child.wait()
        if not child.stdout.closed:
            child.stdout.close()


def _finish(child):
    try:
        output, _ = child.communicate(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
            output, _ = child.communicate()
    return output.decode(errors="replace")


def test_sigterm_closes_the_channels_before_the_process_ends(serve):
    child, marks = serve()
    child.send_signal(signal.SIGTERM)
    output = _finish(child)
    assert child.returncode == -signal.SIGTERM, output
    assert (marks / "closed").exists()


def test_a_repeated_sigterm_does_not_cut_the_close_short(serve):
    # The dashboard's shutdown and a one-file build's launcher send SIGTERM
    # again while the channels are still closing.
    child, marks = serve()
    child.send_signal(signal.SIGTERM)
    _wait_for(marks / "closing", child, time.monotonic() + 30)
    child.send_signal(signal.SIGTERM)
    output = _finish(child)
    assert child.returncode == -signal.SIGTERM, output
    assert (marks / "closed").exists()


def test_sigterm_still_ends_a_server_started_with_ctrl_c_ignored(serve):
    # asyncio does not stop on an ignored Ctrl-C, so SIGTERM keeps its
    # default and ends the process, as it did before.
    child, _marks = serve(ignore_sigint=True)
    child.send_signal(signal.SIGTERM)
    output = _finish(child)
    assert child.returncode == -signal.SIGTERM, output


def test_sigterm_ends_the_server_while_a_local_goal_runs(serve):
    # The channels close, then the process ends as SIGTERM always ended it,
    # instead of waiting at exit for the goal to finish.
    child, marks = serve(mode="goal")
    child.send_signal(signal.SIGTERM)
    try:
        output, _ = child.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail("serve kept running after SIGTERM until its local goal finished")
    assert child.returncode == -signal.SIGTERM, output.decode(errors="replace")
    assert (marks / "closed").exists()


def test_sigterm_ends_the_server_while_channel_work_runs_on_a_thread(serve):
    # asyncio.run waits at its close for every thread it lent work to; once
    # the channels are closed, SIGTERM ends the process without that wait.
    child, marks = serve(mode="thread")
    child.send_signal(signal.SIGTERM)
    try:
        output, _ = child.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail("serve kept running after SIGTERM until its thread work finished")
    assert child.returncode == -signal.SIGTERM, output.decode(errors="replace")
    assert (marks / "closed").exists()


@pytest.mark.parametrize("mode", ["", "goal", "thread"])
def test_sigterm_ends_the_server_once_nothing_reads_its_output(serve, mode):
    # The dashboard that started it is gone, so its output has no reader and
    # writing fails: the channels still close and SIGTERM still ends it.
    child, marks = serve(mode=mode)
    child.stdout.close()
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail("serve kept running after SIGTERM once nothing read its output")
    assert child.returncode == -signal.SIGTERM
    assert (marks / "closed").exists()


def test_sigterm_ends_a_server_started_with_its_output_closed(serve):
    child, marks = serve(mode="goal", no_output=True)
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail("serve kept running after SIGTERM with its output closed")
    assert child.returncode == -signal.SIGTERM
    assert (marks / "closed").exists()
