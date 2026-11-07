"""`maverick serve` stops on SIGTERM as on Ctrl-C, so its channels close cleanly."""
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
    import asyncio, pathlib, sys

    import maverick.deployment as deployment
    import maverick.server as server_mod
    from maverick.cli import main

    marks = pathlib.Path(sys.argv[1])

    class Server:
        max_depth = None

        async def run(self):
            try:
                (marks / "started").write_text("")
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


def _serve(tmp_path, *, ignore_sigint=False):
    marks = tmp_path / "marks"
    marks.mkdir()
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    env = {**os.environ, "HOME": str(tmp_path), "MAVERICK_HOME": str(tmp_path / "home")}
    child = subprocess.Popen(
        [sys.executable, str(script), str(marks)], env=env, cwd=tmp_path,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        # A script's background job starts with Ctrl-C ignored.
        preexec_fn=(lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)) if ignore_sigint else None)
    _wait_for(marks / "started", child, time.monotonic() + 60)
    return child, marks


def _finish(child):
    try:
        output, _ = child.communicate(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
            output, _ = child.communicate()
    return output.decode(errors="replace")


def test_sigterm_closes_the_channels_and_exits_cleanly(tmp_path):
    child, marks = _serve(tmp_path)
    child.send_signal(signal.SIGTERM)
    output = _finish(child)
    assert child.returncode == 0, output
    assert (marks / "closed").exists()


def test_a_repeated_sigterm_does_not_cut_the_close_short(tmp_path):
    # The dashboard's shutdown and a one-file build's launcher send SIGTERM
    # again while the channels are still closing.
    child, marks = _serve(tmp_path)
    child.send_signal(signal.SIGTERM)
    _wait_for(marks / "closing", child, time.monotonic() + 30)
    child.send_signal(signal.SIGTERM)
    output = _finish(child)
    assert child.returncode == 0, output
    assert (marks / "closed").exists()


def test_sigterm_still_ends_a_server_started_with_ctrl_c_ignored(tmp_path):
    # asyncio does not stop on an ignored Ctrl-C, so SIGTERM keeps its
    # default and ends the process, as it did before.
    child, _marks = _serve(tmp_path, ignore_sigint=True)
    child.send_signal(signal.SIGTERM)
    output = _finish(child)
    assert child.returncode == -signal.SIGTERM, output
