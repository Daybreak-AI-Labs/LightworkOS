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
                (marks / "closed").write_text("")  # where Server.run closes every channel

        async def stop(self):
            pass

    deployment.require_enterprise_or_die = lambda: None
    server_mod.build_from_config = lambda **_kwargs: Server()
    main(["serve"])
""")


def test_sigterm_closes_the_channels_and_exits_cleanly(tmp_path):
    marks = tmp_path / "marks"
    marks.mkdir()
    script = tmp_path / "child.py"
    script.write_text(_CHILD)
    env = {**os.environ, "HOME": str(tmp_path), "MAVERICK_HOME": str(tmp_path / "home")}
    child = subprocess.Popen([sys.executable, str(script), str(marks)], env=env, cwd=tmp_path,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 60
        while not (marks / "started").exists():
            assert child.poll() is None, child.stdout.read().decode(errors="replace")
            assert time.monotonic() < deadline, "serve did not start"
            time.sleep(0.05)
        child.send_signal(signal.SIGTERM)
        output, _ = child.communicate(timeout=30)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
    assert child.returncode == 0, output.decode(errors="replace")
    assert (marks / "closed").exists()
