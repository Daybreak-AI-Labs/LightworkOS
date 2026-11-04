"""Owned pipe transport; no native shell, provider, or customer profile launch."""
import io
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick_dashboard._server import DESKTOP_DRAIN, DashboardServer, _read_desktop_control


@pytest.mark.parametrize("command,accepted", [(DESKTOP_DRAIN, True), (b"", True), (b"bad\n", False)])
def test_control_only_accepts_fixed_command_or_owner_exit(command, accepted):
    ready = threading.Event()
    ready.set()
    calls = []
    loop = SimpleNamespace(is_closed=lambda: False, call_soon_threadsafe=lambda callback: callback())
    _read_desktop_control(io.BytesIO(command), ready, loop, lambda: calls.append(True))
    assert bool(calls) is accepted


def test_control_flag_consumed_without_authorizing_unmarked_servers(monkeypatch):
    monkeypatch.delenv("MAVERICK_DESKTOP_CONTROL", raising=False)
    assert not DashboardServer(None).desktop_control
    monkeypatch.setenv("MAVERICK_DESKTOP_CONTROL", "stdin-v1")
    assert DashboardServer(None).desktop_control
    assert "MAVERICK_DESKTOP_CONTROL" not in os.environ


@pytest.mark.parametrize("command", [DESKTOP_DRAIN, b"", None])
def test_real_child_server_drains_on_owned_pipe_and_persists_final_state(tmp_path, command):
    script = tmp_path / "synthetic_dashboard.py"
    marker = tmp_path / "final.txt"
    ready = tmp_path / "ready.txt"
    script.write_text('''
import asyncio, os, socket, sys, threading
from contextlib import asynccontextmanager
from pathlib import Path
sys.path[:0] = sys.argv[3:]  # Use this checkout even with -I and another installed copy.
from fastapi import FastAPI
from maverick_dashboard._lifecycle import ShutdownSupervisor
from maverick_dashboard._server import DashboardServer
marker, ready = map(Path, sys.argv[1:3])
@asynccontextmanager
async def lifespan(app):
    stop = threading.Event()
    def work():
        stop.wait(15)
        marker.write_text("final state saved", encoding="utf-8")
    worker = threading.Thread(target=work)
    worker.start()
    def close(*, timeout, wait=True):
        stop.set()
        if wait: worker.join(timeout)
    supervisor = ShutdownSupervisor(2)
    supervisor.register("fixture", close, worker.is_alive)
    app.state.lifecycle_supervisor = supervisor
    ready.write_text("ready", encoding="utf-8")
    if os.environ.get("FIXTURE_NORMAL_EXIT") == "1":
        async def normal_exit():
            await asyncio.sleep(.2)
            server.should_exit = True
        asyncio.create_task(normal_exit())
    try: yield
    finally: await supervisor.stop()
app = FastAPI(lifespan=lifespan)
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
server = DashboardServer(app, log_config=None)
server.run(sockets=[listener])
assert app.state.lifecycle_supervisor.phase == "stopped"
''', encoding="utf-8")
    environment = {**os.environ, "MAVERICK_DESKTOP_CONTROL": "stdin-v1"}
    if command is None:
        environment["FIXTURE_NORMAL_EXIT"] = "1"
    package_root = Path(__file__).resolve().parents[1]
    core_root = package_root.parent / "maverick-core"
    child = subprocess.Popen([sys.executable, "-I", str(script), str(marker), str(ready),
                              str(package_root), str(core_root)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        assert ready.exists(), "synthetic child did not start"
        if command is None:
            # Keep the private pipe open while another normal exit occurs.
            # A daemon reader must not retain Python's buffered stdin lock.
            child.wait(timeout=8)
        stdout, stderr = child.communicate(command, timeout=8)
        assert child.returncode == 0, (stdout, stderr)
        assert marker.read_text(encoding="utf-8") == "final state saved"
    except subprocess.TimeoutExpired as exc:
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
        raise AssertionError(("synthetic child did not drain", stdout, stderr)) from exc
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)


def test_helpers_started_by_the_server_never_inherit_the_owned_pipe(tmp_path):
    script = tmp_path / "synthetic_dashboard.py"
    observed = tmp_path / "helper.txt"
    ready = tmp_path / "ready.txt"
    script.write_text('''
import socket, subprocess, sys
from contextlib import asynccontextmanager
from pathlib import Path
sys.path[:0] = sys.argv[3:]
from fastapi import FastAPI
from maverick_dashboard._server import DashboardServer
observed, ready = map(Path, sys.argv[1:3])
@asynccontextmanager
async def lifespan(app):
    # A helper started with the default stdin, as PowerShell and tool workers are.
    # Windows reports every character device (the null device included) as a
    # terminal, so standard input must not be one.
    probe = "import os, stat, sys; sys.stdout.write(repr((sys.stdin.buffer.read(64), stat.S_ISCHR(os.fstat(0).st_mode), os.isatty(0))))"
    try:
        helper = subprocess.run([sys.executable, "-I", "-c", probe], capture_output=True, text=True, timeout=3)
        observed.write_text(helper.stdout, encoding="utf-8")
    except subprocess.TimeoutExpired:
        observed.write_text("blocked on the owned pipe", encoding="utf-8")
    ready.write_text("ready", encoding="utf-8")
    yield
app = FastAPI(lifespan=lifespan)
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
DashboardServer(app, log_config=None).run(sockets=[listener])
''', encoding="utf-8")
    environment = {**os.environ, "MAVERICK_DESKTOP_CONTROL": "stdin-v1"}
    package_root = Path(__file__).resolve().parents[1]
    core_root = package_root.parent / "maverick-core"
    child = subprocess.Popen([sys.executable, "-I", str(script), str(observed), str(ready),
                              str(package_root), str(core_root)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        deadline = time.monotonic() + 20
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        assert ready.exists(), "synthetic child did not start"
        # The helper saw end of input, not the desktop's open control pipe, on
        # a stream that is no terminal, and the drain still reached the server.
        assert observed.read_text(encoding="utf-8") == "(b'', False, False)"
        stdout, stderr = child.communicate(DESKTOP_DRAIN, timeout=8)
        assert child.returncode == 0, (stdout, stderr)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
