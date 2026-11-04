"""The per-thread federation state connections can be released explicitly."""
from __future__ import annotations

import os
import select
import signal
import sqlite3
import subprocess
import sys
import threading

import pytest
from maverick import federation


def _closed(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError as exc:
        return "closed database" in str(exc)
    return False


@pytest.fixture
def state(tmp_path):
    federation.close_cached_connections()
    yield federation._FederationState(tmp_path / "inbound_state.sqlite3")
    federation.close_cached_connections()


def test_registry_closes_connections_cached_by_two_threads(state):
    cached: dict[str, sqlite3.Connection] = {}
    ready = threading.Barrier(3)
    release = threading.Event()

    def cache(name: str) -> None:
        cached[name] = state._connect()
        ready.wait(timeout=10)
        release.wait(timeout=10)

    threads = [threading.Thread(target=cache, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    try:
        ready.wait(timeout=10)
        assert cached["a"] is not cached["b"]
        federation.close_cached_connections()
        assert _closed(cached["a"])
        assert _closed(cached["b"])
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=10)


def test_a_later_call_after_close_opens_a_fresh_working_connection(state):
    first = state._connect()
    federation.close_cached_connections()
    assert _closed(first)
    federation.close_cached_connections()  # nothing left to close is not an error
    second = state._connect()
    assert second is not first
    assert not _closed(second)
    # claim_replay returns True for a signature that was already claimed.
    assert state.claim_replay("scope", "sig", expires_at=2000.0, now=1000.0) is False
    assert state.claim_replay("scope", "sig", expires_at=2000.0, now=1001.0) is True


def test_other_threads_reopen_after_close_instead_of_reusing_their_cache(state):
    first: dict[str, sqlite3.Connection] = {}
    second: dict[str, sqlite3.Connection] = {}
    opened = threading.Event()
    closed = threading.Event()

    def worker() -> None:
        first["connection"] = state._connect()
        opened.set()
        closed.wait(timeout=10)
        second["connection"] = state._connect()

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert opened.wait(timeout=10)
        federation.close_cached_connections()
    finally:
        closed.set()
        thread.join(timeout=10)
    assert _closed(first["connection"])
    assert second["connection"] is not first["connection"]
    assert not _closed(second["connection"])


def test_connections_of_threads_that_have_ended_are_released_by_the_next_open(state):
    ended: dict[str, sqlite3.Connection] = {}

    def worker() -> None:
        ended["connection"] = state._connect()

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)
    assert not _closed(ended["connection"])
    state._connect()  # this thread's first open sweeps the connection of the ended thread
    assert _closed(ended["connection"])


def test_switching_paths_does_not_keep_the_retired_connections_registered(tmp_path):
    first = federation._FederationState(tmp_path / "a.sqlite3")
    second = federation._FederationState(tmp_path / "b.sqlite3")
    retired: list[sqlite3.Connection] = []
    for _ in range(20):
        retired.append(first._connect())
        second._connect()
    # Other threads of this process may hold connections too, so count only this thread's.
    mine = [
        connection
        for owner, connection in federation._FED_STATE_REGISTRY.values()
        if owner is threading.current_thread()
    ]
    assert mine == [second._connect()]
    assert all(_closed(connection) for connection in retired[:-1])
    assert not _closed(mine[0])


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is POSIX only")
@pytest.mark.filterwarnings("ignore:This process .* fork\\(\\) may lead to deadlocks:DeprecationWarning")
def test_a_forked_child_starts_with_an_empty_registry_and_a_free_lock(tmp_path):
    # The child runs only this module's code and exits with os._exit, so the fork is safe here.
    state = federation._FederationState(tmp_path / "fork.sqlite3")
    with federation._STATE_FILE_GATE.shared():
        parent = state._connect()
    read_fd, write_fd = os.pipe()
    # The lock is held at fork time, as it would be if another thread were inside the registry.
    # A child that inherited it as held would block on its first open.
    federation._FED_STATE_REGISTRY_LOCK.acquire()
    pid = os.fork()
    if pid == 0:
        report = b"error"
        try:
            os.close(read_fd)
            inherited = len(federation._FED_STATE_REGISTRY)
            with federation._STATE_FILE_GATE.shared():
                child = federation._FederationState(tmp_path / "fork.sqlite3")._connect()
            report = f"{inherited} {child is parent}".encode()
        except BaseException as exc:  # reported to the parent, which fails the test
            report = repr(exc).encode()
        finally:
            os.write(write_fd, report)
            os._exit(0)
    federation._FED_STATE_REGISTRY_LOCK.release()
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 20)
        if not ready:
            os.kill(pid, signal.SIGKILL)
            pytest.fail("the forked child blocked on the registry lock it inherited")
        report = os.read(read_fd, 4096)
    finally:
        os.close(read_fd)
        os.waitpid(pid, 0)
    assert report == b"0 False"
    # The child's copy of the registry was dropped without closing the parent's connection.
    assert not _closed(parent)


def test_closing_while_state_calls_run_does_not_crash_the_process(tmp_path):
    # Connections are shared across threads for the close, so a close that did not wait for
    # running calls crashed the interpreter. A crash fails this test by its exit code.
    script = f"""
import threading
import time
from pathlib import Path

from maverick import federation

state = federation._FederationState(Path({str(tmp_path / "stress.sqlite3")!r}))
stop = threading.Event()
failures = []


def worker(name):
    while not stop.is_set():
        try:
            state.rate_ok(name, now=time.time(), limit=10**9)
        except Exception as exc:
            failures.append(repr(exc))
            return


threads = [threading.Thread(target=worker, args=(f"peer-{{index}}",)) for index in range(4)]
for thread in threads:
    thread.start()
closes = 0
deadline = time.monotonic() + 2.0
while time.monotonic() < deadline:
    federation.close_cached_connections()
    closes += 1
stop.set()
for thread in threads:
    thread.join(timeout=60)
print("closes", closes, "failures", len(failures), failures[:3])
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=300
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert " failures 0 " in result.stdout, result.stdout


def test_a_connection_opened_while_a_close_waits_is_closed_by_that_close(tmp_path, monkeypatch):
    state = federation._FederationState(tmp_path / "inbound_state.sqlite3")
    real_connect = sqlite3.connect
    opening = threading.Event()
    proceed = threading.Event()
    opened: list[sqlite3.Connection] = []

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        if threading.current_thread().name == "opener":
            opened.append(connection)
            opening.set()
            proceed.wait(timeout=10)
        return connection

    monkeypatch.setattr(federation.sqlite3, "connect", connect)
    opener = threading.Thread(
        target=state.claim_replay,
        args=("scope", "sig"),
        kwargs={"expires_at": 2000.0, "now": 1000.0},
        name="opener",
    )
    opener.start()
    try:
        assert opening.wait(timeout=10)
        closer = threading.Thread(target=federation.close_cached_connections)
        closer.start()
        closer.join(timeout=0.3)
        # The close waits for the call that is opening its connection, so that connection
        # is registered before the close runs and is closed by it.
        assert closer.is_alive()
    finally:
        proceed.set()
        opener.join(timeout=10)
    closer.join(timeout=10)
    assert not closer.is_alive()
    assert len(opened) == 1
    assert _closed(opened[0])
    assert state.claim_replay("scope", "other", expires_at=2000.0, now=1000.0) is False


def test_calls_wait_while_the_state_file_is_held_closed(tmp_path):
    state = federation._FederationState(tmp_path / "inbound_state.sqlite3")
    assert state.claim_replay("scope", "sig", expires_at=2000.0, now=1000.0) is False
    results: dict[str, object] = {}
    with federation.hold_state_file_closed():
        assert len(federation._FED_STATE_REGISTRY) == 0
        caller = threading.Thread(
            target=lambda: results.update(
                claimed=state.claim_replay("scope", "sig", expires_at=2000.0, now=1000.0)
            )
        )
        caller.start()
        caller.join(timeout=0.3)
        assert caller.is_alive(), "a call must wait while the state file is held closed"
        assert len(federation._FED_STATE_REGISTRY) == 0, "no connection may open during the hold"
    caller.join(timeout=10)
    assert not caller.is_alive()
    # The signature claimed before the hold is still there: the hold only closed the file.
    assert results["claimed"] is True


def test_closing_from_inside_a_state_call_is_refused_rather_than_waiting_on_itself(tmp_path):
    state = federation._FederationState(tmp_path / "inbound_state.sqlite3")
    with federation._STATE_FILE_GATE.shared():
        state._connect()
        with pytest.raises(RuntimeError, match="inside a state call"):
            federation.close_cached_connections()
    assert federation.close_cached_connections() is None
