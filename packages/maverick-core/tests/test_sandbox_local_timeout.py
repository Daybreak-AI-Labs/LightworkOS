"""LocalBackend timeout must bound the WHOLE process tree.

subprocess.run's timeout SIGKILLs only the direct /bin/sh child; grandchildren
(a backgrounded ``cmd &``, or even foreground children of a compound list --
dash forks for those too) reparented to init and kept running after exec()
returned 124, so the stated wall-clock bound never bounded host CPU/RAM. The
backend now starts the child in its own session (process group) and kills the
group on timeout, mirroring the reaping every container backend already does.
"""
from __future__ import annotations

import os
import time
from io import StringIO

import pytest
from maverick.sandbox.local import LocalBackend

_POSIX_ONLY = pytest.mark.skipif(
    not hasattr(os, "killpg"), reason="POSIX process groups required",
)


def _gone(pid: int) -> bool:
    """True when ``pid`` no longer runs (vanished, or a killed zombie awaiting
    init's reap -- state ``Z`` on Linux)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        # init can reap a zombie after kill(pid, 0) but before the stat read.
        # Recheck existence instead of reporting that vanished PID as alive.
        # Missing/unreadable procfs alone still cannot prove termination.
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False


@pytest.mark.parametrize("state, expected", [("R", False), ("S", False), ("D", False), ("Z", True)])
def test_gone_distinguishes_live_processes_from_zombies(monkeypatch, state, expected):
    monkeypatch.setattr(os, "kill", lambda pid, signal: None)
    monkeypatch.setitem(globals(), "open", lambda path: StringIO(f"123 (child process) {state} 1"))

    assert _gone(123) is expected


@pytest.mark.parametrize("error, expected", [(ProcessLookupError, True), (PermissionError, False)])
def test_gone_checks_process_existence_without_requiring_procfs(monkeypatch, error, expected):
    def probe(pid, signal):
        raise error

    monkeypatch.setattr(os, "kill", probe)

    assert _gone(123) is expected


@pytest.mark.parametrize("after_read, expected", [(ProcessLookupError, True), (None, False), (PermissionError, False)])
@pytest.mark.parametrize("stat_error", [FileNotFoundError, ProcessLookupError])
def test_gone_handles_process_reaping_between_probe_and_stat(monkeypatch, after_read, expected, stat_error):
    probes = iter([None, after_read])

    def probe(pid, signal):
        error = next(probes)
        if error is not None:
            raise error

    def missing_stat(path):
        raise stat_error(path)

    monkeypatch.setattr(os, "kill", probe)
    monkeypatch.setitem(globals(), "open", missing_stat)

    # A missing stat file proves nothing by itself: procfs may be unavailable,
    # or access may have changed. Only a vanished PID establishes termination.
    assert _gone(123) is expected


def test_gone_does_not_accept_an_unreadable_process_stat(monkeypatch):
    def unreadable_stat(path):
        raise PermissionError(path)

    monkeypatch.setattr(os, "kill", lambda pid, signal: None)
    monkeypatch.setitem(globals(), "open", unreadable_stat)

    assert not _gone(123)


@_POSIX_ONLY
def test_timeout_kills_grandchildren_and_keeps_partial_output(tmp_path):
    b = LocalBackend(workdir=tmp_path)
    pidfile = tmp_path / "grandchild.pid"
    res = b.exec(
        f"sleep 300 & echo $! > {pidfile}; echo started; sleep 300",
        timeout=1.0,
    )
    assert res.exit_code == 124
    assert "TIMEOUT" in res.stderr
    # Output produced before the timeout still comes back to the agent.
    assert "started" in res.stdout

    # The backgrounded grandchild must die with the group, not outlive the
    # timeout re-parented to init (give init a moment to reap).
    pid = int(pidfile.read_text().strip())
    deadline = time.time() + 5.0
    while not _gone(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert _gone(pid), "backgrounded grandchild survived the timeout"


@_POSIX_ONLY
def test_exec_success_and_failure_paths_unchanged(tmp_path):
    b = LocalBackend(workdir=tmp_path)
    ok = b.exec("echo hi")
    assert ok.ok and ok.stdout.strip() == "hi"
    bad = b.exec("echo oops >&2; exit 3")
    assert bad.exit_code == 3
    assert bad.stderr.strip() == "oops"


# ---- sandbox.exec accepts a per-call timeout kwarg ----

class TestSandboxExecTimeout:
    def test_local_backend_accepts_timeout_kwarg(self, tmp_path):
        from maverick.sandbox import LocalBackend
        sb = LocalBackend(workdir=tmp_path, timeout=1.0)
        # A quick command should succeed even when we hand it a long timeout.
        r = sb.exec("echo hello", timeout=10.0)
        assert r.exit_code == 0
        assert "hello" in r.stdout

    def test_local_backend_timeout_kwarg_overrides_self_timeout(self, tmp_path):
        from maverick.sandbox import LocalBackend
        # self.timeout would be 0.1s, but the call passes 5s, so a
        # 0.5s sleep completes successfully (no TIMEOUT).
        # Use python -c for cross-platform sleep (Unix `sleep`
        # is not available on Windows).
        sb = LocalBackend(workdir=tmp_path, timeout=0.1)
        import sys
        py = sys.executable.replace("\\", "/")  # quote-friendly on Windows
        r = sb.exec(
            f'"{py}" -c "import time; time.sleep(0.5); print(\'done\')"',
            timeout=5.0,
        )
        assert r.exit_code == 0
        assert "done" in r.stdout
