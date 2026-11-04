"""Local shell commands must not leave successful background children behind."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest
from maverick.sandbox.local import LocalBackend


def _write_windows_background_tree(
    tmp_path: Path,
    *,
    stem: str,
) -> tuple[Path, Path, Path, Path]:
    """Create a child that proves it started before waiting to escape."""
    ready = tmp_path / f"{stem}-child.pid"
    marker = tmp_path / f"{stem}-child-survived"
    child = tmp_path / f"{stem}-child.py"
    child.write_text(
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8')\n"
        "time.sleep(30)\n"
        "Path(sys.argv[2]).write_text('escaped', encoding='utf-8')\n",
        encoding="utf-8",
    )
    parent = tmp_path / f"{stem}-parent.py"
    parent.write_text(
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen(\n"
        "    [sys.executable, sys.argv[1], sys.argv[2], sys.argv[3]],\n"
        "    stdout=subprocess.DEVNULL,\n"
        "    stderr=subprocess.DEVNULL,\n"
        ")\n"
        "ready = Path(sys.argv[2])\n"
        "deadline = time.monotonic() + 10\n"
        "while not ready.exists():\n"
        "    if child.poll() is not None:\n"
        "        raise RuntimeError(f'child exited early: {child.returncode}')\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise TimeoutError('child did not publish its pid')\n"
        "    time.sleep(0.01)\n"
        "if sys.argv[4] == 'hold':\n"
        "    time.sleep(30)\n",
        encoding="utf-8",
    )
    return child, parent, ready, marker


def _windows_tree_command(
    parent: Path,
    child: Path,
    ready: Path,
    marker: Path,
    *,
    mode: str,
) -> str:
    return subprocess.list2cmdline(
        [sys.executable, str(parent), str(child), str(ready), str(marker), mode]
    )


def _assert_windows_process_exits(pid: int, timeout_seconds: float = 5.0) -> None:
    """Wait on the process object instead of inferring death from a marker."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait_for_single_object.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    handle = open_process(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: the PID is already gone
            return
        raise ctypes.WinError(error)
    try:
        result = wait_for_single_object(handle, int(timeout_seconds * 1000))
        if result == 0:  # WAIT_OBJECT_0
            return
        if result == 0xFFFFFFFF:  # WAIT_FAILED
            raise ctypes.WinError(ctypes.get_last_error())
        pytest.fail(f"background process {pid} survived {timeout_seconds}s")
    finally:
        close_handle(handle)


def _assign_process_to_new_windows_job(proc: subprocess.Popen) -> int:
    """Put a blocked probe in an outer Job to exercise supported nesting."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    create_job.restype = wintypes.HANDLE
    assign_job = kernel32.AssignProcessToJobObject
    assign_job.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_job.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    job = create_job(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    if not assign_job(job, wintypes.HANDLE(int(proc._handle))):  # type: ignore[attr-defined]
        error = ctypes.get_last_error()
        close_handle(job)
        raise ctypes.WinError(error)
    return int(job)


def _terminate_and_close_windows_job(handle: int) -> None:
    """Ensure a failed nesting test cannot leak a process outside the inner Job."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    terminate_job = kernel32.TerminateJobObject
    terminate_job.argtypes = (wintypes.HANDLE, wintypes.UINT)
    terminate_job.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    job = wintypes.HANDLE(handle)
    termination_error = None
    if not terminate_job(job, 1):
        termination_error = ctypes.WinError(ctypes.get_last_error())
    if not close_handle(job):
        raise ctypes.WinError(ctypes.get_last_error())
    if termination_error is not None:
        raise termination_error


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group invariant")
def test_successful_command_reaps_redirected_background_child(tmp_path: Path):
    marker = tmp_path / "background-child-survived"
    payload = (
        "import time; "
        "from pathlib import Path; "
        "time.sleep(0.75); "
        f"Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    command = (
        f"nohup {shlex.quote(sys.executable)} -c {shlex.quote(payload)} "
        ">/dev/null 2>&1 &"
    )

    result = LocalBackend(workdir=tmp_path, timeout=5).exec(command)
    assert result.ok
    time.sleep(1)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object invariant")
def test_windows_success_reaps_redirected_background_child(tmp_path: Path):
    child, parent, ready, marker = _write_windows_background_tree(
        tmp_path,
        stem="success",
    )

    result = LocalBackend(workdir=tmp_path, timeout=5).exec(
        _windows_tree_command(
            parent,
            child,
            ready,
            marker,
            mode="exit",
        )
    )
    assert result.ok
    assert ready.exists(), "child never published its pid"
    _assert_windows_process_exits(int(ready.read_text(encoding="utf-8")))
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object invariant")
def test_windows_timeout_reaps_grandchild_process(tmp_path: Path):
    child, parent, ready, marker = _write_windows_background_tree(
        tmp_path,
        stem="timeout",
    )

    result = LocalBackend(workdir=tmp_path, timeout=2).exec(
        _windows_tree_command(
            parent,
            child,
            ready,
            marker,
            mode="hold",
        )
    )
    assert result.exit_code == 124
    assert ready.exists(), "grandchild never published its pid before timeout"
    _assert_windows_process_exits(int(ready.read_text(encoding="utf-8")))
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object invariant")
def test_windows_job_containment_nests_inside_an_outer_job(tmp_path: Path):
    child, parent, ready, marker = _write_windows_background_tree(
        tmp_path,
        stem="nested",
    )
    go = tmp_path / "nested-probe.go"
    probe = tmp_path / "nested-probe.py"
    probe.write_text(
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "from maverick.sandbox.local import LocalBackend\n"
        "go = Path(sys.argv[1])\n"
        "deadline = time.monotonic() + 10\n"
        "while not go.exists():\n"
        "    if time.monotonic() >= deadline:\n"
        "        raise TimeoutError('outer Job did not release probe')\n"
        "    time.sleep(0.01)\n"
        "command = subprocess.list2cmdline([sys.executable, *sys.argv[2:]])\n"
        "result = LocalBackend(workdir=go.parent, timeout=5).exec(command)\n"
        "print(result.exit_code)\n"
        "raise SystemExit(0 if result.ok else 1)\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [
            sys.executable,
            str(probe),
            str(go),
            str(parent),
            str(child),
            str(ready),
            str(marker),
            "exit",
        ],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    outer_job: int | None = None
    try:
        outer_job = _assign_process_to_new_windows_job(process)
        go.write_text("assigned\n", encoding="utf-8")
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr
        assert stdout.strip() == "0"
        assert ready.exists(), "nested child never published its pid"
        _assert_windows_process_exits(int(ready.read_text(encoding="utf-8")))
        assert not marker.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if outer_job is not None:
            _terminate_and_close_windows_job(outer_job)
