"""Parent-death boundary for the tagged Java stdio MCP launcher.

The Java MCP SDK keeps its transport process private.  The Java example starts
``maverick mcp`` beneath a tagged launcher and supplies the launcher's exact PID
and start time through this private environment contract.  If the launcher
dies before it can finish its ownership registry, this process must not become
an orphan.

No environment variable means no behavior change for ordinary CLI users.
Partial or malformed metadata fails closed before the MCP server starts.
"""

from __future__ import annotations

import ctypes
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path

_PREFIX = "MAVERICK_MCP_PARENT_"
_PID = _PREFIX + "PID"
_STARTED = _PREFIX + "STARTED_EPOCH_MILLIS"
_TOKEN = _PREFIX + "TOKEN"
_READY = _PREFIX + "READY_FILE"
_RELEASE = _PREFIX + "RELEASE_FILE"
_KEYS = (_PID, _STARTED, _TOKEN, _READY, _RELEASE)
_TOKEN_RE = re.compile(r"maverick-mcp-owner-[A-Za-z0-9-]{1,180}\Z")
_PARENT_EXIT_CODE = 70


class ParentGuardError(RuntimeError):
    """The private launcher contract is present but cannot be trusted."""


def arm_from_environment() -> bool:
    """Arm the tagged launcher's parent-death contract when requested."""

    present = {key: os.environ[key] for key in _KEYS if key in os.environ}
    if not present:
        return False
    missing = [key for key in (_PID, _STARTED, _TOKEN) if not present.get(key)]
    if missing:
        raise ParentGuardError("incomplete tagged-launch metadata: missing " + ", ".join(missing))

    token = present[_TOKEN]
    if not _TOKEN_RE.fullmatch(token):
        raise ParentGuardError("invalid tagged-launch ownership token")
    parent_pid = _positive_decimal(present[_PID], _PID)
    parent_started_ms = _positive_decimal(present[_STARTED], _STARTED)
    if parent_pid == os.getpid():
        raise ParentGuardError("tagged launcher PID identifies the MCP process itself")

    if os.name == "nt":
        _arm_windows(parent_pid, parent_started_ms)
    elif sys.platform.startswith("linux"):
        _arm_linux(parent_pid, parent_started_ms)
    else:
        _arm_posix(parent_pid)

    _acceptance_pause(present, token)
    return True


def _positive_decimal(raw: str, name: str) -> int:
    if not raw.isascii() or not raw.isdecimal():
        raise ParentGuardError(f"{name} must be a positive decimal integer")
    value = int(raw)
    if value <= 0:
        raise ParentGuardError(f"{name} must be positive")
    return value


def _arm_linux(parent_pid: int, parent_started_ms: int) -> None:
    if os.getppid() != parent_pid:
        raise ParentGuardError("tagged launcher exited before the MCP guard armed")
    _verify_linux_start(parent_pid, parent_started_ms)

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        error = ctypes.get_errno()
        raise ParentGuardError(f"prctl(PR_SET_PDEATHSIG) failed with errno {error}")
    # The parent can die between the first check and prctl.  Rechecking closes
    # that documented race: the kernel signal handles every point after prctl.
    if os.getppid() != parent_pid:
        os._exit(_PARENT_EXIT_CODE)


def _verify_linux_start(parent_pid: int, expected_ms: int) -> None:
    try:
        stat = Path(f"/proc/{parent_pid}/stat").read_text(encoding="ascii")
        after_name = stat[stat.rfind(")") + 2 :].split()
        start_ticks = int(after_name[19])
        boot_line = next(
            line
            for line in Path("/proc/stat").read_text(encoding="ascii").splitlines()
            if line.startswith("btime ")
        )
        boot_seconds = int(boot_line.split()[1])
        ticks_per_second = int(os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, StopIteration, IndexError) as exc:
        raise ParentGuardError("could not verify tagged launcher start time") from exc
    actual_ms = boot_seconds * 1000 + start_ticks * 1000 // ticks_per_second
    # Linux reports boot time at whole-second precision, while Java's
    # ProcessHandle start instant can retain the fractional boot offset.
    # Parentage plus PR_SET_PDEATHSIG binds this process to the exact live
    # launcher; this tolerance only reconciles the two timestamp clocks.
    tolerance_ms = 1100
    if abs(actual_ms - expected_ms) > tolerance_ms:
        raise ParentGuardError("tagged launcher start time does not match its PID")


def _arm_windows(parent_pid: int, expected_ms: int) -> None:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD

    synchronize = 0x00100000
    query_limited_information = 0x1000
    handle = kernel32.OpenProcess(synchronize | query_limited_information, False, parent_pid)
    if not handle:
        raise ParentGuardError(
            f"could not open tagged launcher process: WinError {ctypes.get_last_error()}"
        )

    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    if not kernel32.GetProcessTimes(
        handle,
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise ParentGuardError(
            f"could not verify tagged launcher start time: WinError {ctypes.get_last_error()}"
        )
    filetime = created.dwLowDateTime | (created.dwHighDateTime << 32)
    actual_ms = (filetime - 116_444_736_000_000_000) // 10_000
    if actual_ms != expected_ms:
        raise ParentGuardError("tagged launcher start time does not match its PID")

    def wait_for_parent() -> None:
        result = kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
        os._exit(_PARENT_EXIT_CODE if result == 0 else _PARENT_EXIT_CODE + 1)

    threading.Thread(
        target=wait_for_parent,
        name="maverick-mcp-parent-guard",
        daemon=True,
    ).start()


def _arm_posix(parent_pid: int) -> None:
    if os.getppid() != parent_pid:
        raise ParentGuardError("tagged launcher exited before the MCP guard armed")

    def poll_parent() -> None:
        while os.getppid() == parent_pid:
            time.sleep(0.02)
        os._exit(_PARENT_EXIT_CODE)

    threading.Thread(
        target=poll_parent,
        name="maverick-mcp-parent-guard",
        daemon=True,
    ).start()
    if os.getppid() != parent_pid:
        os._exit(_PARENT_EXIT_CODE)


def _acceptance_pause(present: dict[str, str], token: str) -> None:
    ready_raw = present.get(_READY)
    release_raw = present.get(_RELEASE)
    if ready_raw is None and release_raw is None:
        return
    if not ready_raw or not release_raw:
        raise ParentGuardError("controlled parent-guard pause requires both file paths")
    if "parent-death-acceptance-" not in token:
        raise ParentGuardError("controlled parent-guard pause is acceptance-only")

    ready = Path(ready_raw)
    release = Path(release_raw)
    if not ready.is_absolute() or not release.is_absolute():
        raise ParentGuardError("controlled parent-guard paths must be absolute")
    temporary = ready.with_name(f"{ready.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(f"{os.getpid()}\n")
        os.replace(temporary, ready)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    while not release.exists():
        time.sleep(0.02)
