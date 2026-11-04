"""Cross-process serialization + atomic writes for small JSON/TOML state files.

Many modules persist a tiny state file with a *read-modify-write*: load the
whole dict, mutate one key, write it all back. Two correctness hazards recur:

  - **Torn read.** A bare ``write_text`` / ``open(..., "w")`` truncates the
    file in place; a concurrent reader sees a half-written file and its
    ``json.load`` raises -> the state is treated as empty or the caller
    crashes. ``atomic_write_text`` writes a *unique* temp file and ``os.replace``
    it into position, so a successful reader only ever sees the old or the new
    whole file. On Windows, a reader racing the rename can receive a transient
    sharing/access error; :func:`atomic_read_text` and
    :func:`atomic_read_bytes` apply the matching bounded retry.

  - **Lost update.** ``os.replace`` makes each write atomic but does NOT stop
    two processes from both loading the same totals and the second clobbering
    the first. A ``threading.Lock`` only serializes threads *within one
    process* — the dashboard, ``serve``, a cron ``dream``, and a webhook can be
    four separate processes against the same tenant data dir.
    ``cross_process_lock`` adds an advisory ``flock`` on a stable sidecar so the
    whole load-modify-save is serialized across processes too.

This mirrors the proven discipline in :mod:`maverick.quotas`
(``_cross_process_lock`` + unique ``mkstemp`` + ``os.replace``); it is factored
out here so the dozen other state stores can adopt it without copy-pasting the
platform-specific locking dance. It uses ``flock`` on POSIX and a byte-range
lock on Windows, plus bounded in-process lock stripes on both platforms.
"""
from __future__ import annotations

import logging
import math
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger(__name__)

__all__ = [
    "cross_process_lock",
    "atomic_read_text",
    "atomic_read_bytes",
    "atomic_create_text",
    "atomic_create_bytes",
    "atomic_create_bytes_chunks",
    "atomic_write_text",
    "atomic_write_text_chunks",
    "atomic_write_bytes",
    "atomic_write_bytes_chunks",
    "open_private_read",
    "open_private_append",
    "ensure_private_directory",
    "prepare_private_directory",
    "require_private_directory",
    "ensure_private_file",
    "harden_path_permissions",
    "private_path_is_restricted",
]


# A Windows byte-range lock is process-scoped enough that competing threads can
# otherwise receive ``EDEADLK`` instead of waiting for each other.  POSIX also
# benefits because ``flock`` semantics can vary for multiple descriptors in one
# process.  The in-process serialization is a REFCOUNTED PER-PATH registry, not
# a fixed stripe table: holding a hash-shared stripe SHARED BY UNRELATED PATHS
# across the whole critical section deadlocks whenever two paths collide while
# callers nest other locks inside -- e.g. the self-harness promotion path
# (harness lock -> addenda lock -> audit-writer lock -> audit-file lock) against
# the audit writer (writer lock -> audit-file lock).  Entries are created
# on acquisition and dropped when the last concurrent user releases, so memory
# is bounded by CONCURRENT lock users -- strictly tighter than the old fixed
# table under the same attacker-controlled-path model, with no false sharing.
_LOCAL_PATH_LOCKS: dict[str, list] = {}
_LOCAL_PATH_LOCKS_GUARD = threading.Lock()
_THREAD_LOCK_STATE = threading.local()
_WINDOWS_LOCK_INITIALIZATION_SECONDS = 2.0


def _canonical_lock_path(path: Path) -> str:
    # Plain and extended Win32 spellings of one sidecar must share the same
    # process-local lock and recursion state.
    if os.name == "nt":
        path = Path(_windows_extended_path(path))
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _windows_extended_path(path: str | Path) -> str:
    r"""Return an absolute Win32 path that is not subject to ``MAX_PATH``.

    The ``\\?\`` namespace requires an absolute, normalized path and uses a
    distinct spelling for UNC shares.  Normalize before adding the prefix
    because Win32 deliberately stops resolving ``.``/``..`` and converting
    separators once an extended-length path reaches the API.
    """
    raw = os.fspath(path)
    if raw.startswith(("\\\\?\\", "\\\\.\\")):
        return raw
    absolute = os.path.normpath(os.path.abspath(raw))
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _unsafe_lock_alias(path: Path, info: os.stat_result) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return (
        stat.S_ISLNK(info.st_mode)
        or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)
        or bool(callable(is_junction) and is_junction())
    )


def _lock_identity(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
    )


def _validate_open_lock_file(path: Path, fd: int) -> os.stat_result:
    """Bind a lock descriptor to one non-alias, single-link regular path."""
    try:
        visible = path.lstat()
        opened = os.fstat(fd)
    except OSError as exc:
        raise PermissionError(f"lock path could not be verified: {path}") from exc
    if (
        _unsafe_lock_alias(path, visible)
        or _unsafe_lock_alias(path, opened)
        or not stat.S_ISREG(visible.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or visible.st_nlink != 1
        or opened.st_nlink != 1
        or _lock_identity(visible) != _lock_identity(opened)
    ):
        raise PermissionError(
            f"lock path is not a stable single-link regular file: {path}"
        )
    return opened


def _validate_existing_lock_path(path: Path) -> os.stat_result:
    """Reject an existing sidecar unless it is one single-link regular file."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise PermissionError(f"lock path could not be inspected: {path}") from exc
    if (
        _unsafe_lock_alias(path, info)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    ):
        raise PermissionError(
            f"lock path is not a stable single-link regular file: {path}"
        )
    return info


def _initialize_windows_lock_file(path: Path, fd: int) -> None:
    """Initialize a newly O_EXCL-created Windows byte-range lock file.

    Only the creator may write the byte. If every contender independently
    checked ``st_size == 0`` and wrote, a creator that had already acquired the
    mandatory byte-range lock could make a later contender's initialization
    write fail with ``PermissionError``.
    """
    if os.name != "nt":
        return
    _validate_open_lock_file(path, fd)
    written = os.write(fd, b"\0")
    if written != 1:
        raise OSError(f"could not initialize lock byte for {path}")
    os.fsync(fd)
    os.lseek(fd, 0, os.SEEK_SET)


def _adopt_orphaned_windows_lock_file(path: Path, fd: int) -> None:
    """Publish the lock byte on a sidecar whose creator never did.

    Adoption is idempotent -- every adopter (and a slow creator arriving
    late) writes the same single ``\\0`` at offset 0, so concurrent writes
    commute. A creator that is alive AND already holds the mandatory
    byte-range lock makes this write fail; that case re-raises the classic
    timeout error, now with the real cause attached, instead of quietly
    fighting a live lock holder.
    """
    _validate_open_lock_file(path, fd)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        if os.write(fd, b"\0") != 1:
            raise OSError(f"could not publish the lock byte for {path}")
        os.fsync(fd)
    except OSError as exc:
        raise PermissionError(f"lock file was never initialized: {path}") from exc
    os.lseek(fd, 0, os.SEEK_SET)


def _wait_for_windows_lock_initialization(path: Path, fd: int) -> None:
    """Wait boundedly for an O_EXCL creator to publish the lock byte.

    A creator that died (or whose file was recreated empty by AV/backup
    tooling) between creating the sidecar and writing the byte used to wedge
    the lock FOREVER: the empty file makes every later opener take the
    existing-file path, so no process can ever become the O_EXCL creator
    again, and each one waited out this timeout and failed. After the bounded
    wait a contender therefore adopts the orphan instead of giving up.
    """
    if os.name != "nt":
        return
    deadline = time.monotonic() + _WINDOWS_LOCK_INITIALIZATION_SECONDS
    delay = 0.001
    while os.fstat(fd).st_size < 1:
        if time.monotonic() >= deadline:
            _adopt_orphaned_windows_lock_file(path, fd)
            return
        time.sleep(delay)
        delay = min(delay * 1.5, 0.025)
    os.lseek(fd, 0, os.SEEK_SET)


def _open_lock_file(path: Path) -> int:
    """Open/create a sidecar without ever creating a link's referent."""
    try:
        prior = path.lstat()
    except FileNotFoundError:
        prior = None
    except OSError as exc:
        raise PermissionError(f"lock path could not be inspected: {path}") from exc
    if prior is not None:
        _validate_existing_lock_path(path)

    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    if prior is not None:
        # No O_CREAT for an existing pathname: if it is swapped to a dangling
        # link after validation, the open fails without creating the referent.
        # Other replacements are caught by descriptor/path identity binding.
        fd = os.open(str(path), flags)
        try:
            _wait_for_windows_lock_initialization(path, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise
    try:
        # O_EXCL makes the lstat/open creation gap safe even on the Windows CRT:
        # a sidecar (including a dangling link) planted after lstat produces
        # EEXIST instead of being followed.
        fd = os.open(str(path), flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # A racer published a sidecar. Re-enter through the existing-object
        # path without O_CREAT, so a dangling link's referent cannot be created.
        _validate_existing_lock_path(path)
        fd = os.open(str(path), flags)
        try:
            _wait_for_windows_lock_initialization(path, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise
    try:
        _initialize_windows_lock_file(path, fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _exclusive_local_lock(path: Path):
    """Hold THIS path's in-process lock -- and no other path's.

    The per-path RLock keeps same-path contenders (and, on platforms where the
    OS lock degrades, the whole in-process serialization) exactly as strict as
    the old stripe table, while guaranteeing that two different lock files can
    never block each other -- the property whose absence deadlocked nested
    acquisitions. The registry entry lives only while someone holds or waits."""
    canonical = _canonical_lock_path(path)
    with _LOCAL_PATH_LOCKS_GUARD:
        entry = _LOCAL_PATH_LOCKS.get(canonical)
        if entry is None:
            entry = _LOCAL_PATH_LOCKS[canonical] = [threading.RLock(), 0]
        entry[1] += 1
    lock: threading.RLock = entry[0]
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _LOCAL_PATH_LOCKS_GUARD:
            entry[1] -= 1
            if entry[1] <= 0:
                _LOCAL_PATH_LOCKS.pop(canonical, None)


def _windows_set_private_dacl(path: Path) -> None:
    """Install a protected owner/SYSTEM/Administrators-only Windows DACL."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    set_security = advapi32.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    set_security.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    # P = protected DACL (no inherited broad Users/Everyone entry). OW is the
    # file owner, SY is LocalSystem, and BA is Built-in Administrators.
    descriptor = ctypes.c_void_p()
    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        security_information = 0x00000004 | 0x80000000
        if not set_security(
            _windows_extended_path(path),
            security_information,
            descriptor,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.LocalFree(descriptor)


def _windows_secure_mkstemp(
    directory: Path,
    *,
    prefix: str,
    suffix: str,
) -> tuple[int, str]:
    """Create a new temp file with the private DACL in the create syscall.

    ``tempfile.mkstemp`` is race-free with respect to the filename, but on
    Windows it initially inherits the parent DACL. Applying a private DACL in a
    second call still lets an inherited writer retain a handle opened between
    those calls. ``CreateFileW`` accepts a security descriptor at creation, so
    there is no permissive intermediate object.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = SECURITY_ATTRIBUTES(
        ctypes.sizeof(SECURITY_ATTRIBUTES),
        descriptor,
        False,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    try:
        for _ in range(100):
            candidate = directory / f"{prefix}{secrets.token_hex(16)}{suffix}"
            handle = create_file(
                _windows_extended_path(candidate),
                0xC0010000,  # GENERIC_READ | GENERIC_WRITE | DELETE
                0,  # no sharing while the private payload is being written
                ctypes.byref(attributes),
                1,  # CREATE_NEW (never follow/overwrite a planted path)
                0x00000080,  # FILE_ATTRIBUTE_NORMAL
                None,
            )
            if handle != invalid_handle:
                try:
                    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
                    flags |= getattr(os, "O_NOINHERIT", 0)
                    fd = msvcrt.open_osfhandle(handle, flags)
                except BaseException:
                    kernel32.CloseHandle(handle)
                    try:
                        os.unlink(_windows_extended_path(candidate))
                    except OSError:
                        pass
                    raise
                # Downstream chmod, ACL verification, and failure cleanup also
                # need the namespace form when the random temp name crosses
                # MAX_PATH, even if the caller's destination itself does not.
                return fd, _windows_extended_path(candidate)
            error = ctypes.get_last_error()
            if error not in {80, 183}:  # ERROR_FILE_EXISTS / ALREADY_EXISTS
                raise ctypes.WinError(error)
    finally:
        kernel32.LocalFree(descriptor)
    raise FileExistsError("unable to allocate a unique secure temporary file")


def _secure_mkstemp(
    directory: Path,
    *,
    prefix: str,
    suffix: str,
    mode: int,
) -> tuple[int, str]:
    if os.name == "nt":
        fd, path = _windows_secure_mkstemp(
            directory,
            prefix=prefix,
            suffix=suffix,
        )
    else:
        fd, path = tempfile.mkstemp(
            dir=str(directory),
            prefix=prefix,
            suffix=suffix,
        )
    try:
        # On Windows the DACL is already private; chmod only applies the
        # requested DOS read-only posture. On POSIX this applies the exact mode.
        os.chmod(path, mode)
        if os.name == "nt" and not private_path_is_restricted(path, mode):
            raise PermissionError(
                "filesystem did not preserve the private create-time ACL"
            )
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return fd, path


def _windows_private_sddl(path: Path) -> tuple[str, str]:
    """Return ``(DACL SDDL, owner SID)`` for a Windows path."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = advapi32.GetNamedSecurityInfoW
    get_info.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    to_sddl = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    to_sddl.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    to_sddl.restype = wintypes.BOOL
    sid_to_text = advapi32.ConvertSidToStringSidW
    sid_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    sid_to_text.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = get_info(
        _windows_extended_path(path),
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000004,  # OWNER + DACL
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, "GetNamedSecurityInfoW failed")
    sddl_text = ctypes.c_wchar_p()
    owner_text = ctypes.c_wchar_p()
    try:
        if not to_sddl(descriptor, 1, 0x00000004, ctypes.byref(sddl_text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not sid_to_text(owner, ctypes.byref(owner_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        return str(sddl_text.value or ""), str(owner_text.value or "")
    finally:
        if sddl_text:
            kernel32.LocalFree(sddl_text)
        if owner_text:
            kernel32.LocalFree(owner_text)
        if descriptor:
            kernel32.LocalFree(descriptor)


def _windows_handle_private_sddl(handle: int) -> tuple[str, str]:
    """Return ``(DACL SDDL, owner SID)`` for one already-open Windows object."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = advapi32.GetSecurityInfo
    get_info.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    to_sddl = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    to_sddl.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    to_sddl.restype = wintypes.BOOL
    sid_to_text = advapi32.ConvertSidToStringSidW
    sid_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    sid_to_text.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = get_info(
        handle,
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000004,  # OWNER + DACL
        ctypes.byref(owner),
        None,
        None,
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, "GetSecurityInfo failed")
    sddl_text = ctypes.c_wchar_p()
    owner_text = ctypes.c_wchar_p()
    try:
        if not to_sddl(descriptor, 1, 0x00000004, ctypes.byref(sddl_text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not sid_to_text(owner, ctypes.byref(owner_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        return str(sddl_text.value or ""), str(owner_text.value or "")
    finally:
        if sddl_text:
            kernel32.LocalFree(sddl_text)
        if owner_text:
            kernel32.LocalFree(owner_text)
        if descriptor:
            kernel32.LocalFree(descriptor)


def _windows_current_user_sid() -> str:
    """Return the current process token's user SID."""
    import ctypes
    from ctypes import wintypes

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    get_token_info = advapi32.GetTokenInformation
    get_token_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_info.restype = wintypes.BOOL
    sid_to_text = advapi32.ConvertSidToStringSidW
    sid_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    sid_to_text.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    token = wintypes.HANDLE()
    if not open_token(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        get_token_info(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
        if not needed.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not get_token_info(
            token,
            1,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        token_user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        sid_text = ctypes.c_wchar_p()
        try:
            if not sid_to_text(token_user.User.Sid, ctypes.byref(sid_text)):
                raise ctypes.WinError(ctypes.get_last_error())
            return str(sid_text.value or "")
        finally:
            if sid_text:
                kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def _windows_acl_is_restricted(sddl: str, owner_sid: str) -> bool:
    """Validate the exact protected allow-only ACL installed by Lightwork."""
    if not sddl.startswith("D:P"):
        return False
    current_sid = _windows_current_user_sid()
    trusted_owners = {
        current_sid,
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # Built-in Administrators
    }
    if owner_sid not in trusted_owners:
        return False
    allowed_principals = {
        "OW",
        "SY",
        "BA",
        owner_sid,
        current_sid,
        "S-1-3-4",
        "S-1-5-18",
        "S-1-5-32-544",
    }
    aces = re.findall(r"\(([^()]*)\)", sddl)
    if not aces:
        return False
    principals: set[str] = set()
    for ace in aces:
        fields = ace.split(";")
        if (
            len(fields) != 6
            or fields[0] != "A"
            or fields[2] != "FA"
            or fields[5] not in allowed_principals
        ):
            return False
        principals.add(fields[5])
    # OW is the owner-rights SID used by our create-time descriptor. Accept an
    # explicit owner ACE too, but never infer trust merely from a private DACL
    # owned by an arbitrary principal.
    return bool(principals & {"OW", "S-1-3-4", owner_sid})


def _windows_open_security_handle(path: Path) -> tuple[int, int]:
    """Open ``path`` itself for identity-bound Windows security inspection."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = create_file(
        _windows_extended_path(path),
        0x00020000 | 0x00000080,  # READ_CONTROL | FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002 | 0x00000004,  # SHARE R/W/DELETE
        None,
        3,  # OPEN_EXISTING
        0x00200000 | 0x02000000,  # OPEN_REPARSE_POINT | BACKUP_SEMANTICS
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        fd = msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
    return fd, handle


def _windows_open_private_file_is_restricted(
    path: Path,
    expected: os.stat_result,
    mode: int,
) -> bool:
    """Verify one Windows file through a no-follow, identity-bound handle.

    A path-based ACL lookup admits an ABA swap (broad B -> private A -> broad
    B). The open handle binds the security descriptor to the same file ID seen
    by both the initial and final path inspections. ACL and DOS write posture
    are sampled twice so a mutation during the check cannot earn a fast return.
    """
    fd, handle = _windows_open_security_handle(path)
    try:
        opened = os.fstat(fd)

        def _require_bound_identity(
            visible: os.stat_result,
            current_opened: os.stat_result,
        ) -> None:
            if (
                not expected.st_dev
                or not expected.st_ino
                or not current_opened.st_dev
                or not current_opened.st_ino
                or _unsafe_lock_alias(path, current_opened)
                or _unsafe_lock_alias(path, visible)
                or not stat.S_ISREG(current_opened.st_mode)
                or not stat.S_ISREG(visible.st_mode)
                or current_opened.st_nlink != 1
                or visible.st_nlink != 1
                or (expected.st_dev, expected.st_ino)
                != (current_opened.st_dev, current_opened.st_ino)
                or (visible.st_dev, visible.st_ino)
                != (current_opened.st_dev, current_opened.st_ino)
                or (opened.st_dev, opened.st_ino)
                != (current_opened.st_dev, current_opened.st_ino)
            ):
                raise PermissionError(
                    f"sensitive state file identity changed: {path}"
                )

        _require_bound_identity(path.lstat(), opened)
        requested_writable = bool(mode & stat.S_IWRITE)
        if bool(opened.st_mode & stat.S_IWRITE) != requested_writable:
            return False
        first_sddl, first_owner = _windows_handle_private_sddl(handle)
        if not _windows_acl_is_restricted(first_sddl, first_owner):
            return False
        _require_bound_identity(path.lstat(), os.fstat(fd))
        refreshed = os.fstat(fd)
        _require_bound_identity(path.lstat(), refreshed)
        if bool(refreshed.st_mode & stat.S_IWRITE) != requested_writable:
            return False
        second_sddl, second_owner = _windows_handle_private_sddl(handle)
        if not _windows_acl_is_restricted(second_sddl, second_owner):
            return False
        _require_bound_identity(path.lstat(), os.fstat(fd))
        return True
    finally:
        os.close(fd)


def harden_path_permissions(path: str | Path, mode: int = 0o600) -> None:
    """Apply real private permissions on POSIX and Windows.

    ``os.chmod(0o600)`` only toggles the DOS read-only bit on Windows and can
    leave sensitive files readable by inherited ``Users``/``Everyone`` ACEs.
    Windows therefore receives a protected DACL; failure is surfaced rather
    than silently claiming the file is private.
    """
    path = Path(path)
    os.chmod(path, mode)
    if os.name == "nt":
        _windows_set_private_dacl(path)


def ensure_private_directory(path: str | Path) -> Path:
    """Create/tighten a directory to an owner-only security boundary."""
    path = Path(path)
    # The native private-file writer already uses extended paths on Windows.
    # Its parent can exceed Win32's shorter CreateDirectory path limit, even
    # when the configured home and each individual path component are valid.
    io_path = Path(_windows_extended_path(path) if os.name == "nt" else path)
    io_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        before = io_path.lstat()
    except OSError as exc:
        raise PermissionError(f"directory could not be inspected: {path}") from exc
    if _unsafe_lock_alias(io_path, before) or not stat.S_ISDIR(before.st_mode):
        raise PermissionError(f"private directory path is an alias: {path}")
    harden_path_permissions(io_path, 0o700)
    try:
        after = io_path.lstat()
    except OSError as exc:
        raise PermissionError(f"directory could not be verified: {path}") from exc
    if (
        _unsafe_lock_alias(io_path, after)
        or not stat.S_ISDIR(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise PermissionError(f"private directory identity changed: {path}")
    if not private_path_is_restricted(io_path, 0o700):
        raise PermissionError(f"directory could not be made private: {path}")
    return path


def require_private_directory(path: str | Path) -> Path:
    """Require an existing owner-only directory without changing its ACL.

    Integrity-sensitive state (for example replay nonces and append-only audit
    ledgers) cannot trust a file whose parent is writable by another principal:
    that principal could replace or delete the private file.  Caller-supplied
    directories are therefore *verified*, never silently claimed by changing
    their mode or DACL.
    """
    path = Path(path)
    io_path = Path(_windows_extended_path(path) if os.name == "nt" else path)
    try:
        info = io_path.lstat()
    except OSError as exc:
        raise PermissionError(
            f"parent directory must already be private: {path}"
        ) from exc
    if (
        _unsafe_lock_alias(io_path, info)
        or not stat.S_ISDIR(info.st_mode)
        or not private_path_is_restricted(io_path, 0o700)
    ):
        raise PermissionError(f"parent directory must already be private: {path}")
    return path


def _prepare_parent_directory(path: str | Path) -> Path:
    """Create a missing private parent, but never mutate an existing parent.

    Generic persistence helpers accept caller-selected paths.  Tightening a
    pre-existing parent would revoke access to unrelated files and services in
    that directory.  A parent created by this call is Lightwork-owned and may
    be hardened; an existing (or concurrently-created) parent is only checked
    for a safe directory type.
    """
    path = Path(path)
    io_path = Path(_windows_extended_path(path) if os.name == "nt" else path)
    try:
        io_path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        try:
            info = io_path.lstat()
        except OSError as exc:
            raise PermissionError(
                f"parent directory could not be inspected: {path}"
            ) from exc
        if _unsafe_lock_alias(io_path, info) or not stat.S_ISDIR(info.st_mode):
            raise PermissionError(
                f"parent directory path is an alias: {path}"
            ) from None
        return path
    return ensure_private_directory(path)


def prepare_private_directory(path: str | Path) -> Path:
    """Create a missing private directory or verify an existing one.

    Unlike :func:`ensure_private_directory`, this never tightens a directory
    that was already present.  It is the safe boundary for caller-selected
    integrity-sensitive storage: a missing dedicated directory may become
    Lightwork-owned, while a shared existing directory is refused unchanged.
    """
    prepared = _prepare_parent_directory(path)
    return require_private_directory(prepared)


_PRIVATE_FILE_PUBLICATION_RETRY_SECONDS = 1.0


def _private_file_publication_in_progress(
    path: Path,
    info: os.stat_result,
) -> bool:
    """Identify the brief POSIX hard-link window of atomic_create_*.

    POSIX publishes an exclusive create with ``link(temp, target)`` followed
    by ``unlink(temp)``. Between those syscalls the newly published inode has
    two links. A concurrent security check must not accept a generic hard
    link, but it also must not reject our still-open, private sibling
    publication. Only the exact internal temp-name shape and inode qualify for
    a bounded retry; the caller still requires ``st_nlink == 1`` before it
    changes permissions or returns.
    """
    if os.name == "nt" or info.st_nlink <= 1:
        return False
    prefix = f".{path.name}-"
    try:
        with os.scandir(path.parent) as entries:
            for entry in entries:
                if not (
                    entry.name.startswith(prefix)
                    and entry.name.endswith(".tmp")
                ):
                    continue
                try:
                    candidate = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if (
                    stat.S_ISREG(candidate.st_mode)
                    and (candidate.st_dev, candidate.st_ino)
                    == (info.st_dev, info.st_ino)
                ):
                    return True
    except OSError:
        return False
    return False


def ensure_private_file(path: str | Path, mode: int = 0o600) -> Path:
    """Tighten and verify an existing sensitive regular file.

    Atomic writers create new files privately, but deployments may already
    contain state written by an older release under inherited/broad ACLs. A
    security-sensitive reader calls this before opening such a file so an
    upgrade protects existing state too. Symlinks and non-regular files are
    refused rather than following an attacker-selected object while changing
    permissions.
    """
    path = Path(path)
    deadline = time.monotonic() + _PRIVATE_FILE_PUBLICATION_RETRY_SECONDS
    while True:
        info = path.lstat()
        if info.st_nlink == 1:
            break
        if _private_file_publication_in_progress(path, info):
            if time.monotonic() >= deadline:
                break
            time.sleep(0.001)
            continue
        # The publisher may have removed its temp between our lstat and the
        # sibling scan. Recheck the same inode once before treating it as a
        # hostile/persistent hard link.
        refreshed = path.lstat()
        if (
            refreshed.st_nlink == 1
            and (refreshed.st_dev, refreshed.st_ino)
            == (info.st_dev, info.st_ino)
        ):
            info = refreshed
            break
        info = refreshed
        break
    if (
        _unsafe_lock_alias(path, info)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    ):
        raise PermissionError(f"sensitive state path is not a regular file: {path}")
    # Atomic Windows creators already publish the requested DOS write posture
    # and protected DACL. Re-applying that DACL to an already-private SQLite
    # file while another connection is opening it can make the Windows VFS
    # report the live database as read-only. The handle-bound verifier avoids
    # that mutation without weakening alias, hard-link, owner, or ABA checks.
    if os.name == "nt" and _windows_open_private_file_is_restricted(path, info, mode):
        return path
    # On POSIX a chmod to the same mode still moves ctime, which readers that
    # bind a file's identity see as a change; an exact private mode is kept.
    if os.name != "nt" and stat.S_IMODE(info.st_mode) == mode:
        return path
    harden_path_permissions(path, mode)
    try:
        after = path.lstat()
    except OSError as exc:
        raise PermissionError(f"file could not be verified: {path}") from exc
    if (
        _unsafe_lock_alias(path, after)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise PermissionError(f"sensitive state file identity changed: {path}")
    if not private_path_is_restricted(path, mode):
        raise PermissionError(f"file could not be made private: {path}")
    return path


def private_path_is_restricted(path: str | Path, mode: int = 0o600) -> bool:
    """Verify the effective owner-only posture used by security tests/health."""
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        return False
    if _unsafe_lock_alias(path, info):
        return False
    if os.name != "nt":
        return (info.st_mode & 0o777) == (mode & 0o777)
    try:
        sddl, owner_sid = _windows_private_sddl(path)
    except (OSError, ValueError):
        return False
    if bool(info.st_mode & stat.S_IWRITE) != bool(mode & stat.S_IWRITE):
        return False
    try:
        return _windows_acl_is_restricted(sddl, owner_sid)
    except OSError:
        return False


def _replace_with_retry(source: str | Path, target: str | Path, *,
                        effect_guard: Callable[[], None] | None = None) -> None:
    """Replace atomically, tolerating brief Windows sharing violations."""
    if os.name != "nt":
        if effect_guard is not None:
            effect_guard()
        os.replace(source, target)
        # The file contents were fsync'd before rename; persist the directory
        # entry too so replay/policy state survives an abrupt power loss.
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        parent_fd = os.open(str(Path(target).parent), flags)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return

    # Python readers on Windows do not request FILE_SHARE_DELETE, so a short
    # read can make MoveFileEx/``os.replace`` fail with ACCESS_DENIED.  Retry
    # with a bounded deadline: this covers normal antivirus/indexer/read races
    # but still fails closed when another process pins the destination.
    deadline = time.monotonic() + 5.0
    delay = 0.002
    import ctypes
    from ctypes import wintypes

    move_file = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file.restype = wintypes.BOOL
    while True:
        if effect_guard is not None:
            effect_guard()
        if move_file(
            _windows_extended_path(source),
            _windows_extended_path(target),
            0x00000001 | 0x00000008,  # REPLACE_EXISTING | WRITE_THROUGH
        ):
            return
        error = ctypes.get_last_error()
        if error not in {5, 32, 33} or time.monotonic() >= deadline:
            raise ctypes.WinError(error)
        time.sleep(delay)
        delay = min(delay * 1.5, 0.05)


def _windows_replace_open_fd(
    fd: int,
    target: str | Path,
    *,
    replace: bool = True,
    effect_guard: Callable[[], None] | None = None,
) -> None:
    """Rename the still-open source object, binding publication to its handle.

    A path-based rename after closing the temp lets a writer on the parent
    directory substitute a different object at the random temp name. Windows'
    ``FileRenameInfo`` renames the object referenced by the verified handle, so
    source-path replacement cannot change the bytes that get published.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    # Do not resolve the final component: replacing an existing symlink must
    # replace the link itself, never follow it and overwrite its referent.
    destination = os.path.abspath(os.fspath(target))
    api_destination = _windows_extended_path(destination)
    encoded_destination = api_destination.encode("utf-16-le")
    utf16_units = len(encoded_destination) // 2

    class FILE_RENAME_INFO(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOL),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            # Non-BMP characters occupy two UTF-16 code units on Windows.
            ("FileName", ctypes.c_wchar * (utf16_units + 1)),
        ]

    info = FILE_RENAME_INFO()
    info.ReplaceIfExists = replace
    info.RootDirectory = None
    info.FileNameLength = len(encoded_destination)
    info.FileName = api_destination

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_info = kernel32.SetFileInformationByHandle
    set_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_info.restype = wintypes.BOOL
    flush = kernel32.FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    handle = msvcrt.get_osfhandle(fd)
    deadline = time.monotonic() + 5.0
    delay = 0.002
    while True:
        if effect_guard is not None:
            effect_guard()
        if set_info(handle, 3, ctypes.byref(info), ctypes.sizeof(info)):
            break
        error = ctypes.get_last_error()
        if (
            not replace
            and error in {5, 32, 33, 80, 183}
            and os.path.lexists(destination)
        ):
            raise FileExistsError(error, "destination already exists", destination)
        if error not in {5, 32, 33} or time.monotonic() >= deadline:
            raise ctypes.WinError(error)
        time.sleep(delay)
        delay = min(delay * 1.5, 0.05)
    if not flush(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _retry_permission_error(operation, *, retry_seconds: float):
    """Run ``operation``, retrying PermissionError until ``retry_seconds`` pass.

    A zero window is a plain call, so callers can make the retry Windows-only
    by choosing the window.
    """
    deadline = time.monotonic() + retry_seconds
    delay = 0.002
    while True:
        try:
            return operation()
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 0.05)


def _read_with_windows_retry(read, *, retry_seconds: float):
    try:
        retry_seconds = float(retry_seconds)
    except (TypeError, ValueError):
        raise ValueError("retry_seconds must be a finite number from 0 to 5") from None
    if not math.isfinite(retry_seconds) or not 0.0 <= retry_seconds <= 5.0:
        raise ValueError("retry_seconds must be a finite number from 0 to 5")
    if os.name != "nt":
        return read()
    return _retry_permission_error(read, retry_seconds=retry_seconds)


def atomic_read_text(
    path: str | Path,
    *,
    encoding: str = "utf-8",
    retry_seconds: float = 1.0,
) -> str:
    """Read an atomically-published text file across Windows rename races."""
    path = Path(_windows_extended_path(path) if os.name == "nt" else path)
    return _read_with_windows_retry(
        lambda: path.read_text(encoding=encoding),
        retry_seconds=retry_seconds,
    )


def atomic_read_bytes(
    path: str | Path,
    *,
    retry_seconds: float = 1.0,
) -> bytes:
    """Read an atomically-published binary file across Windows rename races."""
    path = Path(_windows_extended_path(path) if os.name == "nt" else path)
    return _read_with_windows_retry(
        path.read_bytes,
        retry_seconds=retry_seconds,
    )


def _publish_new_private_temp(fd: int, tmp: str, path: Path) -> None:
    """Publish the open private temp only when ``path`` is still absent."""
    if os.name == "nt":
        _windows_replace_open_fd(fd, path, replace=False)
        return
    os.link(tmp, path, follow_symlinks=False)
    os.unlink(tmp)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_fd = os.open(str(path.parent), flags)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def atomic_create_text(
    path: str | Path,
    text: str,
    *,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> None:
    """Create a private text file atomically, refusing an existing pathname.

    The unpublished temp receives its POSIX mode or protected Windows DACL in
    the creation syscall. Publication is exclusive, so a planted regular file,
    hard link, symlink, or reparse point is never opened or overwritten.
    """
    path = Path(path)
    _prepare_parent_directory(path.parent)
    fd, tmp = _secure_mkstemp(
        path.parent,
        prefix=f".{path.name}-",
        suffix=".tmp",
        mode=mode,
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            fd = -1
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            _publish_new_private_temp(f.fileno(), tmp, path)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_create_bytes(
    path: str | Path,
    data: bytes,
    *,
    mode: int = 0o600,
) -> None:
    """Byte-for-byte sibling of :func:`atomic_create_text`."""
    atomic_create_bytes_chunks(path, (data,), mode=mode)


def atomic_create_bytes_chunks(
    path: str | Path, chunks: Iterable[bytes], *, mode: int = 0o600,
) -> None:
    """Publish bounded byte chunks privately without replacing any destination."""
    path = Path(path)
    _prepare_parent_directory(path.parent)
    fd, tmp = _secure_mkstemp(
        path.parent,
        prefix=f".{path.name}-",
        suffix=".tmp",
        mode=mode,
    )
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            for chunk in chunks:
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
            _publish_new_private_temp(f.fileno(), tmp, path)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def open_private_read(path: str | Path, *, mode: int = 0o600) -> int:
    """Open a private single-link regular file and bind custody to its descriptor.

    Caller owns descriptor closure and snapshot/change detection. This does not
    create a missing source or claim that another process cannot append to it.
    """
    path = Path(path)
    ensure_private_directory(path.parent)
    ensure_private_file(path, mode)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags)
    try:
        visible, opened = path.lstat(), os.fstat(fd)
        if (
            _unsafe_lock_alias(path, visible) or _unsafe_lock_alias(path, opened)
            or not stat.S_ISREG(visible.st_mode) or not stat.S_ISREG(opened.st_mode)
            or visible.st_nlink != 1 or opened.st_nlink != 1
            or (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PermissionError(f"read path is not a stable single-link regular file: {path}")
        if os.name == "nt":
            restricted = _windows_open_private_file_is_restricted(path, opened, mode)
        else:
            restricted = (opened.st_mode & 0o777) == mode
        if not restricted:
            raise PermissionError(f"read file is not private: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_private_append(
    path: str | Path,
    *,
    mode: int = 0o600,
    require_private_parent: bool = False,
) -> int:
    """Open a private single-link regular file for append without following.

    A missing file is first published with :func:`atomic_create_bytes`, which
    prevents the inherited-DACL exposure created by ``O_CREAT`` on Windows.
    Existing state is tightened before opening, and the returned descriptor is
    identity-bound to the inspected pathname before any caller can append.
    """
    path = Path(path)
    if require_private_parent:
        prepare_private_directory(path.parent)
    else:
        _prepare_parent_directory(path.parent)
    try:
        atomic_create_bytes(path, b"", mode=mode)
    except FileExistsError:
        pass
    ensure_private_file(path, mode)
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags)
    try:
        visible = path.lstat()
        opened = os.fstat(fd)
        if (
            _unsafe_lock_alias(path, visible)
            or _unsafe_lock_alias(path, opened)
            or not stat.S_ISREG(visible.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or visible.st_nlink != 1
            or opened.st_nlink != 1
            or (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PermissionError(
                f"append path is not a stable single-link regular file: {path}"
            )
        if os.name != "nt":
            os.fchmod(fd, mode)
        if not private_path_is_restricted(path, mode):
            raise PermissionError(f"append file could not be made private: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def cross_process_lock(target: str | Path, *, strict: bool = False):
    """Advisory exclusive lock serializing a read-modify-write of ``target``.

    Keyed on a stable ``<name>.lock`` sidecar next to the file — never the file
    itself, since ``os.replace`` swaps the target's inode out from under any
    handle held on it. Lock creation/acquisition failures propagate instead of
    silently disabling serialization. ``strict=True`` additionally refuses to
    degrade to a process-local lock on filesystems without a working OS lock.
    """
    target = Path(target)
    lock_path = target.parent / (target.name + ".lock")
    if os.name == "nt":
        # Use one spelling for creation, descriptor/path identity checks, and
        # ACL verification when the sidecar exceeds Win32's legacy limit.
        lock_path = Path(_windows_extended_path(lock_path))
    canonical = _canonical_lock_path(lock_path)
    with _exclusive_local_lock(lock_path):
        held: dict[str, tuple[int, bool]] = getattr(
            _THREAD_LOCK_STATE, "held", {},
        )
        _THREAD_LOCK_STATE.held = held
        if canonical in held:
            # msvcrt byte-range locks are not re-entrant, even from the same
            # thread. The outer scope already owns both the local stripe and
            # OS lock, so only maintain the recursion count here. A strict
            # nested caller must not inherit a degraded process-local lock.
            count, process_safe = held[canonical]
            if strict and not process_safe:
                raise RuntimeError(
                    "cross-process lock backend is unavailable for strict state"
                )
            held[canonical] = (count + 1, process_safe)
            try:
                yield
            finally:
                held[canonical] = (count, process_safe)
            return

        _prepare_parent_directory(target.parent)
        # Failure to create/open the coordination primitive must not silently
        # disable serialization for security-sensitive read-modify-write state.
        fd = _open_lock_file(lock_path)
        backend: str | None = None
        try:
            _validate_open_lock_file(lock_path, fd)
            if os.name == "nt":
                # CRT ``os.open`` does not request WRITE_DAC, so SetSecurityInfo
                # on that handle fails on real Windows.  Harden by path only
                # inside the caller's private parent, bracketed by descriptor /
                # path identity validation so a replacement fails closed.
                harden_path_permissions(lock_path)
                _validate_open_lock_file(lock_path, fd)
            else:
                os.fchmod(fd, 0o600)
                if (os.fstat(fd).st_mode & 0o777) != 0o600:
                    raise PermissionError(
                        f"lock file could not be made private: {lock_path}"
                    )
            try:
                import fcntl
            except ImportError:
                fcntl = None  # type: ignore[assignment]
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    backend = "fcntl"
                except OSError as exc:
                    # flock is genuinely unavailable on this platform/filesystem
                    # (a non-POSIX or network/overlay FS that answers LOCK_EX
                    # with ENOLCK/EOPNOTSUPP). Cross-process serialization is
                    # impossible there; the in-process lock held above
                    # (``_exclusive_local_lock``) still serializes this process, so
                    # degrade to it rather than make every audit write and
                    # security-state read-modify-write fail on such a platform.
                    # A lock-FILE creation failure (the ``os.open`` above) still
                    # propagates -- only acquisition on an already-open fd
                    # degrades, so ``test_cross_process_lock_fails_closed_when_
                    # dir_unwritable`` stays fail-closed.
                    if strict:
                        raise RuntimeError(
                            "cross-process lock backend is unavailable for strict state"
                        ) from exc
                    log.debug(
                        "cross_process_lock: flock unavailable for %s (%s); "
                        "relying on the in-process lock only", lock_path, exc,
                    )
                    backend = None
            elif os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                backend = "msvcrt"
            else:  # pragma: no cover - supported platforms have one backend
                raise RuntimeError(
                    "no cross-process lock backend is available"
                ) from None
            _validate_open_lock_file(lock_path, fd)
            held[canonical] = (1, backend is not None)
            try:
                yield
            finally:
                held.pop(canonical, None)
        finally:
            if backend == "fcntl":
                try:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
            elif backend == "msvcrt":
                try:
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except (ImportError, OSError):
                    pass
            os.close(fd)


def atomic_write_text(path: str | Path, text: str, *, mode: int = 0o600,
                      encoding: str = "utf-8", newline: str | None = None,
                      effect_guard: Callable[[], None] | None = None) -> None:
    """Write ``text`` to ``path`` atomically: a *unique* temp file in the same
    directory, then ``os.replace`` into position.

    A reader concurrent with the write sees either the old whole file or the new
    whole file — never a truncated one. The temp name is unique (``mkstemp``) so
    two concurrent writers don't collide on a shared ``.tmp`` (one ``os.replace``
    would otherwise move the temp out from under the other). The temp is cleaned
    up on any failure so a crashed write leaves no stray files. An optional
    caller guard runs after the temp is flushed, immediately before every
    physical replacement attempt, including Windows sharing retries.
    """
    path = Path(path)
    _prepare_parent_directory(path.parent)
    fd, tmp = _secure_mkstemp(
        path.parent,
        prefix=f".{path.name}-",
        suffix=".tmp",
        mode=mode,
    )
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            fd = -1  # ownership transferred to the file object
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            if os.name == "nt":
                if effect_guard is None:
                    _windows_replace_open_fd(f.fileno(), path)
                else:
                    _windows_replace_open_fd(f.fileno(), path, effect_guard=effect_guard)
            else:
                if effect_guard is None:
                    _replace_with_retry(tmp, path)
                else:
                    _replace_with_retry(tmp, path, effect_guard=effect_guard)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text_chunks(
    path: str | Path,
    chunks: Iterable[str],
    *,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> int:
    """Atomically stream text chunks into a privately-created destination.

    This is the bounded-memory counterpart to :func:`atomic_write_text` for
    exports that may be large. The unpublished temp receives its final POSIX
    mode or Windows DACL at creation; only after every chunk is flushed and
    fsync'd is the verified handle published over ``path``. Returns the number
    of chunks written.
    """
    path = Path(path)
    _prepare_parent_directory(path.parent)
    fd, tmp = _secure_mkstemp(
        path.parent,
        prefix=f".{path.name}-",
        suffix=".tmp",
        mode=mode,
    )
    count = 0
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            fd = -1
            for chunk in chunks:
                f.write(chunk)
                count += 1
            f.flush()
            os.fsync(f.fileno())
            if os.name == "nt":
                _windows_replace_open_fd(f.fileno(), path)
            else:
                _replace_with_retry(tmp, path)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return count


def atomic_write_bytes(path: str | Path, data: bytes, *, mode: int = 0o600,
                       effect_guard: Callable[[], None] | None = None) -> None:
    """Byte-for-byte sibling of :func:`atomic_write_text` for binary payloads
    (e.g. an at-rest-sealed blob): unique temp in the same directory, then
    ``os.replace`` into position; the temp is cleaned up on any failure."""
    if effect_guard is None:
        atomic_write_bytes_chunks(path, (data,), mode=mode)
    else:
        atomic_write_bytes_chunks(path, (data,), mode=mode, effect_guard=effect_guard)


def atomic_write_bytes_chunks(
    path: str | Path, chunks: Iterable[bytes], *, mode: int = 0o600,
    effect_guard: Callable[[], None] | None = None,
) -> int:
    """Publish a private binary stream atomically after all chunks and fsync.

    Generator/read/cancellation failures leave the previous destination intact
    and remove the unpublished temporary file. Memory is owned by one chunk.
    """
    path = Path(path)
    _prepare_parent_directory(path.parent)
    fd, tmp = _secure_mkstemp(
        path.parent,
        prefix=f".{path.name}-",
        suffix=".tmp",
        mode=mode,
    )
    count = 0
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            for chunk in chunks:
                f.write(chunk)
                count += 1
            f.flush()
            os.fsync(f.fileno())
            if os.name == "nt":
                if effect_guard is None:
                    _windows_replace_open_fd(f.fileno(), path)
                else:
                    _windows_replace_open_fd(f.fileno(), path, effect_guard=effect_guard)
            else:
                if effect_guard is None:
                    _replace_with_retry(tmp, path)
                else:
                    _replace_with_retry(tmp, path, effect_guard=effect_guard)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return count
