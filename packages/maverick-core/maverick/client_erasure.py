"""Signed offboarding receipts that survive removal of the client audit tree.

Only minimal operation metadata and the public verification key are retained
outside the client root. The existing audit signer is initialized before any
deletion and stays in memory for the final event; no private key is copied and
completion never recreates the erased tenant's key directory.

As with ordinary local audit chains, an independently held public key is needed
to detect replacement by somebody with access to the signing identity. A
request without a terminal event proves intent, never successful erasure.
"""
from __future__ import annotations

import json
import os
import stat
import time
import uuid
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

from .audit.events import AuditEvent
from .audit.signing import AuditSigner, trusted_audit_public_keys, verify_chain
from .file_lock import (
    atomic_create_text,
    atomic_read_text,
    cross_process_lock,
    ensure_private_directory,
)


class ClientErasureError(RuntimeError):
    """An erase was refused, incomplete, or could not confirm its final record."""

    def __init__(self, message: str, *, receipt_id: str = "", removed: int = 0):
        self.receipt_id = receipt_id
        self.removed = removed
        suffix = f" Activity receipt: {receipt_id}." if receipt_id else ""
        super().__init__(message + suffix)


@lru_cache(maxsize=1)
def _windows_erase_api():
    import ctypes
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class HandleInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD), ("created", FileTime),
            ("accessed", FileTime), ("modified", FileTime),
            ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD),
        ]

    class Disposition(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOL)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_path = kernel.CreateFileW
    open_path.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                          wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    open_path.restype = wintypes.HANDLE
    inspect = kernel.GetFileInformationByHandle
    inspect.argtypes = [wintypes.HANDLE, ctypes.POINTER(HandleInformation)]
    inspect.restype = wintypes.BOOL
    set_info = kernel.SetFileInformationByHandle
    set_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    set_info.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    return open_path, inspect, set_info, close, HandleInformation, Disposition


def windows_erase_target_identity(path: Path) -> tuple[int, int, bool, bool]:
    """Pin a prepared Windows target's file ID and type before its receipt."""
    info = path.lstat()
    if not info.st_ino or info.st_nlink < 1:
        raise ValueError("an erase target has no stable file identity")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise ValueError("an erase target has another hard link outside this path")
    # Take the directory flag from the attributes the deletion handle reports.
    # On the failing Windows run, S_ISDIR on this lstat result disagreed with the
    # handle's DIRECTORY attribute for a directory alias, so every alias looked
    # changed after the inventory. (The S_IFLNK cause is not verified against the docs.)
    attributes = getattr(info, "st_file_attributes", 0)
    return (info.st_dev, info.st_ino, bool(attributes & stat.FILE_ATTRIBUTE_DIRECTORY),
            bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def delete_windows_erase_target(path: Path, expected: tuple[int, int, bool, bool]) -> None:
    """Delete the inspected object by handle, never a replacement pathname."""
    import ctypes

    from .file_lock import _windows_extended_path

    open_path, inspect, set_info, close, info_type, disposition_type = _windows_erase_api()
    # DELETE | FILE_READ_ATTRIBUTES; deny write/delete sharing so a concurrent
    # writer cannot move this object after it has been opened.
    handle = open_path(_windows_extended_path(path), 0x00010080, 0x00000001,
                       None, 3, 0x00200000 | 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "an erase target could not be held safely")
    try:
        info = info_type()
        if not inspect(handle, ctypes.byref(info)):
            raise OSError(ctypes.get_last_error(), "an erase target could not be inspected")
        file_id = (info.index_high << 32) | info.index_low
        if (file_id != expected[1]
                or bool(info.attributes & 0x10) != expected[2]
                or bool(info.attributes & 0x400) != expected[3]
                or windows_erase_target_identity(path) != expected
                or (not expected[2] and info.links != 1)):
            raise ValueError("an erase target changed after the signed inventory")
        disposition = disposition_type(True)
        if not set_info(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise OSError(ctypes.get_last_error(), "the inspected erase target could not be removed")
        final_info = info_type()
        if not inspect(handle, ctypes.byref(final_info)) or final_info.links != 0:
            raise ValueError("an erase target still has another filesystem link")
    finally:
        close(handle)


@contextmanager
def hold_windows_erase_parents(root: Path, parent: Path, root_identity: tuple[int, int]):
    """Keep each deletion ancestor from becoming a junction while it is used.

    A pathname check followed by ``unlink`` is not enough on Windows: another
    local process can rename the checked directory and put a junction in its
    place. A read handle that denies write/delete sharing pins each ordinary
    directory through the mutation. Failure to pin any ancestor refuses that
    target; the caller records an incomplete erase.
    """
    if os.name != "nt":
        yield
        return

    import ctypes

    from .file_lock import _windows_extended_path

    def identity(path: Path) -> tuple[int, int]:
        info = path.lstat()
        junction = getattr(path, "is_junction", None)
        if (path.is_symlink() or (callable(junction) and junction())
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                or not stat.S_ISDIR(info.st_mode) or not info.st_ino):
            raise ValueError("an erase parent is not a stable ordinary directory")
        return info.st_dev, info.st_ino

    relative = parent.relative_to(root)
    ancestors = [root]
    for part in relative.parts:
        ancestors.append(ancestors[-1] / part)

    open_dir, _inspect, _set_info, close, _info_type, _disposition_type = _windows_erase_api()
    handles = []
    try:
        for path in ancestors:
            before = identity(path)
            if path == root and before != root_identity:
                raise ValueError("the client data folder identity changed")
            # GENERIC_READ is required here: FILE_READ_ATTRIBUTES alone does
            # not prevent directory rename on Windows. No share-write/delete.
            handle = open_dir(_windows_extended_path(path), 0x80000000, 0x00000001,
                              None, 3, 0x00200000 | 0x02000000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise OSError(ctypes.get_last_error(), "an erase parent could not be held safely")
            handles.append(handle)
            if identity(path) != before:
                raise ValueError("an erase parent changed while it was being held")
        yield
    finally:
        for handle in reversed(handles):
            close(handle)


class ErasureReceipt:
    """One private, verifiable intent, prepared-inventory and outcome chain."""

    def __init__(self, home: Path, detail: dict[str, Any]):
        self.id = uuid.uuid4().hex
        self.detail = detail
        directory = home / "client-erasure" / self.id
        self.path = directory / "events.ndjson"
        try:
            ensure_private_directory(home)
            ensure_private_directory(directory.parent)
            ensure_private_directory(directory)
            atomic_create_text(self.path, "")
            self.signer = AuditSigner(self.path)
            event = self._event("client_erase_requested", status="requested")
            if self.signer.write(event) is not True:
                raise OSError("the initial receipt was not saved")
            first = json.loads(atomic_read_text(self.path).splitlines()[0])
            self.public_key = trusted_audit_public_keys()[first["key_id"]]
            atomic_create_text(directory / "verification-key.hex", self.public_key + "\n")
            self._verify()
        # failure-policy: fail_closed
        except Exception as exc:
            raise ClientErasureError(
                "The signed activity receipt could not be saved and verified. Nothing was erased.",
                receipt_id=self.id,
            ) from exc

    def _event(self, kind: str, **result: Any) -> dict[str, Any]:
        return AuditEvent(
            ts=time.time(), kind=kind, agent="client-maintenance",
            payload={**self.detail, "event_id": self.id, **result},
        ).to_dict()

    def _verify(self) -> None:
        if verify_chain(self.path, self.public_key):
            raise ValueError("the operation receipt could not be verified")

    def _append(self, kind: str, **result: Any) -> None:
        with cross_process_lock(self.path, strict=True):
            self._verify()
            if self.signer.write(self._event(kind, **result)) is not True:
                raise OSError("the receipt event was not saved")
            self._verify()

    def prepare(self, targets: dict[str, Any]) -> None:
        """Commit the actual deletion inventory after signing is provisioned."""
        try:
            self._append("client_erase_ready", status="prepared", **targets)
            self.detail.update(targets)
        # failure-policy: fail_closed
        except Exception as exc:
            raise ClientErasureError(
                "The prepared deletion inventory could not be saved and verified. Nothing was erased.",
                receipt_id=self.id,
            ) from exc

    def finish(self, *, complete: bool, removed: int, failures: int) -> None:
        """Record the observed result, never inferring success from a request."""
        try:
            self._append(
                "client_erased" if complete else "client_erase_incomplete",
                status="completed" if complete else "incomplete",
                removed=removed, failures=failures,
            )
        # failure-policy: fail_closed
        except Exception as exc:
            raise ClientErasureError(
                "Deletion was attempted, but its final activity receipt could not be confirmed. "
                "Check the remaining data before trying again.",
                receipt_id=self.id, removed=removed,
            ) from exc


__all__ = ["ClientErasureError", "ErasureReceipt", "hold_windows_erase_parents",
           "windows_erase_target_identity", "delete_windows_erase_target"]
