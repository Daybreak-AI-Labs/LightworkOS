"""Authenticated local identity binding for Ekko endpoint collectors."""
from __future__ import annotations

import os


def _windows_account_name() -> str:
    """Return the current access-token account, not an environment variable."""
    import ctypes
    from ctypes import wintypes

    secur32 = ctypes.WinDLL("secur32", use_last_error=True)
    get_name = secur32.GetUserNameExW
    get_name.argtypes = [ctypes.c_int, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    get_name.restype = wintypes.BOOL
    # NameSamCompatible yields DOMAIN\user and is derived from the current
    # access token. A fixed-size first attempt avoids trusting USERNAME/HOME.
    size = wintypes.DWORD(512)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not get_name(2, buffer, ctypes.byref(size)):
        raise RuntimeError("could not bind Ekko to the current Windows account")
    value = buffer.value.strip().casefold()
    if not value:
        raise RuntimeError("current Windows account identity is empty")
    return value


def local_os_principal() -> str:
    """Stable principal for the caller's operating-system security context.

    The ordinary Ekko CLI intentionally has no owner-impersonation option. On
    POSIX, the effective uid is the kernel authorization identity. On Windows,
    the account is read from the current access token through Secur32.
    """
    if os.name == "nt":
        return "os:windows:" + _windows_account_name()
    if hasattr(os, "geteuid"):
        return f"os:posix:{os.geteuid()}"
    raise RuntimeError("Ekko cannot authenticate the local operating-system user")


__all__ = ["local_os_principal"]
