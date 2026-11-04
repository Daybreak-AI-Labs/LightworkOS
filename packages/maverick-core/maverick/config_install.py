"""Headless provisioning: validate a settings file and install it as config.toml.

The work behind ``maverick init --from-file``, shared with the dashboard's
setup page so an administrator can install a prepared settings file without a
terminal. The file is parsed, checked for settings this build cannot apply,
and published privately. Advisory findings remain visible without blocking.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # 3.10
    import tomli as tomllib  # type: ignore[no-redef]


class ConfigInstallError(ValueError):
    """The settings file is not valid TOML (the parser's reason is the text)."""


def parse_config_bytes(data: bytes) -> dict[str, Any]:
    try:
        return tomllib.loads(data.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 -- the parser's reason is kept as the text
        raise ConfigInstallError(str(exc)) from exc


def config_findings(cfg: dict[str, Any]) -> list[Any]:
    """Lint findings for a parsed settings file; never silently skip the check."""
    from .config_lint import lint_config

    return list(lint_config(cfg))


def blocking_config_findings(findings: list[Any]) -> list[Any]:
    """Reject values this build will ignore while preserving advisory warnings."""
    return [f for f in findings if f.severity == "error" or f.message.startswith("unknown ")]


def install_config_bytes(data: bytes, dst: Path | None = None, *,
                         backup: bool = False) -> dict[str, Any]:
    """Serialize provisioning with dashboard settings and other provisioning writers."""
    from .authority_effects import authority_effect_fence
    from .config import dashboard_overrides_path
    from .file_lock import cross_process_lock

    with authority_effect_fence(), cross_process_lock(dashboard_overrides_path(), strict=True):
        return _install_config_bytes_locked(data, dst, backup=backup)


def _install_config_bytes_locked(data: bytes, dst: Path | None = None, *,
                         backup: bool = False) -> dict[str, Any]:
    """Publish ``data`` as the active config.toml (0600).

    Returns ``{"path": dst, "unchanged": bool, "backup": Path | None}``. The
    same logical file (line endings aside) is a true no-op that only repairs
    the file's privacy. With ``backup`` an existing, different file is first
    copied to a dated ``config.toml.bak-YYYYmmdd-HHMMSS`` beside it (the same
    naming ``maverick migrate`` uses).
    """
    from .config import config_path
    from .file_lock import atomic_write_bytes, ensure_private_directory, ensure_private_file

    dst = config_path() if dst is None else dst
    # A provisioned config may contain inline provider keys. Tighten the
    # directory with a protected Windows DACL and publish the bytes from a
    # create-time protected temp; POSIX mode bits passed to os.open do not
    # provide the equivalent Windows custody boundary.
    ensure_private_directory(dst.parent)
    existed = dst.is_file()
    # An unreadable old file cannot be backed up reliably; leave it in place.
    installed = dst.read_bytes() if existed else b""
    unchanged = existed and installed.replace(b"\r\n", b"\n") == data.replace(b"\r\n", b"\n")
    if unchanged:
        # A retried deployment should be a true no-op: do not rotate the inode,
        # mtime, or watcher state when the same logical TOML is installed,
        # including when a cross-platform checkout changed line endings.
        # Still repair/verify custody in case an older release left wide perms.
        ensure_private_file(dst, 0o600)
        return {"path": dst, "unchanged": True, "backup": None}
    saved = None
    if backup and existed:
        import secrets
        import time

        saved = dst.with_name(f"{dst.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}")
        # Back up the bytes just read with private custody from creation.
        atomic_write_bytes(saved, installed, mode=0o600)
    atomic_write_bytes(dst, data, mode=0o600)
    return {"path": dst, "unchanged": False, "backup": saved}


__all__ = ["ConfigInstallError", "parse_config_bytes", "config_findings",
           "blocking_config_findings", "install_config_bytes"]
