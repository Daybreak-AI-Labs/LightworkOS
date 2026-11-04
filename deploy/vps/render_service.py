"""Render a VPS unit from the installed user's actual workspace configuration."""
from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def _unit_value(value: str | Path) -> str:
    text = str(value)
    if any(character in text for character in "\r\n\0"):
        raise ValueError("systemd paths cannot contain newlines or NUL")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def _read_user_config(home: Path) -> str:
    """Read a bounded regular config without following its final components."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    home_fd = os.open(home, flags)
    try:
        state_fd = os.open(".maverick", flags, dir_fd=home_fd)
        try:
            fd = os.open("config.toml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=state_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                    raise ValueError("service configuration must be a regular file under 1 MiB")
                raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("service configuration exceeds 1 MiB")
                return raw.decode("utf-8")
        finally:
            os.close(state_fd)
    finally:
        os.close(home_fd)


def _trusted_home_ancestors(home: Path) -> None:
    """Reject redirectable parents before the privileged configuration read."""
    for directory in (home.parent, *home.parent.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ValueError("service home ancestors must be root-owned and not group/world writable")


def render_service(template: str, *, user: str, home: Path, probe: bool = True) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*\$?", user):
        raise ValueError("invalid service account name")
    home = Path(os.path.abspath(home))
    if not probe:
        _trusted_home_ancestors(home)
    state = home / ".maverick"
    config_file = state / "config.toml"
    config = tomllib.loads(_read_user_config(home))
    configured = config.get("sandbox", {}).get("workdir")
    if not isinstance(configured, str) or not configured.strip():
        raise ValueError("setup must save sandbox.workdir before installing the service")
    if str(config.get("sandbox", {}).get("backend", "local")).strip().lower() == "ssh":
        # SSH workdir belongs to the remote host. A local collision or ACL at
        # the same spelling says nothing about its availability there.
        workspace = state / "service-workspace"
    else:
        if configured == "~":
            configured = str(home)
        elif configured.startswith("~/"):
            configured = str(home / configured[2:])
        workspace = Path(configured)
        if not workspace.is_absolute():
            raise ValueError("sandbox.workdir must be an absolute path for the VPS service")
    workspace = workspace.resolve()
    if probe:
        workspace.mkdir(parents=True, exist_ok=True)
        # Only the unprivileged invocation may create or probe this path.
        with tempfile.TemporaryFile(dir=workspace, prefix=".lightwork-service-") as workspace_probe:
            workspace_probe.write(b"workspace-ready\n")
            workspace_probe.flush()
            os.fsync(workspace_probe.fileno())
    values = {
        "@USER@": user,
        "@WORKDIR@": _unit_value(workspace),
        "@STATE@": _unit_value(state),
        "@ENV_FILE@": _unit_value(state / ".env"),
        "@CONFIG_ENV@": _unit_value("MAVERICK_CONFIG=" + str(config_file)),
        "@EXECUTABLE@": _unit_value(home / ".local/bin/maverick"),
    }
    for marker, value in values.items():
        template = template.replace(marker, value)
    return template


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", required=True)
    parser.add_argument("--home", required=True, type=Path)
    parser.add_argument("--no-probe", action="store_true")
    parser.add_argument("--template", type=Path, default=Path(__file__).with_name("maverick.service"))
    args = parser.parse_args()
    print(render_service(args.template.read_text(encoding="utf-8"), user=args.user, home=args.home,
                         probe=not args.no_probe), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
