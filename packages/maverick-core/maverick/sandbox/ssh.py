"""SSH sandbox backend.

Executes commands on a remote host via the system ``ssh`` binary. No
Python dep (paramiko) -- we just shell out to ssh so users get the
same keys / config / agents they already have set up.
Remote hosts must provide GNU ``timeout``. Its process-group deadline does not
contain commands that deliberately detach; use remote OS isolation for those.

Config::

    [sandbox]
    backend = "ssh"
    host = "me@example.com"
    workdir = "/home/me/maverick-workspace"
    timeout = 60
    ssh_args = ["-i", "~/.ssh/maverick_key"]
    host_key_checking = "accept-new"   # accept-new | yes | no (default accept-new)
"""
from __future__ import annotations

import math
import os
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import ClassVar

from .local import ExecResult, scrub_env


def _ssh_env() -> dict:
    """Keep local agent authentication while removing provider credentials."""
    env = scrub_env()
    if socket_path := os.environ.get("SSH_AUTH_SOCK"):
        env["SSH_AUTH_SOCK"] = socket_path
    return env

# Connection options applied to BOTH the verify probe and every exec(): fail
# fast on an auth prompt / key change instead of blocking the agent loop on a
# hidden interactive prompt.
#  - BatchMode=yes      : never prompt for a password/passphrase (fail instead).
#  - ConnectTimeout=10  : don't hang forever on an unreachable host.
_BASE_SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]

# Host-key policy default. ``accept-new`` pins the key into known_hosts on
# first contact, then REJECTS a later key change (MITM) -- a real check,
# unlike the implicit "no checking" you get when ssh's StrictHostKeyChecking is
# left to its prompt default under BatchMode. We deliberately do NOT default to
# the strictest ``yes`` (would lock out users whose host isn't in known_hosts
# yet); operators can set ``host_key_checking = "yes"`` for that, or "no" to
# restore the old blind-accept behaviour.
_VALID_HOST_KEY_POLICIES = {"accept-new", "yes", "no"}


@dataclass
class SSHBackend:
    # The workspace path names a location on the SSH host, not this machine.
    workdir_is_local: ClassVar[bool] = False
    host: str
    # The workdir lives on the REMOTE host, which is POSIX -- use
    # PurePosixPath, never the platform Path: on a Windows client
    # ``str(Path("/home/me/ws"))`` becomes ``\home\me\ws`` and we would ship
    # a broken backslash path to the (Linux) remote.
    workdir: PurePosixPath = PurePosixPath("~/maverick-workspace")
    timeout: float = 60.0
    ssh_args: list[str] = field(default_factory=list)
    # See _VALID_HOST_KEY_POLICIES. Safe-compatible default: accept-new.
    host_key_checking: str = "accept-new"

    def __post_init__(self) -> None:
        # Coerce unconditionally, not just for str: build_sandbox passes a
        # platform ``pathlib.Path``, which on a Windows client is a WindowsPath
        # (a PurePath, NOT a str), so a str-only guard would let the backslash
        # path the class docstring warns about reach the Linux remote.
        if not isinstance(self.workdir, PurePosixPath):
            self.workdir = PurePosixPath(str(self.workdir))
        policy = (self.host_key_checking or "accept-new").strip().lower()
        if policy not in _VALID_HOST_KEY_POLICIES:
            policy = "accept-new"
        self.host_key_checking = policy
        self._verify_ssh()

    def _ssh_opts(self) -> list[str]:
        """BatchMode + ConnectTimeout + the configured host-key policy."""
        return [
            *_BASE_SSH_OPTS,
            "-o", f"StrictHostKeyChecking={self.host_key_checking}",
        ]

    def _verify_ssh(self) -> None:
        import shutil
        if not shutil.which("ssh"):
            raise RuntimeError(
                "ssh binary not found on PATH. Install openssh-client."
            )
        check = subprocess.run(
            ["ssh", *self._ssh_opts(), *self.ssh_args, self.host, "true"],
            capture_output=True, timeout=15, env=_ssh_env(),
        )
        if check.returncode != 0:
            stderr = check.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"ssh to {self.host} failed: {stderr or 'unknown error'}. "
                "Check your SSH config / keys."
            )

    def _quote_workdir(self) -> str:
        """Shell-quote the remote workdir, but leave a leading ``~/`` (or bare
        ``~``) UNQUOTED so the remote shell expands it to ``$HOME``.

        ``shlex.quote("~/maverick-workspace")`` yields ``'~/maverick-workspace'``,
        and the surrounding single quotes suppress the remote shell's tilde
        expansion -- so the default workdir would be created as a literal ``~``
        directory under the session cwd instead of under ``$HOME``. Quoting only
        the part after the tilde keeps the injection-safety guarantee (the path
        body is still quoted) while restoring expansion.
        """
        s = str(self.workdir)
        if s == "~":
            return "~"
        if s.startswith("~/"):
            rest = s[2:]
            return "~/" + shlex.quote(rest) if rest else "~/"
        return shlex.quote(s)

    def exec(self, cmd: str, timeout: float | None = None) -> ExecResult:
        effective = self.timeout if timeout is None else timeout
        if not math.isfinite(effective) or effective <= 0:
            return ExecResult(stdout="", stderr="Invalid SSH command timeout", exit_code=1)
        # Run cmd as a single quoted argument inside ``sh -c`` so a leading
        # ``;`` / ``&&`` / ``||`` / unbalanced quote can't escape the ``cd``
        # guard and run outside the workspace. The workdir itself is quoted too.
        wd = self._quote_workdir()
        inner = f"mkdir -p {wd} && cd {wd} && sh -c {shlex.quote(cmd)}"
        # A local ssh timeout only kills the client. GNU timeout also enforces
        # a deadline remotely, even after the connection disappears. Requiring
        # it fails closed on hosts where it is unavailable. Processes that
        # deliberately create a new session still need remote OS isolation.
        remote = f"timeout --signal=KILL {max(effective, 0.001):.6f}s sh -c {shlex.quote(inner)}"
        # Env hygiene: ssh forwards local env to the remote shell only via
        # SendEnv/SetEnv, neither of which we set -- so the remote never
        # inherits host secrets. We additionally scrub the LOCAL ssh client's
        # own env (env=scrub_env()) so a provider key can't leak through an
        # ssh feature that reads it (e.g. SSH_ASKPASS-style helpers).
        args = ["ssh", *self._ssh_opts(), *self.ssh_args, self.host, remote]
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=effective,
                env=_ssh_env(),
            )
            return ExecResult(
                stdout=result.stdout[-8000:],
                stderr=result.stderr[-2000:],
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired as e:
            return ExecResult(
                stdout=(e.stdout or b"").decode("utf-8", errors="replace")[-8000:],
                stderr=f"TIMEOUT after {effective}s",
                exit_code=124,
            )
