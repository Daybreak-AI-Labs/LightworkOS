"""Podman sandbox backend.

Daemonless alternative to Docker. Same surface: spawn a fresh
``podman run --rm`` per ``exec()`` with the workdir mounted, network
disabled by default.

Why ship this alongside Docker?
  - Podman is rootless out-of-the-box; common on locked-down CI hosts
    where Docker requires sudo/socket access.
  - Same CLI flags, near-zero porting cost.
  - Lets users keep one ``[sandbox]`` knob (``backend = "podman"``)
    and still get container isolation.

Config::

    [sandbox]
    backend = "podman"
    image = "python:3.12-slim"
    workdir = "/tmp/maverick"
    timeout = 60
    allow_network = false

Same loud-fallback contract as Docker: missing podman binary or
``podman version`` failure raises ``RuntimeError`` so the wizard's
smoke test catches it before the agent runs.
"""
from __future__ import annotations

import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .container_cleanup import CLEANUP_SECONDS, ContainerCleanup, cleanup_container
from .lease import BackendLease, operation_lease
from .local import ExecResult, container_user_args, scrub_env

log = logging.getLogger(__name__)


@dataclass
class PodmanBackend:
    workdir: Path
    image: str = "python:3.12-slim"
    timeout: float = 60.0
    allow_network: bool = False
    # Fork-bomb guard; generous enough for real builds. 0/None disables.
    pids_limit: int | None = 512
    # Bound host RAM so a runaway / prompt-injected process can't exhaust it
    # and trip the kernel OOM-killer. CPU is uncapped by default (the per-exec
    # ``timeout`` already bounds a busy-loop); ``cpus`` exposes the knob. A
    # falsy value ("" / None) disables either cap.
    memory: str | None = "4g"
    cpus: str | None = None
    # Run as the invoking user (uid:gid) by default instead of root, matching
    # DevcontainerBackend. Set ``[sandbox] allow_root = true`` (or
    # MAVERICK_SANDBOX_ALLOW_ROOT) to keep root for images that require it.
    # (Rootless podman maps container-uid 0 to the host user already; with
    # ``--user`` it also needs ``--userns=keep-id``, see ``_user_args``.)
    allow_root: bool = False
    pending_cleanup: dict[str, ContainerCleanup] = field(default_factory=dict, init=False, repr=False)
    _pool_lease: BackendLease = field(default_factory=BackendLease, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._verify_podman()

    def _verify_podman(self) -> None:
        try:
            subprocess.run(
                ["podman", "version"],
                capture_output=True, timeout=5, check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(
                "Podman not available. Install podman, or change "
                "[sandbox] backend to 'local' / 'docker' in "
                "~/.maverick/config.toml."
            ) from e

    def _user_args(self) -> list[str]:
        """``--user uid:gid``, plus ``--userns=keep-id`` under rootless podman.

        Rootless podman maps container uid N to a subordinate host uid, which
        does not own the bind-mounted workspace, so every write failed.
        ``keep-id`` maps the invoking user to the same uid inside.
        """
        args = container_user_args(self.allow_root)
        geteuid = getattr(os, "geteuid", None)
        if args and geteuid is not None and geteuid() != 0:
            args = ["--userns=keep-id", *args]
        return args

    def exec(self, cmd: str, timeout: float | None = None) -> ExecResult:
        with operation_lease(self):
            return self._exec_owned(cmd, timeout)

    def _exec_owned(self, cmd: str, timeout: float | None = None) -> ExecResult:
        if getattr(self, "pending_cleanup", {}):
            self.close()
            if self.pending_cleanup:
                raise RuntimeError("previous sandbox container cleanup is unresolved")
        from .workspace_guard import validate_container_workspace
        validate_container_workspace(self.workdir)
        effective = self.timeout if timeout is None else timeout
        container_name = f"maverick-sandbox-{uuid.uuid4().hex}"
        # `:Z` relabels the SELinux context for the mount so rootless
        # podman on Fedora / RHEL can read+write the workspace.
        args = [
            "podman", "run", "--rm",
            "--name", container_name,
            "-v", f"{self.workdir.resolve()}:/workspace:Z",
            "-w", "/workspace",
            # Containment for a possibly prompt-injected agent: drop all
            # capabilities + block privilege escalation. Harmless to
            # pip/npm/pytest, which need no capabilities.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            *self._user_args(),
        ]
        if self.pids_limit:
            args.extend(["--pids-limit", str(self.pids_limit)])
        if self.memory:
            # Pin --memory-swap to --memory so the cap can't be sidestepped via
            # swap, keeping the RAM bound real.
            args.extend(["--memory", str(self.memory),
                         "--memory-swap", str(self.memory)])
        if self.cpus:
            args.extend(["--cpus", str(self.cpus)])
        if not self.allow_network:
            args.extend(["--network", "none"])
        args.extend([self.image, "sh", "-c", cmd])

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=effective,
                env=scrub_env(),
            )
            return ExecResult(
                stdout=result.stdout[-8000:],
                stderr=result.stderr[-2000:],
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired as e:
            # The timeout killed our local `podman run` client, not the
            # container -- reap it by name. Surface a cleanup failure in stderr
            # instead of swallowing it under a bare except.
            cleanup_note = self._cleanup_owned(container_name).note
            stdout = e.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return ExecResult(
                stdout=stdout[-8000:],
                stderr=f"TIMEOUT after {effective}s{cleanup_note}",
                exit_code=124,
            )

    def _cleanup_owned(self, name: str, timeout: float = CLEANUP_SECONDS) -> ContainerCleanup:
        cleanup = cleanup_container(name, "podman", timeout=timeout)
        if not hasattr(self, "pending_cleanup"):
            self.pending_cleanup = {}
        if cleanup.removed:
            self.pending_cleanup.pop(name, None)
        else:
            self.pending_cleanup[name] = cleanup
            log.warning("sandbox%s", cleanup.note)
        return cleanup

    def close(self) -> None:
        with operation_lease(self, cleanup=True):
            self._close_owned()

    def _close_owned(self) -> None:
        deadline = time.monotonic() + CLEANUP_SECONDS
        for name in sorted(getattr(self, "pending_cleanup", {})):
            self._cleanup_owned(name, max(0.0, deadline - time.monotonic()))
