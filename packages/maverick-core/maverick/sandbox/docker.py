"""Docker sandbox backend.

Each exec spawns a fresh container with the workspace mounted; the
container is removed on exit (``--rm``). Network is disabled by
default (``--network=none``); enable via ``allow_network=True`` if a
specific run needs it.

Fresh containers are the default. Opt-in ``reuse_container`` keeps a guest
within one run; failed cleanup prevents another execution until reconciled.

Falls back loudly: if Docker isn't installed or the daemon isn't
running, ``DockerBackend.__init__`` raises ``RuntimeError`` so the
wizard's smoke test catches it before the agent runs.
"""
from __future__ import annotations

import logging
import math
import shlex
import subprocess
import threading
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path

from .container_cleanup import CLEANUP_SECONDS, ContainerCleanup, cleanup_container
from .lease import BackendLease, operation_lease
from .local import ExecResult, container_user_args, scrub_env

log = logging.getLogger(__name__)


def _kill_container(name: str, engine: str = "docker") -> str:
    """Compatibility renderer for callers that consume a stderr note."""
    return cleanup_container(name, engine).note


class ReadOnlyPathChanged(ValueError):
    """A protected path changed in a way that could unprotect the original."""

    def __init__(self, relative: str, what: str) -> None:
        super().__init__(
            f"read_only_paths entry {relative!r} {what} since the task started, so "
            "the command was not run. Restart the task to re-read the protected paths."
        )


def _identity(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino)


def _ancestor_identities(workspace: Path, path: Path) -> tuple[tuple[int, int], ...]:
    """(device, inode) of the workspace and of each folder down to ``path``'s parent."""
    node = workspace
    chain = [_identity(node)]
    for part in path.relative_to(workspace).parts[:-1]:
        node = node / part
        chain.append(_identity(node))
    return tuple(chain)


@dataclass
class DockerBackend:
    workdir: Path
    image: str = "python:3.12-slim"
    timeout: float = 60.0
    allow_network: bool = False
    # Fork-bomb guard. Generous enough for real builds (pip/npm/pytest
    # spawn plenty of children) while still bounding a runaway agent.
    # Set to 0/None to disable (not recommended).
    pids_limit: int | None = 512
    # Bound host RAM so a runaway / prompt-injected process can't exhaust it
    # and trip the kernel OOM-killer (which can take down unrelated host
    # processes). CPU is left uncapped by default -- the per-exec ``timeout``
    # already bounds a busy-loop -- but ``cpus`` exposes the knob. A falsy
    # value ("" / None) disables either cap.
    memory: str | None = "4g"
    cpus: str | None = None
    # Run as the invoking user (uid:gid) by default instead of root, matching
    # DevcontainerBackend -- root in the container owns the writable
    # ``-v {workdir}:/workspace`` mount on the host. Set
    # ``[sandbox] allow_root = true`` (or MAVERICK_SANDBOX_ALLOW_ROOT) to keep
    # root for images that require it.
    allow_root: bool = False
    # Container runtime (``docker run --runtime``). None = Docker's default
    # (runc). Set to ``runsc`` for the **gVisor** application kernel, which
    # interposes a userspace kernel between the container and the host —
    # stronger isolation for a possibly prompt-injected agent than seccomp +
    # caps alone. The ``gvisor`` backend wires this in; the runtime must be
    # installed and registered with the Docker daemon.
    runtime: str | None = None
    # Warm-container reuse (the "sandbox pool" perf win): instead of a fresh
    # ``docker run --rm`` per command (a cold start every time), keep ONE
    # container alive and ``docker exec`` into it, so the 2nd..Nth command in a
    # run skip container startup. Opt-in (``[sandbox] reuse_container``); the
    # container is torn down on ``close()``. Default off -> run-per-command.
    reuse_container: bool = False
    # Workspace-relative files/directories that model-driven commands may read
    # but must not mutate. Each is overlaid as a separate read-only bind mount
    # inside /workspace. Paths are resolved beneath ``workdir`` at construction
    # time; absolute paths, escapes, and symlinks outside the workspace fail
    # closed. In-process filesystem tools enforce the same list at the agent
    # dispatch chokepoint.
    read_only_paths: tuple[str, ...] = ()
    pending_cleanup: dict[str, ContainerCleanup] = field(default_factory=dict, init=False, repr=False)
    _pool_lease: BackendLease = field(default_factory=BackendLease, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        if isinstance(self.read_only_paths, (str, bytes)) or not isinstance(
            self.read_only_paths, (list, tuple)
        ):
            raise ValueError("read_only_paths must be a list of relative paths")
        workspace = self.workdir.resolve()
        validated: list[tuple] = []
        normalized: list[str] = []
        for raw in self.read_only_paths:
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("read_only_paths entries must be non-empty strings")
            relative = Path(raw)
            if relative.is_absolute():
                raise ValueError("read_only_paths entries must be workspace-relative")
            try:
                source = (workspace / relative).resolve(strict=True)
                contained = source.relative_to(workspace)
            except (OSError, ValueError) as exc:
                raise ValueError(
                    f"read_only_paths entry escapes or is missing: {raw!r}"
                ) from exc
            validated.append(
                (source, f"/workspace/{contained.as_posix()}", _identity(source),
                 _ancestor_identities(workspace, source))
            )
            normalized.append(contained.as_posix())
        self.read_only_paths = tuple(normalized)
        self._read_only_mounts = tuple(validated)
        self._warm_name: str | None = None
        if self.reuse_container:
            # Cold backends retain the exact state accepted by the pool's
            # policy handoff; warm guests are never eligible for that pool.
            self._warm_lock = threading.RLock()
        self._verify_docker()

    def _verify_docker(self) -> None:
        try:
            subprocess.run(
                ["docker", "version"],
                capture_output=True, timeout=5, check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(
                "Docker not available. Install Docker Desktop / docker.io, or "
                "change [sandbox] backend to 'local' in ~/.maverick/config.toml."
            ) from e

    def _container_flags(self) -> list[str]:
        """The run/create flags shared by the cold and warm paths."""
        from .workspace_guard import validate_container_workspace
        validate_container_workspace(self.workdir)
        flags = [
            "-v", f"{self.workdir.resolve()}:/workspace",
            "-w", "/workspace",
            # Containment for a possibly prompt-injected agent: drop every
            # Linux capability and block privilege escalation (setuid/setgid
            # binaries can't gain more than they start with). Neither breaks
            # pip/npm/pytest, which need no capabilities.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            *container_user_args(self.allow_root),
        ]
        # ``_read_only_mounts`` is derived by ``__post_init__``.  Keep this
        # helper tolerant of legacy/unpickled instances (and focused timeout
        # tests) that predate that private cache; the public default is no
        # read-only overlays, so an absent cache is equivalent to ``()``.
        mounts = getattr(self, "_read_only_mounts", ())
        if mounts:
            self._read_only_mounts = tuple(self._recheck_read_only_mount(entry) for entry in mounts)
        for entry in mounts:
            flags.extend(["-v", f"{entry[0]}:{entry[1]}:ro"])
        if self.runtime:
            flags.extend(["--runtime", str(self.runtime)])
        if self.pids_limit:
            flags.extend(["--pids-limit", str(self.pids_limit)])
        if self.memory:
            # Pin --memory-swap to --memory so the cap can't be sidestepped via
            # swap (default: swap == 2x memory), keeping the RAM bound real.
            flags.extend(["--memory", str(self.memory),
                          "--memory-swap", str(self.memory)])
        if self.cpus:
            flags.extend(["--cpus", str(self.cpus)])
        if not self.allow_network:
            flags.extend(["--network", "none"])
        return flags

    def _recheck_read_only_mount(self, entry: tuple) -> tuple:
        """Refuse when a protected path was moved or relinked; return the entry.

        A command can rename a folder that contains a protected path and
        create a new one in its place. Mounting the stored host path again
        would protect the replacement and leave the renamed original writable,
        and a symlink in its place would mount a host path. So the resolved
        path and the identity of every folder from the workspace down to the
        protected path's parent must be unchanged.

        The protected path's OWN inode may change: an editor save (write a
        temporary file, then rename it over the original) or a host-side
        ``git checkout`` does that. Inside the container the protected path is
        a read-only bind mount, and a mount point cannot be renamed or unlinked
        from inside (EBUSY), so with its path and every parent unchanged an
        in-place replacement can only have come from the host side. Its new
        identity is recorded and the run continues.
        """
        source, destination = Path(entry[0]), entry[1]
        ancestors = entry[3] if len(entry) > 3 else None
        workspace = self.workdir.resolve()
        relative = destination[len("/workspace/"):]
        try:
            current = (workspace / relative).resolve(strict=True)
            current.relative_to(workspace)
            current_ancestors = _ancestor_identities(workspace, current)
            identity = _identity(current)
        except (OSError, ValueError) as exc:
            raise ReadOnlyPathChanged(relative, "was moved or removed") from exc
        if current != source:
            raise ReadOnlyPathChanged(relative, "was replaced by a link or moved")
        if ancestors is not None and current_ancestors != ancestors:
            raise ReadOnlyPathChanged(relative, "is inside a folder that was moved or replaced")
        return (source, destination, identity, current_ancestors)

    def exec(self, cmd: str, timeout: float | None = None) -> ExecResult:
        # The warm wrapper reaps every other guest process, so its full
        # lifecycle (including startup and pending cleanup) must be exclusive.
        with operation_lease(self), self._warm_lock if self.reuse_container else nullcontext():
            try:
                return self._exec_owned(cmd, timeout)
            except ReadOnlyPathChanged as exc:
                # An ordinary failed command (nothing ran), so the shell tool
                # reports it to the agent instead of raising out of the turn.
                return ExecResult(stdout="", stderr=str(exc), exit_code=126)

    def _exec_owned(self, cmd: str, timeout: float | None = None) -> ExecResult:
        if getattr(self, "pending_cleanup", {}):
            self.close()
            if self.pending_cleanup:
                raise RuntimeError("previous sandbox container cleanup is unresolved")
        from .workspace_guard import validate_container_workspace
        validate_container_workspace(self.workdir)
        # Per-call `timeout` matches LocalBackend so the shell
        # tool can plumb a longer cap for pytest/npm test/etc. Falls
        # back to self.timeout (default 60 s).
        effective = self.timeout if timeout is None else timeout
        if not math.isfinite(effective) or effective <= 0:
            return ExecResult(stdout="", stderr="Invalid Docker command timeout", exit_code=1)
        if self.reuse_container:
            return self._exec_warm(cmd, effective)
        container_name = f"maverick-sandbox-{uuid.uuid4().hex}"
        args = [
            "docker", "run", "--rm",
            "--name", container_name,
            *self._container_flags(),
        ]
        # A daemon-side deadline still runs if the harness or CLI disappears.
        # Missing timeout in the image fails closed before the command starts.
        args.extend([self.image, "timeout", "-s", "KILL",
                     f"{max(effective, 0.001):.6f}s", "sh", "-c", cmd])

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
            # The timeout killed our local `docker run` client, not the daemon
            # container -- which keeps running (and holding the workspace mount)
            # until reaped. Force-remove it by name. Surface a cleanup failure
            # in stderr instead of swallowing it under a bare except: a leaked
            # container is a real condition the operator should see.
            cleanup_note = self._cleanup_owned(container_name).note
            stdout = e.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return ExecResult(
                stdout=stdout[-8000:],
                stderr=f"TIMEOUT after {effective}s{cleanup_note}",
                exit_code=124,
            )

    # -- warm-container reuse ("sandbox pool") ----------------------------

    def _ensure_warm(self) -> None:
        """Start the persistent container once; subsequent calls reuse it."""
        if self._warm_name is not None:
            return
        name = f"maverick-warm-{uuid.uuid4().hex}"
        args = ["docker", "run", "-d", "--name", name,
                *self._container_flags(),
                self.image, "sleep", "infinity"]
        # A failed `docker run -d` (bad image/tag, registry-auth failure, daemon
        # error) must not leave _warm_name set: _ensure_warm short-circuits on it,
        # so a swallowed failure here would permanently wedge the backend, with
        # every later `docker exec` failing with a confusing "No such container".
        # Fail loudly with the daemon's stderr instead. A timed-out start is the
        # same: don't record a half-started container as ready.
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=self.timeout, env=scrub_env())
        except subprocess.TimeoutExpired as e:
            cleanup = self._cleanup_owned(name)
            raise RuntimeError(
                f"warm container start timed out after {self.timeout}s{cleanup.note}") from e
        if proc.returncode != 0:
            cleanup = self._cleanup_owned(name)
            raise RuntimeError(
                f"warm container start failed (exit {proc.returncode}): "
                f"{(proc.stderr or '').strip()[-500:]}{cleanup.note}")
        self._warm_name = name

    def _exec_warm(self, cmd: str, effective: float) -> ExecResult:
        self._ensure_warm()
        args = ["docker", "exec", self._warm_name, "sh", "-c",
                self._warm_command(cmd)]
        try:
            result = subprocess.run(args, capture_output=True, text=True, errors="replace",
                                    timeout=effective, env=scrub_env())
            return ExecResult(
                stdout=result.stdout[-8000:],
                stderr=result.stderr[-2000:],
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired as e:
            # A timed-out `docker exec` can leave daemon-side children running
            # inside the warm container. Reap the container, just like the cold
            # path does, so no command can outlive its timeout/budget boundary.
            cleanup = self._cleanup_owned(self._warm_name)
            self._warm_name = None  # the timed-out guest is never reusable
            stdout = e.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            return ExecResult(stdout=stdout[-8000:],
                              stderr=f"TIMEOUT after {effective}s{cleanup.note}", exit_code=124)

    def _warm_command(self, cmd: str) -> str:
        """Run a command, then reap any processes it left behind.

        Warm containers intentionally keep filesystem/package state across
        execs, but shell background jobs must not survive a tool call. Docker
        does not provide a per-exec process cleanup primitive, so the wrapper
        runs the requested command in a child shell, preserves its exit status,
        then terminates every other container process except PID 1 and the
        wrapper itself. If the exec times out before reaching this cleanup,
        `_exec_warm` removes the whole container.
        """
        return "\n".join([
            f"sh -c {shlex.quote(cmd)} &",
            "child=$!",
            "wait $child",
            "rc=$?",
            "for proc in /proc/[0-9]*; do",
            "  pid=${proc##*/}",
            "  [ \"$pid\" = 1 ] && continue",
            "  [ \"$pid\" = \"$$\" ] && continue",
            "  kill -TERM \"$pid\" 2>/dev/null || true",
            "done",
            "sleep 0.2",
            "for proc in /proc/[0-9]*; do",
            "  pid=${proc##*/}",
            "  [ \"$pid\" = 1 ] && continue",
            "  [ \"$pid\" = \"$$\" ] && continue",
            "  kill -KILL \"$pid\" 2>/dev/null || true",
            "done",
            "exit $rc",
        ])

    def _cleanup_owned(self, name: str, timeout: float = CLEANUP_SECONDS) -> ContainerCleanup:
        cleanup = cleanup_container(name, timeout=timeout)
        # Legacy/unpickled instances may predate this field.
        if not hasattr(self, "pending_cleanup"):
            self.pending_cleanup = {}
        if cleanup.removed:
            self.pending_cleanup.pop(name, None)
        else:
            self.pending_cleanup[name] = cleanup
            log.warning("sandbox%s", cleanup.note)
        return cleanup

    def close(self) -> None:
        """Drain owned cleanup against one deadline; retain unresolved identities."""
        with operation_lease(self, cleanup=True), self._warm_lock if self.reuse_container else nullcontext():
            self._close_owned()

    def _close_owned(self) -> None:
        names = set(getattr(self, "pending_cleanup", {}))
        if self._warm_name is not None:
            names.add(self._warm_name)
            self._warm_name = None
        deadline = time.monotonic() + CLEANUP_SECONDS
        for name in sorted(names):
            self._cleanup_owned(name, max(0.0, deadline - time.monotonic()))
