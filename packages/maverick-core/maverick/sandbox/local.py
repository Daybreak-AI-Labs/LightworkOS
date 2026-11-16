"""Local subprocess backend.

The Backend interface is intentionally tiny: every backend exposes `exec(cmd)`.
That's the abstraction Hermes' 7 backends collapse to. Start simple.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# Names matching this pattern are stripped from the child shell's env.
# Catches STRIPE_API_KEY, PLAID_SECRET, CLOUDFLARE_API_TOKEN,
# AWS_SECRET_ACCESS_KEY / AWS_ACCESS_KEY_ID / AWS_SESSION_TOKEN,
# *_PASSWORD, *_CREDENTIAL, header blobs that may carry auth values
# (MAVERICK_OTEL_HEADERS, OTEL_EXPORTER_OTLP_HEADERS), plus connection
# strings that embed creds (DATABASE_URL, SENTRY_DSN, MONGO_URI,
# REDIS_URL, *_OAUTH, *_BEARER). KEK/DEK: the tenant envelope-encryption key
# material read by tenant/kms.py (MAVERICK_KMS_KEK) -- neither substring is
# covered by KEY/SECRET/CREDENTIAL above (this key wraps every tenant's DEK,
# so leaking it into a sandboxed shell is a full data-at-rest compromise).
# Short secret suffixes (MYSQL_PWD, DB_PASS, GITHUB_PAT, STRIPE_SK, ...) need the
# underscore so PWD, OLDPWD and PATH are kept; *_TO_PASS names test ids.
# PRIVATE/SIGNING alone are not secrets (GOPRIVATE, CODESIGNING_IDENTITY);
# *_PRIVATE_KEY and *_SIGNING_KEY are covered by KEY.
_SECRET_ENV_RE = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|APIKEY|DSN|URI|URL|CONN"
    r"|OAUTH|BEARER|HEADER|NETRC|COOKIE|AUTH|KEK|DEK|PASSCOMMAND"
    r"|MNEMONIC|_(?:PWD|PAT|SK|SALT|PEM|SIGNING)$|(?<!_TO)_PASS$)",
    re.IGNORECASE,
)
# Stripped explicitly even though the pattern already covers them — kept
# as a readable record of the provider creds we never want in the shell.
_ALWAYS_STRIP_ENV = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    # The tenant KMS key-encryption-key (kms.py) -- also covered by the KEK
    # alternative above, but kept explicit as this codebase's convention for
    # its most sensitive secrets.
    "MAVERICK_KMS_KEK",
    # GitHub Actions command files are a cross-step code-injection surface.
    # A model-driven child that appends to GITHUB_PATH/GITHUB_ENV can alter the
    # trusted step that follows it even when ordinary credentials are scrubbed.
    "GITHUB_ENV",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
    # The SWE-bench gold patch: "GOLD_PATCH" matches no secret keyword in
    # _SECRET_ENV_RE, so without this a `printenv` in a non-opaque child leaks
    # the benchmark answer. shell.py only popped it for opaque runs.
    "MAVERICK_GOLD_PATCH",
)


# Git reads env-based config injection as an ATOMIC protocol: GIT_CONFIG_COUNT=N
# declares exactly N (GIT_CONFIG_KEY_i, GIT_CONFIG_VALUE_i) pairs. Used widely by
# CI/dev hosts (GitHub Actions, Codespaces, devcontainers) for url.insteadOf
# credential rewriting. Tracked separately because _SECRET_ENV_RE strips the
# KEY_* members (they match "KEY") but NOT COUNT/VALUE_*, which would leave git a
# dangling COUNT and abort every command with "missing config key
# GIT_CONFIG_KEY_0" (exit 128). The family must be kept all-or-nothing.
_GIT_CONFIG_INJECT_RE = re.compile(r"^GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+)$")

_TRUE = {"1", "true", "yes", "on"}
_CREATE_SUSPENDED = 0x00000004


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE


def container_user_args(allow_root: bool = False) -> list[str]:
    """Return ``["--user", "uid:gid"]`` for non-root container execution.

    Containers default to running as root; against a writable host mount that
    lets a prompt-injected agent write root-owned files (or worse) on the host.
    Drop to the invoking user's uid/gid -- matching ``DevcontainerBackend`` --
    unless the operator opts back into root via ``[sandbox] allow_root = true``
    or ``MAVERICK_SANDBOX_ALLOW_ROOT`` (truthy).

    ``os.getuid``/``os.getgid`` are POSIX-only (absent on Windows); there is no
    uid/gid mapping to pin there, so fall back to no ``--user`` flag and let the
    container engine's own user handling apply.
    """
    if allow_root or _truthy(os.environ.get("MAVERICK_SANDBOX_ALLOW_ROOT")):
        return []
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        return []
    return ["--user", f"{getuid()}:{getgid()}"]


def _contained(env: dict) -> dict:
    """Containment mode with no network, or a network policy that keeps the
    work area offline: point the proxy variables that host programs honour at
    a dead end (best effort; the tool ACL and container backends carry the
    hard guarantee)."""
    from ..containment import active_profile, assert_no_network_env
    from .network_policy import work_area_offline

    profile = active_profile()
    if (profile is not None and profile.no_network) or work_area_offline():
        return assert_no_network_env(env)
    return env


def scrub_env(source: dict | None = None) -> dict:
    """Return a copy of the environment with secrets removed.

    The default LocalBackend runs model-driven shell commands on the host,
    so a prompt-injected agent can ``printenv`` / ``echo $STRIPE_API_KEY``
    and the value lands in stdout -> back to the model -> out via any
    channel. The tool suite reads dozens of secret vars, so this strips by
    name pattern and new credentials are covered by default
    (deny-by-pattern, not an ad-hoc name list). Tools that legitimately need a credential run in-process
    (Python), not through this shell, so aggressive stripping is safe.
    """
    src = os.environ if source is None else source
    out: dict = {}
    for k, v in src.items():
        if k.upper() in _ALWAYS_STRIP_ENV or _SECRET_ENV_RE.search(k):
            continue
        out[k] = v
    # Keep git's COUNT/KEY_*/VALUE_* config-injection family all-or-nothing: if
    # the secret filter dropped any member (it strips KEY_* but not COUNT/VALUE_*),
    # the survivors form a corrupt injection that aborts every git command with
    # exit 128. Drop the whole family so git cleanly falls back to file config.
    git_family = {k for k in src if _GIT_CONFIG_INJECT_RE.match(k)}
    if git_family - out.keys():  # at least one member was scrubbed
        for k in git_family:
            out.pop(k, None)
    # PYTHONNOUSERSITE is a HARNESS-process hardening knob (the deploy image
    # sets it so a model-driven `pip install --user` can't shadow modules the
    # harness later imports). It must not leak into the agent's own shell:
    # there the agent legitimately `pip install --user`s a package and then
    # runs a script that imports it — inheriting the knob would break that
    # with no visible cause. Dropping an env var here protects nothing anyway
    # (the child could always re-set its own env); the import-path boundary
    # being defended is the harness process, whose env this never touches.
    out.pop("PYTHONNOUSERSITE", None)
    return out


_PR_SET_DUMPABLE = 4
_PR_GET_DUMPABLE = 3
_environ_hidden = False


def _hide_harness_environ() -> None:
    """Make this process non-dumpable so ``/proc/<pid>/environ`` (and the rest
    of ``/proc/<pid>/``) is owned by root and unreadable by a same-uid child.

    :func:`scrub_env` shapes only the child's environment; the child still runs
    as the harness user, and the harness's exec-time environment (where the
    deployment puts provider keys) stays readable through ``/proc/$PPID/environ``
    until the process is marked non-dumpable. Linux only; a no-op elsewhere and
    when prctl is unavailable. Side effect: no core dumps and no same-user
    ptrace of the harness, which is the intended posture.
    """
    global _environ_hidden
    if _environ_hidden or sys.platform != "linux":
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
            _environ_hidden = True
    except (OSError, AttributeError):  # pragma: no cover -- no libc / no prctl
        return


def _harness_environ_hidden() -> bool:
    """True when prctl reports this process as non-dumpable (Linux)."""
    if sys.platform != "linux":
        return False
    try:
        import ctypes

        return ctypes.CDLL(None).prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):  # pragma: no cover
        return False


# Every LocalBackend child carries this marker in its environment, so a
# descendant that left the process group (setsid) can still be found.
_RUN_MARKER_ENV = "MAVERICK_SANDBOX_RUN"


def _reap_marked(marker: str, env: str = _RUN_MARKER_ENV) -> None:
    """Kill processes that still carry this run's marker (Linux ``/proc``).

    Used only when a command timed out or was cancelled, or when a contained
    step ends (:func:`contained_step`); after a normal exit, deliberately
    detached processes (a server the person started) are otherwise kept.

    Best effort: a child that also clears its environment is not found."""
    needle = f"{env}={marker}".encode()
    for _ in range(3):  # a survivor may fork while it is being reaped
        found = False
        try:
            entries = [e.name for e in os.scandir("/proc") if e.name.isdigit()]
        except OSError:
            return
        for name in entries:
            try:
                with open(f"/proc/{name}/environ", "rb") as stream:
                    environ = stream.read().split(b"\0")
            except OSError:
                continue
            if needle in environ and int(name) != os.getpid():
                found = True
                try:
                    os.kill(int(name), signal.SIGKILL)
                except OSError:
                    pass
        if not found:
            return


# A contained step (a code feature run's test run, checker look or author
# round) can span many commands. Every command a LocalBackend runs inside the
# step's folder also carries the step's marker, so the step's end stops all
# it started, detached (setsid) or not, before the next step's folder exists.
_STEP_MARKER_ENV = "MAVERICK_SANDBOX_STEP"
_STEPS: dict[str, str] = {}
_STEPS_LOCK = threading.Lock()


def _step_for(workdir: object) -> tuple[str, str] | None:
    """The contained step (its root folder, its marker) ``workdir`` is in."""
    path = os.path.realpath(str(workdir))
    with _STEPS_LOCK:
        for root, marker in _STEPS.items():
            if path == root or path.startswith(root + os.sep):
                return root, marker
    return None


# Where Linux allows unprivileged user namespaces, each command of a contained
# step runs in its own user, PID and mount namespace. When the command's first
# process exits, the kernel kills every process in it, whatever its session or
# environment (the marker reap cannot find a process that cleared its
# environment). The temporary folder is replaced by an empty private one with
# only the step's own folder mounted back, so a command cannot list or reach
# other rounds' or other proposals' copies. Files elsewhere and the network
# are shared as before: this is not a container.
_NS_PRELUDE = r"""set -e
tmproot=$1 step=$2 wd=$3
shift 3
if [ -n "$tmproot" ]; then
  exec 3<"$step"
  mount -t tmpfs -o mode=0700 lwstep "$tmproot"
  mkdir -p "$step"
  mount --no-canonicalize --bind /proc/self/fd/3 "$step"
  exec 3<&-
fi
cd "$wd"
exec "$@"
"""
_NS_AVAILABLE: list[bool] = []


def _in_step_namespace(cmd: str | list[str], root: str, workdir: object) -> list[str]:
    import shutil
    import tempfile

    tmproot = os.path.realpath(tempfile.gettempdir())
    overlay = tmproot if root.startswith(tmproot + os.sep) else ""
    inner = ["/bin/sh", "-c", cmd] if isinstance(cmd, str) else list(cmd)
    return [shutil.which("unshare") or "unshare", "--user", "--map-root-user", "--pid",
            "--fork", "--kill-child", "--mount", "--propagation", "private", "--mount-proc",
            "/bin/sh", "-c", _NS_PRELUDE, "lw-step", overlay, root, str(workdir), *inner]


def step_namespaces_available() -> bool:
    """Whether contained steps can run in their own namespaces here: Linux,
    ``unshare`` on PATH and user namespaces allowed. Probed once per process
    by running the real wrapper (the same detection idea as the document
    worker's ``unshare -rn`` probe)."""
    import shutil
    import tempfile

    if not _NS_AVAILABLE:
        ok = False
        if sys.platform.startswith("linux") and shutil.which("unshare"):
            with tempfile.TemporaryDirectory(prefix="lw-nsprobe-") as probe:
                root = os.path.realpath(probe)
                Path(root, "mounted").touch()  # proves the step folder is mounted back
                try:
                    ok = subprocess.run(_in_step_namespace(["test", "-f", "mounted"], root, root),
                                        capture_output=True, timeout=10,
                                        check=False).returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    ok = False
        _NS_AVAILABLE.append(ok)
    return _NS_AVAILABLE[0]


@contextmanager
def contained_step(root: str | Path) -> Iterator[None]:
    """Stop every process a command under ``root`` started, once the block ends."""
    marker = uuid.uuid4().hex
    key = os.path.realpath(str(root))
    with _STEPS_LOCK:
        _STEPS[key] = marker
    try:
        yield
    finally:
        with _STEPS_LOCK:
            _STEPS.pop(key, None)
        _reap_marked(marker, _STEP_MARKER_ENV)


def _reap_process_group(proc: subprocess.Popen, marker: str | None = None) -> None:
    """Best-effort POSIX cleanup for descendants that outlive the shell."""
    killpg = getattr(os, "killpg", None)
    if killpg is None:  # pragma: no cover -- Windows has no POSIX process groups
        return
    try:
        # start_new_session=True makes the direct child's pid its process-group
        # id. A redirected `nohup ... &` can survive communicate() unless the
        # group is explicitly reaped even after an otherwise successful command.
        killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    if marker is not None:
        _reap_marked(marker)


def _create_windows_kill_job(proc: subprocess.Popen) -> int | None:
    """Atomically contain a Windows subprocess tree in a kill-on-close Job.

    ``taskkill /T`` loses the tree once a short-lived shell exits. Start the
    shell suspended, assign it to a Job Object whose descendants inherit
    membership, then resume it. Closing the job handle after success or timeout
    deterministically terminates every surviving descendant.
    """
    if os.name != "nt":
        return None

    import ctypes
    from ctypes import wintypes

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    create_job.restype = wintypes.HANDLE
    set_job = kernel32.SetInformationJobObject
    set_job.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    set_job.restype = wintypes.BOOL
    assign_job = kernel32.AssignProcessToJobObject
    assign_job.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_job.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    job = create_job(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = 0x00002000
        if not set_job(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        process_handle = wintypes.HANDLE(int(proc._handle))  # type: ignore[attr-defined]
        if not assign_job(job, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())

        # Popen intentionally starts this Windows child suspended so assignment
        # has no race. Python retains the process handle but closes the primary
        # thread handle, so resume the contained process through ntdll.
        ntdll = ctypes.WinDLL("ntdll")
        resume_process = ntdll.NtResumeProcess
        resume_process.argtypes = (wintypes.HANDLE,)
        resume_process.restype = ctypes.c_long
        status = resume_process(process_handle)
        if status != 0:
            raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
        return int(job)
    except BaseException:  # failure-policy: fail_closed -- close job and re-raise
        close_handle(job)
        raise


def _close_windows_kill_job(job: int | None) -> None:
    """Close a Windows Job Object, terminating every associated process.

    The job does not permit breakaway, so its kill-on-close limit is the
    authoritative tree boundary. Do not supplement it with PID snapshots:
    process identifiers can be recycled between enumeration and termination.
    """
    if os.name != "nt" or job is None:
        return
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(job)):
        raise ctypes.WinError(ctypes.get_last_error())


STDOUT_LIMIT = 8000
STDERR_LIMIT = 2000
# Bytes kept from the end of each stream while it is read: enough for the
# last STDOUT_LIMIT characters at up to 4 UTF-8 bytes each, with margin.
_KEEP_BYTES = 64 * 1024


class _Tail:
    """The last ``_KEEP_BYTES`` of a stream, so memory stays bounded."""

    def __init__(self) -> None:
        self.data = bytearray()

    def feed(self, chunk: bytes) -> None:
        self.data += chunk
        if len(self.data) > _KEEP_BYTES:
            del self.data[:len(self.data) - _KEEP_BYTES]

    def text(self) -> str:
        return bytes(self.data).decode("utf-8", errors="replace")


def _drain(read, tail: _Tail) -> threading.Thread:
    def run() -> None:
        try:
            while chunk := read(65536):
                tail.feed(chunk)
        except (OSError, ValueError):
            pass
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def cap_output(text: str, limit: int = STDOUT_LIMIT) -> str:
    """The last ``limit`` characters, with a visible note when cut."""
    if len(text) <= limit:
        return text
    return f"[output truncated: showing the last {limit:,} characters]\n{text[-limit:]}"


def run_capped(args, *, timeout: float, env=None, cwd=None) -> subprocess.CompletedProcess:
    """``subprocess.run(args, capture_output=True, text=True)`` that keeps only
    the tail of each stream while the command is still writing.

    Raises ``subprocess.TimeoutExpired`` with the captured tail as ``stdout``.
    """
    tails = (_Tail(), _Tail())
    pipes = [os.pipe(), os.pipe()]
    readers = [_drain(lambda n, fd=r: os.read(fd, n), tail)
               for (r, _w), tail in zip(pipes, tails, strict=True)]

    def finish() -> None:
        for _r, w in pipes:
            try:
                os.close(w)
            except OSError:
                pass
        _join_readers(readers, deadline=time.monotonic() + _DRAIN_GRACE_S)
        for (r, _w), reader in zip(pipes, readers, strict=True):
            if not reader.is_alive():  # else a survivor still holds the pipe
                os.close(r)

    try:
        result = subprocess.run(
            args, stdout=pipes[0][1], stderr=pipes[1][1],
            text=True, errors="replace", timeout=timeout, env=env, cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        finish()
        if exc.stdout is None:
            exc.stdout = tails[0].text()
        raise
    except BaseException:  # failure-policy: fail_closed -- close the pipes and re-raise
        finish()
        raise
    finish()
    if not isinstance(result.stdout, str):
        result.stdout = tails[0].text()
    if not isinstance(result.stderr, str):
        result.stderr = tails[1].text()
    return result


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _feed_stdin(proc: subprocess.Popen, text: str) -> None:
    try:
        proc.stdin.write(text.encode("utf-8"))
        proc.stdin.close()
    except (OSError, ValueError):
        pass


# After the command ends (or is killed), all output readers together get at
# most this long to finish; the old communicate() drain had the same bound.
_DRAIN_GRACE_S = 5.0


def _join_readers(readers: list[threading.Thread], *, deadline: float) -> None:
    """Join every reader against ONE shared monotonic deadline."""
    for reader in readers:
        reader.join(timeout=max(0.0, deadline - time.monotonic()))


class LocalBackend:
    # Commands run as a host subprocess against the host filesystem, so files
    # this backend writes ARE visible to the calling (host) process. Container /
    # remote backends leave this False (no such attribute), so output-path
    # verification stays disabled for them. See ``sandbox.fs_is_host_visible``.
    host_visible_fs = True

    def __init__(self, workdir: Path | None = None, timeout: float = 60.0):
        self.workdir = workdir or Path.cwd()
        self.timeout = timeout

    def exec(
        self, cmd: str | list[str], timeout: float | None = None,
        stdin: str | None = None,
    ) -> ExecResult:
        # Per-call `timeout` kwarg lets the test runner override
        # the default 60s (too short for real pytest on SWE-bench
        # instances). Falls back to self.timeout when unset, preserving
        # behaviour for shell-tool callers that pass no timeout.
        # Output is read as bytes while the command runs, keeping only the
        # tail of each stream, and decoded with errors="replace" on return.
        try:
            from ..chaos import maybe_fail
            maybe_fail("sandbox_exec",
                       message=f"chaos: sandbox_exec on {cmd[:40]!r}")
        except ImportError:
            pass
        effective = self.timeout if timeout is None else timeout
        marker = uuid.uuid4().hex
        child_env = {**_contained(scrub_env()), _RUN_MARKER_ENV: marker}
        step = _step_for(self.workdir)
        if step is not None:
            child_env[_STEP_MARKER_ENV] = step[1]
            if os.name != "nt" and step_namespaces_available():
                cmd = _in_step_namespace(cmd, step[0], self.workdir)
        _hide_harness_environ()

        windows_creation_flags = (
            subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED
            if os.name == "nt"
            else 0
        )
        proc = subprocess.Popen(
            cmd,
            # LocalBackend is the intentional unsandboxed host-exec path
            # (CLAUDE.md rule 4 allowlists shell only under sandbox/); env is
            # scrubbed and operators are warned to use a container backend.
            # A list runs directly, avoiding cmd.exe interpolation on Windows.
            shell=isinstance(cmd, str),  # nosec B602
            cwd=str(self.workdir),
            stdin=subprocess.PIPE if stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            # Own session (= new process group) so a timeout can reap the WHOLE
            # tree. subprocess's own timeout SIGKILLs only the direct /bin/sh
            # child; grandchildren (a backgrounded `cmd &`, or even foreground
            # children of a compound list) reparent to init and keep consuming
            # the host after exec() returns 124. Every container backend reaps
            # on timeout; the default local backend must bound the host too.
            start_new_session=os.name != "nt",
            creationflags=windows_creation_flags,
        )
        windows_job: int | None = None
        try:
            try:
                windows_job = _create_windows_kill_job(proc)
            except BaseException:  # failure-policy: fail_closed -- reap child and re-raise
                proc.kill()
                proc.wait(timeout=5)
                raise
            tails = (_Tail(), _Tail())
            readers = [_drain(stream.read1, tail)
                       for stream, tail in zip((proc.stdout, proc.stderr), tails, strict=True)]
            if stdin is not None:
                threading.Thread(target=_feed_stdin, args=(proc, stdin), daemon=True).start()
            # Like communicate(): finish when the pipes close, so a background
            # job that still writes to them is waited for within the timeout.
            deadline = time.monotonic() + effective
            proc.wait(timeout=effective)
            _join_readers(readers, deadline=deadline)
            if any(reader.is_alive() for reader in readers):
                raise subprocess.TimeoutExpired(cmd, effective)
            if os.name == "nt":
                _close_windows_kill_job(windows_job)
                windows_job = None
            else:
                # A normal exit leaves deliberately detached (setsid) processes
                # alone, as before; only the command's own group is reaped.
                _reap_process_group(proc)
            return ExecResult(
                stdout=cap_output(tails[0].text()),
                stderr=cap_output(tails[1].text(), STDERR_LIMIT),
                exit_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            # Kill the whole process group, not just the shell:
            # start_new_session made the child the group leader, so its pid IS
            # the pgid. Fall back to killing the direct child where process
            # groups don't exist (Windows) or the group is already gone.
            try:
                if os.name == "nt":
                    _close_windows_kill_job(windows_job)
                    windows_job = None
                elif getattr(os, "killpg", None) is not None:
                    _reap_process_group(proc, marker)
                else:  # pragma: no cover -- unusual non-POSIX host
                    proc.kill()
            except OSError:
                proc.kill()
            grace = time.monotonic() + _DRAIN_GRACE_S
            try:
                proc.wait(timeout=_DRAIN_GRACE_S)
            except subprocess.TimeoutExpired:
                pass
            # Keep what the (now dead) tree wrote before the kill. Bounded in
            # case the group kill failed and a survivor holds the pipes open.
            _join_readers(readers, deadline=grace)
            return ExecResult(
                stdout=cap_output(tails[0].text()),
                stderr=f"TIMEOUT after {effective}s",
                exit_code=124,
            )
        except BaseException:  # failure-policy: fail_closed -- reap the run, then re-raise
            # Cancelled mid-run (KeyboardInterrupt, a cancelled worker): the
            # command did not finish, so its detached children go with it.
            if os.name != "nt":
                _reap_process_group(proc, marker)
            raise
        finally:
            if windows_job is not None:
                _close_windows_kill_job(windows_job)
