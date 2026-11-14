"""Internal Linux-container primitive for untrusted research candidates.

This is not a submission API or an authenticated evaluator. A trusted caller
supplies bounded bytes, a locally present reviewed image, and a Budget. Nothing
here interprets candidate output as a score or grants production capability.
The Docker daemon and controller host are trusted. No host execution fallback.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from pathlib import Path

from ..budget import Budget

_USER = "65532:65532"
_ENV = ("PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/scratch", "TMPDIR=/scratch",
        "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1")
_MAX_FILES = 256
_MAX_ENTRIES = 4096
_MAX_INPUT = 8 * 1024 * 1024
_SAFE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")


class ResearchContainerError(RuntimeError):
    """The required runtime, immutable input or cleanup boundary failed."""


@dataclass(frozen=True)
class ResearchLimits:
    timeout_seconds: float = 10.0
    output_bytes: int = 64 * 1024
    memory_bytes: int = 128 * 1024 * 1024
    scratch_bytes: int = 16 * 1024 * 1024
    pids: int = 32
    cpus: float = 0.5

    def __post_init__(self):
        bounds = {"timeout_seconds": (0.1, 300), "output_bytes": (1024, 1024 * 1024),
                  "memory_bytes": (32 * 1024 * 1024, 1024 * 1024 * 1024),
                  "scratch_bytes": (1024 * 1024, 256 * 1024 * 1024),
                  "pids": (8, 256), "cpus": (0.1, 2)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not low <= value <= high):
                raise ValueError(f"invalid research limit: {name}")
            if name not in {"timeout_seconds", "cpus"} and type(value) is not int:
                raise ValueError(f"research limit must be an integer: {name}")


@dataclass(frozen=True)
class ResearchResult:
    container_name: str
    image_id: str
    input_sha256: str
    policy_sha256: str
    entrypoint: str
    exit_code: int
    reason: str
    stdout: str
    stderr: str
    captured_bytes: int
    cleanup_verified: bool
    inspect_policy: dict


@dataclass(frozen=True)
class _Capture:
    code: int
    out: bytes
    err: bytes
    reason: str


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _host_environment() -> dict[str, str]:
    # Docker itself needs Windows process/runtime and user context discovery.
    # These values never enter candidate env; DOCKER_HOST/API overrides do not.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME",
               "PROGRAMFILES", "PROGRAMDATA", "LOCALAPPDATA", "APPDATA"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _local_endpoint(endpoint: str) -> bool:
    if type(endpoint) is not str or any(ord(char) < 32 for char in endpoint):
        return False
    return endpoint.startswith("unix:///") or bool(
        re.fullmatch(r"npipe:////\./pipe/[A-Za-z0-9_.-]+", endpoint)
    )


def _capture(args, env, *, timeout, limit, effect_guard=None, cancelled=None) -> _Capture:
    """Drain concurrently; retained bytes are bounded before appending."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ResearchContainerError("process wall budget is exhausted")
    guard = nullcontext() if effect_guard is None else effect_guard()
    with guard:
        process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True)
    buffers = [bytearray(), bytearray()]
    lock, exceeded = threading.Lock(), threading.Event()
    captured = 0

    def drain(stream, target):
        nonlocal captured
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            with lock:
                keep = min(len(chunk), max(0, limit - captured))
                target.extend(chunk[:keep])
                captured += keep
                over = keep < len(chunk)
            if over:
                exceeded.set()
                try:
                    process.kill()
                except OSError:
                    pass
                return

    threads = [threading.Thread(target=drain, args=(stream, target), daemon=True)
               for stream, target in zip((process.stdout, process.stderr), buffers, strict=True)]
    for thread in threads:
        thread.start()
    reason = "completed"
    try:
        if cancelled is None:
            process.wait(timeout=timeout)
        else:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                try:
                    cancellation = cancelled()
                except Exception:
                    # Failure to determine cancellation authority fails closed.
                    cancellation = True
                if cancellation:
                    reason = "cancelled"
                    process.kill()
                    process.wait(timeout=5)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                try:
                    process.wait(timeout=min(0.1, remaining))
                except subprocess.TimeoutExpired:
                    pass
    except subprocess.TimeoutExpired:
        reason = "timeout"
        process.kill()
        process.wait(timeout=5)
    finally:
        for thread in threads:
            thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads):
        raise ResearchContainerError("Docker output pipes did not close")
    process.stdout.close()
    process.stderr.close()
    if exceeded.is_set():
        reason = "output_limit"
    return _Capture(process.returncode, bytes(buffers[0]), bytes(buffers[1]), reason)


def _register_input_path(name: str, nodes: dict[str, tuple[str, str]]) -> None:
    parts = name.split("/")
    for index in range(len(parts)):
        spelling = "/".join(parts[:index + 1])
        node = (spelling, "file" if index == len(parts) - 1 else "directory")
        previous = nodes.get(spelling.casefold())
        if previous is not None and previous != node:
            raise ValueError("candidate paths alias a directory or conflict with a file parent")
        nodes[spelling.casefold()] = node
        if len(nodes) > _MAX_ENTRIES:
            raise ValueError("candidate filesystem entry limit exceeded")


def _inputs(files: Mapping[str, bytes], entrypoint: str) -> dict[str, bytes]:
    if not isinstance(files, Mapping) or not 1 <= len(files) <= _MAX_FILES:
        raise ValueError("candidate requires a bounded file mapping")
    copied, nodes, total = {}, {}, 0
    for name, data in files.items():
        if (type(name) is not str or len(name) > 200 or not _SAFE_PATH.fullmatch(name)
                or any(part in {".", ".."} for part in name.split("/"))
                or type(data) is not bytes):
            raise ValueError("candidate files require unique safe relative paths and bytes")
        # Reject Windows reserved names and trailing-dot aliases even on Linux.
        for part in name.split("/"):
            if (part.endswith(".") or part.split(".")[0].upper() in {
                "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }):
                raise ValueError("candidate path aliases a reserved filename")
        total += len(data)
        if total > _MAX_INPUT:
            raise ValueError("candidate input byte limit exceeded")
        _register_input_path(name, nodes)
        copied[name] = data
    if entrypoint not in copied or not entrypoint.endswith(".py"):
        raise ValueError("entrypoint must name a supplied Python file")
    return copied


def _input_digest(files: Mapping[str, bytes]) -> str:
    return _digest({name: hashlib.sha256(data).hexdigest() for name, data in files.items()})


def _write_snapshot(root: Path, files: Mapping[str, bytes]) -> None:
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o444)
    for directory in root.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o555)
    root.chmod(0o555)


def _snapshot_entries(root: Path) -> list[Path]:
    """Bounded traversal that never follows links or Windows reparse points."""
    paths, pending = [], [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ResearchContainerError("snapshot contains a link or reparse point")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ResearchContainerError("snapshot contains an aliased or special file")
            paths.append(path)
            if len(paths) > _MAX_ENTRIES:
                raise ResearchContainerError("snapshot entry limit exceeded")
    return paths


def _snapshot_matches(root: Path, files: Mapping[str, bytes]) -> bool:
    observed = {}
    for path in _snapshot_entries(root):
        if path.is_file():
            name = path.relative_to(root).as_posix()
            if name not in files or path.stat().st_size != len(files[name]):
                return False
            with path.open("rb") as stream:
                observed[name] = stream.read(len(files[name]) + 1)
    return observed == files


def _delete_snapshot(root: Path, *, parent: Path | None = None) -> None:
    # Only our generated, private temp root is ever removed. Candidate receives
    # a read-only mount and cannot insert links, files or parents into it.
    resolved = root.resolve()
    allowed = Path(tempfile.gettempdir()).resolve() if parent is None else parent.resolve()
    if (resolved.parent != allowed
            or not resolved.name.startswith("lightwork-research-")):
        raise ResearchContainerError("refusing cleanup outside the owned temporary snapshot")
    for path in [*_snapshot_entries(resolved), resolved]:
        path.chmod(0o700 if path.is_dir() else 0o600)
    shutil.rmtree(resolved)


class ResearchContainerRunner:
    """Trusted-caller primitive; deliberately absent from user config/factory.

    It does not implement exec_authenticated_tests or advertise evaluator
    readiness. Image provisioning belongs to the operator; the research_jobs
    controller separately authenticates submissions and owns its evaluator.
    """

    def __init__(self, image: str, *, limits: ResearchLimits | None = None):
        self.limits = limits or ResearchLimits()
        if (type(image) is not str or len(image) > 256
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", image)):
            raise ValueError("a locally present reviewed image is required")
        # Docker readiness and image resolution are deliberately lazy. ``run``
        # owns the caller's Budget, so no controller subprocess may start in
        # this constructor before that budget can cap it.
        self._requested_image = image
        self._env: dict[str, str] = {}
        self._base: list[str] = []
        self.image_id = ""

    def _initialize(self, *, budget: Budget) -> None:
        if not isinstance(budget, Budget):
            raise TypeError("an explicit Budget is required")
        try:
            self._initialize_with_budget(budget)
        except (KeyError, IndexError, TypeError, AttributeError, UnicodeDecodeError) as exc:
            raise ResearchContainerError("Docker setup metadata is incomplete or invalid") from exc

    def _initialize_with_budget(self, budget: Budget) -> None:
        budget.check()
        self._env = _host_environment()
        executable = shutil.which("docker")
        if not executable:
            raise ResearchContainerError("Docker is required; no host fallback is allowed")
        self._base = [str(Path(executable).resolve())]
        context = self._control(["context", "show"], budget=budget).out.decode().strip()
        descriptor = self._json(["context", "inspect", context], budget=budget)[0]
        endpoint = descriptor["Endpoints"]["docker"]["Host"]
        if not _local_endpoint(endpoint):
            raise ResearchContainerError("research requires a local Linux Docker engine")
        self._base.extend(["--host", endpoint])
        if self._control(["info", "--format", "{{.OSType}}"], budget=budget).out.strip() != b"linux":
            raise ResearchContainerError("research requires Linux containers")
        metadata = self._json(["image", "inspect", self._requested_image], budget=budget)[0]
        if metadata.get("Os") != "linux" or metadata.get("Config", {}).get("Volumes"):
            raise ResearchContainerError("image must be Linux with no implicit writable volumes")
        self.image_id = metadata["Id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise ResearchContainerError("image has no immutable local ID")

    def _control(self, args, *, check=True, timeout=15, budget: Budget | None = None,
                 effect_guard=None) -> _Capture:
        if budget is not None:
            timeout = min(timeout, self._control_time(budget))
        try:
            kwargs = {"timeout": min(15, timeout), "limit": 256 * 1024}
            if effect_guard is not None:
                kwargs["effect_guard"] = effect_guard
            result = _capture([*self._base, *args], self._env, **kwargs)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ResearchContainerError(f"Docker control unavailable: {args[0]}") from exc
        if result.reason != "completed" or (check and result.code):
            raise ResearchContainerError(f"Docker control unavailable: {args[0]} ({result.reason}/{result.code})")
        return result

    def _json(self, args, *, timeout=15, budget: Budget | None = None):
        try:
            return json.loads(self._control(args, timeout=timeout, budget=budget).out)
        except (ValueError, KeyError, IndexError) as exc:
            raise ResearchContainerError("Docker metadata is unavailable") from exc

    def _create_args(self, name: str, root: Path, entrypoint: str) -> list[str]:
        limits = self.limits
        return ["create", "--pull=never", "--name", name, "--network=none",
                "--user", _USER, "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--pids-limit", str(limits.pids),
                "--memory", str(limits.memory_bytes), "--memory-swap", str(limits.memory_bytes),
                "--cpus", str(limits.cpus), "--ipc=private", "--log-driver=none",
                "--shm-size", str(limits.scratch_bytes),
                "--mount", f"type=bind,source={root},target=/candidate,readonly",
                "--tmpfs", f"/scratch:rw,noexec,nosuid,nodev,size={limits.scratch_bytes},uid=65532,gid=65532,mode=700",
                "--workdir", "/scratch", "--entrypoint", "/usr/bin/env", self.image_id,
                "-i", *_ENV, "/usr/local/bin/python3", "-I", "-B", f"/candidate/{entrypoint}"]

    def _verify_created(self, name: str, root: Path, entrypoint: str, *, timeout=15) -> dict:
        try:
            return self._inspect_created(name, root, entrypoint, timeout=timeout)
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ResearchContainerError("created container metadata is incomplete or invalid") from exc

    def _inspect_created(self, name: str, root: Path, entrypoint: str, *, timeout=15) -> dict:
        record = self._json(["container", "inspect", name], timeout=timeout)[0]
        host, config = record["HostConfig"], record["Config"]
        mounts = record["Mounts"]
        valid_mount = (len(mounts) == 1 and mounts[0]["Destination"] == "/candidate"
                       and mounts[0]["Type"] == "bind" and mounts[0]["RW"] is False)
        # Docker Desktop rewrites Windows source paths; compare the configured
        # mount source as well as the daemon's effective read-only destination.
        configured = host.get("Mounts") or []
        valid_source = (len(configured) == 1 and configured[0].get("Source") == str(root)
                        and configured[0].get("ReadOnly") is True)
        scratch = host.get("Tmpfs") or {}
        valid_scratch = (set(scratch) == {"/scratch"} and all(
            option in scratch["/scratch"].split(",") for option in (
                "noexec", "nosuid", "nodev", f"size={self.limits.scratch_bytes}",
                "uid=65532", "gid=65532", "mode=700")))
        safe = (record["Image"] == self.image_id and config["User"] == _USER
                and host["ReadonlyRootfs"] is True and host["NetworkMode"] == "none"
                and host["Privileged"] is False and host.get("PidMode", "") == ""
                and host.get("IpcMode") == "private" and host["CapDrop"] == ["ALL"]
                and host.get("ShmSize") == self.limits.scratch_bytes
                and "no-new-privileges" in host["SecurityOpt"] and not host.get("Devices")
                and host["Memory"] == self.limits.memory_bytes
                and host["MemorySwap"] == self.limits.memory_bytes
                and host["PidsLimit"] == self.limits.pids
                and host["NanoCpus"] == round(self.limits.cpus * 1_000_000_000)
                and valid_mount and valid_source and valid_scratch
                and config["Entrypoint"] == ["/usr/bin/env"]
                and config["Cmd"] == ["-i", *_ENV, "/usr/local/bin/python3", "-I", "-B", f"/candidate/{entrypoint}"]
                and host["LogConfig"]["Type"] == "none"
                and record["State"]["Status"] == "created")
        if not safe:
            raise ResearchContainerError("created container does not match the strict research profile")
        return {"image_id": record["Image"], "user": config["User"],
                "network": host["NetworkMode"], "readonly_root": host["ReadonlyRootfs"],
                "mounts": [{"destination": m["Destination"], "type": m["Type"], "rw": m["RW"]}
                           for m in mounts], "security_opt": host["SecurityOpt"],
                "cap_drop": host["CapDrop"], "tmpfs": scratch, "shm_bytes": host["ShmSize"],
                "command": config["Cmd"], "limits": asdict(self.limits)}

    def _cleanup(self, name: str) -> bool:
        try:
            self._control(["container", "rm", "--force", name], check=False)
            remaining = self._control(["container", "ls", "--all", "--filter",
                                       f"name=^/{name}$", "--format", "{{.ID}}"])
            return not remaining.out.strip()
        except ResearchContainerError:
            return False

    @staticmethod
    def _control_time(budget: Budget) -> float:
        budget.check()
        remaining = budget.remaining_wall()
        # inf is a budget with no wall cap (the sandbox's own limits still
        # bound every run); only NaN or nothing left is exhausted.
        if math.isnan(remaining) or remaining <= 0:
            raise ResearchContainerError("research wall budget is exhausted")
        return min(15, remaining)

    def run(self, files: Mapping[str, bytes], *, budget: Budget,
            entrypoint: str = "main.py", effect_guard=None, cancelled=None,
            observation=None) -> ResearchResult:
        if not isinstance(budget, Budget):
            raise TypeError("an explicit Budget is required")
        copied = _inputs(files, entrypoint)
        budget.record_tool_call()
        self._initialize(budget=budget)
        remaining = budget.remaining_wall()
        if math.isnan(remaining) or remaining <= 0:
            raise ResearchContainerError("research wall budget is exhausted")
        timeout = min(self.limits.timeout_seconds, remaining)
        name = "lightwork-research-" + uuid.uuid4().hex
        from ..file_lock import ensure_private_directory
        from ..paths import current_tenant_id_strict, data_dir

        parent = Path(tempfile.gettempdir()).resolve()
        if current_tenant_id_strict():
            parent = (data_dir() / "research-snapshots").resolve()
            ensure_private_directory(parent)
        root = Path(tempfile.mkdtemp(prefix="lightwork-research-", dir=parent)).resolve()
        cleanup = False
        execution_verified = False
        try:
            _write_snapshot(root, copied)
            self._control(self._create_args(name, root, entrypoint),
                          timeout=self._control_time(budget), effect_guard=effect_guard)
            policy = self._verify_created(name, root, entrypoint, timeout=self._control_time(budget))
            if not _snapshot_matches(root, copied):
                raise ResearchContainerError("candidate snapshot changed before execution")
            policy.update(schema="lightwork.research-linux-container-policy.v2",
                          entrypoint=entrypoint)
            if observation is not None:
                observation({"state": "container_prepared", "container": name,
                             "image_id": self.image_id, "input_sha256": _input_digest(copied)})
            budget.check()
            started = time.monotonic()
            try:
                result = _capture([*self._base, "start", "--attach", name], self._env,
                                  timeout=min(timeout, budget.remaining_wall()),
                                  limit=self.limits.output_bytes, effect_guard=effect_guard, **({"cancelled": cancelled} if cancelled is not None else {}))
            except (OSError, subprocess.SubprocessError) as exc:
                raise ResearchContainerError("could not start research container") from exc
            if observation is not None:
                state = self._json(["container", "inspect", name], timeout=self._control_time(budget))[0]["State"]
                started_at = state.get("StartedAt")
                if not isinstance(started_at, str) or started_at.startswith("0001-"):
                    raise ResearchContainerError("actual container start could not be verified")
                policy["execution_started_at"] = started_at
                policy["execution_finished_at"] = state.get("FinishedAt")
            # Always remove the whole container, including background children.
            cleanup = self._cleanup(name)
            if not cleanup:
                raise ResearchContainerError(f"container cleanup unverified: {name}")
            if not _snapshot_matches(root, copied):
                raise ResearchContainerError("read-only candidate snapshot changed")
            policy["elapsed_seconds"] = round(time.monotonic() - started, 6)
            policy_sha256 = _digest(policy)
            execution_verified = True
            stdout = result.out.decode("utf-8", "replace")
            reason = result.reason if stdout.encode("utf-8") == result.out else "invalid_utf8_output"
            return ResearchResult(name, self.image_id, _input_digest(copied),
                                  policy_sha256,
                                  entrypoint,
                                  result.code, reason, stdout,
                                  result.err.decode("utf-8", "replace"), len(result.out) + len(result.err),
                                  True, policy)
        finally:
            if not cleanup:
                cleanup = self._cleanup(name)
            if cleanup:
                _delete_snapshot(root, parent=parent)
                if observation is not None and not execution_verified:
                    observation({"state": "cleanup_verified", "container": name,
                                 "image_id": self.image_id, "input_sha256": _input_digest(copied),
                                 "cleanup_verified": True, "execution_outcome_confirmed": False})
            else:
                raise ResearchContainerError(
                    f"container cleanup remains unverified: {name}; retained snapshot: {root}"
                )
