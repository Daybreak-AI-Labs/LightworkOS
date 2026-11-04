"""Reviewed recovery of runtime-bound local file-tool writes.

This is deliberately separate from the legacy, operator-editable CLI journal.
Only a real run establishes its workdir; encrypted originals and an encrypted
manifest bind the review. Shell commands, remote sandboxes and external writers
are not captured. A private process lease survives async awaits without the
thread reentrancy of the short store locks.
"""
from __future__ import annotations

import base64
import contextvars
import difflib
import hashlib
import json
import os
import re
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from . import file_lock, workspace_journal
from .paths import current_tenant_id_strict, data_dir, maverick_home
from .tenant.kms import seal_text_for_tenant, unseal_text_for_tenant

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 100
_context = contextvars.ContextVar("task_file_capture", default=None)
_leases: set[str] = set()
_lease_guard = threading.Lock()


class RecoveryConflict(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _global():
    return file_lock.ensure_private_directory(maverick_home() / "task-file-locks")


@contextmanager
def mutation_gate():
    """Short synchronous gate shared by run admission, capture and restore."""
    with file_lock.cross_process_lock(_global() / "mutation.lock", strict=True):
        yield


@contextmanager
def _lease(key):
    """Nonblocking, non-reentrant process lease; safe across async awaits."""
    path = _global() / (key + ".lock")
    canonical = str(path.resolve())
    with _lease_guard:
        if canonical in _leases:
            raise RecoveryConflict("This task is running or its files are being recovered.")
        _leases.add(canonical)
    fd = None
    locked = False
    try:
        fd = file_lock._open_lock_file(path)
        file_lock._validate_open_lock_file(path, fd)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise RecoveryConflict("This task is running or its files are being recovered.") from exc
        yield
    finally:
        if fd is not None:
            if locked:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        with _lease_guard:
            _leases.discard(canonical)


def _key(world, goal_id):
    path = getattr(world, "path", None)
    if not isinstance(path, (str, Path)) or str(path).startswith(("postgres", "sqlite:")):
        raise RecoveryConflict("File recovery requires this app's local task database.")
    return _digest([current_tenant_id_strict(), str(Path(path).resolve()), int(goal_id)])


def _directory(key):
    path = data_dir("task-file-recovery", key)
    if os.name == "nt":
        path = Path(file_lock._windows_extended_path(path))
    return file_lock.ensure_private_directory(path)


def _load(key):
    path = _directory(key) / "manifest.sealed"
    if not path.exists():
        return None
    file_lock.ensure_private_file(path)
    if path.stat().st_size > 512 * 1024:
        raise RecoveryConflict("The saved file recovery record is invalid.")
    value = json.loads(unseal_text_for_tenant(current_tenant_id_strict(), file_lock.atomic_read_bytes(path)))
    if not isinstance(value, dict) or value.get("key") != key or not isinstance(value.get("files"), dict):
        raise RecoveryConflict("The saved file recovery record is invalid.")
    return value


def _save(key, value):
    raw = json.dumps(value, sort_keys=True)
    if len(raw.encode()) > 500 * 1024:
        raise RecoveryConflict("The saved file recovery record is full.")
    file_lock.atomic_write_bytes(_directory(key) / "manifest.sealed", seal_text_for_tenant(current_tenant_id_strict(), raw), mode=0o600)


def _alias(path, info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400) or (callable(getattr(path, "is_junction", None)) and path.is_junction())


def _root_identity(root):
    info = root.lstat()
    if _alias(root, info) or not stat.S_ISDIR(info.st_mode):
        raise RecoveryConflict("The task folder is no longer a regular local folder.")
    return [info.st_dev, info.st_ino]


def _target(root, relative):
    rel = Path(relative)
    if not relative or rel.is_absolute() or any(p in {"", ".", ".."} or ":" in p or p.endswith((".", " ")) for p in rel.parts):
        raise RecoveryConflict("A saved file path is unsafe.")
    target = root
    for part in rel.parts:
        target /= part
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        if _alias(target, info) or (target != root / rel and not stat.S_ISDIR(info.st_mode)):
            raise RecoveryConflict("File recovery refuses links or replaced folders.")
    target.relative_to(root)
    return target


def _read(root, relative, root_identity=None):
    target = _target(root, relative)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise RecoveryConflict("A file is not a bounded, regular, single-link file.")
    with _pinned_parent(root, relative, root_identity) as parent_fd:
        fd = os.open(target if parent_fd is None else target.name, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(MAX_FILE + 1)
            after = os.fstat(stream.fileno())
    final = target.lstat()
    identities = {(s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns) for s in (info, opened, after, final)}
    if len(identities) != 1 or len(raw) > MAX_FILE:
        raise RecoveryConflict("A file changed while it was being read. Review again.")
    return raw


def _state(raw):
    return {"exists": raw is not None, "bytes": len(raw) if raw is not None else 0,
            "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None}


def _overlap(first, second):
    return first == second or first in second.parents or second in first.parents


def _no_active(root, own_key):
    records = list(_global().glob("*.active"))
    if len(records) > 512:
        raise RecoveryConflict("Too many active task records; stop tasks before recovery.")
    for path in records:
        if path.stem == own_key:
            # The caller holds this exact task's exclusive OS lease; an old
            # marker can only be from a process that already exited.
            path.unlink()
            continue
        file_lock.ensure_private_file(path)
        if path.stat().st_size > 8192:
            raise RecoveryConflict("Active task authority is unavailable.")
        row = json.loads(file_lock.atomic_read_bytes(path))
        try:
            with _lease(path.stem):
                path.unlink()  # A crashed run released its OS lease.
        except RecoveryConflict:
            if _overlap(root, Path(row["workdir"])):
                raise RecoveryConflict("A task is still running in this folder. Stop it before recovery.") from None


@contextmanager
def run_scope(world, goal_id, sandbox):
    """Bind capture to the actual local runtime; never take a UI workdir."""
    from .sandbox.local import LocalBackend
    if not isinstance(getattr(sandbox, "workdir", None), (str, Path)) or not isinstance(getattr(world, "path", None), (str, Path)):
        yield
        return
    root = Path(sandbox.workdir).resolve()
    key = _key(world, goal_id)
    active = _global() / (key + ".active")
    token = None
    with _lease(key):
        with mutation_gate():
            previous = _load(key)
            if previous and previous.get("operation", {}).get("state") == "applying":
                raise RecoveryConflict("Finish this task's interrupted file recovery before running it again.")
            file_lock.atomic_write_bytes(active, json.dumps({"workdir": str(root)}).encode(), mode=0o600)
            token = _context.set({"key": key, "root": root, "active": False, "local": isinstance(sandbox, LocalBackend)})
        try:
            yield
        finally:
            if token is not None:
                _context.reset(token)
            with mutation_gate():
                active.unlink(missing_ok=True)


def begin_capture(world, goal_id):
    """Called only after the runtime validates its persisted principal."""
    context = _context.get()
    if context is None or not context["local"] or not workspace_journal.enabled() or not workspace_journal.strict():
        return
    goal = world.get_goal(goal_id)
    owner = getattr(goal, "owner", "")
    if not current_tenant_id_strict() or not owner.startswith("user:"):
        return
    root, key = context["root"], context["key"]
    if _overlap(root, maverick_home().resolve()):
        raise RecoveryConflict("Choose a task folder outside Lightwork's private application data before enabling file recovery.")
    with mutation_gate():
        previous = _load(key) or {}
        receipts = list(previous.get("receipts", []))
        if previous.get("operation", {}).get("state") == "complete":
            receipts.append(previous["operation"])
        record = {"key": key, "goal_id": goal_id, "owner": owner, "workdir": str(root), "root_identity": _root_identity(root),
                  "run": uuid.uuid4().hex, "started_at": time.time(), "files": {}, "total": 0, "complete": True, "operation": {}, "receipts": receipts[-20:]}
        _save(key, record)
        # A newly admitted run replaces the prior run's original-content point.
        # Keep compact receipts, not an unbounded second copy of every run.
        for path in _directory(key).iterdir():
            if re.fullmatch(r"[a-f0-9]{32}-[a-f0-9]{64}\.sealed", path.name):
                file_lock.ensure_private_file(path)
                path.unlink()
        context["active"] = True


def capture(workdir, target):
    """Called under mutation_gate immediately before the supported write."""
    context = _context.get()
    if context is None or not context["active"]:
        return False
    key = context["key"]
    record = _load(key)
    root = Path(workdir).resolve()
    if record is None or str(root) != record["workdir"] or _root_identity(root) != record["root_identity"]:
        raise RecoveryConflict("The task's recorded folder changed; refusing the file write.")
    relative = Path(target).relative_to(root).as_posix()
    if relative in record["files"]:
        return True
    raw = _read(root, relative, record["root_identity"])
    if len(record["files"]) >= MAX_FILES or record["total"] + len(raw or b"") > MAX_TOTAL:
        raise RecoveryConflict("Protected file history is full; this file write was refused.")
    blob = record["run"] + "-" + _digest(relative) + ".sealed"
    encoded = base64.b64encode(raw).decode() if raw is not None else ""
    file_lock.atomic_write_bytes(_directory(key) / blob, seal_text_for_tenant(current_tenant_id_strict(), encoded), mode=0o600)
    record["files"][relative] = {**_state(raw), "blob": blob}
    record["total"] += len(raw or b"")
    _save(key, record)
    return True


def _original(key, item):
    blob = item["blob"]
    if not isinstance(blob, str) or len(blob) != 104 or any(c not in "0123456789abcdef-.seal" for c in blob):
        raise RecoveryConflict("The saved original file is invalid.")
    path = _directory(key) / blob
    file_lock.ensure_private_file(path)
    if path.stat().st_size > MAX_FILE * 2:
        raise RecoveryConflict("The saved original file exceeds its bound.")
    raw = base64.b64decode(unseal_text_for_tenant(current_tenant_id_strict(), file_lock.atomic_read_bytes(path)), validate=True)
    raw = raw if item["exists"] else None
    if _state(raw) != {k: item[k] for k in ("exists", "bytes", "sha256")}:
        raise RecoveryConflict("The saved original file failed its integrity check.")
    return raw


def _record(world, goal_id, actor):
    from . import config
    from .job_queue import JobQueue
    loaded = config.load_config()
    if config.config_source_errors(include_tenant=True) or (loaded.get("queue") or {}).get("backend", "") not in {"", "local", "in_process"} or (loaded.get("grpc_dispatch") or {}).get("target") or (loaded.get("sandbox") or {}).get("backend", "local") != "local":
        raise RecoveryConflict("Local file recovery is unavailable while remote task workers are configured.")
    goal = world.get_goal(goal_id)
    if not actor or not actor.startswith("user:") or goal is None or goal.owner != actor:
        raise PermissionError("Only this task's named owner can recover its files.")
    key = _key(world, goal_id)
    record = _load(key)
    if record is None:
        raise RecoveryConflict("No protected file history exists for this task. Enable capture before its next local run.")
    if record["owner"] != actor or record["goal_id"] != goal_id:
        raise PermissionError("Task recovery ownership changed.")
    if goal.status in {"running", "pending", "queued", "planning", "in_progress"}:
        raise RecoveryConflict("Stop the task and cancel queued runs before reviewing its files.")
    queue = JobQueue()
    for status in ("pending", "running"):
        jobs = queue.list(status=status, limit=10001)
        if len(jobs) > 10000 or any(job.payload.get("goal_id") == goal_id for job in jobs):
            raise RecoveryConflict("Cancel pending or running task jobs before file recovery.")
    root = Path(record["workdir"])
    if _root_identity(root) != record["root_identity"]:
        raise RecoveryConflict("The task folder was replaced. Recovery is unavailable.")
    _no_active(root, key)
    return key, record, goal


def _preview(key, record, goal):
    rows, states = [], {}
    for relative, item in sorted(record["files"].items()):
        original = _original(key, item)
        current = _read(Path(record["workdir"]), relative, record["root_identity"])
        states[relative] = _state(current)
        before, after = (current or b"")[:32000], (original or b"")[:32000]
        try:
            diff = "".join(difflib.unified_diff(before.decode("utf-8").splitlines(True), after.decode("utf-8").splitlines(True), fromfile="Current", tofile="Restored", n=3))[:12000]
        except UnicodeDecodeError:
            diff = "Binary content: compare the recorded sizes and fingerprints."
        rows.append({"path": relative, "current": states[relative], "restored": _state(original), "diff": diff, "preview_truncated": max(len(current or b""), len(original or b"")) > 32000})
    version = _digest({"record": record, "current": states, "goal": [goal.owner, goal.status, goal.updated_at, goal.result]})
    return {"goal_id": goal.id, "version": version, "files": rows, "run": record["run"], "operation": record.get("operation", {}),
            "coverage": "Only captured local file-tool writes. Shell commands, remote changes and external services are not undone."}


def preview(world, goal_id, actor):
    key = _key(world, goal_id)
    with _lease(key), mutation_gate():
        key, record, goal = _record(world, goal_id, actor)
        return _preview(key, record, goal)


@contextmanager
def _pinned_parent(root, relative, root_identity=None):
    """Anchor directory traversal against links and rename races."""
    target = _target(root, relative)
    expected_root = root_identity or _root_identity(root)
    handles = []
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            for parent in reversed((target.parent, *target.parent.parents)):
                info = parent.lstat()
                if _alias(parent, info) or not stat.S_ISDIR(info.st_mode):
                    raise RecoveryConflict("Recovery refuses linked parent folders.")
                # No FILE_SHARE_DELETE: held parents cannot be renamed or
                # replaced until the anchored read/replace has completed.
                handle = kernel.CreateFileW(str(parent), 0x80, 3, None, 3, 0x02200000, None)
                if handle == wintypes.HANDLE(-1).value:
                    raise RecoveryConflict("The file's parent folder could not be held safely.")
                handles.append(handle)
                if _root_identity(parent) != [info.st_dev, info.st_ino]:
                    raise RecoveryConflict("A parent folder changed during recovery.")
            if _root_identity(root) != expected_root:
                raise RecoveryConflict("The recorded task folder was replaced.")
            yield None
        else:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            handles.append(fd)
            opened = os.fstat(fd)
            if [opened.st_dev, opened.st_ino] != expected_root:
                raise RecoveryConflict("The recorded task folder was replaced.")
            for part in Path(relative).parent.parts:
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                handles.append(fd)
            yield fd
    finally:
        for handle in reversed(handles):
            if os.name == "nt":
                kernel.CloseHandle(handle)
            else:
                os.close(handle)


def _apply(root, relative, raw, root_identity=None):
    """Replace the directory entry, never truncate through a target link."""
    target = _target(root, relative)
    if not target.parent.is_dir():
        raise RecoveryConflict("A captured file's parent folder is missing. Restore cannot safely recreate it.")
    with _pinned_parent(root, relative, root_identity) as parent_fd:
        try:
            mode = stat.S_IMODE(target.lstat().st_mode) & 0o777
        except FileNotFoundError:
            mode = 0o600
        if raw is None:
            try:
                os.unlink(target if parent_fd is None else target.name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        elif parent_fd is None:
            file_lock.atomic_write_bytes(target, raw, mode=mode)
        else:
            temp = ".lightwork-restore-" + uuid.uuid4().hex
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent_fd)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                try:
                    os.unlink(temp, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass


def revert(world, goal_id, actor, *, version, request_id, confirm):
    if confirm is not True or not isinstance(request_id, str) or not 8 <= len(request_id) <= 100:
        raise ValueError("Review the file changes and explicitly confirm recovery.")
    key = _key(world, goal_id)
    with _lease(key), mutation_gate():
        key, record, goal = _record(world, goal_id, actor)
        for receipt in record.get("receipts", []):
            if receipt["request_id"] == request_id:
                if receipt["version"] != version:
                    raise RecoveryConflict("This request reference already belongs to another reviewed recovery.")
                return receipt
        operation = record.get("operation", {})
        if operation:
            if operation.get("request_id") != request_id or operation.get("version") != version:
                raise RecoveryConflict("This history already has a recovery request. Retry that exact request or start a new task run.")
            if operation["state"] == "complete":
                return operation
        else:
            reviewed = _preview(key, record, goal)
            if reviewed["version"] != version or not reviewed["files"]:
                raise RecoveryConflict("Files or task state changed after review. Review again before recovery.")
            operation = {"request_id": request_id, "version": version, "state": "applying", "actor": actor, "started_at": time.time(),
                         "current": {row["path"]: row["current"] for row in reviewed["files"]}}
            from .audit import audit_event
            if not audit_event("task_file_recovery", goal_id=goal_id, data={"actor": actor, "request_id": request_id, "version": version, "files": len(reviewed["files"])}):
                raise RecoveryConflict("The recovery audit could not be saved. No files were restored.")
            record["operation"] = operation
            _save(key, record)
        root = Path(record["workdir"])
        originals = {}
        for relative, item in record["files"].items():
            raw = _original(key, item)
            if _state(_read(root, relative, record["root_identity"])) not in (operation["current"][relative], _state(raw)):
                raise RecoveryConflict("Files changed during interrupted recovery. No further files were restored.")
            originals[relative] = raw
        for relative, raw in originals.items():
            current = _state(_read(root, relative, record["root_identity"]))
            if current not in (operation["current"][relative], _state(raw)):
                raise RecoveryConflict("A file changed after recovery started. No further files were restored.")
            if current != _state(raw):
                _apply(root, relative, raw, record["root_identity"])
            if _state(_read(root, relative, record["root_identity"])) != _state(raw):
                raise RecoveryConflict("File recovery could not be verified. Retry this exact request.")
        operation = {k: v for k, v in operation.items() if k != "current"}
        operation.update(state="complete", completed_at=time.time(), files=len(originals))
        record["operation"] = operation
        _save(key, record)
        return operation
