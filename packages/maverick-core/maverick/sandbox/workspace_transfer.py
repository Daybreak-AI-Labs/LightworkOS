"""Staged, bounded workspace transfer with conflict-aware file publication.

The remote archive is untrusted. No archive path is extracted by tarfile;
only regular files/directories are admitted through pinned local parents.
Original and exported copies remain available if publication is interrupted.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tarfile
import threading
import uuid
from pathlib import Path, PurePosixPath

from .. import file_lock
from .. import task_file_recovery as paths
from ..paths import data_dir
from .local import scrub_env

MAX_FILES = 20_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + MAX_FILES * 4096


class WorkspaceTransferError(ValueError):
    pass


def capture_archive(args: list[str], archive: Path, timeout: float) -> int:
    """Bound disk and diagnostic output while kubectl is still streaming."""
    exceeded = threading.Event()
    failures: list[Exception] = []
    with archive.open("xb") as destination, subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=scrub_env(),
    ) as process:
        def drain(source, *, output=None, limit):
            used = 0
            try:
                while chunk := source.read(65536):
                    used += len(chunk)
                    if used > limit:
                        exceeded.set()
                        process.kill()
                        return
                    if output is not None:
                        output.write(chunk)
            except (OSError, ValueError) as exc:
                failures.append(exc)
                process.kill()

        readers = [
            threading.Thread(target=drain, args=(process.stdout,),
                             kwargs={"output": destination, "limit": MAX_ARCHIVE_BYTES}, daemon=True),
            threading.Thread(target=drain, args=(process.stderr,),
                             kwargs={"limit": 1024 * 1024}, daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        finally:
            for reader in readers:
                reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise WorkspaceTransferError("workspace export pipes did not close")
        if exceeded.is_set() or failures:
            raise WorkspaceTransferError("workspace export exceeded output limits or could not be saved")
        return process.returncode


def recovery_directory() -> Path:
    parent = file_lock.ensure_private_directory(data_dir("sandbox-recovery"))
    return file_lock.ensure_private_directory(parent / ("k8s-" + uuid.uuid4().hex))


def _relative(name: str) -> str:
    # Tar permits './file'; normalize only that prefix, never '..' or aliases.
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    parts = name.split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                *(f"LPT{i}" for i in range(10))}
    if (not name or len(name) > 4096 or len(parts) > 128
            or PurePosixPath(name).is_absolute() or "\\" in name
            or any(part in {"", ".", ".."} or ":" in part or part.endswith((".", " "))
                   or any(ord(c) < 32 for c in part)
                   or part.split(".")[0].upper() in reserved for part in parts)):
        raise WorkspaceTransferError("workspace contains an unsafe or aliased path")
    return name


def _mkdir(root: Path, relative: str) -> None:
    identity = paths._root_identity(root)
    for part in reversed(Path(relative).parents):
        if str(part) != ".":
            _mkdir_one(root, part.as_posix(), identity)
    _mkdir_one(root, relative, identity)


def _mkdir_one(root: Path, relative: str, identity: list) -> None:
    target = paths._target(root, relative)
    with paths._pinned_parent(root, relative, identity) as parent_fd:
        try:
            os.mkdir(target if parent_fd is None else target.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            info = target.lstat()
            if paths._alias(target, info) or not stat.S_ISDIR(info.st_mode):
                raise WorkspaceTransferError("workspace directory was replaced") from None


def _read(root: Path, relative: str) -> bytes:
    target = paths._target(root, relative)
    initial = target.lstat()
    if (not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1
            or initial.st_size > MAX_FILE_BYTES):
        raise WorkspaceTransferError("workspace requires bounded regular files with no hard links")
    with paths._pinned_parent(root, relative) as parent_fd:
        fd = os.open(target if parent_fd is None else target.name,
                     os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
                     dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            value = stream.read(MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
    final = target.lstat()
    identities = {(s.st_dev, s.st_ino, s.st_mtime_ns, s.st_size) for s in (initial, opened, after, final)}
    if len(identities) != 1 or len(value) > MAX_FILE_BYTES:
        raise WorkspaceTransferError("workspace file changed during transfer")
    return value


def _write(root: Path, relative: str, raw: bytes, mode: int) -> None:
    parent = PurePosixPath(relative).parent.as_posix()
    if parent != ".":
        _mkdir(root, parent)
    paths._apply(root, relative, raw)
    # Preserve executable scripts on POSIX without following a replaced link.
    if os.name != "nt":
        with paths._pinned_parent(root, relative) as parent_fd:
            fd = os.open(Path(relative).name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                os.fchmod(fd, mode & 0o777)
            finally:
                os.close(fd)


def snapshot(root: Path, destination: Path | None = None) -> dict[str, dict]:
    paths._root_identity(root)
    records: dict[str, dict] = {}
    total = 0
    aliases: set[str] = set()
    if destination is not None:
        if destination.resolve().is_relative_to(root.resolve()):
            raise WorkspaceTransferError("snapshot destination must be outside the workspace")
        file_lock.ensure_private_directory(destination)
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted([*dirs, *files]):
            path = Path(directory) / name
            relative = _relative(path.relative_to(root).as_posix())
            alias = os.path.normcase(relative)
            if alias in aliases or len(records) >= MAX_FILES:
                raise WorkspaceTransferError("workspace has too many entries or duplicate paths")
            aliases.add(alias)
            info = path.lstat()
            if paths._alias(path, info):
                raise WorkspaceTransferError("workspace transfer refuses links and reparse points")
            if stat.S_ISDIR(info.st_mode):
                records[relative] = {"kind": "directory"}
                if destination is not None:
                    _mkdir(destination, relative)
            else:
                raw = _read(root, relative)
                total += len(raw)
                if total > MAX_TOTAL_BYTES:
                    raise WorkspaceTransferError("workspace exceeds the transfer byte limit")
                mode = stat.S_IMODE(info.st_mode) & 0o777
                records[relative] = {"kind": "file", "sha256": hashlib.sha256(raw).hexdigest(),
                                     "bytes": len(raw), "mode": mode if os.name != "nt" else 0o600}
                if destination is not None:
                    _write(destination, relative, raw, mode)
    return records


def extract_archive(archive: Path, destination: Path) -> dict[str, dict]:
    file_lock.ensure_private_directory(destination)
    seen: set[str] = set()
    total = 0
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise WorkspaceTransferError("workspace export exceeds the archive limit")
    with tarfile.open(archive, mode="r:") as stream:
        for member in stream:
            if member.name.rstrip("/") in {".", ""} and member.isdir():
                continue
            relative = _relative(member.name)
            alias = os.path.normcase(relative)
            if alias in seen or len(seen) >= MAX_FILES:
                raise WorkspaceTransferError("workspace export has duplicate paths or too many entries")
            seen.add(alias)
            if member.isdir():
                _mkdir(destination, relative)
            elif member.isfile() and not member.issparse():
                total += member.size
                if not 0 <= member.size <= MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise WorkspaceTransferError("workspace export exceeds the file/total byte limit")
                source = stream.extractfile(member)
                if source is None:
                    raise WorkspaceTransferError("workspace archive is incomplete")
                with source:
                    raw = source.read(MAX_FILE_BYTES + 1)
                if len(raw) != member.size:
                    raise WorkspaceTransferError("workspace archive is truncated")
                _write(destination, relative, raw, member.mode)
            else:
                raise WorkspaceTransferError("workspace export contains a link or special file")
    return snapshot(destination)


def publish(root: Path, baseline: dict, exported: Path, backup: Path) -> None:
    desired = snapshot(exported)
    current = snapshot(root)
    changed = {name for name in baseline.keys() | desired.keys() if baseline.get(name) != desired.get(name)}
    conflicts = [name for name in changed if current.get(name) not in (baseline.get(name), desired.get(name))]
    # A removed directory must not hide a concurrently created local child.
    removed_dirs = {name for name in changed if baseline.get(name, {}).get("kind") == "directory"
                    and desired.get(name, {}).get("kind") != "directory"}
    conflicts += [name for name in current if name not in baseline
                  and any(name.startswith(directory + "/") for directory in removed_dirs)]
    if conflicts:
        raise WorkspaceTransferError("workspace changed locally; exported files retained for review")
    if snapshot(root, backup) != current:
        raise WorkspaceTransferError("workspace changed while originals were being saved")
    identity = paths._root_identity(root)
    expected = dict(current)
    # Remove obsolete leaves first, then their now-empty directories. Never
    # recursively remove a user folder; concurrent new children make rmdir fail.
    for name in sorted(changed, key=lambda value: (value.count("/"), value), reverse=True):
        old, new = current.get(name), desired.get(name)
        if old is None or old == new or (old["kind"] == "directory" and new and new["kind"] == "directory"):
            continue
        if new is None or old["kind"] != new["kind"]:
            _check_unchanged(root, name, expected.get(name))
            target = paths._target(root, name)
            with paths._pinned_parent(root, name, identity) as parent_fd:
                if old["kind"] == "directory":
                    os.rmdir(target if parent_fd is None else target.name, dir_fd=parent_fd)
                else:
                    os.unlink(target if parent_fd is None else target.name, dir_fd=parent_fd)
            expected.pop(name, None)
    for name in sorted(changed, key=lambda value: (value.count("/"), value)):
        record = desired.get(name)
        if record is None or current.get(name) == record:
            continue
        _check_unchanged(root, name, expected.get(name))
        if record["kind"] == "directory":
            _mkdir(root, name)
        else:
            _write(root, name, _read(exported, name), record["mode"])


def _check_unchanged(root: Path, name: str, expected: dict | None) -> None:
    """Recheck each leaf immediately before publication, after saving originals."""
    target = paths._target(root, name)
    actual = None
    try:
        info = target.lstat()
        if paths._alias(target, info):
            raise WorkspaceTransferError("workspace path was replaced by an alias")
        if stat.S_ISDIR(info.st_mode):
            actual = {"kind": "directory"}
        else:
            raw = _read(root, name)
            actual = {"kind": "file", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                      "mode": stat.S_IMODE(info.st_mode) & 0o777 if os.name != "nt" else 0o600}
    except FileNotFoundError:
        pass
    if actual != expected:
        raise WorkspaceTransferError("workspace changed during publication; copies retained for review")


def save_manifest(directory: Path, manifest: dict) -> None:
    file_lock.atomic_write_text(directory / "transfer.json", json.dumps(manifest, sort_keys=True))


def cleanup(directory: Path) -> None:
    expected = file_lock.ensure_private_directory(data_dir("sandbox-recovery")).resolve()
    if directory.parent.resolve() != expected or not directory.name.startswith("k8s-"):
        raise WorkspaceTransferError("refusing cleanup outside owned recovery storage")
    paths._root_identity(directory)
    shutil.rmtree(directory)
