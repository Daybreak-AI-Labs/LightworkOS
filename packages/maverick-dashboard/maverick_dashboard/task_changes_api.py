"""What changed during a task: a contained, read-only view of the file journal.

``maverick journal diff`` compares each file the task changed as it was before
the task first touched it with how it is on disk now. The journal's records sit
in files an operator can edit, and each record names its own folder, so a
browser view built on them naively could show any file on the machine. Nothing
a record names is trusted here:

* the only folder read is the task's own work folder, found independently of
  the journal (the sealed file-protection record of the task's real run, else
  the configured task work folder), and a folder that is the whole disk, the
  home folder, or overlaps Lightwork's private data is refused outright;
* a record whose folder is not exactly that folder is skipped;
* every file name must be relative with no ``..``, drive or empty parts, every
  step towards it must be a real folder (no links), the file itself must be a
  regular, single-link file whose real location is inside the folder, and it is
  opened without following links and checked to be the file that was examined;
* saved earlier copies get the same link and size checks plus their recorded
  fingerprint; binary files are named but never shown; counts, sizes, lines
  and the response are bounded;
* the history must live in this workspace's own data folder, so a history
  folder shared between workspaces is refused.

The kernel only records the state before the task and the disk now, so this is
the one comparison offered. Read-only: nothing is changed or restored here.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from .auth import assert_goal_access

router = APIRouter(tags=["task-file-recovery"])

MAX_FILES = 100
MAX_RECORDS = 2000
MAX_RECORD_BYTES = 64 * 1024
MAX_FILE_BYTES = 256 * 1024
MAX_TEXT_LINES = 4000
MAX_LINES_PER_FILE = 400
MAX_LINES_TOTAL = 4000
MAX_LINE_CHARS = 500
_LOCAL_BACKENDS = {"local", "docker", "podman", "gvisor", "devcontainer"}
_RECORD_NAME = re.compile(r"^\d{6,9}\.json$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Refused(ValueError):
    """The whole view is unavailable; the message is written for people."""


class _Skip(Exception):
    """One file cannot be shown; ``kind`` says why."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def _alias(path: Path, info: os.stat_result) -> bool:
    """Symbolic link, Windows reparse point or junction."""
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        return True
    junction = getattr(path, "is_junction", None)
    return bool(callable(junction) and junction())


def _within(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _overlap(first: Path, second: Path) -> bool:
    return _within(first, second) or _within(second, first)


def _read_no_follow(path: Path, info: os.stat_result, limit: int) -> bytes:
    """Read ``path`` without following a link, and only if it is still the
    file ``info`` described (no swap between the check and the open)."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise _Skip("unreadable") from exc
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise _Skip("unsafe")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise _Skip("too_large")
    return data


def work_folder(world, goal_id: int) -> Path:
    """The task's own work folder, resolved; never taken from the journal."""
    from maverick import config, task_file_recovery, workspace_journal
    from maverick.paths import maverick_home

    candidate = None
    try:
        record = task_file_recovery._load(task_file_recovery._key(world, goal_id))
    except Exception:  # an unreadable protected record falls back to the configured folder
        record = None
    if isinstance(record, dict) and isinstance(record.get("workdir"), str):
        candidate = record["workdir"]
    else:
        sandbox = config.get_sandbox()
        if str(sandbox.get("backend") or "local").strip().lower() not in _LOCAL_BACKENDS:
            raise Refused("This task works in a folder on another computer, so its changes can't be shown here.")
        candidate = sandbox.get("workdir")
    if not isinstance(candidate, str) or not candidate.strip():
        raise Refused("This task has no work folder on this computer, so there is nothing to compare.")
    raw = Path(candidate.strip()).expanduser()
    if not raw.is_absolute():
        raise Refused("This task's work folder isn't set to a fixed location, so its changes can't be shown safely.")
    try:
        root = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Refused("This task's work folder can't be found on this computer.") from exc
    if not root.is_dir():
        raise Refused("This task's work folder can't be found on this computer.")
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError, KeyError):
        home = None
    private = maverick_home().resolve(strict=False)
    journal = workspace_journal.journal_root().resolve(strict=False)
    if root == Path(root.anchor) or root == home or _overlap(root, private) or _overlap(root, journal):
        raise Refused("This task's work folder is too broad to show safely. An administrator can choose a separate folder for tasks.")
    return root


def _journal_records(goal_id: int) -> tuple[list[dict], Path | None, bool]:
    """This task's journal records, oldest first, read without following
    links. Returns ``(records, folder, incomplete)``."""
    from maverick import workspace_journal
    from maverick.paths import data_dir

    if not _within(workspace_journal.journal_root().resolve(strict=False), data_dir().resolve(strict=False)):
        raise Refused("This task's change history is kept in a folder shared between workspaces, so it can't be shown here.")
    folder = workspace_journal.goal_dir(goal_id)
    try:
        info = folder.lstat()
    except FileNotFoundError:
        return [], None, False
    if _alias(folder, info) or not stat.S_ISDIR(info.st_mode):
        raise Refused("This task's saved change history can't be read safely.")
    records: list[dict] = []
    incomplete = False
    with os.scandir(folder) as listing:
        names = sorted(entry.name for entry in listing if _RECORD_NAME.match(entry.name))
    if len(names) > MAX_RECORDS:
        names, incomplete = names[:MAX_RECORDS], True
    for name in names:
        path = folder / name
        try:
            record_info = path.lstat()
            if _alias(path, record_info) or not stat.S_ISREG(record_info.st_mode) or record_info.st_size > MAX_RECORD_BYTES:
                continue
            record = json.loads(_read_no_follow(path, record_info, MAX_RECORD_BYTES).decode("utf-8"))
        except (OSError, ValueError, _Skip):
            continue
        if isinstance(record, dict) and isinstance(record.get("seq"), int) and not isinstance(record.get("seq"), bool):
            records.append(record)
    records.sort(key=lambda row: row["seq"])
    try:
        capped = (folder / "CAPPED").lstat()
        incomplete = incomplete or stat.S_ISREG(capped.st_mode)
    except OSError:
        pass
    return records, folder, incomplete


def safe_parts(name: object) -> list[str]:
    """Split a recorded file name into safe parts, or raise ``_Skip``."""
    if not isinstance(name, str) or not 0 < len(name) <= 1024 or "\x00" in name:
        raise _Skip("unsafe")
    text = name.replace("\\", "/")
    if text.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", text):
        raise _Skip("unsafe")
    parts = text.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        raise _Skip("unsafe")
    return parts


def read_inside(root: Path, parts: list[str]) -> bytes | None:
    """Bytes of ``root/parts`` now, or ``None`` when it no longer exists.
    Refuses links anywhere on the way, non-regular or multiply linked files,
    anything resolving outside ``root``, and files over the size bound."""
    current = root
    info = None
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _Skip("unreadable") from exc
        if _alias(current, info):
            raise _Skip("unsafe")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise _Skip("unsafe")
    if info is None or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise _Skip("unsafe")
    if info.st_size > MAX_FILE_BYTES:
        raise _Skip("too_large")
    try:
        real = current.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _Skip("unsafe") from exc
    if not _within(real, root) or real == root:
        raise _Skip("unsafe")
    return _read_no_follow(current, info, MAX_FILE_BYTES)


def _saved_copy(folder: Path, record: dict) -> bytes | None:
    """The copy saved before the task changed the file (``None`` when the file
    did not exist yet). Raises ``_Skip("not_saved")`` when no usable copy exists."""
    if record.get("existed") is not True:
        return None
    seq = record.get("seq")
    if record.get("blob") is not True or not isinstance(seq, int) or not 0 <= seq < 10**9:
        raise _Skip("too_large" if record.get("skipped_reason") == "too_large" else "not_saved")
    path = folder / f"{seq:06d}.pre"
    try:
        info = path.lstat()
    except OSError as exc:
        raise _Skip("not_saved") from exc
    if _alias(path, info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise _Skip("not_saved")
    if info.st_size > MAX_FILE_BYTES:
        raise _Skip("too_large")
    data = _read_no_follow(path, info, MAX_FILE_BYTES)
    expected = record.get("pre_sha256")
    if isinstance(expected, str) and _HEX64.match(expected) and hashlib.sha256(data).hexdigest() != expected:
        raise _Skip("not_saved")
    return data


def _text(data: bytes | None) -> list[str] | None:
    """Lines of a text file, ``[]`` for a missing one, ``None`` for binary."""
    if data is None:
        return []
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None


def _lines(before: list[str], after: list[str], budget: int) -> tuple[list[dict], bool]:
    """Changed lines with a little surrounding context, bounded."""
    out: list[dict] = []
    limit = min(MAX_LINES_PER_FILE, budget)
    diff = difflib.unified_diff(before, after, lineterm="", n=2)
    for line in diff:
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("@@"):
            row = {"kind": "gap", "text": ""}
        elif line.startswith("+"):
            row = {"kind": "add", "text": line[1:]}
        elif line.startswith("-"):
            row = {"kind": "remove", "text": line[1:]}
        else:
            row = {"kind": "same", "text": line[1:]}
        if len(out) >= limit:
            return out, True
        row["text"] = row["text"][:MAX_LINE_CHARS]
        out.append(row)
    return out, False


def task_changes(world, goal_id: int) -> dict:
    """Before-the-task versus now for every journaled file of this task that
    lies inside its own work folder. See the module docstring for the checks."""
    records, folder, incomplete = _journal_records(goal_id)
    if not records:
        return {"available": True, "files": [], "left_out": 0, "more": 0, "incomplete": incomplete}
    root = work_folder(world, goal_id)
    files: list[dict] = []
    seen: set[str] = set()
    left_out = more = 0
    lines_left = MAX_LINES_TOTAL
    for record in records:
        try:
            parts = safe_parts(record.get("path"))
            recorded = record.get("workdir")
            if not isinstance(recorded, str) or not Path(recorded).is_absolute():
                raise _Skip("unsafe")
            if Path(recorded).resolve(strict=False) != root:
                raise _Skip("unsafe")
        except (_Skip, OSError, RuntimeError, ValueError):
            left_out += 1
            continue
        name = "/".join(parts)
        if name in seen:
            continue  # the oldest record holds the state before the task
        seen.add(name)
        if len(files) >= MAX_FILES:
            more += 1
            continue
        row = {"name": name, "change": "edited", "lines": [], "shortened": False}
        try:
            before = _saved_copy(folder, record)
            now = read_inside(root, parts)
        except _Skip as skip:
            if skip.kind == "unsafe":
                left_out += 1
                continue
            row["change"] = skip.kind if skip.kind in {"too_large", "not_saved", "unreadable"} else "not_saved"
            files.append(row)
            continue
        if before == now:
            continue
        row["change"] = "created" if before is None else "deleted" if now is None else "edited"
        old, new = _text(before), _text(now)
        if old is None or new is None:
            row["change"] = "binary"
        elif len(old) > MAX_TEXT_LINES or len(new) > MAX_TEXT_LINES:
            row["change"] = "too_large"
        else:
            row["lines"], row["shortened"] = _lines(old, new, lines_left)
            lines_left -= len(row["lines"])
        files.append(row)
    return {"available": True, "files": files, "left_out": left_out, "more": more, "incomplete": incomplete}


@router.get("/api/v1/task-files/{goal_id}/changes")
async def changes(request: Request, response: Response, goal_id: int):
    """Read-only: what changed in this task's own work folder since before it ran."""
    from .task_file_recovery_api import _authority

    response.headers["Cache-Control"] = "private, no-store"

    def operation():
        # Operate permission, a named owner in the selected workspace, the
        # task's department suite, and the standard per-task access check.
        world, _, context = _authority(request, goal_id)
        assert_goal_access(request, world.get_goal(goal_id))
        try:
            return {"context": context, **task_changes(world, goal_id)}
        except Refused as exc:
            return {"context": context, "available": False, "message": str(exc), "files": []}

    try:
        return await run_in_threadpool(operation)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "The changes could not be loaded. Try again in a moment.") from exc
