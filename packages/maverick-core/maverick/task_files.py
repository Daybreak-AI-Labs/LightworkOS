"""Files a task saved for the person, offered as downloads on the task's page.

The agent workspace is one folder shared by every task on an installation, so
a download must never become a way to read whatever is in it now. Each file a
task writes (``write_file``, ``str_replace_editor``) or hands over on purpose
(``deliver_file``) is recorded on the goal as a ``task_file`` event: the
workspace, the path inside it and the SHA-256 of the bytes the task left.
A download reads the file through a descriptor confined to that workspace and
serves it only while its bytes still match that record; a file another task
changed or removed since is reported, not served. Nothing is copied: the
record is a few hundred bytes, sealed at rest with the other goal events.

Recording is best effort and never fails the write it describes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

EVENT_KIND = "task_file"
EVENT_AGENT = "system"
#: Largest file a task page serves; bigger files stay in the workspace.
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
#: Most files one task lists (the newest record of each path counts once).
MAX_FILES = 200
_EVENT_PAGE = 500
_MAX_EVENT_PAGES = 200


class TaskFileUnavailable(Exception):
    """The recorded file cannot be served; ``str(exc)`` is plain words."""


@dataclass(frozen=True)
class TaskFile:
    number: int        # 1-based position on the task page (stable: first save)
    name: str          # file name shown to the person
    path: str          # workspace-relative POSIX path
    workdir: str       # absolute workspace the task wrote in
    sha256: str
    size: int
    saved_at: float


def iter_goal_events(world, goal_id: int):
    """Every event of a goal, oldest first, a page at a time."""
    since = 0
    for _ in range(_MAX_EVENT_PAGES):
        page = world.goal_events(goal_id, since_id=since, limit=_EVENT_PAGE)
        yield from page
        if len(page) < _EVENT_PAGE:
            return
        since = page[-1].id


def _digest_contained(workdir: Path, target: Path, limit: int) -> tuple[str, int]:
    """SHA-256 and size of a regular file read through a confined descriptor."""
    from .tools.fs import _open_contained

    fd = _open_contained(workdir, target, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("not a regular file")
        digest, size = hashlib.sha256(), 0
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("file is larger than the download limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def record(world, goal_id, workdir, target) -> TaskFile | None:
    """Record the file ``target`` as this goal's current version of it."""
    if world is None or not isinstance(goal_id, int) or isinstance(goal_id, bool):
        return None
    try:
        root = Path(workdir).resolve()
        path = Path(target).resolve()
        relative = path.relative_to(root).as_posix()
        digest, size = _digest_contained(root, path, MAX_DOWNLOAD_BYTES)
    except (OSError, ValueError):
        return None  # outside the workspace, unreadable or too big: not offered
    import time

    entry = {"workdir": str(root), "path": relative, "sha256": digest, "size": size}
    try:
        world.append_event(goal_id, EVENT_AGENT, EVENT_KIND, json.dumps(entry, sort_keys=True))
    except Exception:  # noqa: BLE001 -- the write itself already succeeded
        log.warning("could not record task file %s for goal #%s", relative, goal_id, exc_info=True)
        return None
    return TaskFile(0, Path(relative).name, relative, str(root), digest, size, time.time())


def files_for(world, goal_id: int) -> list[TaskFile]:
    """The files this goal saved, the newest record of each path, in the order
    they were first saved."""
    latest: dict[tuple[str, str], TaskFile] = {}
    order: list[tuple[str, str]] = []
    for event in iter_goal_events(world, goal_id):
        if event.kind != EVENT_KIND or event.agent != EVENT_AGENT:
            continue
        try:
            entry = json.loads(event.content)
            key = (str(entry["workdir"]), str(entry["path"]))
            item = TaskFile(0, Path(key[1]).name, key[1], key[0], str(entry["sha256"]),
                            int(entry["size"]), float(event.ts))
        except (ValueError, KeyError, TypeError):
            continue
        if key not in latest:
            if len(order) >= MAX_FILES:
                continue
            order.append(key)
        latest[key] = item
    return [TaskFile(n, *_fields(latest[key])) for n, key in enumerate(order, 1)]


def _fields(item: TaskFile) -> tuple:
    return (item.name, item.path, item.workdir, item.sha256, item.size, item.saved_at)


def read_for_download(world, goal_id: int, number: int) -> tuple[TaskFile, bytes]:
    """The bytes of file ``number`` exactly as this goal saved them."""
    found = next((f for f in files_for(world, goal_id) if f.number == number), None)
    if found is None:
        raise TaskFileUnavailable("This task has no such file.")
    root = Path(found.workdir)
    target = root / found.path
    from .tools.fs import _open_contained

    try:
        resolved = target.resolve()
        resolved.relative_to(root)
        fd = _open_contained(root, resolved, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError as exc:
        raise TaskFileUnavailable(
            "This file is no longer in the work folder, so it can't be downloaded.") from exc
    except (OSError, ValueError) as exc:
        raise TaskFileUnavailable("This file can't be opened safely, so it can't be downloaded.") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise TaskFileUnavailable("This file can't be opened safely, so it can't be downloaded.")
        data = handle.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES or hashlib.sha256(data).hexdigest() != found.sha256:
        raise TaskFileUnavailable(
            "This file changed after the task saved it (another task or a command may have "
            "rewritten it), so Lightwork won't serve a version this task didn't make.")
    return found, data


def sandbox_link_number(files: list[TaskFile], link: str) -> int | None:
    """The file a ``sandbox:`` (or plain workspace) link in an answer points
    at, matched against this task's own records only."""
    raw = link.removeprefix("sandbox:")
    raw = raw.split("#", 1)[0].split("?", 1)[0].strip()
    if not raw:
        return None
    for item in files:
        absolute = str(Path(item.workdir) / item.path)
        if raw in (absolute, item.path, "./" + item.path, "/workspace/" + item.path):
            return item.number
    return None
