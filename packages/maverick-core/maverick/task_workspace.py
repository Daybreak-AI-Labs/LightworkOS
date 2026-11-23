"""One work folder per chat conversation.

A chat task used to share one workspace with every other task, so files left
by earlier work were taken for this task's own. An ordinary chat conversation
(web chat or a messaging channel) now works in ``<workspace>/tasks/
conversation-<id>``; its follow-ups share that folder. Specialists, samples,
flows, schedules, triggers, codebase work, coding mode and tasks started
outside a conversation keep the shared workspace, as do backends whose folder
is not on this computer and contained runs (they get a throwaway folder).

A file a person keeps in the shared workspace can still be opened by name from
a task folder: the file tools copy it in on first use (:func:`bring_in`), so
the original is never changed. ``[sandbox] task_folders = false`` turns this
off.
"""
from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

log = logging.getLogger(__name__)

TASKS_DIRNAME = "tasks"
#: Backends whose ``workdir`` is a folder on this computer.
_HOST_FOLDER_BACKENDS = frozenset({"local", "docker", "gvisor", "podman"})
#: Origins that keep working in the shared workspace.
_SHARED_ORIGINS = ("codebase_feature", "flow_run", "schedule", "trigger")
#: The dashboard's first workspace ("My workspace"), the one every
#: single-workspace installation runs in (tenant_select_page.FIRST_WORKSPACE).
FIRST_WORKSPACE_ID = "local"
SHARED_NOTE = ("Files in the shared workspace, kept by the person. Use one only when the request "
               "refers to it; open it by name and a copy comes into this task's folder (the original "
               "is not changed):")


def enabled() -> bool:
    """``[sandbox] task_folders``: on unless an administrator turned it off."""
    from ._envparse import coerce_bool
    from .config import load_config
    try:
        section = load_config().get("sandbox", {}) or {}
    except Exception:  # noqa: BLE001 -- unreadable config keeps the default
        section = {}
    return coerce_bool(section.get("task_folders"), True)


def shared_root() -> Path | None:
    """The configured shared workspace, when it is a folder on this computer."""
    from .config import get_sandbox
    try:
        cfg = get_sandbox()
    except Exception:  # noqa: BLE001
        return None
    if str(cfg.get("backend") or "local").strip().lower() not in _HOST_FOLDER_BACKENDS:
        return None
    raw = cfg.get("workdir")
    if not isinstance(raw, str) or not raw.strip():
        return None
    root = Path(raw.strip()).expanduser()
    return root if root.is_absolute() else None


def _conversation(world, goal_id: int) -> int | None:
    rows = world.tenant_query(
        "SELECT t.conversation_id FROM turns t JOIN goals g ON g.id=t.goal_id "
        "WHERE t.goal_id=? AND t.role='user' AND {tenant_exact:g.tenant_id} "
        "ORDER BY t.id LIMIT 1", (int(goal_id),))
    return int(rows[0][0]) if rows else None


def _keeps_shared_workspace(world, goal) -> bool:
    if str(getattr(goal, "domain", "") or "").strip():
        return True
    from .coding_mode import from_env
    if from_env().enabled:
        return True
    from .containment import active_profile
    if active_profile() is not None:
        return True
    from .sample_outcomes import is_sample_goal
    if is_sample_goal(world, goal):
        return True
    marks = ",".join("?" for _ in _SHARED_ORIGINS)
    return bool(world.tenant_query(
        "SELECT 1 FROM goal_origins o JOIN goals g ON g.id=o.goal_id "
        f"WHERE o.goal_id=? AND o.kind IN ({marks}) AND {{tenant_exact:g.tenant_id}} LIMIT 1",
        (int(goal.id), *_SHARED_ORIGINS)))


def _folder_name(conversation_id: int) -> Path:
    from .paths import current_tenant, current_tenant_id, implicit_tenant_id
    name = Path(f"conversation-{int(conversation_id)}")
    if current_tenant_id() in (None, FIRST_WORKSPACE_ID, implicit_tenant_id()):
        return Path(TASKS_DIRNAME) / name
    # Another named workspace sharing this folder keeps its conversations apart.
    return Path(TASKS_DIRNAME) / str(current_tenant()) / name


def folder_for(world, goal, conversation_id: int | None = None, *, create: bool = True) -> Path | None:
    """This goal's own work folder, or ``None`` when it keeps the shared one.

    The conversation is the one the goal's first message was posted in, so
    every follow-up resolves to the same folder; ``conversation_id`` is used
    only when no message was recorded.
    """
    if goal is None or not enabled():
        return None
    base = shared_root()
    if base is None:
        return None
    try:
        if _keeps_shared_workspace(world, goal):
            return None
        conversation = _conversation(world, goal.id)
    except Exception:  # noqa: BLE001 -- the shared workspace is the safe fallback
        log.debug("task folder lookup failed for goal %s", getattr(goal, "id", None), exc_info=True)
        return None
    if conversation is None:
        conversation = conversation_id
    if conversation is None:
        return None
    folder = base / _folder_name(conversation)
    if create:
        folder.mkdir(parents=True, exist_ok=True)
    return folder


def use(sandbox, folder: Path | None) -> None:
    """Tell the file tools which shared workspace a task folder can read from."""
    if folder is None or sandbox is None:
        return
    try:
        sandbox.shared_workdir = shared_root()
    except AttributeError:  # a slotted or stub backend: no shared reads
        pass


def _shared(sandbox) -> tuple[Path, Path] | None:
    shared = getattr(sandbox, "shared_workdir", None)
    workdir = getattr(sandbox, "workdir", None)
    if shared is None or workdir is None:
        return None
    try:
        return Path(shared).resolve(), Path(workdir).resolve()
    except (OSError, RuntimeError):
        return None


def _shared_relative(shared: Path, relative: Path) -> Path | None:
    """``relative`` inside the shared workspace, outside every task folder."""
    if not relative.parts or relative.parts[0] == TASKS_DIRNAME or ".." in relative.parts:
        return None
    try:
        source = (shared / relative).resolve()
        inside = source.relative_to(shared)
    except (OSError, RuntimeError, ValueError):
        return None
    if not inside.parts or inside.parts[0] == TASKS_DIRNAME:
        return None
    return inside


def bring_in(sandbox, target: Path) -> None:
    """Copy a shared-workspace file to ``target`` in the task folder, once.

    Does nothing unless ``target`` is missing from the task folder and the
    same path names a regular file in the shared workspace.
    """
    roots = _shared(sandbox)
    if roots is None:
        return
    shared, workdir = roots
    try:
        if os.path.lexists(target):
            return
        relative = Path(target).relative_to(workdir)
    except (OSError, ValueError):
        return
    inside = _shared_relative(shared, relative)
    if inside is None:
        return
    source = shared / inside
    try:
        if not stat.S_ISREG(source.lstat().st_mode):
            return
        from .sandbox import workspace_transfer
        raw = workspace_transfer._read(shared, inside.as_posix())
        workspace_transfer._write(workdir, relative.as_posix(), raw, 0o644)
    except Exception:  # noqa: BLE001 -- a file that cannot be copied stays unread
        log.debug("could not bring %s into the task folder", inside, exc_info=True)


def shared_listing(sandbox, target: Path) -> list[str]:
    """Shared-workspace entries for a ``list_dir`` of ``target``, not already here."""
    roots = _shared(sandbox)
    if roots is None:
        return []
    shared, workdir = roots
    try:
        relative = Path(target).resolve().relative_to(workdir)
    except (OSError, RuntimeError, ValueError):
        return []
    source = shared if not relative.parts else shared / relative
    if relative.parts and _shared_relative(shared, relative) is None:
        return []
    try:
        entries = sorted(os.scandir(source), key=lambda e: e.name)
    except OSError:
        return []
    local = Path(target)
    shown = []
    for entry in entries:
        if (not relative.parts and entry.name == TASKS_DIRNAME) or entry.name.startswith("."):
            continue
        if os.path.lexists(local / entry.name) or entry.is_symlink():
            continue
        shown.append(f"{'d' if entry.is_dir(follow_symlinks=False) else '-'} {entry.name}")
        if len(shown) >= 200:
            shown.append("... (more files in the shared workspace)")
            break
    return shown


__all__ = ["SHARED_NOTE", "TASKS_DIRNAME", "bring_in", "enabled", "folder_for", "shared_listing",
           "shared_root", "use"]
