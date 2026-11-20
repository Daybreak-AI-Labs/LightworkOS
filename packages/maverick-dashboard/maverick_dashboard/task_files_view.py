"""The files a task saved, as the task page shows and serves them.

``maverick.task_files`` records what a task wrote and serves only those bytes;
this module adds the page's view: the list, the release rule (the same one the
answer's own download follows) and the answer text with links to the task's
files made into download links.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

NOT_RELEASED = ("A reviewer must approve this task's result before its files can be "
                "downloaded.")
UNCHECKED = ("Downloads are unavailable until this task's review requirements can be "
             "checked.")
# A markdown link target the agent wrote for a file: the sandbox: scheme or an
# absolute workspace path (both render as dead or wrong links otherwise).
_LINK_TARGET = re.compile(r"\]\(((?:sandbox:|/)[^()\s]+)\)")


def href(goal_id: int, number: int) -> str:
    return f"/chat/goal/{int(goal_id)}/task-files/{int(number)}"


def release_state(world, goal) -> tuple[bool, str]:
    """Whether this task's files may be downloaded now, and why not."""
    try:
        from .deliverable_policy import goal_gate

        if goal_gate(goal.domain) is None:
            return True, ""
        signoff = world.signoff_for(goal.id)
    except Exception:  # an unreadable policy never releases files
        return False, UNCHECKED
    if signoff is None or signoff.get("decision") != "approved":
        return False, NOT_RELEASED
    return True, ""


def _size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def linked_result(text: str, goal_id: int, files) -> str:
    """``text`` with links to this task's own saved files pointing at their
    downloads. Every other link is left exactly as written."""
    from maverick.task_files import sandbox_link_number

    if not text or not files:
        return text

    def swap(match: re.Match) -> str:
        number = sandbox_link_number(files, match.group(1))
        return match.group(0) if number is None else f"]({href(goal_id, number)})"

    return _LINK_TARGET.sub(swap, text)


def context(world, goal) -> dict[str, Any]:
    """Template values for the answer panel: never raises."""
    from maverick.task_files import files_for

    try:
        files = files_for(world, goal.id)
    except Exception:  # the answer still renders without its file list
        files = []
    released, note = release_state(world, goal) if files else (True, "")
    shown = [{"number": f.number, "name": f.name, "size_text": _size(f.size),
              "href": href(goal.id, f.number)} for f in files]
    result = goal.result or ""
    return {
        "task_files": shown,
        "task_files_released": released,
        "task_files_note": note,
        "result_display": linked_result(result, goal.id, files) if released else result,
    }


def content_disposition(name: str) -> str:
    """An attachment header safe for any file name."""
    ascii_name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .") or "file"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name, safe='')}"
