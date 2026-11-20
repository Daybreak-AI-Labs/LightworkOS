"""Who owns a task started from the command line on this computer.

The dashboard's first-owner setup writes ``dashboard-owner.json`` in the
Lightwork home folder. Once it exists, the dashboard shows each signed-in
person only their own tasks, so a task the CLI started with no owner was
hidden from the owner (404). Command-line access to this home folder is
access as that installation's owner, so CLI tasks are recorded as theirs.
Only a finished, well-formed claim names an owner; anything else leaves the
task ownerless, as before. The dashboard keeps the full claim validation.
"""
from __future__ import annotations

import json

_SCHEMA = "lightwork.local-owner.v1"
_MAX_BYTES = 8192


def goal_owner() -> str:
    """``user:<owner email>`` when this installation has a ready local owner, else ``""``."""
    from ..paths import maverick_home

    path = maverick_home() / "dashboard-owner.json"
    try:
        if path.stat().st_size > _MAX_BYTES:
            return ""
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(row, dict) or row.get("schema") != _SCHEMA or row.get("status") != "ready":
        return ""
    email = row.get("email")
    if not isinstance(email, str) or "@" not in email or len(email) > 320:
        return ""
    return "user:" + email
