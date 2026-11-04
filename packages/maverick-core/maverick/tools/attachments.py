"""list_attachments / read_attachment tools.

``list_attachments`` enumerates files the user uploaded with the goal;
``read_attachment`` returns one's text by id. Attachments live outside the
agent workspace (``read_file`` cannot reach them) and may be sealed at rest,
so reading goes through :func:`maverick.attachments.read_bytes`, scoped to the
current goal. Images are embedded as vision blocks separately (see
``maverick.attachments.content_blocks_for_goal``).
"""
from __future__ import annotations

from . import Tool


def list_attachments_tool(world, goal_id: int | None) -> Tool:
    def fn(_args: dict) -> str:
        if goal_id is None:
            return "(no goal context; no attachments)"
        atts = world.list_attachments(goal_id)
        if not atts:
            return "(no attachments)"
        lines = [
            f"{a.id}  {a.filename}  {a.mime}  {a.size_bytes}B  {a.path}"
            for a in atts
        ]
        return "\n".join(lines)

    return Tool(
        name="list_attachments",
        description=(
            "List files the user uploaded with this goal. Returns one line per "
            "attachment: id, filename, mime, size, path. Use `read_attachment` "
            "with the id to read text content; images are already visible to you."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        fn=fn,
    )


_MAX_READ_CHARS = 100_000
_TEXT_MIMES = ("text/", "application/json", "application/xml", "application/csv")


def read_attachment_tool(world, goal_id: int | None) -> Tool:
    def fn(args: dict) -> str:
        if goal_id is None:
            return "ERROR: no goal context; no attachments"
        try:
            wanted = int(args["id"])
        except (KeyError, TypeError, ValueError):
            return "ERROR: 'id' must be an attachment id from list_attachments"
        match = next((a for a in world.list_attachments(goal_id) if a.id == wanted), None)
        if match is None:
            return f"ERROR: no attachment {wanted} on this goal"
        if not match.mime.startswith(_TEXT_MIMES):
            return (f"ERROR: {match.filename} is {match.mime}; images are already "
                    "visible to you, and documents have a text companion when one "
                    "could be extracted")
        from ..attachments import read_bytes
        try:
            text = read_bytes(match.path).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as data
            return f"ERROR: {match.filename} could not be read: {exc}"
        if len(text) > _MAX_READ_CHARS:
            return text[:_MAX_READ_CHARS] + f"\n... [truncated, total {len(text)} chars]"
        return text

    return Tool(
        name="read_attachment",
        description=("Read the text of one file the user uploaded with this goal, "
                     "by the id `list_attachments` returns."),
        input_schema={"type": "object",
                      "properties": {"id": {"type": "integer"}},
                      "required": ["id"]},
        fn=fn,
    )
