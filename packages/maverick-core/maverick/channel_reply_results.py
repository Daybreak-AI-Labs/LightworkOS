"""Export actual saved task output into the existing channel delivery custody.

Only native artifact content is exported. A path written in an answer is never
opened, and text is not represented as a converted PDF or Office document.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from .paths import current_tenant_id_strict

MAX_FILES = 10
_KINDS = {"text", "markdown", "table", "code", "json", "csv", "html"}
_FILE_CHANNELS = {"slack", "telegram"}


def task_link(goal_id: int) -> str | None:
    from .env_setting import env_or_config

    value = str(env_or_config("MAVERICK_PUBLIC_BASE_URL", "channels", "public_base_url", "") or "").strip()
    parts = urlsplit(value)
    if (parts.scheme not in {"http", "https"} or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment):
        return None
    return value.rstrip("/") + "/chat/goal/" + str(goal_id)


def require_source(source: dict) -> None:
    """Recheck live identity, task ownership and retained source access."""
    try:
        _require_source(source)
    except Exception as exc:
        raise PermissionError("Current task ownership and source access are required for this reply") from exc


def _require_source(source: dict) -> None:
    from maverick_dashboard.auth import fresh_configuration, stored_automation_identity

    from .chat_message_actions import require_copy_sources
    from .domain import suites_for_domain
    from .knowledge_task_context import require_read
    from .oidc import oidc_enabled
    from .personal_identity import account_identity
    from .server import _linked_channel_refusal
    from .world_model import close_world_if_owned, open_world

    if source.get("tenant") != current_tenant_id_strict():
        raise PermissionError("The saved reply belongs to another workspace")
    principal = source["principal"]
    account = source["account_sha256"]
    if oidc_enabled():
        from .channel_oidc_bridge import resolve
        if resolve(source["channel"], account, source["provider_tenant_id"],
                   source["provider_sender_id"]) != principal:
            raise PermissionError("The chat account's current identity changed")
    if account and _linked_channel_refusal(source["channel"],
            account_identity(principal, account), account):
        raise PermissionError("This chat account's permission changed")
    world = open_world()
    try:
        goal = world.get_goal(source["goal_id"])
        if (goal is None or goal.owner != source["owner"]
                or goal.execution_principal != source["execution_principal"]):
            raise PermissionError("The saved reply's task ownership changed")
        with fresh_configuration():
            _, _, suites = stored_automation_identity(source["execution_principal"])
            if suites is not None and not suites_for_domain(goal.domain) <= suites:
                raise PermissionError("The task's department is no longer available")
            require_read(goal, goal.owner)
            require_copy_sources(world, goal.id,
                                 authorize=lambda row: _source_access(row, goal.owner, suites))
    finally:
        close_world_if_owned(world)


def _source_access(goal, owner, suites):
    from .domain import suites_for_domain

    if goal.owner != owner:
        raise PermissionError("A retained reply source changed ownership")
    if suites is not None and not suites_for_domain(goal.domain) <= suites:
        raise PermissionError("A retained reply source's department is no longer available")


def _artifact_file(row: dict) -> dict:
    from .attachments import validate_attachment

    if (row.get("kind") not in _KINDS or type(row.get("id")) is not int
            or type(row.get("version")) is not int or not isinstance(row.get("content"), str)):
        raise ValueError("A saved output cannot be safely exported as text")
    title = re.sub(r"[^\w .-]", "-", str(row.get("title") or "Saved output"))[:100].strip(" .-") or "Saved output"
    # Native text/table content is an export, not a binary document conversion.
    suffix = ".md" if row["kind"] in {"markdown", "table"} else ".txt"
    name = f"output-{row['id']}-v{row['version']}-{title}{suffix}"
    data = row["content"].encode("utf-8")
    mime = "text/markdown" if suffix == ".md" else "text/plain"
    sha = validate_attachment(name, mime, data)
    return {"filename": name, "mime": mime, "data": data, "sha256": sha,
            "source": {"artifact_id": row["id"], "version": row["version"]}}


def prepare_reply(world, msg, goal_id: int, text: str, *, owner: str,
                  execution_principal: str, principal: str):
    """Attach complete native output material, before the delivery receipt saves it."""
    from maverick_channels.base import Reply
    from maverick_channels.rich_render import enabled, has_rich_blocks, render_html

    goal = world.get_goal(goal_id)
    if goal is None or goal.status != "done":
        return text
    rows = world.latest_artifacts(goal_id)
    rich_requested = enabled() and has_rich_blocks(text)
    rich = rich_requested and msg.channel in _FILE_CHANNELS
    if rich_requested and not rich:
        text += "\n\nThis chat cannot attach a rendered copy. The original reply is shown above."
    if not rows and not rich:
        return text
    source = {"goal_id": goal_id, "owner": owner, "execution_principal": execution_principal,
              "tenant": current_tenant_id_strict(), "channel": msg.channel,
              "principal": principal, "account_sha256": getattr(msg, "_verified_channel_account_sha256", None),
              "provider_tenant_id": msg.provider_tenant_id, "provider_sender_id": msg.provider_sender_id}
    require_source(source)
    files = [_artifact_file(row) for row in rows]
    if rich:
        data = render_html(text).encode("utf-8")
        files.append({"filename": "Rendered reply.html", "mime": "text/html", "data": data,
                      "sha256": hashlib.sha256(data).hexdigest(), "source": {"rendered_reply": True}})
    if len(files) > MAX_FILES:
        return text + "\n\nThe saved outputs exceed this chat's ten-file limit. Open the task in Lightwork to review every output."
    from .attachments import validate_attachment
    total = 0
    for item in files:
        validate_attachment(item["filename"], item["mime"], item["data"], existing_total=total)
        total += len(item["data"])
    require_source(source)
    names = [item["filename"] for item in files]
    thread = msg.conversation_ref if msg.channel == "slack" else msg.message_id
    if msg.channel not in _FILE_CHANNELS:
        text += "\n\nSaved text exports: " + ", ".join(names) + ". File attachments cannot be delivered in this chat."
        link = task_link(goal_id)
        text += "\nOpen the task in Lightwork to read its saved output." + (" " + link if link else "")
        # No send here reads files: keep the source for the access re-check at
        # delivery, without sealing and storing files nothing will read.
        msg._channel_reply_material = {"source": source, "files": []}
        return Reply(text, thread_ref=thread)
    if rich:
        text += "\n\nA rendered HTML copy is attached. It uses online display libraries; offline it retains the original text."
    # Runtime-only material comes from this native goal, never an inbound path.
    msg._channel_reply_material = {"source": source, "files": files}
    return Reply(text, attachments=names, thread_ref=thread)
