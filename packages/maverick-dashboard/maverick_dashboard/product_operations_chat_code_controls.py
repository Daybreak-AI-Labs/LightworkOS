"""Protected local snippet copying from current native saved Chat sources."""
from __future__ import annotations

import hashlib
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick.chat_threads import ChatThreads
from maverick.governed_operations import digest
from pydantic import BaseModel, ConfigDict, Field

from .answer_projection import projection, validate_current
from .draft_api import context_for
from .goal_export_ops_api import _current_export, _export_source
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, _context

router = APIRouter(tags=["chat-code-controls"])


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: Literal["answer", "turn", "artifact"]
    goal: int = Field(gt=0)
    version: str = Field(pattern=r"^[a-f0-9]{64}$")
    turn: int | None = Field(default=None, gt=0)
    artifact: int | None = Field(default=None, ge=0, le=255)


def _page(request, goal_id):
    from . import auth
    from ._shared import _world
    from .app import require_page_visible

    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        via = (getattr(principal, "claims", None) or {}).get("via")
        refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                   "proxy": auth._proxy_principal}.get(via)
        if refresh is not None:
            fresh = refresh(request)
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before copying this saved text.")
            request.state.principal = principal = fresh
        if principal is not None:
            auth._enforce_scim_active(principal)
            auth._enforce_workspace_policies(request, principal)
        auth.require_permission(request, "view")
        auth.require_page_permission(request, "/chat")
        require_page_visible(request, "/chat")
        world = _world()
        before = _context(request)
    view = projection(request, world, goal_id)
    if _context(request) != before:
        raise HTTPException(409, "Your conversation access changed. Reopen its current controls.")
    return world, view["goal"], view, digest([before, view["answer_version"]])


@router.post("/api/v1/chat/code-controls/{page_goal}/source")
def source(request: Request, page_goal: int, body: SourceIn):
    """Read only: no model request, upload, clipboard effect or replay writer."""
    from .app import download_chat_answer

    world, _goal, view, page_version = _page(request, page_goal)
    if context_for(request) != body.context:
        raise HTTPException(409, "Your account or workspace changed. Reopen this conversation.")
    source_version = None
    include_artifacts = body.source == "artifact"
    _export_source(request, body.goal, include_artifacts=include_artifacts)
    if body.source in {"answer", "artifact"}:
        if body.goal != page_goal or body.turn is not None or body.version != view["answer_version"]:
            raise HTTPException(409, "This saved answer changed. Refresh its copy controls.")
        _, _, _, source_version = _export_source(request, page_goal, include_artifacts=include_artifacts)
        if body.source == "answer":
            if body.artifact is not None:
                raise HTTPException(422, "Choose one saved answer source.")
            text = download_chat_answer(request, page_goal).body.decode("utf-8")
            plain = False
        else:
            if body.artifact is None or body.artifact >= len(view["artifacts"]):
                raise HTTPException(404, "This saved file is no longer available.")
            row = view["artifacts"][body.artifact]
            if row.get("table") is not None or not isinstance(row.get("prose"), str):
                raise HTTPException(409, "This file does not contain a supported text snippet.")
            text, plain = row["prose"], row.get("kind") in {"code", "json", "csv"}
    else:
        if body.turn is None or body.artifact is not None:
            raise HTTPException(422, "Choose one saved message source.")
        page_binding, binding = ChatThreads(world).binding(page_goal), ChatThreads(world).binding(body.goal)
        if page_binding is None or binding is None or page_binding.conversation_id != binding.conversation_id:
            raise HTTPException(404, "This message is not in the current conversation.")
        _, _, _, source_version = _export_source(request, body.goal)
        text = download_chat_answer(request, body.goal, body.turn).body.decode("utf-8")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != body.version:
            raise HTTPException(409, "This saved message changed. Reopen its current copy controls.")
        plain = False
    if len(text.encode("utf-8")) > 2 * 1024 * 1024:
        raise HTTPException(409, "This saved text is too large to copy here. Use its document download.")
    validate_current(request, world, view, body.context)
    if _page(request, page_goal)[3] != page_version:
        raise HTTPException(409, "This conversation changed while it was read. Refresh its copy controls.")
    if source_version is not None:
        _current_export(request, body.goal, source_version, include_artifacts=include_artifacts)
        if body.source != "artifact" and download_chat_answer(request, body.goal, body.turn).body.decode("utf-8") != text:
            raise HTTPException(409, "This saved message changed while it was read. Refresh it again.")
    if context_for(request) != body.context:
        raise HTTPException(409, "Your account or workspace changed. Reopen this conversation.")
    return JSONResponse({"context": body.context, "version": body.version, "text": text, "plain": plain},
                        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"})


def snapshot(request, selection):
    try:
        goal_id = int(selection.get("id", selection.get("goal_id", 0)))
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "Open the saved conversation first.") from exc
    if goal_id <= 0:
        raise HTTPException(422, "Open the saved conversation first.")
    _, _, view, version = _page(request, goal_id)
    return Snapshot(digest([context_for(request), version, view["answer_version"]]),
        "Copy a snippet from this saved conversation",
        "Open the labelled Copy code controls in this conversation. Opening them does not copy, execute or send code.")


def prepare(request, selection, _arguments):
    value = snapshot(request, selection)
    return Preview(value.summary, native={"chat_code_review": {"scope": "current_page"}})


def entries():
    return (Adapter("conversation.code_controls", "Open snippet copy controls", "tasks", "/chat",
        ("/chat/goal/*",), EmptyInput, snapshot, prepare,
        aliases=("copy a code block", "copy this code", "open snippet copy controls", "copy one snippet")),)
