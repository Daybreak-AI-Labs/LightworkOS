"""Editable Word answers using Chat's current, selected-answer release policy."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from maverick import markdown_word

from .goal_export_ops_api import _current_export, _export_source

router = APIRouter(tags=["chat-answer-exports"])


def word_answer(text: str, title: str) -> bytes:
    """Editable business text and tables (``maverick.markdown_word``)."""
    try:
        return markdown_word.word_answer(text, title)
    except markdown_word.UnwritableText as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/chat/goal/{goal_id}/download.docx")
def download_word_answer(request: Request, goal_id: int, turn_id: int | None = None) -> Response:
    from .app import download_chat_answer

    _world, goal, _artifacts, version = _export_source(request, goal_id)
    selected = download_chat_answer(request, goal_id, turn_id)
    text = selected.body.decode("utf-8")
    document = word_answer(text, goal.title)
    _current_export(request, goal_id, version)
    current = download_chat_answer(request, goal_id, turn_id)
    if current.body != selected.body:
        raise HTTPException(409, "This answer changed. Reload before downloading its Word document.")
    _current_export(request, goal_id, version)
    suffix = f"-message-{turn_id}" if turn_id is not None else ""
    return Response(document, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document", headers={
        "Content-Disposition": f'attachment; filename="lightwork-answer-{goal_id}{suffix}.docx"',
        "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
    })
