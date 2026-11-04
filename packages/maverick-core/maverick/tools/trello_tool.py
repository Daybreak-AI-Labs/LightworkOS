"""Trello tool — boards, lists, cards.

Auth: ``TRELLO_KEY`` + ``TRELLO_TOKEN`` (both query params on every
call, per Trello's API).

ops:
  - boards()
  - lists(board_id)
  - cards(list_id, limit)
  - card_get(card_id)
  - card_create(list_id, name, desc, confirm)
  - card_move(card_id, list_id, confirm)
  - comment(card_id, text, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_TR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["boards", "lists", "cards", "card_get",
                     "card_create", "card_move", "comment"],
        },
        "board_id": {"type": "string"},
        "list_id": {"type": "string"},
        "card_id": {"type": "string"},
        "name": {"type": "string"},
        "desc": {"type": "string"},
        "text": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.trello.com/1"


def _auth() -> dict[str, str]:
    key = os.environ.get("TRELLO_KEY", "").strip()
    tok = os.environ.get("TRELLO_TOKEN", "").strip()
    if not key or not tok:
        raise RuntimeError("Trello requires TRELLO_KEY + TRELLO_TOKEN.")
    return {"key": key, "token": tok}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", params={**_auth(), **(params or {})},
                  timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, params: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", params={**_auth(), **params}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _put(path: str, params: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.put)(f"{_API}{path}", params={**_auth(), **params}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_boards(_args: dict) -> str:
    code, data = _get("/members/me/boards", {"fields": "name,url,closed"})
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: boards ({code}): {data}"
    rows = [b for b in data if not b.get("closed")]
    if not rows:
        return "no boards"
    return "\n".join(f"  {b.get('id')}  {(b.get('name') or '')[:50]}" for b in rows)


def _op_lists(args: dict) -> str:
    bid = (args.get("board_id") or "").strip()
    if not bid:
        return "ERROR: lists requires board_id"
    seg = safe_path_segment(bid)
    if seg is None:
        return "ERROR: lists requires a valid board_id"
    code, data = _get(f"/boards/{seg}/lists", {"fields": "name,closed"})
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: lists ({code}): {data}"
    return "\n".join(
        f"  {lst.get('id')}  {lst.get('name')}" for lst in data
        if not lst.get("closed")
    ) or "no lists"


def _op_cards(args: dict) -> str:
    lid = (args.get("list_id") or "").strip()
    if not lid:
        return "ERROR: cards requires list_id"
    seg = safe_path_segment(lid)
    if seg is None:
        return "ERROR: cards requires a valid list_id"
    code, data = _get(f"/lists/{seg}/cards", {"fields": "name,due,url"})
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: cards ({code}): {data}"
    limit = max(1, min(int(args.get("limit") or 50), 200))
    rows = data[:limit]
    if not rows:
        return "no cards"
    return "\n".join(
        f"  {c.get('id')}  {(c.get('name') or '')[:60]:<60}  due={c.get('due', '?')}"
        for c in rows
    )


def _op_card_get(args: dict) -> str:
    cid = (args.get("card_id") or "").strip()
    if not cid:
        return "ERROR: card_get requires card_id"
    seg = safe_path_segment(cid)
    if seg is None:
        return "ERROR: card_get requires a valid card_id"
    code, data = _get(f"/cards/{seg}", {
        "fields": "name,desc,due,url,idList,labels",
    })
    if code == 404:
        return f"card {cid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: card_get ({code}): {data}"
    return (
        f"{data.get('id')}  {data.get('name')}\n"
        f"  due:   {data.get('due', '?')}\n"
        f"  list:  {data.get('idList')}\n"
        f"  url:   {data.get('url')}\n\n"
        f"{(data.get('desc') or '')[:2000]}"
    )


def _op_card_create(args: dict) -> str:
    lid = (args.get("list_id") or "").strip()
    name = (args.get("name") or "").strip()
    if not lid or not name:
        return "ERROR: card_create requires list_id and name"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create card in list {lid}. Re-run with confirm=true."
    code, data = _post("/cards", {
        "idList": lid, "name": name, "desc": args.get("desc") or "",
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: card_create ({code}): {data}"
    return f"created card {data.get('id')}: {data.get('url', '')}"


def _op_card_move(args: dict) -> str:
    cid = (args.get("card_id") or "").strip()
    lid = (args.get("list_id") or "").strip()
    if not cid or not lid:
        return "ERROR: card_move requires card_id and list_id"
    seg = safe_path_segment(cid)
    if seg is None:
        return "ERROR: card_move requires a valid card_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would move {cid} -> list {lid}. Re-run with confirm=true."
    code, data = _put(f"/cards/{seg}", {"idList": lid})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: card_move ({code}): {data}"
    return f"moved {cid} -> {lid}"


def _op_comment(args: dict) -> str:
    cid = (args.get("card_id") or "").strip()
    text = (args.get("text") or "").strip()
    if not cid or not text:
        return "ERROR: comment requires card_id and text"
    seg = safe_path_segment(cid)
    if seg is None:
        return "ERROR: comment requires a valid card_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would comment on {cid}. Re-run with confirm=true."
    code, data = _post(f"/cards/{seg}/actions/comments", {"text": text})
    if code >= 400:
        return f"ERROR: comment ({code}): {data}"
    return f"commented on {cid}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return {
            "boards":      _op_boards,
            "lists":       _op_lists,
            "cards":       _op_cards,
            "card_get":    _op_card_get,
            "card_create": _op_card_create,
            "card_move":   _op_card_move,
            "comment":     _op_comment,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Trello request failed: {type(e).__name__}: {e}"


def trello_tool() -> Tool:
    return Tool(
        name="trello",
        description=(
            "Trello boards / lists / cards. ops: boards, lists, "
            "cards, card_get, card_create / card_move / comment "
            "(mutations confirm=true). Auth: TRELLO_KEY + "
            "TRELLO_TOKEN."
        ),
        input_schema=_TR_SCHEMA,
        fn=_run,
    )
