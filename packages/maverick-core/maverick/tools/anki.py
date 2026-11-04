"""Anki flashcard tool via AnkiConnect.

Talks to a locally running Anki + AnkiConnect add-on (a JSON-RPC endpoint,
default http://127.0.0.1:8765). Add a Basic note to a deck, or list decks.

ops:
  - add_note(deck, front, back)  — add a Basic {Front, Back} note.
  - decks()                      — list deck names.

Set ``ANKI_CONNECT_URL`` to override the endpoint. Stdlib only
(urllib.request + json). The network layer is a single small helper; the
JSON-RPC payload builder is a pure helper tested without any network access.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from . import Tool

_DEFAULT_URL = "http://127.0.0.1:8765"
_VERSION = 6


def _endpoint() -> str:
    return os.environ.get("ANKI_CONNECT_URL", _DEFAULT_URL).strip() or _DEFAULT_URL


def _build_payload(action: str, params: dict | None = None) -> dict:
    """Build an AnkiConnect JSON-RPC request payload."""
    return {"action": action, "version": _VERSION, "params": params or {}}


def _build_add_note_payload(deck: str, front: str, back: str) -> dict:
    """Build the addNote payload for a Basic {Front, Back} note."""
    return _build_payload(
        "addNote",
        {
            "note": {
                "deckName": deck,
                "modelName": "Basic",
                "fields": {"Front": front, "Back": back},
                "options": {"allowDuplicate": False},
                "tags": [],
            }
        },
    )


def _invoke(payload: dict) -> tuple[Any, Any]:
    """POST a payload to AnkiConnect; return (result, error)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        _endpoint(),
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8", errors="replace")
    obj = json.loads(raw)
    return obj.get("result"), obj.get("error")


def _op_add_note(args: dict) -> str:
    deck = (args.get("deck") or "").strip()
    front = (args.get("front") or "").strip()
    back = (args.get("back") or "").strip()
    if not deck:
        return "ERROR: add_note requires deck"
    if not front or not back:
        return "ERROR: add_note requires front and back"
    result, error = _invoke(_build_add_note_payload(deck, front, back))
    if error:
        return f"ERROR: AnkiConnect: {error}"
    return f"added note {result} to {deck}"


def _op_decks(args: dict) -> str:
    result, error = _invoke(_build_payload("deckNames"))
    if error:
        return f"ERROR: AnkiConnect: {error}"
    decks = result or []
    if not decks:
        return "no decks"
    return "\n".join(f"  {d}" for d in decks)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        return {
            "add_note": _op_add_note,
            "decks":    _op_decks,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return (
            f"ERROR: AnkiConnect request failed ({_endpoint()}): "
            f"{type(e).__name__}: {e}"
        )


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["add_note", "decks"]},
        "deck": {"type": "string", "description": "Deck name (add_note)."},
        "front": {"type": "string", "description": "Front field (add_note)."},
        "back": {"type": "string", "description": "Back field (add_note)."},
    },
    "required": ["op"],
}


def anki() -> Tool:
    return Tool(
        name="anki",
        description=(
            "Anki flashcards via AnkiConnect (local JSON-RPC, default "
            "http://127.0.0.1:8765, override with ANKI_CONNECT_URL). "
            "ops: add_note (deck, front, back) adds a Basic note; decks "
            "lists deck names. Requires Anki running with the AnkiConnect "
            "add-on."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=False,
    )
