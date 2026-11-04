"""Private organization over immutable conversation/task identities."""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick.chat_threads import ChatThreads
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from .auth import assert_goal_access, caller_principal, domain_suites_allowed, require_permission
from .draft_api import context_for

router = APIRouter(tags=["conversations"])


class OrganizationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=0)
    operation_id: str = Field(min_length=8, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field("", max_length=200)
    pinned: bool
    archived: bool


def _store(request):
    # A namespace per authorized account context prevents reading other people's
    # private labels while scanning pin/archive metadata.
    return GovernedRecordStore("conversation-organization-" + context_for(request), "CO", "conversation_organization")


def _index(request):
    context = context_for(request)
    cached = getattr(request.state, "conversation_organization", None)
    if cached and cached[0] == context:
        return cached[1]
    value = _store(request).get("CO-index") or {}
    request.state.conversation_organization = (context, value)
    return value


def _identity(request, world, goal_id, goal=None):
    if goal is None or goal.id != goal_id:
        goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "Conversation is unavailable.")
    assert_goal_access(request, goal)
    owner = caller_principal(request) or ""
    if (goal.owner or "") != owner:
        raise HTTPException(403, "Conversation organization belongs to its owner.")
    if not domain_suites_allowed(request, goal.domain):
        raise HTTPException(403, "Conversation department access changed.")
    binding = ChatThreads(world).binding(goal.id)
    # A conversation's own root is the goal read and checked above; only a
    # different root is read and checked again.
    root = goal if binding is None or binding.root_id == goal.id else world.get_goal(binding.root_id)
    if root is None or (root.owner or "") != owner:
        raise HTTPException(404, "Conversation ownership changed. Reload before continuing.")
    if root is not goal:
        assert_goal_access(request, root)
        if not domain_suites_allowed(request, root.domain):
            raise HTTPException(403, "Conversation department access changed.")
    identity = [root.id, root.created_at, owner]
    key = "CO-" + hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:48]
    return root, key


def organization(request, world, goal_id, *, goal=None):
    """``goal``: the conversation's goal when the caller has just read it."""
    root, key = _identity(request, world, goal_id, goal)
    index = _index(request)
    record = index.get("entries", {}).get(key)
    if record and (record.get("root_id") != root.id or record.get("owner") != (root.owner or "")):
        raise ValueError("Organization metadata does not match its conversation.")
    return {"root_id": root.id, "original_title": root.title, "title": (record or {}).get("title", ""),
            "pinned": (record or {}).get("pinned", False), "archived": (record or {}).get("archived", False),
            "revision": index.get("revision", 0), "context": context_for(request)}


def present_title(request, world, goal):
    try:
        return organization(request, world, goal.id)["title"] or goal.title
    except Exception:
        return goal.title


def pinned_roots(request, world):
    """Pin metadata is one bounded owner-private CAS document, not a global scan."""
    index = _index(request)
    found = []
    for entry in index.get("entries", {}).values():
        if not entry.get("pinned") or entry.get("archived"):
            continue
        try:
            root, _ = _identity(request, world, entry["root_id"])
        except HTTPException:
            continue
        if root.created_at == entry.get("root_created_at"):
            found.append(root)
    return found


@router.get("/api/v1/conversations/{goal_id}/organization")
def get_organization(request: Request, response: Response, goal_id: int):
    from .app import _world

    require_permission(request, "view")
    response.headers["Cache-Control"] = "private, no-store"
    return organization(request, _world(), goal_id)


@router.put("/api/v1/conversations/{goal_id}/organization")
def save_organization(request: Request, goal_id: int, body: OrganizationIn):
    from .app import _require_same_origin, _world

    require_permission(request, "view")  # private organization grants no execution permission
    _require_same_origin(request)
    if request.headers.get("X-Lightwork-Conversation-Context") != context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Reload before saving.")
    title = body.title.strip()
    if any(ord(char) < 32 for char in title):
        raise HTTPException(422, "Use a single line for the conversation name.")
    world = _world()
    root, key = _identity(request, world, goal_id)
    store = _store(request)
    value = {"title": title, "pinned": body.pinned, "archived": body.archived}
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    current = store.get("CO-index")
    entry = (current or {}).get("entries", {}).get(key)
    if entry and entry.get("operation_id") == body.operation_id:
        if entry.get("request_sha256") != digest:
            raise HTTPException(409, "This retry reference belongs to a different change.")
        return organization(request, world, goal_id)
    if (current or {}).get("revision", 0) != body.expected_revision:
        raise HTTPException(409, "Organization changed in another window. Your inputs are kept; refresh before saving again.")

    def mutate(record):
        fresh, fresh_key = _identity(request, world, goal_id)
        if fresh_key != key:
            raise RecordConflict("Conversation ownership or membership changed.")
        entries = dict(record.get("entries") or {})
        if key not in entries and len(entries) >= 10000:
            raise ValueError("Conversation organization reached its supported limit.")
        if value["pinned"] and not value["archived"] and sum(bool(entry.get("pinned") and not entry.get("archived")) for entry_key, entry in entries.items() if entry_key != key) >= 20:
            raise HTTPException(422, "Up to 20 conversations can be pinned. Unpin another conversation first.")
        entries[key] = {**value, "root_id": fresh.id, "owner": fresh.owner or "", "root_created_at": fresh.created_at,
                        "operation_id": body.operation_id, "request_sha256": digest}
        record["entries"] = entries

    try:
        if current:
            store.update("CO-index", mutate, expected_revision=body.expected_revision, action="organize_conversation", actor=caller_principal(request) or "local-operator")
        else:
            record = {"id": "CO-index", "schema": 1, "entries": {}}
            mutate(record)
            store.create(record, action="organize_conversation", actor=caller_principal(request) or "local-operator", max_records=1)
    except RecordConflict as exc:
        raise HTTPException(409, "Organization changed in another window. Refresh before retrying; your draft is kept.") from exc
    request.state.conversation_organization = None
    return organization(request, world, goal_id)


@router.get("/api/v1/conversations")
def conversations(request: Request, response: Response, q: str = Query("", max_length=200),
                  before_id: int | None = Query(None, ge=1), view: str = Query("active", pattern="^(active|archived|pinned|all)$")):
    from .app import _world

    require_permission(request, "view")
    response.headers["Cache-Control"] = "private, no-store"
    world = _world()
    threads = ChatThreads(world)
    gs, gv = threads._scope("g")
    owner = caller_principal(request) or ""
    terms = q.casefold().split()
    if terms:
        cs, cv = threads._scope("c")
        cursor = " AND t.id < ?" if before_id else ""
        found = world.query("SELECT t.id,t.goal_id,t.content,c.id FROM turns t JOIN goals g ON g.id=t.goal_id "
                            "JOIN conversations c ON c.id=t.conversation_id WHERE g.owner=? AND c.channel='web' "
                            f"AND t.role IN ('user','assistant') AND {gs} AND {cs}{cursor} ORDER BY t.id DESC LIMIT 501",
                            (owner, *gv, *cv, *((before_id,) if before_id else ())))
    else:
        cursor = " AND g.id < ?" if before_id else ""
        found = world.query("SELECT g.id,g.id,g.title FROM goals g WHERE g.owner=? AND g.parent_id IS NULL "
                            f"AND {gs}{cursor} ORDER BY g.id DESC LIMIT 501", (owner, *gv, *((before_id,) if before_id else ())))
    items, seen = [], set()
    scanned, next_before = 0, before_id
    for row in found[:500]:
        scanned += 1
        next_before = int(row[0])
        try:
            if terms:
                binding = threads.binding(int(row[1]))
                if binding is None or binding.conversation_id != int(row[3]):
                    continue
            metadata = organization(request, world, int(row[1]))
        except HTTPException:
            continue
        if metadata["root_id"] in seen or (view == "active" and metadata["archived"]) or (view == "archived" and not metadata["archived"]) or (view == "pinned" and not metadata["pinned"]):
            continue
        content = threads.store.open(row[2]) or ""
        title = metadata["title"] or metadata["original_title"]
        haystack = (title + "\n" + content).casefold()
        if any(term not in haystack for term in terms):
            continue
        seen.add(metadata["root_id"])
        position = max(0, content.casefold().find(terms[0]) - 80) if terms else 0
        items.append({**metadata, "display_title": title, "matched_goal_id": int(row[1]),
                      "snippet": content[position:position + 260] if terms else ""})
        if len(items) == 50:
            break
    return {"items": sorted(items, key=lambda item: (not item["pinned"], -item["root_id"])),
            "has_more": len(found) > scanned, "before_id": next_before,
            "scanned": scanned, "context": context_for(request),
            "scope": "Search covers stored user and assistant chat messages across history. Continue scanning to include older matches; attachments and external records are excluded."}


@router.get("/conversations")
def conversations_page(request: Request):
    from .app import templates

    require_permission(request, "view")
    return templates.TemplateResponse(request, "conversations.html", {"conversation_context": context_for(request)}, headers={"Cache-Control": "private, no-store"})
