"""Comment threads and @mentions on tasks, runs, approvals and policies (NOT-4).

Who may read a thread is exactly who may open its object: a task or run's
owner (and anyone holding a reviewed content-read grant for that task), the
people who can open an approval card, and the people who manage a policy.
The mention list offers only those people, the server checks every mention
against the same rule, and a mention is withdrawn from the notification inbox
if the person can no longer open the object.
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth

router = APIRouter()
log = logging.getLogger(__name__)

#: The policy pages that carry a thread: (title, page, permission to read).
POLICIES = {
    "tools": ("Tool permissions", "/permissions", "operate"),
    "spending-limits": ("Spending limits", "/spending-limits", "admin"),
    "data-use": ("Data use rules", "/data-use", "operate"),
}
_TASK_PERMISSION = "view"
_OUTSIDE = "You can mention only people who can open this item. Choose someone from the list."
_UNCHECKED = ("Mentions can't be checked right now: who can open this item could not be read. "
              "Post without the mention or try again.")


def _comments():
    from maverick import comments

    from .feature_gate import feature_off

    if not comments.enabled():
        raise feature_off("collaboration.comments", "Comments")
    return comments


def _world():
    from ._shared import _world as world

    return world()


def _goal_readers(goal, *, among=None) -> set[str]:
    """Those who can open a task now (``auth.goal_readable_by``): its owner,
    or someone holding a current reviewed read grant for it who is still a
    global administrator with access to its department. With ``among``, only
    those people are checked."""
    from . import content_access

    owner = getattr(goal, "owner", "") or ""
    if among is not None:
        # The grant store is read once, never for the owner alone; an error
        # reading it is weighed per person by goal_readable_by.
        try:
            grants = content_access.grant_readers(owner, resource_kind="goal", resource_id=str(goal.id),
                                                  among=set(among) - {owner})
        except Exception as exc:  # noqa: BLE001 -- raised again per person, see above
            grants = exc
        return {principal for principal in among if auth.goal_readable_by(principal, goal, grants=grants)}
    grants = content_access.grant_readers(owner, resource_kind="goal", resource_id=str(goal.id))
    candidates = ({owner} if owner else set()) | grants
    return {principal for principal in candidates if auth.goal_readable_by(principal, goal, grants=grants)}


def _object(request: Request | None, kind: str, object_id: str, *, principal: str = "") -> dict:
    """The object a thread is about, after checking the reader may open it.

    With a request, the caller's own access is checked (404 or 403 as the
    object's page would answer). Without one, ``principal`` is checked against
    the same readers, for a mention shown later in a notification.
    """
    from . import people_directory

    world = _world()
    if kind == "task":
        goal = world.get_goal(int(object_id)) if object_id.isdigit() else None
        if goal is None:
            raise HTTPException(404, "That task no longer exists.")
        if request is not None:
            auth.require_permission(request, _TASK_PERMISSION)
            auth.assert_goal_access(request, goal)
        readers = _goal_readers(goal, among={principal} if principal else None)
        return {"label": f"Task: {str(goal.title)[:120]}", "href": f"/chat/goal/{goal.id}", "readers": readers,
                "subject": goal}
    if kind == "run":
        from maverick.flow import store

        if request is not None:
            auth.require_permission(request, "operate")
            from .flows_api import _load_owned_run

            run = _load_owned_run(request, object_id)
        else:
            run = store.load_run(object_id)
        if run is None:
            raise HTTPException(404, "That run no longer exists.")
        owner = getattr(run, "owner", "") or ""
        flow_id = getattr(run, "flow_id", "") or "flow"
        return {"label": "Workflow run", "href": f"/flows/{flow_id}/runs/{object_id}",
                "readers": {owner} if owner else set()}
    if kind == "approval":
        from . import content_access

        if not object_id.isdigit():
            raise HTTPException(404, "No such approval.")
        if request is not None:
            auth.require_permission(request, "operate")
            approval = content_access.require_approval_content(request, object_id, world)
        else:
            approval = world.get_approval(int(object_id))
            if approval is None:
                raise HTTPException(404, "No such approval.")
        readers = people_directory.allowed(content_access.approval_readers(approval, world), "operate")
        # ``checked``: these readers already passed the company directory check.
        return {"label": f"Request #{approval.id}", "href": f"/approvals#approval-{approval.id}",
                "readers": readers, "checked": True, "subject": approval}
    if kind == "policy":
        if object_id not in POLICIES:
            raise HTTPException(404, "That policy has no comments.")
        title, href, permission = POLICIES[object_id]
        if request is not None:
            auth.require_permission(request, permission)
        if principal:
            # Checked for the person directly: the list of people stops at 200.
            readers = {principal} if people_directory.may(principal, permission) else set()
        else:
            readers = {p["principal"] for p in people_directory.candidates(permission)}
        return {"label": f"Policy: {title}", "href": href, "readers": readers, "checked": True,
                "permission": permission}
    raise HTTPException(404, "Comments work on tasks, runs, approvals and policies.")


def _mentionable(kind: str, target: dict, mentions: set[str]) -> set[str]:
    """Those of ``mentions`` who can open ``target`` now, by the same rules as
    its readers, checked only for the people mentioned. An account the
    company directory turned off can no longer sign in to read a mention.
    Run inside ``strict_reads.strict()``, so a source that cannot be read
    raises instead of reading as "not allowed"."""
    from . import content_access, people_directory

    if kind == "task":
        return people_directory.signed_in(_goal_readers(target["subject"], among=mentions))
    if kind == "run":
        return people_directory.signed_in(mentions & target["readers"])
    if kind == "approval":
        return _every(mentions, lambda: people_directory.allowed(mentions, "operate"),
                      lambda: content_access.approval_readers(target["subject"], _world(), among=mentions))
    # A policy: whoever holds its permission now, among the people it could list.
    return people_directory.allowed(mentions, target["permission"], known_only=True)


def _every(mentions: set[str], *checks) -> set[str]:
    """Those of ``mentions`` every check allows. A check that refuses someone
    decides for them even when another check cannot be read; the error is
    raised only if anyone is left whom every readable check allows."""
    left, unreadable = set(mentions), None
    for check in checks:
        try:
            left &= check()
        except Exception as exc:  # noqa: BLE001 -- only decides for people the others allow
            unreadable = unreadable or exc
    if unreadable is not None and left:
        raise unreadable
    return left


def _check_mentions(kind: str, target: dict, mentions: set[str]) -> None:
    """A 422 when someone mentioned cannot open the item; a 503 when someone
    cannot be confirmed now because a source could not be read."""
    from . import strict_reads

    unconfirmed = set()
    with strict_reads.strict():
        try:
            outside = mentions - _mentionable(kind, target, mentions)
        except Exception:  # noqa: BLE001 -- decided person by person below
            # Each person on their own: someone who cannot open the item is
            # refused even while someone else cannot be confirmed.
            outside = set()
            for mention in sorted(mentions):
                try:
                    if not _mentionable(kind, target, {mention}):
                        outside.add(mention)
                except Exception:  # noqa: BLE001 -- never mention someone unchecked
                    unconfirmed.add(mention)
    if outside:
        raise HTTPException(422, _OUTSIDE)
    if unconfirmed:
        raise HTTPException(503, _UNCHECKED)


def _people(readers: set[str], viewer: str, *, checked: bool = False) -> list[dict]:
    """The people a mention can name. ``checked``: the readers already
    passed the directory check (approvals and policies)."""
    from . import people_directory
    from .identity_format import humanize_principal

    offered = readers - {viewer}
    if not checked:
        try:
            offered = people_directory.signed_in(offered)
        except Exception:  # noqa: BLE001 -- an unreadable directory offers nobody to mention
            log.warning("comment mentions unavailable: the company directory could not be read")
            offered = set()
    out = []
    for principal in sorted(offered):
        ident = humanize_principal(principal)
        out.append({"principal": principal,
                    "label": f"{ident.name} ({ident.detail})" if ident.detail and ident.detail != "Email" else ident.name})
    return sorted(out, key=lambda person: person["label"].lower())


def _view(row: dict, viewer: str) -> dict:
    from .identity_format import humanize_principal

    return {"id": row["id"], "author": humanize_principal(row["author"]).name,
            "mine": row["author"] == viewer, "body": row["body"], "created_at": row["created_at"],
            "mentions": [humanize_principal(p).name for p in row["mentions"]]}


def _thread(request: Request, kind: str, object_id: str, *, target: dict | None = None) -> dict:
    store = _comments()
    viewer = auth.caller_principal(request) or ""
    if target is None:
        target = _object(request, kind, object_id)
    rows = store.list_for(kind, object_id)
    return {"comments": [_view(row, viewer) for row in rows],
            "people": _people(target["readers"], viewer, checked=target.get("checked", False)) if viewer else [],
            "can_comment": viewer.startswith("user:"),
            "label": target["label"]}


@router.get("/api/v1/comments")
async def thread(request: Request, kind: str = Query(..., max_length=16),
                 id: str = Query(..., min_length=1, max_length=128)):  # noqa: A002 -- the query name people see
    return await run_in_threadpool(_thread, request, kind, id)


class CommentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(max_length=16)
    id: str = Field(min_length=1, max_length=128)
    body: str = Field(min_length=1, max_length=4000)
    mentions: list[str] = Field(default_factory=list, max_length=20)


def _post(request: Request, body: CommentIn) -> dict:
    store = _comments()
    author = auth.caller_principal(request) or ""
    if not author.startswith("user:"):
        raise HTTPException(403, "Sign in with your own account to comment.")
    target = _object(request, body.kind, body.id)
    mentions = set(body.mentions)
    if author in mentions:
        raise HTTPException(422, _OUTSIDE)
    if mentions:
        _check_mentions(body.kind, target, mentions)
    try:
        row = store.add(body.kind, body.id, author=author, body=body.body, mentions=body.mentions)
    except store.CommentError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {**_thread(request, body.kind, body.id, target=target), "posted": _view(row, author)}


@router.post("/api/v1/comments", status_code=201)
async def post(request: Request, body: CommentIn):
    return await run_in_threadpool(_post, request, body)


def _remove(request: Request, comment_id: int) -> dict:
    store = _comments()
    viewer = auth.caller_principal(request) or ""
    row = store.get(comment_id)
    if row is None:
        raise HTTPException(404, "That comment no longer exists.")
    _object(request, row["kind"], row["object_id"])
    if row["author"] != viewer or not store.remove(comment_id, by=viewer):
        raise HTTPException(403, "Only the person who wrote a comment can delete it.")
    return _thread(request, row["kind"], row["object_id"])


@router.delete("/api/v1/comments/{comment_id}")
async def remove(request: Request, comment_id: int):
    return await run_in_threadpool(_remove, request, comment_id)


def mention_sources(actor: str, *, since: float | None = None) -> list[dict]:
    """Personal notification sources for comments that mention ``actor``.

    Each mention is checked again now: someone who can no longer open the
    item does not see the mention (or its author's words, which stay in the
    app; the alert carries only who mentioned you and where)."""
    from maverick import comments

    from .identity_format import humanize_principal

    if not comments.enabled():
        return []
    start = time.time() - 7 * 86400 if since is None else since
    out = []
    for row in comments.mentions_for(actor, since=start):
        try:
            target = _object(None, row["kind"], row["object_id"], principal=actor)
        except HTTPException:
            continue
        if actor not in target["readers"]:
            continue
        who = humanize_principal(row["author"]).name
        out.append({"ref": f"comment:{row['id']}", "version": "1", "category": "mention",
                    "title": target["label"], "label": "Mentioned you",
                    # The approval card itself is the place to read its thread.
                    "href": target["href"] if row["kind"] == "approval"
                    else f"{target['href']}#comment-{row['id']}",
                    "goal_id": int(row["object_id"]) if row["kind"] == "task" else None,
                    "project_id": None, "occurred_at": row["created_at"],
                    "reason": f"{who} mentioned you in a comment",
                    "action": "Read the comment and reply", "no_due": "Nothing is due"})
    return out
