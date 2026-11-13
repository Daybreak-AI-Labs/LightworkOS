"""Buttons for the Code page: the actions ``maverick code`` offers on the CLI.

Every mutation is administrator-only and goes through the kernel surface
:mod:`maverick.codebase` -- the same functions the CLI calls -- so the kernel's
own gates stay in force: merging or pushing still needs an approved, unexpired
``codebase_merge`` approval, which is decided in the approvals queue and never
here. Error text is plain and fixed: vault failures can carry paths or remote
output, which never reach the browser.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, execution_user_id_from_request, require_permission

log = logging.getLogger(__name__)
ASSET = "lightwork-code.js"
_PID = re.compile(r"[0-9a-f]{16}\Z")
_PROTECT = {"block", "approve", "audit"}
_REMOTE = re.compile(r"(https?|ssh|git)://([^\s@/]+)(/\S*)?\Z")
# A web request waits for git; the command line keeps the long limit.
_WEB_GIT_TIMEOUT = 120
_INTERNAL_ADDRESS = (
    "Lightwork cannot copy code from an address inside its own network from the "
    "dashboard. Use the project's public address, or ask the person who installed "
    "Lightwork to allow internal code servers."
)


def _public_source(source: str) -> None:
    """Refuse a code address that points at this server or its private network
    (for example the cloud's instance-details address)."""
    from urllib.parse import urlsplit

    from maverick.tools._ssrf import BlockedHost, resolve_pinned_ip

    try:
        host = urlsplit(source).hostname or ""
    except ValueError:
        host = ""
    try:
        resolve_pinned_ip(host)
    except BlockedHost as exc:
        raise HTTPException(status_code=422, detail=_INTERNAL_ADDRESS) from exc


class RepoIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    source: str = Field(min_length=1, max_length=2000)
    branch: str | None = Field(default=None, max_length=200)
    test_command: str | None = Field(default=None, max_length=500)
    protect: str = "block"


class FeatureIn(BaseModel):
    repo: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    max_dollars: float | None = Field(default=None, gt=0, le=1000)


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", text.strip().lower()).strip("-._")
    return slug[:64]


def _vault():
    from maverick.codebase import vault
    if not vault.enabled():
        raise HTTPException(status_code=503, detail="Code projects are turned off.")
    return vault


def _world():
    from ._shared import _world as shared
    try:
        return shared()
    except Exception as exc:  # noqa: BLE001 -- plain message, no internals
        raise HTTPException(status_code=503, detail="Lightwork's records are not available right now.") from exc


def _audit(request: Request, action: str, **payload: Any) -> None:
    from maverick.audit import AuditRefused, audit_event
    try:
        audit_event("codebase_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local", **payload)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail="The activity log refused this change.") from exc


def _find(pid: str) -> dict:
    from maverick.codebase import features, vault
    if not _PID.fullmatch(pid):
        raise HTTPException(status_code=404, detail="That change was not found.")
    try:
        return features.find(pid)
    except vault.VaultError as exc:
        raise HTTPException(status_code=404, detail="That change was not found.") from exc


def _plain_state(world, p: dict) -> str:
    from maverick.codebase import features
    return features.status(world, p)


def _refuse_unapproved(world, p: dict) -> None:
    """Say, in words, why the kernel will refuse -- before asking it."""
    state = _plain_state(world, p)
    if state == "merged":
        raise HTTPException(status_code=409, detail="This change is already merged.")
    if state in ("expired", "unrequested"):
        raise HTTPException(status_code=409, detail=(
            "This change's approval request has lapsed. Use Ask for approval again, "
            "then approve it in the approvals queue."))
    if state == "rejected":
        raise HTTPException(status_code=409, detail="This change was rejected in the approvals queue.")
    if state != "approved":
        raise HTTPException(status_code=409, detail=(
            "This change is still waiting for a person to approve it in the approvals queue."))


router = APIRouter(tags=["code-actions"])

@router.get("/code/heads")
async def repo_heads(request: Request) -> dict:
    """Each code project's latest version, for pickers (Research lab runs)."""
    require_permission(request, "operate")
    from maverick.codebase import vault
    if not vault.enabled():
        return {"repos": []}
    repos = await run_in_threadpool(vault.list_repos)
    return {"repos": [{"name": r.name, "head": r.head} for r in repos if r.head]}


@router.post("/code/repos", status_code=201)
async def add_repo(request: Request, body: RepoIn) -> dict:
    require_permission(request, "admin")
    vault = _vault()
    name = _slug(body.name)
    if not name or not vault.NAME.fullmatch(name):
        raise HTTPException(status_code=422, detail="Give the project a name made of letters or numbers.")
    source = body.source.strip()
    # Only a remote address: a path on the server's own disk is not a
    # choice the web page offers (the CLI keeps that for the owner).
    if not _REMOTE.fullmatch(source):
        raise HTTPException(status_code=422, detail=(
            "Enter the web address of the code project, for example "
            "https://github.com/your-company/your-project."))
    if body.protect not in _PROTECT:
        raise HTTPException(status_code=422, detail="Choose how the code is protected.")
    await run_in_threadpool(_public_source, source)
    from maverick.config import get_codebase

    def _do():
        return vault.register(name, source, default_branch=(body.branch or "").strip() or None,
                              test_command=(body.test_command or "").strip() or None,
                              protect=body.protect or get_codebase()["default_protect"],
                              timeout=_WEB_GIT_TIMEOUT)
    try:
        repo = await run_in_threadpool(_do)
    except vault.VaultError as exc:
        already = "already registered" in str(exc)
        raise HTTPException(status_code=409 if already else 422, detail=(
            "A code project with that name already exists." if already else
            "Lightwork could not copy that code project. Check the address and that "
            "Lightwork is allowed to read it.")) from exc
    _audit(request, "add_repo", repo=repo.name)
    return {"name": repo.name, "default_branch": repo.default_branch}

@router.post("/code/repos/{name}/sync")
async def sync_repo(request: Request, name: str) -> dict:
    require_permission(request, "admin")
    vault = _vault()
    try:
        repo = await run_in_threadpool(vault.get, name)
    except vault.VaultError as exc:
        raise HTTPException(status_code=404, detail="That code project was not found.") from exc
    if _REMOTE.fullmatch(repo.source):
        # Checked again: the address's name may now point somewhere else.
        await run_in_threadpool(_public_source, repo.source)
    try:
        report = await run_in_threadpool(lambda: vault.sync(name, timeout=_WEB_GIT_TIMEOUT))
    except vault.VaultError as exc:
        conflict = "conflicts" in str(exc)
        raise HTTPException(status_code=409 if conflict else 502, detail=(
            "The latest changes clash with changes merged here that were not sent back yet. "
            "Nothing was changed." if conflict else
            "Lightwork could not fetch the latest changes. Nothing was changed.")) from exc
    _audit(request, "sync_repo", repo=name)
    return {"name": name, "updated_branches": len(report.get("fast_forwarded", []))
            + len(report.get("merged", [])), "new_branches": len(report.get("added", [])),
            "kept_branches": len(report.get("diverged_kept", [])) + len(report.get("kept_ahead", []))}

@router.post("/code/features", status_code=202)
async def start_feature(request: Request, body: FeatureIn, bg: BackgroundTasks) -> dict:
    require_permission(request, "admin")
    vault = _vault()
    try:
        await run_in_threadpool(vault.get, body.repo)
    except vault.VaultError as exc:
        raise HTTPException(status_code=404, detail="That code project was not found.") from exc
    if _provider_missing():
        raise HTTPException(status_code=503, detail=(
            "Set up an AI provider in Settings before asking Lightwork to build a change."))
    owner = caller_principal(request) or ""
    user_id = execution_user_id_from_request(request)
    if owner and owner != f"user:{user_id}":
        raise HTTPException(status_code=403, detail="A current named execution identity is required.")
    _audit(request, "start_feature", repo=body.repo)
    bg.add_task(_run_feature, body.repo, body.title.strip(), body.description.strip(),
                body.max_dollars, owner, user_id)
    return {"started": True, "repo": body.repo}

@router.get("/code/proposals/{pid}")
async def proposal_detail(request: Request, pid: str) -> dict:
    require_permission(request, "admin")
    _vault()
    p = await run_in_threadpool(_find, pid)
    world = _world()
    tests = p.get("tests")
    review = p.get("review")
    return {
        "id": p["id"], "repo": p["repo"], "title": p["title"],
        "status": await run_in_threadpool(_plain_state, world, p),
        "approval_id": p.get("approval_id"), "files": list(p.get("files") or [])[:500],
        "tests": None if tests is None else {"passed": bool(tests.get("passed")),
                                             "command": tests.get("command")},
        "tests_output": (p.get("tests_output") or "")[-20000:],
        "review": None if review is None else {
            "approves": bool(review.get("approves")), "blockers": review.get("blockers", 0),
            "comments": [{"file": c.get("path"), "line": c.get("line"),
                          "severity": c.get("severity"), "message": c.get("message")}
                         for c in (review.get("comments") or [])[:50]]},
        "changes": p.get("diff") or "", "changes_cut_short": bool(p.get("diff_truncated")),
        "created_at": p.get("created_at"), "merged_at": p.get("merged_at"),
    }

@router.post("/code/proposals/{pid}/merge")
async def merge_proposal(request: Request, pid: str) -> dict:
    require_permission(request, "admin")
    vault = _vault()
    from maverick.codebase import features
    p = await run_in_threadpool(_find, pid)
    world = _world()
    await run_in_threadpool(_refuse_unapproved, world, p)
    try:
        merged = await run_in_threadpool(features.merge, world, pid)
    except vault.VaultError as exc:
        clean = "no longer merges cleanly" in str(exc)
        raise HTTPException(status_code=409, detail=(
            "This change no longer fits the latest code. Ask Lightwork to build it again."
            if clean else "Lightwork could not merge this change. Nothing was changed.")) from exc
    _audit(request, "merge", repo=merged["repo"], proposal=pid)
    return {"merged": True, "repo": merged["repo"]}

@router.post("/code/proposals/{pid}/push")
async def push_proposal(request: Request, pid: str) -> dict:
    require_permission(request, "admin")
    vault = _vault()
    from maverick.codebase import features
    p = await run_in_threadpool(_find, pid)
    world = _world()
    state = await run_in_threadpool(_plain_state, world, p)
    if state != "merged":
        await run_in_threadpool(_refuse_unapproved, world, p)
    try:
        branch = await run_in_threadpool(features.push, world, pid)
    except vault.VaultError as exc:
        raise HTTPException(status_code=502, detail=(
            "Lightwork could not send this change to the original project. Check that "
            "Lightwork is allowed to write there.")) from exc
    _audit(request, "push", repo=p["repo"], proposal=pid)
    return {"pushed": True, "branch": branch}

@router.post("/code/proposals/{pid}/renew")
async def renew_proposal(request: Request, pid: str) -> dict:
    require_permission(request, "admin")
    vault = _vault()
    from maverick.codebase import features
    p = await run_in_threadpool(_find, pid)
    world = _world()
    try:
        aid = await run_in_threadpool(features.request_approval, world, p)
    except (vault.VaultError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=(
            "This change already has an open approval request, or it is no longer "
            "waiting for one.")) from exc
    _audit(request, "renew", repo=p["repo"], proposal=pid)
    return {"approval_id": aid}

@router.post("/code/merge-approved")
async def merge_all_approved(request: Request) -> dict:
    require_permission(request, "admin")
    _vault()
    from maverick.codebase import features
    world = _world()
    results = await run_in_threadpool(features.settle, world)
    merged = [r for r in results if r["outcome"] == "merged"]
    _audit(request, "merge_approved", merged=len(merged), attempted=len(results))
    return {"merged": len(merged), "not_merged": len(results) - len(merged)}



def _provider_missing() -> bool:
    """True when no AI provider is ready for the work a code change needs."""
    try:
        from maverick.config import load_config
        from maverick.operator_preflight import _routed_configuration_missing
        missing = {p: f for p, f in _routed_configuration_missing(load_config()).items() if f}
    except Exception:  # noqa: BLE001 -- treat an unreadable route as not ready
        missing = {"selected": ("configuration",)}
    return bool(missing)


def _run_feature(repo: str, title: str, description: str, max_dollars: float | None,
                 owner: str, user_id: str | None) -> None:
    """Background: the governed swarm builds the change and parks its approval."""
    from maverick.codebase import features
    from maverick.world_model import close_world_if_owned, open_world

    from . import auth, rbac
    world = open_world()
    try:
        current_owner, current_user_id, suites = auth.stored_automation_identity(owner)
        if (current_owner != owner or current_user_id != user_id
                or (owner and "admin" not in rbac.permissions_for(auth.role_for_principal(owner)))):
            raise PermissionError("Current code-change authority is required")
        features.propose(world, repo, title, description,
                         features.default_runner(max_dollars=max_dollars, user_id=user_id,
                                                 allowed_suites=suites),
                         reviewer=features.default_reviewer(), owner=owner)
    except Exception as exc:  # noqa: BLE001 -- the failed goal carries the outcome
        log.warning("code feature for %s did not finish (%s)", repo, type(exc).__name__)
    finally:
        close_world_if_owned(world)


asset_router = APIRouter()


@asset_router.get("/static/" + ASSET, include_in_schema=False)
async def code_client() -> FileResponse:
    from pathlib import Path
    return FileResponse(Path(__file__).parent / "static" / ASSET,
                        media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "no-store, private, max-age=0",
                                 "X-Content-Type-Options": "nosniff"})


__all__ = ["ASSET", "asset_router", "router"]
