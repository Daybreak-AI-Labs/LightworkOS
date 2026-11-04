"""Buttons for skill, plugin and template operations that were only on the
command line (``maverick skill install`` from a web address, ``skills stats``,
``skills evict``, ``plugin verify`` / ``lock`` / ``reload`` / ``stats`` /
``new`` and ``template ratings-export``).

Every route calls the kernel function the terminal command calls. Skills are
workspace records (the same ``admin`` floor as removing a skill); plugins and
template ratings are installation-wide (global ``admin``, like the Plugins
page). Changes are same-origin checked, need an explicit ``confirm`` where
they remove, replace or reload something, and write one activity-record row
BEFORE the change -- if the record refuses, nothing is changed. Kernel wording
only ever travels as ``technical`` for a collapsed "Technical details".

This module also mounts the sibling routers for the other operations on these
pages (tool servers and connectors, task insights, code projects and the code
sandbox) and the page scripts they use, so the app includes one router.
"""
from __future__ import annotations

import io
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/api/v1")
_TEXT = 400
_GH = re.compile(r"[\w.-]+/[\w.-]+(:[\w./-]+)?\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def same_origin(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)


def actor(request: Request) -> str:
    return auth.caller_principal(request) or "local administrator"


def record(request: Request, verb: str, *, installation: bool, **detail: Any) -> None:
    """One activity-record row, written BEFORE the change it describes.

    A refused row stops the change: the page is told nothing was changed."""
    from maverick.audit import AuditRefused, EventKind, audit_event
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=installation,
                    verb=verb, actor=actor(request), ok=True, **detail)
    except AuditRefused as exc:
        raise HTTPException(503, "The activity record is not accepting entries right now, "
                                 "so nothing was changed.") from exc


def technical(lines) -> list[dict[str, str]]:
    return [{"text": str(line)[:_TEXT]} for line in list(lines)[:60]]


def download(data: bytes, filename: str, media_type: str) -> Response:
    return Response(content=data, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


# ---- Skills: add from a web address, after a check (skill install) --------

_PROBLEMS = (
    ("frontmatter", "It is not laid out as a skill file."),
    ("missing 'name:'", "It has no name."),
    ("kebab-case", "Its name may only use lowercase letters, numbers and dashes."),
    ("triggers", "It does not say when agents should use it."),
    ("too short", "Its instructions are too short to be useful."),
    ("secret", "It seems to contain a password or access key."),
    ("tools_needed", "It does not list the tools it uses."),
    ("section headers", "Its instructions have no headings."),
    ("signed", "It is signed; the signature is checked when it is added."),
)


def _plain_problem(text: str) -> str:
    for marker, plain in _PROBLEMS:
        if marker in text:
            return plain
    return "It has a problem described in the technical details."


def _skill_source(raw: str) -> str:
    source = (raw or "").strip()
    if source.startswith("https://") or (source.startswith("gh:") and _GH.fullmatch(source[3:])):
        return source
    raise HTTPException(422, "Enter a web address starting with https://, or choose a GitHub project.")


def _recorded_source(source: str) -> str:
    """The source as the activity record keeps it: a private link's password
    (``user:pass@``, ``?token=``, ``#...``) is dropped, never recorded."""
    if not source.startswith("https://"):
        return source[:200]
    parts = urlsplit(source)
    return urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, "", ""))[:200]


# One plain sentence the page shows as it is (no ">" or other symbols its
# plain-sentence filter turns into a generic error).
_INSTALL_OFF = ("Adding skills from a web address is turned off. A global administrator can "
                "turn it on under All settings on the Settings page.")


def _install_allowed() -> bool:
    # The server's MAVERICK_ALLOW_SKILL_INSTALL wins; otherwise the All settings
    # switch "Install skills from a typed web address" ([skills] allow_url_install).
    from maverick.skills import url_install_allowed

    return url_install_allowed()


class SkillSourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=2000)


class SkillInstallIn(SkillSourceIn):
    fingerprint: str = Field(min_length=64, max_length=64)
    confirm: bool = False


def _preview(source: str) -> dict[str, Any]:
    from maverick.skills import preview_skill_source
    from maverick.tools._ssrf import BlockedHost
    try:
        p = preview_skill_source(source)
    except BlockedHost as exc:
        raise HTTPException(422, "Lightwork cannot read a skill from an address inside its own "
                                 "network. Use a public address.") from exc
    except Exception as exc:  # noqa: BLE001 -- fetch failures are all "could not read"
        raise HTTPException(422, "Lightwork could not read a skill at that address. Check the "
                                 "address and that the page is public.") from exc
    v = p.validation
    return {
        "name": p.name[:80], "triggers": [t[:200] for t in p.triggers[:50]],
        "tools": [t[:120] for t in p.tools_needed[:50]], "instructions": p.body[:4000],
        "instructions_cut_short": len(p.body) > 4000, "signed": p.signed, "ok": bool(v.ok),
        "problems": sorted({_plain_problem(e) for e in v.errors}),
        "suggestions": sorted({_plain_problem(w) for w in v.warnings}),
        "fingerprint": p.sha256, "technical": technical([*v.errors, *v.warnings]),
    }


@router.post("/skills/source-preview")
async def skill_source_preview(body: SkillSourceIn, request: Request) -> dict:
    same_origin(request)
    require_permission(request, "admin")
    # Switched off means off: the server reads nothing from the address either.
    if not _install_allowed():
        raise HTTPException(403, _INSTALL_OFF)
    out = await run_in_threadpool(_preview, _skill_source(body.source))
    out["can_add"] = bool(out["ok"])
    out["adding_allowed"] = True
    return out


@router.post("/skills/source-install", status_code=201)
async def skill_source_install(body: SkillInstallIn, request: Request) -> dict:
    same_origin(request)
    require_permission(request, "admin")
    if not _install_allowed():
        raise HTTPException(403, _INSTALL_OFF)
    source = _skill_source(body.source)
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want to add this skill.")
    if not _HEX64.fullmatch(body.fingerprint):
        raise HTTPException(422, "Check the skill again before adding it.")
    record(request, "skill_install", installation=False, source=_recorded_source(source))
    from maverick.skills import install_skill
    try:
        s = await run_in_threadpool(lambda: install_skill(
            source, trusted_local=False, expected_sha256=body.fingerprint))
    except ValueError as exc:
        if "changed since it was checked" in str(exc):
            raise HTTPException(409, "The skill changed after you checked it. Check it again "
                                     "before adding it.") from exc
        raise HTTPException(422, "The skill was not added: it did not pass Lightwork's safety "
                                 "checks.") from exc
    return {"name": s.name, "triggers": s.triggers, "tools_needed": s.tools_needed}


# ---- Skills suggested by completed shared work -----------------------------


class LearnedAdmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    publish_name: str = Field(default="", max_length=96)
    confirm: bool = False
    review_token: str = Field(default="", max_length=100000)


class LearnedWithdrawalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm: bool = False
    review_token: str = Field(default="", max_length=100000)


class LearnedReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["admit", "withdraw"]
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    publish_name: str = Field(default="", max_length=96)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


def _learned_admission_allowed() -> tuple[bool, str]:
    from maverick.config import get_skills
    from maverick.skill.distillation_local import enabled

    if not enabled():
        return False, "Learning from completed work is off. Turn it on in Learning settings first."
    if get_skills()["require_signed"]:
        return False, "This workspace only accepts signed skills. These suggestions need a trusted signature before they can be added."
    return True, ""


def _learned_candidates() -> dict:
    from maverick.skill import stats as skill_stats
    from maverick.skills import (
        admitted_learned_skills,
        available_skills,
        learned_skill_candidates,
        learned_skill_use_key,
    )
    from maverick.swarm import _default_use_skills

    allowed, reason = _learned_admission_allowed()
    admitted = admitted_learned_skills()
    recall_enabled = _default_use_skills()
    runtime = {skill.name: skill for skill in available_skills()
               if learned_skill_use_key(skill)}
    use_keys = {name: learned_skill_use_key(skill) for name, skill in runtime.items()}
    uses = {row["name"]: row["uses"] for row in skill_stats.usage_rows(list(use_keys.values()))}
    tracking = skill_stats._enabled()

    def saved_row(row) -> dict:
        ready = row.source_shared and recall_enabled and row.name in runtime
        status = (
            "Paused: the source task is no longer shared. Agents cannot use this skill."
            if not row.source_shared else
            "Paused: agent skills are turned off. Turn them on in Settings to use this."
            if not recall_enabled else
            "Paused: current skill trust settings prevent agents from using this skill."
            if row.name not in runtime else
            "Available for matching new tasks."
        )
        return {
            "name": row.name, "fingerprint": row.fingerprint,
            "candidate_fingerprint": row.candidate_fingerprint,
            "source_shared": row.source_shared, "recall_ready": ready,
            "use_tracking": tracking, "uses": uses.get(use_keys.get(row.name, ""), 0),
            "status": status,
        }

    return {
        "can_add": allowed, "blocked": reason,
        "suggestions": [{
            "name": row.name, "triggers": row.triggers,
            "tools": row.tools_needed, "instructions": row.body,
            "source_tasks": row.source_goal_ids,
            "fingerprint": row.fingerprint, "ok": row.validation.ok,
            "problems": [_plain_problem(e) for e in row.validation.errors],
            "suggestions": [_plain_problem(w) for w in row.validation.warnings],
        } for row in learned_skill_candidates()],
        "added": [saved_row(row) for row in admitted],
    }


@router.get("/skills/learned-candidates")
async def skill_learned_candidates(request: Request) -> dict:
    require_permission(request, "admin")
    def current():
        from .learned_skill_changes import authority
        context = authority(request)
        value = _learned_candidates()
        authority(request, context)
        return {**value, "context": context}
    return await run_in_threadpool(current)


@router.post("/skills/learned-candidates/{name}/review")
async def skill_learned_review(request: Request, name: str, body: LearnedReviewIn):
    from . import learned_skill_changes as changes
    changes.authority(request, body.context, write=True)
    return await run_in_threadpool(changes.sealed_review, request, name, body.action, body.fingerprint, body.publish_name)


@router.get("/skills/learned-requests")
async def skill_learned_requests(request: Request):
    from .learned_skill_changes import recent
    return await run_in_threadpool(recent, request)


@router.get("/skills/learned-requests/{operation}")
async def skill_learned_original(request: Request, operation: str):
    from .learned_skill_changes import original
    return await run_in_threadpool(original, request, operation)


def _record_learned_change(request: Request, verb: str, *, name: str,
                           fingerprint: str, source_tasks: tuple[int, ...],
                           phase: str) -> None:
    """Record intent before the file change and completion only afterward."""
    from maverick.audit import EventKind, audit_event

    try:
        written = audit_event(
            EventKind.CONTROL_PLANE_ACTION, agent="dashboard", verb=verb,
            actor=actor(request), phase=phase,
            **({"ok": True} if phase == "completed" else {}), name=name,
            content_sha256=fingerprint, source_goal_ids=list(source_tasks),
        )
    except Exception as exc:
        if phase == "completed":
            raise HTTPException(503, "The skill changed, but the activity record could not confirm completion. Refresh the current skill list.") from exc
        raise HTTPException(503, "The activity record is not accepting entries, so the skill was not changed.") from exc
    if not written:
        if phase == "completed":
            raise HTTPException(503, "The skill changed, but the activity record could not confirm completion. Refresh the current skill list.")
        raise HTTPException(503, "The activity record is unavailable, so the skill was not changed.")


def admit_checked_learned_skill(request: Request, name: str, body: LearnedAdmissionIn) -> dict:
    """One authority path for the Skills page and Copilot."""
    from . import learned_skill_changes as changes
    changes.authority(request, write=True)
    if not body.confirm:
        raise HTTPException(422, "Read the suggestion and confirm before adding it.")
    if not body.review_token:
        raise HTTPException(409, "Review the full current suggestion before adding it. No skill was changed.")
    review = changes.open_review(request, body.review_token)
    prepared = review["prepared"]
    if (prepared["action"] != "admit" or prepared["name"] != name
            or prepared["fingerprint"] != body.fingerprint or prepared["publish_name"] != (body.publish_name or name)):
        raise HTTPException(409, "This request differs from the reviewed skill. Prepare a fresh review.")
    return changes.apply(request, prepared, review["operation"], expires=review["expires"])


@router.post("/skills/learned-candidates/{name}/admit", status_code=201)
async def skill_learned_admit(request: Request, name: str, body: LearnedAdmissionIn) -> dict:
    return await run_in_threadpool(admit_checked_learned_skill, request, name, body)


def withdraw_checked_learned_skill(request: Request, name: str, body: LearnedWithdrawalIn) -> dict:
    from . import learned_skill_changes as changes
    changes.authority(request, write=True)
    if not body.confirm:
        raise HTTPException(422, "Confirm before removing this saved skill.")
    if not body.review_token:
        raise HTTPException(409, "Review the current saved skill before removing it. No skill was changed.")
    review = changes.open_review(request, body.review_token)
    prepared = review["prepared"]
    if prepared["action"] != "withdraw" or prepared["name"] != name or prepared["fingerprint"] != body.fingerprint:
        raise HTTPException(409, "This request differs from the reviewed removal. Prepare a fresh review.")
    return changes.apply(request, prepared, review["operation"], expires=review["expires"])


@router.post("/skills/learned-candidates/{name}/withdraw")
async def skill_learned_withdraw(request: Request, name: str, body: LearnedWithdrawalIn) -> dict:
    return await run_in_threadpool(withdraw_checked_learned_skill, request, name, body)


# ---- Skills: track record and tidying up (skills stats / skills evict) ----

_MIN_USES = (3, 5, 10, 20)
_MAX_SUCCESS = (0.1, 0.2, 0.3)


def _usage(names: list[str]) -> list[dict]:
    from maverick.skill import stats as skill_stats
    return skill_stats.usage_rows(names[:500])


@router.get("/skills/usage")
async def skill_usage(request: Request) -> dict:
    require_permission(request, "view")
    from maverick.skills import load_skills

    def _do() -> list[dict]:
        return _usage(sorted(s.name for s in load_skills()))
    return {"skills": await run_in_threadpool(_do)}


class EvictIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_uses: int = 5
    max_success: float = 0.2
    names: list[str] = Field(default_factory=list, max_length=200)
    confirm: bool = False


def _candidates(body: EvictIn) -> list[str]:
    if body.min_uses not in _MIN_USES or body.max_success not in _MAX_SUCCESS:
        raise HTTPException(422, "Choose one of the listed options.")
    from maverick.skill import stats as skill_stats
    from maverick.skills import load_skills
    installed = {s.name for s in load_skills()}
    found = skill_stats.evictable(min_uses=body.min_uses, max_win_rate=body.max_success)
    return sorted(n for n in found if n in installed)


@router.post("/skills/tidy-preview")
async def skill_tidy_preview(body: EvictIn, request: Request) -> dict:
    require_permission(request, "admin")
    names = await run_in_threadpool(_candidates, body)
    return {"skills": await run_in_threadpool(_usage, names)}


@router.post("/skills/tidy")
async def skill_tidy(body: EvictIn, request: Request) -> dict:
    same_origin(request)
    require_permission(request, "admin")
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want to remove these skills.")
    # Only skills that are STILL candidates under the same rule, and that the
    # person saw and confirmed, are removed.
    chosen = set(body.names)
    names = [n for n in await run_in_threadpool(_candidates, body) if n in chosen]
    if not names:
        return {"removed": [], "skipped": len(chosen)}
    record(request, "skills_evict", installation=False, skills=names)
    from maverick.skills import remove_skill
    removed = [n for n in names if await run_in_threadpool(remove_skill, n)]
    return {"removed": removed, "skipped": len(chosen) - len(removed)}


# ---- Plugins: versions, pinning, reload, usage, starter (plugin ...) ------

_STATE = {"match": "Matches the approved version", "drifted": "Different version from the approved one",
          "missing": "Approved, but not installed", "unpinned": "Not pinned yet"}
_POLICY = {"off": "Differences are not checked when add-ons load.",
           "warn": "Differences are logged when add-ons load, and the add-on still loads.",
           "enforce": "An add-on that differs from its approved version is not loaded."}


def _versions() -> dict[str, Any]:
    from maverick.plugin_lock import lock_policy, lock_report
    report = lock_report()
    rows = [{"name": r["name"], "approved": r["pinned"] or "", "installed": r["installed"] or "",
             "state": r["state"], "label": _STATE[r["state"]]} for r in report["rows"][:500]]
    if not report["locked"]:
        summary = ("Add-on versions are not pinned yet. Pin them to be told when one changes."
                   if rows else "No add-ons are installed, so there is nothing to pin.")
    elif report["ok"]:
        summary = "Every add-on matches its approved version."
    else:
        bad = sum(1 for r in rows if r["state"] != "match")
        summary = f"{bad} add-on{'s' if bad != 1 else ''} differ{'s' if bad == 1 else ''} from the approved list."
    return {"pinned": report["locked"], "ok": report["ok"], "summary": summary,
            "rule": _POLICY.get(lock_policy(), ""), "addons": rows}


@router.get("/plugins/versions")
async def plugin_versions(request: Request) -> dict:
    require_global_permission(request, "admin")
    return await run_in_threadpool(_versions)


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = False


@router.post("/plugins/versions/pin")
async def plugin_pin(body: ConfirmIn, request: Request) -> dict:
    same_origin(request)
    require_global_permission(request, "admin")
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want to pin the current versions.")
    record(request, "plugin_lock", installation=True)
    from maverick.plugin_lock import write_lock
    pins = await run_in_threadpool(write_lock)
    return {"pinned": len(pins), **await run_in_threadpool(_versions)}


class ReloadIn(ConfirmIn):
    addon: str = Field(min_length=1, max_length=200)


@router.post("/plugins/reload")
async def plugin_reload(body: ReloadIn, request: Request) -> dict:
    same_origin(request)
    require_global_permission(request, "admin")
    if not body.confirm:
        raise HTTPException(422, "Confirm that you want to reload this add-on.")
    from maverick.plugin_lock import lock_report
    report = await run_in_threadpool(lock_report)
    installed = {r["name"] for r in report["rows"] if r["installed"]}
    if body.addon not in installed:
        raise HTTPException(404, "That add-on is not installed.")
    record(request, "plugin_reload", installation=True, addon=body.addon)
    from maverick.plugins import reload_plugin
    dropped = await run_in_threadpool(reload_plugin, body.addon)
    if not dropped:
        raise HTTPException(409, "Lightwork found nothing to reload for that add-on.")
    return {"reloaded_parts": len(dropped), "technical": technical(dropped)}


@router.get("/plugins/usage")
async def plugin_usage(request: Request) -> dict:
    require_global_permission(request, "admin")
    from maverick import plugin_telemetry

    def _do() -> dict:
        data = plugin_telemetry.stats()
        rows = [{"tool": str(name)[:120], "addon": str(e.get("dist") or "")[:120],
                 "calls": int(e.get("calls") or 0), "last_used": e.get("last_used")}
                for name, e in data.items() if isinstance(e, dict)]
        rows.sort(key=lambda r: -r["calls"])
        return {"counting": bool(plugin_telemetry.enabled()), "tools": rows[:500]}
    return await run_in_threadpool(_do)


class StarterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)
    kind: Literal["tool", "channel", "persona"] = "tool"


def _starter_zip(name: str, kind: str) -> bytes:
    from maverick.plugin_scaffold import scaffold
    with tempfile.TemporaryDirectory(prefix="lw-plugin-") as tmp:
        files = scaffold(name, kind, dest=Path(tmp))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in files:
                zf.write(path, str(path.relative_to(tmp)))
        return buf.getvalue()


@router.post("/plugins/starter")
async def plugin_starter(body: StarterIn, request: Request) -> Response:
    """A starter add-on for a developer, as a download. Nothing is written
    into this server's code or installed."""
    same_origin(request)
    require_global_permission(request, "admin")
    from maverick.plugin_scaffold import ScaffoldError, validate_name
    name = re.sub(r"[^a-z0-9]+", "-", body.name.strip().lower()).strip("-")
    try:
        validate_name(name)
    except ScaffoldError as exc:
        raise HTTPException(422, "Use a name of 3 to 42 letters, numbers or dashes, starting "
                                 "with a letter.") from exc
    data = await run_in_threadpool(_starter_zip, name, body.kind)
    return download(data, f"{name}-starter.zip", "application/zip")


# ---- Templates: download your ratings (template ratings-export) ----------

@router.get("/templates/ratings-export")
async def template_ratings_export(request: Request) -> Response:
    require_global_permission(request, "admin")
    from maverick.marketplace.ratings import RatingsLedger
    text = await run_in_threadpool(lambda: RatingsLedger().export_for_submission())
    return download(text.encode("utf-8"), "Lightwork-template-ratings.json", "application/json")


# ---- Page scripts and sibling routers --------------------------------------

ASSETS = ("lightwork-tool-ops.js", "lightwork-insight-ops.js", "lightwork-code-sandbox.js")


def _asset(name: str):
    async def serve() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / name,
                            media_type="application/javascript; charset=utf-8",
                            headers={"Cache-Control": "no-store, private, max-age=0",
                                     "X-Content-Type-Options": "nosniff"})
    serve.__name__ = "asset_" + name.replace("-", "_").replace(".", "_")
    return serve


def build_router() -> APIRouter:
    from . import code_ops_api, connector_ops_api, insight_ops_api, repl_ops_api
    combined = APIRouter()
    combined.include_router(router)
    for module in (connector_ops_api, insight_ops_api, code_ops_api, repl_ops_api):
        combined.include_router(module.router)
    for name in ASSETS:
        combined.add_api_route("/static/" + name, _asset(name), methods=["GET"],
                               include_in_schema=False)
    return combined


__all__ = ["ASSETS", "build_router", "router"]
