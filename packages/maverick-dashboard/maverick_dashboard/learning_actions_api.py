"""Buttons for the Learned and Learning pages: the learning commands that were
CLI-only (``self-harness forget/retire/canary``, ``dream``, ``dream --rollback``,
``hindsight``, ``prove-learning``).

Every change is a deployment-wide learning action, so it needs a global
administrator -- the same rung as the Learning page's switches and the corpus
review. Each call goes through the kernel function the CLI uses, so the
kernel's own guards (the learning stop, audit rows, snapshots) stay in force.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(tags=["learning-actions"])
_SNAPSHOT = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")


class GuidanceLineIn(BaseModel):
    model_id: str = Field(min_length=1, max_length=200)
    line: str = Field(min_length=1, max_length=4000)
    domain: str | None = Field(default=None, max_length=200)


class ModelIn(BaseModel):
    model_id: str = Field(min_length=1, max_length=200)


class RetireIn(BaseModel):
    older_than_days: Literal[30, 90, 180, 365]


class DreamIn(BaseModel):
    preview: bool = True


class RollbackIn(BaseModel):
    snapshot: str = Field(min_length=1, max_length=80)
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class HindsightIn(BaseModel):
    snapshot: str | None = Field(default=None, max_length=80)
    all_tasks: bool = False
    record: bool = False


class ProveIn(BaseModel):
    baseline: list[float] = Field(min_length=1, max_length=10000)
    treatment: list[float] = Field(min_length=1, max_length=10000)


def _world():
    from ._shared import _world as shared
    try:
        return shared()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="Lightwork's records are not available right now.") from exc


def snapshot_label(name: str) -> str:
    """``20260927T101500Z`` -> ``27 Sep 2026, 10:15 UTC``; anything else as-is."""
    digits = re.sub(r"\D", "", name)
    for fmt, size in (("%Y%m%d%H%M%S", 14), ("%Y%m%d%H%M", 12)):
        if len(digits) >= size:
            try:
                when = _dt.datetime.strptime(digits[:size], fmt)
                return when.strftime("%d %b %Y, %H:%M UTC").lstrip("0")
            except ValueError:
                continue
    return name


def _record(request: Request, action: str, **detail) -> None:
    """One learning activity-record row naming the administrator who acted.

    The kernel's own learning rows do not know who pressed the button; this
    one does. Raises HTTP 503 when the activity record refuses the row (the
    change has already been made, so the page says so)."""
    from maverick.audit import AuditRefused, EventKind, audit_event

    from . import auth
    try:
        audit_event(EventKind.LEARNING_UPDATE, agent="dashboard", _global=True,
                    action=action, actor=auth.caller_principal(request) or "local administrator",
                    **detail)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "The change was made, but it could not be added to the activity record.")) from exc


def _halted(exc: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail=(
        "Learning is stopped for this installation right now. Earlier work may have been kept. Check recent learning and the saved point before trying again."))


@router.post("/learned/guidance/remove")
async def remove_guidance(request: Request, body: GuidanceLineIn) -> dict:
    require_global_permission(request, "admin")
    from maverick.self_harness import forget_addendum
    removed = await run_in_threadpool(forget_addendum, body.model_id, line=body.line,
                                      domain=(body.domain or None))
    if not removed:
        raise HTTPException(status_code=404, detail="That guidance was already removed.")
    return {"removed": True}


@router.post("/learned/guidance/retire")
async def retire_guidance(request: Request, body: RetireIn) -> dict:
    require_global_permission(request, "admin")
    from maverick.self_harness import retire_stale
    n = await run_in_threadpool(lambda: retire_stale(older_than_days=float(body.older_than_days)))
    return {"retired": int(n)}


@router.post("/learned/guidance/probation-review")
async def review_probation(request: Request, body: ModelIn) -> dict:
    require_global_permission(request, "admin")
    from maverick.self_harness import review_canaries
    res = await run_in_threadpool(review_canaries, body.model_id)
    return {"kept": len(res.get("graduated") or []), "removed": len(res.get("demoted") or [])}


@router.get("/learning/snapshots")
async def snapshots(request: Request) -> dict:
    require_global_permission(request, "admin")
    from maverick import dreaming
    names = await run_in_threadpool(dreaming.list_snapshots)
    return {"snapshots": [{"value": n, "label": snapshot_label(n)} for n in reversed(names)]}



def current_snapshot_coverage(request: Request, name: str) -> dict:
    require_global_permission(request, "admin")
    from maverick import dreaming
    if name == "latest" or not _SNAPSHOT.fullmatch(name):
        raise HTTPException(422, "Choose one named saved point from the list.")
    try:
        return dreaming.snapshot_coverage(name)
    except ValueError as exc:
        raise HTTPException(404, "That saved point no longer exists.") from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(409, "This saved point cannot be safely read. Choose another point or check your learning safety copies. Nothing was restored.") from exc


@router.get("/learning/snapshots/{name}/coverage")
async def saved_point_coverage(request: Request, name: str) -> dict:
    return await run_in_threadpool(current_snapshot_coverage, request, name)


def _dream(preview: bool) -> dict:
    from maverick import dreaming
    from maverick.learning_guard import check_learning_halt
    world = _world()
    if preview:
        report = dreaming.dream_cycle_dry(world)
    else:
        check_learning_halt("dreaming", "dashboard_start")
        with dreaming.learning_mutation_scope():
            try:
                report = dreaming.dream_cycle(world)
            except dreaming.DreamAuditError as exc:
                if not exc.started:
                    raise
                report = exc.report
    return {"preview": preview, "tasks_reviewed": report.goals_replayed,
            "failures_reviewed": report.failures_replayed,
            "lessons_written": report.insights_written,
            "skills_learned": report.skills_distilled,
            "skills_retired": report.skills_retired + report.skills_quarantined,
            "notes_tidied": report.reflexions_pruned + report.facts_pruned
            + report.insights_expired + report.insights_retired,
            "paused": bool(report.learning_frozen),
            "cycle_id": report.cycle_id, "saved_point": report.saved_point,
            "activity_recorded": bool(report.activity_recorded),
            "notice": ("Learning ran, but its completion record was not confirmed. Work already completed may have been kept. Check recent learning and review the saved point before deciding what to do next. Do not repeat the cycle to recover its result."
                       if not preview and not report.activity_recorded else "")}


def _authorized_dream(request: Request, preview: bool) -> dict:
    from maverick.authority_effects import authority_effect_fence

    from . import auth

    # This dashboard path passes no model client: its default cycle is local
    # and deterministic. Keep role changes outside its physical learning writes.
    with authority_effect_fence(), auth.fresh_configuration():
        require_global_permission(request, "admin")
        if not preview:
            from maverick import dreaming
            if not dreaming.enabled():
                raise HTTPException(409, "Turn on Dreaming under Learning systems first. No learning was run.")
        return _dream(preview)


def current_cycle_activity(request: Request) -> dict:
    """Read current native evidence, never dispatch another learning cycle."""
    require_global_permission(request, "admin")
    from maverick import dreaming
    try:
        observed = dreaming.recent_cycle_activity()
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(503, "Recent learning cannot be safely checked right now. Review the activity record and learning safety copies. No learning was run.") from exc
    rows = []
    for row in observed:
        item = {"when": _dt.datetime.fromtimestamp(row["time"], _dt.timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC"),
                "status": ("Completion recorded" if row["completion_recorded"] else "Start recorded; completion unconfirmed"),
                "saved_point": row["saved_point"]}
        if row["completion_recorded"]:
            item.update(tasks_reviewed=row["goals_replayed"], failures_reviewed=row["failures_replayed"],
                        lessons_written=row["insights_written"], skills_learned=row["skills_distilled"],
                        skills_retired=row["skills_retired"] + row["skills_quarantined"])
        rows.append(item)
    result = {"cycles": rows, "notice": "The latest 20 recorded cycles from today, in this workspace. An unconfirmed completion or an absent record does not mean nothing changed. This check never repeats learning."}
    if rows and rows[0]["saved_point"]:
        name = rows[0]["saved_point"]
        try:
            coverage = current_snapshot_coverage(request, name)
        except HTTPException:
            result["saved_point_notice"] = "This cycle's saved point is no longer available for verified restoration. Review current learning before any new cycle."
        else:
            result["learning_saved_point"] = {"name": name, "revision": coverage["revision"]}
    require_global_permission(request, "admin")
    return result


@router.get("/learning/dream/activity")
async def dream_activity(request: Request) -> dict:
    return await run_in_threadpool(current_cycle_activity, request)


@router.post("/learning/dream")
async def run_dream(request: Request, body: DreamIn) -> dict:
    require_global_permission(request, "admin")
    from maverick import dreaming
    from maverick.learning_guard import Halted
    if not body.preview and not dreaming.enabled():
        raise HTTPException(status_code=409, detail=(
            "Turn on Dreaming under Learning systems first."))
    if not body.preview and not dreaming.settings().get("snapshots", True):
        raise HTTPException(409, "Turn on Save a restore point before learning in All settings, Memory & learning before starting. No learning was run.")
    try:
        result = await run_in_threadpool(_authorized_dream, request, body.preview)
    except dreaming.DreamAuditError as exc:
        raise HTTPException(503, "Learning could not record its start, so no learning was run. In All settings, Security, turn on Sign the activity record and restart Lightwork if requested. If it is already on, check the Activity page before starting again.") from exc
    except Halted as exc:
        raise _halted(exc) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(503, "The learning cycle could not finish. Check learning safety copies and the current learning record before trying again.") from exc
    if not body.preview and result["activity_recorded"]:
        from maverick.audit import AuditRefused, EventKind, audit_event

        from . import auth
        try:
            recorded = await run_in_threadpool(lambda: audit_event(
                EventKind.LEARNING_UPDATE, agent="dashboard", _global=True,
                action="dream_run", actor=auth.caller_principal(request) or "local administrator",
                **{k: v for k, v in result.items() if k != "preview"}))
        except AuditRefused:
            recorded = False
        if recorded is not True:
            result["notice"] = "Learning completed and its cycle record was saved, but the administrator's activity entry was not confirmed. Check recent learning before deciding whether to run another cycle."
    require_global_permission(request, "admin")
    return result


def restore_current_snapshot(request: Request, body: RollbackIn) -> dict:
    from maverick.authority_effects import authority_effect_fence

    with authority_effect_fence():
        require_global_permission(request, "admin")
        return _restore_reviewed_snapshot(request, body)


def _restore_reviewed_snapshot(request: Request, body: RollbackIn) -> dict:
    require_global_permission(request, "admin")
    from maverick import dreaming
    coverage = current_snapshot_coverage(request, body.snapshot)
    if body.revision != coverage["revision"]:
        raise HTTPException(409, "This saved point changed after review. Read its coverage again before restoring. Nothing was restored.")
    try:
        restored = dreaming.rollback_learning_state(
            body.snapshot, expected_revision=body.revision,
        )
    except ValueError as exc:
        raise HTTPException(404, "That saved point no longer exists.") from exc
    except dreaming.LearningRollbackError as exc:
        raise HTTPException(503, "Lightwork could not fully restore that saved point. Some learned information may have changed. Review the Learned and Learning pages before trying again.") from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(409, "The saved point or learning storage changed or could not be safely checked. Nothing was restored. Read the saved point again before continuing.") from exc
    if not restored:
        raise HTTPException(404, "There is no saved point to go back to yet.")
    _record(request, "rollback", snapshot=body.snapshot, restored=[str(n) for n in restored])
    return {"restored": len(restored), "coverage": coverage}


@router.post("/learning/rollback")
async def rollback(request: Request, body: RollbackIn) -> dict:
    return await run_in_threadpool(restore_current_snapshot, request, body)


@router.post("/learning/hindsight")
async def hindsight(request: Request, body: HindsightIn) -> dict:
    require_global_permission(request, "admin")
    from maverick import dreaming
    from maverick import hindsight as _h
    names = await run_in_threadpool(dreaming.list_snapshots)
    if not names:
        raise HTTPException(status_code=409, detail=(
            "There is no saved point to compare with yet. Run a learning cycle first."))
    chosen = body.snapshot or names[-1]
    if chosen not in names:
        raise HTTPException(status_code=404, detail="That saved point no longer exists.")
    world = _world()

    def _run():
        report = _h.replay(world, before=dreaming.snapshots_dir() / chosen, after=None,
                           limit=100, status=None if body.all_tasks else "blocked")
        if body.record:
            _h.write_ledger(report, before_label=chosen)
        return report
    report = await run_in_threadpool(_run)
    return {"compared_with": snapshot_label(chosen), "tasks": report.n_goals,
            "covered_before": report.covered_before, "covered_now": report.covered_now,
            "gained": list(report.gained)[:50], "lost": list(report.regressed)[:50],
            "recorded": bool(body.record)}


@router.post("/learning/prove")
async def prove(request: Request, body: ProveIn) -> dict:
    require_global_permission(request, "admin")
    from maverick.learning_proof import paired_lift
    if len(body.baseline) != len(body.treatment):
        raise HTTPException(status_code=422, detail=(
            "Both result sets must cover the same tasks, in the same order."))
    if any(not 0.0 <= x <= 1.0 for x in (*body.baseline, *body.treatment)):
        raise HTTPException(status_code=422, detail="Scores must be between 0 and 1.")
    try:
        r = paired_lift(body.baseline, body.treatment)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Those results cannot be compared.") from exc
    verdict = ("improved" if r.improved else
               "worse" if (r.significant and r.delta < 0) else "no_clear_change")
    return {"evidence_kind": "supplied_paired_scores", "causal_claim_supported": False,
            "verdict": verdict, "tasks": r.n, "before": round(r.baseline_mean, 4),
            "after": round(r.treatment_mean, 4), "change": round(r.delta, 4),
            "better": r.wins, "worse": r.losses, "same": r.ties}


__all__ = ["router", "snapshot_label"]
