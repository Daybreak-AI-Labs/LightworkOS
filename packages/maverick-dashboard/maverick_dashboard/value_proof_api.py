"""Value and proof read-outs that were CLI-only: ``compounding``,
``memory-plane compounding/export/verify``, ``cost-retro``, ``budget-tune``,
``failures``, ``earned-autonomy`` (status and revoke), ``fleet-memory`` and
``record stats/export/verify``.

Reads of workspace totals need ``view``; the cost retrospective names
individual tasks, so it needs ``audit``. Downloads of the signed Operating
Record and memory attestation carry the workspace's decisions, so they need
an administrator (like the proof bundle download) and are recorded in the
activity log with the person who downloaded them. Withdrawing an earned
auto-approval tightens control and needs a workspace administrator; it goes
through the kernel's own ledger and audit row. Everything reads the active
workspace's world and stores, and heavy reads run off the event loop.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, has_permission, require_permission

router = APIRouter(prefix="/value-proof", tags=["value-proof"])

_MAX_UPLOAD = 10_000_000
_MODE_LABELS = {
    "budget": "Hit a spending limit",
    "timeout": "Took too long",
    "network": "Could not reach a service",
    "auth": "Sign-in or permission problem",
    "shield": "Stopped by a safety check",
    "sandbox": "Blocked by the safe workspace",
    "cancelled": "Cancelled",
    "error": "Other error",
}
_CLAIM_LABELS = {
    "cross_vendor": "Agents from more than one vendor shared this memory",
    "compounding": "Work got cheaper without getting less reliable",
    "tenant_isolation": "The statement covers only this workspace",
}


class DocumentIn(BaseModel):
    document: str = Field(min_length=2, max_length=_MAX_UPLOAD)
    # The text of the publisher's key file (``attest key`` output), for a
    # statement signed by another installation (``memory-plane verify --key``).
    publisher_key: str | None = Field(default=None, max_length=2000)


class RevokeIn(BaseModel):
    action: str = Field(min_length=1, max_length=200)


def _world():
    from ._shared import _world as shared
    try:
        return shared()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="Lightwork's records are not available right now.") from exc


def _audit(request: Request, action: str, **payload: Any) -> None:
    from maverick.audit import AuditRefused, audit_event
    try:
        audit_event("control_plane_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local", **payload)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail="The activity log refused this download.") from exc


def _pick(value: int, allowed: tuple[int, ...]) -> int:
    """A tuning value must be one the page offered (the CLI's options)."""
    if value not in allowed:
        raise HTTPException(status_code=422, detail="Choose from the list.")
    return value


def _words(value: Any) -> str:
    text = " ".join(str(value or "").replace("_", " ").split())
    return text[:1].upper() + text[1:200]


@router.get("/access")
async def access(request: Request) -> dict:
    """Which controls to show: the routes still enforce every check."""
    require_permission(request, "view")
    return {"admin": has_permission(request, "admin"), "audit": has_permission(request, "audit")}


# ---- results --------------------------------------------------------------

@router.get("/compounding")
async def compounding(request: Request, window: int = 5) -> dict:
    require_permission(request, "view")
    from maverick.compounding_metric import report_from_world
    _pick(window, (3, 5, 10))
    world = _world()
    reps = await run_in_threadpool(lambda: report_from_world(world, window=window))
    return {"task_types": [
        {"name": _words(r.task_class), "runs": int(r.runs),
         "cost_change_pct": float(r.cost_delta_pct),
         "success_change": round(float(r.success_delta), 4),
         "improving": bool(r.improving)}
        for r in reps[:50]
    ]}


@router.get("/departments")
async def departments(request: Request, window: int = 5) -> dict:
    require_permission(request, "view")
    from maverick.memory_plane import compounding_by_department
    _pick(window, (3, 5, 10))
    world = _world()
    curves = await run_in_threadpool(lambda: compounding_by_department(world, window=window))
    return {"departments": [
        {"name": _words(c.department), "runs": int(c.runs),
         "cost_before": round(float(c.cold_cost), 4), "cost_now": round(float(c.warm_cost), 4),
         "improving": bool(c.improving)}
        for c in curves[:50]
    ]}


@router.get("/earned-autonomy")
async def earned_autonomy(request: Request) -> dict:
    require_permission(request, "view")
    from maverick.earned_autonomy import enabled, policy_from_config, shared

    def _read() -> dict:
        engine = shared()
        policy = policy_from_config()
        return {
            "enabled": bool(enabled()),
            "auto_grant_on": False,
            "needs": {"outcomes": int(policy.min_samples), "streak": int(policy.min_streak),
                      "accuracy_pct": round(float(policy.min_accuracy) * 100)},
            "actions": [
                {"action": s.action, "name": _words(s.action), "auto_approved": False,
                 "evidence_qualified": bool(s.graduated),
                 "confirmed": int(s.hits), "missed": int(s.misses), "streak": int(s.streak)}
                for s in engine.status()[:200]
            ],
        }
    return await run_in_threadpool(_read)


@router.post("/earned-autonomy/revoke")
async def revoke_earned_autonomy(request: Request, body: RevokeIn) -> dict:
    require_permission(request, "admin")
    from maverick.earned_autonomy import shared
    engine = shared()
    known = {s.action for s in await run_in_threadpool(engine.status)}
    if body.action not in known:
        raise HTTPException(status_code=404, detail="That action is no longer on the list. Refresh the page.")
    who = caller_principal(request) or "local:dashboard"
    recorded = await run_in_threadpool(lambda: engine.revoke(
        body.action, reason="withdrawn from the dashboard", principal=who))
    return {"revoked": True, "recorded": bool(recorded)}


@router.get("/fleet-memory")
async def fleet_memory(request: Request) -> dict:
    require_permission(request, "view")
    from maverick import fleet_memory as fm
    if not fm.enabled():
        return {"enabled": False, "agents": []}
    st = await run_in_threadpool(fm.status)
    rows = []
    for a in (st.get("agents") or [])[:200]:
        counts = (st.get("ingested") or {}).get(a.get("source"), {})
        rows.append({"agent": str(a.get("agent_id") or ""), "vendor": _words(a.get("vendor")),
                     "description": str(a.get("description") or "")[:200],
                     "worked": int(counts.get("success", 0)), "failed": int(counts.get("failure", 0))})
    return {"enabled": True, "agents": rows}


@router.get("/record-stats")
async def record_stats(request: Request) -> dict:
    require_permission(request, "view")
    from maverick import operating_record as orec

    from .value_views import value_scope
    world = _world()
    # Counts only; a read-only role counts the whole workspace.
    owner = value_scope(request)["owner"]
    s = await run_in_threadpool(lambda: orec.stats(orec.assemble(world, limit=500, owner=owner)))
    depts = sorted(s.departments.items(), key=lambda kv: -kv[1])[:12]
    return {"records": s.n_records, "tasks": s.n_goals, "approvals": s.n_approvals,
            "human_decisions": s.n_human_decisions,
            "departments": [{"name": _words(k), "count": int(v)} for k, v in depts]}


# ---- spend ----------------------------------------------------------------

@router.get("/cost-retro")
async def cost_retro(request: Request, top: int = 10) -> dict:
    require_permission(request, "audit")
    from maverick.cost.retrospective import retrospective
    _pick(top, (5, 10, 25))
    world = _world()
    rep = await run_in_threadpool(lambda: retrospective(world, top_n=top))
    return {
        "total": float(rep["total_spend"]), "tasks": int(rep["priced_goals"]),
        "failed_spend": float(rep["failed_spend"]), "failed_share": float(rep["failed_share"]),
        "costliest": [{"task": int(r["goal_id"]), "title": str(r.get("title") or "")[:200],
                       "cost": float(r["cost"]), "failed": bool(r["failed"])}
                      for r in rep["top_goals"][:top]],
        "advice": [str(o)[:300] for o in rep["observations"][:10]],
    }


@router.get("/budget-tune")
async def budget_tune(request: Request, percentile: int = 90, min_samples: int = 5) -> dict:
    require_permission(request, "view")
    from maverick.budget_tuner import recommend_for_world
    _pick(percentile, (75, 90, 95))
    _pick(min_samples, (3, 5, 10))
    world = _world()
    recs = await run_in_threadpool(lambda: recommend_for_world(world, pct=float(percentile),
                                                               min_samples=min_samples))
    return {"minimum_tasks": min_samples, "percentile": percentile, "suggestions": [
        {"for": "Every task" if cls == "default" else _words(cls),
         "cap": float(info["recommended_max_dollars"]),
         "typical_high": float(info.get(f"p{percentile}", 0.0)), "tasks": int(info["samples"])}
        for cls, info in sorted(recs.items())[:20]
    ]}


@router.get("/failures")
async def failures(request: Request) -> dict:
    require_permission(request, "view")
    from maverick.failure_telemetry import enabled, summarize
    s = await run_in_threadpool(summarize)
    return {"recording": bool(enabled()), "total": int(s["total"]), "reasons": [
        {"reason": _MODE_LABELS.get(mode, _words(mode)), "count": int(n)}
        for mode, n in list(s["by_mode"].items())[:20]
    ]}


# ---- signed downloads and checks --------------------------------------------

def _download(data: bytes, name: str) -> Response:
    return Response(content=data, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"',
                             "Cache-Control": "no-store"})


@router.get("/record-export")
async def record_export(request: Request) -> Response:
    require_permission(request, "admin")
    from maverick import operating_record as orec
    world = _world()

    def _build() -> bytes:
        with tempfile.TemporaryDirectory(prefix="lw-record-") as tmp:
            path = orec.export_capsule(world, Path(tmp) / "record.json", limit=500)
            ok, _reason = orec.verify_capsule_integrity(path)
            if not ok:
                raise RuntimeError("capsule failed its own verification")
            return path.read_bytes()
    try:
        data = await run_in_threadpool(_build)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=(
            "Signing is not available on this installation, so the record cannot be downloaded.")) from exc
    _audit(request, "operating_record_export", size=len(data))
    return _download(data, "lightwork-operating-record.json")


@router.get("/memory-export")
async def memory_export(request: Request) -> Response:
    require_permission(request, "admin")
    from maverick import memory_plane
    world = _world()

    def _build() -> bytes:
        with tempfile.TemporaryDirectory(prefix="lw-memory-") as tmp:
            return memory_plane.export(Path(tmp) / "memory.json", world).read_bytes()
    try:
        data = await run_in_threadpool(_build)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=(
            "Signing is not available on this installation, so the statement cannot be downloaded.")) from exc
    _audit(request, "memory_plane_export", size=len(data))
    return _download(data, "lightwork-learning-statement.json")


def _own_key() -> str:
    try:
        from maverick.attestation import publisher_key
        return publisher_key()[1]
    except Exception:  # noqa: BLE001 -- no signing key: nothing can match it
        return ""


def _parse(document: str) -> dict:
    try:
        parsed = json.loads(document)
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="That file is not one Lightwork made.")
    return parsed


@router.post("/record-verify")
async def record_verify(request: Request, body: DocumentIn) -> dict:
    require_permission(request, "view")
    from maverick import operating_record as orec
    capsule = _parse(body.document)

    def _check() -> dict:
        with tempfile.TemporaryDirectory(prefix="lw-check-") as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(body.document, encoding="utf-8")
            ok, _reason = orec.verify_capsule_integrity(path)
        own = _own_key()
        return {"intact": bool(ok), "from_this_installation": bool(ok and own and capsule.get("pubkey") == own),
                "records": len(capsule.get("records") or []) if ok else 0}
    return await run_in_threadpool(_check)


@router.post("/memory-verify")
async def memory_verify(request: Request, body: DocumentIn) -> dict:
    require_permission(request, "view")
    from maverick import memory_plane
    bundle = _parse(body.document)
    own = await run_in_threadpool(_own_key)
    anchor = own
    if body.publisher_key:
        found = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", body.publisher_key)
        if len(set(k.lower() for k in found)) != 1:
            raise HTTPException(status_code=422, detail=(
                "That key file does not hold exactly one key. Ask the other installation for its key file."))
        anchor = found[0].lower()
    if not anchor:
        raise HTTPException(status_code=409, detail=(
            "Signing is not available on this installation, so the statement cannot be checked here."))
    result = await run_in_threadpool(lambda: memory_plane.verify(bundle, trusted_key_hex=anchor))
    return {"intact": bool(result.ok), "from_this_installation": bool(own) and anchor == own.lower(),
            "claims": [
        {"claim": _CLAIM_LABELS.get(c.name, _words(c.name)),
         "result": {"HOLDS": "Holds", "FAILS": "Does not hold",
                    "NOT_APPLICABLE": "Does not apply here"}.get(c.status, "Could not be decided")}
        for c in result.claims[:20]
    ]}


__all__ = ["router"]
