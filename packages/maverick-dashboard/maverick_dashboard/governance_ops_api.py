"""AI governance operations that were only reachable from a terminal.

* ``GET  /api/v1/governance-ops/policy`` -- the company rules every action
  passes (``maverick governance show``; ``view``).
* ``GET  /api/v1/governance-ops/gateway`` -- the AI gateway's state and the
  apps that called it, busiest first (``maverick gateway status`` /
  ``callers``; ``operate``). Request contents are never stored, so none are
  shown.
* ``GET  /api/v1/governance-ops/assets`` -- AI systems to attach evidence to.
* ``POST /api/v1/governance-ops/fairness`` / ``sensitivity`` / ``reasons`` --
  the explainability checks (``maverick explainability ...``) on numbers the
  person enters or a spreadsheet they choose; optionally saved as evidence
  for one AI system (``operate``, like adding an explanation).
* ``POST /api/v1/governance-ops/underwriting-pack`` -- prepare the signed
  insurance evidence pack in the background, then download it
  (``maverick underwriting-pack export``; ``operate``, like the evidence pack).
* ``POST /api/v1/governance-ops/regulatory-feed/preview`` and ``/sync`` --
  bring reviewed regulatory alerts into impact records with one guided rule
  (``maverick regulatory-feed sync``; installation administrators, like the
  one-alert version, in the chosen workspace).

Kernel functions are the ones the terminal commands call. Changes are
recorded in the activity log with the person who asked, before they happen.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/governance-ops", tags=["governance-operations"])

_MAX_SHEET_BYTES = 2 * 1024 * 1024
_MAX_SHEET_ROWS = 5000
_MAX_COLUMNS = 64
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$")

_RISK_WORDS = {"low": "low-risk", "medium": "medium-risk", "high": "high-risk"}


def _actor(request: Request) -> str:
    from .request_identity import request_actor as _request_actor

    return _request_actor(request)


def _record(request: Request, action: str, *, installation: bool = False, **detail: Any) -> None:
    from maverick.audit import AuditRefused, audit_event

    extra = {"_global": True} if installation else {}
    try:
        audit_event("control_plane_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local administrator", **extra, **detail)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was changed.")) from exc


def _words(value: str) -> str:
    from .identity_format import humanize

    return humanize(value)


# ---- company rules for actions (maverick governance show) ---------------------

def _policy() -> dict[str, Any]:
    from maverick.governance import Policy

    pol = Policy.from_config()
    rules: list[str] = []
    for action in sorted(pol.deny_actions):
        rules.append(f"{_words(action)} is never allowed.")
    for action in sorted(pol.require_human_actions):
        rules.append(f"{_words(action)} waits for a person to approve it.")
    if pol.deny_min_risk:
        rules.append(f"Every {_RISK_WORDS.get(pol.deny_min_risk, pol.deny_min_risk)} action or riskier is never allowed.")
    if pol.require_human_min_risk:
        rules.append(f"Every {_RISK_WORDS.get(pol.require_human_min_risk, pol.require_human_min_risk)} action or "
                     "riskier waits for a person to approve it.")
    for action, amount in sorted((pol.deny_above or {}).items()):
        who = "Any action" if action == "*" else _words(action)
        rules.append(f"{who} over {amount:,.2f} is never allowed.")
    for action, amount in sorted((pol.require_human_above or {}).items()):
        who = "Any action" if action == "*" else _words(action)
        rules.append(f"{who} over {amount:,.2f} waits for a person to approve it.")
    if pol.require_fresh_human_approval:
        rules.append("An approval is used once: every held action needs a fresh one.")
    return {
        "rules": rules,
        "summary": ("No company rules are set, so actions are only limited by each assistant's own limits."
                    if pol.is_empty() and not rules else
                    f"{len(rules)} company rule{'s apply' if len(rules) != 1 else ' applies'} to every action."),
        "regulations": [_words(p) for p in pol.compliance_profiles],
    }


@router.get("/policy")
async def policy(request: Request) -> dict:
    require_permission(request, "view")
    try:
        return await run_in_threadpool(_policy)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="The company rules could not be read.") from exc


# ---- AI gateway (maverick gateway status / callers) -----------------------------

_STATUS_WORDS = {"ok": "Answered", "allowed": "Answered", "blocked": "Blocked", "denied": "Blocked",
                 "error": "Failed", "upstream_error": "Failed", "budget_exceeded": "Over its budget",
                 "rate_limited": "Too many requests"}


def _gateway() -> dict[str, Any]:
    from maverick import llm_gateway

    state = llm_gateway.gateway_status()
    rows = llm_gateway.list_callers(limit=100)
    callers = [{
        "app": f"App {str(row.get('caller_digest') or '')[:8]}",
        "team": _words(str(row.get("team") or "default")),
        "model": str(row.get("model") or ""),
        "calls": int(row.get("request_count") or 0),
        "last_result": _STATUS_WORDS.get(str(row.get("last_status") or ""),
                                         _words(str(row.get("last_status") or "unknown"))),
        "last_seen": row.get("last_seen"),
        "hidden_details": int(row.get("redaction_count") or 0),
    } for row in rows]
    enabled = bool(state.get("enabled"))
    summary = (f"The AI gateway is {'on' if enabled else 'off'}. "
               f"{state.get('callers', 0)} app{'s have' if state.get('callers', 0) != 1 else ' has'} "
               f"sent {state.get('request_count', 0)} request{'s' if state.get('request_count', 0) != 1 else ''}.")
    return {"enabled": enabled, "callers": callers, "summary": summary,
            "results": {(_STATUS_WORDS.get(k, _words(k)) or "Unknown"): v
                        for k, v in (state.get("last_status_counts") or {}).items()}}


@router.get("/gateway")
async def gateway(request: Request) -> dict:
    require_permission(request, "operate")
    try:
        return await run_in_threadpool(_gateway)
    except (ValueError, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=503, detail="The AI gateway's records could not be read.") from exc


# ---- AI systems (evidence targets) ---------------------------------------------

def _assets() -> list[dict[str, str]]:
    from maverick import model_risk_assurance as mra

    if not mra.enabled():
        return []
    rows = mra.list_inventory()[:500]
    out = []
    for row in rows:
        asset_id = str(row.get("asset_id") or "")
        if asset_id:
            out.append({"id": asset_id, "name": str(row.get("name") or row.get("display_name") or _words(asset_id))})
    return out


@router.get("/assets")
async def assets(request: Request) -> dict:
    require_permission(request, "operate")
    try:
        return {"assets": await run_in_threadpool(_assets)}
    except (ValueError, RuntimeError, OSError):
        return {"assets": []}


# ---- explainability ---------------------------------------------------------------

class GroupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    selected: int = Field(ge=0, le=10**9)
    total: int = Field(ge=1, le=10**9)


class FairnessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    groups: list[GroupIn] = Field(min_length=2, max_length=64)
    threshold: float = Field(default=0.8, ge=0.5, le=1.0)
    asset_id: str | None = Field(default=None, max_length=128)


class SheetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sheet: str = Field(min_length=3, max_length=_MAX_SHEET_BYTES)
    #: sensitivity: the column holding each decision's score.
    score_column: str | None = Field(default=None, max_length=200)
    #: reasons: which row (1 = first data row) is the decision to explain.
    row: int | None = Field(default=None, ge=1, le=_MAX_SHEET_ROWS)
    top: int = Field(default=4, ge=1, le=16)
    asset_id: str | None = Field(default=None, max_length=128)


def _sheet(text: str) -> tuple[list[str], list[list[float]]]:
    reader = csv.reader(io.StringIO(text))
    try:
        header = [h.strip() for h in next(reader)]
    except StopIteration:
        raise HTTPException(status_code=422, detail="The spreadsheet is empty.") from None
    if len(header) < 2 or len(header) > _MAX_COLUMNS or any(not h for h in header) or len(set(header)) != len(header):
        raise HTTPException(status_code=422, detail=(
            "The first row must name each column once, with at least two columns."))
    rows: list[list[float]] = []
    for line in reader:
        if not any(cell.strip() for cell in line):
            continue
        if len(line) != len(header):
            raise HTTPException(status_code=422, detail=f"Row {len(rows) + 1} does not have a value in every column.")
        try:
            values = [float(cell) for cell in line]
        except ValueError:
            raise HTTPException(status_code=422, detail=(
                f"Row {len(rows) + 1} has a value that is not a number. Use numbers only.")) from None
        if not all(math.isfinite(v) for v in values):
            raise HTTPException(status_code=422, detail="Use ordinary numbers only.")
        rows.append(values)
        if len(rows) > _MAX_SHEET_ROWS:
            raise HTTPException(status_code=413, detail="That spreadsheet has too many rows. Use 5,000 or fewer.")
    if len(rows) < 3:
        raise HTTPException(status_code=422, detail="Add at least three rows of numbers.")
    return header, rows


def _asset(asset_id: str | None) -> str | None:
    if not asset_id:
        return None
    if not _ID.fullmatch(asset_id):
        raise HTTPException(status_code=422, detail="Choose an AI system from the list.")
    return asset_id


def _save_evidence(kind: str, asset_id: str | None, report: dict, source: str, actor: str) -> bool:
    if not asset_id:
        return False
    from maverick import explainability

    if kind == "fairness":
        explainability.record_fairness_evidence(asset_id, report, source_id=source, actor=actor)
    else:
        explainability.record_explainability_evidence(asset_id, report, source_id=source, actor=actor)
    return True


def _fairness(body: FairnessIn, actor: str) -> dict[str, Any]:
    from maverick import fairness_monitor

    names = [g.name.strip() for g in body.groups]
    if len(set(names)) != len(names):
        raise HTTPException(status_code=422, detail="Give each group a different name.")
    if any(g.selected > g.total for g in body.groups):
        raise HTTPException(status_code=422, detail="A group cannot have more people chosen than in the group.")
    counts = {g.name.strip(): {"selected": g.selected, "total": g.total} for g in body.groups}
    report = fairness_monitor.metrics_report(counts, threshold=body.threshold)
    if report is None:
        raise HTTPException(status_code=422, detail="Enter at least two groups with people in them.")
    saved = _save_evidence("fairness", _asset(body.asset_id), report, "dashboard", actor)
    groups = [{"group": name, "rate": report["rates"].get(name), "ratio": report["impact_ratios"].get(name),
               "passes": name not in report["failing_groups"]} for name in counts]
    passed = bool(report["passed"])
    return {
        "passed": passed, "groups": groups, "saved": saved,
        "lowest_ratio": report["min_impact_ratio"],
        "summary": ("Every group is chosen at a similar rate (the four-fifths check passes)." if passed else
                    "These groups are chosen much less often than the most-chosen group: "
                    + ", ".join(report["failing_groups"]) + "."),
    }


def _sensitivity(body: SheetIn, actor: str) -> dict[str, Any]:
    from maverick import explainability

    header, rows = _sheet(body.sheet)
    score = body.score_column or header[-1]
    if score not in header:
        raise HTTPException(status_code=422, detail="Choose the score column from the list.")
    index = header.index(score)
    features = {name: [r[i] for r in rows] for i, name in enumerate(header) if i != index}
    report = explainability.global_sensitivity(features, [r[index] for r in rows])
    saved = _save_evidence("explainability", _asset(body.asset_id), report, "sensitivity", actor)
    ranked = [{"input": row["feature"], "strength": round(abs(row["spearman"]), 3),
               "direction": "Higher score" if row["spearman"] >= 0 else "Lower score"}
              for row in report["features"]]
    return {"ranked": ranked, "decisions": report["sample_count"], "saved": saved,
            "summary": f"Checked {report['sample_count']} decisions. The inputs that move the score most are listed first."}


def _reasons(body: SheetIn, actor: str) -> dict[str, Any]:
    from maverick import explainability

    header, rows = _sheet(body.sheet)
    if body.row is None or body.row > len(rows):
        raise HTTPException(status_code=422, detail="Choose the decision to explain from the list.")
    chosen = rows[body.row - 1]
    features = {name: [r[i] for r in rows] for i, name in enumerate(header)}
    report = explainability.reason_codes(features, dict(zip(header, chosen, strict=True)),
                                         top_k=min(body.top, len(header)))
    saved = _save_evidence("explainability", _asset(body.asset_id), report, "reasons", actor)
    reasons = [{"input": row["feature"], "value": row["value"], "usual": round(row["population_mean"], 4),
                "how_far": abs(round(row["z_score"], 2)), "direction": row["direction"]}
               for row in report["reasons"]]
    return {"reasons": reasons, "saved": saved,
            "summary": f"The main reasons for decision {body.row}, most unusual first."}


async def _explain(function, body, request: Request) -> dict:
    if body.asset_id:
        await run_in_threadpool(_record, request, "explainability_evidence", asset=body.asset_id)
    try:
        return await run_in_threadpool(function, body, _actor(request))
    except HTTPException:
        raise
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="That AI system is no longer in the inventory.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Those numbers cannot be checked. Check the spreadsheet and try again.") from exc
    except RuntimeError as exc:
        text = str(exc).lower()
        off = "disabled" in text or "enable" in text
        raise HTTPException(status_code=503, detail=(
            "Explainability checks are turned off. An administrator can turn them on in Settings." if off else
            "The check could not be completed right now.")) from exc


@router.post("/fairness")
async def fairness(request: Request, body: FairnessIn) -> dict:
    require_permission(request, "operate")
    return await _explain(_fairness, body, request)


@router.post("/sensitivity")
async def sensitivity(request: Request, body: SheetIn) -> dict:
    require_permission(request, "operate")
    return await _explain(_sensitivity, body, request)


@router.post("/reasons")
async def reasons(request: Request, body: SheetIn) -> dict:
    require_permission(request, "operate")
    return await _explain(_reasons, body, request)


# ---- insurance evidence pack (maverick underwriting-pack export) ----------------

class PackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str | None = Field(default=None, max_length=128)


def _pack_failure(exc: Exception) -> str:
    text = str(exc).lower()
    if "model-risk assurance" in text or "disabled" in text:
        return "The insurance pack needs AI model records turned on first. An administrator can turn them on in Settings."
    return "The insurance pack could not be prepared. Try again later."


@router.post("/underwriting-pack", status_code=202)
async def underwriting_pack(request: Request, body: PackIn) -> dict:
    require_permission(request, "operate")
    asset_id = _asset(body.asset_id)
    actor = _actor(request)
    from . import ops_file_jobs as ops_jobs

    def build(_workdir) -> bytes:
        from maverick import underwriting_pack as up

        pack = up.export_underwriting_pack(actor=actor, asset_id=asset_id)
        # The same bytes the terminal command writes: the embedded assurance
        # pack keeps its own signature and fingerprint.
        return json.dumps(pack, indent=2, sort_keys=True, default=str).encode("utf-8")

    await run_in_threadpool(_record, request, "underwriting_pack_export", asset=asset_id or "")
    name = "lightwork-insurance-evidence-" + time.strftime("%Y-%m-%d", time.gmtime()) + ".json"
    job = ops_jobs.start("underwriting_pack", ops_jobs.owner_of(request), name, "application/json",
                         build, _pack_failure)
    return {"job": job, "state": "running"}


def _job(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", value or ""):
        raise HTTPException(status_code=404, detail="That download is no longer available. Start it again.")
    return value


@router.get("/underwriting-pack/{job}")
async def underwriting_pack_status(request: Request, job: str) -> dict:
    require_permission(request, "operate")
    from . import ops_file_jobs as ops_jobs

    return ops_jobs.status(_job(job), ops_jobs.owner_of(request))


@router.get("/underwriting-pack/{job}/download")
async def underwriting_pack_download(request: Request, job: str):
    require_permission(request, "operate")
    from fastapi.responses import FileResponse

    from . import ops_file_jobs as ops_jobs

    path, name, media = ops_jobs.finished_file(_job(job), ops_jobs.owner_of(request))
    return FileResponse(path, media_type=media, filename=name, headers={"Cache-Control": "no-store"})


# ---- regulatory alerts into impact records (maverick regulatory-feed sync) ------

Queue = Literal["accepted", "in_review", "open"]


class FeedPreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    queue: Queue = "accepted"


class FeedSyncIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    queue: Queue = "accepted"
    regimes: list[str] = Field(default_factory=list, max_length=64)
    domains: list[str] = Field(default_factory=list, max_length=64)
    asset_ids: list[str] = Field(default_factory=list, max_length=64)
    send_notices: bool = False
    confirm: bool = False


def _tenant() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(status_code=409, detail="Choose a workspace first. Nothing was changed.")
    return tenant


def _feed_preview(queue: str) -> dict[str, Any]:
    from maverick import ai_regulatory_feed as feed

    alerts = feed.list_reviewed_alerts(status=queue, limit=100)
    regimes: set[str] = set()
    domains: set[str] = set()
    for alert in alerts:
        regimes.update(str(v) for v in getattr(alert, "matched_regimes", ()) or ())
        domains.update(str(v) for v in getattr(alert, "matched_domains", ()) or ())
    return {"alerts": len(alerts),
            "regimes": [{"value": v, "label": _words(v)} for v in sorted(regimes)],
            "domains": [{"value": v, "label": _words(v)} for v in sorted(domains)]}


def _feed_sync(body: FeedSyncIn, actor: str) -> dict[str, Any]:
    from maverick import ai_regulatory_feed as feed

    rule = {"rule_id": "dashboard-rule", "regimes": body.regimes, "domains": body.domains,
            "asset_ids": body.asset_ids}
    outcome = feed.sync_reviewed_alerts(rules=[rule], actor=actor, status=body.queue,
                                        limit=100, deliver=body.send_notices)
    bridged = outcome["bridged"]
    stale = sum(int(r["stale_evidence"]) for r in bridged)
    return {
        "alerts": outcome["alerts"], "matched": len(bridged), "failed": len(outcome["failures"]),
        "stale_evidence": stale,
        "summary": (f"{len(bridged)} of {outcome['alerts']} alert{'s' if outcome['alerts'] != 1 else ''} "
                    f"matched your rule and now have impact records"
                    + (f"; {stale} piece{'s' if stale != 1 else ''} of evidence need refreshing" if stale else "")
                    + (f". {len(outcome['failures'])} could not be processed." if outcome["failures"] else ".")),
        "technical": [str(f)[:300] for f in outcome["failures"][:50]],
    }


@router.post("/regulatory-feed/preview")
async def feed_preview(request: Request, body: FeedPreviewIn) -> dict:
    require_global_permission(request, "admin")
    _tenant()
    try:
        return await run_in_threadpool(_feed_preview, body.queue)
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="The regulatory alerts could not be read right now.") from exc


@router.post("/regulatory-feed/sync")
async def feed_sync(request: Request, body: FeedSyncIn) -> dict:
    require_global_permission(request, "admin")
    _tenant()
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirm to continue. Nothing was changed.")
    values = body.regimes + body.domains + body.asset_ids
    if not body.regimes and not body.domains:
        raise HTTPException(status_code=422, detail="Choose at least one regulation or area.")
    if any(not _ID.fullmatch(v) for v in values):
        raise HTTPException(status_code=422, detail="Choose from the lists.")
    await run_in_threadpool(_record, request, "regulatory_feed_sync", installation=False,
                            queue=body.queue, send_notices=body.send_notices)
    try:
        return await run_in_threadpool(_feed_sync, body, _actor(request))
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="The regulatory alerts could not be processed right now.") from exc


__all__ = ["router"]
