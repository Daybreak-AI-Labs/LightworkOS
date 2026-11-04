"""Installation checks and maintenance for administrators (Settings > Maintenance).

Buttons for the operator tasks that were only reachable from a terminal:
the installation health check, the go-live readiness check, the settings-file
check, the background work queue with native schedule review links, at-rest
encryption maintenance and live diagnostics. Every
route calls the same kernel functions the terminal commands call and answers in
plain sentences; the exact technical rows are returned separately so the page
can keep them inside a collapsed "Technical details" section.

Also the one-button checks (regulated-deployment guarantees, no outbound
connections, hardware memory protection, add-on versions), the organisation's
data download and erase, and tidying up old records.

Routes that read or change installation-wide state require the global
``admin`` permission; the read-only checks need the global ``audit``
permission; tidying up acts on the current workspace only and needs that
workspace's ``admin`` permission. Mutations are also same-origin checked and
recorded with the person who made them.
"""
from __future__ import annotations

import threading
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .auth import require_global_permission
from .queue_status_api import redacted_error

router = APIRouter(prefix="/api/v1/admin/system")
_DOCTOR_LOCK = threading.Lock()


def _admin(request: Request) -> None:
    require_global_permission(request, "admin")


def _mutation(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)
    _admin(request)


def _record(request: Request, verb: str, **detail: Any) -> None:
    """One activity-record row per maintenance change, naming who made it.

    Raises HTTP 503 when the activity record refuses the row (the change has
    already been made, so the page says so rather than claiming nothing
    happened).
    """
    from maverick.audit import AuditRefused, EventKind, audit_event
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=True,
                    verb=verb, principal="*",
                    actor=auth.caller_principal(request) or "local administrator",
                    ok=True, **detail)
    except AuditRefused as exc:
        raise HTTPException(
            503, "The change was made, but it could not be added to the activity record."
        ) from exc


def _row(key: str, label: str, ok: bool, detail: str, fix_label: str = "",
         fix_href: str = "") -> dict[str, Any]:
    return {"key": key, "label": label, "ok": bool(ok), "detail": detail,
            "fix_label": "" if ok else fix_label, "fix_href": "" if ok else fix_href}


# ---- go-live readiness (maverick launch-check) -----------------------------

def _readiness() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        from maverick import spending_limits
        limits = spending_limits.load()
        has_limit = bool(limits.get("workspace") or limits.get("default"))
        if not has_limit:
            from maverick.quotas import _quota_config
            quota = _quota_config()
            has_limit = bool(quota.get("enforce")) and (
                float(quota.get("max_dollars_per_day") or 0) > 0
                or float(quota.get("max_tokens_per_day") or 0) > 0)
        rows.append(_row("spending", "Spending limits", has_limit,
                         "A spending limit is set." if has_limit else "No spending limit is set, so costs are not capped.",
                         "Set spending limits", "/spending-limits"))
    except Exception:  # noqa: BLE001 -- a readiness row never aborts the page
        rows.append(_row("spending", "Spending limits", False,
                         "The spending limits could not be read.", "Open spending limits", "/spending-limits"))
    try:
        from maverick.paths import tenant_by_user_enabled
        on = bool(tenant_by_user_enabled())
        rows.append(_row("separation", "Each person's work kept separate", on,
                         "Each person works in their own space." if on
                         else "Everyone shares one space. Whoever installed Lightwork can change this.",
                         "Manage workspaces", "/tenants"))
    except Exception:  # noqa: BLE001
        rows.append(_row("separation", "Each person's work kept separate", False,
                         "This setting could not be read.", "Manage workspaces", "/tenants"))
    try:
        from maverick.crypto_at_rest import at_rest_enabled
        on = bool(at_rest_enabled())
        rows.append(_row("encryption", "Protection for new saved records", on,
                         "New supported records are encrypted on disk. Check Encryption to review older records and key custody." if on
                         else "Protection for new supported records is off. Review Encryption in Maintenance before changing it.",
                         "See encryption", "#maintenance-encryption"))
    except Exception:  # noqa: BLE001
        rows.append(_row("encryption", "Stored data is encrypted", False,
                         "The encryption setting could not be read.", "See encryption", "#maintenance-encryption"))
    try:
        from .provider_readiness import workspace_readiness
        readiness = workspace_readiness()
        ok = readiness["verdict"] == "ready"
        action = readiness["next_action"] or {"label": "Open providers", "href": "/providers"}
        rows.append(_row("provider", "AI provider connected", ok, readiness["reason"],
                         action["label"], action["href"]))
    except Exception:  # noqa: BLE001
        rows.append(_row("provider", "AI provider connected", False,
                         "The provider settings could not be read.", "Open provider keys",
                         "/settings#settings-integrations"))
    return rows


@router.get("/readiness")
async def readiness(request: Request) -> dict:
    _admin(request)
    rows = await run_in_threadpool(_readiness)
    return {"ready": all(r["ok"] for r in rows), "checks": rows}


@router.get("/probe-details")
async def probe_details(request: Request) -> JSONResponse:
    _admin(request)
    if not auth.caller_principal(request) and not auth._dashboard_token_authenticated(request):
        raise HTTPException(401, "Sign in as an administrator to view probe details.")
    from . import app as app_module
    from .health_routes import readiness_response
    from .provider_readiness import public_verdict, workspace_readiness

    response = await readiness_response(
        world_provider=app_module._world, provider_key_set=app_module._any_provider_key_set,
        include_details=True, provider_verdict=lambda: public_verdict(workspace_readiness()),
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


# ---- installation health (maverick doctor) ---------------------------------

def installation_health_context(request: Request, expected: str | None = None) -> dict[str, str]:
    from .draft_api import context_for
    _admin(request)
    context = context_for(request)
    if expected is not None and expected != context:
        raise HTTPException(409, "The signed-in account or workspace changed. Reload Help before running a check.")
    return {"context": context}


@router.get("/health-context")
def health_context(request: Request) -> dict[str, str]:
    return installation_health_context(request)


def _doctor(*, before_check=None) -> dict[str, Any]:
    from maverick import health
    rows: list[dict[str, str]] = []

    def collect(marker: str, label: str, detail: str = "", fix: str = "") -> None:
        if marker == health.RED:
            health._FAILURES.append(label)
            state = "problem"
        elif marker == health.YELLOW:
            state = "attention"
        else:
            state = "ok"
        rows.append({"state": state, "label": str(label), "detail": str(detail), "fix": str(fix)})

    # diagnose() prints through health._row; collect the rows instead. One run
    # at a time: the collector is swapped in for the duration of the check.
    with _DOCTOR_LOCK:
        if before_check is not None:
            before_check()
        original = health._row
        health._row = collect
        try:
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                failures = health.diagnose()
        finally:
            health._row = original
    problems = sum(1 for r in rows if r["state"] == "problem")
    attention = sum(1 for r in rows if r["state"] == "attention")
    if failures or problems:
        summary = (f"{problems} problem{'s' if problems != 1 else ''} found. "
                   "Share the technical details with whoever looks after this installation.")
    elif attention:
        summary = f"Lightwork is working. {attention} item{'s' if attention != 1 else ''} could be improved."
    else:
        summary = "Lightwork is installed correctly and working."
    return {"healthy": not (failures or problems), "problems": problems,
            "attention": attention, "checked": len(rows), "summary": summary,
            "technical": rows}


def _health_worker(request: Request, context: str) -> dict[str, Any]:
    def current() -> None:
        with auth.fresh_configuration():
            installation_health_context(request, context)
    current()
    return _doctor(before_check=current)


@router.post("/health-check")
async def health_check(request: Request) -> dict:
    _mutation(request)  # runs live checks (it may contact your AI provider)
    context = installation_health_context(request, request.headers.get("X-Lightwork-Health-Context"))["context"]
    try:
        result = await run_in_threadpool(_health_worker, request, context)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "The health check could not finish. No settings were repaired or changed. Ask an installation administrator to review the saved safety settings.") from exc
    with auth.fresh_configuration():
        installation_health_context(request, context)
    return result


# ---- settings file check (maverick config-lint) ----------------------------

def _config_check() -> dict[str, Any]:
    from maverick.config import config_path
    path = config_path()
    if not path.exists():
        return {"file_present": False, "errors": 0, "warnings": 0,
                "summary": "Lightwork is using its built-in settings. There is nothing to check.",
                "technical": []}
    try:
        try:
            import tomllib
        except ModuleNotFoundError:  # 3.10
            import tomli as tomllib
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 -- unreadable file is itself the finding
        return {"file_present": True, "errors": 1, "warnings": 0,
                "summary": "The installation settings file could not be read, so its settings are being ignored. "
                           "Whoever installed Lightwork needs to repair it.",
                "technical": [{"level": "error", "text": "settings file is not valid"}]}
    from maverick.config_lint import lint_config
    findings = lint_config(raw)
    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity != "error"]
    if errors:
        summary = (f"{len(errors)} setting{'s' if len(errors) != 1 else ''} in the installation settings file "
                   "cannot be used. Share the technical details with whoever installed Lightwork.")
    elif warnings:
        summary = (f"The installation settings work. {len(warnings)} "
                   f"suggestion{'s' if len(warnings) != 1 else ''} to tidy up.")
    else:
        summary = "The installation settings file has no problems."
    technical = [{"level": f.severity,
                  "text": f"[{f.section}]{(' ' + f.key) if f.key else ''}: {f.message}"}
                 for f in findings]
    return {"file_present": True, "errors": len(errors), "warnings": len(warnings),
            "summary": summary, "technical": technical}


@router.get("/settings-check")
async def settings_check(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_config_check)


# ---- background work queue (maverick queue status/failed/reconcile) --------

_QUEUE_STATES = {"pending": "Waiting", "running": "Running", "done": "Finished", "failed": "Stopped"}


def _job_kind(kind: str) -> str:
    return {"run_goal": "Run a task", "run_flow": "Run a workflow"}.get(
        kind, kind.replace("_", " ").replace(".", " ").capitalize())


def _queue() -> dict[str, Any]:
    from maverick.job_queue import JobQueue
    q = JobQueue()
    counts = q.counts()
    failed = q.list(status="failed", limit=25)
    return {
        "counts": [{"state": _QUEUE_STATES.get(k, k.capitalize()), "count": int(v)}
                   for k, v in sorted(counts.items())],
        "stopped": [{
            "id": j.id,
            "attempts": int(j.attempts or 0),
            "what": _job_kind(j.kind),
            "when": j.updated_at or j.created_at,
            "needs_decision": bool(j.recurrence_reconcile_required),
            # Masked the same way as the Action Center: a provider error can
            # quote the key it was given.
            "technical": redacted_error(j.last_error)[:300],
        } for j in failed],
    }


@router.get("/queue")
async def queue_summary(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_queue)


class ResumeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempts: int = Field(ge=0, le=10_000)


@router.post("/queue/{job_id}/resume")
async def queue_resume(job_id: int, body: ResumeIn, request: Request) -> dict:
    """Refuse the old shortcut; native recovery needs a complete exact review."""
    _mutation(request)
    raise HTTPException(409, {
        "message": "Open this schedule in Automations to review what happened and choose its next step.",
        "href": "/automations?recover_schedule=" + str(job_id),
    })


# ---- encryption (maverick encryption migrate / rotate) ---------------------

_SHARED_DATABASE_NOTE = (
    "Older records are kept in a shared database that this page cannot check or "
    "encrypt. Whoever installed Lightwork can encrypt them there."
)


def _world_db():
    """The world database file this request's workspace uses, or None.

    Resolved exactly as the other dashboard pages resolve it, so the count and
    the "Encrypt older records" button act on the workspace's own records. None
    means the records live in a shared database server, which this page does
    not handle.
    """
    from pathlib import Path

    from maverick.world_model_backends import is_postgres_configured
    if is_postgres_configured():
        return None
    from ._shared import _world
    return Path(_world().path)


def _encryption() -> dict[str, Any]:
    from maverick.crypto_at_rest import at_rest_enabled
    on = bool(at_rest_enabled())
    unprotected = None
    note = ""
    if on:
        try:
            from maverick.encryption_migrate import migrate_world_db
            db = _world_db()
            if db is None:
                note = _SHARED_DATABASE_NOTE
            else:
                unprotected = sum(migrate_world_db(db, dry_run=True).values()) if db.exists() else 0
        except Exception:  # noqa: BLE001 -- status read is best effort
            unprotected = None
    return {"enabled": on, "older_unprotected": unprotected, "older_note": note}


@router.get("/encryption")
async def encryption_status(request: Request) -> dict:
    _admin(request)
    from .encryption_maintenance import current
    state = await run_in_threadpool(current, request)
    state.pop("key_revision", None)
    return JSONResponse(state, headers={"Cache-Control": "private, no-store"})


class EncryptionReview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["protect", "rotate"]


class EncryptionChange(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    review: str = Field(min_length=1, max_length=8192)
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")
    confirm: bool


@router.post("/encryption/review")
async def encryption_review(body: EncryptionReview, request: Request):
    _mutation(request)
    from .encryption_maintenance import prepare
    return JSONResponse(await run_in_threadpool(prepare, request, body.action),
                        headers={"Cache-Control": "private, no-store"})


@router.get("/encryption/actions/{operation}")
async def encryption_action_receipt(operation: str, request: Request):
    _admin(request)
    from .encryption_maintenance import receipt
    return JSONResponse({"receipt": await run_in_threadpool(receipt, request, operation)},
                        headers={"Cache-Control": "private, no-store"})


async def _encryption_change(request, body, action):
    _mutation(request)
    from .draft_api import context_for
    from .encryption_maintenance import execute
    if body.confirm is not True or body.context != context_for(request):
        raise HTTPException(409, "Review the action in your current account and workspace before confirming it.")
    return JSONResponse(await run_in_threadpool(execute, request, action, body.review, body.operation),
                        headers={"Cache-Control": "private, no-store"})


@router.post("/encryption/protect-older", dependencies=[Depends(_mutation)])
async def encryption_protect_older(body: EncryptionChange, request: Request) -> dict:
    return await _encryption_change(request, body, "protect")


@router.post("/encryption/new-key", dependencies=[Depends(_mutation)])
async def encryption_new_key(body: EncryptionChange, request: Request) -> dict:
    return await _encryption_change(request, body, "rotate")


# ---- live diagnostics (maverick diag circuits / ratelimits) ----------------

def _diagnostics() -> dict[str, Any]:
    from maverick.circuit_breaker import snapshot
    from maverick.rate_limit_predictor import report

    from .plain_labels import provider_name

    paused = [s for s in snapshot() if s.get("state") in {"open", "half_open", "half-open"}]
    groups: dict[tuple[str, str], int] = {}
    for entry in paused:
        key = str(entry.get("key") or "").split(":", 2)
        name = provider_name(key[1]) + " connection" if len(key) > 1 and key[0] == "llm" else "Connected service"
        state = "Paused after repeated errors" if entry.get("state") == "open" else "A new request may check this connection"
        groups[(name, state)] = groups.get((name, state), 0) + 1
    return {
        "paused_services": [{"name": name + (f" ({count} recorded connections)" if count > 1 else ""),
                             "state": state} for (name, state), count in sorted(groups.items())[:64]],
        "recent_calls": [{"provider": provider_name(str(r.get("provider") or "")),
                          "calls": int(r.get("recorded") or 0)} for r in report()[:64]],
    }


@router.get("/diagnostics")
async def diagnostics(request: Request) -> dict:
    _admin(request)
    return JSONResponse(await run_in_threadpool(_diagnostics), headers={"Cache-Control": "private, no-store"})


# ---- one-button installation checks -----------------------------------------
# (maverick enterprise verify / airgap check / confidential-compute / plugin
# verify). Read-only: they need the global ``audit`` permission; the exact
# kernel wording is returned separately as ``technical`` for the collapsed
# "Technical details" section.

_GUARANTEE_LABELS = {
    "Egress lock": "Data cannot be sent to outside AI services",
    "At-rest encryption": "Saved data is encrypted",
    "Threat shield": "Harmful requests are screened",
    "Tamper-evident audit": "The activity record cannot be secretly changed",
    "Human oversight": "People approve risky actions",
    "Retention policy": "Old data is removed on a schedule",
    "Sandbox isolation": "Tasks run in a sealed workspace",
    "Data residency": "Data stays in the chosen region",
}
_TECHNICAL_LIMIT = 60


def _auditor(request: Request) -> None:
    require_global_permission(request, "audit")


def _bounded(text: Any, limit: int = 400) -> str:
    return str(text)[:limit]


def _enterprise_check() -> dict[str, Any]:
    from maverick.deployment import all_passed, verify_deployment
    checks = verify_deployment()
    rows = [{"label": _GUARANTEE_LABELS.get(c.name, c.name), "ok": bool(c.passed)} for c in checks]
    failed = sum(1 for r in rows if not r["ok"])
    passed = all_passed(checks)
    summary = ("Every protection for a regulated deployment is working." if passed else
               f"{failed} protection{'s' if failed != 1 else ''} for a regulated deployment "
               f"{'is' if failed == 1 else 'are'} not in place. Share the technical details with "
               "whoever installed Lightwork.")
    technical = [{"level": "pass" if c.passed else "fail", "text": _bounded(f"{c.name}: {c.detail}")}
                 for c in checks][:_TECHNICAL_LIMIT]
    return {"passed": bool(passed), "checks": rows, "summary": summary, "technical": technical}


@router.get("/enterprise-check")
async def enterprise_check(request: Request) -> dict:
    _auditor(request)
    return await run_in_threadpool(_enterprise_check)


def _offline_reason(violation: str) -> str:
    text = violation.lower()
    if text.startswith("remote model"):
        return "An AI model is reached over the internet."
    if "[sandbox]" in text:
        return "The task workspace can reach the network."
    if "sentry" in text:
        return "Error reports are sent to another computer."
    if "siem" in text:
        return "The activity record is copied to another computer."
    if "[webhooks]" in text:
        return "Notifications are sent to other apps."
    if "egress" in text or "allowed_hosts" in text:
        return "Outgoing connections are not blocked."
    if "[enterprise]" in text:
        return "Private mode is not turned on."
    return "Something can still send data out."


def _offline_check() -> dict[str, Any]:
    from maverick.air_gap import audit
    report = audit()
    violations = [str(v) for v in report.get("violations") or []]
    reasons = list(dict.fromkeys(_offline_reason(v) for v in violations))
    summary = ("Lightwork's settings have no way to send data off this computer." if report.get("clean")
               else f"Lightwork can still send data off this computer in "
                    f"{len(reasons)} way{'s' if len(reasons) != 1 else ''}.")
    return {"clean": bool(report.get("clean")), "reasons": reasons, "summary": summary,
            "technical": [{"level": "fail", "text": _bounded(v)} for v in violations][:_TECHNICAL_LIMIT]}


@router.get("/offline-check")
async def offline_check(request: Request) -> dict:
    _auditor(request)
    return await run_in_threadpool(_offline_check)


def _hardware_check() -> dict[str, Any]:
    from maverick.confidential_compute import detect
    report = detect()
    confidential = bool(report.get("confidential"))
    maker = "Intel" if report.get("tdx") else ("AMD" if report.get("sev_snp") else "")
    summary = (f"This computer keeps Lightwork's memory encrypted in hardware ({maker})."
               if confidential else
               "This computer does not encrypt Lightwork's memory in hardware. Most installations "
               "do not need this; it matters only if your rules require it.")
    return {"confidential": confidential, "summary": summary,
            "technical": [{"level": "pass", "text": _bounded(i)} for i in report.get("indicators") or []]}


@router.get("/hardware-check")
async def hardware_check(request: Request) -> dict:
    _auditor(request)
    return await run_in_threadpool(_hardware_check)


def _plugin_check() -> dict[str, Any]:
    from maverick.plugin_lock import verify_lock
    report = verify_lock()
    if report.get("unlocked"):
        return {"ok": True, "pinned": False, "problems": [],
                "summary": "Add-on versions are not pinned, so there is nothing to compare. "
                           "Whoever installed Lightwork can pin them.",
                "technical": []}
    problems: list[str] = []
    technical: list[dict[str, str]] = []
    for name, pinned, installed in report.get("drifted") or []:
        problems.append(f"{name} is a different version from the approved one.")
        technical.append({"level": "fail", "text": _bounded(f"{name}: approved {pinned}, installed {installed}")})
    for name in report.get("missing") or []:
        problems.append(f"{name} was approved but is not installed.")
        technical.append({"level": "fail", "text": _bounded(f"{name}: approved, not installed")})
    for name in report.get("unpinned") or []:
        problems.append(f"{name} is installed but was never approved.")
        technical.append({"level": "fail", "text": _bounded(f"{name}: installed, not in the approved list")})
    ok = bool(report.get("ok"))
    summary = ("Every installed add-on matches its approved version." if ok else
               f"{len(problems)} add-on{'s' if len(problems) != 1 else ''} "
               f"{'does' if len(problems) == 1 else 'do'} not match the approved list.")
    return {"ok": ok, "pinned": True, "problems": problems[:_TECHNICAL_LIMIT], "summary": summary,
            "technical": technical[:_TECHNICAL_LIMIT]}


@router.get("/plugin-check")
async def plugin_check(request: Request) -> dict:
    _auditor(request)
    return await run_in_threadpool(_plugin_check)


# ---- client data (maverick client status / export / erase) ------------------
# Installation-wide: every route needs the global ``admin`` permission; the
# export and the erase are recorded with the person who asked.

def _client_status() -> dict[str, Any]:
    from maverick.client import status
    st = status()
    bound = bool(st.get("bound"))
    if bound:
        summary = (f"This installation holds data for one organisation: {st.get('client_id')}. "
                   "You can request a local data export here. To remove its local folder, "
                   "Lightwork must be stopped first. Other workspaces, connected services, "
                   "and saved copies need separate review.")
    elif st.get("enforced"):
        summary = ("This installation must be set up for one organisation, but none is set. "
                   "Whoever installed Lightwork needs to fix this.")
    else:
        summary = ("This installation is not set up for one named organisation, so its data cannot be "
                   "erased from here. You can still download it.")
    return {"bound": bound, "organisation": st.get("client_id") or "", "enforced": bool(st.get("enforced")),
            "summary": summary,
            "technical": [{"level": "info", "text": _bounded(f"data folder: {st.get('data_root')}")}]}


@router.get("/client")
async def client_status(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_client_status)


def _export_failure(exc: Exception) -> str:
    from maverick.backup import BackupError
    if isinstance(exc, BackupError):
        return ("A data export needs a signing secret that whoever installed Lightwork sets up first. "
                "Nothing was exported.")
    return "The export could not be prepared. Try again, or ask whoever installed Lightwork."


def _build_client_export(workdir) -> Any:
    from maverick.backup import create_backup
    return create_backup(workdir / "export.tgz")


@router.post("/client/export", status_code=202)
async def client_export(request: Request) -> dict:
    """Start preparing every file of this installation's organisation
    (portability). The file can be large, so it is built in the background;
    the page asks for its status and then downloads it."""
    _mutation(request)
    import time as _time

    from . import ops_file_jobs as ops_jobs
    # Recorded before the file is prepared: a refused record prepares nothing.
    try:
        await run_in_threadpool(_record, request, "client_export")
    except HTTPException as exc:
        raise HTTPException(503, "This download could not be added to the activity record, "
                                 "so it was not prepared.") from exc
    name = "Lightwork-data-export-" + _time.strftime("%Y-%m-%d", _time.gmtime()) + ".tgz"
    job = ops_jobs.start("client_export", ops_jobs.owner_of(request), name, "application/gzip",
                         _build_client_export, _export_failure)
    return {"job": job, "state": "running"}


@router.get("/client/export/{job}")
async def client_export_status(job: str, request: Request) -> dict:
    _admin(request)
    from . import ops_file_jobs as ops_jobs
    return ops_jobs.status(_job_id(job), ops_jobs.owner_of(request))


@router.get("/client/export/{job}/download")
async def client_export_download(job: str, request: Request):
    _admin(request)
    from fastapi.responses import FileResponse

    from . import ops_file_jobs as ops_jobs
    path, name, media = ops_jobs.finished_file(_job_id(job), ops_jobs.owner_of(request))
    return FileResponse(path, media_type=media, filename=name,
                        headers={"Cache-Control": "private, no-store"})


def _job_id(value: str) -> str:
    import re as _re
    if not _re.fullmatch(r"[0-9a-f]{32}", value or ""):
        raise HTTPException(404, "That download is no longer available. Start it again.")
    return value


_AREA_LABELS = {
    "audit": "Activity record", "world.db": "Tasks and conversations", "memory": "Saved memory",
    "fleet": "Shared memory for outside agents", "backups": "Earlier data exports",
    "(top level)": "Other files",
}


@router.get("/client/erase/preview")
async def client_erase_preview(request: Request, keep_activity_record: bool = True) -> dict:
    """What erasing the organisation would remove, without removing anything."""
    _admin(request)
    from maverick.client import ClientBindingError, erase_client_preview
    try:
        preview = await run_in_threadpool(lambda: erase_client_preview(keep_audit=keep_activity_record))
    except ClientBindingError as exc:
        raise HTTPException(409, "This installation is not set up for one organisation, so nothing can be erased.") from exc
    areas = sorted(preview["by_area"].items(), key=lambda kv: -kv[1])
    return {
        "organisation": preview["client_id"],
        "files": int(preview["files"]),
        "areas": [{"label": _AREA_LABELS.get(name, name.replace("_", " ").replace("-", " ").capitalize()),
                   "files": count} for name, count in areas[:40]],
        "keeps_activity_record": bool(preview["kept_audit"]),
    }


@router.get("/client/erase/receipt/{receipt_id}")
async def client_erase_receipt(receipt_id: str, request: Request) -> JSONResponse:
    """Download the surviving signed record without reopening erased client data."""
    import json
    import re

    from maverick.audit import verify_chain
    from maverick.paths import maverick_home

    _admin(request)
    if not re.fullmatch(r"[0-9a-f]{32}", receipt_id):
        raise HTTPException(404, "That activity receipt was not found.")
    base = maverick_home() / "client-erasure"
    directory = base / receipt_id
    receipt = directory / "events.ndjson"
    key_file = directory / "verification-key.hex"
    try:
        if (directory.is_symlink() or directory.resolve().parent != base.resolve()
                or receipt.is_symlink() or key_file.is_symlink()
                or not receipt.is_file() or not key_file.is_file()):
            raise HTTPException(404, "That activity receipt was not found.")
        if receipt.stat().st_size > 64_000 or key_file.stat().st_size > 256:
            raise ValueError("receipt is too large")
        with key_file.open("rb") as key_stream, receipt.open("rb") as receipt_stream:
            key_bytes = key_stream.read(257)
            original_bytes = receipt_stream.read(64_001)
        if len(key_bytes) > 256 or len(original_bytes) > 64_000:
            raise ValueError("receipt is too large")
        public_key = key_bytes.decode("utf-8").strip()
        original = original_bytes.decode("utf-8")
        with receipt.open("rb") as receipt_stream:
            if verify_chain(receipt, public_key) or original_bytes != receipt_stream.read(64_001):
                raise ValueError("receipt verification failed")
        status = json.loads(original.splitlines()[-1]).get("status", "requested")
    except HTTPException:
        raise
    except (OSError, RuntimeError, UnicodeError, ValueError, IndexError) as exc:
        raise HTTPException(503, "The activity receipt could not be verified. Ask an administrator to check it.") from exc
    return JSONResponse(
        {"receipt_id": receipt_id, "status": status, "events_ndjson": original,
         "verification_key": public_key,
         "verification_scope": "Signature valid against the included key; keep an independent copy of that key to detect replacement."},
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff",
                 "Content-Disposition": f'attachment; filename="lightwork-activity-receipt-{receipt_id}.json"'},
    )


class EraseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organisation: str = Field(min_length=1, max_length=64)
    keep_activity_record: bool = True
    confirm: bool


@router.post("/client/erase")
async def client_erase(body: EraseIn, request: Request) -> dict:
    """Erase all of this organisation's data (offboarding).

    ``organisation`` is the name the person typed to confirm; anything but the
    current binding is refused, so a typo or a stale page can never erase
    someone else's data."""
    _mutation(request)
    if body.confirm is not True:
        raise HTTPException(409, "Confirm the erase to continue. Nothing was erased.")
    from maverick.client import client_id
    current = await run_in_threadpool(client_id)
    if not current:
        raise HTTPException(409, "This installation is not set up for one organisation, so nothing was erased.")
    if current != body.organisation:
        raise HTTPException(409, "The name typed does not match this organisation, or it changed since the page "
                                 "was loaded. Nothing was erased.")
    # This request runs inside the live dashboard, which holds tenant database
    # handles and may have workers writing the same root. On Windows a file can
    # survive deletion while siblings are removed; other platforms can recreate
    # deleted files before the server stops. Never begin a partial live erase.
    raise HTTPException(
        409,
        "Lightwork must be stopped before local data can be erased safely. "
        "This running page cannot do that yet. Nothing was erased.",
    )


# ---- tidy up old records (maverick gc) --------------------------------------
# Acts on the current workspace's records only, so a workspace administrator
# may run it; it is recorded with the person who ran it.

_CLEANUP_CHOICES = (7, 30, 60, 90, 180, 365)


def _cleanup_admin(request: Request) -> None:
    from .auth import require_permission
    require_permission(request, "admin")


def _require_workspace() -> None:
    from maverick.paths import current_tenant_id
    from maverick.world_model_backends import is_postgres_configured
    if is_postgres_configured() and current_tenant_id() is None:
        raise HTTPException(409, "Choose a workspace first. Nothing was changed.")


def _cleanup_world():
    _require_workspace()
    from ._shared import _world
    return _world()


def _count_idle_conversations(world: Any, cutoff: float) -> int | None:
    from maverick.world_model import WorldModel
    if not isinstance(world, WorldModel):
        return None  # a shared database server: counted when it runs
    row = world._read_one("SELECT COUNT(*) FROM conversations WHERE last_seen < ?", (cutoff,))
    return int(row[0] or 0) if row is not None else 0


def _cleanup_preview(days: int, activity_days: int) -> dict[str, Any]:
    import time as _time

    from maverick.ediscovery import LegalHoldApplies
    from maverick.records_gc import assert_no_broad_holds

    # The same gate as the run: a held workspace shows no counts, so the preview promises nothing the run refuses.
    _require_workspace()
    try:
        assert_no_broad_holds()
    except LegalHoldApplies:
        return {"conversations": 0, "activity": 0, "days": days, "activity_days": activity_days, "held": True}
    world = _cleanup_world()
    now = _time.time()
    conversations = _count_idle_conversations(world, now - days * 86400)
    events = int(world.purge_goal_events_before(now - activity_days * 86400, dry_run=True))
    return {"conversations": conversations, "activity": events, "days": days, "activity_days": activity_days}


def _cleanup_run(days: int, activity_days: int) -> dict[str, int]:
    from maverick.ediscovery import LegalHoldApplies
    from maverick.records_gc import assert_no_broad_holds

    # The same gate as `maverick gc`: a recorded privacy-rights case hold or an active matter pauses it.
    _require_workspace()
    try:
        assert_no_broad_holds()
    except LegalHoldApplies as exc:
        raise HTTPException(409, str(exc)) from exc
    world = _cleanup_world()
    return {
        "conversations": int(world.prune_conversations(idle_for_seconds=days * 86400)),
        "activity": int(world.prune_goal_events(older_than_seconds=activity_days * 86400)),
        "duplicate_checks": int(world.prune_processed_messages(older_than_seconds=30 * 86400)),
    }


def _cleanup_days(days: int, activity_days: int) -> None:
    if days not in _CLEANUP_CHOICES or activity_days not in _CLEANUP_CHOICES:
        raise HTTPException(422, "Choose one of the listed time periods.")


@router.get("/cleanup/preview")
async def cleanup_preview(request: Request, days: int = 90, activity_days: int = 30) -> dict:
    _cleanup_admin(request)
    _cleanup_days(days, activity_days)
    return await run_in_threadpool(_cleanup_preview, days, activity_days)


class CleanupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: int
    activity_days: int
    confirm: bool


@router.post("/cleanup")
async def cleanup_run(body: CleanupIn, request: Request) -> dict:
    from . import app as app_module
    app_module._require_same_origin(request)
    _cleanup_admin(request)
    _cleanup_days(body.days, body.activity_days)
    if body.confirm is not True:
        raise HTTPException(409, "Confirm the clean-up to continue. Nothing was removed.")
    result = await run_in_threadpool(_cleanup_run, body.days, body.activity_days)
    await run_in_threadpool(_record_workspace, request, "records_cleanup", days=body.days,
                            activity_days=body.activity_days, **result)
    return result


def _record_workspace(request: Request, verb: str, **detail: Any) -> None:
    """Like :func:`_record`, but in the current workspace's activity record."""
    from maverick.audit import AuditRefused, EventKind, audit_event
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", verb=verb,
                    actor=auth.caller_principal(request) or "local administrator",
                    ok=True, **detail)
    except AuditRefused as exc:
        raise HTTPException(
            503, "The change was made, but it could not be added to the activity record."
        ) from exc
