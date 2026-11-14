"""Settings > Maintenance controls for installation commands that were terminal-only.

Each route calls the same kernel function as its ``maverick`` command and
answers in plain sentences; exact kernel wording is returned separately as
``technical`` for the page's collapsed "Technical details":

* installed versions (``version``) and the encryption-key fingerprint
  (``shared-key-digest``);
* the release parts check (``release-runtime-check``), the shared-database
  separation check (``tenant rls-preflight``), waiting database updates
  (``schema-plan``) and the local AI model server plan (``local-runtime plan``);
* bringing the settings file up to date (``migrate``), with a preview first
  and a dated backup copy kept by the kernel;
* the whole configuration (``config``): every key, its effective value and
  where it comes from, secrets only as set / not set;
* tidying delivered message receipts (``channel-maintenance compact``);
* release checks (``canary record`` / ``canary compare``);
* preparing connection components (``gen-stubs``) and assigning older records
  to a workspace (``tenant backfill``) as background jobs;
* moving learning files into the shared records (``self-harness
  migrate-store``) and scheduling the task-record move that can only run while
  Lightwork is stopped (``a2a migrate-claims``).

Everything here reveals or changes installation internals, so every route needs
the global ``admin`` permission (a workspace administrator is refused).
Changes are same-origin checked, need an explicit ``confirm`` and add one
activity-record row naming who made them.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import ops_admin_jobs as ops_jobs
from .auth import require_global_permission
from .queue_status_api import redacted_error

router = APIRouter(prefix="/api/v1/admin/installation")
asset_router = APIRouter()
_STATIC = Path(__file__).parent / "static"
_TECHNICAL_LIMIT = 80
_WORKSPACE_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$"


@asset_router.get("/static/lightwork-maintenance-ops.js", include_in_schema=False)
async def maintenance_ops_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-maintenance-ops.js",
                        media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


def _admin(request: Request) -> None:
    require_global_permission(request, "admin")


def _mutation(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)
    _admin(request)


def _record(request: Request, verb: str, **detail: Any) -> None:
    from .system_checks_api import _record as record
    record(request, verb, **detail)


def _failed(request: Request, verb: str) -> None:
    """The outcome row for a change that did not complete (its request row is
    already in the activity record, so a refused outcome row is not raised)."""
    try:
        _record(request, verb, succeeded=False)
    except HTTPException:
        pass


def _confirmed(confirm: bool, what: str) -> None:
    if confirm is not True:
        raise HTTPException(409, f"Confirm to {what}. Nothing was changed.")


def _bounded(text: Any, limit: int = 400) -> str:
    return redacted_error(str(text))[:limit]


def _words(name: Any) -> str:
    text = " ".join(str(name or "").replace("_", " ").replace(".", " ").split())
    return text[:1].upper() + text[1:120]


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = Field(strict=True)


class WorkspaceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace: str = Field(min_length=1, max_length=128, pattern=_WORKSPACE_ID)
    confirm: bool = Field(default=False, strict=True)


def _known_workspace(workspace: str) -> str:
    from maverick.tenant.registry import get_tenant
    if get_tenant(workspace) is None:
        raise HTTPException(404, "Choose a workspace from the list.")
    return workspace


# ---- installed versions (maverick version) -----------------------------------

_PACKAGE_LABELS = {
    "maverick-agent": "Lightwork core",
    "maverick-shield": "Safety screening",
    "maverick-channels": "Chat channels",
    "maverick-evolve": "Self-improvement",
    "maverick-dashboard": "This app",
    "maverick-mcp-server": "Tool server for outside apps",
    "maverick-knowledge": "Knowledge library",
    "maverick-installer": "Setup assistant",
}
_PLATFORMS = {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}


def _versions() -> dict[str, Any]:
    from maverick.installation_info import package_versions, runtime_facts
    parts = [{"name": _PACKAGE_LABELS.get(name, _words(name)), "version": version or "",
              "installed": bool(version)} for name, version in package_versions()]
    facts = runtime_facts()
    persona = facts.get("persona") or {}
    details = [
        {"label": "Records database version", "value": str(facts["schema"]) if facts["schema"] else "Unknown"},
        {"label": "Safety screening", "value": _words(facts["shield_backend"]) if facts["shield_backend"]
         else "Not installed"},
        {"label": "AI services supported", "value": str(len(facts["providers"] or []))},
        {"label": "Assistant persona", "value": persona.get("name") or "None"},
        {"label": "Python", "value": facts["python"]},
        {"label": "Operating system", "value": _PLATFORMS.get(facts["platform"], _words(facts["platform"]))},
    ]
    core = next((p["version"] for p in parts if p["name"] == "Lightwork core"), "")
    missing = sum(1 for p in parts if not p["installed"])
    summary = (f"Lightwork {core} is installed." if core else "Lightwork's core version could not be read.")
    if missing:
        summary += f" {missing} optional part{'s are' if missing != 1 else ' is'} not installed."
    return {"summary": summary, "parts": parts, "details": details}


@router.get("/versions")
async def versions(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_versions)


# ---- encryption key fingerprint (maverick shared-key-digest) -------------------

def _key_fingerprint() -> dict[str, Any]:
    from maverick.installation_info import KeyDigestError, encryption_key_digest
    try:
        fingerprint = encryption_key_digest()
    except KeyDigestError as exc:
        summary = ("This installation was not given its own encryption key by your IT team, so there is "
                   "no fingerprint to show." if exc.reason == "unset" else
                   "The encryption key your IT team provided could not be read. Ask them to check it.")
        return {"available": False, "summary": summary, "fingerprint": ""}
    return {"available": True, "fingerprint": fingerprint,
            "summary": "This fingerprint identifies the encryption key without revealing it. Your IT team "
                       "enters it when they connect a shared records database."}


@router.get("/key-fingerprint")
async def key_fingerprint(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_key_fingerprint)


# ---- release parts check (maverick release-runtime-check) ----------------------

def _release_check() -> dict[str, Any]:
    from maverick.release_runtime import libpq_label, verify_full_release_runtime
    try:
        libpq = verify_full_release_runtime()
    except Exception as exc:  # noqa: BLE001 -- the failing check is the finding
        return {"ready": False,
                "summary": "Some parts that come with the full release are missing or not working. "
                           "Share the technical details with whoever installed Lightwork.",
                "technical": [{"level": "fail", "text": _bounded(exc)}]}
    return {"ready": True,
            "summary": "Every part that comes with the full release is present and working: AI service "
                       "connectors, document readers, the database driver, maths formatting and "
                       "performance measures.",
            "technical": [{"level": "pass", "text": f"bundled database driver {libpq_label(libpq)}"}]}


@router.post("/release-check")
async def release_check(request: Request) -> dict:
    _mutation(request)  # runs the full packaged-feature checks
    return await run_in_threadpool(_release_check)


# ---- shared database separation (maverick tenant rls-preflight) ----------------

_NOT_SHARED = ("This installation keeps its records on this computer, not in a shared database, so there "
               "is nothing to check.")


def _database_separation() -> dict[str, Any]:
    from maverick.world_model_backends import pg_rls
    dsn = pg_rls.resolve_dsn(None)
    if not dsn:
        return {"shared_database": False, "ready": None, "summary": _NOT_SHARED, "rows": [], "technical": []}
    try:
        conn = pg_rls.connect(dsn, autocommit=True)
    except ImportError:
        return {"shared_database": True, "ready": False, "rows": [], "technical": [],
                "summary": "The database driver isn't installed with this copy of Lightwork."}
    except Exception:  # noqa: BLE001 -- connection errors can quote the address
        return {"shared_database": True, "ready": False, "rows": [], "technical": [],
                "summary": "Lightwork could not reach the shared database. Ask your IT team to check it."}
    try:
        report = pg_rls.preflight(conn)
    finally:
        conn.close()
    rows = []
    for table, info in report["tables"].items():
        legacy = int(info.get("null_tenant_rows") or 0) + int(info.get("empty_tenant_rows") or 0)
        if info.get("missing"):
            state = "Not created yet"
        elif not info.get("owned_by_current_role"):
            state = "Lightwork's database account can't protect these"
        elif legacy:
            state = f"{legacy:,} older entr{'ies' if legacy != 1 else 'y'} not assigned to a workspace"
        else:
            state = "Ready"
        rows.append({"records": _words(table), "state": state, "ok": state == "Ready"})
    waiting = sum(1 for row in rows if not row["ok"])
    summary = ("The shared database is ready to keep every workspace's records separate."
               if report["ready"] else
               f"{waiting} kind{'s' if waiting != 1 else ''} of records need attention before the shared "
               "database can keep workspaces separate. Assign older records to a workspace below, and ask "
               "your IT team to give Lightwork's database account ownership of the rest.")
    return {"shared_database": True, "ready": bool(report["ready"]), "summary": summary, "rows": rows,
            "technical": [{"level": "info", "text": f"database account: {_bounded(report.get('role'), 80)}"}]}


@router.get("/database-separation")
async def database_separation(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_database_separation)


# ---- waiting database updates (maverick schema-plan) ---------------------------

def _database_updates() -> dict[str, Any]:
    from maverick.schema_migrations import current_plan, online_only

    from ._shared import _world
    world = _world()
    problems, current, target, steps = current_plan(world if hasattr(world, "schema_version") else None)
    if problems:
        return {"ok": False, "pending": 0, "needs_pause": False,
                "summary": "This copy of Lightwork has a problem in its database update list. Share the "
                           "technical details with whoever looks after this installation.",
                "technical": [{"level": "fail", "text": _bounded(p)} for p in problems][:_TECHNICAL_LIMIT]}
    if not steps:
        summary = f"The records database is up to date (version {current})."
    elif online_only(steps):
        summary = (f"{len(steps)} database update{'s are' if len(steps) != 1 else ' is'} waiting. They can be "
                   "applied while Lightwork keeps running.")
    else:
        summary = (f"{len(steps)} database update{'s are' if len(steps) != 1 else ' is'} waiting. Some need "
                   "Lightwork to pause briefly, so plan a quiet time for the next update.")
    return {"ok": True, "current": current, "target": target, "pending": len(steps),
            "needs_pause": bool(steps) and not online_only(steps), "summary": summary,
            "technical": [{"level": s.kind, "text": _bounded(f"v{s.version} [{s.kind}] {s.statement}", 160)}
                          for s in steps][:_TECHNICAL_LIMIT]}


@router.get("/database-updates")
async def database_updates(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_database_updates)


# ---- local AI model server (maverick local-runtime plan) -----------------------

_ENGINES = {"vllm": "vLLM", "tgi": "Text Generation Inference", "llamacpp": "llama.cpp",
            "llama_cpp": "llama.cpp", "llama.cpp": "llama.cpp"}


def _local_models() -> dict[str, Any]:
    import shlex

    from maverick.local_runtime import Launcher, LocalRuntimeError
    try:
        launcher = Launcher()
        argv, env = launcher.plan()
    except LocalRuntimeError as exc:
        return {"planned": False,
                "summary": "The local AI model server isn't fully set up yet. Choose its model and engine "
                           "in All settings.",
                "technical": [{"level": "fail", "text": _bounded(exc)}]}
    cfg = launcher.cfg
    facts = [{"label": "Turned on", "value": "Yes" if cfg.get("enabled") else "No"},
             {"label": "Engine", "value": _ENGINES.get(str(cfg.get("engine")), _words(cfg.get("engine")))},
             {"label": "Model", "value": str(cfg.get("model") or "")[:200]}]
    summary = ("Lightwork would start the local AI model server with the settings below." if cfg.get("enabled")
               else "The local AI model server is turned off. This shows what it would run once turned on.")
    technical = [{"level": "info", "text": "setting " + _bounded(name, 80)} for name in sorted(env)]
    technical.append({"level": "info", "text": _bounded(shlex.join(argv), 600)})
    return {"planned": True, "enabled": bool(cfg.get("enabled")), "summary": summary, "facts": facts,
            "technical": technical}


@router.get("/local-models")
async def local_models(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_local_models)


# ---- settings file update (maverick migrate) -----------------------------------

def _migration_summary(report: Any, *, applied: bool) -> dict[str, Any]:
    kinds = {"advisory": 0, "lint": 0, "rewrite": 0}
    for finding in report.findings:
        kinds[finding.kind] = kinds.get(finding.kind, 0) + 1
    no_file = any(f.id == "no-config" for f in report.findings)
    unreadable = any(f.id == "unparseable" for f in report.findings)
    if no_file:
        summary = "Lightwork is using its built-in settings, so there is no settings file to update."
    elif unreadable:
        summary = ("The installation settings file could not be read. Whoever installed Lightwork needs "
                   "to repair it; nothing was changed.")
    elif report.clean:
        summary = "The settings file is up to date. Nothing needs to change."
    else:
        parts = []
        if kinds["rewrite"]:
            verb = "were updated" if applied and report.wrote else "will be updated"
            parts.append(f"{kinds['rewrite']} setting name{'s' if kinds['rewrite'] != 1 else ''} {verb}")
        if kinds["advisory"]:
            parts.append(f"{kinds['advisory']} suggestion{'s' if kinds['advisory'] != 1 else ''} to review")
        if kinds["lint"]:
            parts.append(f"{kinds['lint']} section{'s' if kinds['lint'] != 1 else ''} this version does not use")
        summary = "; ".join(parts).capitalize() + "."
        if not kinds["rewrite"]:
            summary += " Nothing needs to be rewritten."
    return {
        "summary": summary,
        "rewrites": kinds["rewrite"],
        "suggestions": kinds["advisory"],
        "unused_sections": kinds["lint"],
        "can_update": bool(kinds["rewrite"]) and not applied,
        "wrote": bool(report.wrote),
        "backup": report.backup_path.name if report.backup_path else "",
        "technical": [{"level": f.kind, "text": _bounded(f.message)} for f in report.findings][:_TECHNICAL_LIMIT],
    }


def _migrate(apply: bool) -> dict[str, Any]:
    from maverick.migrate import migrate
    return _migration_summary(migrate(None, apply=apply), applied=apply)


@router.get("/settings-file")
async def settings_file_preview(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_migrate, False)


@router.post("/settings-file/update")
async def settings_file_update(body: ConfirmIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "update the settings file")
    await run_in_threadpool(_record, request, "settings_file_update_requested")
    try:
        result = await run_in_threadpool(_migrate, True)
    except Exception:
        await run_in_threadpool(_failed, request, "settings_file_update")
        raise
    await run_in_threadpool(_record, request, "settings_file_update", rewrites=result["rewrites"],
                            wrote=result["wrote"], backup=result["backup"], succeeded=True)
    return result


# ---- whole configuration (maverick config show) --------------------------------

_SOURCE_LABELS = {
    "file": "Installation settings file",
    "dashboard": "Changed in this app",
    "operator": "Set by your IT team",
    "workspace": "This workspace's own settings",
    "environment": "Set on the server",
}
_DEDICATED_PAGES = {
    "providers": ("/settings#settings-integrations", "Settings: Connections"),
    "models": ("/settings#settings-models", "Settings: Models"),
    "capabilities": ("/settings#settings-controls", "Settings: Features"),
    "features": ("/settings#settings-controls", "Settings: Features"),
    "webhooks": ("/settings#settings-integrations", "Settings: Connections"),
    "channels": ("/channels", "Channels"),
    "plugins": ("/plugins", "Add-ons"),
    "mcp_servers": ("/mcp", "Tool servers"),
    "value": ("/savings", "Savings"),
    "spending_limits": ("/spending-limits", "Spending limits"),
    "oauth": ("/connections", "Connections"),
    "connections": ("/connections", "Connections"),
    "security_ops": ("/security", "Security"),
    "research_execution": ("/research", "Research"),
}
_SECURITY_SWITCHES = {"threat_hunt", "env_hunt"}
# Why a key has no control in the app (shown in place of a Change link).
_DEVELOPER_SECTIONS = frozenset({"langchain", "coding", "model_proxy", "perf", "ebpf_monitor", "benchmark"})
_INSTALL_ONLY_KEYS = frozenset({"client.id", "deployment.type"})
_REASON_DEVELOPER = "A developer tool setting. Change it in the installation settings file."
_REASON_INSTALL = "Fixed when Lightwork is installed."
_REASON_MODULE = "This module's details are set in the installation settings file; its on/off switch is in All settings."
_REASON_SERVER = "Names a file, program or variable on the server, so it is set in the installation settings file."
_REASON_NONE = "Not yet changeable in the app. Change it in the installation settings file."


def _catalog_index() -> tuple[dict[str, tuple[str, str]], list[tuple[str, tuple[str, str]]]]:
    from . import settings_catalog as catalog
    from .settings_all_page import _slug
    exact: dict[str, tuple[str, str]] = {}
    tables: list[tuple[str, tuple[str, str]]] = []
    for setting in catalog.SETTINGS:
        target = ("/settings/all#group-" + _slug(setting.group), setting.label)
        if setting.key_kind == "key":
            exact.setdefault(".".join(setting.path), target)
        else:
            tables.append((".".join(setting.path) + ".", target))
    return exact, tables


def _switch_index() -> tuple[frozenset[str], dict[str, tuple[str, str]]]:
    """Module sections switched in All settings, and on/off keys with their own page."""
    from . import module_activation, settings_store
    switched: dict[str, tuple[str, str]] = {}
    for section, key in settings_store.LEARNING_TOGGLES:
        switched[f"{section}.{key}"] = ("/learning", "Learning")
    for section in settings_store.SWITCHABLE_SECTIONS:
        page = ("/security", "Security") if section in _SECURITY_SWITCHES else ("/learning", "Learning")
        switched.setdefault(f"{section}.enable", page)
    return frozenset(module_activation._MODULE_SWITCHES), switched


def _target(path: str, top: str, index: tuple) -> tuple[tuple[str, str] | None, str]:
    """``((href, label) or None, reason)`` for one key."""
    exact, tables, modules, switched = index
    target = exact.get(path) or next((t for prefix, t in tables if path.startswith(prefix)), None)
    target = target or switched.get(path)
    section = path.rsplit(".", 1)[0]
    if target is None and path.endswith(".enable") and section in modules:
        target = ("/settings/all#group-modules", "Modules")
    if target is None and top in _DEDICATED_PAGES and path not in _INSTALL_ONLY_KEYS:
        target = _DEDICATED_PAGES[top]
    if target is not None:
        return target, ""
    if path in _INSTALL_ONLY_KEYS:
        return None, _REASON_INSTALL
    if top in _DEVELOPER_SECTIONS:
        return None, _REASON_DEVELOPER
    if path.endswith(("_env", "_path", "_bin")) or path.endswith("sdn_path"):
        return None, _REASON_SERVER
    if top in modules or section in modules:
        return None, _REASON_MODULE
    return None, _REASON_NONE


def _display(value: Any) -> str:
    if isinstance(value, bool):
        return "On" if value else "Off"
    if isinstance(value, list):
        if not value:
            return "None"
        if all(isinstance(item, (str, int, float)) and not isinstance(item, bool) for item in value):
            return ", ".join(str(item) for item in value)[:300]
        return f"{len(value)} entries"
    if value is None or value == "":
        return "Not set"
    return str(value)[:300]


def _configuration() -> dict[str, Any]:
    from maverick.config_inventory import describe
    exact, tables = _catalog_index()
    index = (exact, tables, *_switch_index())
    inventory = describe()
    sections = []
    editable = listed = 0
    for section in inventory["sections"]:
        rows = []
        for key in section["keys"]:
            path = key["path"]
            target, reason = _target(path, section["name"], index)
            listed += 1
            editable += 1 if target else 0
            rows.append({
                "setting": target[1] if target and exact.get(path) else _words(key["key"]),
                "where": _words(key["section"]) if key["section"] else "General",
                "value": ("Set" if key["set"] else "Not set") if key["secret"] else _display(key.get("value")),
                "secret": key["secret"],
                "source": _SOURCE_LABELS.get(key["source"], _words(key["source"])),
                "href": target[0] if target else "",
                "link_label": "Change in All settings" if target and target[0].startswith("/settings/all")
                else (f"Change on {target[1]}" if target else ""),
                "reason": reason,
            })
        sections.append({"name": _words(section["name"]) or "General", "keys": rows})
    read_only = listed - editable
    summary = (f"{listed} setting{'s are' if listed != 1 else ' is'} in effect beyond the built-in defaults. "
               + (f"{read_only} can only be changed in the installation settings file; each says why."
                  if read_only else "Every one of them can be changed in this app."))
    if not listed:
        summary = "Lightwork is using its built-in settings. Nothing has been changed yet."
    return {"summary": summary, "sections": sections, "count": listed, "read_only": read_only,
            "unreadable": bool(inventory["unreadable"]), "truncated": inventory["truncated"]}


@router.get("/configuration")
async def configuration(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_configuration)


# ---- message receipts (maverick channel-maintenance compact) -------------------

def _tidy_receipts() -> int:
    from maverick_channels.delivery import DeliveryJournal
    return int(DeliveryJournal().compact_delivered(limit=100))


@router.post("/message-receipts/tidy")
async def tidy_message_receipts(body: ConfirmIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "tidy up message receipts")
    await run_in_threadpool(_record, request, "message_receipts_tidy_requested")
    try:
        count = await run_in_threadpool(_tidy_receipts)
    except ImportError as exc:
        await run_in_threadpool(_failed, request, "message_receipts_tidy")
        raise HTTPException(409, "Chat channels aren't installed with this copy of Lightwork.") from exc
    except Exception as exc:  # noqa: BLE001 -- a paused or restoring workspace refuses plainly
        await run_in_threadpool(_failed, request, "message_receipts_tidy")
        raise HTTPException(409, "Message receipts can't be tidied right now. Try again later.") from exc
    await run_in_threadpool(_record, request, "message_receipts_tidy", cleared=count, succeeded=True)
    return {"cleared": count,
            "summary": (f"Cleared the stored text of {count} delivered message{'s' if count != 1 else ''}. "
                        if count else "Nothing needed clearing in this pass. ")
            + "Each pass looks at up to 100 receipts; run it again to continue through older ones."}


# ---- release checks (maverick canary record / compare) -------------------------

_METRICS = {
    "cost_per_task": "Cost per task",
    "tokens_per_task": "AI usage per task",
    "p95_latency_s": "Time for the slowest tasks",
    "success_rate": "Tasks that finished successfully",
}
_VERDICTS = {"regressed": "Got worse", "improved": "Got better", "ok": "About the same", "new": "New measure",
             "missing": "Not measured", "invalid": "Not a valid number"}
_TOLERANCES = (0.05, 0.10, 0.20, 0.30)


def _current_release() -> str:
    from maverick.installation_info import package_versions
    return next((v for name, v in package_versions() if name == "maverick-agent" and v), "") or "current"


def _measure() -> dict[str, float]:
    from maverick.release_canary import measure

    from ._shared import _world
    return measure(_world(), window_days=30)


def _release_checks() -> dict[str, Any]:
    from maverick.release_canary import CanaryStore
    return {"releases": CanaryStore().releases()[-100:], "current_release": _current_release(),
            "measured": bool(_measure())}


@router.get("/release-checks")
async def release_checks(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_release_checks)


@router.post("/release-checks/baseline")
async def record_baseline(body: ConfirmIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "record the baseline")
    from maverick.release_canary import CanaryStore
    metrics = await run_in_threadpool(_measure)
    if not metrics:
        raise HTTPException(409, "No tasks finished in the last 30 days, so there is nothing to measure yet.")
    release = await run_in_threadpool(_current_release)
    await run_in_threadpool(CanaryStore().record, release, metrics)
    await run_in_threadpool(_record, request, "release_baseline_recorded", release=release,
                            measures=len(metrics))
    return {"release": release, "summary": f"Recorded today's performance as the baseline for version {release}."}


@router.get("/release-checks/compare")
async def compare_release(request: Request, baseline: str, tolerance: float = 0.10) -> dict:
    _admin(request)
    if tolerance not in _TOLERANCES:
        raise HTTPException(422, "Choose one of the listed allowances.")
    if not baseline or len(baseline) > 128:
        raise HTTPException(422, "Choose a recorded baseline from the list.")
    from maverick.release_canary import CanaryStore, compare
    base = await run_in_threadpool(CanaryStore().get, baseline)
    if base is None:
        raise HTTPException(404, "Choose a recorded baseline from the list.")
    current = await run_in_threadpool(_measure)
    if not current:
        raise HTTPException(409, "No tasks finished in the last 30 days, so there is nothing to compare yet.")
    result = compare(base, current, tolerance=tolerance)
    rows = [{"measure": _METRICS.get(v.metric, _words(v.metric)),
             "before": v.baseline if math.isfinite(v.baseline) else None,
             "now": v.candidate if math.isfinite(v.candidate) else None,
             "change": v.rel_change if abs(v.rel_change) != float("inf") else None,
             "result": _VERDICTS.get(v.verdict, _words(v.verdict)), "ok": v.verdict not in {"regressed", "missing", "invalid"}}
            for v in result.verdicts]
    worse = len(result.regressions)
    summary = ("Performance held up against the baseline." if result.passed else
               f"{worse} measure{'s' if worse != 1 else ''} got worse than the baseline by more than "
               f"{round(tolerance * 100)}%.")
    return {"passed": result.passed, "summary": summary, "rows": rows}


# ---- connection components (maverick gen-stubs) --------------------------------

_COMPONENTS = {"maverick.proto": "Task connection", "federation.proto": "Connection between installations",
               "plugin_host.proto": "Add-on connection"}


def _components_writable() -> bool:
    import maverick.grpc_api as grpc_api
    return os.access(Path(grpc_api.__file__).parent, os.W_OK)


def _prepare_components() -> dict[str, Any]:
    from maverick.grpc_stubs import generate_all
    done = generate_all()
    return {"prepared": [_COMPONENTS.get(name, _words(name)) for name in done],
            "summary": f"Prepared {len(done)} connection component{'s' if len(done) != 1 else ''}."}


def _component_failure(exc: BaseException) -> str:
    if isinstance(exc, ImportError):
        return "The component builder isn't installed with this copy of Lightwork."
    if isinstance(exc, PermissionError):
        return "This installation's program files are read-only, so components can't be prepared here."
    return "The connection components could not be prepared. Share the activity record with your IT team."


@router.post("/connection-components")
async def prepare_connection_components(body: ConfirmIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "prepare the connection components")
    if not await run_in_threadpool(_components_writable):
        raise HTTPException(409, "This installation's program files are read-only, so components can't be "
                                 "prepared here. They are prepared when the installation image is built.")

    def finished(job: dict) -> None:
        _record(request, "connection_components_prepared", succeeded=job["state"] == "done")
    try:
        job = ops_jobs.start("components", _prepare_components, failure=_component_failure, on_finish=finished)
    except ops_jobs.JobBusy as exc:
        raise HTTPException(409, "Components are already being prepared. Wait for that to finish.") from exc
    return {"job": ops_jobs.public(job)}


@router.get("/jobs/{job_id}")
async def job_status(job_id: str, request: Request) -> dict:
    _admin(request)
    job = ops_jobs.get(job_id[:32])
    if job is None:
        raise HTTPException(404, "That task is no longer listed. Start it again if needed.")
    return {"job": ops_jobs.public(job)}


# ---- older records to a workspace (maverick tenant backfill) -------------------

def _backfill(workspace: str, dry_run: bool) -> dict[str, int]:
    from maverick.world_model_backends import pg_rls
    dsn = pg_rls.resolve_dsn(None)
    if not dsn:
        raise HTTPException(409, _NOT_SHARED)
    conn = pg_rls.connect(dsn, autocommit=False)
    try:
        return pg_rls.backfill(conn, workspace, dry_run=dry_run)
    finally:
        conn.close()


def _backfill_rows(report: dict[str, int]) -> list[dict[str, Any]]:
    return [{"records": _words(table), "count": int(count)} for table, count in sorted(report.items())]


@router.post("/older-records/preview")
async def older_records_preview(body: WorkspaceIn, request: Request) -> dict:
    _mutation(request)  # opens a database transaction (rolled back)
    workspace = await run_in_threadpool(_known_workspace, body.workspace)
    try:
        report = await run_in_threadpool(_backfill, workspace, True)
    except HTTPException:
        raise
    except ImportError as exc:
        raise HTTPException(409, "The database driver isn't installed with this copy of Lightwork.") from exc
    except Exception as exc:  # noqa: BLE001 -- connection errors can quote the address
        raise HTTPException(503, "Lightwork could not reach the shared database. Ask your IT team.") from exc
    total = sum(report.values())
    return {"total": total, "rows": _backfill_rows(report),
            "summary": (f"{total:,} older record{'s' if total != 1 else ''} would be assigned to this workspace."
                        if total else "There are no older records to assign.")}


@router.post("/older-records/assign")
async def older_records_assign(body: WorkspaceIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "assign the older records")
    workspace = await run_in_threadpool(_known_workspace, body.workspace)
    await run_in_threadpool(_record, request, "older_records_assign_requested", workspace=workspace)

    def work() -> dict[str, Any]:
        report = _backfill(workspace, False)
        total = sum(report.values())
        return {"total": total, "rows": _backfill_rows(report),
                "summary": f"Assigned {total:,} older record{'s' if total != 1 else ''} to the workspace."}

    def failure(exc: BaseException) -> str:
        if isinstance(exc, HTTPException):
            return str(exc.detail)
        if isinstance(exc, ImportError):
            return "The database driver isn't installed with this copy of Lightwork."
        return "The older records could not be assigned. Nothing was changed; ask your IT team to check the database."

    def finished(job: dict) -> None:
        _record(request, "older_records_assigned", workspace=workspace, succeeded=job["state"] == "done",
                assigned=int((job.get("result") or {}).get("total") or 0))
    try:
        job = ops_jobs.start("older-records", work, failure=failure, on_finish=finished)
    except ops_jobs.JobBusy as exc:
        raise HTTPException(409, "Older records are already being assigned. Wait for that to finish.") from exc
    return {"job": ops_jobs.public(job)}


# ---- learning files to the shared records (maverick self-harness migrate-store) ----

def _learning_move_state() -> dict[str, Any]:
    from maverick.learning_store_migration import preview
    state = preview()
    waiting = state["addenda"] + state["provenance"] + state["tried"]
    if not state["world_store"]:
        summary = ("Lightwork keeps what it learns in files on this computer. To share it across your "
                   "installations, first choose the shared records option for where improvements are kept "
                   "in All settings.")
    elif state.get("unreadable"):
        summary = (f"The learning file {state['unreadable']} on this computer could not be read, so "
                   "nothing can be moved yet. Fix or move that file, then try again.")
    elif waiting:
        summary = (f"{waiting:,} learned item{'s are' if waiting != 1 else ' is'} still in files on this computer "
                   "and can be moved into the shared records.")
    else:
        summary = "Nothing learned on this computer is waiting to be moved."
    return {"ready": bool(state["world_store"]), "waiting": waiting, "summary": summary,
            "includes_test_cases": state["corpus_configured"]}


@router.get("/learning-move")
async def learning_move_state(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_learning_move_state)


def _learning_move() -> dict[str, Any]:
    from maverick.learning_store_migration import (
        migrate_corpus,
        migrate_learning_files,
        require_world_store,
    )
    require_world_store()
    learned = migrate_learning_files()
    corpus = migrate_corpus()
    moved = sum(v for k, v in (learned or {}).items() if k != "merged")
    cases = sum((corpus or {}).values()) if corpus else 0
    if not moved and not cases:
        summary = "Nothing learned on this computer needed moving."
    else:
        summary = (f"Moved {moved:,} learned item{'s' if moved != 1 else ''}"
                   + (f" and {cases:,} test case{'s' if cases != 1 else ''}" if cases else "")
                   + " into the shared records. The old files were kept as backups.")
    return {"moved": moved, "test_cases": cases, "merged": int((learned or {}).get("merged") or 0),
            "summary": summary}


@router.post("/learning-move")
async def learning_move(body: ConfirmIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "move the learned items")
    from maverick.learning_store_migration import MigrationRefused
    await run_in_threadpool(_record, request, "learning_move_requested")
    try:
        result = await run_in_threadpool(_learning_move)
    except MigrationRefused as exc:
        await run_in_threadpool(_failed, request, "learning_move")
        unreadable = getattr(exc, "path", None)
        raise HTTPException(409, "The learned items could not be moved safely, so the files on this computer "
                                 "were left as they were."
                                 + (f" The learning file {unreadable} could not be read; fix or move it first."
                                    if unreadable else "")) from exc
    except Exception:
        await run_in_threadpool(_failed, request, "learning_move")
        raise
    await run_in_threadpool(_record, request, "learning_move", moved=result["moved"],
                            test_cases=result["test_cases"], succeeded=True)
    return result


# ---- task records move (maverick a2a migrate-claims) ---------------------------

@router.get("/task-records")
async def task_records(request: Request) -> dict:
    _admin(request)
    from . import offline_maintenance
    return await run_in_threadpool(offline_maintenance.task_records_state)


@router.post("/task-records/schedule")
async def schedule_task_records(body: WorkspaceIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "schedule the move")
    workspace = await run_in_threadpool(_known_workspace, body.workspace)
    from . import offline_maintenance
    try:
        await run_in_threadpool(offline_maintenance.task_records_ready, workspace)
    except offline_maintenance.NotReady as exc:
        raise HTTPException(409, str(exc)) from exc
    await run_in_threadpool(_record, request, "task_records_move_scheduled", workspace=workspace)
    from .auth import caller_principal
    await run_in_threadpool(offline_maintenance.schedule, "task_records", workspace,
                            caller_principal(request) or "local administrator")
    return await run_in_threadpool(offline_maintenance.task_records_state)


@router.post("/task-records/cancel")
async def cancel_task_records(body: ConfirmIn, request: Request) -> dict:
    _mutation(request)
    _confirmed(body.confirm, "cancel the scheduled move")
    from . import offline_maintenance
    await run_in_threadpool(_record, request, "task_records_move_cancel_requested")
    try:
        await run_in_threadpool(offline_maintenance.cancel, "task_records")
    except Exception:
        await run_in_threadpool(_failed, request, "task_records_move_cancelled")
        raise
    await run_in_threadpool(_record, request, "task_records_move_cancelled", succeeded=True)
    return await run_in_threadpool(offline_maintenance.task_records_state)


# ---- tidy up old records in every workspace (maverick gc, the roster sweep) ----

_MAX_SWEEP_WORKSPACES = 1000


class SweepIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: int
    activity_days: int
    confirm: bool = Field(default=False, strict=True)


def _sweep_periods(days: int, activity_days: int) -> None:
    from .system_checks_api import _CLEANUP_CHOICES
    if days not in _CLEANUP_CHOICES or activity_days not in _CLEANUP_CHOICES:
        raise HTTPException(422, "Choose one of the listed time periods.")


def _roster() -> list[Any]:
    from maverick.tenant.registry import list_tenants
    tenants = list_tenants()
    if len(tenants) > _MAX_SWEEP_WORKSPACES:
        raise HTTPException(409, f"This installation has more than {_MAX_SWEEP_WORKSPACES} workspaces; tidy them "
                                 "up one workspace at a time.")
    return tenants


def _sweep_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"workspace": row["name"], "empty": bool(row.get("empty")), "held": bool(row.get("held")),
             "conversations": row.get("conversations"), "activity": row.get("activity"),
             "duplicate_checks": row.get("duplicate_checks")} for row in rows]


def _held_note(rows: list[dict[str, Any]]) -> str:
    """Plain words for workspaces skipped because a legal hold applies there."""
    held = sum(1 for row in rows if row["held"])
    if not held:
        return ""
    return (f" {held} workspace{'s' if held != 1 else ''} skipped: a legal hold applies there, "
            "so its old records were kept.")


def _sweep_preview(days: int, activity_days: int) -> dict[str, Any]:
    from maverick.records_gc import sweep_workspaces
    tenants = _roster()
    if not tenants:
        return {"workspaces": [], "total_conversations": 0, "total_activity": 0,
                "summary": "This installation has a single workspace. Use the clean-up above."}
    rows = _sweep_rows(sweep_workspaces(tenants, days=days, events_days=activity_days, dry_run=True,
                                        skip_empty=True))
    known = [r["conversations"] for r in rows if r["conversations"] is not None]
    conversations = sum(known)
    activity = sum(int(r["activity"] or 0) for r in rows)
    unknown = any(r["conversations"] is None and not r["empty"] for r in rows)
    summary = (f"Across {len(rows)} workspace{'s' if len(rows) != 1 else ''}: {conversations:,} "
               f"conversation{'s' if conversations != 1 else ''}{' or more' if unknown else ''} and "
               f"{activity:,} activity entr{'ies' if activity != 1 else 'y'} would be removed."
               + _held_note(rows))
    return {"workspaces": rows, "total_conversations": conversations, "total_activity": activity,
            "summary": summary}


@router.get("/all-workspaces-cleanup")
async def all_workspaces_cleanup_preview(request: Request, days: int = 90, activity_days: int = 30) -> dict:
    _admin(request)
    _sweep_periods(days, activity_days)
    return await run_in_threadpool(_sweep_preview, days, activity_days)


@router.post("/all-workspaces-cleanup")
async def all_workspaces_cleanup(body: SweepIn, request: Request) -> dict:
    _mutation(request)
    _sweep_periods(body.days, body.activity_days)
    _confirmed(body.confirm, "tidy up every workspace")
    tenants = await run_in_threadpool(_roster)
    if not tenants:
        raise HTTPException(409, "This installation has a single workspace. Use the clean-up above.")

    def work() -> dict[str, Any]:
        from maverick.records_gc import sweep_workspaces
        rows = _sweep_rows(sweep_workspaces(tenants, days=body.days, events_days=body.activity_days))
        totals = {key: sum(int(r[key] or 0) for r in rows)
                  for key in ("conversations", "activity", "duplicate_checks")}
        return {"workspaces": rows, **totals,
                "summary": f"Removed {totals['conversations']:,} conversations and {totals['activity']:,} "
                           f"activity entries across {len(rows)} workspaces." + _held_note(rows)}

    def failure(exc: BaseException) -> str:
        return ("The clean-up stopped part way. Workspaces already tidied stay tidied; run it again to "
                "finish the rest.")

    def finished(job: dict) -> None:
        result = job.get("result") or {}
        _record(request, "records_cleanup_all_workspaces", days=body.days, activity_days=body.activity_days,
                workspaces=len(tenants), succeeded=job["state"] == "done",
                conversations=int(result.get("conversations") or 0),
                activity=int(result.get("activity") or 0),
                duplicate_checks=int(result.get("duplicate_checks") or 0))
    try:
        job = ops_jobs.start("cleanup-all", work, failure=failure, on_finish=finished)
    except ops_jobs.JobBusy as exc:
        raise HTTPException(409, "Every workspace is already being tidied up. Wait for that to finish.") from exc
    return {"job": ops_jobs.public(job)}
