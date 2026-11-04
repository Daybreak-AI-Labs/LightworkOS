"""The full setup guide (``maverick init``) inside the app.

The terminal setup assistant (``apps/installer-cli/maverick_installer/wizard/``)
is the source of truth for what setup covers. Its advanced flow walks 44 steps
(``wizard.STEPS``); :data:`STEPS` below names, for each one, where the same
settings are changed in this app. Most live in All settings (the catalog of
product settings, which writes the same keys the assistant writes); the rest
have their own page. A step whose settings are fixed when Lightwork is
installed is marked as such, with the reason. ``tests`` keep this list in step
with the assistant's own.

The page also offers the assistant's headless path (``maverick init
--from-file``): an administrator uploads a prepared settings file, sees whether
it is valid and what the settings check says about it, and installs it; the
previous file is kept as a dated backup copy. It uses the same kernel code as
the command (:mod:`maverick.config_install`).

Global administrators only; installing is same-origin checked, needs an
explicit confirmation and adds one activity-record row.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter()
_MAX_FILE = 256 * 1024
_STATIC = Path(__file__).parent / "static"


@router.get("/static/lightwork-setup-guide.js", include_in_schema=False)
async def setup_guide_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-setup-guide.js", media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})

# (wizard step id, title, what it covers, config sections it writes, dedicated page or "")
STEPS: tuple[tuple[str, str, str, tuple[str, ...], str], ...] = (
    ("deployment", "Where Lightwork runs", "Desktop, server or cloud. Chosen when Lightwork is installed.",
     ("deployment",), ""),
    ("providers", "AI providers", "Which AI services Lightwork may use, and their keys.", ("providers",),
     "/settings#settings-integrations"),
    ("role_models", "Models", "Which AI model each kind of work uses.", ("models",), "/settings#settings-models"),
    ("channels", "Chat channels", "The chat apps people can give work from.", ("channels",), "/channels"),
    ("safety", "Safety", "How carefully requests and actions are screened.", ("safety",), ""),
    ("signed_skills", "Signed skills", "Whether only signed skills may be added.", ("skills",), ""),
    ("budget", "Spending", "The most one task may spend, and when spending alerts arrive.",
     ("budget", "spending_limits"), ""),
    ("approvals", "Approvals", "How long a decision can be undone, the confirmation for risky requests, "
     "and who approves a risky action someone asked for.", ("approval",), ""),
    ("sandbox", "Protected work area", "Where agent commands run and what they may reach.", ("sandbox",), ""),
    ("research_execution", "Research lab", "Whether research experiments may run, and their limits.",
     ("research_execution",), "/research"),
    ("candidate_promotion", "Candidate promotion", "How proposed improvements are reviewed before use.",
     ("candidate_promotion",), ""),
    ("knowledge_access", "Governed knowledge", "Which knowledge agents may use.", ("knowledge_access",), ""),
    ("capabilities", "Capabilities", "Browser, computer and code tools agents may use, the tests "
     "changed agent instructions must pass before they are published, and practice mode.",
     ("capabilities", "agent_factory", "practice"),
     "/settings#settings-controls"),
    ("self_learning", "Self-learning", "Whether agents learn from past work.", ("self_learning",), ""),
    ("ekko", "Work discovery", "Finding work that could be automated.", ("ekko",), ""),
    ("automation_import", "Automation import", "Bringing in automations from other tools.",
     ("automation_import",), ""),
    ("event_triggers", "Event triggers", "Starting work when something happens elsewhere.",
     ("event_triggers",), ""),
    ("flows", "Workflows", "The workflow engine and its options.", ("flows",), ""),
    ("knowledge", "Knowledge library", "Searchable documents for agents.", ("knowledge",), ""),
    ("oauth_vault", "Account connections", "Keeping signed-in accounts sealed per workspace.", ("oauth",),
     "/connections"),
    ("governed_connectors", "Governed connectors", "Connections to business systems.", ("governed_connectors",),
     ""),
    ("durable", "Durable work", "Resuming long work after a restart.", ("durable",), ""),
    ("journal", "Change journal", "Recording file changes so they can be undone.", ("workspace",), ""),
    ("finance", "Finance", "Finance tools and their limits.", ("finance", "finance_operations"), ""),
    ("value", "Savings assumptions", "Your cost of doing work by hand, for the savings figures.", ("value",),
     "/savings"),
    ("intent_value", "Work value and opportunities", "Estimated labor value, execution costs and optional workflow suggestions.",
     ("intent_value",), "/work-value"),
    ("assessments", "Assessments", "Help with assessments and reviews.", ("assessments",), ""),
    ("security_suite", "Security and compliance", "The security and compliance modules.",
     ("governance_agents", "threat_hunt", "env_hunt"), ""),
    ("monitoring", "Monitoring and key management",
     "Where timing traces, measurements and the activity record are sent, and the cloud key "
     "service. In All settings they are under Performance and Security.",
     ("observability", "kms", "audit"), "/settings/all"),
    ("advanced", "Advanced reasoning", "Planning, checking, showing the plan before acting and other advanced options.",
     ("reflexion", "planning", "verification", "autonomy"), ""),
    ("api_keys", "API access", "Personal and service-account keys for scripts and integrations.",
     ("dashboard",), "/settings#api-keys"),
    ("web_search", "Web search", "Whether agents may search the web.", ("search",), ""),
    ("mcp_servers", "Tool servers", "Outside tool servers agents may use.", ("mcp_servers",), "/mcp"),
    ("plugins", "Add-ons", "Installed add-ons and what they may do.", ("plugins",), "/plugins"),
    ("tool_acl", "Tool permissions", "Which tools each channel may use.", ("tools",), ""),
    ("rate_limits", "Usage limits", "How often each tool may be used.", ("rate_limits",), ""),
    ("retention", "Data retention", "How long records are kept.", ("retention",), ""),
    ("analytics", "Usage analytics", "Whether usage is measured.", ("analytics",), ""),
    ("persona", "Assistant persona", "The assistant's name and style.", ("persona",), ""),
    ("notifications", "Notifications", "Where alerts are sent.", ("notifications",), ""),
    ("deadline_alerts", "Deadline alerts", "Warnings before a data request, incident clock, renewal or approval is due.",
     ("deadline_alerts",), ""),
    ("daily_summary", "Daily summary and chat approvals",
     "Each person's daily summary, approval cards in Slack, the Help menu's status page and support contact, "
     "and comments with mentions.",
     ("my_work", "notifications", "support", "collaboration"), "/me"),
    ("webhooks", "Webhooks", "Sending events to other apps.", ("webhooks",), "/settings#settings-integrations"),
    ("a2a", "Outside agents", "Letting agents from other systems send work.", ("a2a",), ""),
)
_INSTALL_ONLY = {
    "deployment": "Fixed when Lightwork is installed: it records how this copy was set up.",
}


def _catalog_groups() -> dict[str, str]:
    from . import settings_catalog as catalog
    from .settings_all_page import _slug
    groups: dict[str, str] = {}
    for setting in catalog.SETTINGS:
        groups.setdefault(setting.top, _slug(setting.group))
    return groups


def steps() -> list[dict[str, Any]]:
    groups = _catalog_groups()
    out = []
    for number, (step_id, title, about, sections, page) in enumerate(STEPS, start=1):
        slug = next((groups[s] for s in sections if s in groups), "")
        if page:
            href, label = page, "Open"
        elif slug:
            href, label = "/settings/all#group-" + slug, "Open in All settings"
        else:
            href, label = "", ""
        out.append({"number": number, "id": step_id, "title": title, "about": about, "href": href,
                    "label": label, "in_app": bool(href),
                    "note": _INSTALL_ONLY.get(step_id, "" if href else "Not yet changeable in the app.")})
    return out


@router.get("/start/setup", response_class=HTMLResponse)
async def setup_guide_page(request: Request) -> HTMLResponse:
    require_global_permission(request, "admin")
    from .app import templates
    rows = await run_in_threadpool(steps)
    return templates.TemplateResponse(request, "setup_guide.html", {
        "steps": rows, "in_app": sum(1 for row in rows if row["in_app"]), "total": len(rows)},
        headers={"Cache-Control": "private, no-store"})


# ---- install a prepared settings file (maverick init --from-file) ---------------

async def _file(request: Request) -> bytes:
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > _MAX_FILE:
            raise HTTPException(413, "That file is too large to be a settings file.")
    if not raw.strip():
        raise HTTPException(422, "Choose a settings file.")
    return raw


def _check(raw: bytes) -> dict[str, Any]:
    from maverick.config_install import (
        ConfigInstallError,
        blocking_config_findings,
        config_findings,
        parse_config_bytes,
    )
    try:
        cfg = parse_config_bytes(raw)
    except ConfigInstallError as exc:
        return {"valid": False, "summary": "This isn't a valid settings file, so it can't be installed.",
                "problems": 0, "technical": [{"level": "error", "text": str(exc)[:300]}]}
    from maverick.config import _ENV_PATTERN

    def has_environment_reference(value):
        if isinstance(value, str):
            return bool(_ENV_PATTERN.search(value))
        if isinstance(value, dict):
            return any(has_environment_reference(item) for item in value.values())
        if isinstance(value, list):
            return any(has_environment_reference(item) for item in value)
        return False

    if has_environment_reference(cfg):
        return {"valid": False,
                "summary": "Environment references must be installed by the server operator, not through the dashboard.",
                "problems": 1, "technical": [{"level": "error", "text": "Environment references require operator-owned configuration."}]}
    findings = config_findings(cfg)
    blocking = blocking_config_findings(findings)
    if blocking:
        summary = (f"This file has {len(blocking)} setting"
                   f"{'s' if len(blocking) != 1 else ''} Lightwork cannot use. "
                   "Correct them and check the file again. Nothing has changed.")
    elif findings:
        summary = (f"The file is ready to install. Review {len(findings)} note"
                   f"{'s' if len(findings) != 1 else ''} below.")
    else:
        summary = "The file is ready to install."
    return {"valid": not blocking, "summary": summary, "problems": len(findings),
            "sections": len([k for k, v in cfg.items() if isinstance(v, dict)]),
            "technical": [{"level": getattr(f, "severity", "info"),
                           "text": f"{getattr(f, 'section', '')}: {getattr(f, 'message', '')}"[:300]}
                          for f in findings][:80]}


def _receipt_path(token: str) -> Path:
    import re

    from maverick.config import config_path

    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise HTTPException(422, "Check this file again before installing it.")
    return config_path().parent / "settings-install-reviews" / (token + ".json")


def _write_receipt(path: Path, receipt: dict) -> None:
    import json

    from maverick.file_lock import atomic_write_text, ensure_private_directory

    ensure_private_directory(path.parent)
    atomic_write_text(path, json.dumps(receipt, sort_keys=True), mode=0o600)


def _read_receipt(request: Request, token: str) -> tuple[Path, dict]:
    import json

    from .draft_api import context_for

    path = _receipt_path(token)
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "This file review is unavailable. Check the file again.") from exc
    if receipt.get("context") != context_for(request):
        raise HTTPException(409, "The account or workspace changed. Check the file again.")
    return path, receipt


def _file_preview_value(setting, value):
    from . import settings_all_page as page
    from .draft_store import validate_payload
    shown = page._audit_value(setting, value)
    try:
        validate_payload({'value': shown})
    except (ValueError, TypeError):
        return 'Configured (value withheld)'
    return shown


def _file_review_revision(raw: bytes, layers: dict | None = None) -> str:
    import hashlib
    import json
    import os

    from maverick.config import _ENV_PATTERN

    from . import settings_all_page as page
    names = set(_ENV_PATTERN.findall(raw.decode("utf-8")))
    environment = {name: os.environ.get(name, "") for name in names}
    return hashlib.sha256(json.dumps([page._revision(layers), environment], sort_keys=True).encode()).hexdigest()


def _prepare_file(request: Request, raw: bytes) -> dict:
    import hashlib
    import secrets
    import time

    from maverick.config_install import parse_config_bytes

    from . import settings_all_page as page
    from . import settings_catalog as catalog
    from . import settings_store
    from .draft_api import context_for

    with settings_store._locked(strict=True):
        checked = _check(raw)
        if not checked["valid"]:
            return checked
        layers = page._sources()
        # _sources already expands only the operator-owned layers. Re-expanding
        # the dashboard or workspace layer would reveal process secrets.
        preview_layers = layers
        proposed = {**preview_layers, "base": parse_config_bytes(raw)}
        impact = []
        for setting in catalog.SETTINGS:
            old, new = page._resolve(setting, preview_layers), page._resolve(setting, proposed)
            old_base = catalog.lookup(preview_layers["base"], setting.path)
            new_base = catalog.lookup(proposed["base"], setting.path)
            if old_base == new_base:
                continue
            impact.append({"label": setting.label, "source": page.SOURCE_TEXT[new["source"]],
                           "change": "Added" if not old_base[0] else "Removed" if not new_base[0] else "Changed",
                           "before": _file_preview_value(setting, old["value"]),
                           "after": _file_preview_value(setting, new["value"]),
                           "overridden": new["source"] in {"here", "deployment"},
                           "impact": "After restart" if setting.restart else "Next task"})
        impact.extend(_other_file_impact(preview_layers, proposed['base']))
        token = secrets.token_hex(32)
        _write_receipt(_receipt_path(token), {
            "context": context_for(request), "digest": hashlib.sha256(raw).hexdigest(),
            "revision": _file_review_revision(raw, layers), "created_at": time.time(), "status": "reviewed",
        })
        return {**checked, "review": token, "impact": impact,
                "scope": "All users and workspaces on this installation"}


def _other_file_impact(layers: dict, proposed_base: dict) -> list[dict]:
    """Account for dedicated/unknown fields without displaying unclassified values.

    The catalog provides typed/redacted values above. Remaining file fields may
    contain credentials even when their names look innocent, so this projection
    exposes presence/change/source only. It never guesses that a value is public.
    """
    import os

    from . import settings_catalog as catalog
    from . import settings_store

    def leaves(value, prefix=()):
        result = {}
        if isinstance(value, dict) and value:
            for key, item in value.items():
                result.update(leaves(item, (*prefix, key)))
        else:
            result[prefix] = value
        return result

    before, after = leaves(layers['base']), leaves(proposed_base)
    paths = [setting.path for setting in catalog.SETTINGS]
    providers = {item['name']: item for item in settings_store.PROVIDERS}
    result = []
    for path in sorted(before.keys() | after.keys()):
        if not path or any(path[:len(known)] == known for known in paths):
            continue
        existed, exists = path in before, path in after
        if existed == exists and before.get(path) == after.get(path):
            continue
        source = 'Settings file'
        overridden = False
        for name, label in [('here', 'Saved dashboard override'), ('operator', 'Deployment override')]:
            if catalog.lookup(layers[name], path)[0]:
                source, overridden = label, True
        if len(path) == 3 and path[0] == 'providers' and path[2] == 'api_key':
            provider = providers.get(path[1], {})
            if any(os.environ.get(name, '').strip() for name in provider.get('env', ())):
                source, overridden = 'Deployment environment', True
        # Only boolean feature switches are interpreted as enabled/disabled.
        # Other values remain opaque, including lists of credentials or names.
        def state(present, value, section=path[0]):
            if not present:
                return 'Not present in file'
            if section in {'features', 'capabilities'} and isinstance(value, bool):
                return 'Enabled' if value else 'Disabled'
            return 'Present (value withheld)'
        result.append({'label': '.'.join(path), 'source': source,
                       'change': 'Added' if not existed else 'Removed' if not exists else 'Changed',
                       'before': state(existed, before.get(path)), 'after': state(exists, after.get(path)),
                       'overridden': overridden,
                       'impact': 'Dedicated setting: restart may be required; validate this field on its owning page',
                       'unclassified': True})
    return result


@router.post("/api/v1/setup/settings-file/check")
async def check_settings_file(request: Request) -> dict:
    from . import app as app_module
    app_module._require_same_origin(request)
    require_global_permission(request, "admin")
    from fastapi.responses import JSONResponse
    return JSONResponse(await run_in_threadpool(_prepare_file, request, await _file(request)),
                        headers={"Cache-Control": "private, no-store"})


def _install_reviewed(request: Request, raw: bytes, token: str) -> dict:
    import hashlib
    import time

    from maverick.config import config_path, reset_config_cache
    from maverick.config_install import install_config_bytes

    from . import settings_store
    from .system_checks_api import _record

    with settings_store._locked(strict=True):
        if not _check(raw)["valid"]:
            raise HTTPException(422, "The settings file is no longer permitted. Check it again.")
        path, receipt = _read_receipt(request, token)
        if receipt["digest"] != hashlib.sha256(raw).hexdigest():
            raise HTTPException(409, "The file changed after review. Check it again.")
        if receipt["status"] == "confirmed":
            return {"installed": receipt.get("installed", True), "summary": receipt["summary"],
                    "review": token, "audit_pending": receipt.get("audit_pending", False)}
        if receipt["status"] != "reviewed":
            raise HTTPException(409, "This installation needs its result checked before another attempt.")
        if time.time() - receipt["created_at"] > 900 or receipt["revision"] != _file_review_revision(raw):
            raise HTTPException(409, "Settings changed or this review expired. Check the file again.")
        receipt["status"] = "pending"
        _write_receipt(path, receipt)
        try:
            _record(request, "settings_file_install_requested", review=token)
            result = install_config_bytes(raw, backup=True)
            reset_config_cache()
            if config_path().read_bytes() != raw and not result["unchanged"]:
                raise OSError("settings readback did not match")
        except Exception:
            receipt["status"] = "uncertain"
            _write_receipt(path, receipt)
            raise HTTPException(503, "Installation was not confirmed. Check the saved result before trying again.") from None
        summary = ("This settings file is already installed. Nothing changed." if result["unchanged"] else
                   "Installed the reviewed settings file. It applies to the next task; some settings need a restart. "
                   "The previous file was kept as a backup when one existed.")
        receipt.update(status="confirmed", installed=not result["unchanged"], summary=summary,
                       installed_digest=hashlib.sha256(config_path().read_bytes()).hexdigest(), audit_pending=True)
        _write_receipt(path, receipt)
        try:
            _record(request, "settings_file_install_confirmed", review=token,
                    changed=not result["unchanged"])
        except HTTPException:
            pass  # durable receipt exposes pending audit; never misreport a failed write as installed
        else:
            receipt["audit_pending"] = False
            _write_receipt(path, receipt)
        return {"installed": receipt["installed"], "summary": summary, "review": token,
                "audit_pending": receipt["audit_pending"]}


@router.post("/api/v1/setup/settings-file/install")
async def install_settings_file(request: Request, confirm: bool = False, review: str = "") -> dict:
    from . import app as app_module
    app_module._require_same_origin(request)
    require_global_permission(request, "admin")
    if confirm is not True:
        raise HTTPException(409, "Confirm to install the reviewed settings file. Nothing was changed.")
    from fastapi.responses import JSONResponse
    return JSONResponse(await run_in_threadpool(_install_reviewed, request, await _file(request), review),
                        headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/setup/settings-file/result/{review}")
def settings_file_result(request: Request, review: str) -> dict:
    import hashlib

    from maverick.config import config_path

    from . import settings_store

    require_global_permission(request, "admin")
    with settings_store._locked(strict=True):
        _path, receipt = _read_receipt(request, review)
        try:
            matches = hashlib.sha256(config_path().read_bytes()).hexdigest() == receipt.get("installed_digest", receipt["digest"])
        except OSError:
            matches = False
        from fastapi.responses import JSONResponse
        return JSONResponse({"status": receipt["status"], "matches_review": matches,
                "audit_pending": receipt.get("audit_pending", receipt["status"] in {"pending", "uncertain"}),
                "summary": ("The installed file matches your reviewed file." if matches else
                            "The installed file does not match this review. Check the current settings before proceeding.")},
                            headers={"Cache-Control": "private, no-store"})


@router.post("/api/v1/setup/settings-file/reconcile/{review}")
def reconcile_settings_file(request: Request, review: str):
    """Record observed current bytes after a lost acknowledgement; never reinstall."""
    import hashlib

    from fastapi.responses import JSONResponse
    from maverick.config import config_path

    from . import app as app_module
    from . import settings_store
    from .system_checks_api import _record

    app_module._require_same_origin(request)
    require_global_permission(request, "admin")
    with settings_store._locked(strict=True):
        path, receipt = _read_receipt(request, review)
        if receipt['status'] not in {'pending', 'uncertain', 'confirmed'}:
            raise HTTPException(409, "This review has no installation attempt to reconcile.")
        try:
            matches = hashlib.sha256(config_path().read_bytes()).hexdigest() == receipt.get('installed_digest', receipt['digest'])
        except OSError:
            matches = False
        if not matches:
            raise HTTPException(409, "The current file differs from this review. Review current settings; no installation or activity confirmation was made.")
        if receipt.get('audit_pending', True):
            _record(request, 'settings_file_install_reconciled', review=review, observed_match=True)
        receipt.update(status='confirmed', audit_pending=False,
                       summary='The current settings file matches this review. This observation is recorded; the file was not reinstalled.')
        receipt.setdefault('installed', False)
        _write_receipt(path, receipt)
        return JSONResponse({'summary': receipt['summary'], 'audit_pending': False},
                            headers={"Cache-Control": "private, no-store"})
