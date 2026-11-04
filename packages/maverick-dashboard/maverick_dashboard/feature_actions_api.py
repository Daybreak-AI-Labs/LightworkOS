"""Buttons for features that were only reachable from a terminal.

* ``whoami``: "Your account" -- the signed-in person's role, what they may do
  and the limits on the tools their tasks may use (``/account``).
* ``insights-export`` / ``insights-import``: share learned lessons with a
  trusted Lightwork installation, with a preview before anything is added
  (Learning page). Global ``admin``, like every other learning change.
* ``overrides export`` / ``overrides load``: download this workspace's agent
  customizations and load them elsewhere, previewed and re-checked (Roles
  page). Loading uses the same gates as editing roles and specialists.
* ``mcp-registry browse``: a searchable list of tool servers from the
  configured registries, with an Add button (the Tool servers page already
  lets global administrators add servers).

Every route calls the kernel function the terminal command calls. Reads
need ``view`` (or the page's own floor); changes need ``admin`` (global
``admin`` for installation-wide state), are same-origin checked, and are
recorded in the activity record with the person who made them. Uploads are
size-bounded and heavy work runs in a worker thread. The exact kernel wording
is only ever returned as ``technical`` for a collapsed "Technical details".
"""
from __future__ import annotations

import io
import json
import re
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .auth import (
    has_global_permission,
    has_permission,
    require_global_permission,
    require_permission,
)

router = APIRouter()
page_router = APIRouter()

_TEXT = 400


def _same_origin(request: Request) -> None:
    from . import app as app_module
    app_module._require_same_origin(request)


def _actor(request: Request) -> str:
    return auth.caller_principal(request) or "local administrator"


def _record(request: Request, verb: str, *, installation: bool, **detail: Any) -> None:
    """One activity-record row per change, naming who made it."""
    from maverick.audit import AuditRefused, EventKind, audit_event
    try:
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=installation,
                    verb=verb, actor=_actor(request), ok=True, **detail)
    except AuditRefused as exc:
        raise HTTPException(
            503, "The change was made, but it could not be added to the activity record."
        ) from exc


async def _body(request: Request, limit: int) -> bytes:
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > limit:
            raise HTTPException(413, "That file is too large.")
    if not data:
        raise HTTPException(422, "Choose a file first.")
    return bytes(data)


def _technical(lines: list[str]) -> list[dict[str, str]]:
    return [{"text": str(line)[:_TEXT]} for line in lines[:60]]


# ---- Your account (maverick whoami) -----------------------------------------

_RISK_LABELS = {"low": "Low-risk actions only", "medium": "Up to medium-risk actions",
                "high": "Up to high-risk actions"}


def _workspace_name() -> str:
    """The workspace this page works in, by its display name."""
    try:
        from maverick.paths import current_tenant_id
        tenant = current_tenant_id()
    except Exception:  # noqa: BLE001 -- the panel still shows everything else
        return "Unknown"
    if not tenant:
        return "The main workspace"
    try:
        from maverick.tenant.registry import list_tenants
        for record in list_tenants():
            if record.id == tenant:
                return str(getattr(record, "display_name", "") or record.id)
    except Exception:  # noqa: BLE001 -- fall back to its short name
        pass
    return str(tenant)


def _account(request: Request) -> dict[str, Any]:
    from maverick.capability import capability_enforced, capability_from_config

    from .identity_format import humanize_principal, role_label
    principal = auth.caller_principal(request)
    signed_in = principal is not None
    role = auth.caller_role(request) if signed_in else None
    abilities = []
    for permission, label in (("view", "See work and results"), ("operate", "Start and run tasks"),
                              ("audit", "Read the activity record"), ("admin", "Change settings and manage people")):
        abilities.append({"label": label, "allowed": bool(has_permission(request, permission))})
    execution_user = auth.execution_user_id_from_request(request)
    cap = capability_from_config(principal or "user:local",
        channel="dashboard" if execution_user else None, user_id=execution_user)
    policy_unavailable = any("\x00" in name for name in cap.allow_tools)
    tools = "Unavailable: tools denied" if policy_unavailable else "No named allow-list; remaining ceilings still apply" if not cap.allow_tools else f"{len(cap.allow_tools)} names in the allowed set"
    blocked = len(cap.deny_tools)
    suites = auth.caller_suites(request)
    from maverick.enterprise import enterprise_enabled
    from maverick.profile import active_profile

    from . import scim_groups, suite_grants
    from .access_explanations import role as explain_role

    provenance = explain_role(principal)
    department_source = "Configured department default"
    if principal is None or auth.is_dashboard_admin(principal):
        department_source = "Installation authority"
    elif suite_grants.get_grant(principal) is not None:
        department_source = "Explicit account department grant"
    elif scim_groups.suites_for_principal(principal) is not None:
        department_source = "Verified sign-in group mapping"
    from maverick.safety.tool_risk import tool_risk
    examples = []
    for name, label in (("read_file", "Read an allowed file"), ("write_file", "Change an allowed file"), ("shell", "Run a command")):
        permitted = cap.permits(name)
        reason = "Within this base grant; task, resource, consent and provider checks still apply."
        if not has_permission(request, "operate"):
            reason, permitted = "Your current workspace role does not allow starting tool actions.", False
        elif not permitted:
            if cap.is_expired():
                reason = "The effective capability expired."
            elif name in cap.deny_tools:
                reason = "The effective tool policy explicitly blocks this tool."
            elif cap.allow_tools and name not in cap.allow_tools:
                reason = "This tool is outside the effective allowed-tool set."
            else:
                reason = f"This tool's {tool_risk(name)} risk exceeds the effective {cap.max_risk} ceiling."
        examples.append({"name": name, "label": label, "allowed": permitted, "reason": reason})
    profile = active_profile()
    boundary = enterprise_enabled()
    return {
        "signed_in": signed_in,
        "name": humanize_principal(principal).name if signed_in else "You (this computer)",
        "role": (role_label(role) or "No role yet") if signed_in else "Local installation authority (unowned content only)",
        "installation_admin": bool(has_global_permission(request, "admin")),
        "workspace": _workspace_name(),
        "abilities": abilities,
        "departments": sorted(s.replace("_", " ").capitalize() for s in suites) if suites is not None else [],
        "all_departments": suites is None,
        "tools": tools,
        "blocked_tools": blocked,
        "risk": _RISK_LABELS.get(cap.max_risk or "", "No limit"),
        "limits_enforced": bool(capability_enforced()),
        "role_source": provenance["source"],
        "access_owner": provenance["owner"],
        "department_source": department_source,
        "tool_examples": examples,
        "allowed_tool_names": sorted(name for name in cap.allow_tools if "\x00" not in name and cap.permits(name)),
        "allowed_tool_summary": "No tools: policy resolution failed closed." if policy_unavailable else "No named allow-list; remaining ceilings still apply." if not cap.allow_tools else "No listed tool passes the remaining ceilings.",
        "blocked_tool_names": sorted(cap.deny_tools),
        "tool_policy_source": "Effective dashboard-channel and current-user root grant: installation/workspace ACL, runtime blocks, assigned capability role and regulatory ceilings. Individual tasks may narrow it further.",
        "profile": profile,
        "enterprise_boundary": boundary,
        "profile_overridden": profile == "enterprise" and not boundary,
        "privacy_scope": "Employee tasks, chats and companion conversations are private to their owner. Administrators manage policy and audit metadata. Specific task reads or subject exports require an independent, expiring content-access approval; shared result packets retain their explicit reviewer access.",
        "can": {name: bool(has_permission(request, name)) for name in ("view", "operate", "audit", "admin")}
        | {"installation_admin": bool(has_global_permission(request, "admin"))},
    }


@router.get("/api/v1/account/me")
async def account(request: Request) -> dict:
    require_permission(request, "view")
    return await run_in_threadpool(_account, request)


@page_router.get("/account", response_class=HTMLResponse)
def account_page(request: Request) -> HTMLResponse:
    require_permission(request, "view")
    from .app import templates
    from .local_owner_mfa_routes import owner_link_visible
    return templates.TemplateResponse(request, "account.html",
                                      {"owner_authenticator": owner_link_visible(request)},
                                      headers={"Cache-Control": "private, no-store"})


# ---- Share lessons with a trusted installation (insights-export/import) -----

_INSIGHT_LIMIT = 256 * 1024


def _plain_insight_problem(reason: str) -> str:
    text = reason.lower()
    if "learning halted" in text:
        return "Learning is paused. No lessons were added. Ask an administrator to resume it, then try again."
    if "replay claim could not be released" in text:
        return "No lessons were added, and this file cannot be retried. Ask for a new lesson file."
    if "learning audit" in text:
        return "Lightwork could not record the required activity entry. No lessons were added. Try again after activity recording is restored."
    if "bundle replay rejected" in text:
        return "This lesson file has already been used. Ask for a new file to share more lessons."
    if "sanitization unavailable" in text:
        return "The safety check is unavailable. No lessons were added. Try again when it is restored."
    if "no insight change was published" in text:
        return "This file contained no new lesson to add."
    if "untrusted" in text or "trust anchor" in text or "trusted_insight_pubkeys" in text:
        return ("This file comes from an installation you have not chosen to trust yet. "
                "Whoever installed Lightwork can add it to the trusted list.")
    if "stale" in text:
        return "This file is more than a week old. Ask for a new one."
    if "future" in text:
        return "This file's date is in the future. Check the clocks on both computers and ask for a new one."
    if "signature" in text or "cryptograph" in text:
        return "This file could not be confirmed as genuine, so it was not used."
    if "limit" in text or "exceeds" in text:
        return "This file holds too many lessons."
    return "This file is not a lesson file Lightwork can use."


def _insight_status() -> dict[str, Any]:
    from maverick.insight_exchange import trusted_pubkeys
    try:
        trusted = len(trusted_pubkeys())
    except RuntimeError:
        trusted = 0
    return {"trusted_installations": trusted}


@router.get("/api/v1/learning-exchange")
async def learning_exchange_status(request: Request) -> dict:
    require_global_permission(request, "admin")
    return await run_in_threadpool(_insight_status)


class InsightExportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    how_many: Literal[10, 25, 50, 100] = 50


@router.post("/api/v1/learning-exchange/export")
async def learning_exchange_export(body: InsightExportIn, request: Request) -> Response:
    _same_origin(request)
    require_global_permission(request, "admin")
    from maverick.insight_exchange import export_insights

    def _do() -> bytes:
        with tempfile.TemporaryDirectory(prefix="lw-insights-") as folder:
            path = export_insights(Path(folder) / "lessons.json", max_insights=body.how_many)
            return path.read_bytes()
    try:
        data = await run_in_threadpool(_do)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(409, "Lessons could not be packaged on this installation. "
                                 "Share the technical details with whoever installed Lightwork.") from exc
    count = len(json.loads(data).get("insights") or [])
    await run_in_threadpool(lambda: _record(request, "insights_export", installation=True, lessons=count))
    return Response(data, media_type="application/json", headers={
        "Content-Disposition": 'attachment; filename="Lightwork-lessons.json"',
        "Cache-Control": "private, no-store", "X-Lightwork-Lessons": str(count)})


def _insight_preview(raw: bytes) -> dict[str, Any]:
    from maverick import insight_exchange as ix
    with tempfile.TemporaryDirectory(prefix="lw-insights-") as folder:
        path = Path(folder) / "lessons.json"
        path.write_bytes(raw)
        try:
            bundle = ix._read_bundle(path)
            anchors = ix.trusted_pubkeys()
            peer, sig, ts, rows = ix._validate_envelope(bundle, anchors, now=time.time())
            ix._verify_bundle(peer, sig, ts, rows)
        except Exception as exc:  # noqa: BLE001 -- every refusal is shown plainly
            return {"usable": False, "summary": _plain_insight_problem(str(exc)),
                    "lessons": [], "count": 0, "technical": _technical([str(exc)])}
    sample = [str(r.get("text") or "")[:_TEXT] for r in rows if isinstance(r, dict)][:10]
    return {"usable": True, "count": len(rows), "lessons": sample, "sent": ts,
            "summary": f"This file holds {len(rows)} lesson{'s' if len(rows) != 1 else ''} from a trusted "
                       "installation. Each one is checked again for private or harmful text when you add it.",
            "technical": []}


@router.post("/api/v1/learning-exchange/preview")
async def learning_exchange_preview(request: Request) -> dict:
    _same_origin(request)
    require_global_permission(request, "admin")
    raw = await _body(request, _INSIGHT_LIMIT)
    return await run_in_threadpool(_insight_preview, raw)


@router.post("/api/v1/learning-exchange/import")
async def learning_exchange_import(request: Request) -> dict:
    _same_origin(request)
    require_global_permission(request, "admin")
    raw = await _body(request, _INSIGHT_LIMIT)
    from maverick.insight_exchange import import_insights
    from maverick.orchestrator import _build_shield
    principal = auth.caller_principal(request)

    def _do() -> tuple[int, str]:
        with tempfile.TemporaryDirectory(prefix="lw-insights-") as folder:
            path = Path(folder) / "lessons.json"
            path.write_bytes(raw)
            return import_insights(
                path, shield=_build_shield(),
                operator_ref=principal or "local administrator",
                operator_basis="dashboard_session" if principal else "local_mode",
            )
    imported, reason = await run_in_threadpool(_do)
    if reason == "import published but completion audit is unavailable":
        return JSONResponse(status_code=202, content={
            "added": int(imported), "audit_complete": False,
            "message": ("The lessons were added, but their final activity entry could not be recorded. "
                        "Do not add this file again. Ask an administrator to review the activity record."),
        })
    if reason == "insight write outcome is uncertain; replay claim retained":
        return JSONResponse(status_code=202, content={
            "added": 0, "outcome": "unconfirmed",
            "message": ("Lightwork could not confirm whether these lessons were saved. "
                        "Do not add this file again. Check the Learning page and activity record first."),
        })
    if reason != "ok":
        operational = any(token in reason for token in ("learning halted", "learning audit", "sanitization unavailable"))
        raise HTTPException(503 if operational else 409, _plain_insight_problem(reason))
    # The shared importer recorded the caller identity basis and both learning phases
    # before this endpoint can report a clean success.
    return {"added": int(imported), "audit_complete": True}


# ---- Move customizations (overrides export / load) --------------------------

_BUNDLE_LIMIT = 2 * 1024 * 1024
_BUNDLE_FILE_LIMIT = 256 * 1024
_BUNDLE_FILES = 200
_PACK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.toml\Z")


def _require_customizing(request: Request) -> None:
    from .editor_policy import require_pack_editing as _require_pack_editing
    from .editor_policy import require_role_editing as _require_role_editing
    require_permission(request, "admin")
    _require_role_editing(request)
    _require_pack_editing(request)


def _zip_folder(folder: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(folder.rglob("*.toml")):
            archive.write(path, path.relative_to(folder).as_posix())
    return buffer.getvalue()


def _customizations_export() -> tuple[bytes, dict]:
    from maverick.overrides_bundle import export_overrides
    with tempfile.TemporaryDirectory(prefix="lw-overrides-") as folder:
        counts = export_overrides(folder)
        return _zip_folder(Path(folder)), counts


@router.get("/api/v1/customizations/export")
async def customizations_export(request: Request) -> Response:
    # A full copy of every department's customizations crosses department
    # scoping, so it needs the workspace's admin permission.
    require_permission(request, "admin")
    data, counts = await run_in_threadpool(_customizations_export)
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": 'attachment; filename="Lightwork-customizations.zip"',
        "Cache-Control": "private, no-store",
        "X-Lightwork-Specialists": str(counts.get("domains", 0)),
        "X-Lightwork-Roles": str(counts.get("roles", 0))})


def _unpack(raw: bytes, folder: Path) -> list[str]:
    """Unpack only ``domains/<name>.toml`` and ``roles.toml`` (optionally
    under one top folder). Anything else is named as ignored."""
    ignored: list[str] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise HTTPException(422, "Choose a customizations file downloaded from Lightwork.") from exc
    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) > _BUNDLE_FILES:
            raise HTTPException(413, "That file holds too many items.")
        parts_list = [[p for p in m.filename.replace("\\", "/").split("/") if p] for m in members]
        tops = {parts[0] for parts in parts_list if len(parts) > 1 and parts[0] != "domains"}
        strip = len(tops) == 1 and all(len(p) > 1 and p[0] in tops for p in parts_list)
        for member, parts in zip(members, parts_list, strict=True):
            if strip:
                parts = parts[1:]
            name = "/".join(parts)
            if member.file_size > _BUNDLE_FILE_LIMIT:
                ignored.append(name)
                continue
            if parts == ["roles.toml"]:
                target = folder / "roles.toml"
            elif len(parts) == 2 and parts[0] == "domains" and _PACK_NAME.fullmatch(parts[1]):
                target = folder / "domains" / parts[1]
            else:
                ignored.append(name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member)[:_BUNDLE_FILE_LIMIT])
    return ignored


def _customizations_preview(raw: bytes) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:  # 3.10
        import tomli as tomllib
    from maverick.domain import lint_profile, load_domain
    from maverick.role_edit import validate_role
    items: list[dict[str, Any]] = []
    technical: list[str] = []
    with tempfile.TemporaryDirectory(prefix="lw-overrides-") as folder:
        root = Path(folder)
        ignored = _unpack(raw, root)
        for path in sorted((root / "domains").glob("*.toml")):
            label = path.stem.replace("_", " ").replace("-", " ").capitalize()
            try:
                errors, _ = lint_profile(load_domain(path))
            except Exception as exc:  # noqa: BLE001 -- a bad file is a finding
                errors = [str(exc)]
            items.append({"kind": "Agent or specialist", "name": label, "ok": not errors})
            technical += [f"domains/{path.name}: {e}" for e in errors[:3]]
        roles_file = root / "roles.toml"
        if roles_file.is_file():
            try:
                tables = tomllib.loads(roles_file.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                tables = {}
                items.append({"kind": "Role", "name": "Roles file", "ok": False})
                technical.append(f"roles.toml: {exc}")
            for role, table in tables.items():
                patch = {k: str((table or {}).get(k) or "") for k in ("system_addendum", "model", "effort")}
                errors = validate_role(role, patch)
                items.append({"kind": "Role", "name": str(role).replace("_", " ").capitalize(), "ok": not errors})
                technical += [f"roles.toml[{role}]: {e}" for e in errors[:3]]
    usable = sum(1 for i in items if i["ok"])
    skipped = len(items) - usable
    if not items:
        summary = "This file has no customizations Lightwork can use."
    else:
        summary = (f"{usable} customization{'s' if usable != 1 else ''} can be loaded"
                   + (f"; {skipped} will be skipped because they did not pass the safety checks." if skipped else "."))
    technical += [f"ignored: {name}" for name in ignored[:20]]
    return {"items": items[:_BUNDLE_FILES], "usable": usable, "skipped": skipped, "summary": summary,
            "technical": _technical(technical)}


@router.post("/api/v1/customizations/preview")
async def customizations_preview(request: Request) -> dict:
    _same_origin(request)
    _require_customizing(request)
    raw = await _body(request, _BUNDLE_LIMIT)
    return await run_in_threadpool(_customizations_preview, raw)


@router.post("/api/v1/customizations/load")
async def customizations_load(request: Request) -> dict:
    _same_origin(request)
    _require_customizing(request)
    raw = await _body(request, _BUNDLE_LIMIT)
    from maverick.overrides_bundle import load_overrides

    def _do() -> dict:
        with tempfile.TemporaryDirectory(prefix="lw-overrides-") as folder:
            _unpack(raw, Path(folder))
            return load_overrides(folder)
    result = await run_in_threadpool(_do)
    await run_in_threadpool(lambda: _record(
        request, "overrides_load", installation=False, specialists=int(result.get("domains") or 0),
        roles=int(result.get("roles") or 0), skipped=len(result.get("skipped") or [])))
    return {"specialists": int(result.get("domains") or 0), "roles": int(result.get("roles") or 0),
            "skipped": len(result.get("skipped") or []),
            "technical": _technical([str(s) for s in result.get("skipped") or []])}


# ---- Tool server registry (mcp-registry browse / add) -----------------------

def _registry() -> dict[str, Any]:
    from maverick.mcp_registry import _configured_mcp_registries, load_mcp_registry
    if not _configured_mcp_registries():
        return {"configured": False, "servers": []}
    servers = []
    for entry in load_mcp_registry()[:500]:
        spec = entry.spec or {}
        servers.append({
            "name": str(entry.name)[:80],
            "summary": str(entry.summary or "")[:_TEXT],
            "verified": bool(entry.verified),
            "online": bool(spec.get("url")),
        })
    return {"configured": True, "servers": servers}


@router.get("/api/v1/mcp-registry")
async def mcp_registry(request: Request) -> dict:
    require_global_permission(request, "admin")
    return await run_in_threadpool(_registry)


class RegistryAddIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    # The details the person looked at (Tool servers page preview): when
    # given, a server whose details changed since is refused, not added.
    fingerprint: str | None = Field(default=None, min_length=64, max_length=64)


@router.post("/api/v1/mcp-registry/add")
async def mcp_registry_add(body: RegistryAddIn, request: Request) -> dict:
    _same_origin(request)
    require_global_permission(request, "admin")
    from maverick.mcp_registry import install_mcp_from_registry
    from maverick.runtime_overrides import add_mcp_server

    def _do() -> str:
        spec = install_mcp_from_registry(body.name)
        if body.fingerprint is not None:
            from .connector_ops_api import spec_fingerprint
            if spec_fingerprint(spec.to_dict()) != body.fingerprint:
                raise HTTPException(409, "This tool server's details changed since you looked. "
                                         "Look again before adding it.")
        add_mcp_server(spec.name, spec.to_dict())
        return spec.name
    try:
        name = await run_in_threadpool(_do)
    except ValueError as exc:
        raise HTTPException(409, "Registry server installation is unavailable until publisher "
                                 "authentication is implemented. Independently review and configure the server.") from exc
    await run_in_threadpool(lambda: _record(request, "mcp_registry_add", installation=True, server=name))
    return {"added": name}
