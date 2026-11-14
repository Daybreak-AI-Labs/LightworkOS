"""Buttons behind the /compliance page.

The control-coverage report (``maverick.compliance``) says what is on and what
needs action. This router turns each "what to do" into something a person can
press instead of a config key or a terminal command:

* switch on a protection (signed activity record, AI notice, anonymous logs,
  encryption, strict mode) -- global administrators only, strengthen-only;
* set how long data is kept and apply those rules now;
* find a person's conversations, download everything held about them, or
  erase it (the same kernel paths ``maverick export-user`` / ``erase`` use);
* download the SOC 2 snapshot, AI bill of materials, OSCAL results and the
  Statement of Applicability, run the EU AI Act self-check and search the
  control library.

Every mutation is permission-gated and keeps the kernel's own checks: erasure
still runs the audited, receipt-backed erase command and is verified after.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import threading
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from .auth import require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance-controls"])

_PERSON_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
_CHANNEL_TEXT = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_ASSESSMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
# click echoes to the process streams; erasure output names the person, so it
# is captured instead of reaching the server log. One erasure at a time.
_ERASE_LOCK = threading.Lock()

#: Plain wording per status (the stored values stay the kernel's).
STATUS_TEXT = {
    "active": "On",
    "available": "Available when needed",
    "action_needed": "Needs action",
}

#: The protections a global administrator may switch on from the page.
SWITCHES: dict[str, dict[str, Any]] = {
    "signed_audit": {
        "label": "Turn on signed activity record",
        "confirm": (
            "Sign every entry in the activity record so any later change can be "
            "detected? New entries are signed from the next restart."
        ),
    },
    "ai_disclosure": {
        "label": "Turn on the AI notice",
        "confirm": (
            "Tell people at the start of every chat that they are talking to an "
            "AI assistant?"
        ),
    },
    "anonymous_logs": {
        "label": "Hide personal details in logs",
        "confirm": (
            "Replace email addresses, phone numbers and other personal details "
            "in the activity record with protected codes from now on?"
        ),
    },
    "encryption": {
        "label": "Turn on encryption",
        "confirm": (
            "Encrypt stored conversations, tasks and memory from now on? Data "
            "saved before today stays as it is until it is re-saved."
        ),
    },
    "strict_mode": {
        "label": "Turn on strict mode",
        "confirm": (
            "Turn on strict mode? Risky actions will wait for a person to "
            "approve them, and AI requests will only go to AI models you run "
            "yourself. Work that relies on outside AI services will stop."
        ),
    },
}

#: Plain explanation and the button each control gets. ``action`` kinds:
#: switch (turn a protection on), retention, people, halt, link.
CONTROL_GUIDE: dict[str, dict[str, Any]] = {
    "AI transparency disclosure": {
        "about": "People are told they are talking to an AI at the start of each chat.",
        "action": {"kind": "switch", "key": "ai_disclosure"},
    },
    "Audit logging (record-keeping)": {
        "about": "Lightwork keeps a permanent record of everything it does.",
        "action": {"kind": "link", "href": "/audit", "label": "Open the activity record"},
    },
    "Tamper-evident audit": {
        "about": "Each entry in the activity record is signed, so any later change is detectable.",
        "action": {"kind": "switch", "key": "signed_audit"},
    },
    "Human oversight (consent gating)": {
        "about": "Risky actions wait for a person to approve them before they run.",
        "action": {"kind": "switch", "key": "strict_mode"},
    },
    "Kill switch": {
        "about": "You can stop all running work at once.",
        "action": {"kind": "halt", "label": "Stop all work now"},
    },
    "Data-subject access & portability": {
        "about": "You can give a person a copy of everything Lightwork holds about them.",
        "action": {"kind": "people", "label": "Export a person's data"},
    },
    "Right to erasure": {
        "about": "You can permanently delete everything Lightwork holds about a person.",
        "action": {"kind": "people", "label": "Erase a person's data"},
    },
    "Storage limitation (retention)": {
        "about": "Old records are deleted automatically after the period you choose.",
        "action": {"kind": "retention", "label": "Choose how long data is kept"},
    },
    "Data-egress control": {
        "about": "Your data only goes to AI models you run yourself.",
        "action": {"kind": "switch", "key": "strict_mode"},
    },
    "Secret redaction in logs": {
        "about": "Passwords and keys are always removed from the activity record.",
        "action": None,
    },
    "PII redaction in logs": {
        "about": "Email addresses, phone numbers and similar details are hidden in the activity record.",
        "action": {"kind": "switch", "key": "anonymous_logs"},
    },
    "Encryption at rest": {
        "about": "Stored conversations, tasks and memory are encrypted.",
        "action": {"kind": "switch", "key": "encryption"},
    },
    "Log data minimization (anonymous mode)": {
        "about": "People's identifiers are replaced with protected codes in the activity record.",
        "action": {"kind": "switch", "key": "anonymous_logs"},
    },
    "Governance, accountability & records": {
        "about": "Signed records, approvals and a stop button show who did what and when.",
        "action": {"kind": "link", "href": "/audit", "label": "Open the activity record"},
    },
    "Measurement & monitoring": {
        "about": "Quality checks, spending limits and monitoring are available.",
        "action": None,
    },
    "Consumer notice of AI": {
        "about": "People are told they are talking to an AI at the start of each chat.",
        "action": {"kind": "switch", "key": "ai_disclosure"},
    },
    "Human review of consequential decisions": {
        "about": "A person reviews important decisions before they take effect.",
        "action": {"kind": "switch", "key": "strict_mode"},
    },
    "Automated employment-decision audit trail": {
        "about": (
            "Signed decision records support the yearly independent bias audit, "
            "which your organization arranges itself."
        ),
        "action": {"kind": "link", "href": "/audit", "label": "Open the activity record"},
    },
    "Consumer access & deletion": {
        "about": "You can give a person a copy of their data or delete it.",
        "action": {"kind": "people", "label": "Export or erase a person's data"},
    },
}


def guide_for(check: Any) -> dict[str, Any]:
    """The plain explanation and button for one ``ControlCheck``."""
    entry = CONTROL_GUIDE.get(getattr(check, "control", ""), {})
    action = entry.get("action")
    status = getattr(check, "status", "")
    if action and action.get("kind") == "switch":
        if status == "active":
            action = None
        else:
            action = {**action, **SWITCHES[action["key"]]}
    return {
        "about": entry.get("about", ""),
        "status_text": STATUS_TEXT.get(status, "Unknown"),
        "action": action,
    }


def _settings_for(key: str) -> dict[tuple[str, str], object]:
    if key == "signed_audit":
        return {("audit", "sign"): True}
    if key == "anonymous_logs":
        return {("privacy", "anonymous"): True}
    if key == "encryption":
        return {("encryption", "at_rest"): True}
    if key == "strict_mode":
        return {("enterprise", "mode"): True}
    if key == "ai_disclosure":
        from maverick.compliance import DEFAULT_DISCLOSURE

        return {("compliance", "disclosure_text"): DEFAULT_DISCLOSURE}
    raise HTTPException(status_code=404, detail="That protection is not available here.")


#: Protections that put the deployment into a regulated posture, which makes
#: the dashboard require sign-in. Turning one on without sign-in configured
#: would lock everyone out, so it is refused until sign-in is set up.
_NEEDS_SIGN_IN = frozenset({"strict_mode"})
SIGN_IN_FIRST = (
    "Set up sign-in for Lightwork first. Once this is on, everyone must sign in, "
    "so without sign-in nobody could open the dashboard."
)


def sign_in_configured() -> bool:
    """Whether the dashboard has a sign-in mechanism (token, OIDC, SSO...)."""
    from . import auth
    from ._shared import dashboard_token

    return bool(dashboard_token()) or not auth.auth_genuinely_off()


def _status_by_control() -> dict[str, str]:
    from maverick.compliance import compliance_report

    return {c.control: c.status for c in compliance_report()}


_SWITCH_CONTROLS = {
    "signed_audit": "Tamper-evident audit",
    "ai_disclosure": "AI transparency disclosure",
    "anonymous_logs": "PII redaction in logs",
    "encryption": "Encryption at rest",
    "strict_mode": "Data-egress control",
}


def _audit_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    return "set"  # text (the disclosure wording) is recorded as changed, not copied


async def _save_recorded(request: Request, updates: dict[tuple[str, str], object]) -> None:
    """Save compliance settings and record who changed what.

    If the activity record refuses the change, the previous values are put
    back so nothing changes without a record of it."""
    from maverick.audit import AuditRefused, EventKind, audit_event

    from . import settings_store
    from .auth import caller_principal

    def previous_values() -> dict[tuple[str, str], object]:
        overlay = settings_store.load_overlay()
        out: dict[tuple[str, str], object] = {}
        for section, key in updates:
            table = overlay.get(section)
            out[(section, key)] = (table.get(key, settings_store.REMOVE)
                                   if isinstance(table, dict) else settings_store.REMOVE)
        return out

    try:
        previous = await run_in_threadpool(previous_values)
        await run_in_threadpool(settings_store.set_compliance_settings, updates)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="That setting could not be saved.") from exc
    except settings_store.SecuritySuiteConfigUnavailable as exc:
        raise HTTPException(status_code=503, detail="Settings could not be read.") from exc
    actor = caller_principal(request) or "local administrator"

    def record() -> None:
        for (section, key), value in updates.items():
            old = previous[(section, key)]
            audit_event(EventKind.SETTING_CHANGED, agent="dashboard", _global=True, actor=actor,
                        section=section, key=key,
                        old=None if old is settings_store.REMOVE else _audit_value(old),
                        new=_audit_value(value), source="compliance")

    try:
        await run_in_threadpool(record)
    except AuditRefused as exc:
        try:
            await run_in_threadpool(settings_store.set_catalog_values, previous)
        except Exception as rollback_exc:
            raise HTTPException(
                status_code=500,
                detail="The change could not be recorded and could not be undone.",
            ) from rollback_exc
        raise HTTPException(
            status_code=503, detail="The change could not be recorded, so it was undone."
        ) from exc


@router.post("/switches/{key}")
async def turn_on_protection(request: Request, key: str) -> dict:
    """Switch one protection on (deployment-wide, global admin only)."""
    require_global_permission(request, "admin")
    if key not in SWITCHES:
        raise HTTPException(status_code=404, detail="That protection is not available here.")
    if key in _NEEDS_SIGN_IN and not sign_in_configured():
        raise HTTPException(status_code=409, detail=SIGN_IN_FIRST)
    await _save_recorded(request, _settings_for(key))
    try:
        now_on = (await run_in_threadpool(_status_by_control)).get(_SWITCH_CONTROLS[key]) == "active"
    except Exception:  # pragma: no cover - the save itself succeeded
        now_on = False
    return {
        "saved": True,
        "active": now_on,
        "message": (
            "Turned on."
            if now_on
            else (
                "Saved. It takes effect after Lightwork restarts. If it still shows "
                "as needing action after that, it is being overridden by how "
                "Lightwork was installed; ask the person who installed it."
            )
        ),
    }


# ---- Retention -----------------------------------------------------------

RETENTION_FIELDS: tuple[tuple[str, str], ...] = (
    ("audit_days", "Activity record"),
    ("episodes_days", "Task history"),
    ("events_days", "Task activity details"),
    ("messages_days", "Chat messages"),
    ("usage_days", "Spending records"),
)
RETENTION_CHOICES: tuple[int, ...] = (30, 90, 180, 365, 730, 1095, 2555)


class RetentionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The activity record is kept at least a month: a shorter period would let
    # one save and one apply erase the record of who changed it.
    audit_days: int | None = Field(default=None, ge=30, le=3650)
    episodes_days: int | None = Field(default=None, ge=1, le=3650)
    events_days: int | None = Field(default=None, ge=1, le=3650)
    messages_days: int | None = Field(default=None, ge=1, le=3650)
    usage_days: int | None = Field(default=None, ge=1, le=3650)


def _current_retention() -> dict[str, int | None]:
    from maverick.config import load_global_config

    section = (load_global_config() or {}).get("retention") or {}
    out: dict[str, int | None] = {}
    for key, _label in RETENTION_FIELDS:
        value = section.get(key) if isinstance(section, dict) else None
        out[key] = value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
    return out


@router.get("/retention")
async def retention_settings(request: Request) -> dict:
    require_permission(request, "view")
    current = await run_in_threadpool(_current_retention)
    return {
        "fields": [
            {"key": key, "label": label, "days": current.get(key)}
            for key, label in RETENTION_FIELDS
        ],
        "choices": list(RETENTION_CHOICES),
    }


@router.post("/retention")
async def save_retention(request: Request, body: RetentionIn) -> dict:
    require_global_permission(request, "admin")
    from .retention_maintenance import authorize

    authorize(request, request.headers.get("X-Lightwork-Retention-Context"))
    updates = {
        ("retention", key): 0 if value is None else value
        for key, value in body.model_dump(exclude_unset=True).items()
    }
    if not updates:
        raise HTTPException(status_code=422, detail="Choose at least one period.")
    await _save_recorded(request, updates)
    effective = await run_in_threadpool(_current_retention)
    if any(effective[key] != (value or None) for (_, key), value in updates.items()):
        raise HTTPException(409, {
            "message": "The saved preference is overridden by installation policy. Effective periods have not changed; ask your installation administrator.",
            "effective": effective,
        })
    return {"saved": True, "effective": effective, "message": "Retention periods saved. Keep until I choose disables automatic pruning for that record type."}


def _summarize_retention(report: dict) -> dict:
    if report.get("status") == "disabled":
        return {"applied": False, "removed": 0, "message": "No retention periods are set yet. Choose them first."}
    removed = 0
    unresolved = []

    def walk(value: Any) -> None:
        nonlocal removed
        if isinstance(value, dict):
            for k, v in value.items():
                if (k in {"error", "failed", "skipped", "unknown"} and v) or (k == "status" and v in {"partial", "unknown", "failed", "running"}):
                    unresolved.append(k)
                counted = str(k).startswith(("deleted", "removed"))
                if counted and isinstance(v, int) and not isinstance(v, bool):
                    removed += v
                elif counted and isinstance(v, list):
                    removed += len(v)
                elif k != "marker":
                    walk(v)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(report)
    return {
        "applied": not unresolved,
        "removed": removed,
        "unresolved": bool(unresolved),
        "message": (
            f"Retention needs attention. {removed} removals are confirmed; some records were skipped or have an unknown outcome. Review the per-store receipt before retrying."
            if unresolved else f"Retention applied. {removed} old record(s) were removed."
            if removed
            else "Retention applied. Nothing was old enough to remove."
        ),
    }


class RetentionApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    confirm_no_holds: bool = False
    retry: bool = False
    context: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    operation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


def _retention_response(value):
    from fastapi.responses import JSONResponse

    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.post("/retention/preview")
async def preview_retention(request: Request) -> dict:
    require_global_permission(request, "admin")
    from . import retention_maintenance

    operation = request.headers.get("X-Lightwork-Retention-Operation")
    if operation is not None and not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "The preview reference is invalid. Reopen retention.")
    value = await run_in_threadpool(retention_maintenance.preview, request,
                                   request.headers.get("X-Lightwork-Retention-Context"), operation_id=operation)
    return _retention_response(value)


@router.get("/retention/reviews")
async def retention_reviews(request: Request):
    from . import retention_maintenance

    return _retention_response(await run_in_threadpool(retention_maintenance.history, request))


@router.get("/retention/runs/{run_id}")
async def retention_receipt(request: Request, run_id: str) -> dict:
    require_global_permission(request, "admin")
    from . import retention_maintenance

    return _retention_response(await run_in_threadpool(retention_maintenance.read, request, run_id))


@router.post("/retention/apply")
async def apply_retention(request: Request, body: RetentionApplyIn) -> dict:
    """Apply a reviewed, frozen cutoff in its actual workspace scope."""
    require_global_permission(request, "admin")
    from maverick.audit import AuditRefused

    from . import retention_maintenance

    if body.retry:
        raise HTTPException(409, "Read the original result. A new deletion needs a fresh preview and separate confirmation.")
    try:
        receipt = await run_in_threadpool(
            retention_maintenance.apply, request, body.review_id,
            confirm_holds=body.confirm_no_holds, expected_context=body.context,
            expected_revision=body.expected_revision, operation_id=body.operation_id,
        )
    except AuditRefused as exc:
        raise HTTPException(503, "The deletion approval could not be recorded; no new store was started.") from exc
    return _retention_response({"applied": receipt["status"] == "completed", "removed": receipt["removed"],
                               "unresolved": receipt["unresolved"], "message": receipt["message"], "receipt": receipt})


# ---- People: export / erase ---------------------------------------------


def _world_for_request() -> Any:
    from ._shared import _world

    return _world()


def _channel_label(channel: str) -> str:
    known = {
        "cli": "This computer", "dashboard": "Dashboard", "slack": "Slack",
        "teams": "Microsoft Teams", "telegram": "Telegram", "sms": "Text message",
        "whatsapp": "WhatsApp", "email": "Email", "discord": "Discord",
        "matrix": "Matrix", "signal": "Signal", "webchat": "Website chat",
    }
    return known.get(channel, channel.replace("_", " ").replace("-", " ").capitalize())


def _list_people(limit: int = 500) -> list[dict]:
    world = _world_for_request()
    seen: dict[tuple[str, str], dict] = {}
    for conv in world.list_conversations():
        channel = str(getattr(conv, "channel", "") or "")
        user = str(getattr(conv, "user_id", "") or "")
        if not channel or not user:
            continue
        if channel == "cli" and user.startswith("local:"):
            user = "local"
        key = (channel, user)
        row = seen.get(key)
        last = getattr(conv, "last_seen", None) or 0
        if row is None:
            seen[key] = {
                "channel": channel,
                "user": user,
                "channel_label": _channel_label(channel),
                "person": "You (this computer)" if (channel, user) == ("cli", "local") else user,
                "conversations": 1,
                "last_seen": last,
            }
        else:
            row["conversations"] += 1
            row["last_seen"] = max(row["last_seen"] or 0, last)
    rows = sorted(seen.values(), key=lambda r: -(r["last_seen"] or 0))
    return rows[:limit]


@router.get("/people")
async def list_people(request: Request) -> dict:
    """People Lightwork has talked with in this workspace (for the picker)."""
    require_permission(request, "admin")
    try:
        people = await run_in_threadpool(_list_people)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="People could not be listed.") from exc
    return {"people": people}


class PersonIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = Field(min_length=1, max_length=64)
    user: str = Field(min_length=1, max_length=256)


def _validated(person: PersonIn) -> tuple[str, str]:
    if not _CHANNEL_TEXT.fullmatch(person.channel) or not _PERSON_TEXT.fullmatch(person.user):
        raise HTTPException(status_code=422, detail="Choose a person from the list.")
    return person.channel, person.user


@router.post("/people/export")
async def export_person(request: Request, person: PersonIn) -> Response:
    """Download everything held about one person (right of access)."""
    require_permission(request, "admin")
    channel, user = _validated(person)
    from .content_access import require_employee_content
    resource_id = json.dumps([channel, user], separators=(",", ":"))
    require_employee_content(request, "channel:" + resource_id,
                             resource_kind="subject_data", resource_id=resource_id)
    from maverick.audit import AuditRefused, audit_event
    from maverick.dsar import export_subject_data

    from .auth import caller_principal

    # Who downloaded a person's data, and when; never whose data it was.
    try:
        await run_in_threadpool(
            lambda: audit_event("person_data_exported", agent="dashboard",
                                actor=caller_principal(request) or "local administrator",
                                channel=channel, source="dashboard"))
    except AuditRefused as exc:
        raise HTTPException(
            status_code=503, detail="This download could not be recorded, so it was not created."
        ) from exc
    world = _world_for_request()
    try:
        bundle = await run_in_threadpool(
            export_subject_data, user, channel=channel, world=world
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Choose a person from the list.") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="The export could not be created.") from exc
    body = json.dumps(bundle, indent=2, default=str)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="lightwork-person-data.json"',
            "Cache-Control": "no-store",
        },
    )


_CLOSURE_STEP_LABELS = {
    "user_notes": "saved notes about the person",
    "llm_cache": "stored AI replies",
    "audit_scrub": "earlier activity records",
    "audit_reanchor": "the activity record's tamper seal",
    "audit_record": "the note that this erasure happened",
    "knowledge": "stored knowledge about the person",
    "residual data": "the check that nothing remains",
    "verification": "the check that nothing remains",
    "could not verify": "the check that nothing remains",
}


def _unfinished_steps(failures: list) -> list[str]:
    labels = []
    for failure in failures:
        step = str(failure).split(":", 1)[0]
        label = _CLOSURE_STEP_LABELS.get(step, "stored files")
        if label not in labels:
            labels.append(label)
    return labels


def _run_subject_residue_erase(world, channel: str, user: str, actor: str) -> dict:
    """Erase what is stored about a person who has no conversation left."""
    import click
    from maverick.audit import AuditRefused, EventKind, audit_event
    from maverick.cli import erase as erase_command

    obj = {"db": getattr(world, "path", None)}
    refused = False
    with _ERASE_LOCK, contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        ctx = click.Context(erase_command, obj=obj)
        try:
            with ctx:
                ctx.invoke(erase_command, channel=channel, user=user, yes=True)
        except AuditRefused:
            refused = True  # raised only after the scrub
        except (SystemExit, click.exceptions.Exit, click.ClickException) as exc:
            if obj.get("erase_refusal"):  # a legal hold: nothing was deleted
                return {"erased": False, "conversations": 0, "clean": False,
                        "message": obj["erase_refusal"]}
            if "erase_residue" not in obj:
                raise RuntimeError("erasure command stopped") from exc
    residue = obj.get("erase_residue")
    if residue is None:
        raise RuntimeError("erasure command did not report its outcome")
    removed = int(residue.get("removed") or 0)
    unfinished = _unfinished_steps(residue.get("failures") or [])
    if refused and "the note that this erasure happened" not in unfinished:
        unfinished.append("the note that this erasure happened")
    if not removed and not unfinished:
        return {"erased": False, "conversations": 0, "clean": False,
                "message": "Nothing was found for this person."}
    if removed:
        try:  # who erased, never whose data
            audit_event(EventKind.ERASE, agent="operator", actor=actor, channel=channel,
                        conversations=0, source="dashboard")
        except AuditRefused:
            if "the note that this erasure happened" not in unfinished:
                unfinished.append("the note that this erasure happened")
    if unfinished:
        message = (
            f"No conversations were found. {removed} other stored item(s) about this "
            "person were erased, but these could not be cleaned up: "
            + ", ".join(unfinished)
            + ". Try again, or ask your administrator to check storage and the activity record."
        )
    else:
        message = (
            f"No conversations were found. {removed} other stored item(s) about this "
            "person (saved facts, notes, activity records or knowledge) were erased, "
            "and nothing was found afterwards."
        )
    return {"erased": bool(removed), "conversations": 0,
            "clean": not unfinished, "unfinished": unfinished, "receipt_id": None,
            "message": message}


def _run_erase(channel: str, user: str, actor: str = "local") -> dict:
    import click
    from maverick.audit import AuditRefused
    from maverick.cli import erase as erase_command

    world = _world_for_request()
    from maverick.ediscovery import conversation_user_matches

    before = sum(
        1
        for conv in world.list_conversations(channel)
        if conversation_user_matches(conv.user_id, user, channel)
    )
    if not before:
        # Facts, notes, activity lines and knowledge are keyed by the person,
        # not a conversation, so they can outlive one: the command scrubs them.
        return _run_subject_residue_erase(world, channel, user, actor)
    out, err = io.StringIO(), io.StringIO()
    obj = {"db": getattr(world, "path", None)}
    refused = False
    with _ERASE_LOCK, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        ctx = click.Context(erase_command, obj=obj)
        try:
            with ctx:
                ctx.invoke(erase_command, channel=channel, user=user, yes=True)
        except AuditRefused:
            # Raised only after the deletion committed: the data is gone, but
            # the record of the erasure was refused.
            refused = True
        except (SystemExit, click.exceptions.Exit, click.ClickException) as exc:
            # A command-line exit must not end the server's worker thread.
            if obj.get("erase_refusal"):
                # A legal hold refused the erasure before anything was deleted.
                return {"erased": False, "conversations": before, "clean": False,
                        "message": obj["erase_refusal"]}
            raise RuntimeError("erasure command stopped") from exc
    # Who erased, never whose data (the subject is exactly what was erased).
    from maverick.audit import EventKind, audit_event
    try:
        audit_event(EventKind.ERASE, agent="operator", actor=actor, channel=channel,
                    conversations=before, source="dashboard")
    except AuditRefused:
        refused = True
    outcome = obj.get("erase_outcome") or {}
    residual = sum(int(v or 0) for v in (outcome.get("residual") or {}).values())
    unfinished = _unfinished_steps(outcome.get("closure_failures") or [])
    if refused and "the note that this erasure happened" not in unfinished:
        unfinished.append("the note that this erasure happened")
    clean = bool(outcome.get("clean")) and not refused
    if clean:
        message = f"Erased {before} conversation(s) and everything linked to them. The erasure was verified."
    elif residual:
        message = (
            f"Erased {before} conversation(s), but {residual} item(s) could not be "
            "removed. Try again, or ask your administrator to check the activity record."
        )
    elif unfinished:
        message = (
            f"Erased {before} conversation(s), but these could not be cleaned up: "
            + ", ".join(unfinished)
            + ". The erasure could not be certified. Try again, or ask your administrator "
            "to check storage and the activity record."
        )
    else:
        message = (
            f"Erased {before} conversation(s). No data was found afterwards, but the "
            "erasure could not be certified because its signed receipt could not be "
            "stored. Ask your administrator to check the activity record."
        )
    return {"erased": True, "conversations": before, "remaining": residual,
            "clean": clean, "unfinished": unfinished,
            "receipt_id": outcome.get("receipt_id"), "message": message}


@router.post("/people/erase")
async def erase_person(request: Request, person: PersonIn) -> dict:
    """Permanently erase one person's data (right to erasure)."""
    require_permission(request, "admin")
    channel, user = _validated(person)
    try:
        from .auth import caller_principal
        return await run_in_threadpool(
            _run_erase, channel, user, caller_principal(request) or "local")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="The erasure could not be completed.") from exc


# ---- Fingerprints -------------------------------------------------------

_FINGERPRINT_MAX_BYTES = 50 * 1024 * 1024


@router.post("/fingerprint")
async def fingerprint(request: Request) -> dict:
    """SHA-256 of an uploaded file, so evidence pages never ask a person to
    type a fingerprint. The bytes are hashed while streaming and never kept."""
    require_permission(request, "operate")
    import hashlib

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > _FINGERPRINT_MAX_BYTES:
        raise HTTPException(status_code=413, detail="That file is too large.")
    digest = hashlib.sha256()
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _FINGERPRINT_MAX_BYTES:
            raise HTTPException(status_code=413, detail="That file is too large.")
        digest.update(chunk)
    if not size:
        raise HTTPException(status_code=422, detail="The file is empty.")
    return {"sha256": digest.hexdigest(), "size": size}


# ---- Downloads and self-checks ----------------------------------------


def _attachment(document: Any, filename: str) -> Response:
    return Response(
        content=json.dumps(document, indent=2, sort_keys=True, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/downloads/soc2")
async def download_soc2(request: Request) -> Response:
    require_permission(request, "admin")
    from maverick.soc2 import collect_soc2_evidence

    from . import report_downloads

    context = report_downloads.capture(request, "soc2")
    evidence = await run_in_threadpool(collect_soc2_evidence)
    return report_downloads.finish(request, "soc2", context, _attachment(evidence, "lightwork-soc2-snapshot.json"))


@router.get("/downloads/ai-bom")
async def download_ai_bom(request: Request) -> Response:
    require_permission(request, "admin")
    from maverick import ai_bom

    from . import report_downloads

    context = report_downloads.capture(request, "ai_inventory")
    try:
        document = await run_in_threadpool(ai_bom.export_ai_bom)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="The AI inventory is not available.") from exc
    return report_downloads.finish(request, "ai_inventory", context, _attachment(document, "lightwork-ai-inventory.cdx.json"))


def _assessment_id(value: str) -> str:
    if not _ASSESSMENT_ID.fullmatch(value or ""):
        raise HTTPException(status_code=422, detail="Choose an assessment from the list.")
    return value


@router.get("/downloads/oscal")
async def download_oscal(request: Request, assessment: str) -> Response:
    require_permission(request, "operate")
    from maverick import assessment_exports

    from . import report_downloads

    context = report_downloads.capture(request, "oscal")
    try:
        document = await run_in_threadpool(
            assessment_exports.render_oscal_assessment_results, _assessment_id(assessment)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="That assessment no longer exists.") from exc
    return report_downloads.finish(request, "oscal", context, _attachment(document, "lightwork-assessment-results.oscal.json"))


@router.get("/downloads/soa")
async def download_soa(request: Request, assessment: str) -> Response:
    require_permission(request, "operate")
    from maverick import assessment_exports

    from . import report_downloads

    context = report_downloads.capture(request, "soa")
    try:
        soa = await run_in_threadpool(
            assessment_exports.render_statement_of_applicability, _assessment_id(assessment)
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="That assessment no longer exists.") from exc
    response = Response(
        content=assessment_exports.soa_markdown(soa),
        media_type="text/markdown",
        headers={
            "Content-Disposition": 'attachment; filename="lightwork-statement-of-applicability.md"',
            "Cache-Control": "no-store",
        },
    )
    return report_downloads.finish(request, "soa", context, response)


@router.get("/assessments")
async def list_assessments(request: Request) -> dict:
    """Saved assessments for the download pickers (newest first)."""
    require_permission(request, "operate")
    from maverick.assessment import list_saved

    rows = await run_in_threadpool(list_saved)
    return {
        "assessments": [
            {
                "id": row.get("id"),
                "subject": row.get("subject") or "Untitled",
                "type": row.get("type") or "",
                "created_at": row.get("created_at") or 0,
            }
            for row in rows[:200]
        ]
    }


@router.get("/ai-act")
async def ai_act_self_check(request: Request) -> dict:
    """EU AI Act self-check: the live notice status plus the checklists."""
    require_permission(request, "view")
    from maverick.ai_act import assess_ai_act

    report = await run_in_threadpool(assess_ai_act)
    posture = report.get("transparency_obligation_art50") or {}
    checklist = report.get("self_assessment") or {}
    tiers = report.get("obligations_by_tier") or {}
    return {
        "notice_on": bool(posture.get("disclosure_active")),
        "default_level": (
            "Limited risk. An AI assistant that tells people it is an AI is "
            "limited risk, as long as none of the uses below apply."
        ),
        "banned_uses": list(checklist.get("prohibited_art5") or []),
        "high_risk_uses": list(checklist.get("high_risk_annex_iii") or []),
        "duties": [
            {"level": "Limited risk", "text": tiers.get("limited_risk_art50", "")},
            {"level": "High risk", "text": tiers.get("high_risk_annex_iii", "")},
            {"level": "Banned", "text": tiers.get("prohibited_art5", "")},
        ],
        "note": report.get("disclaimer", ""),
    }


@router.get("/control-finder")
async def control_finder(request: Request, q: str = "") -> dict:
    """Controls that address a described risk, with framework references."""
    require_permission(request, "view")
    from maverick.controls import find_controls

    query = (q or "")[:300]
    hits = find_controls(query, limit=8) if query.strip() else []
    return {
        "controls": [
            {
                "title": c.title,
                "area": c.theme.capitalize(),
                "references": [
                    {"framework": fw, "reference": ref} for fw, ref in c.frameworks.items()
                ],
            }
            for c in hits
        ]
    }


__all__ = ["CONTROL_GUIDE", "SIGN_IN_FIRST", "sign_in_configured", "RETENTION_FIELDS", "STATUS_TEXT", "SWITCHES", "guide_for", "router"]
