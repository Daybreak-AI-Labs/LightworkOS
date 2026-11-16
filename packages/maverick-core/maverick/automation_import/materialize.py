"""Map an :class:`~.ir.ImportedAutomation` onto Lightwork's existing primitives.

The actions become a signed user ``Template`` (so the whole run path -- render →
``create_goal`` → orchestrator, with budget guardrails -- is reused unchanged).
The trigger becomes either a cron **schedule** (created here via the core
``scheduler`` when a JobQueue is supplied) or a **webhook trigger** (which lives
in the dashboard's ``triggers_store``, so we don't create it here -- we return a
``suggested_trigger`` the CLI/dashboard wires up). Runs spawned later are tagged
through the existing ``goal_origins`` table by those trigger/schedule paths, so
imported automations appear in the Automations history automatically.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .ir import TRIGGER_SCHEDULE, TRIGGER_WEBHOOK, ImportedAutomation


@dataclass
class MaterializeResult:
    template_name: str
    title: str
    created_template: bool
    suggested_trigger: dict[str, Any] | None = None   # for webhook triggers
    schedule: dict[str, Any] | None = None            # {job_id, run_at, cron} if created
    tool_hints: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# What an import itself sets on the schedule it creates. Their digest is kept
# with the schedule, so a re-import can tell "the source changed" from "a
# person changed this schedule here".
_IMPORTED_KEYS = ("text", "title", "__cron__", "max_dollars", "max_wall_seconds",
                  "owner", "channel", "user_id", "imported_from")


def _import_digest(payload: dict[str, Any]) -> str:
    values = {key: payload.get(key) for key in _IMPORTED_KEYS}
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _replaced_values(stored: dict[str, Any], payload: dict[str, Any]) -> str:
    """The time, zone and title a re-import is about to replace, in words.

    They go in the import note and the schedule's history, so a person whose
    own changes are replaced can put them back.
    """
    was = []
    zone = str(stored.get("__tz__") or "")
    if stored.get("__cron__") != payload["__cron__"] or zone:
        was.append(f"the time was {stored.get('__cron__')}" + (f" ({zone})" if zone else ""))
    if stored.get("title") != payload["title"]:
        was.append(f"the title was {str(stored.get('title') or '')[:80]!r}")
    return ", ".join(was)


def _other_name_note(automation: ImportedAutomation, marked: list[dict[str, Any]]) -> str:
    """Name a schedule that keeps running for the same source id under another name."""
    for row in marked:
        if automation.is_other_name_of(str(row["payload"].get("imported_from") or "")):
            return (f"a schedule from an earlier import with the same source id is still active "
                    f"under another name (job {row['id']}, {row['title']!r}); if this workflow "
                    "was renamed at the source, that is its old schedule -- retire it if it is "
                    "no longer wanted")
    return ""


def _activate_schedule(queue: Any, automation: ImportedAutomation, payload: dict[str, Any],
                       result: MaterializeResult, notes: list[str], *, mark: bool) -> None:
    """Create this import's schedule, or bring the one it made earlier up to date.

    The schedule follows the source only when the source changed since the
    last import. Until then a person's own changes to it (time, zone, title)
    are kept, and so is a pause. With ``mark`` off, or for a workflow that
    has no source id, the schedule carries no mark and is only ever created:
    this workflow cannot be told from another one with the same name.
    """
    from ..schedule_definitions import change_definition, imported_definitions
    from ..scheduler import CronError, schedule_cron

    cron = payload["__cron__"]
    try:
        current = None
        if not automation.source_id:
            # A mark built from a name alone would also match another workflow
            # that has the same name, and update its schedule.
            mark = False
            notes.append("this workflow has no id at the source, so a later import cannot tell "
                         "it from another workflow with the same name; an import creates its "
                         "schedule once and never changes it")
        if mark:
            payload["imported_from"] = automation.import_ref()
            digest = payload["import_digest"] = _import_digest(payload)
            marked = imported_definitions(queue, owner=payload.get("owner", ""))
            current = next((row for row in marked
                            if row["payload"].get("imported_from") == payload["imported_from"]), None)
            if current is None and (note := _other_name_note(automation, marked)):
                notes.append(note)
        if current is None:
            job_id, run_at = schedule_cron(queue, cron, "start_goal", payload)
            result.schedule = {"job_id": job_id, "run_at": run_at, "cron": cron,
                               "schedule_id": payload["schedule_id"]}
            return
        stored = current["payload"]
        paused = current["state"] == "paused"
        # An import sets no time zone, so a zone is always a person's choice.
        edited = _import_digest(stored) != stored.get("import_digest") or bool(stored.get("__tz__"))
        updates, replaced = None, ""
        if stored.get("import_digest") != digest:
            # The time and its zone belong together: a new source time read in
            # the person's old zone would be a time nobody chose.
            updates = {**{key: payload.get(key) for key in _IMPORTED_KEYS},
                       "import_digest": digest, "__tz__": None}
            replaced = _replaced_values(stored, payload) if edited else ""
        elif paused or current["next_run"] or current["running"]:
            notes.append(f"schedule already {'exists and is paused' if paused else 'active'} "
                         f"(job {current['id']}); not duplicated"
                         + ("; the workflow did not change, so changes made to this "
                            "schedule in Lightwork were kept" if edited else ""))
            return
        # Future runs follow the definition. A run already admitted keeps the
        # text it started with.
        changed = change_definition(
            queue, current["definition_id"], expected_revision=current["revision"],
            state="paused" if paused else "active", actor=payload.get("owner") or "import",
            rationale="Workflow imported again" + (f"; replaced: {replaced}" if replaced else ""),
            payload_updates=updates,
        )
        result.schedule = {"job_id": changed["id"], "run_at": changed["next_run"],
                           "cron": changed["cron"], "schedule_id": changed["schedule_id"],
                           "updated": True}
        if updates is None:
            notes.append("schedule had no upcoming run and is scheduled again")
        else:
            notes.append("schedule updated to match the re-imported workflow"
                         + ("; it is still paused" if paused else "")
                         + ("; changes made to this schedule in Lightwork were replaced"
                            + (f": {replaced}" if replaced else "") if edited else ""))
    except CronError as e:
        notes.append(f"could not create schedule from cron {cron!r}: {e}")
    except (KeyError, ValueError) as e:
        notes.append(f"schedule was not updated: {e}")


def materialize(
    automation: ImportedAutomation,
    *,
    save: bool = True,
    budget_dollars: float | None = None,
    budget_wall_seconds: float | None = None,
    queue: Any | None = None,
    overwrite: bool = True,
    owner: str | None = None,
    channel: str | None = None,
    user_id: str | None = None,
    expected_generation: int | None = None,
    effect_guard: Callable[[], None] | None = None,
    complete: bool = False,
    mark_schedule: bool = True,
) -> MaterializeResult:
    """Create the Template (and optionally a cron schedule) for one automation.

    ``queue`` (a ``maverick.job_queue.JobQueue``) enables auto-creating a cron
    schedule for ``schedule``-triggered automations whose cron we recovered.
    ``owner`` is retained on the imported template and activated schedule;
    ``channel``/``user_id`` carry the authenticated identity into scheduled runs.
    Webhook/event triggers are returned as ``suggested_trigger`` for the caller
    to wire (the webhook trigger store is a dashboard concern).
    ``mark_schedule=False`` creates the schedule without the import's mark, so
    no later import updates it: for a caller that cannot tell this workflow
    from another one in the same import (same name, no source id).
    """
    from ..catalog_trust import shield_scan
    from ..templates import save_user_template

    title, body = automation.render(complete=True) if complete else automation.render()
    tname = automation.template_name()
    notes: list[str] = []

    # Payload fields the workflow reads from its trigger -> declared template
    # params, so the trigger's data reaches the run by-name. Empty for
    # schedule/manual triggers. ``field_defaults`` covers EVERY {{placeholder}}
    # the saved template ends up declaring (payload fields plus any placeholder a
    # step input happens to carry), each defaulting to "" on the wired trigger --
    # so a fire never fails on a missing param while real payload data overrides
    # by-name.
    import re as _re
    fields = automation.payload_fields()
    _declared = list(dict.fromkeys(_re.findall(r"\{\{\s*(\w+)\s*\}\}", body)))
    field_defaults = dict.fromkeys(_declared, "")

    created = False
    if save:
        shield_scan(body, label=f"imported automation template {tname!r}")
        save_user_template(
            tname,
            title=title,
            body=body,
            params=fields,
            budget_dollars=budget_dollars,
            budget_wall_seconds=budget_wall_seconds,
            overwrite=overwrite,
            owner=owner,
            expected_generation=expected_generation,
            effect_guard=effect_guard,
        )
        created = True

    result = MaterializeResult(
        template_name=tname,
        title=title,
        created_template=created,
        tool_hints=automation.tool_hints(),
        notes=notes,
    )

    trig = automation.trigger
    if trig.kind == TRIGGER_SCHEDULE:
        if trig.cron and not automation.enabled:
            # The source operator turned this automation OFF; never auto-activate
            # a live schedule for it. Surface it as a suggestion so a human can
            # wire it deliberately, matching the source's disabled state.
            result.suggested_trigger = {"kind": "schedule", "cron": trig.cron, "template": tname}
            notes.append("source automation is disabled; schedule not activated -- "
                         "enable it at the source or wire it manually")
        elif trig.cron and queue is not None and save:
            from uuid import uuid4

            # Match the dashboard /api/v1/schedules payload exactly: the worker's
            # start_goal handler mints a fresh goal from "text" on every fire and
            # requires it to be non-empty (a {"template": ...} payload would fail
            # at run time). We snapshot the rendered brief as the goal text, like
            # the dashboard does, and carry a schedule_id for run provenance.
            # Authenticated callers may also pass owner/channel/user_id to match
            # the normal dashboard schedule path and avoid falling back to local.
            payload = {
                "text": body,
                "title": title[:200],
                "__cron__": trig.cron,
                "schedule_id": uuid4().hex,
            }
            if budget_dollars is not None:
                payload["max_dollars"] = budget_dollars
            if budget_wall_seconds is not None:
                payload["max_wall_seconds"] = budget_wall_seconds
            owner_value = str(owner or "").strip()
            if owner_value:
                payload["owner"] = owner_value
            channel_value = str(channel or "").strip()
            user_id_value = str(user_id or "").strip()
            if user_id_value:
                if channel_value:
                    payload["channel"] = channel_value
                payload["user_id"] = user_id_value
            # The import's own mark lets a re-import update this schedule
            # instead of adding a second one or leaving stale text running.
            _activate_schedule(queue, automation, payload, result, notes, mark=mark_schedule)
        elif trig.cron:
            result.suggested_trigger = {"kind": "schedule", "cron": trig.cron, "template": tname}
            notes.append("schedule recovered; pass a queue (or use the dashboard) to activate it")
        else:
            notes.append("source trigger is a schedule but no cron expression was recoverable; "
                         "set one when wiring the schedule")
    elif trig.kind in (TRIGGER_WEBHOOK,):
        result.suggested_trigger = {"kind": "webhook", "template": tname, "name": tname,
                                    "params": field_defaults}
        notes.append("wire an inbound webhook trigger bound to this template "
                     "(dashboard Automations, or `maverick` trigger tooling)")
    else:
        result.suggested_trigger = {"kind": trig.kind, "template": tname, "name": tname,
                                    "event": f"{trig.app} {trig.event}".strip(),
                                    "params": field_defaults}
        notes.append(f"source trigger ({trig.render()}) has no direct Lightwork equivalent; "
                     "bind the template to a webhook/schedule, or run it on demand")
    if fields:
        notes.append("trigger payload fields mapped to template params (fill on fire): "
                     + ", ".join(fields))

    return result
