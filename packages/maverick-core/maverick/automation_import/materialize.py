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
) -> MaterializeResult:
    """Create the Template (and optionally a cron schedule) for one automation.

    ``queue`` (a ``maverick.job_queue.JobQueue``) enables auto-creating a cron
    schedule for ``schedule``-triggered automations whose cron we recovered.
    ``owner`` is retained on the imported template and activated schedule;
    ``channel``/``user_id`` carry the authenticated identity into scheduled runs.
    Webhook/event triggers are returned as ``suggested_trigger`` for the caller
    to wire (the webhook trigger store is a dashboard concern).
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

            from ..scheduler import CronError, schedule_cron
            # Match the dashboard /api/v1/schedules payload exactly: the worker's
            # start_goal handler mints a fresh goal from "text" on every fire and
            # requires it to be non-empty (a {"template": ...} payload would fail
            # at run time). We snapshot the rendered brief as the goal text, like
            # the dashboard does, and carry a schedule_id for run provenance.
            # Authenticated callers may also pass owner/channel/user_id to match
            # the normal dashboard schedule path and avoid falling back to local.
            schedule_id = uuid4().hex
            payload = {
                "text": body,
                "title": title[:200],
                "__cron__": trig.cron,
                "schedule_id": schedule_id,
            }
            owner_value = str(owner or "").strip()
            if owner_value:
                payload["owner"] = owner_value
            channel_value = str(channel or "").strip()
            user_id_value = str(user_id or "").strip()
            if user_id_value:
                if channel_value:
                    payload["channel"] = channel_value
                payload["user_id"] = user_id_value
            try:
                job_id, run_at = schedule_cron(queue, trig.cron, "start_goal", payload)
                result.schedule = {
                    "job_id": job_id, "run_at": run_at, "cron": trig.cron,
                    "schedule_id": schedule_id,
                }
            except CronError as e:
                notes.append(f"could not create schedule from cron {trig.cron!r}: {e}")
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
