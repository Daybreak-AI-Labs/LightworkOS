"""Copilot schedule reviews use the same native service and exact receipts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field, create_model

from . import starter_team_schedule_api as schedules
from . import starter_teams_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/starter-teams"
PAGES = (PAGE, "/workforce", "/agents", "/shoring")


class ScheduleForm(StrictInput):
    setup_id: str = Field(min_length=1, max_length=80)
    starts_utc: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
    ends_utc: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
    interval_hours: int = Field(ge=1, le=8760)
    max_runs: int = Field(ge=1, le=100)
    max_dollars_per_run: float = Field(gt=0, le=100, allow_inf_nan=False)
    max_total_dollars: float = Field(gt=0, le=1000, allow_inf_nan=False)
    max_wall_seconds: int = Field(default=300, ge=1, le=1800)


ItemForm = create_model("StarterTeamScheduleItemForm", __base__=StrictInput,
    as_of=(str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")),
    **{f"table_{index}": (str, Field(default="", max_length=200_000)) for index in range(12)})


def _state(request):
    rows = schedules.available_schedules(request)
    setups = native.service(request).list_setups()
    choices = [{"value": row["id"], "label": "Schedule starting " + schedules._date(row["start_at"])} for row in rows]
    revision = digest({"context": native.context(request).binding(), "schedules": rows, "setups": setups})
    return rows, setups, choices, revision


def _selected(request, selection):
    from maverick.starter_teams import get_team

    if selection.get("kind") != "starter_team_schedule" or not selection.get("id"):
        raise HTTPException(409, "Choose a saved schedule on Starter teams before adding an evidence package.")
    row = schedules.service(request).get_schedule(selection["id"])
    setup = native.service(request).get_setup(row["setup_id"])
    return row, get_team(setup["team_id"])


def create_snapshot(request, selection):
    from maverick.starter_teams import get_team

    _, setups, _, revision = native.call(lambda: _state(request))
    now = datetime.now(timezone.utc)
    fields = [
        {"name": "setup_id", "label": "Saved team", "kind": "select", "required": True,
         "choices": [{"value": row["id"], "label": get_team(row["team_id"])["title"] + " - " + row["owner_label"]} for row in setups]},
        {"name": "starts_utc", "label": "Starts in UTC (YYYY-MM-DDTHH:MM)", "required": True,
         "value": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M")},
        {"name": "ends_utc", "label": "Ends in UTC (YYYY-MM-DDTHH:MM)", "required": True,
         "value": (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")},
    ]
    fields.extend({"name": name, "label": label, "kind": "number", "value": value, "required": True}
                  for name, label, value in (
                      ("interval_hours", "Hours between runs", 24), ("max_runs", "Maximum runs", 7),
                      ("max_dollars_per_run", "Maximum dollars per run", 1),
                      ("max_total_dollars", "Maximum total dollars", 7),
                      ("max_wall_seconds", "Maximum seconds per run", 300)))
    return Snapshot(revision, "Current saved teams and their scope", schedules.NOTICE,
                    fields=fields, blocked="Save a starter team first." if not setups else "")


def choose_snapshot(request, selection):
    _, _, choices, revision = native.call(lambda: _state(request))
    return Snapshot(revision, "Current reviewed schedules", schedules.NOTICE,
                    fields=[{"name": "schedule_id", "label": "Saved schedule", "kind": "select",
                             "required": True, "choices": choices}],
                    blocked="Review and save a schedule first." if not choices else "")


def pause_snapshot(request, selection):
    value = choose_snapshot(request, selection)
    return Snapshot(value.revision, value.source, value.summary, fields=[*value.fields,
                    {"name": "paused", "label": "Pause new runs (clear to resume)", "kind": "boolean", "value": True}],
                    blocked=value.blocked)


def item_snapshot(request, selection):
    row, team = native.call(lambda: _selected(request, selection))
    fields = [{"name": "as_of", "label": "Evidence review date", "required": True,
               "value": datetime.now(timezone.utc).date().isoformat()}]
    fields.extend({"name": f"table_{index}", "label": table["label"] + " (CSV)", "kind": "textarea",
                   "value": ",".join(table["columns"]) + "\n", "required": True, "max_length": 200_000}
                  for index, table in enumerate(team["inputs"]))
    return Snapshot(digest({"schedule": row, "team": team, "context": native.context(request).binding()}),
                    "Selected schedule and its evidence requirements", schedules.NOTICE,
                    details={"Team": team["title"], **schedules.public_schedule(row)}, fields=fields)


def _arguments(request, selection, action, arguments):
    args = dict(arguments)
    if action == "schedule":
        for source, target in (("starts_utc", "start_at"), ("ends_utc", "end_at")):
            args[target] = datetime.strptime(args.pop(source), "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc).timestamp()
    elif action == "item":
        row, team = _selected(request, selection)
        if any(args.get(f"table_{index}") for index in range(len(team["inputs"]), 12)):
            raise ValueError("Supply only the listed evidence tables")
        args = {"schedule_id": row["id"], "as_of": args["as_of"],
                "tables": {table["key"]: args[f"table_{index}"] for index, table in enumerate(team["inputs"])}}
    return args


def _prepare(action):
    def prepare(request, selection, arguments):
        material, public = native.call(lambda: schedules.prepare_operation(
            request, action, _arguments(request, selection, action, arguments)))
        return Preview("Review the exact scope, evidence and spending limits before confirming.",
                       [{"label": key, "after": value} for key, value in public.items()], material)
    return prepare


def execute(request, selection, arguments, material, operation_id):
    value = native.call(lambda: schedules.execute_operation(request, material, operation_id))
    return Outcome("confirmed", "Scheduled team work recorded.", schedules.public_outcome(value))


def recover(request, selection, arguments, material, operation_id):
    value = native.call(lambda: schedules.recover_operation(request, material, operation_id))
    return Outcome("replayed", "Original result found; no work was repeated.", schedules.public_outcome(value)) if value else None


def status_snapshot(request, selection):
    rows, _, _, revision = native.call(lambda: _state(request))
    return Snapshot(revision, "Current schedule records", schedules.NOTICE, {"Saved schedules": len(rows)})


def status_prepare(request, selection, arguments):
    rows, _, _, _ = native.call(lambda: _state(request))
    details = {"Schedules": [schedules.public_schedule(row) for row in rows], "Meaning": schedules.NOTICE}
    if selection.get("kind") == "starter_team_schedule":
        row, _ = native.call(lambda: _selected(request, selection))
        items = native.call(lambda: schedules.service(request).list_items(row["id"]))
        details["Evidence packages"] = [{"State": item.get("status", "Unknown"),
                                        "Review": schedules._item_preview(item)} for item in items]
    return Preview("Current schedule state; nothing changed.", native=details)


def entries():
    return (
        Adapter("teams.starter.schedule.status", "Read my team schedules", "tasks", PAGE, PAGES,
                EmptyInput, status_snapshot, status_prepare),
        Adapter("teams.starter.schedule.create", "Review a bounded team schedule", "tasks", PAGE, PAGES,
                ScheduleForm, create_snapshot, _prepare("schedule"), execute, recover, read_recovery=recover),
        Adapter("teams.starter.schedule.item", "Review an evidence package for scheduled work", "tasks", PAGE, (PAGE,),
                ItemForm, item_snapshot, _prepare("item"), execute, recover, read_recovery=recover, review_max_bytes=1_000_000),
        Adapter("teams.starter.schedule.pause", "Pause or resume a team schedule", "tasks", PAGE, PAGES,
                schedules.PauseInput, pause_snapshot, _prepare("pause"), execute, recover, read_recovery=recover),
        Adapter("teams.starter.schedule.tick", "Review running a due team package", "tasks", PAGE, PAGES,
                schedules.ScheduleSelection, choose_snapshot, _prepare("tick"), execute, recover, read_recovery=recover),
    )
