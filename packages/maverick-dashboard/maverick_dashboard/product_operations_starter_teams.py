"""Copilot uses the same starter-team previews, cases and recovery as the page."""
from __future__ import annotations

from datetime import date

from maverick.governed_operations import digest
from pydantic import Field, create_model

from . import starter_teams_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/starter-teams"
PAGES = (PAGE, "/workforce", "/agents", "/shoring")
RecordsEntry = create_model("StarterTeamRecordsEntry", __base__=StrictInput,
    as_of=(str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")),
    **{f"table_{index}": (str, Field(default="", max_length=200_000)) for index in range(12)})


def _choices(request):
    teams = native.available_catalog(request)
    setups = native.service(request).list_setups()
    names = {team["id"]: team["title"] for team in teams}
    choices = [{"value": row["id"], "label": names.get(row["team_id"], "Saved team") + " — " + row["owner_label"]} for row in setups]
    revision = digest({"context": native.context(request).binding(), "teams": teams, "setups": setups})
    return teams, setups, choices, revision


def _selected(request, selection):
    from fastapi import HTTPException
    from maverick.starter_teams import get_team

    if selection.get("kind") != "starter_team" or not selection.get("id"):
        raise HTTPException(409, "Choose a saved team on Starter teams, then open these controls.")
    setup = native.service(request).get_setup(selection["id"])
    return setup, get_team(setup["team_id"])


def setup_snapshot(request, selection):
    teams, _, _, revision = native.call(lambda: _choices(request))
    return Snapshot(revision, "Current permitted starter-team catalog", native.NOTICE,
        fields=[{"name": "team_id", "label": "Team", "kind": "select", "required": True,
                 "choices": [{"value": team["id"], "label": team["title"]} for team in teams]},
                {"name": "owner_label", "label": "Responsible person", "required": True},
                {"name": "scope", "label": "Scope of work", "kind": "textarea", "required": True, "max_length": 1000},
                {"name": "cadence", "label": "Cadence preference (no automatic runs)", "kind": "select", "value": "manual",
                 "choices": [{"value": value, "label": label} for value, label in (("manual", "When requested"), ("daily", "Daily"), ("weekly", "Weekly"), ("monthly", "Monthly"))]},
                {"name": "max_rows", "label": "Maximum records per run", "kind": "number", "value": 250}],
        blocked="No permitted teams are available." if not teams else "")


def run_snapshot(request, selection):
    _, _, choices, revision = native.call(lambda: _choices(request))
    return Snapshot(revision, "Your current saved teams", native.NOTICE,
        fields=[{"name": "setup_id", "label": "Saved team", "kind": "select", "required": True, "choices": choices}],
        blocked="Save a starter team first." if not choices else "")


def pause_snapshot(request, selection):
    value = run_snapshot(request, selection)
    return Snapshot(value.revision, value.source, value.summary, fields=[*value.fields,
        {"name": "paused", "label": "Pause manual runs (clear to resume)", "kind": "boolean", "value": True}], blocked=value.blocked)


def inputs_snapshot(request, selection):
    setup, team = native.call(lambda: _selected(request, selection))
    fields = [{"name": "as_of", "label": "Review date (year-month-day)", "value": date.today().isoformat(), "required": True}]
    for index, table in enumerate(team["inputs"]):
        fields.append({"name": f"table_{index}", "label": table["label"] + " (CSV)", "kind": "textarea",
                       "value": ",".join(table["columns"]) + "\n", "required": True, "max_length": 200_000})
    return Snapshot(digest({"setup": setup, "team": team, "context": native.context(request).binding()}),
        "Selected saved team and its declared input columns", native.NOTICE,
        {"Team": team["title"], "Scope": setup["scope"]}, fields,
        "Resume this team before running checks." if setup.get("paused") else "")


def runtime_snapshot(request, selection):
    setup, team = native.call(lambda: _selected(request, selection))
    cases = native.call(lambda: native.service(request).list_cases(setup["id"]))
    choices = [{"value": row["id"], "label": ("Sample" if row["mode"] == "sample" else "Record check") + " " + str(index + 1)}
               for index, row in enumerate(cases) if row.get("status") == "awaiting_review" and row.get("mode") == "supplied_export"]
    return Snapshot(digest({"setup": setup, "cases": cases, "context": native.context(request).binding()}),
        "Saved evidence cases for the selected starter team", "Review an actual specialist workflow, its sources and its total budget.",
        {"Team": team["title"]},
        [{"name": "case_id", "label": "Saved evidence case", "kind": "select", "choices": choices, "required": True},
         {"name": "max_dollars", "label": "Maximum total cost (USD)", "kind": "number", "value": 1.0, "required": True},
         {"name": "max_wall_seconds", "label": "Maximum total time (seconds)", "kind": "number", "value": 900, "required": True}],
        "Check your approved records first; bundled samples do not start paid specialist work." if not choices else "Resume this team before starting specialists." if setup.get("paused") else "")


def _prepare(action):
    def prepare(request, selection, arguments):
        values = arguments
        if action == "inputs":
            setup, team = native.call(lambda: _selected(request, selection))
            values = {"setup_id": setup["id"], "as_of": arguments["as_of"],
                      "tables": {table["key"]: arguments[f"table_{index}"] for index, table in enumerate(team["inputs"])}}
            if any(arguments.get(f"table_{index}") for index in range(len(team["inputs"]), 12)):
                from fastapi import HTTPException
                raise HTTPException(422, "Only supply the listed input tables.")
        material, public = native.call(lambda: native.prepare_operation(request, action, values))
        return Preview("Review the team, scope and limits before confirming.",
                       [{"label": key, "after": value} for key, value in public.items()], material)
    return prepare


def execute(request, selection, arguments, material, operation_id):
    result = native.call(lambda: native.execute_operation(request, material, operation_id))
    return Outcome("confirmed", "Starter-team work recorded.", native.public_outcome(result))


def recover(request, selection, arguments, material, operation_id):
    result = native.call(lambda: native.recover_operation(request, material, operation_id))
    return Outcome("replayed", "The original result is confirmed.", native.public_outcome(result)) if result else None


def status_snapshot(request, selection):
    teams, setups, _, revision = native.call(lambda: _choices(request))
    return Snapshot(revision, "Your current starter-team records", native.NOTICE,
                    {"Available teams": len(teams), "Saved setups": len(setups)})


def status_prepare(request, selection, arguments):
    teams, setups, _, _ = native.call(lambda: _choices(request))
    names = {team["id"]: team["title"] for team in teams}
    details = {"Meaning": native.NOTICE, "Saved teams": [{"Team": names.get(row["team_id"], "Saved team"),
        "Responsible person": row["owner_label"], "Scope": row["scope"], "State": "Paused" if row.get("paused") else "Ready for manual runs"} for row in setups]}
    if selection.get("kind") == "starter_team":
        from maverick.starter_team_runtime import StarterTeamRuntime

        setup, _ = native.call(lambda: _selected(request, selection))
        cases = native.call(lambda: native.service(request).list_cases(setup["id"]))
        details["Saved results"] = [native.public_outcome({"case": row}) for row in cases]
        runtime = StarterTeamRuntime(native.service(request))
        workflows = [native.call(lambda case_id=row["id"]: runtime.reconcile(case_id)) for row in cases]
        details["Specialist workflows"] = [native.public_outcome({"runtime": row}) for row in workflows if row]
    return Preview("Current starter-team state; nothing changed.", native=details)


def entries():
    return (
        Adapter("teams.starter.status", "Read my starter teams and results", "tasks", PAGE, PAGES, EmptyInput, status_snapshot, status_prepare),
        Adapter("teams.starter.setup", "Review a starter-team setup", "tasks", PAGE, PAGES, native.SetupInput, setup_snapshot, _prepare("setup"), execute, recover, read_recovery=recover),
        Adapter("teams.starter.sample", "Review a starter-team sample", "tasks", PAGE, PAGES, native.SampleInput, run_snapshot, _prepare("sample"), execute, recover, read_recovery=recover),
        Adapter("teams.starter.inputs", "Review checks of my records", "tasks", PAGE, (PAGE,), RecordsEntry, inputs_snapshot, _prepare("inputs"), execute, recover, read_recovery=recover, review_max_bytes=1_000_000),
        Adapter("teams.starter.pause", "Pause or resume a starter team", "tasks", PAGE, PAGES, native.PauseInput, pause_snapshot, _prepare("pause"), execute, recover, read_recovery=recover),
        Adapter("teams.starter.runtime", "Review a specialist team workflow", "tasks", PAGE, (PAGE,), native.RuntimeInput, runtime_snapshot, _prepare("runtime"), execute, recover, read_recovery=recover, review_max_bytes=1_000_000),
    )
