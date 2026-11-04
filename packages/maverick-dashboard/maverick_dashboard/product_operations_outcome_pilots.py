"""Protected operating and read controls for the same native pilot lifecycle."""
from __future__ import annotations

import re
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field, create_model

from . import outcome_pilot_releases, outcome_pilots, outcome_pilots_api
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PILOT_ID = re.compile(r"OPL-[a-f0-9]{48}\Z")


def _id(selection):
    if (not isinstance(selection, dict) or set(selection) != {"kind", "id"}
            or selection["kind"] != "outcome_pilot"
            or not isinstance(selection["id"], str)
            or _PILOT_ID.fullmatch(selection["id"]) is None):
        raise HTTPException(404, "Choose an improvement pilot on its page first.")
    return selection["id"]


def snapshot(request, selection):
    pilot_id = _id(selection)
    context = outcome_pilots_api._context(request)
    try:
        record = outcome_pilots.get(pilot_id, context)
    except LookupError as exc:
        raise HTTPException(404, "This pilot is no longer available to your account and workspace.") from exc
    binding_data = record.get("release_binding")
    if binding_data is None:
        return Snapshot(digest([context, pilot_id, record["plan_version"], "no_release"]),
                        "Selected improvement pilot", "Check the pilot's measured work on its page.",
                        blocked="This pilot has no candidate release to check.")
    try:
        binding = outcome_pilot_releases.ReleaseBinding(**binding_data)
        current = outcome_pilot_releases.status(request, binding)
    except (TypeError, ValueError, PermissionError) as exc:
        raise HTTPException(503, "The release check is unavailable. Open the pilot to refresh its status.") from exc
    details = {
        "pilot": record["title"],
        "promotion_state": current["promotion_state"],
        "deployment_state": current["deployment_state"],
        "release_evidence_current": current["release_evidence_current"],
        "case_exposure_verified": current["case_exposure_verified"],
        "causal_lift_qualified": current["causal_lift_qualified"],
        "checked_at": current.get("checked_at"),
        "release_decisions": {"href": "/research#research-promotions",
                              "label": "Open release decisions"},
    }
    # The observation time changes on every healthy read. It is useful to show,
    # but cannot be part of a revision that Copilot rechecks several times.
    revision_details = {key: value for key, value in details.items() if key != "checked_at"}
    return Snapshot(digest([context, pilot_id, record["plan_version"], revision_details]),
                    "Current release check",
                    "Check which release the installation currently reports. This does not prove which release each case saw or that the change improved results.",
                    details=details)


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    if current.blocked:
        raise HTTPException(409, current.blocked)
    return Preview(current.summary, native=current.details)


def value_snapshot(request, selection):
    """Read the same source-authorized pilot evidence shown by the native page."""
    pilot_id = _id(selection)
    context = outcome_pilots_api._context(request)
    try:
        record = outcome_pilots.get(pilot_id, context)
    except LookupError as exc:
        raise HTTPException(404, "This pilot is no longer available to your account and workspace.") from exc
    report = outcome_pilots.report(record, resolve=outcome_pilots_api._resolver(request))
    details = {
        "pilot": report["title"],
        "groups": report["groups"],
        "evidence_readiness": report["evidence_readiness"],
        "limitations": report["limitations"],
        "case_exposure_verified": False,
        "causal_lift_qualified": False,
        "href": "/outcome-pilots",
    }
    current_cases = [(row["id"], row["status"],
                      row.get("source", {}).get("version")) for row in report["cases"]]
    return Snapshot(digest([context, pilot_id, report["revision"], current_cases, details]),
                    "Current source-authorized pilot evidence",
                    "Review what the full frozen cohort's operator-reported evidence supports and what remains missing. It does not prove causal improvement or independently verified savings.",
                    details=details)


def value_prepare(request, selection, _arguments):
    current = value_snapshot(request, selection)
    return Preview(current.summary, native=current.details)


def entries():
    return (Adapter("learning.pilot_release_status", "Check this pilot's release", "learning",
                    "/outcome-pilots", ("/outcome-pilots",), EmptyInput,
                    snapshot, prepare,
                    aliases=("check pilot release", "check this pilot's release")),
            Adapter("learning.pilot_value_evidence", "Review this pilot's value evidence", "learning",
                    "/outcome-pilots", ("/outcome-pilots",), EmptyInput,
                    value_snapshot, value_prepare,
                    aliases=("pilot results", "pilot value", "what did this pilot save")),
            Adapter("learning.pilot_form", "Open complete pilot controls", "learning", "/outcome-pilots", ("/outcome-pilots", "/learning"), FormInput, form_snapshot, form_prepare),
            *(Adapter(identifier, label, "learning", "/outcome-pilots", ("/outcome-pilots",), model,
                      partial(write_snapshot, kind=kind), partial(write_prepare, kind=kind),
                      partial(write_execute, kind=kind), partial(write_recover, kind=kind),
                      read_recovery=partial(write_recover, kind=kind, read_only=True), review_max_bytes=1400000)
              for kind, identifier, label, model in (
                  ("prepare", "learning.pilot_prepare_task", "Prepare a pilot task", TaskInput),
                  ("plan", "learning.pilot_freeze_plan", "Save and freeze a pilot plan", PlanInput),
                  ("observe", "learning.pilot_observe", "Record this pilot case’s observation", ObserveInput),
                  ("review", "learning.pilot_independent_review", "Record an independent pilot review", ReviewInput))))


class FormInput(StrictInput):
    action: str = Field(pattern=r"^(?:prepare|plan|observe|review|costs|value|history)$")


class TaskInput(StrictInput):
    title: str = Field(min_length=1, max_length=200)
    domain: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=4000)


class PlanInput(StrictInput):
    title: str = Field(min_length=1, max_length=200)
    customer: str = Field(min_length=1, max_length=200)
    workflow: str = Field(min_length=1, max_length=1000)
    criteria: str = Field(min_length=1, max_length=4000)
    cases: list[str] = Field(min_length=4, max_length=100)
    learning_mode: str = Field(pattern=r"^(?:observational|exclude_local_learning)$")
    prior_exposure_statement: str = Field(default="", max_length=2000)
    candidate_id: str = Field(default="", max_length=128)


class ReviewInput(StrictInput):
    pilot: str = Field(pattern=r"^OPL-[a-f0-9]{48}$")
    decision: str = Field(pattern=r"^(?:accepted_local_scope|needs_more_evidence)$")
    notes: str = Field(min_length=20, max_length=4000)
    confirm: bool


ObserveInput = create_model("PilotObservationArguments", __base__=StrictInput,
    case=(str, Field(pattern=r"^(?:[1-9][0-9]?|100)$")),
    **{name: (field.annotation, Field(default=field.default, **{
        "max_length": 4000} if name in {"evidence", "note"} else {}))
       for name, field in outcome_pilots_api.ObservationIn.model_fields.items()
       if name not in {"expected_revision", "operation_id", "source_version", "cost_coverage"}},
    **{key: definition for family in outcome_pilots_api.COST_COVERAGE_FAMILIES for key, definition in (
        ("coverage_" + family + "_status", (str, Field(pattern=r"^(?:included|zero|unknown)$"))),
        ("coverage_" + family + "_note", (str, Field(min_length=1, max_length=1000))))})


def _field(name, label, *, choices=None, kind="text", required=True, value=None, maximum=4000):
    return {"name": name, "label": label, "kind": "select" if choices is not None else kind,
            "required": required, "max_length": maximum, **({"choices": choices} if choices is not None else {}),
            **({"value": value} if value is not None else {})}


def form_snapshot(request, selection):
    context = outcome_pilots_api.context_for(request)
    outcome_pilots_api._current_actor(request, context)
    return Snapshot(digest([context, selection]), "Current pilot controls", "Open the same protected ordinary forms. Entered work is kept; no work starts.",
                    fields=[_field("action", "Pilot work", choices=[{"value": key, "label": label} for key, label in
                       (("prepare", "Prepare a task"), ("plan", "Plan and freeze a pilot"), ("observe", "Record a case observation"), ("review", "Independent policy review"), ("costs", "Allocate provider costs"), ("value", "Record cost and value evidence"), ("history", "Check an original request"))])])


def form_prepare(request, selection, arguments):
    context = outcome_pilots_api.context_for(request)
    outcome_pilots_api._current_actor(request, context)
    pilot = _id(selection) if selection.get("kind") == "outcome_pilot" else ""
    if pilot:
        outcome_pilots.get(pilot, context)
    return Preview("Open the complete protected pilot form. No task starts or record changes.", native={
        "outcome_pilot_form": {"context": context, "action": arguments["action"], "pilot": pilot, "case": ""}})


def write_snapshot(request, selection, *, kind):
    native = outcome_pilots_api
    context = native._context(request)
    native._current_actor(request, context, write=True, review=kind == "review")
    fields, material, blocked = [], [context, kind], ""
    if kind in {"prepare", "plan"}:
        catalogue = native.outcome_pilot_sources.choices(request)
        material.append(catalogue)
        if kind == "prepare":
            fields = [_field("title", "Task name", maximum=200), _field("domain", "Agent or specialist", choices=[{"value": "", "label": "Choose an agent or specialist"}, *[{"value": row["domain"], "label": row["label"]} for row in catalogue["specialists"]]]), _field("description", "Task instructions", kind="textarea")]
            if not catalogue["specialists"]:
                blocked = "No permitted agent or specialist with a reviewed result is available. Review workforce settings first."
        else:
            fields = [_field("title", "Pilot name", maximum=200), _field("customer", "Customer or team", maximum=200), _field("workflow", "Workflow", kind="textarea", maximum=1000), _field("criteria", "Acceptance criteria", kind="textarea"),
                      {"name": "cases", "label": "Choose four or more unstarted cases", "kind": "multiselect", "presentation": "checkboxes", "required": True, "max_selections": 100, "choices": [{"value": row["kind"] + ":" + row["reference"], "label": ("Task: " if row["kind"] == "goal" else "Vendor: ") + row["label"]} for row in catalogue["items"]]},
                      _field("learning_mode", "Learning-data treatment", choices=[{"value": "observational", "label": "Record observations; learning stays unchanged"}, {"value": "exclude_local_learning", "label": "Keep evaluation tasks out of local learning"}]),
                      _field("prior_exposure_statement", "Prior exposure checks and limitations", kind="textarea", required=False, maximum=2000),
                      _field("candidate_id", "Candidate release", choices=[{"value": "", "label": "No release — workflow observations"}], required=False)]
            releases = native.outcome_pilot_releases.choices(request)
            if releases.get("available"):
                fields[-1]["choices"] += [{"value": row["candidate_id"], "label": row.get("label") or "Candidate for " + row["target_id"]} for row in releases.get("items", [])]
                material.append(releases)
            if len(catalogue["items"]) < 4:
                blocked = "Prepare at least four currently accessible unstarted cases before freezing a pilot."
    elif kind == "observe":
        try:
            pilot = _id(selection)
            row = native._record(request, pilot, context)
            report = outcome_pilots.report(row, resolve=native._resolver(request))
        except (HTTPException, LookupError):
            return Snapshot(digest(material), "Current pilot cases", "Choose a saved pilot in Workflow pilots.", blocked="Choose a current saved pilot before recording observations.")
        material += [row["revision"], [(row["id"], (row.get("source") or {}).get("version")) for row in report["cases"]]]
        fields = [_field("case", "Pilot case", choices=[{"value": "", "label": "Choose a case"}, *[{"value": row["id"], "label": row["source"]["title"]} for row in report["cases"] if row.get("source")]])]
        for key, label in (("baseline_minutes", "Baseline hands-on minutes"), ("ai_hands_on_minutes", "AI workflow hands-on minutes"), ("review_minutes", "Review minutes"), ("rework_minutes", "Rework minutes"), ("corrections", "Corrections requested"), ("baseline_wall_minutes", "Baseline elapsed minutes"), ("ai_wall_minutes", "AI workflow elapsed minutes"), ("baseline_cost", "Total baseline cost"), ("ai_total_cost", "Total AI workflow cost"), ("human_cost", "Human preparation and review cost"), ("rework_cost", "Rework cost"), ("currency", "Currency, such as USD"), ("evidence", "Observation and cost evidence"), ("note", "Method and limitations")):
            fields.append(_field(key, label, kind="textarea" if key in {"evidence", "note"} else "number" if key.endswith("minutes") or key == "corrections" else "text", required=key in {"evidence", "note"}))
        fields.append(_field("criteria_met", "Met the frozen criteria", choices=[{"value": None, "label": "Not measured"}, {"value": True, "label": "Yes"}, {"value": False, "label": "No"}], required=False))
        for family in native.COST_COVERAGE_FAMILIES:
            fields += [_field("coverage_" + family + "_status", family.replace("_", " ").capitalize() + " coverage", choices=[{"value": "unknown", "label": "Unknown"}, {"value": "included", "label": "Included in total"}, {"value": "zero", "label": "Confirmed zero"}]), _field("coverage_" + family + "_note", family.replace("_", " ").capitalize() + " evidence or assumption", kind="textarea", maximum=1000)]
    else:
        actor = native.caller_principal(request) or ""
        queue = outcome_pilots.review_queue(actor)
        material.append(queue)
        fields = [_field("pilot", "Pilot to review", choices=[{"value": "", "label": "Choose a pilot"}, *[{"value": row["id"], "label": row["title"]} for row in queue]]),
                  _field("decision", "Independent decision", choices=[{"value": "", "label": "Choose a decision"}, {"value": "needs_more_evidence", "label": "More evidence needed"}, {"value": "accepted_local_scope", "label": "Accept this installation’s local scope"}]),
                  _field("notes", "Evidence checked and remaining limitations", kind="textarea"), _field("confirm", "I reviewed the complete fixed plan and learning exclusions", kind="boolean")]
        if not queue:
            blocked = "No other person’s protected pilot is waiting for your independent review."
    return Snapshot(digest(material), "Current protected pilot work", "This uses the same native pilot controls. No task or AI run starts. Operator reports do not establish causal improvement.",
                    details={"Scope": "Current account and workspace", "Available cases": "The same bounded current cases offered by the ordinary pilot page."}, fields=fields, blocked=blocked)


def _body(request, selection, arguments, kind):
    values, pilot, case = dict(arguments), "", ""
    if kind == "plan":
        catalogue = outcome_pilots_api.outcome_pilot_sources.choices(request)
        by_key = {row["kind"] + ":" + row["reference"]: row for row in catalogue["items"]}
        if any(key not in by_key for key in values["cases"]):
            raise HTTPException(409, "A chosen case is no longer available. Keep your plan and review current cases.")
        values["cases"] = [{"kind": by_key[key]["kind"], "reference": by_key[key]["reference"], "label": by_key[key]["label"]} for key in values["cases"]]
        if not values["candidate_id"]:
            values.pop("candidate_id")
    elif kind == "observe":
        pilot, case = _id(selection), values.pop("case")
        values["cost_coverage"] = {family: {"status": values.pop("coverage_" + family + "_status"), "note": values.pop("coverage_" + family + "_note")} for family in outcome_pilots_api.COST_COVERAGE_FAMILIES}
        for key in ("currency", "baseline_cost", "ai_total_cost", "human_cost", "rework_cost"):
            if values.get(key) == "":
                values[key] = None
    elif kind == "review":
        pilot = values.pop("pilot")
    return {"kind": kind, "pilot": pilot, "case": case, "values": values}


def write_prepare(request, selection, arguments, *, kind):
    prepared = outcome_pilots_api.prepare_native(request, _body(request, selection, arguments, kind))
    changes = prepared.pop("changes")
    return Preview("Review the complete current pilot source and every proposed detail. No AI runs or spending occur.", changes=changes, native={"prepared": prepared, "arguments_digest": digest(arguments)})


def _outcome(row, replay=False):
    return Outcome("replayed" if replay and row["confirmed"] else "confirmed" if row["confirmed"] else "unconfirmed", row["message"],
                   {"Original request": row["title"] or "Not confirmed", "Open current records": {"href": row["href"], "label": "Open current records"}})


def write_execute(request, selection, arguments, prepared, operation, *, kind):
    if digest(arguments) != prepared["arguments_digest"] or kind != prepared["prepared"]["kind"]:
        raise HTTPException(409, "The entered details changed after review. Review again before saving.")
    return _outcome(outcome_pilots_api.execute_native(request, prepared["prepared"], operation))


def write_recover(request, selection, arguments, prepared, operation, *, kind, read_only=False):
    if digest(arguments) != prepared["arguments_digest"] or kind != prepared["prepared"]["kind"]:
        raise HTTPException(409, "This original request belongs to another review.")
    native = prepared["prepared"]
    row = outcome_pilots_api.original_native(request, kind, operation, native["pilot"], native["case"], prepared=native)
    if not row["found"] and not read_only:
        return None
    return _outcome(row, replay=True)
