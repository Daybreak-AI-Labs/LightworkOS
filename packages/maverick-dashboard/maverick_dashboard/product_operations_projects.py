"""Typed project planning adapters, using the exact native service and receipts."""
from __future__ import annotations

from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from maverick.privacy_ops import RecordConflict
from maverick.project_reviews import ProjectReviewDenied
from pydantic import Field

from . import project_workspaces_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class DetailsIn(StrictInput):
    outcome: str = Field(default="", max_length=6000)
    criteria: str = Field(default="", max_length=12000)
    labels: str = Field(default="", max_length=1600)
    default_view: Literal["list", "board", "timeline"] = "list"


class MilestoneIn(StrictInput):
    milestone: str = Field(default="", max_length=32)
    title: str = Field(min_length=1, max_length=200)
    due: str = Field(default="", max_length=10)
    goals: list[str] = Field(default_factory=list, max_length=50)
    reviews: list[str] = Field(default_factory=list, max_length=50)


class ReorderIn(StrictInput):
    milestone: str = Field(min_length=32, max_length=32)
    direction: Literal["up", "down"]


class DependencyIn(StrictInput):
    milestone: str = Field(min_length=32, max_length=32)
    prerequisite: str = Field(min_length=32, max_length=32)
    required: bool = True


class MemberIn(StrictInput):
    member: str = Field(min_length=6, max_length=256)
    allowed: bool = True


class SourceIn(StrictInput):
    source: str = Field(min_length=1, max_length=80)


class RemoveMilestoneIn(StrictInput):
    milestone: str = Field(min_length=32, max_length=32)


class RemoveContextIn(StrictInput):
    reference: str = Field(min_length=32, max_length=32)


class DefaultsIn(StrictInput):
    action: Literal["save_defaults", "apply_defaults"]


def project_id(selection):
    if selection.get("kind") != "project" or type(selection.get("id")) is not int or selection["id"] < 1:
        raise HTTPException(404, "Open a project workspace to choose its current planning controls.")
    return selection["id"]


def _native(operation):
    try:
        return operation()
    except ProjectReviewDenied as exc:
        raise HTTPException(404, "This project or linked source is unavailable to your current account.") from exc
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Project storage could not confirm this operation. Check native status before another change.") from exc


def _state(request, selection):
    return _native(lambda: native.state(request, project_id(selection)))


def _choices(rows):
    return [{"value": str(row["id"]), "label": row["title"]} for row in rows]


def _field(name, label, kind="text", **extra):
    return {"name": name, "label": label, "kind": kind, **extra}


def snapshot(request, selection, operation="status"):
    state = _state(request, selection)
    w, choices = state["workspace"], state["choices"]
    details = {key: w[key] for key in ("name", "outcome", "criteria", "labels", "default_view")}
    names = {row["id"]: row["title"] for row in w["milestones"]}
    details["milestones"] = [{"name": row["title"], "target_date": row["due"], "state": row["state"],
                              "planning_prerequisites": [names[key] for key in row["depends_on"]],
                              "linked_work": [{"title": item["title"], "state": item["status"]} for item in row["sources"]]}
                             for row in w["milestones"]]
    details["context"] = [{"title": row["title"], "state": row["state"]} for row in w["context"]]
    details["latest_accepted"] = ({"title": w["latest_accepted"]["title"], "accepted_at": w["latest_accepted"]["accepted_at"]}
                                  if w["latest_accepted"] else None)
    fields = []
    milestones = _choices(w["milestones"])
    select_milestone = _field("milestone", "Milestone", "select", required=True, choices=milestones)
    if operation == "details":
        fields = [_field("outcome", "Outcome", "textarea", value=w["outcome"], max_length=6000),
                  _field("criteria", "Acceptance criteria, one per line", "textarea", value="\n".join(w["criteria"]), max_length=12000),
                  _field("labels", "Labels, one per line", "textarea", value="\n".join(w["labels"]), max_length=1600),
                  _field("default_view", "Project default view", "select", value=w["default_view"],
                         choices=[{"value": view, "label": view.capitalize()} for view in ("list", "board", "timeline")])]
    elif operation == "milestone":
        fields = [_field("milestone", "Milestone", "select", value="", choices=[{"value": "", "label": "Add a new milestone"}, *milestones]),
                  _field("title", "Milestone name", required=True), _field("due", "Target date (YYYY-MM-DD), optional"),
                  _field("goals", "Linked tasks", "multiselect", value=[], choices=_choices(choices["goals"])),
                  _field("reviews", "Linked fixed reviews", "multiselect", value=[], choices=_choices(choices["reviews"]))]
    elif operation == "reorder":
        fields = [select_milestone, _field("direction", "Presentation order", "select", value="up",
                                         choices=[{"value": "up", "label": "Move up"}, {"value": "down", "label": "Move down"}])]
    elif operation == "dependency":
        fields = [select_milestone, _field("prerequisite", "Planning prerequisite", "select", choices=milestones),
                  _field("required", "Require this planning prerequisite", "boolean", value=True)]
    elif operation == "member":
        fields = [_field("member", "Workspace colleague", "select", choices=[{"value": actor, "label": actor.removeprefix("user:")} for actor in choices.get("members", [])]),
                  _field("allowed", "Share planning metadata with this colleague", "boolean", value=True)]
    elif operation == "context":
        fields = [_field("source", "Current saved source", "select", choices=[
            {"value": "result/" + str(row["id"]), "label": "Saved result: " + row["title"]} for row in choices["goals"] if row["result_available"]] + [
            {"value": "review/" + row["id"], "label": "Fixed review: " + row["title"]} for row in choices["reviews"]])]
    elif operation == "remove_milestone":
        fields = [select_milestone]
    elif operation == "remove_context":
        fields = [_field("reference", "Context reference to remove", "select", choices=[
            {"value": row["reference"], "label": row["title"]} for row in w["context"] if row["reference"]])]
    elif operation == "defaults":
        fields = [_field("action", "Reusable personal structure", "select", choices=[
            {"value": "save_defaults", "label": "Save this structure as my defaults"},
            {"value": "apply_defaults", "label": "Apply my defaults to this empty project structure"}])]
    return Snapshot(digest({"workspace": w, "choices": choices, "defaults": state["defaults"]}),
                    "Current project planning and independently authorized linked sources",
                    "Project planning never grants private task or review access, executes tasks, or changes their execution dependencies.",
                    details, fields, "Only the project owner can change its planning." if operation != "status" and not w["can_edit"] else "")


def preview(request, selection, args, operation):
    project = project_id(selection)
    state = _state(request, selection)
    action, payload, source = operation, {}, None
    if operation == "details":
        payload = {**args, "criteria": [line.strip() for line in args["criteria"].splitlines() if line.strip()],
                   "labels": [line.strip() for line in args["labels"].splitlines() if line.strip()]}
    elif operation == "milestone":
        if any(not value.isdecimal() for value in args["goals"]):
            raise HTTPException(422, "Choose the named tasks offered by the project controls.")
        milestone_id = args["milestone"] or digest({"project": project, "revision": state["workspace"]["revision"], "args": args})[:32]
        payload = {"id": milestone_id, "title": args["title"], "due": args["due"],
                   "goals": [int(value) for value in args["goals"]], "reviews": args["reviews"]}
    elif operation in {"remove_milestone", "reorder", "dependency"}:
        payload = {("id" if key == "milestone" else key): value for key, value in args.items()}
    elif operation in {"member", "remove_context"}:
        payload = args
    elif operation == "context":
        try:
            kind, source_id = args["source"].split("/", 1)
        except ValueError as exc:
            raise HTTPException(422, "Choose a current project source.") from exc
        source = _native(lambda: native.service(request).preview_source(project, kind, source_id))
        if len(source["content"]) > 12000:
            raise HTTPException(422, "This result is too long for the Copilot review. Read and attach the complete source in the project workspace.")
        payload = {"kind": kind, "source_id": source_id, "version": source["version"]}
    elif operation == "defaults":
        action, payload = args["action"], {"defaults_revision": state["defaults"]["revision"]}
    reviewed = _native(lambda: native.prepare(request, project, action, payload))
    changes = reviewed["changes"]
    if source:
        changes = [*changes, {"label": "Exact reviewed source: " + source["title"], "before": "Not attached at this version", "after": source["content"]}]
    return Preview(reviewed["summary"], changes,
                   {"action": action, "payload": payload, "expected_revision": reviewed["revision"]})


def execute(request, selection, args, prepared, operation_id):
    result = _native(lambda: native.execute(request, project_id(selection), native.ChangeIn(**prepared, operation_id=operation_id, confirmed=True)))
    return Outcome(result["status"], "The reviewed project planning change is saved. Private source and execution permissions are unchanged.",
                   {"project": result["workspace"]["name"], "outcome": result["workspace"]["outcome"]})


def recover(request, selection, args, prepared, operation_id):
    if _native(lambda: native.service(request).receipt(project_id(selection), operation_id, prepared["action"], prepared["payload"], prepared["expected_revision"])):
        return Outcome("replayed", "This exact project planning change was already saved. Open the project workspace for current status.")
    return None


def entries():
    pages = ("/project-workspaces/*", "/projects/*")
    adapters = [Adapter("projects.status", "Show project outcome and milestones", "reviews", "/project-workspaces", pages,
                        EmptyInput, lambda request, selection: replace(snapshot(request, selection), fields=[]),
                        lambda request, selection, args: Preview("Current authorized project planning; no change was made.", native=snapshot(request, selection).details))]
    definitions = (("details", "Change project outcome", DetailsIn), ("milestone", "Add or edit a project milestone", MilestoneIn),
                   ("reorder", "Reorder project milestones", ReorderIn), ("dependency", "Change a planning prerequisite", DependencyIn),
                   ("member", "Change project planning access", MemberIn), ("context", "Review and attach project context", SourceIn),
                   ("remove_milestone", "Remove a project milestone", RemoveMilestoneIn), ("remove_context", "Remove project context", RemoveContextIn),
                   ("defaults", "Save or apply my project defaults", DefaultsIn))
    for operation, label, model in definitions:
        adapters.append(Adapter("projects." + operation, label, "reviews", "/project-workspaces", pages, model,
                                lambda request, selection, operation=operation: snapshot(request, selection, operation),
                                lambda request, selection, args, operation=operation: preview(request, selection, args, operation), execute, recover))
    return tuple(adapters)
