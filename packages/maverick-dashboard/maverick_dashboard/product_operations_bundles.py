"""Bundle controls share the native source, recipient, receipt and CAS contracts."""
from __future__ import annotations

from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from .deliverable_bundles_api import Choices, call, candidates, service
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class CreateInput(StrictInput):
    artifact_ids: list[str] = Field(default_factory=list, max_length=30)
    attachment_ids: list[str] = Field(default_factory=list, max_length=30)
    include_result: bool = False
    name: str = Field(min_length=1, max_length=160)
    recipient: str = Field(min_length=6, max_length=256)
    note: str = Field(min_length=1, max_length=4000)
    unresolved: str = Field(default="", max_length=4000)
    lifetime: Literal["3600", "86400", "604800"] = "86400"


class DecisionInput(StrictInput):
    action: Literal["accept", "revoke"]
    note: str = Field(default="", max_length=4000)


def _goal(selection):
    value = selection.get("goal_id", selection.get("id"))
    if selection.get("kind") != "goal" or type(value) is not int or value < 1:
        raise HTTPException(404, "Open your task's selected bundle preparation first.")
    return value


def _bundle(selection):
    value = selection.get("id")
    if selection.get("kind") != "bundle" or not isinstance(value, str):
        raise HTTPException(404, "Open a shared bundle first.")
    return value


def _choices(args):
    values = dict(args)
    for name in ("artifact_ids", "attachment_ids"):
        if any(not value.isdecimal() or not value.isascii() for value in values[name]):
            raise HTTPException(422, "Choose available named evidence from the list.")
        values[name] = [int(value) for value in values[name]]
    values["lifetime"] = int(values["lifetime"])
    return Choices.model_validate(values).model_dump()


def create_snapshot(request, selection):
    import json

    auth.require_permission(request, "operate")
    value = json.loads(candidates(request, _goal(selection)).body)
    source = value["source"]
    metadata = {**source, "result": digest(source["result"]), "recipients": value["recipients"]}
    return Snapshot(digest(metadata), "Your task's current artifact versions, evidence files and eligible workspace recipients",
                    "Share an exact selected copy with one named colleague. No task, conversation or credential authority is shared.",
                    {"title": source["title"], "status": source["status"]},
                    [{"name": "name", "label": "Bundle name", "kind": "text", "required": True, "value": source["title"][:160]},
                     {"name": "recipient", "label": "Recipient", "kind": "select", "required": True,
                      "choices": [{"value": row["id"], "label": row["name"]} for row in value["recipients"]]},
                     {"name": "include_result", "label": "Include saved task result", "kind": "boolean", "value": False},
                     {"name": "artifact_ids", "label": "Selected artifact versions", "kind": "multiselect",
                      "choices": [{"value": str(row["id"]), "label": row["title"] + " · version " + str(row["version"])} for row in source["artifacts"]]},
                     {"name": "attachment_ids", "label": "Selected evidence files", "kind": "multiselect",
                      "choices": [{"value": str(row["id"]), "label": row["title"]} for row in source["attachments"]]},
                     {"name": "note", "label": "Recipient's job", "kind": "textarea", "required": True},
                     {"name": "unresolved", "label": "Unresolved items and checks", "kind": "textarea", "value": ""},
                     {"name": "lifetime", "label": "Access expires after", "kind": "select", "value": "86400",
                      "choices": [{"value": "3600", "label": "One hour"}, {"value": "86400", "label": "One day"},
                                  {"value": "604800", "label": "Seven days"}]}],
                    "No eligible recipients are available in this workspace." if not value["recipients"] else "")


def create_preview(request, selection, args):
    auth.require_permission(request, "operate")
    source = service(request)
    prepared = call(lambda: source.prepare(_goal(selection), **_choices(args)))
    return Preview("Share only these captured files with the named recipient. Downloaded copies cannot be recalled. Human acceptance and external submission have not occurred.",
                   [{"label": "Recipient", "after": prepared["recipient"]},
                    {"label": "Selected items", "after": [{"title": item["title"], "source": item["source"], "bytes": item["bytes"]} for item in prepared["items"]]},
                    {"label": "Recipient's job", "after": prepared["note"]},
                    {"label": "Source warnings", "after": prepared["source_warnings"]},
                    {"label": "Unresolved items", "after": prepared["unresolved"]}],
                   {"expected_review": prepared["review_version"]})


def create_execute(request, selection, args, native, operation_id):
    auth.require_permission(request, "operate")
    source = service(request)
    record = call(lambda: source.create(_goal(selection), expected_review=native["expected_review"],
                                       operation_id=operation_id, **_choices(args)))
    return Outcome("confirmed", "The selected bundle was shared. No human acceptance or external submission was performed.",
                   {"bundle_id": record["id"], "name": record["payload"]["name"], "href": "/deliverable-bundles"})


def create_recover(request, selection, args, native, operation_id):
    source = service(request)
    identifier = "DLB-" + digest([source.actor, operation_id])[:32]
    if source.store.get(identifier) is None:
        return None
    result = create_execute(request, selection, args, native, operation_id)
    return Outcome("replayed", result.message, result.details)


def bundle_snapshot(request, selection):
    source = service(request)
    row = call(lambda: source.get(_bundle(selection)))
    choices = []
    if row["can_accept"]:
        choices.append({"value": "accept", "label": "Accept this captured bundle"})
    if row["can_revoke"]:
        choices.append({"value": "revoke", "label": "End future recipient access"})
    return Snapshot(digest([row["revision"], row["stale"], row["can_accept"], row["can_revoke"]]),
                    "Current selected bundle, recipient access and source freshness", row["payload"]["name"],
                    {"name": row["payload"]["name"], "stale": row["stale"], "acceptance_current": row["acceptance_current"],
                     "items": [{"title": item["title"], "source": item["source"]} for item in row["payload"]["items"]]},
                    [{"name": "action", "label": "Response", "kind": "select", "choices": choices, "required": True},
                     {"name": "note", "label": "Human acceptance and limitations", "kind": "textarea", "value": ""}],
                    "No response is available for this bundle and your current authority." if not choices else "")


def decision_preview(request, selection, args):
    source = service(request)
    row = call(lambda: source.get(_bundle(selection)))
    allowed = row["can_accept"] if args["action"] == "accept" else row["can_revoke"]
    if not allowed or args["action"] == "accept" and not args["note"].strip():
        raise HTTPException(409, "Choose a currently permitted response and enter your human review comment.")
    return Preview("Record human acceptance for the exact captured version." if args["action"] == "accept" else
                   "End future recipient access. Copies they previously downloaded cannot be recalled.",
                   [{"label": "Bundle", "after": row["payload"]["name"]}, {"label": "Comment", "after": args["note"]}],
                   {"expected_revision": row["revision"]})


def decision_execute(request, selection, args, native, operation_id):
    auth.require_permission(request, "operate")
    source = service(request)
    row = call(lambda: source.respond(_bundle(selection), expected_revision=native["expected_revision"],
                                     operation_id=operation_id, **args))
    return Outcome("confirmed", "Your bundle response was recorded. No execution or external submission was performed.",
                   {"status": row["status"], "acceptance_current": row["acceptance_current"], "href": "/deliverable-bundles"})


def decision_recover(request, selection, args, native, operation_id):
    source = service(request)
    call(lambda: source.get(_bundle(selection)))
    record = source.store.get(_bundle(selection))
    if operation_id not in record.get("operations", {}):
        return None
    result = decision_execute(request, selection, args, native, operation_id)
    return Outcome("replayed", result.message, result.details)


def download_preview(request, selection, args):
    source = service(request)
    row = call(lambda: source.get(_bundle(selection)))
    return Preview("Download the selected files and offline verification manifest from the bundle screen. Download rechecks current access and source freshness.",
                   [{"label": "Bundle", "after": row["payload"]["name"]},
                    {"label": "Download selected bundle and offline manifest", "href": "/api/v1/deliverable-bundles/" + row["id"] + "/export"}])


def download_snapshot(request, selection):
    return replace(bundle_snapshot(request, selection), fields=[], blocked="")


def entries():
    return (
        Adapter("artifacts.share_bundle", "Share selected deliverables", "artifacts", "/deliverable-bundles",
                ("/deliverable-bundles", "/chat/goal/*"), CreateInput,
                create_snapshot, create_preview, create_execute, create_recover),
        Adapter("artifacts.respond_bundle", "Accept or revoke a selected bundle", "artifacts", "/deliverable-bundles",
                ("/deliverable-bundles",), DecisionInput,
                bundle_snapshot, decision_preview, decision_execute, decision_recover),
        Adapter("artifacts.bundle_download", "Prepare an offline bundle download", "artifacts", "/deliverable-bundles",
                ("/deliverable-bundles",), EmptyInput,
                download_snapshot, download_preview),
    )
