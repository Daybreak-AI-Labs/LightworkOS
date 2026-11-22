"""The legal department's direct controls and Copilot share one service boundary."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from maverick.legal_workforce_catalog import ROLES
from maverick.legal_workspace_models import OPERATIONS
from pydantic import Field

from . import legal_workspace_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGE = "/legal"
LINKS = {"source_id": "sources", "source_ids": "sources", "contract_id": "contracts",
         "assignment_id": "assignments", "obligation_id": "obligations", "engagement_id": "engagements",
         "invoice_id": "invoices", "decision_id": "decisions"}


class ExportInput(StrictInput):
    packet_id: str = Field(default="", max_length=80)


def export_snapshot(request, selection):
    row = native.call(lambda: selected(request, selection))
    return Snapshot(digest({"authority": native.context(request), "matter": row}),
                    "Current authorized matter and prepared counsel packets", "Choose the record to download.",
                    fields=[{"name": "packet_id", "label": "Record", "kind": "select", "value": "", "choices": [
                        {"value": "", "label": "Full matter record (includes internal work)"},
                        *({"value": entry["id"], "label": entry["title"]} for entry in row["packets"])]}])


def export_prepare(request, selection, arguments):
    from urllib.parse import quote
    row = native.call(lambda: selected(request, selection))
    native.call(lambda: native.service(request).export(row["id"], arguments["packet_id"]))
    url = "/api/v1/legal/matters/" + quote(row["id"], safe="") + "/export"
    if arguments["packet_id"]:
        url += "?packet_id=" + quote(arguments["packet_id"], safe="")
    return Preview("Download the selected record. Current matter access is checked again when opening the link.",
                   native={"Download": {"label": "Download legal record", "href": url}})


def fields_for(action, row, members):
    schema = OPERATIONS[action][1].model_json_schema()
    fields = []
    for name, prop in schema["properties"].items():
        field = {"name": name, "label": prop.get("title", name), "required": name in schema.get("required", []),
                 "value": prop.get("default", ""), "max_length": prop.get("maxLength", 4000)}
        if name in LINKS:
            field.update(kind="multiselect" if prop["type"] == "array" else "select",
                         choices=[{"value": entry["id"], "label": entry.get("title", entry.get("firm", entry.get("reference", "Record")))}
                                  for entry in (row or {}).get(LINKS[name], [])])
            if prop["type"] == "array":
                field.update(value=[], presentation="checkboxes", max_selections=prop.get("maxItems", 20))
            elif not field["required"]:
                field["choices"].insert(0, {"value": "", "label": "No related contract"})
        elif name == "role_id":
            field.update(kind="select", choices=[{"value": role["id"], "label": role["title"]} for role in ROLES])
        elif name == "principal":
            choices = {entry["value"]: entry for entry in members}
            for member in (row or {}).get("members", []):
                choices.setdefault(member, {"value": member, "label": member.removeprefix("user:")})
            field.update(kind="select", choices=list(choices.values()))
        elif "enum" in prop:
            field.update(kind="select", choices=[{"value": value, "label": value.replace("_", " ").capitalize()} for value in prop["enum"]])
        elif prop["type"] == "boolean":
            field["kind"] = "boolean"
        elif prop["type"] in {"integer", "number"}:
            field.update(kind="number", minimum=prop.get("minimum", 0), maximum=prop.get("maximum"), integer=prop["type"] == "integer")
        else:
            field["kind"] = "textarea" if prop.get("maxLength", 0) > 500 else "text"
        if action == "edit_matter" and row and name in row:
            field["value"] = row[name]
        fields.append(field)
    return fields


def selected(request, selection):
    if selection.get("kind") != "legal_matter" or not selection.get("id"):
        raise HTTPException(409, "Select a matter in Legal before opening its controls.")
    return native.service(request).get(selection["id"])


def snapshot_for(action):
    def snapshot(request, selection):
        row = None if action == "create_matter" else native.call(lambda: selected(request, selection))
        authority = native.context(request)
        return Snapshot(digest({"authority": authority, "matter": row}),
                        "Current authorized legal matter and selected records", native.BOUNDARY,
                        {"Matter": row["title"]} if row else {}, fields_for(action, row, native.member_choices(request)))
    return snapshot


def prepare_for(action):
    def prepare(request, selection, arguments):
        row = None if action == "create_matter" else native.call(lambda: selected(request, selection))
        material = native.call(lambda: native.prepare_operation(request, action, arguments, row["id"] if row else ""))
        return Preview(OPERATIONS[action][0],
                       [{"label": key, "after": value} for key, value in native.public_preview(material).items()], material)
    return prepare


def execute(request, _selection, _arguments, material, operation_id):
    row = native.call(lambda: native.execute_operation(request, material, operation_id))
    return Outcome("confirmed", "Legal work recorded.", {"Matter": row["title"], "State": row["status"],
                   "Next step": {"label": "Open matter", "href": PAGE + "#" + row["id"]}})


def recover(request, _selection, _arguments, material, operation_id):
    row = native.call(lambda: native.recover_operation(request, material, operation_id))
    return Outcome("replayed", "The original operation is recorded.", {"Matter": row["title"]}) if row else None


def status_snapshot(request, _selection):
    view = native.call(lambda: native.service(request).overview())
    return Snapshot(digest({"view": view, "authority": native.context(request)}),
                    "Your currently accessible legal matters", "Read legal workload, review queues and outside counsel spend.", view)


def status_prepare(request, selection, _arguments):
    details = status_snapshot(request, selection).details
    if selection.get("kind") == "legal_matter":
        details["selected_matter"] = native.call(lambda: selected(request, selection))
    return Preview("Current legal records; nothing changed.", native=details)


def entries():
    return (Adapter("legal.status", "Read legal matters, workers and oversight", "tasks", PAGE, (PAGE,),
                    EmptyInput, status_snapshot, status_prepare),
            Adapter("legal.export", "Download a matter or counsel packet", "tasks", PAGE, (PAGE,),
                    ExportInput, export_snapshot, export_prepare),
            *(Adapter("legal." + action, label, "tasks", PAGE, (PAGE,), model, snapshot_for(action),
                      prepare_for(action), execute, recover, read_recovery=recover, review_max_bytes=1000000)
              for action, (label, model) in OPERATIONS.items()))
