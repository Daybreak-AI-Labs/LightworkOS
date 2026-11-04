"""Protected Copilot erasure uses the same complete native review as Workspaces."""
from pydantic import Field

from . import workspace_erasure as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ChooseInput(StrictInput):
    workspace: str = Field(min_length=1, max_length=200)
    acknowledge_previous: bool = False


def snapshot(request, selection):
    value = native.inventory(request)
    choices = [{"value": row["id"], "label": row["display_name"]} for row in value["workspaces"]]
    return Snapshot(value["revision"], "Current removed workspaces on this installation",
                    "Review irreversible local erasure of one already removed workspace. Backups and external copies are separate.",
                    fields=[{"name": "workspace", "label": "Removed workspace", "kind": "select", "required": True, "choices": choices},
                            {"name": "acknowledge_previous", "label": "I understand that an earlier unconfirmed erasure may already have erased records and want separately reviewed cleanup", "kind": "boolean", "value": False}],
                    blocked="There are no removed workspaces to review." if not choices else "")


def prepare(request, selection, arguments):
    value = native.prepare(request, arguments["workspace"], arguments["acknowledge_previous"])
    return Preview("Review every consequence before permanently erasing the selected local workspace records.",
                   value["changes"], {"token": value["token"]})


def execute(request, selection, arguments, prepared, operation_id):
    value = native.apply(request, prepared["token"], True)
    return Outcome(value["status"], value["message"], value)


def recover(request, selection, arguments, prepared, operation_id):
    value = native.original(request, prepared["token"])
    # A missing original is not a result and must not suppress first admission;
    # an existing unknown original has retained started_at and never replays.
    if "started_at" not in value:
        return None
    return Outcome(value["status"], value["message"], value)


def read_recovery(request, selection, arguments, prepared, operation_id):
    value = native.original(request, prepared["token"])
    return Outcome(value["status"], value["message"], value)


def status_prepare(request, selection, arguments):
    value = native.inventory(request)
    return Preview(f"{len(value['workspaces'])} removed workspaces. Open Workspaces to restore retained records or read saved erasure results.",
                   native={"href": "/tenants#removed-workspaces", "label": "Open removed workspaces"})


class OriginalInput(StrictInput):
    workspace: str = Field(min_length=1, max_length=200)
    operation: str = Field(pattern=r"^[a-f0-9]{48}$")


def original_snapshot(request, selection):
    state = native.inventory(request)
    histories = {row["id"]: native.history(request, row["id"])["originals"] for row in state["workspaces"]}
    fields = [
        {"name": "workspace", "label": "Removed workspace", "kind": "select", "required": True,
         "choices": [{"value": row["id"], "label": row["display_name"]} for row in state["workspaces"]]},
        {"name": "operation", "label": "Original erasure", "kind": "select", "required": True,
         "depends_on": "workspace", "choices_by": {key: [
             {"value": row["operation"], "label": _original_label(row)} for row in rows]
             for key, rows in histories.items()}},
    ]
    from maverick.governed_operations import digest
    return Snapshot(digest([state, histories]), "Exact owned original erasure metadata",
                    "Read one original result. No records are erased and no previous attempt repeats.", fields=fields)


def _original_label(row):
    from datetime import datetime, timezone
    when = datetime.fromtimestamp(row["started_at"], timezone.utc).strftime("%B %d, %Y at %H:%M:%S UTC")
    return when + (" · Local records erased" if row["status"] == "confirmed" else " · Result unconfirmed")


def original_prepare(request, selection, arguments):
    value = native.original_by_id(request, arguments["workspace"], arguments["operation"])
    return Preview(value["message"], native={"Started": _original_label(value), "Files selected": value["files"],
                                           "Folders selected": value["folders"], "Bytes selected": value["bytes"],
                                           "href": "/tenants#removed-workspaces", "label": "Open removed workspaces"})


def entries():
    pages = ("/tenants",)
    return (
        Adapter("workspaces.erase", "Erase a removed workspace", "preferences", "/tenants#removed-workspaces", pages,
                ChooseInput, snapshot, prepare, execute, recover, read_recovery=read_recovery,
                aliases=("erase removed workspace",)),
        Adapter("workspaces.erasure_status", "Show removed workspace recovery", "preferences", "/tenants#removed-workspaces", pages,
                EmptyInput, lambda request, selection: Snapshot(native.inventory(request)["revision"],
                    "Current removed workspace metadata", "Open the native recovery controls."), status_prepare),
        Adapter("workspaces.erasure_original", "Read an original workspace erasure", "preferences", "/tenants#removed-workspaces", pages,
                OriginalInput, original_snapshot, original_prepare),
    )
