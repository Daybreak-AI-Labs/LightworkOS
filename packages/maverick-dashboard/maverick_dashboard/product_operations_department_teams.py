"""Named department team previews, native saves and exact original receipts."""
from __future__ import annotations

from pydantic import Field

from . import auth
from . import department_team_updates as native
from .department_team_updates_api import public_receipt
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class TeamInput(StrictInput):
    department: str = Field(min_length=1, max_length=80)


def snapshot(request, selection):
    from maverick.departments import list_departments
    from maverick.governed_operations import digest
    auth.require_permission(request, "operate")
    allowed = auth.caller_suites(request)
    options = [{"value": dept.key, "label": dept.title} for dept in list_departments()
               if allowed is None or dept.key in allowed]
    return Snapshot(digest({"context": native.context(request), "choices": options}),
        "Current permitted departments and native saved teams", "Review the saved team before adding new ready specialists.",
        {"Meaning": "No task is started. Existing manual changes are preserved."},
        [{"name": "department", "label": "Department", "kind": "select", "required": True,
          "value": options[0]["value"] if options else "", "choices": options}],
        "No permitted department is available." if not options else "")


def prepare(request, selection, arguments):
    material, public = native.review(request, arguments["department"])
    changes = [{"label": key, "before": public["Before"], "after": public["After"]} if key == "Saved roster" else
               {"label": key, "after": public[key]} for key in
               ("Saved roster", "New specialists", "Preserved", "Setup still needed", "Older team", "Recovery history", "Meaning")]
    return Preview("Review the complete before and after. This saves team setup only; it starts no tasks.", changes, material)


def execute(request, selection, arguments, material, operation_id):
    accepted, replayed = native.apply(request, material, operation_id)
    value = public_receipt(accepted, replayed=replayed)
    return Outcome(value["status"], value["message"], value["details"])


def recover(request, selection, arguments, material, operation_id):
    accepted = native.receipt(request, material, operation_id)
    if accepted is None:
        return None
    value = public_receipt(accepted, replayed=True)
    return Outcome(value["status"], value["message"], value["details"])


def entries():
    return (Adapter("teams.department.update", "Review and update my department team", "tasks", "/workforce#departments",
                    ("/workforce", "/agents"), TeamInput, snapshot, prepare, execute, recover,
                    aliases=("update my team", "set up my department"), read_recovery=recover),)
