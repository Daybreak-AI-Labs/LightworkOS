"""Copilot adapters reuse the native administrator plugin workbench."""
from __future__ import annotations

import json

from fastapi import HTTPException
from maverick import plugin_workbench as workbench
from maverick.governed_operations import digest
from pydantic import Field

from . import plugin_practice_forms_api as practice
from . import plugin_workbench_api as native
from .draft_api import context_for
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class StatusInput(StrictInput):
    fingerprint: str = Field(default="", pattern=r"^([a-f0-9]{64})?$")


def state(request):
    native._authority(request)
    from maverick import plugins

    context = context_for(request)
    rows = workbench.snapshot()
    entries = {(group, entry.name, plugins._ep_dist_name(entry) or ""): entry
               for group in plugins._PLUGIN_GROUPS for entry in plugins._entry_points(group)}
    for row in rows:
        entry = entries.get((row["group"], row["name"], row["distribution"]))
        if entry is not None:
            row["compatibility_reason"] = plugins._entry_compatibility_error(entry)
    return {"context": context, "plugins": rows, **workbench.history(context)}


def snapshot(request, selection, kind="status"):
    value = state(request)
    choices = [{"value": row["fingerprint"], "label": row["name"] + " / " + row["version"]}
               for row in value["plugins"] if row["eligible"]]
    fields = []
    if kind == "status":
        fields.append({"name": "fingerprint", "label": "Add-on to check", "kind": "select", "value": "",
                       "choices": [{"value": "", "label": "All add-ons — summary"}]
                       + [{"value": row["fingerprint"], "label": row["name"] + " / " + row["version"]}
                          for row in value["plugins"]]})
    if kind in {"check", "inspect", "publish", "migrate"}:
        fields.append({"name": "fingerprint", "label": "Exact plugin version", "kind": "select", "choices": choices, "required": True})
    if kind == "publish":
        fields.append({"name": "rollback", "label": "Affected-work review and rollback plan", "kind": "textarea", "required": True})
    if kind == "cancel":
        fields.append({"name": "check_id", "label": "Recorded check", "kind": "select", "required": True,
            "choices": [{"value": row["id"], "label": row["plugin"] + " / " + row["state"]} for row in value["checks"]]})
    if kind == "migrate":
        value["pins"] = migration_pins(request)
        fields.append({"name": "pin", "label": "Stopped task or workflow pin", "kind": "select", "required": True,
            "choices": [{"value": item["id"], "label": item["label"]} for item in value["pins"]]})
    return Snapshot(digest(value), "Plugin qualification ledger", "Readiness is restricted-container evidence; no live capability is accepted.",
        details=value, fields=fields, blocked="No eligible installed plugin is available." if kind in {"check", "inspect", "publish", "migrate"} and not choices else "")


class CheckInput(StrictInput):
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class PublishInput(StrictInput):
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    rollback: str = Field(min_length=10, max_length=2000)


class CancelInput(StrictInput):
    check_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class MigrateInput(StrictInput):
    pin: str = Field(pattern=r"^[a-f0-9]{64}$")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


def migration_pins(request):
    dependencies = native._dependencies(request)
    result = []
    for kind, rows in (("task", dependencies["tasks"]), ("flow", dependencies.get("runs", []))):
        for row in rows:
            identity = {"kind": kind, "record": row["goal_id"] if kind == "task" else row["run_id"],
                        "distribution": row["distribution"], "name": row["name"], "previous": row["fingerprint"]}
            result.append({**identity, "id": digest(identity), "state": row["state"],
                           "label": ("Task: " if kind == "task" else "Workflow: ") + row["title"] + " / " + row["name"] + " / " + row["state"],
                           "title": row["title"], "version_recorded_at": row.get("updated_at")})
    return result


def prepare(request, selection, arguments):
    value = state(request)
    changes = []
    if "fingerprint" in arguments:
        selected = workbench.selected(arguments["fingerprint"])
        changes.extend([{"label": "Selected plugin", "after": selected["name"]},
                        {"label": "Installed version", "after": selected["version"]},
                        {"label": "Publisher package", "after": selected["distribution"]},
                        {"label": "Qualification scope", "after": selected["scope"]}])
    if "sample_json" in arguments:
        try:
            sample, expected = json.loads(arguments["sample_json"]), json.loads(arguments["expected_json"])
            if type(sample) is not dict:
                raise ValueError
            json.dumps([sample, expected], allow_nan=False)
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, "Use valid finite JSON and an object input. No check started.") from exc
        changes.extend([{"label": "Check", "after": {"sample": "Run the practice input and compare its answer",
                        "timeout": "Observe whether the bounded check stops on time",
                        "cancellation": "Observe whether the bounded check stops when cancelled"}[arguments["mode"]]},
                        {"label": "Complete practice input", "after": json.dumps(sample, ensure_ascii=False, indent=2, allow_nan=False)},
                        {"label": "Exact expected answer", "after": json.dumps(expected, ensure_ascii=False, indent=2, allow_nan=False)}])
    if "rollback" in arguments:
        changes.extend([{"label": "Action", "after": "Publish readiness for the reviewed restricted checks only"},
                        {"label": "Affected work and restoration plan", "after": arguments["rollback"]}])
    if "check_id" in arguments:
        check_row = next((row for row in value["checks"] if row["id"] == arguments["check_id"]), None)
        if check_row is None:
            raise HTTPException(404, "Choose a saved check from your current qualification history.")
        changes.extend([{"label": "Selected check", "after": check_row["plugin"] + " / " + check_row["version"]},
                        {"label": "Check type", "after": check_row["mode"].capitalize()},
                        {"label": "Current result", "after": check_row["state"].replace("_", " ")},
                        {"label": "Action", "after": "Request cancellation; verify the original check's cleanup and outcome"}])
    prepared = {"context": value["context"]}
    if "pin" in arguments:
        pin = next((item for item in migration_pins(request) if item["id"] == arguments["pin"]), None)
        if pin is None or pin["distribution"] != selected["distribution"] or pin["name"] != selected.get("pin_name", selected["name"]):
            raise HTTPException(409, "Select an owned pin for this exact plugin before reviewing migration.")
        prepared["pin"] = pin
        prepared["new_content"] = selected["content_sha256"]
        changes.extend([{"label": "Selected stopped work", "after": pin["label"]},
                        {"label": "Current work status", "after": pin["state"].replace("_", " ")},
                        {"label": "Version change", "before": "The exact version already recorded for this work",
                         "after": selected["name"] + " / " + selected["version"]},
                        {"label": "What happens next", "after": "Only this selected work's plugin version changes. No task resumes and no previous action repeats."}])
    return Preview("Review this exact plugin operation. Network, credentials and host writes remain unavailable; nothing installs, resumes or replays work.",
                   changes=changes, native=prepared)


def status_prepare(request, selection, arguments):
    value = state(request)
    rows = value["plugins"]
    details = {"Add-ons found": len(rows), "Compatibility refusals": sum(bool(row.get("compatibility_reason")) for row in rows),
               "Policy allows use": sum(bool(row.get("policy_allowed")) for row in rows),
               "Ready for guided practice": sum(bool(row.get("eligible")) for row in rows),
               "Saved practice checks": len(value["checks"]), "href": "/plugins"}
    if arguments.get("fingerprint"):
        row = next((row for row in rows if row["fingerprint"] == arguments["fingerprint"]), None)
        if row is None:
            raise ValueError("This add-on changed. Refresh the list before checking it again.")
        details.update({"Add-on": row["name"], "Version": row["version"],
                        "Compatibility reason": row.get("compatibility_reason") or "No compatibility refusal is recorded for this entry.",
                        "Use": "Current policy allows it" if row.get("policy_allowed") else "Blocked by current policy",
                        "Practice": "Ready for a guided check" if row.get("eligible") else "Not ready for a guided check"})
    return Preview("Current add-on compatibility and saved practice checks. No add-on code was run.",
                   native=details)


def recover_check(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    row = next((item for item in workbench.history(prepared["context"])["checks"] if item["id"] == operation), None)
    if row is not None:
        return Outcome("replayed", "Existing check receipt recovered; execution was not repeated.", row)
    return None


def inspect_prepare(request, selection, arguments):
    selected = workbench.selected(arguments["fingerprint"])
    native._authority(request)
    return Preview("Read this exact plugin's practice questions once inside the already installed reviewed restricted image. No tool action, network, credentials, host writes or downloads are permitted. Reading questions does not qualify this plugin.",
                   changes=[{"label": "Selected plugin", "after": selected["name"]},
                            {"label": "Installed version", "after": selected["version"]},
                            {"label": "Action", "after": "Read ordinary practice questions without invoking an action"}],
                   native={"context": context_for(request)})


def _inspection_outcome(row, fingerprint, status):
    details = {"plugin": row["plugin"], "version": row["version"], "notice": row["notice"]}
    if row["state"] == "ready":
        details["plugin_practice_page"] = {"fingerprint": fingerprint, "receipt": row["receipt"]}
    return Outcome(status if row["state"] == "ready" else "unconfirmed", row["notice"], details)


def inspect_execute(request, selection, arguments, prepared, operation):
    row = practice.inspect_current(request, practice.InspectIn(context=prepared["context"], fingerprint=arguments["fingerprint"],
                                                              operation_id=operation, confirm=True))
    return _inspection_outcome(row, arguments["fingerprint"], "confirmed")


def inspect_recover(request, selection, arguments, prepared, operation):
    from maverick import plugin_practice_forms

    native._authority(request, prepared["context"])
    try:
        row = practice.project(plugin_practice_forms.read_contract(prepared["context"], operation, fingerprint=arguments["fingerprint"],
                               authorize=lambda: native._authority(request, prepared["context"])))
    except LookupError:
        return None
    except (ValueError, PermissionError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return _inspection_outcome(row, arguments["fingerprint"], "replayed")


def guided_prepare(request, selection, arguments):
    row = practice.current(request, arguments["fingerprint"])
    if row["state"] != "ready":
        raise HTTPException(409, row["notice"] + " Choose Read a plugin's practice questions first.")
    return Preview("Open this exact inspected plugin's ordinary questions and expected-answer controls. Complete its named fields and review the full practice answers before explicitly running a restricted check. No check starts from this handoff.",
                   native={"plugin_practice_page": {"fingerprint": arguments["fingerprint"], "receipt": row["receipt"]}})


def check(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    recovered = recover_check(request, selection, arguments, prepared, operation)
    if recovered:
        return recovered
    row = workbench.run_check(prepared["context"], operation, arguments["fingerprint"],
        json.loads(arguments["sample_json"]), arguments["mode"],
        expected=json.loads(arguments["expected_json"]), authorize=lambda: native._authority(request, prepared["context"]))
    return Outcome("confirmed" if row["state"] == "passed_scoped_check" else "unconfirmed", "Check recorded. Review the observed completion/interruption and cleanup evidence.", row)


def recover_publish(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    row = next((item for item in workbench.history(prepared["context"])["publications"] if item.get("operation_id") == operation), None)
    return Outcome("replayed", "Existing scoped publication recovered without another change.", row) if row else None


def publish(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    row = workbench.publish(prepared["context"], arguments["fingerprint"], arguments["rollback"], operation=operation,
        authorize=lambda: native._authority(request, prepared["context"]))
    return Outcome("confirmed", "Scoped readiness published; no plugin was installed and no task migrated.", row)


def cancel(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    row = workbench.cancel(prepared["context"], arguments["check_id"])
    return Outcome("confirmed", "Cancellation request recorded. Check the ledger for verified cleanup and the final outcome.", row)


def recover_migration(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    # Inventory performs the same exact task/run ownership checks as the page.
    dependencies = native._dependencies(request)
    reviewed = prepared["pin"]
    rows = dependencies["tasks"] if reviewed["kind"] == "task" else dependencies.get("runs", [])
    for row in rows:
        record = row.get("goal_id") if reviewed["kind"] == "task" else row.get("run_id")
        if (record == reviewed["record"] and row["distribution"] == reviewed["distribution"] and row["name"] == reviewed["name"]
                and row.get("migration_operations", {}).get(operation) == {"previous": reviewed["previous"], "current": prepared["new_content"]}):
            return Outcome("replayed", "This exact version migration was already recorded. No task was resumed or historical action replayed.", {"migrated": True})
    return None


def migrate(request, selection, arguments, prepared, operation):
    native._authority(request, prepared["context"])
    recovered = recover_migration(request, selection, arguments, prepared, operation)
    if recovered:
        return recovered
    pin = prepared["pin"]
    options = {"context": prepared["context"], "fingerprint": arguments["fingerprint"],
               "previous": pin["previous"], "operation_id": operation, "confirm": True}
    if pin["kind"] == "task":
        result = native.migrate_plugin_pin(request, native.MigrateIn(goal_id=pin["record"], **options))
    else:
        result = native.migrate_flow_plugin_pin(request, native.MigrateFlowIn(run_id=pin["record"], **options))
    return Outcome("confirmed", "Owned stopped-work pin migrated. No work was resumed and no previous effect replayed.", result)


def entries():
    shared = {"family": "plugins", "direct_ui": "/plugins", "pages": ("/plugins",)}
    return (
        Adapter("plugins.status", "Review plugin qualification", input_model=StatusInput, snapshot=snapshot, prepare=status_prepare, **shared),
        Adapter("plugins.inspect", "Read a plugin's practice questions", input_model=CheckInput,
                snapshot=lambda r, s: snapshot(r, s, "inspect"), prepare=inspect_prepare, execute=inspect_execute, recover=inspect_recover, read_recovery=inspect_recover, **shared),
        Adapter("plugins.check", "Open a guided plugin practice check", input_model=CheckInput,
                snapshot=lambda r, s: snapshot(r, s, "check"), prepare=guided_prepare, **shared),
        Adapter("plugins.publish", "Publish scoped plugin readiness", input_model=PublishInput,
                snapshot=lambda r, s: snapshot(r, s, "publish"), prepare=prepare, execute=publish, recover=recover_publish, **shared),
        Adapter("plugins.migrate", "Migrate a stopped-work plugin pin", input_model=MigrateInput,
                snapshot=lambda r, s: snapshot(r, s, "migrate"), prepare=prepare, execute=migrate, recover=recover_migration, **shared),
        Adapter("plugins.cancel", "Cancel a recorded plugin check", input_model=CancelInput,
                snapshot=lambda r, s: snapshot(r, s, "cancel"), prepare=prepare, execute=cancel, **shared),
    )
