"""My Data native journeys through the same closed, reviewed Copilot registry."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import HTTPException
from pydantic import Field

from . import auth
from . import personal_data_api as native
from . import personal_data_exports as exports
from . import personal_data_requests as deletion
from .identity_format import humanize_principal
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput
from .product_operations_identity import _choices, _field


class Channel(StrictInput):
    channel: str = Field(min_length=1, max_length=32)


class Identity(StrictInput):
    identity_id: str = Field(min_length=1, max_length=64)


class Scope(StrictInput):
    scope_id: str = Field(min_length=1, max_length=64)


class Recall(Scope):
    recall: bool


class NoteRef(Scope):
    note_id: str = Field(pattern=r"^[a-f0-9]{64}$")


class Note(NoteRef):
    operation: Literal["edit", "delete", "suppress"]
    replacement: str = Field(default="", max_length=160)


class Share(StrictInput):
    source_id: str = Field(min_length=1, max_length=64)


class Task(StrictInput):
    goal_id: int = Field(gt=0)


class Delete(Scope):
    stores: list[str] = Field(min_length=1, max_length=20)


class Review(StrictInput):
    request_id: str = Field(min_length=5, max_length=100)
    external_holds_clear: Literal[True]


class AccountExport(StrictInput):
    store: Literal["model_test_history", "conversation_inbox", "saved_views_and_pins"]


def _authority(request, *, write=False):
    actor = native._actor(request)
    if write:
        native._app()._require_same_origin(request)
    return actor


def _scope(state, identifier):
    result = next((row for row in state["scopes"] if row["id"] == identifier), None)
    if result is None:
        raise HTTPException(404, "Choose a currently verified personal scope.")
    return result


def _requests(request):
    actor = _authority(request)
    reviewer = auth.has_permission(request, "admin")
    return deletion.list_requests(actor, reviewer=reviewer), reviewer


def _review(request, identifier):
    actor = _authority(request)
    auth.require_permission(request, "admin")
    row = deletion.STORE.get(identifier)
    if row is None:
        raise HTTPException(404, "This deletion request is unavailable.")
    if row["owner"] == actor:
        raise HTTPException(403, "A different current administrator must review your deletion request.")
    if row["status"] not in {"requested", "held"}:
        raise HTTPException(409, "This request was dispatched already. Review its saved per-store outcomes; do not repeat deletion.")
    return row


def _scope_fields(state):
    return [_field("scope_id", "Verified personal scope", "select", choices=_choices((row["id"], row["channel"]) for row in state["scopes"]))]


def _fields(state, action, requests):
    if action == "link_begin":
        return [_field("channel", "Authenticated channel", "select", choices=_choices((v, v) for v in state["identity"]["channels"]))]
    if action in {"link_confirm", "link_unlink"}:
        rows = state["identity"]["challenges" if action == "link_confirm" else "links"]
        rows = [r for r in rows if action != "link_confirm" or r["status"] == "proof_received"]
        return [_field("identity_id", "Exact proved sender" if action == "link_confirm" else "Linked identity", "select",
                       choices=_choices((r["id"], r["channel"] + ": " + str(r.get("sender_id", ""))) for r in rows))]
    if action == "recall":
        return _scope_fields(state) + [_field("recall", "Allow personal recall and preference collection in this scope", "boolean", value=False)]
    if action in {"note", "note_source"}:
        fields = _scope_fields(state) + [
            _field("note_id", "Owned note (first 200 in each scope; My data shows all)", "select", depends_on="scope_id",
                   choices_by={r["id"]: _choices((n["id"], n["note"][:160]) for n in r["notes"][:200]) for r in state["scopes"]})]
        if action == "note_source":
            return fields
        return fields + [_field("operation", "Correction", "select", choices=_choices((("edit", "Correct note"), ("delete", "Remove exact note"), ("suppress", "Do not remember this topic again")))),
            _field("replacement", "Corrected preference (required for edit only)", "textarea", required=False)]
    if action == "sharing":
        return [_field("source_id", "One authoritative personal source", "select", choices=_choices([("channel_only", "Keep recall separate in each channel"), *((r["id"], r["channel"]) for r in state["scopes"])]))]
    if action == "exclude_task":
        return [_field("goal_id", "Exact owned task number", "number", min=1)]
    if action == "deletion_request":
        return _scope_fields(state) + [_field("stores", "Stores to request for independently reviewed deletion", "multiselect", choices=_choices((v, v.replace("_", " ")) for v in sorted(deletion.KINDS)))]
    if action == "deletion_review":
        return [_field("request_id", "Employee deletion request", "select", choices=_choices((r["id"], r["id"] + ": " + r["status"]) for r in requests if r["status"] in {"requested", "held"})),
                _field("external_holds_clear", "I independently checked preservation obligations with the records owner", "boolean", value=False)]
    if action == "export_scope":
        return _scope_fields(state)
    if action == "export_account":
        return [_field("store", "Owned account store", "select", choices=_choices((("model_test_history", "Model-test history"), ("conversation_inbox", "Queued messages and human exchanges"), ("saved_views_and_pins", "Saved views and task pins"))))]
    return []


def snapshot(request, _selection, *, action):
    state = native._state(request)
    rows, reviewer = _requests(request)
    actor = _authority(request)
    reviewable = [r for r in rows if r["owner"] != actor] if reviewer else []
    # Exact note/identity versions are sealed by the registry; status details
    # exclude preference text. Native deletion repeats its complete source CAS.
    material = {"state": state, "requests": [{"id": r["id"], "revision": r["revision"], "status": r["status"]} for r in rows]}
    details = {"policy": state["policy"], "scope_count": len(state["scopes"]),
               "requests": material["requests"], "notice": "Personal recall, training restrictions, shared source policy and retained evidence remain distinct."}
    return Snapshot(deletion._digest(material), "Current named owner, verified links, memory controls and deletion requests",
                    "Only current owned scopes are available. Linking does not grant tools; deletion needs a different reviewer and exact preservation checks.",
                    details, _fields(state, action, reviewable),
                    "A current workspace administrator is required for independent deletion review." if action == "deletion_review" and not reviewer else "")


def _identity_prepare(state, args, action):
    identity = state["identity"]
    if action == "link_begin":
        if args["channel"] not in identity["channels"]:
            raise HTTPException(422, "Choose an authenticated supported channel.")
        return Preview("Create a ten-minute private linking command. Send it as yourself to the configured bot, then confirm the authenticated sender here. No sharing or tools are granted.")
    rows = identity["challenges" if action == "link_confirm" else "links"]
    row = next((r for r in rows if r["id"] == args["identity_id"]), None)
    if row is None or action == "link_confirm" and row["status"] != "proof_received":
        raise HTTPException(409, "This exact link or authenticated proof is no longer available.")
    return Preview("Confirm this authenticated identity; personal sharing is still a separate choice." if action == "link_confirm" else "Remove this exact link. Future linked recall and direct notification delivery stop; provider consent and retained records are separate.",
                   [{k: row.get(k) for k in ("channel", "sender_id", "user_id")}], {"revision": identity["revision"]})


def _memory_prepare(state, args, action):
    scope = _scope(state, args["scope_id"])
    data = {"channel": scope["channel"], "user_id": scope["user_id"], "revision": scope["revision"]}
    if action == "recall":
        return Preview("Change personal recall and preference collection for this exact verified scope. This does not remove prior records or unlearn models.", [{"channel": scope["channel"], "recall": args["recall"]}], data)
    row = next((n for n in scope["notes"] if n["id"] == args["note_id"]), None)
    if row is None:
        raise HTTPException(409, "The selected owned note changed. Refresh its current source.")
    if args["operation"] == "edit" and not args["replacement"].strip():
        raise HTTPException(422, "Enter the corrected preference.")
    return Preview("Correct personal recall with a durable suppression rule. Source history and prior training remain separately retained.",
                   [{"note": row["note"], "operation": args["operation"], "replacement": args["replacement"] if args["operation"] == "edit" else ""}], data)


def _deletion_scope(record):
    """Complete human scope; exact source identifiers stay in native receipts."""
    labels = {"preference_notes": "Remembered preferences", "conversation_history": "Conversation history and associated work",
              "recovery_drafts": "Private editor recovery copies", "companion_history": "Employee companion history",
              "experience_preferences": "Personal account and conversation preferences", "model_memory": "Personal model memory",
              "notification_receipts": "Notification delivery history", "diagnostic_reports": "Personal diagnostic reports",
              "activation_drafts": "Private activation drafts", "project_defaults": "Personal project defaults",
              "model_test_history": "Personal model-check history", "generated_tools": "Currently authorized learned tools",
              "conversation_inbox": "Queued messages and human exchanges", "saved_views_and_pins": "Saved views and task pins"}
    targets = []
    for target in record["targets"]:
        kind = target["store"]
        item = {"Information": labels[kind], "Scope": "This exact account's selected " + record["channel"] + " scope"}
        if "count" in target:
            item["Selected items"] = target["count"]
        if "records" in target:
            item["Selected records"] = len(target["records"])
        if "scope" in target:
            item.update({"Conversations": len(target["scope"]["conversation_ids"]),
                         "Associated tasks": len(target["scope"]["goal_ids"]),
                         "Task activity records": len(target["scope"]["episode_ids"])})
        inventory = target.get("inventory", {})
        for key, label in (("saved", "Saved recovery copies"), ("discarded", "Retired recovery copies"),
                           ("files", "History files"), ("consumed_items", "Recorded notification items"),
                           ("pin_count", "Pinned tasks"), ("view_count", "Saved views"), ("blocked", "Items awaiting reconciliation")):
            if key in inventory:
                item[label] = inventory[key]
        if "receipts" in inventory:
            item["Delivery receipts"] = len(inventory["receipts"])
        if kind == "companion_history":
            from maverick.employee_companion import EmployeeCompanionStore
            history = EmployeeCompanionStore().history(record["owner"])
            if deletion._digest(history) != target["history_revision"]:
                raise HTTPException(409, "The selected companion history changed. Review a fresh deletion scope.")
            item["Conversation entries"] = len(history)
        elif kind == "experience_preferences":
            from maverick import experience_preferences
            directory = experience_preferences.data_dir("experience-preferences")
            prefix = experience_preferences._principal_key(record["owner"])
            paths = [directory / (prefix + ".enc"), *directory.glob(prefix + "-thread-*.enc")]
            versions = [[p.name, p.stat().st_size, p.stat().st_mtime_ns] for p in paths if p.is_file()]
            if deletion._digest(versions) != target["revision"]:
                raise HTTPException(409, "The selected preferences changed. Review a fresh deletion scope.")
            item["Personal preference records"] = len(versions)
        for key in ("use", "retained", "note"):
            if target.get(key) or inventory.get(key):
                item[{"use": "Included work", "retained": "Kept separately", "note": "Coverage"}[key]] = target.get(key) or inventory[key]
        targets.append(item)
    holds = record["holds"]
    return {"Selected account": humanize_principal(record["owner"]).name, "Selected channel": record["channel"],
            "Complete selected stores": targets,
            "Preservation obligations": {"Deletion blocked": holds["blocked"], "Recorded legal holds": holds["legal_holds"],
                "Other recorded deletion restrictions": holds["retention_blocks"], "Coverage": holds["coverage"]},
            "Every retained exception": [{"Information": row["store"].replace("_", " "),
                "Result": row["state"].replace("-", " "), "Why": row["reason"],
                **({"Full controls": {"label": "Review this retained information", "href": row["href"]}} if row.get("href") else {})}
                for row in record["exceptions"]],
            "Scope limit": record["notice"]}


def prepare(request, _selection, args, *, action):
    actor = _authority(request, write=action not in READ_ACTIONS)
    state = native._state(request)
    if action == "status":
        return Preview("Current owned store inventory and policy; unavailable stores never claim zero records.", native=native._inventory(request))
    if action == "deletion_status":
        rows, _reviewer = _requests(request)
        return Preview("Authorized saved per-store outcomes and retained exceptions. Requested or held does not mean deleted.", native={"requests": rows})
    if action == "note_source":
        scope = _scope(state, args["scope_id"])
        note = next((n for n in scope["notes"] if n["id"] == args["note_id"]), None)
        if not note or not note.get("conversation_id") or not note.get("turn_id"):
            raise HTTPException(404, "This note has no retained original source. A manual correction or legacy note does not prove original content.")
        result = _decode(native.source(request, note["conversation_id"], note["turn_id"]))
        return Preview("Current authorized original turn. Compare its revision with the saved memory before correcting it.", native=result)
    if action.startswith("link_"):
        return _identity_prepare(state, args, action)
    if action in {"recall", "note"}:
        return _memory_prepare(state, args, action)
    if action == "sharing":
        source = None if args["source_id"] == "channel_only" else _scope(state, args["source_id"])["id"]
        return Preview("Choose one source for verified cross-channel preference recall. Other channel notes are retained separately; no tool or source permissions expand.", [{"source": source}], {"revision": state["sharing"]["revision"]})
    if action == "exclude_task":
        from maverick.pilot_learning import restriction_state
        goal = native._app()._world().get_goal(args["goal_id"])
        if goal is None or goal.owner != actor:
            raise HTTPException(403, "Only the exact task owner may narrow its learning use.")
        return Preview("Stop future local reuse and learning from this task and descendants. Retained business history, prior models and external copies are separate.", [{"task": goal.id, "current": restriction_state(goal.id)}])
    if action == "deletion_request":
        scope = _scope(state, args["scope_id"])
        reviewed = deletion.preview(actor, scope["channel"], scope["user_id"], args["stores"], native._app()._world())
        return Preview("Request independent deletion review for these exact stores. Nothing is deleted now; current holds and retained exceptions remain explicit.",
                       [_deletion_scope(reviewed)], {"channel": scope["channel"], "user_id": scope["user_id"], "snapshot": reviewed["snapshot"], "actor": actor})
    if action == "deletion_review":
        row = _review(request, args["request_id"])
        current = deletion.preview(row["owner"], row["channel"], row["user_id"], [target["store"] for target in row["targets"]], native._app()._world())
        if current["targets"] != row["targets"]:
            raise HTTPException(409, "The selected information changed. Its owner must review a fresh deletion scope.")
        return Preview("Dispatch the separately requested exact deletion scope only if all current holds and source checks pass. Interrupted outcomes are never automatically retried.",
                       [_deletion_scope(current)], {"revision": row["revision"]})
    if action == "export_scope":
        scope = _scope(state, args["scope_id"])
        return Preview("Download the current verified scope. The authenticated link expires in ten minutes and rechecks current ownership at download.", native=exports.link(request, channel=scope["channel"], user_id=scope["user_id"]))
    if action == "export_account":
        return Preview("Download this current owned account store. Other retained stores and external copies remain separate.", native=exports.link(request, store=args["store"]))
    raise HTTPException(422, "Unsupported personal-data operation.")


def _decode(result):
    return json.loads(result.body) if hasattr(result, "body") else result


def execute(request, _selection, args, prepared, _operation_id, *, action):
    actor = _authority(request, write=True)
    if action == "link_begin":
        row = native.personal_identity.begin(actor, args["channel"])
        return Outcome("confirmed", "Private command created. Send it only to your configured channel bot, then independently confirm its displayed sender in My data.", row)
    if action in {"link_confirm", "link_unlink"}:
        fn = native.personal_identity.confirm if action == "link_confirm" else native.personal_identity.unlink
        fn(actor, args["identity_id"], expected_revision=prepared["revision"])
        return Outcome("confirmed", "The exact identity-link change is recorded. Provider consent and personal recall sharing remain separate.")
    if action in {"recall", "note"}:
        options = {"recall": args["recall"]} if action == "recall" else {"note": args["note_id"], "operation": args["operation"], "replacement": args["replacement"]}
        native.personal_memory.update(actor, prepared["channel"], prepared["user_id"], expected_revision=prepared["revision"], **options)
        return Outcome("confirmed", "Personal recall controls are saved; source history and previous models are separately retained.")
    if action == "sharing":
        native.personal_memory.share(actor, source=None if args["source_id"] == "channel_only" else args["source_id"], expected_revision=prepared["revision"])
        return Outcome("confirmed", "Your authoritative personal recall source is saved; no tools or access ceilings changed.")
    if action == "exclude_task":
        result = _decode(native.exclude_learning(request, args["goal_id"], native.ContextIn(context=native.context_for(request))))
        return Outcome("unconfirmed" if result["state"].endswith("pending") else "confirmed", result["message"], result)
    if action == "deletion_request":
        row = deletion.request_deletion(actor, prepared["channel"], prepared["user_id"], args["stores"], prepared["snapshot"], native._app()._world())
    elif action == "deletion_review":
        _review(request, args["request_id"])
        row = _decode(native.apply_deletion(request, args["request_id"], native.DeletionApplyIn(context=native.context_for(request), expected_revision=prepared["revision"], external_holds_clear=args["external_holds_clear"])))
    else:
        raise HTTPException(422, "Unsupported personal-data mutation.")
    uncertain = row.get("_audit_pending") or row["status"] in {"partial", "processing", "partial-held"}
    return Outcome("unconfirmed" if uncertain else "confirmed", "Deletion request saved as " + row["status"] + ". Inspect each store and retained exceptions; this is not a whole-person deletion certificate.",
                   {"id": row["id"], "status": row["status"], "targets": row["targets"], "exceptions": row["exceptions"]})


def recover(request, _selection, _args, prepared, _operation_id, *, action):
    actor = _authority(request, write=True)
    if action == "deletion_request" and actor == prepared["actor"]:
        row = deletion.latest_request(actor, prepared["snapshot"])
        if row and row["owner"] == actor:
            return Outcome("unconfirmed" if row.get("_audit_pending") else "replayed", "This exact request is already saved; no deletion or review was repeated.", {"id": row["id"], "status": row["status"]})
    # Value equality is not evidence that this operation ran. Fresh registry and
    # native revisions fence changed sources; ambiguous mutations never repeat.
    return None


READ_ACTIONS = {"status", "deletion_status", "note_source", "export_scope", "export_account"}


def entries():
    operations = [
        ("status", "Inspect my personal-data stores", EmptyInput),
        ("link_begin", "Start verified channel linking", Channel),
        ("link_confirm", "Confirm authenticated channel identity", Identity),
        ("link_unlink", "Unlink my channel identity", Identity),
        ("recall", "Change personal recall and collection", Recall),
        ("note", "Correct or suppress a personal memory", Note),
        ("note_source", "Read the original source of my memory", NoteRef),
        ("sharing", "Choose a personal recall source", Share),
        ("exclude_task", "Exclude my task from future learning", Task),
        ("deletion_request", "Request reviewed personal-data deletion", Delete),
        ("deletion_review", "Independently review requested data deletion", Review),
        ("deletion_status", "Inspect saved per-store deletion outcomes", EmptyInput),
        ("export_scope", "Export a verified personal scope", Scope),
        ("export_account", "Export my private account records", AccountExport),
    ]
    result = []
    for action, label, model in operations:
        read = action in READ_ACTIONS
        result.append(Adapter(id="personal_data." + action, label=label,
            family="reviews" if action == "deletion_review" else "preferences", direct_ui="/my-data", pages=("/my-data", "/account"), input_model=model,
            snapshot=lambda request, selection, value=action: snapshot(request, selection, action=value),
            prepare=lambda request, selection, args, value=action: native._call(lambda: prepare(request, selection, args, action=value), json_response=False),
            execute=None if read else lambda request, selection, args, prepared, operation_id, value=action: native._call(lambda: execute(request, selection, args, prepared, operation_id, action=value), json_response=False),
            recover=None if read else lambda request, selection, args, prepared, operation_id, value=action: recover(request, selection, args, prepared, operation_id, action=value)))
    return tuple(result)
