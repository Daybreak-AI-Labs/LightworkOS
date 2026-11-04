"""Facts controls share native scope, privacy, history and CAS with Copilot."""
from __future__ import annotations

from datetime import date, datetime, timezone
from functools import partial

from fastapi import HTTPException, Response
from maverick.authority_effects import authority_effect_fence
from maverick.fact_revision import is_private_fact_key, normalize_tags
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import Field

from . import auth, facts_api
from .draft_api import context_for
from .plain_labels import datetime_text
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

STORE = GovernedRecordStore("fact_operation_receipts", "FOP", "fact_operation_receipt")


class Search(StrictInput):
    query: str = Field(default="", max_length=200)
    source: str = Field(default="", max_length=200)
    tag: str = Field(default="", max_length=64)
    before: str = Field(default="", pattern=r"^(?:[0-9]{4}-[0-9]{2}-[0-9]{2})?$")
    page: int = Field(default=1, ge=1, le=10000)


class Value(StrictInput):
    value: str = Field(min_length=1, max_length=20000)


class Create(Value):
    key: str = Field(min_length=1, max_length=200)


class Tags(StrictInput):
    labels: str = Field(default="", max_length=1300)


class Restore(StrictInput):
    version: str = Field(pattern=r"^[a-f0-9]{64}$")


def _authority(request, *, write=False):
    auth.require_permission(request, "operate" if write else "view")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return context_for(request)


def _keys(selection):
    if not selection:
        return []
    keys = selection.get("keys")
    if (selection.get("kind") != "facts" or set(selection) != {"kind", "keys"}
            or not isinstance(keys, list) or not 1 <= len(keys) <= 50
            or any(not isinstance(key, str) or not key or len(key) > 200 or is_private_fact_key(key) for key in keys)
            or len(set(keys)) != len(keys)):
        raise HTTPException(404, "Choose shared facts from the current Facts page.")
    return keys


def _record(request, key):
    return facts_api.record(request, Response(), key=key)


def _selected(request, selection, *, one=False):
    keys = _keys(selection)
    if not keys or one and len(keys) != 1:
        raise HTTPException(422, "Open one shared fact's details before changing it." if one else "Select shared facts to review.")
    return [_record(request, key) for key in keys]


def _page(request, arguments):
    try:
        before = datetime.combine(date.fromisoformat(arguments["before"]), datetime.min.time(), tzinfo=timezone.utc).timestamp() if arguments["before"] else None
    except ValueError as exc:
        raise HTTPException(422, "Choose a valid updated-before date.") from exc
    options = {"query": arguments["query"], "source": arguments["source"], "tag": arguments["tag"],
               "updated_before": before, "limit": 50}
    first = facts_api.records(request, Response(), **options, offset=0, snapshot="")
    if arguments["page"] == 1:
        return first
    return facts_api.records(request, Response(), **options, offset=(arguments["page"] - 1) * 50, snapshot=first["snapshot"])


def _field(name, label, value="", *, kind="text", **extra):
    return {"name": name, "label": label, "kind": kind, "value": value, **extra}


def snapshot(request, selection, *, action):
    context = _authority(request, write=action not in {"search", "inspect"})
    if action in {"search", "create"}:
        # Catalog metadata only; no ambient read of all fact values or history.
        from ._shared import _world
        revision = _world().fact_catalog_revision()
        fields = ([_field("key", "New shared fact name", required=True),
                   _field("value", "Detail", kind="textarea", required=True, max_length=20000)] if action == "create" else
                  [_field("query", "Fact name"), _field("source", "Source or author"), _field("tag", "Tag"),
                   _field("before", "Updated before (YYYY-MM-DD, UTC)"), _field("page", "Current results page", 1, kind="number")])
        return Snapshot(digest([context, revision]), "Current shared workspace facts",
                        "Names, tags and source metadata are searchable. Personal and task working notes are excluded.", fields=fields)
    keys = _keys(selection)
    if not keys or action != "inspect" and len(keys) != 1:
        return Snapshot(digest([context, keys]), "Current Facts selection", "Review one fact before changing it.",
                        blocked="Open one fact's Details and history, or select facts for read-only review.")
    try:
        records = _selected(request, selection)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        # The shared executor asks for a snapshot before recovering a receipt.
        # A removed fact must not make a completed removal impossible to check.
        return Snapshot(digest([context, keys, "missing"]), "Fact no longer saved",
                        "A previous operation receipt can still be checked.", blocked="Refresh current Facts before a new action.")
    item = records[0]["item"]
    fields = []
    if action == "update":
        fields = [_field("value", "New detail", item["value"], kind="textarea", required=True, max_length=20000)]
    elif action == "tags":
        fields = [_field("labels", "Tags separated by commas", ", ".join(item.get("tags") or []), max_length=1300)]
    elif action == "restore":
        fields = [_field("version", "Saved version to restore as a new edit", kind="select", required=True,
                         choices=[{"value": digest(version), "label": datetime_text(version["valid_from"], seconds=True)}
                                  for version in records[0]["history"]])]
    blocked = ("An administrator can enable fact tags in Memory & learning settings." if action == "tags" and not facts_api.tags_enabled() else
               "No retained version is available to restore." if action == "restore" and not records[0]["history"] else "")
    material = [[record["item"]["key"], record["item"]["revision"], digest(record["history"])] for record in records]
    return Snapshot(digest([context, material, facts_api.tags_enabled()]), "Currently authorized selected shared facts",
                    "Edits and removal compare the exact reviewed version. Removal stops recall; retained history is not erased.",
                    details={"selected_names": keys, "history_notice": records[0]["history_notice"]}, fields=fields, blocked=blocked)


def prepare(request, selection, arguments, *, action):
    context = _authority(request, write=action not in {"search", "inspect"})
    if action == "search":
        page = _page(request, arguments)
        return Preview("Current bounded search page. Each explicit page request starts a fresh authorized view; use native Facts paging for one continuous snapshot.",
                       native={"items": page["items"], "has_more": page["has_more"], "page": arguments["page"], "scope": "Shared fact names, tags and source metadata only"})
    if action == "inspect":
        records = _selected(request, selection)
        # Bulk review is read-only. Detailed version values are requested one
        # fact at a time, bounding response size and avoiding bulk mutations.
        return Preview("Current selected facts; historical values use the same native access checks.",
                       native={"items": records if len(records) == 1 else [record["item"] for record in records],
                               "notice": "Open one fact to review its retained versions. Bulk selection cannot mutate or delete facts."})
    if action == "create":
        key = arguments["key"].strip()
        if not key or is_private_fact_key(key):
            raise HTTPException(422, "Choose a shared business fact name, without a reserved personal or task prefix.")
        from ._shared import _world
        if _world().fact_record(key) is not None:
            raise HTTPException(409, "This name is already saved. Open its current detail before editing.")
        return Preview("Create one shared business fact. Workspace viewers can read it; do not put secrets in shared memory.",
                       changes=[{"label": key, "before": "Not saved", "after": arguments["value"]}],
                       native={"key": key, "value": arguments["value"], "revision": 0, "context": context})
    record = _selected(request, selection, one=True)[0]
    item = record["item"]
    native = {"key": item["key"], "revision": item["revision"], "context": context}
    if action == "tags":
        if not facts_api.tags_enabled():
            raise HTTPException(409, "An administrator can enable fact tags in Memory & learning settings.")
        try:
            tags = normalize_tags([tag.strip() for tag in arguments["labels"].split(",") if tag.strip()])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        native["tags"] = tags
        before, after = item.get("tags") or [], tags
    elif action in {"update", "restore"}:
        if action == "restore":
            version = next((value for value in record["history"] if digest(value) == arguments["version"]), None)
            if version is None:
                raise HTTPException(409, "That retained version changed or is no longer available. Review current history.")
            value = version["value"]
        else:
            value = arguments["value"]
        native["value"] = value
        before, after = item["value"], value
    else:
        before, after = "Currently recalled", "Stop new recall; recorded history remains governed by workspace retention"
    return Preview("Review one exact fact change. A concurrent edit, role change or workspace switch refuses this prepared action.",
                   changes=[{"label": item["key"], "before": before, "after": after}], native=native)


def _binding(request, selection, prepared, operation_id, action):
    if _authority(request, write=True) != prepared["context"]:
        raise HTTPException(409, "Your account or workspace changed. Review this fact again.")
    if is_private_fact_key(prepared["key"]) or action != "create" and _keys(selection) != [prepared["key"]]:
        raise HTTPException(409, "Your selected fact changed. Review it again.")
    actor = auth.caller_principal(request) or "local:dashboard"
    scope = digest([prepared["context"], actor, operation_id])
    return actor, "FOP-" + scope[:56], digest([scope, action, prepared])


def recover(request, selection, arguments, prepared, operation_id, *, action):
    actor, record_id, binding = _binding(request, selection, prepared, operation_id, action)
    receipt = STORE.get(record_id)
    if receipt is None:
        return None
    if receipt.get("binding") != binding or receipt.get("owner") != actor:
        raise HTTPException(409, "This operation receipt belongs to a different review.")
    if receipt.get("state") != "confirmed" or receipt.get("_audit_pending"):
        return Outcome("unconfirmed", "This attempt has no confirmed completion receipt. It will not run again. Open current Facts before preparing another action.")
    return Outcome("replayed", "This exact operation already completed; nothing was run again. Current facts may have changed since that receipt.",
                   {"saved_revision": receipt.get("saved_revision"), "operation": action})


def _write(request, prepared, action):
    if action == "remove":
        facts_api.remove_fact(request, prepared["key"], prepared["revision"], prepared["context"])
        return None
    if action == "tags":
        return facts_api.update_fact_tags(request, prepared["key"], prepared["tags"], prepared["revision"], prepared["context"])
    from .api import FactIn, save_fact
    return save_fact(request, FactIn(key=prepared["key"], value=prepared["value"], expected_revision=prepared["revision"], context=prepared["context"]))


def execute(request, selection, arguments, prepared, operation_id, *, action):
    with authority_effect_fence():
        actor, record_id, binding = _binding(request, selection, prepared, operation_id, action)
        existing = recover(request, selection, arguments, prepared, operation_id, action=action)
        if existing is not None:
            return existing
        # Only digests and outcome metadata are retained. A durable pre-effect
        # receipt prevents retries from resurrecting a subsequently deleted fact.
        try:
            receipt = STORE.create({"id": record_id, "owner": actor, "binding": binding, "state": "dispatching"},
                                   action="fact_operation_admitted", actor=actor, max_records=10000)
        except RecordConflict:
            return recover(request, selection, arguments, prepared, operation_id, action=action)
        if receipt.get("_audit_pending"):
            return Outcome("unconfirmed", "Audit admission is not confirmed. No fact change was dispatched; this review will not be retried automatically.")
        revision = _write(request, prepared, action)
        # Native CAS returning proves the effect. Readback is additional evidence,
        # never an inference that an unknown attempt executed because values match.
        if action != "remove":
            try:
                current = _record(request, prepared["key"])["item"]
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                current = {}
            matches = current.get("tags") == prepared["tags"] if action == "tags" else current.get("value") == prepared["value"]
            if current.get("revision") != revision or not matches:
                return Outcome("unconfirmed", "The write returned, but its exact saved version could not be read back. Open current Facts; this review will not run again.")
        def complete(value):
            value.update(state="confirmed", saved_revision=revision)
        receipt = STORE.update(record_id, complete, expected_revision=receipt["revision"], action="fact_operation_completed", actor=actor)
        if not receipt or receipt.get("_audit_pending"):
            return Outcome("unconfirmed", "The native fact change returned, but its completion audit is not confirmed. Check current Facts; this review will not run again.")
        return Outcome("confirmed", "The exact reviewed change completed. Removal stops recall; retained history still follows workspace policy.",
                       {"saved_revision": revision, "operation": action})


def entries():
    specifications = [("search", "Find shared business facts", Search), ("inspect", "Review selected facts and history", EmptyInput),
                      ("create", "Add a shared business fact", Create), ("update", "Edit the selected fact", Value),
                      ("restore", "Restore a reviewed fact version", Restore), ("tags", "Edit the selected fact's tags", Tags),
                      ("remove", "Stop recalling the selected fact", EmptyInput)]
    return tuple(Adapter("facts." + action, label, "learning", "/facts", ("/facts",), schema,
                         partial(snapshot, action=action), partial(prepare, action=action),
                         None if action in {"search", "inspect"} else partial(execute, action=action),
                         None if action in {"search", "inspect"} else partial(recover, action=action))
                 for action, label, schema in specifications)
