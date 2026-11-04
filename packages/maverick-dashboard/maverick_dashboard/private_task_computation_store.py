"""Owned native-file local checks, one fixed outward result and retained originals."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import json
import re
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException
from maverick import attachments, config, crypto_at_rest, knowledge_task_context
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget, BudgetExceeded
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.private_task_computation import (
    MAX_BYTES,
    RESULTS,
    SCHEMA,
    artifact,
    compute,
    parse_csv,
    validate,
)

from . import auth
from .draft_api import context_for

STORE = GovernedRecordStore("private-task-computation", "PTC", "private_task_computation", required_backend="local")
FEATURE = "private_task_computation"
TTL, CHECK_LIMIT = 600, 4
NOTICE = "Check one selected row using the conditions and possible values you enter. The complete local calculation is compared with two ordinary references. Entered assumptions and file contents are not independently verified business facts. Only the single approved Yes/No result can become a downloadable file after a separate release review. No outside model or connected action is used. This checks fixed result bytes, not timing, unusual patterns or what someone could infer across other releases."
ACTION_NAMES = {"create": "Saved private check", "edit": "Replaced fixed check and permission", "run": "Ran private local check",
    "release": "Approved the fixed result file", "withdraw": "Withdrew source and release permission", "scope": "Reviewed source permission",
    "acknowledge": "Stopped waiting for an unknown original", "remove": "Removed current private check"}


def authority(request, context=None, *, historical=False):
    auth.require_permission(request, "operate")
    actor, current = auth.caller_principal(request), context_for(request)
    if not actor or not actor.startswith("user:"):
        raise HTTPException(403, "Sign in with your named task-owning workspace account.")
    if context is not None and not hmac.compare_digest(context, current):
        raise HTTPException(409, "Your account or workspace changed. Reload this private check.")
    if not historical and (config.config_source_errors(include_tenant=True) or config.get_features().get(FEATURE) is not True):
        raise HTTPException(403, "Private local checks are off. Earlier original results remain readable.")
    return actor, current


def _world():
    from .app import _world as world
    return world()


@contextlib.contextmanager
def _writer():
    """Fence authority, then freeze native source rows, then governed custody."""
    with authority_effect_fence():
        world = _world()
        # Checked before taking the write lock: a Postgres world has no local
        # write connection to freeze the source rows with.
        writing = getattr(world, "_writing", None)
        backend = STORE._backend()
        if not callable(writing) or backend.kind != "local":
            raise HTTPException(503, "This bounded private check requires native local custody.")
        with writing() as connection:
            connection.execute("BEGIN IMMEDIATE")
            with cross_process_lock(backend._store._dir() / ".fixed-source-admission", strict=True):
                yield world


def _task(request, world, goal_id, *, action="analyze"):
    actor, _context = authority(request)
    goal = world.get_goal(goal_id)
    if not goal or goal.owner != actor or not auth.can_access_goal(request, goal):
        raise HTTPException(404, "This owned task is unavailable in your current department access.")
    if goal.project_id is not None:
        project = world.get_project(goal.project_id)
        if not project or project.get("owner") != actor:
            raise HTTPException(404, "The task project is unavailable to your account.")
    # A source-analysis task retains its native source policy. Viewing it is
    # never substituted for analysis or export/derivative permission.
    if knowledge_task_context.has_binding(goal.id, world):
        if not knowledge_task_context._path(goal.id).is_file():
            raise knowledge_task_context.SourceContextUnavailable("The retained analysis-source policy is unavailable; analysis and release are refused.")
        knowledge_task_context.require_read(goal, actor, action=action)
        if action == "export":
            knowledge_task_context.require_read(goal, actor, action="analyze")
    return goal


def _source(request, goal_id, attachment_id, *, action="analyze", budget=None):
    budget = budget or Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    world = _world()
    goal = _task(request, world, goal_id, action=action)
    rows = world.list_attachments(goal_id)
    if len(rows) > 100:
        raise HTTPException(409, "The complete attachment list exceeds one hundred. No source was omitted.")
    selected = [row for row in rows if row.id == attachment_id]
    if len(selected) != 1:
        raise HTTPException(404, "This task file is unavailable.")
    attachment = selected[0]
    if not attachment.filename.lower().endswith(".csv") or not 1 <= attachment.size_bytes <= MAX_BYTES:
        raise HTTPException(422, "Choose a complete local CSV attachment of at most 128 KiB.")
    path = Path(attachment.path)
    root = attachments._root_for_goal(goal_id)
    try:
        if path.is_symlink() or path.parent.resolve() != root.resolve() or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError
        # Sealed overhead is bounded; never fetch a missing S3 mirror or open
        # an arbitrary path supplied by the caller.
        if path.stat().st_size > MAX_BYTES + 256:
            raise ValueError
        data = attachments.read_bytes(path)
    except (OSError, ValueError, attachments.AttachmentRejected) as exc:
        raise HTTPException(409, "The exact private file is not available locally. Restore it through the task's existing file controls.") from exc
    budget.check()
    sha = hashlib.sha256(data).hexdigest()
    if len(data) != attachment.size_bytes or sha != attachment.sha256:
        raise HTTPException(409, "The complete file changed or could not be verified. No old result can be used.")
    headers, records = parse_csv(data, budget=budget)
    inherited = knowledge_task_context._read(goal.id) if knowledge_task_context.has_binding(goal.id, world) else None
    source = {"goal": goal.id, "attachment": attachment.id, "owner": goal.owner, "domain": goal.domain,
        "project": goal.project_id, "task_created": goal.created_at, "task_title": goal.title,
        "task_binding": digest([goal.title, goal.description, goal.created_at, goal.owner, goal.domain, goal.project_id]),
        "file_name": attachment.filename, "file_created": attachment.created_at,
        "file_sha": sha, "bytes": len(data), "columns": headers, "rows": len(records),
        "task_source": digest(inherited) if inherited else None, "inherited_purpose": inherited["purpose"] if inherited else None}
    _task(request, world, goal_id, action=action)
    budget.check()
    return source, data


def choices(request):
    actor, context = authority(request)
    world = _world()
    goals = world.list_goals(owner=actor, limit=101, order="desc")
    if len(goals) > 100:
        raise HTTPException(409, "This bounded picker supports one hundred owned tasks. No choices were silently omitted.")
    result = []
    with authority_effect_fence():
        for goal in goals:
            try:
                _task(request, world, goal.id)
            except (HTTPException, knowledge_task_context.SourceContextUnavailable):
                continue
            files = world.list_attachments(goal.id)
            if len(files) > 100:
                raise HTTPException(409, "An owned task exceeds the attachment bound; no list was truncated.")
            for file in files:
                if file.filename.lower().endswith(".csv") and 1 <= file.size_bytes <= MAX_BYTES:
                    result.append({"goal": goal.id, "attachment": file.id, "label": goal.title + " · " + file.filename})
        authority(request, context)
    return {"context": context, "choices": result, "notice": NOTICE}


def inspect_source(request, goal, attachment):
    with _writer():
        actor, context = authority(request)
        source, _data = _source(request, goal, attachment)
        identifier = _id(actor, context, source)
        return {"context": context, "source": source, "id": identifier, "exists": STORE.get(identifier) is not None, "notice": NOTICE}


def _id(actor, context, source):
    return "PTC-" + digest([actor, context, source["goal"], source["attachment"]])[:32]


def _source_keys(source):
    # The governed namespace already belongs to the current tenant. Spending
    # belongs to the physical source, even if its owning account changes.
    return [digest(["physical-file", source["goal"], source["attachment"], source["task_created"], source["file_created"]]),
        digest(["file-content", source["file_sha"]])]


def _seal(row, payload):
    text = json.dumps({"identity": [row["id"], row["actor"], row["context"]], "payload": payload}, allow_nan=False, separators=(",", ":"))
    if len(text.encode()) > 600000:
        raise HTTPException(413, "The complete original history exceeds its custody bound. Nothing was dropped.")
    row["envelope"] = crypto_at_rest.seal_to_str(text)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(409, "Enable stored-data encryption before using private local checks.")


def _open(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if value["identity"] != [row["id"], row["actor"], row["context"]]:
        raise HTTPException(409, "The retained private-check owner could not be verified.")
    return value["payload"]


def _owned(request, identifier, *, historical=False):
    actor, context = authority(request, historical=historical)
    if type(identifier) is not str or not re.fullmatch(r"PTC-[a-f0-9]{32}", identifier):
        raise HTTPException(404, "This private check is unavailable.")
    row = STORE.get(identifier)
    if not row or (row.get("actor"), row.get("context")) != (actor, context):
        raise HTTPException(404, "This private check is unavailable to your account and workspace.")
    if row.get("_audit_pending"):
        row = STORE._flush(row)
    return row


def _cohort(keys):
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The one-hundred-source custody bound is full. Original history was not omitted.")
    private = [_open(row) for row in rows]
    keys = set(keys)
    matched = []
    while True:
        found = [payload for payload in private if (set(payload["source_keys"]) | set(_source_keys(payload["source"]))) & keys and payload not in matched]
        if not found:
            break
        matched.extend(found)
        for payload in found:
            keys.update(payload["source_keys"])
            keys.update(_source_keys(payload["source"]))
    return {"checks_used": sum(payload["checks_used"] for payload in matched),
        "release_used": any(payload["release_used"] for payload in matched), "keys": sorted(keys)}


def _current_source(request, payload, *, action="analyze", budget=None):
    source, data = _source(request, payload["source"]["goal"], payload["source"]["attachment"], action=action, budget=budget)
    if digest(source) != digest(payload["source"]):
        raise HTTPException(409, "The owned task, file or inherited source policy changed. Review a separate current intent.")
    return source, data


def view(request, identifier):
    with _writer():
        row = _owned(request, identifier)
        payload = _open(row)
        if payload["removed"]:
            raise HTTPException(409, "This private check was removed. Earlier originals remain readable.")
        source, _data = _source(request, payload["source"]["goal"], payload["source"]["attachment"], action="read")
        changed = digest(source) != digest(payload["source"])
        analysis_allowed = True
        try:
            _task(request, _world(), source["goal"])
        except knowledge_task_context.SourceContextUnavailable:
            analysis_allowed = False
        actor, context = authority(request)
        cohort = _cohort(payload["source_keys"] + _source_keys(source))
        usable = payload["consent"] and time.time() < payload["model"]["expires_at"] and not payload["pending"] and not changed and analysis_allowed
        return {"context": context, "id": identifier, "revision": row["revision"], "author_binding": digest([payload, source]), "source": source,
            "source_changed": changed, "analysis_allowed": analysis_allowed,
            "model": payload["model"], "row": payload["row"], "consent": payload["consent"], "usable": usable,
            "result": payload["result"] if usable else None, "pending": payload["pending"],
            "downloadable": usable and payload["released"] is not None, "allowance": {"remaining_checks": max(0, CHECK_LIMIT - cohort["checks_used"]),
            "release_used": cohort["release_used"]}, "notice": NOTICE}


def original(request, identifier, operation, *, binding=None):
    row = _owned(request, identifier, historical=True)
    value = _open(row)["operations"].get(operation)
    if not value or (binding is not None and value["binding"] != binding):
        raise HTTPException(404, "This exact original request is unavailable.")
    authority(request, row["context"], historical=True)
    confirmed = value["state"] == "confirmed" and not row.get("_audit_pending")
    return {"context": row["context"], "id": identifier, "operation": operation, "confirmed": confirmed, "receipt": value,
        "message": "This exact original was recorded. Nothing ran or released again." if confirmed else
        "The original remains unknown. It will never repeat automatically; used check and release allowances remain spent."}


def history(request):
    actor, context = authority(request, historical=True)
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The complete original history exceeds its bounded custody.")
    choices = []
    for row in rows:
        if (row.get("actor"), row.get("context")) != (actor, context):
            continue
        choices.extend({"value": row["id"] + "|" + operation, "label": ACTION_NAMES[receipt["action"]] + " · " +
            ("Recorded result" if receipt["state"] == "confirmed" and not row.get("_audit_pending") else "Original result unknown")}
            for operation, receipt in _open(row)["operations"].items())
    authority(request, context, historical=True)
    return {"context": context, "choices": choices}


def _arguments(action, arguments):
    allowed = {"create": {"goal", "attachment", "row", "model"}, "edit": {"row", "model", "acknowledge_new_intent"},
        "run": set(), "release": {"approved_result", "acknowledge_release"}, "withdraw": set(),
        "scope": {"expires_at", "basis", "acknowledge_source_rights"}, "acknowledge": {"acknowledge_unknown"}, "remove": set()}
    if action not in allowed or type(arguments) is not dict or set(arguments) != allowed[action]:
        raise HTTPException(422, "Enter every supported field for this fixed action, without additional instructions.")
    if action in {"create", "edit"}:
        validate(arguments["model"])
        if type(arguments["row"]) is not int or not 1 <= arguments["row"] <= 200:
            raise HTTPException(422, "Choose one fixed data row from one to 200.")
        _expiry(arguments["model"]["expires_at"])
    if action == "create" and any(type(arguments[key]) is not int or arguments[key] < 1 for key in ("goal", "attachment")):
        raise HTTPException(422, "Choose a saved owned task and actual file.")
    if action == "edit" and arguments["acknowledge_new_intent"] is not True:
        raise HTTPException(409, "A changed condition or row is a separate intent. Review it completely and acknowledge earlier originals remain.")
    if action == "release" and (arguments["approved_result"] not in RESULTS or arguments["acknowledge_release"] is not True):
        raise HTTPException(409, "Explicitly approve only the fixed result shown in the release review.")
    if action == "scope":
        _expiry(arguments["expires_at"])
        if type(arguments["basis"]) is not str or not 10 <= len(arguments["basis"].strip()) <= 2000 or arguments["acknowledge_source_rights"] is not True:
            raise HTTPException(422, "Review the current reuse and release rights and enter their basis.")
    if action == "acknowledge" and arguments["acknowledge_unknown"] is not True:
        raise HTTPException(409, "Acknowledge that the original remains unknown and its allowance will not be refunded.")


def _expiry(value):
    if type(value) not in {int, float} or not time.time() < value <= time.time() + 30 * 86400:
        raise HTTPException(422, "Choose a future source-permission review time within thirty days.")


def prepare(request, identifier, action, arguments):
    _arguments(action, arguments)
    with _writer():
        actor, context = authority(request)
        if action == "create":
            source, _data = _source(request, arguments["goal"], arguments["attachment"])
            identifier = _id(actor, context, source)
            if STORE.get(identifier):
                raise HTTPException(409, "This physical source already has retained intent and allowance. Open it or its earlier originals.")
            payload, revision = None, 0
        else:
            row = _owned(request, identifier)
            payload, revision = _open(row), row["revision"]
            if payload["removed"] or row.get("_audit_pending"):
                raise HTTPException(409, "This check is removed or original custody is pending. Read its original history.")
            source, _data = _source(request, payload["source"]["goal"], payload["source"]["attachment"], action=_source_action(action))
            if action not in {"edit", "withdraw", "remove", "acknowledge"} and digest(source) != digest(payload["source"]):
                raise HTTPException(409, "The complete source changed. Use a separately acknowledged new-intent review.")
            _action_ready(payload, action, arguments)
        keys = (payload["source_keys"] if payload else []) + _source_keys(source)
        allowance = _cohort(keys)
        if action == "run" and allowance["checks_used"] >= CHECK_LIMIT:
            raise HTTPException(409, "The shared lifetime check allowance is exhausted. Removing or copying the source cannot reset it.")
        if action == "release" and allowance["release_used"]:
            raise HTTPException(409, "This physical source has already spent its one fixed release allowance, including any unknown original.")
        if action in {"create", "edit"} and arguments["row"] > source["rows"]:
            raise HTTPException(422, "The selected row does not exist in the complete source.")
        model = arguments.get("model") if action in {"create", "edit"} else payload["model"]
        if action in {"create", "edit", "run", "release", "scope"} and source["inherited_purpose"] is not None and model["purpose"] != source["inherited_purpose"]:
            raise HTTPException(403, "This task's inherited source policy permits its exact retained purpose only. Enter that purpose or use a separately authorized native source.")
        return {"actor": actor, "context": context, "id": identifier, "action": action, "arguments": copy.deepcopy(arguments),
            "revision": revision, "before": digest(payload), "source": source, "source_keys": allowance["keys"], "allowance": allowance,
            "model": model,
            "row": arguments.get("row") if action in {"create", "edit"} else payload["row"],
            "result": payload.get("result") if payload else None, "pending": payload.get("pending") if payload else None,
            "expires": time.time() + TTL}


def _action_ready(payload, action, arguments):
    if payload["pending"] and action not in {"acknowledge", "withdraw", "remove"}:
        raise HTTPException(409, "An exact original attempt is unknown. Read it and separately acknowledge its wait before any new intent.")
    if action in {"run", "release"} and (not payload["consent"] or time.time() >= payload["model"]["expires_at"]):
        raise HTTPException(409, "Current source permission has expired or was withdrawn. Review permission again before a new local check.")
    if action == "release" and (not payload["result"] or payload["result"].get("result") != payload["model"]["approved_result"]
            or arguments["approved_result"] != payload["model"]["approved_result"]):
        raise HTTPException(409, "The current complete local check does not match the one fixed approved result. Nothing can be released.")
    if action == "acknowledge" and not payload["pending"]:
        raise HTTPException(409, "There is no unknown original waiting for acknowledgment.")


def _source_action(action):
    if action in {"withdraw", "remove", "acknowledge"}:
        return "read"
    return "export" if action == "release" else "analyze"


def changes(prepared):
    source, model = prepared["source"], prepared["model"]
    rows = [{"name": name, "label": label, "before": None, "after": value} for name, label, value in (
        ("action", "Your selected action", ACTION_NAMES[prepared["action"]]), ("owner", "Task and file owner", source["owner"]),
        ("task", "Selected private task", source["task_title"]), ("file", "Complete local file", source["file_name"]),
        ("file_size", "Complete file size in bytes", source["bytes"]), ("rows", "Complete data rows", source["rows"]),
        ("columns", "All file column names", source["columns"]), ("row", "Only selected data row", prepared["row"]),
        ("purpose", "Fixed purpose", model["purpose"]), ("basis", "Entered basis for reuse and release rights", model["basis"]),
        ("expiry", "Review source permission again by", datetime.fromtimestamp(model["expires_at"], timezone.utc).isoformat()), ("fields", "Complete possible values you enter", model["fields"]),
        ("conditions", "Every entered condition", model["conditions"]), ("combine", "How conditions combine", "Every condition" if model["mode"] == "all" else "At least one condition"),
        ("only_result", "The only result allowed into a file", model["approved_result"]),
        ("allowance", "Shared lifetime allowance already used", {"checks": prepared["allowance"]["checks_used"], "fixed_release_spent": prepared["allowance"]["release_used"]}),
        ("current_check", "Current local result and complete comparison", prepared["result"]),
        ("original_wait", "Earlier original still waiting", bool(prepared["pending"])),
        ("new_intent", "Complete acknowledgment and selected change", prepared["arguments"]),
        ("meaning", "What this establishes", NOTICE))]
    if prepared["action"] == "release":
        rows.append({"name": "outward", "label": "Complete downloadable file contents", "before": None,
            "after": artifact(model["approved_result"]).decode("ascii")})
    rows.append({"name": "recorded_source_details", "label": "Recorded source details", "before": None,
        "after": {key: prepared[key] for key in ("actor", "context", "id", "revision", "before", "source", "source_keys", "expires")}})
    return rows


def _guard(request, prepared, *, deadline=True, budget=None):
    actor, context = authority(request, prepared["context"])
    if actor != prepared["actor"]:
        raise HTTPException(403, "Only the person who reviewed this fixed intent may confirm it.")
    if deadline and time.time() >= prepared["expires"]:
        raise HTTPException(409, "The complete review expired while waiting. Read its original before preparing a current review.")
    source, data = _source(request, prepared["source"]["goal"], prepared["source"]["attachment"],
        action=_source_action(prepared["action"]), budget=budget)
    if digest(source) != digest(prepared["source"]):
        raise HTTPException(409, "The exact reviewed task, local file or current source permission changed. Nothing will repeat.")
    _arguments(prepared["action"], prepared["arguments"])
    return data


def recover(request, prepared, operation):
    authority(request, prepared["context"], historical=True)
    row = STORE.get(prepared["id"])
    if not row:
        return None
    if (row.get("actor"), row.get("context")) != (prepared["actor"], prepared["context"]):
        raise HTTPException(404, "The original request is unavailable.")
    if operation not in _open(row)["operations"]:
        return None
    return original(request, prepared["id"], operation, binding=digest(prepared))


def _reserve(request, prepared, operation):
    actor = prepared["actor"]
    receipt = {"action": prepared["action"], "actor": actor, "context": prepared["context"], "binding": digest(prepared),
        "state": "unconfirmed", "recorded_at": time.time(), "business_verified": False}
    if prepared["action"] == "create":
        row = {"id": prepared["id"], "actor": actor, "context": prepared["context"], "schema": SCHEMA}
        payload = {"source": prepared["source"], "source_keys": prepared["source_keys"], "model": prepared["arguments"]["model"],
            "row": prepared["row"], "consent": False, "removed": False, "checks_used": 0, "release_used": False,
            "pending": operation, "result": None, "released": None, "operations": {operation: receipt}}
        _seal(row, payload)
        _guard(request, prepared)
        return STORE.create(row, action="private_check_reserved", actor=actor, max_records=100)

    def reserve(row):
        _guard(request, prepared)
        payload = _open(row)
        if row.get("_audit_pending") or digest(payload) != prepared["before"] or len(payload["operations"]) >= 200:
            raise HTTPException(409, "The complete retained intent or original custody changed. Review the current check.")
        _action_ready(payload, prepared["action"], prepared["arguments"])
        allowance = _cohort(prepared["source_keys"])
        if prepared["action"] == "run":
            if allowance["checks_used"] >= CHECK_LIMIT:
                raise HTTPException(409, "The shared lifetime check allowance is exhausted.")
            payload["checks_used"] += 1
            payload["result"], payload["released"] = None, None
        if prepared["action"] == "release":
            if allowance["release_used"]:
                raise HTTPException(409, "The physical source's one fixed release allowance is already spent.")
            payload["release_used"] = True
        payload["operations"][operation] = receipt
        payload["pending"] = operation
        _seal(row, payload)
        _guard(request, prepared)
    return STORE.update(prepared["id"], reserve, expected_revision=prepared["revision"], action="private_check_reserved", actor=actor)


def _finish_payload(payload, prepared, operation, result):
    action, arguments = prepared["action"], prepared["arguments"]
    if action in {"create", "edit"}:
        payload.update(source=prepared["source"], source_keys=prepared["source_keys"], model=arguments["model"],
            row=arguments["row"], consent=True, result=None, released=None)
    elif action == "run":
        payload["result"] = result
    elif action == "release":
        payload["released"] = {"operation": operation, "result": payload["model"]["approved_result"]}
    elif action == "scope":
        payload["model"]["expires_at"], payload["model"]["basis"] = arguments["expires_at"], arguments["basis"]
        payload.update(consent=True, result=None, released=None)
    elif action == "withdraw":
        payload.update(consent=False, result=None, released=None)
    elif action == "remove":
        payload.update(removed=True, consent=False, result=None, released=None)
    elif action == "acknowledge":
        held = prepared["pending"]
        payload["operations"][held]["wait_acknowledged_by"] = operation
        payload.update(consent=False, result=None, released=None)
    if action in {"withdraw", "remove"} and prepared["pending"]:
        payload["operations"][prepared["pending"]]["wait_acknowledged_by"] = operation
    payload["pending"] = None


def apply(request, prepared, operation):
    if type(operation) is not str or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "The exact original request reference is required.")
    # Original reads remain available after feature-off, withdrawal and expiry.
    prior = recover(request, prepared, operation)
    if prior:
        return prior
    with _writer():
        prior = recover(request, prepared, operation)
        if prior:
            return prior
        _guard(request, prepared)
        reserved = _reserve(request, prepared, operation)
        if not reserved or reserved.get("_audit_pending"):
            return original(request, prepared["id"], operation)
        budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
        result = None
        if prepared["action"] == "run":
            try:
                data = _guard(request, prepared, budget=budget)
                budget.check()
                result = compute(prepared["model"], data, prepared["row"], budget=budget)
            except BudgetExceeded:
                result = {"status": "unknown", "reason": "The complete local comparison exceeded its shared time allowance. No previous result was reused."}
            except ValueError:
                result = {"status": "unknown", "reason": "The complete file or declared possibilities could not be qualified. No result can be released."}
        def finish(row):
            _guard(request, prepared)
            payload = _open(row)
            if row.get("_audit_pending") or payload["pending"] != operation:
                raise HTTPException(409, "The original completion is uncertain. Read its exact retained request.")
            _finish_payload(payload, prepared, operation, result)
            payload["operations"][operation].update(state="confirmed", outcome="unknown" if result and result.get("status") == "unknown" else "recorded",
                checks_used=payload["checks_used"], release_used=payload["release_used"])
            _seal(row, payload)
            _guard(request, prepared)
            if prepared["action"] in {"run", "release"} and time.time() >= payload["model"]["expires_at"]:
                raise HTTPException(409, "Source permission expired before the native writer completed. The original remains unknown and will not repeat.")
        STORE.update(prepared["id"], finish, expected_revision=reserved["revision"], action="private_check_" + prepared["action"], actor=prepared["actor"])
        return original(request, prepared["id"], operation)


def download(request, identifier):
    with _writer():
        row = _owned(request, identifier)
        payload = _open(row)
        if (payload["removed"] or not payload["consent"] or payload["pending"] or not payload["released"]
                or time.time() >= payload["model"]["expires_at"] or row.get("_audit_pending")):
            raise HTTPException(409, "A current explicitly approved fixed result is required. Unknown, removed or withdrawn results are unavailable.")
        _current_source(request, payload, action="export")
        receipt = payload["operations"][payload["released"]["operation"]]
        if receipt["state"] != "confirmed" or payload["released"]["result"] != payload["model"]["approved_result"]:
            raise HTTPException(409, "The exact original release is not confirmed.")
        data = artifact(payload["released"]["result"])
        authority(request, row["context"])
        _current_source(request, payload, action="export")
        if time.time() >= payload["model"]["expires_at"]:
            raise HTTPException(409, "Source permission expired before this download.")
        return data


def author_handoff(request, identifier=None):
    with _writer():
        _actor, context = authority(request)
        if identifier is None:
            return {"context": context, "id": None, "binding": None}
        row = _owned(request, identifier)
        payload = _open(row)
        if payload["removed"]:
            raise HTTPException(409, "This current check was removed; read its earlier originals.")
        source, _data = _source(request, payload["source"]["goal"], payload["source"]["attachment"], action="read")
        return {"context": context, "id": identifier, "binding": digest([payload, source])}
