"""Durable conversation intent, distinct from a task's execution ownership.

Only the serialized worker consumes approved guidance. Task admission retains
ChatThreads' transaction fence and SubmissionStore's exactly-once identity.
Private text and pending bytes are sealed inside the governed CAS record.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import secrets
import time

from . import config
from .crypto_at_rest import seal_bound, unseal_bound
from .governed_operations import digest
from .governed_records import GovernedRecordStore
from .paths import current_tenant_id_strict
from .privacy_ops import RecordConflict

STORE = GovernedRecordStore("conversation_inbox", "CI", "conversation_inbox")
EDITABLE = {"queued", "needs_decision", "guidance_ready", "blocked"}
MODES = ("guidance", "queue", "independent")
MAX_BYTES = 4 * 1024 * 1024
MAX_FILES = 10
MAX_ITEMS = 1000
# People can add guidance, queue the next message or start separate work while
# a task runs unless an administrator turned it off ([conversation_inbox]
# enabled = false, in the organization or workspace settings). An explicit
# "off" always stands.
ENABLED_DEFAULT = True


def policy():
    cfg = config.load_config().get("conversation_inbox", {})
    global_cfg = config.load_global_config().get("conversation_inbox", {})
    enabled = (not config.config_source_errors(include_tenant=True)
               and global_cfg.get("enabled", ENABLED_DEFAULT) is True
               and cfg.get("enabled", ENABLED_DEFAULT) is True)
    modes = [mode for mode in MODES if cfg.get(mode, True) is True and global_cfg.get(mode, True) is True]
    ceiling = global_cfg.get("max_pending", 20)
    pending = cfg.get("max_pending", 20)
    if type(ceiling) is not int or type(pending) is not int or not 1 <= ceiling <= 100 or not 1 <= pending <= 100:
        enabled, pending, ceiling = False, 20, 20
    return {"enabled": enabled, "modes": modes, "max_pending": min(pending, ceiling),
            "max_files": MAX_FILES, "max_file_bytes": MAX_BYTES, "max_total_bytes": MAX_BYTES}


def operation(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", value):
        raise ValueError("Use the original message request identity")
    return value


def _binding(record):
    return "conversation-inbox:" + digest([record["id"], record["owner"], record["root_id"]])


def _pack(value, record):
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("Conversation receipt storage is full; start a separate conversation. The current message has not changed.")
    return base64.b64encode(seal_bound(raw, _binding(record))).decode()


def _unpack(record):
    value = json.loads(unseal_bound(base64.b64decode(record["payload"], validate=True), _binding(record)).decode())
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError("Conversation inbox could not be authenticated")
    return value


def file_record(filename, mime, data):
    from .attachments import validate_attachment
    if not data or len(data) > MAX_BYTES:
        raise ValueError("Choose nonempty files up to 4 MiB")
    validate_attachment(filename, mime, data)
    sha = hashlib.sha256(data).hexdigest()
    return {"id": digest([filename, mime, sha])[:32], "filename": filename, "mime": mime,
            "size_bytes": len(data), "sha256": sha, "data": base64.b64encode(data).decode()}


def public_file(value):
    return {key: value[key] for key in ("id", "filename", "mime", "size_bytes", "sha256")}


def task_snapshot(goal):
    value = {"title": goal.title, "description": goal.description, "result": goal.result or ""}
    return {**value, "version": digest([goal.id, goal.owner, goal.domain, goal.project_id, value])}


def public_item(item):
    value = copy.deepcopy(item)
    value["files"] = [public_file(row) for row in value["files"]]
    value.pop("fingerprint", None)
    value["snapshot_version"] = (value.pop("snapshot", None) or {}).get("version", "")
    value.pop("delivery_token", None)
    value["may_edit"] = item["state"] in EDITABLE and not item.get("goal_id")
    return value


class ConversationInbox:
    def __init__(self, world, *, principal, authorize, store=None):
        if not isinstance(principal, str) or not principal.strip():
            raise PermissionError("Sign in with a named account to use the conversation inbox")
        self.world, self.principal, self.authorize = world, principal, authorize
        self.store = store or STORE
        self.tenant = current_tenant_id_strict()

    def target(self, goal_id, *, write=True):
        from .chat_threads import ChatThreads
        from .human_conversation_handoffs import require_ai_open
        from .task_handoffs import require_open
        if current_tenant_id_strict() != self.tenant:
            raise PermissionError("The workspace changed; reopen the conversation")
        goal = self.world.get_goal(goal_id)
        if not goal or goal.owner != self.principal:
            raise PermissionError("This conversation belongs to another account or is unavailable")
        self.authorize(goal)
        if write:
            require_ai_open(self.world, goal_id)
            require_open(self.world, goal_id)
        binding = ChatThreads(self.world).binding(goal_id)
        root_id = binding.root_id if binding else goal.id
        root = self.world.get_goal(root_id)
        if not root or root.owner != self.principal:
            raise PermissionError("The conversation owner changed")
        self.authorize(root)
        return goal, root

    def _read(self, root):
        identity = {"root": root.id, "owner": root.owner, "created_at": root.created_at}
        record_id = "CI-" + digest(identity)[:32]
        record = self.store.get(record_id)
        if record is None:
            return {"id": record_id, "owner": self.principal, "root_id": root.id,
                    "revision": 0, "schema": "lightwork.conversation-inbox.v1"}, {"generation": 0, "items": [], "operations": {}}
        if record.get("owner") != self.principal or record.get("root_id") != root.id:
            raise PermissionError("Conversation inbox ownership changed")
        return record, _unpack(record)

    def state(self, goal_id):
        goal, root = self.target(goal_id, write=False)
        record, value = self._read(root)
        from .task_handoffs import closure
        closed = bool(closure(self.world, goal_id))
        return {"generation": value.get("generation", 0), "execution_closed": closed,"root_id": root.id, "revision": record["revision"],
                "items": [public_item(item) for item in value["items"]],
                "target": {"id": goal.id, "title": goal.title, "description": goal.description, "status": goal.status,
                           "result": goal.result or "", "snapshot_version": task_snapshot(goal)["version"]},
                "audit_pending": bool(record.get("_audit_pending")),
                "guidance_review_version": self.review_version(goal, value)}

    @staticmethod
    def review_version(goal, value):
        return digest({"target": [goal.id, goal.title, goal.description, goal.status, goal.updated_at],
                       "guidance": [[row["id"], row["revision"], row["state"]] for row in value["items"]
                                    if row["mode"] == "guidance"]})

    def receipt(self, goal_id, operation_id):
        _, root = self.target(goal_id, write=False)
        _, value = self._read(root)
        receipt = value["operations"].get(operation(operation_id))
        if receipt is None:
            return {"received": False, "item": None}
        return {"received": True, "item": copy.deepcopy(receipt["item"])}

    def _save(self, record, value, *, actor, action):
        payload = _pack(value, record)
        if record["revision"] == 0:
            return self.store.create({key: val for key, val in {**record, "payload": payload}.items()
                                      if key != "revision"}, actor=actor, action=action)
        def change(current):
            if current.get("owner") != self.principal:
                raise PermissionError("Conversation owner changed")
            current["payload"] = payload
        saved = self.store.update(record["id"], change, expected_revision=record["revision"], actor=actor, action=action)
        if saved is None:
            raise RecordConflict("Conversation inbox changed; refresh before retrying")
        return saved

    def submit(self, goal_id, *, operation_id, mode, text, files=(), item_id=None,
               expected_revision=None, keep_files=(), independent_context="none", expected_generation=0, expected_snapshot="", task_selection=None):
        goal, root = self.target(goal_id)
        limits = policy()
        if not limits["enabled"] or mode not in limits["modes"]:
            raise PermissionError("This conversation operation is disabled by administrator policy")
        operation_id = operation(operation_id)
        if not isinstance(text, str) or not text.strip() or len(text) > 16000:
            raise ValueError("Enter a message up to 16,000 characters")
        if independent_context not in {"none", "conversation_snapshot"}:
            raise ValueError("Choose no context or a reviewed conversation snapshot")
        record, value = self._read(root)
        old = next((row for row in value["items"] if row["id"] == item_id), None)
        from .task_model_selection import validate as validate_model
        task_selection = validate_model(task_selection if task_selection is not None else (old or {}).get("task_model_selection"))
        if mode == "guidance" and task_selection is not None:
            raise ValueError("Guidance cannot change the running task's AI model. Choose the model for a new task instead.")
        args = {"goal_id": goal_id, "mode": mode, "text": text, "files": [public_file(row) for row in files],
                "item_id": item_id, "expected_revision": expected_revision, "keep_files": list(keep_files),
                "independent_context": independent_context, "expected_generation": expected_generation, "expected_snapshot": expected_snapshot}
        fingerprint = digest(args)
        if task_selection is not None:
            fingerprint = digest([args, task_selection])
        prior = value["operations"].get(operation_id)
        if prior:
            if prior["fingerprint"] != fingerprint:
                raise RecordConflict("This request identity already belongs to different message contents")
            return copy.deepcopy(prior["item"])
        if type(expected_generation) is not int or expected_generation != value.get("generation", 0):
            raise RecordConflict("Conversation data was erased or replaced; refresh before saving a new message")
        if item_id and (old is None or old["revision"] != expected_revision or old["state"] not in EDITABLE):
            raise RecordConflict("The pending message changed or was already consumed; refresh before editing")
        if old and old.get("goal_id"):
            raise RecordConflict("This message already has a durable task draft; cancel that admission before sending revised contents")
        if old and old["mode"] != mode:
            raise ValueError("Cancel this pending message before changing its execution boundary")
        if len(value["operations"]) >= 4000 or (not old and len(value["items"]) >= MAX_ITEMS):
            raise ValueError("This conversation receipt history is full; start a separate conversation")
        retained = [row for row in (old or {}).get("files", []) if row["id"] in keep_files]
        if len(retained) != len(set(keep_files)):
            raise ValueError("A retained attachment changed; refresh the pending message")
        selected = {row["id"]: row for row in [*retained, *files]}
        if len(selected) > MAX_FILES:
            raise ValueError("Choose up to ten files")
        byte_total = sum(row["size_bytes"] for row in selected.values())
        byte_total += sum(file["size_bytes"] for row in value["items"] if row is not old
                          for file in row["files"] if "data" in file)
        if byte_total > MAX_BYTES:
            raise ValueError("Pending files in one conversation must total at most 4 MiB; send fewer files or wait for pending messages")
        if not old and sum(row["state"] in EDITABLE | {"dispatching"} for row in value["items"]) >= limits["max_pending"]:
            raise ValueError("The administrator's pending-message limit is reached")
        snapshot = old.get("snapshot") if old else task_snapshot(goal)
        if independent_context == "conversation_snapshot" and (mode != "independent" or not snapshot or expected_snapshot != snapshot["version"]):
            raise RecordConflict("The selected task snapshot changed; review its exact current context before starting separately")
        if independent_context == "conversation_snapshot" and sum(len(str(snapshot[key])) for key in ("title", "description", "result")) > 32000:
            raise ValueError("This task snapshot is too large for an independent message; choose no context and include a selected summary explicitly")
        now = time.time()
        item = {"id": old["id"] if old else "turn-" + digest([self.principal, operation_id])[:32],
                "revision": old["revision"] + 1 if old else 1, "mode": mode, "text": text,
                "files": list(selected.values()), "target_id": goal_id, "created_at": old["created_at"] if old else now,
                "state": "needs_decision" if mode == "guidance" else "queued", "message": "Saved durably; not yet executed.",
                "goal_id": None, "acknowledgement": None, "independent_context": independent_context,
                "delivery_token": secrets.token_hex(16),
                "snapshot": snapshot if mode == "independent" and independent_context == "conversation_snapshot" else None,
                **({"task_model_selection": task_selection} if task_selection is not None else {})}
        if old:
            value["items"][value["items"].index(old)] = item
        else:
            value["items"].append(item)
        value["operations"][operation_id] = {"fingerprint": fingerprint, "item_id": item["id"], "item": public_item(item)}
        self.target(goal_id)
        self._save(record, value, actor=self.principal, action="message_saved")
        return public_item(item)

    def change(self, goal_id, item_id, *, expected_revision, operation_id, action, decision=None, expected_review=None):
        goal, root = self.target(goal_id, write=action != "cancel")
        record, value = self._read(root)
        operation_id = operation(operation_id)
        fingerprint = digest([item_id, expected_revision, action, decision, expected_review])
        prior = value["operations"].get(operation_id)
        if prior:
            if prior["fingerprint"] != fingerprint:
                raise RecordConflict("This request identity belongs to another change")
            return copy.deepcopy(prior["item"])
        item = next((row for row in value["items"] if row["id"] == item_id), None)
        if not item or item["revision"] != expected_revision or item["state"] not in EDITABLE:
            raise RecordConflict("The message changed or was already consumed; refresh before changing it")
        if action != "cancel" and (not policy()["enabled"] or item["mode"] not in policy()["modes"]):
            raise PermissionError("This operation is disabled by administrator policy")
        if action == "cancel":
            if item.get("goal_id"):
                from .goal_stop import stop
                draft = self.world.get_goal(item["goal_id"])
                if not draft or draft.owner != self.principal or draft.status not in {"draft", "cancelled"}:
                    raise RecordConflict("This message already reached an execution task; review that task's Stop action")
                if draft.status == "draft":
                    stop(self.world, draft.id, actor=self.principal, operation_id="inbox-cancel:" + operation_id,
                         expected_updated_at=draft.updated_at, expected_owner=self.principal)
            item["state"], item["message"] = "cancelled", "Cancelled before execution or guidance consumption."
            item["files"] = [public_file(row) for row in item["files"]]
        elif action == "approve_guidance" and item["mode"] == "guidance" and decision in {"append", "replace_pending"}:
            if item["target_id"] != goal.id or expected_review != self.review_version(goal, value):
                raise RecordConflict("The reviewed task or guidance changed; review the current brief and pending guidance before deciding")
            if goal.status in {"done", "completed", "failed", "cancelled", "blocked", "error"}:
                raise RecordConflict("The selected task is no longer running; guidance will not start another task")
            if decision == "replace_pending":
                for other in value["items"]:
                    if other is not item and other["mode"] == "guidance" and other["state"] in EDITABLE:
                        other.update(state="cancelled", message="Replaced by an explicitly reviewed guidance decision.", revision=other["revision"] + 1)
                        other["files"] = [public_file(row) for row in other["files"]]
            item["state"], item["message"] = "guidance_ready", "Approved; waiting for the selected task's next safe model-turn checkpoint."
            item["decision"] = decision
        elif action == "retry_dispatch" and item["mode"] != "guidance" and item["state"] == "blocked":
            item["state"], item["message"] = "queued", "Explicit retry requested; current authority and execution state will be checked."
        else:
            raise ValueError("Choose an available action for this pending message")
        item["revision"] += 1
        value["operations"][operation_id] = {"fingerprint": fingerprint, "item_id": item_id, "item": public_item(item)}
        self.target(goal_id, write=action != "cancel")
        self._save(record, value, actor=self.principal, action="message_" + action)
        return public_item(item)

    def transition(self, goal_id, item_id, *, revision, state, message, goal=None, acknowledgement=None):
        """Worker CAS: never resurrect an edited/cancelled message."""
        _, root = self.target(goal_id)
        record, value = self._read(root)
        item = next((row for row in value["items"] if row["id"] == item_id), None)
        if item is None or item["revision"] != revision:
            raise RecordConflict("The pending message changed before the worker claimed it")
        item.update(state=state, message=message, revision=revision + 1)
        if goal is not None:
            item["goal_id"] = goal
        if acknowledgement is not None:
            item["acknowledgement"] = acknowledgement
        if state in {"consumed", "submitted", "cancelled"}:
            item["files"] = [public_file(row) for row in item["files"]]
        self._save(record, value, actor=self.principal, action="message_" + state)
        return copy.deepcopy(item)


def current_authority(goal):
    """Web-only feature: absent dashboard authority adapters fail closed."""
    from maverick_dashboard import rbac, scim_groups
    from maverick_dashboard.auth import stored_automation_identity

    from .domain import suites_for_domain
    from .tenant.registry import assert_tenant_active
    tenant = current_tenant_id_strict()
    assert_tenant_active(tenant)
    if scim_groups.active_for_principal(goal.owner) is False:
        raise PermissionError("The task owner is no longer active")
    if tenant and "operate" not in rbac.permissions_for(rbac.get_tenant_role(tenant, goal.owner)):
        raise PermissionError("The task owner no longer has workspace execution permission")
    _, user_id, suites = stored_automation_identity(goal.owner)
    if suites is not None and not suites_for_domain(goal.domain) <= suites:
        raise PermissionError("The task department is no longer authorized")
    return user_id, suites


def publish_files(world, goal_id, files):
    """Publish content-addressed evidence without executing it or calling a model."""
    from . import attachments
    from .attachment_submissions import SubmissionStore
    published = []
    for row in files:
        if "data" not in row:
            known = next((item for item in world.list_attachments(goal_id) if item.sha256 == row["sha256"]
                          and item.filename == row["filename"] and item.size_bytes == row["size_bytes"]), None)
            if known is None:
                raise ValueError("A consumed attachment is unavailable; restore it before continuing")
            published.append(attachments.Stored(known.filename, known.mime, known.size_bytes, known.sha256, known.path))
            continue
        data = base64.b64decode(row["data"], validate=True)
        if len(data) != row["size_bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("A pending attachment failed its integrity check")
        published.append(attachments.store(goal_id, row["filename"], row["mime"], data))
    SubmissionStore(world).admit(goal_id, published, verify_existing=True)


def _delivered_earlier(acknowledgement, checkpoint_id):
    """Whether this same run already passed the checkpoint that consumed it.

    Checkpoint ids are ``<episode>:<agent>:<step>``. Compaction may summarize
    the delivered turn and its marker away; only a history resumed from before
    that checkpoint, or another run, has not seen the guidance.
    """
    run, _, step = str(checkpoint_id).rpartition(":")
    then_run, _, then_step = str((acknowledgement or {}).get("checkpoint", "")).rpartition(":")
    return (bool(run) and run == then_run and step.isdigit() and then_step.isdigit()
            and int(step) > int(then_step))


def checkpoint(world, goal_id, *, checkpoint_id, messages):
    """Deliver exact reviewed guidance at a root model-turn boundary.

Consumed records replay into an absent checkpoint history after a crash, while
the stable marker prevents duplicate insertion into an existing history. A
later checkpoint of the run that consumed it never replays it, even after
compaction removed the marker. The receipt confirms delivery to this boundary,
never semantic compliance.
"""
    from .authority_effects import authority_effect_fence
    if not policy()["enabled"] or "guidance" not in policy()["modes"]:
        return
    goal = world.get_goal(goal_id)
    if not goal or not goal.owner:
        return
    with authority_effect_fence():
        inbox = ConversationInbox(world, principal=goal.owner, authorize=lambda goal: None)
        _, root = inbox.target(goal_id, write=False)
        _, value = inbox._read(root)
        history = json.dumps(messages, ensure_ascii=False)
        for item in value["items"]:
            if item["mode"] != "guidance" or item["target_id"] != goal_id or item["state"] not in {"guidance_ready", "consuming", "consumed"}:
                continue
            inbox.authorize = current_authority
            inbox.target(goal_id)
            marker = "[Lightwork guidance receipt " + item["id"] + ":" + item["delivery_token"] + "]"
            if marker in history:
                continue
            if item["state"] == "consumed" and _delivered_earlier(item.get("acknowledgement"), checkpoint_id):
                continue
            if item["state"] == "guidance_ready":
                item = inbox.transition(goal_id, item["id"], revision=item["revision"], state="consuming",
                                        message="Claimed by the selected task at a safe checkpoint; edits are now closed.")
            current_authority(world.get_goal(goal_id))
            publish_files(world, goal_id, item["files"])
            acknowledgement = item.get("acknowledgement") or {
                "text": item["text"], "files": [public_file(row) for row in item["files"]],
                "checkpoint": str(checkpoint_id), "at": time.time()}
            names = ", ".join(row["filename"] for row in item["files"]) or "none"
            messages.append({"role": "user", "content": marker + "\nThe task owner explicitly reviewed this additional guidance. "
                             "It cannot undo completed actions, widen tools, permissions or budget, or override higher-priority policy. "
                             "If it conflicts with completed work or other instructions, ask for a decision before acting.\n"
                             + item["text"] + "\nAttached evidence available through the task attachment tools (not yet read): " + names})
            if item["state"] == "consuming":
                inbox.transition(goal_id, item["id"], revision=item["revision"], state="consumed",
                                 message="Delivered at a safe model-turn checkpoint. This is delivery evidence, not proof of compliance.",
                                 acknowledgement=acknowledgement)


def _human_private(value):
    sessions=value.get("human",{}).get("sessions",{}).values()
    return bool(value.get("label") or value.get("until") or any(session.get("purpose") or session.get("messages")
        or any(session.get("shared",{}).values()) for session in sessions))


def _human_held(value):
    from .human_conversation_handoffs import HELD
    return any(session.get("state") in HELD for session in value.get("human",{}).get("sessions",{}).values())


def owned_inventory(principal):
    """Owned My Data inventory; the adapter owns verified actor admission."""
    if not isinstance(principal, str) or not principal.startswith("user:"):
        raise PermissionError("A named data owner is required")
    result, cursor, seen, owned = [], "", set(), 0
    while True:
        page = list(STORE.iter_record_ids(start_after=cursor, limit=100))
        if not page:
            break
        for position, record_id in page:
            cursor = position
            if record_id in seen:
                return result
            seen.add(record_id)
            record = STORE.get(record_id)
            if record and record.get("owner") == principal:
                # Only this owner's records count: other people's volume
                # must not make anyone's inventory (or erasure) fail.
                owned += 1
                if owned > 10000:
                    raise ValueError("Conversation inventory needs a narrower reviewed owner scope")
                payload = _unpack(record)
                if any(item["state"] != "erased" for item in payload["items"]) or _human_private(payload):
                    result.append({"id": record_id, "revision": record["revision"], "owner": principal,
                                   "root_id": record["root_id"], "inflight": _human_held(payload) or bool(payload.get("human", {}).get("sessions") and record.get("_audit_pending")) or any(item["state"] in {"consuming", "dispatching"}
                                       for item in payload["items"])})
                if len(result) > 1000:
                    raise ValueError("Conversation inventory exceeds the reviewed bounded export; narrow the request")
    return result


def owned_items(principal):
    """Every message still held for ``principal`` across their conversations (legal-matter scope).

    Read only: erased items are left out, and no record is changed.
    """
    items = []
    for record in owned_inventory(principal):
        for item in export_owned(principal, record["id"], record["revision"])["items"]:
            if item["state"] != "erased":
                items.append({**item, "conversation_id": record["id"]})
    return items


def export_owned(principal, record_id, expected_revision):
    record = STORE.get(record_id)
    if not record or record.get("owner") != principal:
        raise PermissionError("Conversation data is outside the reviewed owner scope")
    if type(expected_revision) is not int or record["revision"] != expected_revision:
        raise RecordConflict("Conversation data changed after the export review")
    value=_unpack(record)
    result={"id": record_id, "revision": record["revision"], "owner": principal, "root_id": record["root_id"],
            "items": copy.deepcopy(value["items"])}
    if "human" in value:
        result["human_conversations"]=copy.deepcopy(value["human"])
    if "label" in value:
        result["on_duty"]={"label":value["label"],"until":value["until"]}
    return result


def erase_owned(principal, record_id, expected_revision, operation_id, *, actor):
    """Reviewed erasure; keep only replay tombstones and a stale-save barrier."""
    operation_id = operation(operation_id)
    if not isinstance(actor, str) or not actor.startswith("user:"):
        raise PermissionError("A reviewed deletion actor is required")
    record = STORE.get(record_id)
    if not record or record.get("owner") != principal:
        raise PermissionError("Conversation data is outside the reviewed owner scope")
    value = _unpack(record)
    previous = value.get("erasures", {}).get(operation_id)
    fingerprint = digest([principal, actor, expected_revision])
    if previous:
        if previous != fingerprint:
            raise RecordConflict("The erasure request identity belongs to a different review")
        return {"status": "unconfirmed" if record.get("_audit_pending") else "replayed", "revision": record["revision"]}
    if type(expected_revision) is not int or record["revision"] != expected_revision:
        raise RecordConflict("Conversation data changed after the erasure review")
    if _human_held(value) or (value.get("human", {}).get("sessions") and record.get("_audit_pending")):
        raise RecordConflict("Read the original decision and hand back any active human conversation first. Unconfirmed sharing and AI holds cannot be erased silently.")
    if any(item["state"] in {"consuming", "dispatching"} for item in value["items"]):
        raise RecordConflict("A conversation message is being consumed or admitted. Review its durable receipt before erasure")
    from .ediscovery import assert_personal_chats_erasable
    # A legal matter that holds any message of this conversation refuses the erasure before any change.
    assert_personal_chats_erasable(principal, [item["created_at"] for item in value["items"]
                                               if item["state"] != "erased"], actor=actor)
    for item in value["items"]:
        item.update(text="", files=[], snapshot=None, acknowledgement=None, state="erased",
                    message="Private message contents erased by the reviewed owner data request.", revision=item["revision"] + 1)
    for session in value.get("human",{}).get("sessions",{}).values():
        session.update(shared={"title":"","brief":"","saved_reply":""},purpose="",messages=[],duty_label="",erased=True)
    if "label" in value:
        value.update(label="",until=0)
    for receipt in value["operations"].values():
        if "item_id" not in receipt:
            continue
        receipt["item"] = public_item(next(item for item in value["items"] if item["id"] == receipt["item_id"]))
    value["generation"] = value.get("generation", 0) + 1
    value.setdefault("erasures", {})[operation_id] = fingerprint
    payload = _pack(value, record)
    def clear(current):
        if current.get("owner") != principal:
            raise PermissionError("Conversation owner changed")
        current["payload"] = payload
    saved = STORE.update(record_id, clear, expected_revision=expected_revision, action="conversation_data_erased", actor=actor)
    if not saved:
        raise RecordConflict("Conversation data is no longer available")
    return {"status": "unconfirmed" if saved.get("_audit_pending") else "confirmed", "revision": saved["revision"]}
