"""Encrypted, tenant-owned native action evidence with authenticated review.

Enrollment grants bounded retention, never execution authority. Native hooks run
inside the existing run lock; capture failure must not replay a business effect.
The local governed store is not assumed to encrypt new rows: sensitive content
is explicitly sealed and bound to its record, tenant, run and logical revision.
"""
from __future__ import annotations

import copy
import json
import math
import re
import time
from dataclasses import dataclass

from .. import crypto_at_rest
from ..audit.errors import AuditRefused
from ..governed_operations import ServiceContext, audit_authority_denial, digest
from ..governed_records import GovernedRecordStore, RecordConflict
from ..paths import current_tenant_id_strict, tenant_scope
from . import store
from .action_episodes import (
    MAX_EPISODE_BYTES,
    TEACHING_FAMILY,
    _object,
    _result_object,
    _snapshot,
    capture_plan,
    teaching_capture_plan,
)
from .approvals import paused_operation_binding

SCHEMA = "lightwork.action-episode-review.v1"
ENVELOPE_SCHEMA = "lightwork.action-episode-envelope.v1"
MAX_RECORDS = 1000
MAX_RETENTION_SECONDS = 604800
# Schemas add properties/items containers, and envelopes add metadata wrappers.
# Their JSON depth is distinct from the unchanged eight-level business limit.
_METADATA_DEPTH = 24
_RECORDS = GovernedRecordStore("flow_action_episodes", "LAE", "flow_action_episode")
_CALL_ID = re.compile(r"[0-9a-f]{24}\Z")
_META = ("schema", "id", "binding", "contract_sha256", "enrollment_sha256", "retain_until",
         "status", "reason", "completed_steps", "planned_steps", "episode_sha256", "payload_revision")
_META_OPTIONAL = ("review_revision", "review_sha256", "grant_sha256", "bundle_sha256", "withdrawal", "teaching_sha256", "decision_receipts")


class ActionEpisodeConflict(RecordConflict):
    """An enrollment, revision, immutable source or reviewed verdict changed."""


class ActionEpisodeAuditPending(AuditRefused):
    def __init__(self, record_id: str):
        super().__init__("action episode has a pending audit receipt")
        self.record_id = record_id


def _text(value, label, maximum=256):
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} must be a nonempty bounded string")
    return value


def _number(value, label):
    if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)):
        raise ValueError(f"{label} must be a finite number")
    return value


def _revision(value):
    if type(value) is not int or value < 1:
        raise ValueError("expected_revision must be a positive integer")
    return value


def _schema(value, *, root=True, depth=0, remaining=None):
    """Admit a small closed schema language, never arbitrary JSON Schema code."""
    remaining = [512] if remaining is None else remaining
    remaining[0] -= 1
    if type(value) is not dict or depth > 8 or remaining[0] < 0:
        raise ValueError("retention schema exceeds its structural limit")
    kind = value.get("type")
    if root and kind != "object":
        raise ValueError("retained inputs, arguments and results require object schemas")
    allowed = {"boolean": {"type"}, "null": {"type"},
               "string": {"type", "maxLength", "minLength"},
               "integer": {"type", "minimum", "maximum"},
               "number": {"type", "minimum", "maximum"},
               "array": {"type", "items", "minItems", "maxItems"},
               "object": {"type", "properties", "required", "additionalProperties"}}
    if type(kind) is not str or kind not in allowed or set(value) - allowed[kind]:
        raise ValueError("unsupported retention schema keyword or type")
    if kind == "object":
        props, required = value.get("properties"), value.get("required")
        if (type(props) is not dict or len(props) > 64 or type(required) is not list
                or any(type(key) is not str for key in required)
                or len(set(required)) != len(required) or set(required) != set(props)
                or value.get("additionalProperties") is not False):
            raise ValueError("object schema must require every declared field and reject extras")
        for key, child in props.items():
            _text(key, "schema field", 1024)
            _schema(child, root=False, depth=depth + 1, remaining=remaining)
    elif kind == "array":
        low, high = value.get("minItems"), value.get("maxItems")
        if type(low) is not int or type(high) is not int or low != high or not 0 <= low <= 64:
            raise ValueError("array schema requires one bounded exact length")
        _schema(value.get("items"), root=False, depth=depth + 1, remaining=remaining)
    elif kind == "string":
        high, low = value.get("maxLength"), value.get("minLength", 0)
        if type(high) is not int or type(low) is not int or not 0 <= low <= high <= 1024 or high < 1:
            raise ValueError("string schema requires bounded lengths")
    elif kind in {"integer", "number"}:
        low, high = _number(value.get("minimum"), "minimum"), _number(value.get("maximum"), "maximum")
        if kind == "integer" and (type(low) is not int or type(high) is not int):
            raise ValueError("integer schema bounds must be integers")
        if not -10**24 <= low <= high <= 10**24:
            raise ValueError("numeric schema bounds exceed limits")


def _matches(value, schema):
    kind = schema["type"]
    expected = {"object": dict, "array": list, "string": str, "integer": int,
                "number": float, "boolean": bool, "null": type(None)}[kind]
    if type(value) is not expected:
        raise ValueError("retained value does not match its strict declared type")
    if kind == "object":
        if set(value) != set(schema["properties"]):
            raise ValueError("retained object has missing or unexpected fields")
        for key, child in value.items():
            _matches(child, schema["properties"][key])
    elif kind == "array":
        if len(value) != schema["minItems"]:
            raise ValueError("retained array changed its declared length")
        for child in value:
            _matches(child, schema["items"])
    elif kind == "string" and not schema.get("minLength", 0) <= len(value) <= schema["maxLength"]:
        raise ValueError("retained string exceeds its declared bounds")
    elif kind in {"integer", "number"} and not schema["minimum"] <= value <= schema["maximum"]:
        raise ValueError("retained number exceeds its declared bounds")


def _contract(allowed_tools, input_schema, tool_data_schemas):
    if (type(allowed_tools) is not list or not 1 <= len(allowed_tools) <= 8
            or any(type(tool) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", tool)
                   for tool in allowed_tools) or len(set(allowed_tools)) != len(allowed_tools)):
        raise ValueError("capture requires an explicit unique tool allowlist")
    if type(tool_data_schemas) is not dict or set(tool_data_schemas) != set(allowed_tools):
        raise ValueError("capture schemas must name exactly the allowed tools")
    _schema(input_schema)
    for pair in tool_data_schemas.values():
        if type(pair) is not dict or set(pair) != {"arguments", "result"}:
            raise ValueError("each tool requires exact arguments and result schemas")
        _schema(pair["arguments"])
        _schema(pair["result"])
    return _snapshot({"allowed_tools": sorted(allowed_tools), "input_schema": input_schema,
                      "tool_data_schemas": tool_data_schemas}, limit=MAX_EPISODE_BYTES,
                     private=False, max_depth=_METADATA_DEPTH)


def _identifier(tenant, flow_id, run_id):
    return "LAE-" + digest({"tenant": tenant, "flow_id": flow_id, "run_id": run_id})[:32]


def _binding(ctx, run, pinned):
    family = TEACHING_FAMILY if getattr(pinned, "recipe_teaching", None) is not None else "native_governed_flow_actions_v1"
    return {"family": family, "tenant_sha256": digest(ctx.tenant),
            "owner": run.owner, "flow_id": run.flow_id, "run_id": run.run_id,
            "definition_digest": run.definition_digest, "definition_version": run.definition_version,
            "definition_revision": run.definition_revision, "release_digest": run.release_digest,
            "release_id": run.release_id, "plan_sha256": digest(pinned.to_dict()),
            "original_input_sha256": digest(run.input_data),
            "execution_identity_sha256": digest({"channel": run.execution_channel,
                "user_id": run.execution_user_id, "allowed_suites": run.allowed_suites})}


def _source(ctx, flow_id, run_id):
    current = store.load_flow(flow_id)
    run = store.load_run(run_id, owner=ctx.resource_owner, flow_id=flow_id)
    if current is None or run is None:
        raise LookupError("capture source is unavailable")
    if not current.owner or current.owner != ctx.resource_owner or run.owner != current.owner:
        raise PermissionError("capture requires the current source owner")
    pinned = store.load_flow_snapshot(run.definition_digest)
    if (pinned.id != flow_id or pinned.owner != run.owner or run.dry_run
            or pinned.version != run.definition_version or pinned.revision != run.definition_revision
            or current.revision != run.definition_revision):
        raise ActionEpisodeConflict("capture source generation changed")
    return run, pinned, digest(current.to_dict()) == digest(pinned.to_dict())


def _teaching_gate():
    from ..config import get_flows

    if get_flows().get("action_recipe_teaching") is not True:
        raise PermissionError("native choice teaching capture is disabled")


def _validate_teaching_options(question, contract):
    """Every retained hypothetical option needs its own declared data bounds."""
    for option in question["options"]:
        _matches(_object(option["arguments"]), contract["tool_data_schemas"][option["tool"]]["arguments"])


def _validate_teaching_capture(row, payload, run, pinned):
    """Recheck the actual selected plan and question against immutable source bytes."""
    from . import recipe_flow

    if row["binding"]["family"] != TEACHING_FAMILY:
        if getattr(pinned, "recipe_teaching", None) is not None or "teaching" in payload:
            raise ValueError("teaching provenance cannot use the straight-line capture family")
        return
    plan = teaching_capture_plan(pinned, allowed_tools=payload["contract"]["allowed_tools"])
    if payload.get("teaching_plan") != plan or row["planned_steps"] != 2:
        raise ValueError("retained teaching plan changed")
    teaching = payload.get("teaching")
    if teaching is None:
        if (payload["expected"] != [plan["prefix"]] or len(payload["slots"]) > 1
                or row.get("teaching_sha256")
                or row["status"] in {"awaiting_review", "accepted", "rejected", "withdrawn"}):
            raise ValueError("teaching capture requires a native authenticated route choice")
        return
    from .action_provenance import local_trust, validate_teaching, verify_teaching_signature

    if not payload["slots"] or payload["slots"][0]["status"] != "completed":
        raise ValueError("teaching decision lacks a complete native prefix")
    if (digest(teaching) != row.get("teaching_sha256")
            or teaching["parent_lineage"] != pinned.recipe_lineage):
        raise ValueError("teaching decision or parent admission commitment changed")
    question = recipe_flow.validate_teaching_question(pinned.learned_recipe, {
        "input": payload["inputs"], "_recipe_step_0": payload["slots"][0]["result"],
        "_recipe_teaching_question": teaching["question"],
    })
    if question != teaching["question"]:
        raise ValueError("teaching question changed")
    _validate_teaching_options(question, payload["contract"])
    selected = plan["branches"].get(teaching["route"])
    if selected is None or teaching["tool"] != selected[1] or payload["expected"] != [plan["prefix"], selected]:
        raise ValueError("teaching selected execution plan changed")
    validate_teaching(teaching, source=row["binding"], inputs=payload["inputs"],
                      prefix_result=payload["slots"][0]["result"])
    tenant = current_tenant_id_strict()
    verify_teaching_signature(teaching, trust=local_trust(tenant), tenant=tenant)
    if len(payload["slots"]) > 2:
        raise ValueError("teaching capture contains extra effects")
    for index, slot in enumerate(payload["slots"]):
        if [slot["node_id"], slot["tool"]] != payload["expected"][index]:
            raise ValueError("teaching capture used the wrong native action")
    if len(payload["slots"]) == 2:
        option = next(item for item in question["options"] if item["route"] == teaching["route"])
        if payload["slots"][1]["arguments"] != option["arguments"]:
            raise ValueError("native teaching terminal arguments differ from the reviewed choice")
    if run.status == "completed":
        if (run.data.get("_recipe_teaching_decision") != "route:" + teaching["route"]
                or run.data.get("_recipe_teaching_question") != question):
            raise ValueError("durable teaching decision differs from native source completion")
        finished_actions = {node.id for node in pinned.nodes.values() if node.kind == "action"
                            and (run.nodes.get(node.id) or {}).get("status") == "done"}
        if finished_actions != {pair[0] for pair in payload["expected"]}:
            raise ValueError("completed teaching source has a different native action trace")


def _episode(row, payload):
    return {"id": row["binding"]["run_id"], "inputs": copy.deepcopy(payload["inputs"]),
            "steps": [{"tool": slot["tool"], "arguments": copy.deepcopy(slot["arguments"]),
                       "result": copy.deepcopy(slot["result"])} for slot in payload["slots"]]}


def _seal(row, payload, revision):
    if not crypto_at_rest.at_rest_enabled():
        raise crypto_at_rest.EncryptionUnavailable("retained action evidence requires encryption")
    row["payload_revision"] = revision
    material = _metadata(row)
    envelope = {"schema": ENVELOPE_SCHEMA, "metadata_sha256": digest(material), "payload": payload}
    if row.get("bundle_sha256"):
        from .action_provenance import canonical
        raw = canonical(envelope, max_bytes=524_288)
    else:
        raw = json.dumps(_snapshot(envelope, limit=MAX_EPISODE_BYTES, private=False,
                                   max_depth=_METADATA_DEPTH),
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    sealed = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(sealed):
        raise crypto_at_rest.EncryptionUnavailable("retained evidence encryption did not produce ciphertext")
    row["sensitive_envelope"] = sealed


def _metadata(row):
    return {key: row[key] for key in (*_META, *_META_OPTIONAL) if key in row}


def _open(ctx, row):
    bound = row.get("binding", {})
    if (row.get("schema") != SCHEMA or bound.get("tenant_sha256") != digest(ctx.tenant)
            or bound.get("owner") != ctx.resource_owner
            or row.get("id") != _identifier(ctx.tenant, bound.get("flow_id"), bound.get("run_id"))):
        raise PermissionError("retained evidence belongs to another source or tenant")
    if row.get("payload_revision") != row.get("revision", 1):
        raise ValueError("retained evidence revision binding changed")
    if row.get("status") == "expired":
        if "sensitive_envelope" in row:
            raise ValueError("expired capture still contains sensitive evidence")
        return None
    token = row.get("sensitive_envelope")
    if not crypto_at_rest.is_sealed_str(token):
        raise ValueError("retained evidence requires a sealed envelope; plaintext is refused")
    envelope = json.loads(crypto_at_rest.unseal_from_str(token))
    if row.get("bundle_sha256"):
        from .action_provenance import canonical
        canonical(envelope, max_bytes=524_288)
    else:
        _snapshot(envelope, limit=MAX_EPISODE_BYTES, private=False, max_depth=_METADATA_DEPTH)
    if (set(envelope) != {"schema", "metadata_sha256", "payload"}
            or envelope["schema"] != ENVELOPE_SCHEMA
            or envelope["metadata_sha256"] != digest(_metadata(row))):
        raise ValueError("retained evidence envelope binding changed")
    payload = envelope["payload"]
    if digest(payload["contract"]) != row["contract_sha256"]:
        raise ValueError("retention contract commitment changed")
    if row.get("withdrawal"):
        withdrawal = payload.get("withdrawal")
        if (type(withdrawal) is not dict or set(withdrawal) != {"rationale"}
                or digest(_text(withdrawal["rationale"], "withdrawal rationale", 2000)) != row["withdrawal"]["rationale_sha256"]):
            raise ValueError("retained withdrawal rationale commitment changed")
    return payload


def _gate():
    from ..config import get_flows
    from ..learning_guard import learning_write_allowed
    from . import enabled

    if (not enabled() or get_flows().get("action_episode_capture") is not True
            or not learning_write_allowed("flow_action_episode_capture")):
        raise PermissionError("durable action episode capture is disabled or halted")


def _lineage_gate():
    from ..config import get_flows

    _gate()
    if get_flows().get("action_recipe_lineage") is not True:
        raise PermissionError("signed action evidence is disabled")


class ActionEpisodeReviewService:
    """Retain one encrypted record; callbacks must freshly authenticate authority."""

    def __init__(self, authorize, *, records=None, clock=time.time):
        if not callable(authorize) or not callable(clock):
            raise TypeError("capture requires authoritative authorization and clock callbacks")
        self.authorize = authorize
        self.records = _RECORDS if records is None else records
        self.clock = clock

    def _permit(self, ctx, capability, flow_id, *, human=False):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        if (human and ctx.human is not True) or self.authorize(ctx, capability, flow_id) is not True:
            audit_authority_denial(ctx, capability, flow_id, "capture_authority_denied")
            raise PermissionError("current authority denied action episode access")

    def _recover(self, row):
        if row.get("_audit_pending"):
            self.records.retry_pending(limit=MAX_RECORDS)
            row = self.records.get(row["id"])
            if row is None:
                raise LookupError("action episode is unavailable")
        return row

    def _fresh(self, ctx, row):
        run, pinned, current = _source(ctx, row["binding"]["flow_id"], row["binding"]["run_id"])
        if _binding(ctx, run, pinned) != row["binding"]:
            raise ActionEpisodeConflict("retained source binding changed")
        return run, pinned, current

    def _decision_source(self, ctx, row, capability):
        if not self._fresh(ctx, row)[2] and capability in {"flow.episode.review", "flow.episode.grant"}:
            raise ActionEpisodeConflict("reviewed procedure changed before learning decision")

    def _commit(self, ctx, row, payload, *, status, reason, action, capability, episode_sha256=None, metadata=None,
                decision=None, before_write=None):
        if row.get("_audit_pending"):
            raise ActionEpisodeAuditPending(row["id"])
        # Withdrawing existing authority is maintenance, not permission to learn.
        # Keep its human/source/CAS/encryption/audit checks while a feature or
        # learning halt prevents every expansive operation.
        withdrawal = status == "withdrawn" and capability == "flow.episode.withdraw"

        def mutate(current):
            _open(ctx, current)
            self._permit(ctx, capability, current["binding"]["flow_id"])
            self._decision_source(ctx, current, capability)
            if status != "expired":
                if not withdrawal:
                    _gate()
                if self.clock() >= current["retain_until"]:
                    raise ActionEpisodeConflict("capture retention expired")
            if before_write is not None:
                before_write()
            current.update(status=status, reason=reason)
            if metadata:
                current.update(metadata)
            if decision is not None:
                receipts = copy.deepcopy(current.get("decision_receipts", []))
                if len(receipts) >= 2 or any(item["operation"] == decision["operation"] for item in receipts):
                    raise ActionEpisodeConflict("original learning decision identity is unavailable")
                receipts.append({**decision, "actor": ctx.actor, "action": capability,
                    "source_revision": row["revision"], "episode_sha256": row["episode_sha256"],
                    "recorded_at": self.clock(), "accepted": status == "accepted"})
                current["decision_receipts"] = receipts
            if payload is not None:
                current["completed_steps"] = sum(slot["status"] == "completed" for slot in payload["slots"])
            if episode_sha256 is not None:
                current["episode_sha256"] = episode_sha256
            if status == "expired":
                current.pop("sensitive_envelope", None)
                current["payload_revision"] = current["revision"] + 1
            else:
                _seal(current, payload, current["revision"] + 1)
            # Sealing can be slow: recheck current authority/source after the
            # expensive work, while still inside the guarded CAS mutation.
            self._permit(ctx, capability, current["binding"]["flow_id"])
            self._decision_source(ctx, current, capability)
            if status != "expired":
                if not withdrawal:
                    _gate()
                    if capability in {"flow.episode.grant", "flow.episode.export_signed"}:
                        _lineage_gate()
                    if capability == "flow.episode.grant" and self.clock() >= payload["training_grant"]["use_until"]:
                        raise ActionEpisodeConflict("training permission expired before admission")
                if self.clock() >= current["retain_until"]:
                    raise ActionEpisodeConflict("capture retention expired")
            if before_write is not None:
                before_write()

        saved = self.records.update(row["id"], mutate, expected_revision=row["revision"],
                                    action=action, actor=ctx.actor)
        if saved is None:
            raise LookupError("action episode is unavailable")
        return saved

    def _load(self, ctx, flow_id, run_id, capability, *, human=False, reconcile=True):
        self._permit(ctx, capability, flow_id, human=human)
        row = self.records.get(_identifier(ctx.tenant, flow_id, run_id))
        if row is None:
            raise LookupError("action episode is unavailable")
        payload = _open(ctx, row)
        # Ownership is mandatory before recovery, but an edited historical source
        # must not strand the already committed hash-only audit outbox.
        current = store.load_flow(flow_id)
        if current is None or current.owner != ctx.resource_owner:
            raise PermissionError("capture source owner changed")
        row = self._recover(row)
        payload = _open(ctx, row)
        self._permit(ctx, capability, flow_id, human=human)
        run, pinned, source_current = self._fresh(ctx, row)
        if payload is not None:
            _validate_teaching_capture(row, payload, run, pinned)
        if row["status"] != "expired" and self.clock() >= row["retain_until"]:
            if not row.get("_audit_pending"):
                row = self._commit(ctx, row, None, status="expired", reason="retention_expired",
                                   action="action_episode_expired", capability=capability)
            payload = None
        elif (reconcile and not row.get("_audit_pending")
              and row["status"] in {"enrolled", "capturing", "paused"}):
            row = self._checkpoint(ctx, row, payload, run, capability)
            payload = _open(ctx, row)
        return row, payload, source_current

    def _present(self, row, payload=None, *, source_current=False, detail=False):
        result = {key: copy.deepcopy(row[key]) for key in
                  ("schema", "id", "revision", "binding", "retain_until", "completed_steps",
                   "planned_steps", "episode_sha256", "reason")}
        result.update(status=row["status"], audit_status="delivered", source_current=source_current)
        result.update({key: copy.deepcopy(row[key]) for key in _META_OPTIONAL if key in row})
        grant = payload.get("training_grant") if type(payload) is dict else None
        result["training_available"] = bool(
            row["status"] == "accepted" and not row.get("_audit_pending") and type(grant) is dict
            and row.get("grant_sha256") == digest(grant)
            and self.clock() < grant["use_until"] <= row["retain_until"])
        if row.get("_audit_pending"):
            result.update(status="audit_pending", committed_status=row["status"], audit_status="pending")
        elif detail and payload is not None and row["status"] == "withdrawn" and self.clock() < row["retain_until"]:
            result["withdrawal_detail"] = copy.deepcopy(payload["withdrawal"])
        elif detail and payload is not None and row["status"] != "withdrawn" and self.clock() < row["retain_until"]:
            evidence = copy.deepcopy(payload)
            # Signed bytes have their own fresh trust/authority boundary. A
            # general detail read must not bypass export_signed after recovery.
            evidence.pop("issuance", None)
            result["evidence"] = evidence
        return result

    def enroll(self, ctx, flow_id, run_id, *, expected_pause_binding, allowed_tools,
               input_schema, tool_data_schemas, retain_until):
        _text(flow_id, "flow_id")
        _text(run_id, "run_id")
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            _gate()
            self._permit(ctx, "flow.episode.enroll", flow_id, human=True)
            contract = _contract(allowed_tools, input_schema, tool_data_schemas)
            expiry = _number(retain_until, "retain_until")
            if not self.clock() < expiry <= self.clock() + MAX_RETENTION_SECONDS:
                raise ValueError("retention must expire within seven days")
            request_hash = digest({"pause": expected_pause_binding, "contract": contract, "expiry": expiry})
            identity = _identifier(ctx.tenant, flow_id, run_id)
            existing = self.records.get(identity)
            if existing is not None:
                row, payload, current = self._load(ctx, flow_id, run_id, "flow.episode.enroll", human=True)
                if row["enrollment_sha256"] != request_hash:
                    raise ActionEpisodeConflict("run already has a different capture enrollment")
                return self._present(row, payload, source_current=current)
            run, pinned, current = _source(ctx, flow_id, run_id)
            teaching_plan = None
            if getattr(pinned, "recipe_teaching", None) is not None:
                _teaching_gate()
                teaching_plan = teaching_capture_plan(pinned, allowed_tools=allowed_tools)
                from . import recipe_flow
                recipe_flow.check_lineage(pinned.learned_recipe, pinned.recipe_lineage, owner=run.owner)
                expected = [teaching_plan["prefix"]]
            else:
                expected = capture_plan(pinned, allowed_tools=allowed_tools, no_forms=True)
            if (run.status != "paused_approval" or run.cursor != pinned.start
                    or pinned.nodes[pinned.start].kind != "approval"
                    or any(node_id in run.nodes for node_id, _ in expected)
                    or paused_operation_binding(run) != expected_pause_binding):
                raise ActionEpisodeConflict("capture enrollment requires the exact initial approval before actions")
            inputs = _object(run.input_data.get("input", run.input_data))
            _matches(inputs, contract["input_schema"])
            payload = {"inputs": inputs, "contract": contract, "expected": [list(pair) for pair in expected],
                       "slots": [], "pause": {"binding": expected_pause_binding, "cursor": run.cursor},
                       "enrollment": {"actor": ctx.actor, "authority_sha256": digest(ctx.binding()),
                                      "enrolled_at": self.clock()}, "review": None}
            if teaching_plan is not None:
                payload.update(teaching_plan=teaching_plan, teaching=None)
            row = {"schema": SCHEMA, "id": identity, "binding": _binding(ctx, run, pinned),
                   "contract_sha256": digest(contract), "enrollment_sha256": request_hash,
                   "retain_until": expiry, "status": "enrolled", "reason": "initial_approval_enrollment",
                   "completed_steps": 0, "planned_steps": 2 if teaching_plan is not None else len(expected), "episode_sha256": ""}
            _seal(row, payload, 1)
            self._permit(ctx, "flow.episode.enroll", flow_id, human=True)
            latest, _, _ = _source(ctx, flow_id, run_id)
            if paused_operation_binding(latest) != expected_pause_binding:
                raise ActionEpisodeConflict("initial approval changed during enrollment")
            _gate()
            saved = self.records.create(row, action="action_episode_enrolled", actor=ctx.actor, max_records=MAX_RECORDS)
            return self._present(saved, source_current=current)

    def _checkpoint(self, ctx, row, payload, run, capability):
        if row["status"] not in {"enrolled", "capturing", "paused"}:
            return row
        slots = payload["slots"]
        complete = all(slot["status"] == "completed" for slot in slots)
        expected = payload["expected"]
        finished = [node for node, _ in expected if (run.nodes.get(node) or {}).get("status") == "done"]
        admitted = [slot["node_id"] for slot in slots if slot["status"] == "completed"]
        if not complete or finished != admitted:
            status, reason = "unusable", "native_prefix_incomplete"
        elif row["binding"]["family"] == TEACHING_FAMILY and run.status == "completed" and not payload.get("teaching"):
            status, reason = "unusable", "teaching_requires_authenticated_choice"
        elif run.status == "completed" and len(slots) == len(expected):
            return self._commit(ctx, row, payload, status="awaiting_review", reason="native_episode_complete",
                                action="action_episode_completed", capability=capability,
                                episode_sha256=digest(_episode(row, payload)))
        elif run.status == "paused_approval":
            pause = {"binding": paused_operation_binding(run), "cursor": run.cursor}
            if payload["pause"] == pause and row["status"] in {"enrolled", "paused"}:
                return row
            payload["pause"] = pause
            status, reason = "paused", "native_approval_pause"
        elif run.status in {"running", "resuming"}:
            status, reason = "unusable", "interrupted_capture_segment"
        else:
            status, reason = "unusable", "source_run_not_complete"
        return self._commit(ctx, row, payload, status=status, reason=reason,
                            action="action_episode_checkpoint", capability=capability)

    def get(self, ctx, flow_id, run_id, *, detail=False):
        if type(detail) is not bool:
            raise ValueError("detail must be a boolean")
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            _gate()
            capability = "flow.episode.detail" if detail else "flow.episode.read"
            row, payload, current = self._load(ctx, flow_id, run_id, capability)
            return self._present(row, payload, source_current=current, detail=detail)

    @staticmethod
    def _validate_decision(decision):
        if decision is not None and (type(decision) is not dict
                or set(decision) != {"operation", "context", "binding"}
                or any(type(decision[key]) is not str or not re.fullmatch(pattern, decision[key])
                       for key, pattern in (("operation", r"[a-f0-9]{32}"), ("context", r"[a-f0-9]{64}"), ("binding", r"[a-f0-9]{64}")))):
            raise ValueError("invalid original learning decision identity")

    def original_decision(self, ctx, flow_id, run_id, *, operation, context):
        """Read only actual accepted decision metadata; never infer from current status."""
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            self._permit(ctx, "flow.episode.read", flow_id)
            row = self.records.get(_identifier(ctx.tenant, flow_id, run_id))
            if row is None:
                raise LookupError("original learning decision is unavailable")
            _open(ctx, row)
            receipt = next((item for item in row.get("decision_receipts", [])
                            if item["operation"] == operation and item["actor"] == ctx.actor and item["context"] == context), None)
            self._permit(ctx, "flow.episode.read", flow_id)
            return {"receipt": copy.deepcopy(receipt), "audit_pending": bool(row.get("_audit_pending")),
                    "current_status": row["status"], "current_revision": row["revision"],
                    "decisions": [copy.deepcopy(item) for item in row.get("decision_receipts", [])
                                  if item["actor"] == ctx.actor and item["context"] == context]}

    def review(self, ctx, flow_id, run_id, *, expected_revision, expected_episode_sha256, accepted, rationale,
               decision=None, before_write=None):
        revision = _revision(expected_revision)
        if type(accepted) is not bool:
            raise ValueError("accepted must be a boolean")
        rationale = _snapshot(_text(rationale, "rationale", 2000))
        self._validate_decision(decision)
        request_material = {"episode": expected_episode_sha256, "accepted": accepted,
                            "rationale": rationale, "reviewer": ctx.actor}
        if decision is not None:
            request_material["decision"] = decision
        request_hash = digest(request_material)
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id), store._definitions_lock():
            _gate()
            row, payload, current = self._load(ctx, flow_id, run_id, "flow.episode.review", human=True)
            if row.get("_audit_pending"):
                return self._present(row, source_current=current)
            if payload is not None and payload["review"] is not None:
                if payload["review"]["request_sha256"] == request_hash:
                    return self._present(row, source_current=current)
                raise ActionEpisodeConflict("episode already has a different reviewed verdict")
            if (row["status"] != "awaiting_review" or row["revision"] != revision
                    or row["episode_sha256"] != expected_episode_sha256
                    or digest(_episode(row, payload)) != expected_episode_sha256):
                raise ActionEpisodeConflict("review requires the exact complete episode and revision")
            payload["review"] = {"reviewed": True, "accepted": accepted, "authenticated": True,
                "reviewer": ctx.actor, "rationale": rationale, "reviewed_at": self.clock(),
                "authority": "authenticated_service_context", "authority_sha256": digest(ctx.binding()),
                "episode_sha256": expected_episode_sha256, "request_sha256": request_hash}
            saved = self._commit(ctx, row, payload, status="accepted" if accepted else "rejected",
                                 reason="reviewed_training_evidence", action="action_episode_reviewed",
                                 capability="flow.episode.review", metadata={"review_revision": row["revision"] + 1,
                                                                            "review_sha256": digest(payload["review"])},
                                 decision=decision, before_write=before_write)
            return self._present(saved, source_current=current)

    def export(self, ctx, flow_id, run_id):
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            _gate()
            row, payload, current = self._load(ctx, flow_id, run_id, "flow.episode.export")
            if row.get("_audit_pending"):
                raise ActionEpisodeAuditPending(row["id"])
            if row["status"] != "accepted" or payload is None:
                raise ActionEpisodeConflict("episode has no accepted unexpired review")
            episode = _episode(row, payload)
            if digest(episode) != row["episode_sha256"] or payload["review"]["episode_sha256"] != row["episode_sha256"]:
                raise ValueError("reviewed episode commitment changed")
            self._permit(ctx, "flow.episode.export", flow_id)
            return {"episode": episode, "provenance": {**copy.deepcopy(row["binding"]),
                "steps": [{key: copy.deepcopy(slot[key]) for key in
                           ("node_id", "call_id", "principal", "tool_schema_sha256", "step_sha256")}
                          for slot in payload["slots"]], "episode_sha256": row["episode_sha256"],
                "record_id": row["id"], "revision": row["revision"], "source_current": current,
                "audit_status": "delivered",
                **({"teaching": copy.deepcopy(payload["teaching"]), "teaching_sha256": row["teaching_sha256"]}
                   if row["binding"]["family"] == TEACHING_FAMILY else {})}, "review": copy.deepcopy(payload["review"])}


    def grant_training(self, ctx, flow_id, run_id, *, expected_revision, expected_episode_sha256,
                       use_until, retain_derived_copies, rationale, decision=None, before_write=None):
        """Grant bounded reuse/derived-copy retention; never imply automatic erasure."""
        from . import action_provenance as provenance

        self._validate_decision(decision)
        revision = _revision(expected_revision)
        if retain_derived_copies is not True:
            raise ValueError("an explicit derived-copy retention grant is required")
        deadline = _number(use_until, "use_until")
        rationale = _snapshot(_text(rationale, "rationale", 2000))
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id), store._definitions_lock():
            _lineage_gate()
            row, payload, current = self._load(ctx, flow_id, run_id, "flow.episode.grant", human=True)
            if row.get("_audit_pending"):
                return self._present(row, source_current=current)
            if row["status"] != "accepted" or payload is None or row["episode_sha256"] != expected_episode_sha256:
                raise ActionEpisodeConflict("training use requires the exact accepted unexpired episode")
            review_hash = digest(payload["review"])
            # The signed bundle recomputes exactly these fields; the reviewed
            # decision identity is recorded with the commit, not in this hash.
            request_material = {"episode": expected_episode_sha256, "review": review_hash, "actor": ctx.actor,
                "use_until": deadline, "retain_derived_copies": True, "rationale": rationale}
            request_hash = digest(request_material)
            existing = payload.get("training_grant")
            if existing is not None:
                if existing["request_sha256"] == request_hash:
                    return self._present(row, payload, source_current=current)
                raise ActionEpisodeConflict("training grant is immutable; changed scope requires new evidence")
            if row["revision"] != revision or not self.clock() < deadline <= row["retain_until"]:
                raise ActionEpisodeConflict("training grant revision or retention deadline changed")
            grant = {"schema": provenance.GRANT_SCHEMA, "purpose": provenance.PURPOSE, "tenant": ctx.tenant,
                     "actor": ctx.actor, "granted_at": self.clock(), "use_until": deadline,
                     "retain_derived_copies": True, "rationale": rationale, "authority_sha256": digest(ctx.binding()),
                     "episode_sha256": expected_episode_sha256, "review_sha256": review_hash,
                     "request_sha256": request_hash}
            payload["training_grant"] = grant
            saved = self._commit(ctx, row, payload, status="accepted", reason="training_use_granted",
                action="action_episode_training_granted", capability="flow.episode.grant",
                metadata={"review_revision": row.get("review_revision", row["revision"]),
                          "review_sha256": review_hash, "grant_sha256": digest(grant)},
                decision=decision, before_write=before_write)
            return self._present(saved, payload, source_current=current)

    def _signed_body(self, ctx, row, payload, current):
        from ..config import get_flows
        from . import action_provenance as provenance
        from .action_recipe import _digest as recipe_digest

        episode = _episode(row, payload)
        body = {"schema": provenance.SCHEMA, "issuer": get_flows().get("action_evidence_issuer", ""),
                "tenant": ctx.tenant, "purpose": provenance.PURPOSE, "canonicalization": provenance.CANONICALIZATION,
                "episode": episode, "episode_sha256": recipe_digest(episode), "capture_episode_sha256": row["episode_sha256"],
                "source": copy.deepcopy(row["binding"]), "record_id": row["id"], "review_revision": row["review_revision"],
                "review": copy.deepcopy(payload["review"]), "review_sha256": row["review_sha256"],
                "contract": copy.deepcopy(payload["contract"]), "contract_sha256": row["contract_sha256"],
                "enrollment": copy.deepcopy(payload["enrollment"]), "enrollment_sha256": digest(payload["enrollment"]),
                "enrollment_request_sha256": row["enrollment_sha256"],
                "steps": [{key: copy.deepcopy(slot[key]) for key in
                           ("node_id", "call_id", "principal", "tool_schema_sha256", "step_sha256")}
                          for slot in payload["slots"]], "issued_at": self.clock(), "retain_until": row["retain_until"],
                "grant": copy.deepcopy(payload["training_grant"]), "grant_sha256": row["grant_sha256"],
                "issuance_status": "accepted_audited", "source_current_at_issue": current}
        if row["binding"]["family"] == TEACHING_FAMILY:
            body.update(schema=provenance.TEACHING_SCHEMA, teaching=copy.deepcopy(payload["teaching"]),
                        teaching_sha256=row["teaching_sha256"])
        body["bundle_id"] = "AEB-" + provenance.digest({"record_id": row["id"], "review_sha256": row["review_sha256"],
                                                       "grant_sha256": row["grant_sha256"]})[:32]
        return provenance.validate_body(body)

    def export_signed(self, ctx, flow_id, run_id, *, expected_revision, expected_episode_sha256, expected_grant_sha256):
        """Issue once inside the source CAS/outbox; pending audit never exposes signed bytes."""
        from ..audit.signing import sign_detached_digest
        from . import action_provenance as provenance

        revision = _revision(expected_revision)
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            _lineage_gate()
            row, payload, current = self._load(ctx, flow_id, run_id, "flow.episode.export_signed", human=True)
            if row.get("_audit_pending"):
                raise ActionEpisodeAuditPending(row["id"])
            if (row["status"] != "accepted" or payload is None or row["episode_sha256"] != expected_episode_sha256
                    or not payload.get("training_grant") or row.get("grant_sha256") != expected_grant_sha256
                    or self.clock() >= payload["training_grant"]["use_until"]):
                raise ActionEpisodeConflict("signed export requires the exact current accepted training grant")
            issued = payload.get("issuance")
            if issued is None:
                if row["revision"] != revision:
                    raise ActionEpisodeConflict("signed export revision changed")
                body = self._signed_body(ctx, row, payload, current)
                bundle = {"body": body, "signature": sign_detached_digest(provenance.digest(body))}
                # Signing is outside the signer-independent authority boundary.
                self._permit(ctx, "flow.episode.export_signed", flow_id, human=True)
                self._fresh(ctx, row)
                _lineage_gate()
                provenance.verify_bundle(bundle, trust=provenance.local_trust(ctx.tenant),
                                         expected_tenant=ctx.tenant, now=self.clock())
                payload["issuance"] = {"source_revision": revision, "bundle": bundle}
                row = self._commit(ctx, row, payload, status="accepted", reason="signed_evidence_issued",
                    action="action_episode_evidence_issued", capability="flow.episode.export_signed",
                    metadata={"bundle_sha256": provenance.digest(bundle)})
                if row.get("_audit_pending"):
                    raise ActionEpisodeAuditPending(row["id"])
                payload = _open(ctx, row)
                issued = payload["issuance"]
            elif revision not in {issued["source_revision"], row["revision"]}:
                raise ActionEpisodeConflict("signed export revision changed")
            self._permit(ctx, "flow.episode.export_signed", flow_id, human=True)
            self._fresh(ctx, row)
            _lineage_gate()
            bundle = issued["bundle"]
            if provenance.digest(bundle) != row["bundle_sha256"]:
                raise ValueError("retained signed bundle commitment changed")
            provenance.verify_bundle(bundle, trust=provenance.local_trust(ctx.tenant),
                                     expected_tenant=ctx.tenant, now=self.clock())
            self._permit(ctx, "flow.episode.export_signed", flow_id, human=True)
            self._fresh(ctx, row)
            _lineage_gate()
            return provenance.snapshot(bundle)

    def assert_bundle_current(self, ctx, bundle):
        """Fresh same-owner/source check; no cross-record linearizable revocation claim."""
        from . import action_provenance as provenance

        with tenant_scope(tenant=ctx.tenant):
            _lineage_gate()
            verified = provenance.verify_bundle(bundle, trust=provenance.local_trust(ctx.tenant),
                                                 expected_tenant=ctx.tenant, now=self.clock())
            body = verified["body"]
            flow_id, run_id = body["source"]["flow_id"], body["source"]["run_id"]
            with store.run_lock(run_id):
                row, payload, current = self._load(ctx, flow_id, run_id, "flow.episode.current")
                if row.get("_audit_pending"):
                    raise ActionEpisodeAuditPending(row["id"])
                if (row["status"] != "accepted" or payload is None or not payload.get("issuance")
                        or row.get("withdrawal") or row.get("review_revision") != body["review_revision"]
                        or row.get("review_sha256") != body["review_sha256"] or row.get("grant_sha256") != body["grant_sha256"]
                        or row["binding"] != body["source"] or digest(payload["review"]) != body["review_sha256"]
                        or row["episode_sha256"] != body["capture_episode_sha256"]
                        or digest(_episode(row, payload)) != body["capture_episode_sha256"]
                        or row["contract_sha256"] != body["contract_sha256"] or payload["contract"] != body["contract"]
                        or row["enrollment_sha256"] != body["enrollment_request_sha256"]
                        or payload["enrollment"] != body["enrollment"]
                        or payload["training_grant"] != body["grant"]
                        or (row["binding"]["family"] == TEACHING_FAMILY
                            and (body.get("teaching") != payload.get("teaching")
                                 or body.get("teaching_sha256") != row.get("teaching_sha256")))
                        or provenance.digest(payload["issuance"]["bundle"]) != row.get("bundle_sha256")
                        or provenance.digest(provenance.snapshot(bundle)) != row.get("bundle_sha256")):
                    raise ActionEpisodeConflict("bundle source review/grant is no longer current")
                self._permit(ctx, "flow.episode.current", flow_id)
                self._fresh(ctx, row)
                # A policy update during recovery cannot inherit the earlier snapshot.
                verified = provenance.verify_bundle(bundle, trust=provenance.local_trust(ctx.tenant),
                                                     expected_tenant=ctx.tenant, now=self.clock())
                self._permit(ctx, "flow.episode.current", flow_id)
                self._fresh(ctx, row)
                _lineage_gate()
                return {**verified, "live_status": "accepted", "source_revision": row["revision"],
                        "source_current": current, "checked_at": self.clock()}

    def prepare_withdrawal(self, ctx, flow_id, run_id):
        """Read the current restrictive decision without enabling capture/learning.

        Never expose retained inputs, results or signed bundles through this
        maintenance path. Do not reconcile capture into new training evidence.
        Existing audit recovery and retention expiry remain authoritative.
        """
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            row, _payload, current = self._load(
                ctx, flow_id, run_id, "flow.episode.withdraw", human=True, reconcile=False)
            result = self._present(row, source_current=current)
            result["withdrawal_available"] = (
                row["status"] == "accepted" and not row.get("_audit_pending")
                and not row.get("withdrawal") and self.clock() < row["retain_until"])
            return result

    def withdraw(self, ctx, flow_id, run_id, *, expected_revision, expected_episode_sha256,
                 expected_review_sha256, rationale):
        """Append a withdrawal tombstone without rewriting the original acceptance."""
        revision = _revision(expected_revision)
        rationale = _snapshot(_text(rationale, "rationale", 2000))
        request_hash = digest({"actor": ctx.actor, "episode": expected_episode_sha256,
                               "review": expected_review_sha256, "rationale": rationale})
        with tenant_scope(tenant=ctx.tenant), store.run_lock(run_id):
            row, payload, current = self._load(
                ctx, flow_id, run_id, "flow.episode.withdraw", human=True, reconcile=False)
            if row.get("_audit_pending"):
                return self._present(row, source_current=current)
            if row.get("withdrawal"):
                if row["withdrawal"]["request_sha256"] == request_hash:
                    return self._present(row, source_current=current)
                raise ActionEpisodeConflict("withdrawal history is immutable")
            if (row["status"] != "accepted" or payload is None or row["revision"] != revision
                    or row["episode_sha256"] != expected_episode_sha256
                    or digest(payload["review"]) != expected_review_sha256):
                raise ActionEpisodeConflict("withdrawal requires the exact accepted review and revision")
            tombstone = {"actor": ctx.actor, "withdrawn_at": self.clock(), "rationale_sha256": digest(rationale),
                         "review_sha256": expected_review_sha256, "episode_sha256": expected_episode_sha256,
                         "request_sha256": request_hash}
            payload["withdrawal"] = {"rationale": rationale}
            saved = self._commit(ctx, row, payload, status="withdrawn", reason="review_withdrawn",
                action="action_episode_review_withdrawn", capability="flow.episode.withdraw",
                metadata={"withdrawal": tombstone})
            return self._present(saved, source_current=current)


@dataclass(frozen=True)
class _Prepared:
    record_id: str
    ordinal: int
    call_id: str
    arguments_sha256: str


class DurableActionEpisodeCapture:
    """Native-only handle. Storage failure disables evidence, never business work."""

    def __init__(self, service, ctx, flow_id, run_id):
        self.service, self.ctx, self.flow_id, self.run_id = service, ctx, flow_id, run_id
        self.disabled = False

    def _load(self):
        _gate()
        row, payload, _ = self.service._load(self.ctx, self.flow_id, self.run_id,
                                            "flow.episode.capture", reconcile=False)
        if row.get("_audit_pending") or row["status"] not in {"enrolled", "paused", "capturing"}:
            raise ActionEpisodeConflict("capture record is not available for native observation")
        if row["binding"]["family"] == TEACHING_FAMILY:
            _teaching_gate()
        return row, payload

    def teaching_decision(self, flow, run, *, decision, decided_by, approval_binding_sha256,
                          approval_authority_binding_sha256, decision_attestation):
        """Persist authenticated route provenance before the native continuation."""
        from . import recipe_flow
        from .approvals import flow_decision_attestation_material, require_current_paused_operation

        row, payload = self._load()
        if row["binding"]["family"] != TEACHING_FAMILY or run.cursor != "teaching_review":
            raise ValueError("not an enrolled native teaching pause")
        if (decision not in {"route:0", "route:1"} or not decided_by
                or len(payload["slots"]) != 1 or payload["slots"][0]["status"] != "completed"):
            raise ValueError("teaching requires one completed prefix and an authenticated offered route")
        require_current_paused_operation(run, flow, inputs={}, expected_binding=approval_binding_sha256,
            authority_binding_sha256=approval_authority_binding_sha256, decision=decision,
            decided_by=decided_by, decision_attestation=decision_attestation)
        question = recipe_flow.validate_teaching_question(flow.learned_recipe, run.data)
        if question["observation"] != {"inputs": payload["inputs"], "prefix_result": payload["slots"][0]["result"]}:
            raise ValueError("teaching question differs from the retained native prefix")
        _validate_teaching_options(question, payload["contract"])
        recipe_flow.check_lineage(flow.learned_recipe, flow.recipe_lineage, owner=run.owner)
        route = decision.removeprefix("route:")
        option = next(option for option in question["options"] if option["route"] == route)
        material = flow_decision_attestation_material(run, inputs={},
            operation_binding_sha256=approval_binding_sha256,
            authority_binding_sha256=approval_authority_binding_sha256,
            decision=decision, decided_by=decided_by)
        teaching = _snapshot({"schema": "lightwork.native-choice-teaching-decision.v1",
            "decision_origin": "authenticated_human", "parent_lineage": flow.recipe_lineage,
            "question": question, "question_sha256": question["question_sha256"],
            "route": route, "tool": option["tool"], "actor": decided_by,
            "decided_at": self.service.clock(), "approval_binding_sha256": approval_binding_sha256,
            "authority_binding_sha256": approval_authority_binding_sha256,
            "decision_material": material, "decision_attestation": decision_attestation},
            limit=MAX_EPISODE_BYTES, private=False, max_depth=_METADATA_DEPTH)
        if payload.get("teaching") is not None:
            previous = payload["teaching"]
            if any(previous[key] != teaching[key] for key in teaching if key != "decided_at"):
                raise ActionEpisodeConflict("native teaching decision is immutable")
            return
        payload["teaching"] = teaching
        payload["expected"] = [payload["teaching_plan"]["prefix"], payload["teaching_plan"]["branches"][route]]
        _validate_teaching_capture({**row, "teaching_sha256": digest(teaching)}, payload, run, flow)
        saved = self.service._commit(self.ctx, row, payload, status="paused", reason="authenticated_native_teaching_choice",
            action="action_episode_teaching_decided", capability="flow.episode.capture",
            metadata={"teaching_sha256": digest(teaching)})
        if saved.get("_audit_pending"):
            raise ActionEpisodeAuditPending(saved["id"])

    def invalidate(self, reason):
        self.disabled = True
        try:
            row, payload = self._load()
            self.service._commit(self.ctx, row, payload, status="unusable", reason="native_capture_unavailable",
                                 action="action_episode_unusable", capability="flow.episode.capture")
        except Exception:
            pass  # Capture is optional; an unavailable record never retries an effect.

    def prepare(self, node_id, tool, arguments, *, call_id, principal, input_schema):
        if self.disabled:
            return None
        try:
            row, payload = self._load()
            args = _object(arguments)
            _matches(args, payload["contract"]["tool_data_schemas"][tool]["arguments"])
            if type(call_id) is not str or not _CALL_ID.fullmatch(call_id) or type(input_schema) is not dict:
                raise ValueError("native invocation identity is invalid")
            slots = payload["slots"]
            ordinal = len(slots)
            slot = {"status": "prepared", "node_id": node_id, "tool": tool, "call_id": call_id,
                    "principal": _snapshot(principal or ""), "arguments": args,
                    "arguments_sha256": digest(args), "tool_schema_sha256": digest(_snapshot(
                        input_schema, private=False, max_depth=_METADATA_DEPTH))}
            if slots and slots[-1]["status"] == "prepared":
                if slots[-1] != slot:
                    raise ActionEpisodeConflict("native prepared observation changed")
                return _Prepared(row["id"], ordinal - 1, call_id, digest(args))
            if ordinal >= len(payload["expected"]) or payload["expected"][ordinal] != [node_id, tool]:
                raise ValueError("native action is outside the expected prefix")
            slots.append(slot)
            saved = self.service._commit(self.ctx, row, payload, status="capturing", reason="native_step_prepared",
                                         action="action_episode_step_prepared", capability="flow.episode.capture")
            if saved.get("_audit_pending"):
                raise ActionEpisodeAuditPending(saved["id"])
            return _Prepared(saved["id"], ordinal, call_id, digest(args))
        except Exception:
            self.invalidate("prepare_failed")
            return None

    def complete(self, token, normalized_result, *, terminal_recorded):
        if self.disabled or token is None:
            return
        try:
            row, payload = self._load()
            if type(token) is not _Prepared or token.record_id != row["id"] or terminal_recorded is not True:
                raise ValueError("native terminal receipt is unavailable")
            slot = payload["slots"][token.ordinal]
            if slot["call_id"] != token.call_id or slot["arguments_sha256"] != token.arguments_sha256:
                raise ValueError("native terminal invocation changed")
            result = _result_object(normalized_result)
            _matches(result, payload["contract"]["tool_data_schemas"][slot["tool"]]["result"])
            step_hash = digest({"tool": slot["tool"], "arguments": slot["arguments"], "result": result})
            if slot["status"] == "completed":
                if slot["step_sha256"] != step_hash:
                    raise ValueError("native completion changed")
                return
            slot.update(status="completed", result=result, step_sha256=step_hash)
            self.service._commit(self.ctx, row, payload, status="capturing", reason="native_step_completed",
                                 action="action_episode_step_completed", capability="flow.episode.capture")
        except Exception:
            self.invalidate("completion_failed")

    def finish(self, saved_run):
        if self.disabled:
            return
        try:
            row, payload = self._load()
            persisted, _, _ = self.service._fresh(self.ctx, row)
            if (saved_run.run_id != persisted.run_id or saved_run.status != persisted.status
                    or saved_run.updated != persisted.updated):
                raise ValueError("capture checkpoint is not the durable run")
            self.service._checkpoint(self.ctx, row, payload, persisted, "flow.episode.capture")
        except Exception:
            self.invalidate("checkpoint_failed")


def load_capture_runtime(flow, run, *, resumed, initial_data, submitted_inputs, from_failure, expired, decision,
                         decided_by="", approval_binding_sha256="", approval_authority_binding_sha256="",
                         decision_attestation=None):
    """Load enrollment only after native approval checks, under the existing run lock."""
    tenant = current_tenant_id_strict()
    if not tenant or not run.owner:
        return None
    ctx = ServiceContext(tenant=tenant, actor=run.execution_user_id or run.owner,
        resource_owner=run.owner, credential_authority="native_approval_runtime",
        credential_ref="not_applicable", human=False)

    def authorize(context, capability, resource):
        from ..tenant.registry import assert_tenant_active

        assert_tenant_active(tenant)
        return (context == ctx and capability == "flow.episode.capture" and resource == flow.id
                and current_tenant_id_strict() == tenant)

    service = ActionEpisodeReviewService(authorize)
    handle = DurableActionEpisodeCapture(service, ctx, flow.id, run.run_id)
    try:
        row = service.records.get(_identifier(tenant, flow.id, run.run_id))
        if row is None:
            return None
        _gate()
        row, payload, _ = service._load(ctx, flow.id, run.run_id, "flow.episode.capture", reconcile=True)
        teaching_pause = row["binding"]["family"] == TEACHING_FAMILY and run.cursor == "teaching_review"
        permitted_decision = decision in {"route:0", "route:1"} if teaching_pause else decision == "approved"
        if (not resumed or from_failure or expired or submitted_inputs or not permitted_decision
                or row.get("_audit_pending") or payload is None or row["status"] not in {"enrolled", "paused"}
                or run.status != "paused_approval" or paused_operation_binding(run) != payload["pause"]["binding"]
                or digest(initial_data) != row["binding"]["original_input_sha256"]
                or digest(flow.to_dict()) != row["binding"]["plan_sha256"]):
            raise ValueError("capture resume is outside the enrolled native approval")
        if teaching_pause:
            handle.teaching_decision(flow, run, decision=decision, decided_by=decided_by,
                approval_binding_sha256=approval_binding_sha256,
                approval_authority_binding_sha256=approval_authority_binding_sha256,
                decision_attestation=decision_attestation)
        return handle
    except Exception:
        handle.invalidate("resume_not_admitted")
        return None
