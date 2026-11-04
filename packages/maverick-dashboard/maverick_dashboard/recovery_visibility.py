"""Reviewed native local practices with owner-bound original custody."""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone

from fastapi import HTTPException, Response
from maverick import config
from maverick import recovery_visibility as engine
from maverick.authority_effects import authority_effect_fence
from maverick.budget import BudgetExceeded
from maverick.governed_operations import digest
from maverick.governed_records import (
    GovernedRecordBackendError,
    GovernedRecordStore,
    RecordConflict,
)
from maverick.learning_guard import Halted
from maverick.privacy_ops import AuditOutboxError, PrivacyStateError

from .candidate_promotion_api import _binding

PAGE = "/learning/recovery-visibility"
API = "/api/v1/learning/recovery-visibility"
FEATURE = "recovery_visibility"
NOTICE = ("Practice with fictional sign-offs in fresh local databases. The complete declared search uses two reviewers, one request, "
          "one or two required sign-offs and up to three interactions. It records votes, acknowledges local activity and separately undoes "
          "effective decisions through this installation's native safeguards. No live request, connected service, AI provider or business action is used.")
LIMITS = ("These observations distinguish only the stated local obligations within the complete bounded practice. "
          "A pending activity entry is unconfirmed. A local activity acknowledgement is not a remote delivery or customer acceptance receipt. "
          "Matching current state cannot identify another person's original request. External notifications and their multiplicity are not modeled. "
          "The same-information ordinary exhaustive comparison must match; no research superiority or customer reliability gain is established.")


def call(function):
    """Keep failed admission and original-custody uncertainty customer-readable."""
    try:
        return function()
    except (RecordConflict, BudgetExceeded, ValueError, Halted) as exc:
        raise HTTPException(409, "The complete reviewed practice could not be qualified. Check the original result without repeating it, or review current choices for a separate practice.") from exc
    except (OSError, GovernedRecordBackendError, AuditOutboxError, PrivacyStateError) as exc:
        raise HTTPException(503, "The original practice record could not be confirmed. Check its original result; no request will repeat automatically.") from exc


def records():
    return GovernedRecordStore("recovery-visibility-practices", "RVP", "recovery_visibility_practice")


def authority(request, context=None, *, write=False):
    tenant, owner, current = _binding(request, Response())
    if context is not None and context != current:
        raise HTTPException(409, "Your account, workspace or access changed. Reload before continuing.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return tenant, owner, current


def enabled():
    return not config.config_source_errors(include_tenant=True) and config.get_features().get(FEATURE) is True


def _material(request, body):
    from maverick.learning_guard import check_learning_halt

    from .api_flow_operator_review import _workspace_authority
    tenant, owner, context = authority(request)
    if not enabled():
        raise HTTPException(409, "Recovery visibility practice is off. An administrator can enable it in Settings; earlier original results remain readable.")
    check_learning_halt("recovery_visibility", "practice")
    return {"tenant": tenant, "owner": owner, "context": context, "body": engine.choices(body),
            "workspace": _workspace_authority(request, owner, tenant), "source": engine.version(),
            "policy": digest([config.get_features(), config.load_config().get("learning", {})])}


def listing(request):
    tenant, owner, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(409, "The retained practice history exceeds this bounded view. No partial original-request list was shown.")
    result = {"context": context, "enabled": enabled(), "notice": NOTICE, "limits": LIMITS,
              "observations": [{"value": value, "label": label} for value, label in engine.OBSERVATIONS.items()],
              "history": [{"value": row["id"], "when": row["created_at"], "state": row["state"],
                           "label": ("Result retained" if row["state"] == "done" and not row.get("_audit_pending") else "Original result unconfirmed") + " · " +
                           datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%d %b, %H:%M:%S.%f")[:-3] + " UTC"} for row in rows
                          if (row.get("tenant"), row.get("owner"), row.get("context")) == (tenant, owner, context)][-50:]}
    authority(request, context)
    return result


def prepare(request, body, context):
    authority(request, context, write=True)
    with authority_effect_fence():
        value = _material(request, body)
        value.update(deadline=time.time() + 600, operation="RVP-" + secrets.token_hex(16))
        changes = [{"label": "Fictional request", "after": "Two fictional reviewers; " + str(value["body"]["quorum"]) + " required sign-off(s)."},
                   {"label": "Complete search", "after": "Every reachable native practice situation through " + str(value["body"]["steps"]) + " interaction(s), with equivalent native situations joined."},
                   {"label": "Visible observations", "after": "\n".join(engine.OBSERVATIONS[name] for name in value["body"]["observations"])},
                   {"label": "Permitted interactions", "after": "\n".join(engine.ACTIONS.values())},
                   {"label": "Next permitted observations", "after": "\n".join(engine.OBSERVATIONS.values())},
                   {"label": "Allowance", "after": "One complete local search, comparison and pair replay together: at most 1,200 local setup/action/readback operations and twenty seconds, plus process and receipt overhead. No provider charge."},
                   {"label": "Installed source", "after": "The exact current native approval and practice implementation is bound to this review."},
                   {"label": "Consequence and scope", "after": NOTICE + " " + LIMITS}]
        authority(request, context)
        return value, changes


def _guard(request, value):
    authority(request, value["context"], write=True)
    fresh = _material(request, value["body"])
    if fresh != {key: item for key, item in value.items() if key not in {"deadline", "operation"}}:
        raise HTTPException(409, "The reviewed account, permissions, policy or installed safeguards changed. Review current choices again.")
    if type(value["deadline"]) not in (int, float) or not time.time() < value["deadline"] <= time.time() + 600:
        raise HTTPException(409, "This review expired before the native write. Review current choices again.")


def _owned(request, identifier, binding=None):
    tenant, owner, context = authority(request)
    if not isinstance(identifier, str) or len(identifier) != 36 or not identifier.startswith("RVP-"):
        raise HTTPException(404, "Choose an original local practice.")
    row = records().get(identifier)
    if row is None:
        raise HTTPException(404, "This original local practice has no readable retained record. Nothing was repeated.")
    if (row.get("tenant"), row.get("owner"), row.get("context")) != (tenant, owner, context):
        raise HTTPException(404, "This original local practice is unavailable to the current account.")
    if binding is not None and row.get("binding") != binding:
        raise HTTPException(409, "This original request belongs to a different reviewed practice.")
    authority(request, context)
    return row


def original(request, identifier):
    row = _owned(request, identifier)
    confirmed = row["state"] == "done" and not row.get("_audit_pending")
    try:
        current = enabled() and row["source"] == engine.version()
    except (OSError, ValueError):
        current = False
    result = {"id": row["id"], "context": row["context"], "confirmed": confirmed, "current": current,
              "state": row["state"], "when": row["created_at"], "notice": NOTICE, "limits": LIMITS,
              "message": "The complete original local practice was retained. Nothing ran again." if confirmed else
              "This original request has no confirmed complete result. It will not run again. Review current choices before starting a separate practice.",
              "result": row["result"] if confirmed else None}
    authority(request, row["context"])
    return result


def apply(request, value):
    authority(request, value["context"], write=True)
    identifier, service, binding = value["operation"], records(), digest(value)
    with authority_effect_fence():
        existing = service.get(identifier)
        if existing is not None:
            _owned(request, identifier, binding)
            return original(request, identifier)
        _guard(request, value)
        try:
            row = service.create({"id": identifier, **value, "binding": binding, "state": "prepared"},
                                 action="recovery.visibility.reviewed", actor=value["owner"], max_records=1000)
        except RecordConflict:
            _owned(request, identifier, binding)
            return original(request, identifier)
        def claim(current):
            _guard(request, value)
            if current["state"] != "prepared" or current.get("_audit_pending") or current.get("binding") != binding:
                raise HTTPException(409, "Original practice admission is unconfirmed. Read its original result; nothing will run again.")
            current["state"] = "running"
        row = service.update(identifier, claim, expected_revision=row["revision"], action="recovery.visibility.start", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
    result = engine.check(value["body"])
    with authority_effect_fence():
        def finish(current):
            _guard(request, value)
            if current["state"] != "running" or current["binding"] != binding or result["source"] != value["source"]:
                raise HTTPException(409, "The original complete result could not be admitted. It remains unconfirmed and will not run again.")
            current.update(state="done", result=result)
        service.update(identifier, finish, expected_revision=row["revision"], action="recovery.visibility.complete", actor=value["owner"])
    return original(request, identifier)
