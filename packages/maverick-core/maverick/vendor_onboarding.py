"""AI vendor onboarding application service over existing domain authorities.

The vendor register and AI vendor-risk register remain their systems of record.
This tenant-scoped saga stores coordination, operation intent and customer
outcomes. The supported deployment is one persistent application replica.
Provider effects cannot participate in its local transaction: ambiguous creates
require read-only reconciliation, including after a lost receipt or restart.
"""
from __future__ import annotations

import base64
import binascii
import copy
import functools
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import uuid
from dataclasses import asdict
from typing import NoReturn

from . import ai_vendor_risk as risk
from . import vendor_management as vendors
from . import vendor_onboarding_documents as documents
from .approval_cards import (
    ApprovalCardError,
    build_approval_card,
    require_current_approval_card,
    validate_approval_card,
)
from .file_lock import cross_process_lock
from .governed_operations import (
    ActionReviewRequiredError,
    ApprovalBindingError,
    ServiceContext,
    apply_declared,
    audit_authority_denial,
    digest,
    operation_binding,
    validate_approval,
)
from .governed_records import GovernedRecordStore, RecordConflict
from .paths import data_dir, tenant_scope
from .platform_contracts import build_contract
from .vendor_onboarding_adapters import (
    CredentialAuthorityChanged,
    EvidenceDocument,
    ProviderMultipleMatches,
    validate_jira_verification,
)

_CASES = GovernedRecordStore("vendor_onboarding", "VON", "vendor_onboarding_case")
_LOCK = threading.RLock()
_PROJECT = re.compile(r"[A-Z][A-Z0-9_]{1,31}\Z")
_SUBMISSION_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}\Z")
_CASE_ID = re.compile(r"VON-[A-Za-z0-9_-]{1,59}\Z")
_QUEUE_VIEWS = frozenset({"all", "active", "unresolved", "renewal", "closed"})
_MAX_QUEUE_CURSOR = 768
_MAX_QUEUE_PAGE = 100
_MAX_QUEUE_SCAN = 400
_CLOSED_OPERATION = {"executing", "reconciliation_required", "verified"}
_MAX_RECONCILIATION_HISTORY = 100
CASE_SCHEMA = "lightwork.vendor-onboarding.v1"
EVIDENCE_EXPORT_SCHEMA = "lightwork.vendor-onboarding.evidence-export.v1"

_JOURNEY_CONTRACT_V1 = {
    "id": "supplier-evidence-onboarding",
    "version": 1,
    "supported_deployment": {
        "topology": "single_persistent_application_replica",
        "workers": "tenant_and_credential_scoped",
        "external_systems": ["Google Drive evidence", "Jira Task delivery"],
    },
    "technical_acceptance": {
        "effect": "one Jira Task matches the exact approved payload",
        "evidence": "fresh authoritative Jira readback under the bound credential version",
    },
    "business_acceptance": {
        "decision": "an authenticated authorized human explicitly accepts or rejects the verified deliverable",
        "accepted_value": True,
    },
    "renewal": "accepted cases retain the evidence freshness deadline and require current source and ticket checks",
    "out_of_scope": [
        "procurement approval, payment, contracting, or ERP provisioning",
        "production release or authorization of the reviewed vendor or model",
        "multi-replica application operation",
    ],
}
JOURNEY_CONTRACT_V1_REF = {
    "id": _JOURNEY_CONTRACT_V1["id"],
    "version": _JOURNEY_CONTRACT_V1["version"],
    "sha256": digest(_JOURNEY_CONTRACT_V1),
}
CURRENT_JOURNEY_CONTRACT_REF = dict(JOURNEY_CONTRACT_V1_REF)
_JOURNEY_CONTRACTS = {
    (_JOURNEY_CONTRACT_V1["id"], _JOURNEY_CONTRACT_V1["version"]): _JOURNEY_CONTRACT_V1,
}
_WORK_ITEM_STATE = {
    "intake": ("Draft", "obtain_evidence"),
    "evidence_collected": ("Ready", "build_assessment"),
    "pending_review": ("Awaiting approval", "review_assessment"),
    "review_approved": ("Ready", "prepare_action"),
    "review_rejected": ("Failed", "correct_or_close"),
    "action_pending_approval": ("Awaiting approval", "approve_action"),
    "action_approved": ("Ready", "execute_action"),
    "executing": ("Running", "wait_or_reconcile"),
    "reconciliation_required": ("Needs reconciliation", "reconcile"),
    "execution_completed": ("Verified", "accept_or_reject"),
    "acceptance_reevaluation_required": ("Awaiting approval", "start_reevaluation_request"),
    "accepted": ("Accepted", "check_renewal"),
    "customer_rejected": ("Failed", "closed"),
    "cancelled": ("Cancelled", "closed"),
}


class VendorOnboardingContractError(ValueError):
    """A persisted record cannot be interpreted under a supported contract."""

    def __init__(self, message, *, code):
        super().__init__(message)
        self.code = code


class VendorOnboardingDeploymentError(ValueError):
    """The current installation cannot safely operate the supplier saga."""

    def __init__(self, readiness):
        super().__init__(readiness["message"])
        self.code = readiness["code"]
        self.next_action = readiness["next_action"]


class VendorOnboardingIdempotencyConflict(RecordConflict):
    """A submission key was durably bound to another intake payload."""

    def __init__(self, case_id):
        super().__init__("submission key is already bound to a different vendor request")
        self.case_id = case_id


class VendorOnboardingEvidenceReviewRequired(ValueError):
    """A consequential decision cannot reuse evidence that is no longer current."""

    code = "evidence_reevaluation_required"

    def __init__(self, case_id):
        super().__init__(
            "Reviewed evidence changed, expired, or became unavailable. "
            "The prior review cannot be reused; start a reevaluation request before "
            "approval or acceptance. Any verified external effect remains retained."
        )
        self.case_id = case_id



def _utc_date(seconds: float) -> str:
    """A readable UTC date and time for people reading the ticket."""
    import datetime as _dt

    return _dt.datetime.fromtimestamp(float(seconds), _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def deployment_readiness() -> dict:
    """Read deployment policy without taking a lease or opening any store.

    This is configuration admission, not proof of a live replica count, durable
    storage or usable connections. A shared governed-record backend does not
    make the supplier saga's local cross-process lock work across hosts.
    """
    from .config import config_source_errors, load_global_config
    from .control_plane_lease import OVERRIDE_ENV
    from .governed_records import _replica_count

    result = {
        "supported": False, "profile": "single_persistent_application_replica",
        "code": "deployment_configuration_unavailable",
        "message": "Supplier workflow settings could not be verified for this installation.",
        "next_action": "Ask an administrator to review installation settings, then retry.",
    }
    try:
        current = load_global_config()
        if not isinstance(current, dict) or config_source_errors(include_tenant=False):
            return result
        section = current.get("deployment", {})
        if not isinstance(section, dict):
            return result
        raw = os.environ.get(OVERRIDE_ENV)
        if raw is None:
            multiple = section.get("allow_multiple_control_planes", False)
            if type(multiple) is not bool:
                return result
        else:
            normalized = raw.strip().lower()
            if normalized not in {"", "0", "false", "no", "off", "1", "true", "yes", "on"}:
                return result
            multiple = normalized in {"1", "true", "yes", "on"}
        replicas = _replica_count()
    except Exception:
        # Configuration exception text may contain paths or private values.
        return result
    if replicas != 1 or multiple:
        return dict(result, code="unsupported_deployment",
                    message="The supplier workflow is unavailable for this installation.",
                    next_action="Ask an administrator to use one persistent application instance with single-instance protection enabled, then retry.")
    return dict(result, supported=True, code="deployment_supported",
                message="Configured for one persistent Lightwork installation.",
                next_action="Complete workspace setup and review connection access before starting work.")


def _require_supported_deployment():
    readiness = deployment_readiness()
    if not readiness["supported"]:
        raise VendorOnboardingDeploymentError(readiness)


def _text(value, name, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be a nonempty string of at most {limit} characters")
    return value.strip()


def _optional_due_at(value):
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise ValueError("due_at must be a positive finite timestamp or null")
    return float(value)


def enabled() -> bool:
    from .config import load_global_config

    return (load_global_config().get("vendor_onboarding") or {}).get("enable") is True


def _scoped(method):
    @functools.wraps(method)
    def call(self, ctx, *args, **kwargs):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        _require_supported_deployment()
        if not enabled():
            raise RuntimeError("vendor onboarding requires [vendor_onboarding] enable = true")
        with tenant_scope(tenant=ctx.tenant):
            from .provider_cost_cap import work_item_scope

            case_id = (
                args[0]
                if (
                    method.__name__ not in {"intake", "search_documents", "list", "list_page"}
                    and args
                    and isinstance(args[0], str)
                    and _CASE_ID.fullmatch(args[0])
                )
                else None
            )
            # Serializes domain read/CAS/reference composition on the supported
            # persistent single replica, across threads and worker processes.
            if case_id is None:
                with _LOCK, cross_process_lock(
                    data_dir("vendor_onboarding", "saga"), strict=True,
                ):
                    return method(self, ctx, *args, **kwargs)
            with work_item_scope(f"vendor:{case_id}"):
                with _LOCK, cross_process_lock(
                    data_dir("vendor_onboarding", "saga"), strict=True,
                ):
                    return method(self, ctx, *args, **kwargs)
    return call


class VendorOnboardingService:
    def __init__(self, documents, tickets, authorize, *, clock=time.time):
        if not callable(authorize):
            raise TypeError("an authoritative authorization callback is required")
        self.documents, self.tickets = documents, tickets
        self.authorize, self.clock = authorize, clock

    def check_renewal(self, ctx, case_id):
        """Application boundary used by the dashboard for current renewal status."""
        _require_supported_deployment()
        from .vendor_evidence_evolution import EvidenceRenewalEvolution

        return EvidenceRenewalEvolution(self.authorize, clock=self.clock).run_for_case(ctx, self, case_id)

    def _permit(self, ctx, capability, resource, *, human=False):
        _require_supported_deployment()
        if human and not ctx.human:
            audit_authority_denial(ctx, capability, resource, "authenticated_human_required")
            raise PermissionError("this decision requires an authenticated human")
        try:
            allowed = self.authorize(ctx, capability, resource)
        except Exception:
            audit_authority_denial(ctx, capability, resource, "current_authority_unavailable")
            raise
        if allowed is not True:
            audit_authority_denial(ctx, capability, resource, "current_authority_denied")
            raise PermissionError(f"permission denied: {capability}")

    def _reconciliation_authority_available(self, ctx, row) -> bool:
        """Check current local authority without contacting the provider."""
        operation = row.get("operation") or {}
        if operation.get("state") not in {"executing", "reconciliation_required"}:
            return True
        original = operation.get("context") or {}
        if any(
            original.get(field) != getattr(ctx, field)
            for field in ("tenant", "resource_owner", "credential_authority", "credential_ref")
        ):
            return False
        expected = (operation.get("preconditions") or {}).get("ticket_credential_version")
        if not isinstance(expected, str) or not expected:
            return False
        try:
            if self.authorize(ctx, "action.reconcile", row["id"]) is not True:
                return False
            # JiraTickets.authority_version resolves only the enrolled local
            # credential record. It does not issue a provider request.
            return self.tickets.authority_version(ctx) == expected
        except Exception:
            return False

    def _present_current(self, ctx, row):
        presented = self._present(row)
        if (
            presented.get("reconciliation")
            and not self._reconciliation_authority_available(ctx, row)
        ):
            presented["reconciliation"] = self._reconciliation_summary(
                row, current_access_unavailable=True,
            )
        return presented

    def _get(self, ctx, case_id, expected_revision=None):
        self._permit(ctx, "read", case_id)
        row = _CASES.get(case_id)
        if not row or row.get("tenant") != ctx.tenant or row.get("owner") != ctx.resource_owner:
            audit_authority_denial(ctx, "read", case_id, "resource_scope_mismatch")
            raise KeyError("vendor onboarding case not found")
        if expected_revision is not None:
            if type(expected_revision) is not int or row["revision"] != expected_revision:
                raise RecordConflict("vendor onboarding case revision changed")
        return self._present_current(ctx, row)

    @staticmethod
    def _contract(row):
        if row.get("schema") != CASE_SCHEMA:
            raise VendorOnboardingContractError(
                "unsupported vendor onboarding schema", code="unsupported_record_version",
            )
        stored = row.get("journey_contract")
        binding = "explicit_at_intake"
        if stored is None:
            stored = JOURNEY_CONTRACT_V1_REF
            binding = "legacy_schema_default"
        if (not isinstance(stored, dict) or set(stored) != {"id", "version", "sha256"}
                or not isinstance(stored.get("id"), str) or type(stored.get("version")) is not int
                or not isinstance(stored.get("sha256"), str)):
            raise VendorOnboardingContractError(
                "invalid journey contract reference", code="invalid_contract_reference",
            )
        contract = _JOURNEY_CONTRACTS.get((stored["id"], stored["version"]))
        if contract is None:
            raise VendorOnboardingContractError(
                "unsupported journey contract", code="unsupported_contract_version",
            )
        expected = {"id": contract["id"], "version": contract["version"],
                    "sha256": digest(contract)}
        if stored != expected:
            raise VendorOnboardingContractError(
                "journey contract digest mismatch", code="contract_integrity_failed",
            )
        return copy.deepcopy(contract), copy.deepcopy(expected), binding

    def _present(self, row):
        contract, reference, binding = self._contract(row)
        due_at = _optional_due_at(row.get("due_at"))
        try:
            lifecycle, next_action = _WORK_ITEM_STATE[row["stage"]]
        except KeyError as exc:
            raise VendorOnboardingContractError(
                "unsupported vendor onboarding lifecycle state", code="unsupported_lifecycle_state",
            ) from exc
        operation = row.get("operation") or {}
        outcome = row.get("outcome") or {}
        technical = ("verified" if operation.get("state") == "verified" else
                     "indeterminate" if operation.get("state") in {"executing", "reconciliation_required"}
                     else "not_verified")
        if row.get("cancellation") and technical == "verified":
            next_action = "closed_external_effect_retained"
        business = ("accepted" if outcome.get("accepted") is True else
                    "rejected" if outcome.get("accepted") is False else "pending")
        preconditions = operation.get("preconditions") or {}
        credential_versions = {
            name: str(preconditions[name]) for name in (
                "document_credential_version", "ticket_credential_version",
            ) if preconditions.get(name) is not None
        }
        measured_cost = (row.get("metrics") or {}).get("execution_cost_usd")
        cost = ({"state": "exact", "currency": "USD", "amount": str(measured_cost)}
                if type(measured_cost) in (int, float) and math.isfinite(measured_cost)
                else {"state": "unknown", "reason": "provider_billing_unmeasured"})
        evidence = row.get("evidence") or {}
        freshness = evidence.get("fresh_until") if evidence.get("status") == "available" else None
        idempotency = ({"state": "bound", "key": operation["id"]}
                       if operation.get("id") else
                       {"state": "unknown", "reason": "action_not_prepared"})
        work_item = build_contract(
            "work-item", contract_id=row["id"], tenant_id=row["tenant"],
            owner_id=row["owner"], purpose=row["purpose"],
            created_at=row.get("created_at", row["started_at"]),
            updated_at=row.get("updated_at", row["started_at"]), revision=row["revision"],
            fields={
                "requester": row.get("requested_by") or row["owner"],
                "objective": row["purpose"], "process": reference,
                "due_at": due_at,
                "contract_binding": binding,
                "supported_deployment": contract["supported_deployment"],
                "acceptance_contract": {
                    "technical": contract["technical_acceptance"],
                    "business": contract["business_acceptance"],
                },
                "out_of_scope": contract["out_of_scope"],
                "lifecycle": lifecycle, "next_action": next_action,
                "technical_effect": technical, "business_outcome": business,
                "target_scope": {"provider": "jira", "project": row["project"]},
                "deployment_profile": contract["supported_deployment"],
                "admission_id": row["id"],
                "acceptance_contract_ref": reference,
                "parent_work_item_id": row.get("renewal_of"),
            },
            provenance={"record_schema": row["schema"], "record_revision": row["revision"]},
            policy_snapshot_ref=reference,
            authority_versions={"journey_contract": f"{reference['id']}:{reference['version']}"},
            credential_versions=credential_versions,
            idempotency=idempotency,
            budget={"state": "unknown", "reason": "workflow_budget_not_configured"},
            cost=cost,
            fresh_until=(freshness if freshness is not None else
                         {"state": "unknown", "reason": "evidence_incomplete" if evidence else "evidence_not_collected"}),
            human_intervention={
                "required": True, "review_count": len(row.get("review_history") or []),
                "acceptance_state": business,
            },
            uncertainty={"state": "bounded" if technical == "verified" else "unknown",
                         "basis": "authoritative_readback" if technical == "verified"
                                  else "technical_effect_not_verified"},
            causal_status={"state": "not_applicable", "basis": "operational_workflow"},
        )
        presented = dict(row)
        if row.get("intake_idempotency"):
            presented["intake_idempotency"] = {
                "state": "bound",
                "scope": "tenant_resource_owner",
            }
        if operation.get("state") in {"executing", "reconciliation_required"}:
            presented["reconciliation"] = self._reconciliation_summary(row)
        return dict(
            presented,
            due_at=due_at,
            journey_contract=reference,
            work_item=work_item,
            attention=self._attention(row),
        )

    def _attention(self, row):
        """Describe one customer-visible queue state from persisted dates.

        This projection is intentionally computed at read time.  Opening the
        renewal queue must never rewrite a frozen acceptance merely because its
        evidence deadline passed.
        """
        now = float(self.clock())
        stage = row.get("stage")
        outcome = row.get("outcome") or {}
        if stage in {"executing", "reconciliation_required"}:
            operation = row.get("operation") or {}
            return {
                "state": "needs_reconciliation",
                "kind": "external_effect",
                "requires_attention": True,
                "effective_at": operation.get("started_at") or row.get("updated_at"),
                "as_of": now,
            }
        if stage == "acceptance_reevaluation_required":
            evidence_check = row.get("acceptance_evidence_check") or {}
            return {
                "state": "renewal_required",
                "kind": "evidence",
                "requires_attention": True,
                "effective_at": evidence_check.get("checked_at") or row.get("updated_at"),
                "as_of": now,
            }
        if outcome.get("accepted") is False or stage == "customer_rejected":
            return {
                "state": "rejected",
                "kind": "business_decision",
                "requires_attention": False,
                "effective_at": outcome.get("decided_at") or outcome.get("accepted_at"),
                "as_of": now,
            }
        if stage == "cancelled":
            cancellation = row.get("cancellation") or {}
            return {
                "state": "cancelled",
                "kind": "workflow",
                "requires_attention": False,
                "effective_at": cancellation.get("requested_at") or row.get("updated_at"),
                "as_of": now,
            }
        if outcome.get("accepted") is True or stage == "accepted":
            renewal_due_at = _optional_due_at(outcome.get("renewal_due_at"))
            return {
                "state": "overdue" if renewal_due_at is not None and renewal_due_at <= now else "due",
                "kind": "evidence_renewal",
                "requires_attention": renewal_due_at is not None and renewal_due_at <= now,
                "effective_at": renewal_due_at,
                "as_of": now,
            }
        due_at = _optional_due_at(row.get("due_at"))
        if due_at is not None:
            return {
                "state": "overdue" if due_at <= now else "due",
                "kind": "requested_completion",
                "requires_attention": due_at <= now,
                "effective_at": due_at,
                "as_of": now,
            }
        return {
            "state": "current",
            "kind": "workflow",
            "requires_attention": False,
            "effective_at": row.get("updated_at"),
            "as_of": now,
        }

    def _save(self, ctx, row, *, audit_action="vendor_onboarding_changed", **changes):
        _require_supported_deployment()
        self._contract(row)
        result = _CASES.update(
            row["id"], lambda value: value.update(changes),
            expected_revision=row["revision"], action=audit_action, actor=ctx.actor,
        )
        if result is None:
            raise KeyError("vendor onboarding case disappeared")
        return self._present(result)

    def _editable(self, row):
        self._require_active_intent(row)
        if row.get("stage") == "acceptance_reevaluation_required":
            raise VendorOnboardingEvidenceReviewRequired(row["id"])
        if ((row.get("operation") or {}).get("state") in _CLOSED_OPERATION
                or row.get("outcome") is not None):
            raise ValueError("external execution or acceptance freezes this case; create a renewal")

    @staticmethod
    def _require_active_intent(row):
        if row.get("cancellation") or row.get("stage") == "cancelled":
            raise ValueError("this request is cancelled; only existing-effect reconciliation remains available")

    @_scoped
    def cancel(self, ctx, case_id, expected_revision, rationale):
        """Stop local intent without compensating or erasing provider effects.

        The saga lock serializes cancellation with dispatch. A caller that
        reviewed an earlier revision must reload the actual effect state first.
        A durable execution claim is conservatively possibly dispatched even
        when the worker lost authority before reaching the provider.
        """
        row = self._get(ctx, case_id, expected_revision)
        self._permit(ctx, "action.cancel", case_id, human=True)
        why = _text(rationale, "rationale")
        if row.get("cancellation"):
            return row
        if row.get("outcome") is not None:
            raise ValueError("an existing customer decision cannot be replaced by cancellation")
        operation = row.get("operation") or {}
        attempted = (operation.get("state") in _CLOSED_OPERATION
                     or operation.get("attempts", 0) > 0)
        verified = operation.get("state") == "verified"
        cancellation = {
            "requested_by": ctx.actor, "requested_at": self.clock(), "rationale": why,
            "authority": ctx.binding(), "reviewed_revision": row["revision"],
            "operation_id": operation.get("id"), "scope": "local_intent_only",
            "dispatch_state_at_cancellation": "possibly_dispatched" if attempted else "not_dispatched",
            "technical_effect_at_cancellation": ("verified" if verified else
                                                  "indeterminate" if attempted else "not_verified"),
            "effect_reversal": "not_requested",
        }
        changes = ({"operation": dict(operation, state="verified" if verified else "reconciliation_required")}
                   if attempted else self._invalidate(row, reason="local_intent_cancelled"))
        return self._save(
            ctx, row, cancellation=cancellation,
            stage="reconciliation_required" if attempted and not verified else "cancelled",
            audit_action="vendor_onboarding_cancelled", **changes,
        )

    def _invalidate(self, row, *, reason=None):
        history = list(row.get("operation_history") or [])
        if row.get("operation"):
            invalidated = dict(row["operation"], state="invalidated")
            if reason:
                invalidated["invalidated_reason"] = reason
            history.append(invalidated)
        return {"operation": None, "operation_history": history}

    def _require_new_action_review(
        self,
        ctx,
        row,
        *,
        code,
        message,
        error_type=ApprovalBindingError,
    ) -> NoReturn:
        audit_authority_denial(ctx, "action.execute", row["id"], code)
        self._save(
            ctx,
            row,
            stage="review_approved",
            **self._invalidate(row, reason=code),
        )
        raise error_type(message, code=code)

    def _invalidate_changed_execution_authority(self, ctx, case_id):
        """Retire an approval when its executor lost bound authority.

        Execution normally loads a case through the current ``read`` grant.
        A role or credential change can remove that grant, though, so waiting
        until after ``_get`` would leave the old approval reusable if the grant
        were later restored.  This narrow pre-read check may only retire an
        approved operation owned by the same tenant, resource owner and actor;
        it never returns case content to the denied caller.
        """
        row = _CASES.get(case_id)
        if not row or row.get("tenant") != ctx.tenant or row.get("owner") != ctx.resource_owner:
            return
        operation = row.get("operation") or {}
        bound = operation.get("context")
        if operation.get("state") != "approved" or not isinstance(bound, dict):
            return
        if bound.get("actor") != ctx.actor or bound == ctx.binding():
            return
        self._require_new_action_review(
            ctx,
            row,
            code="approval_authority_changed",
            message="Operation authority changed; prepare and review a new action.",
        )

    @_scoped
    def intake(self, ctx, vendor_name, document_id, project, purpose, *,
               freshness_days=365, renewal_of=None, document_ids=None,
               submission_key=None, due_at=None):
        self._permit(ctx, "intake", ctx.resource_owner)
        name = _text(vendor_name, "vendor_name", 256)
        validated_purpose = _text(purpose, "purpose")
        ids = self._document_ids(document_ids if document_ids is not None else ([document_id] if document_id else []))
        if document_id and document_id not in ids:
            raise ValueError("primary document must be included in document_ids")
        doc = ids[0] if ids else ""
        uploads = []
        if not isinstance(project, str) or not _PROJECT.fullmatch(project):
            raise ValueError("project must be a literal Jira project key")
        if type(freshness_days) is not int or not 1 <= freshness_days <= 730:
            raise ValueError("freshness_days must be between 1 and 730")
        validated_due_at = _optional_due_at(due_at)
        if renewal_of:
            prior = self._get(ctx, renewal_of)
            prior_operation_state = (prior.get("operation") or {}).get("state")
            prior_evidence_check = prior.get("acceptance_evidence_check") or {}
            reevaluation = (
                prior.get("stage") == "acceptance_reevaluation_required"
                and prior_operation_state in {None, "verified"}
                and prior.get("outcome") is None
                and prior_evidence_check.get("status") == "reevaluation_required"
            )
            if not (prior.get("outcome") or {}).get("accepted") and not reevaluation:
                raise ValueError(
                    "renewal requires an accepted case or a verified case whose evidence requires reevaluation"
                )
            if name != prior["vendor_name"]:
                raise ValueError("renewal vendor identity changed")
            uploads = list(prior.get("uploads") or [])
        if len(ids) + len(uploads) > documents.MAX_DOCUMENTS:
            raise ValueError("a case supports at most 8 evidence documents")
        if submission_key is None:
            normalized_key = uuid.uuid4().hex
        elif not isinstance(submission_key, str) or not _SUBMISSION_KEY.fullmatch(submission_key):
            raise ValueError(
                "submission_key must be 16 to 128 URL-safe characters"
            )
        else:
            normalized_key = submission_key
        key_sha256 = hashlib.sha256(normalized_key.encode("utf-8")).hexdigest()
        scope = {"tenant": ctx.tenant, "owner": ctx.resource_owner}
        case_id = "VON-" + hashlib.sha256(
            json.dumps(
                {"scope": scope, "submission_key": normalized_key},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:32]
        request_sha256 = digest({
            "vendor_name": name,
            "document_id": doc,
            "document_ids": ids,
            "uploads": uploads,
            "project": project,
            "purpose": validated_purpose,
            "freshness_days": freshness_days,
            "due_at": validated_due_at,
            "renewal_of": renewal_of,
            "requested_by": ctx.actor,
        })
        existing = _CASES.get(case_id)
        if existing is not None:
            if (existing.get("tenant") != ctx.tenant
                    or existing.get("owner") != ctx.resource_owner):
                raise VendorOnboardingIdempotencyConflict(case_id)
            self._permit(ctx, "read", case_id)
            idempotency = existing.get("intake_idempotency") or {}
            if (idempotency.get("key_sha256") == key_sha256
                    and idempotency.get("request_sha256") == request_sha256):
                return self._present(existing)
            raise VendorOnboardingIdempotencyConflict(case_id)
        vendor_id = vendors._vendor_id(name)
        vendor = vendors.get_vendor(vendor_id)
        if vendor is None:
            try:
                vendor = vendors.register_vendor(
                    name, category="AI vendor", criticality="high", owner=ctx.resource_owner,
                    actor=ctx.actor, source="vendor_onboarding",
                )
            except RecordConflict:
                vendor = vendors.get_vendor(vendor_id)
        if vendor is None or vendor["owner"] != ctx.resource_owner:
            raise PermissionError("vendor belongs to a different resource owner")
        started_at = self.clock()
        row = _CASES.create({
            "id": case_id, "schema": CASE_SCHEMA,
            "tenant": ctx.tenant, "owner": ctx.resource_owner,
            "requested_by": ctx.actor,
            "intake_idempotency": {
                "key_sha256": key_sha256,
                "request_sha256": request_sha256,
                "scope": "tenant_resource_owner",
            },
            "journey_contract": copy.deepcopy(CURRENT_JOURNEY_CONTRACT_REF),
            "vendor_id": vendor_id, "vendor_name": name, "document_id": doc,
            "document_ids": ids, "uploads": uploads,
            "project": project, "purpose": validated_purpose,
            "freshness_days": freshness_days, "due_at": validated_due_at,
            "renewal_of": renewal_of,
            "stage": "intake", "evidence": None, "assessment": None,
            "review_history": [], "operation": None, "operation_history": [],
            "exceptions": [], "outcome": None, "started_at": started_at,
            "metrics": {"execution_cost_usd": 0.0 if self.documents.mode == "offline_synthetic"
                        and self.tickets.mode == "offline_synthetic" else None,
                        "cost_basis": "no model calls; provider billing unmeasured",
                        "human_review_seconds": 0.0, "document_reads": 0},
            "integration_mode": {"documents": self.documents.mode, "tickets": self.tickets.mode},
        }, action="vendor_onboarding_intake", actor=ctx.actor, max_records=10000)
        return self._present(row)

    @_scoped
    def update_draft(
        self,
        ctx,
        case_id,
        expected_revision,
        *,
        project,
        purpose,
        freshness_days,
        due_at=None,
    ):
        """Update customer-owned request details with optimistic concurrency.

        Changes that can alter evidence eligibility restart evidence review.
        A Jira target change invalidates a prepared external action while
        retaining an otherwise current assessment. A scheduling-only change
        keeps the technical workflow at its current state.
        """

        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "intake", case_id, human=True)
        if not isinstance(project, str) or not _PROJECT.fullmatch(project):
            raise ValueError("project must be a literal Jira project key")
        validated_purpose = _text(purpose, "purpose")
        if type(freshness_days) is not int or not 1 <= freshness_days <= 730:
            raise ValueError("freshness_days must be between 1 and 730")
        validated_due_at = _optional_due_at(due_at)
        material_changed = (
            validated_purpose != row["purpose"]
            or freshness_days != row["freshness_days"]
        )
        target_changed = project != row["project"]
        schedule_changed = validated_due_at != row.get("due_at")
        if not (material_changed or target_changed or schedule_changed):
            return self._present(row)

        changes = {
            "project": project,
            "purpose": validated_purpose,
            "freshness_days": freshness_days,
            "due_at": validated_due_at,
        }
        if material_changed:
            changes.update(
                evidence=None,
                assessment=None,
                stage="intake",
                **self._invalidate(row, reason="draft_material_changed"),
            )
        elif target_changed:
            assessment = row.get("assessment") or {}
            evidence = row.get("evidence") or {}
            if assessment.get("status") == "approved":
                stage = "review_approved"
            elif assessment:
                stage = "pending_review"
            elif evidence.get("status") == "available":
                stage = "evidence_collected"
            else:
                stage = "intake"
            changes.update(
                stage=stage,
                **self._invalidate(row, reason="draft_target_changed"),
            )
        return self._save(
            ctx,
            row,
            audit_action="vendor_onboarding_draft_updated",
            **changes,
        )

    @staticmethod
    def _document_ids(values):
        if not isinstance(values, list) or len(values) > documents.MAX_DOCUMENTS:
            raise ValueError("document_ids must be a list of at most 8 Drive file IDs")
        cleaned = [_text(value, "document_id", 256) for value in values]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("each evidence document must be selected once")
        return sorted(cleaned)

    @_scoped
    def search_documents(self, ctx, query):
        self._permit(ctx, "evidence.read", ctx.resource_owner)
        return self.documents.search(ctx, query)

    @_scoped
    def set_documents(self, ctx, case_id, expected_revision, document_ids, upload_ids):
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "evidence.read", case_id)
        ids = self._document_ids(document_ids)
        if not isinstance(upload_ids, list) or any(not isinstance(value, str) for value in upload_ids) or len(set(upload_ids)) != len(upload_ids):
            raise ValueError("uploaded evidence references must be distinct")
        uploads = {item["document_id"]: item for item in row.get("uploads", [])}
        if set(upload_ids) - uploads.keys() or len(ids) + len(upload_ids) > documents.MAX_DOCUMENTS:
            raise ValueError("select at most 8 documents belonging to this case")
        return self._save(ctx, row, document_ids=ids, document_id=ids[0] if ids else "",
                          uploads=[uploads[key] for key in sorted(upload_ids)], evidence=None,
                          assessment=None, stage="intake", **self._invalidate(row))

    @_scoped
    def upload_document(self, ctx, case_id, expected_revision, *, content, name, mime, document_date):
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "evidence.upload", case_id, human=True)
        if len(row.get("document_ids", [row["document_id"]])) + len(row.get("uploads", [])) >= documents.MAX_DOCUMENTS:
            raise ValueError("remove a document before adding more than 8")
        filename = _text(name, "document name", 256)
        if re.search(r"[\x00-\x1f/\\]", filename):
            raise ValueError("document name must not contain a path or control characters")
        if type(document_date) not in (int, float) or not math.isfinite(document_date):
            raise ValueError("provide the document's actual date")
        document = EvidenceDocument("upload-" + uuid.uuid4().hex, "1", document_date, content, mime)
        result = documents.extract(document, source="upload", name=filename, now=self.clock(),
                                   freshness_days=row["freshness_days"])
        result.update(uploaded_by=ctx.actor, uploaded_at=self.clock(),
                      verification_basis="retained_upload_snapshot; no provider readback")
        # Failed extraction remains visible and must be removed or replaced;
        # it never becomes a complete assessment through partial success.
        return self._save(ctx, row, uploads=[*row.get("uploads", []), result], evidence=None,
                          assessment=None, stage="intake", **self._invalidate(row))

    def _upload_preview(self, ctx, case_id, expected_revision, *, content, name, mime,
                        document_date, transcription=None, expires_at=None):
        from .config import vendor_reviewed_uploads_enabled

        if not vendor_reviewed_uploads_enabled():
            raise PermissionError("Reviewed evidence uploads are disabled by this deployment")
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "evidence.upload", case_id, human=True)
        if len(row.get("document_ids", [])) + len(row.get("uploads", [])) >= documents.MAX_DOCUMENTS:
            raise ValueError("Remove a document before adding more than 8")
        if len(content) + sum(item.get("byte_length", 0) for item in row.get("uploads", [])) > documents.MAX_TOTAL_BYTES:
            raise ValueError("Uploaded evidence exceeds the 32 MiB request limit; remove a file before continuing")
        filename = _text(name, "document name", 256)
        if re.search(r"[\x00-\x1f/\\]", filename):
            raise ValueError("Document name must not contain a path or control characters")
        if type(document_date) not in (int, float) or not math.isfinite(document_date):
            raise ValueError("Provide the document's actual date")
        now = self.clock()
        expires_at = now + 600 if expires_at is None else expires_at
        if type(expires_at) not in (int, float) or not math.isfinite(expires_at) or not now < expires_at <= now + 600:
            raise ValueError("Evidence preview expired; review the selected file again")
        identity = digest({"bytes": hashlib.sha256(content).hexdigest(), "name": filename,
                           "mime": mime, "document_date": document_date, "transcription": transcription})
        document = EvidenceDocument("upload-" + identity[:32], "1", document_date, content, mime)
        if any(item["document_id"] == document.document_id for item in row.get("uploads", [])):
            raise ValueError("This reviewed file is already attached to the request")
        preview = {}
        result = documents.extract(document, source="upload", name=filename, now=now,
                                   freshness_days=row["freshness_days"], transcription=transcription, preview=preview)
        binding = digest({"context": asdict(ctx), "case_id": case_id, "revision": expected_revision,
                          "source": identity, "text": preview["text"], "expires_at": expires_at,
                          "extraction": result["extraction"]})
        return row, result, dict(preview, name=filename, mime=mime, source_sha256=result["content_sha256"],
            text_sha256=hashlib.sha256(preview["text"].encode("utf-8")).hexdigest(),
            status=result["status"], extraction=result["extraction"], review_digest=binding,
            expires_at=expires_at, case_id=case_id, expected_revision=expected_revision,
            review_required=True, saved=False)

    @_scoped
    def preview_upload(self, ctx, case_id, expected_revision, **kwargs):
        """Transient review only: no case mutation, provider call or full-text retention."""
        return self._upload_preview(ctx, case_id, expected_revision, **kwargs)[2]

    @_scoped
    def upload_reviewed(self, ctx, case_id, expected_revision, *, confirm, review_digest, **kwargs):
        if confirm is not True:
            raise ValueError("Confirm that you reviewed the extracted text against the original file")
        row, result, preview = self._upload_preview(ctx, case_id, expected_revision, **kwargs)
        if not isinstance(review_digest, str) or review_digest != preview["review_digest"]:
            raise ValueError("The file, text, account or request changed; review the evidence again")
        if result["status"] != "available":
            raise ValueError("No supported text is ready; use the transcription option or select another file")
        result.update(uploaded_by=ctx.actor, uploaded_at=self.clock(), reviewed_by=ctx.actor,
                      reviewed_at=self.clock(), review_basis="uploader_attested_original_comparison",
                      verification_basis="retained_upload_snapshot; no provider readback")
        return self._save(ctx, row, uploads=[*row.get("uploads", []), result], evidence=None,
                          assessment=None, stage="intake", **self._invalidate(row))

    @_scoped
    def get(self, ctx, case_id):
        return self._get(ctx, case_id)

    @_scoped
    def list(self, ctx):
        self._permit(ctx, "read", ctx.resource_owner)
        rows = _CASES.list(limit=10001)
        if len(rows) > 10000:
            raise RuntimeError("case capacity exceeded; list completeness unavailable")
        return [self._present_current(ctx, row) for row in rows if row.get("tenant") == ctx.tenant
                and row.get("owner") == ctx.resource_owner
                and self.authorize(ctx, "read", row["id"]) is True]

    @staticmethod
    def _queue_match(row, view):
        stage = row.get("stage")
        if stage not in _WORK_ITEM_STATE:
            return False
        if view == "unresolved":
            return stage in {"executing", "reconciliation_required"}
        if view == "renewal":
            return bool(row.get("renewal_of")) or stage in {
                "accepted", "acceptance_reevaluation_required",
            }
        if view == "closed":
            return stage in {"accepted", "customer_rejected", "cancelled"}
        if view == "active":
            return stage not in {"accepted", "customer_rejected", "cancelled"}
        return True

    def _queue_summary(self, ctx, row):
        presented = self._present_current(ctx, row)
        operation = row.get("operation") or {}
        evidence = row.get("evidence") or {}
        blocker = None
        if operation.get("state") in {"executing", "reconciliation_required"}:
            blocker = "external_effect_uncertain"
        elif row.get("stage") == "acceptance_reevaluation_required":
            blocker = "evidence_reevaluation_required"
        elif row.get("stage") == "review_rejected":
            blocker = "assessment_rejected"
        elif evidence and evidence.get("status") != "available":
            blocker = "evidence_" + str(evidence.get("status") or "unavailable")
        summary = {
            "id": row["id"],
            "schema": row["schema"],
            "revision": row["revision"],
            "vendor_name": row["vendor_name"],
            "owner": row["owner"],
            "requested_by": row.get("requested_by"),
            "stage": row["stage"],
            "updated_at": row.get("updated_at"),
            "due_at": _optional_due_at(row.get("due_at")),
            "renewal_of": row.get("renewal_of"),
            "blocker": blocker,
            "next_action": presented["work_item"]["next_action"],
            "work_item": presented["work_item"],
            "attention": presented["attention"],
        }
        if presented.get("reconciliation"):
            summary["reconciliation"] = presented["reconciliation"]
        return summary

    @staticmethod
    def _reconciliation_summary(row, *, current_access_unavailable=False):
        """Project an actionable, provider-data-free view of an uncertain effect."""
        operation = row.get("operation") or {}
        receipt = operation.get("receipt") or {}
        last = operation.get("last_reconciliation") or {}
        failure = str(operation.get("failure_kind") or "")
        outcome = str(last.get("outcome") or "")
        access_unavailable = current_access_unavailable or outcome == "access_unavailable" or failure in {
            "CredentialAuthorityChanged", "PermissionError",
        }
        if access_unavailable:
            reason = "current_connection_access_unavailable"
            explanation = (
                "The enrolled Jira access changed or is unavailable. No provider read or write "
                "will run until current access to the original destination is restored."
            )
            next_action = {
                "kind": "restore_access",
                "label": "Restore the original Jira connection access, then check status",
                "mode": "read_only",
                "href": "/connections",
            }
        elif outcome == "no_match":
            reason = "no_matching_effect_observed"
            explanation = (
                "The latest lookup found no matching Jira task. This does not prove that the "
                "original create had no effect."
            )
            next_action = {
                "kind": "check_status",
                "label": "Check the original Jira destination again",
                "mode": "read_only",
            }
        elif outcome == "multiple_matches":
            reason = "multiple_matching_effects_observed"
            explanation = (
                "The latest lookup found multiple possible Jira tasks, so Lightwork did not "
                "choose one or report success."
            )
            next_action = {
                "kind": "review_ambiguity",
                "label": "Review the possible Jira results before any separate resolution",
                "mode": "read_only",
            }
        elif outcome == "readback_mismatch":
            reason = "matching_effect_content_mismatch"
            explanation = (
                "One Jira task matched the operation marker, but its current content did not "
                "match the exact approved task. Lightwork did not report success."
            )
            next_action = {
                "kind": "review_ambiguity",
                "label": "Review the changed Jira task before any separate resolution",
                "mode": "read_only",
            }
        elif outcome == "readback_unavailable":
            reason = "authoritative_readback_unavailable"
            explanation = (
                "The latest Jira status check did not produce a trustworthy readback. The "
                "original effect remains unresolved."
            )
            next_action = {
                "kind": "check_status",
                "label": "Check the original Jira destination again when it is available",
                "mode": "read_only",
            }
        elif receipt:
            reason = "receipt_recorded_readback_unverified"
            explanation = (
                "A provider receipt was recorded, but authoritative readback has not verified "
                "the exact approved task."
            )
            next_action = {
                "kind": "check_status",
                "label": "Check the recorded Jira task against the approved content",
                "mode": "read_only",
            }
        else:
            reason = "attempt_result_unrecorded"
            explanation = (
                "A create attempt was durably recorded, but its provider result is unknown. "
                "Checking status cannot create another task."
            )
            next_action = {
                "kind": "check_status",
                "label": "Search the original Jira destination for the approved marker",
                "mode": "read_only",
            }
        actor = str((operation.get("context") or {}).get("actor")
                    or row.get("requested_by") or "")
        observations = [
            {
                "kind": "execution_attempt",
                "state": "recorded" if operation.get("attempts", 0) else "not_recorded",
                "count": operation.get("attempts", 0),
                "observed_at": operation.get("started_at"),
            },
            {
                "kind": "provider_receipt",
                "state": "recorded" if receipt else "not_recorded",
            },
            {
                "kind": "authoritative_readback",
                "state": outcome or "not_completed",
                **({"match_count": last["match_count"]}
                   if type(last.get("match_count")) is int else {}),
                **({"match_count_lower_bound": last["match_count_lower_bound"]}
                   if type(last.get("match_count_lower_bound")) is int else {}),
                "observed_at": last.get("checked_at"),
            },
        ]
        return {
            "schema": "lightwork.vendor-onboarding.reconciliation-summary.v1",
            "attempted_action": {
                "operation_id": operation.get("id"),
                "action": operation.get("action"),
                "attempt_count": operation.get("attempts", 0),
                "started_at": operation.get("started_at"),
                "target": {"provider": "jira", "project": row.get("project")},
            },
            "known_observations": observations,
            "uncertainty": {
                "state": "unresolved",
                "reason": reason,
                "explanation": explanation,
            },
            "safe_next_check": next_action,
            "responsible_operator": {
                "principal": actor,
                "business_owner": row.get("owner") or "",
            },
            "resolution": {
                "automatic_compensation_supported": False,
                "unreviewed_replacement_allowed": False,
                "requires_separate_review": True,
                "explanation": (
                    "Lightwork will not delete, modify, or replace a possible Jira task from "
                    "this status check. Any supported resolution requires a separate reviewed action."
                ),
            },
        }

    def _save_reconciliation(self, ctx, row, operation, *, outcome, failure_kind,
                             match_count=None, match_count_lower_bound=None):
        event = {
            "schema": "lightwork.vendor-onboarding.reconciliation-observation.v1",
            "outcome": outcome,
            "checked_at": self.clock(),
            "checked_by": ctx.actor,
            "read_only": True,
        }
        if type(match_count) is int:
            event["match_count"] = match_count
        if type(match_count_lower_bound) is int:
            event["match_count_lower_bound"] = match_count_lower_bound
        history = row.get("reconciliation_history")
        if not isinstance(history, list):
            history = []
        history = [*history[-(_MAX_RECONCILIATION_HISTORY - 1):], event]
        return self._save(
            ctx,
            row,
            stage="reconciliation_required",
            operation=dict(
                operation,
                state="reconciliation_required",
                failure_kind=failure_kind,
                last_reconciliation=event,
            ),
            reconciliation_history=history,
        )

    @staticmethod
    def _queue_scope(ctx):
        return digest({"tenant": ctx.tenant, "owner": ctx.resource_owner})

    @staticmethod
    def _encode_queue_cursor(*, backend, position, case_id, scope, view):
        payload = json.dumps({
            "backend": backend,
            "case_id": case_id,
            "position": position,
            "scope": scope,
            "v": 1,
            "view": view,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_queue_cursor(cursor, *, backend, scope, view):
        if cursor in (None, ""):
            return "", ""
        if not isinstance(cursor, str) or len(cursor) > _MAX_QUEUE_CURSOR:
            raise ValueError("case queue cursor is invalid")
        try:
            raw = base64.b64decode(
                cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True,
            )
            payload = json.loads(raw)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("case queue cursor is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {
                "backend", "case_id", "position", "scope", "v", "view"}:
            raise ValueError("case queue cursor is invalid")
        position, case_id = payload.get("position"), payload.get("case_id")
        if (payload.get("v") != 1 or payload.get("backend") != backend
                or payload.get("scope") != scope or payload.get("view") != view
                or not isinstance(position, str) or len(position) > 128
                or not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id)):
            raise ValueError("case queue cursor is invalid")
        return position, case_id

    @_scoped
    def list_page(self, ctx, *, limit=25, cursor="", view="all"):
        """Return one bounded, stable queue scan without hiding uncertainty."""
        self._permit(ctx, "read", ctx.resource_owner)
        if type(limit) is not int or not 1 <= limit <= _MAX_QUEUE_PAGE:
            raise ValueError("case queue limit must be between 1 and 100")
        if not isinstance(view, str) or view not in _QUEUE_VIEWS:
            raise ValueError("case queue view is invalid")
        backend = _CASES.backend_kind
        scope = self._queue_scope(ctx)
        start_after, last_case_id = self._decode_queue_cursor(
            cursor, backend=backend, scope=scope, view=view,
        )
        scan_limit = min(_MAX_QUEUE_SCAN, max(limit * 4, limit + 1))
        window = list(_CASES.iter_record_ids(
            start_after=start_after, limit=scan_limit + 1,
        ))
        forward = []
        for position, case_id in window:
            if last_case_id and case_id <= last_case_id:
                break
            forward.append((position, case_id))

        cases = []
        consumed = []
        record_reads = 0
        for position, case_id in forward[:scan_limit]:
            consumed.append((position, case_id))
            row = _CASES.get(case_id)
            record_reads += 1
            if (row is None or row.get("tenant") != ctx.tenant
                    or row.get("owner") != ctx.resource_owner
                    or self.authorize(ctx, "read", case_id) is not True
                    or not self._queue_match(row, view)):
                continue
            cases.append(self._queue_summary(ctx, row))
            if len(cases) == limit:
                break

        has_more = bool(consumed) and (
            len(consumed) < len(forward) or len(forward) > scan_limit
        )
        next_cursor = None
        if has_more:
            position, case_id = consumed[-1]
            next_cursor = self._encode_queue_cursor(
                backend=backend,
                position=position,
                case_id=case_id,
                scope=scope,
                view=view,
            )
        counts = {
            "admitted": len(cases),
            "accepted": sum(
                item["work_item"]["business_outcome"] == "accepted" for item in cases
            ),
            "rejected": sum(
                item["work_item"]["business_outcome"] == "rejected" for item in cases
            ),
            "needs_reconciliation": sum(
                item["attention"]["state"] == "needs_reconciliation" for item in cases
            ),
            "renewal_attention": sum(
                item["attention"]["kind"] == "evidence_renewal"
                and item["attention"]["requires_attention"]
                for item in cases
            ),
        }
        return {
            "schema": "lightwork.vendor-onboarding.case-page.v1",
            "cases": cases,
            "page_counts": counts,
            "view": view,
            "limit": limit,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "record_reads": record_reads,
            "scan_complete": not has_more,
            "order": "case_id_ascending",
        }

    @_scoped
    def collect_evidence(self, ctx, case_id, expected_revision):
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        # Evidence collection is the first underlying-work transition for a
        # vendor pilot case.  Enforce the tenant-scoped pilot binding before
        # any provider document read or workflow mutation.  Unclaimed vendor
        # cases remain ordinary onboarding work.
        from .outcome_pilot_start_gate import require_work_item_admission

        require_work_item_admission("vendor", case_id)
        self._permit(ctx, "evidence.read", case_id)
        results = []
        ids = row.get("document_ids", [row["document_id"]])
        for document_id in ids:
            result = {"document_id": document_id, "source": "gdrive", "collected_at": self.clock()}
            try:
                document = self.documents.fetch(ctx, document_id)
                if document.document_id != document_id:
                    raise ValueError("unsupported or corrupted evidence metadata")
                result = documents.extract(document, source="gdrive", name=document_id,
                                           now=self.clock(), freshness_days=row["freshness_days"])
                result.update(credential_ref=ctx.document_credential_ref,
                              credential_version=self.documents.authority_version(ctx))
            except FileNotFoundError:
                result["status"] = "missing"
            except (ValueError, UnicodeError):
                result["status"] = "corrupted"
            except PermissionError:
                raise
            except Exception:
                result["status"] = "unavailable"
            results.append(result)
        results.extend(dict(item, fresh_until=item["modified_at"] + row["freshness_days"] * 86400)
                       for item in row.get("uploads", []))
        evidence = self._evidence_set(results)
        previous = row.get("evidence")
        if row.get("renewal_of"):
            previous = self._get(ctx, row["renewal_of"]).get("evidence")
        evidence["changes"] = documents.document_diff(previous, evidence)
        metrics = dict(row["metrics"], document_reads=row["metrics"]["document_reads"] + len(ids))
        exceptions = list(row["exceptions"])
        if evidence["status"] != "available":
            exceptions.append({"kind": "evidence_" + evidence["status"], "at": self.clock(),
                               "supersedes_case_revision": row["revision"]})
        return self._save(ctx, row, evidence=evidence, assessment=None, stage="evidence_collected",
                          metrics=metrics, exceptions=exceptions, **self._invalidate(row))

    def _evidence_set(self, results):
        results = sorted(results, key=lambda item: (item["source"], item["document_id"]))
        failures = [item for item in results if item["status"] != "available"]
        status = "missing" if not results else failures[0]["status"] if failures else "available"
        if sum(item.get("byte_length", 0) for item in results) > documents.MAX_TOTAL_BYTES:
            status = "extraction_limit"
        if len(results) == 1:
            evidence = dict(results[0])
        else:
            evidence = {"source": "evidence_set", "version": digest([dict(self._identity(item), source=item["source"]) for item in results]),
                        "content_sha256": digest([{key: item.get(key) for key in ("source", "document_id", "version", "content_sha256")}
                                                   for item in results]),
                        "fresh_until": min((item["fresh_until"] for item in results
                                             if item["status"] == "available"
                                             and type(item.get("fresh_until")) in (int, float)
                                             and math.isfinite(item["fresh_until"])
                                             and item["fresh_until"] > 0), default=0)}
        return dict(evidence, status=status, documents=results, collected_at=self.clock())

    @staticmethod
    def _identity(item):
        return {key: item.get(key) for key in ("document_id", "version", "modified_at", "mime")}

    def current_evidence_version(self, ctx, row, *, verify_bytes=False):
        _require_supported_deployment()
        evidence = row["evidence"]
        observed = []
        items = sorted(evidence.get("documents") or [evidence],
                       key=lambda item: (item.get("source", "gdrive"), item["document_id"]))
        for item in items:
            if item.get("source") == "upload":
                current = next((upload for upload in row.get("uploads", []) if upload["document_id"] == item["document_id"]), None)
                if current is None or current["content_sha256"] != item["content_sha256"] or self._identity(current) != self._identity(item):
                    raise ValueError("uploaded evidence snapshot changed")
                head = self._identity(current)
            else:
                if verify_bytes:
                    document = self.documents.fetch(ctx, item["document_id"])
                    head = document.identity()
                    if hashlib.sha256(document.content).hexdigest() != item["content_sha256"]:
                        raise ValueError("source evidence bytes changed")
                else:
                    head = self.documents.head(ctx, item["document_id"])
                if head != self._identity(item):
                    raise ValueError("source evidence version changed")
            observed.append(dict(head, source=item.get("source", "gdrive")))
        return observed[0]["version"] if len(observed) == 1 else digest(observed)

    @staticmethod
    def _source_reference(row, index):
        return "EVR-" + digest({
            "case_id": row["id"],
            "evidence_sha256": row["evidence"]["content_sha256"],
            "ordinal": index,
        })[:32]

    @staticmethod
    def _safe_export_text(value, limit):
        if not isinstance(value, str):
            return ""
        from .safety.secret_detector import redact

        # All current callers already enforce smaller domain bounds. This
        # defensive cap keeps corrupted provider metadata from becoming an
        # unbounded export/redaction input.
        redacted, _matches = redact(value[:8192])
        return redacted[:limit]

    def _source_observations(self, ctx, row, *, require_review_authority):
        evidence = row.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("status") != "available":
            raise ValueError("available reviewed evidence is required")
        items = sorted(
            evidence.get("documents") or [evidence],
            key=lambda item: (item.get("source", "gdrive"), item.get("document_id", "")),
        )
        if not 1 <= len(items) <= documents.MAX_DOCUMENTS:
            raise ValueError("reviewed evidence document set is invalid")
        drive_authority = None
        drive_authority_status = "current"
        if require_review_authority and any(item.get("source") != "upload" for item in items):
            try:
                drive_authority = self.documents.authority_version(ctx)
            except PermissionError:
                drive_authority_status = "access_unavailable"
            except Exception:
                drive_authority_status = "unavailable"
        expected_authority = ((row.get("operation") or {}).get("preconditions") or {}).get(
            "document_credential_version"
        )
        observations = []
        for index, item in enumerate(items):
            source = item.get("source", "gdrive")
            document_id = item.get("document_id")
            version = item.get("version")
            content_sha256 = item.get("content_sha256")
            modified_at, fresh_until = item.get("modified_at"), item.get("fresh_until")
            if (source not in {"gdrive", "upload"}
                    or not isinstance(document_id, str) or not document_id
                    or not isinstance(version, str) or not version or len(version) > 512
                    or not isinstance(content_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", content_sha256)
                    or type(modified_at) not in (int, float) or not math.isfinite(modified_at)
                    or type(fresh_until) not in (int, float) or not math.isfinite(fresh_until)):
                raise ValueError("reviewed evidence source metadata is invalid")
            status = "current"
            current_version = None
            if source == "upload":
                current = next((upload for upload in row.get("uploads", [])
                                if upload.get("document_id") == document_id), None)
                if (current is None or current.get("content_sha256") != content_sha256
                        or self._identity(current) != self._identity(item)):
                    status = "changed"
                else:
                    current_version = current.get("version")
            elif drive_authority_status != "current":
                status = drive_authority_status
            elif (require_review_authority
                  and (drive_authority != item.get("credential_version")
                       or drive_authority != expected_authority)):
                status = "authority_changed"
            else:
                try:
                    current = self.documents.fetch(ctx, document_id)
                    current_version = current.version
                    if (current.identity() != self._identity(item)
                            or hashlib.sha256(current.content).hexdigest() != content_sha256):
                        status = "changed"
                except FileNotFoundError:
                    status = "missing"
                except PermissionError:
                    status = "access_unavailable"
                except ValueError:
                    status = "changed"
                except Exception:
                    status = "unavailable"
            if status == "current" and fresh_until <= self.clock():
                status = "expired"
            observations.append({
                "reference": self._source_reference(row, index),
                "source": source,
                "document_id": document_id,
                "reviewed_version": version,
                "current_version": current_version,
                "status": status,
                "item": item,
            })
        return observations

    def _acceptance_evidence_check(self, ctx, row):
        observations = self._source_observations(
            ctx, row, require_review_authority=True,
        )
        current = all(item["status"] == "current" for item in observations)
        return {
            "schema": "lightwork.vendor-onboarding.acceptance-evidence-check.v1",
            "status": "current" if current else "reevaluation_required",
            "checked_at": self.clock(),
            "reviewed_evidence_sha256": row["evidence"]["content_sha256"],
            "reviewed_assessment_id": row["assessment"]["id"],
            "documents": [{
                "reference": item["reference"],
                "source": item["source"],
                "document_id": item["document_id"],
                "reviewed_version": self._safe_export_text(item["reviewed_version"], 256),
                "current_version": self._safe_export_text(item["current_version"], 256),
                "status": item["status"],
            } for item in observations],
        }

    def _require_current_acceptance_evidence(self, ctx, row):
        if row.get("stage") == "acceptance_reevaluation_required":
            raise VendorOnboardingEvidenceReviewRequired(row["id"])
        evidence_check = self._acceptance_evidence_check(ctx, row)
        if evidence_check["status"] == "current":
            return evidence_check
        operation = row.get("operation") or {}
        preserve_verified_effect = operation.get("state") == "verified"
        exceptions = [*row.get("exceptions", []), {
            "kind": "evidence_reevaluation_required",
            "at": self.clock(),
            "source_references": [item["reference"] for item in evidence_check["documents"]
                                  if item["status"] != "current"],
            "supersedes_case_revision": row["revision"],
            "decision_point": "acceptance" if preserve_verified_effect else "action_authorization",
        }]
        changes = ({} if preserve_verified_effect else
                   self._invalidate(row, reason="evidence_reevaluation_required"))
        self._save(
            ctx,
            row,
            stage="acceptance_reevaluation_required",
            acceptance_evidence_check=evidence_check,
            exceptions=exceptions,
            audit_action="vendor_onboarding_evidence_invalidated",
            **changes,
        )
        raise VendorOnboardingEvidenceReviewRequired(row["id"])

    @staticmethod
    def _citation_location(citation):
        location = {}
        pages = citation.get("pages")
        if (isinstance(pages, list) and len(pages) <= 100
                and all(type(page) is int and 1 <= page <= 100000 for page in pages)):
            location["pages"] = pages
        for key in ("paragraph", "transcription_paragraph"):
            value = citation.get(key)
            if type(value) is int and 1 <= value <= 1000000:
                location[key] = value
        raw_locations = citation.get("locations")
        if isinstance(raw_locations, list) and len(raw_locations) <= 100:
            projected = []
            for value in raw_locations:
                if not isinstance(value, dict):
                    continue
                item = {}
                for key in ("sheet", "cell"):
                    text = value.get(key)
                    if isinstance(text, str) and 1 <= len(text) <= 256:
                        item[key] = text
                paragraph = value.get("paragraph")
                if type(paragraph) is int and 1 <= paragraph <= 1000000:
                    item["paragraph"] = paragraph
                if item:
                    projected.append(item)
            if projected:
                location["locations"] = projected
        return location

    def _build_evidence_export(self, ctx, row):
        assessment = risk.get_vendor_assessment(row["assessment"]["id"])
        if (assessment is None or assessment.get("revision") != row["assessment"].get("revision")
                or assessment.get("assessment_sha256") != row["assessment"].get("assessment_sha256")):
            raise ValueError("current reviewed assessment is unavailable or changed")
        reviews = row.get("review_history") or []
        if not reviews:
            raise ValueError("a human evidence review is required before export")
        review = reviews[-1]
        if (review.get("assessment_id") != assessment["id"]
                or review.get("assessment_revision") != assessment["revision"]
                or review.get("evidence_sha256") != row["evidence"]["content_sha256"]
                or review.get("decision") != assessment.get("status")):
            raise ValueError("the retained review does not bind the current evidence and assessment")
        outcome = row.get("outcome") or {}
        if outcome and (outcome.get("assessment_sha256") != assessment["assessment_sha256"]
                        or outcome.get("evidence_sha256") != row["evidence"]["content_sha256"]):
            raise ValueError("the customer decision does not bind the current evidence")

        observations = self._source_observations(
            ctx, row, require_review_authority=False,
        )
        by_source = {(item["source"], item["document_id"]): item for item in observations}
        included, withheld = [], []
        for observation in observations:
            item = observation["item"]
            if observation["status"] in {"current", "expired"}:
                included.append({
                    "reference": observation["reference"],
                    "dependency_type": "retained_upload" if observation["source"] == "upload"
                                       else "connected_source_evidence",
                    "disposition": "included",
                    "source_type": "customer_upload" if observation["source"] == "upload"
                                   else "connected_document",
                    "reviewed_version": self._safe_export_text(observation["reviewed_version"], 256),
                    "modified_at": item["modified_at"],
                    "fresh_until": item["fresh_until"],
                    "freshness": "expired" if observation["status"] == "expired" else "current",
                    "content_sha256": item["content_sha256"],
                    "extraction_method": self._safe_export_text(
                        (item.get("extraction") or {}).get("method", "unspecified"), 128,
                    ),
                })
            else:
                reason = {
                    "access_unavailable": "current_source_access_unavailable",
                    "missing": "current_source_missing",
                    "changed": "reviewed_source_changed",
                    "unavailable": "current_source_unavailable",
                    "authority_changed": "review_authority_changed",
                }.get(observation["status"], "current_source_unavailable")
                withheld.append({
                    "reference": observation["reference"],
                    "dependency_type": "external_evidence",
                    "disposition": "withheld",
                    "reason": reason,
                })
        included_refs = {item["reference"] for item in included}
        withheld_refs = {item["reference"] for item in withheld}
        correction_rows = review.get("corrections") or {}
        claims = []
        for claim_id in sorted(assessment.get("answers") or {}):
            answer = assessment["answers"][claim_id]
            citations, evidence_refs, inaccessible_refs = [], set(), set()
            raw_citations = answer.get("citations") or []
            if not isinstance(raw_citations, list) or len(raw_citations) > 3:
                raise ValueError("assessment evidence citations are invalid")
            for citation in raw_citations:
                if not isinstance(citation, dict):
                    raise ValueError("assessment evidence citation is invalid")
                source = citation.get("source", "gdrive")
                source_id = citation.get("document_id")
                observation = by_source.get((source, source_id))
                if observation is None:
                    continue
                reference = observation["reference"]
                if reference in included_refs:
                    evidence_refs.add(reference)
                    citations.append({
                        "evidence_ref": reference,
                        "quote": self._safe_export_text(citation.get("quote"), 320),
                        "location": self._citation_location(citation),
                    })
                elif reference in withheld_refs:
                    inaccessible_refs.add(reference)
            correction = correction_rows.get(claim_id) or {}
            justification = ""
            if not evidence_refs:
                justification = self._safe_export_text(
                    correction.get("note") or review.get("rationale"), 4000,
                )
            source_kind = (assessment.get("answer_sources") or {}).get(claim_id, {}).get("kind")
            if source_kind not in {"document", "manual", "vendor_attested", "prior_approved", "missing"}:
                source_kind = "unknown"
            claim = {
                "claim_id": claim_id,
                "answer": answer.get("answer") if answer.get("answer") in {"yes", "no", "na", "unknown"}
                          else "unknown",
                "note": self._safe_export_text(answer.get("note"), 1000),
                "source_basis": source_kind,
                "evidence_refs": sorted(evidence_refs),
                "withheld_evidence_refs": sorted(inaccessible_refs),
                "citations": citations,
                "review_justification": justification or None,
            }
            if outcome.get("accepted") is True and not evidence_refs and not justification:
                raise ValueError(
                    f"accepted material claim {claim_id} lacks accessible evidence or review justification"
                )
            claims.append(claim)

        state = ("accepted" if outcome.get("accepted") is True else
                 "rejected" if outcome.get("accepted") is False else "reviewed")
        export = {
            "schema": EVIDENCE_EXPORT_SCHEMA,
            "prepared_at": self.clock(),
            "case": {
                "id": row["id"],
                "revision": row["revision"],
                "workflow_schema": row["schema"],
                "evidence_sha256": row["evidence"]["content_sha256"],
                "assessment_id": assessment["id"],
                "assessment_revision": assessment["revision"],
                "assessment_sha256": assessment["assessment_sha256"],
            },
            "decision": {
                "state": state,
                "reviewer": self._safe_export_text(
                    outcome.get("reviewer") or review.get("reviewer"), 256,
                ),
                "rationale": self._safe_export_text(
                    outcome.get("rationale") or review.get("rationale"), 4000,
                ),
                "decided_at": outcome.get("decided_at") or outcome.get("accepted_at")
                              or review.get("at"),
            },
            "claims": claims,
            "manifest": {
                "schema": "lightwork.vendor-onboarding.evidence-export-manifest.v1",
                "included": included,
                "withheld": withheld,
                "included_count": len(included),
                "withheld_count": len(withheld),
                "complete": not withheld,
            },
            "limitations": [
                "Source fingerprints and review provenance do not establish that source claims are true.",
                "Only bounded redacted quotations are exported; source bytes and full extracted text are omitted.",
                "OCR, password-protected PDFs, images, charts and unsupported formats are not interpreted.",
            ],
        }
        export["binding_sha256"] = digest({
            key: value for key, value in export.items() if key != "prepared_at"
        })
        return export

    @_scoped
    def preview_evidence_export(self, ctx, case_id, expected_revision):
        row = self._get(ctx, case_id, expected_revision)
        self._permit(ctx, "evidence.export", case_id, human=True)
        return self._build_evidence_export(ctx, row)

    @_scoped
    def download_evidence_export(self, ctx, case_id, expected_revision, *, confirm,
                                 expected_export_sha256):
        row = self._get(ctx, case_id, expected_revision)
        self._permit(ctx, "evidence.export", case_id, human=True)
        if confirm is not True:
            raise ValueError("confirm the reviewed evidence export")
        if (not isinstance(expected_export_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_export_sha256)):
            raise ValueError("evidence export binding is invalid")
        export = self._build_evidence_export(ctx, row)
        if not hmac.compare_digest(export["binding_sha256"], expected_export_sha256):
            raise ValueError("evidence access or export content changed; preview the export again")
        return export

    def _draft(self, ctx, row, answers=None, marker=None):
        # Recover a risk record created before the saga's reference write failed.
        actor = (marker or f"onboarding:{row['id']}:{row['revision']}") + ":" + digest(answers)[:20]
        found = [r for r in risk._bounded_records() if r.get("assessed_by") == actor]
        if len(found) > 1:
            raise RuntimeError("assessment intent has multiple records; human reconciliation required")
        if found:
            return risk.get_vendor_assessment(found[0]["id"])
        return risk.draft_vendor_assessment(
            row["vendor_name"], answers=answers,
            document_results=[item["extracted"] for item in row["evidence"].get("documents") or [row["evidence"]]],
            actor=actor, use_prior=False,
        )

    @_scoped
    def assess(self, ctx, case_id, expected_revision):
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "assess", case_id)
        if (row.get("evidence") or {}).get("status") != "available":
            raise ValueError("assessment requires available, nonempty, supported evidence")
        assessment = self._draft(ctx, row)
        return self._save(ctx, row, assessment=assessment, stage="pending_review",
                          **self._invalidate(row))

    @_scoped
    def review(self, ctx, case_id, expected_revision, decision, rationale, *,
               corrections=None, review_seconds=None):
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "review", case_id, human=True)
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        why = _text(rationale, "rationale")
        seconds = 0.0
        if review_seconds is not None:
            if (type(review_seconds) not in (int, float) or not math.isfinite(review_seconds)
                    or not 0 <= review_seconds <= 86400):
                raise ValueError("review_seconds must be finite and between zero and one day")
            seconds = float(review_seconds)
        assessment = row.get("assessment")
        if not assessment:
            raise ValueError("assessment required")
        original = {"id": assessment["id"], "revision": assessment["revision"],
                    "assessment_sha256": assessment["assessment_sha256"]}
        if corrections:
            if not isinstance(corrections, dict):
                raise ValueError("corrections must map questionnaire IDs to typed answers")
            answers = {key: {"answer": value["answer"], "note": value.get("note", "")}
                       for key, value in assessment["answers"].items()}
            if not set(corrections).issubset(answers):
                raise ValueError("unknown correction question")
            answers.update(corrections)
            assessment = self._draft(ctx, row, answers, marker=f"correction:{case_id}:{row['revision']}")
        else:
            current = risk.get_vendor_assessment(assessment["id"])
            if current is None or current["assessment_sha256"] != assessment["assessment_sha256"]:
                raise ValueError("assessment source changed")
            assessment = current
        if assessment["status"] == "pending_review":
            assessment = risk.review_vendor_assessment(
                assessment["id"], decision=decision, rationale=why, reviewer=ctx.actor,
                expected_revision=assessment["revision"],
            )
        else:
            previous_review = assessment.get("review") or {}
            if (assessment["status"] != decision or previous_review.get("reviewer") != ctx.actor
                    or previous_review.get("rationale") != why
                    or (not corrections and row["assessment"]["status"] != "pending_review")):
                raise ValueError("reviewed assessment requires a new corrected draft")
        review = {"reviewer": ctx.actor, "decision": decision, "rationale": why,
                  "at": self.clock(), "corrections": corrections or {}, "supersedes": original,
                  "evidence_sha256": row["evidence"]["content_sha256"],
                  "assessment_id": assessment["id"], "assessment_revision": assessment["revision"],
                  "workflow_schema": row["schema"], "review_seconds": review_seconds,
                  "review_time_basis": "reported_by_human" if review_seconds is not None else "unmeasured"}
        return self._save(ctx, row, assessment=assessment, stage=f"review_{decision}",
                          review_history=[*row["review_history"], review],
                          metrics=dict(row["metrics"], human_review_seconds=
                                       row["metrics"]["human_review_seconds"] + seconds),
                          **self._invalidate(row))

    def _preconditions(self, ctx, row):
        evidence = row["evidence"]
        assessment = risk.get_vendor_assessment(row["assessment"]["id"])
        if assessment is None or assessment["status"] != "approved":
            raise ValueError("current domain assessment is not approved")
        if assessment["revision"] != row["assessment"]["revision"]:
            raise ValueError("domain assessment version changed")
        if evidence["fresh_until"] <= self.clock():
            raise ValueError("evidence freshness expired; renew evidence before execution")
        source_version = self.current_evidence_version(ctx, row)
        vendor = vendors.get_vendor(row["vendor_id"])
        if not vendor or vendor["owner"] != ctx.resource_owner or vendor["status"] == "offboarded":
            raise PermissionError("vendor ownership or lifecycle changed")
        return {"evidence_sha256": evidence["content_sha256"], "source_version": source_version,
                "assessment_id": assessment["id"], "assessment_revision": assessment["revision"],
                "assessment_sha256": assessment["assessment_sha256"],
                "vendor_revision": vendor["revision"],
                "document_credential_version": (self.documents.authority_version(ctx)
                    if any(item.get("source") != "upload" for item in evidence.get("documents") or [evidence])
                    else "not_applicable:retained_uploads"),
                "ticket_credential_version": self.tickets.authority_version(ctx)}

    @_scoped
    def prepare_action(self, ctx, case_id, expected_revision):
        row = self._get(ctx, case_id, expected_revision)
        self._editable(row)
        self._permit(ctx, "action.prepare", case_id)
        if not row.get("assessment") or row["assessment"]["status"] != "approved":
            raise ValueError("human-reviewed approved assessment required")
        if row.get("operation"):
            raise ValueError("operation already prepared; use its exact approval")
        preconditions = self._preconditions(ctx, row)
        op_id = "VOP-" + uuid.uuid4().hex
        payload = {
            "project": row["project"],
            "summary": f"AI vendor diligence: {row['vendor_name']}"[:255],
            "description": (
                f"Vendor: {row['vendor_name']}\nRequest: {row['purpose']}\nCase: {case_id}\n"
                f"Assessment: {row['assessment']['id']} revision {row['assessment']['revision']}\n"
                f"Assessment fingerprint: {row['assessment']['assessment_sha256']}\n"
                f"Risk: {row['assessment']['result']['risk_rating']}\n"
                f"Evidence: {len(row['evidence'].get('documents') or [row['evidence']])} document(s), version {row['evidence']['version']}\n"
                f"Evidence fingerprint: {row['evidence']['content_sha256']}\n"
                f"Evidence valid until: {_utc_date(row['evidence']['fresh_until'])}\n"
                f"Human review: {row['review_history'][-1]['rationale']}"
            ),
            "marker": "lightwork-" + op_id.lower(),
        }
        expires_at = min(self.clock() + 3600, row["evidence"]["fresh_until"])
        approval_card = build_approval_card(
            action="jira.create",
            summary=f"Create one reviewed Jira task for {row['vendor_name']}",
            target_label=f"Jira project {payload['project']}",
            target={
                "credential_ref": ctx.credential_ref,
                "project": payload["project"],
                "resource_owner": ctx.resource_owner,
            },
            parameters=payload,
            parameter_summary=[
                f"Project: {payload['project']}",
                f"Ticket title: {payload['summary']}",
                f"Reference that prevents a duplicate ticket: {payload['marker']}",
                "Ticket description: the vendor, the request, the approved assessment and "
                "its risk rating, the evidence and when it expires, and the reviewer's reasons",
            ],
            actor=ctx.actor,
            workspace=ctx.tenant,
            role=ctx.authorization_role,
            authority_versions={
                "role_policy": ctx.authorization_policy,
                "workspace": ctx.workspace_authority,
                "budget": ctx.budget_authority,
            },
            input_versions=preconditions,
            credential_versions={
                "ticket_reference": ctx.credential_ref,
                "ticket_version": preconditions["ticket_credential_version"],
                "document_reference": ctx.document_credential_ref,
                "document_version": preconditions["document_credential_version"],
            },
            budget={
                "currency": "USD",
                "external_effect_cost": "unmeasured",
                "authority": ctx.budget_authority,
            },
            expires_at=expires_at,
            known_effects=[
                "Creates exactly one Jira task with the reviewed title, description, and marker.",
                "The task becomes visible to people who can access the target Jira project.",
            ],
            unresolved_assumptions=[
                "Jira automation, notifications, and project workflows may create downstream effects.",
                "Lightwork cannot atomically retract notifications or copies made after creation.",
            ],
            before="No Jira task has been dispatched for this prepared operation.",
            after="One matching Jira task exists and must be verified by authoritative readback.",
            irreversible=True,
        )
        operation = {"id": op_id, "action": "jira.create", "state": "prepared",
                     "context": ctx.binding(), "payload": payload, "payload_sha256": digest(payload),
                     "preconditions": preconditions, "scope": "create_one_jira_task",
                     "expires_at": expires_at, "approval_card": approval_card,
                     "approval": None, "receipt": None, "external_confirmation": None,
                     "provider_idempotency": False, "attempts": 0}
        return self._save(ctx, row, operation=operation, stage="action_pending_approval")

    @_scoped
    def approve_action(
        self,
        ctx,
        case_id,
        expected_revision,
        approval_binding_sha256,
    ):
        row = self._get(ctx, case_id, expected_revision)
        self._permit(ctx, "action.approve", case_id, human=True)
        self._require_active_intent(row)
        operation = row.get("operation")
        if not operation or operation["state"] != "prepared":
            raise ValueError("prepared operation required")
        try:
            approval_card = validate_approval_card(operation.get("approval_card"))
        except ApprovalCardError:
            self._require_new_action_review(
                ctx,
                row,
                code="approval_binding_invalid",
                message="The prepared approval card is invalid; prepare and review a new action.",
            )
        if not isinstance(approval_binding_sha256, str):
            raise ApprovalBindingError(
                "The exact approval card was not confirmed.",
                code="approval_binding_invalid",
            )
        approval_time = self.clock()
        try:
            require_current_approval_card(
                approval_card,
                expected_binding=approval_binding_sha256,
                now=approval_time,
            )
        except ApprovalCardError as exc:
            if approval_time >= approval_card["expires_at"]:
                # Evidence expiry can be the reason the card expired because
                # action-card lifetime is capped by the reviewed source. Keep
                # that source-specific status instead of replacing it with a
                # generic card-expiry reset.
                execution = ServiceContext(**operation["context"])
                if operation["context"] == execution.binding():
                    self._require_current_acceptance_evidence(execution, row)
                self._require_new_action_review(
                    ctx,
                    row,
                    code="approval_expired",
                    message="The approval card expired; prepare and review a new action.",
                )
            raise ApprovalBindingError(
                "The exact approval card was not confirmed.",
                code="approval_binding_invalid",
            ) from exc
        # Review credentials may differ from execution credentials; source and
        # domain checks always use the bound execution principal.
        execution = ServiceContext(**operation["context"])
        if operation["context"] != execution.binding():
            self._require_new_action_review(
                ctx, row, code="approval_authority_changed",
                message="Operation authority changed; prepare and review a new action.",
            )
        try:
            self._permit(execution, "action.execute", case_id)
        except PermissionError:
            self._require_new_action_review(
                ctx, row, code="approval_authority_changed",
                message="Operation authority changed; prepare and review a new action.",
            )
        self._check_prepared_inputs(execution, row)
        approval = {"reviewer": ctx.actor, "reviewer_context": ctx.binding(),
                    "at": self.clock(), "binding_sha256": operation_binding(operation),
                    "scope": operation["scope"]}
        return self._save(ctx, row, operation=dict(operation, state="approved", approval=approval),
                          stage="action_approved")

    def _check_prepared_inputs(self, ctx, row):
        # Re-observe each reviewed source independently before comparing the
        # remaining operation bindings. This preserves actionable evidence
        # status instead of collapsing source drift into a generic retry.
        self._require_current_acceptance_evidence(ctx, row)
        try:
            matches = self._preconditions(ctx, row) == row["operation"]["preconditions"]
        except (PermissionError, ValueError):
            # Provider exception text is untrusted and may contain credentials.
            matches = False
        if not matches:
            self._require_new_action_review(
                ctx, row, code="approval_preconditions_changed",
                message="Action inputs or connection access changed; refresh the evidence and review a new action.",
                error_type=ActionReviewRequiredError,
            )

    def _permit_readback(self, ctx, row, operation):
        """Authorize a current observer without rewriting historical authority.

        Navigation, actor and spend policy changes cannot grant another create
        or strand an existing effect. The original connector enrollment and
        credential generation still pin its destination for read-only checks.
        """
        self._permit(ctx, "action.reconcile", row["id"])
        original = operation.get("context") or {}
        for field in ("tenant", "resource_owner", "credential_authority", "credential_ref"):
            if original.get(field) != getattr(ctx, field):
                audit_authority_denial(ctx, "action.reconcile", row["id"], "effect_scope_changed")
                raise PermissionError(
                    "Original effect credential scope is unavailable; restore its enrolled connection for readback."
                )
        if digest(operation["payload"]) != operation["payload_sha256"]:
            raise ValueError("operation payload digest mismatch")
        if (operation.get("approval") or {}).get("binding_sha256") != operation_binding(operation):
            raise ValueError("original operation approval binding is invalid")

    def _finish(self, ctx, row, operation, key, *, reconciled=False,
                reconciliation_event=None):
        self._permit_readback(ctx, row, operation)
        confirmation = validate_jira_verification(
            self.tickets.verify(
                ctx, key, operation["payload"],
                expected_credential_version=operation["preconditions"]["ticket_credential_version"],
            ),
            expected_key=key,
        )
        if confirmation.get("verified") is not True:
            raise ValueError("external record does not match the approved payload")
        confirmation = dict(confirmation, confirmed_at=self.clock(), reconciled=reconciled,
                            observer=ctx.binding())
        if reconciliation_event is not None:
            history = row.get("reconciliation_history")
            if not isinstance(history, list):
                history = []
            operation = dict(operation, last_reconciliation=reconciliation_event)
            history = [*history[-(_MAX_RECONCILIATION_HISTORY - 1):],
                       reconciliation_event]
        else:
            history = row.get("reconciliation_history")
        changes = {
            "operation": dict(operation, state="verified", external_confirmation=confirmation),
            "stage": "cancelled" if row.get("cancellation") else "execution_completed",
            "completed_at": self.clock(),
        }
        if isinstance(history, list):
            changes["reconciliation_history"] = history
        return self._save(ctx, row, **changes)

    @_scoped
    def execute(self, ctx, case_id, expected_revision=None):
        self._invalidate_changed_execution_authority(ctx, case_id)
        row = self._get(ctx, case_id, expected_revision)
        self._permit(ctx, "action.execute", case_id)
        self._require_active_intent(row)
        operation = row.get("operation")
        if not operation:
            raise ValueError("approved operation required")
        if operation["state"] == "verified":
            return row
        if operation["state"] in {"executing", "reconciliation_required"}:
            return self._save(ctx, row, stage="reconciliation_required",
                              operation=dict(operation, state="reconciliation_required"))
        if operation["state"] != "approved":
            raise ValueError("approved operation required")
        try:
            validate_approval(operation, ctx, self.clock())
        except ApprovalBindingError as exc:
            self._require_new_action_review(ctx, row, code=exc.code, message=str(exc))
        approval = operation["approval"]
        reviewer_context = approval.get("reviewer_context")
        if reviewer_context is None:
            # Older approvals were possible only for the bound executor.
            if approval["reviewer"] != operation["context"]["actor"]:
                raise ApprovalBindingError(
                    "The exact operation has no valid human approval.",
                    code="approval_binding_invalid",
                )
            reviewer_context = operation["context"]
        approver = ServiceContext(**reviewer_context, human=True)
        if approver.actor != approval["reviewer"] or approver.tenant != ctx.tenant:
            raise ApprovalBindingError(
                "The exact operation has no valid human approval.",
                code="approval_binding_invalid",
            )
        try:
            self._permit(approver, "action.approve", case_id, human=True)
        except PermissionError:
            self._require_new_action_review(
                ctx, row, code="approval_authority_changed",
                message="Operation authority changed; prepare and review a new action.",
            )
        self._check_prepared_inputs(ctx, row)
        operation = dict(operation, state="executing", attempts=operation["attempts"] + 1,
                         started_at=self.clock())
        row = self._save(ctx, row, operation=operation, stage="executing")
        try:
            # Revalidate after the durable claim and immediately before the
            # provider boundary. A policy/input failure here is still a known
            # zero-dispatch outcome, so invalidate it for a fresh review rather
            # than mislabelling it as an ambiguous provider effect.
            try:
                self._permit(ctx, "action.execute", case_id)
                self._check_prepared_inputs(ctx, row)
                validate_approval(operation, ctx, self.clock())
                self._permit(approver, "action.approve", case_id, human=True)
                self._permit(ctx, "action.execute", case_id)
            except (ActionReviewRequiredError, VendorOnboardingEvidenceReviewRequired):
                raise
            except ApprovalBindingError as exc:
                self._require_new_action_review(
                    ctx,
                    row,
                    code=exc.code,
                    message=str(exc),
                )
            except PermissionError:
                self._require_new_action_review(
                    ctx,
                    row,
                    code="approval_authority_changed",
                    message="Operation authority changed; prepare and review a new action.",
                )
            try:
                receipt, lineage = apply_declared(
                    operation, lambda payload: self.tickets.create(
                        ctx, payload, operation["id"],
                        expected_credential_version=operation["preconditions"]["ticket_credential_version"],
                    ),
                )
            except CredentialAuthorityChanged:
                # This exception is a known-zero result only while the create
                # adapter is still inside its pre-dispatch authority fence.
                self._require_new_action_review(
                    ctx,
                    row,
                    code="approval_authority_changed",
                    message="Connection access changed; prepare and review a new action.",
                    error_type=ActionReviewRequiredError,
                )
            operation = dict(operation, receipt=receipt, lineage=lineage)
            return self._finish(ctx, row, operation, receipt["key"])
        except (
            ActionReviewRequiredError,
            ApprovalBindingError,
            VendorOnboardingEvidenceReviewRequired,
        ):
            raise
        except Exception as exc:
            # Store only a failure class: provider responses may contain secrets.
            return self._save(ctx, row, stage="reconciliation_required",
                              operation=dict(operation, state="reconciliation_required",
                                             failure_kind=type(exc).__name__))

    @_scoped
    def reconcile(self, ctx, case_id):
        row = self._get(ctx, case_id)
        self._permit(ctx, "action.reconcile", case_id)
        operation = row.get("operation") or {}
        if operation.get("state") not in {"executing", "reconciliation_required", "verified"}:
            raise ValueError("an attempted operation is required")
        self._permit_readback(ctx, row, operation)
        try:
            matches = self.tickets.find(ctx, operation["payload"],
                                        expected_credential_version=operation["preconditions"]["ticket_credential_version"])
        except ProviderMultipleMatches as exc:
            return self._save_reconciliation(
                ctx, row, operation, outcome="multiple_matches",
                failure_kind="MultipleMatchingEffects",
                match_count_lower_bound=exc.minimum,
            )
        except (CredentialAuthorityChanged, PermissionError):
            return self._save_reconciliation(
                ctx, row, operation, outcome="access_unavailable",
                failure_kind="CredentialAuthorityChanged",
            )
        except Exception as exc:
            return self._save_reconciliation(
                ctx, row, operation, outcome="readback_unavailable",
                failure_kind=type(exc).__name__,
            )
        if len(matches) == 0:
            return self._save_reconciliation(
                ctx, row, operation, outcome="no_match",
                failure_kind="NoMatchingEffect", match_count=0,
            )
        if len(matches) != 1:
            return self._save_reconciliation(
                ctx, row, operation, outcome="multiple_matches",
                failure_kind="MultipleMatchingEffects", match_count=len(matches),
            )
        event = {
            "schema": "lightwork.vendor-onboarding.reconciliation-observation.v1",
            "outcome": "exact_match_verified",
            "checked_at": self.clock(),
            "checked_by": ctx.actor,
            "read_only": True,
            "match_count": 1,
        }
        try:
            return self._finish(
                ctx, row, operation, matches[0], reconciled=True,
                reconciliation_event=event,
            )
        except (CredentialAuthorityChanged, PermissionError):
            return self._save_reconciliation(
                ctx, row, operation, outcome="access_unavailable",
                failure_kind="CredentialAuthorityChanged", match_count=1,
            )
        except ValueError:
            return self._save_reconciliation(
                ctx, row, operation, outcome="readback_mismatch",
                failure_kind="ExternalRecordMismatch", match_count=1,
            )
        except Exception as exc:
            return self._save_reconciliation(
                ctx, row, operation, outcome="readback_unavailable",
                failure_kind=type(exc).__name__, match_count=1,
            )

    @_scoped
    def accept(self, ctx, case_id, expected_revision, accepted, rationale):
        row = self._get(ctx, case_id, expected_revision)
        self._permit(ctx, "accept", case_id, human=True)
        self._require_active_intent(row)
        if type(accepted) is not bool or row.get("outcome") is not None:
            raise ValueError("one explicit boolean acceptance decision is required")
        why = _text(rationale, "rationale")
        operation = row.get("operation") or {}
        if operation.get("state") != "verified":
            raise ValueError("verified external effect required before customer acceptance")
        evidence_check = None
        if accepted:
            evidence_check = self._require_current_acceptance_evidence(ctx, row)
        self._permit_readback(ctx, row, operation)
        confirmation_key = operation["external_confirmation"]["key"]
        observed = validate_jira_verification(
            self.tickets.verify(
                ctx, confirmation_key, operation["payload"],
                expected_credential_version=operation["preconditions"]["ticket_credential_version"],
            ),
            expected_key=confirmation_key,
        )
        if observed.get("verified") is not True:
            raise ValueError("external state changed before acceptance")
        observed = dict(observed, confirmed_at=self.clock(), observer=ctx.binding())
        vendor = vendors.get_vendor(row["vendor_id"])
        if vendor is None or vendor["owner"] != ctx.resource_owner:
            raise PermissionError("vendor ownership unavailable or changed")
        if not any(link.get("kind") == "ai_vendor_assessment"
                   and link.get("reference") == row["assessment"]["id"]
                   for link in vendor.get("links", [])):
            # Reference-before-outcome is recoverable: a retry observes the
            # existing link and cannot manufacture a second external effect.
            vendors.link_vendor_record(row["vendor_id"], kind="ai_vendor_assessment",
                                       reference=row["assessment"]["id"], actor=ctx.actor,
                                       expected_revision=vendor["revision"])
        if accepted:
            # Bracket the ticket/vendor readback with source reads. An external
            # source can change while another provider is being verified, so
            # the first successful check alone is not acceptance authority.
            evidence_check = self._require_current_acceptance_evidence(ctx, row)
        decided_at = self.clock()
        outcome = {"accepted": accepted, "reviewer": ctx.actor, "rationale": why,
                   "decided_at": decided_at, "accepted_at": decided_at,
                   "execution_completed": True,
                   "validation": "verified_external_record", "released": False,
                   "journey_contract": copy.deepcopy(row["journey_contract"]),
                   "external_confirmation": observed,
                   "assessment_id": row["assessment"]["id"],
                   "assessment_sha256": row["assessment"]["assessment_sha256"],
                   "evidence_sha256": row["evidence"]["content_sha256"],
                   "operation_id": operation["id"], "workflow_schema": row["schema"],
                   "elapsed_seconds": max(0.0, self.clock() - row["started_at"]),
                   "execution_cost_usd": row["metrics"]["execution_cost_usd"],
                   "evidence_checked_at": (evidence_check or {}).get("checked_at"),
                   "renewal_due_at": row["evidence"]["fresh_until"] if accepted else None}
        return self._save(ctx, row, outcome=outcome,
                          acceptance_evidence_check=evidence_check,
                          stage="accepted" if accepted else "customer_rejected")
