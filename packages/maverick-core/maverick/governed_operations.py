"""Durable operation bindings shared by bounded application services.

The owning domain persists the operation before calling a provider. Existing
GovernedActions still supplies typed simulation, approval gating and lineage.
An ``executing`` record after restart is ambiguous, never permission to retry.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from typing import Any

from .governed_actions import ActionSpec, GovernedActions
from .paths import canonical_tenant_id

AUTHORITY_SCHEMA = "lightwork.worker-authority.v1"


class ApprovalBindingError(PermissionError):
    """An exact approval is absent, stale or bound to different authority."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class ActionReviewRequiredError(ValueError):
    """Current action inputs no longer match the prepared operation."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


def digest(value: Any, *, default: Any = None) -> str:
    return hashlib.sha256(json.dumps(
        value, default=default, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _dataclass_fields(value: Any) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: getattr(value, field.name) for field in fields(value)}
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def dataclass_digest(value: Any) -> str:
    """``digest(asdict(value))`` without first deep-copying the whole tree.

    The encoder expands each dataclass as it meets it, so the JSON (and the
    digest) is byte-identical; a 2,000-specialist list took 180 ms per page
    the other way.
    """
    return digest(value, default=_dataclass_fields)


@dataclass(frozen=True)
class ServiceContext:
    """Authority supplied by authenticated composition, never model/body data.

    ``human`` is an assertion by the trusted caller, not authentication itself;
    the mandatory authorization callback must validate it for human operations.
    Credential references identify sealed connection records, never raw secrets.
    """

    tenant: str
    actor: str
    resource_owner: str
    credential_authority: str
    credential_ref: str
    document_credential_ref: str = "gdrive"
    human: bool = False
    authorization_role: str = "local_owner"
    authorization_policy: str = "local_owner_policy"
    budget_authority: str = "unregistered_local_budget"
    workspace_authority: str = "explicit_service_context"
    authority_schema: str = AUTHORITY_SCHEMA

    def __post_init__(self) -> None:
        for key, value in asdict(self).items():
            if key == "human":
                if type(value) is not bool:
                    raise ValueError("human must be a boolean")
            elif not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{key} must be a nonempty bounded string")
        canonical_tenant_id(self.tenant)
        if self.authority_schema != AUTHORITY_SCHEMA:
            raise ValueError("unsupported worker authority schema")

    def binding(self) -> dict[str, str]:
        return {k: v for k, v in asdict(self).items() if k != "human"}


def audit_authority_denial(
    context: ServiceContext,
    capability: str,
    resource: str,
    reason: str,
) -> None:
    """Write a tenant-local denial without disclosing the resource identifier."""
    from . import audit

    audit.audit_event(
        audit.EventKind.CAPABILITY_DENIED,
        agent=context.actor,
        action=capability,
        principal=context.actor,
        tenant=context.tenant,
        resource_sha256=digest(resource),
        reason=reason,
    )


def operation_binding(operation: dict) -> str:
    """Exact unredacted payload digest; credentials are references only."""
    material = {key: operation[key] for key in (
        "id", "action", "context", "payload", "payload_sha256", "preconditions",
        "scope", "expires_at",
    )}
    # Structured consequence/authority presentation is itself reviewed data.
    # New operations bind it; legacy rows without a card retain their historical
    # digest and are not silently rewritten during readback.
    if "approval_card" in operation:
        material["approval_card"] = operation["approval_card"]
    return digest(material)


def validate_approval(operation: dict, context: ServiceContext, now: float) -> None:
    if operation["context"] != context.binding():
        raise ApprovalBindingError(
            "Operation authority changed; prepare and review a new action.",
            code="approval_authority_changed",
        )
    if digest(operation["payload"]) != operation["payload_sha256"]:
        raise ValueError("operation payload digest mismatch")
    approval = operation.get("approval") or {}
    if approval.get("binding_sha256") != operation_binding(operation):
        raise ApprovalBindingError(
            "The exact operation has no valid human approval.",
            code="approval_binding_invalid",
        )
    if now >= operation["expires_at"]:
        raise ApprovalBindingError(
            "Operation approval expired; prepare and review a new action.",
            code="approval_expired",
        )


def apply_declared(operation: dict, apply) -> tuple[dict, dict]:
    """Execute a declared Jira operation after the domain's durable claim.

    A caller must treat *every* exception here as an ambiguous external effect.
    In particular, lineage/receipt failure cannot authorize a second create.
    """
    receipt: dict = {}

    def invoke(params):
        receipt.update(apply(params))
        return json.dumps(receipt, sort_keys=True)

    actions = GovernedActions()
    actions.register(ActionSpec(
        name="jira.create", params={"project": str, "summary": str,
                                    "description": str, "marker": str},
        risk="high", simulate=lambda _: "Create one reviewed Jira task",
        apply=invoke,
    ))
    actions.commit(
        "jira.create", operation["payload"],
        approver=operation["approval"]["reviewer"],
        sources=(operation["preconditions"]["evidence_sha256"],),
    )
    return receipt, asdict(actions.lineage[-1])
