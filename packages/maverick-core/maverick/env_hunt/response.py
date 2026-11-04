"""Human-gated defensive response seam; proposal-only is the default."""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict, replace
from typing import Any, Protocol, runtime_checkable

from ..audit.errors import AuditRefused
from .models import (
    GovernedApproval,
    ResponseProposal,
    ResponseReceipt,
)

AuditRecorder = Callable[[str, dict[str, Any]], bool]


class ResponseNotAuthorized(PermissionError):
    pass


class ResponseExecutionPending(RuntimeError):
    """A prior durable claim exists and its external outcome is not retry-safe."""


@runtime_checkable
class ApprovalVerifier(Protocol):
    def verify(self, proposal: ResponseProposal, approval: GovernedApproval) -> str | None: ...


@runtime_checkable
class ResponseExecutor(Protocol):
    name: str

    def execute(
        self, proposal: ResponseProposal, approval: GovernedApproval,
    ) -> ResponseReceipt: ...


@runtime_checkable
class ResponseExecutionLedger(Protocol):
    def claim_response_execution(self, **kwargs) -> dict[str, Any]: ...

    def complete_response_execution(self, **kwargs) -> dict[str, Any]: ...

    def mark_response_execution_ambiguous(self, **kwargs) -> None: ...


class ResponseExecutorRegistry:
    """Vendor-neutral binding point; intentionally ships with no executors."""

    def __init__(self):
        self._executors: dict[str, ResponseExecutor] = {}

    def register(self, executor: ResponseExecutor) -> None:
        if not isinstance(executor, ResponseExecutor):
            raise TypeError("executor does not implement the governed response contract")
        name = str(executor.name).strip().lower()
        if not name:
            raise ValueError("response executor requires a name")
        if name in self._executors:
            raise ValueError(f"response executor {name} is already registered")
        self._executors[name] = executor

    def get(self, name: str) -> ResponseExecutor:
        try:
            return self._executors[name.strip().lower()]
        except KeyError as exc:
            raise KeyError(f"unknown response executor {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._executors))


class Ed25519ApprovalVerifier:
    """Adapter for Lightwork's exact-payload cryptographic approval boundary."""

    def __init__(self, trusted_pubkeys: list[str] | tuple[str, ...]):
        if not trusted_pubkeys:
            raise ValueError("response approval requires trusted public keys")
        self._trusted_pubkeys = list(trusted_pubkeys)

    def verify(self, proposal: ResponseProposal, approval: GovernedApproval) -> str | None:
        from ..approval_signing import verify

        if not approval.signature:
            return None
        return verify(
            response_approval_request(
                proposal,
                approval_id=approval.approval_id,
                approved_by=approval.approved_by,
            ),
            approval.signature,
            self._trusted_pubkeys,
        )


def response_approval_request(
    proposal: ResponseProposal,
    *,
    approval_id: str = "",
    approved_by: str = "",
):
    """Return the exact queue-decision-bound payload an offline approver signs.

    ``approval_id`` and ``approved_by`` are intentionally part of the signed
    domain.  A signature for one approved queue row therefore cannot authorize a
    replacement row for the same deterministic proposal, nor can mutable queue
    state silently substitute a different decision identity after signing.

    Callers may omit the two fields only to display an explicitly *unbound*
    template before the queue decision.  Such a signature is never accepted by
    :class:`Ed25519ApprovalVerifier`, which always supplies the governed row's
    exact values.
    """
    from ..approval_signing import ApprovalRequest

    decision_id = str(approval_id).strip()
    decision_sha256 = hashlib.sha256(decision_id.encode("utf-8")).hexdigest()
    decider = str(approved_by).strip()
    decider_sha256 = hashlib.sha256(decider.encode("utf-8")).hexdigest()
    return ApprovalRequest(
        candidate_id=proposal.proposal_id,
        rung=(
            f"env_response:{proposal.action}:{proposal.executor or 'unbound'}:"
            f"approval_sha256:{decision_sha256}:decider_sha256:{decider_sha256}"
        ),
        payload_sha256=proposal.digest,
    )


def response_execution_enabled(config: dict[str, Any] | None = None) -> bool:
    if config is None:
        try:
            from ..config import config_source_errors, load_global_config

            config = load_global_config()
            if config_source_errors(include_tenant=False):
                return False
        except Exception:  # failure-policy: fail_closed
            return False
    section = config.get("env_hunt") if isinstance(config, dict) else None
    return (
        section.get("response_execution", False) is True
        if isinstance(section, dict)
        else False
    )


def _audit(
    recorder: AuditRecorder | None, kind: str, payload: dict[str, Any],
) -> bool:
    if recorder is not None:
        try:
            return bool(recorder(kind, payload))
        except AuditRefused:
            raise
        except Exception:  # failure-policy: fail_closed
            return False
    try:
        from ..audit import record

        return bool(record(kind, **payload))
    except AuditRefused:
        raise
    except Exception:  # failure-policy: visible_degradation
        return False


def propose_response(
    action: str,
    target: str,
    reason: str,
    evidence: tuple,
    *,
    parameters: dict[str, Any] | None = None,
    executor: str = "",
    audit_recorder: AuditRecorder | None = None,
) -> ResponseProposal:
    proposal = ResponseProposal.build(
        action, target, reason, evidence, parameters, executor=executor,
    )
    audited_proposal = replace(proposal, audit_accepted=True)
    audited = _audit(audit_recorder, "env_hunt_response_proposed", {
        "proposal_id": proposal.proposal_id,
        "proposal_sha256": audited_proposal.digest,
        "action": proposal.action,
        "executor": proposal.executor,
        "target_sha256": __import__("hashlib").sha256(target.encode()).hexdigest(),
        "evidence_ids": [item.event_id for item in proposal.evidence],
    })
    if not audited:
        # The proposal remains non-executable; exact authorization below also
        # requires the platform approval verifier, so audit degradation cannot
        # become an execution bypass.
        return proposal
    return audited_proposal


def execute_response(
    proposal: ResponseProposal,
    approval: GovernedApproval,
    *,
    approval_verifier: ApprovalVerifier,
    executor: ResponseExecutor,
    execution_ledger: ResponseExecutionLedger | None = None,
    execution_enabled: bool = False,
    audit_recorder: AuditRecorder | None = None,
    actor: str = "system",
) -> ResponseReceipt:
    """Execute only with explicit opt-in and an exact proposal-bound approval."""
    if execution_enabled is not True:
        raise ResponseNotAuthorized("response execution is disabled; proposal only")
    if proposal.audit_accepted is not True:
        raise ResponseNotAuthorized("response proposal has no accepted audit record")
    if not proposal.executor:
        raise ResponseNotAuthorized("response proposal is not bound to an executor")
    executor_name = str(getattr(executor, "name", "")).strip().lower()
    if proposal.executor != executor_name or approval.executor.strip().lower() != executor_name:
        raise ResponseNotAuthorized("approval is not bound to this exact response executor")
    if approval.proposal_id != proposal.proposal_id or approval.proposal_sha256 != proposal.digest:
        raise ResponseNotAuthorized("approval is not bound to this exact response proposal")
    if not str(approval.approval_id).strip() or not approval.approved_by.strip():
        raise ResponseNotAuthorized("approval is not bound to an exact queue decision")
    approver = approval_verifier.verify(proposal, approval)
    if not approver:
        raise ResponseNotAuthorized("governed human approval could not be verified")
    if not isinstance(executor, ResponseExecutor):
        raise TypeError("executor does not implement the governed response contract")
    if not isinstance(execution_ledger, ResponseExecutionLedger):
        raise TypeError("response execution requires a durable claim ledger")
    authorized = _audit(audit_recorder, "env_hunt_response_authorized", {
        "proposal_id": proposal.proposal_id,
        "proposal_sha256": proposal.digest,
        "approval_id": approval.approval_id,
        "signing_key_id": approver,
        "queue_decider_sha256": hashlib.sha256(
            approval.approved_by.encode("utf-8"),
        ).hexdigest(),
        "executor": executor_name,
    })
    if not authorized:
        raise RuntimeError("response authorization audit was not accepted")
    claim = execution_ledger.claim_response_execution(
        proposal_id=proposal.proposal_id,
        proposal_sha256=proposal.digest,
        approval_id=approval.approval_id,
        executor=executor_name,
        actor=actor,
    )
    if claim.get("new_claim") is not True:
        if claim.get("status") == "completed" and isinstance(claim.get("receipt"), dict):
            return ResponseReceipt(**claim["receipt"])
        raise ResponseExecutionPending(
            "response execution was already claimed; reconcile its external outcome"
        )
    try:
        # The adapter receives the exact governed approval so it can bind the
        # external action receipt without relying on mutable global state.
        receipt = executor.execute(proposal, approval)
        if (
            receipt.proposal_id != proposal.proposal_id
            or receipt.approval_id != approval.approval_id
            or receipt.executor.strip().lower() != executor_name
        ):
            raise RuntimeError("response executor returned an unbound receipt")
        committed = execution_ledger.complete_response_execution(
            proposal_id=proposal.proposal_id,
            proposal_sha256=proposal.digest,
            approval_id=approval.approval_id,
            executor=executor_name,
            receipt=asdict(receipt),
            actor=actor,
        )
    except Exception as exc:
        try:
            execution_ledger.mark_response_execution_ambiguous(
                proposal_id=proposal.proposal_id,
                proposal_sha256=proposal.digest,
                approval_id=approval.approval_id,
                executor=executor_name,
                error_kind=type(exc).__name__,
                actor=actor,
            )
        except Exception:
            pass
        raise RuntimeError(
            "response execution outcome is ambiguous; manual reconciliation is required"
        ) from exc
    return ResponseReceipt(**committed)


__all__ = [
    "ApprovalVerifier",
    "Ed25519ApprovalVerifier",
    "ResponseExecutor",
    "ResponseExecutorRegistry",
    "ResponseExecutionLedger",
    "ResponseExecutionPending",
    "ResponseNotAuthorized",
    "execute_response",
    "propose_response",
    "response_approval_request",
    "response_execution_enabled",
]
