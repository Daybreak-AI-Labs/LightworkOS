"""Actionable approvals: signed approve/reject links a human can click from a
channel -- Slack, Teams, email, SMS -- to open the exact flow approval pause.

A link carries a stateless HMAC token over the run, decision, expiry, and
the exact approval pause (cursor/prompt/run timestamp). The
dashboard verifies the token and separately requires an authenticated,
authorized approver identity before resuming, so a forwarded token is not a
bearer decision capability. The token uses a dedicated approval-link secret and
FAILS CLOSED -- with no secret configured, no token is minted and no link is
posted (the human falls back to the dashboard).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import time

from ..approval_cards import ApprovalCardError, digest
from ..constant_time import text_equals

_DEFAULT_TTL = 7 * 24 * 3600      # a week to act on an approval
_DECISIONS = ("approved", "rejected")
FLOW_DECISION_ATTESTATION_SCHEMA = "lightwork.flow-decision-attestation.v1"


def approval_card_presentation(flow, paused, next_node, prompt: str | None,
                               *, legacy: bool = False,
                               run_data_sha256: str = "") -> dict:
    """One presentation contract for pause creation and resume verification.

    The card binds customer-facing copy as well as the operation. Both paths must
    derive that copy identically or a valid approval becomes impossible to use.
    """
    if legacy:
        target_label = (
            f"{next_node.kind} node {next_node.label or next_node.id}"
            if next_node is not None else f"complete flow {flow.id}"
        )
        return {
            "target_label": target_label,
            "parameter_summary": [
                f"Flow: {flow.name or flow.id}",
                f"Continue after approval node: {paused.id}",
                f"Current input digest: {run_data_sha256}",
                f"Next node: {target_label}",
            ],
            "known_effects": [
                "Resumes only the immutable published flow release recorded on this run.",
                "The remaining flow may invoke its reviewed external action nodes once.",
            ],
            "unresolved_assumptions": [
                "Connector credentials and target records must still pass dispatch-time authorization.",
                "External systems may apply notifications or automation after a tool action.",
            ],
            "before": "The run remains paused and no continuation node has executed.",
            "after": "The pinned continuation may execute once under current worker authority.",
        }
    step_words = {
        "agent": "AI task", "action": "Connected action",
        "branch": "Decision", "switch": "Choice",
        "foreach": "Repeat for each item", "while": "Repeat while needed",
        "parallel": "Run together", "setvar": "Update information",
        "subflow": "Run another flow", "scope": "Handle a failure",
        "delay": "Wait", "wait_event": "Wait for another app",
        "approval": "Ask for approval",
    }
    target_label = (
        next_node.label or step_words.get(next_node.kind, "Next step")
        if next_node is not None else f"Finish {flow.name or 'this flow'}"
    )
    return {
        "target_label": target_label,
        "parameter_summary": [
            f"Flow: {flow.name or 'Untitled flow'}",
            f"Decision: {prompt or paused.label or 'Continue this flow?'}",
            f"Next: {target_label}",
        ],
        "known_effects": [
            "This approval continues the reviewed version of this flow once.",
            "Remaining steps may use connected services under current permissions.",
        ],
        "unresolved_assumptions": [
            "Connected services and target records are checked again before use.",
            "A connected service may act after a step is sent to it.",
        ],
        "before": "This flow is waiting for your decision.",
        "after": "If approved, Lightwork may continue the remaining steps under current permissions.",
    }


def _secret() -> str | None:
    from ..secret_provider import get_secret
    from ..webhooks import separate_webhook_credential
    secret = get_secret("MAVERICK_FLOW_APPROVAL_SECRET")
    return secret if separate_webhook_credential(secret, "approval") else None


def _secret_for_tenant(tenant: str) -> str | None:
    """Resolve the signing key inside the token's tenant scope."""
    if not tenant:
        return _secret()
    try:
        from ..tenant.registry import assert_tenant_active
        assert_tenant_active(tenant)
        from ..paths import reset_tenant, set_tenant
        token = set_tenant(tenant)
    except Exception:  # failure-policy: fail_closed -- no secret means no signed approval
        return None
    try:
        return _secret()
    finally:
        reset_tenant(token)


def _decode_body(body: str) -> dict | None:
    if not body or len(body) > 12_000:
        return None
    try:
        pad = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + pad))
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _sign(material: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def mint_token(run_id: str, decision: str, *, cursor: str | None = None,
               prompt: str = "", updated: float | None = None,
               assignee: str = "", owner: str = "",
               binding_sha256: str = "",
               tenant: str | None = None,
               ttl: int = _DEFAULT_TTL, now: float | None = None) -> str | None:
    """A signed, self-expiring token authorising ONE decision on ONE approval
    pause. ``None`` when no secret is configured or inputs are invalid (fail closed)."""
    if tenant is None:
        from ..paths import current_tenant_id
        tenant = current_tenant_id() or ""
    tenant = str(tenant or "")
    secret = _secret_for_tenant(tenant)
    if (not secret or decision not in _DECISIONS or not run_id or not cursor
            or updated is None):
        return None
    if binding_sha256 and (
        len(binding_sha256) != 64
        or any(char not in "0123456789abcdef" for char in binding_sha256)
    ):
        return None
    exp = int((now if now is not None else time.time()) + ttl)
    raw = json.dumps({"r": str(run_id), "d": decision, "e": exp,
                      "c": str(cursor)[:256], "p": str(prompt)[:2000],
                      "u": float(updated), "t": tenant,
                      "a": str(assignee)[:500], "o": str(owner)[:500],
                      "b": binding_sha256},
                     separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{body}.{_sign(body.encode('ascii'), secret)}"


def verify_token(token: str, *, now: float | None = None) -> dict | None:
    """Return the approval claim for a valid, unexpired, correctly-signed token;
    ``None`` otherwise (no secret / bad format / bad signature / expired)."""
    if not token or len(token) > 16_384 or "." not in token:
        return None
    body, _, sig = token.partition(".")
    payload = _decode_body(body)
    if payload is None:
        return None
    # The tenant is untrusted until the signature verifies, but it is safe to
    # use solely as a key-selection namespace. No run data is read beforehand.
    tenant = str(payload.get("t") or "")
    secret = _secret_for_tenant(tenant)
    try:
        valid_sig = bool(secret) and text_equals(
            sig, _sign(body.encode("ascii"), secret or ""))
    except (UnicodeEncodeError, ValueError):
        return None
    if not valid_sig:
        return None
    run_id, decision, exp = payload.get("r"), payload.get("d"), payload.get("e")
    cursor, updated = payload.get("c"), payload.get("u")
    if (decision not in _DECISIONS or not run_id or not cursor
            or not isinstance(exp, (int, float)) or not isinstance(updated, (int, float))):
        return None
    if (now if now is not None else time.time()) > exp:
        return None
    binding = str(payload.get("b") or "")
    if binding and (
        len(binding) != 64 or any(char not in "0123456789abcdef" for char in binding)
    ):
        return None
    return {"run_id": str(run_id), "decision": str(decision),
            "cursor": str(cursor), "prompt": str(payload.get("p", "")),
            "updated": float(updated), "tenant": tenant,
            "assignee": str(payload.get("a") or ""),
            "owner": str(payload.get("o") or ""),
            "binding_sha256": binding}


def approval_links(base_url: str, run_id: str, *, cursor: str | None = None,
                   prompt: str = "", updated: float | None = None,
                   assignee: str = "", owner: str = "",
                   binding_sha256: str = "",
                   tenant: str | None = None,
                   ttl: int = _DEFAULT_TTL, now: float | None = None) -> dict | None:
    """The approve/reject URLs for a run (pointing at ``/flow/approve``), or
    ``None`` when unsigned (no secret) so the caller can fall back to a plain
    notification."""
    approve = mint_token(run_id, "approved", cursor=cursor, prompt=prompt,
                         updated=updated, assignee=assignee, owner=owner,
                         binding_sha256=binding_sha256,
                         tenant=tenant, ttl=ttl, now=now)
    reject = mint_token(run_id, "rejected", cursor=cursor, prompt=prompt,
                        updated=updated, assignee=assignee, owner=owner,
                        binding_sha256=binding_sha256,
                        tenant=tenant, ttl=ttl, now=now)
    if not (approve and reject):
        return None
    base = base_url.rstrip("/")
    return {"approve": f"{base}/flow/approve?token={approve}",
            "reject": f"{base}/flow/approve?token={reject}"}


def paused_operation_binding(
    run,
    *,
    inputs: dict | None = None,
    authority: dict | None = None,
) -> str:
    """Commit a queued verdict to one exact persisted approval pause."""
    return digest({
        "schema": "lightwork.flow-approval-operation.v1",
        "run_id": str(run.run_id),
        "flow_id": str(run.flow_id),
        "status": str(run.status),
        "cursor": str(run.cursor or ""),
        "prompt": str(run.prompt or ""),
        "updated": float(run.updated or 0.0),
        "owner": str(run.owner or ""),
        "data": dict(run.data or {}),
        "human": dict(run.human or {}),
        "definition_digest": str(run.definition_digest or ""),
        "release_digest": str(run.release_digest or ""),
        "release_id": str(run.release_id or ""),
        "execution_channel": str(run.execution_channel or ""),
        "execution_user_id": str(run.execution_user_id or ""),
        "allowed_suites": (
            None if run.allowed_suites is None else list(run.allowed_suites)
        ),
        "cost_dollars": float(run.cost_dollars or 0.0),
        "budget_limit_dollars": getattr(run, "budget_limit_dollars", None),
        "submitted_inputs": dict(inputs or {}),
        "authority": dict(authority or {}),
    })


def current_flow_runtime_authority(
    *,
    owner: str,
    execution_user_id: str,
    execution_channel: str,
    allowed_suites: list[str] | tuple[str, ...] | None,
) -> dict[str, str]:
    """Resolve current flow authority for a durable approval card.

    The returned values are commitments only. They bind the card to the strict
    workspace, current role policy, named/environment credential inventory and
    budget authority without persisting credential material itself.
    """

    try:
        from ..paths import current_tenant_id_strict

        workspace = current_tenant_id_strict() or "local"
    except Exception as exc:  # failure-policy: fail_closed -- workspace authority unavailable
        raise ApprovalCardError(
            "current flow workspace authority is unavailable"
        ) from exc

    role = "flow-execution-owner"
    permissions: list[str] = []
    dashboard_state = "not_installed"
    try:
        from maverick_dashboard.auth import auth_genuinely_off, role_for_principal
        from maverick_dashboard.rbac import permissions_for

        dashboard_state = "off" if auth_genuinely_off() else "configured"
        resolved = role_for_principal(owner or None)
        if resolved:
            role = str(resolved)
            permissions = sorted(str(item) for item in permissions_for(resolved))
        elif dashboard_state == "configured":
            raise ApprovalCardError("current flow role authority is unavailable")
    except ImportError:
        pass
    except ApprovalCardError:
        raise
    except Exception as exc:  # failure-policy: fail_closed -- role authority unavailable
        raise ApprovalCardError(
            "current flow role authority is unavailable"
        ) from exc

    try:
        from ..connections import list_connections

        named_connections = sorted(
            (
                {
                    "name": row.get("name"),
                    "connector": row.get("connector"),
                    "revision": row.get("revision"),
                    "owner": row.get("owner"),
                    "access": row.get("access"),
                }
                for row in list_connections()
                if not row.get("owner") or row.get("owner") == owner
            ),
            key=lambda row: (str(row["name"]), str(row["revision"])),
        )
        environment_credentials = [
            {
                "name_sha256": digest(name),
                "value_sha256": digest(value),
            }
            for name, value in sorted(os.environ.items())
            if value and any(
                marker in name.upper()
                for marker in ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
            )
        ]
    except Exception as exc:  # failure-policy: fail_closed -- credential authority unavailable
        raise ApprovalCardError(
            "current flow credential authority is unavailable"
        ) from exc

    try:
        from ..config import get_budget_overrides
        from ..runtime_overrides import budget_override

        configured_budget = get_budget_overrides()
        if not isinstance(configured_budget, dict):
            raise TypeError("budget overrides are not an object")
        budget_material = {
            "configured": configured_budget,
            "dashboard_dollar_cap": budget_override(),
            "environment_dollar_cap": os.environ.get("MAVERICK_BUDGET_DOLLARS"),
        }
    except Exception as exc:  # failure-policy: fail_closed -- budget authority unavailable
        raise ApprovalCardError(
            "current flow budget authority is unavailable"
        ) from exc

    runtime = {
        "schema": "lightwork.flow-runtime-authority.v1",
        "workspace": workspace,
        "owner": owner or "local:operator",
        "execution_user_id": execution_user_id,
        "execution_channel": execution_channel or "local",
        "allowed_suites": (
            None if allowed_suites is None else sorted(str(item) for item in allowed_suites)
        ),
        "dashboard_state": dashboard_state,
        "role": role,
        "permissions": permissions,
        "credential_inventory_sha256": digest({
            "named_connections": named_connections,
            "environment_credentials": environment_credentials,
        }),
        "budget_authority_sha256": digest(budget_material),
    }
    return {
        "workspace": workspace,
        "role": role,
        "authority_sha256": digest(runtime),
        "credential_inventory_sha256": runtime["credential_inventory_sha256"],
        "budget_authority_sha256": runtime["budget_authority_sha256"],
    }


def require_current_flow_approver(actor: str) -> None:
    """Require current dashboard approval authority when dashboard auth exists."""

    try:
        from maverick_dashboard.auth import auth_genuinely_off, role_for_principal
        from maverick_dashboard.rbac import permissions_for
    except ImportError:
        return
    try:
        if auth_genuinely_off():
            return
        role = role_for_principal(actor or None)
        if not role or "operate" not in permissions_for(role):
            raise ApprovalCardError(
                "the current approver lacks flow approval authority"
            )
    except ApprovalCardError:
        raise
    except Exception as exc:  # failure-policy: fail_closed -- approver authority unavailable
        raise ApprovalCardError(
            "current flow approver authority is unavailable"
        ) from exc


def flow_decision_attestation_material(
    run,
    *,
    inputs: dict | None,
    operation_binding_sha256: str,
    authority_binding_sha256: str,
    decision: str,
    decided_by: str,
) -> dict:
    """Return the exact non-secret material an authenticated decision signs."""

    card = (run.human or {}).get("approval_card")
    return {
        "schema": "lightwork.flow-decision-material.v1",
        "run_id": str(run.run_id),
        "flow_id": str(run.flow_id),
        "cursor": str(run.cursor or ""),
        "updated": float(run.updated or 0.0),
        "card_binding_sha256": str(
            card.get("binding_sha256") if isinstance(card, dict) else ""
        ),
        "workspace": str(
            ((card.get("authority") or {}).get("workspace") or "local")
            if isinstance(card, dict) else "local"
        ),
        "operation_binding_sha256": str(operation_binding_sha256 or ""),
        "authority_binding_sha256": str(authority_binding_sha256 or ""),
        "inputs_sha256": digest(dict(inputs or {})),
        "decision": str(decision or ""),
        "decided_by": str(decided_by or ""),
    }


def verify_flow_decision_attestation(
    attestation: object,
    *,
    expected_material: dict,
    expected_tenant: str,
    now: float | None = None,
) -> None:
    """Verify a dashboard-authenticated, audit-key-signed flow decision."""

    if not isinstance(attestation, dict):
        raise ApprovalCardError(
            "an authenticated flow decision attestation is required"
        )
    expected_fields = {
        "schema", "principal", "tenant", "action", "resource", "issued_at",
        "expires_at", "material_sha256", "signature",
    }
    if set(attestation) != expected_fields:
        raise ApprovalCardError("flow decision attestation fields are invalid")
    body = dict(attestation)
    signature = body.pop("signature")
    if body.get("schema") != FLOW_DECISION_ATTESTATION_SCHEMA:
        raise ApprovalCardError("flow decision attestation schema is invalid")
    material_sha256 = digest(expected_material)
    if not hmac.compare_digest(str(body.get("material_sha256") or ""), material_sha256):
        raise ApprovalCardError("flow decision attestation does not match the operation")
    if (
        body.get("principal") != expected_material.get("decided_by")
        or body.get("resource") != expected_material.get("run_id")
        or body.get("action") != "flow.approval.decide"
        or body.get("tenant") != str(expected_tenant or "")
    ):
        raise ApprovalCardError("flow decision authority does not match the operation")
    issued_at = body.get("issued_at")
    expires_at = body.get("expires_at")
    current = time.time() if now is None else float(now)
    if (
        type(issued_at) not in (int, float)
        or type(expires_at) not in (int, float)
        or not math.isfinite(float(issued_at))
        or not math.isfinite(float(expires_at))
        or float(issued_at) > current + 30
        or current >= float(expires_at)
        or float(expires_at) <= float(issued_at)
    ):
        raise ApprovalCardError("flow decision attestation is expired or invalid")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "digest", "key_id", "message_version", "signature",
    }:
        raise ApprovalCardError("flow decision signature is invalid")
    signed_digest = digest(body)
    if not hmac.compare_digest(str(signature.get("digest") or ""), signed_digest):
        raise ApprovalCardError("flow decision signature does not match the attestation")
    from ..audit.signing import (
        DETACHED_DIGEST_MESSAGE_VERSION,
        trusted_audit_public_keys,
        verify_detached_digest,
    )

    key_id = str(signature.get("key_id") or "")
    registry = trusted_audit_public_keys()
    public_key = registry.get(key_id)
    if (
        signature.get("algorithm") != "Ed25519-SHA256"
        or signature.get("message_version") != DETACHED_DIGEST_MESSAGE_VERSION
        or not public_key
        or not verify_detached_digest(
            public_key, signed_digest, str(signature.get("signature") or ""),
        )
    ):
        raise ApprovalCardError("flow decision signature is untrusted")


def _checked_paused_operation(
    run,
    flow,
    *,
    inputs: dict | None = None,
    expected_binding: str,
    authority_binding_sha256: str = "",
    decision: str = "",
    decided_by: str = "",
    expired: bool = False,
    decision_attestation: object | None = None,
    refresh: bool = False,
    now: float | None = None,
) -> dict:
    """Validate the exact persisted approval before core flow execution.

    The dashboard additionally binds mutable RBAC, credential, workspace and
    budget authority.  This core check is deliberately mandatory as well so a
    direct worker or restored job cannot bypass the persisted card, its expiry,
    immutable continuation, reviewed inputs, or consequence disclosure by
    calling :func:`flow.execution.execute` directly.
    """
    import math

    from ..approval_cards import (
        build_approval_card,
        require_current_approval_card,
        validate_approval_card,
    )
    from .payloads import approval_data

    submitted = dict(inputs or {})
    try:
        card = (
            validate_approval_card((run.human or {}).get("approval_card"))
            if expired or refresh
            else require_current_approval_card(
                (run.human or {}).get("approval_card"), now=now,
            )
        )
        paused = flow.node(run.cursor) if run.cursor else None
        if paused is None or paused.kind != "approval":
            raise ApprovalCardError("approval pause target is unavailable")
        next_node = flow.node(paused.next) if paused.next else None
        continuation = (
            next_node.to_dict()
            if next_node is not None
            else {"kind": "complete", "id": "end"}
        )
        presentation = approval_card_presentation(flow, paused, next_node, run.prompt)
        persisted_data = approval_data(run.data or {}, card)
        runtime_authority = current_flow_runtime_authority(
            owner=str(run.owner or ""),
            execution_user_id=str(run.execution_user_id or ""),
            execution_channel=str(run.execution_channel or ""),
            allowed_suites=run.allowed_suites,
        )
        card_kwargs = dict(
            action="flow.resume",
            summary=run.prompt or f"Resume {flow.name or flow.id}",
            target_label=presentation["target_label"],
            target={
                "flow_id": flow.id,
                "pause_node": paused.id,
                "continuation": continuation,
            },
            parameters={"data": persisted_data, "continuation": continuation},
            parameter_summary=presentation["parameter_summary"],
            actor=run.owner or "local:operator",
            workspace=runtime_authority["workspace"],
            role=runtime_authority["role"],
            authority_versions={
                "definition_digest": run.definition_digest,
                "release_digest": run.release_digest,
                "release_id": run.release_id,
                "execution_principal_sha256": digest(
                    run.execution_user_id or run.owner or "local:operator"
                ),
                "allowed_suites_sha256": digest(run.allowed_suites),
                "runtime_authority_sha256": runtime_authority["authority_sha256"],
            },
            input_versions={
                **({"run_data_format": card["inputs"]["run_data_format"]}
                   if "run_data_format" in card["inputs"] else {}),
                "run_data_sha256": digest(persisted_data),
                "definition_revision": run.definition_revision or flow.revision,
            },
            credential_versions={
                "execution_channel": run.execution_channel or "local",
                "inventory_sha256": runtime_authority[
                    "credential_inventory_sha256"
                ],
            },
            budget={
                "currency": "USD",
                "run_limit_dollars": (
                    run.budget_limit_dollars or flow.max_dollars or "configured runtime limit"
                ),
                "reserved_so_far_dollars": round(float(run.cost_dollars or 0.0), 4),
                "authority_sha256": runtime_authority["budget_authority_sha256"],
            },
            expires_at=float(card["expires_at"]),
            known_effects=presentation["known_effects"],
            unresolved_assumptions=presentation["unresolved_assumptions"],
            before=presentation["before"],
            after=presentation["after"],
            irreversible=bool(next_node is not None and next_node.kind == "action"),
        )
        expected_card = build_approval_card(**card_kwargs)
        if not hmac.compare_digest(
            card["binding_sha256"], expected_card["binding_sha256"]
        ):
            # A pause saved before the customer-facing copy changed must still
            # resume against its exact historical card. Rebuild that fixed
            # previous presentation; never trust submitted card text as input.
            old = approval_card_presentation(
                flow, paused, next_node, run.prompt, legacy=True,
                run_data_sha256=digest(persisted_data),
            )
            legacy_card = build_approval_card(**{**card_kwargs, **old})
            if not hmac.compare_digest(
                card["binding_sha256"], legacy_card["binding_sha256"]
            ):
                raise ApprovalCardError(
                    "approval card no longer describes the durable operation"
                )
        binding = paused_operation_binding(run, inputs=submitted)
        if not expected_binding or not hmac.compare_digest(
            binding, str(expected_binding)
        ):
            raise ApprovalCardError(
                "approval operation changed; review the current operation"
            )
        if refresh:
            if (run.status != "paused_approval" or run.resume_at is not None
                    or paused.expires_after or time.time() < float(card["expires_at"])):
                raise ApprovalCardError("only an expired open-ended approval can be refreshed")
            require_current_flow_approver(decided_by)
        elif expired:
            due_at = run.resume_at
            if (
                type(due_at) not in (int, float)
                or not math.isfinite(float(due_at))
                or time.time() < float(due_at)
            ):
                raise ApprovalCardError("approval expiry is not due")
        else:
            require_current_flow_approver(decided_by)
            verify_flow_decision_attestation(
                decision_attestation,
                expected_material=flow_decision_attestation_material(
                    run,
                    inputs=submitted,
                    operation_binding_sha256=expected_binding,
                    authority_binding_sha256=authority_binding_sha256,
                    decision=decision,
                    decided_by=decided_by,
                ),
                expected_tenant=runtime_authority["workspace"],
                now=now,
            )
        return card
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ApprovalCardError):
            raise
        raise ApprovalCardError("approval card is stale or invalid") from exc


def require_current_paused_operation(
    run, flow, *, inputs: dict | None = None, expected_binding: str,
    authority_binding_sha256: str = "", decision: str = "", decided_by: str = "",
    expired: bool = False, decision_attestation: object | None = None,
    now: float | None = None,
) -> dict:
    """Check a decision or scheduled expiry before any continuation executes.

    ``now`` fixes the instant at which card and decision freshness are judged
    (default: the current wall clock); every other binding is checked live.
    """
    return _checked_paused_operation(
        run, flow, inputs=inputs, expected_binding=expected_binding,
        authority_binding_sha256=authority_binding_sha256, decision=decision,
        decided_by=decided_by, expired=expired, decision_attestation=decision_attestation,
        now=now,
    )


def review_expired_paused_approval(run, flow, *, decided_by: str) -> dict:
    """Check an unchanged expired review without authorizing its continuation.

    Only an open-ended pause is renewable. A timed-out gate must take its
    declared expiry path. Integrity, execution data, credentials, budgets and
    current owner authority must still match the original review exactly.
    """
    return _checked_paused_operation(
        run, flow, expected_binding=paused_operation_binding(run),
        decided_by=decided_by, refresh=True,
    )


__all__ = [
    "mint_token", "verify_token", "approval_links", "paused_operation_binding",
    "current_flow_runtime_authority", "require_current_flow_approver",
    "flow_decision_attestation_material", "verify_flow_decision_attestation",
    "require_current_paused_operation", "review_expired_paused_approval",
]
