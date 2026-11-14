"""MCP caller identity, revocation, capabilities and task authorization."""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass

from .protocol import ProtocolError as _ProtocolError

log = logging.getLogger(__name__)

# Task/session records retain only a process-local, non-reusable credential
# fingerprint. The authentication and refresh paths share this same key.
_CREDENTIAL_FINGERPRINT_KEY = secrets.token_bytes(32)


def credential_fingerprint(credential: str, *, stored_agent_token: bool = False) -> str:
    """Fingerprint the same verifier form for raw and at-rest agent tokens.

    Shared credentials are always raw, even if their literal value starts with
    ``sha256:``; otherwise rotating a shared token to that text would alias the
    old credential. Only Agent Trust's stored form recognizes the prefix.
    """
    from maverick.agent_trust import hash_token

    if not (stored_agent_token and credential.startswith("sha256:")):
        credential = hash_token(credential)
    return hmac.new(
        _CREDENTIAL_FINGERPRINT_KEY,
        credential.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True)
class _TaskExecutionContext:
    """Non-secret authority that survives a tools/call -> task handoff.

    The credential itself is deliberately absent.  Its keyed fingerprint lets
    the worker detect rotation/revocation without retaining a reusable bearer.
    The frozen capability is only an upper bound: execution re-loads Agent
    Trust and intersects this snapshot with the caller's current capability.
    """

    caller_identity: str | None
    trust_principal: str
    credential_kind: str
    credential_fingerprint: str
    capability: object | None


def capability_permits(capability, tool_name: str) -> bool:
    """Fail-closed capability + revocation decision using core policy."""
    if capability is None:
        return True
    try:
        from maverick.revocation import revoked_principal

        principals = (
            capability.revocation_principals()
            if hasattr(capability, "revocation_principals")
            else (getattr(capability, "principal", ""),)
        )
        if revoked_principal(principals) is not None:
            return False
        # Capability.permits resolves max_risk through the same
        # maverick.safety.tool_risk authority used by the kernel registry.
        return bool(capability.permits(tool_name))
    except Exception as e:  # malformed/unavailable policy must not widen
        log.error("MCP capability evaluation failed for %s: %s", tool_name, e)
        return False


def principal_permits(principal: str | None) -> bool:
    """Fail closed when the authenticated transport principal is revoked."""
    if not principal:
        return True
    try:
        from maverick.revocation import revoked_principal

        candidates = (principal,)
        if not principal.startswith("agent:"):
            candidates = (f"agent:{principal}", principal)
        return revoked_principal(candidates) is None
    except Exception as e:
        log.error("MCP principal revocation evaluation failed: %s", e)
        return False


def capability_principal(capability, caller_identity: str | None) -> str:
    if caller_identity:
        return caller_identity
    principal = str(getattr(capability, "principal", "") or "")
    return principal.removeprefix("agent:") or "mcp"


def connector_principal(
    caller_identity: str | None,
    caller_trust_principal: str | None,
    capability,
) -> str | None:
    """Canonical authenticated principal for downstream connectors.

    HTTP per-agent credentials carry an unprefixed Agent Trust id while
    connection grants use the canonical ``agent:<id>`` form.  The legacy
    shared bearer is still an authenticated surface principal (``mcp``),
    so it must not collapse into the unscoped local/operator path.  An
    in-process capability supplies the final fallback for callers that do
    not traverse the HTTP transport.
    """
    transport_identity = str(
        caller_identity or caller_trust_principal or "",
    ).strip()
    if transport_identity:
        # HTTP identities come exclusively from Agent Trust (including the
        # shared ``mcp`` surface). Always add the namespace at this trust
        # boundary: a future relaxation of the agent-id grammar must not
        # let an id like ``user:alice`` or ``agent:peer`` alias an existing
        # principal.
        return f"agent:{transport_identity}"
    principal = str(getattr(capability, "principal", "") or "").strip()
    if not principal:
        return None
    if principal.startswith(("agent:", "user:")):
        return principal
    return f"agent:{principal}"


def task_execution_context(
    *,
    caller_identity: str | None,
    trust_principal: str | None,
    credential_kind: str | None,
    credential_fingerprint: str | None,
    capability,
) -> _TaskExecutionContext | None:
    """Build a complete task authority snapshot or fail closed."""
    if trust_principal or credential_kind:
        if not (trust_principal and credential_kind and credential_fingerprint):
            raise _ProtocolError(-32603, "incomplete task authorization context")
        return _TaskExecutionContext(
            caller_identity=caller_identity,
            trust_principal=trust_principal,
            credential_kind=credential_kind,
            credential_fingerprint=credential_fingerprint,
            capability=capability,
        )
    if capability is not None or caller_identity:
        # Non-HTTP callers may supply an in-process capability. HTTP always
        # supplies refreshable credential metadata through the branch above.
        return _TaskExecutionContext(
            caller_identity=caller_identity,
            trust_principal="",
            credential_kind="in_process",
            credential_fingerprint="",
            capability=capability,
        )
    return None



def task_authorizer(
    capability, caller_identity: str | None, caller_trust_principal: str | None, *,
    audit_denial: bool, refresh_context: _TaskExecutionContext | None,
    refresh_capability, record_denial, principal_check, capability_check,
):
    """Build a per-task check that can revalidate a waiting caller's grant."""
    if capability is None and caller_trust_principal is None:
        return None

    def authorize(tool_name: str) -> bool:
        current_capability = capability
        if refresh_context is not None:
            try:
                current_capability = refresh_capability(refresh_context)
            except PermissionError:
                if audit_denial:
                    record_denial(capability, caller_identity, tool_name)
                return False
        allowed = principal_check(caller_trust_principal) and capability_check(
            current_capability, tool_name,
        )
        if not allowed and audit_denial:
            record_denial(current_capability, caller_identity, tool_name)
        return allowed

    return authorize


def refresh_task_capability(context: _TaskExecutionContext, *, setting, fingerprint):
    """Re-authorize queued network work and return its narrowed grant.

    Authentication at task creation is not durable authorization: an
    operator can revoke/rotate the credential or narrow the registry entry
    while the request waits in the executor.  Re-read the trust state at
    worker pickup, verify the credential's keyed fingerprint, and
    intersect the frozen grant with the current one.  Every error is a
    denial; a queued task must never execute under stale authority.
    """
    if context.credential_kind == "in_process":
        return context.capability
    if context.credential_kind not in {"agent", "shared"}:
        raise PermissionError("task authorization is no longer valid")
    try:
        from maverick import agent_trust

        enforced, registry = agent_trust.load_trust_state()
        if context.credential_kind == "agent":
            current_agent = registry.get(context.trust_principal)
            current_credential = (
                current_agent.mcp_token if current_agent is not None else ""
            )
            # A per-agent bearer is an explicitly governed credential even
            # when default-deny admission is currently disengaged.
            decision = agent_trust.decide_inbound(
                context.trust_principal,
                registry=registry,
                enforced=True,
            )
        else:
            current_credential = setting("token", "") or ""
            # The legacy shared bearer remains unscoped in local/dev while
            # Agent Trust is disengaged. If policy became enforced while
            # queued, the current `mcp` entry becomes mandatory.
            decision = agent_trust.decide_inbound(
                context.trust_principal,
                registry=registry,
                enforced=enforced,
            )
        credential_matches = bool(current_credential) and hmac.compare_digest(
            fingerprint(current_credential, stored_agent_token=context.credential_kind == "agent"),
            context.credential_fingerprint,
        )
        if not credential_matches:
            agent_trust.record_denied(
                context.trust_principal,
                direction="inbound",
                rule="credential_rotated",
                reason="queued MCP task credential was removed or rotated",
            )
            raise PermissionError("task authorization is no longer valid")
        if decision.denied:
            agent_trust.record_denied(
                context.trust_principal,
                decision,
                direction="inbound",
            )
            raise PermissionError("task authorization is no longer valid")

        frozen = context.capability
        current = decision.capability
        if frozen is None:
            return current
        if current is None:
            return frozen
        # Preserve the authenticated principal while taking the strict
        # intersection; current policy can narrow but never broaden the
        # capability accepted at task creation.
        return frozen.intersect(current, principal=frozen.principal)
    except PermissionError:
        raise
    except Exception as e:
        log.error("queued MCP task re-authorization failed closed: %s", e)
        raise PermissionError("task authorization is unavailable") from None
