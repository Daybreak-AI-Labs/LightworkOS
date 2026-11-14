"""Bring-your-own-agent: enroll agents built on OTHER platforms into the
governed workforce.

An Agentforce, Bedrock, OpenAI, LangChain, or home-grown agent runs on its own
runtime — Lightwork cannot orchestrate it, but it CAN govern and account for
it. This module is the missing spine between the two registries that already
exist (the Agent Trust Plane for identity/ceilings, the fleet-memory roster
for learning) and the Operating Record:

* ``enroll``       — one call registers the agent in BOTH registries, stamps
                     platform provenance (which vendor runtime it lives on,
                     who owns it, which department it serves), and audits who
                     enrolled it.
* ``mint_token``   — issues the per-surface bearer credential the agent will
                     actually authenticate with (today that is a hand-edited
                     TOML field). The token value is returned exactly once.
* ``record_run``   — ingests a completed external run as a first-class
                     Operating Record row: a goal owned by ``agent:<id>``
                     with a step trail, an outcome, and a costed episode — so
                     Overview / Spend / Workforce / Savings and the audit
                     binder see foreign agents exactly like native ones.
* ``screen``       — the governance seam: the external agent asks BEFORE
                     acting. Trust admission (registry, direction, tool and
                     risk ceilings, revocation), cumulative budget, Shield
                     input scanning, and the ``[actions]`` approval floor all
                     apply; high-risk actions park a real approval row the
                     human decides in the dashboard queue.

The external boundary is fail-closed throughout: an unenrolled agent is
denied, a Shield scanner error DENIES (never waves through), a malformed
sidecar reads as empty-but-alarmed and is never overwritten, and over-budget
agents are refused further actions rather than silently accumulating spend.
"""
from __future__ import annotations

import copy
import json
import logging
import math
import re
import secrets
import time
from collections.abc import Callable
from typing import Any

from .constant_time import text_equals

log = logging.getLogger("maverick.external_agents")

#: Platform semantics for enrollment — where the agent actually runs. This is
#: provenance (it shows on the roster, in audit rows, and as the fleet-memory
#: vendor), not a behavior switch: every platform gets the same governance.
PLATFORMS: dict[str, str] = {
    "agentforce": "Salesforce Agentforce",
    "bedrock": "AWS Bedrock Agents",
    "copilot": "Microsoft Copilot Studio",
    "openai": "OpenAI Agents",
    "langchain": "LangChain / LangGraph",
    "custom": "Custom / other runtime",
}

#: Credential surfaces an external agent can hold a bearer for. ``rest`` is
#: the external-agents HTTP API itself; the rest are the existing per-surface
#: tokens on the trust entry (distinct so a leak on one surface cannot
#: authenticate another).
TOKEN_SURFACES = ("rest", "a2a", "grpc", "mcp")

_MAX_TEXT = 4000
_MAX_STEPS = 50
_MAX_AGENTS = 500
#: Remembered idempotency keys per agent (newest kept) — a retried
#: ``record_run`` returns the original goal instead of double-counting.
_MAX_RUN_KEYS = 200
#: Auto-containment threshold: this many screening denials inside the window
#: flips the agent to contained (fail-closed; an admin releases it).
_CONTAIN_DENIALS = 5
_CONTAIN_WINDOW_SECONDS = 24 * 3600

#: Budget accounting modes. ``monthly`` resets the meter each calendar month
#: (UTC); ``total`` is a lifetime cap. Pre-v1.1 enrollments carry no period
#: and are treated as ``total`` so their semantics never change under them.
BUDGET_PERIODS = ("monthly", "total")

#: Governed-execution ledger bounds. A parked (approved-not-yet-committed)
#: execution lives at most the TTL; a full pending backlog refuses new parks
#: rather than growing the sidecar without bound.
_MAX_PENDING_EXECUTIONS = 20
_EXECUTION_TTL_SECONDS = 24 * 3600
#: Recovery scan for the newest approvals after a process dies between the
#: approval transaction and the sidecar binding write.  The approval is born
#: during that exact window, so a bounded newest-first scan is sufficient
#: while preventing an unbounded queue read on the gateway hot path.
_EXECUTION_APPROVAL_RECONCILE_LIMIT = 10_000
#: Canonical-JSON body ceiling for the execute tier — the sidecar ledger and
#: the approver display must stay readable; bulk payloads belong on the
#: system of record's own bulk surfaces, not proxied through the gateway.
_MAX_EXECUTE_BODY_BYTES = 32 * 1024
#: How long a claimed (``executing``) entry stays authoritative past its
#: claim before the status view reports it INDETERMINATE — the worker died
#: between the claim and the terminal write, so the effect may or may not
#: have fired and must never re-fire automatically.
_EXECUTING_GRACE_SECONDS = 600
#: Consumed step-up mint approvals remembered per agent (newest kept) — the
#: one-shot ledger that makes one approval mint exactly one credential.
_MAX_USED_MINT_APPROVALS = 50


class ExternalAgentsError(Exception):
    """Operator-facing failure (bad input, unknown agent, plane disabled)."""


def _safe_exception_text(exc: BaseException, *, fallback: str) -> str:
    """Bound and redact exception text before persistence or user display."""

    try:
        from .safety.secret_detector import redact

        text, _matches = redact(str(exc))
        return (text.strip() or fallback)[:200]
    except Exception:
        return fallback


class ExternalAgentsDependencyError(ExternalAgentsError):
    """The enrollment sidecar exists but cannot be used as an authority."""


class ApprovalBindingMismatch(ExternalAgentsError):
    """A caller's remembered approval binding is no longer authoritative."""


class MintApprovalPending(ExternalAgentsError):
    """A gated credential mint parked a world approval and stopped.

    ``[external_agents] mint_approval`` requires a human decision before a
    bearer is issued; the caller re-runs the mint with ``mint_approval_id``
    once approval ``approval_id`` is approved."""

    def __init__(self, message: str, approval_id: int):
        super().__init__(message)
        self.approval_id = approval_id


def enabled() -> bool:
    """``[external_agents] enable`` or ``MAVERICK_EXTERNAL_AGENTS=1``."""
    import os
    if str(os.environ.get("MAVERICK_EXTERNAL_AGENTS", "")).strip() == "1":
        return True
    try:
        from .config import load_config
        return bool((load_config() or {}).get(
            "external_agents", {}).get("enable", False))
    except Exception:
        return False


# -- sidecar registry (platform/ownership metadata + reported-spend meter) ----

def _seat_limit() -> int:
    """Enrollment cap: ``[external_agents] max_enrolled`` clamped to the
    structural ceiling. The enrollment limit lives in config, set by the
    operator (for example to match a licence); the hard cap protects the
    JSON-sidecar storage model."""
    try:
        from .config import load_config
        raw = int((load_config() or {}).get(
            "external_agents", {}).get("max_enrolled", _MAX_AGENTS))
        return max(1, min(raw, _MAX_AGENTS))
    except Exception:
        return _MAX_AGENTS


def note_seen(agent_id: str) -> None:
    """Stamp the agent's last authenticated contact (credential audit trail).

    Throttled to 5-minute granularity so the hot path never write-amplifies
    the sidecar; failures are swallowed — liveness bookkeeping must never
    break a request."""
    try:
        now = time.time()
        meta = _load_sidecar().get(agent_id)
        if meta is None or now - float(meta.get("last_seen") or 0) < 300:
            return
        with _sidecar_locked():
            sidecar = _load_sidecar()
            if agent_id in sidecar:
                sidecar[agent_id]["last_seen"] = now
                _save_sidecar(sidecar)
    except Exception:  # pragma: no cover -- bookkeeping never blocks
        log.debug("external_agents: last-seen stamp failed", exc_info=True)


def registry_path():
    """Enrollment metadata sidecar (``external_agents.json``), tenant-scoped.

    Identity and ceilings live in the Agent Trust Plane; this file carries what
    the trust entry deliberately does not: platform provenance, ownership, and
    the cumulative reported-spend meter the budget cutoff reads."""
    from .paths import data_dir
    return data_dir("external_agents.json")


def _load_sidecar(*, strict: bool = False) -> dict[str, dict]:
    path = registry_path()
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("sidecar root must be an object")
        if strict and any(not isinstance(value, dict) for value in data.values()):
            raise ValueError("sidecar contains a non-object enrollment")
        return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except (OSError, UnicodeError, ValueError) as e:
        # Metadata loss must not widen trust (identity still gates), but it
        # must not pass silently either -- the spend meters live here.
        if strict:
            raise ExternalAgentsDependencyError(
                "external-agent enrollment authority is unavailable"
            ) from e
        log.warning("external_agents: sidecar unreadable (%s); treating as "
                    "empty", e)
        return {}


def _save_sidecar(entries: dict[str, dict]) -> None:
    from .file_lock import atomic_write_text, ensure_private_directory
    # Callers read with the lenient loader, which turns an unreadable or
    # corrupt sidecar into ``{}``. Writing that back would replace every other
    # agent's enrollment, containment flag and meters, so refuse instead.
    _load_sidecar(strict=True)
    path = registry_path()
    ensure_private_directory(path.parent)
    atomic_write_text(path, json.dumps(entries, indent=2, sort_keys=True),
                      mode=0o600)


def _sidecar_locked():
    from contextlib import ExitStack

    from .authority_effects import authority_effect_fence
    from .file_lock import cross_process_lock

    # The enrollment/containment/budget/execution sidecar is authority.  Keep
    # its mutation order aligned with the trust registry and provider paths:
    # global authority fence first, then the store-specific lock.
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(cross_process_lock(registry_path()))
        return stack.pop_all()


def _month_key(now: float | None = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(now if now is not None
                                              else time.time()))


def _period_spent(meta: dict, now: float | None = None) -> float:
    """The spend that counts against the cap under the agent's budget mode."""
    if meta.get("period") == "monthly":
        if meta.get("period_key") != _month_key(now):
            return 0.0  # the month rolled; nothing spent yet this period
        return float(meta.get("period_spent") or 0.0)
    return float(meta.get("spent_dollars") or 0.0)


def _parse_tool_entry(entry: str) -> tuple[str, str | None]:
    """Split an enrollment tool entry ``name`` / ``name:risk``.

    The optional risk is the OPERATOR'S rating for that tool and floors
    whatever the caller later declares — external tool names are arbitrary,
    so the registry, not the agent's honesty, decides how risky a tool is."""
    from .safety.tool_risk import RISK_LEVELS
    name, sep, risk = str(entry).partition(":")
    name = name.strip()
    if not sep:
        return name, None
    risk = risk.strip().lower()
    if risk not in RISK_LEVELS:
        raise ExternalAgentsError(
            f"tool entry {entry!r}: unknown risk {risk!r}; expected one of "
            f"{', '.join(RISK_LEVELS)}")
    return name, risk


# -- text hygiene at the boundary ---------------------------------------------

def _clean_text(text: Any, *, shield: Any | None = None) -> str | None:
    """Redact secrets, refuse injection payloads. ``None`` = reject.

    Same posture as the fleet-memory inbox: external text is untrusted; a
    tripwire hit rejects the field rather than laundering it into the record.
    A Shield instance, when provided, gets the final word — and a scanner
    ERROR rejects (fail-closed: this is an external boundary)."""
    safe = str(text or "")[:_MAX_TEXT]
    if not safe:
        return ""
    try:
        from .safety.secret_detector import redact
        safe = redact(safe)[0]
    except Exception:
        return None
    try:
        from .memory_guard import injection_markers
        if injection_markers(safe):
            return None
    except Exception:
        return None
    if shield is not None:
        try:
            verdict = shield.scan_input(safe)
            if not verdict.allowed:
                return None
        except Exception:
            return None
    return safe


# -- enrollment ---------------------------------------------------------------

def enroll(
    agent_id: str,
    platform: str,
    *,
    description: str = "",
    owner: str = "",
    department: str = "",
    allow_tools: list[str] | None = None,
    deny_tools: list[str] | None = None,
    max_risk: str | None = None,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
    data_scopes: list[str] | None = None,
    expires_days: float | None = None,
    budget_period: str = "monthly",
    enrolled_by: str = "",
) -> dict:
    """Enroll one external agent across every plane in a single call.

    Creates/replaces the managed Agent Trust entry (direction ``inbound`` —
    the agent calls us; we never dial an enrolled foreign runtime), registers
    the agent on the fleet-memory roster when that plane is enabled, and
    stamps the enrollment metadata sidecar. Returns a summary; raises
    :class:`ExternalAgentsError` on bad input."""
    from .agent_trust import AgentTrustError, put_agent
    platform = str(platform or "").strip().lower()
    if platform not in PLATFORMS:
        raise ExternalAgentsError(
            f"unknown platform {platform!r}; expected one of "
            f"{', '.join(sorted(PLATFORMS))}")
    if budget_period not in BUDGET_PERIODS:
        raise ExternalAgentsError(
            f"unknown budget_period {budget_period!r}; expected one of "
            f"{', '.join(BUDGET_PERIODS)}")
    # Tool entries may carry the operator's risk rating ("name:risk"); the
    # trust entry keeps the bare names, the sidecar keeps the risk map.
    tool_names: list[str] = []
    tool_risks: dict[str, str] = {}
    for raw in allow_tools or []:
        name, tool_risk = _parse_tool_entry(raw)
        if name:
            tool_names.append(name)
            if tool_risk:
                tool_risks[name] = tool_risk
    sidecar = _load_sidecar()
    if agent_id not in sidecar and len(sidecar) >= _seat_limit():
        raise ExternalAgentsError(
            f"enrollment limit reached ({_seat_limit()} seats); raise "
            "[external_agents] max_enrolled or unenroll unused agents")
    entry: dict[str, Any] = {
        "id": agent_id,
        "direction": "inbound",
        "allow_tools": sorted(tool_names),
        "deny_tools": sorted(deny_tools or []),
        "max_risk": max_risk,
        "max_dollars": max_dollars,
        "max_wall_seconds": max_wall_seconds,
        "data_scopes": sorted(data_scopes or []),
    }
    if expires_days is not None:
        if not isinstance(expires_days, (int, float)) or expires_days <= 0:
            raise ExternalAgentsError("expires_days must be a positive number")
        entry["expires_at"] = time.time() + float(expires_days) * 86400
    try:
        agent = put_agent(entry, preserve_existing_identity=True)
    except AgentTrustError as e:
        raise ExternalAgentsError(
            _safe_exception_text(e, fallback="external-agent enrollment failed")
        ) from e
    fleet = "disabled"
    try:
        from . import fleet_memory
        if fleet_memory.enabled():
            fleet = ("registered" if fleet_memory.register_agent(
                agent.id, platform, description=description) else "refused")
    except Exception as e:
        fleet = "error"
        log.warning("external_agents: fleet roster registration failed for "
                    "%r: %s", agent.id, e)
    with _sidecar_locked():
        sidecar = _load_sidecar()
        prior = sidecar.get(agent.id, {})
        # Re-enrollment updates the enrollment fields and keeps everything
        # else the entry carries (execution and mint ledgers, last contact).
        sidecar[agent.id] = {
            **prior,
            "platform": platform,
            "description": str(description or "")[:500],
            "owner": str(owner or "")[:200],
            "department": str(department or "")[:100],
            "enrolled_by": str(enrolled_by or "")[:200],
            "enrolled_at": prior.get("enrolled_at") or time.time(),
            "spent_dollars": float(prior.get("spent_dollars") or 0.0),
            "runs": int(prior.get("runs") or 0),
            "last_run_at": prior.get("last_run_at"),
            # v1.1 governance state (re-enrollment preserves the meters and
            # NEVER silently lifts a containment — that's the release action).
            "period": budget_period,
            "period_key": prior.get("period_key") or _month_key(),
            "period_spent": float(prior.get("period_spent") or 0.0),
            "tool_risks": tool_risks,
            "run_keys": dict(prior.get("run_keys") or {}),
            "denials": list(prior.get("denials") or []),
            "contained": bool(prior.get("contained")),
            "wall_violations": int(prior.get("wall_violations") or 0),
        }
        _save_sidecar(sidecar)
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_AGENT_ENROLLED, agent="external_agents",
                external_agent=agent.id, platform=platform,
                department=department, enrolled_by=enrolled_by)
    return {"id": agent.id, "platform": platform, "trust": "registered",
            "fleet_memory": fleet, "expires_at": agent.expires_at}


def unenroll(agent_id: str) -> bool:
    """Remove the managed trust entry + sidecar metadata. The fleet-memory
    roster entry (learning provenance) is kept — history is not rewritten."""
    from .agent_trust import remove_agent
    removed = remove_agent(agent_id)
    with _sidecar_locked():
        sidecar = _load_sidecar()
        if sidecar.pop(agent_id, None) is not None:
            _save_sidecar(sidecar)
            removed = True
    return removed


def mint_token(
    agent_id: str,
    surface: str,
    *,
    minted_by: str = "",
    mint_approval_id: int | None = None,
    mint_authority: object | None = None,
) -> str:
    """Mint (or rotate) the bearer credential for one surface.

    Returns the token value — the ONLY time it is ever shown; the registry
    stores it for verification but no read path returns it. Raises on an
    unknown agent or surface.

    Step-up re-auth: with ``[external_agents] mint_approval`` on, a call
    without ``mint_approval_id`` parks a world approval (dual-control quorum
    at "high" risk, requested by ``minted_by``) and raises
    :class:`MintApprovalPending` carrying its id; the caller re-runs the mint
    with that id once a decision-maker approves. Approvals are one-shot and
    bound to exactly this agent + surface."""
    from .agent_trust import AgentTrustError, lookup, put_agent
    if surface not in TOKEN_SURFACES:
        raise ExternalAgentsError(
            f"unknown surface {surface!r}; expected one of "
            f"{', '.join(TOKEN_SURFACES)}")
    from .authority_effects import authority_effect_fence

    # Resolve, approve, and replace the same trust generation under the shared
    # effect fence.  Without this outer scope, a concurrent attenuation or
    # credential rotation could land between the approval check and put_agent,
    # then be silently overwritten from the stale snapshot read above.
    with authority_effect_fence():
        agent = lookup(agent_id)
        if agent is None:
            raise ExternalAgentsError(f"agent {agent_id!r} is not enrolled")
        authority = _current_mint_authority(
            agent_id,
            surface,
            minted_by=minted_by,
            opaque_authority=mint_authority,
        )
        approved_id: int | None = None
        if _mint_approval_required():
            if mint_approval_id is None:
                approval_id = _park_mint_approval(agent_id, surface, authority)
                raise MintApprovalPending(
                    f"credential mint for {agent_id!r} ({surface}) requires "
                    f"approval: parked as approval #{approval_id} — have a "
                    "decision-maker approve it in the dashboard queue, then "
                    "re-run the mint with that approval id", approval_id)
            approved_id = _consume_mint_approval(
                agent_id, surface, mint_approval_id, authority=authority,
            )
        token = f"lw-{surface}-{secrets.token_urlsafe(32)}"
        entry = _entry_from_agent(agent)
        # At rest the registry holds only the hash — a leaked overlay backup
        # must never authenticate. The raw value exists in this return alone.
        from .agent_trust import hash_token
        entry[f"{surface}_token"] = hash_token(token)
        try:
            put_agent(entry)
        except AgentTrustError as e:
            raise ExternalAgentsError(
                _safe_exception_text(e, fallback="external-agent credential update failed")
            ) from e
    from .audit import EventKind, audit_event
    extra = {"mint_approval_id": approved_id} if approved_id else {}
    audit_event(EventKind.EXTERNAL_CREDENTIAL_MINTED, agent="external_agents",
                external_agent=agent_id, surface=surface, **extra)
    return token


def _mint_approval_required() -> bool:
    """``[external_agents] mint_approval``: step-up re-auth on credential
    minting — a mint parks a world approval a decision-maker must approve."""
    try:
        from .config import config_source_errors, get_external_agents
        required = bool(get_external_agents()["mint_approval"])
        # An unreadable config may have lost the policy: park the approval.
        return required or bool(config_source_errors(include_tenant=True))
    except Exception as exc:
        raise ExternalAgentsError(
            "credential mint approval policy is unavailable; refusing to "
            "mint (fail closed)"
        ) from exc


def _mint_action(agent_id: str, surface: str) -> str:
    """The approval action string a mint approval is bound to — the exact-
    match check is what stops an approval minting for another agent/surface."""
    return f"mint-credential:{agent_id}:{surface}"


_MINT_ROLE = "external_agent_credential_admin"
_MINT_AUTHORITY_VERSIONS = {
    "request_schema": "lightwork.operation-approval.v1",
}
_MINT_BUDGET = {
    "state": "not_applicable",
    "operation": "credential_rotation",
}
_EXECUTION_ROLE = "external_agent_operator"
_EXECUTION_AUTHORITY_VERSIONS = {
    "request_schema": "lightwork.operation-approval.v1",
}
_EXECUTION_BUDGET = {"state": "governed_again_at_execution"}


def _current_workspace() -> str:
    try:
        from .paths import current_tenant_id_strict

        return current_tenant_id_strict() or "local"
    except Exception as exc:
        raise ExternalAgentsError(
            "external-agent workspace authority is unavailable"
        ) from exc


def _current_execution_authority(agent_id: str) -> dict[str, object]:
    """Resolve the exact principal/workspace/role bound to an execution."""

    return {
        "actor": f"agent:{agent_id}",
        "workspace": _current_workspace(),
        "role": _EXECUTION_ROLE,
        "versions": dict(_EXECUTION_AUTHORITY_VERSIONS),
    }


def _current_mint_authority(
    agent_id: str,
    surface: str,
    *,
    minted_by: str,
    opaque_authority: object | None,
) -> dict[str, object]:
    """Resolve current mint authority at the credential-effect boundary."""

    workspace = _current_workspace()
    actor = " ".join(str(minted_by or "local:operator").split())
    if opaque_authority is None:
        try:
            from maverick_dashboard.auth import auth_genuinely_off

            if not auth_genuinely_off():
                raise ExternalAgentsError(
                    "an authenticated credential mint authority is required"
                )
        except ImportError:
            # Core-only local installations have no dashboard identity boundary.
            pass
    if opaque_authority is not None:
        expected_resource = f"{agent_id}:{surface}"
        if (
            getattr(opaque_authority, "action", None)
            != "external_agents.credential_mint"
            or getattr(opaque_authority, "resource", None) != expected_resource
            or getattr(opaque_authority, "tenant", None) != workspace
        ):
            raise ExternalAgentsError(
                "authenticated credential mint authority does not match this request"
            )
        actor = " ".join(str(getattr(opaque_authority, "principal", "")).split())
        if not actor:
            raise ExternalAgentsError(
                "authenticated credential mint authority has no actor"
            )
    return {
        "actor": actor,
        "workspace": workspace,
        "role": _MINT_ROLE,
        "versions": dict(_MINT_AUTHORITY_VERSIONS),
        "budget": dict(_MINT_BUDGET),
    }


def _agent_credential_versions(agent_id: str) -> dict[str, str]:
    """Commit approval cards to the current external-agent trust record."""
    from .agent_trust import lookup
    from .approval_cards import digest

    agent = lookup(agent_id)
    if agent is None:
        raise ExternalAgentsError(f"agent {agent_id!r} is not enrolled")
    return {"agent_trust_sha256": digest(_entry_from_agent(agent))}


def _approval_card_matches(
    detail: str | None,
    *,
    action: str,
    target: dict,
    parameters: dict,
    input_versions: dict,
    credential_versions: dict,
    authority: dict | None = None,
    budget: dict | None = None,
) -> bool:
    """Validate one current structured card against the operation in hand."""
    from .approval_cards import (
        ApprovalCardError,
        decode_approval_detail,
        digest,
        require_current_approval_card,
    )

    try:
        card = decode_approval_detail(detail)
        if card is None:
            return False
        card = require_current_approval_card(card)
        return (
            card["action"] == action
            and secrets.compare_digest(card["target"]["sha256"], digest(target))
            and secrets.compare_digest(
                card["parameters"]["sha256"], digest(parameters)
            )
            and card["inputs"] == input_versions
            and card["credentials"] == credential_versions
            and (authority is None or card["authority"] == authority)
            and (budget is None or card["budget"] == budget)
        )
    except (ApprovalCardError, KeyError, TypeError, ValueError):
        return False


def _park_mint_approval(agent_id: str, surface: str, authority: dict) -> int:
    """Park the step-up approval for one credential mint; returns its id."""
    from .approval_cards import encode_operation_approval_detail
    from .safety.dual_control import required_approvals
    from .world_model import open_world

    action = _mint_action(agent_id, surface)
    target = {"agent_id": agent_id, "surface": surface}
    parameters = {"operation": "mint_or_rotate"}
    credential_versions = _agent_credential_versions(agent_id)
    return open_world().create_approval(
        action, risk="high",
        detail=encode_operation_approval_detail(
            action=action,
            summary=f"Mint or rotate the {surface} bearer for {agent_id}",
            target_label=f"External agent {agent_id} ({surface})",
            target=target,
            parameters=parameters,
            parameter_summary=[
                f"Credential surface: {surface}",
                "The prior bearer will stop working immediately.",
            ],
            actor=str(authority["actor"]),
            role=str(authority["role"]),
            authority_versions=dict(authority["versions"]),
            credential_versions=credential_versions,
            budget=dict(authority["budget"]),
            known_effects=[
                "Issues one new bearer and replaces the current bearer for this surface.",
                "Returns the new bearer to the requester exactly once.",
            ],
            unresolved_assumptions=[
                "The requester will transfer and store the new bearer securely."
            ],
            before="The current credential state remains authoritative.",
            after="A newly generated bearer becomes authoritative for this surface.",
            # Rotating a bearer invalidates the prior secret immediately. A
            # later rotation can restore access, but cannot make that old
            # bearer valid again.
            irreversible=True,
        ),
        provenance="external_agents",
        approvals_required=required_approvals("high"),
        requested_by=str(authority["actor"]))


def _consume_mint_approval(
    agent_id: str,
    surface: str,
    mint_approval_id: int,
    *,
    authority: dict,
) -> int:
    """Validate + spend one mint approval; returns its id, raises on refusal.

    The approval must exist under our provenance, match this agent + surface's
    action string exactly, and be approved. Consumption is recorded in the
    agent's sidecar (``used_mint_approvals``, bounded, checked under the lock)
    BEFORE the mint so one approval mints exactly one credential — a racing or
    repeated mint with the same id is refused, and a storage failure after the
    spend burns the approval rather than ever letting it cover two mints."""
    try:
        approval_id = int(mint_approval_id)
    except (TypeError, ValueError) as e:
        raise ExternalAgentsError(
            f"mint_approval_id {mint_approval_id!r} is not an approval "
            "id") from e
    from .approval_cards import digest as approval_digest
    from .world_model import open_world
    approval = open_world().get_approval(approval_id)
    if approval is None or approval.provenance != "external_agents":
        raise ExternalAgentsError(f"unknown mint approval {approval_id!r}")
    action = _mint_action(agent_id, surface)
    if approval.action != action:
        raise ExternalAgentsError(
            f"approval #{approval_id} was granted for {approval.action!r}, "
            f"not {action!r} — a mint approval is bound to exactly one "
            "agent and surface")
    if approval.status != "approved":
        raise ExternalAgentsError(
            f"approval #{approval_id} is {approval.status}; minting needs "
            "an approved decision")
    if approval.requested_by != authority["actor"]:
        raise ExternalAgentsError(
            f"approval #{approval_id} was requested by a different actor; "
            "park and approve a new credential mint"
        )
    target = {"agent_id": agent_id, "surface": surface}
    parameters = {"operation": "mint_or_rotate"}
    card_matches = _approval_card_matches(
        approval.detail,
        action=action,
        target=target,
        parameters=parameters,
        input_versions={
            "request_sha256": approval_digest(
                {"target": target, "parameters": parameters}
            )
        },
        credential_versions=_agent_credential_versions(agent_id),
        authority={
            "actor": authority["actor"],
            "workspace": authority["workspace"],
            "role": authority["role"],
            "versions": authority["versions"],
        },
        budget=dict(authority["budget"]),
    )
    with _sidecar_locked():
        sidecar = _load_sidecar()
        meta = sidecar.setdefault(agent_id, {})
        # String-compare the ledger so a junk entry can never crash the
        # check (we only ever write ints; junk stays inert but preserved).
        used = list(meta.get("used_mint_approvals") or [])
        spent = (f"approval #{approval_id} has already minted a credential; "
                 "approvals are one-shot — run the mint without an approval "
                 "id to park a new one")
        if any(str(u) == str(approval_id) for u in used):
            raise ExternalAgentsError(spent)
        # A world approval never expires, so the bounded ledger alone would
        # let an id become reusable once it aged out. The floor is the
        # highest id ever EVICTED: everything at or below it is treated as
        # spent, so forgetting can only ever refuse, never re-authorize.
        floor = int(meta.get("mint_approval_floor") or 0)
        if approval_id <= floor:
            raise ExternalAgentsError(spent)
        if not card_matches:
            raise ExternalAgentsError(
                f"approval #{approval_id} no longer matches the current "
                "credential mint; park and approve a new request"
            )
        used.append(approval_id)
        keep = used[-_MAX_USED_MINT_APPROVALS:]
        for stale in used[:len(used) - len(keep)]:
            try:
                floor = max(floor, int(stale))
            except (TypeError, ValueError):  # junk entry; nothing to raise to
                continue
        meta["mint_approval_floor"] = floor
        meta["used_mint_approvals"] = keep
        _save_sidecar(sidecar)
    return approval_id


def _entry_from_agent(agent) -> dict:
    """A managed-registry entry dict reconstructed from a parsed TrustedAgent,
    so read-modify-write flows (token mint, revoke-with-note) can go through
    ``put_agent`` without reaching into the overlay file format."""
    return {
        "id": agent.id,
        "pubkey": agent.pubkey,
        "direction": agent.direction,
        "allow_tools": sorted(agent.allow_tools),
        "deny_tools": sorted(agent.deny_tools),
        "max_risk": agent.max_risk,
        "max_dollars": agent.max_dollars,
        "max_wall_seconds": agent.max_wall_seconds,
        "data_scopes": sorted(agent.data_scopes),
        "rest_token": agent.rest_token,
        "a2a_token": agent.a2a_token,
        "grpc_token": agent.grpc_token,
        "mcp_token": agent.mcp_token,
        "jwt_issuer": agent.jwt_issuer,
        "jwt_audience": agent.jwt_audience,
        "jwks_file": agent.jwks_file,
        "hmac_secret_ref": agent.hmac_secret_ref,
        "not_before": agent.not_before,
        "expires_at": agent.expires_at,
        "revoked": agent.revoked,
    }


# -- run ingest onto the Operating Record -------------------------------------

def record_run(agent_id: str, run: dict, *, shield: Any | None = None) -> dict:
    """Ingest one COMPLETED external run as a governed Operating Record row.

    ``run`` schema: ``{title, outcome: success|failure, summary?, steps?:
    [str], cost_dollars?, input_tokens?, output_tokens?, tool_calls?,
    department?}``. The goal lands owned by ``agent:<id>`` so every
    owner-scoped surface (spend, workforce, savings, audit binder,
    containment) sees the foreign agent as a first-class principal.

    Returns ``{goal_id, over_budget}``; raises :class:`ExternalAgentsError`
    on deny (not enrolled, revoked, plane disabled, poisoned text)."""
    if not enabled():
        raise ExternalAgentsError("external agents plane is disabled")
    from .agent_trust import decide_inbound, record_denied
    # enforced=True: the gateway is an external boundary in its own right, so
    # the registry binds here even when the global trust plane is disengaged.
    decision = decide_inbound(agent_id, enforced=True)
    if not decision.allowed:
        record_denied(agent_id, decision, direction="inbound",
                      correlation_id="record_run")
        raise ExternalAgentsError(f"denied: {decision.reason}")
    sidecar = _load_sidecar()
    if agent_id not in sidecar:
        raise ExternalAgentsError(
            f"agent {agent_id!r} has a trust entry but no enrollment; "
            "enroll it before ingesting runs")
    if sidecar[agent_id].get("contained"):
        raise ExternalAgentsError(
            "denied: agent is contained pending review (an administrator "
            "can release it from the console)")
    # Exactly-once ingest: a retried report with the same key returns the
    # original goal instead of double-counting spend (same posture as the
    # A2A message-id ledger). Keys are per-agent and bounded.
    idem = str(run.get("idempotency_key") or "").strip()[:128]
    if idem:
        prior_gid = (sidecar[agent_id].get("run_keys") or {}).get(idem)
        if prior_gid is not None:
            return {"goal_id": prior_gid, "over_budget":
                    bool(sidecar[agent_id].get("over_budget")),
                    "duplicate": True}
    title = _clean_text(run.get("title"), shield=shield)
    summary = _clean_text(run.get("summary"), shield=shield)
    if title is None or summary is None or not (title or "").strip():
        raise ExternalAgentsError(
            "run title/summary rejected by the ingest screen")
    outcome = "success" if str(run.get("outcome", "")).lower() in (
        "success", "done", "ok") else "failure"
    steps: list[str] = []
    for raw in list(run.get("steps") or [])[:_MAX_STEPS]:
        cleaned = _clean_text(raw, shield=shield)
        if cleaned is None:
            raise ExternalAgentsError(
                "a run step was rejected by the ingest screen")
        if cleaned:
            steps.append(cleaned)
    cost = max(0.0, float(run.get("cost_dollars") or 0.0))
    meta = sidecar[agent_id]
    principal = f"agent:{agent_id}"
    from .world_model import open_world
    w = open_world()
    gid = w.create_goal(
        title, description=summary or "",
        owner=principal,
        domain=str(run.get("department") or meta.get("department") or ""))
    for step in steps:
        w.append_event(gid, principal, "status", step)
    eid = w.start_episode(gid)
    w.end_episode(
        eid, summary or title,
        "success" if outcome == "success" else "failure",
        cost_dollars=cost,
        input_tokens=max(0, int(run.get("input_tokens") or 0)),
        output_tokens=max(0, int(run.get("output_tokens") or 0)),
        tool_calls=max(0, int(run.get("tool_calls") or 0)),
    )
    w.set_goal_status(
        gid, "done" if outcome == "success" else "blocked",
        result=summary or title)
    # Wall-clock ceiling: a reported duration above the enrollment's
    # max_wall_seconds is ingested (spend must never go uncounted) but
    # flagged and counted — repeat offenders are visible on the roster.
    duration = max(0.0, float(run.get("duration_seconds") or 0.0))
    wall_cap = decision.agent.max_wall_seconds if decision.agent else None
    over_wall = bool(wall_cap is not None and duration > wall_cap)
    over_budget = _settle_spend(
        agent_id, gid, cost=cost, idem=idem, over_wall=over_wall,
        cap=decision.agent.max_dollars if decision.agent else None)
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_RUN_INGESTED, agent="external_agents",
                goal_id=gid, external_agent=agent_id, outcome=outcome,
                cost_dollars=cost, steps=len(steps), over_budget=over_budget,
                over_wall=over_wall)
    return {"goal_id": gid, "over_budget": over_budget,
            "over_wall": over_wall}


def _settle_spend(agent_id: str, gid: int, *, cost: float, idem: str,
                  over_wall: bool, cap: float | None) -> bool:
    """Meter one run against the sidecar: spend, period rollover, run count,
    wall violations, idempotency ledger, and the over-budget flag. Shared by
    after-the-fact ingest and the live finish path."""
    with _sidecar_locked():
        sidecar = _load_sidecar()
        meta = sidecar.setdefault(agent_id, {})
        meta["spent_dollars"] = float(meta.get("spent_dollars") or 0.0) + cost
        if meta.get("period") == "monthly":
            month = _month_key()
            if meta.get("period_key") != month:
                meta["period_key"] = month
                meta["period_spent"] = 0.0
            meta["period_spent"] = float(meta.get("period_spent") or 0.0) + cost
        meta["runs"] = int(meta.get("runs") or 0) + 1
        meta["last_run_at"] = time.time()
        if over_wall:
            meta["wall_violations"] = int(meta.get("wall_violations") or 0) + 1
        if idem:
            keys = dict(meta.get("run_keys") or {})
            keys[idem] = gid
            if len(keys) > _MAX_RUN_KEYS:
                for stale in sorted(keys, key=keys.get)[:len(keys)
                                                        - _MAX_RUN_KEYS]:
                    keys.pop(stale, None)
            meta["run_keys"] = keys
        over_budget = bool(cap is not None and _period_spent(meta) > cap)
        meta["over_budget"] = over_budget
        _save_sidecar(sidecar)
    return over_budget


# -- live runs (start / heartbeat / finish) -----------------------------------

def start_run(agent_id: str, run: dict, *, shield: Any | None = None) -> dict:
    """Open a LIVE external run on the Operating Record.

    The goal lands ``active`` under ``agent:<id>`` so Oversight sees the work
    while it is happening, and the kill switch can bite mid-flight: the agent
    must heartbeat well within the orphan-reclaim window (default 60s, see
    ``MAVERICK_ORPHAN_RECLAIM_SECONDS``) or the run is reclaimed to blocked
    with a restart marker. Schema: ``{title, summary?, department?}``."""
    if not enabled():
        raise ExternalAgentsError("external agents plane is disabled")
    from .agent_trust import decide_inbound, record_denied
    decision = decide_inbound(agent_id, enforced=True)
    if not decision.allowed:
        record_denied(agent_id, decision, direction="inbound",
                      correlation_id="start_run")
        raise ExternalAgentsError(f"denied: {decision.reason}")
    sidecar = _load_sidecar()
    meta = sidecar.get(agent_id)
    if meta is None:
        raise ExternalAgentsError(
            f"agent {agent_id!r} has a trust entry but no enrollment")
    if meta.get("contained"):
        raise ExternalAgentsError("denied: agent is contained pending review")
    title = _clean_text(run.get("title"), shield=shield)
    summary = _clean_text(run.get("summary"), shield=shield)
    if title is None or summary is None or not (title or "").strip():
        raise ExternalAgentsError("run title rejected by the ingest screen")
    principal = f"agent:{agent_id}"
    from .world_model import open_world
    w = open_world()
    gid = w.create_goal(
        title, description=summary or "", owner=principal,
        domain=str(run.get("department") or meta.get("department") or ""))
    # Freshly created by us; the id is unknown to anyone else, so the
    # ownerless CAS is safe (and the Postgres backend's owner-aware claim
    # deliberately fails closed).
    w.claim_goal_for_run(gid)
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_RUN_STARTED, agent="external_agents",
                goal_id=gid, external_agent=agent_id)
    from .world_model import reclaim_window_seconds
    window = reclaim_window_seconds()
    # The reclaim window is a deadline, not a heartbeat cadence. Returning
    # that same duration would race a normal network delay against the
    # recurring sweep. Leave several beat opportunities inside the window.
    heartbeat_seconds = (
        1.0 if not math.isfinite(window) or window < 4.0
        else min(15.0, window / 4.0)
    )
    return {"goal_id": gid,
            "heartbeat_seconds": heartbeat_seconds}


def heartbeat(agent_id: str, goal_id: int) -> dict:
    """Keep a live run alive AND ask permission to continue.

    Returns ``{"continue": bool, "reason": str}``. ``continue: false`` is
    the kill switch reaching mid-flight work: containment, revocation,
    expiry, or the run having been reclaimed/finished all stop the agent.
    A truthful agent halts on false; an agent that ignores it stops
    refreshing its liveness anyway and gets reclaimed."""
    if not enabled():
        return {"continue": False, "reason": "external agents plane disabled"}
    from .agent_trust import decide_inbound
    decision = decide_inbound(agent_id, enforced=True)
    if not decision.allowed:
        return {"continue": False, "reason": decision.reason}
    meta = _load_sidecar().get(agent_id)
    if meta is None or meta.get("contained"):
        return {"continue": False,
                "reason": "agent is contained or unenrolled"}
    from .world_model import open_world
    alive = open_world().touch_goal(int(goal_id),
                                    expected_owner=f"agent:{agent_id}")
    if not alive:
        return {"continue": False,
                "reason": "run is not live under this agent (finished, "
                          "reclaimed, or not yours)"}
    return {"continue": True, "reason": "ok"}


def finish_run(agent_id: str, goal_id: int, run: dict,
               *, shield: Any | None = None) -> dict:
    """Close a live run: outcome, step trail, costed episode, spend meter.

    Same schema as ``record_run`` minus ``title``. The goal must be live and
    owned by the caller — cross-agent finishes are refused. A contained agent
    may still close its run so the reported cost reaches the spend meter, but
    its summary, steps and outcome are not accepted: the goal is closed as
    blocked with a fixed note."""
    if not enabled():
        raise ExternalAgentsError("external agents plane is disabled")
    from .agent_trust import decide_inbound, lookup, record_denied
    decision = decide_inbound(agent_id, enforced=True)
    if not decision.allowed:
        record_denied(agent_id, decision, direction="inbound",
                      correlation_id="finish_run")
        raise ExternalAgentsError(f"denied: {decision.reason}")
    meta = _load_sidecar().get(agent_id)
    if meta is None:
        raise ExternalAgentsError(
            f"agent {agent_id!r} has a trust entry but no enrollment")
    contained = bool(meta.get("contained"))
    principal = f"agent:{agent_id}"
    from .world_model import open_world
    w = open_world()
    goal = w.get_goal(int(goal_id))
    if goal is None or goal.owner != principal or goal.status not in (
            "active", "pending"):
        raise ExternalAgentsError(
            "run is not live under this agent (finished, reclaimed, or "
            "not yours)")
    if contained:
        summary, outcome, steps = _CONTAINED_CLOSE, "failure", []
    else:
        summary, outcome, steps = _finished_run_text(run, shield)
    for step in steps:
        w.append_event(goal_id, principal, "status", step)
    cost = max(0.0, float(run.get("cost_dollars") or 0.0))
    eid = w.start_episode(goal_id)
    w.end_episode(
        eid, summary or goal.title,
        "success" if outcome == "success" else "failure",
        cost_dollars=cost,
        input_tokens=max(0, int(run.get("input_tokens") or 0)),
        output_tokens=max(0, int(run.get("output_tokens") or 0)),
        tool_calls=max(0, int(run.get("tool_calls") or 0)),
    )
    w.set_goal_status(
        goal_id, "done" if outcome == "success" else "blocked",
        result=summary or goal.title)
    agent = lookup(agent_id)
    duration = max(0.0, float(run.get("duration_seconds") or 0.0))
    wall_cap = agent.max_wall_seconds if agent else None
    over_wall = bool(wall_cap is not None and duration > wall_cap)
    over_budget = _settle_spend(
        agent_id, int(goal_id), cost=cost,
        idem=str(run.get("idempotency_key") or "").strip()[:128],
        over_wall=over_wall, cap=agent.max_dollars if agent else None)
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_RUN_INGESTED, agent="external_agents",
                goal_id=int(goal_id), external_agent=agent_id,
                outcome=outcome, cost_dollars=cost, steps=len(steps),
                over_budget=over_budget, over_wall=over_wall, live=True)
    out = {"goal_id": int(goal_id), "over_budget": over_budget,
           "over_wall": over_wall}
    if contained:
        out["contained"] = True
    return out


_CONTAINED_CLOSE = ("Closed while the agent was contained; its reported outcome "
                    "was not accepted.")


def _finished_run_text(run: dict, shield: Any | None) -> tuple[str, str, list[str]]:
    """Screened summary, outcome and step trail of a finished run."""
    summary = _clean_text(run.get("summary"), shield=shield)
    if summary is None:
        raise ExternalAgentsError("run summary rejected by the ingest screen")
    outcome = "success" if str(run.get("outcome", "")).lower() in (
        "success", "done", "ok") else "failure"
    steps: list[str] = []
    for raw in list(run.get("steps") or [])[:_MAX_STEPS]:
        cleaned = _clean_text(raw, shield=shield)
        if cleaned is None:
            raise ExternalAgentsError(
                "a run step was rejected by the ingest screen")
        if cleaned:
            steps.append(cleaned)
    return summary, outcome, steps


# -- learning plane (fleet memory over the gateway) ---------------------------

def memory_ingest(agent_id: str, record: dict,
                  *, shield: Any | None = None) -> tuple[bool, str]:
    """Deposit one experience record into fleet memory over the gateway.

    The learning plane was MCP-only; platforms that speak plain HTTPS
    (Agentforce External Services, Bedrock action groups) could not reach
    it. The vendor is the enrollment's platform — provenance comes from OUR
    registry, never the caller's claim — and the caller identity is bound so
    the trust plane's "an agent acts only as itself" rule applies."""
    if not enabled():
        return False, "external agents plane is disabled"
    from . import fleet_memory
    meta = _load_sidecar().get(agent_id)
    if meta is None:
        return False, f"agent {agent_id!r} is not enrolled"
    if meta.get("contained"):
        return False, "agent is contained pending review"
    body = {
        "agent_id": agent_id,
        "vendor": str(meta.get("platform") or "custom"),
        "kind": record.get("kind"),
        "goal_text": record.get("goal_text"),
        "reflection": record.get("reflection"),
        "tools_used": record.get("tools_used"),
        "domain": record.get("domain") or meta.get("department") or None,
    }
    with fleet_memory.bind_caller(agent_id):
        return fleet_memory.ingest(body, shield=shield)


def memory_recall(agent_id: str, query: str, *, domain: str | None = None,
                  shield: Any | None = None) -> tuple[str, str]:
    """Governed memory read over the gateway — same identity binding and
    data-scope gates as the MCP path; every read is audited."""
    if not enabled():
        return "", "external agents plane is disabled"
    from . import fleet_memory
    meta = _load_sidecar().get(agent_id)
    if meta is None:
        return "", f"agent {agent_id!r} is not enrolled"
    if meta.get("contained"):
        return "", "agent is contained pending review"
    with fleet_memory.bind_caller(agent_id):
        return fleet_memory.recall(
            query, agent_id=agent_id,
            vendor=str(meta.get("platform") or "custom"),
            domain=domain or meta.get("department") or None, shield=shield)


def _memory_counts() -> dict[str, dict]:
    """Per-agent fleet-memory contribution counts, keyed by agent id.

    Best-effort join against ``fleet_memory.status()`` (source keys are
    ``vendor:agent_id``); an unavailable learning plane yields {}."""
    try:
        from . import fleet_memory
        if not fleet_memory.enabled():
            return {}
        counts = fleet_memory.status().get("ingested") or {}
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for source, kinds in counts.items():
        _, _, agent_id = str(source).partition(":")
        if agent_id:
            row = out.setdefault(agent_id, {})
            for kind, n in (kinds or {}).items():
                row[kind] = int(row.get(kind, 0)) + int(n)
    return out


# -- pre-action screening (the governance seam) -------------------------------

def screen(
    agent_id: str,
    tool: str,
    *,
    detail: str = "",
    risk: str | None = None,
    shield: Any | None = None,
) -> dict:
    """Decide one proposed external action BEFORE the agent takes it.

    Applies, in order: containment, trust admission (registry / direction /
    revocation / tool + risk ceilings — the requested risk is FLOORED by the
    operator's per-tool rating from the enrollment, so an agent cannot
    under-declare its way beneath a gate), the period budget cutoff, Shield
    input scanning over ``detail`` (scanner error = DENY — external
    boundary), and the ``[actions] require_approval_at`` floor — at/above
    the floor the action parks a real approval row.

    Repeated denials inside the containment window flip the agent to
    ``contained`` (every call refused until an admin releases it).

    Returns ``{allowed, rule, reason, requires_approval?, approval_id?}``.
    Every decision is audited."""
    if not enabled():
        return _screen_verdict(agent_id, tool, False, "disabled",
                               "external agents plane is disabled")
    from .safety.tool_risk import risk_rank
    deny, meta, _decision, req_risk = _screen_admission(
        agent_id, tool, risk=risk, detail=detail, shield=shield)
    if deny is not None:
        return deny
    floor = _approval_floor()
    if req_risk and risk_rank(req_risk) >= risk_rank(floor):
        from .approval_cards import (
            decode_approval_detail,
            encode_operation_approval_detail,
        )
        from .safety.dual_control import required_approvals
        from .world_model import open_world
        action = f"external:{agent_id}:{tool}"
        target = {"agent_id": agent_id, "tool": tool}
        parameters = {"detail": str(detail or ""), "risk": req_risk}
        approval_detail = encode_operation_approval_detail(
            action=action,
            summary=f"Review external agent action {tool}",
            target_label=f"External agent {agent_id}: {tool}",
            target=target,
            parameters=parameters,
            parameter_summary=[
                f"Resolved risk: {req_risk}",
                f"Request detail digest is bound to agent {agent_id}.",
            ],
            actor=f"agent:{agent_id}",
            role="external_agent_operator",
            credential_versions=_agent_credential_versions(agent_id),
            known_effects=[
                "Records a human decision for this exact screened action."
            ],
            unresolved_assumptions=[
                "This screening approval does not execute the external action."
            ],
            before="The screened external action remains blocked.",
            after="The approval decision is available to the requesting agent.",
            irreversible=False,
        )
        approval_card = decode_approval_detail(approval_detail)
        if approval_card is None:  # pragma: no cover - encoder contract
            raise ExternalAgentsError("screen approval binding was not encoded")
        approval_id = open_world().create_approval(
            action, risk=req_risk,
            scope=meta.get("department") or None,
            detail=approval_detail,
            provenance="external_agents",
            approvals_required=required_approvals(req_risk),
            requested_by=f"agent:{agent_id}")
        _notify_approval(approval_id, agent_id, tool, req_risk,
                         meta.get("department") or "")
        out = _screen_verdict(
            agent_id, tool, False, "approval_required",
            f"risk {req_risk} is at/above the {floor} approval floor; "
            "awaiting a human decision")
        out["requires_approval"] = True
        out["approval_id"] = approval_id
        out["approval_binding_sha256"] = approval_card["binding_sha256"]
        return out
    return _screen_verdict(agent_id, tool, True, "allow", "within ceilings")


def _screen_admission(
    agent_id: str,
    tool: str,
    *,
    risk: str | None,
    detail: str,
    shield: Any | None,
    correlation: str = "screen",
) -> tuple[dict | None, dict | None, Any, str]:
    """The admission chain shared by ``screen`` and the execute tier.

    Containment, risk validation + the operator's per-tool floor, trust
    admission (registry / direction / revocation / tool + risk ceilings),
    enrollment, the period budget cutoff, and Shield input scanning —
    everything except the approval floor, which each caller handles itself
    (a screen parks a bare approval; an execute parks a digest-bound pending
    execution). Returns ``(deny_verdict|None, meta, decision, req_risk)``;
    a non-None verdict has already been audited and, where it should,
    counted toward containment."""
    from .agent_trust import decide_inbound, record_denied
    from .safety.tool_risk import RISK_LEVELS, risk_rank
    meta = _load_sidecar().get(agent_id)
    if meta is not None and meta.get("contained"):
        return (_screen_verdict(
            agent_id, tool, False, "contained",
            "agent is contained pending review (repeated denials); an "
            "administrator can release it from the console"), meta, None, "")
    req_risk = str(risk or "").strip().lower()
    if req_risk and req_risk not in RISK_LEVELS:
        return (_deny_and_count(agent_id, tool, "bad_risk",
                                f"unknown risk level {req_risk!r}"),
                meta, None, "")
    # The operator's per-tool rating floors the caller's declaration:
    # external tool names are arbitrary, so the registry decides the risk.
    mapped = (meta or {}).get("tool_risks", {}).get(tool)
    if mapped and (not req_risk
                   or risk_rank(mapped) > risk_rank(req_risk)):
        req_risk = mapped
    # The capability gate rates the tool name too. An external tool unrated in
    # Lightwork takes the operator's enrollment rating; without one it keeps
    # the unrated high floor and is refused under a lower ceiling.
    from .safety.tool_risk import reviewed_ratings
    with reviewed_ratings({tool: mapped} if tool and mapped else {}):
        decision = decide_inbound(
            agent_id, requested_tools=[tool] if tool else (),
            max_risk=req_risk or None, enforced=True)
    if not decision.allowed:
        record_denied(agent_id, decision, direction="inbound",
                      correlation_id=correlation)
        return (_deny_and_count(agent_id, tool, decision.rule,
                                decision.reason), meta, decision, req_risk)
    if meta is None:
        return (_screen_verdict(agent_id, tool, False, "not_enrolled",
                                "agent has a trust entry but no enrollment"),
                None, decision, req_risk)
    cap = decision.agent.max_dollars if decision.agent else None
    if cap is not None and _period_spent(meta) > cap:
        period = ("this month's" if meta.get("period") == "monthly"
                  else "cumulative")
        return (_deny_and_count(
            agent_id, tool, "budget",
            f"{period} reported spend exceeds the ${cap:,.2f} ceiling"),
            meta, decision, req_risk)
    if detail and shield is not None:
        try:
            verdict = shield.scan_input(str(detail)[:_MAX_TEXT])
            if not verdict.allowed:
                return (_deny_and_count(
                    agent_id, tool, "shield",
                    "action detail was blocked by the input screen"),
                    meta, decision, req_risk)
        except Exception:
            # Fail CLOSED: an erroring scanner must never wave an external
            # action through unscreened. OUR failure, not the agent's — it
            # does not count toward containment.
            return (_screen_verdict(
                agent_id, tool, False, "screen_error",
                "input screen unavailable; action denied (fail-closed)"),
                meta, decision, req_risk)
    return None, meta, decision, req_risk


def _notify_approval(approval_id: int, agent_id: str, tool: str,
                     risk: str, department: str) -> None:
    """Tell a human an external agent is blocked waiting — fail-soft.

    Approvals were pull-only: the agent sat in a poll loop until someone
    happened to open the queue. Two channels, both best-effort on a
    governance hot path: the ops push transport, and the signed outbound
    webhook (``[external_agents] approval_webhook``, HMAC + SSRF guard via
    the shared webhook machinery). The payload is provenance-only — never
    the ``detail`` string, which is untrusted external text."""
    try:
        from .ops_alert import alert
        alert("external_approval.pending",
              f"{agent_id} is waiting on approval #{approval_id}: "
              f"{tool} ({risk})", severity="high")
    except Exception:  # pragma: no cover -- notification never blocks
        log.warning("external_agents: approval push notification failed",
                    exc_info=True)
    try:
        from .config import load_config
        url = str((load_config() or {}).get("external_agents", {}).get(
            "approval_webhook", "")).strip()
        if url:
            from .webhooks import fire
            fire("external_approval.created",
                 {"approval_id": approval_id, "agent_id": agent_id,
                  "tool": tool, "risk": risk, "department": department},
                 urls=[url])
    except Exception:  # pragma: no cover -- notification never blocks
        log.warning("external_agents: approval webhook failed",
                    exc_info=True)


def _approval_floor() -> str:
    from .safety.tool_risk import RISK_LEVELS
    try:
        from .config import config_source_errors, load_config
        v = str((load_config() or {}).get("actions", {}).get(
            "require_approval_at", "high")).strip().lower()
        if config_source_errors(include_tenant=True):
            # An unreadable policy cannot lower the floor: every risk parks.
            return RISK_LEVELS[0]
        return v if v in RISK_LEVELS else "high"
    except Exception:
        return "high"


def _screen_verdict(agent_id: str, tool: str, allowed: bool, rule: str,
                    reason: str) -> dict:
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_ACTION_SCREENED, agent="external_agents",
                external_agent=agent_id, tool=tool, allowed=allowed,
                rule=rule, reason=reason)
    return {"allowed": allowed, "rule": rule, "reason": reason}


def _deny_and_count(agent_id: str, tool: str, rule: str, reason: str) -> dict:
    """A denial that counts toward auto-containment.

    Misbehavior denials (ceiling breaches, budget, blocked payloads, junk
    risk words) accumulate in a sliding window; at the threshold the agent
    is contained — every subsequent call refused until an administrator
    releases it. Platform-side failures (scanner errors) and the ordinary
    approval-floor park never count."""
    contained_now = False
    with _sidecar_locked():
        sidecar = _load_sidecar()
        meta = sidecar.get(agent_id)
        if meta is not None:
            now = time.time()
            denials = [t for t in (meta.get("denials") or [])
                       if now - float(t) < _CONTAIN_WINDOW_SECONDS]
            denials.append(now)
            meta["denials"] = denials[-(_CONTAIN_DENIALS * 4):]
            if len(denials) >= _CONTAIN_DENIALS and not meta.get("contained"):
                meta["contained"] = True
                contained_now = True
            _save_sidecar(sidecar)
    if contained_now:
        from .audit import EventKind, audit_event
        audit_event(EventKind.EXTERNAL_AGENT_CONTAINED,
                    agent="external_agents", external_agent=agent_id,
                    denials=_CONTAIN_DENIALS,
                    window_hours=_CONTAIN_WINDOW_SECONDS // 3600,
                    last_rule=rule)
    return _screen_verdict(agent_id, tool, False, rule, reason)


def containment_state(agent_id: str) -> bool | None:
    """Return gateway containment, or ``None`` when the id is not enrolled.

    This is an authority read: corruption/outage raises a sanitized dependency
    error instead of being laundered into an unenrolled/healthy answer.
    """
    meta = _load_sidecar(strict=True).get(agent_id)
    return None if meta is None else bool(meta.get("contained"))


def contain(agent_id: str, *, contained_by: str = "") -> bool:
    """Admin action: contain an enrolled agent at the external gateway.

    Returns false only for an unenrolled id. A successful return is verified
    against the persisted post-state while the cross-process lock is held.
    """
    with _sidecar_locked():
        sidecar = _load_sidecar(strict=True)
        meta = sidecar.get(agent_id)
        if meta is None:
            return False
        meta["contained"] = True
        _save_sidecar(sidecar)
        after = _load_sidecar(strict=True).get(agent_id)
        landed = after is not None and bool(after.get("contained"))
    if not landed:
        return False
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_AGENT_CONTAINED, agent="external_agents",
                external_agent=agent_id, contained_by=contained_by,
                trigger="control_plane")
    return True


def release(agent_id: str, *, released_by: str = "") -> bool:
    """Admin action: lift gateway containment and clear the denial window.

    Returns false for an unenrolled id or when the persisted post-state still
    says contained. Dependency failures raise rather than masquerading as an
    unenrolled agent.
    """
    with _sidecar_locked():
        sidecar = _load_sidecar(strict=True)
        meta = sidecar.get(agent_id)
        if meta is None:
            return False
        meta["contained"] = False
        meta["denials"] = []
        _save_sidecar(sidecar)
        after = _load_sidecar(strict=True).get(agent_id)
        landed = after is not None and not bool(after.get("contained"))
    if not landed:
        return False
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_AGENT_RELEASED, agent="external_agents",
                external_agent=agent_id, released_by=released_by)
    return True


def reset_budget(agent_id: str, *, reset_by: str = "") -> bool:
    """Admin action: zero the active budget meter (period AND the flag).

    The lifetime total is preserved — the reset changes what counts against
    the cap, never what was historically reported."""
    with _sidecar_locked():
        sidecar = _load_sidecar()
        meta = sidecar.get(agent_id)
        if meta is None:
            return False
        meta["period_key"] = _month_key()
        meta["period_spent"] = 0.0
        if meta.get("period") != "monthly":
            # A lifetime-cap agent's meter IS spent_dollars; a reset converts
            # the remainder into an explicit baseline by moving to monthly
            # accounting from now on (documented in the console).
            meta["period"] = "monthly"
        meta["over_budget"] = False
        _save_sidecar(sidecar)
    from .audit import EventKind, audit_event
    audit_event(EventKind.EXTERNAL_BUDGET_RESET, agent="external_agents",
                external_agent=agent_id, reset_by=reset_by)
    return True


def approval_status(
    agent_id: str,
    approval_id: int,
    *,
    expected_binding_sha256: str = "",
) -> dict:
    """Poll endpoint for a parked ``screen`` approval: the external agent
    holds its action until the human decides in the dashboard queue."""
    from .approval_cards import (
        ApprovalCardError,
        decode_approval_detail,
        digest,
        require_current_approval_card,
    )
    from .world_model import open_world

    approval = open_world().get_approval(int(approval_id))
    requester = f"agent:{agent_id}"
    if (
        approval is None
        or approval.provenance != "external_agents"
        or approval.requested_by != requester
        or not str(approval.action).startswith(f"external:{agent_id}:")
    ):
        raise ExternalAgentsError(f"unknown approval {approval_id!r}")
    tool = str(approval.action).split(":", 2)[2]
    try:
        card = decode_approval_detail(approval.detail)
        if card is None:
            raise ApprovalCardError("legacy approval detail")
        card = require_current_approval_card(card)
        expected_authority = {
            "actor": requester,
            "workspace": _current_workspace(),
            "role": "external_agent_operator",
            "versions": {"request_schema": "lightwork.operation-approval.v1"},
        }
        if (
            card["action"] != approval.action
            or card["target"]["sha256"]
            != digest({"agent_id": agent_id, "tool": tool})
            or card["authority"] != expected_authority
            or card["credentials"] != _agent_credential_versions(agent_id)
            or card["budget"] != {"state": "governed_again_at_execution"}
        ):
            raise ApprovalCardError("approval authority changed")
    except (ApprovalCardError, KeyError, TypeError, ValueError) as exc:
        raise ApprovalBindingMismatch(
            "approval binding is stale; submit the screened action again"
        ) from exc
    binding = str(card["binding_sha256"])
    remembered = str(expected_binding_sha256 or "").strip().lower()
    if remembered and not text_equals(remembered, binding):
        raise ApprovalBindingMismatch(
            "approval binding changed; submit the screened action again"
        )
    return {
        "approval_id": approval.id,
        "status": approval.status,
        "risk": approval.risk,
        "action": approval.action,
        "approval_binding_sha256": binding,
        "target_sha256": card["target"]["sha256"],
        "parameters_sha256": card["parameters"]["sha256"],
        "inputs": card["inputs"],
        "credentials": card["credentials"],
        "expires_at": card["expires_at"],
    }


# -- governed execution (the enforcement tier above screening) ----------------

def execute_connectors() -> list[str]:
    """Governed-REST connectors external agents may execute through.

    ``[external_agents] connectors`` (env override
    ``MAVERICK_EXTERNAL_CONNECTORS``, comma-separated), intersected with the
    reference factories — an unknown name can never open an egress path.
    Empty means the enforcement tier is off and the gateway is screen-only."""
    import os

    from .governed_rest import GOVERNED_REST_FACTORIES
    raw = os.environ.get("MAVERICK_EXTERNAL_CONNECTORS")
    if raw is not None:
        names = [p.strip().lower() for p in raw.split(",") if p.strip()]
    else:
        try:
            from .config import get_external_agents
            names = get_external_agents()["connectors"]
        except Exception:
            return []
    return [n for n in names if n in GOVERNED_REST_FACTORIES]


def _request_digest(connector: str, op: str, path: str,
                    body: dict | None, *,
                    runtime_context_sha256: str = "") -> str:
    """Canonical fingerprint binding an approval to EXACTLY one request."""
    import hashlib
    material = {
        "connector": connector,
        "op": op,
        "path": path,
        "body": body or {},
    }
    # Preserve the legacy digest exactly while the runtime plane is off.  When
    # it is on, bind the parked approval to the gateway-derived asset/detail
    # context so a commit cannot swap to an easier policy authority.
    if runtime_context_sha256:
        material["runtime_context_sha256"] = runtime_context_sha256
    canon = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _prune_executions(meta: dict, now: float | None = None) -> dict:
    """Drop expired execution-ledger entries in place; returns the live map.

    An ``executing`` entry gets the claim grace on top of the TTL: a commit
    whose network call straddles the TTL boundary must still find its row
    for the terminal status write — pruning it mid-flight would erase the
    ledger's memory of a fired effect."""
    now = time.time() if now is None else now
    ex: dict[str, dict] = {}
    for k, v in dict(meta.get("executions") or {}).items():
        if not isinstance(v, dict):
            continue
        horizon = _EXECUTION_TTL_SECONDS
        if v.get("status") == "executing":
            horizon += _EXECUTING_GRACE_SECONDS
        if now - float(v.get("created_at") or 0) <= horizon:
            ex[k] = v
    meta["executions"] = ex
    return ex


def _screen_execute_request(agent_id: str, request: dict, *,
                            shield: Any | None) -> tuple[dict | None, dict]:
    """Parse and boundary-screen one execute request.

    Validation bounds every component FIRST (detail 4k, path 2k, body 32k
    canonical JSON), then the injection tripwire and Shield scan cover the
    WHOLE blob with no truncation — nothing can pad another field outside
    the scan window. The checker erroring denies (external boundary,
    fail-closed), and the request is never rewritten: a redacted path would
    execute against the wrong record, so we flag, never launder. Returns
    ``(deny_verdict|None, parsed)``."""
    from .governed_rest import WRITE_OPS
    connector = str(request.get("connector") or "").strip().lower()
    op = str(request.get("op") or "").strip().lower()
    path = str(request.get("path") or "").strip()
    body = request.get("body")
    detail = str(request.get("detail") or "")
    raw_idempotency_key = request.get("idempotency_key")
    idempotency_key = (
        raw_idempotency_key.strip()
        if isinstance(raw_idempotency_key, str)
        else ""
    )
    runtime_context_sha256 = request.get("_runtime_context_sha256")
    tool = (f"{connector}.{'read' if op == 'get' else 'write'}"
            if connector else "execute")
    parsed = {"connector": connector, "op": op, "path": path,
              "body": body if isinstance(body, dict) else None,
              "preview": bool(request.get("preview")), "detail": detail,
              "tool": tool, "idempotency_key": idempotency_key,
              "runtime_context_sha256": runtime_context_sha256 or ""}
    if runtime_context_sha256 is not None and (
        not isinstance(runtime_context_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", runtime_context_sha256)
    ):
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "bad_runtime_context",
            "runtime policy context binding is malformed",
        ), parsed
    if (
        (
            raw_idempotency_key is not None
            and raw_idempotency_key != ""
            and not isinstance(raw_idempotency_key, str)
        )
        or
        len(idempotency_key) > 128
        or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@/-"
            for char in idempotency_key
        )
    ):
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "bad_idempotency_key",
            "idempotency_key must be a bounded opaque identifier",
        ), parsed
    if connector not in execute_connectors():
        return _screen_verdict(
            agent_id, tool, False, "connector_not_enabled",
            f"connector {connector!r} is not enabled for external "
            "execution ([external_agents] connectors)"), parsed
    if op != "get" and op not in WRITE_OPS:
        return _deny_and_count(
            agent_id, tool, "bad_op",
            f"unknown op {op!r}; expected get or one of "
            f"{', '.join(WRITE_OPS)}"), parsed
    if not path or len(path) > 2000:
        return _screen_verdict(
            agent_id, tool, False, "bad_path",
            "path is required (and bounded at 2000 chars)"), parsed
    if body is not None and not isinstance(body, dict):
        return _screen_verdict(agent_id, tool, False, "bad_body",
                               "body must be a JSON object"), parsed
    if len(detail) > _MAX_TEXT:
        return _screen_verdict(
            agent_id, tool, False, "detail_too_long",
            f"detail exceeds {_MAX_TEXT} chars"), parsed
    body_json = ""
    if body:
        body_json = json.dumps(body, sort_keys=True,
                               separators=(",", ":"), default=str)
        if len(body_json.encode("utf-8")) > _MAX_EXECUTE_BODY_BYTES:
            return _screen_verdict(
                agent_id, tool, False, "body_too_large",
                f"request body exceeds {_MAX_EXECUTE_BODY_BYTES} bytes"), \
                parsed
    scan_blob = "\n".join(x for x in (detail, path, body_json) if x)
    try:
        from .memory_guard import injection_markers
        if injection_markers(scan_blob):
            return _deny_and_count(
                agent_id, tool, "injection",
                "request payload tripped the injection screen"), parsed
    except Exception:
        return _screen_verdict(
            agent_id, tool, False, "screen_error",
            "injection screen unavailable; action denied "
            "(fail-closed)"), parsed
    if shield is not None:
        try:
            verdict = shield.scan_input(scan_blob)
            if not verdict.allowed:
                return _deny_and_count(
                    agent_id, tool, "shield",
                    "request payload was blocked by the input screen"), \
                    parsed
        except Exception:
            return _screen_verdict(
                agent_id, tool, False, "screen_error",
                "input screen unavailable; action denied "
                "(fail-closed)"), parsed
    return None, parsed


def _execution_request_snapshot(parsed: dict, *, goal_id: int | None) -> dict:
    """Detach provider inputs from a caller-owned, potentially mutable dict."""

    snapshot = {
        "connector": parsed["connector"],
        "op": parsed["op"],
        "path": parsed["path"],
        "body": copy.deepcopy(parsed["body"]),
        "detail": parsed["detail"],
        "goal_id": goal_id,
    }
    if parsed["runtime_context_sha256"]:
        snapshot["_runtime_context_sha256"] = parsed["runtime_context_sha256"]
    return snapshot


def _goal_execution_verdict(
    agent_id: str,
    tool: str,
    goal_id: int | None,
) -> dict | None:
    """Require a still-live, same-owner Operating Record when one is bound."""

    if goal_id is None:
        return None
    try:
        from .world_model import open_world

        goal = open_world().get_goal(int(goal_id))
    except Exception:
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "goal_unavailable",
            "the bound Operating Record could not be revalidated; no effect occurred",
        )
    if (
        goal is None
        or goal.owner != f"agent:{agent_id}"
        or goal.status not in ("active", "pending")
    ):
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "bad_goal",
            "goal is not a live run owned by this agent",
        )
    return None


def _revalidate_execution_admission(
    agent_id: str,
    request: dict,
    *,
    connector: str,
    op: str,
    path: str,
    digest: str,
    goal_id: int | None,
    shield: Any | None,
    correlation: str,
) -> tuple[dict | None, str]:
    """Resolve all mutable admission inputs at the provider boundary."""

    deny, parsed = _screen_execute_request(agent_id, request, shield=shield)
    if deny is not None:
        return deny, ""
    live_body = parsed["body"] if isinstance(parsed["body"], dict) else None
    live_digest = _request_digest(
        parsed["connector"],
        parsed["op"],
        parsed["path"],
        live_body,
        runtime_context_sha256=parsed["runtime_context_sha256"],
    )
    if (
        parsed["preview"]
        or parsed["connector"] != connector
        or parsed["op"] != op
        or parsed["path"] != path
        or not secrets.compare_digest(live_digest, digest)
    ):
        return (
            _screen_verdict(
                agent_id,
                parsed["tool"],
                False,
                "request_changed",
                "the request changed before the provider boundary; no effect occurred",
            ),
            "",
        )
    risk = "low" if op == "get" else "high"
    deny, _meta, _decision, resolved_risk = _screen_admission(
        agent_id,
        parsed["tool"],
        risk=risk,
        detail="",
        shield=shield,
        correlation=correlation,
    )
    if deny is not None:
        return deny, resolved_risk
    goal_verdict = _goal_execution_verdict(agent_id, parsed["tool"], goal_id)
    return goal_verdict, resolved_risk


def _runtime_revalidation_verdict(
    agent_id: str,
    tool: str,
    *,
    runtime_context_sha256: str,
    runtime_revalidator: Callable[[], bool] | None,
) -> dict | None:
    """Require a server-owned current runtime decision when that plane binds."""

    if runtime_revalidator is None:
        if not runtime_context_sha256:
            return None
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "runtime_authority_unavailable",
            "runtime policy context cannot be trusted without server revalidation; "
            "no effect occurred",
        )
    try:
        current = runtime_revalidator()
    except Exception:
        log.warning(
            "external_agents: runtime authority revalidation failed",
            exc_info=True,
        )
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "runtime_authority_unavailable",
            "current runtime policy authority is unavailable; no effect occurred",
        )
    if current is not True:
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "runtime_authority_changed",
            "runtime policy, asset, or revision changed before the provider "
            "boundary; no effect occurred",
        )
    return None


def execute(
    agent_id: str,
    request: dict,
    *,
    shield: Any | None = None,
    runtime_revalidator: Callable[[], bool] | None = None,
    enforcement_observer: Callable[[str, str], None] | None = None,
) -> dict:
    """Perform one outbound action ON THE AGENT'S BEHALF through a governed
    connector — the enforcement tier above :func:`screen`.

    ``screen`` answers "may I?" and trusts the agent to act on its own
    platform; ``execute`` makes Lightwork the actor. The request runs through
    the same admission chain, then through the governed-REST connector path —
    host IP-pinning, enterprise egress allowlists, no redirects — with a
    tamper-evident PREPARE/COMMIT receipt around the effect. Reads are
    low-risk and run immediately; writes are high-risk and park a
    DIGEST-BOUND approval: the agent re-sends the byte-identical request to
    :func:`execute_commit` once a human approves, so what executes is exactly
    what was authorized — never a swapped payload.

    ``request``: ``{connector, op: get|post|put|patch|delete, path, body?,
    preview?, detail?, goal_id?, idempotency_key?}``. A stable idempotency key
    makes an ambiguous write-park retry return the original execution instead
    of creating a second approval. ``preview: true`` describes a write
    without performing it (no network, no approval — there is no side
    effect). ``goal_id`` binds the effect to one of the agent's live runs so
    the receipt and the step trail land on that Operating Record row.
    Returns a verdict dict; every decision is audited."""
    if not enabled():
        return _screen_verdict(agent_id, "execute", False, "disabled",
                               "external agents plane is disabled")
    deny, parsed = _screen_execute_request(agent_id, request, shield=shield)
    if deny is not None:
        return deny
    connector, op, path = parsed["connector"], parsed["op"], parsed["path"]
    body, preview = parsed["body"], parsed["preview"]
    detail, tool = parsed["detail"], parsed["tool"]
    idempotency_key = parsed["idempotency_key"]
    runtime_context_sha256 = parsed["runtime_context_sha256"]
    risk = "low" if (op == "get" or preview) else "high"
    # detail="" — the full blob (detail included) was scanned above; the
    # shared chain still applies containment, ceilings, and budget.
    deny, meta, _decision, req_risk = _screen_admission(
        agent_id, tool, risk=risk, detail="",
        shield=shield, correlation="execute")
    if deny is not None:
        return deny
    gid = request.get("goal_id")
    if gid is not None:
        try:
            gid = int(gid)
        except (TypeError, ValueError):
            return _screen_verdict(agent_id, tool, False, "bad_goal",
                                   "goal_id must be an integer")
        goal_verdict = _goal_execution_verdict(agent_id, tool, gid)
        if goal_verdict is not None:
            return goal_verdict
    try:
        execution_request = _execution_request_snapshot(parsed, goal_id=gid)
    except (TypeError, ValueError, RecursionError):
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "bad_body",
            "request body could not be frozen for exact execution",
        )
    body = execution_request["body"]
    digest = _request_digest(connector, op, path,
                             body if isinstance(body, dict) else None,
                             runtime_context_sha256=runtime_context_sha256)
    if preview:
        if op == "get":
            return _screen_verdict(agent_id, tool, False, "bad_op",
                                   "preview applies to writes only")
        from .governed_rest import GOVERNED_REST_FACTORIES

        conn = GOVERNED_REST_FACTORIES[connector]()
        out = _screen_verdict(
            agent_id, tool, True, "preview",
            "described without performing (no side effect)")
        out["preview"] = conn.preview_write(
            {"op": op, "path": path, "body": body or {}})
        out["request_sha256"] = digest
        return out
    from .safety.tool_risk import risk_rank
    floor = _approval_floor()
    if req_risk and risk_rank(req_risk) >= risk_rank(floor):
        from .governed_rest import GOVERNED_REST_FACTORIES

        conn = GOVERNED_REST_FACTORIES[connector]()
        return _park_execution(agent_id, conn, meta, tool=tool,
                               connector=connector, op=op, path=path,
                               body=body, detail=detail, digest=digest,
                               req_risk=req_risk, floor=floor, goal_id=gid,
                               idempotency_key=idempotency_key)

    def _final_authority() -> dict | None:
        boundary_verdict, current_risk = _revalidate_execution_admission(
            agent_id,
            execution_request,
            connector=connector,
            op=op,
            path=path,
            digest=digest,
            goal_id=gid,
            shield=shield,
            correlation="execute_provider_boundary",
        )
        if boundary_verdict is not None:
            return boundary_verdict
        runtime_verdict = _runtime_revalidation_verdict(
            agent_id,
            tool,
            runtime_context_sha256=runtime_context_sha256,
            runtime_revalidator=runtime_revalidator,
        )
        if runtime_verdict is not None:
            return runtime_verdict
        if current_risk and risk_rank(current_risk) >= risk_rank(
            _approval_floor()
        ):
            return _screen_verdict(
                agent_id,
                tool,
                False,
                "approval_policy_changed",
                "current policy now requires approval; submit the request again",
            )
        return None

    return _perform_execution(agent_id, connector, op, path,
                              body if isinstance(body, dict) else None,
                              goal_id=gid, digest=digest, tool=tool,
                              approved=False,
                              enforcement_observer=enforcement_observer,
                              final_authority=_final_authority)


def _park_execution(agent_id: str, conn, meta: dict, *, tool: str,
                    connector: str, op: str, path: str, body: dict | None,
                    detail: str, digest: str, req_risk: str, floor: str,
                    goal_id: int | None,
                    idempotency_key: str = "") -> dict:
    """Park one digest-bound execution behind a real approval row.

    The slot is reserved BEFORE the approval is created so a full backlog
    never strands an orphan approval in the queue; the approval id is bound
    to the slot right after.  A unique approval action is persisted with the
    slot first, allowing an exact retry/status poll to reconcile the approval
    if the process dies between those two durable writes. The approver sees
    the network-free preview and the request fingerprint — what they authorize
    is exactly what :func:`execute_commit` will verify before acting."""
    execution_id = secrets.token_urlsafe(12)
    approval_action = f"external-exec:{agent_id}:{tool}:{execution_id}"
    now = time.time()
    backlog = enrolled = False
    replay: tuple[str, dict] | None = None
    conflict = False
    with _sidecar_locked():
        sidecar = _load_sidecar()
        m = sidecar.get(agent_id)
        if m is not None:
            enrolled = True
            live = _prune_executions(m, now)
            if idempotency_key:
                for existing_id, existing in live.items():
                    if existing.get("idempotency_key") != idempotency_key:
                        continue
                    if secrets.compare_digest(
                        str(existing.get("digest")
                            or existing.get("idempotency_digest") or ""),
                        digest,
                    ):
                        replay = (existing_id, dict(existing))
                    else:
                        conflict = True
                    break
            if replay is not None or conflict:
                pass
            elif sum(1 for e in live.values()
                     if e.get("status") == "pending") >= _MAX_PENDING_EXECUTIONS:
                backlog = True
            else:
                live[execution_id] = {
                    "approval_id": None, "digest": digest,
                    "approval_action": approval_action,
                    "connector": connector, "op": op, "path": path,
                    "goal_id": goal_id, "created_at": now,
                    "status": "pending",
                    "idempotency_key": idempotency_key or None,
                    "idempotency_digest": digest if idempotency_key else None}
                _save_sidecar(sidecar)
    if not enrolled:
        return _screen_verdict(agent_id, tool, False, "not_enrolled",
                               "agent has a trust entry but no enrollment")
    if conflict:
        return _deny_and_count(
            agent_id,
            tool,
            "idempotency_conflict",
            "idempotency_key is already bound to a different request",
        )
    if replay is not None:
        existing_id, existing = replay
        if not existing.get("approval_id"):
            reconciled = _reconcile_execution_approval(agent_id, existing_id)
            if reconciled is not None:
                existing = reconciled
        status = str(existing.get("status") or "pending")
        rule = "approval_required" if status == "pending" else "already_finished"
        reason = (
            "an identical request already has a parked approval"
            if existing.get("approval_id")
            else "an identical request is still being parked; poll its execution"
        )
        if status != "pending":
            reason = f"execution already {status}; the write was not re-fired"
        out = _screen_verdict(agent_id, tool, False, rule, reason)
        out.update({
            "duplicate": True,
            "execution_id": existing_id,
            "status": status,
            "requires_approval": status == "pending",
            "approval_id": existing.get("approval_id"),
            "expires_at": float(existing.get("created_at") or now)
            + _EXECUTION_TTL_SECONDS,
        })
        return out
    if backlog:
        return _screen_verdict(
            agent_id, tool, False, "execution_backlog",
            f"{_MAX_PENDING_EXECUTIONS} executions already await decisions "
            "for this agent; wait for approvals or expiry")
    try:
        describe = (conn.preview_write({"op": op, "path": path,
                                        "body": body or {}})
                    if op != "get" else f"would GET {connector}{path}")
        from .approval_cards import encode_operation_approval_detail
        from .safety.dual_control import required_approvals
        from .world_model import open_world
        target = {
            "agent_id": agent_id,
            "connector": connector,
            "operation": op,
            "path": path,
        }
        parameters = {"request_sha256": digest, "goal_id": goal_id}
        approval_id = open_world().create_approval(
            approval_action, risk=req_risk,
            scope=meta.get("department") or None,
            detail=encode_operation_approval_detail(
                action=approval_action,
                summary=f"Execute {op.upper()} through {connector}",
                target_label=f"{connector} {op.upper()} {path}"[:500],
                target=target,
                parameters=parameters,
                parameter_summary=[
                    str(describe)[:500],
                    f"Request SHA-256: {digest}",
                ],
                actor=f"agent:{agent_id}",
                role=_EXECUTION_ROLE,
                authority_versions=dict(_EXECUTION_AUTHORITY_VERSIONS),
                input_versions={"request_sha256": digest},
                credential_versions=_agent_credential_versions(agent_id),
                budget=dict(_EXECUTION_BUDGET),
                known_effects=[
                    "Performs this exact connector request at most once after approval."
                ],
                unresolved_assumptions=[
                    "The target system may trigger its own downstream automation."
                ],
                before="No connector write has been performed for this execution.",
                after="The reviewed connector request may be committed once.",
                # Any provider write can become irreversible once the target
                # or downstream automation observes it.
                irreversible=op != "get",
                ttl_seconds=_EXECUTION_TTL_SECONDS,
            ),
            provenance="external_agents",
            approvals_required=required_approvals(req_risk),
            requested_by=f"agent:{agent_id}")
    except Exception:
        # Nothing was authorized and nothing will fire — hand the reserved
        # slot back instead of stranding a 24h pending entry that has no
        # approval row and can never be committed.
        log.warning("external_agents: park failed for %r; releasing the "
                    "slot", agent_id, exc_info=True)
        _set_execution_status(agent_id, execution_id, None, drop=True,
                              expect="pending")
        return _screen_verdict(
            agent_id, tool, False, "park_failed",
            "could not create the approval; nothing was recorded — "
            "submit the request again")
    with _sidecar_locked():
        sidecar = _load_sidecar()
        entry = ((sidecar.get(agent_id) or {}).get("executions")
                 or {}).get(execution_id)
        if entry is not None:
            entry["approval_id"] = approval_id
            _save_sidecar(sidecar)
    _notify_approval(approval_id, agent_id, tool, req_risk,
                     meta.get("department") or "")
    out = _screen_verdict(
        agent_id, tool, False, "approval_required",
        f"risk {req_risk} is at/above the {floor} approval floor; re-send "
        "the identical request to the commit endpoint once approved")
    out.update({"requires_approval": True, "approval_id": approval_id,
                "execution_id": execution_id,
                "expires_at": now + _EXECUTION_TTL_SECONDS})
    return out


def _reconcile_execution_approval(
    agent_id: str,
    execution_id: str,
) -> dict | None:
    """Repair the approval-to-sidecar crash boundary without creating rows.

    Approval creation is a committed WorldModel transaction while execution
    metadata is an atomic sidecar write, so they cannot share one transaction.
    The sidecar durably records a unique action first.  If the second write is
    interrupted, this routine finds the one exact approval and binds its id.
    It never guesses between duplicate matches and never creates an approval.
    """

    with _sidecar_locked():
        sidecar = _load_sidecar()
        entry = ((sidecar.get(agent_id) or {}).get("executions")
                 or {}).get(str(execution_id))
        if entry is None:
            return None
        if entry.get("approval_id"):
            return dict(entry)
        action = entry.get("approval_action")
        if not isinstance(action, str) or not action:
            return dict(entry)
        try:
            from .world_model import open_world
            matches = [
                approval
                for approval in open_world().list_approvals(
                    limit=_EXECUTION_APPROVAL_RECONCILE_LIMIT
                )
                if approval.action == action
                and approval.provenance == "external_agents"
                and approval.requested_by == f"agent:{agent_id}"
            ]
        except Exception:
            log.warning(
                "external_agents: approval reconciliation failed",
                exc_info=True,
            )
            return dict(entry)
        if len(matches) != 1:
            if len(matches) > 1:
                log.error(
                    "external_agents: ambiguous approval reconciliation for %r",
                    agent_id,
                )
            return dict(entry)
        entry["approval_id"] = int(matches[0].id)
        _save_sidecar(sidecar)
        return dict(entry)


def _retained_execution_status(entry: dict, now: float) -> str:
    status = str(entry.get("status") or "pending")
    created = float(entry.get("created_at") or 0)
    if status == "pending" and now - created > _EXECUTION_TTL_SECONDS:
        return "expired"
    if status == "executing" and now - float(
            entry.get("claimed_at") or created) > _EXECUTING_GRACE_SECONDS:
        return "indeterminate"
    return status


def execute_status(agent_id: str, execution_id: str) -> dict:
    """Poll one parked execution: ledger status joined with the live approval
    decision, so the agent knows when to re-send the request and commit."""
    meta = _load_sidecar().get(agent_id)
    entry = ((meta or {}).get("executions") or {}).get(str(execution_id))
    if entry is None:
        raise ExternalAgentsError(f"unknown execution {execution_id!r}")
    if not entry.get("approval_id") and entry.get("approval_action"):
        entry = _reconcile_execution_approval(agent_id, str(execution_id)) or entry
    created = float(entry.get("created_at") or 0)
    status = _retained_execution_status(entry, time.time())
    out = {"execution_id": str(execution_id), "status": status,
           "approval_id": entry.get("approval_id"),
           "connector": entry.get("connector"), "op": entry.get("op"),
           "expires_at": created + _EXECUTION_TTL_SECONDS}
    if status in {"indeterminate", "accepted"}:
        out["request_sha256"] = entry.get("digest")
        out["reason"] = (
            ("The service accepted the request, but completion has not been confirmed. "
             if status == "accepted" else "The change may already have happened. ")
            + "Check the connected service "
            "before submitting another request; this execution will not run again."
        )
    if status == "pending" and entry.get("approval_id"):
        try:
            from .world_model import open_world
            ap = open_world().get_approval(int(entry["approval_id"]))
            out["approval_status"] = ap.status if ap else "unknown"
        except Exception:
            out["approval_status"] = "unknown"
    return out


def _execution_approval_matches(
    approval: object,
    entry: dict,
    *,
    agent_id: str,
    connector: str,
    op: str,
    path: str,
    request_digest: str,
) -> bool:
    """Bind a queue decision to the live request and trust generation."""
    try:
        action = str(entry.get("approval_action") or "")
        target = {
            "agent_id": agent_id,
            "connector": connector,
            "operation": op,
            "path": path,
        }
        parameters = {
            "request_sha256": request_digest,
            "goal_id": entry.get("goal_id"),
        }
        return (
            getattr(approval, "action", None) == action
            and getattr(approval, "provenance", None) == "external_agents"
            and getattr(approval, "requested_by", None) == f"agent:{agent_id}"
            and _approval_card_matches(
                getattr(approval, "detail", None),
                action=action,
                target=target,
                parameters=parameters,
                input_versions={"request_sha256": request_digest},
                credential_versions=_agent_credential_versions(agent_id),
                authority=_current_execution_authority(agent_id),
                budget=dict(_EXECUTION_BUDGET),
            )
        )
    except ExternalAgentsError:
        return False


def _execution_approval_verdict(
    approval: object,
    entry: dict,
    *,
    approval_id: object,
    execution_id: str,
    agent_id: str,
    connector: str,
    op: str,
    path: str,
    tool: str,
    request_digest: str,
) -> dict | None:
    """Return a refusal for a non-current queue decision, else ``None``."""
    decision = getattr(approval, "status", None)
    if decision == "denied":
        _set_execution_status(agent_id, execution_id, "denied", expect="pending")
        return _screen_verdict(
            agent_id, tool, False, "approval_denied", "a human denied this action"
        )
    if decision != "approved":
        out = _screen_verdict(
            agent_id,
            tool,
            False,
            "approval_pending",
            "still awaiting a human decision",
        )
        out.update({
            "requires_approval": True,
            "approval_id": approval_id,
            "execution_id": execution_id,
        })
        return out
    if _execution_approval_matches(
        approval,
        entry,
        agent_id=agent_id,
        connector=connector,
        op=op,
        path=path,
        request_digest=request_digest,
    ):
        return None
    _set_execution_status(agent_id, execution_id, None, drop=True, expect="pending")
    return _screen_verdict(
        agent_id,
        tool,
        False,
        "approval_mismatch",
        "the approval no longer matches the current action, request, or "
        "credential state; submit it again for a new approval",
    )


def _commit_request_context(
    agent_id: str,
    tool: str,
    request: dict,
    entry: dict,
    *,
    shield: Any | None,
) -> tuple[dict | None, dict | None, int | None, bool, str]:
    """Screen and detach the exact request replay for a parked execution."""

    request_verdict, parsed = _screen_execute_request(
        agent_id, request, shield=shield
    )
    if request_verdict is not None:
        return request_verdict, None, None, False, ""
    request_goal_id = request.get("goal_id")
    if request_goal_id is not None:
        try:
            request_goal_id = int(request_goal_id)
        except (TypeError, ValueError):
            return (
                _screen_verdict(
                    agent_id,
                    tool,
                    False,
                    "bad_goal",
                    "goal_id must be an integer",
                ),
                None,
                None,
                False,
                "",
            )
    parked_goal_id = entry.get("goal_id")
    if parked_goal_id is not None:
        try:
            parked_goal_id = int(parked_goal_id)
        except (TypeError, ValueError):
            return (
                _screen_verdict(
                    agent_id,
                    tool,
                    False,
                    "approval_mismatch",
                    "the parked execution has an invalid Operating Record binding",
                ),
                None,
                None,
                False,
                "",
            )
    try:
        snapshot = _execution_request_snapshot(parsed, goal_id=parked_goal_id)
    except (TypeError, ValueError, RecursionError):
        return (
            _screen_verdict(
                agent_id,
                tool,
                False,
                "bad_body",
                "request body could not be frozen for exact execution",
            ),
            None,
            parked_goal_id,
            False,
            "",
        )
    body = snapshot["body"] if isinstance(snapshot["body"], dict) else None
    digest = _request_digest(
        parsed["connector"],
        parsed["op"],
        parsed["path"],
        body,
        runtime_context_sha256=parsed["runtime_context_sha256"],
    )
    return (
        None,
        snapshot,
        parked_goal_id,
        request_goal_id == parked_goal_id,
        digest,
    )


def _revalidate_claimed_execution(
    agent_id: str,
    execution_id: str,
    request: dict,
    *,
    approval_id: object,
    connector: str,
    op: str,
    path: str,
    digest: str,
    goal_id: int | None,
    tool: str,
    shield: Any | None,
    runtime_context_sha256: str,
    runtime_revalidator: Callable[[], bool] | None,
) -> dict | None:
    """Re-resolve a claimed approval and authority at the provider boundary."""

    boundary_verdict, _current_risk = _revalidate_execution_admission(
        agent_id,
        request,
        connector=connector,
        op=op,
        path=path,
        digest=digest,
        goal_id=goal_id,
        shield=shield,
        correlation="execute_commit_provider_boundary",
    )
    if boundary_verdict is not None:
        return boundary_verdict
    runtime_verdict = _runtime_revalidation_verdict(
        agent_id,
        tool,
        runtime_context_sha256=runtime_context_sha256,
        runtime_revalidator=runtime_revalidator,
    )
    if runtime_verdict is not None:
        return runtime_verdict
    try:
        with _sidecar_locked():
            current_entry = (
                ((_load_sidecar(strict=True).get(agent_id) or {}).get(
                    "executions"
                ) or {}).get(str(execution_id))
            )
            if current_entry is not None:
                current_entry = dict(current_entry)
    except ExternalAgentsDependencyError:
        current_entry = None
    if (
        current_entry is None
        or current_entry.get("status") != "executing"
        or current_entry.get("approval_id") != approval_id
        or current_entry.get("connector") != connector
        or current_entry.get("op") != op
        or current_entry.get("path") != path
        or current_entry.get("goal_id") != goal_id
        or not secrets.compare_digest(
            str(current_entry.get("digest") or ""), digest
        )
    ):
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "execution_authority_changed",
            "the claimed execution authority changed; no effect occurred",
        )
    try:
        from .world_model import open_world

        current_approval = open_world().get_approval(int(approval_id))
    except Exception:
        current_approval = None
    if (
        getattr(current_approval, "status", None) != "approved"
        or not _execution_approval_matches(
            current_approval,
            current_entry,
            agent_id=agent_id,
            connector=connector,
            op=op,
            path=path,
            request_digest=digest,
        )
    ):
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "approval_mismatch",
            "the approval is no longer current for this exact authority; "
            "no effect occurred",
        )
    return None


def execute_commit(
    agent_id: str,
    execution_id: str,
    request: dict,
    *,
    shield: Any | None = None,
    runtime_revalidator: Callable[[], bool] | None = None,
    enforcement_observer: Callable[[str, str], None] | None = None,
) -> dict:
    """Commit one approved execution — a digest-bound replay.

    The agent re-sends the IDENTICAL request; a sha256 mismatch voids the
    parked execution and counts as misbehavior (an attempt to swap the
    payload after approval). The admission chain runs again in full because
    the world may have changed while the approval sat in the queue —
    containment, revocation, ceilings, and budget all re-bind at commit
    time; the human's yes is necessary, not sufficient. At-most-once: the
    entry is claimed before the effect, so a racing or repeated commit
    reports the terminal status instead of re-firing."""
    if not enabled():
        return _screen_verdict(agent_id, "execute", False, "disabled",
                               "external agents plane is disabled")
    connector = str(request.get("connector") or "").strip().lower()
    op = str(request.get("op") or "").strip().lower()
    path = str(request.get("path") or "").strip()
    body = request.get("body")
    tool = (f"{connector}.{'read' if op == 'get' else 'write'}"
            if connector else "execute")
    entry = ((_load_sidecar().get(agent_id) or {}).get("executions")
             or {}).get(str(execution_id))
    if entry is None:
        return _screen_verdict(agent_id, tool, False, "unknown_execution",
                               f"unknown execution {str(execution_id)!r}")
    if not entry.get("approval_id") and entry.get("approval_action"):
        entry = _reconcile_execution_approval(agent_id, str(execution_id)) or entry
    now = time.time()
    # Terminal state FIRST, regardless of age: a replayed commit on an
    # already-fired execution must always hear the terminal status — an
    # aged executed entry told "expired; submit it again" is an instruction
    # to duplicate the effect through a second park + approval.
    if entry.get("status") != "pending":
        status = _retained_execution_status(entry, now)
        out = _screen_verdict(
            agent_id, tool, False, "already_finished",
            f"execution already {status}; a commit never re-fires"
            + (" — verify in the system of record"
               if status == "indeterminate" else ""))
        out["status"] = status
        return out
    # The operator's connector allowlist re-binds at commit time: emptying
    # [external_agents] connectors is the documented kill switch, and an
    # approval parked before the switch flipped must not outrun it.
    if connector not in execute_connectors():
        return _screen_verdict(
            agent_id, tool, False, "connector_not_enabled",
            f"connector {connector!r} is no longer enabled for external "
            "execution ([external_agents] connectors)")
    if now - float(entry.get("created_at") or 0) > _EXECUTION_TTL_SECONDS:
        if not _set_execution_status(agent_id, str(execution_id), None,
                                     drop=True, expect="pending"):
            # A concurrent commit claimed it between our snapshot and the
            # void — report the live state instead of acting on the stale one.
            return execute_commit(agent_id, execution_id, request,
                                  shield=shield,
                                  runtime_revalidator=runtime_revalidator,
                                  enforcement_observer=enforcement_observer)
        return _screen_verdict(
            agent_id, tool, False, "execution_expired",
            "the parked execution expired before any effect; submit it "
            "again")
    (
        request_verdict,
        execution_request,
        parked_goal_id,
        goal_matches,
        digest,
    ) = _commit_request_context(
        agent_id, tool, request, entry, shield=shield
    )
    if request_verdict is not None:
        return request_verdict
    if execution_request is None:  # pragma: no cover - helper contract
        return _screen_verdict(
            agent_id,
            tool,
            False,
            "authority_unavailable",
            "the exact request context is unavailable; no effect occurred",
        )
    body = execution_request["body"]
    approval_id = entry.get("approval_id")
    if not approval_id:
        # The park never completed (approval creation failed after the slot
        # was reserved). Nothing was authorized and nothing fired — void the
        # slot and have the agent start over.
        _set_execution_status(agent_id, str(execution_id), None,
                              drop=True, expect="pending")
        return _screen_verdict(
            agent_id, tool, False, "park_incomplete",
            "the park never completed (no approval exists); submit the "
            "request again")
    if (
        not secrets.compare_digest(digest, str(entry.get("digest") or ""))
        or not goal_matches
    ):
        # Void only while still pending: a stale snapshot must never delete
        # an entry a concurrent (correct) commit has claimed and is
        # executing. The mismatch is misbehavior either way — count it.
        _set_execution_status(agent_id, str(execution_id), None,
                              drop=True, expect="pending")
        return _deny_and_count(
            agent_id, tool, "digest_mismatch",
            "the committed request does not match what was approved; the "
            "parked execution has been voided")
    approval = None
    if approval_id:
        try:
            from .world_model import open_world
            approval = open_world().get_approval(int(approval_id))
        except Exception:
            approval = None
    approval_verdict = _execution_approval_verdict(
        approval,
        entry,
        approval_id=approval_id,
        execution_id=str(execution_id),
        agent_id=agent_id,
        connector=connector,
        op=op,
        path=path,
        tool=tool,
        request_digest=digest,
    )
    if approval_verdict is not None:
        return approval_verdict
    risk = "low" if op == "get" else "high"
    deny, _meta, _decision, _risk = _screen_admission(
        agent_id, tool, risk=risk, detail="", shield=shield,
        correlation="execute_commit")
    if deny is not None:
        return deny
    if not _claim_execution(agent_id, str(execution_id)):
        out = _screen_verdict(
            agent_id, tool, False, "already_finished",
            "a concurrent commit claimed this execution first")
        return out

    verdict = _perform_execution(
        agent_id, connector, op, path,
        body if isinstance(body, dict) else None,
        goal_id=parked_goal_id, digest=digest, tool=tool,
        approved=True,
        enforcement_observer=enforcement_observer,
        final_authority=lambda: _revalidate_claimed_execution(
            agent_id,
            str(execution_id),
            execution_request,
            approval_id=approval_id,
            connector=connector,
            op=op,
            path=path,
            digest=digest,
            goal_id=parked_goal_id,
            tool=tool,
            shield=shield,
            runtime_context_sha256=str(
                execution_request.get("_runtime_context_sha256") or ""
            ),
            runtime_revalidator=runtime_revalidator,
        ))
    if verdict.get("rule") == "receipt_unavailable":
        # Nothing fired — hand the slot back so the agent can retry the
        # commit once the receipt store recovers.
        _set_execution_status(agent_id, str(execution_id), "pending",
                              expect="executing")
    else:
        terminal_status = verdict.get("status")
        if terminal_status is None and verdict.get("allowed") is False:
            terminal_status = "denied"
        _set_execution_status(agent_id, str(execution_id),
                              terminal_status or "failed",
                              expect="executing")
        verdict.setdefault("status", terminal_status or "failed")
    verdict["execution_id"] = str(execution_id)
    return verdict


def _claim_execution(agent_id: str, execution_id: str) -> bool:
    """Flip pending -> executing atomically; the loser of a race gets False."""
    with _sidecar_locked():
        sidecar = _load_sidecar()
        entry = ((sidecar.get(agent_id) or {}).get("executions")
                 or {}).get(execution_id)
        if entry is None or entry.get("status") != "pending":
            return False
        entry["status"] = "executing"
        entry["claimed_at"] = time.time()
        _save_sidecar(sidecar)
    return True


def _set_execution_status(agent_id: str, execution_id: str,
                          status: str | None, *, drop: bool = False,
                          expect: str | None = None) -> bool:
    """Mutate (or drop) one ledger entry under the lock.

    ``expect`` guards against acting on a stale snapshot: the change applies
    only while the entry's CURRENT status still matches — a drop decided
    against a pending snapshot must never delete an entry a concurrent
    commit has since claimed. Returns whether the change was applied."""
    with _sidecar_locked():
        sidecar = _load_sidecar()
        meta = sidecar.get(agent_id)
        if meta is None:
            return False
        ex = dict(meta.get("executions") or {})
        entry = ex.get(execution_id)
        if entry is None:
            return False
        if expect is not None and entry.get("status") != expect:
            return False
        if drop:
            ex.pop(execution_id, None)
        else:
            entry = dict(entry)
            entry["status"] = status
            if status in ("executed", "failed", "denied", "indeterminate", "accepted"):
                entry["finished_at"] = time.time()
                # Keep an uncertain request's fingerprint for reconciliation.
                # Its terminal status, not digest deletion, prevents re-firing.
                if status not in {"indeterminate", "accepted"}:
                    entry.pop("digest", None)
            ex[execution_id] = entry
        meta["executions"] = ex
        _save_sidecar(sidecar)
    return True


class _ExecutionEnforcement:
    """Default-inert receipt observer around a physical external attempt."""

    def __init__(self, callback):
        self.callback = callback
        self.started = False

    def prepare(self, final_authority):
        if self.callback is None:
            return None
        try:
            self.callback("prepare", "prepared")
            self.started = True
            return final_authority()
        except Exception:
            return {"allowed": False, "rule": "receipt_unavailable", "status": "refused",
                "reason": "Safeguard activity could not be retained; no action occurred."}

    def observed(self, verdict, *, effect_started):
        if self.callback is not None and self.started:
            try:
                self.callback("outcome", str(verdict.get("status") or "refused"))
            except Exception:
                return {"allowed": effect_started, "rule": "indeterminate" if effect_started else "receipt_unavailable",
                    "status": "indeterminate" if effect_started else "refused",
                    "reason": "Safeguard activity could not confirm this result. Read the original; do not send the action again."}
        return verdict


def _abort_receipt(record_tool_lineage, goal_id, tool, receipt, principal,
                   digest, verdict) -> None:
    """Close an open PREPARE receipt with ABORT for a refused execution."""
    try:
        record_tool_lineage(
            goal_id,
            tool,
            receipt,
            actor=principal,
            transaction_id=digest[:16],
            phase="abort",
            result=str(verdict.get("rule") or "denied")[:200],
            force=True,
        )
    except Exception:  # pragma: no cover - no effect already assured
        log.warning("external_agents: ABORT receipt failed", exc_info=True)


def _perform_execution(agent_id: str, connector: str, op: str, path: str,
                       body: dict | None, *, goal_id: int | None,
                       digest: str, tool: str, approved: bool,
                       final_authority: Callable[[], dict | None],
                       enforcement_observer: Callable[[str, str], None] | None = None) -> dict:
    """The effect itself, receipted.

    PREPARE is fsynced tamper-evident BEFORE any network I/O (no receipt =
    no effect, same posture as the internal governed-write path); the call
    goes through the governed-REST connector — the SSRF-safe,
    enterprise-egress-guarded request path — and a COMMIT (or, on a
    transport error, INDETERMINATE) receipt closes the transaction. The
    receipt carries field NAMES and the request fingerprint, never body
    values; the response is secret-redacted and bounded before it returns
    to the caller."""
    from .governed_actions import record_tool_lineage
    principal = f"agent:{agent_id}"
    fields = sorted(body) if isinstance(body, dict) and body else []
    receipt = {"path": path, "fields": fields, "request_sha256": digest}
    try:
        prepared = record_tool_lineage(
            goal_id, tool, receipt, actor=principal,
            sources=(f"external:{agent_id}",), transaction_id=digest[:16],
            phase="prepare", force=True, strict=True)
    except Exception:
        prepared = False
    if not prepared:
        return _screen_verdict(
            agent_id, tool, False, "receipt_unavailable",
            "could not persist the PREPARE receipt; refusing to act "
            "(fail-closed)")
    effect_started = False
    enforcement = _ExecutionEnforcement(enforcement_observer)
    try:
        from .authority_effects import authority_effect_fence
        from .governed_rest import GOVERNED_REST_FACTORIES

        with authority_effect_fence():
            try:
                boundary_verdict = final_authority()
            except Exception:
                log.warning(
                    "external_agents: final execution authority check failed",
                    exc_info=True,
                )
                boundary_verdict = _screen_verdict(
                    agent_id,
                    tool,
                    False,
                    "authority_unavailable",
                    "current execution authority could not be revalidated; "
                    "no effect occurred",
                )
            if boundary_verdict is not None:
                _abort_receipt(record_tool_lineage, goal_id, tool, receipt, principal,
                               digest, boundary_verdict)
                return boundary_verdict
            try:
                conn = GOVERNED_REST_FACTORIES[connector]()
            except Exception:
                log.warning(
                    "external_agents: governed connector initialization failed",
                    exc_info=True,
                )
                verdict = _screen_verdict(
                    agent_id,
                    tool,
                    False,
                    "connector_unavailable",
                    "the governed connector could not be initialized; "
                    "no effect occurred",
                )
                record_tool_lineage(
                    goal_id,
                    tool,
                    receipt,
                    actor=principal,
                    transaction_id=digest[:16],
                    phase="abort",
                    result="connector_unavailable",
                    force=True,
                )
                return verdict
            boundary_verdict = enforcement.prepare(final_authority)
            if boundary_verdict is not None:
                _abort_receipt(record_tool_lineage, goal_id, tool, receipt, principal,
                               digest, boundary_verdict)
                return enforcement.observed(boundary_verdict, effect_started=False)
            effect_started = True
            if op == "get":
                raw = conn.read({"path": path})
            else:
                raw = conn.write({"op": op, "path": path, "body": body or {}})
    except Exception as e:
        if not effect_started:
            try:
                record_tool_lineage(
                    goal_id,
                    tool,
                    receipt,
                    actor=principal,
                    transaction_id=digest[:16],
                    phase="abort",
                    result="authority_unavailable",
                    force=True,
                )
            except Exception:  # pragma: no cover - no effect already assured
                log.warning("external_agents: ABORT receipt failed", exc_info=True)
            return _screen_verdict(
                agent_id,
                tool,
                False,
                "authority_unavailable",
                "the provider boundary could not acquire current authority; "
                "no effect occurred",
            )
        try:
            record_tool_lineage(
                goal_id, tool, receipt, actor=principal,
                transaction_id=digest[:16], phase="indeterminate",
                result=_safe_exception_text(
                    e, fallback="external provider request failed",
                ), force=True)
        except Exception:  # pragma: no cover -- receipt is best-effort here
            log.warning("external_agents: INDETERMINATE receipt failed",
                        exc_info=True)
        _audit_execution(agent_id, connector, op, "indeterminate", digest,
                         approved=approved, goal_id=goal_id)
        return enforcement.observed({"allowed": True, "rule": "indeterminate", "status": "indeterminate",
                "result": "The connection ended before the result was confirmed. "
                          "The change may already have happened. Check the connected "
                          "service before submitting another request."}, effect_started=effect_started)
    from .connector_attempts import ConnectorResult
    from .tool_results import ToolOutcome, ToolResultState, ToolResultText, classify_tool_result

    explicit_state = (classify_tool_result(raw)
                      if isinstance(raw, (ConnectorResult, ToolOutcome, ToolResultText)) else None)
    unknown = (explicit_state is ToolResultState.INDETERMINATE if explicit_state is not None else (
        isinstance(raw, ConnectorResult) and raw.attempt.outcome_unknown
    ) or str(raw).lstrip().startswith("INDETERMINATE:"))
    accepted = isinstance(raw, ConnectorResult) and raw.attempt.status_code == 202
    outcome = (
        "indeterminate" if unknown else
        "accepted" if accepted else
        "failed" if (explicit_state is not None and explicit_state is not ToolResultState.SUCCEEDED)
        or (explicit_state is None and str(raw).lstrip().startswith("ERROR")) else "executed"
    )
    try:
        record_tool_lineage(
            goal_id, tool, receipt, actor=principal,
            transaction_id=digest[:16],
            phase="indeterminate" if unknown else "commit", result=outcome,
            force=True)
    except Exception:  # pragma: no cover -- effect already happened
        log.warning("external_agents: COMMIT receipt failed", exc_info=True)
    try:
        from .safety.secret_detector import redact
        raw_text = raw.content if isinstance(raw, ToolOutcome) else str(raw)
        result = redact(raw_text)[0][:_MAX_TEXT]
    except Exception:
        # The redactor erroring must not leak the raw response outward.
        result = f"({outcome}; response withheld — redaction unavailable)"
    if unknown:
        result = (
            "The connected service did not confirm the result. The change may "
            "already have happened. Check that service before submitting another request."
        )
    if goal_id is not None:
        try:
            from .world_model import open_world
            open_world().append_event(
                int(goal_id), principal, "status",
                f"{op.upper()} {connector}{path} -> {outcome} "
                "(governed execution)")
        except Exception:  # pragma: no cover -- bookkeeping never blocks
            log.warning("external_agents: goal event append failed",
                        exc_info=True)
    try:
        with _sidecar_locked():
            sidecar = _load_sidecar()
            m = sidecar.get(agent_id)
            if m is not None:
                m["executions_total"] = int(
                    m.get("executions_total") or 0) + 1
                _save_sidecar(sidecar)
    except Exception:  # pragma: no cover -- bookkeeping never blocks
        log.warning("external_agents: execution meter failed", exc_info=True)
    _audit_execution(agent_id, connector, op, outcome, digest,
                     approved=approved, goal_id=goal_id)
    return enforcement.observed({"allowed": True, "rule": outcome if unknown or accepted else "executed", "status": outcome,
            "result": result}, effect_started=effect_started)


def _audit_execution(agent_id: str, connector: str, op: str, outcome: str,
                     digest: str, *, approved: bool,
                     goal_id: int | None) -> None:
    from .audit import EventKind, audit_event
    extra = {"goal_id": int(goal_id)} if goal_id is not None else {}
    audit_event(EventKind.EXTERNAL_ACTION_EXECUTED, agent="external_agents",
                external_agent=agent_id, connector=connector, op=op,
                outcome=outcome, request_sha256=digest, approved=approved,
                **extra)


# -- roster / detail (the dashboard's data) -----------------------------------

def roster(*, registry: dict[str, Any] | None = None,
           strict: bool = True) -> list[dict]:
    """Enrolled agents joined across the trust plane and the sidecar (never
    including token values — only which surfaces hold one).

    The roster is an operator authority, so its default is strict: an unreadable
    sidecar raises instead of returning a reassuring empty enrollment list.
    """
    from .agent_trust import load_registry
    registry = load_registry(strict=strict) if registry is None else registry
    out = []
    for agent_id, meta in sorted(_load_sidecar(strict=strict).items()):
        agent = registry.get(agent_id)
        active, rule = agent.is_active() if agent else (False, "missing_trust")
        out.append({
            "id": agent_id,
            "platform": meta.get("platform", "custom"),
            "platform_label": PLATFORMS.get(
                str(meta.get("platform")), "Custom / other runtime"),
            "description": meta.get("description", ""),
            "owner": meta.get("owner", ""),
            "department": meta.get("department", ""),
            "enrolled_at": meta.get("enrolled_at"),
            "active": active,
            "lifecycle": rule,
            "max_risk": agent.max_risk if agent else None,
            "max_dollars": agent.max_dollars if agent else None,
            "spent_dollars": round(float(meta.get("spent_dollars") or 0.0), 4),
            "period": meta.get("period", "total"),
            "period_spent": round(_period_spent(meta), 4),
            "over_budget": bool(meta.get("over_budget")),
            "contained": bool(meta.get("contained")),
            "wall_violations": int(meta.get("wall_violations") or 0),
            "tool_risks": dict(meta.get("tool_risks") or {}),
            "runs": int(meta.get("runs") or 0),
            "last_run_at": meta.get("last_run_at"),
            "last_seen": meta.get("last_seen"),
            "executions_total": int(meta.get("executions_total") or 0),
            "pending_executions": sum(
                1 for e in (meta.get("executions") or {}).values()
                if isinstance(e, dict) and e.get("status") == "pending"
                and time.time() - float(e.get("created_at") or 0)
                <= _EXECUTION_TTL_SECONDS),
            "credentials": [s for s in TOKEN_SURFACES
                            if agent and getattr(agent, f"{s}_token", "")],
        })
    return out


def _execution_history(agent_id: str) -> dict:
    """Bounded read-only metadata; no approval repair or private request data."""
    entries = (_load_sidecar(strict=True).get(agent_id) or {}).get("executions") or {}
    if not isinstance(entries, dict) or any(not isinstance(e, dict) for e in entries.values()):
        raise ExternalAgentsDependencyError("The agent's saved request history is unavailable.")
    try:
        ordered = sorted(entries.items(), key=lambda item: float(item[1].get("created_at") or 0), reverse=True)
        now, rows = time.time(), []
        for identity, entry in ordered[:20]:
            if entry.get("status", "pending") not in {
                "pending", "executing", "executed", "failed", "denied", "expired", "indeterminate", "accepted",
            }:
                raise ValueError("invalid request status")
            row = {"execution_id": identity, "status": _retained_execution_status(entry, now),
                   "connector": entry.get("connector"), "op": entry.get("op")}
            for key in ("connector", "op"):
                value = row[key]
                if value is not None and (not isinstance(value, str) or len(value) > 200):
                    raise ValueError("invalid request metadata")
            for key in ("created_at", "claimed_at", "finished_at"):
                stamp = entry.get(key)
                if stamp is not None:
                    stamp = float(stamp)
                    if not math.isfinite(stamp) or not 0 <= stamp <= 253402300799:
                        raise ValueError("invalid request time")
                    row[key] = stamp
            if row["status"] == "pending" and entry.get("approval_id"):
                try:
                    from .world_model import open_world
                    approval = open_world().get_approval(int(entry["approval_id"]))
                    row["approval_status"] = approval.status if approval else "unknown"
                except Exception:
                    row["approval_status"] = "unknown"
            rows.append(row)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ExternalAgentsDependencyError("The agent's saved request history cannot be checked.") from exc
    return {"executions": rows, "execution_coverage": {"retained_count": len(entries),
            "displayed_count": len(rows), "limit": 20, "retention_seconds": _EXECUTION_TTL_SECONDS}}


def agent_detail(agent_id: str) -> dict:
    """One agent's roster row + its Operating Record footprint."""
    rows = [r for r in roster() if r["id"] == agent_id]
    if not rows:
        raise ExternalAgentsError(f"agent {agent_id!r} is not enrolled")
    row = rows[0]
    row.update(_execution_history(agent_id))
    principal = f"agent:{agent_id}"
    try:
        from .world_model import open_world
        w = open_world()
        row["record"] = w.total_spend(owner=principal)
        row["episodes"] = [
            {"goal_id": e.goal_id, "started_at": e.started_at,
             "ended_at": e.ended_at, "outcome": e.outcome,
             "cost_dollars": e.cost_dollars}
            for e in w.list_episodes(limit=10, owner=principal)]
    except Exception as e:
        log.warning("external_agents: world lookup failed for %r: %s",
                    agent_id, e)
        row["record"] = {}
        row["episodes"] = []
    row["memory"] = _memory_counts().get(agent_id, {})
    return row


def status() -> dict:
    """Counts for the health surface and the dashboard header."""
    rows = roster()
    return {
        "enabled": enabled(),
        "enrolled": len(rows),
        "active": sum(1 for r in rows if r["active"]),
        "over_budget": sum(1 for r in rows if r["over_budget"]),
        "contained": sum(1 for r in rows if r["contained"]),
        "wall_violations": sum(r["wall_violations"] for r in rows),
        "platforms": sorted({r["platform"] for r in rows}),
        "runs": sum(r["runs"] for r in rows),
        "executions": sum(r["executions_total"] for r in rows),
        "pending_executions": sum(r["pending_executions"] for r in rows),
        "reported_dollars": round(
            sum(r["spent_dollars"] for r in rows), 4),
        "memory_contributions": sum(
            sum(kinds.values()) for kinds in _memory_counts().values()),
    }
