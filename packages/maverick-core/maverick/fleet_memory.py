"""Fleet memory: the agent-agnostic learning plane (Learning System of Record).

Lightwork's learning loops were built for Lightwork agents; this opens them to
ANY agent — Agentforce, Copilot, custom, open-source runtimes — so the
enterprise gets ONE governed memory across its whole fleet. Two operations:

* :func:`ingest` — an external agent deposits experience (a success, a
  failure, or an explicit lesson). Every record is schema-validated,
  size-capped, secret-redacted, Shield-scanned, provenance-tagged
  (``vendor:agent_id``), tenant-isolated, and audited. Successes/failures
  land in the fleet inbox as donation-shaped records (the dream cycle
  consolidates them alongside native experience); lessons land as
  provenance-tagged reflexions so recall surfaces them immediately.
* :func:`recall` — an external agent queries governed memory for a task.
  Reads are scoped (department boost; user-preference notes are NEVER
  exposed — they stay private to their channel/user) and every read is
  audited, so "which agent learned what, and who recalled it" is provable.

Off by default (``[fleet_memory] enable`` / ``MAVERICK_FLEET_MEMORY=1``):
exposing the memory plane to third-party agents is an explicit trust
decision. Fail-open internals, fail-closed surface (disabled = refuse;
unregistered agents = refuse).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from .config import env_flag
from .file_lock import (
    atomic_create_text,
    atomic_read_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    open_private_append,
)

log = logging.getLogger(__name__)

_MAX_TEXT = 2000
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KINDS = ("success", "failure", "lesson")

# The authenticated caller identity for the current fleet operation, bound by
# the network transport. ``None`` (the default) = unbound: stdio / in-process /
# local trust, where there is no remote principal to forge. ``""`` = an
# authenticated SHARED-token caller that carries no per-caller identity. A
# non-empty value is the per-caller :class:`~maverick.agent_trust.TrustedAgent`
# id proven by an ``[agent_trust] mcp_token``. ``recall``/``ingest`` read
# ``agent_id``/``vendor`` from the caller-supplied body, so WITHOUT this binding
# any token-holder could act AS any rostered agent and inherit its trust scope
# (cross-department read + audit forgery). :func:`_authorize_claim` ties the
# claimed fleet identity to the proven caller.
_caller: ContextVar[str | None] = ContextVar("fleet_caller", default=None)


def current_caller() -> str | None:
    """Return the transport-bound fleet identity, if any."""
    return _caller.get()


@contextmanager
def bind_caller(identity: str | None):
    """Bind the authenticated caller identity for fleet ops in this context.

    ``identity`` is the per-caller :class:`~maverick.agent_trust.TrustedAgent`
    id (proven by an mcp_token), ``""`` for a shared-token caller (no per-caller
    identity), or ``None`` to leave unbound (local/in-process trust). The
    transport scopes this per request so identities never leak across concurrent
    calls (a ContextVar is copied into ``asyncio.to_thread`` worker contexts).
    """
    token = _caller.set(identity)
    try:
        yield
    finally:
        _caller.reset(token)


@contextmanager
def bind_verified_caller(identity: str):
    """Bind an external caller without replacing a transport-bound identity."""
    existing = _caller.get()
    if existing is not None and existing != identity:
        raise PermissionError("fleet caller identity does not match the authenticated caller")
    with bind_caller(identity):
        yield


def _authorize_claim(agent_id: str) -> str | None:
    """Tie the claimed fleet ``agent_id`` to the authenticated caller.

    Returns a denial reason, or ``None`` to allow:

    * unbound caller (``None`` -- stdio / in-process) -> allow (local trust);
    * per-caller agent (non-empty id) -> may act ONLY as its own id;
    * shared-token caller (``""``) -> may not bear a specific fleet identity once
      the Agent Trust Plane is engaged (it can't prove ownership); the default
      disengaged deployment treats the shared bearer as the trusted admin path.
    """
    caller = _caller.get()
    if caller is None:
        return None  # unbound: local/in-process trust (no network principal)
    if caller:
        if caller != agent_id:
            return (f"caller {caller!r} may not act as fleet agent "
                    f"{agent_id!r} (a per-caller agent acts only as itself)")
        return None
    try:
        from . import agent_trust
        enforced, _ = agent_trust.load_trust_state()
    except Exception:
        return "agent trust state is unavailable"
    if enforced:
        return ("shared-token caller cannot act as a specific fleet agent while "
                "the agent trust plane is engaged; use a per-caller mcp_token")
    return None


def _registration_denial(agent_id: str, vendor: str) -> str | None:
    """Return why a claimed fleet identity is not uniquely registered.

    Agent Trust authenticates the stable ``agent_id`` while fleet provenance is
    ``vendor:agent_id``.  Allowing one id under two vendors would therefore let
    the same credential select either provenance label and its audit/data scope.
    Treat agent ids as globally unique and fail closed on ambiguous legacy
    rosters as well as on new registrations.
    """
    source = f"{vendor}:{agent_id}"
    sources = {
        str(row.get("source"))
        for row in roster()
        if row.get("agent_id") == agent_id
    }
    if source not in sources:
        return f"unregistered fleet agent {source!r}: register it first"
    if sources != {source}:
        return (
            f"ambiguous fleet agent id {agent_id!r}: an agent_id may belong to "
            "exactly one vendor"
        )
    return None


def _dir() -> Path:
    from .paths import current_tenant_id, data_dir

    # ``data_dir`` resolves the active tenant dynamically. When no tenant is
    # active, force the legacy shared path explicitly; never pin whichever
    # tenant happened to import this module first.
    tenant = current_tenant_id()
    return data_dir("fleet-memory", tenant=tenant or None)


def inbox_dir() -> Path:
    return _dir() / "inbox"


def registry_path() -> Path:
    return _dir() / "agents.ndjson"


def enabled() -> bool:
    _v = env_flag("MAVERICK_FLEET_MEMORY")
    if _v is not None:
        base = _v
    else:
        try:
            from .config import load_config
            base = bool((load_config().get("fleet_memory") or {}).get("enable", False))
        except Exception:  # pragma: no cover
            return False
    return base


def _sanitize(text: str, *, shield: Any | None) -> str | None:
    """Redact + Shield-scan one field; None = reject the record."""
    safe = str(text or "")[:_MAX_TEXT]
    try:
        from .safety.secret_detector import redact as _redact
        safe, _ = _redact(safe)
    except Exception:
        return None
    # Fleet records are EXTERNAL-trust, third-party input that later rides into
    # orchestrator prompts via dream/reflexion recall. Apply the same injection
    # tripwire memory_guard uses for EXTERNAL writes (it documents this list as
    # reusable by the fleet inbox), so a marker-bearing record is rejected even
    # when no Shield is wired (shield=None, the common path).
    try:
        from .memory_guard import injection_markers
        if injection_markers(safe):
            return None
    except Exception:
        return None
    if shield is not None:
        try:
            verdict = shield.scan_input(safe)
            if not getattr(verdict, "allowed", True):
                return None
        except Exception:  # pragma: no cover -- fail toward the gate
            return None
    return safe


#: Names ``audit.record`` takes as its own parameters. A payload key that
#: collides with one of these raises TypeError *inside* the audit call, and the
#: catch below then drops the row silently -- which is how every fleet ingest
#: went unaudited while reads were logged fine (``kind=`` was passed through for
#: the record's success/failure/lesson class and shadowed the event kind).
_RESERVED_AUDIT_KEYS = ("kind", "agent", "goal_id")


def _audit(event: str, **payload) -> None:
    """Record one fleet-plane event on the signed chain.

    Never blocks the plane, but never *silently* loses a row either: a governed
    memory plane whose audit trail quietly has holes in it is worse than one
    with no audit trail, because the holes are invisible to the operator relying
    on it.
    """
    for key in _RESERVED_AUDIT_KEYS:
        if key in payload:
            payload[f"fleet_{key}"] = payload.pop(key)
    try:
        from .audit import EventKind, record
        record(EventKind.LEARNING_UPDATE, agent="fleet_memory",
               fleet=event, **payload)
    except Exception:  # pragma: no cover -- audit never blocks the plane
        log.warning("fleet_memory: audit write failed for %r", event,
                    exc_info=True)


def register_agent(agent_id: str, vendor: str, *, description: str = "") -> bool:
    """Add an external agent to the fleet roster (idempotent).

    ``agent_id`` is globally unique because it is also the authenticated trust
    principal.  Registering that principal under a second vendor would create
    two selectable provenance identities for one credential.
    """
    if not (
        isinstance(agent_id, str)
        and isinstance(vendor, str)
        and _ID_RE.fullmatch(agent_id)
        and _ID_RE.fullmatch(vendor)
    ):
        return False
    path = registry_path()
    source = f"{vendor}:{agent_id}"
    try:
        ensure_private_directory(path.parent)
        with cross_process_lock(path, strict=True):
            rows = roster()
            registrations = {
                str(row.get("source"))
                for row in rows
                if row.get("agent_id") == agent_id
            }
            if registrations:
                if registrations == {source}:
                    return True
                _audit(
                    "register_blocked",
                    source=source,
                    reason="agent_id_already_registered_to_another_vendor",
                )
                return False
            fd = open_private_append(path, require_private_parent=True)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.time(), "source": source, "vendor": vendor,
                    "agent_id": agent_id, "description": str(description)[:200],
                }) + "\n")
                f.flush()
                os.fsync(f.fileno())
    except (OSError, RuntimeError) as e:
        log.warning("fleet_memory: register failed: %s", e)
        return False
    _audit("register", source=source)
    return True


def roster() -> list[dict]:
    path = registry_path()
    if not path.exists():
        return []
    out: list[dict] = []
    try:
        ensure_private_file(path)
        lines = atomic_read_text(path).splitlines()
    except OSError:
        return []
    for raw in lines:
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(d, dict):
            continue
        agent_id = d.get("agent_id")
        vendor = d.get("vendor")
        source = d.get("source")
        if not (
            isinstance(agent_id, str)
            and isinstance(vendor, str)
            and isinstance(source, str)
            and _ID_RE.fullmatch(agent_id)
            and _ID_RE.fullmatch(vendor)
            and source == f"{vendor}:{agent_id}"
        ):
            continue
        out.append(d)
    return out


def ingest(record: dict, *, shield: Any | None = None) -> tuple[bool, str]:
    """Deposit one external experience record. Returns ``(ok, reason)``.

    Schema: ``{agent_id, vendor, kind: success|failure|lesson, goal_text,
    reflection?, tools_used?, domain?}``. The source agent must be on the
    roster — an unregistered agent cannot write memory (fail-closed).
    """
    if not enabled():
        return False, "fleet memory is disabled ([fleet_memory] enable = true)"
    if not isinstance(record, dict):
        return False, "record must be an object"
    agent_id = str(record.get("agent_id", "") or "")
    vendor = str(record.get("vendor", "") or "")
    # Re-validate the identifiers up front: ingest later builds an inbox
    # filename from them (f"...-{vendor}-{agent_id}.json"), so a "/" or ".."
    # here would be path-injection. register_agent already enforces _ID_RE, so a
    # legitimately-registered agent always passes this; checking per-component
    # (rather than relying on the roster string-equality match below to reject a
    # malformed pair) makes the path-safety local and explicit.
    if not (_ID_RE.match(agent_id) and _ID_RE.match(vendor)):
        return False, "invalid agent_id or vendor (must match the registered id format)"
    source = f"{vendor}:{agent_id}"
    registration_denial = _registration_denial(agent_id, vendor)
    if registration_denial:
        return False, registration_denial
    denial = _authorize_claim(agent_id)
    if denial:
        _audit("ingest_blocked", source=source, reason=denial)
        return False, denial
    kind = str(record.get("kind", "") or "").lower()
    if kind not in KINDS:
        return False, f"kind must be one of {KINDS}"
    goal_text = _sanitize(record.get("goal_text", ""), shield=shield)
    reflection = _sanitize(record.get("reflection", ""), shield=shield)
    if goal_text is None or reflection is None:
        _audit("ingest_blocked", source=source)
        return False, "record blocked by Shield"
    if not goal_text.strip():
        return False, "goal_text is required"
    raw_tools = record.get("tools_used") or []
    if not isinstance(raw_tools, list):
        return False, "tools_used must be a list"
    tools: list[str] = []
    for raw_tool in raw_tools[:16]:
        safe_tool = _sanitize(raw_tool, shield=shield)
        if safe_tool is None:
            return False, "record blocked by safety screening"
        tools.append(safe_tool[:80])
    raw_domain = str(record.get("domain", "") or "")
    domain = _sanitize(raw_domain, shield=shield) if raw_domain else None
    if raw_domain and domain is None:
        return False, "record blocked by safety screening"

    # A per-agent credential always carries its registered data scopes, even
    # when optional installation-wide default-deny enforcement is disabled.
    # Shared-operator and local calls retain their existing trust contract.
    try:
        from . import agent_trust
        enforced, registry = agent_trust.load_trust_state()
        enforced = enforced or bool(_caller.get())
        if enforced:
            d = agent_trust.decide_memory_access(
                agent_id, domain, registry=registry, enforced=True)
            if d.denied:
                agent_trust.record_denied(agent_id, d, direction="inbound")
                _audit("ingest_blocked", source=source, reason=d.rule)
                return False, f"ingest refused by agent trust plane: {d.reason}"
    except Exception:
        _audit("ingest_blocked", source=source, reason="trust_state_unavailable")
        return False, "ingest refused: agent trust state is unavailable"

    if kind == "lesson":
        from . import reflexion
        ok = reflexion.record(
            goal_text=goal_text, failure_class="fleet_lesson",
            failure_msg=f"from {source}", reflection=reflection,
            tools_used=tools, domain=domain,
        )
        if not ok:
            _audit("ingest_blocked", source=source, reason="write_failed")
            return False, "write failed"
        _audit("ingest", source=source, kind=kind)
        return True, "ok"

    # success / failure -> donation-shaped record in the fleet inbox; the
    # dream cycle consolidates it alongside native experience
    # (dream_cycle(donations_dir=fleet_memory.inbox_dir())).
    row = {
        "schema_version": 1, "ts": time.time(),
        "task_brief_text": goal_text,
        "outcome": "success" if kind == "success" else "failure",
        "tools_used": tools, "verifier_critique": reflection or "",
        "source": source, "vendor": vendor, "domain": domain,
    }
    try:
        inbox = inbox_dir()
        ensure_private_directory(inbox)
        name = f"{int(time.time() * 1000)}-{uuid.uuid4().hex}-{vendor}-{agent_id}.json"
        # A fleet event is immutable evidence.  Refuse an already-published
        # name instead of replacing attacker-planted or collision state.
        atomic_create_text(inbox / name, json.dumps(row, sort_keys=True))
    except OSError as e:
        log.warning("fleet_memory: ingest write failed: %s", e)
        return False, "write failed"
    _audit("ingest", source=source, kind=kind)
    return True, "ok"


def recall(
    query: str, *, agent_id: str = "", vendor: str = "",
    domain: str | None = None, channel: str | None = None,
    user_id: str | None = None, shield: Any | None = None,
) -> tuple[str, str]:
    """Governed memory read for an external agent. Returns ``(context, reason)``.

    Surfaces department-boosted reflexion lessons and dream insights; never
    user-preference notes. Every read lands in the audit log with the
    reader's identity — "who recalled what" is provable.
    """
    if not enabled():
        return "", "fleet memory is disabled ([fleet_memory] enable = true)"
    if not (_ID_RE.match(agent_id or "") and _ID_RE.match(vendor or "")):
        return "", "invalid agent_id or vendor"
    source = f"{vendor}:{agent_id}"
    registration_denial = _registration_denial(agent_id, vendor)
    if registration_denial:
        return "", registration_denial
    denial = _authorize_claim(agent_id)
    if denial:
        _audit("recall_blocked", source=source, reason=denial)
        return "", denial
    # Per-agent credentials always enforce their data scopes and hard-filter
    # recall; global trust enforcement also applies this to other callers.
    enforced = False
    try:
        from . import agent_trust
        enforced, registry = agent_trust.load_trust_state()
        enforced = enforced or bool(_caller.get())
        if enforced:
            d = agent_trust.decide_memory_access(
                agent_id, domain, registry=registry, enforced=True)
            if d.denied:
                agent_trust.record_denied(agent_id, d, direction="inbound")
                return "", d.reason
    except Exception:
        _audit("recall_blocked", source=source, reason="trust_state_unavailable")
        return "", "recall refused: agent trust state is unavailable"
    safe_query = _sanitize(query, shield=shield)
    if safe_query is None or not safe_query.strip():
        return "", "query blocked or empty"

    def _in_scope(items: list) -> list:
        # When engaged, drop any hit whose domain != the (validated) requested
        # scope, so boost-only ranking can't surface another department's data.
        if not enforced:
            return items
        return [pair for pair in items
                if getattr(pair[1], "domain", None) == domain]

    blocks: list[str] = []
    n_reflexion = n_dream = 0
    try:
        from . import reflexion
        hits = _in_scope(reflexion.recall(
            safe_query, k=3, domain=domain,
            channel=channel, user_id=user_id,
        ))
        n_reflexion = len(hits)
        block = reflexion.format_context(hits, shield=shield)
        if block:
            blocks.append(block)
    except Exception:  # pragma: no cover
        pass
    try:
        from . import dreaming
        ins = _in_scope(dreaming.recall_insights(
            safe_query, domain=domain, k=3,
            channel=channel, user_id=user_id,
        ))
        n_dream = len(ins)
        block = dreaming.format_context(ins, shield=shield)
        if block:
            blocks.append(block)
    except Exception:  # pragma: no cover
        pass
    # Audit what was disclosed (counts per source), not just that a read happened.
    _audit("recall", source=source, domain=domain or "", hits=len(blocks),
           reflexion_hits=n_reflexion, dream_hits=n_dream)
    return "\n".join(blocks), "ok"


def status() -> dict:
    """Roster + per-source ingestion counts (the fleet console's data)."""
    counts: dict[str, dict[str, int]] = {}
    inbox = inbox_dir()
    if inbox.is_dir():
        for p in inbox.glob("*.json"):
            try:
                ensure_private_file(p)
                d = json.loads(atomic_read_text(p))
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            src = str(d.get("source", "") or "(unknown)")
            by = counts.setdefault(src, {"success": 0, "failure": 0})
            key = "success" if d.get("outcome") == "success" else "failure"
            by[key] += 1
    return {"agents": roster(), "ingested": counts}


__all__ = [
    "KINDS", "enabled", "register_agent", "roster", "ingest", "recall",
    "status", "inbox_dir", "registry_path", "bind_caller", "bind_verified_caller", "current_caller",
]
