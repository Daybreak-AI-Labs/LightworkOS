"""Agent Trust Plane — the single registry + decision point for talking to
*external* agents.

Lightwork has several cross-agent pathways, each with its own enable flag,
auth model and "who's allowed" list:

  * federation (``[federation] peers``)        — shared-secret tokens;
  * A2A tasks (``[a2a]``)                       — a single bearer token;
  * fleet memory (``agents.ndjson`` roster)     — a registration list.

The question a company asks — *"which outside agents may our agents talk to,
and what may they do or see?"* — needs one answer across all of them, and the
weakest identity model (a symmetric shared secret) must not be the only gate
on the most powerful path (goal delegation).

This module provides **one registry** (``[agent_trust] agents``) that
names every trusted external agent by its *pinned Ed25519 public key* (the same
asymmetric identity ``federation_envelope`` already uses), declares the
**direction** it may communicate, and bounds **what it may do** (a tool/risk
ceiling), **how much it may spend** (a budget ceiling), and **what company data
it may read** (data scopes). And **one decision point** —
:func:`decide_inbound` / :func:`decide_outbound` — that every transport
consults before a cross-agent interaction.

**Posture (default-deny at the boundary, open in-process).** The trust plane is
*engaged* exactly when :func:`agent_trust_enforced` is true — automatically
under enterprise mode (the "I handle sensitive data" switch, mirroring
:func:`maverick.capability.capability_enforced`), or explicitly via
``[agent_trust] enforce = true`` / ``MAVERICK_AGENT_TRUST=1``. When engaged, an
external agent absent from the registry is **denied** (zero-trust at the
company edge). When *not* engaged it is a strict no-op — every decision is
ALLOW with no ceiling — so kernel rule 1 (default-open, fail-open) and every
existing deployment behave byte-for-byte as before. In-process peer messaging
(``agent_bus``) is internal and never gated here.

Pure and offline (no I/O beyond reading config), so the decision logic is
exhaustively unit-testable; wiring it into each transport is a separate,
deliberate step.

Registry format (``~/.maverick/config.toml``)::

    [agent_trust]
    enforce = true                       # or rely on [enterprise] mode
    agents = [
      { id = "vega", pubkey = "<64-hex Ed25519>", direction = "both",
        allow_tools = ["read_file", "http_fetch"], max_risk = "medium",
        max_dollars = 2.0, max_wall_seconds = 600, data_scopes = ["support"] },
      { id = "copilot", pubkey = "<64-hex>", direction = "inbound",
        allow_tools = ["research"], max_risk = "low" },
    ]
"""
from __future__ import annotations

import logging
import math
import os
import re
import threading
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # import only for type-checkers/IDEs; never at runtime
    from .capability import Capability

log = logging.getLogger(__name__)

# An agent id becomes an audit field and a federation principal segment, so the
# charset matches federation_envelope's origin rules: no "/", no whitespace.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Raw Ed25519 public key, hex-encoded: exactly 32 bytes.
_PUBKEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RISK_LEVELS = ("low", "medium", "high")
_DIRECTIONS = frozenset({"inbound", "outbound", "both"})
_MAX_AGENTS = 256

# Serializes the managed-registry load-modify-save. _save_managed is already
# atomic (no torn read), but the mutators are lock-free RMW: a set_revoked
# racing a put_agent/rotate would otherwise be clobbered -- a revoked external
# agent silently stays trusted. In-process threading.Lock + cross-process flock.
_MANAGED_LOCK = threading.Lock()


def _managed_locked():
    from contextlib import ExitStack

    from .authority_effects import authority_effect_fence
    from .file_lock import cross_process_lock

    # Authority changes and external effects share one global-then-store lock
    # order.  An effect re-resolves the trust record while it owns this fence,
    # so a revoke, removal, rotation, or attenuation can either land first and
    # block the effect or wait until the already-authorized provider boundary
    # has completed.  Never acquire the managed lock before this fence: doing
    # so would invert the execution path's lock order.
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_MANAGED_LOCK)
        stack.enter_context(cross_process_lock(managed_path()))
        return stack.pop_all()


class AgentTrustError(ValueError):
    """A registry entry or request the trust plane refuses to deal with."""


class RevokedAgentRemovalRefused(AgentTrustError):
    """Removing this managed entry would lift a revocation (see
    :func:`remove_agent`). Callers report it as a conflict (HTTP 409) with
    ``str(exc)``, not as a server error."""


def valid_agent_id(agent_id: object) -> bool:
    return isinstance(agent_id, str) and bool(_ID_RE.fullmatch(agent_id))


def _risk(value: object) -> str | None:
    return value if isinstance(value, str) and value in _RISK_LEVELS else None


def _positive_float(value: object) -> float | None:
    """Coerce a config value to a finite positive float, or ``None``.

    ``float("nan")`` and infinity compare in surprising ways and must never
    become budget or credential-lifetime ceilings.  Treat them as malformed,
    alongside zero and negative values.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) and f > 0 else None


_INVALID = object()  # sentinel: a present-but-malformed security field


def _lifecycle_bound(entry: dict, key: str) -> object:
    """Parse a credential lifecycle bound (``not_before`` / ``expires_at``).

    Returns the positive epoch float, ``None`` when the field is ABSENT (no
    bound — legitimate), or the ``_INVALID`` sentinel when it is PRESENT but
    malformed. The caller drops the whole entry on ``_INVALID``: unlike a
    budget ceiling, a typo'd or zero/negative expiry must NOT silently coerce
    to "never expires" / "always valid" — that would make a misconfigured
    credential immortal (fail-open on a security field). Fail closed instead.
    """
    if key not in entry or entry.get(key) is None:
        return None
    parsed = _positive_float(entry.get(key))
    return parsed if parsed is not None else _INVALID


def _names(value: object) -> frozenset[str]:
    if isinstance(value, str):
        value = [value]
    if isinstance(value, (list, tuple, set)):
        return frozenset(str(v).strip() for v in value if str(v).strip())
    return frozenset()


def _security_names(entry: dict, key: str) -> object:
    """Strictly parse a security-bound list field.

    The permissive :func:`_names` helper is also used for untrusted runtime
    requests, where ignoring junk is appropriate.  Registry policy is the
    opposite: a present malformed ``allow_tools`` must not collapse to the
    empty-set "allow all" sentinel, and a malformed deny/scope list must not
    silently discard restrictions.  Missing fields remain legitimate empty
    sets for backwards compatibility.
    """
    if key not in entry:
        return frozenset()
    value = entry.get(key)
    if isinstance(value, str):
        values: object = [value]
    else:
        values = value
    if not isinstance(values, (list, tuple, set)):
        return _INVALID
    cleaned: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            return _INVALID
        cleaned.append(item.strip())
    return frozenset(cleaned)


def _optional_positive_bound(entry: dict, key: str) -> object:
    """Return a positive finite bound, absent ``None``, or ``_INVALID``."""
    if key not in entry:
        return None
    parsed = _positive_float(entry.get(key))
    return parsed if parsed is not None else _INVALID


@dataclass(frozen=True)
class TrustedAgent:
    """One ``[agent_trust] agents`` entry — a single external agent's identity,
    reach, and limits. Frozen so a parsed registry can't be mutated under a
    decision.

    - ``pubkey`` is the *pinned* Ed25519 public key (hex); it is the agent's
      canonical identity for asymmetric verification. ``""`` means no pinned
      key (identity must then come from a transport's own auth, e.g. the
      federation shared token — discouraged but allowed for migration).
    - ``direction`` bounds who may start the conversation: ``inbound`` (the
      agent may call us), ``outbound`` (we may call it), or ``both``.
    - ``allow_tools`` / ``deny_tools`` / ``max_risk`` form the tool ceiling the
      agent runs under, expressed as a :class:`~maverick.capability.Capability`.
    - ``max_dollars`` / ``max_wall_seconds`` bound a delegated run's spend.
    - ``data_scopes`` are the memory domains/departments the agent may read
      (consumed by fleet-memory recall); empty == no governed-memory access.
    """

    id: str
    pubkey: str = ""
    direction: str = "both"
    allow_tools: frozenset[str] = frozenset()
    deny_tools: frozenset[str] = frozenset()
    max_risk: str | None = None
    max_dollars: float | None = None
    max_wall_seconds: float | None = None
    data_scopes: frozenset[str] = frozenset()
    # Per-caller bearers for the single-shared-bearer surfaces (A2A / gRPC goal
    # API / MCP), which carry no per-caller identity in-protocol. A request
    # presenting one resolves to principal "agent:<id>" and is governed by THIS
    # entry. Distinct per surface so a token leaked on one surface can't
    # authenticate another. "" = this agent has no bearer for that surface.
    a2a_token: str = ""
    grpc_token: str = ""
    mcp_token: str = ""
    # The external-agents HTTP gateway (run ingest / action screening) is its
    # own surface with its own bearer, same isolation rationale as above.
    rest_token: str = ""
    # Platform-native identity (external gateway). ``jwt_issuer`` /
    # ``jwt_audience`` route and pin an OIDC-style JWT to THIS entry;
    # ``jwks_file`` is the issuer's signing key material read at VERIFY time,
    # never at parse time: a local path (PEM public key or JSON JWKS), or an
    # ``https://`` JWKS endpoint for identity federation with Entra ID / Okta
    # / any OIDC IdP (fetched with a bounded timeout, keys cached).
    # ``hmac_secret_ref`` NAMES a secret resolved through
    # ``maverick.secret_provider.get_secret`` at verify time — the registry
    # stores the reference, never the secret (it must stay recoverable, unlike
    # a hashed bearer). "" = that scheme is not configured for this agent.
    # Ed25519 identity stays on ``pubkey``; JWT key material never overloads it.
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwks_file: str = ""
    hmac_secret_ref: str = ""
    # Key lifecycle (all default to "always valid" so existing configs are
    # byte-for-byte unchanged): a revoked or out-of-window entry is denied by
    # decide_inbound/decide_outbound/verify_identity. `not_before`/`expires_at`
    # are epoch seconds; supporting an overlap window (old key valid until
    # expires_at, new key not_before) is the zero-downtime rotation primitive.
    not_before: float | None = None
    expires_at: float | None = None
    revoked: bool = False

    def permits_inbound(self) -> bool:
        return self.direction in ("inbound", "both")

    def permits_outbound(self) -> bool:
        return self.direction in ("outbound", "both")

    def is_active(self, now: float | None = None) -> tuple[bool, str]:
        """``(active, rule)``. An expired/revoked/not-yet-valid entry is dead.

        ``rule`` is one of ``active`` / ``revoked`` / ``not_yet_valid`` /
        ``expired`` so a denial names *why* the credential is no longer good.
        """
        if self.revoked:
            return False, "revoked"
        t = time.time() if now is None else now
        if self.not_before is not None and t < self.not_before:
            return False, "not_yet_valid"
        if self.expires_at is not None and t >= self.expires_at:
            return False, "expired"
        return True, "active"

    def permits_scope(self, scope: str | None) -> bool:
        """True iff the agent may read memory tagged ``scope``.

        Empty ``data_scopes`` means *no* governed-memory access (fail-closed:
        an operator opts an external agent into a domain explicitly). A ``None``
        / unscoped query is always allowed — it carries no department to gate.
        """
        if not scope:
            return True
        return scope in self.data_scopes

    def capability(self, principal: str | None = None) -> Capability:
        """The tool ceiling this agent runs under, as a ``Capability``.

        Built lazily so the kernel imports without pulling in the capability
        module until a decision actually needs it. The entry's ``expires_at``
        propagates onto the grant so the handed-out capability expires with the
        registry entry (a grant must never outlive the trust that minted it).
        """
        from .capability import COORDINATION_TOOLS, Capability
        # The general Capability type keeps a coordination floor so trusted
        # in-process specialists can always participate in their workforce.
        # An external trust-registry allowlist is a different boundary: a
        # caller granted only ``read_file`` must not implicitly gain fan-out,
        # delegation, peer messaging, or user-interaction authority.  Convert
        # every omitted coordination tool into an explicit deny; operators can
        # opt in by naming the tool in ``allow_tools`` (or leave the allowlist
        # empty to retain the documented allow-all behavior).
        deny_tools = self.deny_tools
        if self.allow_tools:
            deny_tools = deny_tools | (COORDINATION_TOOLS - self.allow_tools)
        return Capability(
            principal=principal or f"agent:{self.id}",
            allow_tools=self.allow_tools,
            deny_tools=deny_tools,
            max_risk=self.max_risk,
            expires_at=self.expires_at,
        )


@dataclass(frozen=True)
class TrustDecision:
    """The outcome of a trust-plane check.

    ``rule`` names the clause that fired (``disabled`` / ``not_in_registry`` /
    ``direction`` / ``capability`` / ``revoked`` / ``not_yet_valid`` /
    ``expired`` / ``data_scope`` / ``allow``) so the choice lands in the audit
    record with a reason, not just an allow/deny bit. ``capability`` is the tool
    ceiling the caller should narrow the run against — ``None`` when the plane
    is disengaged (no-op) so callers stay byte-for-byte identical to today.
    """

    allowed: bool
    reason: str
    rule: str
    agent: TrustedAgent | None = None
    capability: Capability | None = None

    @property
    def denied(self) -> bool:
        return not self.allowed


# -- config ----------------------------------------------------------------

def agent_trust_enforced(cfg: dict | None = None) -> bool:
    """Is the trust plane engaged (default-deny for external agents)?

    On when ``MAVERICK_AGENT_TRUST`` is truthy, ``[agent_trust] enforce =
    true``, or enterprise mode is active (sensitive-data deployments get the
    zero-trust boundary automatically). Off by default — disengaged means every
    decision is a no-op ALLOW, preserving kernel rule 1. Mirrors
    :func:`maverick.capability.capability_enforced`.

    Pass ``cfg`` (a pre-loaded config) to read engagement from the *same*
    config snapshot the registry is read from — :func:`load_trust_state` does
    this so one operation observes one consistent config view (no TOCTOU
    between the enforced flag and the registry).
    """
    env = os.environ.get("MAVERICK_AGENT_TRUST")
    if env is not None and env.strip() != "":
        normalized = env.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise AgentTrustError(
            "MAVERICK_AGENT_TRUST must be a recognized boolean"
        )
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            return True
    except Exception as exc:
        raise AgentTrustError("enterprise trust policy is unavailable") from exc
    if cfg is None:
        from .config import config_source_errors, load_config

        cfg = load_config() or {}
        if config_source_errors():
            raise AgentTrustError("agent trust config source is unreadable")
    if not isinstance(cfg, dict):
        raise AgentTrustError("agent trust config root must be a table")
    trust_cfg = cfg.get("agent_trust")
    if trust_cfg is None:
        return False
    if not isinstance(trust_cfg, dict):
        raise AgentTrustError("agent_trust config section must be a table")
    if "enforce" not in trust_cfg:
        return False
    enforce = trust_cfg.get("enforce")
    if not isinstance(enforce, bool):
        raise AgentTrustError("agent_trust.enforce must be a boolean")
    return enforce


def load_trust_state() -> tuple[bool, dict[str, TrustedAgent]]:
    """Load ``(enforced, registry)`` from a SINGLE config read.

    Every cross-agent operation should take one snapshot of the trust state and
    thread it through :func:`decide_inbound` / :func:`decide_outbound` /
    :func:`clamp_budget` (which all accept ``registry=`` / ``enforced=``), so a
    config edit mid-request can't make one check see "engaged, old registry"
    and the next see "disengaged, new registry". Env/enterprise still win for
    the enforced flag (they're not part of the config table).
    """
    # Do not turn an I/O/import/config-loader failure into a disengaged trust
    # plane.  Cross-agent transports catch this seam and deny the request; an
    # empty fallback here would instead report ``enforced=False`` and fail
    # open at exactly the boundary this function protects.
    from .config import config_source_errors, load_config
    cfg = load_config()
    source_errors = config_source_errors()
    if source_errors:
        paths = ", ".join(sorted(source_errors))
        raise AgentTrustError(f"agent trust config source is unreadable: {paths}")
    if cfg is None:
        cfg = {}
    if not isinstance(cfg, dict):
        raise AgentTrustError("agent trust config root must be a table")
    trust_cfg = cfg.get("agent_trust")
    if trust_cfg is not None and not isinstance(trust_cfg, dict):
        raise AgentTrustError("agent_trust config section must be a table")
    return agent_trust_enforced(cfg), load_registry(cfg, strict=True)


def _agent_from_entry(entry: dict) -> TrustedAgent | None:
    """Parse one registry entry, or ``None`` if it's malformed (fail-closed: a
    bad entry simply never matches, it does not broaden trust)."""
    raw_id = entry.get("id") or entry.get("origin") or ""
    if not isinstance(raw_id, str):
        log.warning("[agent_trust] skipping entry with non-string id")
        return None
    if entry.get("id") and entry.get("origin") and entry.get("id") != entry.get("origin"):
        log.warning("[agent_trust] skipping entry with conflicting id/origin")
        return None
    agent_id = raw_id.strip()
    if not valid_agent_id(agent_id):
        log.warning("[agent_trust] skipping entry with bad id %r", agent_id)
        return None
    if "pubkey" in entry:
        raw_pubkey = entry.get("pubkey")
        if not isinstance(raw_pubkey, str):
            log.warning("[agent_trust] agent %r: malformed pubkey; dropping entry",
                        agent_id)
            return None
        pubkey = raw_pubkey.strip().lower()
        if not _PUBKEY_RE.fullmatch(pubkey):
            log.warning("[agent_trust] agent %r: malformed pubkey; dropping entry",
                        agent_id)
            return None
    else:
        pubkey = ""

    if "direction" in entry:
        raw_direction = entry.get("direction")
        if not isinstance(raw_direction, str):
            log.warning("[agent_trust] agent %r: malformed direction; dropping entry",
                        agent_id)
            return None
        direction = raw_direction.strip().lower()
        if direction not in _DIRECTIONS:
            log.warning("[agent_trust] agent %r: bad direction %r; dropping entry",
                        agent_id, direction)
            return None
    else:
        direction = "both"

    if "max_risk" in entry:
        raw_risk = entry.get("max_risk")
        max_risk = _risk(raw_risk.strip().lower()) if isinstance(raw_risk, str) else None
        if max_risk is None:
            log.warning("[agent_trust] agent %r: malformed max_risk; dropping entry",
                        agent_id)
            return None
    else:
        max_risk = None

    max_dollars = _optional_positive_bound(entry, "max_dollars")
    max_wall_seconds = _optional_positive_bound(entry, "max_wall_seconds")
    allow_tools = _security_names(entry, "allow_tools")
    deny_tools = _security_names(entry, "deny_tools")
    data_scopes = _security_names(entry, "data_scopes")
    if any(value is _INVALID for value in (
        max_dollars, max_wall_seconds, allow_tools, deny_tools, data_scopes,
    )):
        log.warning("[agent_trust] agent %r: malformed security limit; "
                    "dropping entry", agent_id)
        return None
    not_before = _lifecycle_bound(entry, "not_before")
    expires_at = _lifecycle_bound(entry, "expires_at")
    if not_before is _INVALID or expires_at is _INVALID:
        # Fail closed: a present-but-malformed lifecycle bound drops the entry
        # (the agent is simply untrusted) rather than minting an immortal cred.
        log.warning("[agent_trust] agent %r: malformed not_before/expires_at; "
                    "dropping entry (fail-closed)", agent_id)
        return None
    tokens: dict[str, str] = {}
    for field in ("a2a_token", "grpc_token", "mcp_token", "rest_token",
                  "jwt_issuer", "jwt_audience", "jwks_file",
                  "hmac_secret_ref"):
        value = entry.get(field, "")
        if (
            not isinstance(value, str)
            or value != value.strip()
            or len(value) > 4096
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        ):
            log.warning(
                "[agent_trust] agent %r: malformed %s; dropping entry",
                agent_id,
                field,
            )
            return None
        tokens[field] = value
    revoked = entry.get("revoked", False)
    if not isinstance(revoked, bool):
        log.warning("[agent_trust] agent %r: malformed revoked flag; dropping entry", agent_id)
        return None
    return TrustedAgent(
        id=agent_id,
        pubkey=pubkey,
        direction=direction,
        allow_tools=allow_tools,  # type: ignore[arg-type]  # frozenset (not _INVALID)
        deny_tools=deny_tools,  # type: ignore[arg-type]
        max_risk=max_risk,
        max_dollars=max_dollars,  # type: ignore[arg-type]  # float|None
        max_wall_seconds=max_wall_seconds,  # type: ignore[arg-type]
        data_scopes=data_scopes,  # type: ignore[arg-type]
        a2a_token=tokens["a2a_token"],
        grpc_token=tokens["grpc_token"],
        mcp_token=tokens["mcp_token"],
        rest_token=tokens["rest_token"],
        jwt_issuer=tokens["jwt_issuer"],
        jwt_audience=tokens["jwt_audience"],
        jwks_file=tokens["jwks_file"],
        hmac_secret_ref=tokens["hmac_secret_ref"],
        not_before=not_before,  # type: ignore[arg-type]  # float|None (not _INVALID)
        expires_at=expires_at,  # type: ignore[arg-type]
        revoked=revoked,
    )


def _registry_config(cfg: dict | None, *, strict: bool) -> dict | None:
    """Validate the registry's config authority for strict/transport callers."""
    if cfg is None:
        try:
            from .config import config_source_errors, load_config
            cfg = load_config() or {}
            if config_source_errors():
                raise AgentTrustError("agent trust config source is unreadable")
        except Exception as exc:
            if strict:
                raise AgentTrustError(
                    "agent trust registry authority is unavailable"
                ) from exc
            log.warning("agent_trust: config unreadable; registry is empty")
            return None
    if not isinstance(cfg, dict):
        if strict:
            raise AgentTrustError("agent trust registry authority is unavailable")
        log.warning("agent_trust: config root must be a table; registry is empty")
        return None
    trust_cfg = cfg.get("agent_trust")
    if trust_cfg is not None and not isinstance(trust_cfg, dict):
        if strict:
            raise AgentTrustError("agent trust registry authority is unavailable")
        log.warning("agent_trust: config section must be a table; registry is empty")
        return None
    return cfg


def load_registry(
    cfg: dict | None = None, *, strict: bool = False,
) -> dict[str, TrustedAgent]:
    """Parse ``[agent_trust] agents`` into ``{id: TrustedAgent}``.

    The default remains forgiving for transport authorization: junk entries are
    skipped and an unreadable authority becomes an empty, fail-closed registry.
    Operator roster callers pass ``strict=True`` so an authority outage cannot
    masquerade as a healthy deployment with zero external agents.
    """
    cfg = _registry_config(cfg, strict=strict)
    if cfg is None:
        return {}
    trust_cfg = cfg.get("agent_trust")
    raw = (trust_cfg or {}).get("agents")
    out: dict[str, TrustedAgent] = {}
    if isinstance(raw, list):
        for item in raw[:_MAX_AGENTS]:
            if not isinstance(item, dict):
                log.warning("[agent_trust] skipping non-table entry %r", item)
                continue
            agent = _agent_from_entry(item)
            if agent is not None and agent.id not in out:
                out[agent.id] = agent
    elif raw is not None:
        if strict:
            raise AgentTrustError("agent trust registry authority is unavailable")
        log.warning("[agent_trust] agents must be a list; ignoring")
    # Merge the CLI-managed registry overlay (agent_trust.json, client-scoped):
    # managed entries add to / override the hand-edited config ones, so
    # `maverick trust` add/rotate/revoke take effect without editing TOML.
    try:
        managed = _load_managed()
    except AgentTrustError as e:
        # The overlay may contain a revocation or stricter replacement for a
        # TOML entry.  Continuing with TOML after losing that overlay would
        # silently re-trust the agent, so invalidate the whole snapshot.
        if strict:
            raise AgentTrustError(
                "agent trust registry authority is unavailable"
            ) from e
        log.warning("agent_trust: %s; registry is empty (fail-closed)", e)
        return {}
    for item in managed:
        agent = _agent_from_entry(item)
        if agent is None:
            if strict:
                raise AgentTrustError(
                    "agent trust registry authority is unavailable"
                )
            log.warning("agent_trust: malformed managed entry; registry is "
                        "empty (fail-closed)")
            return {}
        config_agent = out.get(agent.id)
        if config_agent is not None and config_agent.revoked and not agent.revoked:
            # An operator's ``revoked = true`` in config.toml wins over an
            # app-managed edit (attenuate, enroll, rotate) of the same agent.
            agent = replace(agent, revoked=True)
        if agent.id in out or len(out) < _MAX_AGENTS:
            out[agent.id] = agent
    return out


def load_registry_strict(cfg: dict | None = None) -> dict[str, TrustedAgent]:
    """Operator-authority registry read that raises on dependency failure."""
    return load_registry(cfg, strict=True)


# -- CLI-managed registry overlay (JSON; client-scoped via the tenant floor) --

def managed_path():
    """Path to the CLI-managed registry overlay (``agent_trust.json``).

    Under the active client's data dir (the tenant floor), so the managed
    registry is automatically per-deployment/per-client.
    """
    from .paths import data_dir
    return data_dir("agent_trust.json")


def _load_managed() -> list[dict]:
    import json

    from .file_lock import atomic_read_text, ensure_private_directory, ensure_private_file
    from .paths import maverick_home

    try:
        p = managed_path()
        ensure_private_directory(maverick_home())
        ensure_private_directory(p.parent)
        if not p.exists():
            return []
        ensure_private_file(p)
        raw = atomic_read_text(p)
        if len(raw) > 4 * 1024 * 1024:
            raise AgentTrustError("managed registry exceeds the size limit")

        def _reject_constant(value: str):
            raise ValueError(f"non-finite number {value!r}")

        def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError(f"duplicate key {key!r}")
                out[key] = value
            return out

        data = json.loads(
            raw,
            parse_constant=_reject_constant,
            object_pairs_hook=_object,
        )
    except AgentTrustError:
        raise
    except (OSError, UnicodeError, ValueError) as e:
        raise AgentTrustError("managed registry is unreadable or invalid") from e
    if not isinstance(data, list):
        raise AgentTrustError("managed registry root must be a list")
    if len(data) > _MAX_AGENTS or any(not isinstance(a, dict) for a in data):
        raise AgentTrustError("managed registry has an invalid entry or size")
    return data


def _save_managed(entries: list[dict]) -> None:
    import json

    from .file_lock import atomic_write_text, ensure_private_directory
    from .paths import maverick_home

    p = managed_path()
    ensure_private_directory(maverick_home())
    ensure_private_directory(p.parent)
    body = json.dumps(entries[:_MAX_AGENTS], indent=2, sort_keys=True)
    atomic_write_text(p, body, mode=0o600)


def _entry_from_agent(agent: TrustedAgent) -> dict[str, Any]:
    """Serialize an effective entry into managed-overlay JSON values."""
    out: dict[str, Any] = {}
    for name in agent.__dataclass_fields__:
        value = getattr(agent, name)
        out[name] = sorted(value) if isinstance(value, frozenset) else value
    return hash_overlay_tokens(out)


def hash_overlay_tokens(entry: dict[str, Any]) -> dict[str, Any]:
    """Replace plaintext config-file bearers in an overlay entry by their hash.

    Every surface's verifier accepts the hashed form: :func:`_token_matches`
    for authentication, and the MCP per-task credential refresh, which
    fingerprints the raw and the ``sha256:`` stored forms identically."""
    for name in _HASHABLE_TOKEN_ATTRS:
        token = entry.get(name)
        if isinstance(token, str) and token and not token.startswith(_TOKEN_HASH_PREFIX):
            entry[name] = hash_token(token)
    return entry


def attenuate_agent(
    agent_id: str,
    *,
    deny_tools: object = (),
    max_risk: str | None = None,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
) -> tuple[TrustedAgent, bool]:
    """Atomically narrow one effective trust entry.

    The effective read, union/tightening calculation, managed-overlay write and
    post-write verification all occur under the managed registry's thread and
    cross-process locks. Concurrent deny additions therefore union instead of
    overwriting one another. Empty, widening, and unchanged requests raise
    before :func:`_save_managed`, so no cosmetic write can look like a policy
    change. Returns ``(persisted_agent, created_overlay)``.
    """
    if not valid_agent_id(agent_id):
        raise AgentTrustError("invalid agent id")
    if isinstance(deny_tools, str):
        raw_deny: object = [deny_tools]
    else:
        raw_deny = deny_tools
    if not isinstance(raw_deny, (list, tuple, set, frozenset)):
        raise AgentTrustError("deny_tools must be a collection of names")
    extra_deny: set[str] = set()
    for value in raw_deny:
        if not isinstance(value, str) or not value.strip():
            raise AgentTrustError("deny_tools contains an invalid name")
        extra_deny.add(value.strip())
    if (
        not extra_deny
        and max_risk is None
        and max_dollars is None
        and max_wall_seconds is None
    ):
        raise AgentTrustError("attenuation requires at least one tighter constraint")
    if max_risk is not None and max_risk not in _RISK_LEVELS:
        raise AgentTrustError("max_risk must be one of low, medium, high")

    def _cap(current: float | None, requested: float | None, label: str) -> float | None:
        if requested is None:
            return current
        parsed = _positive_float(requested)
        if parsed is None:
            raise AgentTrustError(f"{label} must be finite and positive")
        if current is not None and parsed > current:
            raise AgentTrustError(
                f"{label} {parsed} would widen the current ceiling {current}"
            )
        return parsed

    with _managed_locked():
        registry = load_registry(strict=True)
        agent = registry.get(agent_id)
        if agent is None:
            raise AgentTrustError(f"agent:{agent_id} is not in the trust registry")
        entries = _load_managed()
        managed = next(
            (dict(entry) for entry in entries
             if str(entry.get("id") or "") == agent_id),
            None,
        )
        created_overlay = managed is None
        entry = managed if managed is not None else _entry_from_agent(agent)

        new_deny = frozenset(agent.deny_tools) | frozenset(extra_deny)
        new_risk = agent.max_risk
        if max_risk is not None:
            current_rank = (
                _RISK_LEVELS.index(agent.max_risk)
                if agent.max_risk in _RISK_LEVELS else len(_RISK_LEVELS)
            )
            if _RISK_LEVELS.index(max_risk) > current_rank:
                raise AgentTrustError(
                    f"max_risk {max_risk} would widen {agent.max_risk}"
                )
            new_risk = max_risk
        new_dollars = _cap(agent.max_dollars, max_dollars, "max_dollars")
        new_wall = _cap(
            agent.max_wall_seconds, max_wall_seconds, "max_wall_seconds",
        )
        if (
            new_deny == agent.deny_tools
            and new_risk == agent.max_risk
            and new_dollars == agent.max_dollars
            and new_wall == agent.max_wall_seconds
        ):
            raise AgentTrustError(
                "attenuation request does not tighten the current ceiling"
            )

        entry.update({
            "deny_tools": sorted(new_deny),
            "max_risk": new_risk,
            "max_dollars": new_dollars,
            "max_wall_seconds": new_wall,
        })
        clean = {
            key: (sorted(value) if isinstance(value, frozenset) else value)
            for key, value in entry.items()
            if value not in (None, "", [], {})
        }
        clean["id"] = agent_id
        candidate = _agent_from_entry(clean)
        if candidate is None:
            raise AgentTrustError("attenuation produced an invalid trust entry")
        kept = [
            existing for existing in entries
            if str(existing.get("id") or "") != agent_id
        ]
        if len(kept) >= _MAX_AGENTS:
            raise AgentTrustError("managed registry is at capacity")
        kept.append(clean)
        _save_managed(kept)

        persisted_entry = next(
            (item for item in _load_managed()
             if str(item.get("id") or "") == agent_id),
            None,
        )
        persisted = (
            _agent_from_entry(persisted_entry)
            if isinstance(persisted_entry, dict) else None
        )
        if persisted is None or (
            persisted.deny_tools != new_deny
            or persisted.max_risk != new_risk
            or persisted.max_dollars != new_dollars
            or persisted.max_wall_seconds != new_wall
        ):
            raise AgentTrustError("attenuated trust entry did not persist")
        return persisted, created_overlay


_CEILING_FIELDS = (
    "allow_tools", "deny_tools", "max_risk", "max_dollars", "max_wall_seconds",
    "data_scopes",
)


def _keep_unrequested_ceilings(clean: dict, prior: dict | None, agent_id: str) -> None:
    """Carry every ceiling the re-enrollment did not set from the current entry.

    An absent ceiling is not a request to lift it: an empty allow-list means
    allow-all, and a missing risk or dollar cap means none. The current entry
    is the managed one, or else the config.toml one the overlay would shadow."""
    current = prior
    if current is None:
        existing = load_registry(strict=True).get(agent_id)
        current = _entry_from_agent(existing) if existing is not None else {}
    for field in _CEILING_FIELDS:
        if field not in clean and current.get(field) not in (None, "", [], {}):
            clean[field] = current[field]


def put_agent(entry: dict, *, preserve_existing_identity: bool = False) -> TrustedAgent:
    """Add or replace a managed agent (by ``id``). Returns the parsed agent.

    Validates via :func:`_agent_from_entry`; raises :class:`AgentTrustError` on a
    malformed entry so the CLI surfaces a clear error instead of silently
    dropping it."""
    # CLI/programmatic callers naturally pass optional values as None/empty;
    # canonicalize those to absence before applying strict on-disk parsing.
    entry = {k: v for k, v in entry.items() if v not in (None, "", [], {})}
    raw_pubkey = str(entry.get("pubkey") or "").strip()
    if raw_pubkey and not _PUBKEY_RE.fullmatch(raw_pubkey):
        raise AgentTrustError(
            "invalid pubkey: expected a 64-character hex Ed25519 public key"
        )
    agent = _agent_from_entry(entry)
    if agent is None:
        raise AgentTrustError("invalid agent entry")
    with _managed_locked():
        loaded = _load_managed()
        prior = next((e for e in loaded if str(e.get("id") or "") == agent.id), None)
        clean = {k: v for k, v in entry.items() if v not in (None, "", [], {})}
        clean["id"] = agent.id
        if preserve_existing_identity and prior is not None:
            # Re-enrollment edits reach, never identity or lifecycle. Merge
            # under the same lock as revocation and token rotation so an edit
            # cannot race either operation and silently re-enable the agent.
            for field in (
                "pubkey", "a2a_token", "grpc_token", "mcp_token", "rest_token",
                "jwt_issuer", "jwt_audience", "jwks_file", "hmac_secret_ref",
                "not_before", "expires_at", "revoked",
            ):
                if field in prior:
                    clean[field] = prior[field]
                else:
                    clean.pop(field, None)
        if preserve_existing_identity:
            _keep_unrequested_ceilings(clean, prior, agent.id)
        if prior is not None and prior.get("revoked") is True:
            # Generic trust edits must not be an unguarded restore path either.
            # Only the explicit revocation workflow may clear this flag.
            clean["revoked"] = True
        persisted = _agent_from_entry(clean)
        if persisted is None:
            raise AgentTrustError("updated agent entry is invalid")
        entries = [e for e in loaded if str(e.get("id") or "") != agent.id]
        if len(entries) >= _MAX_AGENTS:
            raise AgentTrustError("managed registry is at capacity")
        entries.append(clean)
        _save_managed(entries)
    return persisted


def remove_agent(agent_id: str) -> bool:
    """Delete a managed agent by id. Returns True if one was removed.

    A revoked overlay that shadows a config-defined agent is the revocation of
    that agent; deleting it would restore the config entry as active, so it is
    refused (as it is when the config cannot be read to tell)."""
    with _managed_locked():
        entries = _load_managed()
        kept = [e for e in entries if str(e.get("id") or "") != agent_id]
        if len(kept) == len(entries):
            return False
        if any(e.get("revoked") is True for e in entries
               if str(e.get("id") or "") == agent_id) and _config_defines(agent_id):
            raise RevokedAgentRemovalRefused(
                f"Agent {agent_id!r} is revoked and is also defined in the "
                "server's config file, so removing its app-managed entry would "
                "make it trusted again. Restore it through the revocation "
                "workflow first, or remove it from the config file.")
        _save_managed(kept)
    return True


def _config_defines(agent_id: str) -> bool:
    """Does ``[agent_trust] agents`` name ``agent_id``? Unreadable config raises."""
    cfg = _registry_config(None, strict=True) or {}
    raw = (cfg.get("agent_trust") or {}).get("agents")
    return isinstance(raw, list) and any(
        isinstance(item, dict) and str(item.get("id") or "") == agent_id for item in raw)


def set_revoked(agent_id: str, revoked: bool) -> bool:
    """Mark a managed agent revoked / unrevoked. Returns True if it existed."""
    with _managed_locked():
        entries = _load_managed()
        found = False
        for e in entries:
            if str(e.get("id") or "") == agent_id:
                e["revoked"] = bool(revoked)
                found = True
        if found:
            _save_managed(entries)
    return found


def local_pubkey() -> str | None:
    """This deployment's pinned Ed25519 public key (hex) for out-of-band
    distribution to peers, or ``None`` when ``cryptography`` is unavailable."""
    try:
        from .audit import signing as audit_signing
        if not audit_signing._have_crypto():
            return None
        _priv, pub, _key_id = audit_signing._load_or_create_keypair()
        return pub.hex()
    except Exception:  # pragma: no cover
        return None


def lookup(agent_id: str, *, registry: dict[str, TrustedAgent] | None = None) -> TrustedAgent | None:
    reg = load_registry() if registry is None else registry
    return reg.get(agent_id)


_TOKEN_ATTRS = {"a2a": "a2a_token", "grpc": "grpc_token", "mcp": "mcp_token",
                "rest": "rest_token"}
_HASHABLE_TOKEN_ATTRS = ("a2a_token", "grpc_token", "mcp_token", "rest_token")

#: Tokens minted from the app are stored hashed; hand-edited config-file
#: tokens stay plaintext-compatible. The prefix disambiguates the two forms.
_TOKEN_HASH_PREFIX = "sha256:"


def hash_token(raw: str) -> str:
    """The at-rest form of a minted bearer: ``sha256:<hex>``.

    The managed overlay (``agent_trust.json``) should never hold a raw
    credential — a leaked backup of that file must not authenticate. Raw
    tokens in the operator's hand-edited TOML remain accepted for
    compatibility; app-minted tokens always store this form."""
    import hashlib
    return _TOKEN_HASH_PREFIX + hashlib.sha256(
        (raw or "").encode()).hexdigest()


def _token_matches(configured: str, presented: bytes) -> bool:
    """Constant-time bearer check handling both at-rest forms."""
    import hashlib
    import hmac
    if configured.startswith(_TOKEN_HASH_PREFIX):
        digest = _TOKEN_HASH_PREFIX + hashlib.sha256(presented).hexdigest()
        return hmac.compare_digest(configured.encode(), digest.encode())
    return hmac.compare_digest(configured.encode(), presented)


def agent_for_token(
    token: str, surface: str, *, registry: dict[str, TrustedAgent] | None = None,
) -> TrustedAgent | None:
    """Resolve a valid presented per-caller bearer for ``surface`` (a2a/grpc/mcp)
    to its registered agent, or ``None``.

    Constant-time compares against every entry's surface token (scanning all so
    timing doesn't reveal which matched); an empty token never matches. A token
    is an authentication credential, so it only resolves while the matching
    trust entry is active and inbound-permitted -- revoked, expired,
    not-yet-valid, or outbound-only entries therefore fail authentication for
    management methods as well as task execution. This is how a per-caller
    bearer maps to a specific :class:`TrustedAgent` so the registry can govern
    individual callers on a single-shared-bearer surface."""
    attr = _TOKEN_ATTRS.get(surface)
    presented = (token or "").encode()
    if attr is None or not presented:
        return None
    reg = load_registry() if registry is None else registry
    matched: TrustedAgent | None = None
    active_matches = 0
    for agent in reg.values():
        configured = getattr(agent, attr, "")
        if configured and _token_matches(configured, presented):
            active, _ = agent.is_active()
            if active and agent.permits_inbound():
                active_matches += 1
                matched = agent
    # A bearer is an identity, not merely a shared secret.  If two active
    # inbound principals carry the same surface token there is no unambiguous
    # authenticated caller, so reject it instead of silently picking whichever
    # registry entry happened to be iterated first.
    return matched if active_matches == 1 else None


def agent_for_a2a_token(
    token: str, *, registry: dict[str, TrustedAgent] | None = None,
) -> TrustedAgent | None:
    """Back-compat wrapper: resolve a per-caller A2A bearer (see
    :func:`agent_for_token`)."""
    return agent_for_token(token, "a2a", registry=registry)


# -- decision point --------------------------------------------------------

def _resolve(enforced: bool | None) -> bool:
    return agent_trust_enforced() if enforced is None else enforced


def decide_inbound(
    agent_id: str,
    *,
    requested_tools: Any = (),
    max_risk: str | None = None,
    registry: dict[str, TrustedAgent] | None = None,
    enforced: bool | None = None,
) -> TrustDecision:
    """Decide whether external agent ``agent_id`` may act *on us*.

    Returns a :class:`TrustDecision`. When the plane is disengaged the decision
    is a no-op ALLOW with ``capability=None`` (callers change nothing). When
    engaged: an agent absent from the registry is DENIED; an agent whose
    ``direction`` forbids inbound is DENIED; an agent whose ceiling does not
    permit a *requested* (required) tool is DENIED; otherwise ALLOWED, and the
    decision carries the agent's :class:`Capability` ceiling for the caller to
    narrow the run against.
    """
    if not _resolve(enforced):
        return TrustDecision(True, "agent trust plane disengaged", "disabled")
    agent = lookup(agent_id, registry=registry)
    if agent is None:
        return TrustDecision(
            False, f"external agent {agent_id!r} is not in the trust registry",
            "not_in_registry")
    active, why = agent.is_active()
    if not active:
        return TrustDecision(
            False, f"agent {agent_id!r} credential is {why}", why, agent)
    if not agent.permits_inbound():
        return TrustDecision(
            False, f"agent {agent_id!r} is not permitted inbound "
                   f"(direction={agent.direction!r})", "direction", agent)
    cap = agent.capability()
    requested = _names(requested_tools)
    # Normalise case BEFORE validating: a request for "HIGH"/"Critical" must not
    # slip past the ceiling because it didn't match the lowercase risk set. An
    # unrecognised risk word is REFUSED (fail-closed), never waved through.
    if max_risk is not None:
        norm = str(max_risk).strip().lower()
        if norm and _risk(norm) is None:
            return TrustDecision(
                False, f"agent {agent_id!r} requested unrecognised risk "
                       f"{max_risk!r}", "capability", agent, cap)
        max_risk = norm or None
    denied = sorted(t for t in requested if not cap.permits(t))
    if denied:
        return TrustDecision(
            False, f"agent {agent_id!r} may not use required tools: {denied}",
            "capability", agent, cap)
    if max_risk and agent.max_risk and _rank(max_risk) > _rank(agent.max_risk):
        return TrustDecision(
            False, f"agent {agent_id!r} requested risk {max_risk!r} above its "
                   f"ceiling {agent.max_risk!r}", "capability", agent, cap)
    return TrustDecision(True, "permitted", "allow", agent, cap)


def decide_outbound(
    agent_id: str,
    *,
    registry: dict[str, TrustedAgent] | None = None,
    enforced: bool | None = None,
) -> TrustDecision:
    """Decide whether *we* may initiate contact with external agent ``agent_id``.

    The egress half: a company controls which outside agents its agents may
    *dial*. Disengaged -> no-op ALLOW. Engaged -> an unknown agent, or one whose
    ``direction`` forbids outbound, is DENIED before any connection is opened.
    """
    if not _resolve(enforced):
        return TrustDecision(True, "agent trust plane disengaged", "disabled")
    agent = lookup(agent_id, registry=registry)
    if agent is None:
        return TrustDecision(
            False, f"external agent {agent_id!r} is not in the trust registry",
            "not_in_registry")
    active, why = agent.is_active()
    if not active:
        return TrustDecision(
            False, f"agent {agent_id!r} credential is {why}", why, agent)
    if not agent.permits_outbound():
        return TrustDecision(
            False, f"agent {agent_id!r} is not permitted outbound "
                   f"(direction={agent.direction!r})", "direction", agent)
    return TrustDecision(True, "permitted", "allow", agent, agent.capability())


def decide_memory_access(
    agent_id: str,
    domain: str | None,
    *,
    registry: dict[str, TrustedAgent] | None = None,
    enforced: bool | None = None,
) -> TrustDecision:
    """Decide whether external agent ``agent_id`` may read/write memory tagged
    ``domain`` — the gate shared by fleet-memory ingest AND recall.

    Disengaged -> no-op ALLOW. Engaged: the agent must be registered, active,
    inbound-permitted, and ``domain`` must be a NON-EMPTY scope the agent's
    ``data_scopes`` allows. An unscoped (``domain=None``) request is **denied**
    when engaged — an external agent cannot read across all departments by
    simply omitting the scope (the old ``permits_scope(None) -> True`` bypass).
    """
    if not _resolve(enforced):
        return TrustDecision(True, "agent trust plane disengaged", "disabled")
    agent = lookup(agent_id, registry=registry)
    if agent is None:
        return TrustDecision(
            False, f"external agent {agent_id!r} is not in the trust registry",
            "not_in_registry")
    active, why = agent.is_active()
    if not active:
        return TrustDecision(
            False, f"agent {agent_id!r} credential is {why}", why, agent)
    if not agent.permits_inbound():
        return TrustDecision(
            False, f"agent {agent_id!r} is not permitted inbound "
                   f"(direction={agent.direction!r})", "direction", agent)
    scope = (domain or "").strip()
    if not scope:
        return TrustDecision(
            False, f"agent {agent_id!r} must declare a data scope (one of "
                   f"{sorted(agent.data_scopes)}) — unscoped access is denied",
            "data_scope", agent)
    if not agent.permits_scope(scope):
        return TrustDecision(
            False, f"agent {agent_id!r} may not access data scope {scope!r}",
            "data_scope", agent)
    return TrustDecision(True, "permitted", "allow", agent, agent.capability())


def _rank(risk: str) -> int:
    try:
        return _RISK_LEVELS.index(risk)
    except ValueError:
        return -1


def clamp_budget(
    agent: TrustedAgent | None,
    *,
    max_dollars: float | None = None,
    max_wall_seconds: float | None = None,
) -> tuple[float | None, float | None]:
    """Clamp a requested run budget DOWN to the agent's ceiling (never up).

    ``None`` on either side means "no ceiling from that side"; the result is the
    tighter of the two. Used so a delegated run can request *less* than its
    ceiling but never more.
    """
    def _min(req: float | None, cap: float | None) -> float | None:
        vals = [v for v in (req, cap) if v is not None]
        return min(vals) if vals else None

    if agent is None:
        return max_dollars, max_wall_seconds
    return (
        _min(max_dollars, agent.max_dollars),
        _min(max_wall_seconds, agent.max_wall_seconds),
    )


# -- identity --------------------------------------------------------------

def verify_identity(
    agent_id: str,
    envelope: object,
    *,
    expected_schema: str,
    registry: dict[str, TrustedAgent] | None = None,
) -> tuple[bool, str]:
    """Verify a signed envelope against ``agent_id``'s *pinned* public key.

    Reuses :func:`maverick.federation_envelope.verify_envelope` — the same
    Ed25519 / pinned-key, fail-closed primitive the channel and marketplace
    paths use — so every external surface shares one asymmetric identity model
    instead of inventing its own. Fails closed: an unknown agent, an agent with
    no pinned key, a schema/signature mismatch, or absent ``cryptography`` all
    return ``(False, reason)`` and never raise.
    """
    agent = lookup(agent_id, registry=registry)
    if agent is None:
        return False, f"agent {agent_id!r} is not in the trust registry"
    active, why = agent.is_active()
    if not active:
        return False, f"agent {agent_id!r} credential is {why}"
    if not agent.pubkey:
        return False, f"agent {agent_id!r} has no pinned public key"
    # Bind the claimed identity to the signed envelope explicitly. verify_envelope
    # keys peers on the envelope's own `origin`, so without this check an envelope
    # whose origin differs from agent_id would be rejected with a confusing "not
    # in peer trust list" (or, if a deployment's signing origin legitimately
    # differs from its registry id, a valid envelope would silently fail). Assert
    # the binding up front with a clear reason.
    if not isinstance(envelope, dict):
        return False, "envelope is not an object"
    origin = envelope.get("origin")
    if origin != agent_id:
        return False, (f"envelope origin {origin!r} does not match the claimed "
                       f"agent {agent_id!r}")
    from .federation_envelope import verify_envelope
    return verify_envelope(
        envelope,
        expected_schema=expected_schema,
        peers={agent.id: {"origin": agent.id, "pubkey": agent.pubkey}},
    )


# -- audit + status --------------------------------------------------------

def record_denied(
    agent_id: str,
    decision: TrustDecision | None = None,
    *,
    direction: str,
    correlation_id: str = "",
    rule: str | None = None,
    reason: str | None = None,
) -> None:
    """Record a trust-plane denial to the audit chain.

    Pass a :class:`TrustDecision` (the usual case) or ``rule=``/``reason=``
    directly — the latter lets a caller log a denial without fabricating a
    throwaway decision object. A denial is a security-relevant event, so it
    lands in the Operating Record alongside capability/governance denials.
    Ordinary audit outages remain fail-soft. A policy/custody refusal
    propagates so a denied trust decision cannot be reported as fully recorded
    when the configured audit guarantee explicitly declined the write.
    """
    if decision is not None:
        rule, reason = decision.rule, decision.reason
    from .audit import EventKind, audit_event

    audit_event(
        EventKind.AGENT_TRUST_DENIED, agent="agent_trust",
        peer=agent_id, direction=direction, rule=rule or "denied",
        reason=reason or "", correlation_id=correlation_id,
    )


def status() -> dict[str, Any]:
    """A summary for ``maverick doctor`` / dashboards: engaged flag + roster."""
    enforced, reg = load_trust_state()
    return {
        "enforced": enforced,
        "count": len(reg),
        "agents": [
            {
                "id": a.id,
                "direction": a.direction,
                "pinned_key": bool(a.pubkey),
                "max_risk": a.max_risk,
                "data_scopes": sorted(a.data_scopes),
                "active": a.is_active()[0],
                "expires_at": a.expires_at,
            }
            for a in reg.values()
        ],
    }


__all__ = [
    "AgentTrustError",
    "TrustedAgent",
    "TrustDecision",
    "agent_trust_enforced",
    "attenuate_agent",
    "load_trust_state",
    "load_registry",
    "load_registry_strict",
    "managed_path",
    "put_agent",
    "remove_agent",
    "set_revoked",
    "local_pubkey",
    "lookup",
    "agent_for_token",
    "agent_for_a2a_token",
    "decide_inbound",
    "decide_outbound",
    "decide_memory_access",
    "clamp_budget",
    "verify_identity",
    "record_denied",
    "status",
    "valid_agent_id",
]
