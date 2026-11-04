"""Agent Control Plane: one governed roster and one set of operator verbs over
every agent this deployment runs or admits.

Lightwork already has the primitives an operator needs to control an agent:
the capability revocation registry (``revocation.py``, consulted on every tool
call), the external-agent trust registry (``agent_trust.py``), the security
plane's containment (``agent_edr.py``), the bring-your-own-agent sidecar
(``external_agents.py``) and the local deployment killswitch
(``killswitch.py``). What it
did not have is a single place that lists every principal those primitives
govern and applies the same verb to any of them. This module is that place.

It adds NO new enforcement. Every verb lands in a store the runtime already
consults on its hot path, and reports what it *confirmed* landed rather than
what it asked for (a suspend whose revocation did not persist is a failure,
not a success with a caveat).

Principals:

- a native run is governed by the capability principal its goal runs under --
  ``user:<id>`` (``agent.py``'s root grant; ``user:local`` when no user is
  bound). Revoking it denies the next tool call of every agent in that
  subtree, because a child grant carries its ancestors and
  ``revocation.revoked_principal`` walks them;
- an external agent is ``agent:<id>``, the trust registry's principal. A
  suspend flips the trust entry's ``revoked`` flag as well, so the gateway
  and the A2A/gRPC/MCP surfaces refuse it too, not only the capability path.

Config: ``[control_plane] enable`` (or ``MAVERICK_CONTROL_PLANE=1``). Reads
(roster, status, ledger) work either way; the mutating verbs refuse while the
plane is off, so a stray click on a deployment that never opted in cannot
revoke anything.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import math
import secrets
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

KIND_NATIVE = "native"
KIND_EXTERNAL = "external"
EXTERNAL_PREFIX = "agent:"

# Principal values are opaque identity-provider subjects, not filenames or URL
# path components.  Keep this domain broad enough for valid OIDC/SAML subjects
# (Unicode, spaces, ``|`` and ``/`` are all legitimate) while rejecting values
# that are ambiguous in operator output or unsafe to persist in text records.
# The dashboard transports these values in a query/body; its legacy path route
# remains deliberately restricted for backwards compatibility.
_MAX_PRINCIPAL = 512
_MAX_REASON = 500
_MAX_NATIVE_GOALS = 10_000
_MAX_ROSTER_PAGE = 500
_MAX_BULK_TARGETS = 500
_MAX_PLATFORM_SELECTOR = 160
_MAX_TIMEBOX_IDEMPOTENCY_KEY = 160
_MAX_TIMEBOX_SECONDS = 31 * 24 * 60 * 60
_MAX_TIMEBOX_RECORDS = 2_000
_MAX_TIMEBOX_STATE_BYTES = 2 * 1024 * 1024
_TIMEBOX_LEASE_SECONDS = 60.0
_TIMEBOX_SCHEMA = "lightwork.agent-control-plane-timeboxes.v1"
_SELECTION_SCHEMA = "lightwork.agent-control-plane-selection.v1"


class ControlPlaneError(RuntimeError):
    """A verb could not be applied (the deployment state is unchanged)."""


class ControlPlaneDisabled(ControlPlaneError):
    """The plane is off: ``[control_plane] enable`` is false."""


class ControlPlaneDependencyError(ControlPlaneError):
    """A roster authority is unavailable, so no healthy-empty answer exists."""

    def __init__(self, dependency: str):
        self.dependency = dependency
        super().__init__(f"{dependency} authority is unavailable")


class _ConcurrentHalt(ControlPlaneError):
    """A newer local HALT generation superseded an in-flight clear."""


class ControlPlaneStaleSelection(ControlPlaneError):
    """The roster changed after an operator reviewed a bulk selection."""


# ---- model ------------------------------------------------------------------

@dataclass(frozen=True)
class AgentPrincipal:
    """One row of the roster: a principal and what the runtime knows of it."""

    principal: str
    kind: str
    label: str
    state: str
    running_goals: int = 0
    revoked: bool = False
    revoked_reason: str = ""
    contained: bool = False
    max_risk: str | None = None
    max_dollars: float | None = None
    max_wall_seconds: float | None = None
    allow_tools: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    # ``platform`` remains the roster's human-readable label for existing UI
    # callers; ``platform_id`` is the stable enrollment slug for bulk APIs.
    platform: str = ""
    platform_id: str = ""

    def to_dict(self) -> dict:
        out = dataclasses.asdict(self)
        out["allow_tools"] = list(self.allow_tools)
        out["deny_tools"] = list(self.deny_tools)
        return out


@dataclass
class ControlResult:
    """What a verb confirmed. ``ok`` is False when any part did not land."""

    verb: str
    principal: str
    ok: bool
    code: str | None = None
    detail: str = ""
    notes: list[str] = field(default_factory=list)
    audit_written: bool | None = None

    def to_dict(self) -> dict:
        return {"verb": self.verb, "principal": self.principal, "ok": self.ok,
                "code": self.code,
                "detail": self.detail, "notes": list(self.notes),
                "audit_written": self.audit_written}


@dataclass(frozen=True)
class ControlPlaneSnapshot:
    """One coherent authority scan reusable for status plus roster rendering."""

    rows: tuple[AgentPrincipal, ...]
    captured_at: float

    def page(self, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        start = max(0, int(offset))
        size = max(1, min(int(limit), _MAX_ROSTER_PAGE))
        selected = self.rows[start:start + size]
        return {
            "captured_at": self.captured_at,
            "offset": start,
            "limit": size,
            "total": len(self.rows),
            "items": [row.to_dict() for row in selected],
        }


@dataclass(frozen=True)
class BulkSelection:
    """An operator-reviewed, tenant-bound exact set of principals.

    The digest pins every roster attribute used to make the selection. A bulk
    mutation always scans again and refuses if this evidence is no longer
    current; a broad platform label is never treated as a live wildcard.
    """

    tenant: str
    platform: str | None
    principals: tuple[str, ...]
    snapshot_sha256: str
    captured_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _SELECTION_SCHEMA,
            "tenant": self.tenant,
            "platform": self.platform,
            "principals": list(self.principals),
            "snapshot_sha256": self.snapshot_sha256,
            "captured_at": self.captured_at,
        }


@dataclass
class BulkControlResult:
    """Confirmed outcomes for one snapshot-pinned bulk operator action."""

    verb: str
    selection: BulkSelection
    results: list[ControlResult]
    ok: bool
    audit_written: bool | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verb": self.verb,
            "selection": self.selection.to_dict(),
            "results": [result.to_dict() for result in self.results],
            "ok": self.ok,
            "audit_written": self.audit_written,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class TimeboxedContainment:
    """A durable protected containment with an explicit future release time."""

    operation_id: str
    principal: str
    tenant: str
    containment_generation: str
    release_at: float
    status: str
    result: ControlResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "principal": self.principal,
            "tenant": self.tenant,
            "containment_generation": self.containment_generation,
            "release_at": self.release_at,
            "status": self.status,
            "result": self.result.to_dict(),
        }


# ---- gate -------------------------------------------------------------------

def enabled(*, strict: bool = False) -> bool:
    """``[control_plane] enable`` or ``MAVERICK_CONTROL_PLANE=1``.

    Ordinary callers retain the historical fail-soft predicate.  Status and
    mutation gates pass ``strict=True`` so an unreadable active config source
    is reported as an unavailable authority, never laundered into "disabled".
    """
    try:
        from .config import config_source_errors, get_control_plane

        configured = bool(get_control_plane().get("enable"))
        if strict and config_source_errors():
            raise ControlPlaneDependencyError("control-plane configuration")
        return configured
    except ControlPlaneDependencyError:
        raise
    except Exception as exc:
        if strict:
            raise ControlPlaneDependencyError(
                "control-plane configuration"
            ) from exc
        log.warning("control_plane: config unreadable; plane is off", exc_info=True)
        return False


def _require_enabled(verb: str) -> None:
    if not enabled(strict=True):
        raise ControlPlaneDisabled(
            f"control plane is off: `{verb}` refused (set [control_plane] enable "
            "= true or MAVERICK_CONTROL_PLANE=1)")


def valid_principal(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and value == value.strip()
        and len(value) <= _MAX_PRINCIPAL
        and value.isprintable()
    )


def _check_principal(principal: object) -> str:
    if not valid_principal(principal):
        raise ValueError(
            "invalid principal (non-empty printable text, max 512 characters)"
        )
    return str(principal)


def _check_reason(reason: object) -> str:
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("a reason is required")
    if len(reason) > _MAX_REASON:
        raise ValueError(f"reason exceeds {_MAX_REASON} characters")
    return reason.strip()


def _check_actor(actor: object) -> str:
    return actor.strip() if isinstance(actor, str) and actor.strip() else "operator"


def _active_tenant_scope() -> str:
    """Return the exact active tenant, never a best-effort diagnostic value."""

    try:
        from .paths import current_tenant_id_strict

        return current_tenant_id_strict() or ""
    except Exception as exc:
        raise ControlPlaneDependencyError("tenant boundary") from exc


def _check_tenant_selector(tenant: object, active_tenant: str) -> str:
    if not isinstance(tenant, str) or tenant != tenant.strip():
        raise ValueError("tenant selection must be exact printable text")
    if tenant != active_tenant:
        raise ValueError("selection crosses the active tenant boundary")
    return tenant


def _check_platform_selector(platform: object) -> str:
    if (
        not isinstance(platform, str)
        or not platform
        or platform != platform.strip()
        or len(platform) > _MAX_PLATFORM_SELECTOR
        or not platform.isprintable()
    ):
        raise ValueError("platform selection must be non-empty printable text")
    return platform


def _check_timebox_seconds(seconds: object) -> float:
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError("release_after_seconds must be a positive finite number")
    selected = float(seconds)
    if not math.isfinite(selected) or not 0 < selected <= _MAX_TIMEBOX_SECONDS:
        raise ValueError(
            "release_after_seconds must be between 0 and "
            f"{_MAX_TIMEBOX_SECONDS} seconds"
        )
    return selected


def _check_timebox_idempotency_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > _MAX_TIMEBOX_IDEMPOTENCY_KEY
        or not all(char.isascii() and (char.isalnum() or char in "._:-")
                   for char in value)
    ):
        raise ValueError(
            "idempotency_key must be 1-160 ASCII letters, digits, '.', '_', ':' or '-'"
        )
    return value


def _sha256_payload(value: object) -> str:
    body = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


@contextmanager
def _trace_control_operation(name: str, attributes: dict[str, Any]):
    """Use the shared OTel path without allowing telemetry to block control."""

    with ExitStack() as stack:
        try:
            from .observability import trace_span

            stack.enter_context(trace_span(name, attributes=attributes))
        except Exception:
            log.debug("control_plane: telemetry span unavailable", exc_info=True)
        yield


def is_external(principal: str) -> bool:
    return principal.startswith(EXTERNAL_PREFIX) and len(principal) > len(EXTERNAL_PREFIX)


def _external_id(principal: str) -> str:
    return principal[len(EXTERNAL_PREFIX):]


# ---- audit ------------------------------------------------------------------

def _audit(verb: str, principal: str, actor: str, ok: bool, detail: str,
           **extra) -> bool:
    """Attempt one audit row and return whether it was written.

    Signing is deployment policy, not implied here. A configured audit refusal
    propagates; an ordinary fail-soft outage returns false and is exposed on the
    :class:`ControlResult`.
    """
    from .audit import EventKind, audit_event
    return audit_event(
        EventKind.CONTROL_PLANE_ACTION, agent="control_plane",
        verb=verb, principal=principal, actor=actor, ok=bool(ok),
        detail=detail[:_MAX_REASON], **extra,
    )


def _audit_result(result: ControlResult, actor: str, detail: str,
                  **extra: Any) -> ControlResult:
    if not result.ok and result.code is None:
        result.code = "not_applied"
    result.audit_written = _audit(
        result.verb, result.principal, actor, result.ok, detail, **extra,
    )
    if not result.audit_written:
        result.notes.append("control action audit row was not written")
    return result


def _dependency_failure(
    result: ControlResult,
    *,
    authority: str,
    exc: BaseException,
) -> None:
    """Set a stable dependency result without exposing exception detail."""

    log.warning(
        "control_plane: %s unavailable during %s",
        authority,
        result.verb,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    result.code = "dependency_unavailable"
    result.detail = f"{authority} is unavailable"


# ---- roster -----------------------------------------------------------------

def _revocations() -> dict[str, Any]:
    try:
        from .revocation import shared
        return shared().revoked()
    except Exception as exc:
        log.warning("control_plane: revocation registry unreadable", exc_info=True)
        raise ControlPlaneDependencyError("revocation registry") from exc


def _native_rows(revoked: dict[str, Any]) -> list[AgentPrincipal]:
    """Running goals grouped by the capability principal they run under, plus
    every revoked native principal (a suspended run must stay listed so it can
    be resumed after its goals have drained)."""
    counts: dict[str, int] = {}
    try:
        from .world_model import open_world
        # ``active`` is the WorldModel's actual in-flight status.  ``running``
        # is a UI label, not a stored status, and querying it produced a
        # permanently empty native roster against the real backend.
        goals = open_world().list_goals(
            status="active", limit=_MAX_NATIVE_GOALS + 1, order="desc",
        )
        if len(goals) > _MAX_NATIVE_GOALS:
            raise ControlPlaneDependencyError("bounded native-goal roster")
        for goal in goals:
            runtime = (
                getattr(goal, "execution_principal", "")
                or getattr(goal, "owner", "")
                or "user:local"
            )
            counts[runtime] = counts.get(runtime, 0) + 1
    except ControlPlaneDependencyError:
        raise
    except Exception as exc:
        log.warning("control_plane: world model unavailable; native runs unknown",
                    exc_info=True)
        raise ControlPlaneDependencyError("world model") from exc
    principals = set(counts) | {p for p in revoked if not is_external(p)}
    rows = []
    for principal in sorted(principals):
        rev = revoked.get(principal)
        running = counts.get(principal, 0)
        protected = bool(getattr(rev, "protected", False)) if rev is not None else False
        state = (
            "contained" if protected else
            "suspended" if rev is not None else
            "running" if running else "idle"
        )
        rows.append(AgentPrincipal(
            principal=principal, kind=KIND_NATIVE, label=principal, state=state,
            running_goals=running, revoked=rev is not None,
            revoked_reason=getattr(rev, "reason", "") if rev is not None else "",
            contained=protected,
        ))
    return rows


def _external_rows(revoked: dict[str, Any]) -> list[AgentPrincipal]:
    from .agent_trust import load_registry_strict
    contained: dict[str, bool] = {}
    platforms: dict[str, str] = {}
    platform_ids: dict[str, str] = {}
    try:
        registry = load_registry_strict()
    except Exception as exc:
        log.warning("control_plane: agent trust authority unavailable",
                    exc_info=True)
        raise ControlPlaneDependencyError("agent trust registry") from exc
    try:
        from .external_agents import roster as xa_roster
        for row in xa_roster(registry=registry, strict=True):
            contained[row["id"]] = bool(row.get("contained"))
            platforms[row["id"]] = str(row.get("platform_label") or "")
            platform_ids[row["id"]] = str(row.get("platform") or "")
    except Exception as exc:
        log.warning("control_plane: external-agent sidecar unavailable",
                    exc_info=True)
        raise ControlPlaneDependencyError("external-agent sidecar") from exc
    rows = []
    for agent in registry.values():
        principal = EXTERNAL_PREFIX + agent.id
        rev = revoked.get(principal)
        active, rule = agent.is_active()
        protected = bool(getattr(rev, "protected", False)) if rev is not None else False
        is_contained = bool(protected or contained.get(agent.id))
        if is_contained:
            state = "contained"
        elif rev is not None or agent.revoked:
            state = "suspended"
        else:
            state = "active" if active else rule
        rows.append(AgentPrincipal(
            principal=principal, kind=KIND_EXTERNAL, label=agent.id, state=state,
            revoked=rev is not None or agent.revoked,
            revoked_reason=getattr(rev, "reason", "") if rev is not None else "",
            contained=is_contained,
            max_risk=agent.max_risk, max_dollars=agent.max_dollars,
            max_wall_seconds=agent.max_wall_seconds,
            allow_tools=tuple(sorted(agent.allow_tools)),
            deny_tools=tuple(sorted(agent.deny_tools)),
            platform=platforms.get(agent.id, ""),
            platform_id=platform_ids.get(agent.id, ""),
        ))
    # A revoked external principal that has no (or no longer has a) trust entry
    # must stay visible: it is still denied on every tool call, and the only
    # way to lift that is from here. Dropping it would strand the revocation.
    listed = {row.principal for row in rows}
    for principal, rev in sorted(revoked.items()):
        if is_external(principal) and principal not in listed:
            rows.append(AgentPrincipal(
                principal=principal, kind=KIND_EXTERNAL, label=_external_id(principal),
                state="suspended", revoked=True,
                revoked_reason=getattr(rev, "reason", ""),
                platform="not in trust registry",
            ))
    return rows


def snapshot() -> ControlPlaneSnapshot:
    """Scan each roster authority once and return a reusable snapshot."""
    revoked = _revocations()
    rows = tuple(_native_rows(revoked) + _external_rows(revoked))
    return ControlPlaneSnapshot(rows=rows, captured_at=time.time())


def roster(*, source: ControlPlaneSnapshot | None = None) -> list[AgentPrincipal]:
    """Every governed principal from one strict authority snapshot."""
    view = source if source is not None else snapshot()
    return list(view.rows)


def lookup(principal: str, *, source: ControlPlaneSnapshot | None = None,
           ) -> AgentPrincipal | None:
    principal = _check_principal(principal)
    for row in roster(source=source):
        if row.principal == principal:
            return row
    return None


# ---- snapshot-pinned fleet selection -----------------------------------------

def _snapshot_sha256(view: ControlPlaneSnapshot, *, tenant: str) -> str:
    """Digest the complete roster state, excluding the wall-clock scan time.

    Captured-at changes on every read and is useful to show an operator, but
    would turn an otherwise identical second authority scan into a false stale
    selection. The set is sorted explicitly because a registry implementation
    may legitimately change its iteration order without changing authority.
    """

    return _sha256_payload({
        "schema": _SELECTION_SCHEMA,
        "tenant": tenant,
        "rows": [row.to_dict() for row in sorted(
            view.rows, key=lambda row: row.principal,
        )],
    })


def select_bulk(
    *,
    tenant: str | None = None,
    platform: str | None = None,
    source: ControlPlaneSnapshot | None = None,
) -> BulkSelection:
    """Select an exact active-tenant fleet subset from one roster snapshot.

    ``tenant`` must match the process/request's already-bound tenant exactly;
    this core API never traverses tenant storage itself. A platform matches the
    roster's stable enrollment slug or its provenance label case-insensitively.
    Calling without an explicit tenant or platform is refused so a UI bug cannot
    mean "all tenants" or an accidental deployment-wide action.
    """

    if tenant is None and platform is None:
        raise ValueError("selection requires an explicit tenant or platform")
    active_tenant = _active_tenant_scope()
    selected_tenant = (
        active_tenant if tenant is None
        else _check_tenant_selector(tenant, active_tenant)
    )
    selected_platform = (
        _check_platform_selector(platform) if platform is not None else None
    )
    view = source if source is not None else snapshot()
    rows = list(view.rows)
    if selected_platform is not None:
        needle = selected_platform.casefold()
        rows = [
            row for row in rows
            if (
                row.kind == KIND_EXTERNAL
                and (
                    row.platform.casefold() == needle
                    or row.platform_id.casefold() == needle
                )
            )
        ]
    principals = tuple(sorted({row.principal for row in rows}))
    if not principals:
        raise LookupError("selection matched no governed principals")
    if len(principals) > _MAX_BULK_TARGETS:
        raise ControlPlaneError(
            f"selection exceeds the {_MAX_BULK_TARGETS}-principal safety bound"
        )
    return BulkSelection(
        tenant=selected_tenant,
        platform=selected_platform,
        principals=principals,
        snapshot_sha256=_snapshot_sha256(view, tenant=selected_tenant),
        captured_at=view.captured_at,
    )


def _refresh_bulk_selection(selection: BulkSelection) -> BulkSelection:
    if not isinstance(selection, BulkSelection):
        raise TypeError("selection must be a BulkSelection")
    active_tenant = _active_tenant_scope()
    if selection.tenant != active_tenant:
        raise ControlPlaneStaleSelection(
            "selection tenant is not the active tenant; re-select in that tenant"
        )
    try:
        fresh = select_bulk(
            tenant=selection.tenant,
            platform=selection.platform,
            source=snapshot(),
        )
    except LookupError as exc:
        raise ControlPlaneStaleSelection(
            "selection is stale; refresh the roster before acting"
        ) from exc
    if (
        fresh.snapshot_sha256 != selection.snapshot_sha256
        or fresh.principals != selection.principals
    ):
        raise ControlPlaneStaleSelection(
            "selection is stale; refresh the roster before acting"
        )
    return fresh


# ---- trust-entry helpers (external agents) -----------------------------------

def _trust_entry(agent_id: str):
    from .agent_trust import load_registry_strict
    return load_registry_strict().get(agent_id)


def _managed_entry(agent_id: str) -> dict | None:
    from .agent_trust import _load_managed
    for entry in _load_managed():
        if str(entry.get("id") or "") == agent_id:
            return dict(entry)
    return None


def _overlay_from(agent) -> dict:
    """A managed-registry entry equivalent to a parsed ``TrustedAgent`` (used
    when the entry lives only in TOML: the overlay overrides it by id)."""
    entry: dict[str, Any] = {}
    for f in dataclasses.fields(agent):
        value = getattr(agent, f.name)
        entry[f.name] = sorted(value) if isinstance(value, frozenset) else value
    return entry


def _set_trust_revoked(agent_id: str, revoked: bool, notes: list[str]) -> bool:
    """Flip the trust entry's ``revoked`` flag; True when it is confirmed."""
    from .agent_trust import put_agent, set_revoked
    agent = _trust_entry(agent_id)
    if agent is None:
        notes.append("no trust-registry entry: the capability revocation alone applies")
        return True
    if not set_revoked(agent_id, revoked):
        entry = _overlay_from(agent)
        entry["revoked"] = revoked
        put_agent(entry)
        notes.append("trust entry is config-defined; wrote a managed overlay")
    after = _trust_entry(agent_id)
    return after is not None and after.revoked is revoked


# ---- durable time-boxed containment -----------------------------------------

_TIMEBOX_STATUSES = frozenset({
    "arming", "scheduled", "releasing", "released", "manually_released",
    "superseded", "failed",
})


def _timebox_state_path():
    """Tenant-scoped durable schedule state, separate from revocation truth."""

    from .paths import data_dir

    return data_dir("control_plane_timeboxes.json")


def _empty_timebox_state() -> dict[str, Any]:
    return {"schema": _TIMEBOX_SCHEMA, "records": {}}


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _valid_timebox_timestamp(value: object, *, positive: bool) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    selected = float(value)
    return math.isfinite(selected) and (selected > 0 if positive else selected >= 0)


def _validate_timebox_record(key: object, value: object) -> dict[str, Any]:
    expected = {
        "idempotency_sha256", "request_sha256", "operation_id", "principal",
        "tenant", "reason_sha256", "created_at", "updated_at", "release_at",
        "status", "generation", "lease_until", "attempts", "error_code",
    }
    if not isinstance(key, str) or not _valid_sha256(key):
        raise ValueError("timebox record key is invalid")
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("timebox record shape is invalid")
    if value.get("idempotency_sha256") != key or not _valid_sha256(
        value.get("request_sha256")
    ) or not _valid_sha256(value.get("reason_sha256")):
        raise ValueError("timebox record digest is invalid")
    operation_id = value.get("operation_id")
    if (
        not isinstance(operation_id, str)
        or not operation_id.startswith("tb-")
        or len(operation_id) != 27
        or not all(char in "0123456789abcdef" for char in operation_id[3:])
    ):
        raise ValueError("timebox operation id is invalid")
    if not valid_principal(value.get("principal")):
        raise ValueError("timebox principal is invalid")
    tenant = value.get("tenant")
    if (
        not isinstance(tenant, str)
        or len(tenant) > _MAX_PRINCIPAL
        or not tenant.isprintable()
    ):
        raise ValueError("timebox tenant is invalid")
    if not all(
        _valid_timebox_timestamp(value.get(name), positive=True)
        for name in ("created_at", "updated_at", "release_at")
    ) or not _valid_timebox_timestamp(value.get("lease_until"), positive=False):
        raise ValueError("timebox timestamp is invalid")
    if value.get("status") not in _TIMEBOX_STATUSES:
        raise ValueError("timebox status is invalid")
    generation = value.get("generation")
    if (
        not isinstance(generation, str)
        or len(generation) > 128
        or (generation and not generation.isalnum())
    ):
        raise ValueError("timebox containment generation is invalid")
    attempts = value.get("attempts")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 0 <= attempts <= 1000:
        raise ValueError("timebox attempt count is invalid")
    error_code = value.get("error_code")
    if (
        not isinstance(error_code, str)
        or len(error_code) > 80
        or not error_code.isascii()
        or any(
            char not in "abcdefghijklmnopqrstuvwxyz0123456789_-"  # pragma: allowlist secret
            for char in error_code
        )
    ):
        raise ValueError("timebox error code is invalid")
    return dict(value)


def _load_timebox_state(path) -> dict[str, Any]:
    from .file_lock import atomic_read_text, ensure_private_file

    try:
        if not path.exists():
            return _empty_timebox_state()
        ensure_private_file(path, 0o600)
        if path.stat().st_size > _MAX_TIMEBOX_STATE_BYTES:
            raise ValueError("timebox state exceeds capacity")
        raw = atomic_read_text(path, encoding="utf-8")
        if len(raw.encode("utf-8")) > _MAX_TIMEBOX_STATE_BYTES:
            raise ValueError("timebox state exceeds capacity")

        def _reject_constant(value: str):
            raise ValueError(f"non-finite number {value!r}")

        def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError("duplicate timebox state key")
                out[key] = value
            return out

        loaded = json.loads(
            raw,
            parse_constant=_reject_constant,
            object_pairs_hook=_object,
        )
        if not isinstance(loaded, dict) or set(loaded) != {"schema", "records"}:
            raise ValueError("timebox state shape is invalid")
        if loaded.get("schema") != _TIMEBOX_SCHEMA:
            raise ValueError("timebox state schema is invalid")
        records = loaded.get("records")
        if not isinstance(records, dict) or len(records) > _MAX_TIMEBOX_RECORDS:
            raise ValueError("timebox records are invalid")
        active_tenant = _active_tenant_scope()
        normalized_records = {
            str(key): _validate_timebox_record(key, value)
            for key, value in records.items()
        }
        if any(record["tenant"] != active_tenant for record in normalized_records.values()):
            raise ValueError("timebox record crosses the active tenant boundary")
        return {
            "schema": _TIMEBOX_SCHEMA,
            "records": normalized_records,
        }
    except ControlPlaneError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        log.warning("control_plane: timebox state unavailable", exc_info=True)
        raise ControlPlaneDependencyError("timeboxed containment records") from exc


def _save_timebox_state(path, state: dict[str, Any]) -> None:
    from .file_lock import atomic_write_text

    try:
        records = state.get("records") if isinstance(state, dict) else None
        if (
            state.get("schema") != _TIMEBOX_SCHEMA
            or not isinstance(records, dict)
            or len(records) > _MAX_TIMEBOX_RECORDS
        ):
            raise ValueError("timebox state is invalid")
        normalized = {
            "schema": _TIMEBOX_SCHEMA,
            "records": {
                str(key): _validate_timebox_record(key, value)
                for key, value in records.items()
            },
        }
        body = json.dumps(
            normalized,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(body.encode("utf-8")) > _MAX_TIMEBOX_STATE_BYTES:
            raise ValueError("timebox state exceeds capacity")
        atomic_write_text(path, body, mode=0o600, encoding="utf-8")
    except ControlPlaneError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        log.warning("control_plane: timebox state could not be saved", exc_info=True)
        raise ControlPlaneDependencyError("timeboxed containment records") from exc


def _mutate_timebox_state(callback):
    """Atomically mutate one tenant's private schedule state."""

    try:
        from .file_lock import cross_process_lock, ensure_private_directory

        path = _timebox_state_path()
        ensure_private_directory(path.parent)
        with cross_process_lock(path, strict=True):
            state = _load_timebox_state(path)
            result = callback(state)
            _save_timebox_state(path, state)
            return result
    except (ControlPlaneError, ValueError):
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        log.warning("control_plane: timebox mutation unavailable", exc_info=True)
        raise ControlPlaneDependencyError("timeboxed containment records") from exc


def _timebox_idempotency_sha256(tenant: str, key: str) -> str:
    return hashlib.sha256(
        f"lightwork.agent-control-plane.timebox-key.v1:{tenant}:{key}".encode()
    ).hexdigest()


def _timebox_request_sha256(
    *, tenant: str, principal: str, actor: str, reason: str, seconds: float,
) -> tuple[str, str]:
    reason_sha256 = hashlib.sha256(reason.encode("utf-8")).hexdigest()
    return _sha256_payload({
        "schema": "lightwork.agent-control-plane-timebox-request.v1",
        "tenant": tenant,
        "principal": principal,
        "actor_sha256": hashlib.sha256(actor.encode("utf-8")).hexdigest(),
        "reason_sha256": reason_sha256,
        "release_after_seconds": seconds,
    }), reason_sha256


def _timebox_marker(operation_id: str) -> str:
    return f"[timebox:{operation_id}]"


def _reserve_timebox(
    *, tenant: str, principal: str, request_sha256: str, reason_sha256: str,
    idempotency_sha256: str, seconds: float, now: float,
) -> tuple[str, dict[str, Any]]:
    """Reserve one idempotent arm operation before touching enforcement."""

    def _mutate(state: dict[str, Any]):
        records = state["records"]
        existing = records.get(idempotency_sha256)
        if existing is not None:
            if existing["request_sha256"] != request_sha256:
                raise ValueError(
                    "idempotency_key was already used for a different containment"
                )
            if existing["status"] == "arming":
                if float(existing["lease_until"]) > now:
                    return "in_progress", dict(existing)
                existing["lease_until"] = now + _TIMEBOX_LEASE_SECONDS
                existing["updated_at"] = now
                existing["attempts"] = int(existing["attempts"]) + 1
                return "claimed", dict(existing)
            return "existing", dict(existing)
        if len(records) >= _MAX_TIMEBOX_RECORDS:
            raise ControlPlaneError("timeboxed containment record capacity reached")
        operation_id = f"tb-{idempotency_sha256[:24]}"
        record = {
            "idempotency_sha256": idempotency_sha256,
            "request_sha256": request_sha256,
            "operation_id": operation_id,
            "principal": principal,
            "tenant": tenant,
            "reason_sha256": reason_sha256,
            "created_at": now,
            "updated_at": now,
            "release_at": now + seconds,
            "status": "arming",
            "generation": "",
            "lease_until": now + _TIMEBOX_LEASE_SECONDS,
            "attempts": 1,
            "error_code": "",
        }
        records[idempotency_sha256] = record
        return "claimed", dict(record)

    return _mutate_timebox_state(_mutate)


def _update_timebox(
    idempotency_sha256: str,
    callback,
) -> dict[str, Any]:
    def _mutate(state: dict[str, Any]):
        record = state["records"].get(idempotency_sha256)
        if record is None:
            raise ControlPlaneError("timeboxed containment record is missing")
        callback(record)
        return dict(record)

    return _mutate_timebox_state(_mutate)


def _finish_timebox(
    idempotency_sha256: str,
    *,
    status: str,
    now: float,
    generation: str | None = None,
    error_code: str = "",
) -> dict[str, Any]:
    if status not in _TIMEBOX_STATUSES:
        raise ValueError("invalid timebox status")

    def _finish(record: dict[str, Any]) -> None:
        # A concurrent manual release must not be overwritten by an old timer
        # worker that had already claimed this record.
        if record["status"] == "manually_released" and status != "manually_released":
            return
        record["status"] = status
        record["updated_at"] = now
        record["lease_until"] = 0.0
        record["error_code"] = error_code
        if generation is not None:
            record["generation"] = generation

    return _update_timebox(idempotency_sha256, _finish)


def _timebox_result(
    record: dict[str, Any],
    result: ControlResult,
) -> TimeboxedContainment:
    return TimeboxedContainment(
        operation_id=str(record["operation_id"]),
        principal=str(record["principal"]),
        tenant=str(record["tenant"]),
        containment_generation=str(record["generation"]),
        release_at=float(record["release_at"]),
        status=str(record["status"]),
        result=result,
    )


def _retire_timeboxes_after_manual_release(
    *, principal: str, generation: str, now: float,
) -> int:
    """Mark only the exact released containment; never touch a newer one."""

    if not generation:
        return 0
    # A deployment that never uses time-boxes must not gain a new state file
    # merely because it released an ordinary containment.
    if not _timebox_state_path().exists():
        return 0

    def _mutate(state: dict[str, Any]):
        retired = 0
        for record in state["records"].values():
            if (
                record["principal"] == principal
                and record["generation"] == generation
                and record["status"] in {"arming", "scheduled"}
            ):
                record["status"] = "manually_released"
                record["updated_at"] = now
                record["lease_until"] = 0.0
                record["error_code"] = ""
                retired += 1
        return retired

    return _mutate_timebox_state(_mutate)


# ---- verbs ------------------------------------------------------------------

def suspend(principal: str, *, reason: str, actor: str = "") -> ControlResult:
    """Revoke ``principal`` (reversible with :func:`resume`).

    Native: the next tool call under that principal is denied. External: the
    trust entry is marked revoked as well, so every surface refuses it.
    """
    _require_enabled("suspend")
    principal = _check_principal(principal)
    reason = _check_reason(reason)
    actor = _check_actor(actor)
    from .revocation import shared
    result = ControlResult("suspend", principal, ok=False)
    try:
        registry = shared()
        registry.revoke(principal, reason=f"{actor}: {reason}")
        landed = registry.is_revoked(principal)
        if not landed:
            result.detail = "revocation did not persist"
        elif is_external(principal) and not _set_trust_revoked(
                _external_id(principal), True, result.notes):
            result.detail = "capability revoked but the trust entry did not flip"
        else:
            result.ok = True
            result.detail = "revoked; the next tool call is denied"
    except Exception as exc:
        _dependency_failure(result, authority="revocation authority", exc=exc)
    return _audit_result(result, actor, reason)


def resume(principal: str, *, actor: str = "") -> ControlResult:
    """Lift an ordinary :func:`suspend`.

    A security containment is deliberately excluded; only :func:`release` may
    clear its durable protected revocation.
    """
    _require_enabled("resume")
    principal = _check_principal(principal)
    actor = _check_actor(actor)
    from .revocation import shared
    result = ControlResult("resume", principal, ok=False)
    try:
        registry = shared()
        if is_external(principal):
            agent_id = _external_id(principal)

            def _restore_trust() -> None:
                if not _set_trust_revoked(agent_id, False, result.notes):
                    raise RuntimeError("trust entry is still revoked")

            observed = registry.revoked().get(principal)
            if observed is None:
                # The trust overlay can be independently revoked. Guard its
                # restore with the same authority lock so a concurrent security
                # containment either refuses this callback or lands afterward
                # and re-applies the restrictive projection.
                registry.run_if_unprotected(principal, _restore_trust)
                result.notes.append("principal was not revoked")
            else:
                registry.unrevoke(principal, durable_clear=_restore_trust)
        elif not registry.unrevoke(principal):
            result.notes.append("principal was not revoked")
        if registry.is_revoked(principal):
            result.detail = "revocation is still in place"
        else:
            result.ok = True
            result.detail = "principal may act again"
    except Exception as exc:
        from .revocation import ProtectedRevocationError
        if isinstance(exc, ProtectedRevocationError):
            result.code = "protected_containment"
            result.detail = (
                "resume refused: principal is security-contained; use release"
            )
        else:
            _dependency_failure(result, authority="revocation authority", exc=exc)
    return _audit_result(result, actor, result.detail)


def contain(principal: str, *, reason: str, actor: str = "",
            registry: Any | None = None, edges: dict[str, Any] | None = None,
            ) -> ControlResult:
    """Incident response: the security plane's containment, from the console.

    Revokes the principal's whole capability subtree (``edges``) and seals it
    in the live swarm when a quarantine ``registry`` is supplied; an
    out-of-band call has none, and the result says so rather than implying a
    running agent stopped. External agents are also revoked in the trust
    registry. Undo with :func:`release`.
    """
    _require_enabled("contain")
    principal = _check_principal(principal)
    reason = _check_reason(reason)
    actor = _check_actor(actor)
    from .agent_edr import contain as edr_contain
    result = ControlResult("contain", principal, ok=False)
    try:
        def _apply_external_authorities() -> bool:
            if not is_external(principal):
                return True
            agent_id = _external_id(principal)
            if not _set_trust_revoked(agent_id, True, result.notes):
                result.detail = "capability contained but the trust entry did not flip"
                return False
            try:
                from .external_agents import contain as xa_contain
                from .external_agents import (
                    containment_state as xa_containment_state,
                )

                before = xa_containment_state(agent_id)
                if before is None:
                    result.notes.append("agent is not enrolled in the gateway")
                    return True
                landed = bool(xa_contain(agent_id, contained_by=actor))
                after = xa_containment_state(agent_id)
                if not landed or after is not True:
                    result.detail = "gateway containment did not persist"
                    return False
                return True
            except Exception:
                result.code = "dependency_unavailable"
                result.detail = "gateway containment authority is unavailable"
                return False

        outcome = edr_contain(principal, reason=f"{actor}: {reason}",
                              registry=registry, edges=edges,
                              durable_apply=_apply_external_authorities)
        result.notes.extend(outcome.notes)
        result.notes.extend(f"failed: {f}" for f in outcome.failed)
        result.ok = outcome.contained
        if result.ok:
            result.detail = f"contained; revoked {len(outcome.revoked)} principal(s)"
        elif not result.detail:
            result.detail = "containment incomplete"
    except Exception as exc:
        _dependency_failure(result, authority="containment authority", exc=exc)
    return _audit_result(result, actor, reason)


def _audit_timebox_result(
    timebox: TimeboxedContainment,
    *,
    actor: str,
    verb: str,
) -> TimeboxedContainment:
    """Emit only through the established CONTROL_PLANE_ACTION audit stream."""

    written = _audit(
        verb,
        timebox.principal,
        actor,
        timebox.result.ok,
        timebox.result.detail,
        timebox_id=timebox.operation_id,
        timebox_status=timebox.status,
        release_at=timebox.release_at,
    )
    if not written:
        timebox.result.notes.append("time-box control audit row was not written")
    return timebox


def contain_timeboxed(
    principal: str,
    *,
    reason: str,
    release_after_seconds: float,
    idempotency_key: str,
    actor: str = "",
) -> TimeboxedContainment:
    """Contain one principal and durably schedule a generation-bound release.

    The schedule is deliberately *not* stored in the revocation registry: a
    revocation remains fail-closed until a timer observes its exact protected
    generation. A crash after the protected revocation lands but before the
    schedule write is recoverable by the marker in that revocation; a timer can
    never release a later, unrelated containment.

    This bounded API has no subtree/edge option. A subtree has multiple
    protected generations and must be scheduled as separately reviewed rows,
    rather than pretending one root release clears all descendants.
    """

    _require_enabled("timeboxed-contain")
    principal = _check_principal(principal)
    reason = _check_reason(reason)
    actor = _check_actor(actor)
    seconds = _check_timebox_seconds(release_after_seconds)
    key = _check_timebox_idempotency_key(idempotency_key)
    tenant = _active_tenant_scope()
    key_sha256 = _timebox_idempotency_sha256(tenant, key)
    request_sha256, reason_sha256 = _timebox_request_sha256(
        tenant=tenant,
        principal=principal,
        actor=actor,
        reason=reason,
        seconds=seconds,
    )
    marker = _timebox_marker(f"tb-{key_sha256[:24]}")
    if len(reason) + len(marker) + 1 > _MAX_REASON:
        raise ValueError("reason is too long for a time-boxed containment marker")
    now = time.time()
    phase, record = _reserve_timebox(
        tenant=tenant,
        principal=principal,
        request_sha256=request_sha256,
        reason_sha256=reason_sha256,
        idempotency_sha256=key_sha256,
        seconds=seconds,
        now=now,
    )
    if phase == "in_progress":
        raise ControlPlaneError(
            "time-boxed containment with this idempotency_key is already in progress"
        )

    with _trace_control_operation(
        "agent_control_plane.timeboxed_contain",
        {
            "control_plane.operation": "timeboxed_contain",
            "control_plane.target_count": 1,
            "control_plane.tenant_bound": bool(tenant),
            "control_plane.idempotent_replay": phase == "existing",
        },
    ):
        if phase == "existing":
            status = str(record["status"])
            ok = status in {"scheduled", "released", "manually_released"}
            result = ControlResult(
                "contain",
                principal,
                ok=ok,
                code="idempotent_replay" if ok else status,
                detail=(
                    "time-boxed containment already recorded"
                    if ok else "prior time-boxed containment did not schedule a release"
                ),
            )
            return _audit_timebox_result(
                _timebox_result(record, result), actor=actor, verb="timebox-replay",
            )

        try:
            from .revocation import shared

            observed = shared().revoked().get(principal)
        except Exception:
            log.warning("control_plane: revocation authority unavailable", exc_info=True)
            result = ControlResult(
                "contain",
                principal,
                ok=False,
                code="dependency_unavailable",
                detail="revocation registry is unavailable",
            )
            return _audit_timebox_result(
                _timebox_result(record, result), actor=actor, verb="timebox-contain",
            )

        if (
            observed is not None
            and bool(getattr(observed, "protected", False))
            and marker in str(getattr(observed, "reason", ""))
        ):
            try:
                record = _finish_timebox(
                    key_sha256,
                    status="scheduled",
                    now=time.time(),
                    generation=str(getattr(observed, "generation", "")),
                )
                result = ControlResult(
                    "contain",
                    principal,
                    ok=True,
                    code="recovered",
                    detail="protected containment recovered; release is scheduled",
                )
            except ControlPlaneError:
                result = ControlResult(
                    "contain",
                    principal,
                    ok=False,
                    code="dependency_unavailable",
                    detail="containment remains protected; release schedule is unavailable",
                )
            return _audit_timebox_result(
                _timebox_result(record, result), actor=actor, verb="timebox-contain",
            )

        if observed is not None and bool(getattr(observed, "protected", False)):
            record = _finish_timebox(
                key_sha256,
                status="failed",
                now=time.time(),
                error_code="protected_containment",
            )
            result = ControlResult(
                "contain",
                principal,
                ok=False,
                code="protected_containment",
                detail="principal already has a separately protected containment",
            )
            return _audit_timebox_result(
                _timebox_result(record, result), actor=actor, verb="timebox-contain",
            )

        result = contain(
            principal,
            reason=f"{reason} {marker}",
            actor=actor,
        )
        if not result.ok:
            record = _finish_timebox(
                key_sha256,
                status="failed",
                now=time.time(),
                error_code="containment_failed",
            )
            return _audit_timebox_result(
                _timebox_result(record, result), actor=actor, verb="timebox-contain",
            )

        try:
            from .revocation import shared

            landed = shared().revoked().get(principal)
            if (
                landed is None
                or not bool(getattr(landed, "protected", False))
                or marker not in str(getattr(landed, "reason", ""))
                or not str(getattr(landed, "generation", ""))
            ):
                raise ControlPlaneError("time-boxed containment could not be verified")
            record = _finish_timebox(
                key_sha256,
                status="scheduled",
                now=time.time(),
                generation=str(getattr(landed, "generation", "")),
            )
            result.detail = "contained; durable automatic release is scheduled"
        except Exception:
            # The protected containment is intentionally left live. Its durable
            # arming record and marker let the same idempotency key recover a
            # schedule later instead of re-containing or widening access.
            result.ok = False
            result.code = "schedule_unavailable"
            result.detail = "containment remains protected; release schedule is unavailable"
        return _audit_timebox_result(
            _timebox_result(record, result), actor=actor, verb="timebox-contain",
        )


def release(principal: str, *, actor: str = "", registry: Any | None = None,
            ) -> ControlResult:
    """Undo a :func:`contain`: unrevoke, unseal, and (external) lift the
    gateway's containment and the trust revocation."""
    _require_enabled("release")
    principal = _check_principal(principal)
    actor = _check_actor(actor)
    from .agent_edr import release as edr_release
    result = ControlResult("release", principal, ok=False)
    released_generation = ""
    try:
        # Remember the protected generation before the EDR's CAS release. If
        # this succeeds, only its matching timebox may be retired; a timer for
        # a newer containment must remain armed (and the EDR refuses its
        # release in the first place).
        try:
            from .revocation import shared

            observed = shared().revoked().get(principal)
            if observed is not None and bool(getattr(observed, "protected", False)):
                released_generation = str(getattr(observed, "generation", ""))
        except Exception:
            # ``edr_release`` is the authoritative operation and will surface
            # a stable dependency failure itself. Do not turn this bookkeeping
            # observation into a path that can widen a containment.
            released_generation = ""

        def _clear_external_authorities() -> None:
            if not is_external(principal):
                return
            agent_id = _external_id(principal)

            # This callback runs inside the protected revocation CAS lock.
            # Clear the trust projection first; if the gateway cannot then be
            # confirmed clear, restore every restrictive projection before
            # returning an error and retaining the protected revocation row.
            if not _set_trust_revoked(agent_id, False, result.notes):
                _set_trust_revoked(agent_id, True, result.notes)
                result.detail = "trust release did not persist"
                raise RuntimeError("dependent trust release did not persist")

            gateway_enrolled = False
            try:
                from .external_agents import contain as xa_contain
                from .external_agents import (
                    containment_state as xa_containment_state,
                )
                from .external_agents import release as xa_release

                before = xa_containment_state(agent_id)
                if before is None:
                    result.notes.append("agent is not enrolled in the gateway")
                    return
                gateway_enrolled = True
                landed = bool(xa_release(agent_id, released_by=actor))
                after = xa_containment_state(agent_id)
                if not landed or after is not False:
                    raise RuntimeError("dependent gateway release did not persist")
            except Exception:
                result.detail = "gateway release did not persist"
                if not _set_trust_revoked(agent_id, True, result.notes):
                    result.notes.append("failed to restore the restrictive trust projection")
                if gateway_enrolled:
                    try:
                        restored = bool(xa_contain(agent_id, contained_by=actor))
                        if not restored or xa_containment_state(agent_id) is not True:
                            result.notes.append(
                                "failed to restore the restrictive gateway projection"
                            )
                    except Exception:
                        result.notes.append(
                            "gateway compensation was unavailable; durable capability "
                            "containment remains in place"
                        )
                raise RuntimeError("dependent containment release failed") from None

        outcome = edr_release(
            principal,
            registry=registry,
            durable_clear=_clear_external_authorities,
        )
        result.notes.extend(outcome.notes)
        result.notes.extend(f"failed: {f}" for f in outcome.failed)
        result.ok = outcome.contained  # "no failures" in Containment terms
        if outcome.superseded:
            result.code = "concurrent_containment"
            result.detail = "release superseded; newer containment retained"
        elif result.ok:
            result.detail = "released"
        elif not result.detail:
            result.detail = "release incomplete"
    except Exception as exc:
        _dependency_failure(result, authority="containment authority", exc=exc)
    if result.ok and released_generation:
        try:
            retired = _retire_timeboxes_after_manual_release(
                principal=principal,
                generation=released_generation,
                now=time.time(),
            )
            if retired:
                result.notes.append("retired matching time-boxed release record")
        except Exception:
            # The protected revocation has already been safely released. A
            # later timer sees the absent containment and marks the schedule
            # manual rather than ever recreating or widening authority.
            result.notes.append(
                "time-box record retirement unavailable; timer will verify state"
            )
    return _audit_result(result, actor, result.detail)


def timeboxed_containments() -> list[dict[str, Any]]:
    """Read the active tenant's durable time-box records, earliest first."""

    _active_tenant_scope()  # resolve storage boundary strictly before reading
    path = _timebox_state_path()
    if not path.exists():
        return []
    state = _load_timebox_state(path)
    return [
        dict(record)
        for record in sorted(
            state["records"].values(),
            key=lambda record: (float(record["release_at"]), record["operation_id"]),
        )
    ]


def _claim_due_timeboxes(*, now: float, limit: int) -> list[dict[str, Any]]:
    path = _timebox_state_path()
    if not path.exists():
        return []

    def _claim(state: dict[str, Any]):
        selected: list[dict[str, Any]] = []
        records = sorted(
            state["records"].values(),
            key=lambda record: (float(record["release_at"]), record["operation_id"]),
        )
        for record in records:
            if len(selected) >= limit or float(record["release_at"]) > now:
                break
            stale_lease = (
                record["status"] == "releasing"
                and float(record["lease_until"]) <= now
            )
            if record["status"] != "scheduled" and not stale_lease:
                continue
            record["status"] = "releasing"
            record["lease_until"] = now + _TIMEBOX_LEASE_SECONDS
            record["updated_at"] = now
            record["attempts"] = int(record["attempts"]) + 1
            selected.append(dict(record))
        return selected

    return _mutate_timebox_state(_claim)


def _retry_timebox_release(
    idempotency_sha256: str,
    *, now: float, error_code: str,
) -> dict[str, Any]:
    def _retry(record: dict[str, Any]) -> None:
        if record["status"] == "releasing":
            record["status"] = "scheduled"
            record["lease_until"] = 0.0
            record["updated_at"] = now
            record["error_code"] = error_code

    return _update_timebox(idempotency_sha256, _retry)


def sweep_timeboxed_releases(
    *,
    now: float | None = None,
    actor: str = "",
    limit: int = _MAX_BULK_TARGETS,
) -> list[ControlResult]:
    """Release due schedules only when their protected generation still wins.

    This is scheduler-safe but intentionally does not create a scheduler. A
    deployment's existing job runner can invoke it per active tenant. A timer
    outage is fail-closed: containment remains protected and its durable row is
    retried after its short worker lease expires.
    """

    _require_enabled("timeboxed-release-sweep")
    actor = _check_actor(actor)
    selected_now = time.time() if now is None else now
    if not _valid_timebox_timestamp(selected_now, positive=True):
        raise ValueError("now must be a positive finite timestamp")
    selected_now = float(selected_now)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_BULK_TARGETS:
        raise ValueError(f"limit must be an integer between 1 and {_MAX_BULK_TARGETS}")
    _active_tenant_scope()
    claimed = _claim_due_timeboxes(now=selected_now, limit=limit)
    results: list[ControlResult] = []
    with _trace_control_operation(
        "agent_control_plane.timeboxed_release_sweep",
        {
            "control_plane.operation": "timeboxed_release_sweep",
            "control_plane.due_count": len(claimed),
            "control_plane.tenant_bound": bool(_active_tenant_scope()),
        },
    ):
        for record in claimed:
            principal = str(record["principal"])
            key_sha256 = str(record["idempotency_sha256"])
            generation = str(record["generation"])
            try:
                from .revocation import shared

                observed = shared().revoked().get(principal)
            except Exception:
                result = ControlResult(
                    "timebox-release",
                    principal,
                    ok=False,
                    code="dependency_unavailable",
                    detail="revocation registry is unavailable",
                )
                try:
                    record = _retry_timebox_release(
                        key_sha256,
                        now=selected_now,
                        error_code="dependency_unavailable",
                    )
                except ControlPlaneError:
                    result.notes.append("release schedule retry record is unavailable")
                results.append(
                    _audit_timebox_result(
                        _timebox_result(record, result),
                        actor=actor,
                        verb="timebox-release",
                    ).result
                )
                continue

            if observed is None:
                record = _finish_timebox(
                    key_sha256,
                    status="manually_released",
                    now=selected_now,
                )
                result = ControlResult(
                    "timebox-release",
                    principal,
                    ok=True,
                    code="already_released",
                    detail="containment was already manually released",
                )
            elif (
                not bool(getattr(observed, "protected", False))
                or str(getattr(observed, "generation", "")) != generation
            ):
                record = _finish_timebox(
                    key_sha256,
                    status="superseded",
                    now=selected_now,
                    error_code="superseded",
                )
                result = ControlResult(
                    "timebox-release",
                    principal,
                    ok=False,
                    code="superseded",
                    detail="time-boxed release retained a newer or nonmatching containment",
                )
            else:
                result = release(principal, actor=actor)
                result.verb = "timebox-release"
                if result.ok:
                    record = _finish_timebox(
                        key_sha256,
                        status="released",
                        now=selected_now,
                    )
                elif result.code == "concurrent_containment":
                    record = _finish_timebox(
                        key_sha256,
                        status="superseded",
                        now=selected_now,
                        error_code="superseded",
                    )
                else:
                    try:
                        record = _retry_timebox_release(
                            key_sha256,
                            now=selected_now,
                            error_code="release_failed",
                        )
                    except ControlPlaneError:
                        result.notes.append("release schedule retry record is unavailable")
            results.append(
                _audit_timebox_result(
                    _timebox_result(record, result),
                    actor=actor,
                    verb="timebox-release",
                ).result
            )
    return results


# ---- snapshot-pinned fleet actions -------------------------------------------

_BULK_VERBS = frozenset({"suspend", "resume", "contain", "release"})


def _derived_bulk_timebox_key(root_key: str, principal: str) -> str:
    """Derive a stable per-principal key without persisting the caller key."""

    digest = hashlib.sha256(
        f"lightwork.agent-control-plane.bulk-timebox.v1:{root_key}:{principal}".encode()
    ).hexdigest()
    return f"bulk-{digest}"


def _bulk_failure_result(
    *, verb: str, principal: str, actor: str, code: str,
) -> ControlResult:
    result = ControlResult(
        verb,
        principal,
        ok=False,
        code=code,
        detail="bulk action could not be applied",
    )
    return _audit_result(result, actor, result.detail)


def bulk_action(
    selection: BulkSelection,
    *,
    verb: str,
    actor: str = "",
    reason: str | None = None,
    release_after_seconds: float | None = None,
    idempotency_key: str | None = None,
) -> BulkControlResult:
    """Apply one safe verb to an exact, freshly revalidated fleet selection.

    Results are intentionally per-principal rather than a synthetic all-good
    response. An interruption or dependency error leaves restrictive state in
    place and exposes precisely which rows require a new reviewed selection.
    Timed containment requires an idempotency key and stores one durable,
    recoverable release record per target.
    """

    if not isinstance(verb, str) or verb not in _BULK_VERBS:
        raise ValueError(
            "bulk verb must be one of " + ", ".join(sorted(_BULK_VERBS))
        )
    _require_enabled(f"bulk-{verb}")
    actor = _check_actor(actor)
    requires_reason = verb in {"suspend", "contain"}
    selected_reason = _check_reason(reason) if requires_reason else None
    if not requires_reason and reason is not None:
        raise ValueError(f"bulk {verb} does not accept a reason")
    if release_after_seconds is not None and verb != "contain":
        raise ValueError("release_after_seconds applies only to bulk contain")
    selected_seconds: float | None = None
    root_key: str | None = None
    if release_after_seconds is not None:
        selected_seconds = _check_timebox_seconds(release_after_seconds)
        if idempotency_key is None:
            raise ValueError("time-boxed bulk containment requires idempotency_key")
        root_key = _check_timebox_idempotency_key(idempotency_key)
    elif idempotency_key is not None:
        raise ValueError("idempotency_key applies only to time-boxed bulk containment")

    # Never use the supplied object as a live wildcard. This fresh scan checks
    # both the complete state digest and the exact membership before any row
    # reaches the existing containment/revocation authority.
    _refresh_bulk_selection(selection)
    results: list[ControlResult] = []
    with _trace_control_operation(
        "agent_control_plane.bulk_action",
        {
            "control_plane.operation": "bulk_action",
            "control_plane.verb": verb,
            "control_plane.target_count": len(selection.principals),
            "control_plane.platform_selected": bool(selection.platform),
            "control_plane.tenant_bound": bool(selection.tenant),
            "control_plane.timeboxed": selected_seconds is not None,
        },
    ):
        for principal in selection.principals:
            try:
                if verb == "suspend":
                    result = suspend(
                        principal,
                        reason=selected_reason or "",
                        actor=actor,
                    )
                elif verb == "resume":
                    result = resume(principal, actor=actor)
                elif verb == "release":
                    result = release(principal, actor=actor)
                elif selected_seconds is not None:
                    timebox = contain_timeboxed(
                        principal,
                        reason=selected_reason or "",
                        release_after_seconds=selected_seconds,
                        idempotency_key=_derived_bulk_timebox_key(
                            root_key or "", principal,
                        ),
                        actor=actor,
                    )
                    result = timebox.result
                else:
                    result = contain(
                        principal,
                        reason=selected_reason or "",
                        actor=actor,
                    )
            except (KeyboardInterrupt, SystemExit):
                raise
            except ControlPlaneDisabled:
                raise
            except Exception as exc:
                from .audit import AuditRefused

                if isinstance(exc, AuditRefused):
                    raise
                log.warning(
                    "control_plane: bulk %s failed for one principal",
                    verb,
                    exc_info=True,
                )
                result = _bulk_failure_result(
                    verb=verb,
                    principal=principal,
                    actor=actor,
                    code="action_error",
                )
            results.append(result)
    summary = BulkControlResult(
        verb=verb,
        selection=selection,
        results=results,
        ok=bool(results) and all(result.ok for result in results),
    )
    summary.audit_written = _audit(
        f"bulk-{verb}",
        "*",
        actor,
        summary.ok,
        f"bulk {verb} completed for {len(results)} reviewed principal(s)",
        selection_sha256=selection.snapshot_sha256,
        target_count=len(results),
        platform=selection.platform or "",
        timeboxed=selected_seconds is not None,
    )
    if not summary.audit_written:
        summary.notes.append("bulk control audit row was not written")
    return summary


def attenuate(principal: str, *, deny_tools: Any = (), max_risk: str | None = None,
              max_dollars: float | None = None, max_wall_seconds: float | None = None,
              actor: str = "") -> ControlResult:
    """Narrow an EXTERNAL agent's ceiling in the trust registry. Never widens:
    a request that would raise a risk cap, lift a budget, or drop a denied tool
    is refused whole. Native runs have no persistent per-principal ceiling
    (their grant is minted from ``[capabilities]`` at goal start), so they are
    refused here rather than silently ignored."""
    _require_enabled("attenuate")
    principal = _check_principal(principal)
    actor = _check_actor(actor)
    if not is_external(principal):
        raise ValueError("attenuate applies to external agents (`agent:<id>`) only")
    agent_id = _external_id(principal)
    from .agent_trust import AgentTrustError, attenuate_agent
    result = ControlResult("attenuate", principal, ok=False)
    changed: dict[str, Any] | None = None
    try:
        after, created_overlay = attenuate_agent(
            agent_id,
            deny_tools=deny_tools,
            max_risk=max_risk,
            max_dollars=max_dollars,
            max_wall_seconds=max_wall_seconds,
        )
        if created_overlay:
            result.notes.append("trust entry is config-defined; wrote a managed overlay")
        result.ok = True
        result.detail = "ceiling narrowed"
        changed = {
            "deny_tools": sorted(after.deny_tools),
            "max_risk": after.max_risk,
            "max_dollars": after.max_dollars,
            "max_wall_seconds": after.max_wall_seconds,
        }
    except AgentTrustError as exc:
        message = str(exc)
        if "not in the trust registry" in message:
            raise LookupError(
                f"{principal} is not in the trust registry"
            ) from exc
        safe_request_prefixes = (
            "attenuation requires ",
            "attenuation request does not tighten ",
            "deny_tools ",
            "max_risk ",
            "max_dollars ",
            "max_wall_seconds ",
        )
        if message.startswith(safe_request_prefixes):
            raise ValueError(message) from exc
        _dependency_failure(result, authority="agent trust authority", exc=exc)
    except Exception as exc:
        _dependency_failure(result, authority="agent trust authority", exc=exc)
    extra = {"ceiling": changed} if changed is not None else {}
    return _audit_result(result, actor, result.detail, **extra)


def halt_all(reason: str, *, actor: str = "") -> ControlResult:
    """Arm this deployment's durable local HALT file and verify it.

    This is intentionally not described as cluster-wide. Replicas on other
    hosts need their own shared halt authority; the dashboard uses that hardened
    shared API rather than this local CLI primitive.
    """
    _require_enabled("halt")
    return halt_local(reason, actor=actor)


def halt_local(reason: str, *, actor: str = "") -> ControlResult:
    """Arm the local emergency stop without requiring the optional control plane.

    The basic CLI must remain available on a new installation.  Both CLI
    entrypoints use this same locked, private, audited local authority.
    """
    reason = _check_reason(reason)
    actor = _check_actor(actor)
    from . import killswitch
    result = ControlResult("halt", "*", ok=False)
    try:
        from .file_lock import (
            atomic_write_text,
            cross_process_lock,
            prepare_private_directory,
        )
        path = killswitch._halt_file_path()
        # ``MAVERICK_HALT_FILE`` is caller-selected.  Never seize an existing
        # shared parent by rewriting its ACL; only create a missing dedicated
        # directory or require an existing parent that is already private.
        prepare_private_directory(path.parent)
        with cross_process_lock(
            killswitch._halt_authority_lock_path(path), strict=True,
        ):
            payload = json.dumps({
                "reason": reason,
                "source": f"control_plane:{actor}",
                "created_at": time.time(),
                "generation": secrets.token_urlsafe(24),
                "scope": "local-deployment",
            }, sort_keys=True)
            atomic_write_text(path, payload, mode=0o600)
            result.ok = bool(
                killswitch._halt_file_generation(path) is not None
                and killswitch._file_halt_active(
                    min_interval=0.0, fail_closed=True,
                )
            )
        result.detail = (
            "durable local HALT file armed"
            if result.ok else "local HALT file did not take effect"
        )
    except Exception as exc:
        _dependency_failure(result, authority="local HALT authority", exc=exc)
    return _audit_result(
        result, actor, reason, scope="local-deployment",
        outcome_detail=result.detail, _global=True,
    )


def clear_halt(*, actor: str = "") -> ControlResult:
    """Clear and verify this deployment's local HALT file/process state."""
    _require_enabled("clear-halt")
    return clear_local_halt(actor=actor)


def clear_local_halt(
    *, actor: str = "", reason: str = "manual clear",
) -> ControlResult:
    """Clear only the observed local HALT generation under the strict lock."""
    reason = _check_reason(reason)
    actor = _check_actor(actor)
    from . import killswitch
    result = ControlResult("clear-halt", "*", ok=False)
    # Clearing expands authority. Require a deployment-global intent record
    # before touching either the durable file or the in-process stop. A strict
    # signing/custody refusal must leave the emergency stop in place.
    if not _audit(
        "clear-halt-request", "*", actor, False, reason,
        scope="local-deployment", phase="intent", _global=True,
    ):
        result.code = "audit_unavailable"
        result.detail = "local HALT was not cleared because audit is unavailable"
        result.audit_written = False
        return result
    try:
        from .file_lock import cross_process_lock, require_private_directory

        path = killswitch._halt_file_path()
        # Snapshot the generation before waiting for the writer lock.  An arm
        # that overlaps this clear either changes the generation before we get
        # the lock (and is retained) or publishes after we release it (and is
        # retained).  A clear may delete only the exact generation it observed.
        require_private_directory(path.parent)
        expected_generation = killswitch._halt_file_generation(path)
        expected_process_generation = killswitch._in_process_halt_generation()
        with cross_process_lock(
            killswitch._halt_authority_lock_path(path), strict=True,
        ):
            if killswitch._halt_file_generation(path) != expected_generation:
                raise _ConcurrentHalt

            def _delete_expected_generation() -> None:
                if killswitch._halt_file_generation(path) != expected_generation:
                    raise _ConcurrentHalt
                if expected_generation is not None:
                    path.unlink()

            # Clearing expands authority.  The exact-generation unlink runs
            # inside the strict process barrier; any failure leaves both the
            # durable file and the in-process halt unchanged.
            killswitch.clear(
                durable_clear=_delete_expected_generation,
                expected_in_process_generation=expected_process_generation,
            )
        result.ok = not killswitch._file_halt_active(
            min_interval=0.0, fail_closed=True,
        )
        result.detail = (
            "local HALT file cleared"
            if result.ok else "local HALT file is still active"
        )
        if result.ok and killswitch.is_active():
            result.notes.append(
                "local HALT cleared; another halt authority remains active"
            )
    except (killswitch.HaltGenerationChanged, _ConcurrentHalt):
        result.code = "concurrent_halt"
        result.detail = "newer local HALT generation remains armed"
    except Exception as exc:
        _dependency_failure(result, authority="local HALT authority", exc=exc)
    return _audit_result(
        result, actor, reason, scope="local-deployment",
        outcome_detail=result.detail, _global=True,
    )


# ---- read-side ----------------------------------------------------------------

def ledger(principal: str, *, since: float | None = None, limit: int = 50) -> list[dict]:
    """The principal's recorded forensic timeline, newest last.

    Whether individual audit rows are signed is deployment/evidence metadata,
    not implied by this convenience view.
    """
    principal = _check_principal(principal)
    from .agent_edr import timeline
    rows = timeline(principal, since=since)
    return [d.to_dict() for d in rows[-max(1, int(limit)):]]


def _strict_halt_active() -> bool:
    """Return current halt state or refuse an unreadable halt authority."""

    from . import killswitch

    try:
        killswitch.check(force_refresh=True, fail_closed=True)
    except killswitch.Halted as exc:
        if exc.source in {"file-error", "shared-error"}:
            raise ControlPlaneDependencyError("halt") from exc
        return True
    except Exception as exc:
        raise ControlPlaneDependencyError("halt") from exc
    return False


def status(*, source: ControlPlaneSnapshot | None = None) -> dict:
    """Console header derived from one reusable authority snapshot."""
    view = source if source is not None else snapshot()
    rows = roster(source=view)
    native = [r for r in rows if r.kind == KIND_NATIVE]
    external = [r for r in rows if r.kind == KIND_EXTERNAL]
    out: dict[str, Any] = {
        "schema": "lightwork.agent-control-plane-status.v1",
        "captured_at": view.captured_at,
        "enabled": enabled(strict=True),
        "halted": _strict_halt_active(),
        "halt_scope": "observed-process-and-configured-authorities",
        "native": {"principals": len(native),
                   "running_goals": sum(r.running_goals for r in native),
                   "suspended": sum(1 for r in native if r.revoked and not r.contained),
                   "contained": sum(1 for r in native if r.contained)},
        "external": {"agents": len(external),
                     "active": sum(1 for r in external if r.state == "active"),
                     "suspended": sum(
                         1 for r in external if r.revoked and not r.contained
                     ),
                     "contained": sum(1 for r in external if r.contained)},
    }
    try:
        from .agent_trust import agent_trust_enforced
        out["trust_enforced"] = bool(agent_trust_enforced())
    except Exception as exc:
        raise ControlPlaneDependencyError("agent trust policy") from exc
    try:
        from .external_agents import enabled as xa_enabled
        out["external_agents_enabled"] = bool(xa_enabled())
    except Exception:
        out["external_agents_enabled"] = False
    try:
        from .agent_edr import posture
        out["posture"] = posture().to_dict()
    except Exception:
        out["posture"] = {}
    return out


__all__ = [
    "AgentPrincipal",
    "BulkControlResult",
    "BulkSelection",
    "ControlPlaneDisabled",
    "ControlPlaneDependencyError",
    "ControlPlaneError",
    "ControlPlaneSnapshot",
    "ControlPlaneStaleSelection",
    "ControlResult",
    "KIND_EXTERNAL",
    "KIND_NATIVE",
    "attenuate",
    "bulk_action",
    "clear_halt",
    "contain",
    "contain_timeboxed",
    "enabled",
    "halt_all",
    "is_external",
    "ledger",
    "lookup",
    "release",
    "resume",
    "roster",
    "snapshot",
    "status",
    "suspend",
    "sweep_timeboxed_releases",
    "select_bulk",
    "timeboxed_containments",
    "valid_principal",
]
