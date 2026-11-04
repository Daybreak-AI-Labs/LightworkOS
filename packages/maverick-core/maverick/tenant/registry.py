"""Tenant lifecycle / provisioning registry — the hosted control plane's roster.

A :class:`Workspace` isolates one tenant's *data*; this registry is the
*operator's* record of which tenants exist, their status (active / suspended),
plan, and per-tenant quota. It lives at the **un-namespaced** root
(``<home>/tenant_registry.json``, ``tenant=None``) because it is cross-tenant
control-plane state, not any one tenant's data.

Lifecycle: ``create`` → ``suspend`` / ``resume`` → ``delete`` (optionally
purging the tenant's data dir). :func:`assert_tenant_active` is the enforcement
hook a request path calls before doing work for a tenant, so a suspended tenant
is refused. Identifiers are never recycled: namespace reservations and
deletion history outlive the roster and optional data purge. Before any
registry or deletion history exists, single-tenant and unprovisioned deployments
retain their existing behavior.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, field, replace

from ..file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from ..paths import (
    _tenant_namespace_key,
    _tenant_segment,
    bind_tenant_namespace,
    canonical_tenant_id,
    maverick_home,
    tenant_namespace_reserved,
)

log = logging.getLogger(__name__)


def _warn_if_unknown_plan(plan: str) -> str | None:
    """Warn (and return the message) if ``plan`` is not a known billing plan.

    ``billing.entitlements_for`` silently resolves an unknown plan to the
    ``free`` entitlements, so an operator who typos ``--plan pro`` would think a
    tenant is paid when it is not. We warn rather than raise so a plan can be
    pre-assigned before it is defined in ``[billing.plans]``."""
    p = str(plan or "free")
    try:
        from ..billing import known_plan_names
        known = known_plan_names()
    except Exception:  # pragma: no cover -- never block provisioning on billing
        return None
    if p in known:
        return None
    msg = (f"plan {p!r} is not a known billing plan "
           f"({', '.join(sorted(known))}); its entitlements fall back to 'free' "
           f"until it is defined in [billing.plans]")
    log.warning("tenant registry: %s", msg)
    return msg

ACTIVE = "active"
SUSPENDED = "suspended"
_STATUSES = frozenset({ACTIVE, SUSPENDED})

# Billing (payment) status, distinct from the lifecycle ``status`` above: this
# tracks whether the tenant's Stripe subscription/invoices are being paid. It is
# flipped by :mod:`maverick.billing_stripe`'s webhook handler and consulted by
# :func:`maverick.billing.tenant_entitled` -- a ``past_due`` tenant is served the
# base ("free") entitlement tier without losing its subscribed ``plan`` (so a
# ``payment_succeeded`` webhook can restore it). ``current`` is the default and
# the state of every tenant provisioned before Stripe billing exists.
BILLING_CURRENT = "current"
BILLING_PAST_DUE = "past_due"
_BILLING_STATUSES = frozenset({BILLING_CURRENT, BILLING_PAST_DUE})

# A newly provisioned tenant has no daily spend cap unless one is chosen
# (``0`` means no cap). Administrators set workspace and per-person limits in
# Admin > Spending limits (maverick.spending_limits) or a daily cap here.
DEFAULT_TENANT_DAILY_DOLLARS = 0.0

# Upper bound on each per-tenant feature-override list. A control-plane roster
# edited by an operator should never carry an unbounded blob; a plan has only a
# handful of features and the catalog a few dozen, so 200 is generous headroom
# while keeping the record small.
MAX_FEATURE_OVERRIDES = 200

# Serializes the roster load-modify-save across threads in this process; the
# cross_process_lock below extends that across processes (the registry is edited
# from both the CLI and the dashboard, which are separate processes).
_REGISTRY_LOCK = threading.Lock()

# Serializes the in-flight reservations load-modify-save (a separate file from
# the roster, so a separate lock: reserving a run's dollars must not contend
# with a suspend/set_quota roster edit). Cross-process flock on the sidecar
# extends it across the CLI / dashboard / serve processes.
_RESERVE_LOCK = threading.Lock()


class TenantSuspended(PermissionError):
    """Raised when work is attempted for a suspended (or deleted) tenant."""


class UnknownTenant(KeyError):
    """Raised when an operation targets a tenant that was never provisioned."""


class TenantRegistryError(RuntimeError):
    """Tenant control-plane state exists but cannot be trusted."""


class DuplicateWorkspaceName(ValueError):
    """The requested visible name was refused before tenant publication."""


def _registry_path():
    return maverick_home() / "tenant_registry.json"


def _retirement_path(tenant_id: str):
    key = _tenant_namespace_key(tenant_id)
    return maverick_home() / ".tenant-deletions" / (hashlib.sha256(key.encode("ascii")).hexdigest() + ".json")


def _retirement(tenant_id: str) -> dict | None:
    from ..file_lock import ensure_private_file
    path = _retirement_path(tenant_id)
    if not path.exists():
        return None
    try:
        ensure_private_file(path)
        value = _decode_json(atomic_read_text(path), label="tenant deletion tombstone")
        if (not isinstance(value, dict) or value.get("version") not in (1, 2)
                or not isinstance(value.get("id"), str)
                or _tenant_namespace_key(value["id"]) != _tenant_namespace_key(tenant_id)
                or value["id"] != canonical_tenant_id(value["id"])):
            raise ValueError("invalid deletion identity")
        when = value.get("deleted_at")
        if not isinstance(when, (int, float)) or not math.isfinite(when) or when < 0:
            raise ValueError("invalid deletion time")
        if value["version"] == 2:
            saved = TenantRecord.from_dict(value.get("record"))
            if (saved.id != value["id"] or value.get("state") not in ("removed", "restored")
                    or type(value.get("purged")) is not bool):
                raise ValueError("invalid deletion record")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise TenantRegistryError("Tenant deletion history is unavailable; provisioning and admission are refused.") from exc
    return value


def _retired(tenant_id: str) -> bool:
    value = _retirement(tenant_id)
    return value is not None and value.get("state", "removed") == "removed"


def tenant_retired(tenant_id: str) -> bool:
    """Public read gate for role stores outside the core package."""
    return _retired(_lookup_id(tenant_id))


def _retire(tenant_id: str, record: TenantRecord, *, purge: bool) -> None:
    from ..file_lock import atomic_create_text
    path = _retirement_path(tenant_id)
    previous = _retirement(tenant_id)
    if previous is not None and previous.get("state", "removed") == "removed":
        return
    ensure_private_directory(path.parent)
    value = {
        "version": 2, "id": tenant_id, "deleted_at": time.time(),
        "state": "removed", "purged": purge, "record": record.to_dict(),
    }
    payload = json.dumps(value, sort_keys=True)
    if previous is not None:
        atomic_write_text(path, payload)
    else:
        try:
            atomic_create_text(path, payload)
        except FileExistsError:
            _retirement(tenant_id)  # validate the concurrent winner


def _legacy_role_names() -> set[str]:
    """Orphan global membership keys are history, never fresh ownership proof.

    Kept in core so CLI and SCIM cannot bypass the dashboard migration boundary;
    no dashboard package dependency or membership mutation is introduced.
    """
    from ..file_lock import ensure_private_file
    path = maverick_home() / "dashboard-tenant-roles.json"
    if not path.exists():
        # The dashboard records that memberships existed; their loss is not a
        # clean history (maverick_dashboard.rbac presence marker).
        if os.path.lexists(path.with_name(path.name + ".present")):
            raise TenantRegistryError("Legacy workspace membership history is unavailable; new provisioning is refused.")
        return set()
    try:
        ensure_private_file(path)
        value = _decode_json(atomic_read_text(path), label="legacy tenant memberships")
        if not isinstance(value, dict) or any(not isinstance(members, dict) for members in value.values()):
            raise ValueError("invalid membership inventory")
        return {_tenant_namespace_key(name) for name in value}
    except (OSError, ValueError, TypeError) as exc:
        raise TenantRegistryError("Legacy workspace membership history is unavailable; new provisioning is refused.") from exc


@dataclass(frozen=True)
class TenantRecord:
    """One provisioned tenant."""

    id: str
    status: str = ACTIVE
    plan: str = "free"
    display_name: str = ""
    # Per-tenant aggregate spend cap (USD/day); 0 = unlimited (defer to global).
    max_daily_dollars: float = 0.0
    created_at: float = 0.0
    updated_at: float = 0.0
    # Stripe customer id for platform billing (maverick.billing_stripe), stored
    # once created so the customer is looked up, not re-created. Empty = the
    # tenant has never been synced to Stripe. Not a secret (a ``cus_...`` handle).
    stripe_customer_id: str = ""
    # Payment state (see BILLING_CURRENT / BILLING_PAST_DUE). Never a secret.
    billing_status: str = BILLING_CURRENT
    # Bring-your-own-key opt-in: when true (and the deployment enabled
    # [providers] per_tenant_keys), this tenant runs on its OWN provider API key,
    # resolved from the secret provider under a tenant-scoped name -- NOT stored
    # here. Just a flag; the key bytes never touch the registry. Off => the
    # tenant uses the deployment-global provider key (unchanged behavior).
    byok: bool = False
    # Per-tenant feature overrides layered ON TOP of the plan's entitlements:
    # ``{"add": [feature, ...], "remove": [feature, ...]}`` (empty ``{}`` when
    # unused). ``add`` grants features the plan lacks; ``remove`` revokes plan
    # features. Resolved by :func:`maverick.billing.effective_features`
    # (precedence: ``(plan | add) - remove``). Kept out of the serialized record
    # entirely when empty, so tenants that never override stay byte-identical.
    feature_overrides: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "id": self.id, "status": self.status, "plan": self.plan,
            "display_name": self.display_name,
            "max_daily_dollars": self.max_daily_dollars,
            "created_at": self.created_at, "updated_at": self.updated_at,
        }
        # Only serialize the optional fields when they carry non-default state, so
        # a registry written before this feature stays byte-identical and the
        # on-disk file does not grow a column for tenants that never use it.
        if self.stripe_customer_id:
            out["stripe_customer_id"] = self.stripe_customer_id
        if self.billing_status != BILLING_CURRENT:
            out["billing_status"] = self.billing_status
        if self.byok:
            out["byok"] = self.byok
        if self.feature_overrides:
            out["feature_overrides"] = self.feature_overrides
        return out

    @classmethod
    def from_dict(cls, d: dict) -> TenantRecord:
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or not d["id"].strip():
            raise ValueError("tenant record must be an object with an id")
        tenant_id = d["id"]
        if tenant_id != tenant_id.strip():
            raise ValueError("tenant id must be trimmed")
        tenant_id = _validate_id(tenant_id)
        status = d.get("status", ACTIVE)
        if not isinstance(status, str):
            raise ValueError("tenant status must be a string")
        if status not in _STATUSES:
            raise ValueError(f"unknown tenant status: {status!r}")
        try:
            cap = float(d.get("max_daily_dollars", 0.0) or 0.0)
            created = float(d.get("created_at", 0.0) or 0.0)
            updated = float(d.get("updated_at", 0.0) or 0.0)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError("tenant numeric fields must be finite numbers") from exc
        if not all(math.isfinite(value) and value >= 0 for value in (cap, created, updated)):
            raise ValueError("tenant numeric fields must be finite and non-negative")
        plan = d.get("plan", "free") or "free"
        display_name = d.get("display_name", "") or ""
        if not isinstance(plan, str) or not isinstance(display_name, str):
            raise ValueError("tenant plan and display_name must be strings")
        stripe_customer_id = d.get("stripe_customer_id", "") or ""
        if not isinstance(stripe_customer_id, str):
            raise ValueError("tenant stripe_customer_id must be a string")
        billing_status = d.get("billing_status", BILLING_CURRENT) or BILLING_CURRENT
        if not isinstance(billing_status, str):
            raise ValueError("tenant billing_status must be a string")
        if billing_status not in _BILLING_STATUSES:
            raise ValueError(f"unknown tenant billing_status: {billing_status!r}")
        byok = d.get("byok", False)
        if not isinstance(byok, bool):
            raise ValueError("tenant byok must be a boolean")
        raw_overrides = d.get("feature_overrides", {})
        if raw_overrides in (None, ""):
            raw_overrides = {}
        if not isinstance(raw_overrides, dict):
            raise ValueError("tenant feature_overrides must be an object")
        unknown_keys = set(raw_overrides) - {"add", "remove"}
        if unknown_keys:
            raise ValueError(
                f"tenant feature_overrides has unknown keys: {sorted(unknown_keys)}"
            )
        feature_overrides = _normalize_feature_overrides(
            raw_overrides.get("add"), raw_overrides.get("remove")
        )
        return cls(
            id=tenant_id, status=status, plan=plan,
            display_name=display_name, max_daily_dollars=cap,
            created_at=created, updated_at=updated,
            stripe_customer_id=stripe_customer_id.strip(),
            billing_status=billing_status,
            byok=byok,
            feature_overrides=feature_overrides,
        )

    @property
    def active(self) -> bool:
        return self.status == ACTIVE


def _validate_id(tenant_id: str) -> str:
    tid = (tenant_id or "").strip()
    if not tid:
        raise ValueError("tenant id is required")
    # Persist one canonical Unicode spelling and enforce portable path rules.
    return canonical_tenant_id(tid)


def _lookup_id(tenant_id: str | None) -> str:
    tid = (tenant_id or "").strip()
    return canonical_tenant_id(tid) if tid else ""


def _quota_value(value: object) -> float:
    """Return a finite, non-negative daily cap.

    ``inf`` previously persisted successfully and made the next registry read
    fail as corrupt because :meth:`TenantRecord.from_dict` correctly rejects
    it. Validate at the write boundary so an operator input cannot poison the
    control-plane roster.
    """
    try:
        cap = float(value or 0.0)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("tenant quota must be a finite number") from exc
    if not math.isfinite(cap):
        raise ValueError("tenant quota must be a finite number")
    return max(0.0, cap)


def _clean_feature_list(value: object, *, side: str) -> list[str]:
    """Validate one override list (``add`` or ``remove``): strings only, no
    blanks, deduped, sorted, capped. Raises ``ValueError`` on bad input."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"feature_overrides {side!r} must be a list")
    if len(value) > MAX_FEATURE_OVERRIDES:
        raise ValueError(
            f"feature_overrides {side!r} exceeds the {MAX_FEATURE_OVERRIDES}-entry cap"
        )
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"feature_overrides {side!r} entries must be strings")
        name = item.strip()
        if not name:
            raise ValueError(f"feature_overrides {side!r} entries must be non-blank")
        if name not in seen:
            seen.add(name)
            out.append(name)
    out.sort()
    return out


def _normalize_feature_overrides(add: object, remove: object) -> dict[str, list[str]]:
    """Validate + normalize the per-tenant override lists into a canonical dict.

    Returns ``{}`` when both lists are empty (so a tenant that never uses the
    feature stays byte-identical on disk), else ``{"add": [...], "remove":
    [...]}`` with sorted, deduped entries. A feature in BOTH lists is rejected
    (rather than silently letting one win) so an operator's contradictory input
    is surfaced instead of guessed."""
    add_list = _clean_feature_list(add, side="add")
    remove_list = _clean_feature_list(remove, side="remove")
    overlap = sorted(set(add_list) & set(remove_list))
    if overlap:
        raise ValueError(
            "feature_overrides: a feature must not be in both add and remove: "
            + ", ".join(overlap)
        )
    if not add_list and not remove_list:
        return {}
    return {"add": add_list, "remove": remove_list}


def _load() -> dict[str, TenantRecord]:
    from ..file_lock import ensure_private_file

    ensure_private_directory(maverick_home())
    path = _registry_path()
    ensure_private_directory(path.parent)
    if not path.exists():
        return {}
    try:
        ensure_private_file(path)
        raw = _decode_json(atomic_read_text(path), label="tenant registry")
    except TenantRegistryError:
        raise
    except OSError as exc:
        raise TenantRegistryError(f"tenant registry unreadable: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("tenants"), list):
        raise TenantRegistryError(
            "tenant registry corrupt: top-level object must contain a tenants list"
        )
    out: dict[str, TenantRecord] = {}
    namespace_owners: dict[str, str] = {}
    for d in raw["tenants"]:
        try:
            rec = TenantRecord.from_dict(d)
        except (TypeError, ValueError) as exc:
            raise TenantRegistryError(f"tenant registry corrupt: {exc}") from exc
        if rec.id in out:
            raise TenantRegistryError(f"tenant registry corrupt: duplicate tenant {rec.id!r}")
        namespace_key = _tenant_namespace_key(rec.id)
        prior = namespace_owners.get(namespace_key)
        if prior is not None and prior != rec.id:
            raise TenantRegistryError(
                "tenant registry corrupt: tenant ids "
                f"{prior!r} and {rec.id!r} alias the same filesystem namespace"
            )
        namespace_owners[namespace_key] = rec.id
        out[rec.id] = rec
    return out


def _decode_json(raw: str, *, label: str) -> object:
    def _reject_constant(value: str):
        raise ValueError(f"non-finite number {value!r}")

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate key {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(raw, parse_constant=_reject_constant, object_pairs_hook=_object)
    except (TypeError, ValueError) as exc:
        raise TenantRegistryError(f"{label} corrupt: {exc}") from exc


def _save(records: dict[str, TenantRecord]) -> None:
    payload = {"tenants": [records[k].to_dict() for k in sorted(records)]}
    # Atomic temp+replace (0600): a bare O_TRUNC write truncates in place, so a
    # concurrent _load()/is_active() reader sees a half-written file -> its
    # JSONDecodeError is swallowed as an EMPTY roster, which spuriously refuses a
    # legitimately-active tenant. Each mutator also holds _REGISTRY_LOCK +
    # cross_process_lock across the whole load-modify-save so two edits (e.g. a
    # suspend racing a set_quota) can't have the second save clobber the first.
    atomic_write_text(
        _registry_path(),
        json.dumps(payload, indent=2, sort_keys=True),
    )


def _locked(*, strict: bool = False):
    """Serialize a roster load-modify-save in-process AND cross-process.

    ``strict=True`` is used when a roster read participates in an admission
    transaction.  On a filesystem without a real process lock, admission must
    fail closed instead of racing a control-plane cap change.
    """
    from contextlib import ExitStack

    from ..authority_effects import authority_effect_fence

    ensure_private_directory(maverick_home())
    ensure_private_directory(_registry_path().parent)
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_REGISTRY_LOCK)
        stack.enter_context(cross_process_lock(_registry_path(), strict=strict))
        # Admission paths that already hold the roster (provider_admission)
        # must be able to repair the default tenant without re-locking: the
        # lock is not re-entrant and the flock would block the same process.
        _LOCK_STATE.held = True
        stack.callback(setattr, _LOCK_STATE, "held", False)
        return stack.pop_all()


_LOCK_STATE = threading.local()


def _roster_locked_by_this_thread() -> bool:
    return bool(getattr(_LOCK_STATE, "held", False))


def list_tenants() -> list[TenantRecord]:
    records = _load()
    return [records[k] for k in sorted(records) if not _retired(k)]


def get_tenant(tenant_id: str) -> TenantRecord | None:
    tid = _lookup_id(tenant_id)
    return None if tid and _retired(tid) else _load().get(tid)


def workspace_display_key(name: str) -> str:
    """Compare names as people see them: case-insensitive with collapsed space."""
    return " ".join(name.split()).casefold()


def create_tenant(
    tenant_id: str, *, plan: str = "free", display_name: str = "",
    max_daily_dollars: float = DEFAULT_TENANT_DAILY_DOLLARS,
    allocate_suffix: bool = False,
) -> TenantRecord:
    """Provision a tenant + its workspace. No daily spend cap by default;
    pass ``max_daily_dollars`` to set one. Refuses an existing identifier or
    visible workspace name.
    """
    tid = _validate_id(tenant_id)
    quota = _quota_value(max_daily_dollars)
    display_name = display_name.strip()
    _warn_if_unknown_plan(plan)
    with _locked(strict=True):
        records = _load()
        legacy_roles = _legacy_role_names()
        if allocate_suffix:
            base = tid
            occupied = {_tenant_namespace_key(existing) for existing in records}
            for suffix in range(1000):
                candidate = base if suffix == 0 else f"{base}-{suffix + 1}"
                if (_tenant_namespace_key(candidate) not in occupied and not _retired(candidate)
                        and _tenant_namespace_key(candidate) not in legacy_roles
                        and not tenant_namespace_reserved(candidate)):
                    tid = candidate
                    break
            else:
                raise ValueError("Choose a different workspace name; the available identifiers are reserved.")
        if tid in records:
            raise ValueError(f"tenant already exists: {tid!r}")
        namespace_key = _tenant_namespace_key(tid)
        for existing in records:
            if _tenant_namespace_key(existing) == namespace_key:
                raise ValueError(
                    f"tenant id {tid!r} aliases existing tenant {existing!r}"
                )
        # Use the final allocated identifier when there is no display name.
        # Check under the roster lock, including paused workspaces, so two
        # concurrent creations cannot publish indistinguishable choices.
        name_key = workspace_display_key(display_name or tid)
        if any(workspace_display_key(rec.display_name or rec.id) == name_key
               for rec in records.values()):
            raise DuplicateWorkspaceName("A workspace with that name already exists. Choose another name.")
        if name_key == workspace_display_key(DEFAULT_WORKSPACE_DISPLAY_NAME) and not _registry_path().exists():
            from ..paths import implicit_tenant_id

            implicit = implicit_tenant_id()
            if implicit and _lookup_id(implicit) != tid:
                raise DuplicateWorkspaceName("A workspace with that name already exists. Choose another name.")
        # Reserve the portable name and provision the confidentiality boundary
        # BEFORE publishing an active roster entry. The registry lock keeps the
        # admission check, claim, directory creation, and publication atomic to
        # other provisioning processes.
        if _retired(tid) or namespace_key in legacy_roles:
            raise ValueError("Workspace identifier has retained lifecycle or membership history; choose a new identifier. Use recovery for retained data.")
        bind_tenant_namespace(tid, require_new=True)
        from ..workspace import Workspace
        ensure_private_directory(Workspace(tid).root)
        now = time.time()
        rec = TenantRecord(
            id=tid, status=ACTIVE, plan=plan, display_name=display_name,
            max_daily_dollars=quota,
            created_at=now, updated_at=now,
        )
        records[tid] = rec
        # The first roster publication turns admission from "open" to "listed
        # tenants only". The deployment's implicit default tenant ran every
        # task before this; list it too, or the next task is refused as an
        # unknown tenant.
        default = _default_record(records) if not _registry_path().exists() else None
        if default is not None:
            records[default.id] = default
        _save(records)
    if default is not None:
        _audit_default_registered(default.id, trigger="first_workspace")
    return rec


#: Roster label for the tenant a deployment ran in before it had workspaces.
DEFAULT_WORKSPACE_DISPLAY_NAME = "Default workspace"


def _default_record(records: dict[str, TenantRecord]) -> TenantRecord | None:
    """A fresh active row for the implicit default tenant, or ``None`` when the
    deployment has no binding or the roster already lists it. Caller holds the
    registry lock."""
    from ..paths import implicit_tenant_id

    try:
        tid = _lookup_id(implicit_tenant_id())
    except Exception:
        return None
    if not tid or tid in records:
        return None
    namespace_key = _tenant_namespace_key(tid)
    if any(_tenant_namespace_key(existing) == namespace_key for existing in records):
        return None
    try:
        bind_tenant_namespace(tid)
        from ..workspace import Workspace
        ensure_private_directory(Workspace(tid).root)
    except Exception as exc:
        log.error("default tenant %r could not be provisioned: %s", tid, exc)
        return None
    now = time.time()
    return TenantRecord(
        id=tid, status=ACTIVE, plan="free",
        display_name=DEFAULT_WORKSPACE_DISPLAY_NAME,
        max_daily_dollars=DEFAULT_TENANT_DAILY_DOLLARS,
        created_at=now, updated_at=now,
    )


def _audit_default_registered(tenant_id: str, *, trigger: str, actor: str = "system") -> None:
    from ..audit import EventKind, audit_event

    audit_event(
        EventKind.TENANT_DEFAULT_REGISTERED, agent="system", _global=True,
        actor=actor, tenant=tenant_id, trigger=trigger,
    )


def ensure_default_tenant_registered(*, actor: str = "system") -> TenantRecord | None:
    """Repair an install whose roster predates the default-tenant rule.

    When a roster exists but lacks the deployment's implicit default tenant,
    add it as active and write an audit event. Returns the new record, or
    ``None`` when nothing needed doing (no roster, no binding, already
    listed, or paused on purpose). Safe to call on every startup or admission.
    """
    if not _registry_path().exists():
        return None

    def _register() -> TenantRecord | None:
        records = _load()
        default = _default_record(records)
        if default is not None:
            records[default.id] = default
            _save(records)
        return default

    if _roster_locked_by_this_thread():
        default = _register()
    else:
        with _locked():
            default = _register()
    if default is None:
        return None
    _audit_default_registered(default.id, trigger="repair", actor=actor)
    log.warning("tenant registry: registered the default workspace %r so it "
                "keeps running alongside the named workspaces", default.id)
    return default


def _is_implicit_default(tid: str) -> bool:
    from ..paths import implicit_tenant_id

    try:
        return bool(tid) and _lookup_id(implicit_tenant_id()) == tid
    except Exception:
        return False


def _mutate(tenant_id: str, **changes) -> TenantRecord:
    tid = _lookup_id(tenant_id)
    with _locked():
        records = _load()
        rec = records.get(tid)
        if rec is None or _retired(tid):
            raise UnknownTenant(tid)
        rec = replace(rec, updated_at=time.time(), **changes)
        records[tid] = rec
        _save(records)
    return rec


def suspend_tenant(tenant_id: str) -> TenantRecord:
    return _mutate(tenant_id, status=SUSPENDED)


def resume_tenant(tenant_id: str) -> TenantRecord:
    return _mutate(tenant_id, status=ACTIVE)


def set_stripe_customer_id(tenant_id: str, customer_id: str) -> TenantRecord:
    """Record the tenant's Stripe customer id so it is looked up, not re-created.

    Called once by :func:`maverick.billing_stripe.ensure_customer` after the
    first create. Idempotent: writing the same id again is a harmless no-op-shaped
    mutate (updated_at moves). A blank id is refused so we never clear a real
    handle by accident."""
    cid = (customer_id or "").strip()
    if not cid:
        raise ValueError("stripe customer id must be non-blank")
    return _mutate(tenant_id, stripe_customer_id=cid)


def set_billing_status(tenant_id: str, billing_status: str) -> TenantRecord:
    """Set the tenant's payment state (BILLING_CURRENT / BILLING_PAST_DUE).

    The seam the Stripe webhook handler flips: ``past_due`` on a failed payment
    (which downgrades the tenant to base entitlements via
    :func:`maverick.billing.tenant_entitled`) and back to ``current`` on a
    recovered payment. The subscribed ``plan`` is never touched, so restoring is
    exact. Refuses an unknown status rather than silently persisting garbage."""
    status = (billing_status or "").strip()
    if status not in _BILLING_STATUSES:
        raise ValueError(
            f"unknown billing_status {billing_status!r}; "
            f"expected one of {sorted(_BILLING_STATUSES)}"
        )
    return _mutate(tenant_id, billing_status=status)


def set_byok(tenant_id: str, enabled: bool) -> TenantRecord:
    """Opt a tenant into (or out of) bring-your-own-key provider credentials.

    A pure flag: the provider key itself is set in the secret provider under the
    name :func:`maverick.config.tenant_provider_key_env` reports, never here. On
    ``True``, the tenant runs on its own key when the deployment enabled
    ``[providers] per_tenant_keys`` AND that secret is present; if the flag is on
    but no secret is configured, resolution falls back to the deployment-global
    key (never crashes). Off restores the global-key behavior."""
    return _mutate(tenant_id, byok=bool(enabled))


def set_feature_overrides(
    tenant_id: str, add: list[str], remove: list[str]
) -> TenantRecord:
    """Set the tenant's per-tenant feature overrides on top of its plan.

    ``add`` grants features the plan does not include; ``remove`` revokes plan
    features. The lists are validated (strings only, non-blank, deduped, capped
    at :data:`MAX_FEATURE_OVERRIDES`) and a feature that appears in BOTH is
    rejected. Persisted under the same in-process + cross-process lock and
    atomic temp-file replace as the other setters. Passing two empty lists
    clears any existing overrides. Raises :class:`ValueError` on invalid input
    and :class:`UnknownTenant` for an unprovisioned tenant."""
    overrides = _normalize_feature_overrides(add, remove)
    return _mutate(tenant_id, feature_overrides=overrides)


def get_tenant_by_stripe_customer(customer_id: str) -> TenantRecord | None:
    """Reverse-lookup the tenant that owns a Stripe customer id, or None.

    The webhook handler receives Stripe's ``customer`` (``cus_...``) and needs to
    find which tenant it maps to. A blank id never matches."""
    cid = (customer_id or "").strip()
    if not cid:
        return None
    for rec in list_tenants():
        if rec.stripe_customer_id == cid:
            return rec
    return None


def _audit_billing_change(field: str, tenant_id: str, *, old, new) -> None:
    """Record a tamper-evident audit row for a change to a tenant's billing
    terms (plan / daily cap), so an upgrade or cap change is provable rather than
    a silent edit. Ordinary writer outages remain fail-soft; an explicit
    policy/custody refusal propagates."""
    from ..audit import EventKind, audit_event

    kind = (EventKind.TENANT_PLAN_CHANGED if field == "plan"
            else EventKind.TENANT_QUOTA_CHANGED)
    audit_event(
        kind, agent="operator", tenant=tenant_id, field=field,
        old=old, new=new,
    )


def _mutate_billing(tenant_id: str, field: str, value: object) -> TenantRecord:
    """Commit a billing mutation and its audit result as one locked operation.

    On a strict audit refusal the roster is restored before the exception
    propagates. Keeping the original read, write, audit, and possible rollback
    under one registry lock also prevents the old/new evidence from racing a
    concurrent operator update.
    """
    tid = _lookup_id(tenant_id)
    attr = "plan" if field == "plan" else "max_daily_dollars"
    with _locked():
        records = _load()
        old_rec = records.get(tid)
        if old_rec is None or _retired(tid):
            raise UnknownTenant(tid)
        prior = dict(records)
        old = getattr(old_rec, attr)
        rec = replace(old_rec, updated_at=time.time(), **{attr: value})
        records[tid] = rec
        _save(records)
        from ..audit import AuditRefused

        try:
            _audit_billing_change(field, rec.id, old=old, new=getattr(rec, attr))
        except AuditRefused:
            try:
                _save(prior)
            except Exception as rollback_exc:
                raise TenantRegistryError(
                    "audit refused tenant billing change and rollback failed"
                ) from rollback_exc
            raise
    return rec


def set_quota(tenant_id: str, max_daily_dollars: float) -> TenantRecord:
    rec = _mutate_billing(
        tenant_id,
        "quota",
        _quota_value(max_daily_dollars),
    )
    return rec


def set_plan(tenant_id: str, plan: str) -> TenantRecord:
    _warn_if_unknown_plan(plan)
    rec = _mutate_billing(tenant_id, "plan", str(plan or "free"))
    return rec


def delete_tenant(tenant_id: str, *, purge: bool = False) -> bool:
    """Remove a tenant from the registry. With ``purge=True`` also delete its
    data directory (irreversible). Its identifier remains permanently reserved.
    Returns False if the tenant was unknown."""
    tid = _lookup_id(tenant_id)
    with _locked(strict=True):
        records = _load()
        if tid not in records:
            return False
        # Durable before roster removal or optional purge. A crash here leaves
        # an unavailable tenant, never a reusable incarnation or active row.
        bind_tenant_namespace(tid)
        _retire(tid, records[tid], purge=purge)
        del records[tid]
        _save(records)
    if purge:
        import shutil

        from ..federation import hold_state_file_closed
        from ..workspace import Workspace
        root = Workspace(tid).root
        # Only purge under the tenants/ tree, never the shared root.
        if "tenants" in root.parts:
            # The tenant's federation state file may be open here; an open file cannot be
            # removed on Windows, and rmtree(ignore_errors=True) would skip it silently.
            with hold_state_file_closed():
                shutil.rmtree(root, ignore_errors=True)
    return True


def list_removed_tenants() -> list[dict[str, object]]:
    """Admin-facing removal history; records stay private and unselectable."""
    from ..file_lock import ensure_private_file

    root = maverick_home() / ".tenant-deletions"
    if not root.exists():
        return []
    ensure_private_directory(root)
    rows: list[dict[str, object]] = []
    for path in root.glob("*.json"):
        ensure_private_file(path)
        value = _decode_json(atomic_read_text(path), label="tenant deletion tombstone")
        if not isinstance(value, dict) or not isinstance(value.get("id"), str):
            raise TenantRegistryError("Tenant deletion history is unavailable.")
        tid = _validate_id(value["id"])
        if path != _retirement_path(tid):
            raise TenantRegistryError("Tenant deletion history has an invalid identity.")
        saved = _retirement(tid)
        if saved is None or saved.get("state", "removed") != "removed":
            continue
        record = saved.get("record") or {}
        retained = (maverick_home() / "tenants" / _tenant_segment(tid)).is_dir()
        rows.append({
            "id": tid,
            "display_name": str(record.get("display_name") or tid),
            "removed_at": saved["deleted_at"],
            "restorable": saved["version"] == 2 and not saved["purged"] and retained,
        })
    return sorted(rows, key=lambda row: float(row["removed_at"]), reverse=True)


def _erasure_root(tid):
    """An exact retired namespace, never the shared home or a linked folder."""
    from pathlib import Path
    root = maverick_home() / "tenants" / _tenant_segment(tid)
    parent = root.parent
    if parent.is_symlink() or root.is_symlink():
        raise ValueError("Linked workspace folders cannot be erased here.")
    if root.resolve().parent != parent.resolve() or root == Path(maverick_home()):
        raise ValueError("Workspace storage is outside its reserved folder.")
    return root


def _erasure_stamp(path):
    import stat
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)):
        raise ValueError("Workspace storage includes a linked or unsupported item.")
    return [value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns]


def _erasure_tree(root, check):
    """Full local metadata selection. Private file bodies never enter reviews."""
    entries, pending, total = [], [root], 0
    if not root.exists():
        return entries, total
    while pending:
        check()
        path = pending.pop()
        stamp = _erasure_stamp(path)
        relative = path.relative_to(root).as_posix()
        directory = path.is_dir()
        entries.append({"path": relative, "directory": directory, "stamp": stamp})
        if len(entries) > 50000:
            raise ValueError("This workspace has more than 50,000 local items. Its complete erasure review is unavailable; nothing was erased.")
        if directory:
            pending.extend(sorted(path.iterdir(), reverse=True))
        else:
            total += stamp[3]
    return entries, total


def _erasure_attempts(saved):
    rows = saved.get("erasures", [])
    if not isinstance(rows, list) or len(rows) > 1000:
        raise TenantRegistryError("Workspace erasure history is unavailable.")
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("operation"), str)
                or row["operation"] in seen or row.get("result") not in {"unconfirmed", "confirmed"}
                or not isinstance(row.get("actor"), str) or not isinstance(row.get("context"), str)):
            raise TenantRegistryError("Workspace erasure history is unavailable.")
        seen.add(row["operation"])
    return rows


def _erasure_snapshot_unlocked(tid, check):
    check()
    saved = _retirement(tid)
    if saved is None or saved.get("state", "removed") != "removed" or tid in _load():
        raise ValueError("Choose a workspace that is still removed.")
    root = _erasure_root(tid)
    entries, total = _erasure_tree(root, check)
    rows = _erasure_attempts(saved)
    pending = rows[-1]["operation"] if rows and rows[-1]["result"] == "unconfirmed" else ""
    material = {"home": str(maverick_home().resolve()), "removed": saved, "entries": entries}
    revision = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    record = saved.get("record") or {}
    check()
    return {"workspace": tid, "name": str(record.get("display_name") or tid),
            "removed_at": saved["deleted_at"], "files": sum(not e["directory"] for e in entries),
            "folders": sum(e["directory"] for e in entries), "bytes": total,
            "previous_attempt": pending, "revision": revision}, saved, entries


def erasure_review(tenant_id: str, *, effect_guard=None) -> dict:
    """Read the complete exact local selection for a removed workspace."""
    from ..budget import Budget
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    def check():
        budget.check()
        if effect_guard is not None:
            effect_guard()
    tid = _lookup_id(tenant_id)
    with _locked(strict=True):
        value, _saved, _entries = _erasure_snapshot_unlocked(tid, check)
        return value


def erasure_original(tenant_id: str, operation: str, *, actor: str, context: str, effect_guard=None):
    """Pure original lookup; never infer an earlier outcome from current absence."""
    tid = _lookup_id(tenant_id)
    with _locked(strict=True):
        if effect_guard is not None:
            effect_guard()
        saved = _retirement(tid)
        rows = _erasure_attempts(saved) if saved is not None else []
        for row in rows:
            if row["operation"] == operation and row["actor"] == actor and row["context"] == context:
                if effect_guard is not None:
                    effect_guard()
                return dict(row)
        return None


def erasure_history(tenant_id: str, *, actor: str, context: str, effect_guard=None) -> list[dict]:
    """Complete metadata history for this exact original actor/context."""
    tid = _lookup_id(tenant_id)
    with _locked(strict=True):
        if effect_guard is not None:
            effect_guard()
        saved = _retirement(tid)
        rows = _erasure_attempts(saved) if saved is not None else []
        values = [dict(row) for row in rows if row["actor"] == actor and row["context"] == context]
        if effect_guard is not None:
            effect_guard()
        return values


def _erasure_save(tid, saved, check):
    atomic_write_text(_retirement_path(tid), json.dumps(saved, sort_keys=True), effect_guard=check)


def _erasure_unlink(root, entries, check):
    """Guard every actual unlink, keeping any interrupted attempt unknown."""
    # Deepest first, with the root ('.') below every top-level name: it shares their
    # '/' count and, for a one-character name, their length.
    for entry in sorted(entries, key=lambda e: (-1 if e["path"] == "." else e["path"].count("/"), len(e["path"])), reverse=True):
        check()
        path = root if entry["path"] == "." else root / entry["path"]
        # Check every parent again: no link introduced after the reviewed walk
        # may redirect an unlink outside this exact reserved namespace.
        for parent in (path, *path.parents):
            if parent.is_symlink():
                raise ValueError("Workspace storage changed during erasure. Check the original result.")
            if parent == root:
                break
        actual = _erasure_stamp(path)
        expected = entry["stamp"]
        # Our own child removals change directory dates/size, not its identity.
        if actual[:3] != expected[:3] or (not entry["directory"] and actual != expected):
            raise ValueError("Workspace storage changed during erasure. Check the original result.")
        check()
        path.rmdir() if entry["directory"] else path.unlink()


def _assert_no_legal_hold(tid: str) -> None:
    """Refuse erasing a removed workspace while one of its legal matters is active.

    The matter ledger lives inside the workspace's own tree, so erasing the tree
    would remove the hold with the records it protects.  Fails closed.
    """
    from ..ediscovery import active_matter_count
    from ..paths import tenant_scope

    try:
        with tenant_scope(tenant=tid):
            held = active_matter_count()
    except Exception as exc:  # failure-policy: fail_closed -- an unreadable ledger holds the workspace
        raise TenantRegistryError("Legal holds could not be checked, so nothing was erased.") from exc
    if held:
        raise TenantRegistryError(
            "A legal hold is active in this workspace, so it cannot be erased. "
            "Ask your records administrator to release the hold first.")


def erase_removed_tenant(tenant_id: str, *, revision: str, operation: str, actor: str,
                        context: str, previous_attempt: str = "", effect_guard=None) -> dict:
    """Reviewed retired-only purge using the native deletion history.

    Existing delete/purge callers are unchanged. A durable unknown original is
    reserved before any unlink; only a separate reviewed current intention can
    continue cleanup. Namespace/deletion evidence remains after local erasure.
    """
    from ..audit import audit_event
    from ..budget import Budget
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    def check():
        budget.check()
        if effect_guard is not None:
            effect_guard()
    tid = _lookup_id(tenant_id)
    with _locked(strict=True):
        check()
        saved = _retirement(tid)
        rows = _erasure_attempts(saved) if saved is not None else []
        original = next((r for r in rows if r["operation"] == operation), None)
        if original is not None:
            if original["actor"] != actor or original["context"] != context:
                raise PermissionError("This original erasure belongs to another account or workspace.")
            return dict(original)
        _assert_no_legal_hold(tid)
        value, saved, entries = _erasure_snapshot_unlocked(tid, check)
        if value["revision"] != revision or value["previous_attempt"] != previous_attempt:
            raise ValueError("The removed workspace changed. Review its remaining records again.")
        if len(rows) >= 1000:
            raise ValueError("The retained erasure history is full. Nothing was erased.")
        row = {"operation": operation, "actor": actor, "context": context, "result": "unconfirmed",
               "started_at": time.time(), "reviewed_revision": revision, "previous_attempt": previous_attempt,
               "files": value["files"], "folders": value["folders"], "bytes": value["bytes"]}
        saved["erasures"] = [*rows, row]
        # Once physical erasure may start, restoration must remain closed even
        # if a reply/audit/final save is interrupted.
        saved["purged"] = True
        _erasure_save(tid, saved, check)
        if not audit_event("workspace_erasure_started", agent=actor, _global=True,
                           tenant=tid, operation=operation, files=row["files"], previous_attempt=previous_attempt):
            raise TenantRegistryError("Erasure admission could not be recorded. The original remains unconfirmed.")
        check()
        root = _erasure_root(tid)
        current_entries, _total = _erasure_tree(root, check)
        if current_entries != entries:
            raise ValueError("The local records changed after admission. This original remains unconfirmed; review the remaining records separately.")
        # The tenant's federation state file is among the entries; keep it closed for the unlinks.
        from ..federation import hold_state_file_closed
        with hold_state_file_closed():
            _erasure_unlink(root, entries, check)
        check()
        if _erasure_root(tid).exists():
            raise TenantRegistryError("Local erasure could not be confirmed. Check the original result.")
        if not audit_event("workspace_erasure_completed", agent=actor, _global=True,
                           tenant=tid, operation=operation, files=row["files"]):
            raise TenantRegistryError("The records may be erased, but completion could not be recorded. Check the original result.")
        row["result"] = "confirmed"
        row["finished_at"] = time.time()
        _erasure_save(tid, saved, check)
        return dict(row)


def restore_tenant(tenant_id: str) -> TenantRecord:
    """Restore one retained workspace as paused, without restoring old access.

    The namespace claim remains permanent; this is an explicit recovery of the
    *same* archived workspace, not provisioning a fresh tenant under its id.
    """
    tid = _lookup_id(tenant_id)
    with _locked(strict=True):
        saved = _retirement(tid)
        if saved is None or saved.get("state", "removed") != "removed":
            raise ValueError("Workspace is not removed.")
        if saved["version"] != 2 or saved["purged"]:
            raise ValueError("This workspace has no recoverable saved record.")
        root = maverick_home() / "tenants" / _tenant_segment(tid)
        if not root.is_dir():
            raise ValueError("The workspace records are missing; restore them from a backup first.")
        if _tenant_namespace_key(tid) in _legacy_role_names():
            raise ValueError("Old member access must be cleared before recovery.")
        records = _load()
        rec = TenantRecord.from_dict(saved["record"])
        existing = records.get(tid)
        if existing is not None and existing != replace(
            rec, display_name=existing.display_name, status=SUSPENDED,
            updated_at=existing.updated_at,
        ):
            raise ValueError("Workspace recovery conflicts with an existing roster record.")
        if existing is None:
            if any(_tenant_namespace_key(other.id) == _tenant_namespace_key(tid)
                   for other in records.values()):
                raise ValueError("Workspace recovery conflicts with an existing identifier.")
            names = {workspace_display_key(other.display_name or other.id)
                     for other in records.values()}
            original_name = rec.display_name or rec.id
            if workspace_display_key(original_name) in names:
                for suffix in range(1, 1001):
                    label = "recovered" if suffix == 1 else f"recovered {suffix}"
                    candidate = f"{original_name} ({label})"
                    if workspace_display_key(candidate) not in names:
                        rec = replace(rec, display_name=candidate)
                        break
                else:
                    raise DuplicateWorkspaceName("No available recovery name; rename the newer workspace first.")
            rec = replace(rec, status=SUSPENDED, updated_at=time.time())
            records[tid] = rec
            _save(records)
        else:
            rec = existing
        saved["state"] = "restored"
        saved["restored_at"] = time.time()
        atomic_write_text(_retirement_path(tid), json.dumps(saved, sort_keys=True))
        return rec


def is_active(tenant_id: str | None) -> bool:
    """Whether a tenant may do work.

    The registry is opt-in: before any roster or deletion history exists, named tenants are
    accepted for single-tenant and unprovisioned deployments. Once a roster
    exists, only provisioned active tenants may do work; unknown tenant IDs
    include deleted tenants and are refused.
    """
    tid = _lookup_id(tenant_id)
    if not tid:
        return True
    try:
        if _retired(tid):
            return False
        rec = _load().get(tid)
    except TenantRegistryError:
        return False
    if rec is None:
        if not _registry_path().exists():
            return True
        if _is_implicit_default(tid):
            try:
                rec = ensure_default_tenant_registered()
            except Exception:
                return False
            return rec is not None and rec.active
        return False
    return rec.active


def assert_tenant_active(tenant_id: str | None) -> None:
    """Enforcement hook: raise :class:`TenantSuspended` for inactive tenants.
    No-op for None / deployments without a registry or deletion history, so
    existing flows are unchanged until tenant provisioning is enabled.
    """
    tid = _lookup_id(tenant_id)
    if not tid:
        return
    if _retired(tid):
        raise TenantSuspended("Workspace was deleted; its identifier cannot be reused.")
    path = _registry_path()
    if not path.exists():
        return
    # Unlike the convenience bool returned by is_active(), admission paths
    # need to distinguish a legitimate suspension from unreadable or corrupt
    # control-plane state.  Let TenantRegistryError propagate so callers can
    # emit an operator-visible policy outage and, critically, still deny work.
    rec = _load().get(tid)
    if rec is None and _is_implicit_default(tid):
        # An install whose roster was written before the default-tenant rule:
        # the deployment's own tenant is never "unknown", so list it now.
        rec = ensure_default_tenant_registered()
    if rec is None or not rec.active:
        raise TenantSuspended(f"tenant is suspended or unknown: {tenant_id!r}")


def tenant_spend_today(tenant_id: str) -> float:
    """Today's recorded spend (dollars) across the tenant's usage ledger.

    Reads the tenant-scoped ledger (``tenants/<t>/usage/ledger.json`` — the
    same file the orchestrator's per-principal recording lands in when the
    run is tenant-pinned) and sums every principal's bucket for the current
    UTC day. An unreadable/corrupt ledger counts as infinite spend so a policy
    outage cannot reset a capped tenant's apparent usage to zero.
    """
    tid = _lookup_id(tenant_id)
    from ..paths import data_dir
    from ..quotas import UsageLedger, _today
    try:
        ledger = UsageLedger(data_dir("usage", "ledger.json", tenant=tid))
        data = ledger._load()
        day = _today()
        return sum(
            float((days.get(day) or {}).get("dollars", 0.0))
            for days in data.values() if isinstance(days, dict)
        )
    except Exception as e:
        log.error("tenant_spend_today: unreadable usage ledger for %r: %s; "
                  "treating spend as over cap", tid, e)
        return float("inf")


def _enforce_plan_caps() -> bool:
    """Opt-in: when a tenant has no explicit registry spend cap, fall back to its
    billing plan's entitlement-level daily cap so a config-defined plan cap is
    actually enforced rather than decorative.

    Off by default: a registry cap of 0 means "unlimited" today, so enabling this
    changes already-provisioned tenants. ``MAVERICK_ENFORCE_PLAN_CAPS`` env wins
    over ``[billing] enforce_plan_caps``."""
    env = os.environ.get("MAVERICK_ENFORCE_PLAN_CAPS")
    if env is not None and env.strip() != "":
        value = env.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        raise TenantRegistryError("MAVERICK_ENFORCE_PLAN_CAPS must be a boolean")
    try:
        from ..config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            raise TenantRegistryError(
                "tenant plan-cap policy unavailable: an active config source is invalid"
            )
        billing = cfg.get("billing") or {}
        if not isinstance(billing, dict):
            raise TenantRegistryError("[billing] must be a table")
        value = billing.get("enforce_plan_caps", False)
        if not isinstance(value, bool):
            raise TenantRegistryError("[billing] enforce_plan_caps must be a boolean")
        return value
    except TenantRegistryError:
        raise
    except Exception as exc:
        raise TenantRegistryError(f"tenant plan-cap policy unavailable: {exc}") from exc


def tenant_over_quota(tenant_id: str | None) -> str | None:
    """Human-readable reason when ``tenant_id`` is over its provisioned
    daily-spend cap, else None.

    The cap is ``max_daily_dollars`` on the tenant's roster record. New tenants
    receive :data:`DEFAULT_TENANT_DAILY_DOLLARS` (no cap); ``0`` means no cap. An unprovisioned tenant or no roster still means
    "no cap" for compatibility with single-tenant operation.
    """
    tid = _lookup_id(tenant_id)
    if not tid:
        return None
    if _load().get(tid) is None:
        return None
    cap = _tenant_daily_cap(tid)
    if cap <= 0:
        return None
    spent = tenant_spend_today(tid)
    if spent >= cap:
        return (f"workspace {tid!r} is over its daily spend cap "
                f"(${spent:.2f} >= ${cap:.2f}); resets at midnight UTC")
    # Runs in flight hold the allowance they may still spend. Without
    # counting them here the gate admitted a run that reserve_tenant_budget
    # then granted $0, so it was created, started, and died on its first
    # model call with "budget exceeded" instead of a clean over-quota refusal.
    held = _outstanding_reservations(tid)
    if held > 0 and spent + held >= cap:
        return (f"workspace {tid!r} has no daily spend allowance left: "
                f"${spent:.2f} spent plus ${held:.2f} held by runs in flight "
                f"reaches its ${cap:.2f} cap; retry when those runs finish or "
                "after midnight UTC")
    return None


def _tenant_daily_cap(tenant_id: str) -> float:
    """The effective daily spend cap (USD) for ``tenant_id``: the registry cap,
    falling back to the plan entitlement cap when plan-cap enforcement is on.
    ``0`` means no cap. Shared by :func:`tenant_over_quota` and
    :func:`tenant_remaining_today` so both read the same ceiling."""
    rec = _load().get(_lookup_id(tenant_id))
    if rec is None:
        return 0.0
    cap = rec.max_daily_dollars
    if cap <= 0 and _enforce_plan_caps():
        try:
            from ..billing import entitlements_for
            cap = entitlements_for(rec.plan).max_daily_dollars
        except Exception as exc:
            raise TenantRegistryError(
                f"tenant plan-cap entitlement unavailable for {rec.id!r}: {exc}"
            ) from exc
    return cap if cap > 0 else 0.0


# ---- In-flight dollar reservations (concurrent daily-cap enforcement) --------
#
# The usage ledger is written only at run END, so N runs that START for one
# tenant before any of them records spend would each read the same remaining
# allowance and each clamp to the full remainder -- collectively overshooting
# the daily ceiling by up to N x. A run therefore RESERVES its
# clamped per-run dollar cap here at start; tenant_remaining_today subtracts
# outstanding (non-expired) reservations as well as recorded spend, so a
# concurrent start sees the in-flight hold. Each reservation carries a TTL, so a
# crashed run that never records spend (and so never releases) only dents the
# cap until the hold expires -- the cap self-heals rather than being permanently
# reduced. Stored as a sibling of the tenant usage ledger
# (``tenants/<t>/usage/reservations.json``) with the same atomic
# temp-file+os.replace + cross-process flock discipline the ledger uses.


def _reservations_path(tenant_id: str):
    from ..paths import data_dir
    return data_dir("usage", "reservations.json", tenant=tenant_id)


def _load_reservations(tenant_id: str) -> dict:
    from ..file_lock import ensure_private_file

    ensure_private_directory(maverick_home())
    path = _reservations_path(tenant_id)
    ensure_private_directory(path.parent)
    if not path.exists():
        return {}
    try:
        ensure_private_file(path)
        raw = _decode_json(atomic_read_text(path), label="tenant reservation store")
    except TenantRegistryError:
        raise
    except OSError as exc:
        raise TenantRegistryError(f"tenant reservation store unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise TenantRegistryError(
            "tenant reservation store corrupt: top-level value must be an object"
        )
    out: dict[str, dict[str, float]] = {}
    for reservation_id, value in raw.items():
        if not reservation_id or reservation_id != reservation_id.strip():
            raise TenantRegistryError("tenant reservation ids must be non-blank strings")
        if not isinstance(value, dict):
            raise TenantRegistryError(
                f"tenant reservation {reservation_id!r} must be an object"
            )
        try:
            amount = float(value["dollars"])
            expiry = float(value["expires_at"])
        except (KeyError, OverflowError, TypeError, ValueError) as exc:
            raise TenantRegistryError(
                f"tenant reservation {reservation_id!r} has invalid numeric fields"
            ) from exc
        if not math.isfinite(amount) or amount <= 0 or not math.isfinite(expiry) or expiry <= 0:
            raise TenantRegistryError(
                f"tenant reservation {reservation_id!r} must be finite and positive"
            )
        out[reservation_id] = {"dollars": amount, "expires_at": expiry}
    return out


def _live_reservations(data: dict, now: float) -> dict:
    """Return only the well-formed, non-expired, positive-amount holds in
    ``data`` (the pruning + parsing shared by the read and write paths)."""
    out: dict = {}
    for rid, v in data.items():
        if not isinstance(v, dict):
            continue
        try:
            exp = float(v.get("expires_at", 0.0))
            amt = float(v.get("dollars", 0.0))
        except (TypeError, ValueError):
            continue
        if exp > now and amt > 0:
            out[str(rid)] = {"dollars": amt, "expires_at": exp}
    return out


def _legacy_outstanding_reservations(tenant_id: str | None, *, now: float | None = None) -> float:
    """Sum of a tenant's outstanding (non-expired) in-flight dollar holds."""
    tid = _lookup_id(tenant_id)
    if not tid:
        return 0.0
    at = time.time() if now is None else now
    return sum(v["dollars"] for v in _live_reservations(_load_reservations(tid), at).values())


def _outstanding_reservations(tenant_id: str | None, *, now: float | None = None) -> float:
    tid = _lookup_id(tenant_id)
    if not tid:
        return 0.0
    from .provider_admission import outstanding
    return _legacy_outstanding_reservations(tid, now=now) + outstanding(tid)


def reserve_tenant_dollars(tenant_id: str | None, amount: float,
                           ttl_seconds: float, reservation_id: str) -> None:
    """Hold ``amount`` dollars in-flight against ``tenant_id`` under
    ``reservation_id`` for ``ttl_seconds`` from now.

    Makes concurrent run starts see each other's not-yet-recorded spend:
    :func:`tenant_remaining_today` subtracts outstanding reservations. The TTL is
    a backstop -- a crashed run that never releases only reduces the cap until
    the hold expires. Atomic read-modify-write (in-process lock + cross-process
    flock + temp-file replace) that also prunes expired holds. A blank tenant/id
    or a non-positive amount is a no-op. Callers wrap this (it must never raise
    into the run path)."""
    tid = _lookup_id(tenant_id)
    if not tid or not reservation_id:
        return
    try:
        amt = float(amount or 0.0)
        ttl = float(ttl_seconds or 0.0)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("reservation amount and TTL must be finite numbers") from exc
    if amt <= 0:
        return
    if not math.isfinite(amt) or not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("reservation amount and TTL must be finite and positive")
    now = time.time()
    path = _reservations_path(tid)
    with _RESERVE_LOCK, cross_process_lock(path, strict=True):
        data = _live_reservations(_load_reservations(tid), now)
        if str(reservation_id) in data:
            raise TenantRegistryError(
                f"tenant reservation already exists: {reservation_id!r}"
            )
        data[str(reservation_id)] = {"dollars": amt, "expires_at": now + ttl}
        atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True))


def reserve_tenant_budget(
    tenant_id: str | None,
    requested_amount: float,
    ttl_seconds: float,
    reservation_id: str,
) -> float | None:
    """Atomically clamp and reserve one run against a tenant's daily cap.

    ``None`` means the tenant has no aggregate cap and the caller should keep
    its own per-run ceiling.  Otherwise the return value is the amount granted
    (possibly ``0.0`` when the daily allowance is exhausted).

    The cap/spend/reservation calculation and reservation write share the
    registry lock followed by the strict reservation lock. Consequently two
    starts cannot both observe the same unreserved remainder, and a concurrent
    ``set_quota``/``set_plan`` cannot publish a changed ceiling between this
    transaction's cap read and hold write. Usage settlement records spend
    *before* releasing its hold, so a concurrent allocator sees either the old
    spend plus the hold, the new spend plus the hold, or the new spend after
    release -- never neither.
    """
    tid = _lookup_id(tenant_id)
    if not tid:
        return None
    if not reservation_id or reservation_id != reservation_id.strip():
        raise ValueError("reservation id must be a non-blank trimmed string")
    try:
        requested = float(requested_amount)
        ttl = float(ttl_seconds)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("reservation amount and TTL must be finite numbers") from exc
    if not math.isfinite(requested) or requested < 0:
        raise ValueError("requested reservation amount must be finite and non-negative")
    if not math.isfinite(ttl) or ttl <= 0:
        raise ValueError("reservation TTL must be finite and positive")

    # Avoid creating a tenant data tree merely to discover that a provisioned
    # tenant is unlimited.  The cap is read again under the allocation lock;
    # this first read is only a side-effect-free fast path.
    if _tenant_daily_cap(tid) <= 0:
        return None

    now = time.time()
    path = _reservations_path(tid)
    # Global lock order is roster -> reservation thread lock -> reservation
    # sidecar. Roster mutators take only the first; direct hold/release paths
    # take only the latter two. Keeping this order prevents lock inversion while
    # making the cap read and hold publication one control-plane transaction.
    with _locked(strict=True):
        with _RESERVE_LOCK, cross_process_lock(path, strict=True):
            cap = _tenant_daily_cap(tid)
            if cap <= 0:
                return None
            data = _live_reservations(_load_reservations(tid), now)
            if reservation_id in data:
                raise TenantRegistryError(
                    f"tenant reservation already exists: {reservation_id!r}"
                )
            outstanding = sum(value["dollars"] for value in data.values())
            from .provider_admission import outstanding as provider_outstanding
            outstanding += provider_outstanding(tid)
            remaining = max(0.0, cap - tenant_spend_today(tid) - outstanding)
            granted = min(requested, remaining)
            if granted > 0:
                data[reservation_id] = {
                    "dollars": granted,
                    "expires_at": now + ttl,
                }
                atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True))
            return granted


def release_tenant_reservation(tenant_id: str | None, reservation_id: str) -> bool:
    """Release a hold taken by :func:`reserve_tenant_dollars` (e.g. once the run
    has recorded its actual spend, so it isn't double-counted against the cap for
    the rest of its TTL). Also prunes expired holds. Returns True if the id was
    present; a no-op returning False for a blank tenant/id."""
    tid = _lookup_id(tenant_id)
    if not tid or not reservation_id:
        return False
    now = time.time()
    path = _reservations_path(tid)
    with _RESERVE_LOCK, cross_process_lock(path, strict=True):
        data = _load_reservations(tid)
        existed = str(reservation_id) in data
        data.pop(str(reservation_id), None)
        atomic_write_text(
            path, json.dumps(_live_reservations(data, now), indent=2, sort_keys=True))
    return existed


def tenant_remaining_today(tenant_id: str | None) -> float | None:
    """Dollars a tenant may still spend today before hitting its daily cap.

    Returns ``None`` when no cap applies (no tenant, unprovisioned, cap 0/unset,
    enforcement off) so callers leave their own ceiling untouched. Otherwise the
    non-negative remainder ``cap - spent_today - outstanding_reservations`` --
    which a per-run budget can clamp to so a single run can't overshoot the
    tenant's aggregate ceiling. Subtracting outstanding in-flight
    reservations (spend that concurrent runs have committed to but not yet
    recorded) is what closes that concurrency hole: two runs that
    start before either records spend see each other's holds instead of both
    clamping to the full remainder. Coordinates the per-run cap with the
    per-tenant cap; without it the over-quota gate only fires *between* runs,
    after the overshoot."""
    tid = _lookup_id(tenant_id)
    if not tid:
        return None
    cap = _tenant_daily_cap(tid)
    if cap <= 0:
        return None
    return max(0.0, cap - tenant_spend_today(tid) - _outstanding_reservations(tid))


__all__ = [
    "ACTIVE", "SUSPENDED", "DEFAULT_TENANT_DAILY_DOLLARS",
    "MAX_FEATURE_OVERRIDES", "TenantRecord",
    "BILLING_CURRENT", "BILLING_PAST_DUE",
    "TenantSuspended", "UnknownTenant",
    "TenantRegistryError", "DuplicateWorkspaceName",
    "list_tenants", "get_tenant", "workspace_display_key", "create_tenant", "suspend_tenant",
    "resume_tenant", "delete_tenant", "list_removed_tenants", "restore_tenant", "tenant_retired", "set_quota", "set_plan",
    "set_stripe_customer_id", "set_billing_status", "set_byok",
    "set_feature_overrides",
    "get_tenant_by_stripe_customer",
    "is_active", "assert_tenant_active", "tenant_spend_today",
    "tenant_over_quota", "tenant_remaining_today",
    "reserve_tenant_dollars", "reserve_tenant_budget",
    "release_tenant_reservation",
]
