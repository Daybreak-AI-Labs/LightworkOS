"""Provider-level cost caps across all runs.

:class:`maverick.budget.Budget` caps **one run**; :mod:`maverick.quotas` caps
a **principal** per day. Neither bounds what the deployment as a whole may
spend at a given *provider* — fifty perfectly-budgeted runs are still a
$250 Anthropic day nobody approved. This module is the third axis: a ceiling
per provider per UTC period (day or month), enforced at the LLM dispatch
path via an atomic :func:`reserve` for each physical provider call.

Config (opt-in; nothing configured = no caps = behavior unchanged)::

    [budget]
    provider_caps_period = "day"        # "day" (default) | "month"

    [budget.provider_caps]
    anthropic = 50.0                    # dollars per period
    openai    = 20.0

``MAVERICK_PROVIDER_CAPS_PERIOD`` overrides the period knob (env wins, the
house convention). :func:`caps_from_config` is fail-soft for displays, but
admission (:func:`check`, :func:`reserve`) refuses with
:class:`ProviderAccountingUnavailable` while any config source is unreadable:
the caps may have been lost with the file, so "no caps" cannot be assumed.

The ledger (``provider_spend.json`` in the deployment's data root: the bound
client's, else the shared root; one per deployment, not per tenant) maps
``{period_key: {provider: dollars}}`` — period keys are ``YYYY-MM-DD`` (day)
or ``YYYY-MM`` (month), always UTC so the window doesn't shift with host
timezone/DST. Writes are atomic (unique temp file + ``os.replace``, 0600)
and the whole read-modify-write is serialized by an in-process lock **plus a
cross-process advisory flock** on a ``.lock`` sidecar, mirroring
:mod:`maverick.quotas`; the ledger reloads per call rather than caching, so
concurrent processes don't clobber each other's totals (without the flock two
processes both load the same total, both add, and the second ``os.replace``
wins -- dollars vanish from a *spend-cap* ledger and the deployment overspends
past the configured ceiling). Reservations and settlement receipts share that
transaction. The numeric counter includes confirmed costs and outstanding
reservations, so old numeric readers remain conservative. Configured admission
refuses unreadable accounting and unknown final charges; failures never recreate
a damaged ledger as zero. A required marker distinguishes lost established
accounting from fresh setup. Shared PostgreSQL uses its transactional authority
and never substitutes a local file. Crashed reservations do not expire.

Projected prices are estimates. An actual response can cost more than its
projection; settlement records the full charge and blocks subsequent calls at
the cap. The application cannot guarantee an external provider's final bill.

Clock is injectable everywhere (``now=`` epoch seconds) so rollover tests
are deterministic. Stdlib-only, pure library, nothing imports it by default.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import re
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from .file_lock import (
    atomic_create_text,
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import data_dir

log = logging.getLogger(__name__)

PERIOD_DAY = "day"
PERIOD_MONTH = "month"

_LEDGER_LOCK = threading.Lock()

# Cached shared-world handle for the cluster-wide ledger (see _shared_world).
_shared_world_cache = None
_shared_world_cache_key = None
_shared_world_lock = threading.Lock()
_work_item_context: ContextVar[str | None] = ContextVar(
    "maverick_provider_cost_work_item",
    default=None,
)
_provider_operation_context: ContextVar[object | None] = ContextVar(
    "maverick_provider_cost_operation",
    default=None,
)


def authority_identity():
    """Opaque identity of the actual configured counter authority, never a DSN."""
    from .world_model_backends import is_postgres_configured
    if is_postgres_configured():
        from .world_model_backends.postgres import _rls_enabled
        # PostgresWorldModel resolves the effective DSN from this environment.
        # Credential changes conservatively invalidate reviews too.
        settings = ["postgres", os.environ.get("MAVERICK_PG_DSN", ""), _rls_enabled()]
    else:
        settings = ["local", str(_deployment_ledger_path().absolute())]
    return hashlib.sha256(json.dumps(settings).encode("utf-8")).hexdigest()


def _shared_world():
    """Resolve the configured authority; never substitute a local ledger on failure."""
    global _shared_world_cache, _shared_world_cache_key
    try:
        from .world_model_backends import is_postgres_configured
        if not is_postgres_configured():
            return None
        identity = authority_identity()
        with _shared_world_lock:
            if _shared_world_cache is None or _shared_world_cache_key != identity:
                from .world_model import open_world
                selected = open_world()
                if authority_identity() != identity:
                    raise ProviderAccountingUnavailable
                # A previous in-flight Reservation retains its exact old handle;
                # do not close it when selecting a new configured authority.
                _shared_world_cache, _shared_world_cache_key = selected, identity
            return _shared_world_cache
    except Exception as exc:
        _shared_world_cache = None
        _shared_world_cache_key = None
        raise ProviderAccountingUnavailable from exc


class ProviderAccountingUnavailable(RuntimeError):
    """Configured spending authority cannot safely admit another provider call."""

    def __init__(self):
        super().__init__(
            "Provider accounting is unavailable or has unresolved charges. "
            "New calls are blocked; reconcile the retained accounting before retrying."
        )


class EarlierTenantLedgerUnreadable(ProviderAccountingUnavailable):
    """A per-tenant ledger from an earlier version could not be folded in."""

    def __init__(self, name: str):
        RuntimeError.__init__(
            self,
            f"Provider spending recorded by an earlier version in {name} cannot "
            "be read, so new calls with a configured cap are blocked. On the "
            "Provider spending page, export the current accounting and repair it "
            "with totals confirmed from final provider receipts, including the "
            "spend recorded in that file; the repair marks it as reviewed.",
        )
        self.name = name


class EarlierTenantLedgerConflict(EarlierTenantLedgerUnreadable):
    """An earlier per-tenant ledger reuses a reservation key already taken."""

    def __init__(self, name: str):
        RuntimeError.__init__(
            self,
            f"A provider reservation recorded by an earlier version in {name} "
            "uses the same reference or call attempt as another workspace's, so "
            "it cannot be moved into the shared spending record without "
            "guessing which is which. New calls with a configured cap are "
            "blocked. On the Provider spending page, export the current "
            "accounting and repair it with totals confirmed from final provider "
            "receipts, including the spend recorded in that file; the repair "
            "marks it as reviewed.",
        )
        self.name = name


class ProviderAttemptAlreadyAdmitted(ProviderAccountingUnavailable):
    """A durable operation attempt already owns the right to dispatch once."""

    def __init__(self, existing_reference: str):
        RuntimeError.__init__(
            self,
            "This provider operation attempt was already admitted. Reconcile "
            "its existing receipt before creating a new attempt.",
        )
        self.existing_reference = existing_reference


class ProviderCapExceeded(Exception):
    """A provider's per-period spend ceiling has been reached."""

    def __init__(self, provider: str, spent: float, cap: float, period_key: str):
        super().__init__(
            f"provider {provider!r} has spent ${spent:.2f} of its "
            f"${cap:.2f} cap for {period_key}; refusing further calls. "
            f"Raise [budget.provider_caps] {provider} or wait for the next period."
        )
        self.provider = provider
        self.spent = spent
        self.cap = cap
        self.period_key = period_key


@dataclass(frozen=True)
class CapStatus:
    """One provider's standing against its cap. ``cap``/``remaining`` are
    ``None`` when no cap is configured (always allowed)."""

    allowed: bool
    spent: float
    cap: float | None
    remaining: float | None
    reserved: float = 0.0
    unresolved: bool = False


@dataclass(frozen=True)
class ProviderOperationContext:
    """Logical business-operation attribution inherited by physical calls."""

    operation_id: str
    category: str
    service: str | None = None


def _canon(provider: str) -> str:
    return str(provider or "").strip().lower()


def _budget_cfg() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("budget") or {}
    except Exception:  # config must never crash the call path
        return {}


def caps_from_config() -> dict[str, float]:
    """``[budget.provider_caps]`` as ``{provider: dollars}``; fail-soft.

    Non-numeric and non-positive values are dropped (a zero/negative cap is
    a misconfiguration, not a "block everything" switch — that's what the
    killswitch is for).
    """
    raw = _budget_cfg().get("provider_caps")
    if not isinstance(raw, dict):
        return {}
    caps: dict[str, float] = {}
    for name, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        normalized = float(value)
        provider = _canon(name)
        if provider and math.isfinite(normalized) and normalized > 0:
            caps[provider] = normalized
    return caps


def _admission_cap(provider: str) -> float | None:
    """The configured cap for admission; refuses when the config is unreadable."""
    caps = caps_from_config()
    try:
        from .config import config_source_errors
        unreadable = bool(config_source_errors(include_tenant=True))
    except Exception:
        unreadable = True
    if unreadable:
        raise ProviderAccountingUnavailable
    return caps.get(provider)


def period_from_config() -> str:
    """``"day"`` (default) or ``"month"``; env wins; unrecognized -> day."""
    env = os.environ.get("MAVERICK_PROVIDER_CAPS_PERIOD", "").strip().lower()
    if env in (PERIOD_DAY, PERIOD_MONTH):
        return env
    val = str(_budget_cfg().get("provider_caps_period", PERIOD_DAY)).strip().lower()
    return val if val in (PERIOD_DAY, PERIOD_MONTH) else PERIOD_DAY


def period_key(now: float | None = None, period: str | None = None) -> str:
    """The UTC ledger key for ``now``: ``YYYY-MM-DD`` (day) or ``YYYY-MM``."""
    period = period or period_from_config()
    dt = datetime.fromtimestamp(time.time() if now is None else float(now),
                                tz=timezone.utc)
    return dt.strftime("%Y-%m-%d") if period == PERIOD_DAY else dt.strftime("%Y-%m")


def _deployment_ledger_path() -> Path:
    # Deployment-wide, like the Postgres table: a per-tenant file would give N
    # tenants N times the configured ceiling. The deployment is the bound
    # client (its data root), or the shared root when none is bound.
    from .client import strict_client_id
    return data_dir("provider_spend.json", tenant=strict_client_id())


def _ledger_path() -> Path:
    """The deployment ledger, after folding in the spend that earlier versions
    recorded in per-tenant ledgers (once per deployment)."""
    path = _deployment_ledger_path()
    key = str(path.absolute())
    if key not in _FOLDED:
        _fold_tenant_ledgers(path)
        _FOLDED.add(key)
    return path


# Earlier versions kept one ledger per tenant (tenants/<t>/provider_spend.json).
# Their current-period totals are added to the deployment ledger exactly once.
# A journal beside the ledger makes the fold crash-safe: it records the ledger
# digest before and after the fold, so a retry either finishes or skips it and
# never adds the same spend twice. The old files are left in place.
_FOLDED: set[str] = set()
_TENANT_FOLD_SUFFIX = ".tenant-fold"


def _ledger_digest(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, allow_nan=False).encode()).hexdigest()


def _legacy_tenant_ledgers(path: Path) -> list[Path]:
    from . import provider_spend_sqlite
    from .paths import maverick_home

    root = maverick_home() / "tenants"
    if not root.is_dir():
        return []
    found = []
    for child in sorted(root.iterdir()):
        legacy = child / "provider_spend.json"
        if legacy.absolute() == path.absolute() or not child.is_dir():
            continue
        if (legacy.exists() or legacy.with_suffix(legacy.suffix + ".required").exists()
                or provider_spend_sqlite.is_active(legacy)):
            found.append(legacy)
    return found


def _load_legacy(legacy: Path) -> dict:
    from . import provider_spend_sqlite
    if provider_spend_sqlite.is_active(legacy):
        return provider_spend_sqlite.load(legacy, sys.modules[__name__])
    return _load_json(legacy)


def _home_relative(path: Path) -> str:
    from .paths import maverick_home
    try:
        return str(path.absolute().relative_to(maverick_home().absolute()))
    except ValueError:
        return str(path)


def mark_tenant_fold_reviewed(path: Path) -> None:
    """Record that a reviewed accounting repair of ``path`` covers the spend
    in the earlier per-tenant ledgers, so they are not folded in again.
    Callers hold ``path``'s cross-process lock and have just written the
    operator-confirmed totals."""
    journal = path.with_name(path.name + _TENANT_FOLD_SUFFIX)
    reviewed = [_home_relative(legacy) for legacy in _legacy_tenant_ledgers(path)]
    atomic_write_text(journal, json.dumps({
        "state": "done", "reviewed": reviewed, "reviewed_at": time.time()}), mode=0o600)
    _FOLDED.add(str(path.absolute()))


def _fold_legacy_period(folded: dict, legacy: dict, period: str, name: str) -> None:
    """Add one earlier per-tenant ledger's ``period`` into ``folded``: totals and
    reservation receipts (state, projection and claims unchanged), plus all of
    its attempt-index rows. A receipt's projection is already part of its old
    total, so totals and receipts move as they are and nothing is added twice.
    Keys are kept, so existing references, organization call keys and attempt
    keys still resolve; a key another source already uses is refused."""
    bucket = folded.setdefault(period, {})
    receipts = legacy.get(_RECEIPTS, {}).get(period, {})
    for provider, total in legacy.get(period, {}).items():
        bucket[provider] = _amount(bucket.get(provider, 0.0)) + _amount(total)
        rows = receipts.get(provider) or {}
        if not rows:
            continue
        target = folded.setdefault(_RECEIPTS, {}).setdefault(period, {}).setdefault(provider, {})
        for request_id, row in rows.items():
            if request_id in target:
                raise EarlierTenantLedgerConflict(name)
            target[request_id] = json.loads(json.dumps(row))
    # Every attempt row moves (not only this period's): it is what refuses a
    # second dispatch of an operation attempt that was already admitted.
    index = legacy.get(_ATTEMPT_INDEX) or {}
    for attempt_key, row in index.items():
        existing = folded.setdefault(_ATTEMPT_INDEX, {}).get(attempt_key)
        if existing is not None and existing != row:
            raise EarlierTenantLedgerConflict(name)
        folded[_ATTEMPT_INDEX][attempt_key] = dict(row)


def _fold_tenant_ledgers(path: Path) -> None:
    from .world_model_backends import is_postgres_configured
    if is_postgres_configured():
        return  # the shared database was the authority before, too
    journal = path.with_name(path.name + _TENANT_FOLD_SUFFIX)
    if not journal.exists() and not _legacy_tenant_ledgers(path):
        return
    try:
        with _LEDGER_LOCK, cross_process_lock(path, strict=True):
            state = json.loads(atomic_read_text(journal)) if journal.exists() else {}
            if state.get("state") == "done":
                return
            current = _load(path)
            before = _ledger_digest(current)
            if state.get("state") == "pending":
                if before == state["after"]:
                    atomic_write_text(journal, json.dumps({**state, "state": "done"}), mode=0o600)
                    return
                if before != state["before"]:
                    raise ProviderAccountingUnavailable
            period = state.get("period") or period_key()
            folded = json.loads(json.dumps(current))
            for legacy in _legacy_tenant_ledgers(path):
                try:
                    legacy_data = _load_legacy(legacy)
                except Exception as exc:
                    raise EarlierTenantLedgerUnreadable(_home_relative(legacy)) from exc
                _fold_legacy_period(folded, legacy_data, period, _home_relative(legacy))
            if folded.get(_RECEIPTS) or _ATTEMPT_INDEX in folded:
                try:
                    folded[_ATTEMPT_INDEX] = _complete_attempt_index(folded)
                    _validate_ledger(folded)
                except ProviderAccountingUnavailable as exc:
                    raise EarlierTenantLedgerConflict("tenants/*/provider_spend.json") from exc
            after = _ledger_digest(folded)
            pending = {"state": "pending", "period": period, "before": before, "after": after}
            atomic_write_text(journal, json.dumps(pending), mode=0o600)
            if after != before:
                _save(path, folded)
            atomic_write_text(journal, json.dumps({**pending, "state": "done"}), mode=0o600)
    except ProviderAccountingUnavailable:
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc


def recorded_at() -> float | None:
    """When provider spending last reached this installation's ledger (epoch
    seconds), for a page's "Spending updated" label. None when nothing is
    recorded here, and None for a shared database ledger, whose rows carry no
    time this module can read: no label beats a made-up one."""
    try:
        if _shared_world() is not None:
            return None
    except ProviderAccountingUnavailable:
        return None
    from . import provider_spend_sqlite

    legacy = _deployment_ledger_path()
    database = provider_spend_sqlite.database_path(legacy)
    stamps = []
    for path in (legacy, database, database.with_name(database.name + "-wal")):
        try:
            stamps.append(path.stat().st_mtime)
        except OSError:
            continue
    return max(stamps) if stamps else None


def _use_indexed_ledger(path: Path) -> bool:
    """Migrate healthy local accounting before the legacy file size ceiling."""
    if path.absolute() != _deployment_ledger_path().absolute():
        return False
    from . import provider_spend_sqlite
    if provider_spend_sqlite.is_active(path):
        return True
    try:
        return path.stat().st_size >= _INDEXED_MIGRATION_BYTES
    except FileNotFoundError:
        return False


_RECEIPTS = "__provider_reservations_v1__"
_ATTEMPT_INDEX = "__provider_attempt_index_v1__"
_REFERENCE_PREFIX = "provider-cap:v1:"
_MAX_LEDGER_BYTES = 16 * 1024 * 1024
_INDEXED_MIGRATION_BYTES = 512 * 1024
_MAX_DISCOVERY_PAGE = 200
_MAX_CATALOGUE_RECEIPTS = 2000
_PERIOD = re.compile(r"[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?\Z")
_OPERATION_ID = re.compile(r"[A-Za-z0-9_.:-]{1,192}\Z")
_COST_CATEGORIES = frozenset({
    "evaluation", "generation", "human", "inference", "other", "retrieval",
    "rework", "retry", "search", "storage", "update",
})
_ATTEMPT_STATES = frozenset({"cancelled", "failed", "succeeded", "unknown"})
_LEGACY_UNBOUND_OPERATION_SCOPE = hashlib.sha256(
    b"maverick-provider-operation:legacy-unbound"
).hexdigest()


def _amount(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProviderAccountingUnavailable
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise ProviderAccountingUnavailable
    return value


def _validate_outcome_claim(row):
    claim = row.get("outcome_claim")
    claim_state = row.get("outcome_claim_state")
    claim_event = row.get("outcome_claim_event")
    if claim is not None and (
        not isinstance(claim, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", claim)
    ):
        raise ProviderAccountingUnavailable
    if claim is None:
        if claim_state is not None or claim_event is not None:
            raise ProviderAccountingUnavailable
        return
    # Rows written before the two-phase claim protocol have no state. Treat
    # them as prepared so retention stays conservative until a retry verifies
    # the durable outcome event and commits the claim.
    if claim_state not in {None, "prepared", "committed"}:
        raise ProviderAccountingUnavailable
    if claim_state == "committed":
        if (
            not isinstance(claim_event, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", claim_event)
        ):
            raise ProviderAccountingUnavailable
    elif claim_event is not None:
        raise ProviderAccountingUnavailable


def _validate_operation_metadata(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "operation_id", "category", "parent_category", "attempt_no",
        "service", "attempt_state",
    }:
        raise ProviderAccountingUnavailable
    operation_id = value.get("operation_id")
    category = value.get("category")
    parent_category = value.get("parent_category")
    attempt_no = value.get("attempt_no")
    service = value.get("service")
    attempt_state = value.get("attempt_state")
    if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
        raise ProviderAccountingUnavailable
    if category not in _COST_CATEGORIES or parent_category not in _COST_CATEGORIES:
        raise ProviderAccountingUnavailable
    if type(attempt_no) is not int or not 1 <= attempt_no <= 1_000_000:
        raise ProviderAccountingUnavailable
    if service is not None and (
        not isinstance(service, str)
        or not 1 <= len(service) <= 256
        or service != service.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in service)
    ):
        raise ProviderAccountingUnavailable
    if attempt_state not in _ATTEMPT_STATES:
        raise ProviderAccountingUnavailable
    return dict(value)


def _validate_receipts(total, receipts):
    total = _amount(total)
    if not isinstance(receipts, dict):
        raise ProviderAccountingUnavailable
    charged = 0.0
    for identity, row in receipts.items():
        if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", identity):
            raise ProviderAccountingUnavailable
        if not isinstance(row, dict) or set(row) - {
            "projected", "state", "actual", "reconciliation",
            "work_item_sha256", "outcome_claim", "cost_basis",
            "pricing_evidence", "outcome_claim_state", "outcome_claim_event",
            "operation",
            "operation_scope_sha256",
        } or not {"projected", "state", "actual"} <= set(row):
            raise ProviderAccountingUnavailable
        if "reconciliation" in row and (not isinstance(row["reconciliation"], str)
                                       or not re.fullmatch(r"PAR-[A-Za-z0-9_-]+", row["reconciliation"])):
            raise ProviderAccountingUnavailable
        if "work_item_sha256" in row and (
            not isinstance(row["work_item_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["work_item_sha256"])
        ):
            raise ProviderAccountingUnavailable
        _validate_outcome_claim(row)
        operation = _validate_operation_metadata(row.get("operation"))
        operation_scope = row.get("operation_scope_sha256")
        if operation_scope is not None and (
            operation is None
            or not isinstance(operation_scope, str)
            or not re.fullmatch(r"[0-9a-f]{64}", operation_scope)
            or (
                row.get("work_item_sha256") is not None
                and operation_scope != row["work_item_sha256"]
            )
        ):
            raise ProviderAccountingUnavailable
        projection = _amount(row["projected"])
        if row["state"] not in {"held", "unknown", "settled"}:
            raise ProviderAccountingUnavailable
        if row["state"] == "settled":
            charged += _amount(row["actual"])
            basis = row.get("cost_basis", "estimated")
            if basis not in {"estimated", "observed"}:
                raise ProviderAccountingUnavailable
            evidence = row.get("pricing_evidence")
            if evidence is not None:
                try:
                    from .outcome_accounting import _pricing_evidence

                    normalized = _pricing_evidence(evidence)
                except Exception as exc:
                    raise ProviderAccountingUnavailable from exc
                if basis == "observed" and not normalized["verified"]:
                    raise ProviderAccountingUnavailable
        else:
            if (
                row["actual"] is not None
                or row.get("cost_basis") is not None
                or row.get("pricing_evidence") is not None
            ):
                raise ProviderAccountingUnavailable
            charged += projection
    if not math.isfinite(charged) or charged > total + 1e-8:
        raise ProviderAccountingUnavailable
    return total, receipts


def _operation_attempt_key(
    scope_sha256: str,
    operation_id: str,
    attempt_no: int,
) -> str:
    framed = json.dumps(
        [scope_sha256, operation_id, attempt_no],
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(framed.encode("utf-8")).hexdigest()


def _operation_metadata_sha256(operation: dict[str, object]) -> str:
    encoded = json.dumps(
        {
            "category": operation["category"],
            "parent_category": operation["parent_category"],
            "service": operation["service"],
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _operation_attempt_claim(
    operation: dict[str, object],
    *,
    work_item_sha256: str | None,
    request_id: str,
) -> dict[str, object]:
    scope_sha256 = work_item_sha256 or _LEGACY_UNBOUND_OPERATION_SCOPE
    return {
        "scope_sha256": scope_sha256,
        "operation_id": operation["operation_id"],
        "attempt_no": operation["attempt_no"],
        "category": operation["category"],
        "parent_category": operation["parent_category"],
        "service": operation["service"],
        "metadata_sha256": _operation_metadata_sha256(operation),
        "request_id": request_id,
    }


def _validate_attempt_index_rows(value: object) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        raise ProviderAccountingUnavailable
    validated: dict[str, dict[str, str]] = {}
    for attempt_key, row in value.items():
        if (
            not isinstance(attempt_key, str)
            or not re.fullmatch(r"[0-9a-f]{64}", attempt_key)
            or not isinstance(row, dict)
            or set(row) != {"metadata_sha256", "provider", "period", "request_id"}
            or not isinstance(row.get("metadata_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", row["metadata_sha256"])
            or not isinstance(row.get("provider"), str)
            or not row["provider"]
            or row["provider"] != _canon(row["provider"])
            or not isinstance(row.get("period"), str)
            or not _PERIOD.fullmatch(row["period"])
            or not isinstance(row.get("request_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", row["request_id"])
        ):
            raise ProviderAccountingUnavailable
        validated[attempt_key] = dict(row)
    return validated


def _receipt_attempt_index_row(
    provider: str,
    period: str,
    request_id: str,
    row: dict[str, object],
) -> tuple[str, dict[str, str]] | None:
    operation = _validate_operation_metadata(row.get("operation"))
    if operation is None:
        return None
    scope_sha256 = (
        row.get("operation_scope_sha256")
        or row.get("work_item_sha256")
        or _LEGACY_UNBOUND_OPERATION_SCOPE
    )
    if not isinstance(scope_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", scope_sha256,
    ):
        raise ProviderAccountingUnavailable
    return (
        _operation_attempt_key(
            scope_sha256,
            str(operation["operation_id"]),
            int(operation["attempt_no"]),
        ),
        {
            "metadata_sha256": _operation_metadata_sha256(operation),
            "provider": provider,
            "period": period,
            "request_id": request_id,
        },
    )


def _complete_attempt_index(data: dict) -> dict[str, dict[str, str]]:
    existing = data.get(_ATTEMPT_INDEX)
    index = {} if existing is None else _validate_attempt_index_rows(existing)
    metadata = data.get(_RECEIPTS, {})
    for period, providers in metadata.items():
        for provider, receipts in providers.items():
            for request_id, receipt in receipts.items():
                derived = _receipt_attempt_index_row(
                    provider, period, request_id, receipt,
                )
                if derived is None:
                    continue
                attempt_key, row = derived
                prior = index.get(attempt_key)
                if prior is not None and prior != row:
                    raise ProviderAccountingUnavailable
                index[attempt_key] = row
    return index


def _existing_attempt_reference(row: dict[str, str]) -> str:
    return reservation_reference(
        Reservation(row["provider"], row["period"], row["request_id"], 0.0, None)
    )


def _admit_attempt_index(
    index: dict[str, dict[str, str]],
    claim: dict[str, object],
    *,
    provider: str,
    period: str,
) -> None:
    attempt_key = _operation_attempt_key(
        str(claim["scope_sha256"]),
        str(claim["operation_id"]),
        int(claim["attempt_no"]),
    )
    prior = index.get(attempt_key)
    if prior is not None:
        if prior["metadata_sha256"] != claim["metadata_sha256"]:
            raise ProviderAccountingUnavailable
        raise ProviderAttemptAlreadyAdmitted(_existing_attempt_reference(prior))
    index[attempt_key] = {
        "metadata_sha256": str(claim["metadata_sha256"]),
        "provider": provider,
        "period": period,
        "request_id": str(claim["request_id"]),
    }


def _validate_ledger(raw: dict) -> None:
    if not isinstance(raw, dict):
        raise ProviderAccountingUnavailable
    metadata = raw.get(_RECEIPTS, {})
    if not isinstance(metadata, dict):
        raise ProviderAccountingUnavailable
    for period, bucket in raw.items():
        if period in {_RECEIPTS, _ATTEMPT_INDEX}:
            continue
        if not _PERIOD.fullmatch(period) or not isinstance(bucket, dict):
            raise ProviderAccountingUnavailable
        for name, total in bucket.items():
            if not isinstance(name, str) or not name or name != _canon(name):
                raise ProviderAccountingUnavailable
            _validate_receipts(total, metadata.get(period, {}).get(name, {}))
    for period, providers in metadata.items():
        if not isinstance(providers, dict) or period not in raw:
            raise ProviderAccountingUnavailable
        for name, receipts in providers.items():
            if name not in raw[period]:
                raise ProviderAccountingUnavailable
            _validate_receipts(raw[period][name], receipts)
    if _ATTEMPT_INDEX in raw:
        index = _validate_attempt_index_rows(raw[_ATTEMPT_INDEX])
        if _complete_attempt_index(raw) != index:
            raise ProviderAccountingUnavailable


def _load_json(path: Path) -> dict:
    try:
        ensure_private_directory(path.parent)
        ensure_private_file(path, 0o600)
        if path.stat().st_size > _MAX_LEDGER_BYTES:
            raise ProviderAccountingUnavailable
        raw_text = atomic_read_text(path)
        if len(raw_text.encode("utf-8")) > _MAX_LEDGER_BYTES:
            raise ProviderAccountingUnavailable
        raw = json.loads(raw_text)
        _validate_ledger(raw)
        return raw
    except FileNotFoundError as exc:
        if path.with_suffix(path.suffix + ".required").exists():
            raise ProviderAccountingUnavailable from exc
        return {}
    except (OSError, ValueError, AttributeError, TypeError) as exc:
        raise ProviderAccountingUnavailable from exc


def _load(path: Path) -> dict:
    if _use_indexed_ledger(path):
        from . import provider_spend_sqlite
        try:
            return provider_spend_sqlite.load(path, sys.modules[__name__])
        except Exception as exc:
            raise ProviderAccountingUnavailable from exc
    return _load_json(path)


def _save_json(path: Path, data: dict) -> None:
    ensure_private_directory(path.parent)
    encoded = json.dumps(data, allow_nan=False)
    if len(encoded.encode("utf-8")) > _MAX_LEDGER_BYTES:
        raise ProviderAccountingUnavailable
    # Publish the required marker first: a crash between marker and ledger is
    # safely unavailable, never an apparently fresh zero-balance authority.
    marker = path.with_suffix(path.suffix + ".required")
    try:
        atomic_create_text(marker, "provider accounting v1\n")
    except FileExistsError:
        ensure_private_file(marker, 0o600)
    atomic_write_text(path, encoded, mode=0o600)


def _save(path: Path, data: dict) -> None:
    if _use_indexed_ledger(path):
        from . import provider_spend_sqlite
        try:
            provider_spend_sqlite.replace(path, data, sys.modules[__name__])
        except Exception as exc:
            raise ProviderAccountingUnavailable from exc
        return
    _save_json(path, data)


@dataclass(frozen=True)
class Reservation:
    provider: str
    period: str
    request_id: str
    projected: float
    path: Path | None = field(repr=False)
    shared: object = field(default=None, repr=False, compare=False)
    # The tenant whose organization admission this call holds, if any.
    organization_tenant: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ReservationSnapshot:
    """A verified provider-call receipt safe to project into outcome records."""

    reference: str
    provider: str
    period: str
    request_id: str
    projected: float
    state: str
    actual: float | None
    currency: str
    cost_basis: str
    pricing_evidence: dict[str, object] | None
    work_item_sha256: str | None
    outcome_claim: str | None
    outcome_claim_state: str | None
    outcome_claim_event: str | None
    operation: dict[str, object] | None
    reconciliation: str | None = None


@dataclass(frozen=True)
class ReservationPage:
    """One bounded page of receipts for an exact tenant-bound work item."""

    receipts: tuple[ReservationSnapshot, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class ReservationCatalogue:
    """One coherent, bounded receipt snapshot for an exact work item."""

    receipts: tuple[ReservationSnapshot, ...]
    version: str


def _b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _unb64(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,300}", value):
        raise ProviderAccountingUnavailable
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProviderAccountingUnavailable from exc


def reservation_reference(reservation: Reservation) -> str:
    """Return a versioned opaque reference with no filesystem or DSN details."""

    if not isinstance(reservation, Reservation):
        raise ProviderAccountingUnavailable
    return (
        f"{_REFERENCE_PREFIX}{_b64(reservation.provider)}:"
        f"{reservation.period}:{_b64(reservation.request_id)}"
    )


def _parse_reference(reference: str) -> tuple[str, str, str]:
    if not isinstance(reference, str) or len(reference) > 512:
        raise ProviderAccountingUnavailable
    parts = reference.removeprefix(_REFERENCE_PREFIX).split(":")
    if not reference.startswith(_REFERENCE_PREFIX) or len(parts) != 3:
        raise ProviderAccountingUnavailable
    provider, period, request_id = _unb64(parts[0]), parts[1], _unb64(parts[2])
    if provider != _canon(provider) or not provider or not _PERIOD.fullmatch(period):
        raise ProviderAccountingUnavailable
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", request_id):
        raise ProviderAccountingUnavailable
    return provider, period, request_id


def _work_item_hash(work_item_id: str) -> str:
    from .paths import current_tenant_id_strict

    work_item_id = _validate_work_item_id(work_item_id)
    tenant = current_tenant_id_strict()
    return hashlib.sha256(f"{tenant}\0{work_item_id}".encode()).hexdigest()


def _validate_work_item_id(work_item_id: object) -> str:
    if (
        not isinstance(work_item_id, str)
        or work_item_id != work_item_id.strip()
        or not work_item_id
        or len(work_item_id) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in work_item_id)
    ):
        raise ProviderAccountingUnavailable
    return work_item_id


def _validate_operation_context(
    operation_id: object,
    category: object,
    service: object,
) -> ProviderOperationContext:
    if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
        raise ProviderAccountingUnavailable
    if category not in _COST_CATEGORIES:
        raise ProviderAccountingUnavailable
    if service is not None and (
        not isinstance(service, str)
        or not 1 <= len(service) <= 256
        or service != service.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in service)
    ):
        raise ProviderAccountingUnavailable
    return ProviderOperationContext(operation_id, category, service)


@contextmanager
def work_item_scope(work_item_id: str):
    """Attribute nested physical provider calls to one stable work item.

    Context variables preserve the binding across async tasks while keeping
    concurrent requests isolated. Nested scopes restore the prior binding on
    every exit path. Tenant identity is applied only when a receipt is written,
    inside the caller's authoritative :func:`tenant_scope`.
    """

    token = _work_item_context.set(_validate_work_item_id(work_item_id))
    try:
        yield
    finally:
        _work_item_context.reset(token)


@contextmanager
def provider_operation_scope(
    *,
    operation_id: str,
    category: str,
    service: str | None = None,
    work_item_id: str | None = None,
):
    """Bind semantic cost attribution around one logical provider operation."""

    context = _validate_operation_context(operation_id, category, service)
    token = _provider_operation_context.set(context)
    try:
        if work_item_id is None:
            yield context
        else:
            with work_item_scope(work_item_id):
                yield context
    finally:
        _provider_operation_context.reset(token)


def current_provider_operation() -> ProviderOperationContext | None:
    """Return the current logical operation without exposing tenant material."""

    value = _provider_operation_context.get()
    return value if isinstance(value, ProviderOperationContext) else None


def _reservation_operation(
    *,
    operation_id: str | None,
    category: str | None,
    parent_category: str | None,
    attempt_no: int | None,
    service: str | None,
) -> dict[str, object] | None:
    context = current_provider_operation()
    if (
        context is None
        and operation_id is None
        and category is None
        and parent_category is None
        and attempt_no is None
        and service is None
    ):
        return None
    selected_category = category or (context.category if context else None)
    selected = {
        "operation_id": operation_id or (context.operation_id if context else None),
        "category": selected_category,
        "parent_category": parent_category or selected_category,
        "attempt_no": 1 if attempt_no is None else attempt_no,
        "service": service if service is not None else (context.service if context else None),
        "attempt_state": "unknown",
    }
    return _validate_operation_metadata(selected)


def _current_work_item() -> str | None:
    explicit = _work_item_context.get()
    if explicit is not None:
        return explicit
    try:
        from .logging_config import current_goal_id

        goal_id = current_goal_id()
    except Exception:
        return None
    return None if goal_id is None else f"goal:{goal_id}"


def _snapshot(
    provider: str,
    period: str,
    request_id: str,
    row: dict,
) -> ReservationSnapshot:
    reservation = Reservation(provider, period, request_id, row["projected"], None)
    return ReservationSnapshot(
        reference=reservation_reference(reservation),
        provider=provider,
        period=period,
        request_id=request_id,
        projected=row["projected"],
        state=row["state"],
        actual=row["actual"],
        currency="USD",
        cost_basis=(
            row.get("cost_basis", "estimated")
            if row["state"] == "settled" else "unknown"
        ),
        pricing_evidence=(
            dict(row["pricing_evidence"])
            if row.get("pricing_evidence") is not None else None
        ),
        work_item_sha256=row.get("work_item_sha256"),
        outcome_claim=row.get("outcome_claim"),
        outcome_claim_state=(
            row.get("outcome_claim_state", "prepared")
            if row.get("outcome_claim") is not None else None
        ),
        outcome_claim_event=row.get("outcome_claim_event"),
        operation=_validate_operation_metadata(row.get("operation")),
        reconciliation=row.get("reconciliation"),
    )


def _catalogue_version(
    work_item_sha256: str,
    snapshots: list[ReservationSnapshot],
) -> str:
    rows = [{
        "reference": row.reference,
        "provider": row.provider,
        "period": row.period,
        "request_id": row.request_id,
        "projected": row.projected,
        "state": row.state,
        "actual": row.actual,
        "currency": row.currency,
        "cost_basis": row.cost_basis,
        "pricing_evidence": row.pricing_evidence,
        "work_item_sha256": row.work_item_sha256,
        "operation": row.operation,
    } for row in snapshots]
    encoded = json.dumps(
        {
            "schema": "provider-reservation-catalogue:v1",
            "work_item_sha256": work_item_sha256,
            "receipts": rows,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _mutate(
    name,
    period,
    operation,
    *,
    path=None,
    shared=None,
    attempt_claim=None,
    new_request_id=None,
    target_request_id=None,
    numeric_only=False,
):
    def validated(total, receipts):
        total, receipts, result = operation(total, receipts)
        _validate_receipts(total, receipts)
        if len(json.dumps(receipts, allow_nan=False).encode("utf-8")) > _MAX_LEDGER_BYTES:
            raise ProviderAccountingUnavailable
        return total, receipts, result

    try:
        if shared is not None:
            return shared.mutate_provider_cap(period, name, validated)
        with _LEDGER_LOCK, cross_process_lock(path, strict=True):
            # Select the authority only after acquiring the same lock used by
            # migration. A writer that queued against a growing JSON file
            # must re-check rather than update the stale source after another
            # process published the indexed database.
            if _use_indexed_ledger(path):
                from . import provider_spend_sqlite
                return provider_spend_sqlite.mutate(
                    path, period, name, operation, sys.modules[__name__],
                    attempt_claim=attempt_claim,
                    new_request_id=new_request_id,
                    target_request_id=target_request_id,
                    numeric_only=numeric_only,
                )
            data = _load_json(path)
            attempt_index = None
            if attempt_claim is not None:
                attempt_index = _complete_attempt_index(data)
                _admit_attempt_index(
                    attempt_index,
                    attempt_claim,
                    provider=name,
                    period=period,
                )
            total = data.get(period, {}).get(name, 0.0)
            receipts = data.get(_RECEIPTS, {}).get(period, {}).get(name, {})
            total, receipts, result = validated(total, receipts)
            data.setdefault(period, {})[name] = total
            if receipts:
                data.setdefault(_RECEIPTS, {}).setdefault(period, {})[name] = receipts
            if attempt_index is not None:
                data[_ATTEMPT_INDEX] = attempt_index
            _save_json(path, data)
            return result
    except (ProviderCapExceeded, ProviderAccountingUnavailable):
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc


def record(provider: str, dollars: float, *, now: float | None = None,
           path: Path | None = None) -> None:
    """Record legacy/unreserved spend without replacing damaged accounting.

    An incurred call cannot be undone. Failure is logged, and configured
    admission subsequently refuses the unavailable ledger instead of zeroing it.
    Reserved dispatch uses settle(), which retains its durable charge on failure.
    """
    name = _canon(provider)
    amount = max(0.0, float(dollars or 0.0))
    if not name or amount == 0.0:
        return
    try:
        amount = _amount(amount)
        shared = _shared_world() if path is None else None
        def add(total, receipts):
            total, receipts = _validate_receipts(total, receipts)
            return total + amount, receipts, None
        if shared is not None:
            _mutate_current(
                name,
                lambda _period, total, receipts: add(total, receipts),
                shared=shared,
            )
        else:
            _mutate(name, period_key(now), add, path=path or _ledger_path(),
                    numeric_only=True)
    except (OSError, ProviderAccountingUnavailable):
        log.warning("Provider spend could not be recorded; accounting requires reconciliation.")


def _status(total, receipts, cap):
    total, receipts = _validate_receipts(total, receipts)
    held = sum(row["projected"] for row in receipts.values() if row["state"] != "settled")
    unresolved = any(
        row["state"] == "unknown"
        or (row["state"] == "held" and row["projected"] == 0)
        for row in receipts.values()
    )
    return CapStatus(
        cap is None or (total < cap and not unresolved),
        max(0.0, total - held),
        cap,
        None if cap is None else max(0.0, cap - total),
        held,
        unresolved,
    )


def check(provider: str, *, now: float | None = None,
          path: Path | None = None) -> CapStatus:
    name = _canon(provider)
    cap = _admission_cap(name)
    try:
        shared = _shared_world() if path is None else None
        if shared is not None:
            period, total, receipts = shared.read_current_provider_cap(
                period_from_config(), name,
            )
            if not isinstance(period, str) or not _PERIOD.fullmatch(period):
                raise ProviderAccountingUnavailable
        else:
            period = period_key(now)
            ledger = path or _ledger_path()
            if _use_indexed_ledger(ledger):
                from . import provider_spend_sqlite
                total, held, unresolved = provider_spend_sqlite.read_status(
                    ledger, period, name, sys.modules[__name__],
                )
                return CapStatus(
                    cap is None or (total < cap and not unresolved),
                    max(0.0, total - held), cap,
                    None if cap is None else max(0.0, cap - total),
                    held, unresolved,
                )
            else:
                data = _load(ledger)
                total = data.get(period, {}).get(name, 0.0)
                receipts = data.get(_RECEIPTS, {}).get(period, {}).get(name, {})
        return _status(total, receipts, cap)
    except Exception as exc:
        if cap is None:
            return CapStatus(True, 0.0, None, None)
        if isinstance(exc, ProviderAccountingUnavailable):
            raise
        raise ProviderAccountingUnavailable from exc


def _reserve_provider(
    provider: str,
    projected_dollars: float,
    *,
    now=None,
    path=None,
    request_id: str | None = None,
    work_item_id: str | None = None,
    operation_id: str | None = None,
    category: str | None = None,
    parent_category: str | None = None,
    attempt_no: int | None = None,
    service: str | None = None,
    projection_known: bool = True,
    force_receipt: bool = False,
) -> Reservation | None:
    """Durably encumber capacity before each physical call, including hedges.

    Holds never expire automatically. A crashed caller cannot reopen capacity;
    uncertain completion retains the hold until an exact actual-cost receipt.
    The legacy numeric total includes holds, so older readers stay conservative.
    """
    name = _canon(provider)
    if not name:
        raise ProviderAccountingUnavailable
    cap = _admission_cap(name)
    if type(projection_known) is not bool or (cap is not None and not projection_known):
        raise ProviderAccountingUnavailable
    work_item = _current_work_item() if work_item_id is None else work_item_id
    # Preserve the uncapped, unattributed library path. An attributed platform
    # call still receives a durable cost receipt even when no spending ceiling
    # is configured, which is required for complete per-work accounting.
    if cap is None and work_item is None and not force_receipt:
        return None
    projected = _amount(projected_dollars)
    identity = request_id or uuid.uuid4().hex
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", identity):
        raise ProviderAccountingUnavailable
    shared = _shared_world() if path is None else None
    ledger = None if shared is not None else (path or _ledger_path()).absolute()
    work_item_sha256 = None if work_item is None else _work_item_hash(work_item)
    operation = _reservation_operation(
        operation_id=operation_id,
        category=category,
        parent_category=parent_category,
        attempt_no=attempt_no,
        service=service,
    )
    operation_scope_sha256 = (
        work_item_sha256 or _LEGACY_UNBOUND_OPERATION_SCOPE
        if operation is not None else None
    )
    attempt_claim = (
        _operation_attempt_claim(
            operation,
            work_item_sha256=work_item_sha256,
            request_id=identity,
        )
        if operation is not None else None
    )
    def admit(period, total, receipts):
        total, receipts = _validate_receipts(total, receipts)
        # An admission identity grants one physical dispatch, never a retry.
        if identity in receipts or (
            cap is not None
            and any(
                row["state"] == "unknown"
                or (row["state"] == "held" and row["projected"] == 0)
                for row in receipts.values()
            )
        ):
            raise ProviderAccountingUnavailable
        if cap is not None and (total >= cap or total + projected > cap):
            raise ProviderCapExceeded(name, total, cap, period)
        receipts[identity] = {
            "projected": projected, "state": "held", "actual": None,
            **({"work_item_sha256": work_item_sha256} if work_item_sha256 else {}),
            **({"operation": operation} if operation is not None else {}),
            **(
                {"operation_scope_sha256": operation_scope_sha256}
                if operation_scope_sha256 is not None else {}
            ),
        }
        return total + projected, receipts, None
    if shared is not None:
        period, _ = _mutate_current(
            name,
            admit,
            shared=shared,
            attempt_claim=attempt_claim,
        )
    else:
        period = period_key(now)
        _mutate(
            name,
            period,
            lambda total, receipts: admit(period, total, receipts),
            path=ledger,
            attempt_claim=attempt_claim,
            new_request_id=identity,
        )
    return Reservation(name, period, identity, projected, ledger, shared)


def reserve(
    provider: str, projected_dollars: float, *, now=None, path=None,
    request_id: str | None = None, work_item_id: str | None = None,
    operation_id: str | None = None, category: str | None = None,
    parent_category: str | None = None, attempt_no: int | None = None,
    service: str | None = None, projection_known: bool = True,
    organization_budget=None,
) -> Reservation | None:
    """Admit both organization and provider authorities before one dispatch."""
    from . import spending_limits
    from .budget import BudgetExceeded
    from .tenant import provider_admission as organization

    identity = request_id or uuid.uuid4().hex
    name = _canon(provider)
    if not name or not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", identity):
        raise ProviderAccountingUnavailable
    # Administrator-set workspace and per-person limits (none by default).
    spending_limits.admit(organization_budget or organization.current_budget(),
                          projected_dollars)
    try:
        handle = organization.reserve_call(name, identity, _amount(projected_dollars),
                                           projection_known=projection_known,
                                           budget=organization_budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc
    hold = None
    try:
        hold = _reserve_provider(
            name, projected_dollars, now=now, path=path, request_id=identity,
            work_item_id=work_item_id, operation_id=operation_id, category=category,
            parent_category=parent_category, attempt_no=attempt_no, service=service,
            projection_known=projection_known, force_receipt=handle is not None,
        )
        if handle is not None:
            organization.attach_reference(handle, reservation_reference(hold))
            if hold is not None:
                hold = replace(hold, organization_tenant=handle[0])
        return hold
    except BaseException:
        # Neither authority has released dispatch to the caller. Failure here
        # is known not to have spent externally; no TTL or crash inference.
        try:
            if hold is not None:
                # Never dispatched: an operation's attempt is cancelled, not a
                # $0 success.
                operation = _reservation_operation(
                    operation_id=operation_id, category=category,
                    parent_category=parent_category, attempt_no=attempt_no, service=service)
                _settle_provider(hold, 0.0,
                                 attempt_state=None if operation is None else "cancelled")
            organization.cancel_before_dispatch(handle)
        except Exception as exc:
            raise ProviderAccountingUnavailable from exc
        raise


def _settle_provider(
    reservation: Reservation,
    actual_dollars: float | None,
    *,
    cost_basis: str | None = None,
    pricing_evidence: dict[str, object] | None = None,
    attempt_state: str | None = None,
) -> ReservationSnapshot:
    """Replace one hold with exact usage, or retain it as unresolved.

    Repeated identical receipts are no-ops; conflicting receipts and missing
    identities refuse. None never means free: provider errors/cancellation may
    have incurred external cost. Settlement uses the original backend/period.
    """
    actual = None if actual_dollars is None else _amount(actual_dollars)
    if attempt_state is not None and attempt_state not in _ATTEMPT_STATES:
        raise ProviderAccountingUnavailable
    if actual is None:
        if cost_basis is not None or pricing_evidence is not None:
            raise ProviderAccountingUnavailable
        normalized_basis = None
        normalized_evidence = None
    else:
        normalized_basis = "estimated" if cost_basis is None else cost_basis
        if normalized_basis not in {"estimated", "observed"}:
            raise ProviderAccountingUnavailable
        if pricing_evidence is None:
            normalized_evidence = None
        else:
            try:
                from .outcome_accounting import _pricing_evidence

                _pricing_evidence(pricing_evidence)
                normalized_evidence = dict(pricing_evidence)
            except Exception as exc:
                raise ProviderAccountingUnavailable from exc
            if normalized_basis == "observed" and not normalized_evidence["verified"]:
                raise ProviderAccountingUnavailable
    def finish(total, receipts):
        total, receipts = _validate_receipts(total, receipts)
        row = receipts.get(reservation.request_id)
        if row is None or row["projected"] != reservation.projected:
            raise ProviderAccountingUnavailable
        operation = _validate_operation_metadata(row.get("operation"))
        if attempt_state is not None and operation is None:
            raise ProviderAccountingUnavailable
        if operation is not None:
            current_attempt_state = operation["attempt_state"]
            selected_attempt_state = (
                attempt_state
                if attempt_state is not None
                else (
                    "succeeded"
                    if row["state"] == "held" and actual is not None
                    else current_attempt_state
                )
            )
            if (
                current_attempt_state != "unknown"
                and selected_attempt_state != current_attempt_state
            ):
                raise ProviderAccountingUnavailable
            row["operation"] = {
                **operation,
                "attempt_state": selected_attempt_state,
            }
        if row["state"] == "settled":
            if (
                actual != row["actual"]
                or normalized_basis != row.get("cost_basis", "estimated")
                or normalized_evidence != row.get("pricing_evidence")
            ):
                raise ProviderAccountingUnavailable
            return total, receipts, dict(row)
        if actual is None:
            row["state"] = "unknown"
            return total, receipts, dict(row)
        total = max(0.0, total - row["projected"]) + actual
        row.update(
            state="settled",
            actual=actual,
            cost_basis=normalized_basis,
            **(
                {"pricing_evidence": normalized_evidence}
                if normalized_evidence is not None else {}
            ),
        )
        return total, receipts, dict(row)
    row = _mutate(
        reservation.provider, reservation.period, finish,
        path=reservation.path, shared=reservation.shared,
        target_request_id=reservation.request_id,
    )
    return _snapshot(
        reservation.provider, reservation.period, reservation.request_id, row,
    )


def settle(
    reservation: Reservation, actual_dollars: float | None, *,
    cost_basis: str | None = None, pricing_evidence: dict[str, object] | None = None,
    attempt_state: str | None = None,
) -> ReservationSnapshot:
    snapshot = _settle_provider(reservation, actual_dollars, cost_basis=cost_basis,
                                pricing_evidence=pricing_evidence, attempt_state=attempt_state)
    try:
        from .tenant.provider_admission import settle_call
        settle_call(reservation.provider, reservation.request_id, snapshot.reference, snapshot.actual,
                    tenant=reservation.organization_tenant)
    except Exception as exc:
        # The provider receipt remains durable; do not convert a failed second
        # acknowledgement into permission to retry another paid request.
        raise ProviderAccountingUnavailable from exc
    return snapshot


def _failed_attempt_state(error: BaseException) -> str:
    try:
        import asyncio

        if isinstance(error, asyncio.CancelledError):
            return "cancelled"
    except Exception:  # pragma: no cover - stdlib import cannot normally fail
        pass
    return "cancelled" if isinstance(error, (GeneratorExit, KeyboardInterrupt)) else "failed"


def metered_provider_call(
    provider: str,
    callback,
    *,
    projected_dollars: float | None = None,
    actual_dollars: float | None = None,
    cost_basis: str | None = None,
    pricing_evidence: dict[str, object] | None = None,
    request_id: str | None = None,
    operation_id: str | None = None,
    category: str | None = None,
    parent_category: str | None = None,
    attempt_no: int | None = None,
    service: str | None = None,
):
    """Bracket one synchronous physical provider call with a durable receipt.

    Unpriced successful calls remain monetarily unknown; ``None`` never means
    free. Provider failures are re-raised only after their failed/cancelled
    attempt has been retained. If failure accounting cannot be secured, an
    accounting error stops outer retry/failover from issuing another paid call.
    """

    if not callable(callback):
        raise TypeError("provider callback must be callable")
    name = _canon(provider)
    if not name:
        raise ProviderAccountingUnavailable
    # An unknown estimate cannot safely consume a configured cap: a single
    # hosted call could exceed the entire remaining allowance before any usage
    # receipt exists.  Callers with verified free pricing may explicitly pass
    # zero; callers without a configured ceiling still retain an unknown-cost
    # work receipt after dispatch.
    projection_known = projected_dollars is not None
    projected = 0.0 if projected_dollars is None else _amount(projected_dollars)
    context = current_provider_operation()
    selected_category = category or (context.category if context else "other")
    selected_operation = operation_id or (
        context.operation_id if context else f"provider-{uuid.uuid4().hex}"
    )
    hold = reserve(
        name,
        projected,
        request_id=request_id,
        operation_id=selected_operation,
        category=selected_category,
        parent_category=parent_category or selected_category,
        attempt_no=attempt_no,
        service=service,
        projection_known=projection_known,
    )
    try:
        result = callback()
    except BaseException as error:
        if hold is not None:
            try:
                settle(hold, None, attempt_state=_failed_attempt_state(error))
            except Exception as accounting_error:
                raise ProviderAccountingUnavailable from accounting_error
        raise
    if hold is not None:
        try:
            settle(
                hold,
                actual_dollars,
                cost_basis=cost_basis,
                pricing_evidence=pricing_evidence,
                attempt_state="succeeded",
            )
        except Exception:
            # The call already happened. Its conservative hold remains durable;
            # surfacing a retryable transport error here could duplicate it.
            try:
                settle(hold, None, attempt_state="succeeded")
            except Exception:
                # A zero projection otherwise encumbers no dollars. Admission
                # treats a zero-dollar held operation as unresolved, so even an
                # unavailable second write cannot make the authority look clean.
                log.error(
                    "Provider operation completed, but settlement requires "
                    "reconciliation; its admission remains blocked."
                )
            else:
                log.error(
                    "Provider operation completed with unresolved cost; its "
                    "receipt was retained for reconciliation."
                )
    return result


def inspect_reservation(
    reference: str,
    *,
    expected_work_item_id: str | None = None,
    path: Path | None = None,
) -> ReservationSnapshot:
    """Read one exact receipt from the current tenant/configured authority."""

    provider, period, request_id = _parse_reference(reference)
    shared = _shared_world() if path is None else None
    ledger = None if shared is not None else (path or _ledger_path()).absolute()
    try:
        if shared is not None:
            total, receipts = shared.read_provider_cap(period, provider)
        elif _use_indexed_ledger(ledger):
            from . import provider_spend_sqlite
            row = provider_spend_sqlite.read_receipt(
                ledger, period, provider, request_id, sys.modules[__name__],
            )
            if expected_work_item_id is not None:
                if row.get("work_item_sha256") != _work_item_hash(expected_work_item_id):
                    raise ProviderAccountingUnavailable
            return _snapshot(provider, period, request_id, row)
        else:
            with _LEDGER_LOCK, cross_process_lock(ledger, strict=True):
                data = _load(ledger)
                total = data.get(period, {}).get(provider, 0.0)
                receipts = data.get(_RECEIPTS, {}).get(period, {}).get(provider, {})
        _, receipts = _validate_receipts(total, receipts)
        row = receipts.get(request_id)
        if row is None:
            raise ProviderAccountingUnavailable
        if expected_work_item_id is not None:
            if row.get("work_item_sha256") != _work_item_hash(expected_work_item_id):
                raise ProviderAccountingUnavailable
        return _snapshot(provider, period, request_id, row)
    except ProviderAccountingUnavailable:
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc


def _mutate_current(name, operation, *, shared, attempt_claim=None):
    """Use the shared authority's clock in the same transaction as mutation."""
    def validated(period, total, receipts):
        if not isinstance(period, str) or not _PERIOD.fullmatch(period):
            raise ProviderAccountingUnavailable
        total, receipts, result = operation(period, total, receipts)
        _validate_receipts(total, receipts)
        if len(json.dumps(receipts, allow_nan=False).encode("utf-8")) > _MAX_LEDGER_BYTES:
            raise ProviderAccountingUnavailable
        return total, receipts, result

    try:
        if attempt_claim is None:
            period, result = shared.mutate_current_provider_cap(
                period_from_config(), name, validated,
            )
        else:
            period, admitted, result = shared.reserve_current_provider_cap(
                period_from_config(), name, validated, attempt_claim,
            )
            if not admitted:
                existing = {
                    "metadata_sha256": _operation_metadata_sha256({
                        "category": result["category"],
                        "parent_category": result["parent_category"],
                        "service": result["service"],
                    }),
                    "provider": result["provider"],
                    "period": result["period"],
                    "request_id": result["request_id"],
                }
                if existing["metadata_sha256"] != attempt_claim["metadata_sha256"]:
                    raise ProviderAccountingUnavailable
                raise ProviderAttemptAlreadyAdmitted(
                    _existing_attempt_reference(existing),
                )
        if not isinstance(period, str) or not _PERIOD.fullmatch(period):
            raise ProviderAccountingUnavailable
        return period, result
    except (ProviderCapExceeded, ProviderAccountingUnavailable):
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc


def reservations_for_work_item(
    work_item_id: str,
    *,
    limit: int = _MAX_DISCOVERY_PAGE,
    cursor: str | None = None,
    path: Path | None = None,
) -> ReservationPage:
    """Discover receipts bound to the current tenant and exact work item.

    Results use a stable ``(period, provider, request_id)`` order. The opaque
    cursor is the last returned reservation reference, so callers can page
    without learning ledger paths, DSNs, or another tenant's raw work id.
    """

    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= _MAX_DISCOVERY_PAGE
    ):
        raise ProviderAccountingUnavailable
    work_item_sha256 = _work_item_hash(work_item_id)
    after = None
    if cursor is not None:
        provider, period, request_id = _parse_reference(cursor)
        after = (period, provider, request_id)

    shared = _shared_world() if path is None else None
    ledger = None if shared is not None else (path or _ledger_path()).absolute()
    data = None
    indexed_rows = None
    try:
        if shared is not None:
            keys = shared.find_provider_cap_reservations(
                work_item_sha256,
                limit=limit + 1,
                after=after,
            )
        elif _use_indexed_ledger(ledger):
            from . import provider_spend_sqlite
            rows = provider_spend_sqlite.find_receipts(
                ledger, work_item_sha256, limit=limit + 1, after=after,
                cap=sys.modules[__name__],
            )
            keys = [row[:3] for row in rows]
            indexed_rows = {row[:3]: row[4] for row in rows}
        else:
            with _LEDGER_LOCK, cross_process_lock(ledger, strict=True):
                data = _load(ledger)
                metadata = data.get(_RECEIPTS, {})
                keys = sorted(
                    (period, provider, request_id)
                    for period, providers in metadata.items()
                    for provider, receipts in providers.items()
                    for request_id, row in receipts.items()
                    if row.get("work_item_sha256") == work_item_sha256
                    and (after is None or (period, provider, request_id) > after)
                )[:limit + 1]

        if not isinstance(keys, (list, tuple)) or len(keys) > limit + 1:
            raise ProviderAccountingUnavailable
        previous = after
        normalized: list[tuple[str, str, str]] = []
        for key in keys:
            if (
                not isinstance(key, (list, tuple))
                or len(key) != 3
                or not all(isinstance(value, str) for value in key)
            ):
                raise ProviderAccountingUnavailable
            current = (key[0], key[1], key[2])
            if previous is not None and current <= previous:
                raise ProviderAccountingUnavailable
            if not _PERIOD.fullmatch(current[0]) or current[1] != _canon(current[1]):
                raise ProviderAccountingUnavailable
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", current[2]):
                raise ProviderAccountingUnavailable
            normalized.append(current)
            previous = current

        selected = normalized[:limit]
        snapshots: list[ReservationSnapshot] = []
        buckets: dict[tuple[str, str], dict] = {}
        for period, provider, request_id in selected:
            if indexed_rows is not None:
                snapshots.append(_snapshot(
                    provider, period, request_id,
                    indexed_rows[(period, provider, request_id)],
                ))
                continue
            bucket_key = (period, provider)
            if bucket_key not in buckets:
                if shared is not None:
                    total, receipts = shared.read_provider_cap(period, provider)
                else:
                    total = data.get(period, {}).get(provider, 0.0)
                    receipts = data.get(_RECEIPTS, {}).get(period, {}).get(provider, {})
                _, receipts = _validate_receipts(total, receipts)
                buckets[bucket_key] = receipts
            row = buckets[bucket_key].get(request_id)
            if row is None or row.get("work_item_sha256") != work_item_sha256:
                raise ProviderAccountingUnavailable
            snapshots.append(_snapshot(provider, period, request_id, row))
        return ReservationPage(
            receipts=tuple(snapshots),
            next_cursor=(snapshots[-1].reference if len(normalized) > limit else None),
        )
    except ProviderAccountingUnavailable:
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc


def reservation_catalogue_for_work_item(
    work_item_id: str,
    *,
    limit: int = _MAX_CATALOGUE_RECEIPTS,
    path: Path | None = None,
) -> ReservationCatalogue:
    """Read every bounded receipt for a work item from one coherent snapshot.

    This is the completeness-bearing API. Unlike cursor pagination, an insert
    cannot move behind a cursor and disappear from the declared catalogue.
    The version intentionally excludes outcome claims because claiming a
    receipt does not change its provider cost.
    """
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= _MAX_CATALOGUE_RECEIPTS
    ):
        raise ProviderAccountingUnavailable
    work_item_sha256 = _work_item_hash(work_item_id)
    shared = _shared_world() if path is None else None
    ledger = None if shared is not None else (path or _ledger_path()).absolute()
    snapshots: list[ReservationSnapshot] = []

    def collect(period, provider, total, receipts):
        if (
            not isinstance(period, str)
            or not _PERIOD.fullmatch(period)
            or not isinstance(provider, str)
            or not provider
            or provider != _canon(provider)
        ):
            raise ProviderAccountingUnavailable
        _, validated = _validate_receipts(float(total), receipts)
        for request_id, row in sorted(validated.items()):
            if row.get("work_item_sha256") == work_item_sha256:
                snapshots.append(_snapshot(provider, period, request_id, row))
                if len(snapshots) > limit:
                    raise ProviderAccountingUnavailable

    try:
        if shared is not None:
            buckets = shared.snapshot_provider_cap_reservations(
                work_item_sha256,
                limit=limit + 1,
            )
            if not isinstance(buckets, (list, tuple)) or len(buckets) > limit + 1:
                raise ProviderAccountingUnavailable
            previous = None
            for bucket in buckets:
                if not isinstance(bucket, (list, tuple)) or len(bucket) != 4:
                    raise ProviderAccountingUnavailable
                period, provider, total, encoded = bucket
                current = (period, provider)
                if previous is not None and current <= previous:
                    raise ProviderAccountingUnavailable
                previous = current
                if total is None or not isinstance(encoded, str):
                    raise ProviderAccountingUnavailable
                if len(encoded.encode("utf-8")) > _MAX_LEDGER_BYTES:
                    raise ProviderAccountingUnavailable
                receipts = json.loads(encoded)
                collect(period, provider, total, receipts)
        elif _use_indexed_ledger(ledger):
            from . import provider_spend_sqlite
            for period, provider, request_id, total, row in provider_spend_sqlite.find_receipts(
                ledger, work_item_sha256, limit=limit + 1, after=None,
                cap=sys.modules[__name__],
            ):
                collect(period, provider, total, {request_id: row})
        else:
            with _LEDGER_LOCK, cross_process_lock(ledger, strict=True):
                data = _load(ledger)
                metadata = data.get(_RECEIPTS, {})
                for period, providers in sorted(metadata.items()):
                    for provider, receipts in sorted(providers.items()):
                        collect(period, provider, data[period][provider], receipts)
        snapshots.sort(key=lambda row: (row.period, row.provider, row.request_id))
        return ReservationCatalogue(
            receipts=tuple(snapshots),
            version=_catalogue_version(work_item_sha256, snapshots),
        )
    except ProviderAccountingUnavailable:
        raise
    except Exception as exc:
        raise ProviderAccountingUnavailable from exc


def claim_reservation(
    reference: str,
    *,
    expected_work_item_id: str,
    claim_id: str,
    expected_state: str | None = None,
    expected_projected: float | None = None,
    expected_actual: float | None = None,
    path: Path | None = None,
) -> ReservationSnapshot:
    """Prepare an idempotent provider-receipt claim before outcome append."""

    provider, period, request_id = _parse_reference(reference)
    if not isinstance(claim_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,200}", claim_id,
    ):
        raise ProviderAccountingUnavailable
    work_item_sha256 = _work_item_hash(expected_work_item_id)
    shared = _shared_world() if path is None else None
    ledger = None if shared is not None else (path or _ledger_path()).absolute()

    def claim(total, receipts):
        total, receipts = _validate_receipts(total, receipts)
        row = receipts.get(request_id)
        if row is None or row.get("work_item_sha256") != work_item_sha256:
            raise ProviderAccountingUnavailable
        if expected_state is not None and row["state"] != expected_state:
            raise ProviderAccountingUnavailable
        if expected_projected is not None and row["projected"] != _amount(expected_projected):
            raise ProviderAccountingUnavailable
        if expected_state == "settled":
            if expected_actual is None or row["actual"] != _amount(expected_actual):
                raise ProviderAccountingUnavailable
        elif expected_actual is not None:
            raise ProviderAccountingUnavailable
        prior = row.get("outcome_claim")
        if prior is not None and prior != claim_id:
            raise ProviderAccountingUnavailable
        row["outcome_claim"] = claim_id
        row.setdefault("outcome_claim_state", "prepared")
        return total, receipts, dict(row)

    row = _mutate(provider, period, claim, path=ledger, shared=shared,
                  target_request_id=request_id)
    return _snapshot(provider, period, request_id, row)


def commit_reservation_claim(
    reference: str,
    *,
    expected_work_item_id: str,
    claim_id: str,
    event_id: str,
    expected_state: str | None = None,
    expected_projected: float | None = None,
    expected_actual: float | None = None,
    path: Path | None = None,
) -> ReservationSnapshot:
    """Commit a prepared claim after its exact outcome event is durable."""
    provider, period, request_id = _parse_reference(reference)
    if (
        not isinstance(claim_id, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", claim_id)
        or not isinstance(event_id, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", event_id)
    ):
        raise ProviderAccountingUnavailable
    work_item_sha256 = _work_item_hash(expected_work_item_id)
    shared = _shared_world() if path is None else None
    ledger = None if shared is not None else (path or _ledger_path()).absolute()

    def commit(total, receipts):
        total, receipts = _validate_receipts(total, receipts)
        row = receipts.get(request_id)
        if row is None or row.get("work_item_sha256") != work_item_sha256:
            raise ProviderAccountingUnavailable
        if expected_state is not None and row["state"] != expected_state:
            raise ProviderAccountingUnavailable
        if expected_projected is not None and row["projected"] != _amount(expected_projected):
            raise ProviderAccountingUnavailable
        if expected_state == "settled":
            if expected_actual is None or row["actual"] != _amount(expected_actual):
                raise ProviderAccountingUnavailable
        elif expected_actual is not None:
            raise ProviderAccountingUnavailable
        if row.get("outcome_claim") != claim_id:
            raise ProviderAccountingUnavailable
        claim_state = row.get("outcome_claim_state", "prepared")
        if claim_state == "committed":
            # Corrections create a new durable event under the same record-bound
            # claim. Move the diagnostic backreference only after that append.
            row["outcome_claim_event"] = event_id
            return total, receipts, dict(row)
        if claim_state != "prepared" or row.get("outcome_claim_event") is not None:
            raise ProviderAccountingUnavailable
        row["outcome_claim_state"] = "committed"
        row["outcome_claim_event"] = event_id
        return total, receipts, dict(row)

    row = _mutate(provider, period, commit, path=ledger, shared=shared,
                  target_request_id=request_id)
    return _snapshot(provider, period, request_id, row)


def would_exceed(provider: str, projected_dollars: float, *, now=None, path=None) -> bool:
    st = check(provider, now=now, path=path)
    if st.unresolved and st.cap is not None:
        raise ProviderAccountingUnavailable
    return st.cap is not None and st.spent + st.reserved + _amount(projected_dollars) > st.cap


# (provider, period) pairs we've already paged the operator about, so a blown
# cap alerts ONCE per period instead of on every subsequently-blocked dispatch.
_alerted: set[tuple[str, str]] = set()


def enforce(provider: str, *, projected_dollars: float = 0.0,
            now: float | None = None, path: Path | None = None) -> CapStatus:
    """Preflight configured cap and accounting availability without admission.

    Physical dispatch must additionally reserve capacity atomically; this
    read-only check alone cannot serialize concurrent calls. No configured cap
    leaves dispatch unchanged. Projection is an estimate of external cost.
    """
    st = check(provider, now=now, path=path)
    if st.unresolved and st.cap is not None:
        raise ProviderAccountingUnavailable
    projected = _amount(projected_dollars)
    reached = not st.allowed
    would_exceed_cap = st.cap is not None and st.spent + st.reserved + projected > st.cap
    if reached or would_exceed_cap:
        if path is None:
            shared = _shared_world()
            period = (
                shared.provider_cap_period(period_from_config())
                if shared is not None else period_key(now)
            )
            if not isinstance(period, str) or not _PERIOD.fullmatch(period):
                raise ProviderAccountingUnavailable
        else:
            period = period_key(now)
        canon = _canon(provider)
        # Page the operator ONCE per period only when the cap is actually
        # reached (spend >= cap). A projected-over block on a still-under-cap
        # provider is normal backpressure, not an exhaustion event.
        if reached and (canon, period) not in _alerted:
            _alerted.add((canon, period))
            try:
                from .ops_alert import alert
                alert("provider_cost_cap_exhausted",
                      f"{canon} spend ${st.spent:.2f} reached the ${st.cap:.2f} "
                      f"cap for period {period}; LLM calls are now blocked",
                      severity="critical")
            except Exception:  # pragma: no cover - alerting never blocks the gate
                pass
        raise ProviderCapExceeded(canon, st.spent, float(st.cap or 0.0), period)
    return st


def prune(*, now: float | None = None, path: Path | None = None) -> int:
    """Drop every ledger period except the current one; returns how many
    period buckets were removed.

    Old periods are dead weight once their window closes (and a stale key
    from a period-knob change would otherwise linger forever). Call it
    opportunistically — e.g. after recording at period rollover.
    """
    # The indexed authority keeps historical receipts available for exact
    # outcome attribution and replay prevention. Its rows are never silently
    # dropped as a latency remedy.
    if _use_indexed_ledger(path or _ledger_path()):
        return 0
    current = period_key(now)
    ledger = path if path is not None else _ledger_path()
    with _LEDGER_LOCK, cross_process_lock(ledger):
        data = _load(ledger)
        metadata = data.get(_RECEIPTS, {})
        stale = [
            key for key in data if key not in {current, _RECEIPTS, _ATTEMPT_INDEX}
            and not any(
                row["state"] != "settled"
                or (
                    row.get("work_item_sha256")
                    and (
                        row.get("outcome_claim_state") != "committed"
                        or not row.get("outcome_claim_event")
                    )
                )
                for rows in metadata.get(key, {}).values() for row in rows.values()
            )
        ]
        if not stale:
            return 0
        for k in stale:
            del data[k]
            metadata.pop(k, None)
        try:
            _save(ledger, data)
        except OSError as e:
            log.warning("provider_cost_cap: prune failed for %s: %s", ledger, e)
            return 0
    return len(stale)


__all__ = [
    "ProviderCapExceeded",
    "ProviderAccountingUnavailable",
    "ProviderAttemptAlreadyAdmitted",
    "Reservation",
    "ReservationSnapshot",
    "ReservationPage",
    "ReservationCatalogue",
    "ProviderOperationContext",
    "reservation_reference",
    "inspect_reservation",
    "reservations_for_work_item",
    "reservation_catalogue_for_work_item",
    "work_item_scope",
    "provider_operation_scope",
    "current_provider_operation",
    "metered_provider_call",
    "claim_reservation",
    "commit_reservation_claim",
    "recorded_at",
    "reserve",
    "settle",
    "CapStatus",
    "PERIOD_DAY",
    "PERIOD_MONTH",
    "caps_from_config",
    "period_from_config",
    "period_key",
    "record",
    "check",
    "would_exceed",
    "enforce",
    "prune",
]
