"""Per-principal usage quotas — the "cost as a managed resource" primitive.

:class:`Budget` caps a *single run*. Quotas cap a *principal* across runs over
a rolling time-window (a calendar day), so an operator can do chargeback /
rate-limit spend by user or team — the cost-governance layer the canonical
agent-OS leaves unowned.

A small persistent :class:`UsageLedger` records cumulative spend (dollars +
input/output tokens) per ``(principal, UTC day)`` under the tenant-aware data
dir (``<data>/usage/ledger.json``), so it is already tenant-isolated. Every
write is atomic-ish (temp file + ``os.replace``). The module has two halves:

* **Recording is fail-soft.** :func:`record_usage` logs a ledger error and
  returns ``False`` — cost accounting must not be able to take down the agent
  loop.
* **Enforcement is fail-closed.** :func:`over_quota`, the :class:`UsageLedger`
  methods and the ``[quotas]`` policy reader raise on a corrupt or unreadable
  ledger, or an invalid policy, so the caller can refuse to start a goal
  instead of treating unknown spend as zero.

Default-off and opt-in, exactly like :func:`maverick.capability.capability_enforced`
and :func:`maverick.agent._risk_proportional_verify_enabled`: with nothing
configured :func:`over_quota` returns ``None`` and behaviour is unchanged. Turn
it on with ``[quotas] enforce = true`` (plus ``max_dollars_per_day`` /
``max_tokens_per_day``) or the ``MAVERICK_QUOTA_*`` env vars.
"""
from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from datetime import datetime, timezone

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import data_dir

log = logging.getLogger(__name__)

# Serializes the ledger read-modify-write across threads in this process; the
# flock below extends that across processes (dashboard + serve sharing a tenant
# ledger). Without it, two concurrent record()s load the same totals and the
# second save clobbers the first -- spend is undercounted and a principal slips
# past its quota.
_RECORD_LOCK = threading.Lock()
_LEDGER_FORMAT = "lightwork-usage-v2"


_cross_process_lock = cross_process_lock


class UsageLedgerError(RuntimeError):
    """Usage state exists but cannot be trusted for quota enforcement."""


class QuotaPolicyError(RuntimeError):
    """Quota configuration cannot be resolved safely."""


def _ledger_path():
    """Tenant-scoped ledger location: ``<data>/usage/ledger.json``.

    Practice runs (:mod:`maverick.practice`) keep their own ledger beside it,
    so practice spending never counts toward real quotas or spending limits."""
    from . import practice

    if practice.active():
        return data_dir("practice", "usage", "ledger.json")
    return data_dir("usage", "ledger.json")


def _today() -> str:
    """UTC calendar day key (``YYYY-MM-DD``). UTC so the window doesn't shift
    with the host timezone or DST."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _decode_ledger(raw: str) -> object:
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
        raise UsageLedgerError(f"usage ledger corrupt: {exc}") from exc


def _validate_ledger(data: object) -> dict:
    if not isinstance(data, dict):
        raise UsageLedgerError("usage ledger corrupt: top-level value must be an object")
    validated: dict[str, dict[str, dict[str, int | float]]] = {}
    for principal, days in data.items():
        if not principal or principal != principal.strip() or len(principal) > 1024:
            raise UsageLedgerError("usage ledger corrupt: invalid principal")
        if not isinstance(days, dict):
            raise UsageLedgerError(f"usage ledger corrupt: days for {principal!r} must be an object")
        clean_days: dict[str, dict[str, int | float]] = {}
        for day, cell in days.items():
            try:
                datetime.strptime(day, "%Y-%m-%d")
            except (TypeError, ValueError) as exc:
                raise UsageLedgerError(
                    f"usage ledger corrupt: invalid day for {principal!r}"
                ) from exc
            if not isinstance(cell, dict):
                raise UsageLedgerError(
                    f"usage ledger corrupt: bucket {principal!r}/{day!r} must be an object"
                )
            dollars = cell.get("dollars", 0.0)
            in_tokens = cell.get("in_tokens", 0)
            out_tokens = cell.get("out_tokens", 0)
            if isinstance(dollars, bool) or not isinstance(dollars, (int, float)):
                raise UsageLedgerError("usage ledger corrupt: dollars must be numeric")
            if not math.isfinite(float(dollars)) or float(dollars) < 0:
                raise UsageLedgerError("usage ledger corrupt: dollars must be finite and non-negative")
            if (
                isinstance(in_tokens, bool)
                or not isinstance(in_tokens, int)
                or in_tokens < 0
                or isinstance(out_tokens, bool)
                or not isinstance(out_tokens, int)
                or out_tokens < 0
            ):
                raise UsageLedgerError("usage ledger corrupt: token counts must be non-negative integers")
            clean_days[day] = {
                "dollars": float(dollars),
                "in_tokens": in_tokens,
                "out_tokens": out_tokens,
            }
        validated[principal] = clean_days
    return validated


def _validate_settlements(receipts: object) -> dict:
    if not isinstance(receipts, dict):
        raise UsageLedgerError("usage settlement receipts must be an object")
    for scope, receipt in receipts.items():
        if (not isinstance(scope, str) or len(scope) != 32
                or any(c not in "0123456789abcdef" for c in scope)
                or not isinstance(receipt, dict)):
            raise UsageLedgerError("invalid usage settlement identity")
        principal = receipt.get("principal")
        if not isinstance(principal, str) or not principal.strip():
            raise UsageLedgerError("invalid usage settlement principal")
        for name in ("total", "credited"):
            amount = receipt.get(name)
            if not isinstance(amount, dict) or set(amount) != {"dollars", "in_tokens", "out_tokens"}:
                raise UsageLedgerError("invalid usage settlement counters")
            _validate_ledger({principal: {"2000-01-01": amount}})
        if any(receipt["credited"][key] > receipt["total"][key] for key in receipt["total"]):
            raise UsageLedgerError("settled credit exceeds cumulative usage")
        revision, timestamp = receipt.get("revision"), receipt.get("updated_at")
        if (type(revision) is not int or revision < 1 or type(timestamp) not in (int, float)
                or not math.isfinite(timestamp) or timestamp < 0):
            raise UsageLedgerError("invalid usage settlement revision")
        _validate_ledger({principal: receipt.get("charges")})
    return receipts


class UsageLedger:
    """A persistent ``(principal, day) -> {dollars, in_tokens, out_tokens}`` tally.

    Not a hot path (written once per run, read once per goal start), so each
    call reloads from disk rather than holding shared mutable state — that keeps
    concurrent runs / processes from clobbering each other's totals on the
    last-writer-wins of an in-memory cache. Missing state is empty; corrupt or
    unreadable existing state raises so enforcement cannot interpret it as zero.
    """

    def __init__(self, path=None) -> None:
        self.path = path if path is not None else _ledger_path()

    def _load_state(self) -> tuple[dict, dict]:
        ensure_private_directory(self.path.parent)
        if not self.path.exists():
            return {}, {}
        try:
            ensure_private_file(self.path)
            data = _decode_ledger(atomic_read_text(self.path))
        except UsageLedgerError:
            raise
        except OSError as exc:
            raise UsageLedgerError(f"usage ledger unreadable: {exc}") from exc
        if isinstance(data, dict) and data.get("format") == _LEDGER_FORMAT:
            if set(data) != {"format", "usage", "settlements"}:
                raise UsageLedgerError("invalid usage ledger envelope")
            return _validate_ledger(data["usage"]), _validate_settlements(data["settlements"])
        return _validate_ledger(data), {}

    def _load(self) -> dict:
        """Compatibility view consumed by quotas, billing, and reporting."""
        return self._load_state()[0]

    def _save(self, data: dict) -> None:
        _, receipts = self._load_state()
        self._save_state(data, receipts)

    def _save_state(self, data: dict, receipts: dict) -> None:
        ensure_private_directory(self.path.parent)
        document = ({"format": _LEDGER_FORMAT, "usage": data, "settlements": receipts}
                    if receipts else data)
        atomic_write_text(
            self.path,
            json.dumps(document, sort_keys=True, allow_nan=False),
        )

    def settlement(self, scope: str, principal: str) -> dict | None:
        """Read the durable receipt used to reconcile an interrupted resume."""
        receipt = self._load_state()[1].get(scope)
        if receipt is not None and receipt["principal"] != principal:
            raise UsageLedgerError("usage settlement belongs to another principal")
        return receipt

    def settlement_receipts(self, *, principal: str | None = None,
                            limit: int = 50, offset: int = 0) -> dict:
        """An owner-filtered reconciliation trail, separate from provider invoices."""
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
            raise ValueError("invalid receipt page bounds")
        rows = [{"scope": scope, **receipt} for scope, receipt in self._load_state()[1].items()
                if principal is None or receipt["principal"] == principal]
        rows.sort(key=lambda row: (row["updated_at"], row["scope"]), reverse=True)
        return {"items": rows[offset:offset + limit], "total": len(rows),
                "offset": offset, "limit": limit, "has_more": offset + limit < len(rows)}

    def record_cumulative(
        self, principal: str, scope: str, dollars: float, in_tokens: int, out_tokens: int,
        *, already_settled: dict | None = None, day: str | None = None,
    ) -> None:
        """Commit cumulative counters and their receipt in one atomic write.

        Checkpoint acknowledgement is advisory: repeating any committed total
        cannot add spend again. Only the increase is charged on the current day.
        Legacy checkpoints may carry a previously acknowledged credit, applied
        only when creating their first receipt. Receipts survive bucket pruning
        so restoring an old checkpoint cannot charge the deleted history again.
        """
        total = {"dollars": dollars, "in_tokens": in_tokens, "out_tokens": out_tokens}
        previous = already_settled or {}
        credited = {key: previous.get(key, 0) for key in total}
        candidate = {"principal": principal, "total": total, "credited": credited,
                     "revision": 1, "updated_at": time.time(), "charges": {}}
        _validate_settlements({scope: candidate})
        day = day or _today()
        _validate_ledger({principal: {day: total}})
        with _RECORD_LOCK, _cross_process_lock(self.path):
            usage, receipts = self._load_state()
            prior = receipts.get(scope)
            if prior is not None:
                if prior["principal"] != principal:
                    raise UsageLedgerError("usage settlement belongs to another principal")
                if all(total[key] <= prior["total"][key] for key in total):
                    return  # identical or older delivery, already accounted
                if any(total[key] < prior["total"][key] for key in total):
                    raise UsageLedgerError("usage counters conflict with the settlement receipt")
                candidate.update(credited=prior["credited"], charges=prior["charges"],
                                 revision=prior["revision"] + 1)
            baseline = prior["total"] if prior is not None else credited
            delta = {key: total[key] - baseline[key] for key in total}
            cell = usage.setdefault(principal, {}).setdefault(
                day, {"dollars": 0.0, "in_tokens": 0, "out_tokens": 0},
            )
            charge = candidate["charges"].setdefault(
                day, {"dollars": 0.0, "in_tokens": 0, "out_tokens": 0},
            )
            for key in delta:
                cell[key] += delta[key]
                charge[key] += delta[key]
            receipts[scope] = candidate
            self._save_state(usage, receipts)

    def record(
        self,
        principal: str,
        dollars: float,
        in_tokens: int,
        out_tokens: int,
        *,
        day: str | None = None,
    ) -> None:
        """Add one run's spend to ``(principal, day)``. Negative inputs are
        clamped to zero; a blank principal is ignored.

        Raises ``ValueError`` for an untrimmed or over-long principal or a
        non-finite amount, and :class:`UsageLedgerError` for a corrupt ledger.
        :func:`record_usage` is the wrapper that never raises."""
        if not principal:
            return
        if principal != principal.strip() or len(principal) > 1024:
            raise ValueError("principal must be a trimmed string of at most 1024 characters")
        day = day or _today()
        try:
            amount = float(dollars or 0.0)
            in_count = int(in_tokens or 0)
            out_count = int(out_tokens or 0)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError("usage values must be finite numbers") from exc
        if not math.isfinite(amount):
            raise ValueError("usage dollars must be finite")
        # Serialize the whole load-modify-save so concurrent records accumulate
        # instead of clobbering each other (in-process lock + cross-process
        # flock on a sidecar file).
        with _RECORD_LOCK, _cross_process_lock(self.path):
            data = self._load()
            bucket = data.setdefault(principal, {})
            cell = bucket.setdefault(day, {"dollars": 0.0, "in_tokens": 0, "out_tokens": 0})
            cell["dollars"] = float(cell.get("dollars", 0.0)) + max(0.0, amount)
            cell["in_tokens"] = int(cell.get("in_tokens", 0)) + max(0, in_count)
            cell["out_tokens"] = int(cell.get("out_tokens", 0)) + max(0, out_count)
            self._save(data)

    def usage(self, principal: str, *, day: str | None = None) -> dict:
        """Return ``{dollars, in_tokens, out_tokens}`` for ``(principal, day)``;
        zeros when nothing is recorded."""
        day = day or _today()
        cell = (self._load().get(principal) or {}).get(day) or {}
        return {
            "dollars": float(cell.get("dollars", 0.0)),
            "in_tokens": int(cell.get("in_tokens", 0)),
            "out_tokens": int(cell.get("out_tokens", 0)),
        }

    def spend_by_principal(self, *, day: str | None = None) -> dict[str, float]:
        """``{principal: dollars}`` for ``day`` (default today) — the per-user
        spend enumeration the point lookup :meth:`usage` couldn't provide (no
        way to answer "which user is burning budget?"). Skips zero-spend
        principals; empty when nothing is recorded."""
        day = day or _today()
        out: dict[str, float] = {}
        for principal, days in (self._load() or {}).items():
            dollars = float(((days or {}).get(day) or {}).get("dollars", 0.0))
            if dollars:
                out[str(principal)] = dollars
        return out

    def prune(self, keep_days: int, *, now: float | None = None,
              dry_run: bool = False, review_binding: dict | None = None) -> dict:
        """Drop ``(principal, day)`` buckets older than ``keep_days`` days.

        The ledger accrues a row per ``(principal, UTC day)`` forever; this is
        the retention valve. A day is expired when it is on or before the cutoff
        (``now - keep_days*86400``), matching the audit-file window. Principals
        left with no days are dropped. ``keep_days <= 0`` is a no-op (retention
        disabled). Returns a report. Raises :class:`UsageLedgerError` when
        the existing ledger is corrupt or unreadable, so nothing is pruned
        from state it cannot interpret.
        """
        if not keep_days or int(keep_days) <= 0:
            return {"removed_buckets": 0, "removed_principals": 0, "reason": "disabled"}
        now_ts = now if now is not None else datetime.now(timezone.utc).timestamp()
        cutoff_ts = now_ts - max(1, int(keep_days)) * 86400.0
        # YYYY-MM-DD sorts lexicographically == chronologically, so a string
        # compare against the cutoff day is the same window the SQL purges use.
        cutoff_day = datetime.fromtimestamp(cutoff_ts, timezone.utc).strftime("%Y-%m-%d")
        removed_buckets = 0
        removed_principals = 0
        with _RECORD_LOCK, _cross_process_lock(self.path):
            data, receipts = self._load_state()
            if review_binding is not None:
                from .retention_review_bindings import check, seal

                candidates = ([principal, day, data[principal][day]]
                    for principal in sorted(data)
                    for day in sorted(data[principal]) if isinstance(day, str) and day <= cutoff_day)
                bucket_seal = seal(candidates)
                charges = ([identity, day, receipts[identity]["charges"][day]]
                    for identity in sorted(receipts)
                    for day in sorted(receipts[identity]["charges"]) if day <= cutoff_day)
                charge_seal = seal(charges)
                check(review_binding, {"buckets": bucket_seal, "charges": charge_seal}, dry_run=dry_run)
            for principal in list(data.keys()):
                days = data.get(principal) or {}
                expired = [d for d in days if isinstance(d, str) and d <= cutoff_day]
                remaining = len(days) - len(expired)
                for day in expired:
                    removed_buckets += 1
                    if not dry_run:
                        del days[day]
                # A principal is dropped when no day-buckets would remain after
                # the purge. Decide from the pre-purge counts so the dry-run
                # report matches what a real run removes.
                if remaining <= 0:
                    removed_principals += 1
                    if not dry_run:
                        del data[principal]
            if not dry_run and removed_buckets:
                for receipt in receipts.values():
                    receipt["charges"] = {
                        day: charge for day, charge in receipt["charges"].items()
                        if day > cutoff_day
                    }
                self._save_state(data, receipts)
        return {"removed_buckets": removed_buckets,
                "removed_principals": removed_principals,
                "cutoff_day": cutoff_day}


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        value = float(raw)
    except (OverflowError, TypeError, ValueError) as exc:
        raise QuotaPolicyError(f"{name} must be a finite non-negative number") from exc
    if not math.isfinite(value) or value < 0:
        raise QuotaPolicyError(f"{name} must be a finite non-negative number")
    return value


def _quota_config() -> dict:
    """Merge ``[quotas]`` config under the ``MAVERICK_QUOTA_*`` env vars.

    Env wins over config (same precedence the rest of the kernel uses for
    opt-in toggles). Returns ``enforce`` plus the two caps; ``0``/unset cap
    means "no limit on this dimension". Invalid or unreadable policy raises so
    enforcement cannot silently switch itself off.
    """
    cfg: dict = {}
    try:
        from .config import config_source_errors, load_config

        loaded = load_config()
        if config_source_errors():
            raise QuotaPolicyError("quota policy unavailable: an active config source is invalid")
        cfg = loaded.get("quotas") or {}
        if not isinstance(cfg, dict):
            raise QuotaPolicyError("[quotas] must be a table")
    except QuotaPolicyError:
        raise
    except Exception as exc:
        raise QuotaPolicyError(f"quota policy unavailable: {exc}") from exc

    raw_enforce = cfg.get("enforce", False)
    if not isinstance(raw_enforce, bool):
        raise QuotaPolicyError("[quotas] enforce must be a boolean")
    enforce = raw_enforce
    env_enforce = os.environ.get("MAVERICK_QUOTA_ENFORCE")
    if env_enforce is not None and env_enforce.strip():
        value = env_enforce.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            enforce = True
        elif value in {"0", "false", "no", "off"}:
            enforce = False
        else:
            raise QuotaPolicyError("MAVERICK_QUOTA_ENFORCE must be a boolean")

    def _cap(env_name: str, cfg_key: str) -> float:
        env_val = _env_float(env_name)
        if env_val is not None:
            return env_val
        try:
            value = float(cfg.get(cfg_key, 0) or 0)
        except (OverflowError, TypeError, ValueError) as exc:
            raise QuotaPolicyError(f"[quotas] {cfg_key} must be numeric") from exc
        if not math.isfinite(value) or value < 0:
            raise QuotaPolicyError(f"[quotas] {cfg_key} must be finite and non-negative")
        return value

    return {
        "enforce": enforce,
        "max_dollars_per_day": _cap("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY", "max_dollars_per_day"),
        "max_tokens_per_day": _cap("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY", "max_tokens_per_day"),
    }


def quotas_enforced() -> bool:
    """Opt-in, off by default. ``MAVERICK_QUOTA_ENFORCE=1`` or ``[quotas]
    enforce = true`` turns on the per-principal daily quota check."""
    return _quota_config()["enforce"]


def record_usage(
    principal: str,
    dollars: float,
    in_tokens: int = 0,
    out_tokens: int = 0,
    *,
    reservation_id: str | None = None,
    settlement_id: str | None = None,
    already_settled: dict | None = None,
) -> bool:
    """Record a finished run's spend against ``principal`` for today's window.

    Always safe to call (even when enforcement is off — recording is how the
    ledger accrues chargeback data); fail-soft on any ledger error. Returns
    whether the ledger acknowledged the charge; callers may only persist a
    settled checkpoint marker after a true acknowledgement.

    ``reservation_id``: when the run's budget reserved an in-flight tenant dollar
    hold at start (``budget._tenant_reservation_id`` from
    :func:`maverick.budget.budget_from_config`), pass it here so the hold is
    released now that this run's actual spend is on the ledger — otherwise the
    reservation lingers against the tenant's remaining allowance until its TTL
    backstop expires. Lingering is conservative (it only ever *lowers* remaining,
    never raises it), so releasing is an optimization, not a correctness
    requirement. Release is fail-soft on the same tenant scope the ledger write
    used.
    """
    recorded = False
    try:
        ledger = UsageLedger()
        if settlement_id:
            ledger.record_cumulative(
                principal, settlement_id, dollars, in_tokens, out_tokens,
                already_settled=already_settled,
            )
        else:
            ledger.record(principal, dollars, in_tokens, out_tokens)
        recorded = bool(principal)
    except Exception as e:  # pragma: no cover - ledger is fully fail-soft
        log.warning("quotas: failed to record usage for %r: %s", principal, e)
    # Release only after the ledger accepted the actual spend. If recording
    # failed, retaining the hold until its TTL is conservative and prevents an
    # accounting outage from reopening daily allowance for unmetered work.
    if reservation_id and recorded:
        try:
            from .paths import current_tenant_id
            from .tenant.registry import release_tenant_reservation
            release_tenant_reservation(current_tenant_id(), reservation_id)
        except Exception as e:  # pragma: no cover -- reservation release is fail-soft
            log.warning("quotas: failed to release reservation %r: %s",
                        reservation_id, e)
    if recorded:
        try:
            from .budget_guidance import observe_warnings
            observe_warnings(principal)
        except Exception:
            # Warnings must never turn an acknowledged charge into a failed
            # settlement. The interactive preview can recover the same notice.
            log.warning("Budget warning observation unavailable; usage remains recorded.")
        try:
            from .spending_alerts import observe as observe_spending_alerts
            observe_spending_alerts(principal)
        except Exception:
            # Same rule: an alert is never a reason to fail a recorded charge,
            # and the spending limit itself still stops paid work.
            log.warning("Spending limit alert observation unavailable; usage remains recorded.")
    return recorded


def over_quota(principal: str) -> str | None:
    """Return a human-readable reason if ``principal`` is over its daily quota,
    else ``None``.

    Returns ``None`` (allow) when enforcement is off, no caps are configured,
    or the principal is blank. An unreadable/corrupt ledger raises so the
    orchestration chokepoint can block instead of treating unknown spend as 0.
    """
    cfg = _quota_config()
    if not cfg["enforce"] or not principal:
        return None
    max_dollars = cfg["max_dollars_per_day"]
    max_tokens = cfg["max_tokens_per_day"]
    if max_dollars <= 0 and max_tokens <= 0:
        return None
    used = UsageLedger().usage(principal)
    if max_dollars > 0 and used["dollars"] >= max_dollars:
        return (
            f"principal {principal!r} is over its daily spend quota "
            f"(${used['dollars']:.2f} >= ${max_dollars:.2f})"
        )
    total_tokens = used["in_tokens"] + used["out_tokens"]
    if max_tokens > 0 and total_tokens >= max_tokens:
        return (
            f"principal {principal!r} is over its daily token quota "
            f"({total_tokens} >= {int(max_tokens)} tokens)"
        )
    return None


__all__ = [
    "UsageLedger",
    "UsageLedgerError",
    "QuotaPolicyError",
    "quotas_enforced",
    "record_usage",
    "over_quota",
]
