"""Metering → billing & entitlements.

:mod:`maverick.quotas` *meters* usage (per-principal, per-UTC-day dollars +
tokens in a tenant-scoped ledger). This module turns that meter into money and
gates features by plan:

  - **Rating + invoicing** — aggregate a tenant's ledger over a period into an
    :class:`Invoice` of :class:`LineItem`, rated by a :class:`RateCard`
    (pass-through provider cost + markup, or token-priced).
  - **Entitlements** — a plan → :class:`Entitlements` map (feature flags + soft
    limits) with :func:`entitled` / :func:`tenant_entitled` gating.

Pure and offline: rating is arithmetic over the ledger, so it unit-tests with an
in-memory ledger. Plans are config-overridable via ``[billing.plans]``; the
built-in defaults are the last-resort fallback.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from dataclasses import dataclass, field

from .quotas import UsageLedger

_MILLION = 1_000_000.0


@dataclass(frozen=True)
class RateCard:
    """How recorded usage becomes a charge.

    If either token price is set, charge from tokens; otherwise pass the recorded
    provider dollars through with ``markup_pct`` applied. ``minimum_charge`` is a
    floor on the invoice total.
    """

    markup_pct: float = 0.0
    usd_per_million_input_tokens: float = 0.0
    usd_per_million_output_tokens: float = 0.0
    minimum_charge: float = 0.0
    currency: str = "USD"

    @property
    def token_priced(self) -> bool:
        return bool(self.usd_per_million_input_tokens or self.usd_per_million_output_tokens)

    def rate(self, dollars: float, in_tokens: int, out_tokens: int) -> float:
        if self.token_priced:
            charge = (
                (in_tokens / _MILLION) * self.usd_per_million_input_tokens
                + (out_tokens / _MILLION) * self.usd_per_million_output_tokens
            )
        else:
            charge = float(dollars) * (1.0 + self.markup_pct / 100.0)
        return round(max(0.0, charge), 6)


@dataclass(frozen=True)
class LineItem:
    principal: str
    day: str
    dollars: float
    in_tokens: int
    out_tokens: int
    charge: float
    kind: str = "usage"

    def to_dict(self) -> dict:
        return {
            "principal": self.principal, "day": self.day, "dollars": self.dollars,
            "in_tokens": self.in_tokens, "out_tokens": self.out_tokens,
            "charge": self.charge,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class Invoice:
    tenant: str | None
    period_start: str
    period_end: str
    line_items: list[LineItem] = field(default_factory=list)
    subtotal: float = 0.0
    total: float = 0.0
    currency: str = "USD"
    # Deterministic idempotency key for (tenant, period, currency). A downstream
    # payment/AR step can use it to charge a given tenant-period at most once, so
    # re-running generate_invoice never double-bills the same period.
    invoice_id: str = ""

    def to_dict(self) -> dict:
        return {
            "tenant": self.tenant,
            "invoice_id": self.invoice_id,
            "period_start": self.period_start, "period_end": self.period_end,
            "currency": self.currency,
            "subtotal": self.subtotal, "total": self.total,
            "line_items": [li.to_dict() for li in self.line_items],
        }


def _invoice_id(tenant: str | None, period_start: str, period_end: str,
                currency: str) -> str:
    """Stable idempotency key for one tenant's **closed** billing period.

    Keyed on identity (tenant + period + currency), NOT on the amount, so the
    same logical invoice keeps the same id across re-runs -- that is exactly what
    lets a payment integration dedup.

    Returns ``""`` for an **open-ended** period (a missing ``period_start`` or
    ``period_end``): that invoice means "all usage so far", whose total grows as
    usage accrues, so a deterministic key would let a deduping processor charge
    the first (smaller) run and silently drop later, larger ones -- under-billing.
    Pass both bounds (close the period) to get a safe dedup key."""
    if not period_start or not period_end:
        return ""
    key = json.dumps([tenant or "", period_start, period_end, currency],
                     separators=(",", ":"))
    return "inv_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _in_period(day: str, since: str | None, until: str | None) -> bool:
    # YYYY-MM-DD strings compare lexically the same as chronologically.
    if since and day < since:
        return False
    return not (until and day > until)


def ledger_for_tenant(tenant_id: str | None) -> UsageLedger:
    """A UsageLedger pointed at ``tenant_id``'s tenant-scoped ledger file."""
    from .paths import data_dir
    return UsageLedger(path=data_dir("usage", "ledger.json", tenant=tenant_id))


def rate_ledger(
    ledger: UsageLedger, card: RateCard, *,
    tenant: str | None = None, since: str | None = None, until: str | None = None,
) -> Invoice:
    """Aggregate a ledger over ``[since, until]`` (inclusive, YYYY-MM-DD) into an
    invoice. Both bounds optional (open-ended). Line items are sorted by
    ``(principal, day)`` for a stable statement."""
    data = ledger._load()  # noqa: SLF001 -- intentional read of the persisted tally
    items: list[LineItem] = []
    for principal in sorted(data):
        days = data.get(principal) or {}
        for day in sorted(days):
            if not _in_period(day, since, until):
                continue
            cell = days[day] or {}
            dollars = float(cell.get("dollars", 0.0))
            in_tok = int(cell.get("in_tokens", 0))
            out_tok = int(cell.get("out_tokens", 0))
            if dollars == 0 and in_tok == 0 and out_tok == 0:
                continue
            items.append(LineItem(
                principal=principal, day=day, dollars=round(dollars, 6),
                in_tokens=in_tok, out_tokens=out_tok,
                charge=card.rate(dollars, in_tok, out_tok),
            ))
    subtotal = round(sum(li.charge for li in items), 6)
    total = round(max(subtotal, card.minimum_charge), 6)
    period_start, period_end = since or "", until or ""
    if total > subtotal:
        items.append(LineItem(
            principal="invoice:minimum", day=period_end,
            dollars=0.0, in_tokens=0, out_tokens=0,
            charge=round(total - subtotal, 6), kind="minimum_adjustment",
        ))
    return Invoice(
        tenant=tenant, period_start=period_start, period_end=period_end,
        line_items=items, subtotal=subtotal, total=total, currency=card.currency,
        invoice_id=_invoice_id(tenant, period_start, period_end, card.currency),
    )


def generate_invoice(
    tenant_id: str | None, card: RateCard, *,
    since: str | None = None, until: str | None = None,
) -> Invoice:
    """Rate a tenant's own ledger into an invoice for the period."""
    return rate_ledger(
        ledger_for_tenant(tenant_id), card, tenant=tenant_id, since=since, until=until,
    )


# --- Entitlements ------------------------------------------------------------

@dataclass(frozen=True)
class Entitlements:
    plan: str
    features: frozenset[str]
    max_daily_dollars: float = 0.0   # 0 = unlimited
    max_concurrent_goals: int = 0    # 0 = unlimited


# Last-resort defaults; operators override via ``[billing.plans]`` in config.
# These keys (free/pro/enterprise) are the technical *billing-plan IDs* an operator
# assigns per tenant for feature gating + quotas.
DEFAULT_PLANS: dict[str, Entitlements] = {
    "free": Entitlements("free", frozenset({"core"}), 5.0, 1),
    "pro": Entitlements("pro", frozenset({"core", "grpc", "channels"}), 100.0, 5),
    "enterprise": Entitlements(
        "enterprise",
        frozenset({"core", "grpc", "channels", "sso", "audit_export", "self_host"}),
        0.0, 0,
    ),
}

# A self-hosted installation's own workspace (the first workspace, created for
# its owner) is not on a billing plan: every feature a plan can gate, including
# the departments add-on (``maverick.departments.DEPARTMENTS_FEATURE``), and no
# plan limits. The tiers above remain for operators who bill tenants on a
# shared deployment and assign a plan per tenant.
SELF_HOSTED_PLAN = "self-hosted"
DEFAULT_PLANS[SELF_HOSTED_PLAN] = Entitlements(
    SELF_HOSTED_PLAN,
    frozenset().union(*(spec.features for spec in DEFAULT_PLANS.values()), {"departments"}),
    0.0, 0,
)


class BillingPolicyError(RuntimeError):
    """Billing/feature policy cannot be resolved safely."""


def entitlements_for(plan: str) -> Entitlements:
    """The entitlements for ``plan`` (config override or built-in default;
    unknown plans fall back to ``free``)."""
    try:
        from .config import config_source_errors, load_config

        cfg = load_config()
        if config_source_errors():
            raise BillingPolicyError(
                "billing policy unavailable: an active config source is invalid"
            )
        billing = cfg.get("billing") or {}
        if not isinstance(billing, dict):
            raise BillingPolicyError("[billing] must be a table")
        plans = billing.get("plans") or {}
        if not isinstance(plans, dict):
            raise BillingPolicyError("[billing.plans] must be a table")
        spec = plans.get(plan)
        if spec is not None:
            if not isinstance(spec, dict):
                raise BillingPolicyError(f"billing plan {plan!r} must be a table")
            features = spec.get("features") or []
            if not isinstance(features, (list, tuple)) or any(
                not isinstance(feature, str) or not feature.strip()
                for feature in features
            ):
                raise BillingPolicyError(f"billing plan {plan!r} has invalid features")
            dollars = float(spec.get("max_daily_dollars", 0) or 0)
            concurrent = spec.get("max_concurrent_goals", 0) or 0
            if isinstance(concurrent, bool) or not isinstance(concurrent, int):
                raise BillingPolicyError(
                    f"billing plan {plan!r} max_concurrent_goals must be an integer"
                )
            if not math.isfinite(dollars) or dollars < 0 or concurrent < 0:
                raise BillingPolicyError(f"billing plan {plan!r} has invalid limits")
            return Entitlements(
                plan=plan,
                features=frozenset(feature.strip() for feature in features),
                max_daily_dollars=dollars,
                max_concurrent_goals=concurrent,
            )
    except BillingPolicyError:
        raise
    except (OverflowError, TypeError, ValueError) as exc:
        raise BillingPolicyError(f"billing policy invalid: {exc}") from exc
    except Exception as exc:
        raise BillingPolicyError(f"billing policy unavailable: {exc}") from exc
    return DEFAULT_PLANS.get(plan, DEFAULT_PLANS["free"])


# The base ("free") billing plan: the entitlement floor. ``entitlements_for``
# falls back to it for any unknown plan, and a tenant whose Stripe subscription
# is unpaid is served this tier (see :func:`_effective_plan`).
BASE_PLAN = "free"


def entitled(plan: str, feature: str) -> bool:
    """Whether ``plan`` includes ``feature``."""
    return feature in entitlements_for(plan).features


def _effective_plan(rec) -> str:
    """The plan whose entitlements a tenant record is actually served.

    Normally the tenant's subscribed ``plan``. But when payment has lapsed --
    ``billing_status`` is not ``current``, the state
    :mod:`maverick.billing_stripe`'s webhook flips on ``invoice.payment_failed``
    / a past-due subscription -- the tenant is downgraded to :data:`BASE_PLAN`
    WITHOUT losing its subscribed plan, so a later ``payment_succeeded`` restores
    it exactly. A record written before Stripe billing has no ``billing_status``
    and reads as ``current``, so nothing changes for existing deployments."""
    if getattr(rec, "billing_status", "current") != "current":
        return BASE_PLAN
    return rec.plan


def known_plan_names() -> set[str]:
    """Plan IDs an operator may legitimately assign: the built-in defaults plus
    any defined in the ``[billing.plans]`` config section.

    Used to catch a mistyped plan name -- ``entitlements_for`` silently falls
    back to the ``free`` entitlements for an unknown plan, so a typo (``pr`` for
    ``pro``) would otherwise leave a tenant under-entitled with no signal."""
    names = set(DEFAULT_PLANS)
    try:
        from .config import load_config
        plans = ((load_config() or {}).get("billing") or {}).get("plans") or {}
        if isinstance(plans, dict):
            names.update(str(k) for k in plans)
    except Exception:  # pragma: no cover -- never block on config
        pass
    return names


def _effective_features_for_rec(rec) -> frozenset[str]:
    """Resolve a registry record's effective feature set: the effective plan's
    features (past-due downgrade already applied by :func:`_effective_plan`) with
    the per-tenant overrides layered on. Precedence: ``(plan | add) - remove`` --
    ``remove`` is applied last so a removed feature stays removed against both
    the plan and ``add``, and because the base is already the downgraded tier for
    a past-due tenant, the downgrade also keeps winning for removed features."""
    base = set(entitlements_for(_effective_plan(rec)).features)
    overrides = getattr(rec, "feature_overrides", None) or {}
    add = overrides.get("add") or []
    remove = overrides.get("remove") or []
    return frozenset((base | set(add)) - set(remove))


def plan_features_for_tenant(tenant_id: str) -> frozenset[str]:
    """The plan-entitlement baseline a tenant's overrides apply on top of.

    Its *effective* plan's features (downgraded to the base tier when the Stripe
    subscription is past-due) WITHOUT the per-tenant overrides -- the invariant
    is ``effective_features == plan_features_for_tenant | add - remove``. This is
    the correct basis for computing ``add``/``remove`` override diffs in a UI: a
    diff taken against the *subscribed* plan instead would, for a past-due tenant,
    silently record a ``remove`` for every downgraded feature. An unknown /
    unprovisioned tenant gets the base-tier features."""
    from .tenant.registry import get_tenant
    rec = get_tenant(tenant_id)
    if rec is None:
        return entitlements_for(BASE_PLAN).features
    return entitlements_for(_effective_plan(rec)).features


def effective_features(tenant_id: str) -> frozenset[str]:
    """The features a tenant may actually use: its plan entitlements plus
    per-tenant overrides.

    Equals ``entitlements_for(effective_plan).features`` UNION
    ``overrides["add"]`` MINUS ``overrides["remove"]`` -- see
    :func:`_effective_features_for_rec` for the precedence. A tenant whose Stripe
    subscription is past-due has its base downgraded to the ``free`` tier first
    (see :func:`_effective_plan`), then overrides apply on top. An unknown /
    unprovisioned tenant gets the base-tier features with no overrides."""
    from .tenant.registry import get_tenant
    rec = get_tenant(tenant_id)
    if rec is None:
        return entitlements_for(BASE_PLAN).features
    return _effective_features_for_rec(rec)


def tenant_entitled(tenant_id: str, feature: str) -> bool:
    """Whether the tenant's *effective* feature set includes ``feature``.

    The effective set is the tenant's plan features (downgraded to the base tier
    when the Stripe subscription is past-due) with per-tenant overrides applied
    on top -- see :func:`effective_features`. Unknown tenants get the base-tier
    features."""
    return feature in effective_features(tenant_id)


def feature_allowed(feature: str, *, tenant: str | None = None) -> bool:
    """Enforcement-side gate: may the active deployment use ``feature``?

    Resolves the tenant from the argument or the active context
    (:func:`maverick.paths.current_tenant_id`). The gate is deliberately
    permissive at the edges so it never breaks existing single-tenant or
    not-yet-provisioned deployments -- only an operator who has *explicitly*
    provisioned a tenant with a limited plan can be denied:

      * no active tenant (single-tenant / self-host) -> allowed;
      * a tenant that is not in the registry (e.g. the per-user tenant id used
        by ``MAVERICK_TENANT_BY_USER`` with no roster) -> allowed;
      * a registered tenant -> allowed iff its *effective* feature set includes
        ``feature`` (its plan entitlements with per-tenant overrides applied,
        and a past-due Stripe subscription downgraded to the base tier first --
        see :func:`effective_features`).

    Policy lookup errors propagate so a communication surface can refuse rather
    than silently restoring a feature removed by tenant policy.
    """
    return feature_availability((feature,), tenant=tenant)[feature]


def feature_availability(features: Iterable[str], *, tenant: str | None = None) -> dict[str, bool]:
    """Read one current plan for a display batch; retain no cross-call grants."""
    requested = tuple(features)
    tid = tenant or _active_tenant_id()
    if not tid:
        return dict.fromkeys(requested, True)
    from .tenant.registry import get_tenant
    rec = get_tenant(tid)
    if rec is None:
        return dict.fromkeys(requested, True)
    allowed = _effective_features_for_rec(rec)
    return {feature: feature in allowed for feature in requested}


def _active_tenant_id() -> str | None:
    from .paths import current_tenant_id
    return current_tenant_id()


# Cross-cutting capability flags an operator can toggle per tenant, independent
# of any one business suite. Departments are added on top as one
# ``department:<key>`` entry per suite (see :func:`gateable_features`).
_BASE_GATEABLE_FEATURES = ("core", "channels", "audit_export", "grpc")


def gateable_features() -> list[str]:
    """The catalog of features an operator may toggle per tenant via overrides.

    The cross-cutting capability flags (:data:`_BASE_GATEABLE_FEATURES`) plus one
    ``department:<key>`` entry per business suite, drawn from the canonical suite
    map (:data:`maverick.domain.SUITE_PREFIXES`) so the catalog tracks the real
    department enumeration rather than a hand-kept copy. Import-safe and offline
    (the suite map is a static table); degrades to the base flags if the domain
    layer is unavailable rather than raising."""
    features = list(_BASE_GATEABLE_FEATURES)
    try:
        from .domain import SUITE_PREFIXES
        features += [f"department:{k}" for k in sorted(set(SUITE_PREFIXES.values()))]
    except Exception:  # pragma: no cover -- catalog degrades to base flags
        pass
    return features


__all__ = [
    "RateCard", "LineItem", "Invoice",
    "rate_ledger", "generate_invoice", "ledger_for_tenant",
    "Entitlements", "DEFAULT_PLANS", "SELF_HOSTED_PLAN", "entitlements_for", "entitled",
    "BASE_PLAN", "BillingPolicyError", "tenant_entitled", "feature_allowed", "feature_availability",
    "effective_features", "plan_features_for_tenant", "gateable_features",
]
