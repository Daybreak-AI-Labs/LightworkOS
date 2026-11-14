"""Oversight control plane: the policy decision point for agent actions.

The keystone of Lightwork's enterprise governance (see
``docs/enterprise/architecture.md``, Layer A). Every consequential agent action
is evaluated here against the principal's capability and org policy, yielding a
single decision:

  - ``ALLOW``          -- proceed
  - ``DENY``           -- block (least-privilege or hard policy)
  - ``REQUIRE_HUMAN``  -- pause for human sign-off (the EU AI Act Art 14
                          human-oversight gate)

Decisions are strictest-wins (``DENY`` > ``REQUIRE_HUMAN`` > ``ALLOW``) and carry
a machine-readable ``rule`` + human ``reason`` so the choice lands in the audit
record (Art 12).

Default-open and opt-in: with no ``[governance]`` policy configured, ``evaluate``
allows anything the capability already permits, so a non-enterprise deployment
behaves exactly as before. Enterprise deployments set ``[governance]`` directly
or via a compliance-regime pack, which compiles down to the same :class:`Policy`.

The decision logic (``evaluate``) is pure (no I/O, no network, no agent-loop
coupling) so it is exhaustively unit-testable; ``Policy.from_config`` is the one
place that reads configuration and the policy overlays; wiring it into the kernel's tool path and
recording verdicts to the audit chain are separate, deliberate steps.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field, replace
from enum import Enum

from .safety.tool_risk import risk_rank, tool_risk

log = logging.getLogger(__name__)

_RISK_LEVELS = ("low", "medium", "high")

# Floors operators reach for that aren't in the 3-level scale. "critical" /
# "severe" / "max" all name the most-dangerous tier, which here is "high".
_RISK_ALIASES = {
    "critical": "high",
    "severe": "high",
    "max": "high",
    "maximum": "high",
}

# Explicit "no floor" sentinels so an operator can intentionally clear a floor
# without it being read as a typo and clamped.
_RISK_DISABLE = {"none", "off", "disabled", "never"}

#: The finance automation ladder (finance-agent-suite §3.1), strictest first:
#: ``draft`` (L1: an agent prepares, a person carries the action out -- the
#: agent's call is refused), ``approve`` (L2: every call waits for a person),
#: ``auto_threshold`` (L3: runs on its own only with an amount under the
#: approval threshold), ``straight_through`` (L4: runs within the rest of the
#: policy). An unknown level is treated as the strictest.
AUTOMATION_LEVELS: tuple[str, ...] = (
    "draft", "approve", "auto_threshold", "straight_through",
)


def automation_rank(level: object) -> int:
    """Position on the ladder; lower is stricter, unknown ranks strictest."""
    try:
        return AUTOMATION_LEVELS.index(str(level))
    except ValueError:
        return 0


def stricter_level(a: str | None, b: str | None) -> str | None:
    """The stricter of two automation levels (``None`` == no level)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if automation_rank(a) <= automation_rank(b) else b


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_HUMAN = "require_human"


class GovernancePolicyError(RuntimeError):
    """The configured governance policy cannot be trusted or interpreted."""


@dataclass(frozen=True)
class Verdict:
    """The outcome of a policy evaluation.

    ``rule`` names the policy clause that fired (``capability`` / ``deny_actions``
    / ``deny_min_risk`` / ``deny_above`` / ``require_human_actions`` /
    ``require_human_min_risk`` / ``require_human_above`` /
    ``finance_automation:<level>`` / ``default``) so an auditor can see *why*,
    not just *what*.
    """

    decision: Decision
    reason: str
    rule: str
    #: Exact compliance-profile snapshot used to produce this decision. Audit
    #: call sites pass it back to regulatory_compiler instead of re-reading a
    #: concurrently changing config/tenant overlay after enforcement. ``None``
    #: means policy provenance was unavailable (for example a fail-closed policy
    #: outage); it is intentionally distinct from a trusted empty snapshot.
    compliance_profiles: tuple[str, ...] | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def needs_human(self) -> bool:
        return self.decision is Decision.REQUIRE_HUMAN


def _risk_level(value: object) -> str | None:
    """Strict parse of a risk level: a known level or ``None``.

    Used for the caller-supplied ``risk=`` override in :func:`evaluate`, where an
    unrecognized value deliberately falls through to the tool classifier
    (``_risk_level(risk) or tool_risk(action)``). For a *configured floor* use
    :func:`_risk_floor`, which must never silently disable the gate.
    """
    return value if isinstance(value, str) and value in _RISK_LEVELS else None


def _risk_floor(value: object) -> str | None:
    """Normalize a configured risk *floor* to a known level, or ``None`` if unset.

    A floor (``deny_min_risk`` / ``require_human_min_risk``) only fires when it
    resolves to a real level: ``policy.deny_min_risk and ...``. So a *present but
    unrecognized* value that resolves to ``None`` silently disables the gate --
    fail-OPEN. ``deny_min_risk = "critical"`` (a natural, stricter-sounding
    choice) must not drop the deny floor entirely.

    Resolution, fail-closed on misconfiguration:
      - absent / empty / explicit disable sentinel ("none"/"off"/...) -> ``None``
      - a known level (case/space-insensitive) -> that level
      - a known alias ("critical"/"severe"/"max") -> "high" (the top tier)
      - anything else -> clamp to "high" with a warning, never silently disable
    """
    if value is None:
        return None
    if not isinstance(value, str):
        log.warning("governance: ignoring non-string risk floor %r", value)
        return None
    norm = value.strip().lower()
    if not norm or norm in _RISK_DISABLE:
        return None
    if norm in _RISK_LEVELS:
        return norm
    if norm in _RISK_ALIASES:
        return _RISK_ALIASES[norm]
    log.warning(
        "governance: unrecognized risk floor %r; clamping to 'high' (the "
        "strictest available level) rather than disabling the gate", value,
    )
    return "high"


def _amount_table(value: object) -> dict[str, float]:
    """Coerce a config value into an ``action -> threshold`` map.

    Accepts a TOML table ``{action = amount}`` (a ``"*"`` key is the catch-all),
    or a bare number which becomes the catch-all ``{"*": amount}``. Non-numeric
    entries are dropped.
    """
    out: dict[str, float] = {}
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return {"*": float(value)}
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out[str(k)] = float(v)
    return out


def _policy_config_snapshot() -> dict:
    """Load one trusted config snapshot for every live policy overlay."""
    try:
        from .config import config_source_errors, load_config, single_read

        # One decision: errors this read met stay reported even if another
        # thread's clean read clears the process-wide record in between.
        with single_read(fresh=True):
            snapshot = load_config()
            source_errors = config_source_errors()
    except Exception as exc:
        raise GovernancePolicyError(
            "governance policy source is unavailable"
        ) from exc
    if source_errors:
        raise GovernancePolicyError("governance policy source is invalid")
    if not isinstance(snapshot, dict):
        raise GovernancePolicyError("governance config root must be a table")
    return snapshot


def _governance_config(snapshot: dict | None = None) -> dict:
    """Return ``[governance]`` from one trusted policy snapshot."""
    if snapshot is None:
        snapshot = _policy_config_snapshot()
    if "governance" not in snapshot:
        return {}
    cfg = snapshot.get("governance")
    if not isinstance(cfg, dict):
        raise GovernancePolicyError("[governance] must be a configuration table")
    return cfg


def _policy_names(cfg: dict, key: str) -> frozenset[str]:
    if key not in cfg:
        return frozenset()
    value = cfg.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise GovernancePolicyError(
            f"governance.{key} must be a list of non-empty strings"
        )
    return frozenset(item.strip() for item in value)


def _policy_floor(cfg: dict, key: str) -> str | None:
    if key not in cfg:
        return None
    value = cfg.get(key)
    if not isinstance(value, str):
        raise GovernancePolicyError(
            f"governance.{key} must be a risk-level string"
        )
    return _risk_floor(value)


def _policy_thresholds(cfg: dict, key: str) -> dict[str, float]:
    if key not in cfg:
        return {}
    value = cfg.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        amount = float(value)
        if math.isfinite(amount) and amount >= 0.0:
            return {"*": amount}
        raise GovernancePolicyError(
            f"governance.{key} threshold must be finite and non-negative"
        )
    if not isinstance(value, dict):
        raise GovernancePolicyError(
            f"governance.{key} must be a number or threshold table"
        )
    out: dict[str, float] = {}
    for action, raw_amount in value.items():
        if not isinstance(action, str) or not action.strip():
            raise GovernancePolicyError(
                f"governance.{key} action names must be non-empty strings"
            )
        if (
            not isinstance(raw_amount, (int, float))
            or isinstance(raw_amount, bool)
            or not math.isfinite(float(raw_amount))
            or float(raw_amount) < 0.0
        ):
            raise GovernancePolicyError(
                f"governance.{key}.{action} must be a finite non-negative number"
            )
        out[action.strip()] = float(raw_amount)
    return out


@dataclass(frozen=True)
class Policy:
    """Org-level action policy, layered on top of per-principal capabilities.

    - ``deny_actions`` / ``require_human_actions``: exact action (tool) names.
    - ``deny_min_risk`` / ``require_human_min_risk``: a risk *floor* -- any action
      whose classified risk is at or above it gets the verdict. ``None`` == no
      floor. (Risk order: low < medium < high.)
    - ``deny_above`` / ``require_human_above``: dollar-amount thresholds per action
      (a ``"*"`` key applies to every action). A call whose amount cannot be
      verified (most tools; see the unverifiable-amount rule) also gets the
      verdict once a threshold applies to it, so a ``"*"`` threshold gates
      almost every tool. When a call carries an ``amount`` above the threshold
      it gets the verdict — the finance delegation-of-authority
      tier ("< $5k auto, $5k–50k human, > $50k denied"). Thresholds are in one
      reporting currency; the caller normalises ``amount`` into it.
    - ``automation``: action (lower-case tool name) -> finance automation level
      (:data:`AUTOMATION_LEVELS`), compiled from the Finance Operating Profile
      (:mod:`maverick.finance.profile`). It only ever adds a gate: ``draft``
      denies the agent's call, ``approve`` requires a human, ``auto_threshold``
      requires a human unless the call carries an amount within this policy's
      ``require_human_above`` threshold for the action.
    """

    deny_actions: frozenset[str] = frozenset()
    require_human_actions: frozenset[str] = frozenset()
    deny_min_risk: str | None = None
    require_human_min_risk: str | None = None
    deny_above: dict[str, float] = field(default_factory=dict)
    require_human_above: dict[str, float] = field(default_factory=dict)
    require_fresh_human_approval: bool = False
    automation: dict[str, str] = field(default_factory=dict)
    #: Provenance only; deliberately excluded from ``is_empty`` because a
    #: profile may enforce solely through capability attenuation.
    compliance_profiles: tuple[str, ...] = ()

    def is_empty(self) -> bool:
        return not (
            self.deny_actions
            or self.require_human_actions
            or self.deny_min_risk
            or self.require_human_min_risk
            or self.deny_above
            or self.require_human_above
            or self.require_fresh_human_approval
            or self.automation
        )

    @classmethod
    def from_config(cls) -> Policy:
        """Build the policy from the ``[governance]`` config table (opt-in).

        Absence is the documented default-open community posture. A present
        malformed policy or an unreadable active config source is different:
        raise so the live tool chokepoint can refuse the action instead of
        mistaking policy loss for an intentionally empty policy.
        """
        snapshot = _policy_config_snapshot()
        cfg = _governance_config(snapshot)

        fresh = cfg.get("require_fresh_human_approval", False)
        if not isinstance(fresh, bool):
            raise GovernancePolicyError(
                "governance.require_fresh_human_approval must be a boolean"
            )

        base = cls(
            deny_actions=_policy_names(cfg, "deny_actions"),
            require_human_actions=_policy_names(cfg, "require_human_actions"),
            deny_min_risk=_policy_floor(cfg, "deny_min_risk"),
            require_human_min_risk=_policy_floor(cfg, "require_human_min_risk"),
            deny_above=_policy_thresholds(cfg, "deny_above"),
            require_human_above=_policy_thresholds(cfg, "require_human_above"),
            require_fresh_human_approval=fresh,
        )
        # Compliance profiles and finance regime packs tighten the same live
        # policy strictest-wins. Lazy imports are deliberately below the Policy
        # definition: finance.regimes constructs Policy values at module import,
        # but never calls Policy.from_config, avoiding recursive compilation.
        try:
            from . import compliance_profiles
            profiles = compliance_profiles.configured_profiles(snapshot)
        except Exception as exc:
            raise GovernancePolicyError(
                "compliance governance policy is unavailable"
            ) from exc
        try:
            from .finance import regimes as finance_regimes

            regime_keys = finance_regimes.configured_regimes(snapshot)
        except Exception as exc:
            raise GovernancePolicyError(
                "finance-regime governance policy is unavailable"
            ) from exc
        # The Finance Operating Profile ([finance] framework / materiality,
        # [finance.automation]) compiles to one more strictest-wins overlay.
        # None while the finance layer is off or no profile key is set; a
        # present-but-invalid profile (e.g. a hard-floored action lowered
        # below approve) raises so the chokepoint fails closed.
        try:
            from .finance import profile as finance_profile

            finance_policy = finance_profile.configured_policy(snapshot)
        except Exception as exc:
            raise GovernancePolicyError(
                "finance operating profile is unavailable or invalid"
            ) from exc
        if not profiles and not regime_keys and finance_policy is None:
            return base
        policies = [base]
        try:
            if profiles:
                policies.append(compliance_profiles.compile_policy(profiles))
            if regime_keys:
                policies.append(finance_regimes.compile_policy(regime_keys))
            if finance_policy is not None:
                policies.append(finance_policy)
            combined = finance_regimes.union_policies(policies)
            return replace(combined, compliance_profiles=tuple(profiles))
        except Exception as exc:
            raise GovernancePolicyError(
                "configured governance overlays could not be compiled"
            ) from exc


def _threshold_for(table: dict[str, float], action: str) -> float | None:
    """The amount threshold for ``action``: the STRICTER (lower) of its exact
    entry and the ``"*"`` catch-all.

    The gate is ``amount > threshold``, so a LOWER threshold is stricter (more
    amounts gated). A ``"*"`` entry is therefore a floor: a per-action key can
    only TIGHTEN it, never loosen it. Without this, an org-wide
    ``require_human_above = {"*": 5000}`` (or a ``deny_above`` ceiling) was
    silently defeated for any action that carried its own higher threshold --
    e.g. ``{"*": 5000, "wire_transfer": 50000}`` let a $20k wire auto-approve.
    This also makes the composed/union case correct: ``union_policies`` keeps
    both keys, and the floor is applied here at evaluation time (strictest-wins,
    matching the documented "lowest threshold wins" contract)."""
    exact = table.get(action)
    star = table.get("*")
    if exact is None:
        return star
    if star is None:
        return exact
    return min(exact, star)


def _money(amount: float | None, currency: str) -> str:
    if amount is None:
        return ""
    cur = f" {currency}" if currency else ""
    return f"{amount:g}{cur}"


def transaction_value(action: str, args: object, policy: Policy) -> tuple[float | None, str, bool]:
    """Resolve a dispatch's value, marking relevant but unverifiable amounts.

    Thresholds are dollar ceilings, not exchange rates. A Stripe refund's
    currency comes from the charge, so caller-supplied currency cannot prove it.
    A zero or omitted refund amount means the full, unknown balance.
    """
    from decimal import Decimal, InvalidOperation

    values = args if isinstance(args, dict) else {}
    op = values.get("op")
    refund = action in {"stripe", "shopify"} and op == "refund_create"
    reads = {
        "stripe": {"customer_get", "customer_search", "charges", "subscriptions", "balance"},
        "shopify": {"orders", "order_get", "products", "product_get", "inventory", "customer_get"},
    }
    if action in {"read_file", "list_dir"}:
        return None, "", False
    if op in reads.get(action, set()):
        return None, "", False
    if _threshold_for(policy.deny_above, action) is None and _threshold_for(policy.require_human_above, action) is None:
        return None, "", False
    # Generic connectors and unrecognized operations can ignore a top-level
    # amount while sending a different nested payload. Never trust that field
    # as proof of a transaction's value without a known operation contract.
    if not refund or action == "stripe":
        return None, "", True

    currency = values.get("currency", "")
    if not isinstance(currency, str):
        return None, "", True
    currency = currency.strip().upper()
    if currency and currency != "USD":
        return None, currency, True
    raw = values.get("amount_cents")
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        return None, currency, True
    try:
        amount = Decimal(str(raw))
    except (InvalidOperation, ValueError, OverflowError):
        return None, currency, True
    if not amount.is_finite() or amount <= 0 or amount != amount.to_integral_value() or amount > 2**53:
        return None, currency, True
    return float(amount / 100), currency, False


def _automation_verdict(
    policy: Policy, action: str, amount: float | None, *, stage: str,
) -> Verdict | None:
    """The finance automation ladder's verdict for ``action``, if it adds one.

    ``stage="deny"`` answers only the ``draft`` level (evaluated with the other
    hard denies); ``stage="human"`` answers ``approve`` and an
    ``auto_threshold`` call that cannot be shown to be under its threshold
    (evaluated with the other human gates, so an amount above the threshold is
    already caught by ``require_human_above``).
    """
    level = policy.automation.get(action.strip().lower()) if policy.automation else None
    if level is None or level == "straight_through":
        return None
    rule = f"finance_automation:{level}"
    if stage == "deny":
        if automation_rank(level) == 0:  # draft, or an unknown level
            return Verdict(
                Decision.DENY,
                f"{action!r} is set to the draft automation level: an agent "
                "prepares it and a person carries it out",
                rule, policy.compliance_profiles,
            )
        return None
    if level == "approve":
        return Verdict(Decision.REQUIRE_HUMAN,
                       f"{action!r} is set to the approve automation level and "
                       "requires human approval", rule, policy.compliance_profiles)
    threshold = _threshold_for(policy.require_human_above, action)
    if amount is None or threshold is None:
        why = ("carries no amount" if amount is None
               else "has no approval threshold configured")
        return Verdict(Decision.REQUIRE_HUMAN,
                       f"{action!r} runs automatically only under an approval "
                       f"threshold, and this call {why}; requires human approval",
                       rule, policy.compliance_profiles)
    return None


def evaluate(
    action: str,
    *,
    risk: str | None = None,
    capability=None,
    policy: Policy | None = None,
    amount: float | None = None,
    currency: str = "",
    amount_unavailable: bool | None = None,
) -> Verdict:
    """Decide ALLOW / DENY / REQUIRE_HUMAN for ``action`` (a tool name).

    Strictest-wins evaluation order:
      1. capability (least privilege) -- a forbidden action is denied outright;
      2. org hard-deny (``deny_actions`` / ``deny_min_risk`` / ``deny_above``,
         then a ``draft`` finance automation level);
      3. human-oversight gate (``require_human_actions`` / ``require_human_min_risk``
         / ``require_human_above``, then the ``approve`` / ``auto_threshold``
         finance automation levels);
      4. otherwise allow.

    ``risk`` overrides the classifier (``safety.tool_risk``) when given. ``amount``
    (in ``currency``) is the transaction value, checked against the policy's
    dollar-threshold tiers — the finance delegation-of-authority gate. An
    omitted amount is unverifiable unless a trusted caller explicitly marks it
    not applicable with ``amount_unavailable=False``. ``policy``
    defaults to :meth:`Policy.from_config`; ``capability`` is an optional
    :class:`maverick.capability.Capability`.
    """
    if policy is None:
        policy = Policy.from_config()
    if amount_unavailable is None:
        amount_unavailable = amount is None
    if amount is not None:
        import math
        if (isinstance(amount, bool) or not isinstance(amount, (int, float))
                or not math.isfinite(amount) or amount < 0):
            amount, amount_unavailable = None, True
    if currency and (not isinstance(currency, str) or currency.strip().upper() != "USD"):
        amount, amount_unavailable = None, True
    eff_risk = _risk_level(risk) or tool_risk(action)

    # 1. Least privilege: the capability is the ceiling; deny below it wins.
    if capability is not None and not capability.permits(action):
        return Verdict(Decision.DENY, f"capability does not permit {action!r}",
                       "capability", policy.compliance_profiles)

    # 2. Org hard-deny.
    if action in policy.deny_actions:
        return Verdict(Decision.DENY, f"{action!r} is denied by org policy",
                       "deny_actions", policy.compliance_profiles)
    if policy.deny_min_risk and risk_rank(eff_risk) >= risk_rank(policy.deny_min_risk):
        return Verdict(Decision.DENY,
                       f"{eff_risk}-risk {action!r} denied by org policy",
                       "deny_min_risk", policy.compliance_profiles)
    deny_thresh = _threshold_for(policy.deny_above, action)
    if amount_unavailable and deny_thresh is not None:
        return Verdict(Decision.DENY,
                       f"{action!r} transaction amount cannot be verified against the deny ceiling",
                       "deny_above", policy.compliance_profiles)
    if amount is not None and deny_thresh is not None and amount > deny_thresh:
        return Verdict(Decision.DENY,
                       f"{action!r} amount {_money(amount, currency)} exceeds the "
                       f"deny ceiling {_money(deny_thresh, currency)}", "deny_above",
                       policy.compliance_profiles)
    if (drafted := _automation_verdict(policy, action, amount, stage="deny")) is not None:
        return drafted

    # 3. Human-oversight gate (EU AI Act Art 14).
    if action in policy.require_human_actions:
        return Verdict(Decision.REQUIRE_HUMAN,
                       f"{action!r} requires human approval", "require_human_actions",
                       policy.compliance_profiles)
    if (policy.require_human_min_risk
            and risk_rank(eff_risk) >= risk_rank(policy.require_human_min_risk)):
        return Verdict(Decision.REQUIRE_HUMAN,
                       f"{eff_risk}-risk {action!r} requires human approval",
                       "require_human_min_risk", policy.compliance_profiles)
    hitl_thresh = _threshold_for(policy.require_human_above, action)
    if amount_unavailable and hitl_thresh is not None:
        return Verdict(Decision.REQUIRE_HUMAN,
                       f"{action!r} transaction amount cannot be verified against the approval threshold",
                       "require_human_above", policy.compliance_profiles)
    if amount is not None and hitl_thresh is not None and amount > hitl_thresh:
        return Verdict(Decision.REQUIRE_HUMAN,
                       f"{action!r} amount {_money(amount, currency)} exceeds the "
                       f"approval threshold {_money(hitl_thresh, currency)}, "
                       "requires human approval", "require_human_above",
                       policy.compliance_profiles)
    if (gated := _automation_verdict(policy, action, amount, stage="human")) is not None:
        return gated

    # 4. Default-allow.
    return Verdict(
        Decision.ALLOW, "permitted", "default", policy.compliance_profiles
    )


__all__ = [
    "AUTOMATION_LEVELS", "Decision", "GovernancePolicyError", "Verdict", "Policy",
    "automation_rank", "evaluate", "stricter_level",
]
