"""Finance compliance-regime packs (finance-agent-suite §5).

Same pattern as the EU-AI-Act / NIST packs: each regime compiles to a governance
:class:`~maverick.governance.Policy` (what *must* pause for a human or be denied)
plus a plain-text assertion of what it covers. Selecting several regimes unions
their policies **strictest-wins** (deny beats require-human, the lowest risk floor
and the lowest dollar threshold win) — a US public company turns on
SOX + GAAP + SEC + PCI + AML; a private EU company swaps in IFRS.

Pure data + a pure union function, so the compilation is unit-tested. The
``finance status`` posture report (:mod:`maverick.finance.status`) surfaces which
regimes' controls are actually live. Expanded packs retain primary issuer or
legislator URLs so downstream evidence can identify the authoritative source.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ..governance import Policy, stricter_level
from ..safety.tool_risk import risk_rank

# The money/posting/filing actions a finance maker-checker gate pauses on.
_MONEY_ACTIONS = (
    "post_journal_entry", "release_payment", "release_payroll_payment",
    "run_payroll", "wire_transfer", "ach_send", "place_trade", "execute_fx_trade",
    "vendor_master_change", "close_period",
)
_FILING_ACTIONS = ("file_with_sec",)
_TAX_ACTIONS = ("file_return", "file_tax_return", "remit_tax")
_DORA_ACTIONS = (
    "report_ict_incident",
    "change_critical_ict_provider",
    "approve_ict_third_party",
)
_BASEL_III_ACTIONS = (
    "file_regulatory_capital_report",
    "approve_risk_weight",
    "change_regulatory_capital_model",
)


@dataclass(frozen=True)
class FinanceRegime:
    key: str
    name: str
    asserts: str
    policy: Policy = field(default_factory=Policy)
    source_urls: tuple[str, ...] = ()


REGIMES: dict[str, FinanceRegime] = {
    "sox": FinanceRegime(
        "sox", "SOX (§302/§404/§409/§906)",
        "ICFR exists and is tested; management certifies; tamper-evident records; "
        "segregation of duties.",
        Policy(require_human_actions=frozenset(_MONEY_ACTIONS),
               require_human_min_risk="high"),
    ),
    "coso": FinanceRegime(
        "coso", "COSO 2013",
        "Five components / seventeen principles of internal control, evidenced by "
        "the risk-control matrix and control tests.",
        # COSO is an evidence framework; its enforcement is the SOX policy above.
        Policy(),
    ),
    "gaap": FinanceRegime(
        "gaap", "US GAAP / IFRS",
        "Recognition & disclosure standards (ASC 606/842/740/718/805). Enforced by "
        "persona + knowledge packs that cite the clause; postings stay human.",
        Policy(require_human_actions=frozenset({"post_journal_entry", "close_period"})),
    ),
    "pci": FinanceRegime(
        "pci", "PCI DSS v4.0.1 (June 2024)",
        "Cardholder-data environment protection: Lightwork's stricter no-PAN-storage "
        "posture, secret/PII redaction, and tokenization at AR/expense; access, "
        "logging, testing, and incident-response evidence. Local scope and "
        "validation method remain entity-specific.",
        Policy(),  # enforced by security controls, not a finance action policy
        source_urls=(
            "https://www.pcisecuritystandards.org/document_library/"
            "?class=pcidss&doc=pci_dss",
        ),
    ),
    "glba": FinanceRegime(
        "glba", "GLBA / data residency",
        "Financial-privacy safeguards: egress lock + encryption at rest + tenancy.",
        Policy(),  # enforced by enterprise egress lock + encryption
    ),
    "aml": FinanceRegime(
        "aml", "AML / BSA / OFAC",
        "Sanctions & suspicious-activity controls: mandatory sanctions screening on "
        "every payment + vendor path; flags route to a human (a SAR is a human act).",
        Policy(require_human_actions=frozenset(
            ("release_payment", "wire_transfer", "ach_send", "vendor_master_change",
             "approve_vendor"))),
    ),
    "sec": FinanceRegime(
        "sec", "SEC (Reg S-X / S-K / FD / G)",
        "Public-reporting form & fairness: all external release is human-approved; "
        "non-GAAP reconciled to GAAP.",
        Policy(require_human_actions=frozenset(_FILING_ACTIONS)),
    ),
    "irs": FinanceRegime(
        "irs", "IRS / state & local tax",
        "Filing & remittance obligations: file_return / remit_tax are always human; "
        "a deadline calendar is maintained.",
        Policy(require_human_actions=frozenset(_TAX_ACTIONS)),
    ),
    "dora": FinanceRegime(
        "dora", "DORA (Regulation (EU) 2022/2554)",
        "EU financial-sector digital operational resilience: ICT-risk governance, "
        "incident management/reporting, resilience testing, and ICT third-party "
        "risk. Applicable from 17 January 2025; scope and proportionality remain "
        "entity-specific.",
        Policy(require_human_actions=frozenset(_DORA_ACTIONS)),
        source_urls=(
            "https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng",
        ),
    ),
    "basel_iii": FinanceRegime(
        "basel_iii", "Basel III final reforms (\"endgame\")",
        "Prudential minimums for internationally active banks: capital quality, "
        "credit/market/operational-risk RWA, leverage, liquidity, output-floor, "
        "and disclosure controls. Jurisdiction-specific implementing rules, scope, "
        "and effective dates remain authoritative.",
        Policy(require_human_actions=frozenset(_BASEL_III_ACTIONS)),
        source_urls=(
            "https://www.bis.org/basel_framework/",
            "https://www.bis.org/bcbs/publ/d424.htm",
        ),
    ),
    "ifrs_17": FinanceRegime(
        "ifrs_17", "IFRS 17 Insurance Contracts",
        "Recognition, measurement, presentation, and disclosure for insurance and "
        "reinsurance contracts, including fulfilment cash flows and contractual "
        "service margin. Effective for annual periods beginning on or after "
        "1 January 2023, subject to the reporting jurisdiction.",
        Policy(require_human_actions=frozenset({
            "post_journal_entry",
            "close_period",
            "publish_insurance_financials",
        })),
        source_urls=(
            "https://www.ifrs.org/issued-standards/list-of-standards/"
            "ifrs-17-insurance-contracts/",
        ),
    ),
}


# Accounting-framework packs, selected by ``[finance] framework`` (the Finance
# Operating Profile, :mod:`maverick.finance.profile`) and unioned
# strictest-wins with ``[finance] regimes``. Each gates the actions whose
# treatment the two frameworks actually differ on: what one framework does not
# permit is refused, what it permits only with judgement waits for a person.
_FRAMEWORK_POSTING = ("post_journal_entry", "close_period", "change_accounting_policy")

FRAMEWORKS: dict[str, FinanceRegime] = {
    "us_gaap": FinanceRegime(
        "us_gaap", "US GAAP (FASB Accounting Standards Codification)",
        "Postings, period close and accounting-policy changes stay human. US GAAP "
        "does not permit reversing a recognised impairment loss on assets held and "
        "used (ASC 360-10-35-20) or goodwill (ASC 350-20-35), and measures "
        "property, plant and equipment at historical cost, so an impairment "
        "reversal or an upward revaluation is refused.",
        Policy(
            require_human_actions=frozenset(_FRAMEWORK_POSTING),
            deny_actions=frozenset({"reverse_impairment_loss", "revalue_fixed_asset"}),
        ),
        source_urls=("https://asc.fasb.org/",),
    ),
    "ifrs": FinanceRegime(
        "ifrs", "IFRS Accounting Standards (IASB)",
        "Postings, period close and accounting-policy changes stay human. IFRS "
        "permits the revaluation model (IAS 16.31) and reversing an impairment "
        "loss other than on goodwill (IAS 36.114, IAS 36.124), both judgements, so "
        "they wait for a person; it does not permit LIFO inventory costing "
        "(IAS 2.25), so that is refused.",
        Policy(
            require_human_actions=frozenset({
                *_FRAMEWORK_POSTING, "revalue_fixed_asset", "reverse_impairment_loss",
            }),
            deny_actions=frozenset({"apply_lifo_inventory"}),
        ),
        source_urls=("https://www.ifrs.org/issued-standards/list-of-standards/",),
    ),
}


def list_regimes() -> list[FinanceRegime]:
    return list(REGIMES.values())


def _min_risk(a: str | None, b: str | None) -> str | None:
    """Strictest (lowest) risk floor of two — the one that pauses/denies more."""
    if a is None:
        return b
    if b is None:
        return a
    return a if risk_rank(a) <= risk_rank(b) else b


def _min_thresholds(a: dict[str, float], b: dict[str, float]) -> dict[str, float]:
    """Per-action lowest (strictest) dollar threshold across two tables."""
    out = dict(a)
    for action, amount in b.items():
        out[action] = min(out[action], amount) if action in out else amount
    return out


def union_policies(policies) -> Policy:
    """Strictest-wins union of policies (deny > require-human; lowest floor/threshold;
    the strictest finance automation level per action)."""
    deny_actions: set[str] = set()
    require_human_actions: set[str] = set()
    deny_min_risk: str | None = None
    require_human_min_risk: str | None = None
    deny_above: dict[str, float] = {}
    require_human_above: dict[str, float] = {}
    require_fresh_human_approval = False
    automation: dict[str, str] = {}
    for p in policies:
        deny_actions |= set(p.deny_actions)
        require_human_actions |= set(p.require_human_actions)
        deny_min_risk = _min_risk(deny_min_risk, p.deny_min_risk)
        require_human_min_risk = _min_risk(require_human_min_risk, p.require_human_min_risk)
        deny_above = _min_thresholds(deny_above, p.deny_above)
        require_human_above = _min_thresholds(require_human_above, p.require_human_above)
        require_fresh_human_approval = (
            require_fresh_human_approval or p.require_fresh_human_approval
        )
        for action, level in p.automation.items():
            automation[action] = stricter_level(automation.get(action), level)
    # An action that is hard-denied need not also be listed as require-human --
    # drop it from both the require-human set AND its per-action threshold, or
    # the compiled policy contradicts itself (a hard-deny plus a require-human
    # floor for the same action).
    require_human_actions -= deny_actions
    require_human_above = {
        action: amount
        for action, amount in require_human_above.items()
        if action not in deny_actions
    }
    return Policy(
        deny_actions=frozenset(deny_actions),
        require_human_actions=frozenset(require_human_actions),
        deny_min_risk=deny_min_risk,
        require_human_min_risk=require_human_min_risk,
        deny_above=deny_above,
        require_human_above=require_human_above,
        require_fresh_human_approval=require_fresh_human_approval,
        automation=automation,
    )


def compile_policy(keys) -> Policy:
    """Compile the selected regime keys into one governance Policy (strictest-wins).

    Keys are case/whitespace-normalized so enabling ``"SOX"`` is never silently
    dropped (a mis-cased known regime would otherwise compile to no enforcement).
    Genuinely unknown keys are ignored; with none known, returns an empty Policy
    (default-open — unchanged behavior).
    """
    norm = [str(k).strip().lower() for k in (keys or [])]
    selected = [REGIMES[k].policy for k in norm if k in REGIMES]
    return union_policies(selected)


def configured_regimes(config: Mapping | None = None) -> list[str]:
    """Return normalized ``[finance].regimes`` keys.

    Passing a trusted snapshot is the strict live-policy path: malformed finance
    configuration raises instead of silently dropping enforcement. The no-arg
    posture/reporting helper retains its historical best-effort behavior.
    """
    supplied = config is not None
    try:
        if config is None:
            from ..config import load_config

            config = load_config() or {}
        if not isinstance(config, Mapping):
            raise ValueError("finance config root must be a table")
        if "finance" not in config:
            return []
        cfg = config.get("finance")
        if not isinstance(cfg, Mapping):
            raise ValueError("[finance] must be a configuration table")
        if "regimes" not in cfg:
            return []
        regimes = cfg.get("regimes")
        if not isinstance(regimes, (list, tuple)) or not all(
            isinstance(regime, str) and regime.strip() for regime in regimes
        ):
            raise ValueError("finance.regimes must be a list of non-empty strings")
        normalized = [str(regime).strip().lower() for regime in regimes]
        if supplied:
            unknown = sorted(set(normalized) - set(REGIMES))
            if unknown:
                raise ValueError(
                    "finance.regimes contains unknown regime keys: " + ", ".join(unknown)
                )
        return normalized
    except Exception:
        if supplied:
            raise
        # Best-effort status callers historically treat an unreadable optional
        # finance section as having no declared regimes. Policy.from_config
        # passes its trusted snapshot and therefore never takes this branch.
        return []


__all__ = [
    "FinanceRegime", "FRAMEWORKS", "REGIMES", "list_regimes",
    "union_policies", "compile_policy", "configured_regimes",
]
