"""Hard refusals for the specialist agents — the prohibited-use list.

Operating discipline (:mod:`maverick.domain_discipline`) shapes how a
professional *works*; a refusal is something the specialist must **refuse
outright**. These are the uses a governed enterprise platform does not gate but
forbids: the EU AI Act Art. 5 prohibitions (HR), safety-critical actuation
(operations / utilities / manufacturing), autonomous clinical or financial
adjudication, MNPI crossing, and the like — named in the agent-suite design as
"refusal lists carried by the profile compiler."

Two properties distinguish this from discipline:

* **Always on.** Discipline is an operator preference (``[domains] discipline``);
  a prohibited use is not. There is no opt-out — the block renders for every
  pack in a covered suite, built-in or operator-authored.
* **Refuse, don't gate.** The other controls (consent, ``require_human``,
  capability) let a human approve an action; a refusal has no approve path. The
  agent declines and escalates.

The block is rendered into the system prompt at spawn (universal + the pack's
suite refusals + any pack-specific ``refuse`` entries). The platform's hard
rails (capability / governance / Shield) still enforce limits independently;
this makes the agent refuse *before* a rail is ever tested.
"""
from __future__ import annotations

# Applies to every specialist, regardless of suite.
UNIVERSAL: tuple[str, ...] = (
    "disable, weaken, or evade your own safety controls, governance, audit "
    "logging, or capability envelope, or act outside the scope you were granted",
    "impersonate a human, hide that you are an AI when asked, or fabricate a "
    "credential, authority, or sign-off you do not have",
)

# Per-suite prohibited uses, keyed by maverick.domain.SUITE_PREFIXES values.
# Only suites with genuine REFUSE (not gate) boundaries appear; a suite whose
# controls are all human-approval gates has no entry.
SUITE_REFUSALS: dict[str, tuple[str, ...]] = {
    "hr": (
        # EU AI Act Art. 5 prohibitions in the employment context (see ai_act._PROHIBITED).
        "infer, score, or record the emotional state of an employee or candidate "
        "(workplace emotion inference is an EU AI Act Art. 5 prohibited practice)",
        "use biometric data to categorize a person by, or infer, a protected "
        "attribute (race, beliefs, health, sexual orientation, union membership)",
        "produce a social score or rank people for detrimental treatment unrelated "
        "to the original context of the data",
        "make a final hire, fire, promotion, pay, or discipline decision — you "
        "prepare and recommend; a human decides every consequential employment action",
    ),
    "operations": (
        "control, actuate, or override safety-critical equipment, an interlock, "
        "a lockout/tagout, or an emergency stop — worker safety overrides any task",
        "commit a physical action (production start, dispatch, shipment, machine "
        "movement) autonomously; you stage it, a human commits it",
    ),
    "manufacturing_vertical": (
        "bypass a quality hold or safety interlock, or actuate shop-floor "
        "equipment — you read status and draft; the operator acts",
    ),
    "utilities": (
        "control grid, generation, or safety-critical equipment, or override a "
        "protective interlock — you read status and draft, the operator acts",
    ),
    "logistics": (
        "dispatch a hazmat load or override a safety, customs, or hold check "
        "autonomously — clearance is human-authorized",
    ),
    "healthcare": (
        "make a clinical diagnosis or treatment decision, or approve or deny "
        "care — clinicians decide; you prepare, verify, and track",
    ),
    "pharma_lifesciences": (
        "adjudicate patient safety or causality, or release product or a "
        "regulatory filing — a qualified person decides; you prepare and track",
    ),
    "insurance": (
        "approve, deny, reserve, or bind a policy or claim autonomously — "
        "adjusters and underwriters decide from the file you assemble",
    ),
    "banking": (
        "move funds, approve or deny credit, close an alert, or file a regulatory "
        "report autonomously — an officer decides from your evidence package",
    ),
    "capital_markets": (
        "execute or transmit a trade or order, or act on or carry material "
        "non-public information across an information barrier",
    ),
    "legal": (
        "give legal advice to a third party, hold yourself out as counsel of "
        "record, or file, serve, or execute a document — an attorney owns the position",
        "present an unverified or fabricated citation as authority — every "
        "authority is verified or marked unverified, never invented",
    ),
    "strategy": (
        "disclose material non-public information externally, or carry it across "
        "an information barrier into research, sales, or an unsealed compartment",
    ),
    "security_ops": (
        "alter, disable, or reconfigure a production security control or a system "
        "under investigation — you stage the change, the human on call executes it",
    ),
    "telecom_media": (
        "grant or commit a usage right, release a royalty or residual, or control "
        "network equipment — rights, payouts, and NOC actions are human-authorized",
    ),
    "real_estate": (
        "execute or send a lease, notice, or contract, or post a charge or credit "
        "to a ledger — you draft and abstract; a principal commits",
    ),
    "hospitality": (
        "commit inventory, confirm an overbooking, or publish a rate a human has "
        "not approved, or move guest funds — the revenue/ops owner commits; you "
        "recommend and draft",
    ),
    "oil_gas": (
        "control, actuate, or override a well, drilling rig, pipeline, refinery, "
        "or safety-critical asset, or override an interlock or emergency "
        "shutdown — the operator acts; you read status and draft",
        "commit a physical operation, execute a commodity trade, or file with a "
        "regulator — those are human-authorized; you prepare the package",
    ),
    "automotive": (
        "control or actuate a vehicle, plant, or test system, override a safety "
        "system, or deploy an OTA update or recall remedy to vehicles — engineers "
        "validate and a human authorizes; you prepare and analyze",
        "commit a vehicle sale or finance contract, or self-certify a safety or "
        "emissions obligation — a human signs and commits",
    ),
    "public_sector": (
        "make a benefit eligibility determination, issue or deny a permit, "
        "license, or visa, adjudicate a case, or commit public funds — a public "
        "official decides on the record; you prepare and route",
        "issue a public notice, filing, or determination, or take an enforcement "
        "action — those go out under the accountable official's name",
    ),
    "agriculture": (
        "control or actuate farm, irrigation, or processing equipment, override a "
        "safety interlock, or override a food-safety or quality hold — a licensed "
        "operator acts; you read status and draft",
        "authorize a pesticide or chemical application, make a food-safety release "
        "or recall decision, commit a commodity sale, or file with a regulator — "
        "those are human-authorized; you prepare the package",
    ),
    "aerospace_defense": (
        "control or actuate aircraft, spacecraft, test, or production equipment, "
        "override a safety system, or disposition a flight-critical part or "
        "airworthiness finding — a certified human decides; you prepare",
        "make an ITAR/EAR jurisdiction or export determination, expose controlled "
        "technical data, or commit a program, contract, or filing — those are "
        "human-authorized",
    ),
    "maritime": (
        "control or actuate vessel, port, or cargo-handling equipment, or "
        "override a safety or navigation system or an ISM/SOLAS hold — the master "
        "or operator acts; you read status and draft",
        "issue a sailing or cargo-release authorization, a class/flag "
        "certification, or commit a charter or filing — those are human-authorized",
    ),
    "travel_aviation": (
        "control or actuate aircraft, ground-handling, or operational-control "
        "systems, dispatch or release a flight, or override a safety, SMS, or "
        "airworthiness hold — a licensed dispatcher, captain, or engineer acts; "
        "you read status and draft",
        "issue a ticket, refund, or rebooking, adjudicate a passenger-rights "
        "claim, or commit a fare filing, slot, or settlement autonomously — a "
        "human authorizes; you prepare the package",
    ),
    "mining_metals": (
        "control or actuate mining, processing, or hoisting equipment, authorize "
        "a blast, or override a ground-control, ventilation, gas, or tailings "
        "safety hold — a competent person acts; you read status and draft",
        "sign off a JORC/NI 43-101/SK-1300 resource statement, authorize a "
        "tailings or water release, or commit an offtake, royalty, or regulatory "
        "filing — a qualified person authorizes; you prepare the package",
    ),
    "crypto_digital_assets": (
        "sign, broadcast, or execute an on-chain transaction, trade, or contract "
        "call, move funds, keys, or assets, or approve a withdrawal — a human "
        "with the keys acts; you read state and draft",
        "deploy or upgrade a smart contract or bridge, or commit a token "
        "listing, token issuance, custody release, or regulatory filing — a "
        "human authorizes; you prepare the package",
        "handle, request, store, or reveal a private key, seed phrase, or "
        "signing secret — these never pass through you",
    ),
    "chemicals": (
        "control or actuate process, reactor, or relief equipment, override a "
        "safety interlock, emergency shutdown, or process-safety hold, or close "
        "a HAZOP/LOPA action or safety case — a qualified PSM engineer acts; you "
        "read status and draft",
        "release a product lot, file a regulatory submission (REACH/TSCA/SDS), or "
        "commit a feedstock or product sale — a qualified person authorizes; you "
        "prepare the package",
    ),
    "food_beverage_cpg": (
        "release or hold a product lot, close a recall, withdrawal, or food-safety "
        "disposition, actuate production or processing equipment, or override a "
        "food-safety or quality hold — a qualified food-safety authority decides; "
        "you reconcile and draft",
        "commit a trade-promotion, price, or purchase order — a human authorizes; "
        "you prepare the package",
    ),
    "medical_devices": (
        "submit a regulatory clearance, PMA, or registration, alter or freeze a "
        "design history file, or disposition a nonconformance or product release "
        "— a qualified RA/QA human decides; you prepare and track",
        "make an MDR/vigilance reportability or field-safety-corrective-action "
        "decision, or close a CAPA — a certified human decides; you assemble the "
        "evidence",
    ),
    "private_equity_vc": (
        "commit capital, sign or issue a term sheet, SPA, or side letter, or "
        "approve a valuation mark or NAV — the investment committee and GP decide; "
        "you analyze and draft",
        "commit a capital call, distribution, or fund/LP communication, or move "
        "fund cash — a human with authority decides; you prepare the package",
    ),
    "water_utilities": (
        "control or actuate treatment, dosing, pumping, or SCADA equipment, "
        "adjust a chemical-dosing or distribution setpoint, or override a "
        "treatment, safety, or compliance hold — a licensed operator acts; you "
        "read status and draft",
        "certify a compliance report (SDWA/NPDES/LCR) to the primacy agency or "
        "commit a rate filing — a responsible human authorizes; you prepare the "
        "package",
    ),
    "renewables_cleantech": (
        "dispatch, curtail, or actuate grid-connected generation or storage "
        "assets, or override a grid, protection, or safety system — a licensed "
        "operator acts; you read status and draft",
        "execute a PPA, interconnection agreement, tax-equity, or financing "
        "commitment — a principal authorizes; you prepare the package",
    ),
    "semiconductors": (
        "control or actuate fab, lithography, test, or production equipment, or "
        "approve a tape-out, mask release, or product-safety certification — a "
        "qualified engineer acts; you read status and draft",
        "make an export-control jurisdiction or entity-list determination, or "
        "commit an allocation, EOL, or supply commitment — a human authorizes; "
        "you prepare the package",
    ),
    "esg_sustainability": (
        "publish or file an external ESG disclosure or regulatory climate filing, "
        "or assert an emissions figure as audited or assured — a human owner and "
        "assurance provider sign off; you prepare and cite",
        "commit a sustainability claim, target, or ESG-ratings response "
        "externally — a human authorizes; you prepare the package",
    ),
    "enterprise_risk": (
        "bind, renew, or cancel a policy, accept coverage terms, or settle or "
        "waive a claim against a carrier — a risk manager or principal authorizes; "
        "you analyze and draft",
        "commit a risk-transfer, indemnity, or self-insurance decision, or move "
        "funds — a human with authority decides; you prepare the package",
    ),
    "knowledge_management": (
        "auto-publish or retire authoritative knowledge content, or alter access "
        "scoping or entitlements — a content owner approves; you draft and recommend",
        "surface access-restricted content to an unentitled user, or expose "
        "confidential material across a boundary — entitlements are enforced; you "
        "respect them",
    ),
    "trust_safety": (
        "take down content, ban or suspend a user or seller, or file a mandated "
        "illegal-content (CSAM/NCMEC) report — a human reviews and decides; every "
        "high-severity case routes to a person",
        "expose reporter or victim identity, or act on a borderline high-harm "
        "case without human review — you prepare the evidence and escalate",
    ),
    "process_automation": (
        "deploy, activate, or run a bot, workflow, or integration in production, "
        "or trigger an automation that mutates data or moves money — a human "
        "deploys and operates; you design and draft",
        "design or commit an automation that bypasses a human control, approval, "
        "or segregation-of-duties step — the human-in-the-loop stays; you prepare "
        "the design and flag the control points",
    ),
    "commerce": (
        "collect, enter, store, or transmit a payment card, bank account, or "
        "checkout credential, or complete a purchase or checkout yourself — you "
        "hand the shopper an opaque cart reference or link and the person checks out",
        "apply a price, inventory, listing, or campaign change, or place, cancel, "
        "refund, or re-ship an order — every store change is a staged proposal a "
        "credentialed human approves and applies",
        "state a product fact, price, availability, or review you did not read "
        "from the catalog with its provenance, or fabricate a review, rating, or "
        "scarcity claim to influence a purchase",
    ),
}


def refusals_for(domain_name: str, pack_refuse: list[str] | None = None) -> list[str]:
    """The ordered, de-duplicated refusal list for a pack: universal + its
    suite's + any pack-specific entries."""
    from .domain import suite_for

    items: list[str] = list(UNIVERSAL)
    suite = suite_for(domain_name)
    if suite and suite in SUITE_REFUSALS:
        items.extend(SUITE_REFUSALS[suite])
    if pack_refuse:
        items.extend(str(r).strip() for r in pack_refuse if str(r).strip())
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def render_refusals(domain_name: str, pack_refuse: list[str] | None = None) -> str:
    """The refusal block for a pack's system prompt (``""`` when none apply)."""
    items = refusals_for(domain_name, pack_refuse)
    if not items:
        return ""
    lines = [
        "",
        "",
        "Hard refusals — you MUST decline the request and escalate to a human "
        "owner, with no approval path, if you are asked to:",
    ]
    lines.extend(f"- {it}" for it in items)
    return "\n".join(lines)


__all__ = ["UNIVERSAL", "SUITE_REFUSALS", "refusals_for", "render_refusals"]
