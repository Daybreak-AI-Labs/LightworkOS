"""Department bundles: the specialist packs as deployable teams.

One specialist pack is a single hire; a *department* is the whole team. This
module groups the built-in specialist packs (:mod:`maverick.domain`) by their
business *suite* into named, deployable units — "Finance", "Sales & GTM" — each
with a human-readable charter and a roster. It is the buyable-team layer the
dashboard and installer present on top of the 1,000+ packs: pick a department,
deploy its roster, and a fleet of specialists comes up together.

Read-only over the pack registry — assembling a department never mutates a pack.
Suites turned off in ``[suites]`` config drop out (via
:func:`maverick.domain.enabled_domains`), so a department reflects what the
operator has actually enabled, not the full catalog.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .domain import SUITE_PREFIXES, DomainProfile, enabled_domains, suites_for_domain

# Human-facing label + one-line charter per shipped suite key (the value side
# of ``SUITE_PREFIXES``). Unknown extension keys retain a derived-title fallback;
# every shipped suite is covered by the catalog invariant test.
SUITE_LABELS: dict[str, tuple[str, str]] = {
    "finance": ("Finance",
                "Close the books, forecast, and control spend — FP&A, "
                "controllership, treasury, and SOX."),
    "operations": ("Operations",
                    "Run and improve the operating core — process mapping, "
                    "S&OP, and continuous improvement."),
    "legal": ("Legal",
              "Contracts, corporate governance, and compliance — drafted and "
              "reviewed, never sent without a human."),
    "it_grc": ("IT & GRC",
               "IT service management, risk, and controls — tickets, access, "
               "and audit-ready governance."),
    "sales_gtm": ("Sales & GTM",
                  "Pipeline from first touch to close — demand gen, "
                  "sequencing, deal desk, and onboarding."),
    "hr": ("People & HR",
           "Talent, performance, and employee experience across the "
           "employee lifecycle."),
    "product_engineering": ("Product & Engineering",
                            "Build, review, and ship — APIs, code review, and "
                            "continuous delivery."),
    "strategy": ("Strategy",
                 "Strategic analysis and transformation — market "
                 "intelligence, M&A support, and board-ready cases."),
    "customer_experience": ("Customer Experience",
                            "Support and success that scales — triage, "
                            "resolution, and retention."),
    "marketing": ("Marketing",
                  "Brand, content, and campaigns — editorial calendars, SEO, "
                  "and channel performance."),
    "procurement": ("Procurement",
                    "Strategic sourcing and supplier management — RFPs, "
                    "negotiation, and spend control."),
    "data_analytics": ("Data & Analytics",
                       "Trusted data — governance, quality, cataloging, and "
                       "analysis."),
    "security_ops": ("Security Operations",
                     "24/7 security posture — SOC monitoring, incident "
                     "response, and remediation."),
    "executive_office": ("Executive Office",
                         "Coordinate the firm — exec assistance, "
                         "cross-functional alignment, and reporting."),
    "facilities_ehs": ("Facilities & EHS",
                       "Facilities, environment, health, and safety — "
                       "compliant and audit-ready."),
    "healthcare": ("Healthcare",
                   "Clinical and administrative workflows for healthcare "
                   "operations."),
    "insurance": ("Insurance",
                  "Underwriting, claims, and policy operations."),
    "banking": ("Banking",
                "Retail and commercial banking operations and regulatory "
                "preparation."),
    "retail": ("Retail",
               "Merchandising, replenishment, and store operations."),
    "manufacturing_vertical": ("Manufacturing",
                               "Production, BOM/routing, and plant "
                               "operations."),
    "construction": ("Construction",
                     "Project delivery, estimating, and field operations."),
    "logistics": ("Logistics",
                  "Transportation, track-and-trace, and fulfillment."),
    "professional_services": ("Professional Services",
                              "Engagement delivery, utilization, and client "
                              "operations."),
    "government_contracting": ("Government Contracting",
                               "Capture, compliance, and contract delivery "
                               "for public-sector work."),
    "education_nonprofit": ("Education & Nonprofit",
                            "Program delivery, accommodations, and grant "
                            "operations."),
    "tax": ("Tax",
            "Tax preparation, provision, and compliance across "
            "jurisdictions."),
    "utilities": ("Utilities",
                  "Regulated utility operations and field service."),
    "real_estate": ("Real Estate",
                    "Asset, lease, and property operations."),
    "pharma_lifesciences": ("Pharma & Life Sciences",
                            "Regulated R&D, quality, and commercial "
                            "operations."),
    "telecom_media": ("Telecom & Media",
                      "Network, content, and subscriber operations."),
    "hospitality": ("Hospitality",
                    "Guest, property, and service operations."),
    "capital_markets": ("Capital Markets",
                        "Trading, surveillance, and market operations."),
    "commerce": ("Commerce",
                 "Shopper and merchant agents over a governed storefront — "
                 "search, compare, cart, product Q&A, and staged store "
                 "changes; checkout and every store write stay human."),
    "aerospace_defense": ("Aerospace & Defense",
                          "Prepare aircraft safety reviews, engineering changes, supplier-quality checks, and export-control work."),
    "agriculture": ("Agriculture",
                    "Plan crops and farm operations, monitor supply risks, and prepare market decisions."),
    "automotive": ("Automotive",
                   "Support vehicle programs, dealer sales and service, warranty claims, and connected-car risks."),
    "chemicals": ("Chemicals",
                  "Review batch records, plant safety, product stewardship, and supply performance."),
    "crypto_digital_assets": ("Crypto & Digital Assets",
                              "Review digital-asset custody, transaction risk, compliance, and fund operations."),
    "enterprise_risk": ("Enterprise Risk",
                        "Map business risks to controls, continuity plans, insurance coverage, and board reporting."),
    "esg_sustainability": ("ESG & Sustainability",
                           "Assemble emissions and supplier evidence, prepare sustainability disclosures, and track improvement plans."),
    "food_beverage_cpg": ("Food, Beverage & Consumer Goods",
                          "Support product quality, food safety, demand planning, and retailer trade programs."),
    "knowledge_management": ("Knowledge Management",
                             "Turn scattered documents and lessons into findable, maintained answers for teams."),
    "maritime": ("Maritime",
                 "Prepare vessel, cargo, port, and crew work, including shipping documents and maintenance plans."),
    "medical_devices": ("Medical Devices",
                        "Prepare device design and quality records, complaint reviews, and post-market follow-up."),
    "mining_metals": ("Mining & Metals",
                      "Support exploration, mine planning, plant performance, equipment upkeep, and commodity reporting."),
    "oil_gas": ("Oil & Gas",
                "Support drilling plans, production, pipeline scheduling, safety, and environmental reporting."),
    "private_equity_vc": ("Private Equity & Venture Capital",
                          "Assess deals, coordinate diligence and portfolio plans, and prepare investor reporting."),
    "process_automation": ("Process Automation",
                           "Find repeatable work to automate, map its data and checks, and monitor the automations."),
    "public_sector": ("Public Sector",
                      "Support public programs, benefits and case work, budgeting, and constituent service."),
    "renewables_cleantech": ("Renewables & Clean Tech",
                             "Plan and monitor clean-energy projects, assets, grid connections, and performance."),
    "semiconductors": ("Semiconductors",
                       "Support chip design, fabrication yield, failure analysis, supply planning, and export compliance."),
    "travel_aviation": ("Travel & Aviation",
                        "Support airline and airport operations, bookings, baggage, cargo, and traveler service."),
    "trust_safety": ("Trust & Safety",
                     "Review abuse and harmful content, account integrity, appeals, and escalation to people."),
    "water_utilities": ("Water Utilities",
                        "Support water and wastewater assets, field work, treatment, billing, and compliance."),
}


def department_title(key: str) -> str:
    """Display name for a suite key, derived from the key when unlabeled."""
    label = SUITE_LABELS.get(key)
    return label[0] if label else key.replace("_", " ").title()


def department_charter(key: str) -> str:
    """One-line charter for a suite key (empty when unlabeled)."""
    label = SUITE_LABELS.get(key)
    return label[1] if label else ""


@dataclass
class Department:
    """A business suite presented as a deployable team of specialist packs."""
    key: str                                   # suite key, e.g. "finance"
    title: str
    charter: str
    members: list[str] = field(default_factory=list)   # pack names, sorted

    @property
    def headcount(self) -> int:
        return len(self.members)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "charter": self.charter,
            "headcount": self.headcount,
            "members": list(self.members),
        }


def _group(cfg: dict | None) -> dict[str, list[str]]:
    """Map suite key -> sorted pack names, over the *enabled* packs only.

    Packs with no recognized suite prefix (legacy/generic) are skipped — a
    department is a suite, and those packs belong to no suite."""
    by_suite: dict[str, list[str]] = {}
    for name, profile in enabled_domains(cfg).items():
        for suite in suites_for_domain(name, profile):
            by_suite.setdefault(suite, []).append(name)
    for names in by_suite.values():
        names.sort()
    return by_suite


def list_departments(cfg: dict | None = None) -> list[Department]:
    """Every enabled department, sorted by title.

    A suite whose packs are all disabled simply does not appear. Backward
    compatible with no ``[suites]`` config (every suite present)."""
    grouped = _group(cfg)
    out = [
        Department(
            key=key,
            title=department_title(key),
            charter=department_charter(key),
            members=names,
        )
        for key, names in grouped.items()
    ]
    out.sort(key=lambda d: d.title)
    return out


def get_department(key: str, cfg: dict | None = None) -> Department | None:
    """A single department by suite key, or ``None`` if it has no enabled packs."""
    if key not in SUITE_PREFIXES.values():
        return None
    names = _group(cfg).get(key)
    if not names:
        return None
    return Department(
        key=key,
        title=department_title(key),
        charter=department_charter(key),
        members=names,
    )


def roster(key: str, cfg: dict | None = None) -> list[DomainProfile]:
    """The specialist :class:`~maverick.domain.DomainProfile` objects for a
    department — the team you would deploy as a fleet."""
    dept = get_department(key, cfg)
    if dept is None:
        return []
    domains = enabled_domains(cfg)
    return [domains[name] for name in dept.members if name in domains]


# ---------------------------------------------------------------------------
# Deploy a department as a fleet — a plan-gated add-on.
#
# On a multi-tenant deployment, a tenant deploys a department only
# when its plan carries the ``departments`` add-on (or a per-department
# ``department:<key>`` grant). The gate is :func:`maverick.billing.feature_allowed`,
# which fails OPEN for self-host / single-tenant / unprovisioned deployments and
# closed only for a tenant an operator has explicitly put on a limited plan —
# so this never breaks a self-hoster.
# ---------------------------------------------------------------------------
DEPARTMENTS_FEATURE = "departments"


class EntitlementError(RuntimeError):
    """The active tenant's plan does not include the departments add-on."""

    def __init__(self, key: str, *, feature: str = DEPARTMENTS_FEATURE) -> None:
        self.department = key
        self.feature = feature
        super().__init__(
            f"the {key!r} department is an add-on; the active plan does not "
            f"include the {feature!r} entitlement"
        )


def department_entitled(key: str, *, tenant: str | None = None) -> bool:
    """Whether the active (or given) tenant may deploy department ``key``.

    Granted by the whole-catalog ``departments`` add-on OR a per-department
    ``department:<key>`` feature. Fail-open for self-host/unprovisioned tenants
    (see :func:`maverick.billing.feature_allowed`)."""
    from .billing import feature_allowed
    return (feature_allowed(DEPARTMENTS_FEATURE, tenant=tenant)
            or feature_allowed(f"department:{key}", tenant=tenant))


def department_entitlements(keys: Iterable[str], *, tenant: str | None = None) -> dict[str, bool]:
    """Current catalog availability from one plan read, without caching authority."""
    from .billing import feature_availability

    requested = tuple(keys)
    available = feature_availability(
        (DEPARTMENTS_FEATURE, *(f"department:{key}" for key in requested)), tenant=tenant,
    )
    return {key: available[DEPARTMENTS_FEATURE] or available[f"department:{key}"] for key in requested}


def _owner_slug(owner: str) -> str:
    """A fleet-name-safe, collision-resistant slug for an owner principal.

    Owner principals (``user:alice``, OIDC subs, emails) contain characters a
    fleet name forbids. We sanitize to ``[A-Za-z0-9_]`` and append a short hash
    of the *full* owner so two owners that sanitize to the same prefix still get
    distinct names. Empty owner (single-tenant / auth-off) -> empty slug."""
    o = (owner or "").strip()
    if not o:
        return ""
    import hashlib
    import re
    safe = re.sub(r"[^A-Za-z0-9]+", "_", o).strip("_")[:24]
    digest = hashlib.sha256(o.encode("utf-8")).hexdigest()[:6]
    return f"{safe}_{digest}".strip("_")


def fleet_name_for(key: str, owner: str) -> str:
    """The deployed-fleet name for ``key`` owned by ``owner``.

    Namespaced per owner so two users can each hold their own ``dept-<key>``
    without colliding. Single-tenant / auth-off (empty owner) keeps the plain
    ``dept-<key>`` name (unchanged behaviour)."""
    slug = _owner_slug(owner)
    return f"dept-{key}-{slug}" if slug else f"dept-{key}"


def fleet_from_department(dept: Department, owner: str, *,
                          cfg: dict | None = None, name: str | None = None):
    """Build (but do not save or entitle) a :class:`~maverick.fleet.Fleet` whose
    agents are the department's specialists.

    Each pack becomes one agent: ``name`` = pack name (its run principal),
    ``role`` = the department key (so an operator scopes the whole team with one
    ``[roles.<key>]`` block), ``description`` = the pack's charter line, ``domain``
    = the pack (binds run-time capability). Packs whose name is not a valid
    fleet-agent identifier are skipped. The fleet name is owner-namespaced unless
    overridden via ``name``."""
    from .fleet import Fleet, FleetAgent, valid_name
    domains = enabled_domains(cfg)
    agents = tuple(
        FleetAgent(name=m, role=dept.key,
                   description=(domains[m].description or "")[:200],
                   domain=m)
        for m in dept.members
        if m in domains and valid_name(m)
    )
    return Fleet(name=name or fleet_name_for(dept.key, owner),
                 owner=owner, agents=agents)


def merge_department_fleet(candidate, existing, *, known_members: list[str]):
    """Keep an edited team intact and append only specialists not offered before.

    Older team files have no deployment marker. On their first update we treat
    the current catalog as already offered, so a specialist the customer removed
    cannot be silently recreated. A later release's genuinely new members can
    then be added on the next update.
    """
    from dataclasses import replace

    if existing is None:
        return replace(candidate, department_members_added=tuple(a.name for a in candidate.agents)), len(candidate.agents)
    if existing.name != candidate.name or existing.owner != candidate.owner:
        raise ValueError("the existing team belongs to another owner")
    seen = set(existing.department_members_added) if existing.department_members_added else set(known_members)
    names = {agent.name for agent in existing.agents}
    added = tuple(agent for agent in candidate.agents if agent.name not in seen and agent.name not in names)
    seen.update(agent.name for agent in candidate.agents)
    return replace(existing, agents=(*existing.agents, *added),
                   department_members_added=tuple(sorted(seen))), len(added)


def deploy_department(key: str, owner: str, *, cfg: dict | None = None,
                      tenant: str | None = None, name: str | None = None,
                      save: bool = True):
    """Deploy a department as a fleet of its specialists.

    Entitlement-gated: raises :class:`EntitlementError` when the tenant's plan
    lacks the ``departments`` add-on. Grant-gated at the kernel: raises
    :class:`maverick.suite_grants.DepartmentAccessError` when ``owner`` is a
    scoped principal whose department grant excludes ``key`` — so every caller
    (dashboard, CLI, future surfaces) inherits job-function scoping; an empty
    owner (host operator / auth off) and configured admins stay unrestricted.
    Returns ``None`` if the department has no enabled packs; otherwise the
    saved :class:`~maverick.fleet.Fleet`."""
    dept = get_department(key, cfg)
    if dept is None:
        return None
    if not department_entitled(key, tenant=tenant):
        raise EntitlementError(key)
    from .suite_grants import ensure_suite_allowed
    ensure_suite_allowed(owner, key)
    fleet = fleet_from_department(dept, owner, cfg=cfg, name=name)
    if save:
        from .file_lock import cross_process_lock
        from .fleet import fleets_dir, load_fleet, save_fleet

        target_tenant = tenant or "__active__"
        with cross_process_lock(fleets_dir(tenant=target_tenant) / f"{fleet.name}.json"):
            fleet, _added = merge_department_fleet(
                fleet, load_fleet(fleet.name, tenant=target_tenant), known_members=dept.members,
            )
            save_fleet(fleet, tenant=target_tenant)
    return fleet
