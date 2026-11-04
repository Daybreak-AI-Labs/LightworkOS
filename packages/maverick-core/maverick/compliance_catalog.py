"""Single source of truth for the Autonomous Compliance product surface.

The six compliance suites already ship as dashboard pages scattered across
several nav groups (Govern, Privacy, Consent, AI oversight, Third parties).
The Autonomous Compliance dashboard page presents them as ONE product -- the
compliance platform run by governed agents -- with an honest three-word status
vocabulary: **shipped / preview / external**. This module is
that vocabulary's authority; the product landing page and the module-off gate
banner both read status from here so it can never drift between them.

Status is assigned conservatively from a per-capability review of what the
code in this repository implements:

  * ``shipped``  <- an *Implemented* capability row: a coherent local product
                    path is mounted, configuration-ready and focused-test-
                    covered. It is NOT a claim of live provider
                    interoperability, customer-scale operation or acceptance.
  * ``preview``  <- a *Partial* capability row: useful code exists but material
                    product breadth or live/operational proof is still absent.
  * ``external`` <- an *External / unverifiable* row: the outcome depends on
                    licensed content, commercial feeds, certification or live
                    scale that repository code alone cannot establish.

Every ``path`` below is a real registered dashboard route. This module owns no
rendering and imports nothing from the dashboard; it is a plain data authority.
"""

from __future__ import annotations

from dataclasses import dataclass

STATUS_SHIPPED = "shipped"
STATUS_PREVIEW = "preview"
STATUS_EXTERNAL = "external"

#: Canonical presentation order, most-ready first.
STATUS_ORDER: tuple[str, ...] = (STATUS_SHIPPED, STATUS_PREVIEW, STATUS_EXTERNAL)

#: Human labels for each status value (the stored value is the key).
STATUS_LABELS: dict[str, str] = {
    STATUS_SHIPPED: "Shipped",
    STATUS_PREVIEW: "Preview",
    STATUS_EXTERNAL: "External",
}

#: One-line meaning of each status, for the "what the labels mean" note.
STATUS_MEANINGS: dict[str, str] = {
    STATUS_SHIPPED: (
        "A coherent local product path is mounted, configuration-ready and "
        "test-covered. Not a claim of live provider or customer-scale "
        "acceptance."
    ),
    STATUS_PREVIEW: (
        "Useful code exists, but material product breadth or live/operational "
        "proof is still being built."
    ),
    STATUS_EXTERNAL: (
        "The outcome depends on licensed content, commercial feeds, "
        "certification or live scale that code alone cannot establish."
    ),
}

#: The design-system ``.badge`` modifier each status renders with
#: (see ``static/lightwork.css``): shipped -> ok (green), preview -> warn
#: (amber), external -> idle (muted).
STATUS_BADGE_CLASS: dict[str, str] = {
    STATUS_SHIPPED: "ok",
    STATUS_PREVIEW: "warn",
    STATUS_EXTERNAL: "idle",
}


@dataclass(frozen=True)
class Module:
    """One dashboard surface within a suite. ``path`` is a live route."""

    label: str
    path: str
    status: str


@dataclass(frozen=True)
class Suite:
    """One of the six compliance suites and the modules it presents."""

    key: str
    label: str
    description: str
    modules: tuple[Module, ...]


# The six suites, in product presentation order. Status per module maps a
# dashboard route onto the closest capability row in the parity review (the
# capability ID that most directly backs the surface is noted inline).
_SUITES: tuple[Suite, ...] = (
    Suite(
        key="ai_governance",
        label="AI Governance",
        description=(
            "Discover, register, risk-tier and govern every AI system and "
            "agent, with governed agents doing the work."
        ),
        modules=(
            # Packaged governance agents over common context.
            Module("Governance Agents", "/governance-agents", STATUS_SHIPPED),
            # Review/remediation tasks tied to AI entities.
            Module("AI Entity Tasks", "/ai-entity-tasks", STATUS_SHIPPED),
            # Preview: the parser sandbox is unproven on the shipped host.
            Module("AI Evidence Analysis", "/ai-evidence-analysis", STATUS_PREVIEW),
        ),
    ),
    Suite(
        key="privacy_automation",
        label="Privacy Automation",
        description=(
            "Run the privacy program: assessments, discovery, rights "
            "orchestration, notices and California DROP."
        ),
        modules=(
            # Privacy program and assessments.
            Module("Privacy Workspace", "/privacy", STATUS_SHIPPED),
            # Automated retrieval/deletion/verification.
            Module("Rights Orchestration", "/privacy/rights-orchestration", STATUS_SHIPPED),
            # Preview: no continuously operated live estate.
            Module("Data Discovery", "/privacy/data-discovery", STATUS_PREVIEW),
            # Notice-to-active-configuration publishing.
            Module("Notice Governance", "/privacy/notice-governance", STATUS_SHIPPED),
            # California DROP control plane.
            Module("DROP Requests", "/privacy/drop", STATUS_SHIPPED),
            # Public rights-request form with email verification and
            # verified per-jurisdiction clocks.
            Module("Rights Request Form", "/privacy/rights-form", STATUS_SHIPPED),
        ),
    ),
    Suite(
        key="consent_preferences",
        label="Consent & Preferences",
        description=(
            "Capture, store and honor consumer consent and preferences, with "
            "immutable receipts and a governed preference center."
        ),
        modules=(
            # Receipts and preference collection.
            Module("Consent & Preferences", "/consent", STATUS_SHIPPED),
            # Preview: native/deployed CMP breadth unproven.
            Module("Consent Publishing", "/consent/publishing", STATUS_PREVIEW),
            # Global Opt-Out DSAR application workflow.
            Module("Global Opt-Out", "/consent/global-opt-out", STATUS_SHIPPED),
            # Preview: no consenting live estate scanned.
            Module("Scan Inventory", "/consent/scan-inventory", STATUS_PREVIEW),
        ),
    ),
    Suite(
        key="tech_risk_compliance",
        label="Tech Risk & Compliance",
        description=(
            "Scope frameworks, generate controls and evidence tasks, and prove "
            "compliance across the estate."
        ),
        modules=(
            # Scoping and control library.
            Module("Compliance Workspace", "/compliance", STATUS_SHIPPED),
            # Preview: no live provider tenant contacted.
            Module("Continuous Evidence", "/compliance/continuous-evidence", STATUS_PREVIEW),
            # Preview: readiness code without regulator acceptance.
            Module("AI Governance (EU AI Act)", "/security/governance", STATUS_PREVIEW),
            # Evidence-to-assessment proposals.
            Module("Assessment Evidence", "/assess/evidence-autopopulation", STATUS_SHIPPED),
        ),
    ),
    Suite(
        key="third_party_management",
        label="Third-Party Management",
        description=(
            "Onboard, assess and monitor third parties through their full "
            "lifecycle, with contracts and engagements of record."
        ),
        modules=(
            # Preview: reference contracts, no live feeds.
            Module("Third-Party Intelligence", "/third-party/intelligence", STATUS_PREVIEW),
            # Provider-neutral lifecycle path.
            Module("Third-Party Lifecycle", "/third-party/lifecycle", STATUS_SHIPPED),
            # Contract and Engagement entity lifecycle.
            Module("Contracts & Engagements", "/third-party/contracts", STATUS_SHIPPED),
        ),
    ),
    Suite(
        key="data_use_governance",
        label="Data Use Governance",
        description=(
            "Capture purpose, compile machine-readable policy and enforce "
            "data-use controls native to modern data platforms."
        ),
        modules=(
            # Authority and policy compiler.
            Module("Data Use Governance", "/data-use", STATUS_SHIPPED),
            # Preview: no live Snowflake/Databricks tenant accepted.
            Module("Native Data Controls", "/data-use/providers", STATUS_PREVIEW),
        ),
    ),
)

_STATUS_BY_PATH: dict[str, str] = {
    module.path: module.status for suite in _SUITES for module in suite.modules
}


def suites() -> list[Suite]:
    """The six compliance suites, in product presentation order."""
    return list(_SUITES)


def module_status(path: str) -> str | None:
    """The status of the module at ``path`` (exact match), or ``None`` when
    ``path`` is not one of the catalogued module routes."""
    return _STATUS_BY_PATH.get(path)


def badge_class(status: str) -> str:
    """The design-system ``.badge`` modifier for ``status`` (``""`` if
    unknown), so callers never re-hardcode the mapping."""
    return STATUS_BADGE_CLASS.get(status, "")


__all__ = [
    "STATUS_SHIPPED",
    "STATUS_PREVIEW",
    "STATUS_EXTERNAL",
    "STATUS_ORDER",
    "STATUS_LABELS",
    "STATUS_MEANINGS",
    "STATUS_BADGE_CLASS",
    "Module",
    "Suite",
    "suites",
    "module_status",
    "badge_class",
]
