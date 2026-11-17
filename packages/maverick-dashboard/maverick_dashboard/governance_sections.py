"""Which governance tools on /security/assurance are turned off.

A turned-off tool's API refuses every call, so the page does not call it:
the tool's section is hidden and marked ``data-feature-off``, and one short
summary says what is off and who can turn it on. Switch names never reach
the page.
"""
from __future__ import annotations

import importlib

from markupsafe import Markup

# Section id on the page -> (maverick module whose enabled() gates its API, name for people).
SECTIONS: dict[str, tuple[str, str]] = {
    "ai-literacy-panel": ("ai_literacy", "AI training records"),
    "article-73-panel": ("eu_ai_incidents", "Serious-incident deadlines (EU AI Act)"),
    "ai-business-intake-panel": ("ai_business_intake", "AI business intake"),
    "ai-cost-roi-panel": ("ai_cost_roi", "AI cost and return"),
    "ai-policy-management-panel": ("ai_policy_management", "AI use rules"),
    "dynamic-risk-panel": ("ai_dynamic_risk", "Live risk scores"),
    "runtime-guardrails-panel": ("ai_runtime_guardrails", "Try your safeguards"),
    "ai-explainability-panel": ("ai_explainability", "Explanations of AI decisions"),
    "ai-insurability-panel": ("ai_insurability", "Evidence for insurers"),
    "ai-conformity-panel": ("ai_conformity_workflow", "EU AI Act launch readiness"),
    "ai-regulated-package-workbench": ("ai_regulated_verticals", "Evidence packages for regulated uses"),
    "ai-benchmark-panel": ("ai_benchmark_exchange", "Compare with other organisations"),
    "ai-discovery-sensors-panel": ("ai_discovery_sensors", "AI discovery sensors"),
    "ai-media-provenance-panel": ("ai_media_provenance", "Where media came from (C2PA)"),
    "grc-outbound-panel": ("grc_outbound_sync", "Send to ServiceNow or Archer"),
}


def _off(module_name: str) -> bool:
    """True only when the switch reads as off. A switch that cannot be read
    is not reported as off: its section loads and shows its own error."""
    try:
        return not importlib.import_module(f"maverick.{module_name}").enabled()
    except Exception:  # noqa: BLE001 -- unreadable is not "off"
        return False


def off_sections() -> list[dict]:
    """Each turned-off tool, in page order. ``switch`` is the in-app switch
    (``POST /api/v1/features/modules``) when it has one, else ``""``."""
    from .module_activation import _MODULE_SWITCHES

    return [{"id": panel, "label": label, "switch": module if module in _MODULE_SWITCHES else ""}
            for panel, (module, label) in SECTIONS.items() if _off(module)]


def section_off(panel_id: str) -> bool:
    entry = SECTIONS.get(panel_id)
    return entry is not None and _off(entry[0])


def section_attrs(panel_id: str) -> Markup:
    """Attributes that hide a turned-off section and tell its script not to load it."""
    if not section_off(panel_id):
        return Markup("")
    return Markup(' hidden data-feature-off="{}"').format(SECTIONS[panel_id][0])


def register(env) -> None:
    env.globals["governance_off_sections"] = off_sections
    env.globals["governance_section_off"] = section_off
    env.globals["governance_section_attrs"] = section_attrs
