"""Shared module activation policy and process-local readiness fingerprints."""
from __future__ import annotations

import hashlib
import hmac
import json
import os

# In-app governance-module switches. Each key is the dotted config path of a
# fail-closed [section] enable gate; "requires" is the full requirement chain
# in order (parents first). Turning a module ON enables every path in the
# chain -- one click must open a WORKING workbench, never a child under a
# dead parent -- while turning it OFF disables only the module itself, so
# siblings keep running. Labels are user-facing; config keys stay out of the
# UI (the learning page set that precedent).
_MODULE_SWITCHES: dict[str, dict] = {
    "consent_preferences": {
        "label": "Consent preferences",
        "requires": (),
    },
    "consent_preferences.analytics": {
        "label": "Consent analytics",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.application_scanner": {
        "label": "App tracking checks",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.bulk_jobs": {
        "label": "Bulk consent changes",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.delivery": {
        "label": "Consent delivery",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.experiments": {
        "label": "Consent experiments",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.profile_data": {
        "label": "Consent profile data",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.publishing": {
        "label": "Consent publishing",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.public_api": {
        "label": "Consent public clients",
        "requires": ("consent_preferences", "consent_preferences.publishing"),
    },
    "consent_preferences.native_sdk": {
        "label": "Native consent SDK",
        "requires": (
            "consent_preferences",
            "consent_preferences.publishing",
            "consent_preferences.public_api",
        ),
    },
    "consent_preferences.scanner": {
        "label": "Consent application scanning",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.publishing.web_settings": {
        "label": "Website banner settings",
        "requires": ("consent_preferences", "consent_preferences.publishing"),
    },
    "consent_preferences.profile_data.custom_index": {
        "label": "Find people by preference",
        "requires": ("consent_preferences", "consent_preferences.profile_data"),
    },
    "consent_preferences.global_opt_out": {
        "label": "Global opt-out",
        "requires": ("consent_preferences",),
    },
    "consent_preferences.scanner.notice_proposals": {
        "label": "Scan notice proposals",
        "requires": ("consent_preferences", "consent_preferences.scanner"),
    },
    "consent_preferences.trust_center": {
        "label": "Consumer Trust Center",
        "requires": ("consent_preferences",),
    },
    "consent_registry": {
        "label": "Consent registry",
        "requires": (),
    },
    "data_map": {
        "label": "Data map",
        "requires": (),
    },
    "data_use_governance": {
        "label": "Data-use governance",
        "requires": (),
    },
    "data_use_governance.compiler": {
        "label": "Data-use policy compiler",
        "requires": ("data_use_governance",),
    },
    "data_use_governance.enforcement": {
        "label": "Data-use enforcement",
        "requires": ("data_use_governance", "data_use_governance.compiler"),
    },
    "data_use_governance.snowflake": {
        "label": "Snowflake data-use enforcement",
        "requires": (
            "data_use_governance",
            "data_use_governance.compiler",
            "data_use_governance.enforcement",
        ),
    },
    "data_use_governance.databricks": {
        "label": "Databricks data-use enforcement",
        "requires": (
            "data_use_governance",
            "data_use_governance.compiler",
            "data_use_governance.enforcement",
        ),
    },
    "dsar_fulfillment": {
        "label": "DSAR fulfillment",
        "requires": (),
    },
    "finance_operations": {
        "label": "Finance operations",
        "requires": (),
    },
    "external_agents": {
        "label": "External-agent governance",
        "requires": (),
    },
    "ai_evidence_analysis": {
        "label": "AI evidence analysis",
        "requires": (),
    },
    "ai_inventory": {
        "label": "AI inventory",
        "requires": (),
    },
    "ai_entity_tasks": {
        "label": "AI entity tasks",
        "requires": ("ai_inventory",),
    },
    "governed_document_vault": {
        "label": "Governed document vault",
        "requires": (),
    },
    "tech_risk_compliance.grc_studio": {
        "label": "Compliance studio",
        "requires": ("tech_risk_compliance",),
    },
    "third_party_management.contracts": {
        "label": "Contracts and engagements",
        "requires": ("third_party_management",),
    },
    "assessment_evidence_autopopulation": {
        "label": "Assessment evidence proposals",
        "requires": ("ai_evidence_analysis",),
    },
    "governance_agents": {
        "label": "Governance agents",
        "requires": (),
    },
    "privacy_automation": {
        "label": "Privacy automation",
        "requires": (),
    },
    "privacy_automation.data_discovery": {
        "label": "Privacy data discovery",
        "requires": ("privacy_automation",),
    },
    "privacy_automation.notice_governance": {
        "label": "Privacy notice governance",
        "requires": ("privacy_automation",),
    },
    "privacy_automation.regulatory_intelligence": {
        "label": "Privacy regulatory intelligence",
        "requires": ("privacy_automation",),
    },
    "privacy_automation.rights_orchestration": {
        "label": "Privacy-rights orchestration",
        "requires": ("privacy_automation",),
    },
    "privacy_automation.public_rights_form": {
        "label": "Rights request form",
        "requires": ("privacy_automation",),
    },
    "privacy_automation.rights_consumer_delivery": {
        "label": "Privacy-rights consumer delivery",
        "requires": (
            "privacy_automation",
            "privacy_automation.rights_orchestration",
        ),
    },
    "tech_risk_compliance": {
        "label": "Tech-risk compliance",
        "requires": (),
    },
    "tech_risk_compliance.scoping": {
        "label": "Compliance scoping",
        "requires": ("tech_risk_compliance",),
    },
    "tech_risk_compliance.scope_actions": {
        "label": "Compliance scope actions",
        "requires": ("tech_risk_compliance",),
    },
    "tech_risk_compliance.policy_publication_links": {
        "label": "Policy publication links",
        "requires": ("tech_risk_compliance",),
    },
    "tech_risk_compliance.continuous_evidence": {
        "label": "Continuous evidence",
        "requires": ("tech_risk_compliance",),
    },
    "third_party_management": {
        "label": "Third-party management",
        "requires": (),
    },
    "third_party_management.lifecycle": {
        "label": "Third-party lifecycle",
        "requires": ("third_party_management",),
    },
    "third_party_management.lifecycle.portal": {
        "label": "Third-party collaboration portal",
        "requires": ("third_party_management", "third_party_management.lifecycle"),
    },
    "third_party_management.intelligence": {
        "label": "Third-party intelligence",
        "requires": ("third_party_management",),
    },
    "third_party_management.executive_reports": {
        "label": "Executive vendor reports",
        "requires": ("third_party_management",),
    },
    "vendor_management": {
        "label": "Vendor management",
        "requires": (),
    },
    "connections": {
        "label": "Saved connections",
        "requires": (),
    },
    "evidence_graph": {
        "label": "Evidence records",
        "requires": (),
    },
    "model_risk_assurance": {
        "label": "Model assurance",
        "requires": ("evidence_graph",),
    },
    "ai_vendor_risk": {
        "label": "AI vendor risk",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
    "codebase": {
        "label": "Code projects",
        "requires": (),
    },
    "vendor_onboarding": {
        "label": "AI vendor onboarding",
        "requires": ("connections", "vendor_management", "evidence_graph", "model_risk_assurance", "ai_vendor_risk"),
    },
    # Each gate below is a boolean ``enable`` at this exact path, and each
    # "requires" chain mirrors the kernel module's own enabled() check.
    "control_plane": {  # config.get_control_plane
        "label": "Agent control",
        "requires": (),
    },
    "eu_conformity": {  # eu_conformity.enabled
        "label": "EU AI Act conformity",
        "requires": (),
    },
    "ai_literacy": {  # ai_literacy.enabled
        "label": "AI literacy register",
        "requires": (),
    },
    "policy_packs": {  # policy_packs.enabled
        "label": "Policy packs",
        "requires": (),
    },
    "evidence_gateway": {  # ai_evidence_gateway.enabled
        "label": "AI evidence gateway",
        "requires": (),
    },
    "drift_monitoring": {  # drift_monitoring.enabled -> model_risk_assurance.enabled
        "label": "Model drift monitoring",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
    "ai_incident_reporting": {  # ai_incident_reporting.enabled -> model_risk_assurance
        "label": "AI incident reporting",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
    "explainability": {  # explainability.enabled
        "label": "Decision explanations",
        "requires": (),
    },
    "content_provenance": {  # content_provenance.enabled
        "label": "Content credentials",
        "requires": (),
    },
    "breach_notification": {  # breach_notification.enabled
        "label": "Breach notifications",
        "requires": (),
    },
    "ediscovery": {  # ediscovery.enable
        "label": "Legal holds and matter export",
        "requires": (),
    },
    "privacy_automation.drop_management": {  # privacy_drop_management.enabled
        "label": "Data broker deletion requests",
        "requires": ("privacy_automation", "privacy_automation.rights_orchestration"),
    },
    "ai_regulatory_feed": {  # ai_regulatory_feed.enabled -> finance_operations + evidence_gateway
        "label": "AI regulation updates",
        "requires": ("finance_operations", "evidence_gateway"),
    },
    "ai_business_intake": {  # ai_business_intake.enabled -> model_risk_assurance
        "label": "AI project intake",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
    "ai_dynamic_risk": {  # ai_dynamic_risk.enabled
        "label": "Changing AI risk scores",
        "requires": (),
    },
    "ai_policy_management": {  # ai_policy_management.enabled
        "label": "AI policy library",
        "requires": (),
    },
    "ai_runtime_guardrails": {  # ai_runtime_guardrails.enabled
        "label": "AI guardrails while running",
        "requires": (),
    },
    "ai_explainability": {  # ai_explainability.enabled
        "label": "AI explanation records",
        "requires": (),
    },
    "ai_conformity_workflow": {  # ai_conformity_workflow.enabled -> model_risk_assurance
        "label": "AI conformity reviews",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
    "ai_insurability": {  # ai_insurability.enabled
        "label": "AI insurance readiness",
        "requires": (),
    },
    "ai_regulated_verticals": {  # ai_regulated_verticals.enabled
        "label": "AI rules for regulated industries",
        "requires": (),
    },
    "ai_bank_mrm": {  # ai_bank_mrm.enabled
        "label": "Bank model risk management",
        "requires": (),
    },
    "ai_discovery_sensors": {  # ai_discovery_sensors.enabled
        "label": "Find unlisted AI use",
        "requires": (),
    },
    "portfolio_risk": {  # portfolio_risk.enabled -> model_risk_assurance
        "label": "AI portfolio risk",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
    "ai_cost_roi": {  # ai_cost_roi.enabled
        "label": "AI cost and return",
        "requires": (),
    },
    "eu_ai_incidents": {  # eu_ai_incidents.enabled
        "label": "EU AI incident reports",
        "requires": (),
    },
    "grc_outbound_sync": {  # grc_outbound_sync.policy_from_config
        "label": "Outbound assurance records",
        "requires": (),
    },
    "incident_attachment_metadata": {  # incident_attachment_metadata.enabled
        "label": "Incident attachments",
        "requires": (),
    },
    # agent_topology.enabled -> entity_graph (on by default) + model_risk_assurance
    "agent_topology": {
        "label": "Agent dependency map",
        "requires": ("evidence_graph", "model_risk_assurance"),
    },
}


# Readiness receipts are process-local and bound to an HMAC of the exact
# effective configuration roots for the module.  The random key means the
# public fingerprint cannot be used to test guesses about stored secrets, and
# a restart intentionally returns to ``unverified`` until a fresh probe runs.
_MODULE_FINGERPRINT_KEY = os.urandom(32)


class _ModuleConfigurationUnavailable(RuntimeError):
    """Module state cannot be read without inventing a safe-looking default."""


def _module_path_enable_state(loaded: dict, path: str) -> str:
    node: object = loaded
    for part in path.split("."):
        if not isinstance(node, dict):
            return "invalid"
        if part not in node:
            return "disabled"
        node = node[part]
    if not isinstance(node, dict):
        return "invalid"
    enabled = node.get("enable", False)
    if type(enabled) is not bool:
        return "invalid"
    return "enabled" if enabled else "disabled"


def _module_path_enabled(loaded: dict, path: str) -> bool:
    return _module_path_enable_state(loaded, path) == "enabled"


def _module_switch_enabled(loaded: dict, section: str) -> bool:
    chain = (*_MODULE_SWITCHES[section]["requires"], section)
    return all(_module_path_enabled(loaded, p) for p in chain)


def _module_config_fingerprint(loaded: dict, section: str) -> str:
    chain = (*_MODULE_SWITCHES[section]["requires"], section)
    roots = sorted({path.split(".", 1)[0] for path in chain})
    material = {root: loaded.get(root) for root in roots}
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hmac.new(_MODULE_FINGERPRINT_KEY, encoded, hashlib.sha256).hexdigest()


def _module_activation_state(loaded: dict, section: str) -> dict:
    requirements = tuple(_MODULE_SWITCHES[section]["requires"])
    chain = (*requirements, section)
    path_states = {path: _module_path_enable_state(loaded, path) for path in chain}
    invalid = [path for path, state in path_states.items() if state == "invalid"]
    missing = [path for path in requirements if path_states[path] != "enabled"]
    target_enabled = path_states[section] == "enabled"
    if invalid:
        status = "failed"
        detail = "One or more enable gates have an invalid configuration shape."
    elif not target_enabled:
        status = "disabled"
        detail = "The module's own enable gate is off."
    elif missing:
        status = "incomplete"
        detail = "The module is on, but one or more required parent gates are off."
    else:
        status = "enabled"
        detail = (
            "The complete enable-gate chain is on. This does not prove runtime "
            "readiness."
        )
    return {
        "status": status,
        "enabled": status == "enabled",
        "target_enabled": target_enabled,
        "requirements": list(requirements),
        "missing_requirements": missing,
        "invalid_paths": invalid,
        "detail": detail,
        "fingerprint": _module_config_fingerprint(loaded, section),
    }


def _load_module_config() -> dict:
    from maverick import config as config_module

    try:
        loaded = config_module.load_config()
        source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise _ModuleConfigurationUnavailable from exc
    if source_errors or not isinstance(loaded, dict):
        raise _ModuleConfigurationUnavailable
    return loaded


def module_activation_enabled(section: str) -> bool:
    """Fail-closed effective gate state for server-rendered module banners."""

    if section not in _MODULE_SWITCHES:
        return False
    try:
        loaded = _load_module_config()
    except (KeyboardInterrupt, SystemExit):
        raise
    except _ModuleConfigurationUnavailable:
        return False
    return _module_activation_state(loaded, section)["enabled"] is True
