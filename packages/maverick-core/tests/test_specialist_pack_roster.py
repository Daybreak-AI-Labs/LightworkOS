"""The specialist and platform pack roster: each pack loads and stays governed.

Pins the specialist + platform packs so a future edit can't silently drop
one or relax its envelope. Mirrors the finance-roster pattern: every pack
lints clean, carries a draft-not-do ("never") guardrail, and -- unless it is a
sandbox builder -- denies ``shell``/``write_file`` (read-only by construction).
"""
from __future__ import annotations

import pytest
from maverick.domain import builtin_dir, lint_profile, load_domains

# Net-new packs, grouped by family. Builders (sandbox shell/code_exec) and the
# sealed legal matters are called out because they carry a different envelope.
_NEW = {
    "finance": ["finance_bus_combination", "finance_impairment", "finance_going_concern",
                "finance_unclaimed_property", "finance_global_info_reporting",
                "finance_derivative_collateral"],
    "bank": ["bank_alm_irrbb", "bank_liquidity_reg", "bank_cecl_allowance"],
    "ins": ["ins_stat_reporting", "ins_actuarial_reserving", "ins_reins_recoverable"],
    "itgrc": ["itgrc_pqc_readiness", "itgrc_crypto_agility", "itgrc_nhi_governance",
              "itgrc_agent_identity", "itgrc_mcp_runtime_gov", "itgrc_model_provenance",
              "itgrc_ai_act_gpai", "itgrc_data_residency", "itgrc_secure_by_design",
              "itgrc_ai_agent_audit", "itgrc_dora_tlpt"],
    "data": ["data_corpus_integrity", "data_semantic_layer", "data_vector_rag_ops"],
    "gtm": ["gtm_trust_center", "gtm_consent_ledger_ops", "gtm_answer_engine",
            "gtm_plg_signals", "gtm_pricing_experiment", "gtm_nrr_engineering",
            "gtm_intent_orchestration", "gtm_ecosystem_ops", "gtm_zero_party_data",
            "gtm_ai_sdr_oversight", "gtm_localized_sdr"],
    "hr": ["hr_rif_warn", "hr_aedt_audit", "hr_skills_inference",
           "hr_pay_transparency_report", "hr_accommodation_interactive",
           "hr_workforce_monitoring_governance"],
    "legal": ["legal_ai_addendum", "legal_sep_licensing", "legal_esg_litigation",
              "legal_privacy_litigation", "legal_ediscovery_modern_data"],
    "pe": ["pe_sre_incident_commander", "pe_data_product_owner", "pe_lakehouse_streaming",
           "pe_feature_store", "pe_slo_reliability", "pe_finops_cloud_cost",
           "pe_llmops_observability"],
    "ops": ["ops_control_tower", "ops_demand_sensing", "ops_supply_resilience_reshoring",
            "ops_carbon_dpp_compliance"],
    "plat": ["plat_skill_distiller", "plat_skill_curator", "plat_skill_marketplace_reviewer",
             "plat_agent_pack_author", "plat_learning_lifecycle_op",
             "plat_fleet_memory_librarian", "plat_capability_sod_linter"],
    "cap": ["cap_research_analyst", "cap_portfolio_analytics", "cap_compliance_surveillance",
            "cap_client_reporting", "cap_regulatory_filing_prep"],
    "util": ["util_outage_coord", "util_reg_filing_prep", "util_meter_billing",
             "util_renewable_rec", "util_grid_compliance"],
    "re": ["re_lease_abstraction", "re_property_ops", "re_rent_roll",
           "re_appraisal_support", "re_capital_projects"],
    "pharma": ["pharma_clinical_doc", "pharma_regulatory_submission",
               "pharma_pharmacovigilance", "pharma_gxp_qa", "pharma_lab_notebook"],
    "tmt": ["tmt_rights_clearance", "tmt_royalty_calc", "tmt_content_metadata",
            "tmt_network_noc", "tmt_subscriber_billing"],
    "hosp": ["hosp_reservations", "hosp_revenue_mgmt", "hosp_guest_relations",
             "hosp_property_compliance", "hosp_group_events"],
}

# Sandbox builders: high-risk, may hold shell/code_exec, but must deny self_edit.
_BUILDERS = {"pe_sre_incident_commander", "pe_data_product_owner",
             "pe_lakehouse_streaming", "pe_feature_store"}
# Sealed legal matters: must not reach external web search.
_SEALED_LEGAL = {"legal_esg_litigation", "legal_privacy_litigation",
                 "legal_ediscovery_modern_data"}

_ALL = [n for names in _NEW.values() for n in names]


@pytest.fixture(scope="module")
def packs():
    return load_domains(builtin_dir())


def test_all_new_packs_present(packs):
    missing = [n for n in _ALL if n not in packs]
    assert not missing, f"missing expansion packs: {missing}"


@pytest.mark.parametrize("name", _ALL)
def test_new_pack_is_clean_and_governed(name, packs):
    p = packs[name]
    errors, _ = lint_profile(p)
    assert errors == [], f"{name}: {errors}"
    assert p.compartment, f"{name}: no compartment seal"
    assert p.knowledge_sources, f"{name}: no knowledge_sources"
    assert "never" in (p.persona or "").lower(), f"{name}: persona lacks a 'never' guardrail"
    if name in _BUILDERS:
        assert "self_edit" in p.deny_tools, f"{name}: builder must deny self_edit"
    else:
        # Read-only by construction: the two tools that mutate the host are denied.
        assert "shell" in p.deny_tools and "write_file" in p.deny_tools, (
            f"{name}: read-only pack must deny shell + write_file")
        assert p.max_risk in ("low", "medium"), f"{name}: risk={p.max_risk!r}"


@pytest.mark.parametrize("name", sorted(_SEALED_LEGAL))
def test_sealed_legal_denies_web_search(name, packs):
    p = packs[name]
    assert "web_search" not in p.allow_tools, f"{name}: web_search must not be allowed"
    assert "web_search" in p.deny_tools, f"{name}: web_search must be denied"
    assert "legal_matter" in p.knowledge_sources, f"{name}: must bind the sealed matter source"
