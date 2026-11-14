"""Canonical classification of local state that can authorize work or spend.

Backup comparison and bootstrap restore must agree on this list.  Keeping the
classification pure (it receives the already-detected SQLite bit) avoids a
dependency cycle with :mod:`maverick.backup` while still giving tests one
closed registry to audit.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

# Installation-wide, append-only identity history. These roots are outside
# tenants/ so deleting a workspace cannot free its name or erase its retirement.
TENANT_LIFECYCLE_AUTHORITY_POLICIES = {
    ".tenant-namespaces": "tenant_namespace_reservation",
    ".tenant-deletions": "tenant_deletion_tombstone",
}

# Tenant-local governed record stores whose restored rows require a hold or
# store-specific authenticated reconciliation.  These rows can feed
# approvals, external delivery, regulated status, trust, or execution gates.
# Keeping the mapping closed and exported lets an acceptance test compare it
# with every literal GovernedRecordStore/_RecordStore declaration in source.
GLOBAL_START_JSON_AUTHORITY_POLICIES = {
    "a2a-task-authority-v1": "a2a_task_execution_authority",
    "ai_bank_mrm_packages": "bank_mrm_package_authority",
    "ai_benchmark_cohort_reports": "benchmark_cohort_authority",
    "ai_benchmark_contributions": "benchmark_contribution_authority",
    "ai_business_intakes": "business_intake_authority",
    "ai_discovery_sensor_observations": "sensor_observation_authority",
    "ai_dynamic_risk_signals": "dynamic_risk_signal_authority",
    "ai_dynamic_risk_snapshots": "dynamic_risk_snapshot_authority",
    "ai_explanations": "explainability_authority",
    "ai_insurability_profiles": "insurability_profile_authority",
    "ai_inventory_assets": "ai_inventory_asset_authority",
    "ai_inventory_runs": "ai_inventory_run_authority",
    "ai_inventory_status": "ai_inventory_status_authority",
    "ai_media_provenance": "media_provenance_authority",
    "ai_policy_evaluations": "policy_evaluation_authority",
    "ai_provider_cost_observations": "provider_cost_observation_authority",
    "ai_provider_cost_receipts": "provider_cost_receipt_authority",
    "ai_registry": "privacy_ai_registry_authority",
    "ai_regulated_vertical_packages": "regulated_vertical_authority",
    "ai_regulatory_notices": "regulatory_notice_authority",
    "ai_regulatory_staleness": "regulatory_staleness_authority",
    "ai_roi_assumptions": "roi_assumption_authority",
    # A restored draft reservation or adoption decision is not fresh consent
    # and must not create a second native workflow from an old replay receipt.
    "intent_value_recommendations": "intent_value_draft_decision_authority",
    "ai_serious_incidents": "serious_incident_authority",
    "assessment_evidence_proposals": "assessment_evidence_authority",
    "channel-deliveries": "channel_execution_delivery_authority",
    "channel-delivery-cursors": "channel_delivery_recovery_cursor_authority",
    "channel-poll-cursors": "channel_provider_poll_cursor_authority",
    # Customer workflow records can restore older grants, pending intent or
    # consumed operation receipts. They need current authority reconciliation;
    # an authenticated old backup is not evidence of current consent.
    "conversation_inbox": "conversation_intent_authority",
    "commitment_viability": "commitment_review_authority",
    "commitment_viability_archive": "commitment_review_authority",
    "deliverable_bundles": "deliverable_release_authority",
    "project_workspaces": "project_workspace_membership_authority",
    "task_handoffs": "task_handoff_authority",
    "billing_sync_reviews": "billing_sync_review_authority",
    "budget_accounting_cases": "budget_reconciliation_authority",
    "employee_content_access": "private_content_grant_authority",
    "deliverable-share-releases": "public_release_authority",
    "employee_activation": "employee_activation_authority",
    "employee_departures": "employee_departure_authority",
    # Even metadata-only replay receipts prevent previously consumed changes
    # from executing again. An older restored absence is not fresh admission.
    "fact_operation_receipts": "fact_operation_receipt_authority",
    # Ekko draft-build receipts are the same kind of replay barrier: a lost
    # reply must not rebuild drafts the person has since removed.
    "ekko_build_operations": "ekko_build_operation_receipt_authority",
    "permission_access_requests": "permission_request_authority",
    "personal_data_requests": "personal_erasure_request_authority",
    "owned_task_diagnostics": "private_diagnostic_release_authority",
    "data_map": "privacy_data_map_record_authority",
    "dpa_reviews": "dpa_review_authority",
    "dsar_requests": "dsar_request_authority",
    "eu_ai_article_73_incidents": "eu_incident_authority",
    "eu_ai_conformity_evidence_bindings": "conformity_evidence_authority",
    "eu_ai_conformity_readiness_cases": "conformity_readiness_authority",
    "eu_annex_iv": "eu_annex_iv_authority",
    "eu_art43_routes": "eu_conformity_route_authority",
    "eu_deployer": "eu_deployer_authority",
    "eu_fria": "eu_fria_authority",
    "eu_gpai": "eu_gpai_authority",
    "eu_ifu": "eu_instruction_for_use_authority",
    "eu_pmm_plans": "eu_post_market_monitoring_authority",
    "eu_registrations": "eu_registration_authority",
    "finance_anomaly_cases": "finance_anomaly_case_authority",
    "finance_screening_cases": "finance_screening_case_authority",
    # Retained action evidence, operator answers and recipe admissions carry
    # withdrawal and signed-lineage state; a restored older copy could revive
    # withdrawn evidence or a revoked admission.
    "flow_action_episodes": "flow_action_episode_authority",
    "flow_operator_reviews": "flow_operator_review_authority",
    "flow_recipe_lineage": "flow_recipe_lineage_authority",
    "audit-action-reviews": "audit_maintenance_request_authority",
    "approval-challenges": "approval_challenge_execution_authority",
    "approval-challenge-removals": "approval_challenge_removal_authority",
    "encryption-maintenance": "encryption_maintenance_authority",
    "installation-security-attempts": "installation_security_request_authority",
    "instruction-captures": "instruction_capture_permission_authority",
    "learned-skill-change-requests": "learned_skill_change_authority",
    "manual-skill-removal-requests": "manual_skill_removal_authority",
    "learning-conflict-requests": "learning_check_admission_authority",
    "learning-pass-requests": "learning_pass_admission_authority",
    "learning-flywheel-requests": "learning_flywheel_admission_authority",
    "learning-distinction-requests": "learning_distinction_admission_authority",
    "reward-training-requests": "ranking_training_admission_authority",
    "shared-decision-evidence": "decision_evidence_permission_authority",
    "commitment-capability": "commitment_capability_source_authority",
    "local-work-restructuring": "work_restructuring_source_authority",
    "portable-competence-requests": "portable_competence_source_authority",
    "private-task-computation": "private_task_computation_source_authority",
    "recovery-visibility-practices": "recovery_visibility_source_authority",
    "procedure-interaction-requests": "procedure_interactions_source_authority",
    "request-specific-programs": "request_program_source_authority",
    "operator-acquisition": "operator_acquisition_source_authority",
    "governed-rule-evolution": "governed_rule_evolution_source_authority",
    "local-rule-applicability": "applicability_regions_source_authority",
    "agent-override-removal-requests": "agent_override_change_authority",
    "automation-import-requests": "automation_import_source_authority",
    "generated-tool-removals": "generated_tool_removal_authority",
    "viewpoints-requests": "viewpoints_request_source_authority",
    "settings-catalog-requests": "settings_catalog_request_authority",
    "consent-withdrawal-requests": "consent_withdrawal_request_authority",
    "workflow-step-checks": "workflow_step_check_source_authority",
    "commitment-economic-alternatives": "commitment_economic_alternatives_source_authority",
    "local-rule-requalification": "rule_requalification_authority",
    "learning-case-requests": "learning_case_write_authority",
    "learning-case-import-requests": "learning_case_import_authority",
    "learning-case-setup-requests": "learning_case_setup_authority",
    "learning-holdout-initializations": "learning_holdout_initialization_authority",
    "learning-holdout-requests": "learning_holdout_setup_authority",
    "learning-pending-requests": "learning_question_decision_authority",
    "learning_job_observations": "learning_original_observation_authority",
    "local-flow-comparisons": "local_flow_comparison_authority",
    "local-flow-release-effects": "local_flow_release_effect_authority",
    "local-flow-release-targets": "local_flow_release_target_authority",
    "model-answer-score-requests": "answer_score_admission_authority",
    "imessage-intake-cursors": "imessage_intake_cursor_authority",
    "model_risk_portfolio_snapshots": "model_risk_portfolio_authority",
    "outcome_value_evidence": "outcome_value_evidence_authority",
    "paper_reviews": "paper_review_authority",
    "privacy_incidents": "privacy_incident_authority",
    "ropa": "ropa_authority",
    "security_audits": "security_audit_authority",
    "security_clock_packs": "security_clock_authority",
    "security_controls": "security_control_authority",
    "security_evidence": "security_evidence_authority",
    "security_incidents": "security_incident_authority",
    "security_poam": "security_poam_authority",
    "security_policies": "security_policy_authority",
    "security_risks": "security_risk_authority",
    "security_vendors": "security_vendor_authority",
    "vendor_renewal_observations": "vendor_renewal_observation_authority",
    # Company sign-in: uploaded SAML metadata, certificates and keys, the
    # reviewed setup, provider sign-in checks and local-owner migration.  These
    # carry credential and identity authority; a restored copy is retained and
    # blocks start until current custody is reconciled (never replayed or
    # silently discarded).
    "company-saml-materials": "company_saml_credential_authority",
    "company-saml-setups": "company_saml_setup_authority",
    "company-signin-tests": "company_signin_test_authority",
    "company-signin-migrations": "company_signin_migration_authority",
    # Saved remote Knowledge sources pin an account/container, publish
    # reviewed snapshots for specialist use and journal paid refresh work.
    "knowledge-remote-sources": "knowledge_remote_source_authority",
    "knowledge-source-refreshes": "knowledge_source_refresh_execution_authority",
    "knowledge-source-snapshots": "knowledge_source_snapshot_authority",
    "knowledge-source-decisions": "knowledge_source_decision_authority",
    # Reviewed single sends: a restored request must never resend.
    "channel-test-requests": "channel_test_dispatch_authority",
    "personal-alert-tests": "personal_alert_test_dispatch_authority",
    # Reviewed specialist publication and vendor identity decisions.
    "specialist-drafts": "specialist_draft_publication_authority",
    # A restored trial must not route goals to a version that was since promoted or rolled back.
    "specialist-canaries": "specialist_canary_trial_authority",
    "specialist-canary-goals": "specialist_canary_goal_authority",
    # Starter teams retain reviewed setup, exact-input approvals and native
    # execution/replay receipts. An older backup cannot renew consent, reset
    # occurrence budgets or authorize another dispatch. Keep every store
    # intact and block startup: no authenticated starter-team rebind adapter
    # is currently available to release these restored authorities.
    "starter_team_setups": "starter_team_setup_authority",
    "starter_team_reviews": "starter_team_review_authority",
    "starter_team_cases": "starter_team_case_authority",
    "starter_team_schedules": "starter_team_schedule_authority",
    "starter_team_inbox": "starter_team_input_approval_authority",
    "starter_team_ticks": "starter_team_tick_receipt_authority",
    "starter_team_runtime": "starter_team_runtime_authority",
    "starter_team_runtime_reviews": "starter_team_runtime_review_authority",
    "starter_team_goal_bindings": "starter_team_goal_binding_authority",
    "vendor-profile-decisions": "vendor_profile_decision_authority",
    # Exact retained safety-settings copies and reviewed restore requests are
    # runtime-override authority: a restored copy must not reapply itself.
    "runtime-policy-copies": "runtime_policy_copy_authority",
    "runtime-policy-requests": "runtime_policy_restore_request_authority",
    # Digest-only evidence of guarded connector attempts, and the retained
    # native-authority pins the AI governance loop decides against.
    "runtime-enforcement": "runtime_enforcement_evidence_authority",
    "ai-governance-source-pins": "ai_governance_source_pin_authority",
    # Reviewed business fields keep their exact operation outcomes as replay
    # barriers; independent audit checkpoint copies are second-person approved
    # uploads whose unknown outcomes are never repeated.
    "work-record-details": "work_record_detail_authority",
    "audit-checkpoint-custody": "audit_checkpoint_custody_authority",
}

# These governed records cannot authorize source work, change budget limits or
# grant source access. Preserve them as ordinary customer data. The explicit
# registry distinguishes this reviewed decision from an accidentally unmapped
# authority. Consumers still validate schema, owner and current source access.
NON_AUTHORIZING_GOVERNED_NAMESPACES = frozenset({
    "action_center_preferences", "personal_budget_warnings", "project_workspace_defaults",
    # Derived analytics and economic assumptions never admit work, alter
    # source evidence, grant access or set spending limits. Source access and
    # complete execution evidence are checked again when reporting resumes.
    "intent_value_work", "intent_value_settings", "intent_value_benchmarks",
})

# File authorities from customer workflows have the same anti-rollback needs
# as governed records. None currently has an intrinsic authenticated rebind
# transformation, so bootstrap retains the bytes and blocks admission.
CUSTOMER_FILE_AUTHORITY_POLICIES = {
    "employee_companions": "employee_companion_policy_authority",
    "personal-data": "personal_identity_link_authority",
    "personal-memory": "personal_memory_consent_authority",
    "personal-notifications": "personal_notification_delivery_authority",
    "device-pairing": "device_credential_authority",
    "model-tests": "model_test_dispatch_authority",
    "knowledge-reindex": "knowledge_reindex_execution_authority",
    "knowledge-task-context": "knowledge_task_binding_authority",
    "plugin-flow-pins": "plugin_execution_pin_authority",
    "plugin-task-pins": "plugin_execution_pin_authority",
    "plugin-workbench": "plugin_qualification_authority",
    "goal-share-previews": "external_share_dispatch_authority",
    "retention-runs": "retention_dispatch_authority",
}

# These customer records are part of the supported application-level restore
# proof.  Backup validation authenticates/decrypts their bounded schemas and
# verifies their cross-record links before publication, so they are protected
# without creating an additional external-work blocker.
APPLICATION_VALIDATED_JSON_AUTHORITY_POLICIES = {
    "ai_vendor_risk": "validated_ai_vendor_risk_record",
    "vendor_management": "validated_vendor_record",
}

# The two identity-governance factories use a bounded ``sink`` f-string rather
# than literal namespace declarations.  Both supported sinks are enumerated so
# restored request/outcome delivery state cannot fall through the literal-store
# completeness check.
# Per-person private push (ntfy) stores are named ``<kind>-<32 hex>`` from a
# digest of the owner. Destinations hold the private topic; results hold
# send receipts that must never allow a blind resend after a restore.
PERSONAL_PUSH_AUTHORITY_POLICIES = {
    "private-push-destinations": "personal_push_destination_authority",
    "private-push-results": "personal_push_delivery_receipt_authority",
}
_PERSONAL_PUSH_NAMESPACE = re.compile(
    r"(private-push-destinations|private-push-results)-[0-9a-f]{32}"
)

DYNAMIC_JSON_AUTHORITY_POLICIES = {
    "identity_governance_alert_outcomes": "identity_delivery_outcome_authority",
    "identity_governance_alert_requests": "identity_change_request",
    "identity_governance_dynamic_risk_outcomes": (
        "identity_delivery_outcome_authority"
    ),
    "identity_governance_dynamic_risk_requests": "identity_change_request",
}


def _contains(parts: tuple[str, ...], *sequence: str) -> bool:
    width = len(sequence)
    return any(parts[index:index + width] == sequence for index in range(len(parts) - width + 1))


def authority_policy(relative: str, *, is_sqlite: bool) -> str | None:  # noqa: C901
    """Return the one recovery policy for ``relative``, or ``None``.

    Paths are archive-style POSIX paths and comparison is case-insensitive so
    a snapshot created on a case-sensitive host cannot bypass Windows recovery
    policy with a mixed-case namespace.  Unknown SQLite is deliberately still
    protected and receives a blocking policy rather than becoming ordinary
    data.
    """
    parts = tuple(part.casefold() for part in PurePosixPath(relative).parts)
    if not parts:
        return None
    name = parts[-1]

    # A file that is itself SQLite remains authority even if its custom name
    # resembles a lock sidecar.  Ordinary lock files carry no durable state.
    if not is_sqlite and name.endswith(".lock"):
        return None

    if len(parts) > 1 and parts[0] in TENANT_LIFECYCLE_AUTHORITY_POLICIES:
        return TENANT_LIFECYCLE_AUTHORITY_POLICIES[parts[0]]

    if _contains(parts, "a2a", "tasks.authority.sealed"):
        # This is a database-generation/anti-downgrade receipt, not a credential
        # or a cache. Restoring it requires current shared authority readback;
        # discarding it would allow an already consumed task to execute locally.
        return "a2a_shared_authority_binding"
    if (
        _contains(parts, "connections", "connections.sealed")
        or _contains(parts, "connections", "oauth-setup.sealed")
        or _contains(parts, "oauth", "tokens.sealed")
        or _contains(parts, "partner", "tenants.sealed")
        or _contains(parts, "privacy_automation", "evidence-keys.sealed")
    ):
        return "credential"
    if (
        _contains(parts, "partner", "tenants.json")
        or _contains(parts, "partner", "tenants.json.migrated-plaintext")
    ):
        return "plaintext_credential_residue"
    # Browser-vault keys do not use a ``.key`` suffix, so snapshot key filters
    # cannot identify them.  Treat every file below the vault namespace as
    # credential authority; bootstrap either needs authenticated retained
    # custody or must explicitly discard the restored vault before publication.
    if "vault" in parts[:-1]:
        return "browser_vault_credential_authority"
    # This deployment HMAC key normally lives outside a named tenant workspace.
    # Classifying the path still fails closed for legacy or crafted snapshots
    # that place a copy inside the workspace archive.
    if _contains(parts, "keys", "anon.salt"):
        return "privacy_identity_key_authority"
    if _contains(parts, "keys", "dek.wrapped"):
        return "wrapped_tenant_dek"
    if _contains(parts, "privacy_automation", "discovery-data-use-key.sealed"):
        # Tenant-sealed key for the discovery data-use database (itself an
        # unknown, blocking SQLite). Retain it with that database; a missing or
        # rolled-back key must never be silently regenerated over saved data.
        return "privacy_discovery_data_use_key"
    tenant_scoped_root = len(parts) == 1 or (
        len(parts) >= 3 and parts[-3] == "tenants"
    )
    if tenant_scoped_root and name in {
        "config.toml", "runtime-overrides.toml", "roles.toml",
    }:
        return {
            "config.toml": "tenant_configuration_authority",
            "runtime-overrides.toml": "runtime_override_authority",
            "roles.toml": "role_instruction_authority",
        }[name]
    if len(parts) == 1 and name in {
        "dashboard-config.toml",
        "dashboard-event-triggers.toml",
        "dashboard-triggers.toml",
    }:
        return {
            "dashboard-config.toml": "dashboard_configuration_authority",
            "dashboard-event-triggers.toml": "event_trigger_scheduler_authority",
            "dashboard-triggers.toml": "webhook_trigger_authority",
        }[name]
    if _contains(parts, "model_improvement", "training_receipts.ndjson"):
        return "training_approval_authority"
    if _contains(parts, "keys", "consent-experiments.key"):
        return "consent_experiment_key_authority"
    if "generated_tools" in parts[:-1]:
        return "generated_tool_authority"
    if "learned-skills" in parts[:-1]:
        return "learned_skill_authority"
    if "skills" in parts[:-1]:
        return "skill_instruction_authority"
    if name == "reflexions.ndjson":
        return "reflexion_instruction_authority"
    if name == "factory_corrections.ndjson":
        return "factory_prompt_authority"
    if name == "jit_experience.ndjson":
        return "jit_selection_authority"
    if name == "learning_cache.json":
        return "learned_result_authority"
    if "dreams" in parts[:-1] and name in {
        "insights.ndjson", "rehearsals.ndjson", "user_notes.ndjson",
    }:
        return "dream_instruction_authority"
    if "fleet-memory" in parts[:-1]:
        return (
            "fleet_agent_identity_authority"
            if name == "agents.ndjson"
            else "external_learning_input_authority"
        )
    if "event-input" in parts[:-1]:
        return "event_input_authority"
    if _contains(parts, "assessments", "templates.json"):
        return "assessment_instruction_authority"
    if _contains(parts, "assessments", "register.json"):
        return "assessment_review_authority"
    if "custom_templates" in parts[:-1]:
        return "assessment_template_authority"
    if "task_graphs" in parts[:-1]:
        return "task_graph_authority"
    if "templates" in parts[:-1]:
        return "goal_template_authority"
    if "forms" in parts[:-1]:
        return "form_event_authority"
    if "form-recovery" in parts[:-1]:
        # Signed owner decisions and their accepted markers suppress execution.
        # An older restored absence could revive a deliberately stopped form row.
        return "form_decision_authority"
    if "repl" in parts[:-1]:
        return "repl_execution_authority"
    if "adapters" in parts[:-1]:
        return "adapter_runtime_authority"
    if _contains(parts, "privacy", "clause_playbook.json"):
        return "clause_policy_authority"
    if _contains(parts, "registers", "licenses.json"):
        return "regulatory_license_authority"
    if _contains(parts, "content_provenance", "manifest_attestations.ndjson"):
        return "content_provenance_authority"
    if _contains(parts, "model_risk_assurance", "pack_attestations.ndjson"):
        return "model_risk_pack_trust_authority"
    if _contains(parts, "ai_evidence_gateway", "interaction_receipts.ndjson"):
        return "evidence_delivery_receipt_authority"
    if "ai_evidence_gateway" in parts[:-1] and (
        "interaction_receipts" in parts[:-1]
        or name == "interaction_receipts.index-state.json"
    ):
        return "evidence_delivery_receipt_authority"
    if "ai_evidence_gateway" in parts[:-1] and (
        "assurance_packets" in parts[:-1]
        or name == "assurance_packets.ndjson"
        or name == "assurance_packets.index-state.json"
    ):
        return "evidence_trust_authority"
    if "task-file-recovery" in parts[:-1]:
        return "task_file_recovery"

    if _contains(parts, "flows", "runs"):
        return "flow_run"
    if _contains(parts, "flows", "published"):
        return (
            "flow_publication_history"
            if name.endswith(".revoked")
            else "flow_publication"
        )
    if _contains(parts, "flows", "idempotency"):
        return "flow_idempotency"
    if _contains(parts, "llm_gateway_team_budget", "team_budget.json"):
        return "llm_team_budget"
    if _contains(parts, "mcp_sidecar", "call_budget.json"):
        return "mcp_call_budget"
    # Frozen external billing receipts and provider admission history cannot
    # roll back independently of the provider or cumulative usage ledger.
    if _contains(parts, "billing", "stripe-collections"):
        return "stripe_collection_authority"
    if "usage" in parts[:-1]:
        provider_policies = {
            "provider_holds.json": "organization_provider_holds",
            "provider_holds.required": "organization_provider_holds_required",
            "provider_history.sqlite3": "organization_provider_history",
            "provider_history.required": "organization_provider_history_required",
        }
        if name in provider_policies:
            return provider_policies[name]
    if _contains(parts, "browser", "state.json"):
        return "browser_session"
    if _contains(parts, "keys", "plugin_ca", "revocations.json"):
        return "plugin_ca_revocations"
    if _contains(parts, "unified-audit", "custody-state.json"):
        return "unified_audit_delivery_state"
    if _contains(parts, "governance_agents", "reference-custody-keyring.json"):
        return "governance_reference_keyring"
    if _contains(parts, "governance_inventory", "integrity.key"):
        return "governance_inventory_key"
    if _contains(parts, "notification-links", "signing.key"):
        # Signs one-action mute/unsubscribe links; a restored or rolled-back
        # key would let old links act again, so it stays custody authority.
        return "notification_link_signing_key"
    if _contains(parts, "tech_risk_compliance", "grc-studio", "integrity.key"):
        return "grc_studio_integrity_key"
    if _contains(parts, "harness", "addenda.json"):
        return "harness_instruction_authority"
    if "harness-refine" in parts[:-1] and name in {
        "proposals.json", "refinements.json",
    }:
        return "harness_refinement_authority"

    exact_names = {
        "external_agents.json": "external_agents",
        "agent_trust.json": "agent_trust",
        "capability_revocations.json": "capability_revocations",
        "external-replay.json": "external_replay",
        "channel_federation_outbox.json": "federation_outbox",
        "channel_replay.json": "federation_replay",
        "channel_rate.json": "federation_rate",
        "consent.ledger": "consent_authority",
        "consent.ledger.key": "consent_authority_key",
        "handoff_nonces.json": "handoff_nonce",
        "provider_spend.json": "provider_spend",
        "provider_spend.json.required": "provider_spend_required",
        "provider_spend.json.tenant-fold": "provider_spend_required",
        "provider_spend.sqlite3.active": "provider_spend_required",
        "provider_spend.sqlite3.seal": "provider_spend_required",
        "tenant_registry.json": "tenant_registry",
        "dashboard-owner.json": "dashboard_owner",
        "saml-consumed-assertions.json": "saml_replay",
        "session-revocations.json": "session_revocation",
        "oidc-subjects.json": "oidc_subject_directory",
        "oidc-retired-subjects.json": "oidc_subject_tombstone",
        "channel-oidc-bridge.json": "channel_oidc_identity_link_authority",
        "dashboard-users.json": "dashboard_user_roles",
        # Presence markers: a roster existed, so its absence denies access.
        "dashboard-users.json.present": "dashboard_user_roles",
        "dashboard-tenant-roles.json.present": "dashboard_tenant_roles",
        "dashboard-custom-roles.json": "dashboard_custom_roles",
        "dashboard-tenant-roles.json": "dashboard_tenant_roles",
        "dashboard-invites.json": "dashboard_invites",
        "dashboard-user-suites.json": "dashboard_suite_grants",
        "dashboard-session.key": "dashboard_session_secret",
        "dashboard-passphrases.json": "dashboard_local_passphrases",
        "dashboard-passphrase-resets.json": "dashboard_passphrase_resets",
        "scim_users.json": "scim_user_directory",
        "scim_groups.json": "scim_group_directory",
        "scim_groups.audit-outbox.json": "scim_audit_delivery",
        "privacy-discovery-remediation-scheduler.json": "privacy_remediation_scheduler",
        "privacy-notice-publication-scheduler.json": "privacy_notice_scheduler",
        "trusted_evidence_registry.json": "trusted_evidence_registry",
        "plugins.lock.json": "plugin_lock",
        "config_proposals.json": "config_proposal",
        "control_plane_timeboxes.json": "control_plane_timebox",
        "voice_profiles.json": "voice_identity_profile",
        "shield_rules.json": "shield_rule_authority",
        "calibration_verdict.json": "calibration_authority",
        "self_harness_calibration_receipt.json": "self_harness_calibration_authority",
        "calibration_checker_receipt.json": "self_harness_calibration_authority",
        "budget_tuning.json": "learned_budget_authority",
        "router_bandit.json": "provider_routing_authority",
        "planning_stats.json": "planning_budget_authority",
        "guardrails.json": "learned_guardrail_authority",
        "calibration.ndjson": "calibration_evidence_authority",
        "consequence_cards.ndjson": "earned_autonomy_evidence",
        "consequences.ndjson": "earned_autonomy_outcomes",
        "outcome_links.ndjson": "earned_autonomy_outcome_links",
        "earned_autonomy.ndjson": "earned_autonomy_ledger",
        "self_improvement.json": "self_improvement_authority",
        "self_improvement.json.journal": "self_improvement_authority",
        "supply_chain_pins.json": "supply_chain_trust_authority",
        "dashboard-ui-visibility.json": "dashboard_visibility_authority",
        "dashboard-workspace-tenants.json": "dashboard_workspace_authority",
        "computer_calibration.json": "computer_action_calibration_authority",
        "procedural_memory.json": "procedural_instruction_authority",
        "role_stats.json": "role_routing_authority",
        "skill_stats.json": "skill_ranking_authority",
        "skill_embeddings.json": "skill_retrieval_authority",
        "compaction_hybrid.json": "compaction_strategy_authority",
        "compaction_hybrid_weights.json": "compaction_strategy_authority",
        "codebook.json": "coordination_codec_authority",
        "token_codebook.json": "coordination_codec_authority",
        "tool_cache_snapshot.jsonl": "external_read_cache_authority",
        "release_canary.json": "release_gate_authority",
        "factory_outcomes.ndjson": "factory_learning_input_authority",
        "trajectories.ndjson": "trajectory_learning_input_authority",
        "compaction_stream.json": "compaction_prompt_state_authority",
        "compaction_ledger.json": "compaction_selection_authority",
        "redteam_results.json": "red_team_certification_authority",
        "reliability_cert.json": "reliability_certification_authority",
        "tool_outcomes.json": "tool_outcome_learning_authority",
    }
    exact = exact_names.get(name)
    if exact is not None:
        return exact
    if name == "notification-deliveries.json":
        return "notification_dispatch_authority"
    if name.endswith(".ownership.json"):
        return "generated_content_owner_authority"
    if name.startswith("budget_receipts."):
        return "budget_receipt"
    if name == "retention.index" and "draft-recovery" in parts[:-1]:
        return "draft_recovery_retention"
    if "flows" in parts[:-1] and name in {
        "evolution.ndjson", "node-outcomes.ndjson", "node-tools.ndjson",
    }:
        return "flow_learning_input_authority"

    namespace_policies = {
        **GLOBAL_START_JSON_AUTHORITY_POLICIES,
        **APPLICATION_VALIDATED_JSON_AUTHORITY_POLICIES,
        **DYNAMIC_JSON_AUTHORITY_POLICIES,
        **CUSTOMER_FILE_AUTHORITY_POLICIES,
        "usage": "usage_ledger",
        "grc_sync_outbound": "grc_delivery",
        "grc_outbound_sync_states": "grc_delivery_state",
        "grc_outbound_sync_events": "grc_delivery_history",
        "vendor_onboarding": "vendor_operation",
        "evidence_graph": "evidence_trust_authority",
        "incident_attachment_metadata": "incident_attachment_authority",
        "ai_evidence_conversations": "evidence_delivery_state_authority",
        "ai_evidence_receipts": "evidence_delivery_receipt_authority",
        "ai_evidence_policy_snapshots": "evidence_policy_snapshot_authority",
        "model_risk_observations": "model_risk_asset_authority",
        "model_risk_declarations": "model_risk_declaration_authority",
        "model_risk_evidence": "model_risk_evidence_authority",
        "model_risk_incidents": "model_risk_incident_authority",
        "model_drift_baselines": "model_drift_baseline_authority",
        "ai_literacy_requirements": "literacy_requirement_authority",
        "ai_literacy_assignments": "literacy_assignment_authority",
        "ai_literacy_completions": "literacy_completion_authority",
        "ai_literacy_waivers": "literacy_waiver_authority",
        "ai_literacy_role_requirements": "literacy_role_requirement_authority",
        "ai_literacy_role_assignments": "literacy_role_assignment_authority",
        "ai_literacy_role_completions": "literacy_role_completion_authority",
        "outcome_accounting": "outcome_accounting_authority",
        "finance_screening_lists": "finance_screening_list_authority",
        "finance_screening_list_metadata": "finance_screening_metadata_authority",
        "dsar_fulfillment": "dsar_delivery_authority",
        # Public rights-request form: per-property intake settings and the
        # correspondence templates sent back to requesters.
        "rights_form_properties": "dsar_request_authority",
        "rights_templates": "dsar_delivery_authority",
        "discovery_containment_bindings": "containment_binding",
        "discovery_containment_actions": "containment_action",
        "provider_accounting_reviews": "provider_accounting_review",
        "pilot_learning_exclusions": "learning_exclusion",
        "identity_governance_scheduler": "identity_scheduler",
        "identity_governance_change_coupling": "identity_change_delivery",
        "identity_governance_purview_writeback": "identity_purview_writeback",
        "identity_governance_authority_registry": "identity_authority_registry",
        "red_team_schedules": "red_team_schedule",
        "red_team_campaigns": "red_team_campaign",
        "red_team_results": "red_team_result",
        "ai_discovery_sensor_identities": "sensor_identity_authority",
        "ai_evidence_packet_replays": "evidence_packet_replay_authority",
        "ai_evidence_policies": "evidence_policy_authority",
        "ai_evidence_policy_modes": "evidence_policy_mode_authority",
        "ai_operational_policies": "operational_policy_authority",
        "ai_policy_exceptions": "policy_exception_authority",
        "ai_regulatory_impacts": "regulatory_impact_authority",
        "ai_vendor_portal_invitations": "vendor_portal_identity_authority",
        "ai_vendor_portal_submissions": "vendor_portal_submission_authority",
        "candidate-promotions": "candidate_promotion_authority",
        "consent_application_scans": "consent_scan_authority",
        "consent_applications": "consent_application_authority",
        "consent_global_opt_out": "consent_opt_out_authority",
        "consent_notices": "consent_notice_authority",
        "consent_registry": "consent_receipt_authority",
        "finance_control_cycles": "finance_control_execution_authority",
        "finance_control_reconcile_state": "finance_delivery_authority",
        "identity_governance_ai_asset_bindings": "identity_asset_binding_authority",
        "identity_governance_conditional_access_decisions": (
            "conditional_access_authority"
        ),
        "knowledge-correction-sources": "knowledge_correction_authority",
        "knowledge-rights-archive": "knowledge_access_authority",
        "knowledge-rights-requests": "knowledge_access_authority",
        "llm_gateway": "llm_caller_authority",
        "model_risk_decisions": "model_risk_decision_authority",
        "model_risk_deployments": "model_deployment_authority",
        "outcome_pilot_admission_index": "outcome_pilot_admission_authority",
        "outcome_pilots": "outcome_pilot_execution_authority",
        "policy_pack_attestations": "policy_pack_trust_authority",
        "policy_pack_catalog": "policy_pack_catalog_authority",
        "policy_pack_channels": "policy_pack_channel_authority",
        "policy_pack_subscriptions": "policy_pack_subscription_authority",
        "project_review_packets": "project_review_authority",
        "project_review_teams": "project_review_identity_authority",
        "research-jobs": "research_job_authority",
        "research-registry": "research_component_authority",
        "research-runs": "research_run_authority",
        "vendor_onboarding_setup": "vendor_setup_authority",
        "vendor_renewal_activation": "vendor_renewal_activation_authority",
        "vendor_renewal_candidates": "vendor_renewal_candidate_authority",
    }
    for namespace, policy in namespace_policies.items():
        if namespace in parts[:-1]:
            return policy
    for part in parts[:-1]:
        matched = _PERSONAL_PUSH_NAMESPACE.fullmatch(part)
        if matched:
            return PERSONAL_PUSH_AUTHORITY_POLICIES[matched.group(1)]

    if is_sqlite:
        if name == "provider_spend.sqlite3":
            return "provider_spend_sqlite"
        normalized = "/".join(parts)
        sqlite_policies = {
            "jobs.db": "jobs",
            "world.db": "world",
            "knowledge.db": "passive_sqlite",
            "provider_spend.sqlite3": "provider_spend_sqlite",
            "entity_graph/graph.db": "passive_sqlite",
            "privacy_automation/privacy-data-discovery.sqlite3": "privacy_discovery",
            "privacy_automation/privacy-discovery-remediation.sqlite3": "privacy_remediation",
            "privacy_automation/privacy-discovery-data-map.sqlite3": "privacy_data_map",
        }
        return sqlite_policies.get(normalized, "unknown_sqlite")
    return None


def protected_authority(relative: str, *, is_sqlite: bool) -> bool:
    """Whether backup comparison must treat this path as authority."""
    return authority_policy(relative, is_sqlite=is_sqlite) is not None


# These stores cannot be authenticated from the reviewed retained workspace
# key set.  Bootstrap therefore removes them before publication and binds the
# exact source hash plus the resulting absence into its signed reconciliation
# inventory.  The application creates fresh local custody on first use.
DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES = {
    "vault/key": "browser_vault_credential_authority",
    "vault/browser.json": "browser_vault_credential_authority",
    "vault/authorities/authority-a/key": "browser_vault_credential_authority",
    "vault/authorities/authority-a/browser.json": (
        "browser_vault_credential_authority"
    ),
    "keys/anon.salt": "privacy_identity_key_authority",
    "factory_outcomes.ndjson": "factory_learning_input_authority",
    "trajectories.ndjson": "trajectory_learning_input_authority",
    "flows/evolution.ndjson": "flow_learning_input_authority",
    "flows/node-outcomes.ndjson": "flow_learning_input_authority",
    "flows/node-tools.ndjson": "flow_learning_input_authority",
    "compaction_stream.json": "compaction_prompt_state_authority",
    "compaction_ledger.json": "compaction_selection_authority",
    "tool_outcomes.json": "tool_outcome_learning_authority",
}


# These stores carry replay, revocation, identity, trust, scheduler, delivery,
# or executable-instruction state.  Copies without a supported and authenticated
# store-specific reconciliation must remain visible global-start blockers.
# Malformed channel records also block globally; valid records instead enter
# the channel reconciliation protocol while retaining their exact receipts.
GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES = {
    ".tenant-namespaces/aa/" + "a" * 64 + ".json": "tenant_namespace_reservation",
    ".tenant-deletions/" + "b" * 64 + ".json": "tenant_deletion_tombstone",
    "notification-deliveries.json": "notification_dispatch_authority",
    "generated_tools/example.ownership.json": "generated_tool_authority",
    "custom/example.ownership.json": "generated_content_owner_authority",
    **{f"{namespace}/record.enc": policy
       for namespace, policy in CUSTOMER_FILE_AUTHORITY_POLICIES.items()},
    "a2a/tasks.authority.sealed": "a2a_shared_authority_binding",
    "tenants/tenant-a/a2a/tasks.authority.sealed": "a2a_shared_authority_binding",
    "config.toml": "tenant_configuration_authority",
    "runtime-overrides.toml": "runtime_override_authority",
    "roles.toml": "role_instruction_authority",
    "tenants/tenant-a/config.toml": "tenant_configuration_authority",
    "tenants/tenant-a/runtime-overrides.toml": "runtime_override_authority",
    "tenants/tenant-a/roles.toml": "role_instruction_authority",
    "dashboard-config.toml": "dashboard_configuration_authority",
    "dashboard-event-triggers.toml": "event_trigger_scheduler_authority",
    "dashboard-triggers.toml": "webhook_trigger_authority",
    "billing/stripe-collections/period.json": "stripe_collection_authority",
    "usage/provider_holds.json": "organization_provider_holds",
    "usage/provider_holds.required": "organization_provider_holds_required",
    "usage/provider_history.sqlite3": "organization_provider_history",
    "usage/provider_history.required": "organization_provider_history_required",
    "tenants/tenant-a/billing/stripe-collections/period.json": "stripe_collection_authority",
    "tenants/tenant-a/usage/provider_holds.json": "organization_provider_holds",
    "tenants/tenant-a/usage/provider_holds.required": "organization_provider_holds_required",
    "tenants/tenant-a/usage/provider_history.sqlite3": "organization_provider_history",
    "tenants/tenant-a/usage/provider_history.required": "organization_provider_history_required",
    "model_improvement/training_receipts.ndjson": "training_approval_authority",
    "keys/consent-experiments.key": "consent_experiment_key_authority",
    "generated_tools/recovered.py": "generated_tool_authority",
    "learned-skills/recovered/SKILL.md": "learned_skill_authority",
    "skills/recovered/SKILL.md": "skill_instruction_authority",
    "capability_revocations.json": "capability_revocations",
    "external-replay.json": "external_replay",
    "browser/state.json": "browser_session",
    "keys/plugin_ca/revocations.json": "plugin_ca_revocations",
    "unified-audit/custody-state.json": "unified_audit_delivery_state",
    "governance_agents/reference-custody-keyring.json": "governance_reference_keyring",
    "governance_inventory/integrity.key": "governance_inventory_key",
    "tech_risk_compliance/grc-studio/integrity.key": "grc_studio_integrity_key",
    "harness/addenda.json": "harness_instruction_authority",
    "harness-refine/proposals.json": "harness_refinement_authority",
    "harness-refine/refinements.json": "harness_refinement_authority",
    "saml-consumed-assertions.json": "saml_replay",
    "session-revocations.json": "session_revocation",
    "oidc-subjects.json": "oidc_subject_directory",
    "oidc-retired-subjects.json": "oidc_subject_tombstone",
    "channel-oidc-bridge.json": "channel_oidc_identity_link_authority",
    "dashboard-users.json": "dashboard_user_roles",
    "dashboard-users.json.present": "dashboard_user_roles",
    "dashboard-tenant-roles.json.present": "dashboard_tenant_roles",
    "dashboard-custom-roles.json": "dashboard_custom_roles",
    "dashboard-tenant-roles.json": "dashboard_tenant_roles",
    "dashboard-invites.json": "dashboard_invites",
    "dashboard-user-suites.json": "dashboard_suite_grants",
    "dashboard-session.key": "dashboard_session_secret",
    "dashboard-passphrases.json": "dashboard_local_passphrases",
    "dashboard-passphrase-resets.json": "dashboard_passphrase_resets",
    "notification-links/signing.key": "notification_link_signing_key",
    "privacy_automation/discovery-data-use-key.sealed": "privacy_discovery_data_use_key",
    "scim_users.json": "scim_user_directory",
    "scim_groups.json": "scim_group_directory",
    "scim_groups.audit-outbox.json": "scim_audit_delivery",
    "privacy_automation/privacy-discovery-remediation-scheduler.json": (
        "privacy_remediation_scheduler"
    ),
    "privacy_automation/privacy-notice-publication-scheduler.json": (
        "privacy_notice_scheduler"
    ),
    "tenants/tenant-a/model_improvement/trusted_evidence_registry.json": (
        "trusted_evidence_registry"
    ),
    "plugins.lock.json": "plugin_lock",
    "config_proposals.json": "config_proposal",
    "control_plane_timeboxes.json": "control_plane_timebox",
    "voice_profiles.json": "voice_identity_profile",
    "shield_rules.json": "shield_rule_authority",
    "calibration_verdict.json": "calibration_authority",
    "self_harness_calibration_receipt.json": "self_harness_calibration_authority",
    "calibration_checker_receipt.json": "self_harness_calibration_authority",
    "budget_tuning.json": "learned_budget_authority",
    "router_bandit.json": "provider_routing_authority",
    "planning_stats.json": "planning_budget_authority",
    "guardrails.json": "learned_guardrail_authority",
    "calibration.ndjson": "calibration_evidence_authority",
    "consequence_cards.ndjson": "earned_autonomy_evidence",
    "consequences.ndjson": "earned_autonomy_outcomes",
    "outcome_links.ndjson": "earned_autonomy_outcome_links",
    "earned_autonomy.ndjson": "earned_autonomy_ledger",
    "self_improvement.json": "self_improvement_authority",
    "self_improvement.json.journal": "self_improvement_authority",
    "supply_chain_pins.json": "supply_chain_trust_authority",
    "dashboard-ui-visibility.json": "dashboard_visibility_authority",
    "dashboard-workspace-tenants.json": "dashboard_workspace_authority",
    "computer_calibration.json": "computer_action_calibration_authority",
    "procedural_memory.json": "procedural_instruction_authority",
    "role_stats.json": "role_routing_authority",
    "skill_stats.json": "skill_ranking_authority",
    "skill_embeddings.json": "skill_retrieval_authority",
    "compaction_hybrid.json": "compaction_strategy_authority",
    "compaction_hybrid_weights.json": "compaction_strategy_authority",
    "codebook.json": "coordination_codec_authority",
    "token_codebook.json": "coordination_codec_authority",
    "tool_cache_snapshot.jsonl": "external_read_cache_authority",
    "release_canary.json": "release_gate_authority",
    "reflexions.ndjson": "reflexion_instruction_authority",
    "factory_corrections.ndjson": "factory_prompt_authority",
    "jit_experience.ndjson": "jit_selection_authority",
    "learning_cache.json": "learned_result_authority",
    "dreams/insights.ndjson": "dream_instruction_authority",
    "dreams/rehearsals.ndjson": "dream_instruction_authority",
    "dreams/user_notes.ndjson": "dream_instruction_authority",
    "fleet-memory/agents.ndjson": "fleet_agent_identity_authority",
    "fleet-memory/inbox/entry.json": "external_learning_input_authority",
    "event-input/incoming/event.json": "event_input_authority",
    "assessments/templates.json": "assessment_instruction_authority",
    "assessments/register.json": "assessment_review_authority",
    "custom_templates/recovered.json": "assessment_template_authority",
    "task_graphs/recovered.json": "task_graph_authority",
    "templates/recovered.md": "goal_template_authority",
    "forms/recovered.ndjson": "form_event_authority",
    "form-recovery/example.ndjson": "form_decision_authority",
    "form-recovery/example.ndjson.accepted": "form_decision_authority",
    "repl/recovered/session.json": "repl_execution_authority",
    "adapters/active.json": "adapter_runtime_authority",
    "adapters/payloads/adapter-a/weights.gguf": "adapter_runtime_authority",
    "privacy/clause_playbook.json": "clause_policy_authority",
    "ai_evidence_gateway/interaction_receipts.ndjson": (
        "evidence_delivery_receipt_authority"
    ),
    "ai_evidence_gateway/interaction_receipts/seg-1.ndjson": (
        "evidence_delivery_receipt_authority"
    ),
    "ai_evidence_gateway/interaction_receipts.index-state.json": (
        "evidence_delivery_receipt_authority"
    ),
    "ai_evidence_gateway/assurance_packets/seg-1.ndjson": (
        "evidence_trust_authority"
    ),
    "ai_evidence_gateway/assurance_packets.ndjson": "evidence_trust_authority",
    "ai_evidence_gateway/assurance_packets.index-state.json": (
        "evidence_trust_authority"
    ),
    "registers/licenses.json": "regulatory_license_authority",
    "content_provenance/manifest_attestations.ndjson": (
        "content_provenance_authority"
    ),
    "model_risk_assurance/pack_attestations.ndjson": (
        "model_risk_pack_trust_authority"
    ),
    "redteam_results.json": "red_team_certification_authority",
    "reliability_cert.json": "reliability_certification_authority",
    "ai_evidence_conversations/AIC-a.json": "evidence_delivery_state_authority",
    "ai_evidence_receipts/AIR-a.json": "evidence_delivery_receipt_authority",
    "ai_evidence_policy_snapshots/AIS-a.json": "evidence_policy_snapshot_authority",
    "evidence_graph/EGN-a.json": "evidence_trust_authority",
    "incident_attachment_metadata/IAT-a.json": "incident_attachment_authority",
    "model_risk_observations/MRO-a.json": "model_risk_asset_authority",
    "model_risk_declarations/MRD-a.json": "model_risk_declaration_authority",
    "model_risk_evidence/MRE-a.json": "model_risk_evidence_authority",
    "model_risk_incidents/MRI-a.json": "model_risk_incident_authority",
    "model_drift_baselines/MDB-a.json": "model_drift_baseline_authority",
    "ai_literacy_requirements/ALR-a.json": "literacy_requirement_authority",
    "ai_literacy_assignments/ALA-a.json": "literacy_assignment_authority",
    "ai_literacy_completions/ALC-a.json": "literacy_completion_authority",
    "ai_literacy_waivers/ALW-a.json": "literacy_waiver_authority",
    "ai_literacy_role_requirements/ALR-role.json": (
        "literacy_role_requirement_authority"
    ),
    "ai_literacy_role_assignments/ALA-role.json": (
        "literacy_role_assignment_authority"
    ),
    "ai_literacy_role_completions/ALC-role.json": (
        "literacy_role_completion_authority"
    ),
    "outcome_accounting/OAC-a.json": "outcome_accounting_authority",
    "finance_screening_lists/FSL-a.json": "finance_screening_list_authority",
    "finance_screening_list_metadata/FLM-a.json": (
        "finance_screening_metadata_authority"
    ),
    "dsar_fulfillment/DSF-a.json": "dsar_delivery_authority",
    "rights_form_properties/RFP-a.json": "dsar_request_authority",
    "rights_templates/RTPL-a.json": "dsar_delivery_authority",
    "ai_discovery_sensor_identities/SEN-a.json": "sensor_identity_authority",
    "ai_evidence_packet_replays/AIP-a.json": "evidence_packet_replay_authority",
    "ai_evidence_policies/AIP-a.json": "evidence_policy_authority",
    "ai_evidence_policy_modes/AIM-a.json": "evidence_policy_mode_authority",
    "ai_operational_policies/AOP-a.json": "operational_policy_authority",
    "ai_policy_exceptions/AOE-a.json": "policy_exception_authority",
    "ai_regulatory_impacts/AIR-a.json": "regulatory_impact_authority",
    "ai_vendor_portal_invitations/AVI-a.json": "vendor_portal_identity_authority",
    "ai_vendor_portal_submissions/AVS-a.json": "vendor_portal_submission_authority",
    "candidate-promotions/CPR-a.json": "candidate_promotion_authority",
    "consent_application_scans/CAS-a.json": "consent_scan_authority",
    "consent_applications/CAP-a.json": "consent_application_authority",
    "consent_global_opt_out/CGO-a.json": "consent_opt_out_authority",
    "consent_notices/CCN-a.json": "consent_notice_authority",
    "consent_registry/CCR-a.json": "consent_receipt_authority",
    "finance_control_cycles/FCC-a.json": "finance_control_execution_authority",
    "finance_control_reconcile_state/FCR-a.json": "finance_delivery_authority",
    "identity_governance_ai_asset_bindings/IGA-a.json": (
        "identity_asset_binding_authority"
    ),
    "identity_governance_conditional_access_decisions/IGC-a.json": (
        "conditional_access_authority"
    ),
    "knowledge-correction-sources/KCS-a.json": "knowledge_correction_authority",
    "knowledge-rights-archive/KRA-a.json": "knowledge_access_authority",
    "knowledge-rights-requests/KRR-a.json": "knowledge_access_authority",
    "llm_gateway/LGC-a.json": "llm_caller_authority",
    "model_risk_decisions/MRD-a.json": "model_risk_decision_authority",
    "model_risk_deployments/MRP-a.json": "model_deployment_authority",
    "outcome_pilot_admission_index/OPA-a.json": "outcome_pilot_admission_authority",
    "outcome_pilots/OPL-a.json": "outcome_pilot_execution_authority",
    "policy_pack_attestations/PPA-a.json": "policy_pack_trust_authority",
    "policy_pack_catalog/PPC-a.json": "policy_pack_catalog_authority",
    "policy_pack_channels/PPH-a.json": "policy_pack_channel_authority",
    "policy_pack_subscriptions/PPS-a.json": "policy_pack_subscription_authority",
    "project_review_packets/PRP-a.json": "project_review_authority",
    "project_review_teams/PRT-a.json": "project_review_identity_authority",
    "research-jobs/RSJ-a.json": "research_job_authority",
    "research-registry/RSC-a.json": "research_component_authority",
    "research-runs/RSR-a.json": "research_run_authority",
    "vendor_onboarding_setup/VOS-a.json": "vendor_setup_authority",
    "vendor_renewal_activation/VEA-a.json": "vendor_renewal_activation_authority",
    "vendor_renewal_candidates/VEC-a.json": "vendor_renewal_candidate_authority",
    **{
        f"{namespace}/recovered.json": policy
        for namespace, policy in GLOBAL_START_JSON_AUTHORITY_POLICIES.items()
    },
    **{
        f"{namespace}/recovered.json": policy
        for namespace, policy in DYNAMIC_JSON_AUTHORITY_POLICIES.items()
        if policy != "identity_change_request"
    },
    **{
        f"{kind}-{'c' * 32}/recovered.json": policy
        for kind, policy in PERSONAL_PUSH_AUTHORITY_POLICIES.items()
    },
}


# Representative paths form a reviewable completeness contract.  The runtime
# classifier remains the source of truth; tests assert every sample maps to the
# declared policy and that no protected sample is silently unclassified.
AUTHORITY_SAMPLES = {
    "jobs.db": "jobs",
    "world.db": "world",
    "connections/connections.sealed": "credential",
    "connections/oauth-setup.sealed": "credential",
    "oauth/tokens.sealed": "credential",
    "partner/tenants.sealed": "credential",
    "privacy_automation/evidence-keys.sealed": "credential",
    "partner/tenants.json": "plaintext_credential_residue",
    "partner/tenants.json.migrated-plaintext": "plaintext_credential_residue",
    "flows/runs/run.json": "flow_run",
    "flows/published/flow.json": "flow_publication",
    "flows/idempotency/claim.json": "flow_idempotency",
    "external_agents.json": "external_agents",
    "agent_trust.json": "agent_trust",
    "capability_revocations.json": "capability_revocations",
    "external-replay.json": "external_replay",
    "consent.ledger": "consent_authority",
    "consent.ledger.key": "consent_authority_key",
    "handoff_nonces.json": "handoff_nonce",
    "identity_governance_scheduler/IGS-a.json": "identity_scheduler",
    "identity_governance_change_coupling/IGCC-a.json": "identity_change_delivery",
    "identity_governance_purview_writeback/IGPW-a.json": "identity_purview_writeback",
    "identity_governance_authority_registry/IGAR-a.json": "identity_authority_registry",
    "identity_governance_dynamic_risk_requests/IGRQ-a.json": "identity_change_request",
    "red_team_schedules/RTS-a.json": "red_team_schedule",
    "red_team_campaigns/RTC-a.json": "red_team_campaign",
    "red_team_results/RTR-a.json": "red_team_result",
    "channel_federation_outbox.json": "federation_outbox",
    "federation/channel_replay.json": "federation_replay",
    "federation/channel_rate.json": "federation_rate",
    "llm_gateway_team_budget/team_budget.json": "llm_team_budget",
    "mcp_sidecar/call_budget.json": "mcp_call_budget",
    "pilot_learning_exclusions/PLE-a.json": "learning_exclusion",
    "pilot_learning_exclusions/PLE-a.required": "learning_exclusion",
    "budget_receipts.jsonl": "budget_receipt",
    "provider_spend.json": "provider_spend",
    "provider_spend.json.required": "provider_spend_required",
    "provider_spend.json.tenant-fold": "provider_spend_required",
    "provider_spend.sqlite3": "provider_spend_sqlite",
    "provider_spend.sqlite3.active": "provider_spend_required",
    "provider_spend.sqlite3.seal": "provider_spend_required",
    "tenant_registry.json": "tenant_registry",
    "dashboard-owner.json": "dashboard_owner",
    "privacy_automation/privacy-data-discovery.sqlite3": "privacy_discovery",
    "privacy_automation/privacy-discovery-remediation.sqlite3": "privacy_remediation",
    "privacy_automation/privacy-discovery-data-map.sqlite3": "privacy_data_map",
    "keys/dek.wrapped": "wrapped_tenant_dek",
    **{
        f"{namespace}/recovered.json": policy
        for namespace, policy in APPLICATION_VALIDATED_JSON_AUTHORITY_POLICIES.items()
    },
    **DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES,
    **GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES,
}


__all__ = [
    "TENANT_LIFECYCLE_AUTHORITY_POLICIES",
    "APPLICATION_VALIDATED_JSON_AUTHORITY_POLICIES",
    "CUSTOMER_FILE_AUTHORITY_POLICIES",
    "NON_AUTHORIZING_GOVERNED_NAMESPACES",
    "AUTHORITY_SAMPLES",
    "DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES",
    "DYNAMIC_JSON_AUTHORITY_POLICIES",
    "PERSONAL_PUSH_AUTHORITY_POLICIES",
    "GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES",
    "GLOBAL_START_JSON_AUTHORITY_POLICIES",
    "authority_policy",
    "protected_authority",
]
