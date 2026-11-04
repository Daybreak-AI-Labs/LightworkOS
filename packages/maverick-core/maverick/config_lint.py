"""Config validator for ``~/.maverick/config.toml`` (Lightwork 2.0 RFC item).

Walks an already-loaded config dict (see :func:`maverick.config.load_config`)
and reports likely mistakes: a mistyped section name, an unknown key inside a
section whose key set is fixed, and a small, safe set of obvious type errors
(``budget.max_dollars`` must be a number; ``*.enabled`` must be a bool).

Design constraints:
- Pure stdlib (``difflib`` for "did you mean" suggestions), deterministic.
- Conservative: only flag things we're confident about. Dynamic sections —
  ``[providers.<name>]``, ``[channels.<name>]``, ``[models]``,
  ``[mcp_servers.<name>]``, ``[roles.<role>]`` and similar — accept any
  subkeys, so we never flag their keys.
- Never raises on a weird dict. A non-dict section value, a non-string key,
  ``None`` — all tolerated; we simply skip what we can't reason about.

This is advisory only. The kernel itself fails soft on a bad config (see
``maverick.config.load_config``); this lets the wizard / a ``maverick config
lint`` command surface problems up front.
"""

from __future__ import annotations

import difflib
import math
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from .config_contracts import INTEGER_SETTINGS

# Known top-level sections -> allowed keys, or ``None`` to allow ANY key.
#
# ``None`` is used for two kinds of section:
#   * genuinely dynamic tables whose subkeys are user-chosen names
#     (``models`` role->spec, ``providers.<name>``, ``channels.<name>``,
#     ``mcp_servers.<name>``, ``roles.<role>``), and
#   * sections whose key set is still evolving / spread across modules, where
#     enumerating keys would produce false-positive warnings on valid configs.
#
# Only sections with a small, stable, documented key set get an explicit set;
# those are the ones where an unknown key is a useful signal.
KNOWN_SCHEMA: dict[str, set[str] | None] = {
    "instruction_capture": {"enable"},
    "approval_challenges": {"enable"},
    "image_edit": {"inpaint_model", "variation_model", "upscale_model"},
    # --- fixed-key sections (unknown keys are flagged) ---
    "deployment": {"type", "allow_multiple_control_planes"},
    "personalization": {"locked_fields", "defaults"},
    "copilot": {"operation_families"},
    "settings": {"runtime_status"},
    "mobile_offline": {"enabled", "max_age_seconds", "max_bytes"},
    "workflows": {"versioning", "typed_inputs"},
    "intent_value": {"enabled", "recommendations", "completion_confirmation"},
    "_dashboard_resets": None,  # Internal global-overlay reset metadata; removed before runtime config.
    "budget": {
        "task_limits_enabled",
        "guidance",
        "warnings",
        "warning_thresholds",
        "strict_pricing",
        "max_dollars",
        "max_wall_seconds",
        "max_tool_calls",
        "max_input_tokens",
        "max_output_tokens",
        # Default-on per-task-class self-tuning of max_dollars (self_tuning_budget.py
        # reads [budget] self_tuning). Listed so the documented knob does not
        # lint as an unknown key.
        "self_tuning",
        # Signed per-task spending receipts (budget_receipts.py).
        "receipts",
        # Deployment-wide spend ceilings per AI service (provider_cost_cap.py).
        "provider_caps",
        "provider_caps_period",
    },
    "safety": {
        "profile",
        "block_threshold",
        "scan_input",
        "scan_tool_calls",
        "scan_output",
        "constitution",
        "compartments",
        "compartment_unseal",
        # Periodic human review of long tasks (review_checkpoint.py).
        "review_checkpoint",
        # Read at runtime and set from the dashboard's All settings page:
        # consent gating (safety/consent.py), the shield requirement
        # (shield_policy.py) and the receipt/screenshot signing keys.
        "consent_mode",
        "require_shield",
        "receipt_key",
        "screenshot_key",
        # Shield limits and the start-up software check (All settings).
        "max_scan_chars",
        "decode_hidden",
        "supply_chain_pinning",
        # Second-opinion scan, scan limit per task, and approvals for
        # protected settings (All settings).
        "cascade",
        "shield_rate_limit",
        "quorum_required",
        "quorum_protected_keys",
        "quorum_ttl_days",
        # Goal-risk check before a task starts (safety/goal_risk.py).
        "goal_risk_floor",
        "goal_risk_require_human",
    },
    "sandbox": {
        "backend",
        "workdir",
        "timeout",
        "image",
        "language",
        "require_container",
        "allow_network",
        "allow_root",
        "pids_limit",
        "memory",
        "memory_mb",
        "cpus",
        "runtime",
        "options",
        "reuse_container",
        "cross_run_pool",
        "project_dir",
        "namespace",
        "context",
        "extra_kubectl_args",
        "run_as_user",
        "provider",
        "api_key",
        "network",
        "warm",
        "host",
        "ssh_args",
        "host_key_checking",
        # Per-tool address rules (sandbox/network_policy.py) and the cluster
        # settings file (sandbox/__init__.py), both on the All settings page.
        "tool",
        # The work area's no-network rule (sandbox/network_policy.py).
        "network_policy",
        "kubeconfig",
        "long_command_timeout",
        "firecracker_strict",
    },
    # Per-tool rate limits (safety/rate_limiter.py): keys are tool names
    # ("web_search", "mcp_*", ...), values "N/window" specs -- user-chosen
    # names, so any key is allowed. The wizard writes this section by default;
    # without it here every wizard-written config warned "unknown section".
    "rate_limits": None,
    # Every switch config.get_features() reads (the All settings page writes
    # them); test_config_lint keeps the two in step.
    "features": {
        "action_center", "applicability_regions", "commitment_capability_learning",
        "commitment_economic_alternatives", "commitment_viability", "configuration_profiles",
        "copilot_operations", "deliverable_bundles", "draft_recovery", "employee_activation",
        "employee_companions", "employee_content_access_requests", "employee_departures",
        "employee_task_diagnostics", "governed_rule_evolution", "guided_onboarding",
        "human_conversation_handoffs", "operational_competence_acquisition", "outcome_measurement",
        "pack_editing", "permission_access_requests", "personal_data_controls",
        "personal_preferences", "portable_competence", "private_task_computation",
        "procedure_interactions", "project_reviews", "project_workspaces", "record_search",
        "recovery_visibility", "request_program", "role_editing", "scheduling",
        "semantic_rule_reuse", "shared_decision_evidence", "signing_identity_transition",
        "skills", "streaming", "support_center", "task_handoffs", "triggers",
        "work_restructuring", "workflow_readiness", "workflow_step_checks",
        "workspace_recovery", "world_model",
    },
    "capabilities": {
        "computer_use",
        "browser",
        "web_search",
        "mobile_tools",
        "code_exec",
        # Governance knobs the runtime reads (capability.py / agent.py) that
        # were missing here -- so a client configuring the flagship
        # capability-enforcement feature, or the deferred-tools knob, got a
        # false "unknown key" warning.
        "enforce",
        "per_call_tokens",
        "deferred_tools",
        # The wizard's robotics opt-in; read back by agent.py (enable_ros) and
        # config.py. Missing here, every wizard-written config that answered
        # the ROS question warned "unknown key" on its own output.
        "ros",
        # How long one per-call tool pass stays valid (tool_token.py).
        "per_call_token_ttl",
    },
    # Tamper-evident audit log. The runtime reads [audit] sign (audit/writer.py)
    # and migrate.py already lists it; config-lint flagged the whole section as
    # unknown ("did you mean auth?"), telling a regulated client their flagship
    # signed-audit config looked like a typo.
    "audit": {"sign", "worm", "unified",
              # Off-host key and SIEM forwarding (audit/writer.py, audit_siem.py).
              "require_offhost_key", "siem_dest", "siem_token", "siem_allow_insecure",
              # Vendor SIEM credential fallbacks (audit/forwarder.py); the env vars
              # MAVERICK_DATADOG_API_KEY and MAVERICK_SENTINEL_* are the preferred home.
              "datadog_api_key", "sentinel_tenant_id", "sentinel_client_id",
              "sentinel_client_secret"},
    "entity_graph": {"enable", "staleness_seconds"},
    # Commerce suite caps are money/quantity limits, so the schema is closed: a
    # misspelled cap must not silently fall back to the default.
    "commerce": {
        "enable",
        "backend",
        "max_session_spend",
        "max_line_quantity",
        "max_cart_lines",
        "stripe_refunds",
    },
    "governance_inventory": {
        "enable",
        "retention_seconds",
        "max_source_records",
        "max_entities",
        "max_relationships",
        "max_export_bytes",
        "max_snapshots",
    },
    "durable": {"enabled", "keep_last"},
    # The publisher keys whose signed update bundles release_update accepts
    # (maverick.release_manifest_signing).
    "release": {"publisher_pubkeys"},
    # user_name: the operator's name the wizard collects for greetings and
    # writes under [persona] -- lint must never warn on the wizard's own output.
    "persona": {"name", "style", "addendum", "user_name"},
    # Polled event triggers ("when X appears, run this workflow"), the wizard's
    # opt-in read back by automation_events.py. Absent here, a wizard-written
    # config warned "unknown section" on a section the product itself wrote.
    "event_triggers": {"enable"},
    # The dashboard reads more than the auth token: theme/density/allow_extension
    # (app.py) and a [dashboard.themes] subtable (themes.py). Listing only
    # "token" would make config-lint warn "unknown key" on documented operator
    # settings like `[dashboard] theme = "dark"`.
    # public_url: the externally-reachable base URL used to build signed flow
    # approval links (automation_queue._public_base_url); without it here a client
    # configuring actionable channel approvals got a false "unknown key".
    # default_suites: deny-by-default department scoping for authenticated
    # dashboard users with no explicit grant (maverick.suite_grants).
    # group_roles / group_suites: SCIM-group -> role / department mapping
    # tables (maverick_dashboard.scim_groups), so access flows from IdP team
    # membership.
    "dashboard": {
        "token",
        "theme",
        "density",
        "glass",
        "navigation",
        "navigation_personal",
        "allow_extension",
        "compress",
        "themes",
        "public_url",
        "default_suites",
        "group_roles",
        "group_suites",
        "active_tenant",
        # Sign-in, invitations, API keys and request limits (auth.py, app.py)
        # and the switches the wizard and All settings page write.
        "require_auth", "admins", "default_role", "session_secret", "scim_token",
        "invites", "invite_email", "invite_session_days",
        "api_keys", "api_key_default_days", "api_key_max_days", "api_key_rotation_grace_hours",
        "api_key_prefix", "max_request_mb", "max_goals_per_min", "max_goals_global_per_min",
        "max_sse", "shutdown_timeout_seconds", "local_owner_setup", "extension_form_values",
        "extension_page_structure", "employee_activation_jobs",
    },
    "analytics": {"mcp_client_language", "task_questions", "usability_survey", "usage_measures",
                  "web_vitals", "web_vitals_sample_rate"},
    # Agent Factory: JD hiring (maverick.jd_hiring) and the publish gate
    # (maverick.agent_publish_policy).
    "agent_factory": {"jd_hiring", "require_passing_tests"},
    # Saved answer checks (maverick.agent_tests_policy).
    "agent_tests": {"max_cases_per_specialist", "require_for_new_specialists",
                    "bypass_requires_second_person", "tool_checks", "canary_percent", "canary_auto_rollback"},
    "practice": {"enable", "daily_spend_cap"},
    "collaboration": {"comments", "suggestions", "ai_suggestions"},
    "first_outcome": {"department", "sample_workspace_created"},
    # Work discovery is a high-trust client-controlled sensor.  Keep this
    # section fixed-key so misspelled retention/privacy knobs do not silently
    # fall back to defaults.
    "ekko": {
        "enable",
        "planning_enabled",
        "build_enabled",
        "retention_days",
        "enrollment_days",
        "min_occurrences",
        "min_distinct_days",
        "poll_interval_seconds",
        "capture_level",
        "allowed_apps",
        "blocked_apps",
        "provider_egress",
    },
    # Specialist-model training and promotion is a high-authority mutation
    # boundary.  Keep its schema closed so misspelled receipt, boundary, or
    # sample-floor controls cannot silently fall back to defaults.
    "model_improvement": {
        "enable",
        "allow_hosted",
        "allow_cross_tenant",
        "require_signed_receipt",
        "minimum_train_families",
        "minimum_holdout_families",
    },
    # Definition import reaches third-party APIs and can materialize recurring
    # work, so both opt-ins are closed-schema booleans rather than permissive
    # string truthiness.
    "automation_import": {"enable", "create_schedules", "max_steps"},
    # Evidence release is a high-trust, fail-closed boundary: the master opt-in
    # and the receipt/packet size limits only, so misspelled enforcement keys
    # do not silently create an open-ended policy surface.
    "evidence_gateway": {"enable", "receipt_max_total", "receipt_segment_rows", "receipt_segment_bytes",
                         "packet_max_total", "packet_segment_rows", "packet_segment_bytes"},
    # AI-governance admission capabilities are explicit, default-off
    # authorities. Keep these schemas closed so a misspelled safety limit does
    # not silently fall back to a more permissive value.
    "ai_inventory": {
        "enable",
        "connectors",
        "page_cap",
        "record_cap",
        "retry_attempts",
        "timeout_seconds",
        "missing_grace_runs",
        "poll_seconds",
    },
    "ai_entity_tasks": {
        "enable",
        "max_tasks",
        "retention_seconds",
        "authority_max_age_seconds",
    },
    "ai_vendor_risk": {"enable", "portal_enable"},
    "vendor_onboarding": {
        "enable", "resource_owner", "document_connection", "ticket_connection", "reviewed_uploads",
        "safe_read_attempts", "safe_read_backoff_seconds",
    },
    "policy_packs": {"enable"},
    "portfolio_risk": {"enable"},
    "drift_monitoring": {
        "enable",
        "bins",
        "min_samples",
        "psi_threshold",
        "kl_threshold",
        "js_threshold",
        "ks_p_value_floor",
        "chi2_p_value_floor",
        "embedding_cosine_threshold",
        "performance_decay_threshold",
        "evidence_validity_seconds",
    },
    "agent_topology": {"enable"},
    "ai_regulatory_feed": {"enable"},
    "ai_incident_reporting": {"enable"},
    "ai_literacy": {"enable"},
    "eu_conformity": {"enable"},
    "explainability": {"enable"},
    "content_provenance": {"enable", "claim_generator"},
    "llm_gateway": {
        "enable",
        "upstream_url",
        "upstream_token_env",
        "gateway_token_env",
        "allowed_models",
        "max_body_bytes",
        "screen_prompts",
        "redact_prompts",
        "redact_completions",
        "anthropic_upstream_url",
        "anthropic_upstream_token_env",
        "anthropic_version",
        "team_tokens",
        "team_budgets",
        "budget_window_seconds",
        "default_max_output_tokens",
        # Sealed credentials set on the dashboard (env names above still win).
        "team_passwords",
        "gateway_token",
        "upstream_token",
        "anthropic_upstream_token",
    },
    "vendor_management": {"enable"},
    "consent_registry": {
        "enable", "subject_salt", "webhook_enable", "webhook_secret_env",
    },
    "data_map": {"enable", "graph_token_env", "graph_token"},
    "breach_notification": {"enable"},
    "ediscovery": {"enable"},
    "dsar_fulfillment": {"enable"},
    "grc_sync": {"enable", "connector", "findings_path", "acceptances_path",
                 "incidents_path", "backlink_base", "response_field_params"},
    "red_team_assurance": {
        "enable",
        "commitment_secret_ref",
        "commitment_key",
        "max_cases",
        "max_response_bytes",
        "campaign_ttl_seconds",
        "evidence_validity_seconds",
        "scheduler_poll_seconds",
    },
    "eu_ai_incidents": {"enable", "authorities"},
    "grc_outbound_sync": {
        "enable",
        "targets",
        "max_attempts_per_revision",
        "servicenow_irm",
        "archer",
    },
    "ai_business_intake": {"enable"},
    "ai_cost_roi": {
        "enable",
        "collector_poll_seconds",
        "collector_lookback_days",
        "collector_limits",
        "aws",
        "azure",
        "gcp",
        "openai",
    },
    "ai_dynamic_risk": {"enable"},
    "ai_policy_management": {"enable"},
    "ai_runtime_guardrails": {"enable"},
    "ai_governance_loop": {
        "enable",
        "poll_seconds",
        "batch_size",
        "lease_seconds",
        "max_attempts",
        "retry_base_seconds",
        "max_lag_seconds",
    },
    "ai_explainability": {"enable"},
    "ai_conformity_workflow": {"enable"},
    "ai_insurability": {"enable"},
    "ai_regulated_verticals": {"enable"},
    "ai_bank_mrm": {"enable"},
    "ai_benchmark_exchange": {"enable", "trust_roots", "coordinator"},
    "ai_discovery_sensors": {"enable"},
    "ai_media_provenance": {
        "enable",
        "verification_adapter",
        "c2patool_executable_sha256",
    },
    # Named, packaged governance capabilities remain separately gated from the
    # generic domain-agent/runtime primitives.  Closed allowlists prevent a
    # misspelled agent, media type, or cloud provider from silently becoming an
    # unreviewed extension point.
    "governance_agents": {
        "enable",
        "enabled_agents",
        "context_projection_enable",
        "context_projection_max_records_per_source",
        "context_projection_max_context_items",
        "context_projection_max_total_bytes",
        "context_projection_max_record_bytes",
        "max_context_items",
        "max_context_bytes",
        "max_output_bytes",
        "retention_seconds",
    },
    "ai_evidence_analysis": {
        "enable",
        "enabled_media_types",
        "max_artifact_bytes",
        "max_artifacts_per_case",
        "max_authority_records",
        "max_extracted_text_bytes",
        "retention_seconds",
        "parser_sandbox",
        "ocr",
        "legacy_xls",
    },
    "assessment_evidence_autopopulation": {
        "enable",
        "apply_enabled",
        "retention_seconds",
        "max_records",
        "max_evidence_records_per_proposal",
        "max_citations_per_answer",
        "min_confidence_bps",
    },
    "ai_identity_governance_connectors": {
        "enable",
        "entra",
        "okta",
        "purview",
        "scheduler",
        "controls",
    },
    "administration_document_access": {
        "enable",
        "default_ttl_seconds",
        "max_ttl_seconds",
        "max_uses",
        "delivery_grant_ttl_seconds",
        "retention_seconds",
    },
    "governed_document_vault": {
        "enable",
        "max_document_bytes",
        "max_documents",
        "retention_seconds",
        "grant_ttl_seconds",
        "claim_lease_seconds",
        "stream_chunk_bytes",
        "allowed_media_types",
    },
    "incident_attachment_metadata": {
        "enable",
        "retention_seconds",
        "attachment_ttl_seconds",
        "max_attachments",
        "allowed_media_types",
    },
    # Consumer consent and preference governance is a privacy data plane, not
    # the agent-action consent gate.  Every externally consequential subsystem
    # has its own nested opt-in; property records and destination credentials
    # remain governed runtime records rather than open-ended config keys.
    "consent_preferences": {
        "enable",
        "publishing",
        "public_api",
        "scanner",
        "standards",
        "identity",
        "delivery",
        "analytics",
        "experiments",
        "profile_data",
        "trust_center",
        "bulk_jobs",
        "global_opt_out",
        "application_scanner",
        "native_sdk",
        "storage",
        "edge_cache",
        "limits",
    },
    "data_use_governance": {
        "enable",
        "compiler",
        "enforcement",
        "provider_audit",
        "scheduler",
        "snowflake",
        "databricks",
        "limits",
    },
    "privacy_automation": {
        "enable",
        "discovery_data_use_bridge",
        "data_discovery",
        "regulatory_intelligence",
        "rights_orchestration",
        "rights_consumer_delivery",
        "rights_consumer_intake",
        "ott_ctv_rights",
        "drop_management",
        "notice_governance",
        "public_rights_form",
    },
    "tech_risk_compliance": {
        "enable",
        "continuous_evidence",
        "grc_studio",
        "policy_publication_links",
        "scoping",
        "scope_actions",
    },
    "third_party_management": {
        "enable",
        "contracts",
        "executive_reports",
        "intelligence",
        "lifecycle",
    },
    "customer_sandbox_lifecycle": {"enable", "source_revision"},
    # --- dynamic / open-ended sections (any subkey accepted) ---
    "providers": None,
    "models": None,
    "channels": None,
    "mcp_servers": None,
    "roles": None,
    "routing": None,
    "planning": None,
    "context": None,
    "reflexion": None,
    "effort": None,
    "cache": None,
    "quotas": None,
    "tenancy": None,
    "retention": None,
    "world_model": None,
    "memory": None,
    "voice": None,
    "webhooks": None,
    "a2a": None,
    "auth": None,
    "knowledge": None,
    "skills": None,
    "self_learning": None,
    "autonomy": None,
    "calibration": None,
    "credit": None,
    "adaptive_compute": None,
    "search": None,
    "skill_synthesis": None,
    "experience": None,
    "compliance": None,
    "security": None,
    "plugins": None,
    "tools": None,
}

# Keep this registry in lockstep with migrate.py's KNOWN_SECTIONS (curated
# from the real load_config() call sites) so config-lint never false-flags a
# section the runtime actually reads as a typo. The two had drifted by ~59
# sections -- a client configuring documented features like [provider_failover],
# [enterprise], [egress], [governance], [encryption] got told they were
# typos. Sections with an explicit key schema above
# keep it (setdefault won't overwrite); the rest accept any subkey (None),
# exactly as migrate treats them.
from .migrate import KNOWN_SECTIONS as _RUNTIME_SECTIONS  # noqa: E402

for _section in _RUNTIME_SECTIONS:
    KNOWN_SCHEMA.setdefault(_section, None)


@dataclass
class Finding:
    section: str
    key: str | None
    severity: str  # "error" | "warning"
    message: str


# Keys that, when present, must be a number (int/float, but not bool — in
# Python ``bool`` is an ``int`` subclass, so we exclude it explicitly).
# Section -> key.
_NUMERIC_KEYS: dict[str, set[str]] = {
    "budget": {
        "max_dollars",
        "max_wall_seconds",
        "max_tool_calls",
        "max_input_tokens",
        "max_output_tokens",
    },
    "sandbox": {"timeout", "pids_limit", "memory_mb", "cpus", "run_as_user"},
    "commerce": {"max_session_spend", "max_line_quantity", "max_cart_lines"},
    "durable": {"keep_last"},
    "analytics": {"web_vitals_sample_rate"},
    "ekko": {
        "retention_days",
        "enrollment_days",
        "min_occurrences",
        "min_distinct_days",
        "poll_interval_seconds",
    },
}

# Integer-valued controls. These are kept separate from ``_NUMERIC_KEYS``:
# accepting ``20.5`` as a number would make config lint report success while
# the runtime safely falls back to 20, obscuring an operator mistake.
_INTEGER_KEYS: dict[str, set[str]] = {
    "model_improvement": {
        "minimum_train_families",
        "minimum_holdout_families",
    },
    "knowledge_sources": {
        "max_items",
        "max_pages",
        "max_download_mib",
        "max_text_kib",
        "max_refresh_minutes",
    },
    "customer_sandbox_lifecycle": {"source_revision"},
    "agent_tests": {"max_cases_per_specialist", "canary_percent"},
    "ai_entity_tasks": {
        "max_tasks",
        "retention_seconds",
        "authority_max_age_seconds",
    },
    "governance_agents": {
        "context_projection_max_records_per_source",
        "context_projection_max_context_items",
        "context_projection_max_total_bytes",
        "context_projection_max_record_bytes",
        "max_context_items",
        "max_context_bytes",
        "max_output_bytes",
        "retention_seconds",
    },
    "ai_evidence_analysis": {
        "max_artifact_bytes",
        "max_artifacts_per_case",
        "max_authority_records",
        "max_extracted_text_bytes",
        "retention_seconds",
    },
    "assessment_evidence_autopopulation": {
        "retention_seconds",
        "max_records",
        "max_evidence_records_per_proposal",
        "max_citations_per_answer",
        "min_confidence_bps",
    },
    "administration_document_access": {
        "default_ttl_seconds",
        "max_ttl_seconds",
        "max_uses",
        "delivery_grant_ttl_seconds",
        "retention_seconds",
    },
    "governed_document_vault": {
        "max_document_bytes",
        "max_documents",
        "retention_seconds",
        "grant_ttl_seconds",
        "claim_lease_seconds",
        "stream_chunk_bytes",
    },
    "incident_attachment_metadata": {
        "retention_seconds",
        "attachment_ttl_seconds",
        "max_attachments",
    },
}

# Keys that, when present, must be a bool. Section -> key. Plus the universal
# ``enabled``/``enable`` toggle, handled separately for every known section.
_BOOL_KEYS: dict[str, set[str]] = {
    "intent_value": {"recommendations", "completion_confirmation"},
    "first_outcome": {"sample_workspace_created"},
    "safety": {"scan_input", "scan_tool_calls", "scan_output", "compartments"},
    "features": {"skills", "world_model", "streaming"},
    "capabilities": {
        "computer_use",
        "browser",
        "web_search",
        "mobile_tools",
        "code_exec",
        "enforce",
        "per_call_tokens",
        "deferred_tools",
        "ros",
    },
    "audit": {"sign"},
    "sandbox": {
        "require_container",
        "allow_network",
        "allow_root",
        "reuse_container",
        "cross_run_pool",
        "warm",
    },
    "analytics": {"mcp_client_language", "task_questions", "usability_survey", "usage_measures", "web_vitals"},
    "agent_factory": {"jd_hiring", "require_passing_tests"},
    "agent_tests": {"require_for_new_specialists", "bypass_requires_second_person", "tool_checks",
                    "canary_auto_rollback"},
    "practice": {"enable"},
    "collaboration": {"comments", "suggestions", "ai_suggestions"},
    "self_learning": {
        "preflight",
        "create_tools",
        "provision_packs",
        "allow_mcp_acquisition",
        "allow_provider_egress",
        "distill_local",
        "auto_distill",
    },
    "ekko": {"provider_egress", "planning_enabled", "build_enabled"},
    "model_improvement": {
        "enable",
        "allow_hosted",
        "allow_cross_tenant",
        "require_signed_receipt",
    },
    "automation_import": {"enable", "create_schedules"},
    "ai_vendor_risk": {"portal_enable"},
    "assessment_evidence_autopopulation": {"apply_enabled"},
    "governance_agents": {"context_projection_enable"},
    "models": {"cascade"},
    "routing": {"cost_aware"},
}

_UNIVERSAL_BOOL_KEYS = ("enabled", "enable")
_MODEL_IMPROVEMENT_FAMILY_MIN = 20
_MODEL_IMPROVEMENT_FAMILY_MAX = 1_000_000

_IDENTITY_SCHEDULE_KEYS = {
    "enable",
    "interval_seconds",
    "retry_base_seconds",
    "retry_max_seconds",
    "max_attempts_per_slot",
    "lease_seconds",
    "history_limit",
    "max_snapshot_items",
    "max_delta_digests",
}
_NESTED_GOVERNANCE_SCHEMA: dict[tuple[str, ...], set[str]] = {
    ("audit", "unified"): {
        "enable",
        "custody",
        "page_size",
        "lease_seconds",
        "max_lag_seconds",
        "max_attempts",
        "retry_backoff_seconds",
        "poll_seconds",
    },
    ("ai_benchmark_exchange", "trust_roots"): {"schema", "version", "keys"},
    ("ai_benchmark_exchange", "coordinator"): {
        "enable",
        "origin",
        "timeout_seconds",
        "max_request_bytes",
        "max_response_bytes",
    },
    ("ai_evidence_analysis", "ocr"): {
        "enable",
        "executable",
        "executable_sha256",
        "tesseract_version",
        "traineddata_path",
        "traineddata_sha256",
        "runtime_library_paths",
        "runtime_libraries_sha256",
        "pillow_version",
        "pillow_manifest_sha256",
        "timeout_seconds",
        "max_pixels",
        "max_output_bytes",
        "max_memory_bytes",
    },
    ("ai_evidence_analysis", "legacy_xls"): {
        "enable",
        "xlrd_version",
        "xlrd_manifest_sha256",
        "olefile_version",
        "olefile_manifest_sha256",
        "timeout_seconds",
        "max_workbook_stream_bytes",
        "max_record_bytes",
        "max_records",
        "max_sheets",
        "max_rows_per_sheet",
        "max_columns_per_sheet",
        "max_cells",
        "max_output_bytes",
        "max_memory_bytes",
    },
    ("ai_evidence_analysis", "parser_sandbox"): {
        "enable",
        "mode",
        "launcher",
        "launcher_sha256",
        "launcher_version",
    },
    ("ai_identity_governance_connectors", "scheduler"): {
        "enable",
        "poll_seconds",
        "providers",
    },
    ("ai_identity_governance_connectors", "scheduler", "providers"): {
        "entra",
        "okta",
        "purview",
    },
    ("ai_identity_governance_connectors", "controls"): {
        "enable",
        "change_coupling",
        "federation",
        "conditional_access",
        "purview_writeback",
        "production",
    },
    ("ai_identity_governance_connectors", "controls", "change_coupling"): {
        "enable",
        "dynamic_risk",
        "alerts",
    },
    ("ai_identity_governance_connectors", "controls", "federation"): {"enable"},
    ("ai_identity_governance_connectors", "controls", "conditional_access"): {"enable"},
    ("ai_identity_governance_connectors", "controls", "purview_writeback"): {"enable"},
    ("ai_identity_governance_connectors", "controls", "production"): {
        "enable",
        "mapping_revision",
        "mapping_retention_seconds",
        "max_authority_records",
        "max_observation_age_seconds",
        "max_future_skew_seconds",
        "outcome_max_attempts",
        "outcome_retry_base_seconds",
        "outcome_retry_max_seconds",
        "outcome_lease_seconds",
        "outcome_signal_validity_seconds",
        "purview_max_attempts",
        "purview_operation_lease_seconds",
    },
    ("consent_preferences", "publishing"): {
        "enable",
        "require_signed_publications",
        "web_settings",
    },
    ("consent_preferences", "publishing", "web_settings"): {
        "enable",
        "retention_seconds",
        "max_history",
    },
    ("consent_preferences", "public_api"): {
        "enable",
        "token_ttl_seconds",
        "max_request_bytes",
        "max_response_bytes",
        "requests_per_minute",
    },
    ("consent_preferences", "scanner"): {
        "enable",
        "scheduler",
        "notice_proposals",
        "interval_seconds",
        "max_pages",
        "max_depth",
        "page_timeout_seconds",
        "max_network_events",
        "allow_authenticated_scans",
    },
    ("consent_preferences", "scanner", "scheduler"): {
        "enable",
        "poll_seconds",
        "enqueue_limit",
        "claim_limit",
        "tenant_limit",
    },
    ("consent_preferences", "scanner", "notice_proposals"): {
        "enable",
    },
    ("consent_preferences", "standards"): {
        "gpc",
        "dnt",
        "gpp",
        "tcf",
        "google_consent_mode",
    },
    ("consent_preferences", "identity"): {
        "enable",
        "issuer",
        "audience",
        "jwks_origin",
        "token_ttl_seconds",
        "link_lifecycle_retention_seconds",
    },
    ("consent_preferences", "delivery"): {
        "enable",
        "max_attempts",
        "retry_base_seconds",
        "retry_max_seconds",
        "destinations",
        "worker",
    },
    # Automatic delivery for separately reviewed subscriptions; read by the
    # dashboard (consent_delivery_managed_api.worker_enabled), which refuses
    # any other key.
    ("consent_preferences", "delivery", "worker"): {"enable"},
    ("consent_preferences", "delivery", "destinations"): {
        "enable",
        "enabled_providers",
        "timeout_seconds",
        "max_response_bytes",
        "salesforce",
        "marketo",
        "adobe_experience_platform",
        "snowflake",
    },
    ("consent_preferences", "delivery", "destinations", "salesforce"): {
        "destination_id",
        "origin",
        "credential_secret_ref",
        "credential_revision",
        "api_version",
        "object_api_name",
        "external_id_field",
        "payload_digest_field",
    },
    ("consent_preferences", "delivery", "destinations", "marketo"): {
        "destination_id",
        "origin",
        "credential_secret_ref",
        "credential_revision",
        "custom_object_name",
        "dedupe_field",
        "message_id_field",
        "payload_digest_field",
    },
    (
        "consent_preferences",
        "delivery",
        "destinations",
        "adobe_experience_platform",
    ): {
        "destination_id",
        "origin",
        "credential_secret_ref",
        "credential_revision",
        "connection_id",
        "flow_id",
        "dataset_id",
        "schema_id",
        "ims_org_id",
    },
    ("consent_preferences", "delivery", "destinations", "snowflake"): {
        "destination_id",
        "origin",
        "credential_secret_ref",
        "credential_revision",
        "database",
        "schema",
        "table",
        "warehouse",
        "role",
    },
    ("consent_preferences", "analytics"): {
        "enable",
        "min_cohort_size",
        "retention_days",
    },
    ("consent_preferences", "experiments"): {
        "enable",
    },
    ("consent_preferences", "profile_data"): {
        "enable",
        "custom_index",
    },
    ("consent_preferences", "profile_data", "custom_index"): {
        "enable",
        "key_secret_ref",
        "key_version",
        "max_indexes",
        "max_page_size",
        "retention_seconds",
    },
    ("consent_preferences", "trust_center"): {
        "enable",
        "branding",
    },
    ("consent_preferences", "trust_center", "branding"): {
        "enable",
        "max_asset_bytes",
        "max_assets",
        "max_width",
        "max_height",
        "max_pixels",
        "max_domains",
        "challenge_ttl_seconds",
        "verification_ttl_seconds",
        "retention_seconds",
        "key_ref",
        "key_revision",
    },
    ("consent_preferences", "bulk_jobs"): {
        "enable",
        "initial_credits",
        "max_jobs",
        "max_items_per_job",
        "max_artifact_bytes",
        "lease_seconds",
        "retention_seconds",
        "worker_batch_size",
    },
    ("consent_preferences", "global_opt_out"): {
        "enable",
        "retention_seconds",
        "submission_ttl_seconds",
        "max_records",
    },
    ("consent_preferences", "application_scanner"): {
        "enable",
        "retention_seconds",
        "max_records",
    },
    ("consent_preferences", "native_sdk"): {
        "enable",
        "receipt_key_id",
        "receipt_key_revision",
        "receipt_key_secret_ref",
        "max_applications",
        "max_devices",
        "max_requests",
        "requests_per_minute",
        "require_profile_linking",
        "require_rights_requests",
    },
    ("consent_preferences", "storage"): {
        "backend",
        "dsn",
        "dsn_secret_ref",
    },
    ("consent_preferences", "edge_cache"): {
        "enable",
        "max_age_seconds",
        "stale_if_error_seconds",
    },
    ("consent_preferences", "limits"): {
        "profile_page_size",
        "receipt_page_size",
        "request_body_bytes",
    },
    ("data_use_governance", "compiler"): {
        "enable",
        "max_operations",
        "max_row_filter_nodes",
    },
    ("data_use_governance", "enforcement"): {
        "enable",
        "require_four_eyes",
        "max_attempts",
        "retry_base_seconds",
        "retry_max_seconds",
    },
    ("data_use_governance", "scheduler"): {
        "enable",
        "poll_seconds",
        "lease_seconds",
        "history_limit",
    },
    ("data_use_governance", "snowflake"): {
        "enable",
        "origin",
        "credential_secret_ref",
        "credential_revision",
        "timeout_seconds",
        "max_response_bytes",
    },
    ("data_use_governance", "databricks"): {
        "enable",
        "origin",
        "credential_secret_ref",
        "credential_revision",
        "timeout_seconds",
        "max_response_bytes",
    },
    ("data_use_governance", "limits"): {
        "max_assets",
        "max_fields",
        "max_lineage_edges",
        "max_context_age_seconds",
    },
    ("privacy_automation", "data_discovery"): {
        "enable",
        "adapters",
        "remediation",
    },
    ("privacy_automation", "data_discovery", "adapters"): {
        "enable",
        "enabled_providers",
        "timeout_seconds",
        "max_response_bytes",
        "page_size",
        "max_pages",
        "max_attempts",
        "max_polls",
    },
    ("privacy_automation", "data_discovery", "remediation"): {
        "enable",
        "max_attempts",
        "retention_seconds",
        "data_map",
        "scheduler",
    },
    ("privacy_automation", "data_discovery", "remediation", "data_map"): {
        "enable",
        "retention_seconds",
    },
    ("privacy_automation", "data_discovery", "remediation", "scheduler"): {
        "enable",
        "interval_seconds",
        "jitter_seconds",
        "retry_max_seconds",
        "tenant_limit",
        "worker_limit",
        "reconcile_limit",
        "lease_seconds",
    },
    ("privacy_automation", "regulatory_intelligence"): {
        "enable",
    },
    ("privacy_automation", "public_rights_form"): {
        "enable",
        "verification_ttl_hours",
        "status_ttl_days",
        "requests_per_ip_per_hour",
        "requests_per_email_per_day",
        "internal_target_days",
        "max_message_chars",
    },
    ("privacy_automation", "rights_orchestration"): {
        "enable",
        "source_adapters",
    },
    ("privacy_automation", "rights_orchestration", "source_adapters"): {
        "enable",
        "providers",
        "timeout_seconds",
        "max_response_bytes",
        "max_retrieval_bytes",
        "max_records",
        "batch_size",
        "lease_seconds",
        "retry_delay_seconds",
        "claim_history_retention_seconds",
        "target_custody_retention_seconds",
    },
    ("privacy_automation", "rights_orchestration", "source_adapters", "providers"): {
        "microsoft_graph_users",
        "google_workspace_users",
        "salesforce_contacts",
        "servicenow_users",
    },
    ("data_use_governance", "provider_audit"): {
        "enable",
        "audit_window_seconds",
        "retention_seconds",
        "max_attempts",
        "snowflake_latency_watermark_seconds",
        "cursor_overlap_seconds",
        "max_pages_per_read",
        "scheduler",
    },
    ("data_use_governance", "provider_audit", "scheduler"): {
        "enable",
        "poll_seconds",
        "claim_limit",
        "tenant_limit",
        "lease_seconds",
        "event_limit",
        "retry_backoff_seconds",
        "purge_limit",
    },
    ("privacy_automation", "rights_consumer_delivery"): {
        "enable",
        "digest_key_ref",
        "export_signing_key_ref",
        "package_encryption_key_ref",
        "server_grant_ttl_seconds",
        "max_package_bytes",
    },
    ("privacy_automation", "rights_consumer_intake"): {
        "enable",
        "request_ttl_seconds",
        "retention_seconds",
        "max_active_requests",
        "max_active_requests_per_subject",
    },
    ("privacy_automation", "ott_ctv_rights"): {
        "enable",
    },
    ("privacy_automation", "drop_management"): {
        "enable",
        "principal_binding_key_ref",
        "retention_seconds",
        "scheduler_enable",
        "scheduler_interval_seconds",
        "scheduler_jitter_seconds",
        "scheduler_retry_max_seconds",
    },
    ("privacy_automation", "notice_governance"): {
        "enable",
        "publication_runtime",
    },
    ("privacy_automation", "notice_governance", "publication_runtime"): {
        "enable",
        "scheduler_enable",
        "active_tenants",
        "bindings",
        "poll_seconds",
        "retry_max_seconds",
        "tenant_limit",
        "lease_seconds",
        "retry_delay_seconds",
    },
    ("tech_risk_compliance", "grc_studio"): {
        "enable",
        "max_studios",
        "retention_seconds",
        "max_import_bytes",
    },
    ("tech_risk_compliance", "policy_publication_links"): {
        "enable",
    },
    ("tech_risk_compliance", "scoping"): {
        "enable",
    },
    ("tech_risk_compliance", "scope_actions"): {
        "enable",
    },
    ("tech_risk_compliance", "continuous_evidence"): {
        "enable",
        "enabled_collectors",
        "scheduler",
        "stock_collectors",
    },
    ("tech_risk_compliance", "continuous_evidence", "stock_collectors"): {
        "enable",
        "sources",
    },
    ("tech_risk_compliance", "continuous_evidence", "scheduler"): {
        "enable",
        "poll_seconds",
        "enqueue_limit",
        "claim_limit",
        "tenant_limit",
        "lease_seconds",
        "retry_backoff_seconds",
    },
    ("third_party_management", "intelligence"): {
        "enable",
        "providers",
    },
    ("third_party_management", "intelligence", "providers"): {
        "enable",
        "enabled_providers",
        "generic_approved_host",
        "iss_corporate_solutions_host",
        "supplywisdom_host",
        "timeout_seconds",
        "scheduler",
    },
    ("third_party_management", "intelligence", "providers", "scheduler"): {
        "enable",
        "poll_seconds",
    },
    ("third_party_management", "contracts"): {
        "enable",
        "max_records",
        "retention_seconds",
        "authority_max_age_seconds",
    },
    ("third_party_management", "executive_reports"): {
        "enable",
        "max_reports",
        "max_sources",
        "max_pdf_bytes",
        "retention_seconds",
        "download_token_seconds",
    },
    ("third_party_management", "lifecycle"): {
        "enable",
        "portal",
    },
    ("third_party_management", "lifecycle", "portal"): {
        "enable",
        "invitation_ttl_seconds",
        "retention_seconds",
        "max_messages",
        "max_artifacts",
        "max_artifact_bytes",
    },
}
for _provider in ("entra", "okta", "purview"):
    _NESTED_GOVERNANCE_SCHEMA[
        ("ai_identity_governance_connectors", "scheduler", "providers", _provider)
    ] = _IDENTITY_SCHEDULE_KEYS
for _provider in (
    "microsoft_graph_users",
    "google_workspace_users",
    "salesforce_contacts",
    "servicenow_users",
):
    _NESTED_GOVERNANCE_SCHEMA[
        (
            "privacy_automation",
            "rights_orchestration",
            "source_adapters",
            "providers",
            _provider,
        )
    ] = {
        "enable",
        "source_id",
        "origin",
        "credential_ref",
        "capabilities",
    }

_NESTED_BOOL_KEYS: dict[tuple[str, ...], set[str]] = {
    ("audit", "unified"): {"enable"},
    ("ai_evidence_analysis", "ocr"): {"enable"},
    ("ai_evidence_analysis", "legacy_xls"): {"enable"},
    ("ai_evidence_analysis", "parser_sandbox"): {"enable"},
    ("consent_preferences", "publishing"): {
        "enable",
        "require_signed_publications",
    },
    ("consent_preferences", "public_api"): {"enable"},
    ("consent_preferences", "scanner"): {
        "enable",
        "allow_authenticated_scans",
    },
    ("consent_preferences", "scanner", "scheduler"): {"enable"},
    ("consent_preferences", "scanner", "notice_proposals"): {"enable"},
    ("consent_preferences", "standards"): {
        "gpc",
        "dnt",
        "gpp",
        "tcf",
        "google_consent_mode",
    },
    ("consent_preferences", "identity"): {"enable"},
    ("consent_preferences", "delivery"): {"enable"},
    ("consent_preferences", "delivery", "worker"): {"enable"},
    ("consent_preferences", "delivery", "destinations"): {"enable"},
    ("consent_preferences", "analytics"): {"enable"},
    ("consent_preferences", "experiments"): {"enable"},
    ("consent_preferences", "profile_data"): {"enable"},
    ("consent_preferences", "profile_data", "custom_index"): {"enable"},
    ("consent_preferences", "trust_center"): {"enable"},
    ("consent_preferences", "trust_center", "branding"): {"enable"},
    ("consent_preferences", "bulk_jobs"): {"enable"},
    ("consent_preferences", "global_opt_out"): {"enable"},
    ("consent_preferences", "application_scanner"): {"enable"},
    ("consent_preferences", "native_sdk"): {
        "enable",
        "require_profile_linking",
        "require_rights_requests",
    },
    ("consent_preferences", "edge_cache"): {"enable"},
    ("data_use_governance", "compiler"): {"enable"},
    ("data_use_governance", "enforcement"): {
        "enable",
        "require_four_eyes",
    },
    ("data_use_governance", "provider_audit"): {"enable"},
    ("data_use_governance", "provider_audit", "scheduler"): {"enable"},
    ("data_use_governance", "scheduler"): {"enable"},
    ("data_use_governance", "snowflake"): {"enable"},
    ("data_use_governance", "databricks"): {"enable"},
    ("privacy_automation", "data_discovery"): {"enable"},
    ("privacy_automation", "data_discovery", "adapters"): {"enable"},
    ("privacy_automation", "data_discovery", "remediation"): {"enable"},
    ("privacy_automation", "data_discovery", "remediation", "data_map"): {
        "enable"
    },
    ("privacy_automation", "data_discovery", "remediation", "scheduler"): {
        "enable"
    },
    ("privacy_automation", "regulatory_intelligence"): {"enable"},
    ("privacy_automation", "rights_orchestration"): {"enable"},
    ("privacy_automation", "rights_orchestration", "source_adapters"): {
        "enable"
    },
    ("privacy_automation", "rights_consumer_delivery"): {"enable"},
    ("privacy_automation", "rights_consumer_intake"): {"enable"},
    ("privacy_automation", "ott_ctv_rights"): {"enable"},
    ("privacy_automation", "drop_management"): {"enable", "scheduler_enable"},
    ("privacy_automation", "notice_governance"): {"enable"},
    ("privacy_automation", "notice_governance", "publication_runtime"): {
        "enable",
        "scheduler_enable",
    },
    ("tech_risk_compliance", "policy_publication_links"): {"enable"},
    ("tech_risk_compliance", "scoping"): {"enable"},
    ("tech_risk_compliance", "scope_actions"): {"enable"},
    ("tech_risk_compliance", "continuous_evidence"): {"enable"},
    ("tech_risk_compliance", "continuous_evidence", "stock_collectors"): {
        "enable"
    },
    ("tech_risk_compliance", "continuous_evidence", "scheduler"): {"enable"},
    ("tech_risk_compliance", "grc_studio"): {"enable"},
    ("third_party_management", "intelligence"): {"enable"},
    ("third_party_management", "intelligence", "providers"): {"enable"},
    ("third_party_management", "intelligence", "providers", "scheduler"): {"enable"},
    ("third_party_management", "contracts"): {"enable"},
    ("third_party_management", "executive_reports"): {"enable"},
    ("third_party_management", "lifecycle"): {"enable"},
    ("third_party_management", "lifecycle", "portal"): {"enable"},
}
for _provider in (
    "microsoft_graph_users",
    "google_workspace_users",
    "salesforce_contacts",
    "servicenow_users",
):
    _NESTED_BOOL_KEYS[
        (
            "privacy_automation",
            "rights_orchestration",
            "source_adapters",
            "providers",
            _provider,
        )
    ] = {"enable"}

_NESTED_INTEGER_BOUNDS: dict[tuple[tuple[str, ...], str], tuple[int, int]] = {
    (("agent_tests",), "max_cases_per_specialist"): (
        INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].minimum,
        INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].maximum,
    ),
    (("agent_tests",), "canary_percent"): (
        INTEGER_SETTINGS["agent_tests.canary_percent"].minimum,
        INTEGER_SETTINGS["agent_tests.canary_percent"].maximum,
    ),
    (("governance_inventory",), "retention_seconds"): (86_400, 315_360_000),
    (("governance_inventory",), "max_source_records"): (1, 100_000),
    (("governance_inventory",), "max_entities"): (1, 100_000),
    (("governance_inventory",), "max_relationships"): (1, 200_000),
    (("governance_inventory",), "max_export_bytes"): (1_024, 104_857_600),
    (("governance_inventory",), "max_snapshots"): (2, 10_000),
    (("audit", "unified"), "page_size"): (1, 500),
    (("audit", "unified"), "lease_seconds"): (30, 86_400),
    (("audit", "unified"), "max_lag_seconds"): (1, 31_536_000),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "outcome_max_attempts",
    ): (1, 20),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "outcome_retry_base_seconds",
    ): (1, 86_400),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "outcome_retry_max_seconds",
    ): (1, 604_800),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "outcome_lease_seconds",
    ): (1, 3_600),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "outcome_signal_validity_seconds",
    ): (60, 31_622_400),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "mapping_revision",
    ): (1, 1_000_000),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "mapping_retention_seconds",
    ): (300, 31_622_400),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "max_authority_records",
    ): (1, 10_000),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "max_observation_age_seconds",
    ): (1, 3_600),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "max_future_skew_seconds",
    ): (0, 300),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "purview_max_attempts",
    ): (1, 10),
    (
        ("ai_identity_governance_connectors", "controls", "production"),
        "purview_operation_lease_seconds",
    ): (5, 300),
    (("audit", "unified"), "max_attempts"): (1, 20),
    (("audit", "unified"), "retry_backoff_seconds"): (0, 86_400),
    (("audit", "unified"), "poll_seconds"): (5, 3_600),
    (("customer_sandbox_lifecycle",), "source_revision"): (1, 2**31 - 1),
    (("ai_entity_tasks",), "max_tasks"): (1, 1_000_000),
    (("ai_entity_tasks",), "retention_seconds"): (3_600, 315_360_000),
    (("ai_entity_tasks",), "authority_max_age_seconds"): (60, 31_536_000),
    (("administration_document_access",), "default_ttl_seconds"): (30, 3_600),
    (("administration_document_access",), "max_ttl_seconds"): (30, 3_600),
    (("administration_document_access",), "max_uses"): (1, 10),
    (("administration_document_access",), "delivery_grant_ttl_seconds"): (5, 300),
    (("administration_document_access",), "retention_seconds"): (60, 31_622_400),
    (("governed_document_vault",), "max_document_bytes"): (1_024, 104_857_600),
    (("governed_document_vault",), "max_documents"): (1, 1_000_000),
    (("governed_document_vault",), "retention_seconds"): (60, 315_360_000),
    (("governed_document_vault",), "grant_ttl_seconds"): (5, 300),
    (("governed_document_vault",), "claim_lease_seconds"): (5, 300),
    (("governed_document_vault",), "stream_chunk_bytes"): (4_096, 1_048_576),
    (
        ("privacy_automation", "rights_consumer_delivery"),
        "server_grant_ttl_seconds",
    ): (5, 120),
    (
        ("privacy_automation", "rights_consumer_delivery"),
        "max_package_bytes",
    ): (1_024, 16_777_216),
    (("consent_preferences", "trust_center", "branding"), "max_asset_bytes"): (
        1_024,
        10_485_760,
    ),
    (("consent_preferences", "trust_center", "branding"), "max_assets"): (1, 100_000),
    (("consent_preferences", "trust_center", "branding"), "max_width"): (16, 16_384),
    (("consent_preferences", "trust_center", "branding"), "max_height"): (16, 16_384),
    (("consent_preferences", "trust_center", "branding"), "max_pixels"): (
        256,
        64_000_000,
    ),
    (("consent_preferences", "trust_center", "branding"), "max_domains"): (1, 10_000),
    (("consent_preferences", "trust_center", "branding"), "challenge_ttl_seconds"): (
        300,
        86_400,
    ),
    (("consent_preferences", "trust_center", "branding"), "verification_ttl_seconds"): (
        900,
        7_776_000,
    ),
    (("consent_preferences", "trust_center", "branding"), "retention_seconds"): (
        60,
        315_360_000,
    ),
    (("consent_preferences", "trust_center", "branding"), "key_revision"): (
        1,
        2_147_483_647,
    ),
    (("incident_attachment_metadata",), "retention_seconds"): (
        3_600,
        315_360_000,
    ),
    (("incident_attachment_metadata",), "attachment_ttl_seconds"): (
        60,
        31_536_000,
    ),
    (("incident_attachment_metadata",), "max_attachments"): (1, 1_000_000),
    (("governance_agents",), "max_context_items"): (1, 1_000),
    (("governance_agents",), "max_context_bytes"): (1_024, 10_485_760),
    (("governance_agents",), "max_output_bytes"): (1_024, 1_048_576),
    (("governance_agents",), "retention_seconds"): (3_600, 315_360_000),
    (("governance_agents",), "context_projection_max_records_per_source"): (
        1,
        500,
    ),
    (("governance_agents",), "context_projection_max_context_items"): (1, 100),
    (("governance_agents",), "context_projection_max_total_bytes"): (
        1_024,
        10_485_760,
    ),
    (("governance_agents",), "context_projection_max_record_bytes"): (
        256,
        65_536,
    ),
    (("privacy_automation", "drop_management"), "retention_seconds"): (
        3_600,
        315_360_000,
    ),
    (("privacy_automation", "drop_management"), "scheduler_interval_seconds"): (
        30,
        86_400,
    ),
    (("privacy_automation", "drop_management"), "scheduler_jitter_seconds"): (
        0,
        3_600,
    ),
    (("privacy_automation", "drop_management"), "scheduler_retry_max_seconds"): (
        30,
        86_400,
    ),
    (
        ("privacy_automation", "notice_governance", "publication_runtime"),
        "poll_seconds",
    ): (5, 86_400),
    (
        ("privacy_automation", "notice_governance", "publication_runtime"),
        "retry_max_seconds",
    ): (5, 86_400),
    (
        ("privacy_automation", "notice_governance", "publication_runtime"),
        "tenant_limit",
    ): (1, 1_000),
    (
        ("privacy_automation", "notice_governance", "publication_runtime"),
        "lease_seconds",
    ): (1, 3_600),
    (
        ("privacy_automation", "notice_governance", "publication_runtime"),
        "retry_delay_seconds",
    ): (0, 604_800),
    (("ai_evidence_analysis",), "max_artifact_bytes"): (1_024, 104_857_600),
    (("ai_evidence_analysis",), "max_artifacts_per_case"): (1, 100),
    (("ai_evidence_analysis",), "max_authority_records"): (4, 1_000_000),
    (("ai_evidence_analysis",), "max_extracted_text_bytes"): (1_024, 10_485_760),
    (("ai_evidence_analysis",), "retention_seconds"): (3_600, 315_360_000),
    (("ai_evidence_analysis", "ocr"), "timeout_seconds"): (1, 120),
    (("ai_evidence_analysis", "ocr"), "max_pixels"): (1, 100_000_000),
    (("ai_evidence_analysis", "ocr"), "max_output_bytes"): (1_024, 10_485_760),
    (("ai_evidence_analysis", "ocr"), "max_memory_bytes"): (
        67_108_864,
        2_147_483_648,
    ),
    (("ai_evidence_analysis", "legacy_xls"), "timeout_seconds"): (1, 120),
    (("ai_evidence_analysis", "legacy_xls"), "max_workbook_stream_bytes"): (
        1_024,
        67_108_864,
    ),
    (("ai_evidence_analysis", "legacy_xls"), "max_record_bytes"): (
        1_024,
        16_777_215,
    ),
    (("ai_evidence_analysis", "legacy_xls"), "max_records"): (1, 1_000_000),
    (("ai_evidence_analysis", "legacy_xls"), "max_sheets"): (1, 256),
    (("ai_evidence_analysis", "legacy_xls"), "max_rows_per_sheet"): (
        1,
        1_048_576,
    ),
    (("ai_evidence_analysis", "legacy_xls"), "max_columns_per_sheet"): (1, 256),
    (("ai_evidence_analysis", "legacy_xls"), "max_cells"): (1, 1_000_000),
    (("ai_evidence_analysis", "legacy_xls"), "max_output_bytes"): (
        1_024,
        10_485_760,
    ),
    (("ai_evidence_analysis", "legacy_xls"), "max_memory_bytes"): (
        67_108_864,
        2_147_483_648,
    ),
    (("assessment_evidence_autopopulation",), "retention_seconds"): (
        60,
        316_224_000,
    ),
    (("assessment_evidence_autopopulation",), "max_records"): (1, 10_000),
    (
        ("assessment_evidence_autopopulation",),
        "max_evidence_records_per_proposal",
    ): (1, 32),
    (("assessment_evidence_autopopulation",), "max_citations_per_answer"): (
        1,
        32,
    ),
    (("assessment_evidence_autopopulation",), "min_confidence_bps"): (
        1,
        10_000,
    ),
    (("ai_governance_loop",), "poll_seconds"): (5, 3_600),
    (("ai_governance_loop",), "batch_size"): (1, 500),
    (("ai_governance_loop",), "lease_seconds"): (30, 3_600),
    (("ai_governance_loop",), "max_attempts"): (1, 20),
    (("ai_governance_loop",), "retry_base_seconds"): (1, 86_400),
    (("ai_governance_loop",), "max_lag_seconds"): (1, 31_536_000),
    (("consent_preferences", "public_api"), "token_ttl_seconds"): (60, 86_400),
    (
        ("consent_preferences", "publishing", "web_settings"),
        "retention_seconds",
    ): (60, 316_224_000),
    (
        ("consent_preferences", "publishing", "web_settings"),
        "max_history",
    ): (1, 1_000),
    (("consent_preferences", "bulk_jobs"), "initial_credits"): (0, 1_000_000_000),
    (("consent_preferences", "bulk_jobs"), "max_jobs"): (1, 1_000_000),
    (("consent_preferences", "bulk_jobs"), "max_items_per_job"): (1, 100_000),
    (("consent_preferences", "bulk_jobs"), "max_artifact_bytes"): (
        1_024,
        268_435_456,
    ),
    (("consent_preferences", "bulk_jobs"), "lease_seconds"): (5, 3_600),
    (("consent_preferences", "bulk_jobs"), "retention_seconds"): (
        86_400,
        315_360_000,
    ),
    (("consent_preferences", "bulk_jobs"), "worker_batch_size"): (1, 500),
    (("consent_preferences", "global_opt_out"), "retention_seconds"): (
        3_600,
        315_360_000,
    ),
    (("consent_preferences", "global_opt_out"), "submission_ttl_seconds"): (
        60,
        86_400,
    ),
    (("consent_preferences", "global_opt_out"), "max_records"): (1, 100_000),
    (("consent_preferences", "application_scanner"), "retention_seconds"): (
        86_400,
        315_360_000,
    ),
    (("consent_preferences", "application_scanner"), "max_records"): (
        1,
        1_000_000,
    ),
    (("consent_preferences", "native_sdk"), "receipt_key_revision"): (
        1,
        1_000_000,
    ),
    (("consent_preferences", "native_sdk"), "max_applications"): (1, 100_000),
    (("consent_preferences", "native_sdk"), "max_devices"): (1, 10_000_000),
    (("consent_preferences", "native_sdk"), "max_requests"): (1, 100_000_000),
    (("consent_preferences", "native_sdk"), "requests_per_minute"): (1, 10_000),
    (("consent_preferences", "public_api"), "max_request_bytes"): (
        1_024,
        1_048_576,
    ),
    (("consent_preferences", "public_api"), "max_response_bytes"): (
        1_024,
        4_194_304,
    ),
    (("consent_preferences", "public_api"), "requests_per_minute"): (1, 10_000),
    (("consent_preferences", "scanner"), "interval_seconds"): (300, 2_592_000),
    (("consent_preferences", "scanner"), "max_pages"): (1, 10_000),
    (("consent_preferences", "scanner"), "max_depth"): (0, 20),
    (("consent_preferences", "scanner"), "page_timeout_seconds"): (1, 300),
    (("consent_preferences", "scanner"), "max_network_events"): (1, 100_000),
    (("consent_preferences", "scanner", "scheduler"), "poll_seconds"): (5, 3_600),
    (("consent_preferences", "scanner", "scheduler"), "enqueue_limit"): (1, 500),
    (("consent_preferences", "scanner", "scheduler"), "claim_limit"): (1, 100),
    (("consent_preferences", "scanner", "scheduler"), "tenant_limit"): (
        1,
        10_000,
    ),
    (("consent_preferences", "identity"), "token_ttl_seconds"): (60, 86_400),
    (
        ("consent_preferences", "identity"),
        "link_lifecycle_retention_seconds",
    ): (3_600, 315_360_000),
    (("consent_preferences", "delivery"), "max_attempts"): (1, 20),
    (("consent_preferences", "delivery"), "retry_base_seconds"): (1, 3_600),
    (("consent_preferences", "delivery"), "retry_max_seconds"): (1, 86_400),
    (
        ("consent_preferences", "delivery", "destinations"),
        "max_response_bytes",
    ): (1_024, 1_048_576),
    (
        ("consent_preferences", "delivery", "destinations", "salesforce"),
        "credential_revision",
    ): (1, 2**31 - 1),
    (
        ("consent_preferences", "delivery", "destinations", "marketo"),
        "credential_revision",
    ): (1, 2**31 - 1),
    (
        (
            "consent_preferences",
            "delivery",
            "destinations",
            "adobe_experience_platform",
        ),
        "credential_revision",
    ): (1, 2**31 - 1),
    (
        ("consent_preferences", "delivery", "destinations", "snowflake"),
        "credential_revision",
    ): (1, 2**31 - 1),
    (("consent_preferences", "analytics"), "min_cohort_size"): (2, 100_000),
    (("consent_preferences", "analytics"), "retention_days"): (1, 3_650),
    (
        ("consent_preferences", "profile_data", "custom_index"),
        "key_version",
    ): (1, 1_000_000),
    (
        ("consent_preferences", "profile_data", "custom_index"),
        "max_indexes",
    ): (1, 10_000),
    (
        ("consent_preferences", "profile_data", "custom_index"),
        "max_page_size",
    ): (1, 500),
    (
        ("consent_preferences", "profile_data", "custom_index"),
        "retention_seconds",
    ): (86_400, 157_680_000),
    (("consent_preferences", "edge_cache"), "max_age_seconds"): (0, 86_400),
    (("consent_preferences", "edge_cache"), "stale_if_error_seconds"): (
        0,
        604_800,
    ),
    (("consent_preferences", "limits"), "profile_page_size"): (1, 500),
    (("consent_preferences", "limits"), "receipt_page_size"): (1, 500),
    (("consent_preferences", "limits"), "request_body_bytes"): (
        1_024,
        1_048_576,
    ),
    (("data_use_governance", "compiler"), "max_operations"): (1, 10_000),
    # Native adapters accept row filters of at most 256 parts.
    (("data_use_governance", "compiler"), "max_row_filter_nodes"): (1, 256),
    (("data_use_governance", "enforcement"), "max_attempts"): (1, 5),
    (("data_use_governance", "provider_audit"), "audit_window_seconds"): (
        60,
        604_800,
    ),
    (("data_use_governance", "provider_audit"), "retention_seconds"): (
        60,
        316_224_000,
    ),
    (("data_use_governance", "provider_audit"), "max_attempts"): (1, 20),
    (
        ("data_use_governance", "provider_audit"),
        "snowflake_latency_watermark_seconds",
    ): (10_800, 604_800),
    (
        ("data_use_governance", "provider_audit"),
        "cursor_overlap_seconds",
    ): (60, 3_600),
    (
        ("data_use_governance", "provider_audit"),
        "max_pages_per_read",
    ): (1, 100),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "poll_seconds",
    ): (5, 3_600),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "claim_limit",
    ): (1, 100),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "tenant_limit",
    ): (1, 10_000),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "lease_seconds",
    ): (30, 86_400),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "event_limit",
    ): (1, 500),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "retry_backoff_seconds",
    ): (0, 86_400),
    (
        ("data_use_governance", "provider_audit", "scheduler"),
        "purge_limit",
    ): (1, 500),
    (("data_use_governance", "scheduler"), "poll_seconds"): (5, 3_600),
    (("data_use_governance", "scheduler"), "lease_seconds"): (30, 86_400),
    (("data_use_governance", "scheduler"), "history_limit"): (1, 1_000),
    (("data_use_governance", "snowflake"), "timeout_seconds"): (1, 60),
    (("data_use_governance", "snowflake"), "credential_revision"): (1, 2**31 - 1),
    (("data_use_governance", "snowflake"), "max_response_bytes"): (
        1_024,
        131_072,
    ),
    (("data_use_governance", "databricks"), "timeout_seconds"): (5, 50),
    (("data_use_governance", "databricks"), "credential_revision"): (1, 2**31 - 1),
    (("data_use_governance", "databricks"), "max_response_bytes"): (
        1_024,
        131_072,
    ),
    (("data_use_governance", "limits"), "max_assets"): (1, 1_000_000),
    (("data_use_governance", "limits"), "max_fields"): (1, 10_000_000),
    (("data_use_governance", "limits"), "max_lineage_edges"): (1, 20_000_000),
    (("data_use_governance", "limits"), "max_context_age_seconds"): (
        60,
        31_536_000,
    ),
    (
        ("privacy_automation", "data_discovery", "adapters"),
        "max_response_bytes",
    ): (1_024, 67_108_864),
    (("privacy_automation", "data_discovery", "adapters"), "page_size"): (
        1,
        1_000,
    ),
    (("privacy_automation", "data_discovery", "adapters"), "max_pages"): (
        1,
        10_000,
    ),
    (("privacy_automation", "data_discovery", "adapters"), "max_attempts"): (
        1,
        5,
    ),
    (("privacy_automation", "data_discovery", "adapters"), "max_polls"): (
        1,
        100,
    ),
    (
        ("privacy_automation", "data_discovery", "remediation"),
        "max_attempts",
    ): (1, 20),
    (
        ("privacy_automation", "data_discovery", "remediation"),
        "retention_seconds",
    ): (60, 316_224_000),
    (
        ("privacy_automation", "data_discovery", "remediation", "data_map"),
        "retention_seconds",
    ): (60, 316_224_000),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "interval_seconds",
    ): (5, 86_400),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "jitter_seconds",
    ): (0, 3_600),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "retry_max_seconds",
    ): (5, 86_400),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "tenant_limit",
    ): (1, 10_000),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "worker_limit",
    ): (1, 100),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "reconcile_limit",
    ): (1, 100),
    (
        ("privacy_automation", "data_discovery", "remediation", "scheduler"),
        "lease_seconds",
    ): (1, 3_600),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "max_response_bytes",
    ): (1_024, 4_194_304),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "max_retrieval_bytes",
    ): (1_024, 33_554_432),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "max_records",
    ): (1, 1_000),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "batch_size",
    ): (1, 100),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "lease_seconds",
    ): (1, 3_600),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "retry_delay_seconds",
    ): (0, 604_800),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "claim_history_retention_seconds",
    ): (60, 2_592_000),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "target_custody_retention_seconds",
    ): (3_600, 315_360_000),
    (("privacy_automation", "rights_consumer_intake"), "request_ttl_seconds"): (
        60,
        2_592_000,
    ),
    (("privacy_automation", "rights_consumer_intake"), "retention_seconds"): (
        3_600,
        316_224_000,
    ),
    (("privacy_automation", "rights_consumer_intake"), "max_active_requests"): (
        1,
        10_000,
    ),
    (
        ("privacy_automation", "rights_consumer_intake"),
        "max_active_requests_per_subject",
    ): (1, 10_000),
    (("tech_risk_compliance", "grc_studio"), "max_studios"): (1, 10_000),
    (("tech_risk_compliance", "grc_studio"), "retention_seconds"): (
        86_400,
        315_360_000,
    ),
    (("tech_risk_compliance", "grc_studio"), "max_import_bytes"): (
        1_024,
        2_097_152,
    ),
    (("tech_risk_compliance", "continuous_evidence", "scheduler"), "poll_seconds"): (
        5,
        3_600,
    ),
    (("tech_risk_compliance", "continuous_evidence", "scheduler"), "enqueue_limit"): (
        1,
        500,
    ),
    (("tech_risk_compliance", "continuous_evidence", "scheduler"), "claim_limit"): (
        1,
        100,
    ),
    (("tech_risk_compliance", "continuous_evidence", "scheduler"), "tenant_limit"): (
        1,
        10_000,
    ),
    (("tech_risk_compliance", "continuous_evidence", "scheduler"), "lease_seconds"): (
        30,
        3_600,
    ),
    (
        ("tech_risk_compliance", "continuous_evidence", "scheduler"),
        "retry_backoff_seconds",
    ): (1, 86_400),
    (("third_party_management", "intelligence", "providers"), "timeout_seconds"): (
        1,
        120,
    ),
    (
        ("third_party_management", "intelligence", "providers", "scheduler"),
        "poll_seconds",
    ): (60, 86_400),
    (("third_party_management", "contracts"), "max_records"): (1, 1_000_000),
    (("third_party_management", "contracts"), "retention_seconds"): (
        86_400,
        315_360_000,
    ),
    (("third_party_management", "contracts"), "authority_max_age_seconds"): (
        60,
        31_536_000,
    ),
    (("third_party_management", "executive_reports"), "max_reports"): (
        1,
        1_000_000,
    ),
    (("third_party_management", "executive_reports"), "max_sources"): (1, 500),
    (("third_party_management", "executive_reports"), "max_pdf_bytes"): (
        16_384,
        4_194_304,
    ),
    (("third_party_management", "executive_reports"), "retention_seconds"): (
        86_400,
        315_360_000,
    ),
    (("third_party_management", "executive_reports"), "download_token_seconds"): (
        30,
        86_400,
    ),
    (
        ("third_party_management", "lifecycle", "portal"),
        "invitation_ttl_seconds",
    ): (300, 2_592_000),
    (
        ("third_party_management", "lifecycle", "portal"),
        "retention_seconds",
    ): (3_600, 316_224_000),
    (("third_party_management", "lifecycle", "portal"), "max_messages"): (
        1,
        1_000,
    ),
    (("third_party_management", "lifecycle", "portal"), "max_artifacts"): (
        0,
        100,
    ),
    (("third_party_management", "lifecycle", "portal"), "max_artifact_bytes"): (
        1_024,
        104_857_600,
    ),
}

_NESTED_NUMBER_BOUNDS: dict[
    tuple[tuple[str, ...], str], tuple[float, float]
] = {
    # Data-use enforcement retries wait inside one request (seconds, not minutes).
    (("data_use_governance", "enforcement"), "retry_base_seconds"): (0.05, 10.0),
    (("data_use_governance", "enforcement"), "retry_max_seconds"): (0.25, 60.0),
    (
        ("privacy_automation", "data_discovery", "adapters"),
        "timeout_seconds",
    ): (0.1, 60.0),
    (
        ("privacy_automation", "rights_orchestration", "source_adapters"),
        "timeout_seconds",
    ): (0.1, 60.0),
    (
        ("consent_preferences", "delivery", "destinations"),
        "timeout_seconds",
    ): (0.1, 60.0),
}

_IDENTITY_SCHEDULE_INTEGER_BOUNDS = {
    "interval_seconds": (60, 86_400),
    "retry_base_seconds": (1, 3_600),
    "retry_max_seconds": (1, 86_400),
    "max_attempts_per_slot": (1, 10),
    "lease_seconds": (60, 86_400),
    "history_limit": (1, 32),
    "max_snapshot_items": (1, 10_000),
    "max_delta_digests": (0, 512),
}
_MISSING = object()


# Key names that carry secrets. A literal (non-``${ENV}``) string under one of
# these is a plaintext secret in config.toml -- flagged so operators route it
# through an env var / secrets manager instead. Conservative to avoid noise.
# Bare ``token`` is deliberately NOT here: it is a documented operator setting
# (e.g. ``[dashboard] token``) and too broad to flag without false positives.
# Secret-bearing ``*_token`` keys are still caught by the suffix list below.
_SECRET_KEY_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "private_key",
    }
)
_SECRET_KEY_SUFFIXES = ("_api_key", "_secret", "_password", "_token")


def _is_secret_key(key: str) -> bool:
    k = key.lower()
    return k in _SECRET_KEY_NAMES or k.endswith(_SECRET_KEY_SUFFIXES)


def _looks_like_env_ref(v: str) -> bool:
    """True for an env-var reference or an empty placeholder -- i.e. NOT an inline
    secret. ``${VAR}`` / ``$VAR`` interpolate from the environment; ``""`` is an
    unset placeholder. Anything else under a secret-bearing key is literal."""
    s = v.strip()
    return s == "" or s.startswith("$")


def _lint_inline_secrets(cfg: dict, _path: tuple[str, ...] = ()) -> list[Finding]:
    """Walk the whole config (nested tables included) and warn on a literal
    string under a secret-bearing key -- a plaintext secret in config.toml."""
    out: list[Finding] = []
    for key, val in cfg.items():
        if not isinstance(key, str):
            continue
        if isinstance(val, dict):
            out.extend(_lint_inline_secrets(val, _path + (key,)))
        elif _is_secret_key(key) and isinstance(val, str) and not _looks_like_env_ref(val):
            dotted = ".".join(_path + (key,))
            out.append(
                Finding(
                    section=".".join(_path) or "(root)",
                    key=key,
                    severity="warning",
                    message=(
                        f"{dotted} looks like an inline secret; reference an env var "
                        f'instead (e.g. {key} = "${{MY_SECRET}}") so the secret is not '
                        "stored in plaintext config."
                    ),
                )
            )
    return out


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_valid_numeric_cap(v: int | float) -> bool:
    """Return whether a numeric cap is finite and non-negative.

    ``math.isfinite`` coerces arbitrary-size Python ints to float, which can
    raise ``OverflowError`` for huge TOML integers. Integers are always finite,
    so handle them before checking floats.
    """
    if isinstance(v, int):
        return v >= 0
    return math.isfinite(v) and v >= 0


def _is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_absolute_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 1 <= len(value) <= 1_024
        and "\x00" not in value
        and (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())
    )


def _is_exact_dependency_version(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", value) is not None
    )


def _number_between(value: object, lower: float, upper: float) -> bool:
    """Bound a number without coercing arbitrarily large integers to float."""
    if not _is_number(value):
        return False
    if isinstance(value, int):
        return lower <= value <= upper
    return math.isfinite(value) and lower <= value <= upper


def _suggest(name: str, candidates: list[str]) -> str:
    """Return ' (did you mean "X"?)' for the closest candidate, else ''."""
    matches = difflib.get_close_matches(name, candidates, n=1, cutoff=0.6)
    if matches:
        return f' (did you mean "{matches[0]}"?)'
    return ""


def _at_path(cfg: dict, path: tuple[str, ...]) -> object:
    current: object = cfg
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _nested_error(
    section: str,
    key: str,
    message: str,
    *,
    severity: str = "error",
) -> Finding:
    return Finding(section=section, key=key, severity=severity, message=message)


def _lint_identity_schedule_table(path: tuple[str, ...], value: dict) -> list[Finding]:
    findings: list[Finding] = []
    section = ".".join(path)
    enabled = value.get("enable", _MISSING)
    if enabled is not _MISSING and not isinstance(enabled, bool):
        findings.append(
            _nested_error(
                section,
                "enable",
                f"{section}.enable must be true or false, got {type(enabled).__name__}",
            )
        )
    for key, bounds in _IDENTITY_SCHEDULE_INTEGER_BOUNDS.items():
        item = value.get(key, _MISSING)
        if item is _MISSING:
            continue
        lower, upper = bounds
        if isinstance(item, bool) or not isinstance(item, int) or not lower <= item <= upper:
            findings.append(
                _nested_error(
                    section,
                    key,
                    f"{section}.{key} must be an integer between {lower} and {upper}, got {item!r}",
                )
            )
    retry_base = value.get("retry_base_seconds")
    retry_max = value.get("retry_max_seconds")
    if (
        isinstance(retry_base, int)
        and not isinstance(retry_base, bool)
        and isinstance(retry_max, int)
        and not isinstance(retry_max, bool)
        and retry_max < retry_base
    ):
        findings.append(
            _nested_error(
                section,
                "retry_max_seconds",
                f"{section}.retry_max_seconds must be greater than or equal to retry_base_seconds",
            )
        )
    return findings


def _lint_trust_root_keys(value: dict) -> list[Finding]:
    findings: list[Finding] = []
    section = "ai_benchmark_exchange.trust_roots"
    version = value.get("version", _MISSING)
    if version is not _MISSING and (
        isinstance(version, bool) or not isinstance(version, int) or version < 1
    ):
        findings.append(
            _nested_error(
                section,
                "version",
                f"{section}.version must be a positive integer",
            )
        )
    schema = value.get("schema", _MISSING)
    if schema is not _MISSING and not isinstance(schema, str):
        findings.append(
            _nested_error(
                section,
                "schema",
                f"{section}.schema must be a string",
            )
        )
    keys = value.get("keys", _MISSING)
    if keys is _MISSING:
        return findings
    if not isinstance(keys, list):
        findings.append(
            _nested_error(
                section,
                "keys",
                f"{section}.keys must be an array of tables",
            )
        )
        return findings
    allowed = {"key_id", "public_key_hex", "introduced_in", "revoked_in"}
    required = {"key_id", "public_key_hex", "introduced_in"}
    for index, item in enumerate(keys):
        item_section = f"{section}.keys[{index}]"
        if not isinstance(item, dict):
            findings.append(
                _nested_error(
                    section,
                    "keys",
                    f"{item_section} must be a table",
                )
            )
            continue
        for key in item:
            if isinstance(key, str) and key not in allowed:
                findings.append(
                    _nested_error(
                        item_section,
                        key,
                        f'unknown key "{key}" in [{item_section}]' + _suggest(key, sorted(allowed)),
                        severity="warning",
                    )
                )
        missing = sorted(required - set(item))
        for key in missing:
            findings.append(
                _nested_error(
                    item_section,
                    key,
                    f"{item_section}.{key} is required",
                )
            )
        for key in ("key_id", "public_key_hex"):
            item_value = item.get(key, _MISSING)
            if item_value is not _MISSING and not isinstance(item_value, str):
                findings.append(
                    _nested_error(
                        item_section,
                        key,
                        f"{item_section}.{key} must be a string",
                    )
                )
        for key in ("introduced_in", "revoked_in"):
            item_value = item.get(key, _MISSING)
            if item_value is not _MISSING and (
                isinstance(item_value, bool) or not isinstance(item_value, int) or item_value < 1
            ):
                findings.append(
                    _nested_error(
                        item_section,
                        key,
                        f"{item_section}.{key} must be a positive integer",
                    )
                )
    return findings


def _lint_local_owner_totp(cfg: dict) -> list[Finding]:
    """``[auth.local_owner] totp`` must be one of the three modes; anything else reads as optional."""
    from .config import LOCAL_OWNER_TOTP_MODES

    value = _at_path(cfg, ("auth", "local_owner", "totp"))
    if value is _MISSING:
        return []
    if isinstance(value, str) and value.strip().lower() in LOCAL_OWNER_TOTP_MODES:
        return []
    # As in the runtime, only a short plain word is written out; never a pasted secret.
    shown = f"{value!r}" if isinstance(value, str) and re.fullmatch(r"[a-z]{1,20}", value) else "a value"
    return [
        _nested_error(
            "auth.local_owner",
            "totp",
            f"auth.local_owner.totp must be one of {', '.join(LOCAL_OWNER_TOTP_MODES)}, got {shown}; "
            "until it is fixed the owner's authenticator app is read as optional",
            severity="warning",
        )
    ]


def _lint_identity_controls(cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    controls = _at_path(cfg, ("ai_identity_governance_connectors", "controls"))
    if not isinstance(controls, dict):
        return findings
    section = "ai_identity_governance_connectors.controls"
    connector = _at_path(cfg, ("ai_identity_governance_connectors", "enable"))
    if controls.get("enable") is True and connector is not True:
        findings.append(
            _nested_error(
                section,
                "enable",
                f"enabled {section} requires ai_identity_governance_connectors.enable = true",
            )
        )
    for path, keys in (
        (("controls",), ("enable",)),
        (("controls", "change_coupling"), ("enable", "dynamic_risk", "alerts")),
        (("controls", "federation"), ("enable",)),
        (("controls", "conditional_access"), ("enable",)),
        (("controls", "purview_writeback"), ("enable",)),
        (("controls", "production"), ("enable",)),
    ):
        table = _at_path(cfg, ("ai_identity_governance_connectors", *path))
        if not isinstance(table, dict):
            continue
        table_section = "ai_identity_governance_connectors." + ".".join(path)
        for key in keys:
            value = table.get(key, _MISSING)
            if value is not _MISSING and not isinstance(value, bool):
                findings.append(
                    _nested_error(
                        table_section,
                        key,
                        f"{table_section}.{key} must be true or false, got {type(value).__name__}",
                    )
                )
        if len(path) == 2 and table.get("enable") is True and controls.get("enable") is not True:
            findings.append(
                _nested_error(
                    table_section,
                    "enable",
                    f"enabled {table_section} requires {section}.enable = true",
                )
            )
    change = controls.get("change_coupling")
    if (
        isinstance(change, dict)
        and change.get("enable") is True
        and change.get("dynamic_risk") is not True
        and change.get("alerts") is not True
    ):
        findings.append(
            _nested_error(
                f"{section}.change_coupling",
                "enable",
                "enabled identity change coupling requires dynamic_risk or alerts",
            )
        )
    federation = controls.get("federation")
    federation_enabled = isinstance(federation, dict) and federation.get("enable") is True
    for dependent_name in ("conditional_access", "purview_writeback"):
        dependent = controls.get(dependent_name)
        if (
            isinstance(dependent, dict)
            and dependent.get("enable") is True
            and not federation_enabled
        ):
            dependent_section = f"{section}.{dependent_name}"
            findings.append(
                _nested_error(
                    dependent_section,
                    "enable",
                    f"enabled {dependent_section} requires {section}.federation.enable = true",
                )
            )
    production = controls.get("production")
    if isinstance(production, dict):
        retry_base = production.get("outcome_retry_base_seconds")
        retry_max = production.get("outcome_retry_max_seconds")
        if (
            isinstance(retry_base, int)
            and not isinstance(retry_base, bool)
            and isinstance(retry_max, int)
            and not isinstance(retry_max, bool)
            and retry_max < retry_base
        ):
            findings.append(
                _nested_error(
                    f"{section}.production",
                    "outcome_retry_max_seconds",
                    "outcome_retry_max_seconds must be greater than or equal to outcome_retry_base_seconds",
                )
            )
    return findings


def _is_https_origin(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.path in ("", "/")
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _is_exact_hostname(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 253
        and re.fullmatch(
            r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
            r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
            value,
        )
        is not None
    )


def _is_destination_secret_reference(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(
            r"\$(?:\{[A-Z][A-Z0-9_]{0,127}\}|[A-Z][A-Z0-9_]{0,127})",
            value,
        )
        is not None
    )


def _is_drop_principal_key_reference(value: object) -> bool:
    """Accept only bounded secret-provider references, never inline key material."""

    return (
        isinstance(value, str)
        and len(value) <= 256
        and re.fullmatch(
            r"(?:env:[A-Z][A-Z0-9_]{0,127}|"
            r"(?:kms|secret|vault|aws-kms|azure-keyvault|gcp-kms)://"
            r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,239})",
            value,
        )
        is not None
    )


def _is_rights_delivery_key_reference(value: object) -> bool:
    """Require a named secret-provider reference, never inline key material."""

    return (
        isinstance(value, str)
        and re.fullmatch(
            r"(?:env|vault|secret):[A-Z][A-Z0-9_]{0,95}",
            value,
        )
        is not None
    )


def _is_named_destination_origin(value: object, provider_id: str) -> bool:
    if not _is_https_origin(value):
        return False
    try:
        parsed = urlparse(str(value))
        port = parsed.port
    except ValueError:
        return False
    host = (parsed.hostname or "").rstrip(".").lower()
    suffixes = {
        "salesforce": (".salesforce.com", ".force.com"),
        "marketo": (".mktorest.com",),
        "adobe_experience_platform": (".adobedc.net",),
        "snowflake": (".snowflakecomputing.com",),
    }[provider_id]
    return (port is None or port == 443) and any(
        host.endswith(suffix) and host != suffix[1:] for suffix in suffixes
    )


def _lint_consent_delivery_destinations(cfg: dict) -> list[Finding]:  # noqa: C901
    """Validate the closed named-provider delivery composition."""

    path = ("consent_preferences", "delivery", "destinations")
    section = _at_path(cfg, path)
    if section is _MISSING or not isinstance(section, dict):
        return []
    findings: list[Finding] = []
    section_name = ".".join(path)
    provider_fields = {
        "salesforce": {
            "api_version",
            "object_api_name",
            "external_id_field",
            "payload_digest_field",
        },
        "marketo": {
            "custom_object_name",
            "dedupe_field",
            "message_id_field",
            "payload_digest_field",
        },
        "adobe_experience_platform": {
            "connection_id",
            "flow_id",
            "dataset_id",
            "schema_id",
            "ims_org_id",
        },
        "snowflake": {"database", "schema", "table", "warehouse", "role"},
    }
    provider_ids = set(provider_fields)
    raw_enabled = section.get("enabled_providers", [])
    valid_enabled = (
        isinstance(raw_enabled, list)
        and 0 <= len(raw_enabled) <= len(provider_ids)
        and all(
            isinstance(item, str) and item in provider_ids
            for item in raw_enabled
        )
        and len(set(raw_enabled)) == len(raw_enabled)
    )
    enabled_ids = set(raw_enabled) if valid_enabled else set()
    if section.get("enable") is True:
        if not _table_enabled(cfg, ("consent_preferences", "delivery")):
            findings.append(
                _nested_error(
                    section_name,
                    "enable",
                    "named consent destinations require consent delivery to be enabled",
                )
            )
        if not valid_enabled or not enabled_ids:
            findings.append(
                _nested_error(
                    section_name,
                    "enabled_providers",
                    "enabled consent destinations require a unique non-empty closed provider list",
                )
            )
    # Disabled with services still listed is a clean off: the runtime keeps
    # the list but binds and sends nothing.

    common = {
        "destination_id",
        "origin",
        "credential_secret_ref",
        "credential_revision",
    }
    destination_ids: set[str] = set()
    provider_identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
    token = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
    aep_ref = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
    aep_org = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{1,255}\Z")
    for provider_id, settings in provider_fields.items():
        table = section.get(provider_id, _MISSING)
        if provider_id not in enabled_ids:
            if table is not _MISSING:
                findings.append(
                    _nested_error(
                        section_name,
                        provider_id,
                        f"{provider_id} settings cannot be configured while the adapter is disabled",
                    )
                )
            continue
        provider_section = f"{section_name}.{provider_id}"
        if not isinstance(table, dict):
            findings.append(
                _nested_error(
                    section_name,
                    provider_id,
                    f"enabled {provider_id} consent delivery requires its closed provider table",
                )
            )
            continue
        missing = sorted((common | settings) - set(table))
        for key in missing:
            findings.append(
                _nested_error(
                    provider_section,
                    key,
                    f"enabled {provider_id} consent delivery requires {key}",
                )
            )
        destination_id = table.get("destination_id")
        if not isinstance(destination_id, str) or token.fullmatch(destination_id) is None:
            findings.append(
                _nested_error(
                    provider_section,
                    "destination_id",
                    f"enabled {provider_id} requires a bounded destination identifier",
                )
            )
        elif destination_id in destination_ids:
            findings.append(
                _nested_error(
                    provider_section,
                    "destination_id",
                    "named consent destination identifiers must be unique",
                )
            )
        else:
            destination_ids.add(destination_id)
        if not _is_named_destination_origin(table.get("origin"), provider_id):
            findings.append(
                _nested_error(
                    provider_section,
                    "origin",
                    f"enabled {provider_id} requires one recognized exact public HTTPS origin",
                )
            )
        if not _is_destination_secret_reference(table.get("credential_secret_ref")):
            findings.append(
                _nested_error(
                    provider_section,
                    "credential_secret_ref",
                    f"enabled {provider_id} requires an uppercase $ENV credential reference",
                )
            )
        if provider_id == "salesforce":
            api_version = table.get("api_version")
            if not isinstance(api_version, str) or re.fullmatch(r"v[0-9]{2}\.[0-9]", api_version) is None:
                findings.append(
                    _nested_error(
                        provider_section,
                        "api_version",
                        "Salesforce api_version must use the exact vNN.N form",
                    )
                )
            identifier_keys = settings - {"api_version"}
        elif provider_id == "adobe_experience_platform":
            identifier_keys = set()
            for key in ("connection_id", "flow_id", "dataset_id", "schema_id"):
                value = table.get(key)
                if not isinstance(value, str) or aep_ref.fullmatch(value) is None:
                    findings.append(
                        _nested_error(
                            provider_section,
                            key,
                            f"AEP {key} must be a bounded provider reference",
                        )
                    )
            value = table.get("ims_org_id")
            if not isinstance(value, str) or aep_org.fullmatch(value) is None:
                findings.append(
                    _nested_error(
                        provider_section,
                        "ims_org_id",
                        "AEP ims_org_id must be a bounded organization reference",
                    )
                )
        else:
            identifier_keys = settings
        for key in identifier_keys:
            value = table.get(key)
            if not isinstance(value, str) or provider_identifier.fullmatch(value) is None:
                findings.append(
                    _nested_error(
                        provider_section,
                        key,
                        f"{provider_id} {key} must be a safe provider identifier",
                    )
                )
    return findings


def _table_enabled(cfg: dict, path: tuple[str, ...]) -> bool:
    table = _at_path(cfg, path)
    return isinstance(table, dict) and table.get("enable") is True


def _lint_privacy_rights_source_adapters(cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    path = (
        "privacy_automation",
        "rights_orchestration",
        "source_adapters",
    )
    section = _at_path(cfg, path)
    if section is _MISSING:
        return findings
    name = ".".join(path)
    if not isinstance(section, dict):
        return findings
    if section.get("enable") is True and (
        not _table_enabled(cfg, ("privacy_automation",))
        or not _table_enabled(
            cfg, ("privacy_automation", "rights_orchestration")
        )
    ):
        findings.append(
            _nested_error(
                name,
                "enable",
                "source adapters require enabled privacy rights orchestration",
            )
        )
    providers = section.get("providers", {})
    if not isinstance(providers, dict):
        return findings
    admitted_hosts = {
        "microsoft_graph_users": lambda host: host == "graph.microsoft.com",
        "google_workspace_users": lambda host: host == "admin.googleapis.com",
        "salesforce_contacts": lambda host: (
            host.endswith(".salesforce.com") and host != "salesforce.com"
        ),
        "servicenow_users": lambda host: (
            host.endswith(".service-now.com") and host != "service-now.com"
        ),
    }
    enabled_count = 0
    source_ids: set[str] = set()
    for provider, admission in admitted_hosts.items():
        table = providers.get(provider)
        if not isinstance(table, dict) or table.get("enable") is not True:
            continue
        enabled_count += 1
        provider_name = f"{name}.providers.{provider}"
        source_id = table.get("source_id")
        if (
            not isinstance(source_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", source_id)
            is None
            or source_id in source_ids
        ):
            findings.append(
                _nested_error(
                    provider_name,
                    "source_id",
                    "enabled source adapters require unique bounded source IDs",
                )
            )
        else:
            source_ids.add(source_id)
        parsed = urlparse(str(table.get("origin") or ""))
        host = (parsed.hostname or "").rstrip(".").lower()
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or admission(host) is not True
        ):
            findings.append(
                _nested_error(
                    provider_name,
                    "origin",
                    "enabled source adapter requires its exact public HTTPS origin",
                )
            )
        credential_ref = table.get("credential_ref")
        if (
            not isinstance(credential_ref, str)
            or re.fullmatch(
                r"(?:env|vault|secret):[A-Z][A-Z0-9_]{0,127}",
                credential_ref,
            )
            is None
        ):
            findings.append(
                _nested_error(
                    provider_name,
                    "credential_ref",
                    "enabled source adapter requires an opaque uppercase secret reference",
                )
            )
        capabilities = table.get("capabilities")
        admitted_capabilities = {"discover", "retrieve", "delete", "verify_delete"}
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or len(capabilities) != len(set(capabilities))
            or any(item not in admitted_capabilities for item in capabilities)
        ):
            findings.append(
                _nested_error(
                    provider_name,
                    "capabilities",
                    "enabled source adapter requires a unique closed capability list",
                )
            )
    if section.get("enable") is True and enabled_count == 0:
        findings.append(
            _nested_error(
                name,
                "providers",
                "enabled source adapters require at least one enabled stock provider",
            )
        )
    response_bytes = section.get("max_response_bytes", 1_048_576)
    retrieval_bytes = section.get("max_retrieval_bytes", 8_388_608)
    if (
        isinstance(response_bytes, int)
        and not isinstance(response_bytes, bool)
        and isinstance(retrieval_bytes, int)
        and not isinstance(retrieval_bytes, bool)
        and retrieval_bytes < response_bytes
    ):
        findings.append(
            _nested_error(
                name,
                "max_retrieval_bytes",
                "max_retrieval_bytes must be at least max_response_bytes",
            )
        )
    timeout = section.get("timeout_seconds", 15.0)
    lease = section.get("lease_seconds", 60)
    if (
        isinstance(timeout, (int, float))
        and not isinstance(timeout, bool)
        and math.isfinite(float(timeout))
        and isinstance(lease, int)
        and not isinstance(lease, bool)
        and lease < math.ceil(float(timeout) * 2) + 5
    ):
        findings.append(
            _nested_error(
                name,
                "lease_seconds",
                "lease_seconds must cover bounded lookup plus mutation I/O",
            )
        )
    return findings


def _lint_privacy_notice_publication_runtime(cfg: dict) -> list[Finding]:
    """Validate the closed exact-target local publication composition."""

    findings: list[Finding] = []
    path = ("privacy_automation", "notice_governance", "publication_runtime")
    runtime = _at_path(cfg, path)
    if runtime is _MISSING or not isinstance(runtime, dict):
        return findings
    section = ".".join(path)
    enabled = runtime.get("enable") is True
    scheduler_enabled = runtime.get("scheduler_enable") is True
    if enabled and (
        not _table_enabled(cfg, ("privacy_automation",))
        or not _table_enabled(cfg, ("privacy_automation", "notice_governance"))
        or not _table_enabled(cfg, ("consent_preferences",))
        or not _table_enabled(cfg, ("consent_preferences", "publishing"))
    ):
        findings.append(
            _nested_error(
                section,
                "enable",
                "publication runtime requires enabled notice governance and consent publishing",
            )
        )
    if scheduler_enabled and not enabled:
        findings.append(
            _nested_error(
                section,
                "scheduler_enable",
                "publication scheduler requires publication runtime enablement",
            )
        )
    raw_tenants = runtime.get("active_tenants", [])
    identifier = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
    tenants: set[str] = set()
    if (
        not isinstance(raw_tenants, list)
        or len(raw_tenants) > 10_000
        or any(
            not isinstance(item, str) or identifier.fullmatch(item) is None
            for item in raw_tenants
        )
        or len(raw_tenants) != len(set(raw_tenants))
    ):
        findings.append(
            _nested_error(
                section,
                "active_tenants",
                "active_tenants must be a unique bounded tenant identifier list",
            )
        )
    else:
        tenants = set(raw_tenants)
    bindings = runtime.get("bindings", {})
    required = {
        "tenant_id",
        "notice_id",
        "consent_publication_ref",
        "property_id",
        "rule_group_id",
        "rule_group_version",
        "notice_resource_id",
        "notice_resource_version",
    }
    if not isinstance(bindings, dict) or len(bindings) > 1_000:
        findings.append(
            _nested_error(
                section,
                "bindings",
                "bindings must be a table with at most 1000 exact target bindings",
            )
        )
        bindings = {}
    identities: set[tuple[str, str]] = set()
    binding_tenants: set[str] = set()
    for binding_id, binding in bindings.items():
        name = f"{section}.bindings.{binding_id}"
        if not isinstance(binding_id, str) or identifier.fullmatch(binding_id) is None:
            findings.append(
                _nested_error(section, "bindings", "binding names must be bounded identifiers")
            )
            continue
        if not isinstance(binding, dict) or set(binding) != required:
            findings.append(
                _nested_error(
                    name,
                    "binding",
                    "publication binding must contain only the exact required fields",
                )
            )
            continue
        for key in required - {"rule_group_version", "notice_resource_version"}:
            value = binding.get(key)
            if not isinstance(value, str) or identifier.fullmatch(value) is None:
                findings.append(
                    _nested_error(name, key, f"{key} must be a bounded identifier")
                )
        for key in ("rule_group_version", "notice_resource_version"):
            value = binding.get(key)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 2**31 - 1
            ):
                findings.append(
                    _nested_error(name, key, f"{key} must be a positive integer")
                )
        tenant = binding.get("tenant_id")
        consent_ref = binding.get("consent_publication_ref")
        if isinstance(tenant, str):
            binding_tenants.add(tenant)
            if tenants and tenant not in tenants:
                findings.append(
                    _nested_error(
                        name,
                        "tenant_id",
                        "binding tenant must be explicitly listed in active_tenants",
                    )
                )
        if isinstance(tenant, str) and isinstance(consent_ref, str):
            identity = (tenant, consent_ref)
            if identity in identities:
                findings.append(
                    _nested_error(
                        name,
                        "consent_publication_ref",
                        "tenant consent publication references must be unique",
                    )
                )
            identities.add(identity)
    if enabled and (not tenants or not bindings):
        findings.append(
            _nested_error(
                section,
                "bindings",
                "enabled publication runtime requires active tenants and exact bindings",
            )
        )
    if enabled and tenants - binding_tenants:
        findings.append(
            _nested_error(
                section,
                "bindings",
                "every active publication tenant requires an exact target binding",
            )
        )
    poll = runtime.get("poll_seconds", 30)
    retry_max = runtime.get("retry_max_seconds", 300)
    if (
        isinstance(poll, int)
        and not isinstance(poll, bool)
        and isinstance(retry_max, int)
        and not isinstance(retry_max, bool)
        and retry_max < poll
    ):
        findings.append(
            _nested_error(
                section,
                "retry_max_seconds",
                "retry_max_seconds must be at least poll_seconds",
            )
        )
    return findings


def _lint_trc_stock_collectors(cfg: dict) -> list[Finding]:
    """Validate closed stock-source manifests without opening secrets or providers."""

    from .trc_stock_evidence_collectors import (
        STOCK_COLLECTOR_IDS,
        ProviderControlBinding,
        StockCollectorLimits,
        StockCollectorSource,
    )

    findings: list[Finding] = []
    section = "tech_risk_compliance.continuous_evidence.stock_collectors"
    continuous = _at_path(cfg, ("tech_risk_compliance", "continuous_evidence"))
    if not isinstance(continuous, dict):
        return findings
    stock = continuous.get("stock_collectors")
    if stock is None:
        return findings
    if not isinstance(stock, dict):
        return findings
    selected = continuous.get("enabled_collectors")
    selected_ids = set(selected) if isinstance(selected, list) else set()
    stock_selected = selected_ids.intersection(STOCK_COLLECTOR_IDS)
    stock_enabled = stock.get("enable") is True
    if stock_enabled and not (
        cfg.get("tech_risk_compliance", {}).get("enable") is True
        and continuous.get("enable") is True
    ):
        findings.append(
            _nested_error(
                section,
                "enable",
                "stock collectors require Tech Risk continuous evidence to be enabled",
            )
        )
    if stock_selected and not stock_enabled:
        findings.append(
            _nested_error(
                section,
                "enable",
                "selected stock collector IDs require stock_collectors.enable = true",
            )
        )
    sources = stock.get("sources", [])
    if not isinstance(sources, list) or len(sources) > 64:
        findings.append(
            _nested_error(
                section,
                "sources",
                "stock collector sources must be a bounded list of at most 64 manifests",
            )
        )
        return findings
    if sources and not stock_enabled:
        findings.append(
            _nested_error(
                section,
                "sources",
                "stock collector source manifests require stock collectors to be enabled",
            )
        )
    source_keys = {
        "bindings",
        "capability_revision",
        "collector_key_id",
        "credential_env",
        "definition_id",
        "definition_integrity_sha256",
        "definition_version",
        "enrollment_id",
        "limits",
        "origin",
        "provider",
        "region",
        "scope_ref",
        "stream",
    }
    required_keys = source_keys - {"limits", "region", "stream"}
    limit_keys = {
        "max_elapsed_seconds",
        "max_pages",
        "max_records",
        "max_response_bytes",
        "page_size",
        "timeout_seconds",
    }
    enrollment_ids: set[str] = set()
    for index, source in enumerate(sources):
        key = f"sources[{index}]"
        if (
            not isinstance(source, dict)
            or set(source) - source_keys
            or not required_keys.issubset(source)
        ):
            findings.append(
                _nested_error(section, key, "stock collector source manifest is not closed")
            )
            continue
        enrollment_id = source.get("enrollment_id")
        if isinstance(enrollment_id, str) and enrollment_id in enrollment_ids:
            findings.append(
                _nested_error(section, key, "stock collector enrollment IDs must be unique")
            )
            continue
        if isinstance(enrollment_id, str):
            enrollment_ids.add(enrollment_id)
        bindings_raw = source.get("bindings")
        limits_raw = source.get("limits", {})
        if (
            not isinstance(bindings_raw, list)
            or not bindings_raw
            or len(bindings_raw) > 250
            or not isinstance(limits_raw, dict)
            or set(limits_raw) - limit_keys
        ):
            findings.append(
                _nested_error(section, key, "stock collector bindings or limits are invalid")
            )
            continue
        try:
            bindings = tuple(
                ProviderControlBinding(
                    control_ref=binding["control_ref"],
                    source_ref=binding["source_ref"],
                )
                for binding in bindings_raw
                if isinstance(binding, dict)
                and set(binding) == {"control_ref", "source_ref"}
            )
            if len(bindings) != len(bindings_raw):
                raise ValueError("binding shape")
            parsed = StockCollectorSource(
                tenant_id="config-lint",
                enrollment_id=source["enrollment_id"],
                definition_id=source["definition_id"],
                definition_version=source["definition_version"],
                definition_integrity_sha256=source["definition_integrity_sha256"],
                collector_key_id=source["collector_key_id"],
                capability_revision=source["capability_revision"],
                provider=source["provider"],
                origin=source["origin"],
                scope_ref=source["scope_ref"],
                credential_env=source["credential_env"],
                bindings=bindings,
                region=source.get("region"),
                stream=source.get("stream"),
                limits=StockCollectorLimits(**limits_raw),
            )
        except (KeyError, TypeError, ValueError):
            findings.append(
                _nested_error(section, key, "stock collector source authority is invalid")
            )
            continue
        if parsed.collector_id not in selected_ids:
            findings.append(
                _nested_error(
                    section,
                    key,
                    "stock collector source must be in the tenant collector allowlist",
                )
            )
    return findings


def _lint_product_governance_contracts(
    cfg: dict,
) -> list[Finding]:
    """Validate consent and data-use controls that must fail closed."""

    findings: list[Finding] = []
    findings.extend(_lint_governance_capabilities(cfg))
    findings.extend(_lint_evidence_analysis(cfg))
    findings.extend(_lint_custody_and_cloud(cfg))
    findings.extend(_lint_governed_documents(cfg))
    findings.extend(_lint_governance_dependencies(cfg))
    findings.extend(_lint_discovery_scheduler_contracts(cfg))
    findings.extend(_lint_consent_public_contracts(cfg))
    findings.extend(_lint_consent_native_contracts(cfg))
    consent_public = ("consent_preferences", "public_api")
    consent_publishing = ("consent_preferences", "publishing")
    findings.extend(_lint_continuous_evidence(cfg))
    findings.extend(_lint_rights_delivery_contracts(cfg))
    findings.extend(_lint_portal_identity_storage(cfg, consent_public, consent_publishing))
    findings.extend(_lint_consent_delivery_destinations(cfg))

    findings.extend(_lint_data_use_provider_contracts(cfg))
    findings.extend(_lint_third_party_provider_contracts(cfg))
    findings.extend(_lint_governance_retry_bounds(cfg))
    findings.extend(_lint_privacy_rights_source_adapters(cfg))
    findings.extend(_lint_privacy_notice_publication_runtime(cfg))
    findings.extend(_lint_trc_stock_collectors(cfg))
    return findings


def _lint_custody_and_cloud(cfg: dict) -> list[Finding]:
    """Check custody and cloud evidence prerequisites."""
    findings: list[Finding] = []
    if _table_enabled(cfg, ("audit", "unified", "custody")):
        try:
            from .unified_audit_custody import settings_from

            settings_from(cfg, tenant_id="config-lint")
        except (TypeError, ValueError, RuntimeError):
            findings.append(
                _nested_error(
                    "audit.unified.custody",
                    "enable",
                    "unified audit custody authority or tenant namespace is invalid",
                )
            )
    if _table_enabled(cfg, ("assessment_evidence_autopopulation",)) and not _table_enabled(
        cfg, ("ai_evidence_analysis",)
    ):
        findings.append(
            _nested_error(
                "assessment_evidence_autopopulation",
                "enable",
                "assessment evidence proposals require ai_evidence_analysis.enable = true",
            )
        )
    return findings


def _lint_discovery_scheduler_contracts(cfg: dict) -> list[Finding]:
    """Check scanner, discovery, and remediation dependencies."""
    findings: list[Finding] = []
    consent_scanner = ("consent_preferences", "scanner")
    consent_scan_scheduler = (
        "consent_preferences",
        "scanner",
        "scheduler",
    )
    consent_scan_notice_proposals = (
        "consent_preferences",
        "scanner",
        "notice_proposals",
    )
    privacy_discovery = ("privacy_automation", "data_discovery")
    privacy_discovery_adapters = privacy_discovery + ("adapters",)
    privacy_discovery_remediation = privacy_discovery + ("remediation",)
    privacy_discovery_data_map = privacy_discovery_remediation + ("data_map",)
    privacy_discovery_scheduler = privacy_discovery_remediation + ("scheduler",)
    if _table_enabled(cfg, consent_scan_scheduler) and not _table_enabled(cfg, consent_scanner):
        findings.append(
            _nested_error(
                "consent_preferences.scanner.scheduler",
                "enable",
                "consent scan scheduler requires consent scanner to be enabled",
            )
        )
    if _table_enabled(cfg, consent_scan_notice_proposals) and not _table_enabled(
        cfg, consent_scanner
    ):
        findings.append(
            _nested_error(
                "consent_preferences.scanner.notice_proposals",
                "enable",
                "consent scan notice proposals require consent scanner to be enabled",
            )
        )
    if _table_enabled(cfg, privacy_discovery_adapters):
        if not _table_enabled(cfg, privacy_discovery):
            findings.append(
                _nested_error(
                    "privacy_automation.data_discovery.adapters",
                    "enable",
                    "stock discovery adapters require privacy data discovery to be enabled",
                )
            )
        adapters = _at_path(cfg, privacy_discovery_adapters)
        providers = adapters.get("enabled_providers") if isinstance(adapters, dict) else None
        admitted = {
            "aws_s3",
            "azure_blob",
            "google_cloud_storage",
            "snowflake_metadata",
            "servicenow_cmdb",
            "entra_assets",
        }
        if (
            not isinstance(providers, list)
            or not providers
            or len(providers) > len(admitted)
            or any(not isinstance(item, str) or item not in admitted for item in providers)
            or len(set(providers)) != len(providers)
        ):
            findings.append(
                _nested_error(
                    "privacy_automation.data_discovery.adapters",
                    "enabled_providers",
                    "enabled stock discovery providers must be a unique non-empty admitted list",
                )
            )
    if _table_enabled(cfg, privacy_discovery_remediation) and not _table_enabled(
        cfg, privacy_discovery
    ):
        findings.append(
            _nested_error(
                "privacy_automation.data_discovery.remediation",
                "enable",
                "discovery remediation requires privacy data discovery to be enabled",
            )
        )
    if _table_enabled(cfg, privacy_discovery_data_map) and not _table_enabled(
        cfg, privacy_discovery_remediation
    ):
        findings.append(
            _nested_error(
                "privacy_automation.data_discovery.remediation.data_map",
                "enable",
                "the discovery data-map target requires remediation to be enabled",
            )
        )
    if _table_enabled(cfg, privacy_discovery_remediation) and not _table_enabled(
        cfg, privacy_discovery_data_map
    ):
        findings.append(
            _nested_error(
                "privacy_automation.data_discovery.remediation",
                "enable",
                "stock privacy discovery remediation requires data_map.enable = true",
            )
        )
    if _table_enabled(cfg, privacy_discovery_scheduler) and not _table_enabled(
        cfg, privacy_discovery_remediation
    ):
        findings.append(
            _nested_error(
                "privacy_automation.data_discovery.remediation.scheduler",
                "enable",
                "the discovery remediation scheduler requires remediation to be enabled",
            )
        )
    scheduler_table = _at_path(cfg, privacy_discovery_scheduler)
    if isinstance(scheduler_table, dict):
        interval = scheduler_table.get("interval_seconds", 60)
        jitter = scheduler_table.get("jitter_seconds", 10)
        if (
            isinstance(interval, int)
            and not isinstance(interval, bool)
            and isinstance(jitter, int)
            and not isinstance(jitter, bool)
            and jitter > interval
        ):
            findings.append(
                _nested_error(
                    "privacy_automation.data_discovery.remediation.scheduler",
                    "jitter_seconds",
                    "scheduler jitter_seconds cannot exceed interval_seconds",
                )
            )
    compliance_scoping = ("tech_risk_compliance", "scoping")
    compliance_scope_actions = ("tech_risk_compliance", "scope_actions")
    if _table_enabled(cfg, compliance_scope_actions) and not _table_enabled(
        cfg, compliance_scoping
    ):
        findings.append(
            _nested_error(
                "tech_risk_compliance.scope_actions",
                "enable",
                "compliance scope actions require compliance scoping to be enabled",
            )
        )
    return findings


def _lint_consent_public_contracts(cfg: dict) -> list[Finding]:
    """Check public consent, trust-center, and publishing dependencies."""
    findings: list[Finding] = []
    consent_public = ("consent_preferences", "public_api")
    consent_publishing = ("consent_preferences", "publishing")
    consent_web_settings = (
        "consent_preferences",
        "publishing",
        "web_settings",
    )
    consent_trust_center = ("consent_preferences", "trust_center")
    consent_trust_center_branding = consent_trust_center + ("branding",)
    consent_profile_data = ("consent_preferences", "profile_data")
    consent_custom_index = (
        "consent_preferences",
        "profile_data",
        "custom_index",
    )
    consent_global_opt_out = ("consent_preferences", "global_opt_out")
    if _table_enabled(cfg, consent_public) and not _table_enabled(cfg, consent_publishing):
        findings.append(
            _nested_error(
                "consent_preferences.public_api",
                "enable",
                "public consent API requires consent publishing to be enabled",
            )
        )
    if _table_enabled(cfg, consent_web_settings) and not _table_enabled(cfg, consent_publishing):
        findings.append(
            _nested_error(
                "consent_preferences.publishing.web_settings",
                "enable",
                "website publish settings require consent publishing to be enabled",
            )
        )
    if _table_enabled(cfg, consent_trust_center) and not (
        _table_enabled(cfg, consent_public) and _table_enabled(cfg, consent_publishing)
    ):
        findings.append(
            _nested_error(
                "consent_preferences.trust_center",
                "enable",
                "consumer trust center requires consent publishing and the public API",
            )
        )
    if _table_enabled(cfg, consent_custom_index) and not _table_enabled(cfg, consent_profile_data):
        findings.append(
            _nested_error(
                "consent_preferences.profile_data.custom_index",
                "enable",
                "custom data-element indexes require consent profile data to be enabled",
            )
        )
    if _table_enabled(cfg, consent_global_opt_out) and not _table_enabled(
        cfg,
        ("privacy_automation", "rights_consumer_intake"),
    ):
        findings.append(
            _nested_error(
                "consent_preferences.global_opt_out",
                "enable",
                "Global Opt-Out requires authenticated consumer privacy-rights intake",
            )
        )
    if _table_enabled(cfg, consent_trust_center_branding) and not _table_enabled(
        cfg, consent_trust_center
    ):
        findings.append(
            _nested_error(
                "consent_preferences.trust_center.branding",
                "enable",
                "Trust Center branding requires the consumer Trust Center",
            )
        )
    branding = _at_path(cfg, consent_trust_center_branding)
    if isinstance(branding, dict):
        key_ref = branding.get("key_ref", _MISSING)
        if key_ref is not _MISSING and (
            not isinstance(key_ref, str)
            or key_ref != "env:MAVERICK_TRUST_CENTER_BRAND_ASSET_KEY"
        ):
            findings.append(
                _nested_error(
                    "consent_preferences.trust_center.branding",
                    "key_ref",
                    "Trust Center brand custody uses the deployment-held asset key reference",
                )
            )
        max_width = branding.get("max_width")
        max_height = branding.get("max_height")
        max_pixels = branding.get("max_pixels")
        if all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in (max_width, max_height, max_pixels)
        ) and max_pixels > max_width * max_height:
            findings.append(
                _nested_error(
                    "consent_preferences.trust_center.branding",
                    "max_pixels",
                    "Trust Center brand pixel capacity cannot exceed width times height",
                )
            )
    return findings


def _lint_consent_native_contracts(cfg: dict) -> list[Finding]:
    """Check native consent SDK authority and key requirements."""
    findings: list[Finding] = []
    consent_native_sdk = ("consent_preferences", "native_sdk")
    consent_public = ("consent_preferences", "public_api")
    consent_publishing = ("consent_preferences", "publishing")
    if _table_enabled(cfg, consent_native_sdk):
        required_native_authorities = (consent_publishing, consent_public)
        missing = [
            ".".join(path)
            for path in required_native_authorities
            if not _table_enabled(cfg, path)
        ]
        if missing:
            findings.append(
                _nested_error(
                    "consent_preferences.native_sdk",
                    "enable",
                    "native consent SDK requires enabled authority: " + ", ".join(missing),
                )
            )
        native = _at_path(cfg, consent_native_sdk)
        if isinstance(native, dict):
            key_id = native.get("receipt_key_id")
            if (
                not isinstance(key_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", key_id) is None
            ):
                findings.append(
                    _nested_error(
                        "consent_preferences.native_sdk",
                        "receipt_key_id",
                        "enabled native consent requires a bounded receipt key id",
                    )
                )
            secret_ref = native.get("receipt_key_secret_ref")
            if (
                not isinstance(secret_ref, str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", secret_ref) is None
            ):
                findings.append(
                    _nested_error(
                        "consent_preferences.native_sdk",
                        "receipt_key_secret_ref",
                        "enabled native consent requires an uppercase environment secret reference",
                    )
                )
            if native.get("require_profile_linking") is True and not _table_enabled(
                cfg, ("consent_preferences", "identity")
            ):
                findings.append(
                    _nested_error(
                        "consent_preferences.native_sdk",
                        "require_profile_linking",
                        "native profile linking requires consent identity to be enabled",
                    )
                )
            if native.get("require_rights_requests") is True and not _table_enabled(
                cfg, ("privacy_automation", "rights_consumer_intake")
            ):
                findings.append(
                    _nested_error(
                        "consent_preferences.native_sdk",
                        "require_rights_requests",
                        "native rights requests require authenticated consumer privacy-rights intake",
                    )
                )
    return findings


def _lint_continuous_evidence(cfg: dict) -> list[Finding]:
    """Check continuous evidence and its scheduler."""
    findings: list[Finding] = []
    continuous_evidence = ("tech_risk_compliance", "continuous_evidence")
    continuous_evidence_scheduler = (
        "tech_risk_compliance",
        "continuous_evidence",
        "scheduler",
    )
    if _table_enabled(cfg, continuous_evidence_scheduler) and not _table_enabled(
        cfg, continuous_evidence
    ):
        findings.append(
            _nested_error(
                "tech_risk_compliance.continuous_evidence.scheduler",
                "enable",
                "continuous-evidence scheduler requires continuous evidence to be enabled",
            )
        )
    continuous_table = _at_path(cfg, continuous_evidence)
    if isinstance(continuous_table, dict) and continuous_table.get("enable") is True:
        collectors = continuous_table.get("enabled_collectors")
        if (
            not isinstance(collectors, list)
            or not collectors
            or len(collectors) > 32
            or any(
                not isinstance(item, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", item) is None
                for item in collectors
            )
            or len(set(collectors)) != len(collectors)
        ):
            findings.append(
                _nested_error(
                    "tech_risk_compliance.continuous_evidence",
                    "enabled_collectors",
                    "enabled continuous evidence requires a unique closed collector allowlist",
                )
            )
    return findings


def _lint_rights_delivery_contracts(cfg: dict) -> list[Finding]:
    """Check privacy-rights delivery, intake, and lifecycle admission."""
    findings: list[Finding] = []
    rights_consumer_delivery = (
        "privacy_automation",
        "rights_consumer_delivery",
    )
    if _table_enabled(cfg, rights_consumer_delivery) and not _table_enabled(
        cfg,
        ("privacy_automation", "rights_orchestration"),
    ):
        findings.append(
            _nested_error(
                "privacy_automation.rights_consumer_delivery",
                "enable",
                "rights consumer delivery requires rights orchestration to be enabled",
            )
        )
    if _table_enabled(cfg, rights_consumer_delivery):
        delivery_table = _at_path(cfg, rights_consumer_delivery)
        assert isinstance(delivery_table, dict)
        for key in (
            "digest_key_ref",
            "export_signing_key_ref",
            "package_encryption_key_ref",
        ):
            if not _is_rights_delivery_key_reference(delivery_table.get(key)):
                findings.append(
                    _nested_error(
                        "privacy_automation.rights_consumer_delivery",
                        key,
                        "enabled rights consumer delivery requires an uppercase "
                        "env:, vault:, or secret: key reference",
                    )
                )
        for key in ("server_grant_ttl_seconds", "max_package_bytes"):
            if key not in delivery_table:
                findings.append(
                    _nested_error(
                        "privacy_automation.rights_consumer_delivery",
                        key,
                        f"enabled rights consumer delivery requires {key}",
                    )
                )
    rights_consumer_intake = (
        "privacy_automation",
        "rights_consumer_intake",
    )
    if _table_enabled(cfg, rights_consumer_intake):
        required_intake_authorities = (
            ("privacy_automation", "rights_orchestration"),
            ("consent_preferences", "publishing"),
            ("consent_preferences", "public_api"),
            ("consent_preferences", "trust_center"),
        )
        missing = [
            ".".join(path) for path in required_intake_authorities if not _table_enabled(cfg, path)
        ]
        if missing:
            findings.append(
                _nested_error(
                    "privacy_automation.rights_consumer_intake",
                    "enable",
                    "consumer rights intake requires enabled authority: " + ", ".join(missing),
                )
            )
        tenant_limit = _at_path(cfg, rights_consumer_intake + ("max_active_requests",))
        subject_limit = _at_path(
            cfg,
            rights_consumer_intake + ("max_active_requests_per_subject",),
        )
        if (
            isinstance(tenant_limit, int)
            and not isinstance(tenant_limit, bool)
            and isinstance(subject_limit, int)
            and not isinstance(subject_limit, bool)
            and subject_limit > tenant_limit
        ):
            findings.append(
                _nested_error(
                    "privacy_automation.rights_consumer_intake",
                    "max_active_requests_per_subject",
                    "per-subject active request limit must not exceed the tenant limit",
                )
            )
    ott_ctv_rights = ("privacy_automation", "ott_ctv_rights")
    if _table_enabled(cfg, ott_ctv_rights):
        required_ott_ctv_authorities = (
            ("privacy_automation", "rights_orchestration"),
            ("consent_preferences", "publishing"),
            ("consent_preferences", "public_api"),
            ("consent_preferences", "identity"),
            ("consent_preferences", "trust_center"),
        )
        missing = [
            ".".join(path) for path in required_ott_ctv_authorities if not _table_enabled(cfg, path)
        ]
        if missing:
            findings.append(
                _nested_error(
                    "privacy_automation.ott_ctv_rights",
                    "enable",
                    "OTT/CTV rights require enabled authority: " + ", ".join(missing),
                )
            )
    drop_management = ("privacy_automation", "drop_management")
    if _table_enabled(cfg, drop_management):
        if not _table_enabled(cfg, ("privacy_automation", "rights_orchestration")):
            findings.append(
                _nested_error(
                    "privacy_automation.drop_management",
                    "enable",
                    "DROP management requires privacy rights orchestration to be enabled",
                )
            )
        principal_key_ref = _at_path(cfg, drop_management + ("principal_binding_key_ref",))
        if not _is_drop_principal_key_reference(principal_key_ref):
            findings.append(
                _nested_error(
                    "privacy_automation.drop_management",
                    "principal_binding_key_ref",
                    "enabled DROP management requires a bounded env/KMS secret-provider reference",
                )
            )
        interval = _at_path(cfg, drop_management + ("scheduler_interval_seconds",))
        jitter = _at_path(cfg, drop_management + ("scheduler_jitter_seconds",))
        if (
            isinstance(interval, int)
            and not isinstance(interval, bool)
            and isinstance(jitter, int)
            and not isinstance(jitter, bool)
            and jitter >= interval
        ):
            findings.append(
                _nested_error(
                    "privacy_automation.drop_management",
                    "scheduler_jitter_seconds",
                    "DROP scheduler jitter must be smaller than its interval",
                )
            )
    return findings


def _lint_portal_identity_storage(cfg: dict, consent_public: tuple, consent_publishing: tuple) -> list[Finding]:
    """Check consent identity, storage, and portal dependencies."""
    findings: list[Finding] = []
    if _table_enabled(cfg, ("consent_preferences", "edge_cache")) and not (
        _table_enabled(cfg, consent_public)
    ):
        findings.append(
            _nested_error(
                "consent_preferences.edge_cache",
                "enable",
                "consent edge cache requires the public API to be enabled",
            )
        )
    lifecycle_portal = (
        "third_party_management",
        "lifecycle",
        "portal",
    )
    if _table_enabled(cfg, lifecycle_portal) and not _table_enabled(
        cfg,
        ("third_party_management", "lifecycle"),
    ):
        findings.append(
            _nested_error(
                "third_party_management.lifecycle.portal",
                "enable",
                "third-party collaboration portal requires lifecycle to be enabled",
            )
        )
    third_party_contracts = ("third_party_management", "contracts")
    if _table_enabled(cfg, third_party_contracts) and not _table_enabled(
        cfg,
        ("third_party_management", "intelligence"),
    ):
        findings.append(
            _nested_error(
                "third_party_management.contracts",
                "enable",
                "third-party contracts require the local intelligence vendor authority",
            )
        )

    identity = _at_path(cfg, ("consent_preferences", "identity"))
    if isinstance(identity, dict) and identity.get("enable") is True:
        if not (_table_enabled(cfg, consent_public) and _table_enabled(cfg, consent_publishing)):
            findings.append(
                _nested_error(
                    "consent_preferences.identity",
                    "enable",
                    "consent identity requires consent publishing and the public API",
                )
            )
        for key in ("issuer", "audience"):
            value = identity.get(key)
            if not isinstance(value, str) or not value.strip():
                findings.append(
                    _nested_error(
                        "consent_preferences.identity",
                        key,
                        f"enabled consent identity requires a non-empty {key}",
                    )
                )
        if not _is_https_origin(identity.get("jwks_origin")):
            findings.append(
                _nested_error(
                    "consent_preferences.identity",
                    "jwks_origin",
                    "enabled consent identity requires an exact HTTPS JWKS origin",
                )
            )
        token_ttl = identity.get("token_ttl_seconds", 600)
        lifecycle_retention = identity.get(
            "link_lifecycle_retention_seconds",
            90 * 24 * 60 * 60,
        )
        if (
            isinstance(token_ttl, int)
            and not isinstance(token_ttl, bool)
            and isinstance(lifecycle_retention, int)
            and not isinstance(lifecycle_retention, bool)
            and lifecycle_retention < token_ttl
        ):
            findings.append(
                _nested_error(
                    "consent_preferences.identity",
                    "link_lifecycle_retention_seconds",
                    "identity link lifecycle retention cannot be shorter than the token TTL",
                )
            )

    storage = _at_path(cfg, ("consent_preferences", "storage"))
    if isinstance(storage, dict):
        backend = storage.get("backend", _MISSING)
        if backend is not _MISSING and backend not in {"sqlite", "postgres"}:
            findings.append(
                _nested_error(
                    "consent_preferences.storage",
                    "backend",
                    "consent storage backend must be 'sqlite' or 'postgres'",
                )
            )
        secret_ref = storage.get("dsn_secret_ref", _MISSING)
        if secret_ref is not _MISSING and secret_ref not in ("", None) and (
            not isinstance(secret_ref, str)
            or not re.fullmatch(r"\$?[A-Z][A-Z0-9_]{2,63}", secret_ref.strip())
        ):
            findings.append(
                _nested_error(
                    "consent_preferences.storage",
                    "dsn_secret_ref",
                    "consent storage dsn_secret_ref must name an environment variable",
                )
            )

    return findings


def _lint_evidence_analysis(cfg: dict) -> list[Finding]:
    """Validate local evidence parser, OCR, and spreadsheet configuration."""
    findings: list[Finding] = []
    evidence_table = _at_path(cfg, ("ai_evidence_analysis",))
    if isinstance(evidence_table, dict):
        media = evidence_table.get("enabled_media_types")
        media_values = (
            {item for item in media if isinstance(item, str)}
            if isinstance(media, list)
            else set()
        )
        parent_enabled = evidence_table.get("enable") is True
        maximum_output = evidence_table.get("max_extracted_text_bytes", 1_048_576)
        parser_sandbox = evidence_table.get("parser_sandbox")
        parser_sandbox_enabled = (
            isinstance(parser_sandbox, dict) and parser_sandbox.get("enable") is True
        )
        ocr = evidence_table.get("ocr")
        ocr_enabled = isinstance(ocr, dict) and ocr.get("enable") is True
        legacy_xls = evidence_table.get("legacy_xls")
        legacy_enabled = (
            isinstance(legacy_xls, dict) and legacy_xls.get("enable") is True
        )
        findings.extend(_lint_evidence_sandbox(parser_sandbox, parser_sandbox_enabled, ocr_enabled, legacy_enabled))
        findings.extend(_lint_evidence_ocr(ocr, ocr_enabled, parent_enabled, media_values, maximum_output))
        findings.extend(_lint_evidence_legacy(legacy_xls, legacy_enabled, parent_enabled, media_values, maximum_output))
    return findings


def _lint_evidence_sandbox(parser_sandbox, parser_sandbox_enabled, ocr_enabled, legacy_enabled) -> list[Finding]:
    findings: list[Finding] = []
    if (ocr_enabled or legacy_enabled) and not parser_sandbox_enabled:
        findings.append(
            _nested_error(
                "ai_evidence_analysis.parser_sandbox",
                "enable",
                "enabled local parsers require an enforceable parser sandbox",
            )
        )
    if parser_sandbox_enabled and not (ocr_enabled or legacy_enabled):
        findings.append(
            _nested_error(
                "ai_evidence_analysis.parser_sandbox",
                "enable",
                "parser sandbox requires at least one enabled local parser worker",
            )
        )
    if parser_sandbox_enabled and isinstance(parser_sandbox, dict):
        if parser_sandbox.get("mode") != "bubblewrap":
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.parser_sandbox",
                    "mode",
                    "local parser sandbox mode must be bubblewrap",
                )
            )
        if not _is_absolute_path(parser_sandbox.get("launcher")):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.parser_sandbox",
                    "launcher",
                    "sandbox launcher must be an absolute path",
                )
            )
        if not _is_lower_sha256(parser_sandbox.get("launcher_sha256")):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.parser_sandbox",
                    "launcher_sha256",
                    "sandbox launcher requires an exact lowercase SHA-256 digest",
                )
            )
        if not _is_exact_dependency_version(parser_sandbox.get("launcher_version")):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.parser_sandbox",
                    "launcher_version",
                    "sandbox launcher requires an exact version",
                )
            )
    return findings


def _lint_evidence_ocr(ocr, ocr_enabled, parent_enabled, media_values, maximum_output) -> list[Finding]:
    findings: list[Finding] = []
    if ocr_enabled:
        if not parent_enabled:
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.ocr",
                    "enable",
                    "enabled OCR requires ai_evidence_analysis.enable = true",
                )
            )
        if not media_values.intersection({"jpeg", "png"}):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.ocr",
                    "enable",
                    "enabled OCR requires jpeg or png in enabled_media_types",
                )
            )
        for key in ("executable", "traineddata_path"):
            value = ocr.get(key)
            if not _is_absolute_path(value):
                findings.append(
                    _nested_error(
                        "ai_evidence_analysis.ocr",
                        key,
                        f"enabled OCR requires an absolute {key}",
                    )
                )
        for key in ("tesseract_version", "pillow_version"):
            if not _is_exact_dependency_version(ocr.get(key)):
                findings.append(
                    _nested_error(
                        "ai_evidence_analysis.ocr",
                        key,
                        f"enabled OCR requires an exact bounded {key}",
                    )
                )
        for key in (
            "executable_sha256",
            "traineddata_sha256",
            "runtime_libraries_sha256",
            "pillow_manifest_sha256",
        ):
            if _is_lower_sha256(ocr.get(key)):
                continue
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.ocr",
                    key,
                    f"enabled OCR requires an exact lowercase {key} digest",
                )
            )
        runtime_paths = ocr.get("runtime_library_paths")
        if (
            not isinstance(runtime_paths, list)
            or not 1 <= len(runtime_paths) <= 512
            or len(runtime_paths) != len(set(runtime_paths))
            or any(not _is_absolute_path(path) for path in runtime_paths)
        ):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.ocr",
                    "runtime_library_paths",
                    "enabled OCR requires unique absolute runtime library paths",
                )
            )
        if (
            isinstance(ocr.get("max_output_bytes"), int)
            and not isinstance(ocr.get("max_output_bytes"), bool)
            and isinstance(maximum_output, int)
            and not isinstance(maximum_output, bool)
            and ocr["max_output_bytes"] > maximum_output
        ):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.ocr",
                    "max_output_bytes",
                    "OCR output bound cannot exceed max_extracted_text_bytes",
                )
            )
    return findings


def _lint_evidence_legacy(legacy_xls, legacy_enabled, parent_enabled, media_values, maximum_output) -> list[Finding]:
    findings: list[Finding] = []
    if "xls" in media_values and not legacy_enabled:
        findings.append(
            _nested_error(
                "ai_evidence_analysis.legacy_xls",
                "enable",
                "xls media requires the legacy XLS parser to be explicitly enabled",
            )
        )
    if legacy_enabled and isinstance(legacy_xls, dict):
        if not parent_enabled or "xls" not in media_values:
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.legacy_xls",
                    "enable",
                    "enabled legacy XLS parsing requires AI evidence analysis and xls media",
                )
            )
        for key in ("xlrd_version", "olefile_version"):
            if not _is_exact_dependency_version(legacy_xls.get(key)):
                findings.append(
                    _nested_error(
                        "ai_evidence_analysis.legacy_xls",
                        key,
                        f"enabled legacy XLS parsing requires an exact {key}",
                    )
                )
        for key in ("xlrd_manifest_sha256", "olefile_manifest_sha256"):
            if not _is_lower_sha256(legacy_xls.get(key)):
                findings.append(
                    _nested_error(
                        "ai_evidence_analysis.legacy_xls",
                        key,
                        f"enabled legacy XLS parsing requires an exact {key}",
                    )
                )
        stream_bound = legacy_xls.get("max_workbook_stream_bytes")
        record_bound = legacy_xls.get("max_record_bytes")
        if (
            isinstance(stream_bound, int)
            and not isinstance(stream_bound, bool)
            and isinstance(record_bound, int)
            and not isinstance(record_bound, bool)
            and record_bound > stream_bound
        ):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.legacy_xls",
                    "max_record_bytes",
                    "legacy XLS record bound cannot exceed its workbook stream bound",
                )
            )
        xls_output = legacy_xls.get("max_output_bytes")
        if (
            isinstance(xls_output, int)
            and not isinstance(xls_output, bool)
            and isinstance(maximum_output, int)
            and not isinstance(maximum_output, bool)
            and xls_output > maximum_output
        ):
            findings.append(
                _nested_error(
                    "ai_evidence_analysis.legacy_xls",
                    "max_output_bytes",
                    "legacy XLS output bound cannot exceed max_extracted_text_bytes",
                )
            )
    return findings


def _lint_governance_capabilities(cfg: dict) -> list[Finding]:
    """Check enabled governance authorities and closed capability lists."""
    findings: list[Finding] = []
    if _table_enabled(cfg, ("audit", "unified")):
        audit = cfg.get("audit")
        if not isinstance(audit, dict) or audit.get("sign") is not True:
            findings.append(
                _nested_error(
                    "audit.unified",
                    "enable",
                    "unified audit requires [audit] sign = true",
                )
            )
    if _table_enabled(cfg, ("ai_governance_loop",)):
        required_ai_loop_authorities = (
            ("ai_inventory",),
            ("ai_dynamic_risk",),
            ("ai_policy_management",),
            ("ai_runtime_guardrails",),
        )
        missing = [
            ".".join(path) for path in required_ai_loop_authorities if not _table_enabled(cfg, path)
        ]
        if missing:
            findings.append(
                _nested_error(
                    "ai_governance_loop",
                    "enable",
                    "AI governance loop requires enabled authority: " + ", ".join(missing),
                )
            )
    closed_capability_lists = (
        (
            ("governance_agents",),
            "enabled_agents",
            {
                "breach_response",
                "privacy_risk_assessment",
                "program_copilot",
                "knowledgebase_governance",
                "third_party_risk",
            },
        ),
        (
            ("ai_evidence_analysis",),
            "enabled_media_types",
            {"pdf", "jpeg", "png", "xls", "xlsx", "text"},
        ),
    )
    for path, key, allowed in closed_capability_lists:
        table = _at_path(cfg, path)
        if not isinstance(table, dict) or table.get("enable") is not True:
            continue
        values = table.get(key)
        if (
            not isinstance(values, list)
            or not values
            or len(values) > len(allowed)
            or any(not isinstance(item, str) or item not in allowed for item in values)
            or len(set(values)) != len(values)
        ):
            section = ".".join(path)
            findings.append(
                _nested_error(
                    section,
                    key,
                    f"enabled {section} requires a unique closed {key} allowlist",
                )
            )

    governance_agents = _at_path(cfg, ("governance_agents",))
    if (
        isinstance(governance_agents, dict)
        and governance_agents.get("context_projection_enable") is True
        and governance_agents.get("enable") is not True
    ):
        findings.append(
            _nested_error(
                "governance_agents",
                "context_projection_enable",
                "enabled governance-agent context projection requires governance_agents.enable = true",
            )
        )
    if _table_enabled(cfg, ("governance_agents",)):
        missing = []
        if not _table_enabled(cfg, ("evidence_gateway",)):
            missing.append("evidence_gateway")
        if missing:
            findings.append(
                _nested_error(
                    "governance_agents",
                    "enable",
                    "packaged governance agents require enabled authority: " + ", ".join(missing),
                )
            )
    if _table_enabled(cfg, ("ai_entity_tasks",)) and not _table_enabled(cfg, ("ai_inventory",)):
        findings.append(
            _nested_error(
                "ai_entity_tasks",
                "enable",
                "AI entity task management requires ai_inventory.enable = true",
            )
        )
    if _table_enabled(cfg, ("ai_evidence_analysis",)) and not _table_enabled(
        cfg, ("evidence_gateway",)
    ):
        findings.append(
            _nested_error(
                "ai_evidence_analysis",
                "enable",
                "AI evidence analysis requires evidence_gateway.enable = true",
            )
        )
    return findings


def _lint_governed_documents(cfg: dict) -> list[Finding]:
    """Check governed document and attachment settings."""
    findings: list[Finding] = []
    document_access = _at_path(cfg, ("administration_document_access",))
    if isinstance(document_access, dict):
        default_ttl = document_access.get("default_ttl_seconds", 300)
        maximum_ttl = document_access.get("max_ttl_seconds", 900)
        delivery_ttl = document_access.get("delivery_grant_ttl_seconds", 60)
        if (
            isinstance(default_ttl, int)
            and not isinstance(default_ttl, bool)
            and isinstance(maximum_ttl, int)
            and not isinstance(maximum_ttl, bool)
            and default_ttl > maximum_ttl
        ):
            findings.append(
                _nested_error(
                    "administration_document_access",
                    "default_ttl_seconds",
                    "administration document-access default TTL cannot exceed its maximum TTL",
                )
            )
        if (
            isinstance(delivery_ttl, int)
            and not isinstance(delivery_ttl, bool)
            and isinstance(maximum_ttl, int)
            and not isinstance(maximum_ttl, bool)
            and delivery_ttl > maximum_ttl
        ):
            findings.append(
                _nested_error(
                    "administration_document_access",
                    "delivery_grant_ttl_seconds",
                    "administration document-access delivery grant TTL cannot exceed its maximum TTL",
                )
            )
        if document_access.get("enable") is True:
            audit = cfg.get("audit")
            if not isinstance(audit, dict) or audit.get("sign") is not True:
                findings.append(
                    _nested_error(
                        "administration_document_access",
                        "enable",
                        "administration document access requires audit.sign = true",
                    )
                )

    document_vault = _at_path(cfg, ("governed_document_vault",))
    if isinstance(document_vault, dict):
        media_types = document_vault.get("allowed_media_types", _MISSING)
        if media_types is not _MISSING:
            from .governed_document_vault import DEFAULT_MEDIA_TYPES

            valid_media_types = (
                isinstance(media_types, list)
                and 1 <= len(media_types) <= len(DEFAULT_MEDIA_TYPES)
                and len(media_types) == len(set(media_types))
                and all(
                    isinstance(item, str)
                    and item == item.strip().lower()
                    and item in DEFAULT_MEDIA_TYPES
                    for item in media_types
                )
            )
            if not valid_media_types:
                findings.append(
                    _nested_error(
                        "governed_document_vault",
                        "allowed_media_types",
                        "document vault media types must be a unique non-empty product allowlist",
                    )
                )
        if document_vault.get("enable") is True and not _table_enabled(
            cfg, ("administration_document_access",)
        ):
            findings.append(
                _nested_error(
                    "governed_document_vault",
                    "enable",
                    "governed document vault requires administration_document_access.enable = true",
                )
            )

    incident_attachments = _at_path(cfg, ("incident_attachment_metadata",))
    if isinstance(incident_attachments, dict):
        media_types = incident_attachments.get("allowed_media_types", _MISSING)
        if media_types is not _MISSING:
            from .incident_attachment_metadata import DEFAULT_MEDIA_TYPES

            valid_media_types = (
                isinstance(media_types, list)
                and 1 <= len(media_types) <= 128
                and len(media_types) == len(set(media_types))
                and all(
                    isinstance(item, str)
                    and item == item.strip().lower()
                    and item in DEFAULT_MEDIA_TYPES
                    for item in media_types
                )
            )
            if not valid_media_types:
                findings.append(
                    _nested_error(
                        "incident_attachment_metadata",
                        "allowed_media_types",
                        "incident attachment media types must be a unique non-empty product allowlist",
                    )
                )
        if incident_attachments.get("enable") is True and not _table_enabled(
            cfg, ("administration_document_access",)
        ):
            findings.append(
                _nested_error(
                    "incident_attachment_metadata",
                    "enable",
                    "incident attachment metadata requires administration_document_access.enable = true",
                )
            )
        if (
            incident_attachments.get("enable") is True
            and isinstance(document_vault, dict)
            and document_vault.get("enable") is True
        ):
            from .governed_document_vault import (
                DEFAULT_MEDIA_TYPES as VAULT_DEFAULT_MEDIA_TYPES,
            )

            vault_media_types = document_vault.get(
                "allowed_media_types", list(VAULT_DEFAULT_MEDIA_TYPES)
            )
            incident_media_types = incident_attachments.get(
                "allowed_media_types", list(VAULT_DEFAULT_MEDIA_TYPES)
            )
            if (
                isinstance(vault_media_types, list)
                and isinstance(incident_media_types, list)
                and all(isinstance(item, str) for item in vault_media_types)
                and all(isinstance(item, str) for item in incident_media_types)
                and not set(incident_media_types).issubset(vault_media_types)
            ):
                findings.append(
                    _nested_error(
                        "incident_attachment_metadata",
                        "allowed_media_types",
                        "incident attachment media types must be a subset of "
                        "governed_document_vault.allowed_media_types when the stock vault is enabled",
                    )
                )
    return findings


def _lint_governance_dependencies(cfg: dict) -> list[Finding]:
    """Check product governance and inventory dependencies."""
    findings: list[Finding] = []
    governance_inventory = cfg.get("governance_inventory")
    entity_graph = cfg.get("entity_graph")
    if (
        isinstance(governance_inventory, dict)
        and governance_inventory.get("enable") is True
        and isinstance(entity_graph, dict)
        and entity_graph.get("enable") is False
    ):
        findings.append(
            _nested_error(
                "governance_inventory",
                "enable",
                "enabled governance_inventory requires [entity_graph] enable = true",
            )
        )

    for path, bool_keys in _NESTED_BOOL_KEYS.items():
        table = _at_path(cfg, path)
        if not isinstance(table, dict):
            continue
        section = ".".join(path)
        for key in bool_keys:
            value = table.get(key, _MISSING)
            if value is not _MISSING and not isinstance(value, bool):
                findings.append(
                    _nested_error(
                        section,
                        key,
                        f"{section}.{key} must be true or false, got {type(value).__name__}",
                    )
                )

    for (path, key), (lower, upper) in _NESTED_INTEGER_BOUNDS.items():
        table = _at_path(cfg, path)
        if not isinstance(table, dict):
            continue
        value = table.get(key, _MISSING)
        if value is _MISSING:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
            section = ".".join(path)
            findings.append(
                _nested_error(
                    section,
                    key,
                    f"{section}.{key} must be an integer between "
                    f"{lower} and {upper}, got {value!r}",
                )
            )

    for (path, key), (lower, upper) in _NESTED_NUMBER_BOUNDS.items():
        table = _at_path(cfg, path)
        if not isinstance(table, dict):
            continue
        value = table.get(key, _MISSING)
        if value is _MISSING:
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not lower <= float(value) <= upper
        ):
            section = ".".join(path)
            findings.append(
                _nested_error(
                    section,
                    key,
                    f"{section}.{key} must be a number between "
                    f"{lower} and {upper}, got {value!r}",
                )
            )

    for root in (
        "consent_preferences",
        "data_use_governance",
        "privacy_automation",
        "tech_risk_compliance",
        "third_party_management",
    ):
        root_table = cfg.get(root)
        root_enabled = isinstance(root_table, dict) and root_table.get("enable") is True
        for path in _NESTED_BOOL_KEYS:
            if path[0] != root or not _table_enabled(cfg, path):
                continue
            if not root_enabled:
                section = ".".join(path)
                findings.append(
                    _nested_error(
                        section,
                        "enable",
                        f"enabled {section} requires [{root}] enable = true",
                    )
                )

    return findings


def _lint_data_use_provider_contracts(cfg: dict) -> list[Finding]:
    """Validate the compiler, enforcement, and provider authority relationship."""
    findings: list[Finding] = []
    compiler_enabled = _table_enabled(cfg, ("data_use_governance", "compiler"))
    enforcement_enabled = _table_enabled(cfg, ("data_use_governance", "enforcement"))
    providers_enabled = any(
        _table_enabled(cfg, ("data_use_governance", provider))
        for provider in ("snowflake", "databricks")
    )
    if enforcement_enabled and not compiler_enabled:
        findings.append(
            _nested_error(
                "data_use_governance.enforcement",
                "enable",
                "data-use enforcement requires the policy compiler",
            )
        )
    if enforcement_enabled and not providers_enabled:
        findings.append(
            _nested_error(
                "data_use_governance.enforcement",
                "enable",
                "data-use enforcement requires an explicitly enabled native provider",
            )
        )
    if providers_enabled and not enforcement_enabled:
        findings.append(
            _nested_error(
                "data_use_governance.enforcement",
                "enable",
                "native data-use providers require enforcement to be enabled",
            )
        )
    provider_audit_enabled = _table_enabled(cfg, ("data_use_governance", "provider_audit"))
    if provider_audit_enabled and not (enforcement_enabled and providers_enabled):
        findings.append(
            _nested_error(
                "data_use_governance.provider_audit",
                "enable",
                "provider audit requires enforcement and an enabled native provider",
            )
        )
    provider_audit_scheduler_enabled = _table_enabled(
        cfg,
        ("data_use_governance", "provider_audit", "scheduler"),
    )
    if provider_audit_scheduler_enabled and not provider_audit_enabled:
        findings.append(
            _nested_error(
                "data_use_governance.provider_audit.scheduler",
                "enable",
                "provider-audit scheduling requires provider audit to be enabled",
            )
        )
    provider_audit_table = _at_path(
        cfg,
        ("data_use_governance", "provider_audit"),
    )
    if isinstance(provider_audit_table, dict):
        audit_window = provider_audit_table.get("audit_window_seconds")
        retention = provider_audit_table.get("retention_seconds")
        if (
            isinstance(audit_window, int)
            and not isinstance(audit_window, bool)
            and isinstance(retention, int)
            and not isinstance(retention, bool)
            and retention < audit_window
        ):
            findings.append(
                _nested_error(
                    "data_use_governance.provider_audit",
                    "retention_seconds",
                    "provider-audit retention must cover the complete audit window",
                )
            )
    for provider in ("snowflake", "databricks"):
        path = ("data_use_governance", provider)
        table = _at_path(cfg, path)
        if not isinstance(table, dict) or table.get("enable") is not True:
            continue
        section = ".".join(path)
        if not _is_https_origin(table.get("origin")):
            findings.append(
                _nested_error(
                    section,
                    "origin",
                    f"enabled {provider} enforcement requires an exact HTTPS origin",
                )
            )
        secret_ref = table.get("credential_secret_ref")
        if not isinstance(secret_ref, str) or not secret_ref.strip().startswith("$"):
            findings.append(
                _nested_error(
                    section,
                    "credential_secret_ref",
                    f"enabled {provider} enforcement requires an "
                    "environment-backed credential_secret_ref",
                )
            )
    return findings


def _lint_third_party_provider_contracts(cfg: dict) -> list[Finding]:
    """Validate third-party provider and scheduler admission."""
    findings: list[Finding] = []
    tpi = ("third_party_management", "intelligence")
    tpi_providers = ("third_party_management", "intelligence", "providers")
    tpi_scheduler = (
        "third_party_management",
        "intelligence",
        "providers",
        "scheduler",
    )
    if _table_enabled(cfg, tpi_providers) and not _table_enabled(cfg, tpi):
        findings.append(
            _nested_error(
                "third_party_management.intelligence.providers",
                "enable",
                "third-party provider runtime requires intelligence to be enabled",
            )
        )
    if _table_enabled(cfg, tpi_scheduler) and not _table_enabled(cfg, tpi_providers):
        findings.append(
            _nested_error(
                "third_party_management.intelligence.providers.scheduler",
                "enable",
                "third-party provider scheduler requires the provider runtime",
            )
        )
    tpi_provider_table = _at_path(cfg, tpi_providers)
    if isinstance(tpi_provider_table, dict) and tpi_provider_table.get("enable") is True:
        provider_ids = tpi_provider_table.get("enabled_providers")
        allowed_provider_ids = {
            "riskrecon",
            "securityscorecard",
            "hacknotice",
            "supplywisdom",
            "iss_corporate_solutions",
            "generic_approved",
        }
        if (
            not isinstance(provider_ids, list)
            or not provider_ids
            or len(provider_ids) > len(allowed_provider_ids)
            or any(item not in allowed_provider_ids for item in provider_ids)
            or len(set(provider_ids)) != len(provider_ids)
        ):
            findings.append(
                _nested_error(
                    "third_party_management.intelligence.providers",
                    "enabled_providers",
                    "enabled third-party provider runtime requires a unique closed provider list",
                )
            )
        host_bindings = {
            "generic_approved": "generic_approved_host",
            "supplywisdom": "supplywisdom_host",
            "iss_corporate_solutions": "iss_corporate_solutions_host",
        }
        selected_provider_ids = set(provider_ids) if isinstance(provider_ids, list) else set()
        for provider_id, host_key in host_bindings.items():
            host = tpi_provider_table.get(host_key)
            if provider_id in selected_provider_ids and not _is_exact_hostname(host):
                findings.append(
                    _nested_error(
                        "third_party_management.intelligence.providers",
                        host_key,
                        f"{provider_id} requires one exact deployment-trusted hostname",
                    )
                )
            elif provider_id not in selected_provider_ids and host is not None:
                findings.append(
                    _nested_error(
                        "third_party_management.intelligence.providers",
                        host_key,
                        f"{host_key} cannot be set while {provider_id} is disabled",
                    )
                )
    return findings


def _lint_governance_retry_bounds(cfg: dict) -> list[Finding]:
    """Keep configured maximum retry delays above their corresponding base."""
    findings: list[Finding] = []
    for path in (
        ("consent_preferences", "delivery"),
        ("data_use_governance", "enforcement"),
    ):
        table = _at_path(cfg, path)
        if not isinstance(table, dict):
            continue
        base = table.get("retry_base_seconds")
        maximum = table.get("retry_max_seconds")
        if (
            isinstance(base, int)
            and not isinstance(base, bool)
            and isinstance(maximum, int)
            and not isinstance(maximum, bool)
            and maximum < base
        ):
            section = ".".join(path)
            findings.append(
                _nested_error(
                    section,
                    "retry_max_seconds",
                    f"{section}.retry_max_seconds must be at least retry_base_seconds",
                )
            )
    return findings


def _lint_governance_nested_tables(cfg: dict) -> list[Finding]:
    """Validate the few security-sensitive nested governance tables we own."""

    findings: list[Finding] = []
    for path, allowed in _NESTED_GOVERNANCE_SCHEMA.items():
        value = _at_path(cfg, path)
        if value is _MISSING:
            continue
        section = ".".join(path)
        if not isinstance(value, dict):
            findings.append(
                _nested_error(
                    ".".join(path[:-1]),
                    path[-1],
                    f"{section} must be a table, got {type(value).__name__}",
                )
            )
            continue
        for key in value:
            if isinstance(key, str) and key not in allowed:
                findings.append(
                    _nested_error(
                        section,
                        key,
                        f'unknown key "{key}" in [{section}]' + _suggest(key, sorted(allowed)),
                        severity="warning",
                    )
                )
        if len(path) == 4 and path[:3] == (
            "ai_identity_governance_connectors",
            "scheduler",
            "providers",
        ):
            findings.extend(_lint_identity_schedule_table(path, value))

    scheduler = _at_path(cfg, ("ai_identity_governance_connectors", "scheduler"))
    if isinstance(scheduler, dict):
        enabled = scheduler.get("enable", _MISSING)
        if enabled is not _MISSING and not isinstance(enabled, bool):
            findings.append(
                _nested_error(
                    "ai_identity_governance_connectors.scheduler",
                    "enable",
                    "ai_identity_governance_connectors.scheduler.enable must be "
                    f"true or false, got {type(enabled).__name__}",
                )
            )
        poll = scheduler.get("poll_seconds", _MISSING)
        if poll is not _MISSING and not _number_between(poll, 5, 3_600):
            findings.append(
                _nested_error(
                    "ai_identity_governance_connectors.scheduler",
                    "poll_seconds",
                    "ai_identity_governance_connectors.scheduler.poll_seconds "
                    f"must be between 5 and 3600, got {poll!r}",
                )
            )

    findings.extend(_lint_identity_controls(cfg))
    findings.extend(_lint_local_owner_totp(cfg))
    trust_roots = _at_path(cfg, ("ai_benchmark_exchange", "trust_roots"))
    if isinstance(trust_roots, dict):
        findings.extend(_lint_trust_root_keys(trust_roots))

    coordinator = _at_path(cfg, ("ai_benchmark_exchange", "coordinator"))
    if isinstance(coordinator, dict):
        section = "ai_benchmark_exchange.coordinator"
        enabled = coordinator.get("enable", _MISSING)
        if enabled is not _MISSING and not isinstance(enabled, bool):
            findings.append(
                _nested_error(
                    section,
                    "enable",
                    f"{section}.enable must be true or false, got {type(enabled).__name__}",
                )
            )
        origin = coordinator.get("origin", _MISSING)
        if origin is not _MISSING and not isinstance(origin, str):
            findings.append(
                _nested_error(
                    section,
                    "origin",
                    f"{section}.origin must be a string",
                )
            )
        if enabled is True and (not isinstance(origin, str) or not origin.strip()):
            findings.append(
                _nested_error(
                    section,
                    "origin",
                    f"enabled {section} requires an explicit origin",
                )
            )
        timeout = coordinator.get("timeout_seconds", _MISSING)
        if timeout is not _MISSING and not _number_between(timeout, 1, 60):
            findings.append(
                _nested_error(
                    section,
                    "timeout_seconds",
                    f"{section}.timeout_seconds must be between 1 and 60",
                )
            )
        for key, upper in (
            ("max_request_bytes", 256 * 1_024),
            ("max_response_bytes", 1_024 * 1_024),
        ):
            item = coordinator.get(key, _MISSING)
            if item is not _MISSING and (
                isinstance(item, bool) or not isinstance(item, int) or not 1_024 <= item <= upper
            ):
                findings.append(
                    _nested_error(
                        section,
                        key,
                        f"{section}.{key} must be an integer between 1024 and {upper}",
                    )
                )
    findings.extend(_lint_product_governance_contracts(cfg))
    return findings


def _lint_image_edit_models(cfg: dict) -> list[Finding]:
    from .image_edit_models import validate_model

    table = cfg.get("image_edit", {})
    if not isinstance(table, dict):
        return [Finding("image_edit", None, "error", "Image model settings must be a table.")]
    findings: list[Finding] = []
    for key in KNOWN_SCHEMA["image_edit"]:
        if key in table:
            try:
                validate_model(table[key])
            except ValueError as exc:
                findings.append(Finding("image_edit", key, "error", str(exc)))
    return findings


def lint_config(cfg: dict) -> list[Finding]:
    """Validate a loaded config dict and return findings (possibly empty).

    Never raises: anything we can't interpret is skipped rather than flagged.
    """
    findings: list[Finding] = []
    if not isinstance(cfg, dict):
        return findings

    known_sections = sorted(KNOWN_SCHEMA)

    for section, value in cfg.items():
        if not isinstance(section, str):
            continue

        if section not in KNOWN_SCHEMA:
            findings.append(
                Finding(
                    section=section,
                    key=None,
                    severity="warning",
                    message=(
                        f'unknown config section "{section}"' + _suggest(section, known_sections)
                    ),
                )
            )
            continue

        if not isinstance(value, dict):
            # A section is expected to be a table; a scalar/list here is almost
            # certainly a mistake, but we only own the cases we're sure about.
            continue

        allowed = KNOWN_SCHEMA[section]
        numeric_keys = _NUMERIC_KEYS.get(section, set())
        integer_keys = _INTEGER_KEYS.get(section, set())
        bool_keys = _BOOL_KEYS.get(section, set())

        for key, kval in value.items():
            if not isinstance(key, str):
                continue

            # Unknown key in a fixed-key section.
            if allowed is not None and key not in allowed:
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="warning",
                        message=(
                            f'unknown key "{key}" in [{section}]' + _suggest(key, sorted(allowed))
                        ),
                    )
                )
                # Don't also type-check a key we don't recognize.
                continue

            # Type checks (conservative; only knowable cases).
            if key in integer_keys and (not isinstance(kval, int) or isinstance(kval, bool)):
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(f"{section}.{key} must be an integer, got {type(kval).__name__}"),
                    )
                )
            elif (
                section == "model_improvement"
                and key in integer_keys
                and not (_MODEL_IMPROVEMENT_FAMILY_MIN <= kval <= _MODEL_IMPROVEMENT_FAMILY_MAX)
            ):
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            f"{section}.{key} must be between "
                            f"{_MODEL_IMPROVEMENT_FAMILY_MIN} and "
                            f"{_MODEL_IMPROVEMENT_FAMILY_MAX}, got {kval!r}"
                        ),
                    )
                )
            elif key in numeric_keys and not _is_number(kval):
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(f"{section}.{key} must be a number, got {type(kval).__name__}"),
                    )
                )
            elif key in numeric_keys and not _is_valid_numeric_cap(kval):
                # A negative cap bricks every run (immediate BudgetExceeded); a
                # non-finite cap (TOML nan/inf) silently DISABLES enforcement.
                # Both pass an isinstance check but are never valid caps.
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            f"{section}.{key} must be a finite, non-negative number, got {kval!r}"
                        ),
                    )
                )
            elif (key in bool_keys or key in _UNIVERSAL_BOOL_KEYS) and not isinstance(kval, bool):
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            f"{section}.{key} must be true or false, got {type(kval).__name__}"
                        ),
                    )
                )
            elif (
                section == "ai_media_provenance"
                and key == "verification_adapter"
                and kval != "c2patool"
            ):
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            'ai_media_provenance.verification_adapter must be exactly "c2patool"'
                        ),
                    )
                )
            elif section == "model_improvement" and key == "allow_cross_tenant" and kval is True:
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            "model_improvement.allow_cross_tenant is reserved and "
                            "unsupported; it must remain false"
                        ),
                    )
                )
            elif (
                section == "model_improvement"
                and key == "require_signed_receipt"
                and kval is False
                and value.get("enable") is True
            ):
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            "enabled model improvement requires "
                            "model_improvement.require_signed_receipt = true"
                        ),
                    )
                )
            elif section == "ekko" and key == "provider_egress" and kval is True:
                findings.append(
                    Finding(
                        section=section,
                        key=key,
                        severity="error",
                        message=(
                            "ekko.provider_egress is reserved and unsupported; it must remain false"
                        ),
                    )
                )

        if (
            section == "ai_media_provenance"
            and value.get("verification_adapter") == "c2patool"
            and not _is_lower_sha256(value.get("c2patool_executable_sha256"))
        ):
            findings.append(
                Finding(
                    section=section,
                    key="c2patool_executable_sha256",
                    severity="error",
                    message=(
                        "selected c2patool verification requires "
                        "ai_media_provenance.c2patool_executable_sha256 to be "
                        "an exact lowercase SHA-256 digest"
                    ),
                )
            )

    findings.extend(_lint_image_edit_models(cfg))
    findings.extend(_lint_governance_nested_tables(cfg))
    findings.extend(_lint_inline_secrets(cfg))
    findings.extend(_lint_group_mappings(cfg))
    return findings


def _lint_group_mappings(cfg: dict) -> list[Finding]:
    """Advise on the SCIM-group -> access mapping tables.

    ``[dashboard.group_roles]`` values must name a real dashboard role, and
    ``[dashboard.group_suites]`` values must name real department suites. The
    runtime already fails safe on a bad value (an unknown role/suite confers
    nothing rather than widening access), but a silent no-op is a nasty
    footgun, so surface the typo up front."""
    out: list[Finding] = []
    dash = cfg.get("dashboard")
    if not isinstance(dash, dict):
        return out
    roles = {"admin", "operator", "auditor", "viewer"}
    try:
        from .domain import SUITE_PREFIXES

        suites = set(SUITE_PREFIXES.values())
    except Exception:  # pragma: no cover - never let a lint import break config
        suites = set()

    gr = dash.get("group_roles")
    if isinstance(gr, dict):
        for group, role in gr.items():
            if not (isinstance(role, str) and role.strip().lower() in roles):
                out.append(
                    Finding(
                        section="dashboard.group_roles",
                        key=str(group),
                        severity="error",
                        message=(
                            f"dashboard.group_roles[{group!r}] must name a role "
                            f"{sorted(roles)}, got {role!r}"
                        ),
                    )
                )

    gs = dash.get("group_suites")
    if isinstance(gs, dict):
        for group, val in gs.items():
            vals = (
                [val]
                if isinstance(val, str)
                else (list(val) if isinstance(val, (list, tuple)) else None)
            )
            if vals is None:
                out.append(
                    Finding(
                        section="dashboard.group_suites",
                        key=str(group),
                        severity="error",
                        message=(
                            f"dashboard.group_suites[{group!r}] must be a suite "
                            f"name or list of suite names, got {type(val).__name__}"
                        ),
                    )
                )
                continue
            unknown = [s for s in vals if s not in suites] if suites else []
            if unknown:
                out.append(
                    Finding(
                        section="dashboard.group_suites",
                        key=str(group),
                        severity="warning",
                        message=(
                            f"dashboard.group_suites[{group!r}] names unknown "
                            f"department(s) {unknown} (they confer no access)"
                        ),
                    )
                )
    return out


def format_findings(findings: list[Finding]) -> str:
    """Render findings as a human-readable summary.

    Returns ``"config OK"`` when there are none. Otherwise one line per
    finding, errors before warnings, with a count header.
    """
    if not findings:
        return "config OK"

    ordered = sorted(
        findings,
        key=lambda f: (0 if f.severity == "error" else 1, f.section, f.key or ""),
    )
    n_err = sum(1 for f in findings if f.severity == "error")
    n_warn = len(findings) - n_err

    lines = [f"config: {n_err} error(s), {n_warn} warning(s)"]
    for f in ordered:
        loc = f.section if f.key is None else f"{f.section}.{f.key}"
        lines.append(f"  [{f.severity}] {loc}: {f.message}")
    return "\n".join(lines)


def warn_config_at_startup(*, strict: bool | None = None) -> list[Finding]:
    """Lint the active config and emit findings to the log at server startup.

    Surfaces typo'd sections/keys -- which silently fall back to defaults, so a
    ``[budget] max_dollarss`` runs UNCAPPED -- at the moment a long-running
    server starts, rather than only when an operator happens to run
    ``maverick config-lint``. Warn-only by default (operators may legitimately
    use keys newer than this build). With ``strict`` (or
    ``MAVERICK_CONFIG_STRICT=1``) an error-level finding raises ``SystemExit`` so
    a regulated deployment fails fast instead of running with a mis-typed
    control. Never raises on its own bugs -- config linting must not block a
    start except via the explicit strict gate."""
    import logging
    import os

    _log = logging.getLogger("maverick.config")
    try:
        from .config import _read_toml_raw, config_path

        p = config_path()
        if not p.exists():
            return []
        # Lint the RAW (uninterpolated) TOML, not load_config()'s env-expanded
        # output: the documented `api_key = "${ANTHROPIC_API_KEY}"` pattern
        # expands to the literal secret once the env var is set, which
        # _lint_inline_secrets would then flag as an inline secret -- and in
        # strict mode that false positive refuses to start the server. The raw
        # value keeps the "$..." form _looks_like_env_ref recognizes, and the
        # unknown-key checks still see the operator's literal keys.
        cfg = _read_toml_raw(p) or {}
        findings = lint_config(cfg)
    except Exception:  # pragma: no cover -- linting never blocks startup
        return []
    for f in findings:
        loc = f.section if f.key is None else f"{f.section}.{f.key}"
        _log.warning("config: [%s] %s: %s", f.severity, loc, f.message)
    if strict is None:
        strict = os.environ.get("MAVERICK_CONFIG_STRICT", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    # Strict mode fails on ANY finding, not just error-level ones: an unknown
    # key (a typo that silently uses a default, the dangerous case) is
    # reported as a *warning*, so an error-only gate would miss it. A
    # regulated/strict deployment wants a clean config or no start.
    if strict and findings:
        raise SystemExit(
            "config has problems (logged above) and MAVERICK_CONFIG_STRICT is "
            "set; refusing to start. Run `maverick config-lint` and fix them."
        )
    return findings
