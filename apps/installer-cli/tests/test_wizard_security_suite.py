"""Installer coverage for the Security/GRC and defensive-hunter controls."""

from __future__ import annotations

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def test_pick_security_suite_safe_defaults(monkeypatch):
    from maverick_installer import wizard

    answers = iter([False, True] + [False] * 80)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: next(answers))

    assert wizard.pick_security_suite() == {
        "vendor_onboarding": False,
        "vendor_onboarding_owner": "",
        "vendor_reviewed_uploads": False,
        "customer_sandbox_lifecycle": False,
        "security_ops": True,
        "administration_document_access": False,
        "governed_document_vault": False,
        "incident_attachment_metadata": False,
        "evidence_graph": False,
        "model_risk_assurance": False,
        "evidence_gateway": False,
        "model_improvement": False,
        "allow_hosted_training": False,
        "ai_inventory": False,
        "ai_entity_tasks": False,
        "inventory_connectors": [],
        "ai_vendor_risk": False,
        "ai_vendor_risk_portal": False,
        "portfolio_risk": False,
        "policy_packs": False,
        "governance_agents": False,
        "ai_evidence_analysis": False,
        "ai_evidence_ocr": False,
        "ai_evidence_ocr_executable": "",
        "ai_evidence_ocr_sha256": "",
        "ai_evidence_ocr_tesseract_version": "",
        "ai_evidence_ocr_traineddata_path": "",
        "ai_evidence_ocr_traineddata_sha256": "",
        "ai_evidence_ocr_runtime_library_paths": [],
        "ai_evidence_ocr_runtime_libraries_sha256": "",
        "ai_evidence_ocr_pillow_version": "",
        "ai_evidence_ocr_pillow_manifest_sha256": "",
        "ai_evidence_legacy_xls": False,
        "ai_evidence_xlrd_manifest_sha256": "",
        "ai_evidence_olefile_manifest_sha256": "",
        "ai_evidence_parser_sandbox": False,
        "ai_evidence_parser_sandbox_launcher": "",
        "ai_evidence_parser_sandbox_sha256": "",
        "ai_evidence_parser_sandbox_version": "",
        "assessment_evidence_autopopulation": False,
        "assessment_evidence_apply": False,
        "tech_risk_compliance": {
            "enable": False,
            "grc_studio": {
                "enable": False,
                "max_studios": 10_000,
                "retention_seconds": 31_536_000,
                "max_import_bytes": 2_097_152,
            },
            "policy_publication_links": {"enable": False},
            "scoping": {"enable": False},
            "scope_actions": {"enable": False},
            "continuous_evidence": {
                "enable": False,
                "enabled_collectors": [],
                "stock_collectors": {"enable": False, "sources": []},
                "scheduler": {
                    "enable": False,
                    "poll_seconds": 60,
                    "enqueue_limit": 50,
                    "claim_limit": 10,
                    "tenant_limit": 1_000,
                    "lease_seconds": 120,
                    "retry_backoff_seconds": 30,
                },
            },
        },
        "third_party_management": {
            "enable": False,
            "contracts": {
                "enable": False,
                "max_records": 100_000,
                "retention_seconds": 31_536_000,
                "authority_max_age_seconds": 604_800,
            },
            "executive_reports": {
                "enable": False,
                "max_reports": 10_000,
                "max_sources": 100,
                "max_pdf_bytes": 524_288,
                "retention_seconds": 31_536_000,
                "download_token_seconds": 300,
            },
            "intelligence": {
                "enable": False,
                "providers": {
                    "enable": False,
                    "enabled_providers": [],
                    "timeout_seconds": 20,
                    "scheduler": {"enable": False, "poll_seconds": 900},
                },
            },
            "lifecycle": {
                "enable": False,
                "portal": {
                    "enable": False,
                    "invitation_ttl_seconds": 86_400,
                    "retention_seconds": 31_536_000,
                    "max_messages": 100,
                    "max_artifacts": 20,
                    "max_artifact_bytes": 10_485_760,
                },
            },
        },
        "ai_regulatory_feed": False,
        "red_team_assurance": False,
        "eu_ai_incidents": False,
        "grc_outbound_sync": False,
        "ai_literacy": False,
        "ai_business_intake": False,
        "ai_cost_roi": False,
        "ai_dynamic_risk": False,
        "ai_policy_management": False,
        "ai_runtime_guardrails": False,
        "ai_governance_loop": False,
        "ai_explainability": False,
        "ai_conformity_workflow": False,
        "ai_insurability": False,
        "ai_regulated_verticals": False,
        "ai_bank_mrm": False,
        "ai_benchmark_exchange": False,
        "ai_discovery_sensors": False,
        "ai_media_provenance": False,
        "ai_media_provenance_c2patool": False,
        "ai_media_provenance_c2patool_sha256": "",
        "ai_identity_governance_connectors": False,
        "ai_identity_governance_scheduler": False,
        "ai_identity_governance_controls": False,
        "ai_identity_change_coupling": False,
        "ai_identity_federation": False,
        "ai_identity_conditional_access": False,
        "ai_identity_purview_writeback": False,
        "ai_identity_production_composition": False,
        "threat_hunt": False,
        "env_hunt": False,
        "response_execution": False,
    }


def test_pick_security_suite_response_is_separate_opt_in(monkeypatch):
    from maverick_installer import wizard

    answers = iter([True] * 80)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: next(answers))
    checkbox_answers = iter(
        [
            ["AWS Bedrock", "Google Vertex AI"],
            [
                "AWS Security Hub",
                "AWS Config posture",
                "Azure Defender",
                "Azure Policy posture",
                "Google Cloud Security Command Center",
                "GitHub security streams",
                "Okta policy posture",
            ],
            ["AWS CloudTrail", "Microsoft Entra ID"],
            ["AWS CloudTrail"],
            ["Microsoft Entra ID"],
        ]
    )
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *args, **kwargs: next(checkbox_answers))
    # Confirming a governed parser is not sufficient: absent exact runtime
    # attestations it truthfully remains disabled.  Eleven blank answers cover
    # the OCR/XLS manifest prompts before the unrelated existing text answers.
    text_answers = iter(
        [""] * 11
        + [
            "tenant.supplywisdom.example",
            "tenant.iss-corporate-solutions.example",
            "a" * 64,
            "virustotal, abuseipdb",
            "120",
        ]
    )
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: next(text_answers))

    picked = wizard.pick_security_suite()
    assert picked["evidence_gateway"] is True
    assert picked["administration_document_access"] is True
    assert picked["governed_document_vault"] is True
    assert picked["incident_attachment_metadata"] is True
    assert picked["model_improvement"] is True
    assert picked["allow_hosted_training"] is True
    assert picked["inventory_connectors"] == ["bedrock", "vertex_ai"]
    assert picked["ai_entity_tasks"] is True
    assert picked["ai_vendor_risk"] is True
    assert picked["ai_vendor_risk_portal"] is True
    assert picked["portfolio_risk"] is True
    assert picked["policy_packs"] is True
    assert picked["governance_agents"] is True
    assert picked["ai_evidence_analysis"] is True
    assert picked["ai_evidence_ocr"] is False
    assert picked["ai_evidence_legacy_xls"] is False
    assert picked["ai_evidence_parser_sandbox"] is False
    assert picked["tech_risk_compliance"] == {
        "enable": True,
        "grc_studio": {
            "enable": True,
            "max_studios": 10_000,
            "retention_seconds": 31_536_000,
            "max_import_bytes": 2_097_152,
        },
        "policy_publication_links": {"enable": True},
        "scoping": {"enable": True},
        "scope_actions": {"enable": True},
        "continuous_evidence": {
            "enable": True,
            "enabled_collectors": [
                "local_soc2_v1",
                "aws_security_hub_v1",
                "aws_config_posture_v1",
                "azure_defender_v1",
                "azure_policy_posture_v1",
                "gcp_security_command_center_v1",
                "github_security_v1",
                "okta_posture_v1",
            ],
            "stock_collectors": {"enable": True, "sources": []},
            "scheduler": {
                "enable": True,
                "poll_seconds": 60,
                "enqueue_limit": 50,
                "claim_limit": 10,
                "tenant_limit": 1_000,
                "lease_seconds": 120,
                "retry_backoff_seconds": 30,
            },
        },
    }
    assert picked["third_party_management"] == {
        "enable": True,
        "contracts": {
            "enable": True,
            "max_records": 100_000,
            "retention_seconds": 31_536_000,
            "authority_max_age_seconds": 604_800,
        },
        "executive_reports": {
            "enable": True,
            "max_reports": 10_000,
            "max_sources": 100,
            "max_pdf_bytes": 524_288,
            "retention_seconds": 31_536_000,
            "download_token_seconds": 300,
        },
        "intelligence": {
            "enable": True,
            "providers": {
                "enable": True,
                "enabled_providers": [
                    "riskrecon",
                    "securityscorecard",
                    "hacknotice",
                    "supplywisdom",
                    "iss_corporate_solutions",
                ],
                "supplywisdom_host": "tenant.supplywisdom.example",
                "iss_corporate_solutions_host": (
                    "tenant.iss-corporate-solutions.example"
                ),
                "timeout_seconds": 20,
                "scheduler": {"enable": True, "poll_seconds": 900},
            },
        },
        "lifecycle": {
            "enable": True,
            "portal": {
                "enable": True,
                "invitation_ttl_seconds": 86_400,
                "retention_seconds": 31_536_000,
                "max_messages": 100,
                "max_artifacts": 20,
                "max_artifact_bytes": 10_485_760,
            },
        },
    }
    assert picked["ai_regulatory_feed"] is True
    assert picked["red_team_assurance"] is True
    assert picked["eu_ai_incidents"] is True
    assert picked["grc_outbound_sync"] is True
    assert picked["ai_literacy"] is True
    assert picked["ai_business_intake"] is True
    assert picked["ai_cost_roi"] is True
    assert picked["ai_dynamic_risk"] is True
    assert picked["ai_policy_management"] is True
    assert picked["ai_runtime_guardrails"] is True
    assert picked["ai_governance_loop"] is True
    assert picked["ai_explainability"] is True
    assert picked["ai_conformity_workflow"] is True
    assert picked["ai_insurability"] is True
    assert picked["ai_regulated_verticals"] is True
    assert picked["ai_bank_mrm"] is True
    assert picked["ai_benchmark_exchange"] is True
    assert picked["ai_discovery_sensors"] is True
    assert picked["ai_media_provenance"] is True
    assert picked["ai_media_provenance_c2patool"] is True
    assert picked["ai_media_provenance_c2patool_sha256"] == "a" * 64
    assert picked["ai_identity_governance_connectors"] is True
    assert picked["ai_identity_governance_scheduler"] is True
    assert picked["ai_identity_governance_controls"] is True
    assert picked["ai_identity_change_coupling"] is True
    assert picked["ai_identity_federation"] is True
    assert picked["ai_identity_conditional_access"] is True
    assert picked["ai_identity_purview_writeback"] is True
    assert picked["ai_identity_production_composition"] is True
    assert picked["env_hunt"] is True
    assert picked["response_execution"] is True
    assert picked["connectors"]["cloudtrail"] == {
        "enable": True,
        "push_enable": True,
        "pivot_enable": False,
    }
    assert picked["connectors"]["entra"] == {
        "enable": True,
        "push_enable": False,
        "pivot_enable": True,
    }
    assert picked["connectors"]["edr"] == {
        "enable": False,
        "push_enable": False,
        "pivot_enable": False,
    }
    assert picked["enrichment_sources"] == ["virustotal", "abuseipdb"]
    assert picked["poll_seconds"] == 120


def test_document_access_prompt_derives_attachment_dependency(monkeypatch):
    from maverick_installer import wizard

    def answer(prompt, *args, **kwargs):
        del args, kwargs
        return prompt.startswith(
            (
                "Enable governed short-lived document",
                "Enable the stock tenant-private encrypted document vault",
                "Enable governed metadata-only attachments",
            )
        )

    monkeypatch.setattr(wizard, "_q_confirm", answer)
    picked = wizard.pick_security_suite()

    assert picked["administration_document_access"] is True
    assert picked["governed_document_vault"] is True
    assert picked["incident_attachment_metadata"] is True
    rendered = tomllib.loads("\n".join(wizard._cfg_security_suite(picked)))
    assert rendered["administration_document_access"]["enable"] is True
    assert rendered["governed_document_vault"]["enable"] is True
    assert rendered["incident_attachment_metadata"]["enable"] is True
    assert set(rendered["incident_attachment_metadata"]["allowed_media_types"]).issubset(
        rendered["governed_document_vault"]["allowed_media_types"]
    )


def test_pick_security_suite_scoping_independently_enables_trc_root(monkeypatch):
    from maverick_installer import wizard

    def answer(prompt, *args, **kwargs):
        del args, kwargs
        return prompt.startswith("Enable local Tech Risk & Compliance questionnaire")

    monkeypatch.setattr(wizard, "_q_confirm", answer)
    picked = wizard.pick_security_suite()
    assert picked["tech_risk_compliance"] == {
        "enable": True,
        "grc_studio": {
            "enable": False,
            "max_studios": 10_000,
            "retention_seconds": 31_536_000,
            "max_import_bytes": 2_097_152,
        },
        "policy_publication_links": {"enable": False},
        "scoping": {"enable": True},
        "scope_actions": {"enable": False},
        "continuous_evidence": {
            "enable": False,
            "enabled_collectors": [],
            "stock_collectors": {"enable": False, "sources": []},
            "scheduler": {
                "enable": False,
                "poll_seconds": 60,
                "enqueue_limit": 50,
                "claim_limit": 10,
                "tenant_limit": 1_000,
                "lease_seconds": 120,
                "retry_backoff_seconds": 30,
            },
        },
    }


def test_security_suite_writer_emits_separate_trc_capability_gates():
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    rendered = wizard._cfg_security_suite(
        {
            "security_ops": False,
            "tech_risk_compliance": {
                "enable": True,
                "grc_studio": {
                    "enable": True,
                    "max_studios": 10_000,
                    "retention_seconds": 31_536_000,
                    "max_import_bytes": 2_097_152,
                },
                "policy_publication_links": {"enable": True},
                "scoping": {"enable": True},
                "scope_actions": {"enable": True},
                "continuous_evidence": {
                    "enable": True,
                    "enabled_collectors": ["local_soc2_v1"],
                    "scheduler": {
                        "enable": True,
                        "poll_seconds": 60,
                        "enqueue_limit": 50,
                        "claim_limit": 10,
                        "tenant_limit": 1_000,
                        "lease_seconds": 120,
                        "retry_backoff_seconds": 30,
                    },
                },
            },
            "third_party_management": {
                "enable": True,
                "contracts": {
                    "enable": True,
                    "max_records": 100_000,
                    "retention_seconds": 31_536_000,
                    "authority_max_age_seconds": 604_800,
                },
                "intelligence": {
                    "enable": True,
                    "providers": {
                        "enable": True,
                        "enabled_providers": [
                            "riskrecon",
                            "securityscorecard",
                            "hacknotice",
                        ],
                        "timeout_seconds": 20,
                        "scheduler": {"enable": True, "poll_seconds": 900},
                    },
                },
                "lifecycle": {
                    "enable": True,
                    "portal": {
                        "enable": True,
                        "invitation_ttl_seconds": 86_400,
                        "retention_seconds": 31_536_000,
                        "max_messages": 100,
                        "max_artifacts": 20,
                        "max_artifact_bytes": 10_485_760,
                    },
                },
            },
        }
    )
    parsed = tomllib.loads("\n".join(rendered))
    assert parsed["tech_risk_compliance"] == {
        "enable": True,
        "grc_studio": {
            "enable": True,
            "max_studios": 10_000,
            "retention_seconds": 31_536_000,
            "max_import_bytes": 2_097_152,
        },
        "policy_publication_links": {"enable": True},
        "scoping": {"enable": True},
        "scope_actions": {"enable": True},
        "continuous_evidence": {
            "enable": True,
            "enabled_collectors": ["local_soc2_v1"],
            "scheduler": {
                "enable": True,
                "poll_seconds": 60,
                "enqueue_limit": 50,
                "claim_limit": 10,
                "tenant_limit": 1_000,
                "lease_seconds": 120,
                "retry_backoff_seconds": 30,
            },
        },
    }
    assert parsed["third_party_management"] == {
        "enable": True,
        "contracts": {
            "enable": True,
            "max_records": 100_000,
            "retention_seconds": 31_536_000,
            "authority_max_age_seconds": 604_800,
        },
        "intelligence": {
            "enable": True,
            "providers": {
                "enable": True,
                "enabled_providers": ["riskrecon", "securityscorecard", "hacknotice"],
                "timeout_seconds": 20,
                "scheduler": {"enable": True, "poll_seconds": 900},
            },
        },
        "lifecycle": {
            "enable": True,
            "portal": {
                "enable": True,
                "invitation_ttl_seconds": 86_400,
                "retention_seconds": 31_536_000,
                "max_messages": 100,
                "max_artifacts": 20,
                "max_artifact_bytes": 10_485_760,
            },
        },
    }
    assert lint_config(parsed) == []


def test_pick_security_suite_does_not_offer_federation_dependents_when_off(
    monkeypatch,
):
    from maverick_installer import wizard

    prompts: list[str] = []

    def answer(prompt, *args, **kwargs):
        prompts.append(prompt)
        if prompt.startswith("Enable bounded read-only Entra"):
            return True
        if prompt.startswith("Prepare the separately gated identity control plane"):
            return True
        return False

    monkeypatch.setattr(wizard, "_q_confirm", answer)
    picked = wizard.pick_security_suite()

    assert picked["ai_identity_governance_connectors"] is True
    assert picked["ai_identity_governance_controls"] is True
    assert picked["ai_identity_federation"] is False
    assert picked["ai_identity_conditional_access"] is False
    assert picked["ai_identity_purview_writeback"] is False
    assert not any("conditional-access" in prompt for prompt in prompts)
    assert not any("Purview classification writeback for" in prompt for prompt in prompts)


def test_write_config_emits_independent_security_knobs(tmp_path, monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    wizard.write_config(
        providers=["anthropic"],
        role_models={},
        channels={},
        safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={},
        capabilities={},
        security_suite={
            "security_ops": True,
            "evidence_graph": True,
            "model_risk_assurance": True,
            "evidence_gateway": True,
            "model_improvement": True,
            "allow_hosted_training": False,
            "ai_inventory": True,
            "inventory_connectors": [
                "bedrock",
                "vertex_ai",
                "mlflow",
                "aws_sagemaker",
            ],
            "ai_vendor_risk": True,
            "portfolio_risk": True,
            "policy_packs": True,
            "ai_regulatory_feed": True,
            "red_team_assurance": True,
            "eu_ai_incidents": True,
            "grc_outbound_sync": True,
            "ai_literacy": True,
            "ai_business_intake": True,
            "ai_cost_roi": True,
            "ai_dynamic_risk": True,
            "ai_policy_management": True,
            "ai_runtime_guardrails": True,
            "ai_governance_loop": True,
            "ai_explainability": True,
            "ai_conformity_workflow": True,
            "ai_insurability": True,
            "ai_regulated_verticals": True,
            "ai_bank_mrm": True,
            "ai_benchmark_exchange": True,
            "ai_discovery_sensors": True,
            "ai_media_provenance": True,
            "ai_identity_governance_connectors": True,
            "threat_hunt": True,
            "env_hunt": True,
            "response_execution": False,
        },
    )

    parsed = tomllib.loads((tmp_path / "config.toml").read_text())
    assert parsed["security_ops"]["enable"] is True
    assert parsed["governed_records"] == {"backend": "auto", "pool_size": 0, "pool_timeout_seconds": 5}
    assert parsed["evidence_graph"]["enable"] is True
    assert parsed["model_risk_assurance"] == {
        "enable": True,
        "gate_promotions": True,
    }
    assert parsed["evidence_gateway"] == {"enable": True}
    assert parsed["ai_inventory"] == {
        "enable": True,
        "connectors": ["bedrock", "vertex_ai", "mlflow", "aws_sagemaker"],
        "page_cap": 100,
        "record_cap": 5000,
        "retry_attempts": 3,
        "timeout_seconds": 30,
        "missing_grace_runs": 2,
        "poll_seconds": 900,
    }
    assert parsed["ai_vendor_risk"] == {"enable": True, "portal_enable": False}
    assert parsed["portfolio_risk"] == {"enable": True}
    assert parsed["policy_packs"] == {"enable": True}
    assert parsed["ai_regulatory_feed"] == {"enable": True}
    assert parsed["red_team_assurance"] == {
        "enable": True,
        "commitment_secret_ref": "MAVERICK_RED_TEAM_COMMITMENT_KEY",  # pragma: allowlist secret
        "max_cases": 12,
        "max_response_bytes": 65536,
        "campaign_ttl_seconds": 604800,
        "evidence_validity_seconds": 7776000,
        "scheduler_poll_seconds": 30,
    }
    assert parsed["eu_ai_incidents"] == {"enable": True, "authorities": []}
    assert parsed["grc_outbound_sync"] == {
        "enable": True,
        "targets": ["servicenow_irm", "archer"],
        "max_attempts_per_revision": 8,
        "servicenow_irm": {
            "credential_secret_ref": "SERVICENOW_TOKEN",
            "timeout_seconds": 15,
            "max_response_bytes": 262144,
        },
        "archer": {
            "credential_secret_ref": "ARCHER_GRC_TOKEN",
            "timeout_seconds": 15,
            "max_response_bytes": 262144,
        },
    }
    assert parsed["ai_literacy"] == {"enable": True}
    assert parsed["ai_business_intake"] == {"enable": True}
    assert parsed["ai_cost_roi"] == {
        "enable": True,
        "collector_poll_seconds": 86400,
        "collector_lookback_days": 1,
        "collector_limits": {
            "timeout_seconds": 20,
            "page_cap": 20,
            "record_cap": 1000,
            "max_period_days": 93,
            "page_size": 200,
            "max_bytes_billed": 1000000000,
        },
        "aws": {"enable": False},
        "azure": {"enable": False},
        "gcp": {"enable": False},
        "openai": {"enable": False},
    }
    assert parsed["ai_dynamic_risk"] == {"enable": True}
    assert parsed["ai_policy_management"] == {"enable": True}
    assert parsed["ai_runtime_guardrails"] == {"enable": True}
    assert parsed["ai_governance_loop"] == {
        "enable": True,
        "poll_seconds": 300,
        "batch_size": 100,
        "lease_seconds": 120,
        "max_attempts": 5,
        "retry_base_seconds": 30,
        "max_lag_seconds": 900,
    }
    assert parsed["ai_explainability"] == {"enable": True}
    assert parsed["ai_conformity_workflow"] == {"enable": True}
    assert parsed["ai_insurability"] == {"enable": True}
    assert parsed["ai_regulated_verticals"] == {"enable": True}
    assert parsed["ai_bank_mrm"] == {"enable": True}
    assert parsed["ai_benchmark_exchange"] == {"enable": True}
    assert parsed["ai_discovery_sensors"] == {"enable": True}
    assert parsed["ai_media_provenance"] == {"enable": True}
    assert parsed["ai_identity_governance_connectors"] == {
        "enable": True,
        "entra": {
            "enable": False,
            "tenant_id": "",
            "base_url": "https://graph.microsoft.com",
            "credential_secret_ref": "ENTRA_IDENTITY_GOVERNANCE_TOKEN",
        },
        "okta": {
            "enable": False,
            "tenant_id": "",
            "base_url": "https://replace-me.okta.com",
            "credential_secret_ref": "OKTA_IDENTITY_GOVERNANCE_TOKEN",
        },
        "purview": {
            "enable": False,
            "tenant_id": "",
            "base_url": "https://replace-me.purview.azure.com",
            "credential_secret_ref": "PURVIEW_IDENTITY_GOVERNANCE_TOKEN",
        },
        "scheduler": {
            "enable": False,
            "poll_seconds": 60,
            "providers": {
                "entra": {
                    "enable": False,
                    "interval_seconds": 3600,
                    "retry_base_seconds": 30,
                    "retry_max_seconds": 900,
                    "max_attempts_per_slot": 3,
                    "lease_seconds": 3600,
                    "history_limit": 8,
                    "max_snapshot_items": 5000,
                    "max_delta_digests": 256,
                },
                "okta": {
                    "enable": False,
                    "interval_seconds": 3600,
                    "retry_base_seconds": 30,
                    "retry_max_seconds": 900,
                    "max_attempts_per_slot": 3,
                    "lease_seconds": 3600,
                    "history_limit": 8,
                    "max_snapshot_items": 5000,
                    "max_delta_digests": 256,
                },
                "purview": {
                    "enable": False,
                    "interval_seconds": 3600,
                    "retry_base_seconds": 30,
                    "retry_max_seconds": 900,
                    "max_attempts_per_slot": 3,
                    "lease_seconds": 3600,
                    "history_limit": 8,
                    "max_snapshot_items": 5000,
                    "max_delta_digests": 256,
                },
            },
        },
        "controls": {
            "enable": False,
            "change_coupling": {
                "enable": False,
                "dynamic_risk": False,
                "alerts": False,
            },
            "federation": {"enable": False},
            "conditional_access": {"enable": False},
            "purview_writeback": {"enable": False},
            "production": {
                "enable": False,
                "mapping_revision": 1,
                "mapping_retention_seconds": 86_400,
                "max_authority_records": 10_000,
                "max_observation_age_seconds": 300,
                "max_future_skew_seconds": 30,
                "outcome_max_attempts": 5,
                "outcome_retry_base_seconds": 30,
                "outcome_retry_max_seconds": 3_600,
                "outcome_lease_seconds": 60,
                "outcome_signal_validity_seconds": 86_400,
                "purview_max_attempts": 3,
                "purview_operation_lease_seconds": 60,
            },
        },
    }
    environment = (tmp_path / ".env").read_text(encoding="utf-8")
    commitment_line = next(
        line
        for line in environment.splitlines()
        if line.startswith("MAVERICK_RED_TEAM_COMMITMENT_KEY=")
    )
    assert len(commitment_line.partition("=")[2]) >= 32
    assert parsed["external_agents"]["enable"] is True
    assert parsed["model_improvement"] == {
        "enable": True,
        "allow_hosted": False,
        "allow_cross_tenant": False,
        "require_signed_receipt": True,
        "minimum_train_families": 20,
        "minimum_holdout_families": 20,
    }
    assert parsed["threat_hunt"]["enable"] is True
    assert parsed["env_hunt"] == {
        "enable": True,
        "response_execution": False,
        "poll_seconds": 300,
        "connectors": {
            "cloudtrail": {"enable": False, "push_enable": False, "pivot_enable": False},
            "guardduty": {"enable": False, "push_enable": False, "pivot_enable": False},
            "syslog": {"enable": False, "push_enable": False, "pivot_enable": False},
            "edr": {"enable": False, "push_enable": False, "pivot_enable": False},
            "splunk": {"enable": False, "push_enable": False, "pivot_enable": False},
            "elastic": {"enable": False, "push_enable": False, "pivot_enable": False},
            "sentinel": {"enable": False, "push_enable": False, "pivot_enable": False},
            "kubernetes_audit": {"enable": False, "push_enable": False, "pivot_enable": False},
            "okta": {"enable": False, "push_enable": False, "pivot_enable": False},
            "entra": {"enable": False, "push_enable": False, "pivot_enable": False},
        },
    }


def test_security_suite_high_trust_adapters_require_separate_opt_ins():
    from maverick_installer import wizard

    defaults = tomllib.loads(
        "\n".join(
            wizard._cfg_security_suite(
                {
                    "ai_vendor_risk": True,
                    "ai_media_provenance": True,
                    "ai_identity_governance_connectors": True,
                    "ai_benchmark_exchange": True,
                }
            )
        )
    )
    assert defaults["ai_vendor_risk"]["portal_enable"] is False
    assert defaults["ai_media_provenance"] == {"enable": True}
    assert defaults["ai_identity_governance_connectors"]["scheduler"]["enable"] is False
    assert defaults["ai_identity_governance_connectors"]["controls"] == {
        "enable": False,
        "change_coupling": {
            "enable": False,
            "dynamic_risk": False,
            "alerts": False,
        },
        "federation": {"enable": False},
        "conditional_access": {"enable": False},
        "purview_writeback": {"enable": False},
        "production": {
            "enable": False,
            "mapping_revision": 1,
            "mapping_retention_seconds": 86_400,
            "max_authority_records": 10_000,
            "max_observation_age_seconds": 300,
            "max_future_skew_seconds": 30,
            "outcome_max_attempts": 5,
            "outcome_retry_base_seconds": 30,
            "outcome_retry_max_seconds": 3_600,
            "outcome_lease_seconds": 60,
            "outcome_signal_validity_seconds": 86_400,
            "purview_max_attempts": 3,
            "purview_operation_lease_seconds": 60,
        },
    }
    assert all(
        provider["enable"] is False
        for provider in defaults["ai_identity_governance_connectors"]["scheduler"][
            "providers"
        ].values()
    )
    assert defaults["ai_benchmark_exchange"] == {"enable": True}

    selected = tomllib.loads(
        "\n".join(
            wizard._cfg_security_suite(
                {
                    "ai_vendor_risk": True,
                    "ai_vendor_risk_portal": True,
                    "ai_media_provenance": True,
                    "ai_media_provenance_c2patool": True,
                    "ai_media_provenance_c2patool_sha256": "a" * 64,
                    "ai_identity_governance_connectors": True,
                    "ai_identity_governance_scheduler": True,
                    "ai_identity_governance_controls": True,
                    "ai_identity_change_coupling": True,
                    "ai_identity_federation": True,
                    "ai_identity_conditional_access": True,
                    "ai_identity_purview_writeback": True,
                    "ai_identity_production_composition": True,
                }
            )
        )
    )
    assert selected["ai_vendor_risk"]["portal_enable"] is True
    assert selected["ai_media_provenance"] == {
        "enable": True,
        "verification_adapter": "c2patool",
        "c2patool_executable_sha256": "a" * 64,
    }
    identity = selected["ai_identity_governance_connectors"]
    assert identity["scheduler"]["enable"] is True
    assert all(
        provider["enable"] is False for provider in identity["scheduler"]["providers"].values()
    )
    assert identity["controls"] == {
        "enable": True,
        "change_coupling": {
            "enable": True,
            "dynamic_risk": True,
            "alerts": True,
        },
        "federation": {"enable": True},
        "conditional_access": {"enable": True},
        "purview_writeback": {"enable": True},
        "production": {
            "enable": True,
            "mapping_revision": 1,
            "mapping_retention_seconds": 86_400,
            "max_authority_records": 10_000,
            "max_observation_age_seconds": 300,
            "max_future_skew_seconds": 30,
            "outcome_max_attempts": 5,
            "outcome_retry_base_seconds": 30,
            "outcome_retry_max_seconds": 3_600,
            "outcome_lease_seconds": 60,
            "outcome_signal_validity_seconds": 86_400,
            "purview_max_attempts": 3,
            "purview_operation_lease_seconds": 60,
        },
    }


def test_identity_control_rendering_disables_dependents_without_federation():
    from maverick_installer import wizard

    selected = tomllib.loads(
        "\n".join(
            wizard._cfg_security_suite(
                {
                    "ai_identity_governance_connectors": True,
                    "ai_identity_governance_controls": True,
                    "ai_identity_federation": False,
                    "ai_identity_conditional_access": True,
                    "ai_identity_purview_writeback": True,
                }
            )
        )
    )
    controls = selected["ai_identity_governance_connectors"]["controls"]
    assert controls["federation"]["enable"] is False
    assert controls["conditional_access"]["enable"] is False
    assert controls["purview_writeback"]["enable"] is False


def test_c2patool_rendering_fails_closed_without_an_exact_reviewed_digest():
    from maverick_installer import wizard

    for digest in ("", "not-a-digest"):
        selected = tomllib.loads(
            "\n".join(
                wizard._cfg_security_suite(
                    {
                        "ai_media_provenance": True,
                        "ai_media_provenance_c2patool": True,
                        "ai_media_provenance_c2patool_sha256": digest,
                    }
                )
            )
        )
        assert selected["ai_media_provenance"] == {"enable": True}


def test_evidence_gateway_enables_assurance_dependencies(monkeypatch):
    from maverick_installer import wizard

    answers = iter([False, True, False, False, True] + [False] * 60)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: next(answers))

    picked = wizard.pick_security_suite()

    assert picked["evidence_gateway"] is True
    assert picked["evidence_graph"] is True
    assert picked["model_risk_assurance"] is True


def test_security_connector_knobs_are_explicit_and_independent():
    from maverick_installer import wizard

    lines = wizard._cfg_security_suite(
        {
            "security_ops": True,
            "env_hunt": True,
            "connectors": {
                "cloudtrail": {"enable": True, "push_enable": True},
                "entra": {"enable": True, "pivot_enable": True},
            },
        }
    )
    parsed = tomllib.loads("\n".join(lines))
    assert parsed["env_hunt"]["connectors"]["cloudtrail"]["enable"] is True
    assert parsed["env_hunt"]["connectors"]["cloudtrail"]["push_enable"] is True
    assert parsed["env_hunt"]["connectors"]["cloudtrail"]["pivot_enable"] is False
    assert parsed["env_hunt"]["connectors"]["entra"]["enable"] is True
    assert parsed["env_hunt"]["connectors"]["entra"]["pivot_enable"] is True
    assert parsed["env_hunt"]["connectors"]["edr"]["enable"] is False


def test_security_enrichment_choices_render_as_runtime_enable_tables():
    from maverick_installer import wizard

    lines = wizard._cfg_security_suite(
        {
            "security_ops": True,
            "env_hunt": True,
            "enrichment_sources": ["VirusTotal", "abuseipdb", "virustotal"],
        }
    )
    parsed = tomllib.loads("\n".join(lines))

    assert parsed["env_hunt"]["enrichment_sources"] == {
        "virustotal": {"enable": True},
        "abuseipdb": {"enable": True},
    }


def test_customer_sandbox_wizard_step_is_default_off_and_explicitly_rendered(
    monkeypatch,
):
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    def answer(prompt, *args, **kwargs):
        del args, kwargs
        return prompt.startswith("Enable the global-admin managed customer sandbox")

    monkeypatch.setattr(wizard, "_q_confirm", answer)
    picked = wizard.pick_security_suite()
    assert picked["customer_sandbox_lifecycle"] is True
    rendered = tomllib.loads("\n".join(wizard._cfg_security_suite(picked)))
    assert rendered["customer_sandbox_lifecycle"] == {
        "enable": True,
        "source_revision": 1,
    }
    assert lint_config(rendered) == []


def _write_vendor_onboarding_config(tmp_path, monkeypatch, security_suite, **kwargs):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    wizard.write_config(
        providers=["anthropic"], role_models={}, channels={},
        safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": str(tmp_path / "workspace")},
        keys={}, capabilities={}, security_suite=security_suite, **kwargs,
    )
    return tomllib.loads((tmp_path / "config.toml").read_text(encoding="utf-8"))


def test_vendor_first_run_defers_owner_to_current_workspace_in_app(tmp_path, monkeypatch):
    import io

    from maverick import config, vendor_onboarding_setup
    from maverick.paths import tenant_scope
    from maverick.vendor_onboarding_config import VendorOnboardingSettings
    from maverick_installer import wizard
    from rich.console import Console

    output = io.StringIO()
    monkeypatch.setattr(wizard, "console", Console(file=output, width=140, no_color=True))
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, **kwargs:
        prompt.startswith("Enable AI vendor onboarding") or prompt.startswith("  Allow reviewed local"))

    def no_identity_prompt(prompt, **kwargs):
        pytest.fail("Fresh vendor setup must not request unchecked identity: " + prompt)

    monkeypatch.setattr(wizard, "_q_text", no_identity_prompt)
    selected = wizard.pick_security_suite()
    assert selected["vendor_onboarding"] is True
    assert selected["vendor_onboarding_owner"] == ""
    assert "active workspace member" in output.getvalue()
    assert "in the app" in output.getvalue()
    parsed = _write_vendor_onboarding_config(tmp_path, monkeypatch, selected)
    assert parsed["vendor_onboarding"]["resource_owner"] == ""
    assert parsed["vendor_onboarding"]["reviewed_uploads"] is True
    for key in vendor_onboarding_setup.REQUIRED_MODULES:
        assert parsed[key]["enable"] is True
    # Enablement is not an invented complete binding; runtime still requires
    # ownership until the existing in-app setup chooses a current member.
    with pytest.raises(ValueError, match="resource_owner.*required"):
        VendorOnboardingSettings.from_config(parsed)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    try:
        with tenant_scope(tenant="wizard-first-run"):
            assert vendor_onboarding_setup.owner_policy() == {
                "resource_owner": "", "owner_locked": False, "owner_source": "initial",
            }
    finally:
        config.reset_config_cache()


@pytest.mark.parametrize("owner", ["", "procurement", "user:existing@example.test"])
def test_vendor_resume_preserves_saved_owner_decision(tmp_path, monkeypatch, owner):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH", tmp_path / "wizard-partial.json")
    # Other completed steps are carried unchanged through the real resume loop.
    keys = (
        "safety",
        "signed_skills",
        "budget",
        "approval",
        "sandbox",
        "research_execution",
        "candidate_promotion",
        "knowledge_access",
        "capabilities",
        "self_learning",
        "ekko",
        "automation_import",
        "event_triggers",
        "flows",
        "knowledge",
        "oauth",
        "governed_connectors",
        "durable",
        "workspace",
        "finance",
        "value",
        "intent_value",
        "assessments",
        "advanced",
    )
    saved = dict.fromkeys(keys, {"enable": False})
    # The API access answer rides inside ``advanced``; a saved one is not asked again.
    saved["advanced"] = {"enable": False, "api_keys": {"api_keys": False}}
    saved["security_suite"] = {
        "vendor_onboarding": True, "vendor_onboarding_owner": owner,
        "vendor_reviewed_uploads": False,
    }
    wizard._save_partial(saved)
    resumed = wizard._load_partial()
    assert resumed == saved

    def no_reenrollment():
        pytest.fail("Resume must preserve the saved vendor choice")

    monkeypatch.setattr(wizard, "pick_security_suite", no_reenrollment)
    # The monitoring step is never saved (its credentials stay out of the partial state),
    # so it is asked again on resume; this test is about the vendor answer, so it is stubbed.
    monkeypatch.setattr(wizard, "pick_monitoring", lambda: ({}, {}))
    selected = wizard._run_simple_picks(resumed, lambda: None)
    assert selected["security_suite"] == saved["security_suite"]
    assert wizard._load_partial()["security_suite"] == saved["security_suite"]
    parsed = _write_vendor_onboarding_config(tmp_path, monkeypatch, selected["security_suite"])
    assert parsed["vendor_onboarding"]["resource_owner"] == owner
    assert parsed["vendor_onboarding"]["reviewed_uploads"] is False


@pytest.mark.parametrize("advanced", [None, {"connections": False, "vendor_management": False}])
def test_vendor_onboarding_opt_in_writes_all_runtime_dependencies(tmp_path, monkeypatch, advanced):
    from maverick import (
        ai_vendor_risk,
        config,
        connections,
        evidence_graph,
        model_risk_assurance,
        vendor_management,
        vendor_onboarding,
    )
    from maverick.vendor_onboarding_config import VendorOnboardingSettings

    original_advanced = None if advanced is None else dict(advanced)
    parsed = _write_vendor_onboarding_config(
        tmp_path, monkeypatch,
        {"vendor_onboarding": True, "vendor_onboarding_owner": "procurement"},
        advanced=advanced,
    )
    assert advanced == original_advanced, "deriving dependencies must not mutate caller selections"
    settings = VendorOnboardingSettings.from_config(parsed)
    assert settings.enable is True
    assert settings.resource_owner == "procurement"
    assert settings.document_connection == "gdrive"
    assert settings.ticket_connection == "jira"
    assert settings.document_connection != settings.ticket_connection
    assert settings.safe_read_attempts == 3
    assert settings.safe_read_backoff_seconds == 0.25
    for dependency in (
        "vendor_management", "connections", "evidence_graph", "model_risk_assurance", "ai_vendor_risk",
    ):
        assert parsed[dependency]["enable"] is True
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    try:
        assert vendor_onboarding.enabled()
        assert vendor_management.enabled()
        assert connections.enabled()
        assert evidence_graph.enabled()
        assert model_risk_assurance.enabled()
        assert ai_vendor_risk.enabled()
    finally:
        config.reset_config_cache()


def test_vendor_onboarding_writer_retains_disabled_default(tmp_path, monkeypatch):
    from maverick.vendor_onboarding_config import VendorOnboardingSettings

    parsed = _write_vendor_onboarding_config(tmp_path, monkeypatch, {})
    assert VendorOnboardingSettings.from_config(parsed).enable is False
    for dependency in (
        "vendor_management", "connections", "evidence_graph", "model_risk_assurance", "ai_vendor_risk",
    ):
        assert parsed.get(dependency, {}).get("enable", False) is False


def test_partial_progress_never_persists_oidc_secrets(tmp_path, monkeypatch):
    import json
    import os
    import stat

    from maverick_installer import wizard

    path = tmp_path / "wizard-partial.json"
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH", path)
    state = {"deployment": "desktop", "advanced": {"oidc": {
        "client_secret": "private-client-value", "session_secret": "private-session-value"}}}  # pragma: allowlist secret
    wizard._save_partial(state)
    assert json.loads(path.read_text()) == {"deployment": "desktop"}
    assert state["advanced"]["oidc"]["client_secret"] == "private-client-value"  # pragma: allowlist secret
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # Resume from a legacy file sanitizes it before returning the state.
    path.write_text(json.dumps(state))
    assert wizard._load_partial() == {"deployment": "desktop"}
    assert "private-client-value" not in path.read_text()
    assert "private-session-value" not in path.read_text()


def test_resume_refuses_when_legacy_secret_cleanup_fails(tmp_path, monkeypatch):
    import json

    from maverick import file_lock
    from maverick_installer import wizard

    path = tmp_path / "wizard-partial.json"
    path.write_text(json.dumps({"advanced": {"oidc": {"session_secret": "old-private-value"}}}))  # pragma: allowlist secret
    monkeypatch.setattr(wizard, "PARTIAL_STATE_PATH", path)
    def cannot_write(*args, **kwargs):
        raise OSError("not writable")
    monkeypatch.setattr(file_lock, "atomic_write_text", cannot_write)
    with pytest.raises(RuntimeError, match="Cannot securely remove old OIDC secrets"):
        wizard._load_partial()
