"""Installer coverage for the named governance capability prompts."""

from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def test_named_capability_prompts_enable_safe_dependencies(monkeypatch) -> None:
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    selected_prefixes = (
        "Enable governed task management for AI inventory entities",
        "Enable bounded multimodal AI Evidence Analysis",
        "Enable evidence-assisted assessment answer proposals",
        "Allow a separately approved proposal",
        "Enable role-aware, brandable third-party executive PDF reports",
        "Enable the packaged Breach Response",
    )

    def answer(prompt, *args, **kwargs):
        del args, kwargs
        return prompt.startswith(selected_prefixes)

    monkeypatch.setattr(wizard, "_q_confirm", answer)
    monkeypatch.setattr(
        wizard,
        "_q_checkbox",
        lambda *args, **kwargs: ["AWS Bedrock", "Azure AI Foundry", "Google Vertex AI"],
    )
    picked = wizard.pick_security_suite()

    assert picked["governance_agents"] is True
    assert picked["ai_entity_tasks"] is True
    assert picked["ai_evidence_analysis"] is True
    assert picked["assessment_evidence_autopopulation"] is True
    assert picked["assessment_evidence_apply"] is True
    assert picked["evidence_gateway"] is True
    assert picked["ai_inventory"] is True
    assert picked["ai_policy_management"] is False
    assert picked["ai_runtime_guardrails"] is False
    assert picked["policy_packs"] is False
    assert picked["third_party_management"]["executive_reports"]["enable"] is True

    rendered = tomllib.loads("\n".join(wizard._cfg_security_suite(picked)))
    assert rendered["governance_agents"]["enabled_agents"] == [
        "breach_response",
        "privacy_risk_assessment",
        "program_copilot",
        "knowledgebase_governance",
        "third_party_risk",
    ]
    assert rendered["governance_agents"]["context_projection_enable"] is True
    assert rendered["governance_agents"]["context_projection_max_records_per_source"] == 100
    assert rendered["governance_agents"]["context_projection_max_context_items"] == 32
    assert rendered["governance_agents"]["context_projection_max_total_bytes"] == 2_097_152
    assert rendered["governance_agents"]["context_projection_max_record_bytes"] == 16_384
    assert rendered["ai_entity_tasks"] == {
        "enable": True,
        "max_tasks": 100_000,
        "retention_seconds": 31_536_000,
        "authority_max_age_seconds": 604_800,
    }
    assert rendered["ai_evidence_analysis"]["enabled_media_types"] == [
        "pdf",
        "jpeg",
        "png",
        "xlsx",
        "text",
    ]
    assert rendered["ai_evidence_analysis"]["max_authority_records"] == 100_000
    assert rendered["ai_evidence_analysis"]["ocr"]["enable"] is False
    assert rendered["ai_evidence_analysis"]["legacy_xls"]["enable"] is False
    assert rendered["assessment_evidence_autopopulation"] == {
        "enable": True,
        "apply_enabled": True,
        "retention_seconds": 31_536_000,
        "max_records": 10_000,
        "max_evidence_records_per_proposal": 32,
        "max_citations_per_answer": 32,
        "min_confidence_bps": 7_000,
    }
    assert rendered["third_party_management"]["executive_reports"] == {
        "enable": True,
        "max_reports": 10_000,
        "max_sources": 100,
        "max_pdf_bytes": 524_288,
        "retention_seconds": 31_536_000,
        "download_token_seconds": 300,
    }
    assert rendered["ai_inventory"]["connectors"] == [
        "bedrock",
        "azure_ai_foundry",
        "vertex_ai",
    ]
    assert lint_config(rendered) == []


def test_direct_writer_emits_exact_governed_ocr_and_legacy_xls_contracts() -> None:
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    rendered = tomllib.loads(
        "\n".join(
            wizard._cfg_security_suite(
                {
                    "ai_evidence_analysis": True,
                    "ai_evidence_ocr": True,
                    "ai_evidence_ocr_executable": "/opt/tesseract/bin/tesseract",
                    "ai_evidence_ocr_sha256": "a" * 64,
                    "ai_evidence_ocr_tesseract_version": "5.4.1",
                    "ai_evidence_ocr_traineddata_path": (
                        "/opt/tesseract/share/tessdata/eng.traineddata"
                    ),
                    "ai_evidence_ocr_traineddata_sha256": "b" * 64,
                    "ai_evidence_ocr_runtime_library_paths": [
                        "/opt/tesseract/lib/libtesseract.so"
                    ],
                    "ai_evidence_ocr_runtime_libraries_sha256": "c" * 64,
                    "ai_evidence_ocr_pillow_version": "12.3.0",
                    "ai_evidence_ocr_pillow_manifest_sha256": "d" * 64,
                    "ai_evidence_legacy_xls": True,
                    "ai_evidence_xlrd_manifest_sha256": "e" * 64,
                    "ai_evidence_olefile_manifest_sha256": "f" * 64,
                    "ai_evidence_parser_sandbox": True,
                    "ai_evidence_parser_sandbox_launcher": "/usr/bin/bwrap",
                    "ai_evidence_parser_sandbox_sha256": "1" * 64,
                    "ai_evidence_parser_sandbox_version": "0.11.0",
                }
            )
        )
    )

    assert rendered["ai_evidence_analysis"]["enabled_media_types"] == [
        "pdf",
        "jpeg",
        "png",
        "xls",
        "xlsx",
        "text",
    ]
    assert rendered["ai_evidence_analysis"]["ocr"] == {
        "enable": True,
        "executable": "/opt/tesseract/bin/tesseract",
        "executable_sha256": "a" * 64,
        "tesseract_version": "5.4.1",
        "traineddata_path": "/opt/tesseract/share/tessdata/eng.traineddata",
        "traineddata_sha256": "b" * 64,
        "runtime_library_paths": ["/opt/tesseract/lib/libtesseract.so"],
        "runtime_libraries_sha256": "c" * 64,
        "pillow_version": "12.3.0",
        "pillow_manifest_sha256": "d" * 64,
        "timeout_seconds": 30,
        "max_pixels": 40_000_000,
        "max_output_bytes": 1_048_576,
        "max_memory_bytes": 536_870_912,
    }
    assert rendered["ai_evidence_analysis"]["legacy_xls"]["enable"] is True
    assert rendered["ai_evidence_analysis"]["legacy_xls"]["xlrd_version"] == "2.0.2"
    assert rendered["ai_evidence_analysis"]["legacy_xls"]["xlrd_manifest_sha256"] == (
        "e" * 64
    )
    assert rendered["ai_evidence_analysis"]["legacy_xls"]["olefile_version"] == "0.47"
    assert rendered["ai_evidence_analysis"]["legacy_xls"]["olefile_manifest_sha256"] == (
        "f" * 64
    )
    assert rendered["ai_evidence_analysis"]["parser_sandbox"] == {
        "enable": True,
        "mode": "bubblewrap",
        "launcher": "/usr/bin/bwrap",
        "launcher_sha256": "1" * 64,
        "launcher_version": "0.11.0",
    }
    assert lint_config(rendered) == []


def test_direct_writer_keeps_named_capabilities_default_off() -> None:
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    rendered = tomllib.loads("\n".join(wizard._cfg_security_suite({})))
    assert rendered["ai_entity_tasks"]["enable"] is False
    assert rendered["governance_agents"]["enable"] is False
    assert rendered["ai_evidence_analysis"]["enable"] is False
    assert rendered["assessment_evidence_autopopulation"]["enable"] is False
    assert rendered["assessment_evidence_autopopulation"]["apply_enabled"] is False
    assert "ai_cloud_agent_governance" not in rendered
    assert rendered["administration_document_access"]["enable"] is False
    assert rendered["incident_attachment_metadata"]["enable"] is False
    assert lint_config(rendered) == []


def test_direct_writer_derives_fail_closed_dependencies() -> None:
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    rendered = tomllib.loads(
        "\n".join(
            wizard._cfg_security_suite(
                {
                    "ai_entity_tasks": True,
                    "governance_agents": True,
                    "ai_evidence_analysis": True,
                    "assessment_evidence_autopopulation": True,
                    "assessment_evidence_apply": True,
                }
            )
        )
    )
    assert rendered["evidence_gateway"]["enable"] is True
    assert rendered["assessment_evidence_autopopulation"]["enable"] is True
    assert rendered["assessment_evidence_autopopulation"]["apply_enabled"] is True
    assert rendered["ai_entity_tasks"]["enable"] is True
    assert rendered["ai_inventory"]["enable"] is True
    assert lint_config(rendered) == []
