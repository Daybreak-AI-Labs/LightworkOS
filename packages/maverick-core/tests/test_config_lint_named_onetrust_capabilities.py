"""Closed configuration contracts for the named OneTrust parity increments."""

from __future__ import annotations

from maverick.config_lint import lint_config


def _valid_config() -> dict:
    return {
        "evidence_gateway": {"enable": True},
        "ai_inventory": {"enable": True},
        "ai_entity_tasks": {
            "enable": True,
            "max_tasks": 100_000,
            "retention_seconds": 31_536_000,
            "authority_max_age_seconds": 604_800,
        },
        "ai_policy_management": {"enable": True},
        "ai_runtime_guardrails": {"enable": True},
        "policy_packs": {"enable": True},
        "governance_agents": {
            "enable": True,
            "enabled_agents": [
                "breach_response",
                "privacy_risk_assessment",
                "program_copilot",
                "knowledgebase_governance",
                "third_party_risk",
            ],
            "context_projection_enable": True,
            "context_projection_max_records_per_source": 100,
            "context_projection_max_context_items": 32,
            "context_projection_max_total_bytes": 2_097_152,
            "context_projection_max_record_bytes": 16_384,
            "max_context_items": 100,
            "max_context_bytes": 1_048_576,
            "max_output_bytes": 262_144,
            "retention_seconds": 31_536_000,
        },
        "ai_evidence_analysis": {
            "enable": True,
            "enabled_media_types": ["pdf", "jpeg", "png", "xlsx", "text"],
            "max_artifact_bytes": 52_428_800,
            "max_artifacts_per_case": 20,
            "max_authority_records": 100_000,
            "max_extracted_text_bytes": 1_048_576,
            "retention_seconds": 31_536_000,
        },
        "assessment_evidence_autopopulation": {
            "enable": True,
            "apply_enabled": True,
            "retention_seconds": 31_536_000,
            "max_records": 10_000,
            "max_evidence_records_per_proposal": 32,
            "max_citations_per_answer": 32,
            "min_confidence_bps": 7_000,
        },
        "third_party_management": {
            "enable": True,
            "intelligence": {"enable": True},
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
        },
    }


def _messages(config: dict) -> list[str]:
    return [finding.message for finding in lint_config(config)]


def test_named_capability_configuration_is_closed_and_coherent() -> None:
    assert lint_config(_valid_config()) == []


def test_named_capability_allowlists_reject_unknown_duplicate_and_empty_values() -> None:
    config = _valid_config()
    config["governance_agents"]["enabled_agents"] = ["breach_response", "unknown"]
    config["ai_evidence_analysis"]["enabled_media_types"] = []

    messages = _messages(config)
    assert any("enabled_agents allowlist" in message for message in messages)
    assert any("enabled_media_types allowlist" in message for message in messages)


def test_named_capabilities_require_their_existing_authorities() -> None:
    config = _valid_config()
    del config["evidence_gateway"]
    del config["ai_inventory"]

    messages = _messages(config)
    assert any("packaged governance agents require" in message for message in messages)
    assert any("AI evidence analysis requires" in message for message in messages)


def test_named_capability_limits_reject_bool_fractional_and_out_of_range_values() -> None:
    config = _valid_config()
    config["governance_agents"]["max_context_items"] = True
    config["ai_entity_tasks"]["max_tasks"] = 0
    config["ai_evidence_analysis"]["max_artifacts_per_case"] = 2.5
    config["ai_evidence_analysis"]["max_authority_records"] = 3
    config["assessment_evidence_autopopulation"]["min_confidence_bps"] = 10_001
    config["third_party_management"]["contracts"]["max_records"] = 0
    config["third_party_management"]["executive_reports"]["max_pdf_bytes"] = 1_024

    messages = _messages(config)
    assert any("max_context_items must be an integer" in message for message in messages)
    assert any("max_tasks must be an integer between" in message for message in messages)
    assert any("max_artifacts_per_case must be an integer" in message for message in messages)
    assert any("max_authority_records must be an integer between" in message for message in messages)
    assert any("min_confidence_bps must be an integer between" in message for message in messages)
    assert any("max_records must be an integer between" in message for message in messages)
    assert any("max_pdf_bytes must be an integer between" in message for message in messages)


def test_named_capability_boolean_gates_are_strict() -> None:
    config = _valid_config()
    config["governance_agents"]["enable"] = "true"
    config["governance_agents"]["context_projection_enable"] = "yes"
    config["ai_entity_tasks"]["enable"] = "yes"
    config["ai_evidence_analysis"]["enable"] = 1
    config["assessment_evidence_autopopulation"]["apply_enabled"] = "yes"
    config["third_party_management"]["contracts"]["enable"] = "yes"
    config["third_party_management"]["executive_reports"]["enable"] = "yes"

    messages = _messages(config)
    assert any("governance_agents.enable must be true or false" in message for message in messages)
    assert any(
        "governance_agents.context_projection_enable must be true or false" in message
        for message in messages
    )
    assert any("ai_entity_tasks.enable must be true or false" in message for message in messages)
    assert any(
        "ai_evidence_analysis.enable must be true or false" in message for message in messages
    )
    assert any(
        "assessment_evidence_autopopulation.apply_enabled must be true or false" in message
        for message in messages
    )
    assert any(
        "third_party_management.contracts.enable must be true or false" in message
        for message in messages
    )
    assert any(
        "third_party_management.executive_reports.enable must be true or false" in message
        for message in messages
    )


def test_governance_agent_context_projection_is_parent_gated_and_bounded() -> None:
    config = _valid_config()
    config["governance_agents"]["enable"] = False
    messages = _messages(config)
    assert any(
        "context projection requires governance_agents.enable" in message
        for message in messages
    )

    config = _valid_config()
    config["governance_agents"]["context_projection_max_records_per_source"] = 501
    config["governance_agents"]["context_projection_max_context_items"] = 101
    config["governance_agents"]["context_projection_max_total_bytes"] = 1_023
    config["governance_agents"]["context_projection_max_record_bytes"] = 65_537
    messages = _messages(config)
    for key in (
        "context_projection_max_records_per_source",
        "context_projection_max_context_items",
        "context_projection_max_total_bytes",
        "context_projection_max_record_bytes",
    ):
        assert any(key in message and "integer between" in message for message in messages)


def test_ai_entity_tasks_require_inventory_and_reject_unknown_keys() -> None:
    config = _valid_config()
    config["ai_inventory"]["enable"] = False
    config["ai_entity_tasks"]["unsafe_override"] = True

    messages = _messages(config)
    assert any("AI entity task management requires" in message for message in messages)
    assert any("unknown key" in message and "unsafe_override" in message for message in messages)


def test_third_party_contracts_require_parent_and_reject_unknown_keys() -> None:
    config = _valid_config()
    config["third_party_management"]["enable"] = False
    config["third_party_management"]["contracts"]["unsafe_override"] = True

    messages = _messages(config)
    assert any(
        "enabled third_party_management.contracts requires [third_party_management] enable = true"
        in message
        for message in messages
    )
    assert any("unknown key" in message and "unsafe_override" in message for message in messages)


def test_third_party_contracts_require_local_vendor_authority() -> None:
    config = _valid_config()
    config["third_party_management"]["intelligence"]["enable"] = False

    messages = _messages(config)
    assert any(
        "third-party contracts require the local intelligence vendor authority" in message
        for message in messages
    )


def test_third_party_executive_reports_require_parent_and_reject_unknown_keys() -> None:
    config = _valid_config()
    config["third_party_management"]["enable"] = False
    config["third_party_management"]["executive_reports"]["unsafe_override"] = True

    messages = _messages(config)
    assert any(
        "enabled third_party_management.executive_reports requires [third_party_management] enable = true"
        in message
        for message in messages
    )
    assert any("unknown key" in message and "unsafe_override" in message for message in messages)


def test_assessment_evidence_proposals_require_analysis_and_reject_unknown_keys() -> None:
    config = _valid_config()
    config["ai_evidence_analysis"]["enable"] = False
    config["assessment_evidence_autopopulation"]["unsafe_override"] = True

    messages = _messages(config)
    assert any("assessment evidence proposals require" in message for message in messages)
    assert any("unknown key" in message and "unsafe_override" in message for message in messages)


def test_ai_evidence_local_parser_configuration_is_exact_default_off_and_bounded() -> None:
    disabled = _valid_config()
    disabled["ai_evidence_analysis"]["ocr"] = {"enable": False}
    disabled["ai_evidence_analysis"]["legacy_xls"] = {"enable": False}
    assert lint_config(disabled) == []

    enabled = _valid_config()
    enabled["ai_evidence_analysis"]["enabled_media_types"].insert(3, "xls")
    enabled["ai_evidence_analysis"]["parser_sandbox"] = {
        "enable": True,
        "mode": "bubblewrap",
        "launcher": "/usr/bin/bwrap",
        "launcher_sha256": "b" * 64,
        "launcher_version": "0.11.0",
    }
    enabled["ai_evidence_analysis"]["ocr"] = {
        "enable": True,
        "executable": "/opt/tesseract/bin/tesseract",
        "executable_sha256": "a" * 64,
        "tesseract_version": "5.4.1",
        "traineddata_path": "/opt/tesseract/share/tessdata/eng.traineddata",
        "traineddata_sha256": "c" * 64,
        "runtime_library_paths": ["/opt/tesseract/lib/libtesseract.so"],
        "runtime_libraries_sha256": "d" * 64,
        "pillow_version": "12.3.0",
        "pillow_manifest_sha256": "e" * 64,
        "timeout_seconds": 30,
        "max_pixels": 40_000_000,
        "max_output_bytes": 1_048_576,
        "max_memory_bytes": 536_870_912,
    }
    enabled["ai_evidence_analysis"]["legacy_xls"] = {
        "enable": True,
        "xlrd_version": "2.0.2",
        "xlrd_manifest_sha256": "f" * 64,
        "olefile_version": "0.47",
        "olefile_manifest_sha256": "1" * 64,
        "timeout_seconds": 15,
        "max_workbook_stream_bytes": 33_554_432,
        "max_record_bytes": 8_388_608,
        "max_records": 500_000,
        "max_sheets": 200,
        "max_rows_per_sheet": 200_000,
        "max_columns_per_sheet": 256,
        "max_cells": 200_000,
        "max_output_bytes": 1_048_576,
        "max_memory_bytes": 536_870_912,
    }
    assert lint_config(enabled) == []

    enabled["ai_evidence_analysis"]["ocr"]["executable_sha256"] = "latest"
    enabled["ai_evidence_analysis"]["legacy_xls"]["xlrd_version"] = ""
    enabled["ai_evidence_analysis"]["legacy_xls"]["max_record_bytes"] = 40_000_000
    enabled["ai_evidence_analysis"]["legacy_xls"]["unknown"] = True
    messages = _messages(enabled)
    assert any("exact lowercase executable_sha256" in message for message in messages)
    assert any("exact xlrd_version" in message for message in messages)
    assert any("record bound cannot exceed" in message for message in messages)
    assert any("unknown key" in message and "unknown" in message for message in messages)


def test_ai_evidence_local_parser_requires_absolute_paths_and_sandbox() -> None:
    config = _valid_config()
    config["ai_evidence_analysis"]["ocr"] = {
        "enable": True,
        "executable": "tesseract",
        "executable_sha256": "a" * 64,
        "tesseract_version": "5.4.1",
        "traineddata_path": "eng.traineddata",
        "traineddata_sha256": "b" * 64,
        "runtime_library_paths": ["libtesseract.so"],
        "runtime_libraries_sha256": "c" * 64,
        "pillow_version": "12.3.0",
        "pillow_manifest_sha256": "d" * 64,
    }
    messages = _messages(config)
    assert any("executable" in message and "absolute" in message for message in messages)
    assert any("traineddata_path" in message and "absolute" in message for message in messages)
    assert any("runtime library paths" in message for message in messages)
    assert any("enforceable parser sandbox" in message for message in messages)
