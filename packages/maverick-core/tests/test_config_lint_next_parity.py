"""Closed configuration gates for the next three OneTrust parity journeys."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def _valid_config() -> dict:
    return {
        "ai_inventory": {"enable": True},
        "ai_dynamic_risk": {"enable": True},
        "ai_policy_management": {"enable": True},
        "ai_runtime_guardrails": {"enable": True},
        "ai_governance_loop": {
            "enable": True,
            "poll_seconds": 300,
            "batch_size": 100,
            "lease_seconds": 120,
            "max_attempts": 5,
            "retry_base_seconds": 30,
            "max_lag_seconds": 900,
        },
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "trust_center": {"enable": True},
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "rights_consumer_intake": {
                "enable": True,
                "request_ttl_seconds": 86_400,
                "retention_seconds": 31_536_000,
                "max_active_requests": 1_000,
                "max_active_requests_per_subject": 25,
            },
        },
        "third_party_management": {
            "enable": True,
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


def test_next_parity_contract_is_closed_and_lint_clean() -> None:
    assert "ai_governance_loop" in KNOWN_SECTIONS
    assert lint_config(_valid_config()) == []


def test_ai_governance_loop_requires_every_runtime_authority() -> None:
    config = _valid_config()
    del config["ai_policy_management"]
    config["ai_governance_loop"]["raw_telemetry"] = True
    config["ai_governance_loop"]["lease_seconds"] = 29

    findings = lint_config(config)

    assert any(
        finding.section == "ai_governance_loop"
        and finding.key == "enable"
        and "ai_policy_management" in finding.message
        for finding in findings
    )

    config = _valid_config()
    config["ai_governance_loop"]["lease_seconds"] = 3_601
    assert any(
        finding.section == "ai_governance_loop"
        and finding.key == "lease_seconds"
        and finding.severity == "error"
        for finding in lint_config(config)
    )
    assert any(
        finding.section == "ai_governance_loop"
        and finding.key == "raw_telemetry"
        and finding.severity == "warning"
        for finding in findings
    )
    assert any(
        finding.section == "ai_governance_loop"
        and finding.key == "lease_seconds"
        and finding.severity == "error"
        for finding in findings
    )


def test_consumer_rights_intake_requires_all_server_owned_authorities() -> None:
    config = _valid_config()
    del config["consent_preferences"]["trust_center"]
    config["privacy_automation"]["rights_consumer_intake"]["raw_subject"] = True
    config["privacy_automation"]["rights_consumer_intake"]["max_active_requests"] = 0

    findings = lint_config(config)

    assert any(
        finding.section == "privacy_automation.rights_consumer_intake"
        and finding.key == "enable"
        and "consent_preferences.trust_center" in finding.message
        for finding in findings
    )
    assert any(
        finding.section == "privacy_automation.rights_consumer_intake"
        and finding.key == "raw_subject"
        and finding.severity == "warning"
        for finding in findings
    )
    assert any(
        finding.section == "privacy_automation.rights_consumer_intake"
        and finding.key == "max_active_requests"
        and finding.severity == "error"
        for finding in findings
    )

    config = _valid_config()
    config["privacy_automation"]["rights_consumer_intake"][
        "max_active_requests_per_subject"
    ] = 1_001
    assert any(
        finding.section == "privacy_automation.rights_consumer_intake"
        and finding.key == "max_active_requests_per_subject"
        and "tenant limit" in finding.message
        for finding in lint_config(config)
    )


def test_third_party_portal_requires_lifecycle_and_bounded_contract() -> None:
    config = _valid_config()
    config["third_party_management"]["lifecycle"]["enable"] = False
    portal = config["third_party_management"]["lifecycle"]["portal"]
    portal["raw_documents"] = True
    portal["invitation_ttl_seconds"] = 299

    findings = lint_config(config)

    assert any(
        finding.section == "third_party_management.lifecycle.portal"
        and finding.key == "enable"
        and "requires lifecycle" in finding.message
        for finding in findings
    )
    assert any(
        finding.section == "third_party_management.lifecycle.portal"
        and finding.key == "raw_documents"
        and finding.severity == "warning"
        for finding in findings
    )
    assert any(
        finding.section == "third_party_management.lifecycle.portal"
        and finding.key == "invitation_ttl_seconds"
        and finding.severity == "error"
        for finding in findings
    )


def test_new_boolean_gates_reject_string_truthiness() -> None:
    for path in (
        ("ai_governance_loop",),
        ("privacy_automation", "rights_consumer_intake"),
        ("third_party_management", "lifecycle", "portal"),
    ):
        config = _valid_config()
        table = config
        for part in path:
            table = table[part]
        table["enable"] = "yes"

        findings = lint_config(config)
        assert any(
            finding.section == ".".join(path)
            and finding.key == "enable"
            and finding.severity == "error"
            for finding in findings
        ), path
