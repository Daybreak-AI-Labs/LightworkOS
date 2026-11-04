"""Closed gates for the next OneTrust parity product increment."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def _enabled_config() -> dict:
    return {
        "consent_preferences": {
            "enable": True,
            "experiments": {"enable": True},
        },
        "privacy_automation": {
            "enable": True,
            "regulatory_intelligence": {"enable": True},
        },
        "third_party_management": {
            "enable": True,
            "intelligence": {"enable": True},
            "lifecycle": {"enable": True},
        },
    }


def test_onetrust_intelligence_product_gates_are_known_and_lint_clean() -> None:
    assert "third_party_management" in KNOWN_SECTIONS
    assert lint_config(_enabled_config()) == []


def test_onetrust_intelligence_children_require_exact_parent_opt_in() -> None:
    config = _enabled_config()
    config["consent_preferences"]["enable"] = False
    config["privacy_automation"]["enable"] = False
    config["third_party_management"]["enable"] = False

    findings = lint_config(config)
    messages = {finding.message for finding in findings}

    assert any(
        "consent_preferences.experiments" in message
        and "requires [consent_preferences] enable = true" in message
        for message in messages
    )
    assert any(
        "privacy_automation.regulatory_intelligence" in message
        and "requires [privacy_automation] enable = true" in message
        for message in messages
    )
    assert any(
        "third_party_management.intelligence" in message
        and "requires [third_party_management] enable = true" in message
        for message in messages
    )
    assert any(
        "third_party_management.lifecycle" in message
        and "requires [third_party_management] enable = true" in message
        for message in messages
    )


def test_onetrust_intelligence_gates_are_closed_and_boolean() -> None:
    config = _enabled_config()
    config["consent_preferences"]["experiments"]["unexpected"] = True
    config["privacy_automation"]["regulatory_intelligence"]["enable"] = "yes"
    config["third_party_management"]["intelligence"]["unexpected"] = True
    config["third_party_management"]["lifecycle"]["enable"] = "yes"

    findings = lint_config(config)

    assert any(
        finding.section == "consent_preferences.experiments"
        and finding.key == "unexpected"
        and finding.severity == "warning"
        for finding in findings
    )
    assert any(
        finding.section == "privacy_automation.regulatory_intelligence"
        and finding.key == "enable"
        and finding.severity == "error"
        for finding in findings
    )
    assert any(
        finding.section == "third_party_management.intelligence"
        and finding.key == "unexpected"
        and finding.severity == "warning"
        for finding in findings
    )
    assert any(
        finding.section == "third_party_management.lifecycle"
        and finding.key == "enable"
        and finding.severity == "error"
        for finding in findings
    )
