"""Closed configuration authority for Tech Risk & Compliance capabilities."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def test_policy_publication_links_are_known_with_both_gates_enabled():
    assert "tech_risk_compliance" in KNOWN_SECTIONS
    assert (
        lint_config(
            {
                "tech_risk_compliance": {
                    "enable": True,
                    "policy_publication_links": {"enable": True},
                    "scoping": {"enable": True},
                    "scope_actions": {"enable": True},
                }
            }
        )
        == []
    )


def test_policy_publication_links_require_root_gate_and_closed_boolean_shape():
    findings = lint_config(
        {
            "tech_risk_compliance": {
                "enable": False,
                "policy_publication_links": {
                    "enable": True,
                    "unsigned_content": True,
                },
            }
        }
    )
    assert any(
        item.key == "enable" and "requires [tech_risk_compliance] enable = true" in item.message
        for item in findings
    )
    assert any(item.key == "unsigned_content" and item.severity == "warning" for item in findings)

    wrong_type = lint_config(
        {
            "tech_risk_compliance": {
                "enable": True,
                "policy_publication_links": {"enable": "yes"},
            }
        }
    )
    assert any(item.key == "enable" and item.severity == "error" for item in wrong_type)


def test_compliance_scoping_requires_root_gate_and_closed_boolean_shape():
    findings = lint_config(
        {
            "tech_risk_compliance": {
                "enable": False,
                "scoping": {"enable": True, "framework_text": True},
            }
        }
    )
    assert any(
        item.key == "enable" and "requires [tech_risk_compliance] enable = true" in item.message
        for item in findings
    )
    assert any(item.key == "framework_text" and item.severity == "warning" for item in findings)

    wrong_type = lint_config(
        {
            "tech_risk_compliance": {
                "enable": True,
                "scoping": {"enable": "yes"},
            }
        }
    )
    assert any(item.key == "enable" and item.severity == "error" for item in wrong_type)


def test_compliance_scope_actions_require_root_gate_and_closed_boolean_shape():
    findings = lint_config(
        {
            "tech_risk_compliance": {
                "enable": False,
                "scope_actions": {"enable": True, "provider_write": True},
            }
        }
    )
    assert any(
        item.key == "enable" and "requires [tech_risk_compliance] enable = true" in item.message
        for item in findings
    )
    assert any(item.key == "provider_write" and item.severity == "warning" for item in findings)

    wrong_type = lint_config(
        {
            "tech_risk_compliance": {
                "enable": True,
                "scope_actions": {"enable": "yes"},
            }
        }
    )
    assert any(item.key == "enable" and item.severity == "error" for item in wrong_type)

    missing_scoping = lint_config(
        {
            "tech_risk_compliance": {
                "enable": True,
                "scoping": {"enable": False},
                "scope_actions": {"enable": True},
            }
        }
    )
    assert any(
        item.key == "enable"
        and item.severity == "error"
        and "require compliance scoping" in item.message
        for item in missing_scoping
    )
