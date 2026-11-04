from __future__ import annotations

from copy import deepcopy

from maverick.config_lint import lint_config


def config() -> dict[str, object]:
    return {
        "tech_risk_compliance": {
            "enable": True,
            "continuous_evidence": {
                "enable": True,
                "enabled_collectors": ["local_soc2_v1", "aws_security_hub_v1"],
                "stock_collectors": {
                    "enable": True,
                    "sources": [
                        {
                            "enrollment_id": "aws_security_hub_enrollment",
                            "definition_id": "aws_security_hub_definition",
                            "definition_version": 1,
                            "definition_integrity_sha256": "a" * 64,
                            "collector_key_id": "aws_security_hub_key_v1",
                            "capability_revision": 1,
                            "provider": "aws_security_hub",
                            "origin": "https://securityhub.us-east-1.amazonaws.com",
                            "scope_ref": "123456789012",
                            "credential_env": "LIGHTWORK_AWS_SECURITY_HUB_CREDENTIAL",
                            "region": "us-east-1",
                            "bindings": [
                                {"control_ref": "control-a", "source_ref": "IAM.1"}
                            ],
                            "limits": {
                                "timeout_seconds": 15,
                                "max_elapsed_seconds": 120,
                                "max_response_bytes": 262_144,
                                "page_size": 100,
                                "max_pages": 50,
                                "max_records": 10_000,
                            },
                        }
                    ],
                },
                "scheduler": {"enable": True},
            },
        }
    }


def messages(value: dict[str, object]) -> list[str]:
    return [finding.message for finding in lint_config(value)]


def test_stock_collector_manifest_is_a_valid_closed_config_contract():
    assert lint_config(config()) == []


def test_stock_collector_manifest_rejects_unallowlisted_or_unsafe_authority():
    value = config()
    value["tech_risk_compliance"]["continuous_evidence"]["enabled_collectors"] = [
        "local_soc2_v1"
    ]
    assert any("tenant collector allowlist" in item for item in messages(value))

    value = config()
    source = value["tech_risk_compliance"]["continuous_evidence"]["stock_collectors"][
        "sources"
    ][0]
    source["origin"] = "https://attacker.example"
    assert any("source authority is invalid" in item for item in messages(value))


def test_stock_collector_manifest_rejects_disabled_parent_and_unknown_fields():
    value = config()
    value["tech_risk_compliance"]["continuous_evidence"]["enable"] = False
    assert any("require Tech Risk continuous evidence" in item for item in messages(value))

    value = deepcopy(config())
    value["tech_risk_compliance"]["continuous_evidence"]["stock_collectors"][
        "provider_url"
    ] = "https://attacker.example"
    findings = lint_config(value)
    assert any(finding.key == "provider_url" for finding in findings)
