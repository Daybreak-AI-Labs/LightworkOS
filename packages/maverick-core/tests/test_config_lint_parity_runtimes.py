from __future__ import annotations

from copy import deepcopy

from maverick.config_lint import lint_config


def valid_config():
    return {
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True},
            "enforcement": {"enable": True, "require_four_eyes": True},
            "provider_audit": {"enable": True},
            "snowflake": {
                "enable": True,
                "origin": "https://account.snowflakecomputing.com",
                "credential_secret_ref": "$SNOWFLAKE_TOKEN",
                "credential_revision": 1,
                "timeout_seconds": 10,
                "max_response_bytes": 65_536,
            },
        },
        "tech_risk_compliance": {
            "enable": True,
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
        },
    }


def messages(config):
    return [finding.message for finding in lint_config(config)]


def test_parity_runtime_config_is_closed_and_valid():
    assert lint_config(valid_config()) == []


def test_provider_audit_requires_enforcement_and_native_provider():
    config = valid_config()
    config["data_use_governance"]["enforcement"]["enable"] = False
    assert any("provider audit requires enforcement" in item for item in messages(config))


def test_continuous_evidence_requires_closed_collector_allowlist_and_parent():
    config = valid_config()
    config["tech_risk_compliance"]["continuous_evidence"]["enabled_collectors"] = [
        "local_soc2_v1",
        "local_soc2_v1",
    ]
    assert any("unique closed collector allowlist" in item for item in messages(config))

    config = valid_config()
    config["tech_risk_compliance"]["continuous_evidence"]["enable"] = False
    assert any("scheduler requires continuous evidence" in item for item in messages(config))


def test_third_party_runtime_requires_closed_providers_and_parent_chain():
    config = valid_config()
    config["third_party_management"]["intelligence"]["providers"]["enabled_providers"] = [
        "unknown-provider"
    ]
    assert any("unique closed provider list" in item for item in messages(config))

    config = valid_config()
    config["third_party_management"]["intelligence"]["providers"]["enable"] = False
    assert any("scheduler requires the provider runtime" in item for item in messages(config))

    config = valid_config()
    config["third_party_management"]["intelligence"]["enable"] = False
    assert any("provider runtime requires intelligence" in item for item in messages(config))


def test_generic_provider_requires_exact_hostname():
    config = valid_config()
    providers = config["third_party_management"]["intelligence"]["providers"]
    providers["enabled_providers"] = ["generic_approved"]
    providers["generic_approved_host"] = "https://attacker.test/path"
    assert any("exact deployment-trusted hostname" in item for item in messages(config))

    providers["generic_approved_host"] = "feeds.example.test"
    assert lint_config(config) == []


def test_runtime_bounds_and_unknown_keys_fail_lint():
    config = valid_config()
    config["tech_risk_compliance"]["continuous_evidence"]["scheduler"]["lease_seconds"] = 1
    config["third_party_management"]["intelligence"]["providers"]["timeout_seconds"] = 121
    config["data_use_governance"]["provider_audit"]["provider_url"] = "https://attacker.test"
    result = lint_config(deepcopy(config))
    assert any(finding.key == "lease_seconds" and finding.severity == "error" for finding in result)
    assert any(
        finding.key == "timeout_seconds" and finding.severity == "error" for finding in result
    )
    assert any(
        finding.key == "provider_url" and finding.severity == "warning" for finding in result
    )
