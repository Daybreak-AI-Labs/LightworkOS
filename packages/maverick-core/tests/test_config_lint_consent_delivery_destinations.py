from __future__ import annotations

from copy import deepcopy

from maverick.config_lint import lint_config
from maverick.consent_delivery_destinations import build_consent_destination_registry


def _config() -> dict[str, object]:
    return {
        "consent_preferences": {
            "enable": True,
            "delivery": {
                "enable": True,
                "destinations": {
                    "enable": True,
                    "enabled_providers": [
                        "salesforce",
                        "marketo",
                        "adobe_experience_platform",
                        "snowflake",
                    ],
                    "timeout_seconds": 10.0,
                    "max_response_bytes": 65_536,
                    "salesforce": {
                        "destination_id": "salesforce",
                        "origin": "https://tenant.my.salesforce.com",
                        "credential_secret_ref": "${SALESFORCE_CONSENT_TOKEN}",
                        "credential_revision": 1,
                        "api_version": "v65.0",
                        "object_api_name": "Lightwork_Consent_Event__c",
                        "external_id_field": "Lightwork_Message_Id__c",
                        "payload_digest_field": "Lightwork_Payload_SHA256__c",
                    },
                    "marketo": {
                        "destination_id": "marketo",
                        "origin": "https://123-ABC-456.mktorest.com",
                        "credential_secret_ref": "$MARKETO_CONSENT_TOKEN",
                        "credential_revision": 1,
                        "custom_object_name": "lightworkConsentEvent",
                        "dedupe_field": "lightworkMessageId",
                        "message_id_field": "lightworkMessageId",
                        "payload_digest_field": "payloadSha256",
                    },
                    "adobe_experience_platform": {
                        "destination_id": "aep",
                        "origin": "https://dcs.adobedc.net",
                        "credential_secret_ref": "$AEP_CONSENT_CREDENTIAL",
                        "credential_revision": 1,
                        "connection_id": "connection-1",
                        "flow_id": "flow-1",
                        "dataset_id": "dataset-1",
                        "schema_id": "https://ns.adobe.com/tenant/schemas/consent",
                        "ims_org_id": "tenant@AdobeOrg",
                    },
                    "snowflake": {
                        "destination_id": "snowflake",
                        "origin": "https://account.region.snowflakecomputing.com",
                        "credential_secret_ref": "$SNOWFLAKE_CONSENT_TOKEN",
                        "credential_revision": 1,
                        "database": "LIGHTWORK",
                        "schema": "CONSENT",
                        "table": "PREFERENCE_EVENTS",
                        "warehouse": "LIGHTWORK_WH",
                        "role": "LIGHTWORK_CONSENT_WRITER",
                    },
                },
            },
        }
    }


def _messages(config: dict[str, object]) -> list[str]:
    return [finding.message for finding in lint_config(config)]


def test_named_consent_destinations_are_closed_and_runtime_compatible() -> None:
    config = _config()
    assert lint_config(config) == []
    registry = build_consent_destination_registry(config, "tenant-a")
    assert registry.status()["providers"] == [
        "adobe_experience_platform",
        "marketo",
        "salesforce",
        "snowflake",
    ]


def test_named_consent_destinations_reject_untrusted_authority_and_raw_credentials() -> None:
    config = _config()
    destinations = config["consent_preferences"]["delivery"]["destinations"]  # type: ignore[index]
    destinations["salesforce"]["origin"] = "https://attacker.example/forward"  # type: ignore[index]
    destinations["marketo"]["credential_secret_ref"] = "raw-oauth-token"  # type: ignore[index]
    destinations["snowflake"]["statement"] = "DELETE FROM anything"  # type: ignore[index]

    findings = lint_config(config)
    assert any(
        item.section.endswith("salesforce") and item.key == "origin"
        for item in findings
    )
    assert any(
        item.section.endswith("marketo")
        and item.key == "credential_secret_ref"
        and item.severity == "error"
        for item in findings
    )
    assert any(
        item.section.endswith("snowflake")
        and item.key == "statement"
        and item.severity == "warning"
        for item in findings
    )


def test_named_consent_destination_enablement_is_exact_bounded_and_unique() -> None:
    config = deepcopy(_config())
    delivery = config["consent_preferences"]["delivery"]  # type: ignore[index]
    delivery["enable"] = False  # type: ignore[index]
    destinations = delivery["destinations"]  # type: ignore[index]
    destinations["timeout_seconds"] = 61  # type: ignore[index]
    destinations["max_response_bytes"] = 1_048_577  # type: ignore[index]
    destinations["marketo"]["destination_id"] = "salesforce"  # type: ignore[index]
    del destinations["adobe_experience_platform"]["flow_id"]  # type: ignore[index]

    messages = _messages(config)
    assert any("require consent delivery to be enabled" in message for message in messages)
    assert any("identifiers must be unique" in message for message in messages)
    assert any("requires flow_id" in message for message in messages)
    findings = lint_config(config)
    assert any(item.key == "timeout_seconds" and item.severity == "error" for item in findings)
    assert any(item.key == "max_response_bytes" and item.severity == "error" for item in findings)


def test_unselected_named_provider_table_is_not_dormant_authority() -> None:
    config = _config()
    destinations = config["consent_preferences"]["delivery"]["destinations"]  # type: ignore[index]
    destinations["enabled_providers"] = ["salesforce"]  # type: ignore[index]

    messages = _messages(config)
    assert any("marketo settings cannot be configured" in message for message in messages)
    assert any(
        "adobe_experience_platform settings cannot be configured" in message
        for message in messages
    )
    assert any("snowflake settings cannot be configured" in message for message in messages)


def test_named_provider_list_with_inline_table_never_raises() -> None:
    config = _config()
    destinations = config["consent_preferences"]["delivery"]["destinations"]  # type: ignore[index]
    destinations["enabled_providers"] = [{"salesforce": True}]  # type: ignore[index,list-item]

    assert any(
        item.key == "enabled_providers" and item.severity == "error"
        for item in lint_config(config)
    )


def test_automatic_delivery_worker_switch_is_a_closed_boolean() -> None:
    def findings(worker):
        cfg = {"consent_preferences": {"enable": True, "delivery": {"enable": True, "worker": worker}}}
        return [(f.severity, f.key) for f in lint_config(cfg) if f.section.startswith("consent_preferences")]

    assert findings({"enable": False}) == []
    assert findings({"enable": True}) == []
    assert findings({"enable": "yes"}) == [("error", "enable")]
    assert findings({"enable": True, "destinations": ["x"]}) == [("warning", "destinations")]
