"""config-lint must recognize the flagship governance config keys.

A regulated client configured the two
headline governance features straight from the docs --

    [audit]
    sign = true
    [capabilities]
    enforce = true

-- and `maverick config-lint` flagged [audit] as an unknown section ("did
you mean auth?") and capabilities.enforce as an unknown key, telling them
their flagship signed-audit + capability-enforcement config looked like
typos. Both are real keys the runtime reads (audit/writer.py:_resolve_signing,
capability.py:capability_enforced). The deferred_tools knob was missing too.
"""
from __future__ import annotations

import pytest
from maverick.config_lint import lint_config


def _unknown(findings, section):
    return [f for f in findings if f.section == section
            and ("unknown" in f.message.lower())]


def test_audit_sign_is_recognized():
    findings = lint_config({"audit": {"sign": True}})
    assert not _unknown(findings, "audit"), [f.message for f in findings]


def test_vendor_siem_credential_keys_are_recognized():
    # audit/forwarder.py reads these [audit] fallbacks for the Datadog and
    # Sentinel destinations. Referenced through env vars, as the lint asks, they
    # must lint clean: no "unknown key" warning and no inline-secret warning.
    cfg = {
        "audit": {
            "siem_dest": "datadog://datadoghq.com",
            "datadog_api_key": "${MAVERICK_DATADOG_API_KEY}",
            "sentinel_tenant_id": "${MAVERICK_SENTINEL_TENANT_ID}",
            "sentinel_client_id": "${MAVERICK_SENTINEL_CLIENT_ID}",
            "sentinel_client_secret": "${MAVERICK_SENTINEL_CLIENT_SECRET}",
        }
    }
    findings = lint_config(cfg)
    assert findings == [], [f.message for f in findings]


def test_capabilities_enforce_is_recognized():
    findings = lint_config({"capabilities": {"enforce": True}})
    assert not [f for f in findings if "enforce" in (f.key or "")], \
        [f.message for f in findings]


def test_capabilities_deferred_tools_is_recognized():
    findings = lint_config({"capabilities": {"deferred_tools": False}})
    assert not [f for f in findings if "deferred_tools" in (f.key or "")], \
        [f.message for f in findings]


def test_full_governed_config_lints_clean():
    cfg = {
        "providers": {"vllm": {"base_url": "http://localhost:8000/v1"}},
        "budget": {"max_dollars": 2.0},
        "safety": {"profile": "strict"},
        "audit": {"sign": True},
        "capabilities": {"enforce": True},
        "roles": {"ap_clerk": {"max_risk": "low"}},
    }
    errors = [f for f in lint_config(cfg) if f.severity == "error"]
    unknown = [f for f in lint_config(cfg) if "unknown" in f.message.lower()]
    assert not errors, [f.message for f in errors]
    assert not unknown, [f.message for f in unknown]


def test_a_real_typo_is_still_caught():
    # Known governance keys must not blunt the lint: a genuine unknown key still warns.
    findings = lint_config({"capabilities": {"enforcee": True}})
    assert any("enforcee" in (f.key or "") for f in findings), findings


def test_evidence_gateway_is_closed_and_boolean():
    assert lint_config({"evidence_gateway": {"enable": True}}) == []

    unknown = lint_config({"evidence_gateway": {"enabel": True}})
    assert any(
        finding.section == "evidence_gateway"
        and finding.key == "enabel"
        and "unknown" in finding.message.lower()
        for finding in unknown
    )

    wrong_type = lint_config({"evidence_gateway": {"enable": "true"}})
    assert any(
        finding.section == "evidence_gateway"
        and finding.key == "enable"
        and finding.severity == "error"
        for finding in wrong_type
    )


def test_grc_vendor_transport_tables_are_known_but_root_typos_are_not():
    config = {
        "grc_outbound_sync": {
            "enable": True,
            "targets": ["servicenow_irm", "archer"],
            "max_attempts_per_revision": 8,
            "servicenow_irm": {
                "credential_secret_ref": "SERVICENOW_TOKEN",
                "timeout_seconds": 15,
            },
            "archer": {
                "credential_secret_ref": "ARCHER_GRC_TOKEN",
                "max_response_bytes": 262144,
            },
        }
    }
    assert not _unknown(lint_config(config), "grc_outbound_sync")

    findings = lint_config({"grc_outbound_sync": {"servicenow_imr": {}}})
    assert any(
        item.section == "grc_outbound_sync"
        and item.key == "servicenow_imr"
        and "unknown" in item.message.lower()
        for item in findings
    )


def test_ai_cost_collector_tables_are_known_but_root_typos_are_not():
    config = {
        "ai_cost_roi": {
            "enable": True,
            "collector_poll_seconds": 86400,
            "collector_lookback_days": 1,
            "collector_limits": {"record_cap": 1000},
            "aws": {"enable": False},
            "azure": {"enable": False},
            "gcp": {"enable": False},
            "openai": {"enable": False},
        }
    }
    assert not _unknown(lint_config(config), "ai_cost_roi")

    findings = lint_config({"ai_cost_roi": {"collector_lookback_day": 1}})
    assert any(
        item.section == "ai_cost_roi"
        and item.key == "collector_lookback_day"
        and "unknown" in item.message.lower()
        for item in findings
    )


@pytest.mark.parametrize(
    "section",
    [
        "ai_dynamic_risk",
        "ai_policy_management",
        "ai_runtime_guardrails",
        "ai_explainability",
        "ai_conformity_workflow",
        "ai_insurability",
        "ai_regulated_verticals",
        "ai_bank_mrm",
        "ai_benchmark_exchange",
        "ai_discovery_sensors",
        "ai_media_provenance",
        "ai_identity_governance_connectors",
    ],
)
def test_new_operational_ai_governance_gates_are_closed_and_boolean(section):
    assert lint_config({section: {"enable": True}}) == []

    unknown = lint_config({section: {"enabel": True}})
    assert any(
        finding.section == section
        and finding.key == "enabel"
        and "unknown" in finding.message.lower()
        for finding in unknown
    )

    wrong_type = lint_config({section: {"enable": "true"}})
    assert any(
        finding.section == section
        and finding.key == "enable"
        and finding.severity == "error"
        for finding in wrong_type
    )


def test_vendor_portal_and_c2patool_are_closed_separate_opt_ins():
    assert lint_config(
        {
            "ai_vendor_risk": {"enable": True, "portal_enable": False},
            "ai_media_provenance": {
                "enable": True,
                "verification_adapter": "c2patool",
                "c2patool_executable_sha256": "a" * 64,
            },
        }
    ) == []

    portal_type = lint_config(
        {"ai_vendor_risk": {"enable": True, "portal_enable": "true"}}
    )
    assert any(
        finding.section == "ai_vendor_risk"
        and finding.key == "portal_enable"
        and finding.severity == "error"
        for finding in portal_type
    )

    unsupported = lint_config(
        {
            "ai_media_provenance": {
                "enable": True,
                "verification_adapter": "custom",
            }
        }
    )
    assert any(
        finding.section == "ai_media_provenance"
        and finding.key == "verification_adapter"
        and finding.severity == "error"
        for finding in unsupported
    )

    for digest in (None, "A" * 64, "not-a-digest"):
        selected = {
            "enable": True,
            "verification_adapter": "c2patool",
        }
        if digest is not None:
            selected["c2patool_executable_sha256"] = digest
        findings = lint_config({"ai_media_provenance": selected})
        assert any(
            finding.section == "ai_media_provenance"
            and finding.key == "c2patool_executable_sha256"
            and finding.severity == "error"
            for finding in findings
        )


def test_identity_scheduler_nested_tables_are_closed_and_bounded():
    provider_schedule = {
        "enable": False,
        "interval_seconds": 3600,
        "retry_base_seconds": 30,
        "retry_max_seconds": 900,
        "max_attempts_per_slot": 3,
        "lease_seconds": 3600,
        "history_limit": 8,
        "max_snapshot_items": 5000,
        "max_delta_digests": 256,
    }
    config = {
        "ai_identity_governance_connectors": {
            "enable": True,
            "scheduler": {
                "enable": False,
                "poll_seconds": 60,
                "providers": {
                    "entra": dict(provider_schedule),
                    "okta": dict(provider_schedule),
                    "purview": dict(provider_schedule),
                },
            },
        }
    }
    assert lint_config(config) == []

    typo = config["ai_identity_governance_connectors"]["scheduler"]["providers"]
    typo["entra"]["interval_second"] = typo["entra"].pop("interval_seconds")
    findings = lint_config(config)
    assert any(
        finding.section
        == "ai_identity_governance_connectors.scheduler.providers.entra"
        and finding.key == "interval_second"
        and "unknown" in finding.message.lower()
        for finding in findings
    )

    out_of_bounds = {
        "ai_identity_governance_connectors": {
            "enable": True,
            "scheduler": {
                "enable": True,
                "poll_seconds": 1,
                "providers": {
                    "entra": {"enable": True, "max_snapshot_items": 10001}
                },
            },
        }
    }
    errors = lint_config(out_of_bounds)
    assert any(finding.key == "poll_seconds" for finding in errors)
    assert any(finding.key == "max_snapshot_items" for finding in errors)


def test_identity_control_tables_are_closed_default_off_and_dependency_checked():
    config = {
        "ai_identity_governance_connectors": {
            "enable": True,
            "controls": {
                "enable": True,
                "change_coupling": {
                    "enable": True,
                    "dynamic_risk": True,
                    "alerts": True,
                },
                "federation": {"enable": True},
                "conditional_access": {"enable": True},
                "purview_writeback": {"enable": False},
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
            },
        }
    }
    assert lint_config(config) == []

    config["ai_identity_governance_connectors"]["controls"]["federation"][
        "enabled"
    ] = True
    findings = lint_config(config)
    assert any(
        finding.section
        == "ai_identity_governance_connectors.controls.federation"
        and finding.key == "enabled"
        and "unknown" in finding.message.lower()
        for finding in findings
    )

    invalid_production = {
        "ai_identity_governance_connectors": {
            "enable": True,
            "controls": {
                "enable": True,
                "production": {
                    "enable": True,
                    "mapping_revision": 0,
                    "mapping_retention_seconds": 299,
                    "max_authority_records": 10_001,
                    "max_observation_age_seconds": 3_601,
                    "max_future_skew_seconds": 301,
                    "outcome_max_attempts": 21,
                    "outcome_retry_base_seconds": 86_401,
                    "outcome_retry_max_seconds": 604_801,
                    "outcome_lease_seconds": 3_601,
                    "outcome_signal_validity_seconds": 59,
                    "purview_max_attempts": 11,
                    "purview_operation_lease_seconds": 4,
                    "credential": "forbidden",
                },
            },
        }
    }
    production_findings = lint_config(invalid_production)
    for key in (
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
    ):
        assert any(
            finding.section
            == "ai_identity_governance_connectors.controls.production"
            and finding.key == key
            and finding.severity == "error"
            for finding in production_findings
        )
    assert any(
        finding.section == "ai_identity_governance_connectors.controls.production"
        and finding.key == "credential"
        and "unknown" in finding.message.lower()
        for finding in production_findings
    )

    retry_order = config["ai_identity_governance_connectors"]["controls"]["production"]
    retry_order["outcome_retry_base_seconds"] = 120
    retry_order["outcome_retry_max_seconds"] = 60
    retry_findings = lint_config(config)
    assert any(
        finding.section == "ai_identity_governance_connectors.controls.production"
        and finding.key == "outcome_retry_max_seconds"
        and "greater than or equal" in finding.message
        for finding in retry_findings
    )

    dependencies = lint_config(
        {
            "ai_identity_governance_connectors": {
                "enable": False,
                "controls": {
                    "enable": False,
                    "change_coupling": {
                        "enable": True,
                        "dynamic_risk": False,
                        "alerts": False,
                    },
                },
            }
        }
    )
    assert any("controls.enable = true" in finding.message for finding in dependencies)
    assert any("dynamic_risk or alerts" in finding.message for finding in dependencies)

    for dependent in ("conditional_access", "purview_writeback"):
        missing_federation = lint_config(
            {
                "ai_identity_governance_connectors": {
                    "enable": True,
                    "controls": {
                        "enable": True,
                        "federation": {"enable": False},
                        dependent: {"enable": True},
                    },
                }
            }
        )
        assert any(
            finding.section
            == f"ai_identity_governance_connectors.controls.{dependent}"
            and "federation.enable = true" in finding.message
            for finding in missing_federation
        )


def test_no_code_grc_studio_is_parent_gated_closed_and_bounded() -> None:
    valid = {
        "tech_risk_compliance": {
            "enable": True,
            "grc_studio": {
                "enable": True,
                "max_studios": 10_000,
                "retention_seconds": 31_536_000,
                "max_import_bytes": 2_097_152,
            },
        }
    }
    assert lint_config(valid) == []

    invalid = {
        "tech_risk_compliance": {
            "enable": False,
            "grc_studio": {
                "enable": True,
                "max_studios": 0,
                "retention_seconds": 86_399,
                "max_import_bytes": 2_097_153,
                "raw_target_credentials": True,
            },
        }
    }
    findings = lint_config(invalid)
    assert any("requires [tech_risk_compliance] enable = true" in item.message for item in findings)
    for key in ("max_studios", "retention_seconds", "max_import_bytes"):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_target_credentials" and "unknown" in item.message.lower()
        for item in findings
    )


def test_shared_governance_inventory_is_closed_bounded_and_graph_gated() -> None:
    valid = {
        "entity_graph": {"enable": True},
        "governance_inventory": {
            "enable": True,
            "retention_seconds": 31_536_000,
            "max_source_records": 10_000,
            "max_entities": 20_000,
            "max_relationships": 40_000,
            "max_export_bytes": 10_485_760,
            "max_snapshots": 10_000,
        },
    }
    assert lint_config(valid) == []

    invalid = {
        "entity_graph": {"enable": False},
        "governance_inventory": {
            "enable": True,
            "retention_seconds": 86_399,
            "max_source_records": 0,
            "max_entities": 100_001,
            "max_relationships": 200_001,
            "max_export_bytes": 1_023,
            "max_snapshots": 1,
            "raw_source_ingest": True,
        },
    }
    findings = lint_config(invalid)
    assert any("requires [entity_graph] enable = true" in item.message for item in findings)
    for key in (
        "retention_seconds",
        "max_source_records",
        "max_entities",
        "max_relationships",
        "max_export_bytes",
        "max_snapshots",
    ):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_source_ingest" and "unknown" in item.message.lower()
        for item in findings
    )


def test_benchmark_trust_and_coordinator_tables_are_known_but_closed():
    config = {
        "ai_benchmark_exchange": {
            "enable": True,
            "trust_roots": {
                "schema": "lightwork.ai-benchmark-ed25519-trust-roots.v1",
                "version": 1,
                "keys": [
                    {
                        "key_id": "KEY-" + "a" * 32,
                        "public_key_hex": "b" * 64,
                        "introduced_in": 1,
                    }
                ],
            },
            "coordinator": {
                "enable": False,
                "timeout_seconds": 15,
                "max_request_bytes": 131072,
                "max_response_bytes": 131072,
            },
        }
    }
    assert lint_config(config) == []

    config["ai_benchmark_exchange"]["coordinator"]["endpont"] = (
        "https://benchmark.example.com"
    )
    findings = lint_config(config)
    assert any(
        finding.section == "ai_benchmark_exchange.coordinator"
        and finding.key == "endpont"
        and "unknown" in finding.message.lower()
        for finding in findings
    )

    enabled_without_origin = lint_config(
        {
            "ai_benchmark_exchange": {
                "enable": True,
                "coordinator": {"enable": True},
            }
        }
    )
    assert any(
        finding.section == "ai_benchmark_exchange.coordinator"
        and finding.key == "origin"
        and finding.severity == "error"
        for finding in enabled_without_origin
    )
