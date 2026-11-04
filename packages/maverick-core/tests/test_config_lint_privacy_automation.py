"""Closed configuration authority for Privacy Automation data discovery."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def test_privacy_automation_discovery_is_known_and_valid_when_both_gates_are_true():
    assert "privacy_automation" in KNOWN_SECTIONS
    assert (
        lint_config(
            {
                "privacy_automation": {
                    "enable": True,
                    "data_discovery": {"enable": True},
                    "rights_orchestration": {"enable": True},
                }
            }
        )
        == []
    )


def test_privacy_discovery_requires_root_gate_and_closed_boolean_shape():
    findings = lint_config(
        {
            "privacy_automation": {
                "enable": False,
                "data_discovery": {"enable": True, "raw_samples": True},
            }
        }
    )
    assert any(
        item.key == "enable" and "requires [privacy_automation] enable = true" in item.message
        for item in findings
    )
    assert any(item.key == "raw_samples" and item.severity == "warning" for item in findings)

    wrong_type = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "data_discovery": {"enable": "yes"},
            }
        }
    )
    assert any(item.key == "enable" and item.severity == "error" for item in wrong_type)


def test_privacy_rights_orchestration_requires_exact_closed_boolean_gate():
    parent_off = lint_config(
        {
            "privacy_automation": {
                "enable": False,
                "rights_orchestration": {
                    "enable": True,
                    "raw_subjects": True,
                },
            }
        }
    )
    assert any(
        item.section == "privacy_automation.rights_orchestration"
        and item.key == "enable"
        and "requires [privacy_automation] enable = true" in item.message
        for item in parent_off
    )
    assert any(
        item.section == "privacy_automation.rights_orchestration"
        and item.key == "raw_subjects"
        and item.severity == "warning"
        for item in parent_off
    )
    wrong_type = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": "yes"},
            }
        }
    )
    assert any(
        item.section == "privacy_automation.rights_orchestration"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_rights_consumer_delivery_requires_orchestration_and_closed_gate():
    assert (
        lint_config(
            {
                "privacy_automation": {
                    "enable": True,
                    "rights_orchestration": {"enable": True},
                    "rights_consumer_delivery": {
                        "enable": True,
                        "digest_key_ref": (
                            "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_DIGEST_KEY"
                        ),
                        "export_signing_key_ref": (
                            "env:MAVERICK_PRIVACY_RIGHTS_DELIVERY_EXPORT_KEY"
                        ),
                        "package_encryption_key_ref": "env:MAVERICK_ENCRYPTION_KEY",
                        "server_grant_ttl_seconds": 30,
                        "max_package_bytes": 16_777_216,
                    },
                }
            }
        )
        == []
    )

    findings = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "rights_consumer_delivery": {
                    "enable": True,
                    "raw_response_bytes": True,
                },
            }
        }
    )
    assert any(
        item.section == "privacy_automation.rights_consumer_delivery"
        and item.key == "enable"
        and "requires rights orchestration" in item.message
        for item in findings
    )
    assert any(
        item.section == "privacy_automation.rights_consumer_delivery"
        and item.key == "raw_response_bytes"
        and item.severity == "warning"
        for item in findings
    )
    assert any(
        item.section == "privacy_automation.rights_consumer_delivery"
        and item.key == "digest_key_ref"
        and item.severity == "error"
        for item in findings
    )

    wrong_type = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "rights_consumer_delivery": {"enable": "yes"},
            }
        }
    )
    assert any(
        item.section == "privacy_automation.rights_consumer_delivery"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_ott_ctv_rights_requires_every_identity_and_orchestration_authority():
    valid = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "identity": {
                "enable": True,
                "issuer": "https://id.example.test",
                "audience": "lightwork-consent",
                "jwks_origin": "https://keys.example.test",
                "token_ttl_seconds": 300,
            },
            "trust_center": {"enable": True},
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "ott_ctv_rights": {"enable": True},
        },
    }
    assert lint_config(valid) == []

    missing = {
        "privacy_automation": {
            "enable": True,
            "ott_ctv_rights": {"enable": True, "raw_device_id": True},
        }
    }
    findings = lint_config(missing)
    assert any(
        item.section == "privacy_automation.ott_ctv_rights"
        and item.key == "enable"
        and "consent_preferences.identity" in item.message
        and "privacy_automation.rights_orchestration" in item.message
        for item in findings
    )
    assert any(
        item.section == "privacy_automation.ott_ctv_rights"
        and item.key == "raw_device_id"
        and item.severity == "warning"
        for item in findings
    )

    wrong_type = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "ott_ctv_rights": {"enable": "yes"},
            }
        }
    )
    assert any(
        item.section == "privacy_automation.ott_ctv_rights"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_drop_management_is_closed_and_requires_rights_orchestration():
    valid = {
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "drop_management": {
                "enable": True,
                "principal_binding_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
                "retention_seconds": 31_536_000,
                "scheduler_enable": True,
                "scheduler_interval_seconds": 3_600,
                "scheduler_jitter_seconds": 60,
                "scheduler_retry_max_seconds": 900,
            },
        }
    }
    assert lint_config(valid) == []

    missing_parent = {
        "privacy_automation": {
            "enable": True,
            "drop_management": {
                "enable": True,
                "principal_binding_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
                "retention_seconds": 31_536_000,
            },
        }
    }
    findings = lint_config(missing_parent)
    assert any(
        item.section == "privacy_automation.drop_management"
        and "rights orchestration" in item.message
        for item in findings
    )

    unsafe = {
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "drop_management": {
                "enable": True,
                "retention_seconds": 1,
                "principal_binding_key_ref": "literal-key-material-is-forbidden",
                "scheduler_enable": "yes",
                "scheduler_interval_seconds": 29,
                "scheduler_jitter_seconds": 3_600,
                "scheduler_retry_max_seconds": 29,
                "raw_email": True,
            },
        }
    }
    findings = lint_config(unsafe)
    assert any(
        item.section == "privacy_automation.drop_management" and item.key == "raw_email"
        for item in findings
    )
    assert any(
        item.section == "privacy_automation.drop_management"
        and item.key == "retention_seconds"
        for item in findings
    )
    assert {
        "principal_binding_key_ref",
        "scheduler_enable",
        "scheduler_interval_seconds",
        "scheduler_jitter_seconds",
        "scheduler_retry_max_seconds",
    }.issubset(
        {
            item.key
            for item in findings
            if item.section == "privacy_automation.drop_management"
        }
    )

    kms = valid["privacy_automation"]["drop_management"].copy()
    kms["principal_binding_key_ref"] = "azure-keyvault://lightwork/drop/principal-v1"
    assert lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": True},
                "drop_management": kms,
            }
        }
    ) == []


def test_privacy_notice_governance_requires_exact_closed_boolean_gate():
    assert (
        lint_config(
            {
                "privacy_automation": {
                    "enable": True,
                    "notice_governance": {"enable": True},
                }
            }
        )
        == []
    )

    findings = lint_config(
        {
            "privacy_automation": {
                "enable": False,
                "notice_governance": {
                    "enable": True,
                    "raw_notice_content": True,
                },
            }
        }
    )
    assert any(
        item.section == "privacy_automation.notice_governance"
        and item.key == "enable"
        and "requires [privacy_automation] enable = true" in item.message
        for item in findings
    )
    assert any(
        item.section == "privacy_automation.notice_governance"
        and item.key == "raw_notice_content"
        and item.severity == "warning"
        for item in findings
    )

    wrong_type = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "notice_governance": {"enable": "yes"},
            }
        }
    )
    assert any(
        item.section == "privacy_automation.notice_governance"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_privacy_rights_source_adapters_are_closed_bound_and_lease_safe():
    valid = {
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {
                "enable": True,
                "source_adapters": {
                    "enable": True,
                    "timeout_seconds": 15,
                    "max_response_bytes": 1_048_576,
                    "max_retrieval_bytes": 8_388_608,
                    "max_records": 200,
                    "batch_size": 10,
                    "lease_seconds": 60,
                    "retry_delay_seconds": 30,
                    "claim_history_retention_seconds": 86_400,
                    "target_custody_retention_seconds": 2_592_000,
                    "providers": {
                        "microsoft_graph_users": {
                            "enable": True,
                            "source_id": "directory-graph",
                            "origin": "https://graph.microsoft.com",
                            "credential_ref": "env:GRAPH_RIGHTS_TOKEN",
                            "capabilities": [
                                "discover",
                                "retrieve",
                                "delete",
                                "verify_delete",
                            ],
                        }
                    },
                },
            },
        }
    }
    assert lint_config(valid) == []

    invalid = valid.copy()
    invalid["privacy_automation"] = {
        **valid["privacy_automation"],
        "rights_orchestration": {
            "enable": True,
            "source_adapters": {
                **valid["privacy_automation"]["rights_orchestration"][
                    "source_adapters"
                ],
                "timeout_seconds": 30,
                "lease_seconds": 60,
            },
        },
    }
    findings = lint_config(invalid)
    assert any(
        item.section
        == "privacy_automation.rights_orchestration.source_adapters"
        and item.key == "lease_seconds"
        and "lookup plus mutation I/O" in item.message
        for item in findings
    )


def test_privacy_discovery_stock_adapters_and_data_map_are_closed_and_bounded():
    valid = {
        "privacy_automation": {
            "enable": True,
            "data_discovery": {
                "enable": True,
                "adapters": {
                    "enable": True,
                    "enabled_providers": [
                        "aws_s3",
                        "azure_blob",
                        "google_cloud_storage",
                        "snowflake_metadata",
                        "servicenow_cmdb",
                        "entra_assets",
                    ],
                    "timeout_seconds": 15.0,
                    "max_response_bytes": 8_388_608,
                    "page_size": 250,
                    "max_pages": 500,
                    "max_attempts": 3,
                    "max_polls": 8,
                },
                "remediation": {
                    "enable": True,
                    "max_attempts": 5,
                    "retention_seconds": 2_592_000,
                    "data_map": {
                        "enable": True,
                        "retention_seconds": 31_536_000,
                    },
                    "scheduler": {
                        "enable": True,
                        "interval_seconds": 60,
                        "jitter_seconds": 10,
                        "retry_max_seconds": 300,
                        "tenant_limit": 1_000,
                        "worker_limit": 10,
                        "reconcile_limit": 10,
                        "lease_seconds": 60,
                    },
                },
            },
        }
    }
    assert lint_config(valid) == []

    invalid = {
        "privacy_automation": {
            "enable": True,
            "data_discovery": {
                "enable": False,
                "adapters": {
                    "enable": True,
                    "enabled_providers": ["aws_s3", "aws_s3", "not_real"],
                    "timeout_seconds": 60.1,
                    "max_response_bytes": 1_023,
                    "page_size": 0,
                    "max_pages": 10_001,
                    "max_attempts": 6,
                    "max_polls": 101,
                    "raw_credentials": True,
                },
                "remediation": {
                    "enable": False,
                    "max_attempts": 21,
                    "retention_seconds": 59,
                    "data_map": {
                        "enable": True,
                        "retention_seconds": 316_224_001,
                    },
                    "scheduler": {
                        "enable": True,
                        "interval_seconds": 4,
                        "jitter_seconds": 3_601,
                        "retry_max_seconds": 86_401,
                        "tenant_limit": 10_001,
                        "worker_limit": 101,
                        "reconcile_limit": 101,
                        "lease_seconds": 3_601,
                        "raw_tenant": "tenant-a",
                    },
                },
            },
        }
    }
    findings = lint_config(invalid)
    assert any("adapters require privacy data discovery" in item.message for item in findings)
    assert any(
        item.key == "enabled_providers" and item.severity == "error"
        for item in findings
    )
    assert any("data-map target requires remediation" in item.message for item in findings)
    assert any(
        item.section
        == "privacy_automation.data_discovery.remediation.scheduler"
        and item.key == "raw_tenant"
        for item in findings
    )

    remediation_without_data_map = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "data_discovery": {
                    "enable": True,
                    "remediation": {
                        "enable": True,
                        "data_map": {"enable": False},
                    },
                },
            }
        }
    )
    assert any(
        "stock privacy discovery remediation requires data_map.enable = true"
        in item.message
        for item in remediation_without_data_map
    )

    scheduler_without_remediation = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "data_discovery": {
                    "enable": True,
                    "remediation": {
                        "enable": False,
                        "data_map": {"enable": False},
                        "scheduler": {"enable": True},
                    },
                },
            }
        }
    )
    assert any(
        "scheduler requires remediation to be enabled" in item.message
        for item in scheduler_without_remediation
    )

    jitter_exceeds_interval = lint_config(
        {
            "privacy_automation": {
                "enable": True,
                "data_discovery": {
                    "enable": True,
                    "remediation": {
                        "enable": True,
                        "data_map": {"enable": True},
                        "scheduler": {
                            "enable": True,
                            "interval_seconds": 30,
                            "jitter_seconds": 31,
                        },
                    },
                },
            }
        }
    )
    assert any(
        "jitter_seconds cannot exceed interval_seconds" in item.message
        for item in jitter_exceeds_interval
    )
    for key in (
        "timeout_seconds",
        "max_response_bytes",
        "page_size",
        "max_pages",
        "max_attempts",
        "max_polls",
        "retention_seconds",
    ):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_credentials" and item.severity == "warning"
        for item in findings
    )


def test_privacy_notice_publication_runtime_requires_exact_closed_bindings() -> None:
    valid = {
        "consent_preferences": {"enable": True, "publishing": {"enable": True}},
        "privacy_automation": {
            "enable": True,
            "notice_governance": {
                "enable": True,
                "publication_runtime": {
                    "enable": True,
                    "scheduler_enable": True,
                    "active_tenants": ["tenant-a"],
                    "poll_seconds": 30,
                    "retry_max_seconds": 300,
                    "tenant_limit": 100,
                    "lease_seconds": 60,
                    "retry_delay_seconds": 60,
                    "bindings": {
                        "primary": {
                            "tenant_id": "tenant-a",
                            "notice_id": "privacy-main",
                            "consent_publication_ref": "consent-binding:1",
                            "property_id": "property-main",
                            "rule_group_id": "production-rules",
                            "rule_group_version": 1,
                            "notice_resource_id": "privacy-notice",
                            "notice_resource_version": 1,
                        }
                    },
                },
            },
        },
    }
    assert lint_config(valid) == []

    invalid = {
        **valid,
        "privacy_automation": {
            **valid["privacy_automation"],
            "notice_governance": {
                **valid["privacy_automation"]["notice_governance"],
                "publication_runtime": {
                    **valid["privacy_automation"]["notice_governance"][
                        "publication_runtime"
                    ],
                    "active_tenants": ["tenant-a", "tenant-b"],
                    "retry_max_seconds": 10,
                    "bindings": {
                        "primary": {
                            **valid["privacy_automation"]["notice_governance"][
                                "publication_runtime"
                            ]["bindings"]["primary"],
                            "tenant_id": "tenant-c",
                        }
                    },
                },
            },
        },
    }
    findings = lint_config(invalid)
    assert any("binding tenant must be explicitly listed" in item.message for item in findings)
    assert any("every active publication tenant" in item.message for item in findings)
    assert any("at least poll_seconds" in item.message for item in findings)
