"""Closed configuration authority for Data Use Governance."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def test_data_use_governance_is_known_and_core_only_is_safe():
    assert "data_use_governance" in KNOWN_SECTIONS
    assert lint_config(
        {
            "data_use_governance": {
                "enable": True,
                "compiler": {
                    "enable": True,
                    "max_operations": 500,
                    "max_row_filter_nodes": 100,
                },
                "limits": {
                    "max_assets": 10_000,
                    "max_fields": 100_000,
                    "max_lineage_edges": 250_000,
                    "max_context_age_seconds": 86_400,
                },
            }
        }
    ) == []


def test_native_enforcement_requires_compiler_provider_and_root_authority():
    findings = lint_config(
        {
            "data_use_governance": {
                "enable": False,
                "enforcement": {"enable": True},
            }
        }
    )

    messages = {item.message for item in findings}
    assert any("requires [data_use_governance] enable = true" in item for item in messages)
    assert "data-use enforcement requires the policy compiler" in messages
    assert any("requires an explicitly enabled native provider" in item for item in messages)


def test_native_provider_requires_exact_origin_and_secret_reference():
    findings = lint_config(
        {
            "data_use_governance": {
                "enable": True,
                "compiler": {"enable": True},
                "enforcement": {
                    "enable": True,
                    "require_four_eyes": True,
                    "max_attempts": 3,
                    # In-request retry waits (seconds); older installers wrote
                    # 30 and 300, which the runtime never applied.
                    "retry_base_seconds": 0.5,
                    "retry_max_seconds": 2.0,
                },
                "snowflake": {
                    "enable": True,
                    "origin": "https://account.snowflakecomputing.com",
                    "credential_secret_ref": "${SNOWFLAKE_TOKEN}",
                    "credential_revision": 2,
                    "timeout_seconds": 30,
                    "max_response_bytes": 131_072,
                },
            }
        }
    )
    assert findings == []

    unsafe = lint_config(
        {
            "data_use_governance": {
                "enable": True,
                "compiler": {"enable": True},
                "enforcement": {"enable": True},
                "databricks": {
                    "enable": True,
                    "origin": "http://127.0.0.1/path",
                    "credential_secret_ref": "literal-token",
                    "credential_revision": 0,
                },
            }
        }
    )
    assert any(item.key == "origin" and item.severity == "error" for item in unsafe)
    assert any(
        item.key == "credential_secret_ref" and item.severity == "error"
        for item in unsafe
    )
    assert any(
        item.key == "credential_revision" and item.severity == "error"
        for item in unsafe
    )


def test_data_use_retry_and_bounds_are_closed():
    findings = lint_config(
        {
            "data_use_governance": {
                "enable": True,
                "compiler": {
                    "enable": True,
                    "max_operations": 0,
                    "raw_sql": True,
                },
                "enforcement": {
                    "enable": False,
                    "retry_base_seconds": 100,
                    "retry_max_seconds": 10,
                },
            }
        }
    )

    assert any(item.key == "max_operations" and item.severity == "error" for item in findings)
    assert any(item.key == "raw_sql" and item.severity == "warning" for item in findings)
    assert any(
        item.key == "retry_max_seconds" and item.severity == "error"
        for item in findings
    )


def test_native_provider_bounds_match_the_runtime_contract():
    root = {
        "enable": True,
        "compiler": {"enable": True},
        "enforcement": {"enable": True, "max_attempts": 5},
        "snowflake": {
            "enable": True,
            "origin": "https://account.snowflakecomputing.com",
            "credential_secret_ref": "$SNOWFLAKE_TOKEN",
            "credential_revision": 1,
            "timeout_seconds": 60,
            "max_response_bytes": 131_072,
        },
    }
    assert lint_config({"data_use_governance": root}) == []

    for section, key, value in (
        ("enforcement", "max_attempts", 6),
        ("snowflake", "timeout_seconds", 61),
        ("snowflake", "max_response_bytes", 131_073),
    ):
        invalid = {
            "data_use_governance": {
                **root,
                section: {**root[section], key: value},
            }
        }
        assert any(
            item.key == key and item.severity == "error"
            for item in lint_config(invalid)
        )


def test_databricks_timeout_matches_statement_execution_contract():
    root = {
        "enable": True,
        "compiler": {"enable": True},
        "enforcement": {"enable": True},
        "databricks": {
            "enable": True,
            "origin": "https://workspace.cloud.databricks.com",
            "credential_secret_ref": "$DATABRICKS_TOKEN",
            "credential_revision": 1,
            "timeout_seconds": 10,
        },
    }

    for timeout in (5, 10, 50):
        valid = {
            **root,
            "databricks": {**root["databricks"], "timeout_seconds": timeout},
        }
        assert lint_config({"data_use_governance": valid}) == []

    for timeout in (0, 1, 4, 51, 60):
        invalid = {
            **root,
            "databricks": {**root["databricks"], "timeout_seconds": timeout},
        }
        assert any(
            item.section == "data_use_governance.databricks"
            and item.key == "timeout_seconds"
            and item.severity == "error"
            for item in lint_config({"data_use_governance": invalid})
        )


def test_provider_audit_scheduler_contract_is_closed_and_dependency_gated():
    scheduler = {
        "enable": True,
        "poll_seconds": 60,
        "claim_limit": 10,
        "tenant_limit": 1_000,
        "lease_seconds": 120,
        "event_limit": 100,
        "retry_backoff_seconds": 30,
        "purge_limit": 100,
    }
    root = {
        "enable": True,
        "compiler": {"enable": True},
        "enforcement": {"enable": True},
        "provider_audit": {
            "enable": True,
            "audit_window_seconds": 14_400,
            "retention_seconds": 31_536_000,
            "max_attempts": 5,
            "snowflake_latency_watermark_seconds": 10_800,
            "cursor_overlap_seconds": 300,
            "max_pages_per_read": 20,
            "scheduler": scheduler,
        },
        "snowflake": {
            "enable": True,
            "origin": "https://account.snowflakecomputing.com",
            "credential_secret_ref": "$SNOWFLAKE_TOKEN",
            "credential_revision": 1,
        },
    }
    assert lint_config({"data_use_governance": root}) == []

    without_watermark = {
        **root,
        "provider_audit": {
            key: value
            for key, value in root["provider_audit"].items()
            if key != "snowflake_latency_watermark_seconds"
        },
    }
    assert lint_config({"data_use_governance": without_watermark}) == []

    for key, valid_values in {
        "snowflake_latency_watermark_seconds": (10_800, 604_800),
        "cursor_overlap_seconds": (60, 3_600),
        "max_pages_per_read": (1, 100),
    }.items():
        for value in valid_values:
            valid = {
                **root,
                "provider_audit": {
                    **root["provider_audit"],
                    key: value,
                },
            }
            assert lint_config({"data_use_governance": valid}) == []

    for key, invalid_values in {
        "snowflake_latency_watermark_seconds": (10_799, 604_801, True, 10_800.0),
        "cursor_overlap_seconds": (59, 3_601, True, 300.0),
        "max_pages_per_read": (0, 101, True, 20.0),
    }.items():
        for value in invalid_values:
            invalid = {
                **root,
                "provider_audit": {
                    **root["provider_audit"],
                    key: value,
                },
            }
            assert any(
                item.section == "data_use_governance.provider_audit"
                and item.key == key
                and item.severity == "error"
                for item in lint_config({"data_use_governance": invalid})
            )

    disabled_audit = {
        **root,
        "provider_audit": {
            **root["provider_audit"],
            "enable": False,
        },
    }
    findings = lint_config({"data_use_governance": disabled_audit})
    assert any(
        item.section == "data_use_governance.provider_audit.scheduler"
        and item.key == "enable"
        and item.severity == "error"
        for item in findings
    )

    short_retention = {
        **root,
        "provider_audit": {
            **root["provider_audit"],
            "retention_seconds": 60,
        },
    }
    findings = lint_config({"data_use_governance": short_retention})
    assert any(
        item.section == "data_use_governance.provider_audit"
        and item.key == "retention_seconds"
        for item in findings
    )

    unknown = {
        **root,
        "provider_audit": {
            **root["provider_audit"],
            "scheduler": {**scheduler, "raw_event_endpoint": True},
        },
    }
    findings = lint_config({"data_use_governance": unknown})
    assert any(
        item.section == "data_use_governance.provider_audit.scheduler"
        and item.key == "raw_event_endpoint"
        for item in findings
    )

    unknown_transport_key = {
        **root,
        "provider_audit": {
            **root["provider_audit"],
            "accepted_watermark_seconds": 10_800,
        },
    }
    findings = lint_config({"data_use_governance": unknown_transport_key})
    assert any(
        item.section == "data_use_governance.provider_audit"
        and item.key == "accepted_watermark_seconds"
        for item in findings
    )
