"""Configuration contract for the consumer consent data plane."""

from __future__ import annotations

from maverick.config_lint import lint_config
from maverick.migrate import KNOWN_SECTIONS


def test_consent_preferences_is_a_known_closed_section():
    assert "consent_preferences" in KNOWN_SECTIONS
    assert lint_config({"consent_preferences": {"enable": True}}) == []


def test_consent_preferences_rejects_non_boolean_enable():
    findings = lint_config({"consent_preferences": {"enable": "yes"}})
    assert any(
        item.section == "consent_preferences" and item.key == "enable" and item.severity == "error"
        for item in findings
    )


def test_consent_preferences_warns_on_unknown_authority_key():
    findings = lint_config({"consent_preferences": {"enabled": True}})
    assert any(
        item.section == "consent_preferences"
        and item.key == "enabled"
        and item.severity == "warning"
        for item in findings
    )


def test_consent_preferences_accepts_closed_product_subsystem_contract():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "publishing": {
                    "enable": True,
                    "require_signed_publications": True,
                    "web_settings": {
                        "enable": True,
                        "retention_seconds": 31_536_000,
                        "max_history": 250,
                    },
                },
                "public_api": {
                    "enable": True,
                    "token_ttl_seconds": 900,
                    "max_request_bytes": 65_536,
                    "max_response_bytes": 262_144,
                    "requests_per_minute": 120,
                },
                "scanner": {
                    "enable": True,
                    "notice_proposals": {"enable": True},
                    "scheduler": {
                        "enable": True,
                        "poll_seconds": 60,
                        "enqueue_limit": 100,
                        "claim_limit": 4,
                        "tenant_limit": 1_000,
                    },
                    "interval_seconds": 86_400,
                    "max_pages": 100,
                    "max_depth": 4,
                    "page_timeout_seconds": 30,
                    "max_network_events": 5_000,
                    "allow_authenticated_scans": False,
                },
                "standards": {
                    "gpc": True,
                    "dnt": True,
                    "gpp": False,
                    "tcf": False,
                    "google_consent_mode": False,
                },
                "storage": {"backend": "sqlite"},
            }
        }
    )

    assert findings == []


def test_web_publish_settings_are_closed_bounded_and_require_publishing():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "publishing": {
                    "enable": False,
                    "web_settings": {
                        "enable": True,
                        "retention_seconds": 59,
                        "max_history": 1_001,
                        "csp_nonce_value": "must-not-be-configured",
                    },
                },
            }
        }
    )

    assert any(
        "website publish settings require consent publishing" in item.message
        for item in findings
    )
    assert any(item.key == "retention_seconds" and item.severity == "error" for item in findings)
    assert any(item.key == "max_history" and item.severity == "error" for item in findings)
    assert any(item.key == "csp_nonce_value" and item.severity == "warning" for item in findings)


def test_consent_scan_scheduler_requires_scanner_and_has_closed_bounds():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "scanner": {
                    "enable": False,
                    "scheduler": {
                        "enable": True,
                        "poll_seconds": 4,
                        "enqueue_limit": 501,
                        "claim_limit": 0,
                        "tenant_limit": 10_001,
                        "raw_browser_state": True,
                    },
                },
            }
        }
    )

    assert any("requires consent scanner to be enabled" in item.message for item in findings)
    for key in ("poll_seconds", "enqueue_limit", "claim_limit", "tenant_limit"):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(item.key == "raw_browser_state" and item.severity == "warning" for item in findings)


def test_consent_scan_notice_proposals_require_scanner_and_closed_boolean():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "scanner": {
                    "enable": False,
                    "notice_proposals": {
                        "enable": True,
                        "legal_copy": True,
                    },
                },
            }
        }
    )
    assert any(
        "notice proposals require consent scanner to be enabled" in item.message
        for item in findings
    )
    assert any(item.key == "legal_copy" and item.severity == "warning" for item in findings)

    wrong_type = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "scanner": {
                    "enable": True,
                    "notice_proposals": {"enable": "yes"},
                },
            }
        }
    )
    assert any(
        item.section == "consent_preferences.scanner.notice_proposals"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_external_consent_subsystems_require_root_and_publishing_authority():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": False,
                "public_api": {"enable": True},
                "edge_cache": {"enable": True},
            }
        }
    )

    messages = {item.message for item in findings}
    assert any("requires [consent_preferences] enable = true" in item for item in messages)
    assert "public consent API requires consent publishing to be enabled" in messages


def test_consent_identity_and_postgres_require_exact_external_authority():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "identity": {
                    "enable": True,
                    "issuer": "",
                    "audience": "consumers",
                    "jwks_origin": "http://identity.example.test/path",
                },
                "storage": {
                    "backend": "postgres",
                    "dsn_secret_ref": "plaintext-dsn",
                },
            }
        }
    )

    assert any(item.key == "issuer" and item.severity == "error" for item in findings)
    assert any(item.key == "jwks_origin" and item.severity == "error" for item in findings)
    assert any(
        "consent identity requires consent publishing and the public API" in item.message
        for item in findings
    )
    assert any(item.key == "dsn_secret_ref" and item.severity == "error" for item in findings)


def test_consent_nested_bounds_and_unknown_keys_fail_lint():
    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "scanner": {
                    "enable": "yes",
                    "max_pages": 0,
                    "max_depth": 21,
                    "authenticated_scan_password": "secret",
                },
            }
        }
    )

    assert any(item.key == "enable" and item.severity == "error" for item in findings)
    assert any(item.key == "max_pages" and item.severity == "error" for item in findings)
    assert any(item.key == "max_depth" and item.severity == "error" for item in findings)
    assert any(
        item.key == "authenticated_scan_password" and item.severity == "warning"
        for item in findings
    )


def test_consent_profile_data_requires_exact_closed_boolean_gate():
    assert (
        lint_config(
            {
                "consent_preferences": {
                    "enable": True,
                    "profile_data": {"enable": True},
                }
            }
        )
        == []
    )

    findings = lint_config(
        {
            "consent_preferences": {
                "enable": False,
                "profile_data": {"enable": True, "raw_profile_values": True},
            }
        }
    )
    assert any(
        item.section == "consent_preferences.profile_data"
        and item.key == "enable"
        and "requires [consent_preferences] enable = true" in item.message
        for item in findings
    )
    assert any(
        item.section == "consent_preferences.profile_data"
        and item.key == "raw_profile_values"
        and item.severity == "warning"
        for item in findings
    )

    wrong_type = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "profile_data": {"enable": "yes"},
            }
        }
    )
    assert any(
        item.section == "consent_preferences.profile_data"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_consent_custom_index_has_closed_limits_and_requires_profile_data():
    valid = {
        "consent_preferences": {
            "enable": True,
            "profile_data": {
                "enable": True,
                "custom_index": {
                    "enable": True,
                    "key_secret_ref": "MAVERICK_CONSENT_CUSTOM_INDEX_KEY",
                    "key_version": 1,
                    "max_indexes": 256,
                    "max_page_size": 100,
                    "retention_seconds": 31_536_000,
                },
            },
        }
    }
    assert lint_config(valid) == []

    invalid = {
        "consent_preferences": {
            "enable": True,
            "profile_data": {
                "enable": False,
                "custom_index": {
                    "enable": True,
                    "key_secret_ref": "MAVERICK_CONSENT_CUSTOM_INDEX_KEY",
                    "key_version": 0,
                    "max_indexes": 10_001,
                    "max_page_size": 501,
                    "retention_seconds": 1,
                    "raw_search_values": True,
                },
            },
        }
    }
    findings = lint_config(invalid)
    assert any("require consent profile data" in item.message for item in findings)
    for key in ("key_version", "max_indexes", "max_page_size", "retention_seconds"):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_search_values" and item.severity == "warning"
        for item in findings
    )


def test_consumer_trust_center_requires_public_publishing_authority():
    assert (
        lint_config(
            {
                "consent_preferences": {
                    "enable": True,
                    "publishing": {"enable": True},
                    "public_api": {"enable": True},
                    "trust_center": {"enable": True},
                }
            }
        )
        == []
    )

    findings = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "trust_center": {"enable": True, "raw_identity": True},
            }
        }
    )
    assert any(
        item.section == "consent_preferences.trust_center"
        and item.key == "enable"
        and "requires consent publishing and the public API" in item.message
        for item in findings
    )
    assert any(
        item.section == "consent_preferences.trust_center"
        and item.key == "raw_identity"
        and item.severity == "warning"
        for item in findings
    )

    wrong_type = lint_config(
        {
            "consent_preferences": {
                "enable": True,
                "trust_center": {"enable": "yes"},
            }
        }
    )
    assert any(
        item.section == "consent_preferences.trust_center"
        and item.key == "enable"
        and item.severity == "error"
        for item in wrong_type
    )


def test_consent_bulk_jobs_have_closed_gate_limits_and_root_dependency():
    valid = {
        "consent_preferences": {
            "enable": True,
            "bulk_jobs": {
                "enable": True,
                "initial_credits": 10_000,
                "max_jobs": 10_000,
                "max_items_per_job": 10_000,
                "max_artifact_bytes": 16_777_216,
                "lease_seconds": 60,
                "retention_seconds": 31_536_000,
                "worker_batch_size": 100,
            },
        }
    }
    assert lint_config(valid) == []

    invalid = {
        "consent_preferences": {
            "enable": False,
            "bulk_jobs": {
                "enable": True,
                "initial_credits": -1,
                "max_jobs": 0,
                "max_items_per_job": 100_001,
                "max_artifact_bytes": 1_023,
                "lease_seconds": 4,
                "retention_seconds": 86_399,
                "worker_batch_size": 501,
                "raw_export_path": "forbidden",
            },
        }
    }
    findings = lint_config(invalid)
    assert any("requires [consent_preferences] enable = true" in item.message for item in findings)
    for key in (
        "initial_credits",
        "max_jobs",
        "max_items_per_job",
        "max_artifact_bytes",
        "lease_seconds",
        "retention_seconds",
        "worker_batch_size",
    ):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_export_path" and item.severity == "warning"
        for item in findings
    )


def test_global_opt_out_has_closed_limits_and_requires_consumer_rights_intake():
    valid = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "trust_center": {"enable": True},
            "global_opt_out": {
                "enable": True,
                "retention_seconds": 31_536_000,
                "submission_ttl_seconds": 900,
                "max_records": 10_000,
            },
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "rights_consumer_intake": {"enable": True},
        },
    }
    assert lint_config(valid) == []

    invalid = {
        "consent_preferences": {
            "enable": True,
            "global_opt_out": {
                "enable": True,
                "retention_seconds": 3_599,
                "submission_ttl_seconds": 86_401,
                "max_records": 100_001,
                "raw_subject": "forbidden",
            },
        }
    }
    findings = lint_config(invalid)
    assert any(
        item.section == "consent_preferences.global_opt_out"
        and item.key == "enable"
        and "requires authenticated consumer privacy-rights intake" in item.message
        for item in findings
    )
    for key in ("retention_seconds", "submission_ttl_seconds", "max_records"):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_subject" and item.severity == "warning"
        for item in findings
    )


def test_application_scanner_is_closed_bounded_and_parent_gated():
    valid = {
        "consent_preferences": {
            "enable": True,
            "application_scanner": {
                "enable": True,
                "retention_seconds": 31_536_000,
                "max_records": 25_000,
            },
        }
    }
    assert lint_config(valid) == []

    invalid = {
        "consent_preferences": {
            "enable": False,
            "application_scanner": {
                "enable": True,
                "retention_seconds": 86_399,
                "max_records": 1_000_001,
                "raw_manifest_path": "forbidden",
            },
        }
    }
    findings = lint_config(invalid)
    assert any(
        item.section == "consent_preferences.application_scanner"
        and item.key == "enable"
        and "requires [consent_preferences] enable = true" in item.message
        for item in findings
    )
    for key in ("retention_seconds", "max_records"):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_manifest_path" and item.severity == "warning"
        for item in findings
    )


def test_native_sdk_has_closed_custody_limits_and_authority_dependencies():
    valid = {
        "consent_preferences": {
            "enable": True,
            "publishing": {"enable": True},
            "public_api": {"enable": True},
            "identity": {
                "enable": True,
                "issuer": "https://identity.example.test",
                "audience": "lightwork-native-consent",
                "jwks_origin": "https://identity.example.test",
            },
            "native_sdk": {
                "enable": True,
                "receipt_key_id": "native-receipt-prod",
                "receipt_key_revision": 1,
                "receipt_key_secret_ref": "MAVERICK_NATIVE_CONSENT_RECEIPT_KEY",
                "max_applications": 1_000,
                "max_devices": 100_000,
                "max_requests": 1_000_000,
                "requests_per_minute": 120,
                "require_profile_linking": True,
                "require_rights_requests": True,
            },
            "trust_center": {"enable": True},
        },
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "rights_consumer_intake": {"enable": True},
        },
    }
    assert lint_config(valid) == []

    invalid = {
        "consent_preferences": {
            "enable": True,
            "native_sdk": {
                "enable": True,
                "receipt_key_id": "",
                "receipt_key_revision": 0,
                "receipt_key_secret_ref": "raw-secret",
                "max_applications": 0,
                "max_devices": 10_000_001,
                "max_requests": 100_000_001,
                "requests_per_minute": 10_001,
                "require_profile_linking": True,
                "require_rights_requests": True,
                "raw_receipt_private_key": "forbidden",
            },
        }
    }
    findings = lint_config(invalid)
    assert any(
        item.key == "enable"
        and "requires enabled authority" in item.message
        for item in findings
    )
    for key in (
        "receipt_key_id",
        "receipt_key_revision",
        "receipt_key_secret_ref",
        "max_applications",
        "max_devices",
        "max_requests",
        "requests_per_minute",
        "require_profile_linking",
        "require_rights_requests",
    ):
        assert any(item.key == key and item.severity == "error" for item in findings)
    assert any(
        item.key == "raw_receipt_private_key" and item.severity == "warning"
        for item in findings
    )
