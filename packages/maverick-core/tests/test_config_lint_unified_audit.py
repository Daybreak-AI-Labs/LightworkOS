"""Closed, signed, default-off configuration for the six-suite audit projection."""

from __future__ import annotations

from maverick.config_lint import lint_config


def test_unified_audit_accepts_only_the_closed_signed_contract() -> None:
    config = {
        "audit": {
            "sign": True,
            "unified": {
                "enable": True,
                "page_size": 100,
                "lease_seconds": 120,
                "max_lag_seconds": 300,
                "max_attempts": 5,
                "retry_backoff_seconds": 30,
                "poll_seconds": 60,
            },
        }
    }
    assert lint_config(config) == []

    unknown = lint_config(
        {"audit": {"sign": True, "unified": {"enable": False, "sources": ["ai"]}}}
    )
    assert any(
        finding.key == "sources" and "unknown" in finding.message.lower()
        for finding in unknown
    )


def test_unified_audit_fails_closed_without_signing_or_with_bad_bounds() -> None:
    cases = (
        {"audit": {"unified": {"enable": True}}},
        {"audit": {"sign": False, "unified": {"enable": True}}},
        {"audit": {"sign": True, "unified": {"enable": "true"}}},
        {"audit": {"sign": True, "unified": {"page_size": 0}}},
        {"audit": {"sign": True, "unified": {"lease_seconds": True}}},
        {"audit": {"sign": True, "unified": {"max_lag_seconds": 31_536_001}}},
        {"audit": {"sign": True, "unified": {"max_attempts": 21}}},
        {"audit": {"sign": True, "unified": {"retry_backoff_seconds": -1}}},
        {"audit": {"sign": True, "unified": {"poll_seconds": 4}}},
    )
    for config in cases:
        findings = lint_config(config)
        assert any(finding.severity == "error" for finding in findings), config
