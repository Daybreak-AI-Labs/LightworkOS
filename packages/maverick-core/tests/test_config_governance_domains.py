"""Configuration checks remain ordered and fail closed across domain boundaries."""
from __future__ import annotations

from maverick.config_lint import _lint_product_governance_contracts


def test_cross_domain_findings_keep_all_authority_and_retry_checks():
    config = {
        "audit": {"sign": False, "unified": {"enable": True}},
        "data_use_governance": {
            "enforcement": {"enable": True, "retry_base_seconds": 30, "retry_max_seconds": 10},
        },
        "third_party_management": {
            "intelligence": {"providers": {"enable": True, "enabled_providers": []}},
        },
    }
    findings = _lint_product_governance_contracts(config)
    messages = [finding.message for finding in findings]
    audit = next(i for i, message in enumerate(messages) if "unified audit requires" in message)
    data_use = next(i for i, message in enumerate(messages) if "requires the policy compiler" in message)
    third_party = next(i for i, message in enumerate(messages) if "provider runtime requires intelligence" in message)
    retry = next(i for i, message in enumerate(messages) if "retry_max_seconds must be at least" in message)
    assert audit < data_use < third_party < retry
    assert all(finding.severity == "error" for finding in findings)
