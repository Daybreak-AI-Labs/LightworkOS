from __future__ import annotations

import pytest
from maverick.config_lint import lint_config
from maverick.vendor_onboarding_config import VendorOnboardingSettings


def test_settings_are_disabled_by_default_and_recognized_by_lint():
    assert VendorOnboardingSettings.from_config({}).enable is False
    config = {"vendor_onboarding": {"enable": True, "resource_owner": "procurement",
              "document_connection": "gdrive", "ticket_connection": "jira"}}
    assert VendorOnboardingSettings.from_config(config).resource_owner == "procurement"
    assert VendorOnboardingSettings.from_config(config).safe_read_attempts == 3
    assert VendorOnboardingSettings.from_config(config).safe_read_backoff_seconds == 0.25
    config["vendor_onboarding"]["reviewed_uploads"] = False
    assert VendorOnboardingSettings.from_config(config).reviewed_uploads is False
    assert not [issue for issue in lint_config(config) if "vendor_onboarding" in str(issue)]


@pytest.mark.parametrize("section", [
    {"enable": "true"}, {"enable": True}, {"enable": True, "resource_owner": " "}, {"reviewed_uploads": "true"},
    {"safe_read_attempts": 0}, {"safe_read_attempts": 6}, {"safe_read_attempts": True},
    {"safe_read_backoff_seconds": -1}, {"safe_read_backoff_seconds": 6},
    {"safe_read_backoff_seconds": float("nan")},
    {"enable": False, "automatic_promotion": True},
    {"document_connection": "jira", "ticket_connection": "jira"},
])
def test_settings_fail_closed_on_invalid_enrollment(section):
    with pytest.raises(ValueError):
        VendorOnboardingSettings.from_config({"vendor_onboarding": section})
