"""Shared syntax and defaults for administrator-facing configuration."""
from __future__ import annotations

import pytest
from maverick.config_contracts import TEXT_SETTINGS
from maverick.kms_backends import VaultTransitKMS


@pytest.mark.parametrize(("setting", "valid", "invalid"), [
    ("observability.otel_endpoint", "https://collector.example/v1/traces", "http://remote.example/v1/traces"),
    ("kms.key_id", "arn:aws:kms:us-east-1:123:key/abc", "key with spaces"),
    ("kms.region", "us-east-1", "us east 1"),
    ("kms.address", "https://vault.example", "http://vault.example"),
    ("kms.mount", "transit-keys", "../../private"),
    ("audit.siem_dest", "tcp://collector.example:514", "tcp://bad host"),
])
def test_text_contracts_have_bounded_full_match_syntax(setting, valid, invalid):
    contract = TEXT_SETTINGS[setting]
    assert contract.matches(valid)
    assert not contract.matches(invalid)


def test_vault_mount_explicit_and_configured_values_override_shared_default():
    default = TEXT_SETTINGS["kms.mount"].runtime_default
    assert VaultTransitKMS(key_id="key", cfg={}, client=object()).mount == default
    assert VaultTransitKMS(key_id="key", cfg={"mount": "configured"}, client=object()).mount == "configured"
    assert VaultTransitKMS(key_id="key", mount="explicit", cfg={"mount": "configured"},
                           client=object()).mount == "explicit"


def test_contract_registry_and_entries_are_immutable():
    with pytest.raises(TypeError):
        TEXT_SETTINGS["kms.mount"] = TEXT_SETTINGS["kms.mount"]
    with pytest.raises(AttributeError):
        TEXT_SETTINGS["kms.mount"].default = "changed"
