"""Shared validation boundaries used by settings catalog groups."""

import re

import pytest
from maverick_dashboard import (
    settings_catalog_access,
    settings_catalog_runtime,
    settings_catalog_structured,
)


@pytest.mark.parametrize("module", [
    settings_catalog_access, settings_catalog_runtime, settings_catalog_structured,
])
@pytest.mark.parametrize(("value", "valid"), [
    ("https://example.com/path", True),
    ("http://example.com", False),
    ("https://example.com?token=value", False),
    ("https://example.com/a b", False),
    ("https://", False),
])
def test_https_catalog_pattern(module, value, valid):
    assert bool(re.fullmatch(module._HTTPS, value)) is valid


@pytest.mark.parametrize(("value", "valid"), [
    ("", True),
    ("http://localhost:4318/v1/traces", True),
    ("http://127.0.0.1:4318/v1/traces", True),
    ("http://example.com/v1/traces", False),
    ("https://collector.example.com/v1/traces", True),
])
def test_observability_address_allows_only_secure_or_loopback(value, valid):
    assert bool(re.fullmatch(settings_catalog_runtime._ADDRESS, value)) is valid
