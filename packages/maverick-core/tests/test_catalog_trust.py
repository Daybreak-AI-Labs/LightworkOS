"""Tests for maverick.catalog_trust shared trust gates."""
from __future__ import annotations

import builtins

from maverick import catalog_trust


def test_shield_scan_missing_shield_fails_open_with_warning(caplog, monkeypatch):
    """When the shield extra is not installed, shield_scan must fail OPEN
    (return without raising so installs are not bricked) but NOT silently:
    kernel rule 1 and the function's own docstring promise fail-open-WITH-a-
    warning, otherwise catalog bodies reach the system prompt unscanned with
    no operator signal."""
    real_import = builtins.__import__

    def _no_shield(name, *args, **kwargs):
        if name == "maverick_shield":
            raise ImportError("No module named 'maverick_shield'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_shield)

    with caplog.at_level("WARNING", logger="maverick.catalog_trust"):
        # Fail open: returns None, does not raise.
        assert catalog_trust.shield_scan("some skill body", label="skill body") is None

    assert any(
        "maverick_shield is not installed" in r.getMessage()
        for r in caplog.records
    ), "shield-absent path must emit a warning (fail-open-with-warning)"
