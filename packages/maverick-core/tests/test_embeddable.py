"""Tests for embeddable mode (maverick.embeddable)."""
from __future__ import annotations

import pytest

# ---------- embeddable ----------

def test_embeddable_no_cli_default_false(monkeypatch):
    monkeypatch.delenv("MAVERICK_NO_CLI", raising=False)
    from maverick.embeddable import no_cli
    assert no_cli() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE", "Yes"])
def test_embeddable_no_cli_truthy(monkeypatch, val):
    monkeypatch.setenv("MAVERICK_NO_CLI", val)
    from maverick.embeddable import no_cli
    assert no_cli() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "", "random"])
def test_embeddable_no_cli_falsy(monkeypatch, val):
    monkeypatch.setenv("MAVERICK_NO_CLI", val)
    from maverick.embeddable import no_cli
    assert no_cli() is False


def test_embeddable_short_circuit_in_embedded(monkeypatch):
    monkeypatch.setenv("MAVERICK_NO_CLI", "1")
    from maverick.embeddable import short_circuit_in_embedded
    with pytest.raises(RuntimeError, match="embedded mode"):
        short_circuit_in_embedded("test-path")


def test_embeddable_short_circuit_passthrough_when_not_embedded(monkeypatch):
    monkeypatch.delenv("MAVERICK_NO_CLI", raising=False)
    from maverick.embeddable import short_circuit_in_embedded
    # Should not raise.
    short_circuit_in_embedded("test-path")
