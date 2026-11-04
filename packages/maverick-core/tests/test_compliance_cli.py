"""`maverick compliance --strict` gate behaviour."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in (
        "MAVERICK_ENTERPRISE", "MAVERICK_CONSENT_MODE", "MAVERICK_AUDIT_SIGN",
        "MAVERICK_ENCRYPT_AT_REST", "MAVERICK_AI_DISCLOSURE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_compliance_reports_and_exits_zero_without_strict():
    result = CliRunner().invoke(main, ["compliance"])
    assert result.exit_code == 0
    assert "GDPR + EU AI Act" in result.output


def test_compliance_strict_exits_nonzero_when_action_needed():
    # A bare deployment has opt-in controls off (retention, egress, oversight),
    # so --strict must fail regardless of whether the crypto backend is present.
    result = CliRunner().invoke(main, ["compliance", "--strict"])
    assert result.exit_code != 0
    assert "need action" in result.output
