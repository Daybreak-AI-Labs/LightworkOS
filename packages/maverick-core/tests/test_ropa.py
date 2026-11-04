"""maverick ropa: GDPR Art. 30 record-of-processing scaffold."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in ("MAVERICK_ENTERPRISE", "MAVERICK_ENCRYPT_AT_REST", "MAVERICK_AUDIT_SIGN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_generate_ropa_shape_and_never_raises():
    from maverick.ropa import generate_ropa

    rec = generate_ropa()
    assert rec["record_type"].startswith("GDPR Article 30")
    # The organizational fields are left for the controller to complete.
    assert rec["controller"]["name"].startswith("<TO BE COMPLETED")
    assert rec["processing"]["lawful_basis"].startswith("<TO BE COMPLETED")
    # The schema inventory is pre-filled.
    cats = {c["category"] for c in rec["processing"]["personal_data_categories"]}
    assert "Channel conversation content" in cats


def test_bare_deployment_flags_cloud_recipient_and_indefinite_retention():
    from maverick.ropa import generate_ropa

    rec = generate_ropa()
    assert "third-party" in rec["recipients"][0]
    assert "Possible" in rec["international_transfers"]
    assert "indefinitely" in rec["retention"]


def test_enterprise_profile_reports_local_only_and_no_transfer(monkeypatch):
    from maverick.ropa import generate_ropa

    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"retention": {"audit_days": 365}},
    )
    rec = generate_ropa()
    assert "local LLM only" in rec["recipients"][0]
    assert rec["international_transfers"].startswith("None via the LLM path")
    assert rec["retention"] == "audit_days = 365"
    # Active Art. 32 measures are drawn from the live compliance report.
    assert any("Data-egress control" in m for m in rec["security_measures"])


def test_mistyped_retention_config_falls_back_to_indefinite(monkeypatch):
    from maverick.ropa import generate_ropa

    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"retention": "30 days"},
    )

    rec = generate_ropa()
    assert "indefinitely" in rec["retention"]

    runner = CliRunner()
    result = runner.invoke(main, ["ropa"])
    assert result.exit_code == 0
    assert "indefinitely" in result.output

def test_cli_ropa_text_and_json(monkeypatch, tmp_path):
    runner = CliRunner()

    text = runner.invoke(main, ["ropa"])
    assert text.exit_code == 0
    assert "Record of Processing Activities" in text.output

    js = runner.invoke(main, ["ropa", "--format", "json"])
    assert js.exit_code == 0
    parsed = json.loads(js.output)
    assert parsed["controller"]["dpo_contact"].startswith("<TO BE COMPLETED")

    out = tmp_path / "ropa.json"
    written = runner.invoke(main, ["ropa", "--format", "json", "-o", str(out)])
    assert written.exit_code == 0
    assert json.loads(out.read_text())["record_type"].startswith("GDPR Article 30")
