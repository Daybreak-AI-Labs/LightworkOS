"""The cron-able governance dispatchers: red-team, regulatory-feed, inventory.

Each dispatcher must isolate per-item failures (one bad schedule/alert/
connector never hides the rest), exit non-zero when anything failed, and
pass the operator identity through unchanged.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_red_team_run_due_reports_and_fails_on_partial_dispatch(
    runner, monkeypatch,
):
    from maverick import red_team_assurance as rta

    calls: dict = {}

    def run_due(*, actor: str, limit: int) -> dict:
        calls["args"] = {"actor": actor, "limit": limit}
        return {
            "campaigns": [
                {"id": "RTC-one", "target_binding": {"asset_id": "MAA-" + "a" * 32}},
            ],
            "failures": [{"schedule_id": "RTS-two", "reason": "target retired"}],
            "count": 1,
            "failure_count": 1,
            "due_count": 2,
            "truncated": False,
            "limit": limit,
        }

    monkeypatch.setattr(rta, "run_due_schedules", run_due)
    result = runner.invoke(
        main, ["red-team", "run-due", "--limit", "5", "--by", "cron:ops"],
    )
    assert result.exit_code != 0
    assert calls["args"] == {"actor": "cron:ops", "limit": 5}
    assert "materialized 1 of 2 due" in result.output
    assert "campaign RTC-one" in result.output
    assert "FAILED RTS-two: target retired" in result.output


def test_red_team_run_due_succeeds_quietly_when_nothing_is_due(
    runner, monkeypatch,
):
    from maverick import red_team_assurance as rta

    monkeypatch.setattr(
        rta,
        "run_due_schedules",
        lambda *, actor, limit: {
            "campaigns": [], "failures": [], "count": 0,
            "failure_count": 0, "due_count": 0, "truncated": False,
            "limit": limit,
        },
    )
    result = runner.invoke(main, ["red-team", "run-due", "--by", "cron:ops"])
    assert result.exit_code == 0, result.output
    assert "materialized 0 of 0 due" in result.output


def test_regulatory_feed_sync_bridges_reviewed_alerts_with_isolation(
    runner, monkeypatch, tmp_path,
):
    from types import SimpleNamespace

    from maverick import ai_regulatory_feed as feed
    from maverick.finance import regulatory_change

    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps([{"regime": "eu_ai_act", "control_ids": ["CTRL-1"]}]),
        encoding="utf-8",
    )
    alerts = [
        SimpleNamespace(alert_id="RA-1"),
        SimpleNamespace(alert_id="RA-2"),
        SimpleNamespace(alert_id="RA-3"),
    ]

    class FakeEngine:
        def __init__(self, path):
            self.path = path

        def list_alerts(self, *, status, limit):
            assert status == "accepted"
            assert limit == 100
            return alerts

    monkeypatch.setattr(regulatory_change, "RegulatoryChangeEngine", FakeEngine)

    seen: list[tuple] = []

    def sync_alert(alert, *, rules, actor, deliver):
        seen.append((alert.alert_id, actor, deliver))
        assert rules == [{"regime": "eu_ai_act", "control_ids": ["CTRL-1"]}]
        if alert.alert_id == "RA-2":
            raise ValueError("no rule matched the alert scope")
        if alert.alert_id == "RA-3":
            return {"impact_query": {"matched": False}, "impact": None,
                    "staleness": [], "notice": None}
        return {
            "impact_query": {"matched": True},
            "impact": {"id": "ARI-1"},
            "staleness": [{"id": "ARS-1"}],
            "notice": {"id": "ARN-1", "status": "pending"},
        }

    monkeypatch.setattr(feed, "sync_alert", sync_alert)
    result = runner.invoke(
        main,
        ["regulatory-feed", "sync", "--rules", str(rules_path), "--by", "cron:grc"],
    )
    assert result.exit_code != 0
    assert [row[0] for row in seen] == ["RA-1", "RA-2", "RA-3"]
    assert all(row[1] == "cron:grc" and row[2] is False for row in seen)
    # One bridged with records, one unmatched (silent), one failed loudly.
    assert "RA-1: impact ARI-1  stale-evidence 1  notice ARN-1 [pending]" in result.output
    assert "bridged 1 of 3 accepted alert(s)" in result.output
    assert "FAILED RA-2: no rule matched" in result.output


def test_regulatory_feed_sync_refuses_a_malformed_rules_file(
    runner, tmp_path,
):
    empty = tmp_path / "rules.json"
    empty.write_text("{}", encoding="utf-8")
    result = runner.invoke(
        main,
        ["regulatory-feed", "sync", "--rules", str(empty), "--by", "cron:grc"],
    )
    assert result.exit_code != 0
    assert "non-empty JSON list" in result.output


def test_ai_inventory_sync_sweeps_configured_connectors_with_isolation(
    runner, monkeypatch,
):
    from maverick import ai_inventory

    monkeypatch.setattr(
        ai_inventory,
        "get_ai_inventory_config",
        lambda: {"enable": True, "connectors": ["bedrock", "vertex_ai"]},
    )
    synced: list[tuple[str, str]] = []

    def sync_connector(name, *, actor):
        synced.append((name, actor))
        if name == "vertex_ai":
            raise ai_inventory.DiscoveryTransportError("credential env is unset")
        return {"status": "complete", "asset_count": 7}

    monkeypatch.setattr(ai_inventory, "sync_connector", sync_connector)
    result = runner.invoke(main, ["ai-inventory", "sync", "--by", "cron:ops"])
    assert result.exit_code != 0
    assert synced == [("bedrock", "cron:ops"), ("vertex_ai", "cron:ops")]
    assert "bedrock: complete  assets 7" in result.output
    assert "synced 1 of 2 connector(s)" in result.output
    assert "FAILED vertex_ai: credential env is unset" in result.output

    # Naming one connector narrows the sweep.
    synced.clear()
    result = runner.invoke(
        main,
        ["ai-inventory", "sync", "--connector", "bedrock", "--by", "cron:ops"],
    )
    assert result.exit_code == 0, result.output
    assert synced == [("bedrock", "cron:ops")]


def test_ai_inventory_sync_requires_a_configured_or_named_connector(
    runner, monkeypatch,
):
    from maverick import ai_inventory

    monkeypatch.setattr(
        ai_inventory,
        "get_ai_inventory_config",
        lambda: {"enable": True, "connectors": []},
    )
    result = runner.invoke(main, ["ai-inventory", "sync", "--by", "cron:ops"])
    assert result.exit_code != 0
    assert "no connectors configured" in result.output


def test_governance_alerts_due_exits_nonzero_when_anything_needs_attention(
    runner, monkeypatch,
):
    from maverick import governance_alerts

    monkeypatch.setattr(
        governance_alerts,
        "digest",
        lambda **kwargs: {
            "generated_at": 1.0,
            "attention_count": 3,
            "sections": {
                "serious_incidents": {
                    "enabled": True, "overdue": ["ASI-one"], "due_soon": [],
                    "citation": "Art. 73",
                },
                "ai_literacy": {
                    "enabled": True, "missing": 2, "expired": 0,
                    "expiring_soon": 0, "citation": "Art. 4",
                },
                "eu_conformity": {"enabled": False},
            },
        },
    )
    result = runner.invoke(main, ["governance-alerts", "due"])
    assert result.exit_code != 0
    assert "1 overdue" in result.output
    assert "2 missing" in result.output
    assert "attention items: 3" in result.output

    as_json = runner.invoke(main, ["governance-alerts", "due", "--json"])
    assert as_json.exit_code != 0
    assert json.loads(as_json.output)["attention_count"] == 3


def test_governance_alerts_due_is_quiet_and_green_when_nothing_is(
    runner, monkeypatch,
):
    from maverick import governance_alerts

    monkeypatch.setattr(
        governance_alerts,
        "digest",
        lambda **kwargs: {
            "generated_at": 1.0,
            "attention_count": 0,
            "sections": {
                "serious_incidents": {"enabled": False},
                "ai_literacy": {"enabled": False},
                "eu_conformity": {"enabled": False},
            },
        },
    )
    result = runner.invoke(main, ["governance-alerts", "due"])
    assert result.exit_code == 0
    assert "attention items: 0" in result.output


def test_content_provenance_sign_and_verify_round_trip(
    runner, tmp_path, monkeypatch,
):
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY", raising=False)
    (tmp_path / "config.toml").write_text(
        "[content_provenance]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()

    content = tmp_path / "summary.txt"
    content.write_text("An AI-generated summary.", encoding="utf-8")
    signed = runner.invoke(main, [
        "content-provenance", "sign",
        "--file", str(content),
        "--asset", "MAA-" + "a" * 32,
        "--modality", "text",
        "--by", "publisher",
    ])
    assert signed.exit_code == 0, signed.output
    manifest_path = tmp_path / "summary.txt.provenance.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({
        manifest["attestation"]["key_id"]: manifest["attestation"]["public_key"],
    }), encoding="utf-8")
    verified = runner.invoke(main, [
        "content-provenance", "verify",
        "--file", str(content),
        "--manifest", str(manifest_path),
        "--keys", str(keys),
    ])
    assert verified.exit_code == 0, verified.output
    assert "VALID" in verified.output

    content.write_text("tampered", encoding="utf-8")
    tampered = runner.invoke(main, [
        "content-provenance", "verify",
        "--file", str(content),
        "--manifest", str(manifest_path),
        "--keys", str(keys),
    ])
    assert tampered.exit_code != 0
    assert "INVALID" in tampered.output
    config.reset_config_cache()


def _estate_config(tmp_path, monkeypatch, body: str):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()
    return config


def test_vendor_cli_register_questionnaire_and_posture(
    runner, tmp_path, monkeypatch,
):
    config = _estate_config(
        tmp_path, monkeypatch, "[vendor_management]\nenable = true\n",
    )
    registered = runner.invoke(main, [
        "vendor", "register", "--name", "Acme", "--category", "analytics",
        "--criticality", "high", "--owner", "procurement", "--by", "ops",
    ])
    assert registered.exit_code == 0, registered.output
    vendor_id = registered.output.split()[0]
    assert vendor_id.startswith("VMR-")

    sent = runner.invoke(main, [
        "vendor", "questionnaire", "send", "--vendor", vendor_id,
        "--type", "vendor_risk", "--by", "ops",
    ])
    assert sent.exit_code == 0, sent.output
    assert "/form/" in sent.output

    posture = runner.invoke(main, ["vendor", "status"])
    assert posture.exit_code == 0, posture.output
    assert "vendors 1" in posture.output
    config.reset_config_cache()


def test_consent_cli_record_and_preferences(runner, tmp_path, monkeypatch):
    config = _estate_config(
        tmp_path, monkeypatch,
        '[consent_registry]\nenable = true\n'
        'subject_salt = "cli-test-salt-0123456789abcd"\n',
    )
    recorded = runner.invoke(main, [
        "consent", "record", "--subject", "alice@example.com",
        "--purpose", "marketing emails", "--status", "granted",
        "--policy-version", "2026-01", "--channel", "web", "--by", "ops",
    ])
    assert recorded.exit_code == 0, recorded.output
    assert "alice" not in recorded.output

    prefs = runner.invoke(main, [
        "consent", "preferences", "--subject", "alice@example.com",
    ])
    assert prefs.exit_code == 0, prefs.output
    assert "marketing_emails  granted" in prefs.output
    config.reset_config_cache()


def test_data_map_cli_classify_import_and_status(
    runner, tmp_path, monkeypatch,
):
    config = _estate_config(
        tmp_path, monkeypatch, "[data_map]\nenable = true\n",
    )
    flagged = runner.invoke(main, [
        "data-map", "classify", "customer_email", "order_total",
    ])
    assert flagged.exit_code == 0, flagged.output
    assert "customer_email: email" in flagged.output
    assert "order_total" not in flagged.output

    schema_csv = tmp_path / "columns.csv"
    schema_csv.write_text(
        "table_name,column_name\ncontacts,email\ncontacts,id\n",
        encoding="utf-8",
    )
    imported = runner.invoke(main, [
        "data-map", "import-schema", "--file", str(schema_csv),
        "--system", "snowflake", "--owner", "data-team", "--by", "ops",
    ])
    assert imported.exit_code == 0, imported.output
    assert "imported 1" in imported.output

    posture = runner.invoke(main, ["data-map", "status"])
    assert posture.exit_code == 0, posture.output
    assert "assets 1  flagged 1" in posture.output
    config.reset_config_cache()


def test_deployer_cli_tracks_art26_with_named_oversight(
    runner, tmp_path, monkeypatch,
):
    config = _estate_config(
        tmp_path, monkeypatch, "[eu_conformity]\nenable = true\n",
    )
    opened = runner.invoke(main, [
        "eu-conformity", "deployer", "open", "--asset", "MAA-" + "a" * 32,
        "--workplace", "--by", "ops",
    ])
    assert opened.exit_code == 0, opened.output
    record_id = opened.output.split()[0]

    status = runner.invoke(main, [
        "eu-conformity", "deployer", "status", "--record", record_id,
    ])
    assert status.exit_code == 0, status.output
    assert "oversight: UNASSIGNED" in status.output

    oversight = runner.invoke(main, [
        "eu-conformity", "deployer", "oversight", "--record", record_id,
        "--person", "Ada Lovelace", "--reference", "doc://oversight",
        "--revision", "1", "--by", "ops",
    ])
    assert oversight.exit_code == 0, oversight.output
    assert "Ada Lovelace" in oversight.output
    config.reset_config_cache()


def test_vendor_contract_cli_records_and_lists_renewals(
    runner, tmp_path, monkeypatch,
):
    import time as time_module

    config = _estate_config(
        tmp_path, monkeypatch, "[vendor_management]\nenable = true\n",
    )
    registered = runner.invoke(main, [
        "vendor", "register", "--name", "Acme", "--category", "analytics",
        "--criticality", "high", "--owner", "procurement", "--by", "ops",
    ])
    vendor_id = registered.output.split()[0]
    recorded = runner.invoke(main, [
        "vendor", "contract", "record", "--vendor", vendor_id,
        "--kind", "dpa", "--ref", "doc://dpa",
        "--renews-at", str(time_module.time() + 5 * 86400), "--by", "ops",
    ])
    assert recorded.exit_code == 0, recorded.output
    renewals = runner.invoke(main, ["vendor", "contract", "renewals"])
    assert renewals.exit_code == 0, renewals.output
    assert "due soon  Acme  dpa" in renewals.output
    config.reset_config_cache()


def test_consent_notice_cli_publish_and_coverage(
    runner, tmp_path, monkeypatch,
):
    config = _estate_config(
        tmp_path, monkeypatch,
        '[consent_registry]\nenable = true\n'
        'subject_salt = "cli-test-salt-0123456789abcd"\n',
    )
    notice = tmp_path / "notice.txt"
    notice.write_text("We process personal data to ...", encoding="utf-8")
    published = runner.invoke(main, [
        "consent", "notice", "publish", "--version", "2026-01",
        "--file", str(notice), "--by", "dpo",
    ])
    assert published.exit_code == 0, published.output
    coverage = runner.invoke(main, ["consent", "notice", "coverage"])
    assert coverage.exit_code == 0, coverage.output
    assert "covered True" in coverage.output
    config.reset_config_cache()


def test_fairness_cli_computes_and_fails_on_disparity(
    runner, tmp_path, monkeypatch,
):
    config = _estate_config(
        tmp_path, monkeypatch, "[explainability]\nenable = true\n",
    )
    data = tmp_path / "counts.json"
    data.write_text(json.dumps({"groups": {
        "group_a": {"selected": 8, "total": 10},
        "group_b": {"selected": 4, "total": 10},
    }}), encoding="utf-8")
    result = runner.invoke(main, [
        "explainability", "fairness", "--data-file", str(data),
    ])
    assert result.exit_code == 1, result.output
    assert "FAIL: group_b" in result.output
    assert "min impact ratio 0.500" in result.output

    data.write_text(json.dumps({"groups": {
        "group_a": {"selected": 8, "total": 10},
        "group_b": {"selected": 7, "total": 10},
    }}), encoding="utf-8")
    result = runner.invoke(main, [
        "explainability", "fairness", "--data-file", str(data),
    ])
    assert result.exit_code == 0, result.output
    assert "PASS" in result.output
    config.reset_config_cache()


def test_exports_cli_oscal_soa_and_ai_bom(runner, tmp_path, monkeypatch):
    import hashlib
    import time as time_module

    config = _estate_config(
        tmp_path, monkeypatch,
        "[evidence_graph]\nenable = true\n\n"
        "[model_risk_assurance]\nenable = true\ngate_promotions = false\n",
    )
    from maverick import model_risk_assurance as mra
    from maverick.assessment import AssessmentSession, save_session

    session = AssessmentSession()
    session.restart("iso42001", "ai-platform")
    for question in session.template().questions:
        risky = str(question.risk_answer).strip().lower()
        session.record(question.id, "no" if risky == "yes" else "yes")
    save_session(session)

    oscal_path = tmp_path / "results.oscal.json"
    result = runner.invoke(main, [
        "exports", "oscal", "--assessment", session.id,
        "--out", str(oscal_path),
    ])
    assert result.exit_code == 0, result.output
    assert "observations 22" in result.output
    assert json.loads(oscal_path.read_text(encoding="utf-8"))[
        "assessment-results"]["metadata"]["oscal-version"] == "1.1.2"

    soa_path = tmp_path / "soa.md"
    result = runner.invoke(main, [
        "exports", "soa", "--assessment", session.id, "--out", str(soa_path),
    ])
    assert result.exit_code == 0, result.output
    assert "implemented 22" in result.output
    assert "Statement of Applicability" in soa_path.read_text(encoding="utf-8")

    officer = mra.ModelRiskAssuranceOfficer()
    officer.observe_asset(
        asset_type="model", source="cli_test", source_id="m",
        display_name="M", version_digest=hashlib.sha256(b"m").hexdigest(),
        actor="op", observed_at=time_module.time(),
        metadata={}, dependencies=[],
    )
    bom_path = tmp_path / "ai-bom.json"
    result = runner.invoke(main, [
        "exports", "ai-bom", "--out", str(bom_path),
    ])
    assert result.exit_code == 0, result.output
    assert "components 1" in result.output
    assert json.loads(bom_path.read_text(encoding="utf-8"))[
        "specVersion"] == "1.6"
    config.reset_config_cache()
