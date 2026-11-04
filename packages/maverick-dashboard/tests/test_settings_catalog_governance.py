"""All settings > AI governance, risk and vendor module settings.

Every row in ``settings_catalog_governance`` saves and reads back through the
catalog API into what ``load_config`` returns, refuses values its module would
reject, never returns a sealed key, asks before loosening a protection, and
leaves one audit row per change. The readers changed for these rows (sealed
sign-in keys for identity connectors, GRC vendor systems and red-team
testing) are shown to use the saved value, with the server's own value still
winning, and a sample of module readers is shown to act on saved values.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_governance as governance
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
ROWS = tuple(governance.entries(catalog.S, catalog.C, catalog.Column))
IDS = {row.id for row in ROWS}
SAVEABLE = ROWS
SAVEABLE_IDS = {row.id for row in SAVEABLE}
WEAKENING = tuple(row for row in SAVEABLE if row.warning)
_ENV_TO_CLEAR = (
    "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
    "MAVERICK_SECRETS_BACKEND", "MAVERICK_SECRETS_DIR", "MAVERICK_RED_TEAM_COMMITMENT_KEY",
    "OKTA_IDENTITY_GOVERNANCE_TOKEN", "SERVICENOW_TOKEN", "SERVICENOW_INSTANCE_URL",
    "MAVERICK_GRC_SERVICENOW_SECRET_REF",
    *(name for row in ROWS for name in row.env),
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in _ENV_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []

    def capture(kind, **payload):
        rows.append({"kind": kind, **payload})
        return True

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _loaded() -> dict:
    from maverick import config

    config.reset_config_cache()
    return config.load_config()


def _save(changes, confirm=False):
    return save_catalog(client, API, json={"changes": changes, "confirm": confirm})


def _rows_by_id() -> dict:
    return {row["id"]: row for group in client.get(API).json()["groups"]
            for row in group["settings"]}


def _base(text: str) -> None:
    from maverick import config

    config.config_path().parent.mkdir(parents=True, exist_ok=True)
    config.config_path().write_text(text, encoding="utf-8")
    config.reset_config_cache()


# ------------------------------------------------------------ sample values
_TEXT_SAMPLES = {
    governance._OPT_PATH: "/opt/lightwork/bin/reader",
    governance._TRAINEDDATA: "/usr/share/tessdata/eng.traineddata",
    governance._FINGERPRINT: "ab" * 32,
    governance._VERSION: "1.2.3",
    governance._OPT_HOST: "ratings.example.com",
    governance._SERVICENOW_URL: "https://acme.service-now.com",
    governance._ARCHER_URL: "https://archer.example.com",
    governance._OKTA_URL: "https://acme.okta.com",
    governance._PURVIEW_URL: "https://acme.purview.azure.com",
    governance._ORG_ID: "org-123",
}
_BAD_TEXT = {
    governance._OPT_PATH: "relative/reader",
    governance._TRAINEDDATA: "/usr/share/tessdata/fra.traineddata",
    governance._FINGERPRINT: "not-a-fingerprint",
    governance._VERSION: "1.2 3",
    governance._OPT_HOST: "10.0.0.1",
    governance._SERVICENOW_URL: "http://acme.service-now.com",
    governance._ARCHER_URL: "https://archer.local",
    governance._OKTA_URL: "https://acme.okta.com.evil.example",
    governance._PURVIEW_URL: "https://localhost",
    governance._ORG_ID: "org 123",
}


def _shown(setting, value):
    return None if value is None else round(float(value) / setting.scale, 6)


def _sample(setting):
    """A valid value that differs from the default, as the page sends it."""
    control = setting.control
    if control == "toggle":
        return not setting.default
    if control == "select":
        return next(v for v, _ in setting.choices if v != setting.default)
    if control == "multiselect":
        values = [v for v, _ in setting.choices]
        return values[:1] if list(setting.default) != values[:1] else values[:2]
    if control == "number":
        default = _shown(setting, setting.default)
        return setting.minimum if setting.minimum != default else setting.maximum
    if control == "text":
        return _TEXT_SAMPLES[setting.pattern]
    if control == "fingerprint":
        return "ab" * 32
    if control == "secret":
        return "k" * 40
    if control == "list":
        return ["/usr/lib/libtesseract.so.5"]
    raise AssertionError(setting.id)


def _stored(setting, value):
    """What the kernel reads after the page saved ``value``."""
    if setting.control == "number":
        number = value * setting.scale
        return int(round(number)) if setting.integer else number
    if setting.control == "multiselect":
        order = [v for v, _ in setting.choices]
        return sorted(value, key=order.index)
    return value


def _invalid(setting):
    control = setting.control
    if control == "toggle":
        return "yes"
    if control in {"select", "multiselect"}:
        return "not-an-option" if control == "select" else ["not-an-option"]
    if control == "number":
        return setting.maximum + (setting.step or 1)
    if control == "text":
        return _BAD_TEXT[setting.pattern]
    if control == "fingerprint":
        return "not-a-fingerprint"
    if control == "secret":
        return "short" if setting.pattern else "x" * (setting.max_length + 1)
    if control == "list":
        return ["relative/library.so"]
    raise AssertionError(setting.id)


# ------------------------------------------------------------------ catalog
def test_rows_are_in_the_catalog_and_plain():
    from test_support.plain_language import developer_terms

    assert len(ROWS) == len(IDS)
    for row in ROWS:
        assert catalog.BY_ID[row.id] == row
        assert row.help.endswith(".") and "_" not in row.label
    page = every_group(client)
    assert developer_terms(page) == []
    for label in ("Read text in pictures", "Open files in an isolated area",
                  "Microsoft Entra sign-in key", "Rating providers"):
        assert label in page


# Values that keep the all-rows sample a working combination
# (settings_catalog_governance.cross_checks): picture and older Excel reading
# need their file kinds, and the lookback needs a period at least as long.
_TOGETHER_SAMPLES = {
    "ai_evidence_analysis.enabled_media_types": ["jpeg", "png", "xls"],
    "ai_cost_roi.collector_limits.max_period_days": 366,
}
# Switches that only work with others, saved with them: (first, then) extras.
_EA = "ai_evidence_analysis"
_TOGETHER = {
    f"{_EA}.parser_sandbox.enable": (
        [{"id": f"{_EA}.ocr.enable", "value": True},
         {"id": f"{_EA}.enabled_media_types", "value": ["png"]}],
        [{"id": f"{_EA}.ocr.enable", "value": False}]),
    f"{_EA}.ocr.enable": (
        [], [{"id": f"{_EA}.parser_sandbox.enable", "value": True},
             {"id": f"{_EA}.enabled_media_types", "value": ["png"]}]),
    f"{_EA}.legacy_xls.enable": (
        [], [{"id": f"{_EA}.parser_sandbox.enable", "value": True},
             {"id": f"{_EA}.enabled_media_types", "value": ["xls"]}]),
}


def test_every_row_saves_reads_back_and_resets(audit_rows):
    from maverick import config

    changes = [{"id": row.id, "value": _TOGETHER_SAMPLES.get(row.id, _sample(row))}
               for row in SAVEABLE]
    r = _save(changes, confirm=True)
    assert r.status_code == 200, r.text
    assert set(r.json()["changed"]) == SAVEABLE_IDS
    loaded = _loaded()
    state = _rows_by_id()
    for row, change in zip(SAVEABLE, changes, strict=True):
        present, value = catalog.lookup(loaded, row.path)
        assert present, row.id
        assert value == _stored(row, change["value"]), row.id
        assert state[row.id]["source"] == "here", row.id
    # One audit row per change, keys only as set / not set.
    assert len(audit_rows) == len(SAVEABLE)
    assert {(a["section"], a["key"]) for a in audit_rows} == {(r.section, r.key) for r in SAVEABLE}
    stored = config.dashboard_overrides_path().read_text(encoding="utf-8")
    for row in SAVEABLE:
        if row.secret:
            audited = next(a for a in audit_rows if (a["section"], a["key"]) == (row.section, row.key))
            assert audited["new"] == "set" and audited["old"] == "not set"
            assert state[row.id]["value"] is None and state[row.id]["is_set"] is True
    assert "k" * 40 not in stored and "k" * 40 not in repr(audit_rows)
    assert "k" * 40 not in r.text and "k" * 40 not in client.get(API).text
    assert "k" * 40 not in every_group(client)

    # Going back to a looser default is confirmed like any other loosening.
    everything = [{"id": row.id, "reset": True} for row in SAVEABLE]
    assert _save(everything).status_code == 409
    reset = _save(everything, confirm=True)
    assert reset.status_code == 200, reset.text
    loaded = _loaded()
    for row in SAVEABLE:
        assert not catalog.lookup(loaded, row.path)[0], row.id


@pytest.mark.parametrize("setting", SAVEABLE, ids=lambda s: s.id)
def test_invalid_values_are_refused(setting):
    r = _save([{"id": setting.id, "value": _invalid(setting)}], confirm=True)
    assert r.status_code == 400, (setting.id, r.text)
    assert not catalog.lookup(_loaded(), setting.path)[0]


def _weakening(setting):
    """``(first, then)``: an optional starting value and a loosening change."""
    control, weaker = setting.control, setting.weaker
    if control == "toggle":
        return (None if setting.default is not weaker else not weaker), weaker
    if control == "number":
        default = _shown(setting, setting.default)
        edge = setting.maximum if weaker == "higher" else setting.minimum
        other = setting.minimum if weaker == "higher" else setting.maximum
        return (None if default != edge else other), edge
    if weaker == "grow":
        values = [v for v, _ in setting.choices]
        return (values[:1] if setting.default else None), values[:2]
    assert weaker == "change", setting.id
    return None, _sample(setting)


@pytest.mark.parametrize("setting", WEAKENING, ids=lambda s: s.id)
def test_loosening_needs_confirmation(setting):
    first, then = _weakening(setting)
    first_with, then_with = _TOGETHER.get(setting.id, ([], []))
    if first is not None:
        first_changes = [{"id": setting.id, "value": first}, *first_with]
        assert _save(first_changes, confirm=True).status_code == 200
    then_changes = [{"id": setting.id, "value": then}, *then_with]
    refused = _save(then_changes)
    assert refused.status_code == 409, (setting.id, refused.text)
    assert setting.id in {item["id"] for item in refused.json()["confirm"]}
    assert _save(then_changes, confirm=True).status_code == 200
    assert catalog.lookup(_loaded(), setting.path)[1] == _stored(setting, then)


def test_parser_limits_can_be_lowered_without_confirmation():
    r = _save([{"id": "ai_evidence_analysis.ocr.max_pixels", "value": 10}])
    assert r.status_code == 200
    assert _loaded()["ai_evidence_analysis"]["ocr"]["max_pixels"] == 10_000_000


def test_environment_setting_locks_the_row(monkeypatch):
    monkeypatch.setenv("MAVERICK_EVIDENCE_PACKET_MAX_TOTAL", "500")
    row = _rows_by_id()["evidence_gateway.packet_max_total"]
    assert row["locked"] is True and row["source"] == "deployment"
    r = _save([{"id": "evidence_gateway.packet_max_total", "value": 900}])
    assert r.status_code == 409


# ----------------------------------------------- readers that use saved values
def test_evidence_record_limits_take_effect_with_the_environment_winning(monkeypatch):
    from maverick import ai_evidence_gateway as gateway

    assert _save([{"id": "evidence_gateway.packet_max_total", "value": 250},
                  {"id": "evidence_gateway.receipt_segment_bytes", "value": 8}]).status_code == 200
    assert gateway._packet_capacity() == 250
    assert gateway._receipt_segment_bytes() == 8 * 1024 * 1024
    monkeypatch.setenv("MAVERICK_EVIDENCE_PACKET_MAX_TOTAL", "400")
    assert gateway._packet_capacity() == 400


def test_helper_finding_length_takes_effect_with_the_environment_winning(monkeypatch):
    from maverick.agent import _finding_excerpt

    assert _save([{"id": "swarm.finding_post_max_chars", "value": 300}]).status_code == 200
    assert len(_finding_excerpt("y" * 5000)) < 500
    monkeypatch.setenv("MAVERICK_FINDING_POST_MAX_CHARS", "3000")
    assert len(_finding_excerpt("y" * 5000)) > 2500


def test_saved_identity_connector_key_is_used_and_the_server_key_wins(monkeypatch):
    from maverick_dashboard import identity_governance_runtime as runtime

    key = "saved-okta-key-for-tests"  # pragma: allowlist secret
    r = _save([
        {"id": "ai_identity_governance_connectors.enable", "value": True},
        {"id": "ai_identity_governance_connectors.okta.enable", "value": True},
        {"id": "ai_identity_governance_connectors.okta.tenant_id", "value": "org-123"},
        {"id": "ai_identity_governance_connectors.okta.base_url",
         "value": "https://acme.okta.com", },
        {"id": "ai_identity_governance_connectors.okta.credential", "value": key},
        {"id": "ai_identity_governance_connectors.okta.max_pages", "value": 7},
    ], confirm=True)
    assert r.status_code == 200, r.text
    adapters = runtime._adapters(_loaded()["ai_identity_governance_connectors"])
    assert len(adapters) == 1
    adapter = adapters[0]
    assert adapter._config.base_url == "https://acme.okta.com"
    assert adapter._config.limits.max_pages == 7
    assert adapter._credential() == key
    monkeypatch.setenv("OKTA_IDENTITY_GOVERNANCE_TOKEN", "server-okta-key")
    assert adapter._credential() == "server-okta-key"


def test_identity_connector_without_any_key_still_fails_closed():
    from maverick.ai_identity_governance_connectors import (
        IdentityGovernanceConfigError,
        configured_connectors,
    )

    section = {"enable": True, "okta": {"enable": True, "tenant_id": "org",
                                       "base_url": "https://acme.okta.com"}}
    with pytest.raises(IdentityGovernanceConfigError):
        configured_connectors(section, transports={"okta": object()},
                              secret_resolver=lambda _name: None)
    section["okta"]["credential"] = ""
    with pytest.raises(IdentityGovernanceConfigError):
        configured_connectors(section, transports={"okta": object()},
                              secret_resolver=lambda _name: None)


def test_saved_grc_vendor_key_is_used_and_the_server_key_wins(monkeypatch):
    from maverick import grc_vendor_transports as transports
    from maverick.grc_outbound_sync import GRCSystem

    key = "saved-servicenow-key"  # pragma: allowlist secret
    r = _save([
        {"id": "grc_outbound_sync.servicenow_irm.base_url",
         "value": "https://acme.service-now.com/"},
        {"id": "grc_outbound_sync.servicenow_irm.credential", "value": key},
        {"id": "grc_outbound_sync.servicenow_irm.timeout_seconds", "value": 5},
    ], confirm=True)
    assert r.status_code == 200, r.text
    transport = transports.transport_from_config(GRCSystem.SERVICENOW_IRM)
    assert transport._base_url == "https://acme.service-now.com"
    assert transport._limits.timeout_seconds == 5.0
    resolve = transport._secret_resolver
    reference = transport._credential_secret_ref
    assert transports._credential(reference, resolve, archer=False) == key
    monkeypatch.setenv("SERVICENOW_TOKEN", "server-servicenow-key")
    assert transports._credential(reference, resolve, archer=False) == "server-servicenow-key"


def test_saved_red_team_key_is_used_and_the_server_key_wins(monkeypatch):
    from maverick import red_team_assurance as red_team

    key = "r" * 40
    r = _save([{"id": "red_team_assurance.enable", "value": True},
               {"id": "red_team_assurance.commitment_key", "value": key}])
    assert r.status_code == 200, r.text
    assert red_team._commitment_key(red_team._settings()) == key.encode()
    monkeypatch.setenv("MAVERICK_RED_TEAM_COMMITMENT_KEY", "s" * 40)
    assert red_team._commitment_key(red_team._settings()) == ("s" * 40).encode()


def test_saved_evidence_analysis_limits_reach_the_module():
    from maverick_dashboard.ai_evidence_analysis_composition import (
        ai_evidence_analysis_settings,
    )

    _base("[evidence_gateway]\nenable = true\n\n[ai_evidence_analysis]\nenable = true\n")
    r = _save([
        {"id": "ai_evidence_analysis.enabled_media_types", "value": ["pdf", "text"]},
        {"id": "ai_evidence_analysis.max_artifact_bytes", "value": 5},
        {"id": "ai_evidence_analysis.retention_seconds", "value": 30},
    ], confirm=True)
    assert r.status_code == 200, r.text
    settings = ai_evidence_analysis_settings(_loaded())
    assert settings.max_artifact_bytes == 5 * 1024 * 1024
    assert settings.retention_seconds == 30 * 86400
    assert set(settings.enabled_media_types) == {"application/pdf", "text/plain"}


def test_saved_identity_schedule_reaches_the_scheduler():
    from maverick_dashboard.identity_governance_scheduler import configured_schedules

    _base("[ai_identity_governance_connectors]\nenable = true\n\n"
          "[ai_identity_governance_connectors.entra]\nenable = true\n")
    prefix = "ai_identity_governance_connectors.scheduler"
    r = _save([
        {"id": f"{prefix}.enable", "value": True},
        {"id": f"{prefix}.providers.entra.enable", "value": True},
        {"id": f"{prefix}.providers.entra.interval_seconds", "value": 30},
        {"id": f"{prefix}.providers.entra.history_limit", "value": 4},
    ])
    assert r.status_code == 200, r.text
    (schedule,) = configured_schedules(_loaded()["ai_identity_governance_connectors"])
    assert schedule.provider == "entra"
    assert schedule.interval_seconds == 1800 and schedule.history_limit == 4


def test_saved_rating_providers_reach_the_module():
    from maverick_dashboard.third_party_intelligence_provider_composition import (
        provider_settings,
    )

    _base("[third_party_management]\nenable = true\n\n"
          "[third_party_management.intelligence]\nenable = true\n")
    prov = "third_party_management.intelligence.providers"
    r = _save([
        {"id": f"{prov}.enable", "value": True},
        {"id": f"{prov}.enabled_providers", "value": ["riskrecon", "supplywisdom"]},
        {"id": f"{prov}.supplywisdom_host", "value": "api.supplywisdom.example"},
        {"id": f"{prov}.timeout_seconds", "value": 12},
    ], confirm=True)
    assert r.status_code == 200, r.text
    settings = provider_settings(_loaded())
    assert settings.enabled_providers == ("riskrecon", "supplywisdom")
    assert settings.named_provider_hosts == {"supplywisdom": "api.supplywisdom.example"}
    assert settings.timeout_seconds == 12.0


def test_saved_vault_file_kinds_reach_the_vault():
    from maverick.governed_document_vault import GovernedDocumentVaultConfig

    r = _save([{"id": "governed_document_vault.allowed_media_types",
                "value": ["application/pdf", "text/plain"]}])
    assert r.status_code == 200, r.text
    vault = GovernedDocumentVaultConfig.from_mapping(_loaded())
    assert vault.allowed_media_types == ("application/pdf", "text/plain")


def test_governance_agent_limits_stay_within_their_ceiling():
    # The module never goes above its own defaults, so the page offers no more.
    from maverick.governance_agents import GovernanceAgentLimits

    ceiling = GovernanceAgentLimits()
    for key in ("max_context_items", "max_context_bytes", "max_output_bytes",
                "retention_seconds"):
        row = catalog.BY_ID[f"governance_agents.{key}"]
        assert row.maximum * row.scale == getattr(ceiling, key), key
