"""All settings refuses governance and learning combinations the kernel rejects.

Each rule mirrors a config_lint or module check: a combination the page used
to accept (a picture reader without the isolated area, a retry ceiling below
its first wait, a longer lookback than a collection may cover, a framework
check without cloud oversight, sending benchmark results with no address)
left the module switched off. The page now refuses it with a plain sentence
and saves nothing; a complete combination saved in one go still works.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard import settings_catalog_governance as governance
from maverick_dashboard import settings_catalog_learning as learning
from maverick_dashboard.app import app

from test_support.settings_pages import save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"
_EA = "ai_evidence_analysis"
_ENTRA = "ai_identity_governance_connectors.scheduler.providers.entra"
_OUTCOME = "ai_identity_governance_connectors.controls.production.outcome_retry"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _refused(module, values: dict, words: str) -> None:
    with pytest.raises(catalog.SettingError, match=words):
        module.cross_checks(values, catalog.BY_ID, catalog.SettingError)


def _accepted(module, values: dict) -> None:
    module.cross_checks(values, catalog.BY_ID, catalog.SettingError)


@pytest.mark.parametrize("values, words", [
    ({f"{_EA}.ocr.enable": True, f"{_EA}.enabled_media_types": ["png"]},
     "turn on “Open files in an isolated area” first"),
    ({f"{_EA}.legacy_xls.enable": True, f"{_EA}.enabled_media_types": ["xls"]},
     "turn on “Open files in an isolated area” first"),
    ({f"{_EA}.parser_sandbox.enable": True}, "as well, or leave it off"),
    ({f"{_EA}.parser_sandbox.enable": True, f"{_EA}.ocr.enable": True,
      f"{_EA}.enabled_media_types": ["pdf"]}, "allow JPEG or PNG pictures"),
    ({f"{_EA}.parser_sandbox.enable": True, f"{_EA}.legacy_xls.enable": True,
      f"{_EA}.enabled_media_types": ["xlsx"]}, "allow older Excel workbooks"),
    ({f"{_EA}.enabled_media_types": ["xls"]}, "also need"),
    ({f"{_ENTRA}.retry_base_seconds": 600, f"{_ENTRA}.retry_max_seconds": 60},
     "can't be more than longest wait between retries"),
    ({f"{_OUTCOME}_base_seconds": 600, f"{_OUTCOME}_max_seconds": 60},
     "can't be more than longest wait between follow-up retries"),
    ({"ai_cost_roi.collector_lookback_days": 120,
      "ai_cost_roi.collector_limits.max_period_days": 93},
     "can't be more than longest period one collection covers"),
])
def test_governance_combinations_the_kernel_rejects_are_refused(values, words):
    _refused(governance, values, words)


@pytest.mark.parametrize("values", [
    {},
    {f"{_EA}.parser_sandbox.enable": True, f"{_EA}.ocr.enable": True,
     f"{_EA}.enabled_media_types": ["pdf", "png"]},
    {f"{_EA}.parser_sandbox.enable": True, f"{_EA}.legacy_xls.enable": True,
     f"{_EA}.enabled_media_types": ["xls"]},
    {f"{_ENTRA}.retry_base_seconds": 60, f"{_ENTRA}.retry_max_seconds": 60},
    {"ai_cost_roi.collector_lookback_days": 93,
     "ai_cost_roi.collector_limits.max_period_days": 93},
])
def test_governance_combinations_the_kernel_accepts_pass(values):
    _accepted(governance, values)


def test_sending_benchmark_results_needs_the_service_address():
    send = "ai_benchmark_exchange.coordinator.enable"
    _refused(learning, {send: True}, "fill in “Benchmark service address” first")
    _refused(learning, {send: True, "ai_benchmark_exchange.coordinator.origin": "  "},
             "fill in")
    _accepted(learning, {send: True,
                         "ai_benchmark_exchange.coordinator.origin": "https://bench.example.com"})
    _accepted(learning, {send: False})


def test_the_page_refuses_a_broken_combination_and_saves_nothing():
    from maverick import config

    r = save_catalog(client, API, json={"changes": [{"id": f"{_EA}.parser_sandbox.enable", "value": True}],
                               "confirm": True})
    assert r.status_code == 400
    assert "Open files in an isolated area" in r.json()["message"]
    config.reset_config_cache()
    assert "ai_evidence_analysis" not in config.load_config()


def test_the_page_saves_a_complete_combination_in_one_go():
    from maverick import config

    changes = [
        {"id": f"{_ENTRA}.retry_max_seconds", "value": 1200},
        {"id": f"{_ENTRA}.retry_base_seconds", "value": 900},
    ]
    r = save_catalog(client, API, json={"changes": changes, "confirm": True})
    assert r.status_code == 200, r.text
    config.reset_config_cache()
    table = config.load_config()["ai_identity_governance_connectors"]["scheduler"]
    assert table["providers"]["entra"]["retry_base_seconds"] == 900
    # Raising the first wait above the saved ceiling alone is refused.
    r = save_catalog(client, API, json={"changes": [{"id": f"{_ENTRA}.retry_base_seconds",
                                            "value": 1500}], "confirm": True})
    assert r.status_code == 400
    assert "can't be more than" in r.json()["message"]


def test_config_lint_knows_every_key_the_page_writes():
    # The page saves these keys, and the runtime reads them; config-lint and
    # `maverick doctor` called 91 of them unknown keys (likely typos).
    from maverick.config_lint import lint_config

    unknown = []
    for setting in catalog.SETTINGS:
        if setting.key_kind != "key":
            continue  # tables whose rows are user-named keys
        cfg: dict = {}
        node = cfg
        for part in setting.path[:-1]:
            node = node.setdefault(part, {})
        node[setting.path[-1]] = setting.default if setting.default is not None else ""
        unknown += [f.message for f in lint_config(cfg) if "unknown" in f.message]
    assert unknown == []
