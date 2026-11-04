"""Production wiring for deterministic finance feed and GRC scheduling."""
from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest
from maverick_dashboard import finance_scheduler


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        """[finance]
regimes = ["sox", "dora"]

[finance_operations]
enable = true
federal_register_enable = true
regulatory_poll_seconds = 300
regulatory_domains = ["money_transmitter", "insurance_producer"]
control_test_interval_seconds = 300
""",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    finance_scheduler.stop_finance_scheduler(timeout=0)
    yield tmp_path
    finance_scheduler.stop_finance_scheduler(timeout=0)
    config.reset_config_cache()


def test_configured_sources_include_federal_and_explicit_state_feed():
    sources = finance_scheduler.configured_sources({
        "federal_register_enable": True,
        "texas_register_enable": True,
        "state_feeds": [{
            "key": "ny-register",
            "name": "New York State Register",
            "jurisdiction": "US-NY",
            "url": "https://dos.ny.gov/state-register",
            "format": "json",
            "default_domains": ["money_transmitter"],
            "field_map": {
                "items": "response.records",
                "id": "rule.identifier",
                "title": "rule.heading",
            },
        }],
    })
    assert [source.key for source in sources] == [
        "federal-register", "texas-register", "ny-register",
    ]
    assert sources[1].url == "https://www.sos.state.tx.us/texreg/texreg.xml"
    assert sources[1].default_domains == ("finance",)
    assert sources[2].default_domains == ("money_transmitter",)
    assert dict(sources[2].field_map) == {
        "items": "response.records",
        "id": "rule.identifier",
        "title": "rule.heading",
    }


def test_texas_register_is_opt_in_and_boolean():
    assert finance_scheduler.configured_sources({
        "federal_register_enable": False,
    }) == ()
    assert [source.key for source in finance_scheduler.configured_sources({
        "federal_register_enable": False,
        "texas_register_enable": True,
    })] == ["texas-register"]
    with pytest.raises(ValueError, match="texas_register_enable must be boolean"):
        finance_scheduler.configured_sources({
            "federal_register_enable": False,
            "texas_register_enable": "true",
        })


def test_configured_sources_fail_closed_on_ssrf_or_duplicate_key():
    with pytest.raises(ValueError, match="https"):
        finance_scheduler.configured_sources({
            "federal_register_enable": False,
            "state_feeds": [{
                "key": "local", "name": "Local", "jurisdiction": "US-X",
                "url": "http://127.0.0.1/feed", "format": "rss",
            }],
        })
    with pytest.raises(ValueError, match="unique"):
        finance_scheduler.configured_sources({
            "federal_register_enable": True,
            "state_feeds": [{
                "key": "federal-register", "name": "Duplicate", "jurisdiction": "US-X",
                "url": "https://example.gov/feed", "format": "rss",
            }],
        })


@pytest.mark.parametrize(
    ("field_map", "message"),
    [
        ([], "must be an object"),
        ({f"field-{index}": "value" for index in range(33)}, "no more than 32"),
        ({"x" * 65: "value"}, "keys must not exceed 64"),
        ({"title": "x" * 257}, "paths must not exceed 256"),
        ({"title": "   "}, "must be non-empty"),
    ],
)
def test_configured_sources_reject_unbounded_field_maps(field_map, message):
    with pytest.raises(ValueError, match=message):
        finance_scheduler.configured_sources({
            "federal_register_enable": False,
            "state_feeds": [{
                "key": "state-json",
                "name": "State JSON register",
                "jurisdiction": "US-X",
                "url": "https://example.gov/register.json",
                "format": "json",
                "field_map": field_map,
            }],
        })


def test_field_maps_written_as_entries_by_the_dashboard():
    feed = {"key": "state-json", "name": "State JSON register", "jurisdiction": "US-X",
            "url": "https://example.gov/register.json", "format": "json"}
    sources = finance_scheduler.configured_sources({
        "federal_register_enable": False,
        "state_feeds": [{**feed, "field_map": ["items=data.rows", " title = headline "]}],
    })
    assert dict(sources[0].field_map) == {"items": "data.rows", "title": "headline"}
    for bad in (["title"], ["title=a", "title=b"], ["title=a", 3]):
        with pytest.raises(ValueError, match="must be an object"):
            finance_scheduler.configured_sources({
                "federal_register_enable": False,
                "state_feeds": [{**feed, "field_map": bad}],
            })


def test_tenant_cycle_fetches_enabled_scopes_and_runs_grc(monkeypatch):
    from maverick import config
    from maverick.finance import control_testing, regulatory_change

    fetched = []
    controls = []
    reconciliations = []

    def fake_fetch(engine, source, **kwargs):
        fetched.append((engine.path.name, source.key, kwargs))
        return SimpleNamespace(items_seen=2, versions_created=1, alerts_created=1)

    monkeypatch.setattr(regulatory_change, "fetch_and_ingest", fake_fetch)
    monkeypatch.setattr(
        control_testing,
        "run_control_cycle",
        lambda **kwargs: controls.append(kwargs)
        or {"id": "FCT-test", "status": "pending_human_evidence"},
    )
    monkeypatch.setattr(
        control_testing,
        "reconcile_scheduled_cycles",
        lambda **kwargs: reconciliations.append(kwargs)
        or [{"id": "FCT-test", "status": "human_review_passed"}],
    )
    global_config = config.load_global_config()
    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)

    assert fetched[0][0] == "regulatory_change.sqlite3"
    assert fetched[0][1] == "federal-register"
    assert fetched[0][2]["enabled_regimes"] == ("sox", "dora")
    assert fetched[0][2]["enabled_domains"] == (
        "money_transmitter", "insurance_producer",
    )
    assert controls == [{"actor": "system:test-scheduler"}]
    assert reconciliations == [
        {
            "actor": "system:test-scheduler",
            "scan_limit": 100,
            "priority_cycle_id": "FCT-test",
        },
    ]


def test_poll_claim_is_one_per_tenant_across_processes(_isolate):
    tmp_path = _isolate
    script = """
import os, sys
os.environ['MAVERICK_HOME'] = sys.argv[1]
os.environ['MAVERICK_CONFIG'] = sys.argv[2]
from maverick import config
from maverick.paths import set_tenant
from maverick_dashboard import finance_scheduler
import time
config.reset_config_cache()
set_tenant(sys.argv[3])
with finance_scheduler._poll_lease('regulatory:federal-register', 300) as lease:
    claimed = lease is not None
    if claimed:
        time.sleep(0.25)
        lease.succeed()
print(f'{sys.argv[3]}:{int(claimed)}')
"""
    tenants = ["tenant-a", "tenant-a", "tenant-b", "tenant-b"]
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(tmp_path),
                str(tmp_path / "config.toml"),
                tenant,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for tenant in tenants
    ]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        tenant, claimed = stdout.strip().splitlines()[-1].split(":")
        results.append((tenant, bool(int(claimed))))
    assert sum(claimed for tenant, claimed in results if tenant == "tenant-a") == 1
    assert sum(claimed for tenant, claimed in results if tenant == "tenant-b") == 1


def test_failed_feed_poll_is_immediately_retryable(monkeypatch):
    from maverick import config
    from maverick.finance import control_testing, regulatory_change

    tenant_config = {
        "finance_operations": {
            "enable": True,
            "federal_register_enable": True,
            "regulatory_poll_seconds": 300,
            "regulatory_domains": [],
        },
    }
    attempts = []

    def flaky_fetch(*_args, **_kwargs):
        attempts.append("federal-register")
        if len(attempts) == 1:
            raise RuntimeError("temporary feed failure")
        return SimpleNamespace(items_seen=2, versions_created=1, alerts_created=1)

    monkeypatch.setattr(config, "load_config", lambda: tenant_config)
    monkeypatch.setattr(regulatory_change, "fetch_and_ingest", flaky_fetch)
    monkeypatch.setattr(
        control_testing,
        "schedule_config",
        lambda: {"interval_seconds": 0},
    )
    global_config = {"finance_operations": {"enable": True}}

    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)
    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)
    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)

    assert attempts == ["federal-register", "federal-register"]


def test_failed_licensing_pack_sync_is_immediately_retryable(monkeypatch):
    from maverick import config
    from maverick.finance import control_testing, licensing

    tenant_config = {
        "finance_operations": {
            "enable": True,
            "federal_register_enable": False,
            "regulatory_poll_seconds": 300,
            "regulatory_domains": ["money_transmitter"],
        },
    }
    attempts = []

    def flaky_sync(_engine, pack, **_kwargs):
        attempts.append(pack.vertical)
        if len(attempts) == 1:
            raise RuntimeError("temporary pack failure")
        return SimpleNamespace(items_seen=50, versions_created=50, alerts_created=50)

    monkeypatch.setattr(config, "load_config", lambda: tenant_config)
    monkeypatch.setattr(licensing, "ingest_pack_into_regulatory_register", flaky_sync)
    monkeypatch.setattr(
        control_testing,
        "schedule_config",
        lambda: {"interval_seconds": 0},
    )
    global_config = {"finance_operations": {"enable": True}}

    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)
    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)
    finance_scheduler._tenant_cycle("system:test-scheduler", global_config)

    assert attempts == ["money_transmitter", "money_transmitter"]


def test_start_is_off_when_global_gate_is_disabled(_isolate):
    tmp_path = _isolate
    from maverick import config

    (tmp_path / "config.toml").write_text(
        "[finance_operations]\nenable = false\n", encoding="utf-8"
    )
    config.reset_config_cache()
    assert finance_scheduler.start_finance_scheduler() is False


def test_start_and_stop_are_bounded(monkeypatch):
    monkeypatch.setattr(finance_scheduler, "_scheduler_loop", lambda *_args: None)
    assert finance_scheduler.start_finance_scheduler() is True
    assert finance_scheduler.stop_finance_scheduler(timeout=0.1) is True


def test_configured_sources_include_eu_presets_when_opted_in():
    sources = finance_scheduler.configured_sources({
        "federal_register_enable": False,
        "eur_lex_enable": True,
        "edpb_enable": True,
    })
    assert [s.key for s in sources] == ["eur-lex-legislation", "edpb-news"]
    by_key = {s.key: s for s in sources}
    assert by_key["eur-lex-legislation"].jurisdiction == "EU"
    assert by_key["eur-lex-legislation"].format == "rss"
    assert by_key["eur-lex-legislation"].url.startswith(
        "https://eur-lex.europa.eu/")
    assert by_key["edpb-news"].default_domains == ("privacy",)
    assert by_key["edpb-news"].url.startswith("https://www.edpb.europa.eu/")
    # Off by default: an empty section configures neither.
    default_keys = [s.key for s in finance_scheduler.configured_sources({})]
    assert "eur-lex-legislation" not in default_keys
    assert "edpb-news" not in default_keys


def test_eu_preset_flags_must_be_boolean():
    import pytest

    with pytest.raises(ValueError, match="eur_lex_enable"):
        finance_scheduler.configured_sources({"eur_lex_enable": "yes"})
    with pytest.raises(ValueError, match="edpb_enable"):
        finance_scheduler.configured_sources({"edpb_enable": 1})
