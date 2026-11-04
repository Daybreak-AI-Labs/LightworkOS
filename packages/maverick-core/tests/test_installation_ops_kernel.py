"""Kernel functions shared by installation commands and the dashboard's
maintenance controls: the whole-configuration inventory, the cost/perf
snapshot, the settings-file installer's backup and the key fingerprint."""
from __future__ import annotations

import hashlib
import time
from types import SimpleNamespace

import pytest


@pytest.fixture
def home(monkeypatch, tmp_path):
    from maverick import config
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_TENANT", "MAVERICK_CONFIG_OVERLAY", "MAVERICK_ENCRYPTION_KEY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_inventory_reports_the_winning_layer_and_never_a_secret(home, monkeypatch):
    from maverick import config
    from maverick.config_inventory import describe
    (home / "config.toml").write_text(
        '[safety]\nprofile = "strict"\nscan_input = true\n'
        '[providers.anthropic]\napi_key = "sk-test-not-real"\n'  # pragma: allowlist secret
        '[notifications]\nurl = "${LW_TEST_URL}"\n', encoding="utf-8")
    (home / "dashboard-config.toml").write_text('[safety]\nprofile = "balanced"\n', encoding="utf-8")
    monkeypatch.setenv("LW_TEST_URL", "https://alerts.example")
    config.reset_config_cache()
    report = describe()
    rows = {row["path"]: row for section in report["sections"] for row in section["keys"]}
    assert rows["safety.profile"]["layer"] == "dashboard" and rows["safety.profile"]["value"] == "balanced"
    assert rows["safety.scan_input"]["source"] == "file"
    key = rows["providers.anthropic.api_key"]
    assert key["secret"] is True and key["set"] is True and "value" not in key
    assert "sk-test-not-real" not in repr(report)
    url = rows["notifications.url"]
    assert url["source"] == "environment" and url["env"] == ["LW_TEST_URL"]
    assert url["value"] == "https://alerts.example"
    assert report["layers"] == {"file": True, "dashboard": True, "operator": False, "workspace": False}


def test_measure_summarises_recent_finished_runs():
    from maverick.release_canary import measure
    now = time.time()

    def episode(cost, seconds, outcome, ended=now):
        return SimpleNamespace(started_at=ended - seconds, ended_at=ended, cost_dollars=cost,
                               input_tokens=100, output_tokens=20, outcome=outcome)
    world = SimpleNamespace(list_episodes=lambda limit: [
        episode(0.2, 10, "success"), episode(0.4, 30, "failed"), episode(9.0, 5, "success", ended=now - 90 * 86400),
        SimpleNamespace(started_at=now, ended_at=None, cost_dollars=1, input_tokens=0, output_tokens=0, outcome=None)])
    metrics = measure(world, window_days=30, now=now)
    assert metrics == {"cost_per_task": 0.3, "tokens_per_task": 120.0, "p95_latency_s": 30.0, "success_rate": 0.5}
    assert measure(SimpleNamespace(list_episodes=lambda limit: []), now=now) == {}


def test_settings_file_install_keeps_a_backup_only_when_asked(home):
    from maverick.config_install import install_config_bytes, parse_config_bytes
    target = home / "config.toml"
    target.write_text("[safety]\nprofile = 'balanced'\n", encoding="utf-8")
    first = install_config_bytes(b"[safety]\nprofile = 'strict'\n", target)
    assert first["unchanged"] is False and first["backup"] is None
    second = install_config_bytes(b"[budget]\nmax_dollars = 1\n", target, backup=True)
    assert second["backup"].read_text(encoding="utf-8") == "[safety]\nprofile = 'strict'\n"
    assert install_config_bytes(b"[budget]\r\nmax_dollars = 1\r\n", target, backup=True)["unchanged"] is True
    with pytest.raises(ValueError):
        parse_config_bytes(b"[broken\n")


def test_key_digest_matches_the_injected_key(home, monkeypatch):
    from maverick.installation_info import KeyDigestError, encryption_key_digest
    with pytest.raises(KeyDigestError) as missing:
        encryption_key_digest()
    assert missing.value.reason == "unset"
    key = bytes(range(32))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    assert encryption_key_digest() == "sha256:" + hashlib.sha256(key).hexdigest()


def test_learning_move_preview_counts_waiting_files(home, monkeypatch):
    from maverick import self_harness
    from maverick.learning_store_migration import MigrationRefused, preview, require_world_store
    store = home / "addenda.json"
    store.write_text('{"model-a": "- keep answers short"}', encoding="utf-8")
    monkeypatch.setattr(self_harness, "_store_path", lambda: store)
    state = preview()
    assert state["addenda"] == 1 and state["world_store"] is False
    with pytest.raises(MigrationRefused):
        require_world_store()
