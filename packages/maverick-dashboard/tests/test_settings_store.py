"""Cross-process/in-process locking contract for the dashboard settings
overlay mutators. set_channel/clear_channel do a read-modify-write of the
single dashboard-config.toml file and MUST hold _locked() across it, exactly
like set_provider/clear_provider/set_toggle -- otherwise two concurrent saves
read the same base snapshot and the second _write() clobbers the first,
silently dropping a freshly saved credential (lost update)."""
from __future__ import annotations

import threading

import pytest


def _lock_held_during(monkeypatch, call) -> bool:
    """Report whether ``call`` holds the settings lock for its complete RMW.

    Mutators intentionally use the strict ``_load_overlay_for_update`` reader,
    rather than the forgiving public ``load_overlay`` reader, so an unreadable
    overlay cannot be replaced and lose unrelated settings. Instrument both
    that read and the write from a competing thread. ``_SETTINGS_LOCK`` is
    reentrant for nested reviewed changes, so probing from its owning thread
    would succeed even while the complete mutation is correctly locked.
    """
    from maverick_dashboard import settings_store

    held: list[bool] = []
    real_load = settings_store._load_overlay_for_update
    real_write = settings_store._write

    def record_lock_state() -> None:
        def probe():
            acquired = settings_store._SETTINGS_LOCK.acquire(blocking=False)
            if acquired:
                settings_store._SETTINGS_LOCK.release()
            held.append(not acquired)
        contender = threading.Thread(target=probe)
        contender.start()
        contender.join(timeout=2)
        assert not contender.is_alive(), "The competing lock probe must return without blocking"

    def probing_load():
        record_lock_state()
        return real_load()

    def probing_write(data, **kwargs):
        record_lock_state()
        return real_write(data, **kwargs)

    monkeypatch.setattr(settings_store, "_load_overlay_for_update", probing_load)
    monkeypatch.setattr(settings_store, "_write", probing_write)
    call(settings_store)
    return len(held) == 2 and all(held)


def test_set_channel_holds_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    held = _lock_held_during(
        monkeypatch,
        lambda s: s.set_channel("telegram", True, {"bot_token": "tok-12345"}),  # pragma: allowlist secret
    )
    assert held, "set_channel must hold _locked() during its read-modify-write"


def test_clear_channel_holds_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import settings_store

    settings_store.set_channel("telegram", True, {"bot_token": "tok-12345"})  # pragma: allowlist secret
    held = _lock_held_during(monkeypatch, lambda s: s.clear_channel("telegram"))
    assert held, "clear_channel must hold _locked() during its read-modify-write"


def test_concurrent_channel_and_provider_both_apply(monkeypatch, tmp_path):
    """A set_channel racing a set_provider (different sections of one overlay
    file) must not have either change clobbered by a stale re-read."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import config
    for v in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(v, raising=False)
    from maverick_dashboard import settings_store

    barrier = threading.Barrier(2)

    def do_channel():
        barrier.wait()
        settings_store.set_channel("telegram", True, {"bot_token": "tok-channel"})  # pragma: allowlist secret

    def do_provider():
        barrier.wait()
        settings_store.set_provider("anthropic", api_key="sk-test-prov")  # pragma: allowlist secret

    ts = [threading.Thread(target=do_channel), threading.Thread(target=do_provider)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    overlay = settings_store.load_overlay()
    assert overlay.get("channels", {}).get("telegram", {}).get("bot_token") == "tok-channel"  # pragma: allowlist secret
    assert overlay.get("providers", {}).get("anthropic", {}).get("api_key") == "sk-test-prov"  # pragma: allowlist secret
    persisted = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert "tok-channel" not in persisted  # pragma: allowlist secret
    assert "sk-test-prov" not in persisted  # pragma: allowlist secret
    assert persisted.count("MVKAR1:") >= 2


def test_every_switchable_section_survives_a_round_trip(monkeypatch, tmp_path):
    """_dump is an allowlist: a SWITCHABLE_SECTIONS entry missing from it is
    silently dropped on the next save, so set_section_enable appears to work
    (the in-memory overlay looks right) while the persisted file -- and thus
    the state a restart or a fresh reader sees -- never got the change."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick_dashboard import settings_store

    for section in settings_store.SWITCHABLE_SECTIONS:
        settings_store.set_section_enable(section, True)
        overlay = settings_store.load_overlay()
        assert overlay.get(section, {}).get("enable") is True, section


@pytest.mark.parametrize("enabled", [True, False])
def test_switch_saves_preserve_oauth_and_workspace_settings(enabled):
    from maverick_dashboard import settings_store

    preserved = {"oauth": {"vault": True}, "workspace": {"journal": True, "journal_strict": True}}
    settings_store._write(preserved)
    for section in settings_store.SWITCHABLE_SECTIONS:
        settings_store.set_section_enable(section, enabled)
    settings_store.set_toggle("capabilities", "browser", True)

    # Re-read the persisted TOML after an unrelated save: this also refuses
    # duplicate sections shared by the learning, module, and switch registries.
    overlay = settings_store.load_overlay()
    assert all(overlay.get(section) == value for section, value in preserved.items())
    assert all(overlay.get(section, {}).get("enable") is enabled for section in settings_store.SWITCHABLE_SECTIONS)
    assert overlay["capabilities"]["browser"] is True


def test_research_execution_round_trip_is_validated_and_preserves_other_settings(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import config
    from maverick_dashboard import settings_store

    (tmp_path / "config.toml").write_text("[research_execution]\nenable = false\n",
                                           encoding="utf-8")
    config.reset_config_cache()
    settings_store._write({"oauth": {"vault": True}, "workspace": {"journal": True}})
    before = settings_store.research_execution_state()
    value = {
        "enable": True,
        "image_id": "sha256:" + "2" * 64,
        "queue_seconds": 900,
        "evaluators": {"smoke": {"version": "v1", "stdout_sha256": "3" * 64}},
        "limits": {"timeout_seconds": 12.5, "output_bytes": 4096,
                   "memory_bytes": 67108864, "scratch_bytes": 2097152,
                   "pids": 16, "cpus": 0.25},
    }
    saved = settings_store.set_research_execution(
        value, expected_settings_sha256=before["settings_sha256"])

    assert saved["configuration"] == value
    overlay = settings_store.load_overlay()
    assert overlay["research_execution"] == value
    assert overlay["oauth"] == {"vault": True}
    assert overlay["workspace"] == {"journal": True}
    config.reset_config_cache()


def test_research_execution_overlay_replaces_base_evaluators_and_uses_cas(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import config
    from maverick_dashboard import settings_store

    (tmp_path / "config.toml").write_text(
        '[research_execution]\nenable = true\nimage_id = "sha256:' + "1" * 64 + '"\n'
        '[research_execution.evaluators.old]\nversion = "v1"\nstdout_sha256 = "' +
        "2" * 64 + '"\n', encoding="utf-8")
    config.reset_config_cache()
    original = settings_store.research_execution_state()
    replacement = {
        "enable": True, "image_id": "sha256:" + "3" * 64, "queue_seconds": 3600,
        "evaluators": {"new": {"version": "v2", "stdout_sha256": "4" * 64}},
        "limits": {"timeout_seconds": 10.0, "output_bytes": 65536,
                   "memory_bytes": 134217728, "scratch_bytes": 16777216,
                   "pids": 32, "cpus": 0.5},
    }
    saved = settings_store.set_research_execution(
        replacement, expected_settings_sha256=original["settings_sha256"])
    assert set(saved["configuration"]["evaluators"]) == {"new"}
    with pytest.raises(settings_store.ResearchSettingsConflict):
        settings_store.set_research_execution(
            {"enable": False}, expected_settings_sha256=original["settings_sha256"])
    config.reset_config_cache()


def test_research_execution_refuses_invalid_enabled_and_ambiguous_disabled_profiles(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import config
    from maverick_dashboard import settings_store

    config.reset_config_cache()
    revision = settings_store.research_execution_state()["settings_sha256"]
    with pytest.raises((ValueError, TypeError)):
        settings_store.set_research_execution(
            {"enable": True, "image_id": "latest", "evaluators": {}},
            expected_settings_sha256=revision,
        )
    with pytest.raises(ValueError):
        settings_store.set_research_execution(
            {"enable": False, "evaluators": {}}, expected_settings_sha256=revision)
    config.reset_config_cache()


def test_operator_overlay_research_profile_is_visible_but_not_dashboard_writable(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import config
    from maverick_dashboard import settings_store

    (tmp_path / "config.toml").write_text("[research_execution]\nenable = false\n",
                                           encoding="utf-8")
    operator = tmp_path / "operator.toml"
    operator.write_text(
        '[research_execution]\nenable = true\nimage_id = "sha256:' + "7" * 64 + '"\n'
        '[research_execution.evaluators.operator]\nversion = "v1"\nstdout_sha256 = "' +
        "8" * 64 + '"\n', encoding="utf-8")
    monkeypatch.setenv(config.CONFIG_OVERLAY_ENV, str(operator))
    config.reset_config_cache()

    state = settings_store.research_execution_state()
    assert state["source"] == "operator_overlay" and state["writable"] is False
    assert set(state["configuration"]["evaluators"]) == {"operator"}
    with pytest.raises(settings_store.ResearchSettingsUnavailable):
        settings_store.set_research_execution(
            {"enable": False}, expected_settings_sha256=state["settings_sha256"])
    assert settings_store.load_overlay().get("research_execution") is None
    config.reset_config_cache()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


def test_write_refuses_text_that_would_not_read_back(monkeypatch, tmp_path):
    """A value TOML cannot hold must never replace a readable overlay."""
    from maverick import config
    from maverick_dashboard import settings_store

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    config.reset_config_cache()
    settings_store.set_catalog_values({("sandbox", "timeout"): 30})
    before = config.dashboard_overrides_path().read_text()
    with pytest.raises(settings_store.SecuritySuiteConfigUnavailable):
        settings_store.set_catalog_values({("persona", "name"): "\ud800"})
    assert config.dashboard_overrides_path().read_text() == before
    assert settings_store.load_overlay()["sandbox"]["timeout"] == 30
    config.reset_config_cache()
