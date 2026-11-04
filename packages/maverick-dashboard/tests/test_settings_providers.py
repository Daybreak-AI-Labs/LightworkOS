"""Provider-key entry + capability/feature toggles via the dashboard config
overlay (~/.maverick/dashboard-config.toml, deep-merged in config.load_config).
Neither path touches config.toml. (Per-role models live in the separate runtime
overlay.)"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


def _no_provider_env(monkeypatch):
    from maverick import config
    for v in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(v, raising=False)
    for v in ("GOOGLE_API_KEY", "GROK_API_KEY"):
        monkeypatch.delenv(v, raising=False)


def test_provider_key_overlay_unblocks(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    _no_provider_env(monkeypatch)
    from maverick import config
    from maverick_dashboard import settings_store
    assert config.any_provider_configured() is False
    settings_store.set_provider("anthropic", api_key="sk-test-123456")  # pragma: allowlist secret
    assert config.dashboard_overrides_path().exists()
    assert not config.config_path().exists()            # config.toml untouched
    persisted = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert "sk-test-123456" not in persisted  # pragma: allowlist secret
    assert "MVKAR1:" in persisted
    assert config.any_provider_configured() is True
    assert config.get_provider_config("anthropic")["api_key"] == "sk-test-123456"  # pragma: allowlist secret
    settings_store.clear_provider("anthropic")
    assert config.any_provider_configured() is False


def test_toggle_overlay_reflected(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import config
    from maverick_dashboard import settings_store
    assert config.get_capabilities()["web_search"] is False
    settings_store.set_toggle("capabilities", "web_search", True)
    assert config.get_capabilities()["web_search"] is True
    settings_store.set_toggle("features", "skills", False)
    assert config.get_features()["skills"] is False


def test_settings_exposes_every_runtime_feature_toggle(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import config
    from maverick_dashboard import settings_store

    assert set(settings_store.FEATURE_DEFAULTS) == set(config.get_features())
    settings_store.set_toggle("features", "pack_editing", False)
    settings_store.set_toggle("features", "triggers", False)
    effective = config.get_features()
    assert effective["pack_editing"] is False
    assert effective["triggers"] is False


def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_settings_page_has_provider_entry_and_toggles(monkeypatch, tmp_path):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    r = c.get("/settings")
    assert r.status_code == 200
    assert 'action="/settings/providers"' in r.text      # editable key entry
    assert 'action="/settings/capabilities"' in r.text    # capability toggles
    assert 'name="web_search"' in r.text


def test_provider_post_redacts_and_persists(monkeypatch, tmp_path):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    assert c.post("/settings/providers",
                  data={"provider": "openai", "api_key": "sk-secret-abcd9999"}).status_code == 200  # pragma: allowlist secret
    assert config.get_provider_config("openai")["api_key"] == "sk-secret-abcd9999"  # pragma: allowlist secret
    body = c.get("/settings").text
    assert "sk-secret-abcd9999" not in body  # pragma: allowlist secret  (raw key never echoed)
    assert "9999" in body                                # only the masked hint


def test_tenant_provider_source_is_displayed_and_dashboard_rotation_refused(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    from maverick_dashboard import settings_store

    tenant_path = config.tenant_config_path()
    assert tenant_path is not None
    tenant_path.parent.mkdir(parents=True, exist_ok=True)
    tenant_path.write_text(
        '[providers.openai]\napi_key = "tenant-secret"\n',  # pragma: allowlist secret
        encoding="utf-8",
    )
    config.reset_config_cache()

    state = config.provider_configuration_state("openai")
    assert state["api_key_source"] == "tenant config"  # pragma: allowlist secret
    assert state["dashboard_can_set_api_key"] is False
    page = c.get("/settings").text
    assert "This key is set for this workspace, so it can't be changed here." in page

    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "dashboard-secret"},  # pragma: allowlist secret
    )
    assert response.status_code == 409
    assert "rotate that source" in response.json()["detail"]
    assert config.get_provider_config("openai")["api_key"] == "tenant-secret"  # pragma: allowlist secret
    assert "openai" not in settings_store.load_overlay().get("providers", {})


def test_post_commit_provider_mismatch_rolls_back_dashboard_overlay(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    from maverick_dashboard import settings_store

    monkeypatch.setattr(
        config,
        "get_provider_config",
        lambda _name: {"api_key": "higher-authority-secret"},  # pragma: allowlist secret
    )

    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "rejected-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 409, response.text
    assert not config.dashboard_overrides_path().exists()
    assert "openai" not in settings_store.load_overlay().get("providers", {})


def test_provider_authority_fingerprint_change_prevents_persisted_rotation(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    from maverick_dashboard import settings_store

    generations = iter(("stable", "stable", "stable", "changed", "changed"))
    monkeypatch.setattr(
        settings_store,
        "_provider_authority_fingerprint",
        lambda _name: next(generations),
    )

    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "rejected-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 409, response.text
    assert not config.dashboard_overrides_path().exists()
    assert "openai" not in settings_store.load_overlay().get("providers", {})


def test_provider_rotation_decryption_failure_is_recoverable_503(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    from maverick_dashboard import settings_store

    settings_store.set_provider(
        "anthropic",
        api_key="existing-secret",  # pragma: allowlist secret
    )
    path = config.dashboard_overrides_path()
    before = path.read_bytes()

    def unreadable(_data):
        raise ValueError("ciphertext authentication failed")

    monkeypatch.setattr(settings_store, "_unseal_overlay", unreadable)
    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "new-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 503, response.text
    assert "new-secret" not in response.text  # pragma: allowlist secret
    assert path.read_bytes() == before


def test_provider_rotation_post_write_read_failure_rolls_back_with_503(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    from maverick_dashboard import settings_store

    settings_store.set_provider(
        "anthropic",
        api_key="existing-secret",  # pragma: allowlist secret
    )
    path = config.dashboard_overrides_path()
    before = path.read_bytes()
    real_state = config.provider_configuration_state
    calls = 0

    def fail_after_publish(name):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError("provider config read failed")
        return real_state(name)

    monkeypatch.setattr(config, "provider_configuration_state", fail_after_publish)
    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "new-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 503, response.text
    assert calls == 2
    assert path.read_bytes() == before


def test_provider_rotation_publish_io_failure_rolls_back_with_503(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    from maverick_dashboard import settings_store

    settings_store.set_provider(
        "anthropic",
        api_key="existing-secret",  # pragma: allowlist secret
    )
    path = config.dashboard_overrides_path()
    before = path.read_bytes()
    real_write = settings_store._write
    calls = 0

    def publish_then_fail(data):
        nonlocal calls
        calls += 1
        real_write(data)
        if calls == 1:
            raise OSError("directory sync failed after replace")

    monkeypatch.setattr(settings_store, "_write", publish_then_fail)
    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "new-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 503, response.text
    assert calls == 1  # rollback restores the byte-exact snapshot directly
    assert path.read_bytes() == before


def test_provider_rotation_rollback_restores_exact_bytes_and_mode(
    monkeypatch, tmp_path
):
    import os
    import stat

    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config

    path = config.dashboard_overrides_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = (
        b"# retained operator comment\n"
        b"[future_extension]\n"
        b"opaque = { version = 9, values = [\"a\", \"b\"] }\n"
    )
    path.write_bytes(original)
    os.chmod(path, 0o600)
    original_mode = stat.S_IMODE(path.stat().st_mode)
    config.reset_config_cache()

    monkeypatch.setattr(
        config,
        "get_provider_config",
        lambda _name: {"api_key": "higher-authority-secret"},  # pragma: allowlist secret
    )
    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "rejected-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 409, response.text
    assert path.read_bytes() == original
    assert stat.S_IMODE(path.stat().st_mode) == original_mode


def test_provider_rotation_refuses_process_local_lock_fallback(
    monkeypatch, tmp_path
):
    from contextlib import contextmanager

    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    from maverick import config, file_lock

    path = config.dashboard_overrides_path()

    @contextmanager
    def unavailable_lock(_target, *, strict=False):
        assert strict is True
        raise RuntimeError("cross-process lock backend is unavailable")
        yield  # pragma: no cover

    monkeypatch.setattr(file_lock, "cross_process_lock", unavailable_lock)
    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "new-secret"},  # pragma: allowlist secret
    )

    assert response.status_code == 503, response.text
    assert not path.exists()

    # A failed strict acquisition must not retain the process lock and wedge
    # later dashboard settings operations.
    monkeypatch.undo()
    _no_provider_env(monkeypatch)
    c = _client(monkeypatch, tmp_path)
    follow_up = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "recovered-secret"},  # pragma: allowlist secret
        follow_redirects=False,
    )
    assert follow_up.status_code == 303, follow_up.text


def test_environment_key_can_be_replaced_and_effective_digest_is_verified(
    monkeypatch, tmp_path
):
    _no_provider_env(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "environment-secret")  # pragma: allowlist secret
    c = _client(monkeypatch, tmp_path)
    from maverick import config

    before = config.provider_configuration_state("openai")
    assert before["api_key_source"] == "environment:OPENAI_API_KEY"  # pragma: allowlist secret
    assert before["dashboard_can_set_api_key"] is True

    response = c.post(
        "/settings/providers",
        data={"provider": "openai", "api_key": "rotated-secret"},  # pragma: allowlist secret
    )
    assert response.status_code == 200, response.text
    after = config.provider_configuration_state("openai")
    assert after["api_key_source"] == "dashboard"  # pragma: allowlist secret
    assert config.get_provider_config("openai")["api_key"] == "rotated-secret"  # pragma: allowlist secret


def test_toggle_endpoints(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    from maverick import config
    assert c.post("/settings/capabilities", data={"browser": "on"}).status_code == 200
    assert config.get_capabilities()["browser"] is True
    # an unchecked box is omitted from the form -> deactivated on save
    assert c.post("/settings/capabilities", data={}).status_code == 200
    assert config.get_capabilities()["browser"] is False


def test_concurrent_provider_and_toggle_both_apply(monkeypatch, tmp_path):
    """A set_provider racing a set_toggle (different sections of one overlay
    file) must not have either change clobbered by a stale re-read."""
    import threading

    monkeypatch.setenv("HOME", str(tmp_path))
    _no_provider_env(monkeypatch)
    from maverick_dashboard import settings_store

    barrier = threading.Barrier(2)

    def do_provider():
        barrier.wait()
        settings_store.set_provider("anthropic", api_key="sk-test-abc123")  # pragma: allowlist secret

    def do_toggle():
        barrier.wait()
        name = next(iter(settings_store.FEATURE_DEFAULTS))
        settings_store.set_toggle("features", name, True)

    ts = [threading.Thread(target=do_provider), threading.Thread(target=do_toggle)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    overlay = settings_store.load_overlay()
    assert overlay.get("providers", {}).get("anthropic", {}).get("api_key")
    name = next(iter(settings_store.FEATURE_DEFAULTS))
    assert overlay.get("features", {}).get(name) is True
