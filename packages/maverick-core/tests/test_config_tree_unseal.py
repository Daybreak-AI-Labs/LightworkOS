"""Batch config decryption retains per-read authentication and key freshness."""
from __future__ import annotations

import base64

import pytest
from maverick import config, crypto_at_rest


@pytest.fixture(autouse=True)
def isolated_keys(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    for name in ("MAVERICK_ENCRYPTION_KEY", "MAVERICK_ENTERPRISE", "MAVERICK_REPLICA_COUNT",
                 "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setattr(crypto_at_rest, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _seal(value):
    with crypto_at_rest.deployment_key_scope():
        return crypto_at_rest.seal_to_str(value)


def test_tree_resolves_key_once_per_read_and_keeps_detached_container_types(monkeypatch):
    first, second = _seal("first-value"), _seal("second-value")
    tree = {"a": [first, {"b": second}], "c": (first, "legacy", 3, False, None),
            "marker": "MVKAR1:AAAA"}
    original = crypto_at_rest._load_or_create_key
    calls = []

    def read_key():
        assert crypto_at_rest._FORCE_DEPLOYMENT_KEY.get() is True
        calls.append(True)
        return original()

    monkeypatch.setattr(crypto_at_rest, "_load_or_create_key", read_key)
    expected = {"a": ["first-value", {"b": "second-value"}],
                "c": ("first-value", "legacy", 3, False, None), "marker": "MVKAR1:AAAA"}
    opened = config._unseal_config_tree(tree)
    assert opened == expected
    assert len(calls) == 1
    assert tree["a"][0] == first and tree["a"][1]["b"] == second
    assert opened is not tree and opened["a"] is not tree["a"]
    opened["a"][1]["b"] = "changed locally"
    assert config._unseal_config_tree(tree) == expected
    assert len(calls) == 2  # No key or opened-config cache survives this read.
    assert config._UNSEALING.get() is False
    assert crypto_at_rest._FORCE_DEPLOYMENT_KEY.get() is False


def test_tree_observes_rotation_and_resolves_each_versioned_key_once(monkeypatch):
    legacy = _seal("legacy-value")
    first_id = crypto_at_rest.rotate_at_rest_key()
    first = _seal("first-rotation")
    original = crypto_at_rest._resolve_key_by_id
    calls = []

    def resolve(key_id):
        calls.append(key_id.hex())
        return original(key_id)

    monkeypatch.setattr(crypto_at_rest, "_resolve_key_by_id", resolve)
    assert config._unseal_config_tree([legacy, first, first]) == [
        "legacy-value", "first-rotation", "first-rotation",
    ]
    assert calls == [first_id]
    second_id = crypto_at_rest.rotate_at_rest_key()
    second = _seal("second-rotation")
    assert config._unseal_config_tree([first, second, legacy]) == [
        "first-rotation", "second-rotation", "legacy-value",
    ]
    assert calls == [first_id, first_id, second_id]


def test_tree_rechecks_key_permissions_on_next_read(monkeypatch):
    token = _seal("private-value")
    assert config._unseal_config_tree([token, token]) == ["private-value", "private-value"]

    def denied(_path):
        raise PermissionError("key permissions changed")

    monkeypatch.setattr(crypto_at_rest.file_lock, "ensure_private_file", denied)
    with pytest.raises(crypto_at_rest.EncryptionUnavailable, match="key permissions changed"):
        config._unseal_config_tree([token, token])
    assert config._UNSEALING.get() is False
    assert crypto_at_rest._FORCE_DEPLOYMENT_KEY.get() is False


def test_corrupted_member_refuses_entire_overlay_and_next_read_can_recover(tmp_path):
    good = _seal("authenticated-value")
    blob = bytearray(base64.b64decode(good.partition(":")[2]))
    blob[-1] ^= 1
    corrupt = "MVKAR1:" + base64.b64encode(blob).decode("ascii")
    overlay = tmp_path / config.DASHBOARD_OVERRIDES_BASENAME
    overlay.write_text(f'[sample]\nfirst = "{good}"\nsecond = "{corrupt}"\n', encoding="utf-8")
    assert "sample" not in config.load_config()
    assert str(overlay) in config.config_source_errors()
    assert config._UNSEALING.get() is False
    assert crypto_at_rest._FORCE_DEPLOYMENT_KEY.get() is False
    overlay.write_text(f'[sample]\nfirst = "{good}"\nsecond = "{good}"\n', encoding="utf-8")
    config.reset_config_cache()
    assert config.load_config()["sample"] == {
        "first": "authenticated-value", "second": "authenticated-value",
    }
    assert str(overlay) not in config.config_source_errors()


def test_unreadable_secret_drops_its_section_not_the_other_dashboard_settings(tmp_path):
    """One credential that cannot be opened used to drop the whole dashboard
    overlay, which put back every limit the dashboard had tightened."""
    (tmp_path / "config.toml").write_text(
        '[capabilities]\ncode_exec = true\n[providers.openai]\napi_key = "installer-key"\n'  # pragma: allowlist secret
        '[webhooks]\noutbound = ["https://installer.example"]\n',
        encoding="utf-8")
    good = _seal("authenticated-value")
    blob = bytearray(base64.b64decode(good.partition(":")[2]))
    blob[-1] ^= 1
    corrupt = "MVKAR1:" + base64.b64encode(blob).decode("ascii")
    resets = ('[_dashboard_resets.hooks]\npath = ["webhooks", "outbound"]\nkeep = []\n'
              'entries = false\npreserve_tables = false\nremove_value = true\n'
              '[_dashboard_resets.caps]\npath = ["capabilities", "browser"]\nkeep = []\n'
              'entries = false\npreserve_tables = false\nremove_value = true\n')
    overlay = tmp_path / config.DASHBOARD_OVERRIDES_BASENAME
    overlay.write_text(
        '[capabilities]\ncode_exec = false\n[sandbox]\nbackend = "docker"\n'
        f'[providers.openai]\nbase_url = "https://proxy.example"\napi_key = "{corrupt}"\n'
        f'[webhooks]\nsecret = "{corrupt}"\n[channels.slack]\nbot_token = "{good}"\n' + resets,
        encoding="utf-8")
    config.reset_config_cache()

    loaded = config.load_config()
    assert config.get_capabilities()["code_exec"] is False  # the dashboard's limit holds
    assert config.get_sandbox()["backend"] == "docker"
    # ...so a workspace still cannot loosen it while the overlay is in this state.
    merged, ignored, _fixed = config._tighten_tenant(
        config.load_global_config(), {"capabilities": {"code_exec": True}})
    assert merged["capabilities"]["code_exec"] is False and ignored == ["capabilities.code_exec"]
    assert loaded["channels"]["slack"]["bot_token"] == "authenticated-value"
    # A section with an unreadable secret is ignored as a unit, with its reset
    # marker: the installer's own values stay, and its key is never paired
    # with the dashboard's address.
    assert loaded["providers"]["openai"] == {"api_key": "installer-key"}  # pragma: allowlist secret
    assert loaded["webhooks"] == {"outbound": ["https://installer.example"]}
    assert str(overlay) in config.config_source_errors()  # still reported
    assert config._UNSEALING.get() is False
    assert crypto_at_rest._FORCE_DEPLOYMENT_KEY.get() is False

    overlay.write_text(overlay.read_text(encoding="utf-8").replace(corrupt, good), encoding="utf-8")
    config.reset_config_cache()
    assert config.load_config()["providers"]["openai"] == {
        "base_url": "https://proxy.example", "api_key": "authenticated-value"}  # pragma: allowlist secret
    assert "outbound" not in config.load_config()["webhooks"]
    assert str(overlay) not in config.config_source_errors()
