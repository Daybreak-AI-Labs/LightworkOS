"""The wizard can configure plugin permissions: `[plugins].grant` and
`enforce_permissions`. Rule-6 integrity check — the keys the wizard writes are
exactly the ones `maverick.plugins` reads."""
from __future__ import annotations


def _write(cfg_dir, monkeypatch, **kw):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={"ANTHROPIC_API_KEY": "x"}, capabilities={}, **kw,
    )
    return (cfg_dir / "config.toml").read_text()


def test_plugin_grant_and_enforce_written(tmp_path, monkeypatch):
    cfg = _write(
        tmp_path, monkeypatch,
        plugins=["weather"],
        plugin_grant=["network", "fs_write"],
        plugin_enforce=True,
    )
    assert "[plugins]" in cfg
    assert 'enabled = ["weather"]' in cfg
    assert 'grant = ["network", "fs_write"]' in cfg
    assert "enforce_permissions = true" in cfg


def test_no_grant_no_enforce_omitted(tmp_path, monkeypatch):
    # Defaults (no grant, warn-only) must not emit the optional keys, matching
    # the kernel's "nothing granted, enforce off" default.
    cfg = _write(tmp_path, monkeypatch, plugins=["weather"])
    assert 'enabled = ["weather"]' in cfg
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib
    plugins = tomllib.loads(cfg)["plugins"]
    assert "grant" not in plugins
    assert "enforce_permissions" not in plugins


def test_keys_match_what_kernel_reads(tmp_path, monkeypatch):
    # The wizard's TOML feeds maverick.plugins._plugin_permission_policy, which
    # reads `grant` + `enforce_permissions` from the [plugins] section.
    cfg = _write(
        tmp_path, monkeypatch,
        plugins=["p"], plugin_grant=["subprocess"], plugin_enforce=True,
    )
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    parsed = tomllib.loads(cfg)["plugins"]
    assert parsed["grant"] == ["subprocess"]
    assert parsed["enforce_permissions"] is True


def test_workbench_uses_the_existing_plugins_table():
    from maverick_installer.wizard import _cfg_plugins
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    rendered = "\n".join(_cfg_plugins(["example"], ["network"], True, None, workbench=True))
    assert rendered.count("[plugins]") == 1
    value = tomllib.loads(rendered)["plugins"]
    assert value["enabled"] == ["example"]
    assert value["workbench"] is True
    assert value["enforce_permissions"] is True
