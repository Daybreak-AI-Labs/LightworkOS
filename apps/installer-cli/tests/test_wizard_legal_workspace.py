"""Legal workspace is reachable through installation and in-product settings."""
from __future__ import annotations

import pytest

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


@pytest.mark.parametrize("enabled", [False, True])
def test_legal_workspace_install_choice(tmp_path, monkeypatch, enabled):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
                        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
                        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
                        advanced={"legal_workspace": enabled}, security_suite=None, assessments=None)
    cfg = tomllib.loads((tmp_path / "config.toml").read_text())
    assert cfg.get("legal_workspace", {}).get("enable", False) is enabled


def test_legal_workspace_settings_catalog_and_lint_agree():
    from maverick_dashboard.settings_catalog import BY_ID
    setting = BY_ID["legal_workspace.enable"]
    assert setting.control == "toggle"
    assert setting.default is False
