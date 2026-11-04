"""The wizard's legal-holds choice is off by default and writes exactly [ediscovery] enable."""
from __future__ import annotations

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def _write(cfg_dir, monkeypatch, advanced):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config

    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={"ANTHROPIC_API_KEY": "x"},
        capabilities={}, advanced=advanced,
        security_suite=None, assessments=None,
    )
    return tomllib.loads((cfg_dir / "config.toml").read_text())


def test_legal_holds_choice_writes_only_the_enable_switch(tmp_path, monkeypatch):
    data = _write(tmp_path, monkeypatch, {"ediscovery": True})
    assert data["ediscovery"] == {"enable": True}


def test_legal_holds_are_absent_unless_chosen(tmp_path, monkeypatch):
    data = _write(tmp_path, monkeypatch, {"ediscovery": False})
    assert "ediscovery" not in data
