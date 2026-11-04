"""The wizard step for the Agent Control Plane (kernel rule 6)."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover -- Python 3.10
    import tomli as tomllib


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
    )
    return (cfg_dir / "config.toml").read_text()


def test_the_toggle_writes_the_control_plane_table(tmp_path, monkeypatch):
    text = _write(tmp_path, monkeypatch, {"control_plane": True})
    cfg = tomllib.loads(text)
    assert cfg["control_plane"] == {"enable": True}
    assert text.count("[control_plane]") == 1


def test_off_means_no_table(tmp_path, monkeypatch):
    assert "[control_plane]" not in _write(tmp_path, monkeypatch, {})
    assert "[control_plane]" not in _write(tmp_path, monkeypatch, {"control_plane": False})


def test_the_wizard_asks_the_question():
    """The wizard is the UX source of truth: the advanced step must ask for the toggle."""
    import inspect

    from maverick_installer import wizard
    source = inspect.getsource(inspect.getmodule(wizard.pick_advanced))
    assert '"control_plane": _q_confirm(' in source
    assert "Agent Control Plane" in source
    assert "over every agent" not in source
    assert "halt the fleet" not in source
    assert "attempt a " in source
    assert "control-plane audit row" in source
    assert "Ordinary audit outages are marked in the " in source
    assert "CLI HALT covers this local deployment" in source
    assert "configured shared authority" in source
    assert "reports whether that row was written" not in source
    assert "recorded in the audit trail" not in source
