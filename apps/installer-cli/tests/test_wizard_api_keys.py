"""The wizard's API-access step writes exactly the [dashboard] keys that
``maverick.config.api_key_settings`` reads (rule 6: a wizard answer must reach
the feature)."""
from __future__ import annotations

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick_installer import wizard


def _write(cfg_dir, monkeypatch, advanced):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    wizard.write_config(
        providers=["anthropic"], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={"ANTHROPIC_API_KEY": "x"},
        capabilities={}, advanced=advanced,
    )
    return tomllib.loads((cfg_dir / "config.toml").read_text())


def test_step_is_listed():
    assert ("api_keys", "API access") in wizard.STEPS


def test_defaults_write_nothing(tmp_path, monkeypatch):
    cfg = _write(tmp_path, monkeypatch, {"api_keys": {"api_keys": True}})
    assert "api_keys" not in (cfg.get("dashboard") or {})


def test_declining_and_custom_limits_reach_the_kernel(tmp_path, monkeypatch):
    from maverick.config import api_key_settings

    cfg = _write(tmp_path, monkeypatch, {"api_keys": {"api_keys": False}})
    assert cfg["dashboard"]["api_keys"] is False
    assert api_key_settings(cfg)["enabled"] is False

    cfg = _write(tmp_path, monkeypatch, {"api_keys": {
        "api_keys": True, "api_key_default_days": 30, "api_key_max_days": 180,
        "api_key_rotation_grace_hours": 2,
    }})
    got = api_key_settings(cfg)
    assert (got["enabled"], got["default_days"], got["max_days"], got["rotation_grace_hours"]) == (
        True, 30, 180, 2)


def test_pick_api_keys_prompts(monkeypatch):
    answers = iter([True])
    texts = iter(["45", "200", "6"])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: next(answers))
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: next(texts))
    assert wizard.pick_api_keys() == {
        "api_keys": True, "api_key_default_days": 45, "api_key_max_days": 200,
        "api_key_rotation_grace_hours": 6,
    }
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: False)
    assert wizard.pick_api_keys() == {"api_keys": False}
