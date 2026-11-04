"""Installer coverage for the billing-grade pricing default."""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from maverick_installer import wizard


def test_pick_budget_defaults_to_strict_pricing(monkeypatch):
    prompts: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        wizard,
        "_q_text",
        lambda _message, *, default="": default,
    )

    def confirm(message: str, default: bool = True) -> bool:
        prompts.append((message, default))
        return default

    monkeypatch.setattr(wizard, "_q_confirm", confirm)

    budget = wizard.pick_budget()

    assert budget["strict_pricing"] is True
    assert budget["max_dollars"] == 2.0
    assert budget["max_wall_seconds"] == 1800.0
    assert budget["max_tool_calls"] == 500
    assert prompts == [
        ("  Use task limits? Standard goals stop at $2 and 30 minutes; choose No for no task limit.", True),
        (
            "  Require a reviewed price before paid AI work? Recommended. "
            "You can add your contract's spending ceiling in Settings after installation. "
            "Choose No only if you accept that dollar limits may be under-counted",
            True,
        ),
        ("  Show known budget headroom before work? This never changes execution limits.", True),
        ("  Show in-product warnings as tasks approach their limits?", True),
    ]
    assert budget["guidance"] is True and budget["warnings"] is True
    assert budget["warning_thresholds"] == [0.8, 0.95, 1.0]


def test_pick_budget_preserves_explicit_legacy_estimate_opt_out(monkeypatch):
    monkeypatch.setattr(
        wizard,
        "_q_text",
        lambda _message, *, default="": default,
    )
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **_kwargs: False)

    budget = wizard.pick_budget()

    assert budget["strict_pricing"] is False
    assert budget["task_limits_enabled"] is False


def test_generated_config_persists_strict_default(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")

    wizard.write_config(
        providers=[],
        role_models={},
        channels={},
        safety={"profile": "balanced"},
        budget={
            "max_dollars": 5.0,
            "max_wall_seconds": 3600.0,
            "max_tool_calls": 500,
            "strict_pricing": True,
        },
        sandbox={"backend": "local", "workdir": "~/maverick-workspace"},
        keys={},
        capabilities={},
    )

    generated = tomllib.loads((tmp_path / "config.toml").read_text())
    assert generated["budget"]["strict_pricing"] is True


def test_budget_warning_thresholds_are_written_as_numbers_the_kernel_accepts(monkeypatch):
    from maverick import budget_guidance, config

    monkeypatch.setattr(wizard, "_q_text", lambda _message, *, default="": default)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **_kwargs: True)
    budget = wizard.pick_budget()

    written = tomllib.loads("\n".join(wizard._cfg_core(budget, {}, {})))

    assert written["budget"]["warning_thresholds"] == [0.8, 0.95, 1.0]
    monkeypatch.setattr(config, "config_source_errors", lambda **_kwargs: [])
    monkeypatch.setattr(config, "load_config", lambda *_args, **_kwargs: written)
    assert budget_guidance.policy()["warning_thresholds"] == [0.8, 0.95, 1.0]


def test_budget_contract_defaults_are_shared_with_the_settings_page():
    from maverick.config_contracts import BOOLEAN_SETTINGS, NUMBER_LIST_SETTINGS
    from maverick_dashboard.settings_catalog import BY_ID

    for path in ("budget.strict_pricing", "budget.guidance", "budget.warnings"):
        row, contract = BY_ID[path], BOOLEAN_SETTINGS[path]
        assert row.default == contract.default
        assert row.env == contract.dashboard_env
    contract = NUMBER_LIST_SETTINGS["budget.warning_thresholds"]
    row = BY_ID[contract.setting]
    assert row.default == list(contract.default)
    assert row.max_items == contract.max_items
    assert row.max_length == contract.dashboard_max_length


def test_list_values_keep_their_type_in_the_config_file():
    lines: list[str] = []
    wizard._emit_kv(lines, "mixed", [0.5, 2, True, "text", "12345"])

    assert tomllib.loads("\n".join(lines))["mixed"] == [0.5, 2, True, "text", "12345"]
