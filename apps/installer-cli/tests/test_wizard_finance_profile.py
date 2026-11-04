"""The installer asks for the Finance Operating Profile and writes the keys the
kernel reads, with the same values the dashboard offers."""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib


def _answers(monkeypatch, selects: dict[str, str], text: dict[str, str]):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: kw.get("default", []))

    def _select(message, choices, default=None):
        for needle, answer in selects.items():
            if needle in message:
                assert answer in choices
                return answer
        return default

    def _text(message, default=""):
        for needle, answer in text.items():
            if needle in message:
                return answer
        return default

    monkeypatch.setattr(wizard, "_q_select", _select)
    monkeypatch.setattr(wizard, "_q_text", _text)


def _written(tmp_path: Path, monkeypatch, finance: dict) -> dict:
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    wizard.write_config(
        providers=["anthropic"], role_models={}, channels={},
        safety={"profile": "balanced", "block_threshold": "high", "scan_input": True,
                "scan_tool_calls": True, "scan_output": True},
        budget={"max_dollars": 5.0, "max_wall_seconds": 3600.0, "max_tool_calls": 500},
        sandbox={"backend": "local", "workdir": str(tmp_path / "ws"), "timeout": 60},
        keys={}, capabilities={"computer_use": False, "browser": False},
        finance=finance,
    )
    return tomllib.loads((tmp_path / "config.toml").read_text())


def test_defaults_are_the_safe_profile(monkeypatch, tmp_path):
    from maverick_installer.wizard import pick_finance

    _answers(monkeypatch, {}, {})
    finance = pick_finance()
    assert finance["finance_framework"] == "us_gaap"
    assert finance["finance_automation_default"] == "draft"
    assert finance["finance_sod_mode"] == "enforce"
    assert finance["finance_approvals_timeout"] == "fail_closed"
    parsed = _written(tmp_path, monkeypatch, finance)
    assert parsed["finance"]["framework"] == "us_gaap"
    assert "materiality" not in parsed["finance"]  # 0 = not set
    assert parsed["finance"]["automation"] == {"default": "draft"}
    assert parsed["finance"]["sod"] == {"mode": "enforce"}
    assert parsed["finance"]["approvals"] == {"timeout": "fail_closed"}


def test_answers_are_written_and_read_back_by_the_kernel(monkeypatch, tmp_path):
    from maverick.finance.profile import parse_profile
    from maverick_installer.wizard import pick_finance

    _answers(monkeypatch,
             {"Accounting framework": "ifrs", "How far agents go": "auto_threshold",
              "Separation-of-duties": "warn"},
             {"Materiality": "75000"})
    parsed = _written(tmp_path, monkeypatch, pick_finance())
    assert parsed["finance_operations"]["enable"] is True
    profile = parse_profile(parsed)
    assert (profile.framework, profile.materiality, profile.automation_default,
            profile.sod_mode, profile.approvals_timeout) == (
        "ifrs", 75000.0, "auto_threshold", "warn", "fail_closed")


def test_profile_is_not_asked_without_finance_operations(monkeypatch):
    from maverick_installer import wizard

    _answers(monkeypatch, {}, {})
    confirms = iter([True, False, False])  # suite on, fresh approval off, operations off
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: next(confirms))
    finance = wizard.pick_finance()
    assert finance["operations_enable"] is False
    assert not any(key.startswith("finance_") for key in finance)


def test_wizard_values_match_the_kernel():
    from maverick.finance import profile
    from maverick.governance import AUTOMATION_LEVELS
    from maverick_installer import wizard

    assert wizard.FINANCE_FRAMEWORKS == profile.FRAMEWORK_KEYS
    assert wizard.FINANCE_AUTOMATION_LEVELS == AUTOMATION_LEVELS
    assert wizard.FINANCE_SOD_MODES == profile.SOD_MODES
