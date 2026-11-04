"""The consumer wizard ends with a department-picked first outcome on sample
data, not a haiku on a hard-coded model."""
from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "_consumer_mode_helpers", Path(__file__).with_name("test_wizard_consumer_mode.py"))
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
_stub_wizard_io = _helpers._stub_wizard_io


def _answer_team(label: str):
    """Answer the team question with ``label`` and every other menu with "$5"."""
    return lambda message, *a, **kw: label if "team" in message else "$5"


def _flat(out: str) -> str:
    """Rich wraps long panel lines; compare on collapsed text."""
    return " ".join(out.replace("│", " ").split())


def test_pick_first_outcome_offers_the_eight_departments(monkeypatch):
    from maverick_installer import wizard

    captured = {}

    def fake_select(message, choices, default=None):
        captured["choices"] = choices
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_select", fake_select)
    assert wizard.pick_first_outcome() == "finance"
    assert captured["choices"] == ["Finance", "Privacy & compliance", "Security", "Legal", "HR",
                                   "Procurement", "Customer support", "Tax"]
    assert captured["default"] == "Finance"


def test_pick_first_outcome_maps_labels_and_falls_back(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: "Customer support")
    assert wizard.pick_first_outcome() == "customer_support"
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: "$5")  # a stubbed, unrelated answer
    assert wizard.pick_first_outcome() == "finance"


def test_run_consumer_records_department_and_creates_sample_workspace(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "_q_select", _answer_team("Security"))
    assert wizard.run_consumer() == 0
    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())
    assert config["first_outcome"] == {"department": "security", "sample_workspace_created": True}
    workspace = tmp_path / "workspace" / "sample-outcomes" / "security"
    assert (workspace / "mailbox_export.csv").is_file()
    assert (workspace / "known_senders.md").is_file()
    assert "never counts as real evidence" in (workspace / "SAMPLE_DATA.md").read_text(encoding="utf-8")
    # The knob reads back through the kernel's getter.
    from maverick import config as kernel_config

    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / ".maverick" / "config.toml"))
    kernel_config.reset_config_cache()
    try:
        assert kernel_config.get_first_outcome()["department"] == "security"
    finally:
        kernel_config.reset_config_cache()


def test_run_consumer_prints_the_pack_command_without_a_hard_coded_model(monkeypatch, tmp_path: Path, capsys):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    monkeypatch.setattr(wizard, "_q_select", _answer_team("Legal"))
    wizard.run_consumer()
    out = _flat(capsys.readouterr().out)
    assert "maverick start --sample legal" in out
    assert "Results" in out and "sample data" in out
    assert "--model" not in out and "haiku" not in out.lower()
    assert not hasattr(wizard, "CONSUMER_DEMO_MODEL") and not hasattr(wizard, "CONSUMER_DEMO_GOAL")


def test_sample_workspace_failure_is_recorded_not_hidden(monkeypatch, tmp_path: Path):
    wizard = _stub_wizard_io(monkeypatch, tmp_path)
    from maverick import sample_outcomes

    def _boom(*a, **kw):
        raise OSError("read-only folder")

    monkeypatch.setattr(sample_outcomes, "create_sample_workspace", _boom)
    assert wizard.run_consumer() == 0
    config = tomllib.loads((tmp_path / ".maverick" / "config.toml").read_text())
    assert config["first_outcome"]["sample_workspace_created"] is False
