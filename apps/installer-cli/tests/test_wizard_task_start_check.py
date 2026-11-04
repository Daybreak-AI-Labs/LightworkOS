"""The installer's safety step: asking a person before risky-looking tasks
start is off unless chosen."""
from __future__ import annotations

from maverick_installer import wizard


def _answers(monkeypatch, wait: str):
    def select(prompt, choices, default=None):
        if prompt.startswith("Safety profile"):
            return default
        assert prompt.startswith("Ask a person before starting tasks")
        return next(c for c in choices if c.startswith(wait))

    monkeypatch.setattr(wizard, "_q_select", select)
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, default=False: default)


def test_default_leaves_tasks_starting_straight_away(monkeypatch):
    _answers(monkeypatch, "never")
    assert "goal_risk_require_human" not in wizard.pick_safety()


def test_choosing_high_writes_the_setting(monkeypatch):
    _answers(monkeypatch, "high")
    assert wizard.pick_safety()["goal_risk_require_human"] == "high"
