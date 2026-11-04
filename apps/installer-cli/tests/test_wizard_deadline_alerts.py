"""The Deadline alerts wizard step writes the keys maverick.deadline_alerts reads."""
from __future__ import annotations

from maverick_installer import wizard


def _answers(monkeypatch, *, confirm: bool, texts: dict[str, str] | None = None, select: str | None = None):
    texts = texts or {}
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **kw: select or kw.get("default", a[1][0]))

    def text(message, default=""):
        for key, value in texts.items():
            if key in message:
                return value
        return default
    monkeypatch.setattr(wizard, "_q_text", text)


def test_declining_writes_enabled_false(monkeypatch):
    _answers(monkeypatch, confirm=False)
    assert wizard.pick_deadline_alerts({}) == {"enabled": False}


def test_accepting_writes_mode_owner_quiet_hours_and_leads(monkeypatch):
    _answers(monkeypatch, confirm=True, select="digest - one message per person per check",
             texts={"assignee": "Dana", "Quiet hours": "22:00-07:00", "Days before": "10, 3, x"})
    cfg = wizard.pick_deadline_alerts({"backend": "slack"})
    assert cfg == {
        "enabled": True, "mode": "digest", "owner": "Dana", "quiet_hours": "22:00-07:00",
        "lead_days": {"dsar": [10, 3], "assessment": [30, 7], "vendor": [30, 7]},
        "lead_hours": {"incident": [24, 4], "approval": [24, 4]},
    }
    # The kernel reader accepts exactly this shape.
    from maverick import deadline_alerts
    settings = deadline_alerts.settings({"deadline_alerts": cfg})
    assert settings["lead_days"]["dsar"] == [10, 3] and settings["mode"] == "digest"


def test_config_emits_the_table_and_its_lead_time_subtables():
    lines = wizard._cfg_deadline_alerts({"enabled": True, "mode": "immediate", "owner": "Dana",
                                         "lead_days": {"dsar": [7, 2]}, "lead_hours": {"incident": [24, 4]}})
    text = "\n".join(lines)
    assert "[deadline_alerts]" in text and "enabled = true" in text and 'owner = "Dana"' in text
    assert "[deadline_alerts.lead_days]" in text and "dsar = [7, 2]" in text
    assert "[deadline_alerts.lead_hours]" in text and "incident = [24, 4]" in text
    assert wizard._cfg_deadline_alerts(None) == []
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        import tomli as tomllib
    parsed = tomllib.loads(text)
    assert parsed["deadline_alerts"]["lead_days"]["dsar"] == [7, 2]


def test_step_is_registered_after_notifications():
    keys = [k for k, _ in wizard.STEPS]
    assert keys.index("deadline_alerts") == keys.index("notifications") + 1


def test_warns_when_only_personal_alerts_are_set_up(monkeypatch, capsys):
    # Declining shared delivery still returns the personal-alert choices, and an
    # ntfy answer without a topic does too; neither sets a backend, so alerts
    # would reach nobody. The warning used to check only for an empty answer.
    _answers(monkeypatch, confirm=False)
    for notifications in ({"personal_alerts": True, "personal_background": False}, {}, None):
        wizard.pick_deadline_alerts(notifications)
        assert "reach nobody" in capsys.readouterr().out
    wizard.pick_deadline_alerts({"personal_alerts": True, "backend": "ntfy", "ntfy_topic": "t"})
    assert "reach nobody" not in capsys.readouterr().out
