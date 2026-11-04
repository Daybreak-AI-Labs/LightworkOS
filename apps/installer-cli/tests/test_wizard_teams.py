"""The installer offers Microsoft Teams next to Slack and writes its config."""
from __future__ import annotations


def test_teams_is_offered_and_needs_its_secrets():
    from maverick_installer.wizard import _ALLOWLIST_CHANNELS, _ALLOWLIST_HINT, CHANNELS

    ids = [c[0] for c in CHANNELS]
    assert ids.index("teams") == ids.index("slack") + 1
    envs = dict((c[0], c[2]) for c in CHANNELS)["teams"]
    assert envs == ["TEAMS_APP_ID", "TEAMS_APP_PASSWORD"]
    assert "teams" in _ALLOWLIST_CHANNELS and "Entra" in _ALLOWLIST_HINT["teams"]


def test_teams_step_writes_the_channel_table(monkeypatch):
    from maverick_installer import wizard

    answers = iter(["  AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee ", "8791"])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    envs: set[str] = set()
    cfg = wizard._channel_base_cfg("teams", envs)
    assert cfg == {
        "enabled": True,
        "app_id": "${TEAMS_APP_ID}",
        "app_password": "${TEAMS_APP_PASSWORD}",
        "tenant_id": "AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee",
        "port": 8791,
        "approvals_enabled": True,
    }
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: "12345678-abcd-abcd-abcd-1234567890ab")
    wizard._channel_allowlist("teams", cfg)
    assert cfg["allowed_user_ids"] == ["12345678-abcd-abcd-abcd-1234567890ab"]
