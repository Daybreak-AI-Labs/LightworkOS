"""One-action mute and unsubscribe from inside a notification (NOT-2).

Email, Slack and Telegram messages carry a signed link (in Slack a button)
that mutes the task, the agent or the daily summary for the person it was
sent to, in one action, with undo. The link cannot be altered, reused for
another person or used after it expires.
"""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest
from maverick import notification_unsubscribe as unsub


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("[features]\npersonal_preferences = true\n", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _mutes(principal):
    from maverick import experience_preferences
    from maverick.personal_notifications import validate_preferences

    return validate_preferences(experience_preferences.state(principal)["values"].get("notification_preferences", {}))


def test_a_link_mutes_the_task_for_that_person_and_its_undo_unmutes(home):
    token = unsub.sign("user:ana@corp.com", "task", "42")
    link = unsub.verify(token)
    assert link == {"principal": "user:ana@corp.com", "scope": "task", "key": "42", "tenant": None, "undo": False}
    unsub.apply(link["principal"], "task", "42")
    assert "42" in _mutes("user:ana@corp.com")["muted_tasks"]
    back = unsub.verify(unsub.sign("user:ana@corp.com", "task", "42", undo=True))
    unsub.apply(back["principal"], "task", "42", undo=True)
    assert "42" not in _mutes("user:ana@corp.com")["muted_tasks"]


def test_agent_mute_and_summary_stop(home):
    from maverick import user_preferences

    unsub.apply("user:ana@corp.com", "agent", "finance_close")
    assert "finance_close" in _mutes("user:ana@corp.com")["muted_agents"]
    unsub.apply("user:ana@corp.com", "summary")
    assert user_preferences.get_preferences("user:ana@corp.com")["digest_enabled"] is False
    unsub.apply("user:ana@corp.com", "summary", undo=True)
    assert user_preferences.get_preferences("user:ana@corp.com")["digest_enabled"] is True


def test_altered_or_expired_links_are_refused(home):
    token = unsub.sign("user:ana@corp.com", "task", "42", now=1000.0)
    body, mac = token.split(".")
    with pytest.raises(unsub.LinkRefused, match="not complete"):
        unsub.verify(body[:-2] + "AA" + "." + mac)
    with pytest.raises(unsub.LinkRefused, match="not complete"):
        unsub.verify("nonsense")
    with pytest.raises(unsub.LinkRefused, match="expired"):
        unsub.verify(token, now=1000.0 + unsub.LINK_SECONDS + 1)


def test_only_named_accounts_and_known_scopes_get_links(home):
    with pytest.raises(ValueError):
        unsub.sign("agent:helper", "task", "1")
    with pytest.raises(ValueError):
        unsub.sign("user:ana@corp.com", "everything", "1")
    assert unsub.for_item({"goal_id": 7, "agent": "finance"}) == ("task", "7")
    assert unsub.for_item({"goal_id": None, "agent": "finance"}) == ("agent", "finance")
    assert unsub.for_item({"goal_id": None}) is None


def test_slack_button_mutes_only_for_the_person_it_was_sent_to(home):
    from maverick.slack_interactive import ACTION_MUTE, handle_block_action

    token = unsub.sign("user:ana@corp.com", "task", "9")
    payload = {"type": "block_actions", "user": {"id": "U0AAAAAAA"},
               "actions": [{"action_id": ACTION_MUTE, "value": token}]}
    other = handle_block_action(payload, world=None, principal_for=lambda _u: "user:ben@corp.com")
    assert "someone else" in other["text"]
    assert "9" not in _mutes("user:ana@corp.com")["muted_tasks"]
    reply = handle_block_action(payload, world=None, principal_for=lambda _u: "user:ana@corp.com")
    assert reply["text"] == "Muted alerts about this task for 7 days."
    assert "9" in _mutes("user:ana@corp.com")["muted_tasks"]
    undo = reply["blocks"][1]["elements"][0]
    assert undo["text"]["text"] == "Undo" and undo["action_id"] == ACTION_MUTE
    again = handle_block_action({**payload, "actions": [{"action_id": ACTION_MUTE, "value": undo["value"]}]},
                                world=None, principal_for=lambda _u: "user:ana@corp.com")
    assert again["text"] == "Unmuted alerts about this task."
    assert "9" not in _mutes("user:ana@corp.com")["muted_tasks"]


def test_summary_email_and_slack_carry_one_action_mute_and_stop(home, monkeypatch):
    from maverick import daily_digest
    from maverick.slack_interactive import ACTION_MUTE, digest_blocks

    digest = {"principal": "user:ana@corp.com", "date_label": "Tuesday 06 October 2026", "time_zone": "UTC",
              "approvals": [], "questions": [], "expiring_keys": [], "empty": False,
              "results": [{"id": 5, "title": "Vendor spend", "status_label": "Done", "href": "/chat/goal/5"}],
              "spending": {"dollars": 0, "limit_dollars": 0}, "counts": {}}
    text = daily_digest.render_text(digest, dashboard_url="https://lw.example.test")
    assert "Mute alerts about this task: https://lw.example.test/unsubscribe/" in text
    assert "Stop this summary in one click: https://lw.example.test/unsubscribe/" in text
    html = daily_digest.render_html(digest, dashboard_url="https://lw.example.test")
    assert ">Mute alerts about this task</a>" in html and ">Stop this summary in one click</a>" in html
    buttons = [b for block in digest_blocks(digest) if block["type"] == "actions" for b in block["elements"]]
    assert [b["text"]["text"] for b in buttons] == ["Mute: Vendor spend", "Stop this summary"]
    assert all(b["action_id"] == ACTION_MUTE for b in buttons)
    sent = {}
    monkeypatch.setattr(daily_digest, "dashboard_url", lambda: "https://lw.example.test")
    monkeypatch.setitem(sys.modules, "maverick.notifications", SimpleNamespace(
        send_email=lambda to, subject, text, html_body=None, headers=None: sent.update(headers=headers) or True))
    assert daily_digest._send_email("user:ana@corp.com", digest, [], {"email": "ana@corp.com"})
    assert sent["headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert sent["headers"]["List-Unsubscribe"].startswith("<https://lw.example.test/unsubscribe/")


def test_a_muted_task_is_left_out_of_the_summary(home):
    from maverick import daily_digest

    unsub.apply("user:ana@corp.com", "task", "5")
    assert daily_digest._muted_in_app("user:ana@corp.com") == frozenset({5})


def test_a_private_slack_alert_carries_a_mute_button_and_telegram_a_link(home, monkeypatch, tmp_path):
    from maverick import personal_notification_delivery as delivery
    from maverick.personal_notifications import validate_preferences

    monkeypatch.setattr(delivery, "seal", lambda value: value)
    monkeypatch.setattr(delivery, "unseal", lambda value: value)
    monkeypatch.setattr(delivery, "data_dir", lambda *parts: tmp_path.joinpath("d", *parts))
    monkeypatch.setattr(delivery, "_settings", lambda: {"personal_dashboard_url": "https://lw.example.test"})
    slack = {"id": "a" * 32, "verified_at": 1, "channel": "slack", "sender_id": "U0AAAAAAA"}
    sent = []
    monkeypatch.setitem(sys.modules, "maverick.personal_identity", SimpleNamespace(
        linked_channels=lambda _: [slack], principal_current=lambda _: True))
    monkeypatch.setattr(delivery, "send_private", lambda target, text, buttons=None: sent.append((text, buttons)))
    item = {"id": "b" * 64, "category": "completed", "label": "Finished", "href": "/chat/goal/3",
            "goal_id": 3, "seen_at": None}
    delivery.dispatch("user:ana@corp.com", {"items": [item]},
                      validate_preferences({"external_links": [slack["id"]]}))
    text, buttons = sent[0]
    assert "Mute alerts about this task: https://lw.example.test/unsubscribe/" in text
    assert buttons[0]["text"]["text"] == "Mute alerts about this task"
    token = buttons[0]["value"]
    assert unsub.verify(token)["principal"] == "user:ana@corp.com"
