"""The one-action mute link from a notification message (NOT-2).

Opening the link from an email or Telegram shows one button; a mail app's
own Unsubscribe button posts to the same address (RFC 8058). The signed link
is the credential, so neither needs a sign-in, and the result offers Undo.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    # A locked-down dashboard: every other page needs the bearer.
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "s3cret-dashboard-bearer")  # pragma: allowlist secret
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("[features]\npersonal_preferences = true\n", encoding="utf-8")
    config.reset_config_cache()
    from maverick_dashboard.app import app
    yield TestClient(app, base_url="http://127.0.0.1")
    config.reset_config_cache()


def _muted(principal):
    from maverick import experience_preferences
    from maverick.personal_notifications import validate_preferences

    return validate_preferences(experience_preferences.state(principal)["values"].get(
        "notification_preferences", {}))["muted_tasks"]


def test_the_link_opens_a_one_button_page_without_signing_in(client):
    from maverick.notification_unsubscribe import sign

    assert client.get("/notifications").status_code in (401, 403)  # still locked
    token = sign("user:ana@corp.com", "task", "12")
    page = client.get(f"/unsubscribe/{token}")
    assert page.status_code == 200
    assert "Mute alerts about this task?" in page.text
    assert f'action="/unsubscribe/{token}"' in page.text and ">Mute this task</button>" in page.text
    assert page.headers["Cache-Control"] == "private, no-store"
    assert "12" not in _muted("user:ana@corp.com")  # opening the link changes nothing


def test_one_post_mutes_and_the_page_offers_undo(client):
    from maverick.notification_unsubscribe import sign

    token = sign("user:ana@corp.com", "task", "12")
    # Exactly what a mail app sends for List-Unsubscribe-Post (no cookies, cross-site).
    done = client.post(f"/unsubscribe/{token}", data={"List-Unsubscribe": "One-Click"},
                       headers={"Origin": "https://mail.example.com"})
    assert done.status_code == 200
    assert "Alerts about this task are muted for 7 days." in done.text
    assert "12" in _muted("user:ana@corp.com")
    undo = done.text.split('<form method="post" action="', 1)[1].split('"', 1)[0]
    back = client.post(undo)
    assert back.status_code == 200 and "Alerts about this task are back on" in back.text
    assert "12" not in _muted("user:ana@corp.com")


def test_an_altered_link_is_refused_with_a_way_forward(client):
    page = client.post("/unsubscribe/not-a-real-link")
    assert page.status_code == 404
    assert "This link can't change your notifications" in page.text
    assert "Use the link in the latest message." in page.text
