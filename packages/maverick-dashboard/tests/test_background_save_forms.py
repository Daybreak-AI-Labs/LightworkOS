"""The spending-limit, user-role, daily-summary and invite forms save in the
background (data-mv-save="background"). A background save asks for JSON: a
refused value comes back as a plain message tied to its field. A plain form
post keeps its old redirect, and the same-origin and step-up checks still
apply to both."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}
_JSON = {**_ORIGIN, "accept": "application/json"}
TEMPLATES = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers=_ORIGIN)


def _field_error(response, field):
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["schema"] == "lightwork.error.v1"
    return detail["field_errors"][field]


@pytest.mark.parametrize("name, action", [
    ("spending_limits.html", "/spending-limits/workspace"),
    ("spending_limits.html", "/spending-limits/default"),
    ("spending_limits.html", "/spending-limits/person"),
    ("users.html", "/users/set"),
    ("users.html", "/users/invite"),
    ("me.html", "/me/preferences"),
])
def test_the_four_forms_save_in_the_background_and_keep_what_was_typed(name, action):
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    forms = re.findall(r'<form method="post"[^>]*action="' + re.escape(action) + r'"[^>]*>', source)
    # The one-button "Remove personal limit" form has nothing typed to keep.
    forms = [form for form in forms if "data-limit-remove" not in form]
    assert forms, action
    for form in forms:
        assert 'data-mv-save="background"' in form, form
        assert "data-mv-save-what=" in form and "data-mv-keep=" in form, form


def test_invite_result_has_a_place_to_appear_without_a_reload():
    source = (TEMPLATES / "users.html").read_text(encoding="utf-8")
    assert 'data-mv-save-show="invite-result-slot"' in source
    slot = source.index('<div id="invite-result-slot">')
    assert slot < source.index('id="invite-result"') < source.index("</div>", source.index('data-copy-target="invite-link"'))


def test_spending_limit_refusal_is_tied_to_its_field_for_a_background_save(client):
    plain = client.post("/spending-limits/workspace", data={"choice": "limit", "amount": "-4", "period": "month"},
                        follow_redirects=False)
    assert plain.headers["location"] == "/spending-limits?error=amount"
    background = client.post("/spending-limits/workspace", headers=_JSON,
                             data={"choice": "limit", "amount": "-4", "period": "month"})
    assert _field_error(background, "amount") == "Enter the limit as an amount in dollars, more than $0."
    person = client.post("/spending-limits/person", headers=_JSON,
                         data={"principal": "", "amount": "5", "period": "month"})
    assert _field_error(person, "principal") == "Choose a person."
    saved = client.post("/spending-limits/default", headers=_JSON, follow_redirects=False,
                        data={"choice": "limit", "amount": "40", "period": "day"})
    assert saved.status_code == 303 and saved.headers["location"] == "/spending-limits?saved=default"


def test_role_and_invite_refusals_are_plain_for_a_background_save(client):
    role = client.post("/users/set", headers=_JSON, data={"principal": "user:alice", "role": "no-such-role"})
    assert _field_error(role, "role") == "Choose a person and a role from the lists."
    plain = client.post("/users/set", data={"principal": "user:alice", "role": "no-such-role"})
    assert plain.status_code == 400
    from maverick_dashboard import invites
    if invites.invites_enabled():
        invite = client.post("/users/invite", headers=_JSON, data={"email": "not-an-address", "role": "viewer"})
        assert _field_error(invite, "email").startswith("Enter a full email address.")


def test_daily_summary_refusal_is_tied_to_its_field_for_a_background_save(client):
    background = client.post("/me/preferences", headers=_JSON,
                             data={"time_zone": "Mars/Olympus", "digest_hour": "8", "email": ""})
    assert _field_error(background, "time_zone") == "Choose your time zone from the list."
    plain = client.post("/me/preferences", data={"time_zone": "Mars/Olympus", "digest_hour": "8"},
                        follow_redirects=False)
    assert plain.headers["location"] == "/me?saved=bad_preferences"
    saved = client.post("/me/preferences", headers=_JSON, follow_redirects=False,
                        data={"time_zone": "UTC", "digest_hour": "9", "email": ""})
    assert saved.status_code == 303 and saved.headers["location"] == "/me?saved=preferences"


@pytest.mark.parametrize("path, data", [
    ("/spending-limits/workspace", {"choice": "limit", "amount": "5", "period": "day"}),
    ("/users/set", {"principal": "user:alice", "role": "viewer"}),
    ("/me/preferences", {"time_zone": "UTC", "digest_hour": "8"}),
    ("/users/invite", {"email": "someone@company.test", "role": "viewer"}),
])
def test_a_background_save_from_another_site_is_still_refused(monkeypatch, tmp_path, path, data):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    evil = TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"origin": "http://evil.example", "accept": "application/json"})
    assert evil.post(path, data=data, follow_redirects=False).status_code == 403


@pytest.mark.parametrize("path, data, operation", [
    ("/users/set", {"principal": "user:alice", "role": "viewer"}, "change_role"),
    ("/spending-limits/workspace", {"choice": "none"}, "remove_spending_limit"),
])
def test_step_up_still_sends_a_background_save_to_sign_in_again(client, monkeypatch, path, data, operation):
    from maverick_dashboard import step_up
    asked = []

    def stale(request, op):
        asked.append(op)
        raise step_up.StepUpRequired("/auth/login?fresh=1&return_to=" + path.replace("/", "%2F"))
    monkeypatch.setattr(step_up, "require_recent_mfa", stale)
    refused = client.post(path, headers=_JSON, data=data, follow_redirects=False)
    assert asked == [operation]
    assert refused.status_code == 403
    assert refused.headers["X-Reauthenticate"].startswith("/auth/login?fresh=1")
    assert refused.json()["reauthenticate"] == refused.headers["X-Reauthenticate"]
