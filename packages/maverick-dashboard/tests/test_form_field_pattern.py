"""One form-field pattern with an error summary.

templates/_form_field.html renders a label, hint, error slot and control with
the error tied to the field; mvFieldErrors in lightwork-ui.js validates on
submit and fills the summary (tests/js/form_error_summary.test.js and
tests/js/form_field_migrations.test.js run it). These tests check the macro
and that the most-used forms opted in.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TEMPLATES = Path(__file__).parents[1] / "maverick_dashboard" / "templates"
_ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_DASHBOARD_INVITES",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.runtime_overrides as overrides
    monkeypatch.setattr(overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    import maverick_dashboard.rbac as rbac
    roles = tmp_path / "home" / ".maverick"
    monkeypatch.setattr(rbac, "store_path", lambda: roles / "dashboard-users.json")
    monkeypatch.setattr(rbac, "tenant_store_path", lambda: roles / "dashboard-tenant-roles.json")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers=_ORIGIN)


class Tags(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def find(self, tag=None, **wanted):
        return [attrs for name, attrs in self.tags if (tag is None or name == tag)
                and all(attrs.get(key.replace("_", "-")) == value for key, value in wanted.items())]


def _templates():
    from maverick_dashboard.app import templates
    return templates


IMPORT = '{% from "_form_field.html" import form_field, error_summary %}'


def test_a_field_has_a_label_a_linked_hint_and_a_hidden_error_slot():
    html = _templates().env.from_string(IMPORT + "{{ form_field('invite-email', 'Email address', name='email', "
                                        "type='email', required=true, hint='We send the invitation here.', "
                                        "error_required='Enter the email address.') }}").render()
    tags = Tags(html)
    (label,) = tags.find("label")
    assert label["for"] == "invite-email"
    (control,) = tags.find("input")
    assert control["id"] == "invite-email" and control["name"] == "email" and control["type"] == "email"
    assert "required" in control and "aria-invalid" not in control
    assert control["aria-describedby"] == "invite-email-hint"
    assert control["data-error-required"] == "Enter the email address."
    (hint,) = tags.find(id="invite-email-hint")
    (error,) = tags.find(id="invite-email-error")
    assert "hidden" in error
    assert "We send the invitation here." in html


def test_a_server_error_is_shown_next_to_the_field_and_in_a_summary():
    html = _templates().env.from_string(
        IMPORT + "{{ error_summary('invite-errors', [('invite-email', 'That address already has an invitation.')]) }}"
        "{{ form_field('invite-email', 'Email address', name='email', value='a@b.example', "
        "error='That address already has an invitation.') }}").render()
    tags = Tags(html)
    (summary,) = tags.find(id="invite-errors")
    assert "hidden" not in summary and summary["tabindex"] == "-1" and "data-mv-error-summary" in summary
    assert summary["aria-labelledby"] == "invite-errors-title"
    assert tags.find("a", href="#invite-email")
    (control,) = tags.find("input")
    assert control["aria-invalid"] == "true"
    assert control["aria-describedby"] == "invite-email-error"
    assert control["value"] == "a@b.example", "what was typed stays"
    assert re.search(r'id="invite-email-error"[^>]*>\s*<span class="sr-only">Error: </span>That address', html)


def test_a_select_field_lists_its_choices_and_keeps_the_chosen_one():
    html = _templates().env.from_string(
        IMPORT + "{{ form_field('role', 'Role', type='select', required=true, value='viewer', "
        "options=[('', 'Choose a role'), ('viewer', 'Viewer'), ('admin', 'Administrator')]) }}").render()
    assert '<option value="" disabled>Choose a role</option>' in html
    assert '<option value="viewer" selected>Viewer</option>' in html
    assert 'id="role" name="role" required' in html


def _form(tags, form_id):
    (form,) = tags.find("form", id=form_id)
    return form


def test_users_invite_and_role_forms_use_the_pattern(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    token = "form-field-pattern-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    page = _client().get("/users", headers={"Authorization": f"Bearer {token}"})
    assert page.status_code == 200
    tags = Tags(page.text)
    invite = _form(tags, "invite-form")
    assert "data-mv-validate" in invite and invite["data-mv-keep"] == "users-invite"
    assert tags.find(id="invite-errors")
    # Stream I's wiring for the email field is kept and built on.
    assert tags.find(id="invite-email-error")
    custom = _form(tags, "custom-role-form")
    assert "data-mv-validate" in custom and custom["data-mv-keep"] == "users-role_saved"
    source = (TEMPLATES / "users.html").read_text(encoding="utf-8")
    assert "form_field('give-role-person'" in source
    # The role picker keeps the role descriptions, so it is written out with the
    # same parts: an mv-field, a label for the control and the page's own wording.
    assert 'id="give-role-role"' in source and 'for="give-role-role"' in source
    assert 'data-error-required="Choose the role to give them."' in source
    assert 'data-mv-keep="users-set"' in source


def test_a_new_invite_link_clears_the_kept_invite_form(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    token = "form-field-pattern-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    page = _client().post("/users/invite", data={"email": "new@corp.example", "role": "viewer"},
                          headers={"Authorization": f"Bearer {token}"})
    assert page.status_code == 200
    (result,) = Tags(page.text).find(id="invite-result")
    assert result["data-mv-keep-done"] == "users-invite"


def test_settings_spending_per_task_uses_the_pattern():
    page = _client().get("/settings")
    tags = Tags(page.text)
    form = _form(tags, "settings-budget-form")
    assert "data-mv-validate" in form and form["data-mv-keep"] == "settings-budget"
    assert tags.find(id="settings-budget-errors")
    saved = Tags(_client().get("/settings?saved=budget").text).find(**{"data_mv_keep_done": "settings-budget"})
    assert saved


def test_spending_limit_forms_use_the_pattern_and_name_their_fields():
    page = _client().get("/spending-limits")
    assert page.status_code == 200
    tags = Tags(page.text)
    for form_id in ("limit-workspace", "limit-default"):
        form = _form(tags, form_id)
        assert "data-mv-validate" in form and form["data-mv-keep"] == form_id.replace("limit-", "limits-")
        assert tags.find(id=f"{form_id}-errors")
        (amount,) = tags.find("input", id=f"{form_id}-amount")
        assert "at least $0.01" in amount["data-error-range"]
    assert "Yes, change it" not in page.text
    done = Tags(_client().get("/spending-limits?saved=workspace_cleared").text).find(data_mv_keep_done="limits-workspace")
    assert done


def test_automation_privacy_and_knowledge_forms_opt_in():
    automations = (TEMPLATES / "automations.html").read_text(encoding="utf-8")
    assert '<form id="auto-new-form" novalidate data-mv-validate data-mv-keep="automation-schedule">' in automations
    privacy = (TEMPLATES / "privacy.html").read_text(encoding="utf-8")
    assert 'id="pw-dsar-form" data-endpoint="/api/v1/privacy/dsar" data-mv-validate data-mv-keep="privacy-dsar"' in privacy
    assert "error_summary('pw-dsar-errors')" in privacy
    assert 'data-mv-keep="privacy-dsar-message"' in privacy
    assert "fields.forget(form)" in privacy and "fields.fail(form, e, 'save this')" in privacy
    knowledge = (TEMPLATES / "knowledge_access.html").read_text(encoding="utf-8")
    assert re.search(r'<form id="ka-request-form"[^>]*data-mv-validate>', knowledge)
    assert "error_summary('ka-request-errors')" in knowledge
    assert 'data-error-required="Tick the box to confirm you checked this source."' in knowledge


def test_the_most_used_forms_keep_what_was_typed():
    keeps = {}
    for path in TEMPLATES.glob("*.html"):
        for key in re.findall(r'data-mv-keep="([a-z_-]+)"', path.read_text(encoding="utf-8")):
            keeps.setdefault(key, path.name)
    assert set(keeps) >= {"users-invite", "users-set", "users-role_saved", "settings-budget", "limits-workspace",
                          "limits-default", "limits-person", "automation-schedule", "privacy-dsar",
                          "privacy-dsar-message"}
