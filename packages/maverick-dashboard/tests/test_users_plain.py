"""Users page: people are chosen from lists, never typed as sign-in IDs; role
names are typed as words; destructive buttons confirm first."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

BANNED = ("user:", "sign-in ID", "Sign-in ID", "SSO", "principal", "tenant", "override",
          "deployment", "Ctrl/Cmd", "HTTP ")


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_users_page_has_no_typed_ids_and_no_jargon(client):
    from maverick_dashboard import rbac, subject_directory, suite_grants
    rbac.set_role("user:google-oauth2|1234567890", "operator")
    suite_grants.set_suites("user:google-oauth2|1234567890", ["finance"])
    subject_directory.record_login("okta|newcomer-42", ["new@corp.com"])
    page = client.get("/users").text
    text = visible_text(page)
    for word in BANNED:
        assert word not in text, word
    # No free-text identity fields anywhere on the page.
    assert 'name="principal" placeholder' not in page
    assert 'id="wm-principal" class="input"' not in page
    # The person who signed in but has no role is offered in the picker.
    picker = page.split("Give someone a role", 1)[1].split("</select>", 1)[0]
    assert 'value="user:okta|newcomer-42"' in picker
    # Departments are checkboxes, not a multi-select.
    assert 'type="checkbox" name="suites"' in page and "multiple" not in page
    # Returning to the inherited role is a reviewed access change, not account
    # deletion; the current inherited revision and powers must be explicit.
    assert page.count("data-users-confirm=") >= 1
    assert 'name="expected_standard"' in page and 'data-users-ok="Use standard role"' in page
    assert 'data-autoload="true"' in page


def test_custom_role_name_is_typed_as_words(client):
    r = client.post("/users/roles/save", data={"name": "Privacy Officer", "permissions": ["audit"]},
                    follow_redirects=False)
    assert r.status_code == 303
    from maverick_dashboard import rbac
    assert "privacy-officer" in rbac.list_custom_roles()
    assert "Privacy officer" in visible_text(client.get("/users").text)
    assert client.post("/users/roles/save", data={"name": "!"}).status_code == 400


def test_role_changes_stay_admin_only(client, monkeypatch):
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:vic", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vic")
    assert client.post("/users/roles/save", data={"name": "Helper"}).status_code == 403
    assert client.get("/users").status_code == 403


def test_roles_and_permissions_pages_read_plainly(client):
    roles = client.get("/roles?role=orchestrator").text
    text = visible_text(roles)
    for word in ("system-prompt", "addendum", "inherit", "orchestrator", "claude-opus", "HTTP ", "⛔"):
        assert word not in text, word
    assert "Planner" in text and "Thinking level" in text and "Extra instructions" in text
    perms = client.get("/permissions").text
    ptext = visible_text(perms)
    for word in ("dashboard block", "base policy", "readiness unknown", "tenant", "ACL", "present"):
        assert word not in ptext, word
    assert "Change abilities in Settings" in ptext
