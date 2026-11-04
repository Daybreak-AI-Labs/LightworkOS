"""Users page: filter, select people (or everyone matching), confirm a count,
change their roles at once, and undo it from the change report."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import rbac
    dash_app._world_cache.clear()
    for who, role in (("user:ana@corp.com", "viewer"), ("user:ben@corp.com", "viewer"),
                      ("user:cy@corp.com", "operator"), ("user:dee@other.org", "viewer")):
        rbac.set_role(who, role, actor="user:setup")
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


def roles():
    from maverick_dashboard import rbac
    return rbac.list_users()


def test_filter_narrows_the_list_and_offers_everyone_matching(client):
    page = client.get("/users", params={"q": "corp.com", "has_role": "viewer"}).text
    words = text(page)
    assert "Showing 2 of 4 people matching the filter." in words
    assert "All 2 people matching the filter" in words
    assert page.count("data-bulk-pick />") == 2
    assert 'value="user:dee@other.org" form="users-bulk"' not in page
    # Every control is a native, labelled form control, so it all works by keyboard.
    assert re.search(r'<label class="sr-only" for="pick-1">Select ', page)
    assert '<label for="bulk-role">New role</label>' in page and 'id="bulk-role" required' in page
    assert 'role="search"' in page


def test_bulk_change_confirms_the_count_then_reports_and_undoes(client):
    # Step 1: everyone matching the filter, reviewed before anything changes.
    page = client.post("/users/bulk", data={"scope": "matching", "q": "corp.com", "role_filter": "viewer",
                                            "role": "operator"}).text
    words = text(page)
    assert "Change the role of 2 people to Operator?" in words
    assert "Change the role for 2 people" in words
    assert roles()["user:ana@corp.com"] == "viewer"  # nothing changed yet
    # Step 2: confirm with the count that was shown.
    page = client.post("/users/bulk", data={
        "principals": ["user:ana@corp.com", "user:ben@corp.com"], "scope": "selected",
        "role": "operator", "confirmed": "yes", "expected_count": "2"}).text
    words = text(page)
    assert "Changed: 2 people" in words
    assert roles()["user:ana@corp.com"] == roles()["user:ben@corp.com"] == "operator"
    assert roles()["user:dee@other.org"] == "viewer"
    tokens = re.findall(r'name="restore" value="([^"]+)"', page)
    assert len(tokens) == 2 and "Undo these 2 changes" in words
    # Step 3: undo puts both back.
    page = client.post("/users/bulk/undo", data={"restore": [_html.unescape(t) for t in tokens]}).text
    assert "Undone: 2 people" in text(page)
    assert roles()["user:ana@corp.com"] == roles()["user:ben@corp.com"] == "viewer"


def test_selected_people_only_and_already_holding_the_role(client):
    page = client.post("/users/bulk", data={
        "principals": ["user:cy@corp.com", "user:dee@other.org"], "scope": "selected",
        "role": "operator", "confirmed": "yes", "expected_count": "2"}).text
    assert "Changed: 1 person, 1 already had that role" in text(page)
    assert "Undo this change" in text(page)
    assert roles()["user:dee@other.org"] == "operator"


def test_a_count_that_no_longer_matches_asks_again(client):
    page = client.post("/users/bulk", data={
        "principals": ["user:ana@corp.com", "user:ben@corp.com"], "scope": "selected",
        "role": "auditor", "confirmed": "yes", "expected_count": "3"}).text
    words = text(page)
    assert "The list changed since you confirmed." in words
    assert "Change the role of 2 people to Auditor?" in words
    assert roles()["user:ana@corp.com"] == "viewer"


def test_nothing_selected_or_no_role_is_explained(client):
    page = client.post("/users/bulk", data={"scope": "selected", "role": "operator"}).text
    assert "Select at least one person" in text(page)
    page = client.post("/users/bulk", data={"scope": "matching", "role": ""}).text
    assert "Choose the new role." in text(page)


def test_bulk_change_is_for_installation_administrators(client, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import auth

    def deny(_request, _atom):
        raise HTTPException(status_code=403, detail="no")
    monkeypatch.setattr(auth, "require_global_permission", deny)
    r = client.post("/users/bulk", data={"scope": "matching", "role": "admin", "confirmed": "yes",
                                         "expected_count": "4"})
    assert r.status_code == 403
    assert client.post("/users/bulk/undo", data={"restore": ["user:ana@corp.com\x1fadmin"]}).status_code == 403
    assert roles()["user:ana@corp.com"] == "viewer"


def test_cancel_several_invitations_after_confirming_the_count(client, monkeypatch):
    from maverick_dashboard import invites
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    token = "bulk-invite-admin-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)
    client.headers["Authorization"] = f"Bearer {token}"
    for email in ("a@corp.com", "b@corp.com", "c@corp.com"):
        invites.create_invite(email, "viewer", created_by="user:setup")
    pending = [i for i in invites.list_invites() if i.pending]
    assert len(pending) == 3
    page = client.get("/users").text
    assert 'form="invites-bulk"' in page and "All 3 waiting invitations" in text(page)
    picked = [pending[0].id, pending[1].id]
    page = client.post("/users/invite/bulk-revoke", data={"invite_ids": picked, "scope": "selected"}).text
    words = text(page)
    assert "Cancel 2 invitations?" in words and "This cannot be undone" in words
    assert len([i for i in invites.list_invites() if i.pending]) == 3  # nothing yet
    page = client.post("/users/invite/bulk-revoke", data={
        "invite_ids": picked, "scope": "selected", "confirmed": "yes", "expected_count": "2"}).text
    assert "Cancelled 2 invitations" in text(page)
    assert [i.id for i in invites.list_invites() if i.pending] == [pending[2].id]


def test_a_refusal_by_the_activity_log_for_one_person_does_not_stop_the_others(client, monkeypatch):
    from maverick.audit import AuditRefused
    from maverick_dashboard import rbac, users_bulk
    real = rbac.set_role

    def set_role(principal, role, **kwargs):
        if principal == "user:ana@corp.com":
            raise AuditRefused("custody unavailable")
        return real(principal, role, **kwargs)

    monkeypatch.setattr(rbac, "set_role", set_role)
    report = users_bulk.apply(["user:ana@corp.com", "user:ben@corp.com"], "operator", actor="user:setup")
    assert [row["outcome"] for row in report] == ["refused", "changed"]
    assert "activity log refused" in report[0]["reason"]
    assert roles()["user:ana@corp.com"] == "viewer" and roles()["user:ben@corp.com"] == "operator"
    assert len(users_bulk.undo_tokens(report)) == 1             # the change that happened can be undone


def test_a_change_the_role_list_could_not_roll_back_is_reported_as_it_now_stands(client, monkeypatch):
    # Audit refused the change and putting the list back failed: the list may
    # now hold it. It must never be reported as "not changed" with no Undo.
    from maverick_dashboard import rbac, users_bulk
    real = rbac.set_role

    def stuck(principal, role, **kwargs):
        real(principal, role, **kwargs)
        raise rbac.RosterRollbackError("audit refused RBAC mutation and roster rollback failed")

    monkeypatch.setattr(rbac, "set_role", stuck)
    report = users_bulk.apply(["user:ana@corp.com"], "operator", actor="user:setup")
    assert report[0]["outcome"] == "uncertain" and report[0]["after"] == "operator"
    assert "may now hold the change" in report[0]["reason"]
    assert len(users_bulk.undo_tokens(report)) == 1             # the change it may hold can be undone


def test_a_rollback_failure_that_left_the_list_unchanged_offers_no_undo(client, monkeypatch):
    from maverick_dashboard import rbac, users_bulk

    def fail(principal, role, **kwargs):
        raise rbac.RosterRollbackError("audit refused RBAC mutation and roster rollback failed")

    monkeypatch.setattr(rbac, "set_role", fail)
    report = users_bulk.apply(["user:ana@corp.com"], "operator", actor="user:setup")
    assert report[0]["outcome"] == "uncertain" and report[0]["after"] == report[0]["before"]
    assert users_bulk.undo_tokens(report) == []


def test_undo_leaves_a_role_someone_changed_again_and_still_accepts_older_tokens(client):
    from maverick_dashboard import rbac, users_bulk
    report = users_bulk.apply(["user:ana@corp.com", "user:ben@corp.com"], "operator", actor="user:setup")
    tokens = users_bulk.undo_tokens(report)
    rbac.set_role("user:ana@corp.com", "admin", actor="user:other-admin")      # decided again afterwards
    undone = {row["principal"]: row for row in users_bulk.undo(tokens, actor="user:setup")}
    assert undone["user:ana@corp.com"]["outcome"] == "refused"
    assert "changed again" in undone["user:ana@corp.com"]["reason"]
    assert roles()["user:ana@corp.com"] == "admin"                              # the newer decision stands
    assert undone["user:ben@corp.com"]["outcome"] == "changed" and roles()["user:ben@corp.com"] == "viewer"
    rbac.set_role("user:cy@corp.com", "admin", actor="user:setup")
    old_token = "user:cy@corp.com" + users_bulk._SEP + "operator"            # issued before the role was recorded
    assert users_bulk.undo([old_token], actor="user:setup")[0]["outcome"] == "changed"
    assert roles()["user:cy@corp.com"] == "operator"


def test_changing_the_first_login_baseline_needs_the_same_fresh_second_factor_as_any_role_change(client, monkeypatch):
    from maverick_dashboard import step_up
    asked = []

    def stale(request, operation):
        asked.append(operation)
        raise step_up.StepUpRequired("/auth/reauthenticate")

    monkeypatch.setattr(step_up, "require_recent_mfa", stale)
    response = client.post("/users/first-login-baseline", data={
        "expected_revision": "0" * 64, "confirm": "existing-unassigned"}, follow_redirects=False)
    assert asked == ["change_role"]
    assert "saved=first_login" not in response.headers.get("location", "")
