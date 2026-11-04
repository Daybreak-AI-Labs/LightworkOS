"""Departures reach the people the Users page lists, including workspace invitees.

On an installation where colleagues sign in with a passphrase, someone who
joined through a workspace invitation holds only a workspace role and never
signed in through company sign-in, so the departure picker (role holders and
company sign-ins) could not name them and they could not be offboarded. These
tests use the real stores: an invitation is accepted in a browser, then the
installation owner reviews and begins the departure through the API.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

LOCAL = "http://127.0.0.1:8765"
REMOTE = "https://lightwork.example"
OWNER = "owner@example.test"
OWNER_PASS = "Synthetic owner passphrase for departures"  # pragma: allowlist secret
SAM = "sam@example.test"
SAM_PRINCIPAL = "user:" + SAM
PASSPHRASE = "harbor violet tram ledger"  # pragma: allowlist secret - synthetic fixture passphrase
WORKSPACE = "client-a"


@pytest.fixture
def install(monkeypatch, tmp_path):
    from maverick import client as client_binding
    from maverick import config, world_model

    for name in tuple(os.environ):
        if name.startswith(("MAVERICK_", "LIGHTWORK_")):
            monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text('[features]\nemployee_departures = true\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    client_binding.reset_client_cache()
    from maverick.tenant import registry
    from maverick_dashboard import local_passphrases
    from maverick_dashboard.app import app

    local_passphrases.reset_attempt_limit()
    owner = TestClient(app, base_url=LOCAL, client=("127.0.0.1", 50001),
                       headers={"Origin": LOCAL}, follow_redirects=False)
    claimed = owner.post("/auth/local-owner", data={
        "email": OWNER, "password": OWNER_PASS, "password2": OWNER_PASS, "confirm": "yes"})
    assert claimed.status_code == 303, claimed.text
    registry.create_tenant(WORKSPACE)
    yield owner
    owner.close()
    local_passphrases.reset_attempt_limit()
    config.reset_config_cache()
    client_binding.reset_client_cache()


def _browser():
    from maverick_dashboard.app import app

    return TestClient(app, base_url=REMOTE, client=("192.0.2.40", 50002),
                      headers={"Origin": REMOTE}, follow_redirects=False)


def _invite_to_workspace():
    from maverick_dashboard import invites

    _inv, token = invites.create_invite(SAM, "operator", created_by="user:" + OWNER, tenant=WORKSPACE)
    return f"/auth/invite/{token}"


def _join(browser):
    invite = _invite_to_workspace()
    joined = browser.post(invite, data={"password": PASSPHRASE, "password2": PASSPHRASE})
    assert joined.status_code == 303, joined.text
    assert "mvk_session" in browser.cookies
    opened = browser.post(invite + "/workspace")
    assert opened.status_code == 303, opened.text


def _people(owner):
    listed = owner.get("/api/v1/employee-departures")
    assert listed.status_code == 200, listed.text
    return {row["principal"]: row for row in listed.json()["people"]}


def _depart(owner):
    reviewed = owner.post("/api/v1/employee-departures/preview", json={"principal": SAM_PRINCIPAL})
    assert reviewed.status_code == 200, reviewed.text
    begun = owner.post("/api/v1/employee-departures", json={
        "principal": SAM_PRINCIPAL, "custodian": "user:" + OWNER,
        "snapshot": reviewed.json()["snapshot"], "confirm_preservation": True})
    assert begun.status_code == 200, begun.text
    return reviewed.json(), begun.json()


def test_a_workspace_invited_person_is_offered_for_departure(install):
    # An invitation nobody has accepted yet names no one.
    link = _invite_to_workspace()
    assert SAM_PRINCIPAL not in _people(install)
    assert _browser().post(link, data={"password": PASSPHRASE, "password2": PASSPHRASE}).status_code == 303
    sam = _people(install)[SAM_PRINCIPAL]
    assert sam["active"] is True and sam["admin"] is False and sam["departed"] is False
    assert sam["label"] == SAM
    # The Users page offers the same person: both read one source.
    users = install.get("/users")
    assert users.status_code == 200
    assert f'value="{SAM_PRINCIPAL}"' in users.text
    # The page's own picker offers this kind of person and hides departed ones.
    page = install.get("/users/departures")
    assert page.status_code == 200
    assert "model.people.filter(p => !p.admin && !p.departed)" in page.text


def test_departing_a_workspace_invited_person_ends_every_way_in(install):
    from maverick.paths import tenant_scope
    from maverick_dashboard import api_keys, approval_decisions, rbac, scim_groups

    sam = _browser()
    _join(sam)
    with tenant_scope(tenant=WORKSPACE):
        _key, secret = api_keys.create_key(
            label="sam script", scopes=["tasks:read"], owner=SAM_PRINCIPAL,
            created_by=SAM_PRINCIPAL, workspace=WORKSPACE,
        )
    bearer = {"Authorization": f"Bearer {secret}"}
    check = "/api/v1/features/modules"
    assert sam.get(check).status_code == 200
    assert _browser().get(check, headers=bearer).status_code == 200
    assert rbac.get_tenant_role(WORKSPACE, SAM_PRINCIPAL) == "operator"
    with tenant_scope(tenant=WORKSPACE):
        assert approval_decisions._may_decide(SAM_PRINCIPAL) is True

    reviewed, begun = _depart(install)
    kinds = {(item["kind"], item.get("tenant")) for item in reviewed["items"]}
    assert ("membership", WORKSPACE) in kinds
    assert begun["status"] == "handoff_required"
    assert begun["steps"][-1] == {"kind": "identity", "status": "deactivated", "sessions": "revoked"}

    # The signed-in browser is out, and so is the passphrase on a fresh one.
    assert sam.get(check).status_code == 401
    fresh = _browser()
    refused = fresh.post("/auth/local-login", data={"email": SAM, "password": PASSPHRASE})
    assert refused.status_code != 303 and "mvk_session" not in fresh.cookies
    # The API key is refused although its record still exists.
    assert _browser().get(check, headers=bearer).status_code == 401
    assert api_keys.verify(secret)[0] is not None
    # Neither the workspace role nor an approval delegation lets them act.
    assert scim_groups.active_for_principal(SAM_PRINCIPAL) is False
    assert approval_decisions._may_decide(SAM_PRINCIPAL) is False
    # The owner is untouched.
    assert install.get(check).status_code == 200


def test_a_departed_person_stays_known_for_their_case_but_is_not_offered_again(install):
    from maverick_dashboard import employee_departures

    _join(_browser())
    _reviewed, begun = _depart(install)
    people = _people(install)
    assert people[SAM_PRINCIPAL]["active"] is False and people[SAM_PRINCIPAL]["departed"] is True
    assert people["user:" + OWNER]["departed"] is False
    assert SAM_PRINCIPAL not in [p["principal"] for p in people.values() if not p["admin"] and not p["departed"]]
    # They stay known, so their case can still be reviewed and closed.
    assert employee_departures.preview(SAM_PRINCIPAL)["principal"] == SAM_PRINCIPAL
    assert employee_departures.closure_preview(begun["id"], begun["revision"])["case_id"] == begun["id"]


def test_the_copilot_departure_form_hides_departed_people(install, monkeypatch):
    from maverick_dashboard import employee_departures
    from maverick_dashboard import product_operations_identity as operations

    _join(_browser())
    _depart(install)
    monkeypatch.setattr(operations, "_departures", lambda request: (employee_departures.candidates(), [], False))
    form = operations.departure_snapshot(None, None, action="begin").fields
    employees = next(field for field in form if field["name"] == "principal")["choices"]
    custodians = next(field for field in form if field["name"] == "custodian")["choices"]
    assert SAM_PRINCIPAL not in [choice["value"] for choice in employees]
    assert SAM_PRINCIPAL not in [choice["value"] for choice in custodians]
    assert "user:" + OWNER in [choice["value"] for choice in custodians]


def test_someone_who_is_active_again_can_be_offered_again(install, monkeypatch):
    from maverick_dashboard import employee_departures, scim_groups

    _join(_browser())
    _depart(install)
    monkeypatch.setattr(scim_groups, "active_for_principal", lambda principal: True)
    sam = next(row for row in employee_departures.candidates() if row["principal"] == SAM_PRINCIPAL)
    assert sam["active"] is True and sam["departed"] is False


def test_an_unreadable_invitation_store_does_not_give_a_partial_list(install, tmp_path):
    (tmp_path / "dashboard-invites.json").write_text("{not json", encoding="utf-8")
    refused = install.get("/api/v1/employee-departures")
    assert refused.status_code == 503
    assert "people" not in refused.text
