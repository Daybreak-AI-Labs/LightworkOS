"""Admin-defined custom roles (the "I want to create custom roles" ask).

A custom role is a name plus a subset of the same four permission atoms every
require_permission site gates on -- so a role like "privacy-officer" =
{view, audit, operate} works everywhere a builtin does: role pickers, the
page-visibility matrix, SCIM group mappings, invites, and per-tenant RBAC.
Builtins stay immutable; a role still assigned anywhere cannot be deleted
(deleting it would turn every holder's next request into a corrupt-roster
refusal).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_roundtrip_and_permissions():
    from maverick_dashboard import rbac

    rbac.set_custom_role("privacy-officer", ["view", "audit", "operate"],
                         "Reviews and runs privacy work")
    assert rbac.is_known_role("privacy-officer")
    assert rbac.known_roles()[:4] == rbac.ROLES  # builtins keep their order
    assert "privacy-officer" in rbac.known_roles()
    assert rbac.permissions_for("privacy-officer") == {"view", "audit", "operate"}
    # Update in place.
    rbac.set_custom_role("privacy-officer", ["view", "audit"])
    assert rbac.permissions_for("privacy-officer") == {"view", "audit"}


def test_validation_rules():
    from maverick_dashboard import rbac

    with pytest.raises(ValueError):
        rbac.set_custom_role("admin", ["view"])          # builtin immutable
    with pytest.raises(ValueError):
        rbac.set_custom_role("Bad Name", ["view"])       # slug names only
    with pytest.raises(ValueError):
        rbac.set_custom_role("no-view", ["operate"])     # view is mandatory
    with pytest.raises(ValueError):
        rbac.set_custom_role("bad-atom", ["view", "sudo"])
    with pytest.raises(ValueError):
        rbac.delete_custom_role("viewer")                # builtin immutable


def test_assignments_accept_custom_roles():
    from maverick_dashboard import rbac

    rbac.set_custom_role("reviewer", ["view", "audit"])
    rbac.set_role("user:alice", "reviewer")
    assert rbac.list_users()["user:alice"] == "reviewer"
    rbac.set_tenant_role("acme", "user:bob", "reviewer")
    assert rbac.get_tenant_role("acme", "user:bob") == "reviewer"
    with pytest.raises(ValueError):
        rbac.set_role("user:carol", "never-defined")


def test_delete_refused_while_assigned():
    from maverick_dashboard import rbac

    rbac.set_custom_role("reviewer", ["view", "audit"])
    rbac.set_role("user:alice", "reviewer")
    with pytest.raises(ValueError, match="still assigned"):
        rbac.delete_custom_role("reviewer")
    rbac.remove_user("user:alice")

    rbac.set_tenant_role("acme", "user:bob", "reviewer")
    with pytest.raises(ValueError, match="still assigned"):
        rbac.delete_custom_role("reviewer")
    rbac.remove_tenant_role("acme", "user:bob")

    rbac.delete_custom_role("reviewer")
    assert not rbac.is_known_role("reviewer")
    # And the holder's permissions are gone, not lingering.
    assert rbac.permissions_for("reviewer") == frozenset()


def test_most_privileged_ranks_custom_roles_by_atoms():
    from maverick_dashboard import rbac

    rbac.set_custom_role("audit-operator", ["view", "audit", "operate"])
    # Builtins keep their historical order...
    assert rbac.most_privileged(["viewer", "auditor", "operator"]) == "operator"
    assert rbac.most_privileged(["operator", "admin"]) == "admin"
    # ...and a custom role slots in by what it grants: audit+operate outranks
    # operator (operate only) but never admin.
    assert rbac.most_privileged(["operator", "audit-operator"]) == "audit-operator"
    assert rbac.most_privileged(["admin", "audit-operator"]) == "admin"
    assert rbac.most_privileged([]) is None


def test_visibility_matrix_and_nav_cover_custom_roles():
    from maverick_dashboard import rbac, ui_visibility

    rbac.set_custom_role("reviewer", ["view", "audit"])
    roles_in_matrix = {c["role"] for g in ui_visibility.matrix() for p in g["pages"] for c in p["cells"]}
    assert "reviewer" in roles_in_matrix
    # The role's nav resolves through the same permission atoms.
    hrefs = {ln["href"] for g in ui_visibility.nav_groups("reviewer") for ln in g["links"]}
    assert "/audit" in hrefs          # audit floor reached
    assert "/settings" not in hrefs   # no admin atom
    # And per-cell overrides work for it.
    ui_visibility.set_visibility("/audit", "reviewer", False)
    assert ui_visibility.is_visible(ui_visibility.page_for("/audit"), "reviewer") is False


def test_corrupt_custom_store_denies_not_crashes(tmp_path):
    from maverick_dashboard import rbac

    rbac.set_custom_role("reviewer", ["view", "audit"])
    rbac.custom_roles_path().write_text("{not json", encoding="utf-8")
    assert rbac.permissions_for("reviewer") == frozenset()  # deny
    assert rbac.is_known_role("reviewer") is False
    with pytest.raises(rbac.RbacStoreError):
        rbac.list_custom_roles()


def test_users_page_manages_custom_roles_end_to_end():
    r = client.post(
        "/users/roles/save",
        data={"name": "records-officer", "permissions": ["audit", "operate"],
              "description": "Runs and reviews privacy work"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    page = client.get("/users").text
    assert "Records officer" in page
    assert "Review the history" in page or "audit" in page

    # Assign it, then deletion is refused with the reason.
    assert client.post("/users/set",
                       data={"principal": "user:dana", "role": "records-officer"},
                       follow_redirects=False).status_code == 303
    # The role appears in the assignment pickers.
    assert client.get("/users").text.count('<option value="records-officer"') >= 1
    r = client.post("/users/roles/delete", data={"name": "records-officer"},
                    follow_redirects=False)
    assert r.status_code == 400
    assert "still assigned" in r.json()["detail"]

    from maverick_dashboard.access_explanations import standard_role
    reviewed = standard_role("user:dana")
    assert client.post("/users/remove", data={"principal": "user:dana", "expected_standard": reviewed["revision"]},
                       follow_redirects=False).status_code == 303
    assert client.post("/users/roles/delete", data={"name": "records-officer"},
                       follow_redirects=False).status_code == 303
    assert "Records officer" not in client.get("/users").text


def test_custom_role_management_requires_admin(monkeypatch):
    import maverick_dashboard.auth as auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:viewer")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "viewer")
    assert client.post("/users/roles/save",
                       data={"name": "x-role", "permissions": ["audit"]},
                       follow_redirects=False).status_code == 403
    assert client.post("/users/roles/delete", data={"name": "x-role"},
                       follow_redirects=False).status_code == 403


def test_tenant_role_api_accepts_custom_roles():
    from maverick_dashboard import rbac

    rbac.set_custom_role("reviewer", ["view", "audit"])
    client.post("/api/v1/admin/tenants", json={"id": "acme"})
    r = client.put("/api/v1/admin/tenants/acme/roles/user:eve",
                   json={"role": "reviewer"})
    assert r.status_code == 204, r.text
    assert rbac.get_tenant_role("acme", "user:eve") == "reviewer"
    r = client.put("/api/v1/admin/tenants/acme/roles/user:eve",
                   json={"role": "ghost-role"})
    assert r.status_code == 400
