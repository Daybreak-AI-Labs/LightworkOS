"""Projects pages: list + create, detail (member goals), and filing a goal under
a project from the goal page."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    return world_model.WorldModel(tmp_path / "world.db")


def test_projects_page_lists(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    pid = w.create_project("Q3 Close", domain="finance_sox")
    w.create_goal("Reconcile", "", project_id=pid)
    t = client.get("/projects").text
    assert "Q3 Close" in t and "Finance sox" in t   # department shown as words
    assert "New project" in t  # create form present
    from test_support.plain_language import developer_terms
    assert developer_terms(t) == []


def test_create_project_redirects_to_detail(tmp_path, monkeypatch):
    _world(tmp_path, monkeypatch)
    r = client.post("/projects", data={"name": "Audit FY26", "domain": "assurance"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/projects/")


def test_create_project_requires_name(tmp_path, monkeypatch):
    _world(tmp_path, monkeypatch)
    r = client.post("/projects", data={"name": "   "}, follow_redirects=False)
    assert r.status_code == 422


def test_project_detail_shows_member_goals(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    pid = w.create_project("Close", domain="finance_sox")
    w.create_goal("Reconcile AP", "", project_id=pid)
    w.create_goal("Unrelated", "")  # not in project
    t = client.get(f"/projects/{pid}").text
    assert "Reconcile AP" in t and "Unrelated" not in t
    assert "Tasks in this project" in t
    assert "finance_sox" not in t and "#1<" not in t
    from test_support.plain_language import developer_terms
    assert developer_terms(t) == []


def test_project_detail_404(tmp_path, monkeypatch):
    _world(tmp_path, monkeypatch)
    assert client.get("/projects/9999").status_code == 404


def test_file_goal_under_project_from_goal_page(tmp_path, monkeypatch):
    w = _world(tmp_path, monkeypatch)
    pid = w.create_project("Close")
    gid = w.create_goal("Reconcile", "")
    # goal page offers the project selector
    assert "goal-project-sel" in client.get(f"/chat/goal/{gid}").text
    # file it
    r = client.post(f"/chat/goal/{gid}/project", data={"project_id": str(pid)},
                    follow_redirects=False)
    assert r.status_code == 303
    assert w.get_goal(gid).project_id == pid
    # clear it (empty value)
    client.post(f"/chat/goal/{gid}/project", data={"project_id": ""}, follow_redirects=False)
    assert w.get_goal(gid).project_id is None


def test_project_filing_and_detail_do_not_expose_other_owners(tmp_path, monkeypatch):
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth, rbac

    world = _world(tmp_path, monkeypatch)
    rbac.set_role("user:alice", "operator")
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: "user:alice")
    monkeypatch.setattr(dashboard, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda principal: False)
    mine = world.create_project("Mine", owner="user:alice")
    other = world.create_project("Private project", owner="user:bob")
    legacy = world.create_project("Legacy project", owner="")
    goal = world.create_goal("Alice task", "", owner="user:alice")
    world.create_goal("Private Bob task", "", owner="user:bob", project_id=mine)
    for target in (other, legacy, 99999):
        response = client.post(f"/chat/goal/{goal}/project", data={"project_id":str(target)}, follow_redirects=False)
        assert response.status_code == 404
        assert world.get_goal(goal).project_id is None
    assert client.get(f"/projects/{other}").status_code == 404
    assert client.get(f"/projects/{legacy}").status_code == 404
    page = client.get(f"/projects/{mine}")
    assert page.status_code == 200 and "Private Bob task" not in page.text
    assert client.post(f"/chat/goal/{goal}/project", data={"project_id":"bad"}).status_code == 422
    assert client.post(f"/chat/goal/{goal}/project", data={"project_id":str(mine)}, follow_redirects=False).status_code == 303


def test_new_project_uses_actual_admin_identity_and_requires_operate(tmp_path, monkeypatch):
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth

    world = _world(tmp_path, monkeypatch)
    monkeypatch.setattr(dashboard, "caller_principal", lambda request: "user:admin")
    response = client.post("/projects", data={"name":"Named admin project"}, follow_redirects=False)
    identifier = int(response.headers["location"].split("/")[-1])
    assert world.get_project(identifier)["owner"] == "user:admin"
    monkeypatch.setattr(auth, "has_permission", lambda request, permission: False)
    assert client.post("/projects", data={"name":"Forbidden"}).status_code == 403
