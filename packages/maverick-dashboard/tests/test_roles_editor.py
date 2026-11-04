"""Per-client roles editor: roster + override REST endpoints and the page.

Same harness as test_agents_editor.py: a same-origin client, world DB isolated,
and the role-override file redirected to a temp path so nothing touches the
real workspace.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_ROLES_FILE", str(tmp_path / "roles.toml"))
    yield


class TestRosterAndView:
    def test_page_renders(self):
        r = client.get("/roles")
        assert r.status_code == 200
        assert "roles" in r.text.lower()

    def test_list_includes_orchestrator(self):
        r = client.get("/api/v1/roles")
        assert r.status_code == 200
        assert "orchestrator" in {x["role"] for x in r.json()["roles"]}

    def test_get_role_view(self):
        r = client.get("/api/v1/roles/coder")
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == "coder"
        assert body["is_override"] is False

    def test_page_renders_editable_model_effort(self):
        html = client.get("/roles?role=coder").text
        assert 'id="f-model"' in html and 'name="model"' in html
        assert 'id="f-effort"' in html and 'name="effort"' in html
        assert "Use the standard level" in html   # the "no override" effort option

    def test_unknown_role_404(self):
        assert client.get("/api/v1/roles/not_a_role").status_code == 404


class TestOverrideLifecycle:
    def test_save_addendum_persists(self, tmp_path):
        r = client.post("/api/v1/roles/orchestrator/override",
                        json={"system_addendum": "Lead with the risk summary."})
        assert r.status_code == 200
        assert r.json()["is_override"] is True
        assert (tmp_path / "roles.toml").is_file()
        got = client.get("/api/v1/roles/orchestrator").json()
        assert got["system_addendum"] == "Lead with the risk summary."

    def test_overlong_addendum_rejected_422(self):
        r = client.post("/api/v1/roles/coder/override",
                        json={"system_addendum": "x" * 5000})
        assert r.status_code == 422
        assert client.get("/api/v1/roles/coder").json()["is_override"] is False

    def test_save_model_and_effort(self):
        r = client.post("/api/v1/roles/coder/override",
                        json={"model": "anthropic:claude-opus-4-8", "effort": "high"})
        assert r.status_code == 200
        got = client.get("/api/v1/roles/coder").json()
        assert got["model_override"] == "anthropic:claude-opus-4-8"
        assert got["effort_override"] == "high"
        assert got["is_override"] is True

    def test_invalid_effort_rejected_422(self):
        r = client.post("/api/v1/roles/coder/override", json={"effort": "bogus"})
        assert r.status_code == 422
        assert client.get("/api/v1/roles/coder").json()["is_override"] is False

    def test_delete_reverts(self):
        client.post("/api/v1/roles/writer/override", json={"system_addendum": "plain English"})
        assert client.get("/api/v1/roles/writer").json()["is_override"] is True
        r = client.delete("/api/v1/roles/writer/override")
        assert r.status_code == 200
        assert client.get("/api/v1/roles/writer").json()["is_override"] is False


class TestRoleEditingAuthorization:
    def test_authenticated_non_admin_cannot_mutate_roles(self, monkeypatch):
        import maverick_dashboard.api as api
        monkeypatch.setattr(api, "caller_principal", lambda request: "user:alice")
        monkeypatch.setattr(api, "is_dashboard_admin", lambda principal: False)

        assert client.post("/api/v1/roles/orchestrator/override",
                           json={"system_addendum": "poison"}).status_code == 403
        assert client.delete("/api/v1/roles/orchestrator/override").status_code == 403
        assert client.get("/api/v1/roles/orchestrator").status_code == 200

    def test_authenticated_admin_can_mutate_roles(self, monkeypatch):
        import maverick_dashboard.api as api
        monkeypatch.setattr(api, "caller_principal", lambda request: "user:admin")
        monkeypatch.setattr(api, "is_dashboard_admin", lambda principal: principal == "user:admin")

        r = client.post("/api/v1/roles/orchestrator/override",
                        json={"system_addendum": "Admin-approved addendum."})
        assert r.status_code == 200
        assert r.json()["is_override"] is True
        assert client.delete("/api/v1/roles/orchestrator/override").status_code == 200


class TestRoleEditingGate:
    def test_mutations_403_when_disabled(self, monkeypatch):
        import maverick.config as cfg
        monkeypatch.setattr(cfg, "get_features",
                            lambda: {"skills": True, "world_model": True, "streaming": True,
                                     "pack_editing": True, "role_editing": False})
        assert client.post("/api/v1/roles/coder/override",
                           json={"system_addendum": "x"}).status_code == 403
        assert client.delete("/api/v1/roles/coder/override").status_code == 403
        assert client.get("/api/v1/roles/coder").status_code == 200  # read-only still ok
