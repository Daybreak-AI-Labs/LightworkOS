"""Creating a workspace must not break the default one, and a stopped run
never shows internal text to the person reading the chat.

Reproduces the fresh-install defect: signed in as the local owner (the
deployment bound to ``owner-browser``), create the first workspace on the
Workspaces page, then submit a task in Chat. The run must not stop with
``over quota: tenant policy unavailable or inactive: tenant is suspended or
unknown: 'owner-browser'`` and suggest a spending limit.
"""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

RAW = ("over quota: tenant policy unavailable or inactive: "
       "tenant is suspended or unknown: 'owner-browser'")


def _visible(page: str) -> str:
    page = re.sub(r"<(script|style)\b.*?</\1>", " ", page, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import client, world_model
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import rbac

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    client.reset_client_cache()
    roles_dir = tmp_path / "home" / ".maverick"
    monkeypatch.setattr(rbac, "store_path", lambda: roles_dir / "dashboard-users.json")
    monkeypatch.setattr(rbac, "tenant_store_path", lambda: roles_dir / "dashboard-tenant-roles.json")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api_mod, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()
    client.reset_client_cache()


def test_create_workspace_then_submit_task_is_admitted(env, monkeypatch):
    from maverick.paths import current_tenant_id
    from maverick.tenant import registry

    client, world = env
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    admitted: list[tuple[str | None, str | None]] = []

    async def run(goal_id, **kwargs):
        # The same admission check the orchestrator performs before a run.
        tenant = current_tenant_id()
        try:
            registry.assert_tenant_active(tenant)
            admitted.append((tenant, None))
        except Exception as exc:  # noqa: BLE001 -- the refusal text is the finding
            admitted.append((tenant, str(exc)))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)

    # Workspaces page, "Create a workspace".
    r = client.post("/api/v1/admin/tenants", json={"display_name": "Acme Finance", "plan": "free"})
    assert r.status_code == 201, r.text
    # Chat, submit a task.
    r = client.post("/chat/send", data={"title": "Summarise last month's invoices"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert admitted == [("owner-browser", None)]
    assert registry.get_tenant("owner-browser").active
    assert world.list_goals()[0].status != "blocked"


def test_one_step_client_setup_keeps_the_default_workspace_active(env, monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import invites

    client, _world = env
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    token = "workspace-default-test-token"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", token)  # invitations on means people sign in
    client.headers["Authorization"] = f"Bearer {token}"
    monkeypatch.setattr(invites, "send_invite_email", lambda *a, **k: (False, "off"))
    r = client.post("/api/v1/admin/workspace-ops/onboard", json={
        "display_name": "Beta Co", "plan": "free", "admin_email": "ann@example.com"})
    assert r.status_code == 201, r.text
    registry.assert_tenant_active("owner-browser")


def test_dashboard_startup_repairs_an_install_that_already_hit_the_bug(env, monkeypatch):
    from maverick.tenant import registry
    from maverick_dashboard import app as dashboard

    registry.create_tenant("acme")          # a roster without the default
    monkeypatch.setenv("MAVERICK_TENANT", "owner-browser")
    assert registry.get_tenant("owner-browser") is None
    dashboard.repair_default_workspace()
    assert registry.get_tenant("owner-browser").active


def _blocked_goal(world, owner=""):
    gid = world.create_goal("Summarise last month's invoices", "", owner=owner)
    world.set_goal_status(gid, "blocked", result=RAW)
    return gid


def test_chat_page_never_shows_the_raw_workspace_error(env):
    client, world = env
    gid = _blocked_goal(world)
    page = client.get(f"/chat/goal/{gid}").text
    # Auth-off local mode is the administrator: the raw text may appear only
    # inside the "Technical details" disclosure, never in the card or answer.
    card = page.split("Technical details", 1)[0]
    assert "tenant is suspended or unknown" not in _visible(card)
    text = _visible(page)
    assert "This workspace is paused or hasn't been set up. Open Workspaces to resume it." in text
    assert 'href="/workspaces"' in page
    # The stop is not a spending problem, so the spending-limit advice is
    # not offered for it.
    assert 'data-stop-kind="workspace_paused"' in page
    # The initial page state carries the mapped stop, not the raw result.
    assert "let lastStop = " in page
    assert f"let lastResult = {RAW!r}" not in page


def test_admin_sees_raw_text_only_under_technical_details(env):
    client, world = env
    gid = _blocked_goal(world)
    page = client.get(f"/chat/goal/{gid}").text
    assert "Technical details" in page
    details = page.split("Technical details", 1)[1]
    assert "tenant is suspended or unknown" in details
    before = page.split("Technical details", 1)[0]
    assert "tenant is suspended or unknown" not in _visible(before)


def _as_operator(monkeypatch):
    import maverick_dashboard.auth as auth
    from maverick_dashboard import rbac

    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    rbac.set_role("user:bob", "operator")
    return {"X-Forwarded-User": "bob"}


def test_non_admin_never_receives_the_raw_text(env, monkeypatch):
    client, world = env
    headers = _as_operator(monkeypatch)
    gid = _blocked_goal(world, owner="user:bob")
    page = client.get(f"/chat/goal/{gid}", headers=headers).text
    assert "Technical details" not in page
    assert "tenant is suspended or unknown" not in page
    assert "owner-browser" not in page
    assert "Open Workspaces" in _visible(page)
    # The live payloads the page polls carry the mapped stop for the halt card.
    body = client.get(f"/api/goal/{gid}/events", headers=headers).json()
    assert body["stop"]["kind"] == "workspace_paused"
    assert body["stop"]["link"] == "/workspaces"
    assert "technical" not in body["stop"]
    v1 = client.get(f"/api/v1/goals/{gid}/events", headers=headers).json()
    assert v1["stop"]["kind"] == "workspace_paused"


def test_spending_limit_stop_keeps_the_spending_advice(env):
    client, world = env
    gid = world.create_goal("Plan the launch", "")
    world.set_goal_status(gid, "blocked", result=(
        "over quota: Your spending limit of $5.00 per day has been reached ($6.00 spent today)."))
    page = client.get(f"/chat/goal/{gid}").text
    assert 'data-stop-kind="spending_limit"' in page
    assert 'href="/spending-limits"' in page


def test_workspaces_link_opens_the_workspaces_page(env):
    client, _world = env
    r = client.get("/workspaces", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert r.headers["location"].endswith("/tenants")
