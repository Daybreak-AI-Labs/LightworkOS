"""Customer navigation and direct HTTP admission share actual RBAC authority."""
from __future__ import annotations

from html.parser import HTMLParser

import pytest


def _client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from maverick import world_model
    from maverick_dashboard import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    app._world_cache.clear()
    return TestClient(app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _as(monkeypatch, principal):
    from maverick_dashboard import auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)


def test_customer_destination_labels(monkeypatch, tmp_path):
    from maverick_dashboard import ui_visibility

    monkeypatch.setenv("HOME", str(tmp_path))
    links = {
        link["href"]: link["label"]
        for group in ui_visibility.nav_groups("admin") for link in group["links"]
    }
    assert {path: links[path] for path in (
        "/goals", "/connections", "/knowledge-access", "/deliverables", "/settings"
    )} == {
        "/goals": "Tasks", "/connections": "Connections", "/knowledge-access": "Knowledge",
        "/deliverables": "Results", "/settings": "Settings",
    }


def test_chat_product_navigation_uses_current_role(monkeypatch, tmp_path):
    from maverick_dashboard import rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", "operator")
    _as(monkeypatch, "user:customer")
    page = client.get("/chat")
    assert page.status_code == 200
    assert 'aria-label="Primary"' in page.text
    assert 'href="/goals"' in page.text
    assert 'href="/settings"' not in page.text
    assert 'href="/connections"' not in page.text
    assert 'href="/chat"' in page.text


class _Sidebar(HTMLParser):
    """The shared sidebar's links (Most used, then each group) and shell chrome."""

    def __init__(self, html):
        super().__init__()
        self.stack, self.quick, self.groups, self.brand, self.hrefs = [], [], [], None, set()
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        classes = (values.get("class") or "").split()
        if tag in ("ul", "div"):
            self.stack.append(classes)
        if tag == "div" and "navgrp" in classes:
            self.groups.append((values.get("data-grp"), []))
        if tag == "button" and "navgrp__toggle" in classes and self.groups:
            self.groups[-1] = (values.get("data-grp"), self.groups[-1][1])
        if tag != "a" or not values.get("href"):
            return
        self.hrefs.add(values["href"])
        if {"brand", "cs-brand"} & set(classes):
            self.brand = values["href"]
        if any("navquick-list" in entry for entry in self.stack):
            self.quick.append(values["href"])
        elif any("navgrp" in entry for entry in self.stack):
            self.groups[-1][1].append(values["href"])

    def handle_endtag(self, tag):
        if tag in ("ul", "div") and self.stack:
            self.stack.pop()


@pytest.mark.parametrize("role", [None, "operator", "admin"])
def test_both_shells_render_one_sidebar(monkeypatch, tmp_path, role):
    """Chat (home) and every product page show the same navigation, logo and links."""
    from maverick_dashboard import rbac

    client = _client(monkeypatch, tmp_path)
    if role is not None:
        monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:customer" if role == "admin" else "")
        rbac.set_role("user:customer", role)
        _as(monkeypatch, "user:customer")
    product, chat = (_Sidebar(client.get(path).text) for path in ("/goals", "/chat"))
    assert product.quick and product.groups
    assert (chat.quick, chat.groups) == (product.quick, product.groups)
    # Approvals sits in Most used, so anyone who can decide reaches it in one click.
    assert "/approvals" in chat.quick
    # The logo always goes home; Help, Docs, the account and the workspace
    # switcher are reachable from the chat shell too.
    assert product.brand == chat.brand == "/"
    for href in ("/help", "/account", "/workspace/tenant"):
        assert href in chat.hrefs and href in product.hrefs, href
    docs = "https://daybreak-ai-labs.github.io/LightworkOS/"
    assert any(h.startswith(docs) for h in chat.hrefs) and any(h.startswith(docs) for h in product.hrefs)


@pytest.mark.parametrize("global_role,workspace_role", [("viewer", "viewer"), ("admin", "viewer")])
def test_read_only_chat_projects_workspace_authority(monkeypatch, tmp_path, global_role, workspace_role):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import app, rbac, ui_visibility

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", global_role)
    rbac.set_tenant_role("acme", "user:customer", workspace_role)
    ui_visibility.set_visibility("/chat", "viewer", True)
    _as(monkeypatch, "user:customer")
    scope = set_tenant("acme")
    try:
        world = app._world()
        gid = world.create_goal("Owned answer", "", owner="user:customer")
        world.set_goal_status(gid, "done", result="saved answer")
        page = client.get(f"/chat/goal/{gid}")
        assert page.status_code == 200
        assert 'id="chat-read-only" class="muted" role="status">' in page.text
        assert 'id="copy-result"' in page.text
        assert 'id="edit-toggle"' not in page.text
        assert 'id="feedback-up"' not in page.text
        assert 'id="share-open"' not in page.text
        assert 'id="ps-run"' not in page.text
        assert client.get(f"/chat/goal/{gid}/download.md").status_code == 200
        assert client.post(f"/api/v1/goals/{gid}/deliverable/edit", json={
            "text": "change", "expected_updated_at": world.get_goal(gid).updated_at,
            "operation_id": "viewer-denied-edit-1",
        }).status_code == 403
    finally:
        reset_tenant(scope)


@pytest.mark.parametrize("path,title", [
    ("/goals", "Tasks"), ("/cortex", "Cortex memory diagnostics"), ("/deliverables", "Results"),
])
def test_customer_read_destinations_remain_available(monkeypatch, tmp_path, path, title):
    from maverick_dashboard import rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", "viewer")
    _as(monkeypatch, "user:customer")
    response = client.get(path)
    assert response.status_code == 200
    assert f"<title>{title} · Lightwork</title>" in response.text
    for hidden in ("/settings", "/connections", "/learning", "/benchmarks", "/perf"):
        assert f'href="{hidden}"' not in response.text
    assert 'class="nav-label">New task' not in response.text
    if path == "/goals":
        assert "New task in Chat" not in response.text


@pytest.mark.parametrize("path", [
    "/api/v1/learning", "/api/v1/benchmarks", "/api/v1/perf",
    "/api/v1/features/switches",
])
def test_global_policy_failure_denies_research_data(monkeypatch, tmp_path, path):
    from maverick_dashboard import rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    _as(monkeypatch, "user:customer")

    def unreadable(*args, **kwargs):
        raise rbac.RbacStoreError("synthetic unreadable role policy")

    monkeypatch.setattr(rbac, "get_stored_role", unreadable)
    assert client.get(path).status_code == 403


def test_missing_configured_identity_does_not_get_local_navigation(monkeypatch, tmp_path):
    from fastapi import Request
    from maverick_dashboard import app

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "synthetic-local-dashboard-token")
    context = app._nav_context(Request({"type": "http", "headers": []}))
    assert context["nav_groups"] == []
    assert context["finder_pages"] == []
    assert client.get("/learning").status_code == 401


@pytest.mark.parametrize("path", ["/connections", "/benchmarks", "/learning"])
def test_unreadable_role_policy_denies_before_page_handler(monkeypatch, tmp_path, path):
    from maverick_dashboard import app, rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    _as(monkeypatch, "user:customer")

    def unreadable(*args, **kwargs):
        raise rbac.RbacStoreError("synthetic unreadable role policy")

    def must_not_render(*args, **kwargs):
        pytest.fail("denied caller reached the page renderer")

    monkeypatch.setattr(rbac, "get_stored_role", unreadable)
    monkeypatch.setattr(app.templates, "TemplateResponse", must_not_render)
    assert client.get(path).status_code == 403


@pytest.mark.parametrize("lookup_failure", ["returned_none", "raised"])
def test_role_resolution_failure_hides_navigation(monkeypatch, tmp_path, lookup_failure):
    from fastapi import Request
    from maverick_dashboard import app, rbac

    _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    _as(monkeypatch, "user:customer")

    def unreadable(*args, **kwargs):
        raise rbac.RbacStoreError("synthetic unreadable role policy")

    if lookup_failure == "returned_none":
        monkeypatch.setattr(rbac, "get_stored_role", unreadable)
    else:
        monkeypatch.setattr(app, "caller_role", unreadable)
    context = app._nav_context(Request({"type": "http", "headers": []}))
    assert context["nav_groups"] == []
    assert context["finder_pages"] == []
    assert context["show_settings_link"] is False


@pytest.mark.parametrize("role", ["viewer", "operator", "auditor"])
@pytest.mark.parametrize("path", [
    "/connections", "/settings", "/settings/", "/learning", "/learning/",
    "/benchmarks", "/benchmarks/", "/perf", "/perf/",
])
def test_customer_hidden_admin_and_research_destinations_denied(
    monkeypatch, tmp_path, role, path
):
    from maverick_dashboard import app, rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", role)
    _as(monkeypatch, "user:customer")

    def must_not_render(*args, **kwargs):
        pytest.fail("unauthorized destination reached the page renderer")

    monkeypatch.setattr(app.templates, "TemplateResponse", must_not_render)
    response = client.get(path)
    assert response.status_code == 403
    assert "this page is not enabled" in response.text


def test_tenant_admin_cannot_see_or_open_installation_controls(monkeypatch, tmp_path):
    from fastapi import Request
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import app, rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:tenant-admin", "viewer")
    rbac.set_tenant_role("acme", "user:tenant-admin", "admin")
    _as(monkeypatch, "user:tenant-admin")
    token = set_tenant("acme")
    try:
        # Connections ships switched off. A workspace administrator cannot turn
        # modules on (that is installation-wide), so the sidebar leaves out the
        # page that would only say it is turned off; the finder still lists it.
        context = app._nav_context(Request({"type": "http", "headers": []}))
        assert "/connections" not in {link["href"] for group in context["nav_groups"] for link in group["links"]}
        assert "/connections" in {link["href"] for group in context["finder_pages"] for link in group["links"]}
        from maverick import config
        from maverick_dashboard import settings_store

        settings_store.set_module_enables(["connections"], True)
        config.reset_config_cache()
        context = app._nav_context(Request({"type": "http", "headers": []}))
        for key in ("nav_groups", "finder_pages"):
            links = {link["href"] for group in context[key] for link in group["links"]}
            assert "/connections" in links
            assert links.isdisjoint({"/settings", "/learning", "/benchmarks"})
        assert context["show_settings_link"] is False
        for path in ("/settings", "/learning", "/benchmarks"):
            assert client.get(path).status_code == 403
    finally:
        reset_tenant(token)


@pytest.mark.parametrize("role", ["viewer", "operator", "auditor", "tenant_admin"])
@pytest.mark.parametrize("path", [
    "/api/v1/learning", "/api/v1/benchmarks", "/api/v1/perf",
    "/api/v1/features/switches",
])
def test_research_data_aliases_deny_before_any_reader(monkeypatch, tmp_path, role, path):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import api, rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", "viewer" if role == "tenant_admin" else role)
    _as(monkeypatch, "user:customer")
    token = None
    if role == "tenant_admin":
        rbac.set_tenant_role("acme", "user:customer", "admin")
        token = set_tenant("acme")
    calls = []

    def read_canary(*args, **kwargs):
        calls.append("read")
        return {"suites": [], "history_path": "synthetic-research-canary"}

    async def measure_canary():
        calls.append("measurement")
        return [], "synthetic-research-canary"

    monkeypatch.setattr(api, "_learning_snapshot", read_canary)
    monkeypatch.setattr(api, "_benchmark_snapshot", read_canary)
    monkeypatch.setattr(api, "_cached_perf_sla", measure_canary)
    monkeypatch.setattr(api, "_live_feature_switch_states", read_canary)
    try:
        response = client.get(path)
        assert response.status_code == 403
        assert calls == []
        assert "synthetic-research-canary" not in response.text
    finally:
        if token is not None:
            reset_tenant(token)


def test_static_token_authority_retains_navigation(monkeypatch, tmp_path):
    from fastapi import Request
    from maverick_dashboard import app

    _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "synthetic-local-dashboard-token")
    request = Request({"type": "http", "headers": [
        (b"authorization", b"Bearer synthetic-local-dashboard-token")
    ], "path": "/learning"})
    context = app._nav_context(request)
    assert context["show_settings_link"] is True
    app.enforce_page_visibility(request)


def test_installation_admin_keeps_global_pages_after_workspace_demotion(monkeypatch, tmp_path):
    from fastapi import Request
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import app, rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:installation-admin", "admin")
    rbac.set_tenant_role("acme", "user:installation-admin", "viewer")
    _as(monkeypatch, "user:installation-admin")
    token = set_tenant("acme")
    try:
        context = app._nav_context(Request({"type": "http", "headers": []}))
        for key in ("nav_groups", "finder_pages"):
            links = {link["href"] for group in context[key] for link in group["links"]}
            assert "/settings" in links and "/learning" in links
            assert "/connections" not in links
        assert client.get("/connections").status_code == 403
        for path in ("/settings", "/learning", "/benchmarks"):
            assert client.get(path).status_code == 200
    finally:
        reset_tenant(token)


@pytest.mark.parametrize("global_role,workspace_role,can_manage", [
    ("operator", "operator", False), ("viewer", "admin", False),
    ("admin", "operator", True),
])
def test_security_operators_do_not_request_installation_switches(
    monkeypatch, tmp_path, global_role, workspace_role, can_manage
):
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import rbac

    client = _client(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:customer", global_role)
    rbac.set_tenant_role("acme", "user:customer", workspace_role)
    _as(monkeypatch, "user:customer")
    token = set_tenant("acme")
    try:
        response = client.get("/security")
        assert response.status_code == 200
        assert ('id="sec-hunters"' in response.text) is can_manage
        assert ("mvFetchJSON('/api/v1/features/switches'" in response.text) is can_manage
        if not can_manage:
            assert "An administrator turns threat hunting on or off." in response.text
    finally:
        reset_tenant(token)
