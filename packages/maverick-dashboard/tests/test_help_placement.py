"""Help sits in the same place in both shells (WCAG 3.2.6).

Both shells put Help in the top bar, in one shared cluster: Docs, Help,
Display, Account, Sign out. The chat shell used to put it at the bottom of its
sidebar, so Help moved between pages.
"""
from __future__ import annotations

import re

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal

CLUSTER = ['class="topbar-utilities"', 'Docs (opens in a new tab)', 'id="help-menu"', 'id="prefs-menu"', 'href="/account"']


@pytest.fixture
def client(monkeypatch, tmp_path):

    from maverick import config, world_model
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth

    async def bind(request: Request):
        request.state.principal = VerifiedPrincipal(sub=("user:alice").removeprefix("user:"), issuer="https://idp.test", audience="lightwork")
        return request.state.principal

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    dashboard._world_cache.clear()
    dashboard.app.dependency_overrides[auth.require_principal_in_request_context] = bind
    monkeypatch.setattr(auth, "role_for_principal", lambda _principal: "operator")
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as test_client:
            yield test_client
    finally:
        dashboard.app.dependency_overrides.clear()
    dashboard._world_cache.clear()
    config.reset_config_cache()


def _top_bar(page: str, shell: str) -> str:
    if shell == "chat":
        match = re.search(r'<header class="cs-topbar"[^>]*>(.*?)</header>', page, re.DOTALL)
    else:
        match = re.search(r'<header class="topbar"[^>]*>(.*?)</header>', page, re.DOTALL)
    assert match, f"no top bar in the {shell} shell"
    return match.group(1)


@pytest.mark.parametrize(("path", "shell"), [("/today", "main"), ("/goals", "main"), ("/chat", "chat")])
def test_help_is_in_the_top_bar_in_the_same_order(client, path, shell):
    page = client.get(path).text
    assert page.count('id="help-menu"') == 1
    bar = _top_bar(page, shell)
    positions = [bar.find(marker) for marker in CLUSTER]
    assert -1 not in positions, dict(zip(CLUSTER, positions, strict=True))
    assert positions == sorted(positions), "Docs, Help, Display and Account keep one order"


def test_chat_sidebar_no_longer_carries_help():
    from pathlib import Path

    from maverick_dashboard import app as dashboard
    source = (Path(dashboard.__file__).parent / "templates" / "chat_base.html").read_text(encoding="utf-8")
    side = source.split('<aside class="cs-side"', 1)[1].split("</aside>", 1)[0]
    assert "_help_menu.html" not in side
    assert "_topbar_utilities.html" in source
