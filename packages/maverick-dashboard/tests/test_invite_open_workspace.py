"""Opening the workspace after accepting an invitation.

An installation pinned to one workspace (MAVERICK_TENANT) used to refuse
"Open <workspace>" even when the invitation was for that very workspace, and
the refusal then showed "No direct membership" although the role was saved.
"""
from __future__ import annotations

from types import SimpleNamespace

from starlette.requests import Request


def _request() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/auth/invite/t/workspace", "headers": [],
                    "query_string": b"", "client": ("127.0.0.1", 1), "server": ("127.0.0.1", 80), "scheme": "http"})


def _receipt(monkeypatch, tenant="acme"):
    from maverick_dashboard import invite_routes

    inv = SimpleNamespace(tenant=tenant, grant_confirmed_at=1.0, token="t")
    monkeypatch.setattr(invite_routes, "_original_receipt", lambda request, token: (inv, "admin", True))
    shown = {}
    monkeypatch.setattr(invite_routes, "_page", lambda request, state, **kw: shown.update(state=state, **kw) or shown)
    return invite_routes, shown


def test_a_fixed_installation_opens_the_invited_workspace_it_already_is(monkeypatch):
    invite_routes, shown = _receipt(monkeypatch)
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    response = invite_routes._open_workspace(_request(), "t")
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert shown == {}


def test_a_refused_open_still_shows_the_saved_role(monkeypatch):
    invite_routes, shown = _receipt(monkeypatch)
    monkeypatch.setenv("MAVERICK_TENANT", "another-workspace")
    invite_routes._open_workspace(_request(), "t")
    assert shown["state"] == "accepted" and shown["current_role"] == "admin" and shown["token"] == "t"
    assert "could not be opened" in shown["message"]


def test_the_open_workspace_form_carries_the_workspace_it_was_rendered_under():
    """The invitation page has no shared page script, so its own form must send
    the workspace the page was rendered under, or the stale-tab check refuses
    every Open <workspace> with 'the active workspace changed'."""
    from pathlib import Path

    page = (Path(__file__).resolve().parents[1] / "maverick_dashboard/templates/invite_accept.html").read_text(encoding="utf-8")
    form = page[page.index('action="/auth/invite/{{ invite.token }}/workspace"'):]
    form = form[:form.index("</form>")]
    assert 'name="_expected_tenant"' in form and "workspace_expected_tenant" in form
