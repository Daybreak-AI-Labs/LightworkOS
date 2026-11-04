"""The Cortex page (Observe -> Cortex): the company brain's operator surface.

Hermetic like the trust-receipts page tests -- a bare FastAPI app around the
router with the kernel status and the audit tail stubbed -- plus one render
through the mounted dashboard shell and the static a11y audit on both the
template and the rendered document."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import cortex_page as page
from maverick_dashboard import ui_visibility

_STATUS = {
    "enabled": True,
    "tenant": "acme",
    "sources": {
        "knowledge": {"available": True, "collections": ["finance", "policies"]},
        "skills": {"count": 12, "verified": 3},
        "lessons": {"models": 2, "lines": 9, "enabled": True},
        "record": {"entries": 40, "n_records": 40, "n_goals": 30, "n_approvals": 10,
                   "n_human_decisions": 4, "departments": {"finance": 40}},
        "fleet": {"enabled": False},
    },
    "encryption": {"at_rest": True, "per_tenant": False},
    "isolation": {"tenant_floored": True, "pooled_across_tenants": False,
                  "note": "floored to the active tenant"},
}

# Raw audit rows as ``default_audit_log().tail()`` returns them (payload keys
# are spread at the top level), oldest first, with unrelated kinds mixed in.
_TAIL = [
    {"ts": 1_767_225_500.0, "kind": "tool_call", "agent": "worker-0", "name": "read_file"},
    {"ts": 1_767_225_600.0, "kind": "cortex_recall", "agent": "cortex", "caller": "user:jo",
     "external": False, "tenant": "acme", "sources": ["knowledge", "skills", "fleet"],
     "per_source": {"knowledge": 2, "skills": 1, "fleet": 0},
     "denied": {"fleet": "fleet memory answers enrolled external agents"},
     "query_sha": "abcd", "query_len": 13, "hits": 3, "took_ms": 12},
    {"ts": 1_767_225_700.0, "kind": "cortex_deposit", "agent": "cortex", "caller": "dashboard",
     "external": False, "tenant": "acme", "deposit_kind": "knowledge", "ok": True,
     "reason": "ingested", "text_sha": "ef01", "text_len": 40, "collection": "finance",
     "chunks": 2},
    {"ts": 1_767_225_800.0, "kind": "cortex_deposit", "agent": "cortex", "caller": "agent:copilot",
     "external": True, "vendor": "acme-copilot", "tenant": "acme", "deposit_kind": "fleet",
     "ok": False, "reason": "agent not on the roster"},
]


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=Path(page.__file__).parent / "templates",
        context_processors=[_theme_context],
    )
    selected.env.globals.update(
        theme="dark", font="default", lang="en", density="comfortable",
        custom_theme_css="", custom_theme_names=[], dir="ltr",
        nav_groups=ui_visibility.nav_groups(None), t=lambda key: key,
    )
    return selected


def _app(monkeypatch, *, permitted: bool = True, audit: bool = True,
         status=None, tail=None) -> TestClient:
    def _require(request, permission):
        assert permission == "view"
        if not permitted:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="insufficient role")

    def _has(request, permission):
        assert permission == "audit"
        return audit

    monkeypatch.setattr(page, "require_permission", _require)
    monkeypatch.setattr(page, "has_permission", _has)
    monkeypatch.setattr(page, "_status", lambda: dict(_STATUS if status is None else status))
    monkeypatch.setattr(page, "_audit_tail", lambda n: list(_TAIL if tail is None else tail))
    app = FastAPI()
    app.include_router(page.create_cortex_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1")


def test_page_renders_the_brain_and_is_hardened(monkeypatch) -> None:
    response = _app(monkeypatch).get(page.PAGE_PATH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    csp = response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "style-src 'self' 'nonce-" in csp
    assert "script-src 'self'" in csp
    body = response.text
    assert "<title>Cortex memory diagnostics · Lightwork</title>" in body
    assert body.count("<h1") == 1
    assert "Search your connected sources" in body
    # the figure: the lattice canvas at its native size, captioned
    assert '<canvas id="cortex-lattice" width="640" height="480"' in body
    assert "<figcaption" in body
    assert page.ASSET_PATH in body
    assert f'data-api-base="{page.API_BASE}"' in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body


def test_what_it_holds_has_one_card_per_source_with_counts_and_posture(monkeypatch) -> None:
    body = _app(monkeypatch).get(page.PAGE_PATH).text
    for source in ("knowledge", "skills", "lessons", "record", "fleet"):
        assert f'data-source="{source}"' in body
    assert 'data-source="knowledge" data-available="true"' in body
    assert 'data-source="fleet" data-available="false"' in body
    assert 'data-count="collections">2<' in body
    assert 'data-count="skills">12<' in body and 'data-count="verified">3<' in body
    assert 'data-count="models">2<' in body and 'data-count="lines">9<' in body
    assert 'data-count="entries">40<' in body and 'data-count="approvals">10<' in body
    assert "Finance · Policies" in body
    assert 'data-at-rest="true"' in body and 'data-per-tenant="false"' in body
    assert 'data-tenant-floored="true"' in body and 'data-pooled="false"' in body
    assert "floored to the active tenant" not in body
    assert "only looks at this workspace’s own information" in body
    assert "4 of 5 sources answering" in body


def test_recall_form_is_labelled_and_bounded(monkeypatch) -> None:
    body = _app(monkeypatch).get(page.PAGE_PATH).text
    assert 'id="ctx-recall-form"' in body
    assert 'for="ctx-query"' in body and 'id="ctx-query"' in body and 'maxlength="2000"' in body
    assert 'for="ctx-domain"' in body and '<select class="select" id="ctx-domain"' in body
    assert '<option value="">All areas</option>' in body
    assert 'for="ctx-k"' in body and 'id="ctx-k"' in body and 'data-max="50"' in body
    assert '<option value="50">Up to 50</option>' in body
    for source in ("knowledge", "skills", "lessons", "record", "fleet"):
        assert f'name="sources" value="{source}"' in body
    assert 'id="ctx-recall-state"' in body and 'role="status"' in body


def test_recent_reads_and_writes_come_from_the_audit_tail_newest_first(monkeypatch) -> None:
    body = _app(monkeypatch).get(page.PAGE_PATH).text
    # only the cortex kinds, newest first, with caller / per-source / denied / time
    assert "read_file" not in body
    first = body.index('data-kind="cortex_deposit"')
    assert first < body.rindex('data-kind="cortex_recall"')
    assert 'title="user:jo">jo<' in body and 'title="agent:copilot">copilot<' in body
    assert "1 Jan 2026, 00:00 UTC" in body
    assert "Documents: 2" in body and "Skills: 1" in body
    assert "<strong>Outside assistants&#39; notes</strong>: fleet memory answers enrolled external agents" in body
    assert "Agent not on the roster" in body
    assert "3 results" in body and " ms" not in body


def test_recent_reads_need_the_audit_permission(monkeypatch) -> None:
    def _never(n):
        raise AssertionError("the audit tail must not be read without the audit permission")

    client = _app(monkeypatch, audit=False, tail=[])
    monkeypatch.setattr(page, "_audit_tail", _never)
    body = client.get(page.PAGE_PATH).text
    assert 'id="ctx-recent-locked"' in body
    assert 'data-kind="cortex_recall"' not in body


def test_empty_tail_says_so(monkeypatch) -> None:
    body = _app(monkeypatch, tail=[]).get(page.PAGE_PATH).text
    assert 'id="ctx-recent-empty"' in body


def test_a_broken_status_degrades_instead_of_failing_the_page(monkeypatch) -> None:
    client = _app(monkeypatch)

    def _boom():
        raise RuntimeError("world model unavailable")

    monkeypatch.setattr(page, "_status", _boom)
    response = client.get(page.PAGE_PATH)
    assert response.status_code == 200
    assert "world model unavailable" not in response.text
    assert "could not check its knowledge sources" in response.text
    assert "0 of 5 sources answering" in response.text


def test_page_is_view_gated(monkeypatch) -> None:
    assert _app(monkeypatch, permitted=False).get(page.PAGE_PATH).status_code == 403


def test_unknown_query_params_are_404(monkeypatch) -> None:
    assert _app(monkeypatch).get(page.PAGE_PATH + "?debug=1").status_code == 404
    assert _app(monkeypatch).get(page.PAGE_PATH + "?theme=light").status_code == 200


def test_page_requires_a_template_authority() -> None:
    with pytest.raises(TypeError):
        page.create_cortex_page_router(object())  # type: ignore[arg-type]


def test_page_is_a_hidden_read_only_compatibility_console() -> None:
    paths = [p["path"] for p in ui_visibility.PAGES]
    assert paths.index("/knowledge-access") == paths.index("/learning") - 1
    entry = next(p for p in ui_visibility.PAGES if p["path"] == page.PAGE_PATH)
    assert entry["label"] == "Cortex memory diagnostics"
    assert entry["group"] == "Advanced tools"
    assert entry["floor"] == "view" and entry["default"] == "view"
    assert entry["in_nav"] is False
    sprite = (Path(page.__file__).parent / "templates" / "_icon_sprite.html").read_text(encoding="utf-8")
    assert f'id="i-{entry["icon"]}"' in sprite
    # Compatibility is reachable directly but does not duplicate the primary
    # Knowledge destination in the sidebar.
    for role in (None, "viewer", "auditor", "operator", "admin"):
        hrefs = {ln["href"] for g in ui_visibility.nav_groups(role) for ln in g["links"]}
        assert page.PAGE_PATH not in hrefs, role


def test_nav_entry_is_rendered_and_marked_current(monkeypatch) -> None:
    body = _app(monkeypatch).get(page.PAGE_PATH).text
    assert '<a href="/cortex"' not in body
    assert 'aria-current="page"' not in body


def test_template_and_rendered_page_pass_the_static_a11y_audit(monkeypatch) -> None:
    from maverick.a11y_audit import audit_file, audit_html
    template = Path(page.__file__).parent / "templates" / "cortex.html"
    assert audit_file(template) == []
    rendered = _app(monkeypatch).get(page.PAGE_PATH).text
    assert audit_html(rendered) == []
    assert "<th>" not in rendered  # every header cell is scoped


def test_mounted_page_renders_through_the_dashboard_shell(monkeypatch, tmp_path) -> None:
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    try:
        client = TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
        response = client.get(page.PAGE_PATH)
        assert response.status_code == 200, response.text[:400]
        assert "<title>Cortex memory diagnostics · Lightwork</title>" in response.text
        assert "style-src 'self' 'nonce-" in response.headers["content-security-policy"]
        assert '<a href="/cortex"' not in response.text
        assert '<a href="/knowledge-access"' in response.text
        # the real kernel status: every source is on the page, answering or not
        for source in ("knowledge", "skills", "lessons", "record", "fleet"):
            assert f'data-source="{source}"' in response.text
        # auth off: the audit tail is readable and, with nothing recalled yet, empty
        assert 'id="ctx-recent-empty"' in response.text
    finally:
        config.reset_config_cache()
        audit_writer._default = None
        audit_writer._defaults.clear()
        dash_app._world_cache.clear()


def test_cortex_script_is_served_same_origin(monkeypatch) -> None:
    """The page's script is an explicit route on the real app (the dashboard
    serves no static directory), so a missing route would leave the lattice
    and the recall console silently blank."""
    from maverick_dashboard.app import app as real_app
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "secret-token")  # pragma: allowlist secret
    client = TestClient(real_app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1",
                                           "Authorization": "Bearer secret-token"})
    r = client.get("/static/lightwork-cortex.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/javascript")
    assert b"cortex-lattice" in r.content


def test_page_speaks_plainly_and_offers_to_turn_sources_on(monkeypatch) -> None:
    from test_support.plain_language import developer_terms

    monkeypatch.setattr(page, "_departments", lambda: [{"value": "finance", "label": "Finance"}])
    body = _app(monkeypatch).get(page.PAGE_PATH).text
    assert developer_terms(body) == []
    for label in ("Documents", "Skills", "Lessons", "Decision history"):
        assert f"> {label}</label>" in body
    assert '<option value="finance">Finance</option>' in body
    # fleet is off: an administrator gets a confirmed turn-on button that uses
    # the existing admin-only feature switch
    assert 'data-cortex-switch="fleet_memory"' in body
    assert 'data-cortex-switch="self_harness"' not in body  # lessons already on
    status = dict(_STATUS, sources=dict(_STATUS["sources"], knowledge={"available": False}))
    body = _app(monkeypatch, status=status).get(page.PAGE_PATH).text
    assert 'href="/knowledge-access">Add or connect documents' in body


def test_turn_on_buttons_are_hidden_without_global_admin(monkeypatch) -> None:
    monkeypatch.setattr(page, "has_global_permission", lambda request, perm: False)
    body = _app(monkeypatch).get(page.PAGE_PATH).text
    assert "data-cortex-switch=" not in body
    assert "Ask an administrator to turn this on." in body


def test_a_source_error_is_plain(monkeypatch) -> None:
    status = dict(_STATUS, sources=dict(_STATUS["sources"], skills={"error": "OperationalError: no such table"}))
    body = _app(monkeypatch, status=status).get(page.PAGE_PATH).text
    assert "OperationalError" not in body
    assert "This source could not be reached right now." in body
