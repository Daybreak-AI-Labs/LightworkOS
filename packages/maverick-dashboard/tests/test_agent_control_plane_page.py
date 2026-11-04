from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import agent_control_plane_page as page


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=Path(page.__file__).parent / "templates",
        context_processors=[_theme_context],
    )
    selected.env.globals.update(nav_groups=[])
    return selected


def _app(
    monkeypatch,
    allowed,
    *,
    global_allowed=frozenset(),
    shared_halt: bool = False,
) -> TestClient:
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "has_permission",
                        lambda _request, permission: permission in allowed)
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, permission: permission in global_allowed,
    )
    monkeypatch.setattr(page, "_shared_halt_backend", lambda: shared_halt)
    app = FastAPI()
    app.include_router(page.create_agent_control_plane_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1")


def test_page_is_wired_hardened_and_permission_aware(monkeypatch) -> None:
    response = _app(
        monkeypatch,
        {"operate", "audit"},
        global_allowed={"operate"},
    ).get(page.PAGE_PATH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    csp = response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "style-src 'self' 'nonce-" in csp
    body = response.text
    assert "Agent controls" in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert f'data-api-base="{page.API_BASE}"' in body
    assert page.ASSET_PATH in body
    assert 'data-can-operate="true"' in body
    assert 'data-can-audit="true"' in body
    assert 'data-can-admin="false"' in body
    assert 'data-can-halt="true"' in body
    assert 'data-halt-scope="local"' in body
    # Admin-only verbs are not offered to an operator.
    assert '<option value="contain">' not in body
    assert '<option value="ledger">' in body
    assert 'id="acp-clear-halt" type="button" disabled' in body
    assert 'id="acp-clear-halt" type="button" disabled data-role-disabled="true"' not in body


def test_admin_sees_every_verb(monkeypatch) -> None:
    body = _app(monkeypatch, {"operate", "audit", "admin"}).get(page.PAGE_PATH).text
    assert '<option value="contain"' in body and '<option value="release"' in body
    assert 'data-can-admin="true"' in body


def test_auditor_form_remains_usable_without_mutation_verbs(monkeypatch) -> None:
    body = _app(monkeypatch, {"audit"}).get(page.PAGE_PATH).text

    assert '<option value="suspend"' not in body
    assert '<option value="resume"' not in body
    assert '<option value="contain"' not in body
    assert '<option value="release"' not in body
    assert '<option value="ledger">View history</option>' in body
    assert 'id="acp-verb-controls" disabled' not in body
    assert 'id="acp-attenuate-controls" disabled aria-disabled="true" data-role-disabled="true"' in body


def test_shared_halt_requires_global_admin_and_detection_fails_closed(monkeypatch) -> None:
    tenant_admin = _app(
        monkeypatch,
        {"operate", "admin"},
        shared_halt=True,
    ).get(page.PAGE_PATH).text
    assert 'data-can-halt="false"' in tenant_admin
    assert 'data-halt-scope="cluster"' in tenant_admin
    assert 'id="acp-clear-halt" type="button" disabled data-role-disabled="true"' in tenant_admin

    global_admin = _app(
        monkeypatch,
        {"operate"},
        global_allowed={"admin"},
        shared_halt=True,
    ).get(page.PAGE_PATH).text
    assert 'data-can-halt="true"' in global_admin
    assert 'data-halt-scope="cluster"' in global_admin

    client = _app(monkeypatch, {"operate"})
    monkeypatch.setattr(page, "_shared_halt_backend", lambda: (_ for _ in ()).throw(OSError()))
    unknown = client.get(page.PAGE_PATH).text
    assert 'data-can-halt="false"' in unknown
    assert 'data-halt-scope="unknown"' in unknown


def test_local_halt_ignores_tenant_local_operator_role(monkeypatch) -> None:
    tenant_operator = _app(
        monkeypatch,
        {"operate"},
        global_allowed={"view"},
    ).get(page.PAGE_PATH).text
    assert 'data-can-halt="false"' in tenant_operator
    assert 'data-halt-scope="local"' in tenant_operator

    global_operator = _app(
        monkeypatch,
        set(),
        global_allowed={"operate"},
    ).get(page.PAGE_PATH).text
    assert 'data-can-halt="true"' in global_operator
    assert 'data-halt-scope="local"' in global_operator


def test_agent_console_source_uses_bounded_governed_interactions() -> None:
    package = Path(page.__file__).parent
    source = (package / "static" / "lightwork-agent-control-plane.js").read_text(
        encoding="utf-8"
    )
    template = (package / "templates" / "agent_control_plane.html").read_text(
        encoding="utf-8"
    )
    shared_css = (package / "static" / "lightwork.css").read_text(encoding="utf-8")

    assert "window.prompt(" not in source
    assert "window.confirm(" not in source
    assert "window.mvForm" in source
    assert "window.mvConfirm" in source
    assert 'requestAt("/api/v1/halt"' in source
    assert 'request("/halt"' not in source
    assert "/clear-halt" not in source
    assert 'request("/snapshot?limit=" + rosterLimit + "&offset=" + offset)' in source
    assert "planeRequested" in source and "planeRefreshPromise" in source
    assert "controlPlaneReady" in source and "haltAuthorityReady" in source
    assert "AbortController" in source and "took too long" in source
    assert "response.body.getReader" in source and "utf8ByteLength" in source
    assert 'button.setAttribute("aria-label", label + " " + displayName(row))' in source
    assert "restoreRosterFocus" in source and "rosterHeading.focus()" in source
    assert 'principal.scope = "row"' in source
    assert 'aria-live="polite" aria-atomic="true"' in template
    assert 'class="hero-statebox" role="status" aria-live="polite"' in template
    assert '<caption class="sr-only">' in template
    assert ".acp-form fieldset{border:0;margin:0;min-inline-size:0;padding:0}" in template
    assert 'name="reason" maxlength="200" required' in template
    assert 'name="max_dollars" type="number" min="0.01" max="1000000"' in template
    assert '<select class="select" name="max_wall_seconds">' in template
    assert 'name="principal" maxlength' not in template
    assert template.count('<select class="select" name="principal"') == 2
    assert 'request("/principals/" + verb' in source
    assert 'request("/principals/ledger?" + query.toString())' in source
    assert 'request("/bulk/select"' in source
    assert 'request("/bulk/actions"' in source
    assert "validateFleetSelection" in source
    assert "Press Review group again" in source
    assert 'id="acp-fleet-form"' in template
    assert 'id="acp-fleet-review"' in template
    assert 'id="acp-fleet-apply"' in template
    assert 'id="acp-fleet-selection-state"' in template
    assert "Act on a group" in template
    assert "--text-muted: var(--muted);" in shared_css


def test_unknown_query_params_are_404(monkeypatch) -> None:
    assert _app(monkeypatch, set()).get(page.PAGE_PATH + "?debug=1").status_code == 404


def test_page_requires_a_template_authority() -> None:
    import pytest
    with pytest.raises(TypeError):
        page.create_agent_control_plane_page_router(object())  # type: ignore[arg-type]


_BANNED = re.compile(
    r"\b(tenant|principals?|payload|endpoint|schema|uuid|sha-?256|digest|"
    r"idempoten\w*|revision|json|yaml|toml|ledger|attenuat\w*|halt|"
    r"fail[- ]soft|control[- ]plane)\b|\[[a-z_]+\]|/api/v1|HTTP \d{3}",
    re.IGNORECASE,
)


def _visible_text(html: str) -> str:
    main = html.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL | re.IGNORECASE)
    return re.sub(r"<[^>]+>", " ", main)


def test_page_uses_plain_language_selectors_and_row_actions(monkeypatch) -> None:
    body = _app(
        monkeypatch,
        {"operate", "audit", "admin"},
        global_allowed={"operate"},
    ).get(page.PAGE_PATH).text
    text = _visible_text(body)
    assert _BANNED.search(text) is None, _BANNED.search(text)
    for label in (
        "Agents and people", "Reload list", "Act on one agent or person",
        "Limit an outside agent", "Act on a group", "Review group",
        "Stop all agents now", "Resume all work", "Technical details",
    ):
        assert label in text
    # Choices come from the loaded list, never typed identifiers or seconds.
    assert 'id="acp-verb-principal"' in body and 'id="acp-attenuate-principal"' in body
    assert 'id="acp-fleet-scope"' in body and 'name="tenant"' not in body
    assert 'name="release_after_seconds" type="number"' not in body
    assert 'data-auto-reference type="hidden" name="idempotency_key"' in body


def test_group_actions_are_bound_to_the_active_workspace(monkeypatch) -> None:
    import maverick.paths as paths

    monkeypatch.setattr(paths, "current_tenant_id_strict", lambda: "acme")
    body = _app(monkeypatch, {"operate"}).get(page.PAGE_PATH).text
    assert 'data-workspace-scope="true"' in body and 'data-workspace-value="acme"' in body

    def _broken() -> str:
        raise RuntimeError("tenant boundary unreadable")

    monkeypatch.setattr(paths, "current_tenant_id_strict", _broken)
    body = _app(monkeypatch, {"operate"}).get(page.PAGE_PATH).text
    assert 'data-workspace-scope="false"' in body and 'data-workspace-value=""' in body
