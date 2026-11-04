from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import no_code_grc_studio_page as page


def templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=Path(page.__file__).parent / "templates",
        context_processors=[_theme_context],
    )
    selected.env.globals.update(nav_groups=[])
    return selected


def test_page_is_list_driven_plain_and_permission_aware(monkeypatch) -> None:
    selected_templates = templates()
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(
        page, "has_permission", lambda _request, permission: permission == "operate"
    )
    monkeypatch.setattr(
        page, "has_global_permission", lambda _request, permission: permission == "audit"
    )
    app = FastAPI()
    app.include_router(page.create_no_code_grc_studio_page_router(selected_templates))
    response = TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH)
    assert response.status_code == 200
    body = response.text
    assert "Compliance studio" in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert page.ASSET_PATH in body
    assert 'data-can-operate="true"' in body
    assert 'data-can-audit="true"' in body
    assert 'data-can-admin="false"' in body
    # The register is a table the script fills on load; actions live on each row.
    assert 'id="grcs-version-list"' in body
    assert 'id="grcs-builder-form"' in body
    for composer_control in (
        "grcs-add-object",
        "grcs-add-field",
        "grcs-add-form",
        "grcs-add-rule",
        "grcs-add-binding",
        "grcs-add-view",
    ):
        assert f'id="{composer_control}"' in body
    # Record types and fields are picked from lists, never typed as identifiers.
    assert 'id="grcs-field-object"' in body and "grcs-object-select" in body
    assert 'id="grcs-projection-form"' in body
    assert 'id="grcs-retention-purge"' in body
    assert 'id="grcs-backup-list"' in body
    # Administrator-only controls are disabled for this caller.
    assert re.search(r'id="grcs-retention-purge"[^>]*disabled', body)
    assert re.search(r'id="grcs-import"[^>]*disabled', body)
    for removed in (
        "Studio ID",
        "Operation ID",
        "blueprint_json",
        "envelope_json",
        "Expected integrity",
        "Pointer revision",
        "Backup ID",
    ):
        assert removed not in body
    main = body.split('<main id="content"', 1)[1].split("</main>", 1)[0]
    visible = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", main)
    assert not re.search(
        r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|idempoten\w*|"
        r"json|revision|authority|projection|opaque)\b|/api/v1",
        visible,
        re.IGNORECASE,
    ), visible
    assert "Content-Security-Policy" in response.headers
    assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]


def test_page_rejects_unknown_query_parameters(monkeypatch) -> None:
    selected_templates = templates()
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    app = FastAPI()
    app.include_router(page.create_no_code_grc_studio_page_router(selected_templates))
    assert (
        TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH + "?return_to=https://attacker.invalid").status_code
        == 404
    )


def test_shipped_app_mounts_page_api_and_private_asset(monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "test-tenant")
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get(page.PAGE_PATH).status_code == 200
    assert client.get(f"{page.API_BASE}/status").status_code == 200
    asset = client.get(page.ASSET_PATH)
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "no-store, private, max-age=0"
    assert asset.headers["x-content-type-options"] == "nosniff"


def test_turned_off_studio_shows_its_gate_instead_of_loaders(monkeypatch) -> None:
    from maverick_dashboard import module_activation

    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "has_permission", lambda *_: True)
    monkeypatch.setattr(page, "has_global_permission", lambda *_: True)
    app = FastAPI()
    app.include_router(page.create_no_code_grc_studio_page_router(templates()))
    for enabled in (False, True):
        monkeypatch.setattr(module_activation, "module_activation_enabled", lambda _section, enabled=enabled: enabled)
        body = TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH).text
        main = body[body.index('<div class="grcs-shell"'):body.index(page.ASSET_PATH)]
        assert f'data-module-enabled="{"true" if enabled else "false"}"' in main
        if enabled:
            assert "data-module-gate" not in main and "Loading your blueprints…" in main
            continue
        # The gate follows the title (and shows an ampersand, not "&amp;amp;");
        # the availability panel is hidden and no loader says "Loading".
        assert main.index('class="page-title hero-title"') < main.index("data-module-gate")
        assert "Tech Risk &amp; Compliance" in main and "&amp;amp;" not in main
        assert '<section class="panel" aria-labelledby="grcs-status-title" hidden>' in main
        assert "Loading" not in main
        assert "Blueprints appear here once the studio is turned on." in main
        assert "Backups appear here once the studio is turned on." in main
