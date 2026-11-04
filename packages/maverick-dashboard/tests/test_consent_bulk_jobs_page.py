from __future__ import annotations

import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import consent_bulk_jobs_page as page

ROUTE = "/consent/bulk-jobs"
PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    return templates


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_global_permission", lambda _request, _permission: True)
    app = FastAPI()
    app.include_router(page.create_consent_bulk_jobs_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_workbench_is_store_free_closed_and_copilot_enabled(client: TestClient) -> None:
    response = client.get(ROUTE)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    csp = response.headers["content-security-policy"]
    for directive in (
        "default-src 'none'",
        "base-uri 'none'",
        "connect-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    ):
        assert directive in csp
    from test_support.plain_language import developer_terms

    assert "Bulk consent changes" in response.text
    assert 'id="cbj-operations" disabled' in response.text
    assert "Checking whether bulk changes are available" in response.text
    assert "Checking status never adds to the allowance" in response.text
    assert 'data-api-base="/api/v1/consent/bulk-jobs"' in response.text
    assert 'data-copilot-page="/consent/bulk-jobs"' in response.text
    assert 'src="/static/lightwork-copilot.js' in response.text
    assert 'src="/static/lightwork-consent-bulk-jobs.js"' in response.text
    assert 'src="/static/lightwork-consent-workbench.js"' in response.text
    # No page-local style block is left; the CSP nonce is only for themes.
    parser = _Markup()
    parser.feed(response.text)
    assert [attrs for tag, attrs in parser.tags if tag == "style"] == []
    assert "'nonce-" in csp
    assert developer_terms(response.text) == []


def test_jobs_are_rows_with_buttons_and_the_export_downloads_from_its_row(
    client: TestClient,
) -> None:
    response = client.get(ROUTE)
    assert 'id="cbj-job-list"' in response.text
    source = (
        PACKAGE / "static" / "lightwork-consent-bulk-jobs.js"
    ).read_text(encoding="utf-8")
    for label in ('label: "Details"', 'label: "Download"', 'label: "Run now"', 'label: "Cancel"'):
        assert label in source
    assert 'global.location.assign(apiBase + "/" + encodeURIComponent(j.job_id) + "/download")' in source
    # Versions come from the chosen row, never from a typed field.
    assert "expected_revision: job.revision" in source
    assert "expected_revision: state.credit.revision" in source
    assert "download.href" not in source


@pytest.mark.parametrize(
    ("permissions", "audit", "admin"),
    (
        (frozenset(), False, False),
        (frozenset({"audit"}), True, False),
        (frozenset({"admin"}), False, True),
        (frozenset({"audit", "admin"}), True, True),
    ),
)
def test_page_renders_exact_global_permission_controls(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    permissions: frozenset[str],
    audit: bool,
    admin: bool,
) -> None:
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, permission: permission in permissions,
    )
    parser = _Markup()
    parser.feed(client.get(ROUTE).text)
    by_id = {
        attrs["id"]: attrs
        for _tag, attrs in parser.tags
        if isinstance(attrs.get("id"), str)
    }
    shell = by_id["consent-bulk-jobs-shell"]
    assert (shell["data-can-audit"] == "true") is audit
    assert (shell["data-can-admin"] == "true") is admin
    for button in ("cbj-new", "cbj-add-credits", "cbj-run-next", "cbj-recover", "cbj-purge"):
        assert ("disabled" not in by_id[button]) is admin


def test_forms_collect_only_closed_opaque_bulk_job_fields(client: TestClient) -> None:
    parser = _Markup()
    parser.feed(client.get(ROUTE).text)
    forms = [attrs for tag, attrs in parser.tags if tag == "form"]
    names = {
        value
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"}
        if isinstance((value := attrs.get("name")), str)
    }
    assert forms and all("action" not in form for form in forms)
    for required in (
        "operation",
        "receipt_limit",
        "policy_key",
        "purpose_id",
        "reason_code",
        "identity_kind",
        "scheduled_for",
        "idempotency_key",
    ):
        assert required in names
    # Nothing a person cannot know is typed: no JSON items, job IDs or versions.
    for typed in ("items_json", "job_id", "expected_revision", "amount", "limit"):
        assert typed not in names
    for forbidden in (
        "tenant_id",
        "actor_sha256",
        "principal_ref",
        "worker_sha256",
        "lease_owner_sha256",
        "database_path",
        "storage_path",
        "recovery_path",
        "provider",
        "executor",
        "initial_credits",
    ):
        assert forbidden not in names


def test_page_rejects_query_material_and_requires_tenant(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert client.get(f"{ROUTE}?profile_id=caller-selected").status_code == 404
    assert client.get(f"{ROUTE}?tenant_id=caller-selected").status_code == 404
    assert client.get(f"{ROUTE}?theme=light&density=compact").status_code == 200

    def missing_tenant() -> None:
        raise page.HTTPException(
            status_code=409,
            detail="select an active tenant before using consent bulk jobs",
        )

    monkeypatch.setattr(page, "_tenant_selected", missing_tenant)
    assert client.get(ROUTE).status_code == 409


def test_custom_theme_uses_same_csp_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    import maverick.config as config

    monkeypatch.setattr(config, "load_config", lambda: {
        "dashboard": {"themes": {"custom": {
            "bg": "#000", "panel": "#111", "text": "#fff", "accent": "#0f0",
        }}},
    })
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_global_permission", lambda _request, _permission: True)
    app = FastAPI()
    app.include_router(page.create_consent_bulk_jobs_page_router(_templates()))
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]
    assert len(nonces) == 1
    assert "body.theme-custom { --bg: #000; --panel: #111;" in response.text
    assert nonces[0]
    assert f"'nonce-{nonces[0]}'" in response.headers["content-security-policy"]


def test_liquid_glass_client_is_bounded_accessible_and_injection_safe() -> None:
    template = (PACKAGE / "templates" / "consent_bulk_jobs.html").read_text(
        encoding="utf-8"
    )
    source = (
        PACKAGE / "static" / "lightwork-consent-bulk-jobs.js"
    ).read_text(encoding="utf-8")
    for required in (
        'aria-live="polite"',
        "data-copilot-page",
        "About this page’s safeguards",
    ):
        assert required in template
    for required in (
        "MAX_RESPONSE_BYTES = 64 * 1024",
        "MAX_JSON_INPUT_BYTES = 240 * 1024",
        'headers.get("Content-Length")',
        "response.body.getReader()",
        "reader.cancel()",
        "JSON.parse(responseText)",
        'credentials: "same-origin"',
        'cache: "no-store"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        "operations.disabled = true",
        'api("/worker/run-next"',
        'api("/operations/integrity")',
        'api("/operations/recover"',
        'api("/operations/retention/purge"',
        "CW.confirm(",
        "parseItems",
        "exactShape",
    ):
        assert required in source
    for forbidden in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "localStorage",
        "document.cookie",
        "eval(",
        "new Function",
        "global.confirm(",
        "JSON.stringify(value, null, 2)",
    ):
        assert forbidden not in source
    # Only an opaque submission reference survives reload. The storage key is
    # scoped to the authenticated account/workspace; no job payload is stored.
    assert "'lightwork:consent-submission:' + shell.dataset.requestContext" in source
    assert "global.sessionStorage.setItem(recoveryKey, reference)" in source
    # An allowance request keeps its own opaque reference under the same scope.
    assert "allowanceKey = recoveryKey ? recoveryKey + ':allowance' : ''" in source
    assert "global.sessionStorage.setItem(allowanceKey,reference)" in source
    assert source.count("sessionStorage.setItem(") == 2
    assert "global.sessionStorage.removeItem(recoveryKey)" in source


def test_client_script_has_valid_node_syntax() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    source = PACKAGE / "static" / "lightwork-consent-bulk-jobs.js"
    completed = subprocess.run(
        [node, "--check", str(source)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
