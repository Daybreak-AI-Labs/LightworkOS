from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.a11y_audit import audit_html
from maverick_dashboard.third_party_collaboration_portal import (
    create_third_party_collaboration_portal_router,
)

PORTAL = "portal_ref_1234567890"
ROUTE = f"/api/v1/external/third-party-collaboration/{PORTAL}/portal"
PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"
# Words an outside supplier must never meet on this page.
BANNED = re.compile(
    r"\b(mime|digest|manifests?|bytes?|sha-?256|schema|payload|json|boolean|idempotency)\b",
    re.IGNORECASE,
)


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.text: list[str] = []
        self.technical: list[str] = []
        self.outside: list[str] = []
        self._details_depth = 0
        self._summary: list[str] = []
        self._in_summary = False
        self._technical_stack: list[bool] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        if tag == "details":
            self._technical_stack.append(False)
        if tag == "summary":
            self._in_summary = True
            self._summary = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "summary":
            self._in_summary = False
            if self._technical_stack and "".join(self._summary).strip() == "Technical details":
                self._technical_stack[-1] = True
        if tag == "details" and self._technical_stack:
            self._technical_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._in_summary:
            self._summary.append(data)
        self.text.append(data)
        if any(self._technical_stack):
            self.technical.append(data)
        else:
            self.outside.append(data)


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(create_third_party_collaboration_portal_router())
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_portal_is_a_constant_no_store_same_origin_shell() -> None:
    client = _client()
    response = client.get(ROUTE)
    alternate = client.get(
        "/api/v1/external/third-party-collaboration/alternate_ref_123456789/portal"
    )

    assert response.status_code == 200
    assert alternate.status_code == 200
    assert response.content == alternate.content
    assert PORTAL not in response.text
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

    script = client.get(f"{ROUTE}/assets/client.js")
    stylesheet = client.get(f"{ROUTE}/assets/styles.css")
    assert script.status_code == 200
    assert stylesheet.status_code == 200
    assert script.headers["content-type"].startswith("text/javascript")
    assert stylesheet.headers["content-type"].startswith("text/css")
    for asset in (script, stylesheet):
        assert asset.headers["cache-control"] == "no-store, private, max-age=0"
        assert asset.headers["x-content-type-options"] == "nosniff"
        assert asset.headers["referrer-policy"] == "no-referrer"


def test_portal_rejects_query_tenant_headers_and_invalid_references_without_a_shell() -> None:
    client = _client()

    for response in (
        client.get(f"{ROUTE}?credential=do-not-accept"),
        client.get(ROUTE, headers={"X-Lightwork-Tenant": "tenant-a"}),
        client.get(ROUTE, headers={"X-Maverick-Tenant": "tenant-a"}),
        client.get(ROUTE, headers={"X-Tenant-Id": "tenant-a"}),
        client.get(f"{ROUTE}/assets/client.js?tenant=tenant-a"),
        client.get(
            f"{ROUTE}/assets/styles.css",
            headers={"X-Lightwork-Tenant": "tenant-a"},
        ),
        client.get("/api/v1/external/third-party-collaboration/short/portal"),
        client.get("/api/v1/external/third-party-collaboration/invalid.reference.123/portal"),
    ):
        assert response.status_code == 404
        assert "Supplier Questionnaire" not in response.text


def test_portal_markup_has_only_closed_supplier_controls_and_one_file_chooser() -> None:
    response = _client().get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)

    selectors: list[str] = []
    scripts: list[dict[str, str | None]] = []
    stylesheets: list[dict[str, str | None]] = []
    forms: list[dict[str, str | None]] = []
    inputs: list[dict[str, str | None]] = []
    for tag, attrs in parser.tags:
        if tag in {"input", "select", "textarea"}:
            selectors.extend(
                value.lower()
                for name in ("id", "name")
                if isinstance((value := attrs.get(name)), str)
            )
        if tag == "input":
            inputs.append(attrs)
        if tag == "script":
            scripts.append(attrs)
        if tag == "link" and attrs.get("rel") == "stylesheet":
            stylesheets.append(attrs)
        if tag == "form":
            forms.append(attrs)

    assert scripts == [{"defer": None, "src": "portal/assets/client.js"}]
    assert stylesheets == [{"rel": "stylesheet", "href": "portal/assets/styles.css"}]
    assert all("action" not in form for form in forms)
    input_types = [attrs.get("type") for attrs in inputs]
    assert sorted(input_types) == ["checkbox", "checkbox", "file", "password"]
    file_input = next(attrs for attrs in inputs if attrs.get("type") == "file")
    assert "multiple" in file_input and "hidden" in file_input
    assert file_input["aria-label"] == "Choose evidence files from your computer"
    for selector in selectors:
        for forbidden in (
            "tenant",
            "provider",
            "risk-score",
            "risk_score",
            "scoring",
            "approval",
            "principal",
            "size",
            "sha",
            "media",
        ):
            assert forbidden not in selector
    for phrase in (
        "Supplier Questionnaire",
        "Access code",
        "Open my request",
        "Evidence Files",
        "Add files",
        "Save my answers",
        "Send my answers",
        "Close and sign out",
        "Confirm and Send",
        "About this page's safeguards",
    ):
        assert phrase in response.text


def test_supplier_page_has_no_developer_words_outside_technical_details() -> None:
    response = _client().get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    visible = " ".join(" ".join(parser.text).split())

    assert BANNED.search(response.text) is None, BANNED.search(response.text)
    assert BANNED.search(visible) is None
    for leftover in ("credential", "manifest", "attest", "respondent", "revision", "contract"):
        assert leftover not in visible.lower()
    technical = " ".join(" ".join(parser.technical).split())
    for label in ("Request reference", "Notice fingerprint", "Confirmation code"):
        assert label in technical
        assert label in visible
    outside = " ".join(" ".join(parser.outside).split()).lower()
    assert "reference" not in outside
    assert "fingerprint" not in outside
    assert '<details class="technical">' in response.text
    assert "<details class=\"technical\" open" not in response.text


def test_supplier_page_passes_the_dashboard_accessibility_audit() -> None:
    response = _client().get(ROUTE)
    assert audit_html(response.text) == []
    parser = _Markup()
    parser.feed(response.text)
    labelled = {attrs.get("for") for tag, attrs in parser.tags if tag == "label"}
    for tag, attrs in parser.tags:
        if tag in {"input", "select", "textarea"}:
            assert attrs.get("id") in labelled or attrs.get("aria-label"), attrs
    status = next(attrs for tag, attrs in parser.tags if attrs.get("id") == "portal-status")
    assert status["role"] == "status"
    assert status["aria-live"] == "polite"


def test_portal_client_has_no_persistent_credential_or_raw_document_channel() -> None:
    source = (PACKAGE / "static" / "lightwork-third-party-portal.js").read_text(encoding="utf-8")
    css = (PACKAGE / "static" / "lightwork-third-party-portal.css").read_text(encoding="utf-8")

    for forbidden in (
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "URLSearchParams",
        "FileReader",
        "FormData",
        "arrayBuffer",
        "crypto.subtle",
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "window.confirm",
        "window.alert",
        "window.prompt",
        "'HTTP '",
        "err.message",
    ):
        assert forbidden not in source
    for required in (
        "Authorization: `ThirdPartyInvitation ${state.credential}`",
        'cache: "no-store"',
        'credentials: "omit"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        'portalRequest("/contract", "GET")',
        'portalRequest("/draft", "PUT", body)',
        'portalRequest("/finalize", "POST", body)',
        'portalRequest("/evidence", "POST", file, {',
        'headers["Content-Type"] = "application/octet-stream"',
        "validateContract(raw)",
        "validateEvidenceReceipt(raw, state.contract.artifact_policy)",
        "attested: true",
        "expected_revision: state.contract.draft_revision",
        "expected_draft_revision: state.contract.draft_revision",
    ):
        assert required in source
    assert "tenant_id" not in source
    assert "provider_id" not in source
    assert "risk_score" not in source
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "forced-colors" in css
