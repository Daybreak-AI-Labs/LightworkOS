from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import assessment_evidence_autopopulation_page as page

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(
        nav_groups=[],
    )
    return templates


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(page, "_tenant_selected", lambda: True)
    monkeypatch.setattr(page, "require_permission", lambda *_args: None)
    monkeypatch.setattr(page, "has_permission", lambda *_args: True)
    monkeypatch.setattr(page, "has_global_permission", lambda *_args: True)
    app = FastAPI()
    app.include_router(
        page.create_assessment_evidence_autopopulation_page_router(_templates())
    )
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_liquid_glass_workbench_is_store_free_closed_and_copilot_bound(client):
    response = client.get(page.PAGE_PATH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-frame-options"] == "DENY"
    csp = response.headers["content-security-policy"]
    for directive in (
        "default-src 'none'",
        "connect-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "script-src 'self'",
        "style-src 'self'",
    ):
        assert directive in csp
    assert "Suggested assessment answers" in response.text
    assert "fills only unanswered questions" in response.text
    assert f'data-api-base="{page.API_BASE}"' in response.text
    assert f'data-copilot-page="{page.PAGE_PATH}"' in response.text
    assert f'href="{page.STYLE_PATH}"' in response.text
    assert f'src="{page.SCRIPT_PATH}"' in response.text
    context = page.assessment_evidence_copilot_context()
    assert context.path == page.PAGE_PATH
    assert any("never changes" in item for item in context.boundaries)


def test_page_collects_no_tenant_actor_evidence_bytes_or_mapping_authority(client):
    parser = _Markup()
    parser.feed(client.get(page.PAGE_PATH).text)
    names = {
        value
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"}
        if isinstance((value := attrs.get("name")), str)
    }
    assert {"assessment_id", "rationale", "idempotency_key"}.issubset(names)
    # Records and versions come from the lists; nothing is typed.
    for typed in ("proposal_id", "expected_revision", "expected_assessment_revision", "analysis_ids"):
        assert typed not in names
    for forbidden in (
        "tenant_id",
        "actor_ref",
        "artifact_bytes",
        "extracted_text",
        "mapping_authority",
        "supported_answer",
        "retained_until",
        "storage_path",
    ):
        assert forbidden not in names


def test_page_rejects_query_authority_and_requires_selected_tenant(client, monkeypatch):
    assert client.get(f"{page.PAGE_PATH}?tenant_id=attacker").status_code == 404
    assert client.get(f"{page.PAGE_PATH}?theme=light&density=compact").status_code == 200

    monkeypatch.setattr(page, "_tenant_selected", lambda: False)
    missing = client.get(page.PAGE_PATH)
    assert missing.status_code == 200
    assert "Choose a workspace first" in missing.text
    assert page.SCRIPT_PATH not in missing.text


def test_role_gate_disables_every_mutating_form(client, monkeypatch):
    monkeypatch.setattr(page, "has_permission", lambda *_args: False)
    parser = _Markup()
    parser.feed(client.get(page.PAGE_PATH).text)
    disabled_fieldsets = [attrs for tag, attrs in parser.tags if tag == "fieldset" and "disabled" in attrs]
    assert len(disabled_fieldsets) >= 2


def test_page_is_plain_language_with_pickers_and_a_suggestion_list(client):
    import re

    body = client.get(page.PAGE_PATH).text
    main = body.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL))
    banned = re.compile(
        r"\b(tenant|principals?|payload|endpoint|schema|uuid|sha-?256|digest|idempoten\w*|"
        r"revision|json|CAS|proposal id|analysis ids?)\b|/api/v1|HTTP \d{3}",
        re.IGNORECASE,
    )
    assert banned.search(text) is None, banned.search(text)
    assert '<select class="select" id="aep-assessment-id" name="assessment_id"' in body
    assert 'id="aep-analysis-choices"' in body and 'id="aep-queue"' in body
    assert "<textarea" in body and 'name="analysis_ids"' not in body
    for label in ("Suggest answers", "Suggestions", "Approve selected answers", "Reject all suggestions"):
        assert label in text
