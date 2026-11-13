"""Plain words on the catalog pages and shared error pages.

Tool descriptions, agent instructions, template bodies and pack names are
written for agents. People see a plain summary or readable name; the exact
text stays available only inside a collapsed "Technical details".
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard.plain_labels import fill_placeholders, pack_display_name
from maverick_dashboard.tool_summary import plain_tool_summary

from test_support.plain_language import developer_terms, visible_text

HTML = {"Accept": "text/html", "Origin": "http://127.0.0.1"}
_TECHNICAL = re.compile(
    r"(?is)<details\b[^>]*>\s*<summary>\s*Technical details.*?</details>"
)


def _without_technical(html: str) -> str:
    """Drop collapsed "Technical details" disclosures (people open them on purpose)."""
    previous = None
    while previous != html:
        previous, html = html, _TECHNICAL.sub(" ", html)
    return html


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "home" / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_AUTH_REQUIRED"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    original = list(dash_app.app.router.routes)
    yield
    dash_app.app.router.routes[:] = original
    config.reset_config_cache()


def _client() -> TestClient:
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


# ---------- tools ----------

def test_tool_summaries_drop_agent_instructions():
    connector = (
        "ABC Fitness (ABC Trainerize/Ignite) REST. ops get/post/put/delete (writes need confirm). "
        "Auth: ABC_FITNESS_BASE_URL + ABC_FITNESS_TOKEN. [governed: writes simulated]"
    )
    assert plain_tool_summary("abc_fitness", connector) == (
        "Connects to ABC Fitness. Changes it makes need a person's approval."
    )
    assert plain_tool_summary(
        "abuseipdb_read", "AbuseIPDB REST, READ-ONLY (GET). e.g. /api/v2/check. Auth: ABUSEIPDB_TOKEN."
    ) == "Reads information from AbuseIPDB."
    assert plain_tool_summary(
        "fdic", "FDIC BankFind (institutions & financials), READ-ONLY, keyless. e.g. /api/financials?x=1."
    ) == "Reads information from FDIC BankFind."
    assert plain_tool_summary(
        "ordoro", "Ordoro shipping/inventory REST API. ops get/post (writes need confirm). Auth: ORDORO_TOKEN."
    ).startswith("Connects to Ordoro shipping and inventory.")
    # No write verb is named, but the text still says the tool can write.
    assert plain_tool_summary(
        "acme_crm", "Acme CRM. Auth: env ACME_KEY. ops get/list; writes need confirm"
    ) == "Connects to Acme CRM. Changes it makes need a person's approval."
    assert plain_tool_summary("dom_diff", "Structural diff of two HTML snapshots (before/after). Reports x.") == (
        "Structural diff of two HTML snapshots."
    )
    assert plain_tool_summary("http_fetch", "Fetch an HTTP/HTTPS URL. render='markdown'") == (
        "Opens a web page and reads its content."
    )
    odd = plain_tool_summary("payload_compress", "world_model compression helper. op=stats with 'text'.")
    assert odd == "Payload compress. Open Technical details for how agents use it."
    assert plain_tool_summary("empty_tool", "") == "Empty tool. No description given."


def test_tools_page_shows_plain_summaries_and_keeps_raw_text_collapsed(monkeypatch):
    from maverick import sandbox as sandbox_module
    from maverick import tools as tools_module
    from maverick_dashboard import app as dash_app

    raw = ("Acme CRM REST API. ops get/post/put/delete (writes need confirm). e.g. /api/v2/contacts. "
           "Auth: ACME_BASE_URL + ACME_TOKEN (OAuth2 bearer).")
    catalog = [SimpleNamespace(name="acme_crm", description=raw)]
    monkeypatch.setattr(dash_app, "_world", lambda: object())
    monkeypatch.setattr(sandbox_module, "build_sandbox", lambda: object())
    monkeypatch.setattr(tools_module, "base_registry",
                        lambda **_k: SimpleNamespace(all=lambda: list(catalog)))
    page = _client().get("/tools", headers=HTML)
    assert page.status_code == 200
    assert "Connects to Acme CRM." in page.text
    assert "<summary>Technical details</summary>" in page.text and raw in page.text
    plain = _without_technical(page.text)
    assert raw not in plain
    for word in ("ACME_TOKEN", "ops get", "/api/v2", "bearer", "Auth:"):
        assert word not in plain, word
    assert developer_terms(plain) == []
    # People can search by the words they see.
    found = _client().get("/tools", params={"q": "connects to acme"}, headers=HTML)
    assert "Acme crm" in found.text or "Acme CRM" in found.text


# ---------- agents ----------

def test_pack_names_read_like_job_titles():
    assert pack_display_name(
        "aero_airworthiness",
        "You are the Airworthiness specialist for this business (aero_mro seal) -- a vertical.",
    ) == "Airworthiness Specialist"
    assert pack_display_name(
        "gtm_deal_desk", "You are the Deal Desk specialist: enforce the discount matrix."
    ) == "Deal Desk Specialist"
    assert pack_display_name("x_pack", "", "Contract / order-form assembly.") == "Contract / Order-form Assembly"
    assert pack_display_name("ag_crop", "", "") == "Ag Crop"


def test_assessment_agent_picker_is_readable_grouped_and_filterable():
    page = _client().get("/assessments", headers=HTML)
    assert page.status_code == 200
    picker = page.text.split('<select id="as-agent"', 1)[1].split("</select>", 1)[0]
    assert "<optgroup label=" in picker
    labels = re.findall(r"<option value=\"([^\"]+)\">([^<]+)</option>", picker)
    assert len(labels) > 100
    assert all("_" not in label for _value, label in labels)
    assert any("_" in value for value, _label in labels)  # the exact pack name is still sent
    assert 'id="as-agent-filter"' in page.text and 'type="search"' in page.text
    # Job titles such as "API Design Specialist" or "Lease Administrator" are
    # business words; the rest of the page must have no developer words.
    rest = page.text.replace(picker, "")
    assert developer_terms(rest) == []


def test_specialist_list_shows_descriptions_not_agent_instructions():
    page = _client().get("/compartments", params={"q": "aero", "per_page": 25}, headers=HTML)
    assert page.status_code == 200
    plain = _without_technical(page.text)
    assert "seal)" not in plain and "You are the" not in plain
    assert "Airworthiness Specialist" in plain
    assert "<summary>Technical details</summary>" in page.text
    assert "You are the" in page.text  # still available, collapsed
    assert re.search(r"\baero_[a-z]+\b", re.sub(r"(?s)<[^>]+>", " ", plain.split('<main id="content"', 1)[-1])) is None


# ---------- templates ----------

def test_template_blanks_are_readable():
    assert fill_placeholders("Compare {{category}} — {{option_a}} vs {{ option_b }}") == (
        "Compare [Category] — [Option A] vs [Option B]"
    )
    assert fill_placeholders("Migrate {{library}} from {{old_version}} to {{new_version}}") == (
        "Migrate [Library] from [Old Version] to [New Version]"
    )


def test_templates_page_titles_are_plain_and_instructions_are_collapsed():
    page = _client().get("/templates", headers=HTML)
    assert page.status_code == 200
    plain = _without_technical(page.text)
    main = plain.split('<main id="content"', 1)[-1]
    titles = re.findall(r'<p class="tplm__title">([^<]*)</p>', main)
    assert titles
    for title in titles:
        assert "{{" not in title and not re.search(r"\b[a-z]+_[a-z_]+\b", title), title
    assert "Preview the instructions" not in page.text
    assert "read_file" not in plain and "git log" not in plain


# ---------- error pages ----------

def _route(path, detail, status=403):
    from maverick_dashboard import app as dash_app

    async def fail():
        raise HTTPException(status_code=status, detail=detail)

    dash_app.app.add_api_route(path, fail, methods=["GET"])


def test_feature_off_and_named_sign_in_pages_say_what_is_actually_wrong():
    _route("/__off", "Action Center is disabled in Settings or configuration is unavailable.")
    _route("/__named", "Sign in with a named account and select a workspace to use team reviews.")
    _route("/__role", "admin required")
    _route("/__expired", "unauthorized", status=401)
    client = TestClient(__import__("maverick_dashboard.app", fromlist=["app"]).app, base_url="http://127.0.0.1",
                        raise_server_exceptions=False)
    off = client.get("/__off", headers=HTML)
    assert off.status_code == 403
    off_text = visible_text(off.text)
    assert "This page is turned off" in off_text and 'href="/settings#settings-sections"' in off.text
    assert "Permission required" not in off_text and "disabled in Settings" not in off_text
    named = client.get("/__named", headers=HTML)
    assert named.status_code == 403
    named_text = visible_text(named.text)
    assert "Sign in with your own account" in named_text and "Choose a workspace" in named_text
    assert "named account" not in named_text
    role = client.get("/__role", headers=HTML)
    assert role.status_code == 403
    role_text = visible_text(role.text)
    assert "Permission required" in role_text and "admin required" not in role_text
    expired = client.get("/__expired", headers=HTML)
    assert expired.status_code == 401
    expired_text = visible_text(expired.text)
    assert "Your sign-in has expired. Sign in again." in expired_text
    assert "access token" not in expired_text and "session or" not in expired_text
    # API callers keep the exact machine-readable reason.
    assert client.get("/__off", headers={"Accept": "application/json"}).json() == {
        "detail": "Action Center is disabled in Settings or configuration is unavailable."
    }


def test_action_center_turned_off_shows_the_turned_off_page(monkeypatch):
    from maverick_dashboard import action_center_api

    monkeypatch.setattr(action_center_api.config, "get_features", lambda: {"action_center": False})
    monkeypatch.setattr(action_center_api.config, "config_source_errors", lambda **_k: [])
    page = _client().get("/action-center", headers=HTML)
    assert page.status_code == 403
    assert "This page is turned off" in page.text
    assert "Your current role cannot" not in page.text


# ---------- shared navigation and page sources ----------

def test_sidebar_uses_a_plain_name_for_app_consent():
    page = _client().get("/tools", headers=HTML)
    assert "Mobile app consent" in page.text
    assert "Native Consent SDK" not in page.text


def _static(name: str) -> str:
    return (Path(__file__).resolve().parents[1] / "maverick_dashboard" / name).read_text(encoding="utf-8")


def test_vendor_facing_wording_is_plain():
    portal = _static("static/lightwork-third-party-portal.js")
    assert "Choose Yes or No." in portal and "explicit boolean" not in portal
    assert "You've reached the file limit for this request." in portal
    assert "count bound" not in portal
    assert "Questions supported by this digest manifest" not in portal and '"Remove manifest"' not in portal
    onboarding = _static("static/lightwork-vendor-onboarding.js")
    assert "confirm the list of files" in onboarding and "confirm its manifest" not in onboarding


def test_grc_studio_and_pilot_review_use_pickers_not_typed_references():
    studio = _static("templates/no_code_grc_studio.html")
    assert 'id="grcs-collector-choice"' in studio and 'id="grcs-projection-target"' in studio
    assert "Copy the collector" not in studio
    visible = _without_technical(studio)
    for field in ('name="target_revision"', 'name="target_id"'):
        assert field not in visible, field
    # The chosen source's exact reference travels in hidden fields the picker
    # fills; nobody types or reads a fingerprint.
    for field in ("grcs-collector-id", "grcs-collector-version", "grcs-collector-digest"):
        tags = re.findall(r"<input[^>]*\bid=\"" + field + r"\"[^>]*>", visible)
        assert tags and all('type="hidden"' in tag for tag in tags), field
    pilots = _static("templates/outcome_pilots.html")
    assert '<select class="select" id="op-review-reference"' in pilots
    assert "Pilot reference shared by its owner" not in pilots and 'pattern="OPL-' not in pilots
    assert "exclusion receipts" not in pilots
