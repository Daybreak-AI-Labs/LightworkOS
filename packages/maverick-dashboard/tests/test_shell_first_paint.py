"""The page shell paints after one stylesheet request.

On a phone, first paint waited for three render-blocking stylesheets, each
paying its own round trip. The shell head now links one: ``lightwork.css``,
which carries the preference and translation rules too. The Copilot and its
native controls load deferred, first among deferred scripts, so they no longer
compete with the stylesheet; ``lightwork-ui.js`` and the localization runtime
stay synchronous because inline page scripts and the first paint use them.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

STATIC = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
TEMPLATES = STATIC.parent / "templates"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _page(path: str) -> str:
    from maverick_dashboard.app import app

    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(path)
    assert response.status_code == 200, path
    return response.text


def _head(html: str) -> str:
    return html[html.index("<head"):html.index("</head>")]


@pytest.mark.parametrize("path", ["/overview", "/chat", "/settings"])
def test_the_shell_head_requests_one_stylesheet(path):
    links = re.findall(r'<link rel="stylesheet" href="([^"]+)"', _head(_page(path)))
    assert len(links) == 1 and links[0].startswith("/static/lightwork.css"), links


def test_the_one_stylesheet_carries_the_preference_and_translation_rules():
    css = (STATIC / "lightwork.css").read_text(encoding="utf-8")
    for rule in (".preference-grid {", ".prefs__panel { max-height: min(80dvh, 40rem)",
                 ".active-workspace-banner { margin: 0 var(--space-3) var(--space-3);",
                 "[data-product-copy]{unicode-bidi:isolate}", ".locale-coverage{",
                 '[dir="rtl"] pre[lang="en"]'):
        assert rule in css, rule
    # The cascade order of the three old files is kept: preferences first,
    # the design system, then the translation rules last.
    assert css.index(".preference-grid {") < css.index(":root {")
    assert css.index("[data-product-copy]{unicode-bidi:isolate}") > css.index(".chats__empty")
    assert not (STATIC / "lightwork-preferences.css").exists()
    assert not (STATIC / "lightwork-i18n.css").exists()
    for template in TEMPLATES.glob("*.html"):
        source = template.read_text(encoding="utf-8")
        assert "lightwork-preferences.css" not in source and "lightwork-i18n.css" not in source, template.name


@pytest.mark.parametrize("path", ["/overview", "/chat"])
def test_copilot_scripts_load_after_the_page_not_with_it(path):
    # They shared a slow phone link's bandwidth with the stylesheet and the
    # first paint. lightwork-ui.js loads them when the page is idle or the
    # Copilot is opened (tests/js/copilot_lazy_load.test.js), in this order.
    page = _page(path)
    tags = re.findall(r"<script\b[^>]*>", page)
    for name in ("lightwork-product-operations.js", "lightwork-copilot.js"):
        assert not [tag for tag in tags if name in tag], name
    fab = re.search(r'<button[^>]*id="mv-copilot-fab"[^>]*>', page).group(0)
    operations = re.search(r'data-operations-src="(/static/lightwork-product-operations\.js\?v=[^"]+)"', fab)
    copilot = re.search(r'data-copilot-src="(/static/lightwork-copilot\.js\?v=[^"]+)"', fab)
    assert operations and copilot, fab
    assert "window.mvLoadCopilot = load;" in (STATIC / "lightwork-ui.js").read_text(encoding="utf-8")
    # Inline page scripts call these as the page parses: they stay synchronous.
    for name in ("lightwork-ui.js", "lightwork-i18n.js"):
        tag = re.search(rf"<script\b[^>]*{re.escape(name)}[^>]*>", page).group(0)
        assert " defer" not in tag and " async" not in tag, tag


@pytest.mark.parametrize("path", ["/overview", "/chat"])
def test_the_scripts_the_first_paint_waits_for_are_requested_first(path):
    # On a slow phone link the responses share one connection's bandwidth in
    # the order they were asked for. lightwork-ui.js and lightwork-i18n.js are
    # parser-blocking at the end of the page, so their requests go out right
    # after the stylesheet, before the font.
    head = _head(_page(path))
    stylesheet = head.index('<link rel="stylesheet" href="/static/lightwork.css')
    ui = head.index('<link rel="preload" as="script" href="/static/lightwork-ui.js')
    i18n = head.index('<link rel="preload" as="script" href="/static/lightwork-i18n.js')
    font = head.index('<link rel="preload" href="/static/fonts/manrope-var.woff2"')
    assert stylesheet < ui < font and i18n < font


def test_a_task_conversation_is_visible_from_its_first_paint():
    # The conversation faded in from opacity 0 over 0.4 s, so the task page's
    # largest text (the request) counted as painted 0.4 s late on phones.
    # It still slides in, but is never invisible.
    source = (TEMPLATES / "chat_goal.html").read_text(encoding="utf-8")
    keyframes = re.search(r"@keyframes convoIn \{(.*?)\}\s*\}", source, re.DOTALL)
    assert keyframes is not None
    assert "opacity" not in keyframes.group(1)


@pytest.mark.parametrize("path", ["/approvals", "/security"])
def test_the_assessment_review_code_is_a_cached_file_not_page_text(path):
    # Its 39 KB of code was written into every page with the review pop-out,
    # so a phone downloaded and parsed it before the first paint, on every
    # visit. It is one deferred, cached file now; the pop-out's markup stays.
    page = _page(path)
    assert 'id="arv-dialog"' in page
    assert "window.mvAssessmentReview.open(id): fetch" not in page
    tags = re.findall(r'<script\b[^>]*lightwork-assessment-review\.js[^>]*>', page)
    assert len(tags) == 1 and " defer" in tags[0], tags
    assert "window.mvAssessmentReview = { open: open };" in (
        STATIC / "lightwork-assessment-review.js").read_text(encoding="utf-8")


def test_approval_rows_are_shaped_before_the_review_code_runs():
    # The approvals queue still shapes its rows as the page parses (no shift
    # after the first paint); only the click needs the deferred review code.
    source = (TEMPLATES / "_approvals_queue.html").read_text(encoding="utf-8")
    assert "if (!window.mvAssessmentReview) return;" not in source
    assert "if (!document.getElementById('arv-dialog')) return;" in source
    assert "if (window.mvAssessmentReview) window.mvAssessmentReview.open(assessmentId);" in source


def test_the_brand_mark_is_a_small_download():
    # It loads beside the stylesheet on every page, sharing a slow phone
    # link before the first paint. 256 colours look the same at 30 px.
    data = (STATIC / "daybreak-mark.png").read_bytes()
    assert len(data) < 12_000
