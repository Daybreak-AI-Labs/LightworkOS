"""One shared loading state (mvLoading) instead of page-made "Loading…" text.

Pages wrote "Loading…" into a region themselves: it flashed for a few frames
on a quick answer, stayed forever when a request stalled, and never marked the
region busy. mvLoading in lightwork-ui.js shows its words only after 300 ms,
keeps them 500 ms once shown, sets aria-busy, and turns a stalled wait into
the plain error with Try again. These checks keep the migrated loaders on it.
"""
from __future__ import annotations

from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


def _read(relative: str) -> str:
    return (PACKAGE / relative).read_text(encoding="utf-8")


def test_the_shared_loading_helper_exists() -> None:
    ui = _read("static/lightwork-ui.js")
    assert "window.mvLoading = function (element, opts)" in ui
    assert "aria-busy" in ui and "Try again" in ui
    assert ".mv-loading {" in _read("static/lightwork.css")


def test_security_threat_hunting_switches_use_the_shared_loader() -> None:
    page = _read("templates/security.html")
    start = page.index('id="sec-hunters"')
    assert "Loading…" not in page[start:page.index("</div>", start)]
    assert "window.mvLoading(huntersHost" in page


def test_workforce_inventory_uses_the_shared_loader() -> None:
    assert '<div id="wo-inv" role="status" aria-live="polite"></div>' in _read("templates/_workforce_ops.html")
    script = _read("static/lightwork-workforce-ops.js")
    assert "window.mvLoading($('wo-inv')" in script
    assert "el('p', 'muted', 'Loading…')" not in script


def test_chat_draft_recovery_never_starts_with_loading_words() -> None:
    assert "Checking draft recovery…</summary>" not in _read("templates/_composer_recovery.html")
    script = _read("static/lightwork-draft-recovery.js")
    assert "disclosureTitle.textContent = 'Checking draft recovery…'" not in script
    assert "slowCheck ? 'Checking draft recovery…'" in script


def test_page_scripts_wait_for_the_shared_helpers_before_loading() -> None:
    # Inline page scripts run before lightwork-ui.js, which loads at the end
    # of the page; calling mvLoading at once threw and stopped the page script.
    for path in sorted((PACKAGE / "templates").glob("*.html")):
        text = path.read_text(encoding="utf-8")
        if "window.mvLoading(" in text:
            assert "DOMContentLoaded" in text, path.name


def test_skills_tool_list_only_for_people_who_can_add_skills() -> None:
    page = _read("templates/skills.html")
    start = page.index('<fieldset class="sk-tools">')
    block = page[start:page.index("</fieldset>", start)]
    assert "{% if can_author %}" in block and "{% else %}" in block
    assert "Loading tools…</p>" not in block


def test_saved_task_views_use_the_shared_loader() -> None:
    # The status line said "Loading your saved views…" for 64 ms on Tasks.
    assert "Loading your saved views…</p>" not in _read("templates/_task_saved_views.html")
    assert "window.mvLoading(list," in _read("static/lightwork-task-views.js")
