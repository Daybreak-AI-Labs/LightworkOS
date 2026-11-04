"""Every product string the sign-in timer, settling pages and approval decisions
show has its French, German, Japanese and Chinese rows, and pages use them."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

DASHBOARD = Path(__file__).resolve().parents[1] / "maverick_dashboard"
# file -> the call that looks a string up in the catalog
LOOKUPS = {
    "static/lightwork-session.js": r"\bt\('((?:[^'\\]|\\.)*)'",
    "templates/_approvals_queue.html": r"""\btr\((?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")""",
    "static/lightwork-approvals-count.js": r"""\btr\((?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")""",
    "static/lightwork-immune-console.js": r"LightworkI18n\.text\(\"([^\"]*)\"\)",
    "static/lightwork-third-party-collaboration.js": r"LightworkI18n\.text\(\"([^\"]*)\"\)",
    "static/lightwork-ai-entity-tasks.js": r"LightworkI18n\.text\(\"([^\"]*)\"\)",
    "static/lightwork-audit-actions.js": r"LightworkI18n\.text\('([^']*)'\)",
}


def _catalog():
    from maverick_dashboard import i18n_journeys

    return {row[0] for row in i18n_journeys.ROWS}


@pytest.mark.parametrize("name", sorted(LOOKUPS))
def test_each_looked_up_string_has_its_translations(name):
    from maverick_dashboard import i18n_journeys

    found = re.findall(LOOKUPS[name], (DASHBOARD / name).read_text(encoding="utf-8"))
    sources = ["".join(match) if isinstance(match, tuple) else match for match in found]
    sources = [s.replace("\\'", "'").replace('\\"', '"') for s in sources]
    assert sources, name
    missing = sorted(set(sources) - _catalog())
    assert not missing, (name, missing)
    for source in sources:
        for lang in i18n_journeys.TRANSLATION_LANGS:
            text, actual = i18n_journeys.entry(source, lang)
            assert actual == lang and text.strip() and text != source, (source, lang)


def test_server_rendered_copy_for_these_states_is_in_the_catalog():
    catalog = _catalog()
    for source in ("Still getting this ready", "This page is still being set up. It refreshes by itself in a moment.",
                   "It is taking longer than usual. Reload this page in a minute.", "Approve \"{action}\"",
                   "Reject \"{action}\"", "Approve this action", "Send back for changes",
                   "AI systems can be chosen once AI system tasks are turned on.", "Shared decision reviews",
                   "{count} requests waiting", "Stay signed in", "Not now"):
        assert source in catalog, source


def test_the_approvals_page_speaks_the_chosen_language(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick.world_model import WorldModel

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    WorldModel(tmp_path / "world.db").create_approval("send_email", risk="medium", scope="Customers")
    from maverick_dashboard.app import app

    page = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/approvals", params={"lang": "fr"}).text
    assert "Approuver « Send email »" in page
    assert "Refuser « Send email »" in page
    assert "1 demande en attente" in page
