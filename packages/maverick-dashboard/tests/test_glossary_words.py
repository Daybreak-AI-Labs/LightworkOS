"""The owner's glossary, checked on the pages that show agents and specialists.

"Specialist" means only one of Lightwork's own built-in job specialists (a
workspace's customized copy included). Everything else -- an agent built in
the workspace, an outside agent -- is an "agent". A list that can hold both
says "agents and specialists". See docs/content-style-guide.md.
"""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

# Mixed wording is allowed anywhere: "agents and specialists", "an agent or
# specialist", "every agent's and specialist's setup", "agent, specialist and flow".
MIXED = re.compile(r"\bagent(?:'s|s)?(?:,| and| or) (?:an? )?specialist(?:'s|s)?\b"
                   r"|\bBuild an agent or tailor a specialist\b", re.IGNORECASE)


def visible(fragment: str, *, rows: bool = True) -> str:
    """People-facing text: no scripts, comments or Technical details; with
    ``rows=False`` also no table rows or options, whose names are data."""
    fragment = re.sub(r"<(script|style|template)\b.*?</\1>", " ", fragment, flags=re.DOTALL)
    fragment = re.sub(r"<details[^>]*>\s*<summary>Technical details</summary>.*?</details>", " ",
                      fragment, flags=re.DOTALL)
    if not rows:
        fragment = re.sub(r"<(tbody|optgroup|option)\b.*?</\1>", " ", fragment, flags=re.DOTALL)
    fragment = re.sub(r"<!--.*?-->|\{#.*?#\}", " ", fragment, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment)))


def stray_specialist(text: str) -> list[str]:
    """Each use of "specialist" that is not part of a mixed phrase."""
    rest = MIXED.sub(" ", text)
    return [rest[max(0, m.start() - 40):m.end() + 40] for m in re.finditer(r"specialist", rest, re.IGNORECASE)]


def editor_column(page: str) -> str:
    left = page.split("LEFT: build an agent or tailor a specialist", 1)[1]
    return visible(left.split("RIGHT: your departments", 1)[0])


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def _builtin() -> str:
    from maverick.domain import builtin_domains
    return sorted(builtin_domains())[0]


def test_agent_built_here_is_never_called_a_specialist_in_its_editor(client):
    from maverick.domain_edit import write_override
    write_override("acme_quote_helper", {
        "description": "Drafts customer quotes", "persona": "You draft quotes for customers.",
        "max_risk": "low", "allow_tools": ["read_file"]})
    page = client.get("/agents?name=acme_quote_helper").text
    editor = editor_column(page)
    # Saving keeps a kind-neutral draft; the heading and copy name the kind.
    assert "Edit an agent" in editor and "Save draft" in editor
    assert "changing the agent people use" in editor
    assert stray_specialist(editor) == []


def test_builtin_pack_is_a_specialist_in_its_editor(client):
    page = client.get(f"/agents?name={_builtin()}").text
    editor = editor_column(page)
    assert "Tailor a specialist" in editor and "Save draft" in editor
    assert "changing the specialist people use" in editor
    assert "This agent" not in editor and "Save agent" not in editor
    assert 'data-kind="specialist"' in page


def test_customized_builtin_stays_a_specialist_in_its_editor(client):
    from maverick.domain_edit import write_override
    name = _builtin()
    write_override(name, {"description": "Tuned for this workspace."})
    editor = editor_column(client.get(f"/agents?name={name}").text)
    assert "Tailor a specialist" in editor and "Save draft" in editor
    assert "Customized" in editor


def test_new_custom_agent_and_drafting_controls_say_agent(client):
    page = client.get("/agents?new=1").text
    assert stray_specialist(editor_column(page)) == []
    for block_id in ("biz-setup", "jd-card"):
        block = page.split(f'id="{block_id}"', 1)[1].split("</details>", 1)[0]
        assert stray_specialist(visible(block)) == [], block_id


@pytest.mark.parametrize("path", ["/compartments", "/assessments"])
def test_lists_that_mix_agents_and_specialists_say_both(client, path):
    page = client.get(path)
    assert page.status_code == 200
    main = page.text.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    assert stray_specialist(visible(main, rows=False)) == []


def test_one_answer_uses_the_word_for_its_kind():
    from maverick_dashboard import agent_changelog
    assert agent_changelog.agent_kind(_builtin()) == "specialist"
    assert agent_changelog.agent_kind("acme_quote_helper") == "agent"
    assert agent_changelog.agent_kind("") == "agent"
