"""One empty-state component: what will appear, how to add the first one, one next step."""
from __future__ import annotations

import pathlib
import re

import pytest
from maverick_dashboard.app import templates

_STATIC = pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"


def _render(source, **context):
    return templates.env.from_string(
        '{% from "_empty_state.html" import empty_state %}' + source).render(**context)


def test_empty_state_says_what_appears_and_offers_one_next_step():
    body = _render("{{ empty_state('No results yet', 'Finished tasks appear here. Start a task to get the first one.',"
                   " action_label='Start a task', action_href='/chat') }}")
    assert re.search(
        r'<div class="mv-empty">\s*<p class="mv-empty__title">No results yet</p>\s*'
        r'<p class="mv-empty__body">Finished tasks appear here\. Start a task to get the first one\.</p>\s*'
        r'<a class="btn mv-empty__action" href="/chat">Start a task</a>\s*</div>', body)
    # The next step is never a second primary action on the page.
    assert "btn--primary" not in body


@pytest.mark.parametrize("label, href", [("Start a task", ""), ("", "/chat")])
def test_empty_state_without_a_usable_destination_has_no_button(label, href):
    body = _render("{{ empty_state('No results yet', 'Finished tasks appear here.', action_label=label, action_href=href) }}",
                   label=label, href=href)
    assert "<a" not in body and "mv-empty__action" not in body


def test_empty_state_text_cannot_create_markup():
    probe = '<xprobe title="q">Café & 東京</xprobe>'
    body = _render("{{ empty_state(v, v, action_label=v, action_href=h) }}", v=probe, h='/x?a="b"&c=<d>')
    assert "<xprobe" not in body
    assert body.count("&lt;xprobe title=&#34;q&#34;&gt;Café &amp; 東京&lt;/xprobe&gt;") == 3
    assert 'href="/x?a=&#34;b&#34;&amp;c=&lt;d&gt;"' in body


def test_empty_state_supports_script_toggles_compact_and_a_custom_action():
    body = _render("{% call empty_state('No schedules yet', 'Schedules you add appear here.', id='auto-empty',"
                   " hidden=true, compact=true) %}<button class=\"btn\" type=\"button\">Create a schedule</button>"
                   "{% endcall %}")
    assert '<div class="mv-empty mv-empty--compact" id="auto-empty" hidden>' in body
    assert '<button class="btn" type="button">Create a schedule</button>' in body


def test_empty_state_styles_cover_the_action_and_compact_variant():
    css = (_STATIC / "lightwork.css").read_text(encoding="utf-8")
    assert ".mv-empty--compact {" in css
    assert ".mv-empty__title + .mv-empty__action {" in css


def test_script_helper_documented_next_to_the_macro():
    ui = (_STATIC / "lightwork-ui.js").read_text(encoding="utf-8")
    assert "window.mvEmpty = function (title, body, action, opts)" in ui
