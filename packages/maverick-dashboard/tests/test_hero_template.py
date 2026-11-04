"""Hero text remains untrusted unless its template explicitly owns the markup."""
from __future__ import annotations

import re

import pytest
from jinja2 import ChoiceLoader, DictLoader
from markupsafe import Markup, escape
from maverick_dashboard.app import templates
from maverick_dashboard.identity_format import role_label

_CALLS = {
    "title": "{{ hero('Workspace', value) }}",
    "lede": "{{ hero('Workspace', 'Title', lede=value) }}",
    "copy": "{{ state('Current state', 'Ready', copy=value) }}",
}


def _render_value(field, value):
    return templates.env.from_string(
        '{% from "_hero.html" import hero, state %}' + _CALLS[field],
    ).render(value=value)


@pytest.mark.parametrize("field", _CALLS)
@pytest.mark.parametrize("value", [
    '<xprobe title="quotes">Café & 東京</xprobe>',
    '</h1><svg data-probe="alternate">Résumé</svg>',
    '&lt;xprobe&gt;Already encoded & "quoted"&lt;/xprobe&gt;',
])
def test_hero_plain_text_cannot_create_markup(field, value):
    body = _render_value(field, value)
    assert str(escape(value)) in body
    assert "<xprobe" not in body
    assert "<svg" not in body


@pytest.mark.parametrize("field", _CALLS)
def test_hero_preserves_explicit_trusted_markup(field):
    value = Markup('<strong>Café &amp; 東京</strong> <a href="/privacy">Review</a>')
    assert str(value) in _render_value(field, value)


def _render_content(template_name, **context):
    # Render the real page content without unrelated navigation/context providers.
    env = templates.env.overlay(loader=ChoiceLoader([
        DictLoader({"base.html": "{% block content %}{% endblock %}"}),
        templates.env.loader,
    ]))
    return env.get_template(template_name).render(**context)


@pytest.mark.parametrize("default_role", ["viewer", "<xprobe>reviewer</xprobe>"])
def test_users_hero_keeps_emphasis_and_escapes_dynamic_role(default_role):
    body = _render_content(
        "users.html", default_role=default_role, users=[], bootstrap_admins=[],
        # The installation administrator's lede names the starting role.
        people_labels={}, role_labels={}, role_permissions={}, global_admin=True,
        workspace_role_options=[], first_login=None,
    )
    assert 'id="page-hero-title">Users</h1>' in body
    assert "&amp;amp;" not in body
    assert f"<strong>{escape(role_label(default_role))}</strong>" in body
    assert "<xprobe>" not in body.lower()


def test_roles_hero_keeps_template_owned_emphasis():
    body = _render_content("roles.html", roles=[])
    assert "<strong>model</strong>" in body
    assert "<strong>extra instructions</strong>" in body


def test_tenants_hero_keeps_template_owned_link():
    body = _render_content("tenants.html", tenants=[])
    assert '<a href="/tenants/overview">Workspace overview</a>' in body


def _render(source, **context):
    return templates.env.from_string('{% from "_hero.html" import hero, state %}' + source).render(**context)


def test_hero_actions_slot_renders_template_owned_buttons_once():
    body = _render(
        "{% set hero_actions %}<a class=\"btn btn--primary\" href=\"/chat?q={{ q }}\">Start {{ q }}</a>"
        "{% endset %}{{ hero('Work', 'Tasks', lede='Find your work.', actions=hero_actions) }}",
        q='<xprobe> & "quoted"',
    )
    assert '<div class="hero-actions">' in body
    # Markup captured by {% set %} is not escaped again; values inside it are.
    assert '<a class="btn btn--primary" href="/chat?q=&lt;xprobe&gt; &amp; &#34;quoted&#34;">' in body
    assert "Start &lt;xprobe&gt; &amp; &#34;quoted&#34;</a>" in body
    assert "<xprobe" not in body and "&amp;lt;" not in body
    # The actions sit under the lede, inside the header's text column.
    assert re.search(r'<p class="hero-lede">Find your work\.</p>\s*<div class="hero-actions">', body)


def test_hero_actions_as_plain_text_cannot_create_markup():
    body = _render("{{ hero('Work', 'Tasks', actions=value) }}", value='<a href="/x">Go</a>')
    assert '&lt;a href=&#34;/x&#34;&gt;Go&lt;/a&gt;' in body
    assert '<a href="/x">' not in body


def test_hero_without_actions_has_no_empty_actions_container():
    body = _render("{{ hero('Work', 'Tasks', lede='Find your work.') }}")
    assert "hero-actions" not in body
    assert 'class="hero hero--solo"' in body


def test_hero_actions_coexist_with_the_state_box():
    body = _render(
        "{% set hero_actions %}<button class=\"btn\" type=\"button\">Refresh list</button>{% endset %}"
        "{% call hero('Work', 'Tasks', actions=hero_actions) %}{{ state('Current state', 'Ready') }}{% endcall %}",
    )
    assert 'class="hero"' in body
    assert body.index('class="hero-actions"') < body.index('class="hero-statebox"')


def test_compact_hero_keeps_the_shared_title_and_puts_actions_beside_it():
    body = _render(
        "{% set hero_actions %}<a class=\"btn btn--primary\" href=\"/chat\">New task</a>{% endset %}"
        "{{ hero('Task', 'Task diagnostics', lede='One task.', actions=hero_actions, compact=true) }}",
    )
    assert 'class="hero hero--solo hero--compact"' in body
    # Pages and design tests rely on the shared h1 class order.
    assert re.search(r'<h1 class="page-title hero-title" id="page-hero-title">Task diagnostics</h1>', body)
    # Compact headers place the actions in their own column beside the text.
    assert re.search(r'<p class="hero-lede">One task\.</p>\s*</div>\s*<div class="hero-actions">', body)


def test_hero_styles_define_actions_and_compact_variant():
    import pathlib

    css = (pathlib.Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static" / "lightwork.css").read_text(encoding="utf-8")
    assert ".hero-actions {" in css
    assert ".hero--compact {" in css
    assert ".hero--compact .hero-title {" in css


def test_hero_without_a_kicker_leaves_the_line_out():
    body = _render("{{ hero('', 'Page not found', lede='That page moved.') }}")
    assert "hero-kicker" not in body
    assert '<h1 class="page-title hero-title" id="page-hero-title">Page not found</h1>' in body
