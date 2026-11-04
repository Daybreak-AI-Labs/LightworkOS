"""Keyboard order, names and announcements of the two page shells.

Measured on the dashboard with axe-core and keyboard-only runs: the first
Tab stop on 73 of 74 pages was an invisible "Workspace" link that the body
grid placed at the bottom of the page, the first control after the skip
link sat under the sticky top bar, the Docs link's name did not start with
its visible text, and "Emergency stop" was announced after every page load.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape
from maverick_dashboard import i18n, i18n_journeys

ROOT = Path(__file__).parents[1] / "maverick_dashboard"
CSS = (ROOT / "static" / "lightwork.css").read_text(encoding="utf-8")
SHELLS = ["base.html", "chat_base.html"]
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


def render(name, **values):
    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape())
    request = SimpleNamespace(query_params={}, headers={}, cookies={}, state=SimpleNamespace())
    context = i18n_journeys.context(request, "en")
    context.update(lang="en", page_lang="en", dir="ltr", asset=lambda asset: "/static/" + asset,
                   t=lambda key: i18n.t(key, "en"), threads=[], nav_groups=[], finder_pages=[],
                   can_halt=False, can_create_goal=False, custom_theme_names=[], path="/goals",
                   docs_home="https://daybreak-ai-labs.github.io/LightworkOS/")
    context.update(values)
    return env.get_template(name).render(**context)


class Tree(HTMLParser):
    """Every start tag with its attributes, ancestors and text, in document order."""

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.nodes, self.stack = [], []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "parents": list(self.stack), "text": []}
        self.nodes.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        for node in self.stack:
            node["text"].append(data)


def text(node):
    return " ".join("".join(node["text"]).split())


def focusable(node):
    tag, attrs = node["tag"], node["attrs"]
    if "tabindex" in attrs:
        return int(attrs["tabindex"]) >= 0
    if tag == "a":
        return "href" in attrs
    if tag == "input":
        return attrs.get("type") != "hidden"
    return tag in {"button", "select", "textarea", "summary"}


def keyboard_stops(html):
    """Focusable elements in tab order, leaving out hidden and dialog content."""
    stops = []
    for node in Tree(html).nodes:
        chain = node["parents"] + [node]
        if any("hidden" in item["attrs"] or item["tag"] in {"dialog", "template"} for item in chain):
            continue
        if focusable(node):
            stops.append(node)
    return stops


@pytest.mark.parametrize("name", SHELLS)
@pytest.mark.parametrize("language", ["en", "fr"])
def test_the_skip_link_is_the_first_keyboard_stop(name, language):
    html = render(name, lang=language, can_halt=True)
    first = keyboard_stops(html)[0]
    assert first["tag"] == "a" and first["attrs"].get("class") == "skip-link", first
    assert first["attrs"]["href"] == "#content"


def test_the_workspace_line_is_shown_in_the_sidebar_not_as_a_stray_page_child():
    tree = Tree(render("base.html", workspace_tenant_name="Acme"))
    link = next(node for node in tree.nodes if node["attrs"].get("href") == "/workspace/tenant")
    line = link["parents"][-1]
    assert line["tag"] == "p" and "active-workspace-banner" in line["attrs"]["class"]
    # Inside the sidebar, which the grid places beside the page; never a
    # direct child of <body>, where it was auto-placed after the footer.
    assert [p["attrs"].get("id") for p in line["parents"] if p["tag"] == "aside"] == ["sidebar"]
    assert line["parents"][-1]["tag"] != "body"
    assert text(line) == "Workspace: Acme"


@pytest.mark.parametrize("name", SHELLS)
@pytest.mark.parametrize("can_halt", [True, False])
def test_generic_elements_in_the_shell_do_not_carry_a_prohibited_label(name, can_halt):
    # ARIA does not allow aria-label on a <p>, <span> or <div> without a role
    # (axe aria-prohibited-attr on 73 pages); their visible text names them.
    tree = Tree(render(name, can_halt=can_halt))
    for node in tree.nodes:
        if node["attrs"].get("href") == "/workspace/tenant":
            assert "aria-label" not in node["parents"][-1]["attrs"]
        if node["attrs"].get("id") == "halt-pill" and node["tag"] == "span":
            assert "aria-label" not in node["attrs"]
            assert "role" not in node["attrs"]
            # The explanation is still read, as visually hidden text.
            assert "Halt permission is required to change it." in text(node)


@pytest.mark.parametrize("name", SHELLS)
@pytest.mark.parametrize("can_halt", [True, False])
def test_the_emergency_stop_label_is_not_live_until_its_first_state_is_known(name, can_halt):
    # lightwork-ui.js makes the label a polite live region after the first
    # status read, so a page load never announces "Emergency stop".
    label = next(node for node in Tree(render(name, can_halt=can_halt)).nodes
                 if node["attrs"].get("id") == "halt-label")
    assert "aria-live" not in label["attrs"] and "role" not in label["attrs"]


@pytest.mark.parametrize("name", SHELLS)
def test_the_docs_link_name_starts_with_its_visible_text(name):
    tree = Tree(render(name))
    docs = [node for node in tree.nodes
            if node["tag"] == "a" and node["attrs"].get("target") == "_blank" and text(node) == "Docs"]
    assert len(docs) == 1
    label = docs[0]["attrs"]["aria-label"]
    # WCAG 2.5.3: a voice user who says "click Docs" reaches the link.
    assert label.startswith("Docs") and "new tab" in label


def test_the_sticky_top_bar_never_covers_the_focused_element():
    rule = re.search(r"\bhtml\s*\{([^}]*)\}", CSS)
    assert rule and re.search(r"scroll-padding-top:\s*calc\(var\(--shell-topbar-h\)", rule.group(1))
    assert re.search(r"#content\s*\{[^}]*scroll-margin-top:", CSS)
    # The measured header height also reaches the root, where scroll padding
    # is read (the phone header can wrap to two rows).
    script = (ROOT / "static" / "lightwork-ui.js").read_text(encoding="utf-8")
    assert "document.documentElement.style.setProperty('--shell-topbar-h'" in script


def test_links_inside_running_text_are_underlined_and_always_in_high_contrast():
    # WCAG 1.4.1: a link in a sentence is not told apart by colour alone.
    running = re.search(r"main :where\(([^)]*)\) a:where\(:not\(([^{]*)\)\)\s*,?[^{]*\{([^}]*)\}", CSS)
    assert running, "running-text link rule missing"
    containers = {part.strip() for part in running.group(1).split(",")}
    assert {"p", "li", "td", "dd"} <= containers
    excluded = running.group(2)
    for control in (".btn", ".mv-tab", "nav a", '[role="tab"]'):
        assert control in excluded
    assert "text-decoration: underline" in running.group(3)
    high_contrast = re.search(r"body\.theme-hicontrast main a:where\(:not\([^{]*\)\)\s*\{([^}]*)\}", CSS)
    assert high_contrast and "text-decoration: underline" in high_contrast.group(1)
    workspace = re.search(r"\.active-workspace-banner a\s*[,{]", CSS)
    assert workspace, "the sidebar workspace link sits in a sentence too"
