"""Live-DOM diff."""
from __future__ import annotations

from maverick.dom_diff import diff_html, render_diff


def test_no_change():
    html = "<div><p>hello</p></div>"
    d = diff_html(html, html)
    assert not d["changed"]
    assert render_diff(d) == "no DOM changes"


def test_added_element_and_text():
    before = "<ul><li>one</li></ul>"
    after = "<ul><li>one</li><li>two</li></ul>"
    d = diff_html(before, after)
    assert d["changed"]
    assert "li" in d["added"]
    assert "two" in d["text_added"]
    assert d["removed"] == []


def test_removed_element():
    before = '<div><a href="/x">link</a><span>keep</span></div>'
    after = "<div><span>keep</span></div>"
    d = diff_html(before, after)
    assert any(s.startswith("a[href=/x]") for s in d["removed"])
    assert "link" in d["text_removed"]


def test_signature_includes_id_and_class():
    before = "<div></div>"
    after = '<div id="main" class="box wide"></div>'
    d = diff_html(before, after)
    assert "div#main.box.wide" in d["added"]


def test_invisible_text_ignored():
    before = "<div>x</div>"
    after = "<div>x<script>var secret=1</script></div>"
    d = diff_html(before, after)
    # the <script> element is an added element, but its text is not visible text
    assert "var secret=1" not in d["text_added"]


def test_self_closing_void_invisible_tags_do_not_expose_hidden_text():
    after = (
        "<html><head><meta/><title>hidden instructions</title></head>"
        "<body>Visible</body></html>"
    )
    d = diff_html("", after)
    assert "hidden instructions" not in d["text_added"]
    assert "Visible" in d["text_added"]


def test_self_closing_link_does_not_close_invisible_parent():
    after = (
        "<html><template><link/>hidden template instructions</template>"
        "<body>Visible</body></html>"
    )
    d = diff_html("", after)
    assert "hidden template instructions" not in d["text_added"]
    assert "Visible" in d["text_added"]


def test_malformed_html_does_not_raise():
    d = diff_html("<div><p>unclosed", "<div><p>unclosed<span>")
    assert isinstance(d, dict) and "added" in d
