"""Static accessibility audit: per-rule detection + clean passes."""
from __future__ import annotations

from maverick import a11y_audit as a


def _rules(html):
    return {f.rule for f in a.audit_html(html)}


def test_img_without_alt_flagged():
    assert "img-alt" in _rules('<img src="x.png">')
    assert "img-alt" not in _rules('<img src="x.png" alt="a chart">')
    # a Jinja-templated alt counts as present
    assert "img-alt" not in _rules('<img src="x.png" alt="{{ caption }}">')


def test_html_lang():
    assert "html-lang" in _rules("<html><body></body></html>")
    assert "html-lang" not in _rules('<html lang="en"></html>')
    assert "html-lang" not in _rules('<html lang="{{ lang }}"></html>')


def test_form_control_label():
    assert "control-label" in _rules('<input type="text" id="q">')
    assert "control-label" not in _rules('<input type="text" aria-label="Search">')
    assert "control-label" not in _rules('<label>Q <input type="text"></label>')
    # for/id association, label AFTER the control (forward reference)
    assert "control-label" not in _rules(
        '<input type="text" id="q"><label for="q">Query</label>')
    # hidden/submit need no label
    assert "control-label" not in _rules('<input type="hidden" name="t">')
    assert "control-label" not in _rules('<input type="submit" value="Go">')


def test_empty_interactive_control():
    assert "empty-control" in _rules("<button></button>")
    assert "empty-control" in _rules('<a href="/x"></a>')
    assert "empty-control" not in _rules("<button>Save</button>")
    assert "empty-control" not in _rules('<button aria-label="Close">x</button>'.replace("x", ""))
    assert "empty-control" not in _rules('<a href="/x">Home</a>')
    assert "empty-control" not in _rules('<button>{{ label }}</button>')
    # aria-hidden="true" (or bare) hides the control from AT -> suppressed
    assert "empty-control" not in _rules('<button aria-hidden="true"></button>')
    assert "empty-control" not in _rules("<button aria-hidden></button>")
    # aria-hidden="false" leaves it AT-exposed -> still a violation
    assert "empty-control" in _rules('<button aria-hidden="false"></button>')
    assert "empty-control" in _rules('<a href="/x" aria-hidden="FALSE"></a>')


def test_positive_tabindex():
    assert "tabindex-positive" in _rules('<div tabindex="3">x</div>')
    assert "tabindex-positive" not in _rules('<div tabindex="0">x</div>')
    assert "tabindex-positive" not in _rules('<div tabindex="-1">x</div>')


def test_heading_skip():
    assert "heading-skip" in _rules("<h2>A</h2><h4>B</h4>")
    assert "heading-skip" not in _rules("<h2>A</h2><h3>B</h3>")
    assert "heading-skip" not in _rules("<h1>A</h1><h2>B</h2><h3>C</h3>")


def test_clean_document_no_findings():
    html = """<!doctype html><html lang="en"><head><title>T</title></head>
    <body><h1>Title</h1><img src="a.png" alt="chart">
    <label for="q">Q</label><input type="text" id="q">
    <button>Save</button></body></html>"""
    assert a.audit_html(html) == []


def test_finding_carries_line_number():
    findings = a.audit_html("<html lang='en'>\n<body>\n<img src='x'>\n</body>")
    img = [f for f in findings if f.rule == "img-alt"][0]
    assert img.line == 3


def test_audit_templates_runs_over_dashboard():
    # The real dashboard templates: the audit must run and return a dict
    # (clean or with findings) without error.
    results = a.audit_templates()
    assert isinstance(results, dict)


def test_render_clean_and_dirty():
    assert "no static accessibility issues" in a.render({})
    out = a.render({"x.html": [a.Finding("img-alt", "missing", 4)]})
    assert "x.html:4" in out and "img-alt" in out
