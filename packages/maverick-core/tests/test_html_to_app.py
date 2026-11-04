"""HTML-to-app scaffolder."""
from __future__ import annotations

from maverick.html_to_app import analyze_html, html_to_app, scaffold


class _SB:
    """Minimal sandbox stub exposing a workdir confinement root."""

    def __init__(self, workdir):
        self.workdir = str(workdir)

_HTML = """<html><head><title>Todo App</title></head>
<body>
<h1>My Todos</h1>
<h2>Add one</h2>
<form action="/add" method="post">
  <input name="task" type="text" required>
  <input name="priority" type="number">
  <button type="submit">Add</button>
</form>
<a href="/about">About</a>
<a href="/help">Help</a>
<img src="logo.png">
</body></html>"""


def test_analyze_extracts_structure():
    plan = analyze_html(_HTML)
    assert plan["title"] == "Todo App"
    assert plan["headings"] == ["My Todos", "Add one"]
    assert len(plan["forms"]) == 1
    form = plan["forms"][0]
    assert form["action"] == "/add" and form["method"] == "post"
    names = [f["name"] for f in form["fields"]]
    assert "task" in names and "priority" in names
    assert plan["links"] == ["/about", "/help"]
    assert plan["images"] == 1


def test_analyze_empty_html():
    plan = analyze_html("")
    assert plan["title"] == "Untitled App"
    assert plan["forms"] == []


def test_scaffold_writes_project(tmp_path):
    dest = tmp_path / "app"
    plan = scaffold(_HTML, dest)
    assert (dest / "index.html").exists()
    assert (dest / "app.js").exists()
    assert (dest / "README.md").exists()
    # app.js should wire the discovered form
    js = (dest / "app.js").read_text(encoding="utf-8")
    assert "addEventListener('submit'" in js
    # the script tag is injected if absent
    assert 'src="app.js"' in (dest / "index.html").read_text(encoding="utf-8")
    assert "Todo App" in (dest / "README.md").read_text(encoding="utf-8")
    assert plan["written"] == ["index.html", "app.js", "README.md"]


def test_scaffold_no_form_still_runs(tmp_path):
    dest = tmp_path / "static"
    scaffold("<html><body><h1>Hi</h1></body></html>", dest)
    js = (dest / "app.js").read_text(encoding="utf-8")
    assert "app ready" in js


def test_tool_scaffold_confined_to_workspace(tmp_path):
    out = html_to_app(_SB(tmp_path)).fn(
        {"op": "scaffold", "html": _HTML, "dest": "app"})
    assert "scaffolded" in out
    assert (tmp_path / "app" / "index.html").exists()


def test_tool_scaffold_rejects_escape(tmp_path):
    # A model-supplied absolute/`..` dest must not write outside the sandbox.
    out = html_to_app(_SB(tmp_path)).fn(
        {"op": "scaffold", "html": _HTML, "dest": "../escaped"})
    assert out.startswith("ERROR") and "escape" in out.lower()
    assert not (tmp_path.parent / "escaped").exists()
