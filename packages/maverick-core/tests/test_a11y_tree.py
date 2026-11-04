"""a11y_tree: static HTML -> compact accessibility tree."""
from __future__ import annotations

from maverick.tools.a11y_tree import a11y_tree

_HTML = """
<html><head><style>.x{color:red}</style><script>var a=1;</script></head>
<body>
  <header><nav><a href="/">Home</a><a href="/docs">Docs</a></nav></header>
  <main>
    <h1>Welcome</h1>
    <p>Some text that should be dropped.</p>
    <form>
      <input type="email" placeholder="you@example.com">
      <input type="submit" value="Sign up">
    </form>
    <img src="x.png" alt="A diagram">
  </main>
</body></html>
"""


def test_extract_core_semantics():
    out = a11y_tree().fn({"op": "extract", "html": _HTML})
    assert "[navigation]" in out
    assert "link: 'Home' -> /" in out
    assert "link: 'Docs' -> /docs" in out
    assert "[main]" in out
    assert "heading1: 'Welcome'" in out
    assert "textbox: 'you@example.com'" in out
    assert "button: 'Sign up'" in out
    assert "image: 'A diagram'" in out


def test_drops_script_style_and_prose():
    out = a11y_tree().fn({"op": "extract", "html": _HTML})
    assert "var a=1" not in out
    assert "color:red" not in out
    assert "should be dropped" not in out  # non-semantic prose isn't a node


def test_reports_token_cut():
    out = a11y_tree().fn({"op": "extract", "html": _HTML})
    assert "x smaller)" in out and "raw chars ->" in out


def test_button_inner_text_name():
    out = a11y_tree().fn({"op": "extract", "html": "<button>Click <b>me</b></button>"})
    assert "button: 'Click me'" in out


def test_errors_and_empty():
    t = a11y_tree()
    assert t.fn({"op": "extract", "html": ""}).startswith("ERROR")
    assert t.fn({"op": "extract", "html": "<p>just prose</p>"}).startswith("(no accessible")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "a11y_tree" in names
