"""Tests for the pandoc tool (maverick.tools.pandoc_tool)."""
from __future__ import annotations

from unittest.mock import MagicMock

# ---------- pandoc ----------

def test_pandoc_requires_op():
    from maverick.tools.pandoc_tool import pandoc_tool
    assert "op is required" in pandoc_tool().fn({})


def test_pandoc_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.pandoc_tool import pandoc_tool
    out = pandoc_tool().fn({"op": "convert",
                              "input_path": "/x", "output_path": "/y"})
    assert "pandoc" in out and "PATH" in out


def test_pandoc_markdown_to_html(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/pandoc")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *a, **k: MagicMock(
            returncode=0, stdout="<p>Hello</p>\n", stderr="",
        ),
    )
    from maverick.tools.pandoc_tool import pandoc_tool
    out = pandoc_tool().fn({"op": "markdown_to_html", "text": "Hello"})
    assert "<p>Hello</p>" in out
