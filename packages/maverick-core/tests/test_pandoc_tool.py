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


def test_markdown_to_word_works_without_the_pandoc_program(monkeypatch, tmp_path):
    # Live: asked for a checklist "as a Word document", an agent tried pandoc
    # (not installed), then office_convert, then a shell script that waited
    # for approval. Markdown to .docx now uses the built-in Word writer that
    # the answer page's "Download Word document" uses.
    import io
    import zipfile
    from types import SimpleNamespace

    monkeypatch.setattr("shutil.which", lambda b: None)
    from maverick.tools.pandoc_tool import pandoc_tool

    (tmp_path / "checklist.md").write_text(
        "# Bookkeeper onboarding\n\n- Get system access\n- **Read** the close calendar\n\n"
        "| Week | Goal |\n|---|---|\n| 1 | Shadow |\n", encoding="utf-8")
    tool = pandoc_tool(SimpleNamespace(workdir=str(tmp_path)))
    out = tool.fn({"op": "convert", "input_path": "checklist.md", "output_path": "checklist.docx"})
    assert out.startswith("wrote ") and "checklist.docx" in out
    with zipfile.ZipFile(io.BytesIO((tmp_path / "checklist.docx").read_bytes())) as package:
        document = package.read("word/document.xml").decode("utf-8")
    assert "Get system access" in document and "Shadow" in document
    assert ":tbl>" in document  # the Markdown table became a Word table

    # Anything else still needs the program, and paths stay in the workspace.
    assert "PATH" in tool.fn({"op": "convert", "input_path": "checklist.md", "output_path": "c.rst"})
    assert "escapes" in tool.fn({"op": "convert", "input_path": "checklist.md", "output_path": "../c.docx"})
