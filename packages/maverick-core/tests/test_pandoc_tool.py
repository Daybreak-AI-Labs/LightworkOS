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


def test_word_falls_back_when_pandoc_is_missing_inside_the_sandbox(monkeypatch, tmp_path):
    # Live: pandoc was on the host PATH, so the tool tried it, but the task's
    # Podman sandbox had no pandoc ("sh: 1: pandoc: not found", exit 127) and
    # the agent stopped to ask the person what to do.
    from types import SimpleNamespace

    import maverick.tools as tools_pkg
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/pandoc")
    monkeypatch.setattr(tools_pkg, "sandbox_run", lambda *a, **k: (127, "", "sh: 1: pandoc: not found"))
    (tmp_path / "jd.md").write_text("# Bookkeeper\n\n- 20 hours a week\n", encoding="utf-8")
    out = pandoc_tool(SimpleNamespace(workdir=str(tmp_path))).fn(
        {"op": "convert", "input_path": "jd.md", "output_path": "jd.docx"})
    assert out.startswith("wrote ") and (tmp_path / "jd.docx").exists(), out


def test_markdown_becomes_a_powerpoint_deck_and_keeps_the_image_rules(tmp_path):
    # Live: asked for a 5-slide PowerPoint, the agent's only route was a
    # python-pptx script waiting on a person's shell approval.
    import shutil
    import zipfile

    import pytest
    from maverick.sandbox import LocalBackend
    from maverick.tools.pandoc_tool import pandoc_tool

    if shutil.which("pandoc") is None:
        pytest.skip("pandoc is unavailable")
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"\x89PNG\r\n\x1a\n")
    work = tmp_path / "work"
    work.mkdir()
    (work / "deck.md").write_text("# Office catering\n\n- Fresh daily\n\n# Pricing\n\n- From $12 a head\n",
                                  encoding="utf-8")
    (work / "leak.md").write_text(f"# Slide\n\n![x]({outside})\n", encoding="utf-8")
    tool = pandoc_tool(LocalBackend(workdir=work))
    assert tool.fn({"op": "convert", "input_path": "deck.md", "output_path": "deck.pptx"}).startswith("wrote ")
    with zipfile.ZipFile(work / "deck.pptx") as deck:
        slides = [name for name in deck.namelist() if name.startswith("ppt/slides/slide")]
        assert len(slides) == 2 and b"From $12 a head" in b"".join(deck.read(name) for name in slides)
    assert tool.fn({"op": "convert", "input_path": "leak.md", "output_path": "leak.pptx"}).startswith("ERROR:")
    assert not (work / "leak.pptx").exists()


def test_without_pandoc_a_powerpoint_is_made_built_in(monkeypatch, tmp_path):
    # Live: in a Podman sandbox without pandoc the deck conversion exited 127
    # and the agent stopped to ask the person what to do.
    import zipfile
    from types import SimpleNamespace

    import maverick.tools as tools_pkg
    from maverick.tools.pandoc_tool import pandoc_tool

    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/pandoc")
    monkeypatch.setattr(tools_pkg, "sandbox_run", lambda *a, **k: (127, "", "sh: 1: pandoc: not found"))
    (tmp_path / "deck.md").write_text("# Catering\n\n- Fresh daily\n\n# Pricing\n\n- $12 a head\n", encoding="utf-8")
    out = pandoc_tool(SimpleNamespace(workdir=str(tmp_path))).fn(
        {"op": "convert", "input_path": "deck.md", "output_path": "deck.pptx"})
    assert out.startswith("wrote ") and "built-in PowerPoint writer" in out, out
    with zipfile.ZipFile(tmp_path / "deck.pptx") as deck:
        assert {"ppt/slides/slide1.xml", "ppt/slides/slide2.xml"} <= set(deck.namelist())
