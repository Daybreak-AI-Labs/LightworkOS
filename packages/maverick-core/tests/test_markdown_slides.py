"""Markdown to a PowerPoint deck with no external program (maverick.markdown_slides)."""
from __future__ import annotations

import io
import posixpath
import shutil
import subprocess
import zipfile
from xml.etree import ElementTree as ET

import pytest
from maverick.markdown_slides import MAX_SLIDES, UnwritableSlides, slides_from_markdown

_PITCH = """Bakery catering pitch
Prepared for Acme HQ

# Fresh bakery catering for the office
- Make meetings feel **thoughtful**
- Pastries & savory options <on time>
  - Gluten-free on request

# Why teams choose us
1. Crowd-pleasing menu
2. Reliable delivery

```
# not a heading inside code
```

# Pricing
- From $12 a head
"""

_NS = {"p": "http://schemas.openxmlformats.org/presentationml/2006/main",
       "a": "http://schemas.openxmlformats.org/drawingml/2006/main"}


def _parts(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        assert package.testzip() is None
        return {name: package.read(name) for name in package.namelist()}


def _texts(xml: bytes) -> list[str]:
    root = ET.fromstring(xml)
    return ["".join(t.text or "" for t in p.iter(f"{{{_NS['a']}}}t")) for p in root.iter(f"{{{_NS['a']}}}p")]


def test_every_part_is_declared_well_formed_and_linked():
    parts = _parts(slides_from_markdown(_PITCH))
    types = ET.fromstring(parts["[Content_Types].xml"])
    declared = {o.get("PartName").lstrip("/") for o in types if o.get("PartName")}
    xml_parts = {name for name in parts if name.endswith(".xml") and name != "[Content_Types].xml"}
    assert xml_parts <= declared and declared <= set(parts)
    for name, body in parts.items():
        root = ET.fromstring(body)  # every part parses
        if name.endswith(".rels"):
            base = posixpath.dirname(posixpath.dirname(name))
            for rel in root:
                target = posixpath.normpath(posixpath.join(base, rel.get("Target")))
                assert target in parts, (name, rel.get("Target"))


def test_headings_make_slides_with_titles_bullets_levels_and_bold():
    parts = _parts(slides_from_markdown(_PITCH))
    slides = sorted(n for n in parts if n.startswith("ppt/slides/slide") and n.endswith(".xml"))
    assert len(slides) == 4
    cover, first, second, third = (_texts(parts[f"ppt/slides/slide{n}.xml"]) for n in range(1, 5))
    assert cover == ["Bakery catering pitch", "Prepared for Acme HQ"]
    assert first == ["Fresh bakery catering for the office", "Make meetings feel thoughtful",
                     "Pastries & savory options <on time>", "Gluten-free on request"]
    # A fenced line stays text on its slide; it never starts one.
    assert second == ["Why teams choose us", "Crowd-pleasing menu", "Reliable delivery",
                      "# not a heading inside code"]
    assert third == ["Pricing", "From $12 a head"]
    slide2 = ET.fromstring(parts["ppt/slides/slide2.xml"])
    levels = [p.find("a:pPr", _NS).get("lvl") for p in slide2.iter(f"{{{_NS['a']}}}p") if p.find("a:pPr", _NS) is not None]
    assert levels == ["0", "0", "1"]
    assert [r.get("b") for r in slide2.iter(f"{{{_NS['a']}}}rPr")].count("1") == 1


def test_second_level_headings_split_when_there_is_no_top_heading():
    parts = _parts(slides_from_markdown("## One\n- a\n## Two\n- b\n"))
    assert _texts(parts["ppt/slides/slide1.xml"]) == ["One", "a"]
    assert _texts(parts["ppt/slides/slide2.xml"]) == ["Two", "b"]


def test_empty_or_oversized_text_is_refused():
    with pytest.raises(UnwritableSlides):
        slides_from_markdown("   \n\n")
    with pytest.raises(UnwritableSlides):
        slides_from_markdown("".join(f"# S{n}\n" for n in range(MAX_SLIDES + 1)))


def test_python_pptx_reads_the_deck():
    pptx = pytest.importorskip("pptx")
    deck = pptx.Presentation(io.BytesIO(slides_from_markdown(_PITCH)))
    assert [slide.shapes.title.text for slide in deck.slides] == [
        "Bakery catering pitch", "Fresh bakery catering for the office", "Why teams choose us", "Pricing"]


@pytest.mark.skipif(shutil.which("soffice") is None, reason="LibreOffice is not installed")
def test_libreoffice_renders_every_slide(tmp_path):
    (tmp_path / "deck.pptx").write_bytes(slides_from_markdown(_PITCH))
    subprocess.run(["soffice", "--headless", "--norestore", f"-env:UserInstallation=file://{tmp_path}/profile",
                    "--convert-to", "pdf", "--outdir", str(tmp_path), str(tmp_path / "deck.pptx")],
                   check=True, capture_output=True, timeout=180)
    assert (tmp_path / "deck.pdf").read_bytes().startswith(b"%PDF")
    if shutil.which("pdfinfo"):
        info = subprocess.run(["pdfinfo", str(tmp_path / "deck.pdf")], capture_output=True, text=True,
                              check=True).stdout
        assert "Pages:           4" in info
    if shutil.which("pdftotext"):
        text = subprocess.run(["pdftotext", str(tmp_path / "deck.pdf"), "-"], capture_output=True, text=True,
                              check=True).stdout
        assert "From $12 a head" in text and "Gluten-free on request" in text


def test_escaped_punctuation_is_written_without_its_backslash():
    # Live: an answer wrote "\$8,400"; Markdown shows "$8,400", and the slide
    # showed the backslash.
    parts = _parts(slides_from_markdown("# Pricing \\#1\n\n- Total: \\$8,400 at 7.5\\% \\*not bold\\*\n"))
    texts = " ".join(_texts(parts["ppt/slides/slide1.xml"]))
    assert "Pricing #1" in texts and "$8,400 at 7.5% *not bold*" in texts and "\\" not in texts
