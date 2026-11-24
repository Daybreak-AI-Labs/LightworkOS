"""Word documents made from Markdown open in office programs."""
from __future__ import annotations

import io
import shutil
import subprocess
import zipfile

import pytest
from maverick.markdown_word import UnwritableText, word_answer

_SOP = ("# Opening procedure\n\nArrive at **6:30am**.\n\n- [ ] Unlock the door\n- [ ] Start the espresso machine\n\n"
        "| Step | Owner |\n|---|---|\n| Count the till | Shift lead |\n")


def _parts(document: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(document)) as archive:
        return {name: archive.read(name).decode("utf-8") for name in archive.namelist()}


def test_parts_use_the_standard_namespace_prefixes():
    # Live: every Word file Lightwork made was refused by LibreOffice ("source
    # file could not be loaded"): [Content_Types].xml was written as
    # <ns0:Types xmlns:ns0=...>, and the Word parts as ns0:document.
    parts = _parts(word_answer(_SOP, "Cafe SOP"))
    assert "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"" in parts["[Content_Types].xml"]
    assert 'Extension="md"' in parts["[Content_Types].xml"]
    for name in ("word/document.xml", "word/styles.xml", "word/settings.xml", "word/footer1.xml"):
        assert "ns0:" not in parts[name] and "<w:" in parts[name], name
    assert "Unlock the door" in parts["word/document.xml"] and parts["lightwork/source.md"] == _SOP


def test_text_word_cannot_hold_is_refused():
    with pytest.raises(UnwritableText):
        word_answer("bad \x01 char", "T")


@pytest.mark.skipif(shutil.which("soffice") is None, reason="LibreOffice is not installed")
def test_libreoffice_opens_the_document(tmp_path):
    (tmp_path / "sop.docx").write_bytes(word_answer(_SOP, "Cafe SOP"))
    subprocess.run(["soffice", f"-env:UserInstallation=file://{tmp_path}/profile", "--headless",
                    "--convert-to", "txt:Text", "--outdir", str(tmp_path), str(tmp_path / "sop.docx")],
                   capture_output=True, timeout=180, check=False)
    text = (tmp_path / "sop.txt").read_text(encoding="utf-8", errors="replace")
    assert "Opening procedure" in text and "Start the espresso machine" in text and "Shift lead" in text


def test_escaped_punctuation_is_written_without_its_backslash():
    # Live: a break-even answer wrote "\$8,400"; Markdown shows "$8,400", and
    # the Word file showed the backslash.
    document = _parts(word_answer("Total: \\$8,400 at 7.5\\% \\*not bold\\*\n\n| Item | Cost |\n|---|---|\n"
                                  "| A \\| B | \\$5.00 |\n\n`C:\\temp\\$x`", "Quote"))["word/document.xml"]
    assert "$8,400 at 7.5% *not bold*" in document and "$5.00" in document and "A | B" in document
    assert "\\$" not in document.replace("C:\\temp\\$x", "")


@pytest.mark.parametrize("marker", ["\\newpage", "\\pagebreak", "---PAGE BREAK---", "[Page break]", "<!-- pagebreak -->"])
def test_a_page_break_line_starts_a_new_page(marker):
    # Live: asked for "one letter per page", the agent wrote "---PAGE BREAK---"
    # between letters, and the Word file showed it as text on one long page.
    document = _parts(word_answer(f"Dear Rosa,\n\nPay soon.\n{marker}\nDear Ken,\n\nPay soon.", "Letters"))[
        "word/document.xml"]
    assert document.count('w:type="page"') == 1 and "PAGE" not in document.upper().replace("W:TYPE=\"PAGE\"", "")
    assert "newpage" not in document and "pagebreak" not in document.lower()
