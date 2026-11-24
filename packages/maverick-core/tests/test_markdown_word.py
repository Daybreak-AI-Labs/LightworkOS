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
