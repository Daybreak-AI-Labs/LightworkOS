"""Word track-changes redlines: real w:ins/w:del revisions, stdlib only."""
from __future__ import annotations

import io
import re
import zipfile
from xml.etree import ElementTree as ET

import pytest
from maverick import docx_redline as dr

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
DATE = "2026-07-27T12:00:00Z"

CLAUSE = ("Processor may engage sub-processors at its sole discretion "
          "without notice to Controller.")
FIXED = ("Processor shall not engage any sub-processor without Controller's "
         "prior written authorisation and shall impose equivalent obligations.")


def _make_docx(paragraphs: list[str], *, extra: dict | None = None) -> bytes:
    """A minimal but realistic .docx: runs split mid-sentence the way Word
    actually writes them, plus sibling parts that must survive a redline."""
    body = []
    for p in paragraphs:
        head, _, tail = p.partition(" ")
        body.append(
            "<w:p><w:pPr><w:pStyle w:val='Body'/></w:pPr>"
            f"<w:r><w:t xml:space='preserve'>{head} </w:t></w:r>"
            f"<w:r><w:t xml:space='preserve'>{tail}</w:t></w:r></w:p>")
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           f'<w:document xmlns:w="{dr._W_NS}"><w:body>{"".join(body)}'
           f"{dr._SECT_PR}</w:body></w:document>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", dr._CONTENT_TYPES)
        z.writestr("_rels/.rels", dr._ROOT_RELS)
        z.writestr("word/_rels/document.xml.rels", dr._DOCUMENT_RELS)
        z.writestr("word/settings.xml", dr._SETTINGS)
        z.writestr("word/document.xml", doc)
        z.writestr("word/styles.xml",
                   f'<w:styles xmlns:w="{dr._W_NS}"/>')
        for name, value in (extra or {}).items():
            z.writestr(name, value)
    return buf.getvalue()


def _document_xml(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return z.read("word/document.xml").decode()


def assert_valid_opc(data: bytes) -> None:
    """Structural OPC/ECMA-376 conformance: the checks a strict consumer (Word)
    makes when opening a package. Cheap to run, and it catches the packaging
    mistakes that make a file 'unreadable' with no useful error."""
    ct_ns = "{http://schemas.openxmlformats.org/package/2006/content-types}"
    r_ns = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = set(z.namelist())
        assert "[Content_Types].xml" in names, "missing content types"
        assert "_rels/.rels" in names, "missing package relationships"
        # Every part parses as XML.
        for name in names:
            if name.endswith((".xml", ".rels")):
                ET.fromstring(z.read(name))
        types = ET.fromstring(z.read("[Content_Types].xml"))
        # Every Override names a part that actually exists.
        for override in types.iter(f"{ct_ns}Override"):
            part = override.attrib["PartName"].lstrip("/")
            assert part in names, f"content-type override for missing {part}"
        defaults = {d.attrib["Extension"].lower()
                    for d in types.iter(f"{ct_ns}Default")}
        overrides = {o.attrib["PartName"].lstrip("/")
                     for o in types.iter(f"{ct_ns}Override")}
        # Every part is typed, by Default extension or by Override.
        for name in names:
            if name == "[Content_Types].xml" or name.endswith("/"):
                continue
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            assert ext in defaults or name in overrides, f"untyped part {name}"
        # Every relationship target resolves to a real part.
        for rels_name in (n for n in names if n.endswith(".rels")):
            base = rels_name.rsplit("_rels/", 1)[0]
            for rel in ET.fromstring(z.read(rels_name)).iter(
                    f"{r_ns}Relationship"):
                if rel.attrib.get("TargetMode") == "External":
                    continue
                target = rel.attrib["Target"].lstrip("/")
                assert (base + target) in names or target in names, (
                    f"relationship points at missing part {target}")
        # The officeDocument relationship must reach the main document part.
        root_rels = ET.fromstring(z.read("_rels/.rels"))
        main = [r.attrib["Target"].lstrip("/")
                for r in root_rels.iter(f"{r_ns}Relationship")
                if r.attrib["Type"].endswith("/officeDocument")]
        assert main and main[0] in names, "no reachable main document part"


def test_redline_marks_a_real_tracked_revision():
    original = _make_docx(["1. Scope of processing.", CLAUSE, "3. Term."])
    res = dr.redline_docx(
        original, [dr.ClauseEdit(find=CLAUSE, replace=FIXED,
                                 clause_key="subprocessors")], date=DATE)
    assert len(res.applied) == 1 and not res.unmatched
    xml = _document_xml(res.content)
    # Well-formed OOXML, not string soup.
    root = ET.fromstring(xml)
    dels = root.iter(f"{W}del")
    ins = root.iter(f"{W}ins")
    # The struck text uses w:delText (Word rejects w:t inside w:del).
    del_text = "".join(t.text or "" for d in dels for t in d.iter(f"{W}delText"))
    ins_text = "".join(t.text or "" for i in ins for t in i.iter(f"{W}t"))
    assert CLAUSE in del_text and FIXED in ins_text
    assert "<w:t" not in xml.split("<w:del")[1].split("</w:del>")[0]
    # Authored and dated so Word's review pane attributes the change.
    assert 'w:author="Lightwork Privacy Review"' in xml and DATE in xml
    assert dr.revision_count(res.content) == (1, 1)
    # Editing their package must leave it a conformant package.
    assert_valid_opc(res.content)


def test_matching_survives_word_splitting_a_sentence_across_runs():
    # The fixture deliberately splits every paragraph into two runs; a naive
    # substring search over a single w:t would miss the clause entirely.
    original = _make_docx([CLAUSE])
    assert "</w:t></w:r><w:r>" in _document_xml(original)
    res = dr.redline_docx(original, [dr.ClauseEdit(find=CLAUSE, replace=FIXED)],
                          date=DATE)
    assert len(res.applied) == 1


def test_other_parts_and_paragraph_properties_are_preserved():
    original = _make_docx(["1. Scope.", CLAUSE],
                          extra={"word/numbering.xml": "<numbering/>"})
    res = dr.redline_docx(original, [dr.ClauseEdit(find=CLAUSE, replace=FIXED)],
                          date=DATE)
    with zipfile.ZipFile(io.BytesIO(res.content)) as z:
        names = z.namelist()
        assert "word/styles.xml" in names and "word/numbering.xml" in names
        assert z.read("word/numbering.xml") == b"<numbering/>"
    xml = _document_xml(res.content)
    # The edited paragraph keeps its own pPr, so numbering/style survives.
    assert "w:pStyle" in xml.split("<w:del")[0]
    # The untouched paragraph is passed through byte-for-byte -- its text is
    # still split across the original runs (so it never appears as one
    # contiguous string) and it carries no revision markup.
    paras = dr._PARA_RE.findall(xml)
    untouched = paras[0]
    assert "<w:del" not in untouched and "<w:ins" not in untouched
    assert dr._para_text(untouched) == "1. Scope."


def test_missing_clause_is_appended_as_an_inserted_paragraph():
    original = _make_docx(["1. Scope of processing."])
    res = dr.redline_docx(
        original,
        [dr.ClauseEdit(replace="Processor shall assist with DSARs.",
                       clause_key="assistance")], date=DATE)
    assert len(res.inserted) == 1 and not res.applied
    xml = _document_xml(res.content)
    assert "Proposed additional clauses" in xml
    assert "Processor shall assist with DSARs." in xml
    ins, dels = dr.revision_count(res.content)
    assert dels == 0 and ins >= 1
    # The paragraph MARK itself is marked inserted (w:pPr/w:rPr/w:ins), not
    # just the run text -- otherwise Word leaves an orphan empty paragraph
    # behind when the change is rejected.
    root = ET.fromstring(xml)
    marks = [p for p in root.iter(f"{W}p")
             if p.find(f"{W}pPr/{W}rPr/{W}ins") is not None]
    assert len(marks) == 1


def test_unmatched_edit_is_reported_never_silently_dropped():
    original = _make_docx(["1. Scope of processing."])
    res = dr.redline_docx(
        original, [dr.ClauseEdit(find="a clause that is not in the document",
                                 replace=FIXED)], date=DATE)
    assert not res.applied and len(res.unmatched) == 1
    assert res.to_dict()["unmatched"]


def test_duplicate_valued_edits_are_tracked_by_identity():
    # Two edits with identical field values: only one paragraph exists, so
    # exactly one applies and the other must be reported unmatched.
    original = _make_docx([CLAUSE])
    a = dr.ClauseEdit(find=CLAUSE, replace=FIXED)
    b = dr.ClauseEdit(find=CLAUSE, replace=FIXED)
    res = dr.redline_docx(original, [a, b], date=DATE)
    assert len(res.applied) == 1 and len(res.unmatched) == 1


def test_containment_cannot_replace_surrounding_prose():
    wrapped = ("8.2 Sub-processing. " + CLAUSE + " This section survives "
               "termination.")
    original = _make_docx([wrapped])
    res = dr.redline_docx(original, [dr.ClauseEdit(find=CLAUSE, replace=FIXED)],
                          date=DATE)
    assert not res.applied and len(res.unmatched) == 1
    assert res.edit_results[0]["reason"] == "scope_mismatch"
    # The accepted active text, including qualifiers, is unchanged.
    root = ET.fromstring(_document_xml(res.content))
    assert "".join(t.text or "" for t in root.iter(f"{W}t")) == wrapped
    assert _document_xml(res.content) == _document_xml(original)


def test_synthesized_redline_for_a_pdf_upload():
    res = dr.build_redlined_docx(
        ["1. Scope of processing.", CLAUSE],
        [dr.ClauseEdit(find=CLAUSE, replace=FIXED)],
        date=DATE, title="Acme DPA (reconstructed from PDF)")
    assert res.synthesized and len(res.applied) == 1
    xml = _document_xml(res.content)
    ET.fromstring(xml)          # well-formed
    assert "was not modified" in xml       # honest about the reconstruction
    assert dr.revision_count(res.content) == (1, 1)
    # A complete, spec-conformant package -- not just well-formed XML.
    assert_valid_opc(res.content)
    with zipfile.ZipFile(io.BytesIO(res.content)) as z:
        assert set(z.namelist()) == {
            "[Content_Types].xml", "_rels/.rels", "word/document.xml",
            "word/_rels/document.xml.rels", "word/settings.xml"}
    # Tracking stays ON so counsel's own edits are captured too.
    with zipfile.ZipFile(io.BytesIO(res.content)) as z:
        assert b"trackChanges" in z.read("word/settings.xml")
    # The body ends with section properties, as every Word body does.
    assert xml.rstrip().endswith("</w:sectPr></w:body></w:document>")


def test_xml_special_characters_are_escaped():
    nasty = 'Processor <may> use "AI" & ML at its discretion.'
    res = dr.build_redlined_docx(
        [nasty], [dr.ClauseEdit(find=nasty, replace="Processor shall not.")],
        date=DATE)
    xml = _document_xml(res.content)
    root = ET.fromstring(xml)   # would raise if we emitted raw < or &
    text = "".join(n.text or "" for n in root.iter() if n.text)
    assert "<may>" in text and "&" in text


def test_control_characters_xml_forbids_are_removed():
    # A form feed (PDF page break) made word/document.xml malformed, and an
    # inserted clause then raised an uncaught ParseError.
    res = dr.build_redlined_docx(
        ["Clause one\x0ctext"],
        [dr.ClauseEdit(find="Clause one\x0ctext", replace="Clause\x00 two."),
         dr.ClauseEdit(find="", replace="An added\x0bclause.")],
        date=DATE)
    root = ET.fromstring(_document_xml(res.content))
    text = "".join(n.text or "" for n in root.iter() if n.text)
    assert "Clause one text" in text and "Clause two." in text and "An added clause." in text
    assert len(res.applied) == 1 and len(res.inserted) == 1


def test_rejects_input_that_is_not_a_docx():
    with pytest.raises(dr.RedlineError):
        dr.redline_docx(b"%PDF-1.7 not a zip", [], date=DATE)
    with pytest.raises(dr.RedlineError):
        dr.redline_docx(b"", [], date=DATE)
    # A zip without a document body is rejected, not silently returned.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/styles.xml", "<styles/>")
    with pytest.raises(dr.RedlineError):
        dr.redline_docx(buf.getvalue(), [], date=DATE)


def test_oversized_upload_is_refused():
    with pytest.raises(dr.RedlineError):
        dr.redline_docx(b"x" * (dr._MAX_DOCX_BYTES + 1), [], date=DATE)


def test_revision_ids_are_unique():
    original = _make_docx([CLAUSE, "2. Term.", "3. Fees."])
    res = dr.redline_docx(
        original,
        [dr.ClauseEdit(find=CLAUSE, replace=FIXED),
         dr.ClauseEdit(find="2. Term.", replace="2. Term is three years."),
         dr.ClauseEdit(replace="New clause.")], date=DATE)
    xml = _document_xml(res.content)
    ids = re.findall(r'w:id="(\d+)"', xml)
    assert len(ids) == len(set(ids)) and len(ids) >= 5


# --- the plain builder (generated deliverables) ----------------------------

def test_build_docx_is_valid_opc_with_red_fill_runs():
    content = dr.build_docx([
        ("title", [("DATA PROCESSING AGREEMENT", False)]),
        ("para", [("between ", False), ("Acme Corp", True),
                  (" and ", False), ("[CONTROLLER]", True)]),
        ("heading", [("1. Instructions", False)]),
        ("para", [("Processor shall follow instructions.", False)]),
        ("para", []),
    ])
    assert_valid_opc(content)
    doc = _document_xml(content)
    # Filled values are red; template prose is not.
    assert doc.count(f'<w:color w:val="{dr.FILL_COLOR}"/>') == 2
    assert "Acme Corp" in doc and "[CONTROLLER]" in doc
    # A generated document must never fake tracked changes.
    assert dr.revision_count(content) == (0, 0)


def test_text_to_docx_turns_rule_underlines_into_headings():
    text = ("VENDOR PAPER REVIEW — Acme  (v1)\n"
            "====================\n"
            "Document reviewed : a.docx\n"
            "\n"
            "RECOMMENDATION\n"
            "--------------------\n"
            "Do not sign & fix <clauses> first.\n")
    content = dr.text_to_docx(text, title="Analysis memo")
    assert_valid_opc(content)
    doc = _document_xml(content)
    # Rule lines disappear; the lines above them become styled headings
    # (boldness moved into the style sheet, off the individual runs).
    assert "====" not in doc and "----" not in doc
    assert 'pStyle w:val="Title"' in doc
    assert doc.count('pStyle w:val="Heading1"') == 2
    # Body text survives, XML-escaped.
    assert "Do not sign &amp; fix &lt;clauses&gt; first." in doc


def test_report_docx_ships_the_designed_package():
    """Generated deliverables are designed documents: a styles part with the
    brand ramp, bullets via numbering, a branded header, and a footer with
    page-number fields."""
    content = dr.text_to_docx(
        "SUMMARY OF RECORD\n-----------------\n"
        "System / vendor : Acme\n"
        "Ticket          : PRV1 — requested by Kim\n\n"
        "FINDINGS (1)\n------------\n"
        "1. [HIGH] Assessment: transfer unsafeguarded.\n"
        "   Remediation: fix before renewal.\n\n"
        "REQUIRED CONTROLS\n-----------------\n"
        "- SCCs executed\n",
        title="Risk Analysis — Acme", subtitle="Acme · risk analysis · v1")
    z = zipfile.ZipFile(io.BytesIO(content))
    names = set(z.namelist())
    assert {"word/styles.xml", "word/numbering.xml",
            "word/header1.xml", "word/footer1.xml"} <= names
    doc = z.read("word/document.xml").decode()
    # key : value lines fold into the metadata table, padding gone
    assert "<w:tbl>" in doc and "System / vendor" in doc
    assert "Ticket          :" not in doc
    # severity carries its status color; the bullet uses real numbering
    assert 'w:val="C0392B"' in doc
    assert "<w:numPr>" in doc
    footer = z.read("word/footer1.xml").decode()
    assert " PAGE " in footer and " NUMPAGES " in footer
    assert "Risk Analysis — Acme" in footer
    styles = z.read("word/styles.xml").decode()
    assert "Calibri" in styles and "21426F" in styles


def test_build_docx_keeps_legacy_block_contract():
    """(style, [(text, red_bool)]) blocks from existing callers still render;
    red fills keep the FF0000 fill color."""
    content = dr.build_docx([
        ("title", [("Data Processing Addendum", False)]),
        ("heading", [("1. Scope (Art. 28)", False)]),
        ("para", [("Processor shall act only on instructions of ", False),
                  ("Acme Corp", True)]),
    ])
    assert_valid_opc(content)
    doc = _document_xml(content)
    assert f'w:val="{dr.FILL_COLOR}"' in doc
    assert 'pStyle w:val="Title"' in doc
