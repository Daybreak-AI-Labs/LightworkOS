"""R16: inspect active accepted text and preserve unsupported source structures."""
from __future__ import annotations

import io
import zipfile
from hashlib import sha256
from xml.etree import ElementTree as ET

import pytest
from maverick import docx_redline as dr

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
DATE = "2026-09-22T12:00:00Z"
CLAUSE = "Processor may engage any subcontractor without prior notice."
FIXED = "Processor must obtain prior written approval."


def package(paragraphs):
    xml = (
        f'<w:document xmlns:w="{dr._W_NS}" xmlns:r="urn:test-relationships">'
        f'<w:body>{"".join(paragraphs)}{dr._SECT_PR}</w:body></w:document>')
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
        archive.writestr("word/numbering.xml", b"unchanged numbering")
        archive.writestr("word/_rels/document.xml.rels", b"unchanged relationships")
    return target.getvalue()


def document(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return archive.read("word/document.xml").decode()


def accepted_paragraphs(data):
    # Applying revisions retains ordinary/inserted w:t and drops w:delText.
    root = ET.fromstring(document(data))
    return ["".join(node.text or "" for node in para.iter(f"{W}t"))
            for para in root.iter(f"{W}p")]


def test_full_paragraph_proposal_explicitly_preserves_neighboring_clause():
    wrapped = "8.2. " + CLAUSE + " This duty survives termination."
    replacement = "8.2. " + FIXED + " This duty survives termination."
    original = package([dr._plain_paragraph(wrapped), dr._plain_paragraph("9. Fees remain due.")])
    result = dr.redline_docx(
        original, [dr.ClauseEdit(find=wrapped, replace=replacement)], date=DATE)
    assert accepted_paragraphs(result.content) == [replacement, "9. Fees remain due."]
    assert result.edit_results == [{
        "edit_index": 0, "scope": "paragraph", "status": "applied", "reason": "",
        "source_sha256": sha256(original).hexdigest(), "paragraph_index": 0,
    }]


def test_duplicate_clauses_require_source_bound_location():
    original = package([dr._plain_paragraph(CLAUSE), dr._plain_paragraph(CLAUSE)])
    edit = dr.ClauseEdit(find=CLAUSE, replace=FIXED)
    ambiguous = dr.redline_docx(original, [edit], date=DATE)
    assert not ambiguous.applied
    assert ambiguous.edit_results[0]["reason"] == "ambiguous_match"
    assert accepted_paragraphs(ambiguous.content) == [CLAUSE, CLAUSE]

    edit.location = dr.ParagraphLocation(sha256(original).hexdigest(), 1)
    exact = dr.redline_docx(original, [edit], date=DATE)
    assert accepted_paragraphs(exact.content) == [CLAUSE, FIXED]
    assert exact.edit_results[0]["paragraph_index"] == 1

    changed = package([dr._plain_paragraph("new first paragraph"), dr._plain_paragraph(CLAUSE)])
    stale = dr.redline_docx(changed, [edit], date=DATE)
    assert stale.edit_results[0]["reason"] == "stale_source"
    assert document(stale.content) == document(changed)


@pytest.mark.parametrize("inline", [
    '<w:hyperlink r:id="rId1"><w:r><w:t>{text}</w:t></w:r></w:hyperlink>',
    '<w:bookmarkStart w:id="1" w:name="clause"/><w:r><w:t>{text}</w:t></w:r><w:bookmarkEnd w:id="1"/>',
    '<w:r><w:rPr><w:b/></w:rPr><w:t>{text}</w:t></w:r>',
    '<w:r><w:fldChar w:fldCharType="begin"/><w:t>{text}</w:t></w:r>',
    '<w:ins w:id="9001"><w:r><w:t>{text}</w:t></w:r></w:ins>',
    '<w:r><w:t>{text}</w:t><w:tab/></w:r>',
])
def test_unsupported_target_is_visibly_refused_and_survives_other_edits(inline):
    complex_paragraph = f'<w:p>{inline.format(text=CLAUSE)}</w:p>'
    original = package([complex_paragraph, dr._plain_paragraph("Other complete paragraph.")])
    result = dr.redline_docx(original, [
        dr.ClauseEdit(find=CLAUSE, replace=FIXED),
        dr.ClauseEdit(find="Other complete paragraph.", replace="Other revised paragraph."),
    ], date=DATE)
    assert result.edit_results[0]["reason"] == "unsupported_inline_structure"
    assert complex_paragraph in document(result.content)
    assert accepted_paragraphs(result.content) == [CLAUSE, "Other revised paragraph."]
    with zipfile.ZipFile(io.BytesIO(original)) as before, zipfile.ZipFile(io.BytesIO(result.content)) as after:
        for name in ("word/numbering.xml", "word/_rels/document.xml.rels"):
            assert after.read(name) == before.read(name)


def test_numbering_properties_paragraph_identity_and_untouched_runs_survive():
    original_para = (
        '<w:p w:rsidR="12345678"><w:pPr><w:numPr><w:ilvl w:val="1"/>'
        '<w:numId w:val="2"/></w:numPr></w:pPr>'
        f'<w:r><w:t>{CLAUSE}</w:t></w:r></w:p>')
    neighbor = '<w:p><w:r><w:rPr><w:i/></w:rPr><w:t>Neighbor.</w:t></w:r></w:p>'
    result = dr.redline_docx(package([original_para, neighbor]), [
        dr.ClauseEdit(find=CLAUSE, replace=FIXED)], date=DATE)
    xml = document(result.content)
    assert 'w:rsidR="12345678"' in xml
    assert '<w:numId w:val="2"/>' in xml
    assert neighbor in xml
    assert accepted_paragraphs(result.content) == [FIXED, "Neighbor."]


@pytest.mark.parametrize("location", [-1, 99, True, "0"])
def test_invalid_location_never_expands_scope(location):
    original = package([dr._plain_paragraph(CLAUSE)])
    edit = dr.ClauseEdit(find=CLAUSE, replace=FIXED, location=dr.ParagraphLocation(
        sha256(original).hexdigest(), location))
    result = dr.redline_docx(original, [edit], date=DATE)
    assert not result.applied
    assert result.edit_results[0]["reason"] == "invalid_location"


def test_clause_scope_is_explicitly_unsupported_even_with_exact_text():
    original = package([dr._plain_paragraph(CLAUSE)])
    result = dr.redline_docx(original, [
        dr.ClauseEdit(find=CLAUSE, replace=FIXED, scope="clause")], date=DATE)
    assert result.edit_results[0]["reason"] == "unsupported_scope"
    assert accepted_paragraphs(result.content) == [CLAUSE]


def test_synthesized_pdf_uses_same_scope_rules_and_preserves_section_order():
    wrapped = "8.2. " + CLAUSE + " Survival remains."
    result = dr.build_redlined_docx([wrapped, CLAUSE, CLAUSE], [
        dr.ClauseEdit(find=CLAUSE, replace=FIXED),
        dr.ClauseEdit(replace="Proposed additional duty."),
    ], title="Reconstructed review", date=DATE)
    assert result.synthesized
    assert result.edit_results[0]["reason"] == "ambiguous_match"
    assert wrapped in accepted_paragraphs(result.content)
    assert "was not modified" in document(result.content)
    body = ET.fromstring(document(result.content)).find(f"{W}body")
    assert body[-1].tag == f"{W}sectPr"


def test_location_cannot_override_a_partial_anchor():
    wrapped = "8.2. " + CLAUSE + " Survival remains."
    original = package([dr._plain_paragraph(wrapped)])
    result = dr.redline_docx(original, [dr.ClauseEdit(
        find=CLAUSE, replace=FIXED, location=dr.ParagraphLocation(
            sha256(original).hexdigest(), 0))], date=DATE)
    assert result.edit_results[0]["reason"] == "scope_mismatch"
    assert accepted_paragraphs(result.content) == [wrapped]
