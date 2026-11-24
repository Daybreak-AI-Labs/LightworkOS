"""Hand-labeled document coverage, original-source hashes and exact text identity."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest
from maverick_knowledge.base import KnowledgeBase
from maverick_knowledge.extraction import ExtractionBuilder
from maverick_knowledge.parse import extract_document, extract_text
from maverick_knowledge.store import SqliteVectorStore


def test_unknown_and_mislabeled_binary_are_never_decoded_as_text(tmp_path):
    path = tmp_path / "book.xls"
    path.write_bytes(b"\xd0\xcf\x11\xe0binary source\x00")
    result = extract_document(path)
    assert result.status == "unsupported" and result.text == ""
    assert result.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="qualified extractor"):
        extract_text(path)
    path = tmp_path / "disguised.txt"
    path.write_bytes(b"PK\x03\x04binary archive")
    assert extract_document(path).status == "rejected"
    path.write_bytes(b"text\xffinvalid encoding")
    assert extract_document(path).status == "rejected"


def test_valid_native_written_xlsx_has_ordered_cells_and_no_zip_garbage(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    path = tmp_path / "revenue.xlsx"
    workbook = openpyxl.Workbook()
    workbook.active.title = "Revenue"
    workbook.active.append(["Revenue", 120000])
    workbook.active.append(["Forecast", "=B1*2"])
    workbook.active.append(["Hidden", "private"])
    workbook.active.row_dimensions[3].hidden = True
    workbook.save(path)
    workbook.close()
    original = path.read_bytes()
    result = extract_document(path)
    assert result.status == "partial"
    assert [b.text for b in result.blocks] == ["Revenue!A1: Revenue", "Revenue!B1: 120000",
                                             "Revenue!A2: Forecast", "Revenue!B2: =B1*2 [uncalculated]"]
    assert [b.location for b in result.blocks] == ["worksheet:Revenue!A1", "worksheet:Revenue!B1",
                                                 "worksheet:Revenue!A2", "worksheet:Revenue!B2"]
    assert "private" not in result.text and "\ufffd" not in result.text
    assert any("A3:hidden" in s for s in result.omitted_regions)
    assert path.read_bytes() == original
    assert result.source_sha256 == hashlib.sha256(original).hexdigest()
    for block in result.blocks:
        assert result.text[block.start:block.end] == block.text


def test_valid_native_written_docx_preserves_body_table_body_order(tmp_path):
    docx = pytest.importorskip("docx")
    path = tmp_path / "plan.docx"
    document = docx.Document()
    document.add_paragraph("Before table")
    table = document.add_table(rows=1, cols=2)
    table.cell(0, 0).text, table.cell(0, 1).text = "Revenue", "120000"
    document.add_paragraph("After table")
    document.sections[0].header.paragraphs[0].text = "Header not in body"
    document.save(path)
    result = extract_document(path)
    assert result.status == "partial"
    assert [b.text for b in result.blocks] == ["Before table", "| Revenue | 120000 |", "After table"]
    assert [b.kind for b in result.blocks] == ["paragraph", "table_row", "paragraph"]
    assert result.blocks[1].location.endswith("/row[1]")
    assert any("header" in s for s in result.omitted_regions)


def test_a_word_table_keeps_its_rows_and_blank_cells(tmp_path):
    # A table read one cell per line lost its blanks: "Rent 3000 3000" could
    # not say which quarter was empty, and an agent mis-added a timesheet.
    docx = pytest.importorskip("docx")
    from maverick_knowledge.office_extract import word_tables

    path = tmp_path / "budget.docx"
    document = docx.Document()
    table = document.add_table(rows=4, cols=4)
    for r, row in enumerate([["Item", "Q1", "Q2", "Q3"], ["Rent", "3000", "", "3000"],
                             ["", "", "", ""], ["Ads | print", "", "500", "700"]]):
        for c, value in enumerate(row):
            table.cell(r, c).text = value
    merged = document.add_table(rows=2, cols=3)
    merged.cell(0, 0).merge(merged.cell(0, 1)).text = "Name"
    merged.cell(0, 2).text = "Total"
    merged.cell(1, 0).text, merged.cell(1, 1).text, merged.cell(1, 2).text = "A", "B", "9"
    document.save(path)
    result = extract_document(path)
    rows = [b.text for b in result.blocks if b.kind == "table_row"]
    assert rows[:3] == ["| Item | Q1 | Q2 | Q3 |", "| Rent | 3000 |  | 3000 |", "| Ads \\| print |  | 500 | 700 |"]
    assert rows[3] == "| Name |  | Total |"
    for block in result.blocks:
        assert result.text[block.start:block.end] == block.text
    tables = word_tables(path.read_bytes(), 10_000_000)
    assert tables[0] == [["Item", "Q1", "Q2", "Q3"], ["Rent", "3000", "", "3000"],
                         ["", "", "", ""], ["Ads | print", "", "500", "700"]]
    assert tables[1] == [["Name", "", "Total"], ["A", "B", "9"]]


def test_native_pdf_marks_image_page_without_guessing_ocr_confidence(tmp_path):
    pytest.importorskip("pypdf")
    canvas = pytest.importorskip("reportlab.pdfgen.canvas")
    image = pytest.importorskip("PIL.Image")
    from reportlab.lib.utils import ImageReader

    path = tmp_path / "mixed.pdf"
    writer = canvas.Canvas(str(path))
    writer.drawString(40, 700, "Revenue 120000")
    writer.showPage()
    buffer = io.BytesIO()
    image.new("RGB", (20, 20), "white").save(buffer, "PNG")
    writer.drawImage(ImageReader(buffer), 40, 650, 40, 40)
    writer.save()
    result = extract_document(path)
    assert result.status == "partial"
    assert "Revenue 120000" in result.text
    assert result.covered_regions == ("pdf/page[1]",)
    assert result.omitted_regions[0].startswith("pdf/page[2]: no extracted text")
    assert any("OCR is not configured or invoked" in warning for warning in result.warnings)


@pytest.mark.parametrize("malformation", ["duplicate", "entity", "macro", "external", "traversal"])
def test_hostile_office_package_is_explicitly_rejected(tmp_path, malformation):
    path = tmp_path / "hostile.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        if malformation == "duplicate":
            archive.writestr("[content_types].xml", "<Types/>")
        elif malformation == "entity":
            archive.writestr("word/document.xml", '<!DOCTYPE x [<!ENTITY e "x">]><x>&e;</x>')
        elif malformation == "macro":
            archive.writestr("word/vbaProject.bin", b"opaque")
        elif malformation == "external":
            archive.writestr("word/_rels/document.xml.rels", '<Relationships><Relationship TargetMode="External" Target="https://invalid"/></Relationships>')
        else:
            archive.writestr("../escape.xml", "<x/>")
    result = extract_document(path)
    assert result.status == "rejected" and not result.text


def test_companion_truncation_has_normalized_range_and_partial_source_location():
    builder = ExtractionBuilder()
    builder.append("Revenue 120000. " * 1000, "worksheet:Revenue!A1", "cell")
    result = builder.finish("xlsx", "a" * 64, "fixture-v1")
    companion = result.companion(2400)
    metadata = json.loads(companion.splitlines()[1])
    assert len(companion) <= 2400
    assert metadata["status"] == "partial" and metadata["truncated"]
    assert metadata["source_sha256"] == "a" * 64
    assert metadata["included_range"][0] == 0
    assert metadata["included_range"][1] < metadata["normalized_length"]
    assert metadata["locations"][0]["location"] == "worksheet:Revenue!A1"
    assert metadata["locations"][0]["partial"]
    assert companion.split("[Extracted text]\n", 1)[1] == result.text[:metadata["included_range"][1]]
    with pytest.raises(ValueError, match="too small"):
        result.companion(20)


def test_text_extraction_boundary_remains_explicit_in_ingestion(monkeypatch, tmp_path):
    from maverick_knowledge import extraction

    monkeypatch.setattr(extraction, "MAX_TEXT_CHARS", 30)
    path = tmp_path / "bounded.txt"
    path.write_text("Revenue 120000. " * 5)
    result = extract_document(path)
    assert result.status == "partial" and result.text == path.read_text()[:30]
    assert result.omitted_regions == ("text/character-stream: characters 30 onward",)
    kb = KnowledgeBase(store=SqliteVectorStore(tmp_path / "bounded.db"), chunk_size=15, chunk_overlap=3)
    try:
        kb.ingest_path("sales", path)
        exact = kb.exact_document("sales", hashlib.sha256(result.text.encode()).hexdigest())
        assert exact["text"] == result.text
        assert exact["metadata"]["extraction"]["status"] == "partial"
        assert exact["metadata"]["extraction"]["omitted_regions"] == list(result.omitted_regions)
    finally:
        kb.close()


@pytest.mark.parametrize("suffix", ["pptx", "rtf", "odt"])
def test_unqualified_formats_have_typed_unsupported_coverage(tmp_path, suffix):
    path = tmp_path / ("document." + suffix)
    path.write_bytes(b"format fixture")
    result = extract_document(path)
    assert result.status == "unsupported" and result.omitted_regions == ("whole-source",)
    assert result.text == ""


def test_word_field_results_are_refused_instead_of_silently_skipped(tmp_path):
    docx = pytest.importorskip("docx")
    from docx.oxml import OxmlElement

    path = tmp_path / "field.docx"
    document = docx.Document()
    paragraph = document.add_paragraph("Before ")
    field = OxmlElement("w:instrText")
    field.text = "MERGEFIELD Revenue"
    paragraph.add_run()._r.append(field)
    document.save(path)
    result = extract_document(path)
    assert result.status == "rejected" and result.text == ""
    assert any("fields" in warning for warning in result.warnings)


@pytest.mark.parametrize("tag", ["ins", "del", "instrText", "txbxContent", "altChunk", "object"])
def test_word_tables_refuse_what_extraction_refuses(tmp_path, tag):
    # A table cell with a pending tracked change (or a field, text box or
    # embedded content) was refused by extraction but read by the table path
    # behind `sql`: an unaccepted insertion counted as accepted.
    docx = pytest.importorskip("docx")
    from docx.oxml import OxmlElement
    from maverick_knowledge.parse import word_document_tables

    path = tmp_path / "timesheet.docx"
    document = docx.Document()
    table = document.add_table(rows=2, cols=2)
    table.cell(0, 0).text, table.cell(0, 1).text = "Name", "Hours"
    table.cell(1, 0).text, table.cell(1, 1).text = "Ann", "40"
    table.cell(1, 1).paragraphs[0]._p.append(OxmlElement(f"w:{tag}"))
    document.save(path)
    result = extract_document(path)
    assert result.status == "rejected" and result.text == ""
    with pytest.raises(ValueError, match="reviewed text copy"):
        word_document_tables(path.read_bytes())


def test_ingestion_retains_extraction_metadata_and_exact_reconstruction(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("Revenue 120000. Customer count 12.\n" * 3)
    extraction = extract_document(path)
    kb = KnowledgeBase(store=SqliteVectorStore(tmp_path / "knowledge.db"), chunk_size=32, chunk_overlap=8)
    try:
        assert kb.ingest_path("sales", path) > 1
        digest = hashlib.sha256(extraction.text.encode()).hexdigest()
        exact = kb.exact_document("sales", digest)
        assert exact["text"] == extraction.text
        assert exact["metadata"]["extraction"] == extraction.metadata()
        # Same bytes under incompatible extraction provenance cannot overwrite.
        with pytest.raises(RuntimeError, match="different provenance"):
            kb.ingest_text("sales", extraction.text, source=str(path), extra_meta={"extraction": {"schema": "changed"}})
    finally:
        kb.close()
