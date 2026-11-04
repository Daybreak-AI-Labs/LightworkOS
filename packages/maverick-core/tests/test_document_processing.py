"""Workbook preservation, formula honesty and native-engine boundary regressions."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from maverick import config
from maverick.sandbox.document_engine import _pages
from maverick.sandbox.local import LocalBackend
from maverick.tools import document_processing, spreadsheet
from maverick.tools.office_package import WorkbookPackage, _xml

openpyxl = pytest.importorskip("openpyxl")


def test_frozen_package_retains_document_helper_source_and_parser_imports():
    root = Path(__file__).resolve().parents[3]
    spec = (root / "build/maverick.spec").read_text(encoding="utf-8")
    assert "sandbox/document_engine.py" in spec and "include_py_files=True" in spec
    for module in ("openpyxl", "lxml", "pypdf", "pdfplumber"):
        assert f"collect_submodules('{module}')" in spec


def test_release_document_runtime_requires_real_parsers_and_worker_source(monkeypatch):
    pytest.importorskip("pdfplumber")
    document_processing.verify_release_document_runtime()
    original_import = document_processing.importlib.import_module
    def missing_parser(name):
        if name == "lxml.etree":
            raise ImportError("packaged XML parser missing")
        return original_import(name)
    monkeypatch.setattr(document_processing.importlib, "import_module", missing_parser)
    with pytest.raises(ImportError, match="packaged XML parser missing"):
        document_processing.verify_release_document_runtime()


def _workbook(path, *, macros=False):
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Orders"
    sheet.append(["Quantity", "Price", "Total"])
    sheet.append([10, 25, "=A2*B2"])
    workbook.create_sheet("Summary")["A1"] = "=Orders!C2"
    workbook.save(path)
    workbook.close()
    if macros:
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("xl/vbaProject.bin", b"opaque VBA fixture; preservation test, not executable macro validation")
            archive.writestr("customXml/item1.xml", b'<custom xmlns="urn:test">retained</custom>')
    return path


def _parts(path):
    with zipfile.ZipFile(path) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_formula_read_distinguishes_uncalculated_from_empty_and_zero(tmp_path):
    path = _workbook(tmp_path / "book.xlsx")
    rows = json.loads(spreadsheet._run({"op": "read", "path": str(path)}))
    assert rows[1][2] == {"formula": "=A2*B2", "cached_value": None,
                          "value_status": "uncalculated", "cell": "C2"}
    package = WorkbookPackage(path)
    raw = package.parts["xl/worksheets/sheet1.xml"]
    package.parts["xl/worksheets/sheet1.xml"] = raw.replace(b"<v></v>", b"<v>0</v>")
    package.write(path)
    cell = json.loads(spreadsheet._run({"op": "read", "path": str(path)}))[1][2]
    assert cell["cached_value"] == 0 and cell["value_status"] == "cached"


@pytest.mark.parametrize("dimension", [None, "A1:A1"])
def test_actual_spreadsheet_coordinates_enforce_read_size_ceiling(tmp_path, dimension):
    path = tmp_path / "sparse.xlsx"
    workbook = openpyxl.Workbook()
    for row in range(1, 101):
        workbook.active.cell(row, 1001, row)
    workbook.save(path)
    workbook.close()
    package = WorkbookPackage(path)
    package.set_cell("A1", 1, None)  # Supported editing removes optional dimensions.
    if dimension:
        raw = package.parts["xl/worksheets/sheet1.xml"]
        package.parts["xl/worksheets/sheet1.xml"] = raw.replace(
            b"<sheetData>", f'<dimension ref="{dimension}"/><sheetData>'.encode(),
        )
    package.write(path)
    with pytest.raises(ValueError, match="100,000 cells"):
        spreadsheet._xlsx_read(path, None, 100)
    # A smaller requested range stays usable and is derived from real cells,
    # including when the advertised dimension would hide those cells.
    rows = spreadsheet._xlsx_read(path, None, 2)
    assert len(rows) == 2 and all(len(row) == 1001 for row in rows)
    assert rows[0][-1] == 1 and rows[1][-1] == 2


def test_cached_workbook_open_failure_closes_formula_workbook(tmp_path, monkeypatch):
    path = _workbook(tmp_path / "book.xlsx")
    load = openpyxl.load_workbook
    formula_book = load(path, read_only=True)
    def fail_second_open(*args, **kwargs):
        if kwargs.get("data_only"):
            raise OSError("cached workbook unavailable")
        return formula_book
    monkeypatch.setattr(openpyxl, "load_workbook", fail_second_open)
    with pytest.raises(OSError, match="unavailable"):
        spreadsheet._xlsx_read(path, None, 50)
    assert formula_book._archive.fp is None


def test_macro_cell_edit_preserves_every_untouched_part_and_neutralizes_formulas(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"documents": {"macro_cell_edits": True}})
    path = _workbook(tmp_path / "book.xlsm", macros=True)
    before = _parts(path)
    result = spreadsheet._run({"op": "set_cell", "path": str(path), "cell": "B2", "value": "=WEBSERVICE(\"https://invalid\")"})
    assert result.startswith("set B2"), result
    after = _parts(path)
    assert set(after) == set(before)
    for name in before:
        if name not in {"xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml", "xl/workbook.xml"}:
            assert after[name] == before[name], name
    workbook = openpyxl.load_workbook(path, keep_vba=True)
    try:
        assert workbook["Orders"]["B2"].value.startswith("'=")
        assert workbook["Orders"]["C2"].value == "=A2*B2"
        assert workbook["Summary"]["A1"].value == "=Orders!C2"
    finally:
        workbook.close()
        workbook.vba_archive.close()


def test_new_macro_cell_extends_readable_bounds_without_renaming_sheets(tmp_path):
    path = _workbook(tmp_path / "book.xlsm", macros=True)
    package = WorkbookPackage(path)
    package.set_cell("G8", 99, "Summary")
    package.write(path)
    wb = openpyxl.load_workbook(path, read_only=True)
    try:
        assert wb.sheetnames == ["Orders", "Summary"]
        assert wb["Summary"]["G8"].value == 99
    finally:
        wb.close()


@pytest.mark.parametrize("cell,value", [("A0", 1), ("XFE1", 1), ("A1048577", 1), ("A1:B2", 1), ("B2", float("nan"))])
def test_invalid_macro_edits_leave_original_unchanged(tmp_path, cell, value):
    path = _workbook(tmp_path / "book.xlsm", macros=True)
    original = path.read_bytes()
    with pytest.raises(ValueError):
        WorkbookPackage(path).set_cell(cell, value, None)
    assert path.read_bytes() == original


def test_signed_workbook_and_entity_xml_are_refused(tmp_path):
    path = _workbook(tmp_path / "signed.xlsx")
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("_xmlsignatures/sig1.xml", "signature fixture")
    with pytest.raises(ValueError, match="signed"):
        WorkbookPackage(path)
    with pytest.raises(ValueError, match="entities"):
        _xml(b'<!DOCTYPE x [<!ENTITY e "secret">]><x>&e;</x>')


def test_recalculation_merges_only_caches_and_preserves_original_formulas(tmp_path):
    path = _workbook(tmp_path / "source.xlsm", macros=True)
    original = WorkbookPackage(path)
    output = WorkbookPackage(path)
    for name in output.sheets.values():
        output.parts[name] = output.parts[name].replace(b"<v></v>", b"<v>250</v>")
    assert original.import_caches(output) == 2
    dest = tmp_path / "result.xlsm"
    original.write(dest)
    assert _parts(dest)["xl/vbaProject.bin"] == _parts(path)["xl/vbaProject.bin"]
    values = openpyxl.load_workbook(dest, data_only=True)
    formulas = openpyxl.load_workbook(dest, data_only=False)
    try:
        assert values["Summary"]["A1"].value == 250
        assert formulas["Summary"]["A1"].value == "=Orders!C2"
    finally:
        values.close()
        formulas.close()


def test_missing_native_calculation_result_does_not_change_original(tmp_path, monkeypatch):
    from maverick.sandbox.docker import DockerBackend
    from maverick.sandbox.local import ExecResult
    monkeypatch.setattr(config, "load_config", lambda: {"documents": {"native_recalculation": True}})
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    monkeypatch.setattr(DockerBackend, "exec", lambda self, *args, **kwargs: ExecResult("", "engine missing", 127))
    path = _workbook(tmp_path / "book.xlsx")
    original = path.read_bytes()
    with pytest.raises(RuntimeError, match="no result"):
        document_processing.recalculate(path, DockerBackend(workdir=tmp_path))
    assert path.read_bytes() == original


def test_native_worker_receives_only_job_files_and_no_network(tmp_path, monkeypatch):
    from maverick.sandbox.docker import DockerBackend
    from maverick.sandbox.workspace_guard import validate_container_workspace
    monkeypatch.setattr(DockerBackend, "_verify_docker", lambda self: None)
    (tmp_path / "unrelated-secret.txt").write_text("must stay outside")
    backend = DockerBackend(workdir=tmp_path, allow_network=True, reuse_container=True)
    with document_processing._worker(backend, {"operation": "ocr"}) as (stage, worker):
        assert worker.workdir == stage and worker.workdir != backend.workdir
        assert not worker.allow_network and not worker.reuse_container
        validate_container_workspace(stage)
        assert set(p.name for p in stage.iterdir()) == {"engine.py", "request.json"}
        assert "unrelated-secret.txt" not in (stage / "request.json").read_text()
    assert not stage.exists()
    with pytest.raises(ValueError, match="dedicated workspace"):
        validate_container_workspace(stage)


def test_native_processing_refuses_unsandboxed_host(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"documents": {"pdf_ocr": True}})
    with pytest.raises(RuntimeError, match="Docker, Podman or Kubernetes"):
        document_processing.ocr_pdf(b"PDF fixture", "1", LocalBackend(tmp_path))


def test_ocr_selection_is_bounded_before_large_ranges_are_allocated():
    assert _pages("1-2,4", 5, 3) == [1, 2, 4]
    with pytest.raises(ValueError, match="limited"):
        _pages("1-999999999", 999999999, 20)
    with pytest.raises(ValueError, match="limited"):
        _pages("", 21, 20)
    with pytest.raises(ValueError, match="No PDF pages"):
        _pages("1000-", 3, 20)


def test_ocr_fallback_and_explicit_hybrid_selection_use_job_bytes(tmp_path, monkeypatch):
    from maverick.tools import pdf_reader
    monkeypatch.setattr(config, "load_config", lambda: {"documents": {"pdf_ocr": True}})
    monkeypatch.setattr(pdf_reader, "_selected_text", lambda *args: "")
    seen = []
    def ocr(data, pages, sandbox):
        seen.append((data, pages, sandbox))
        return "Page 1 [OCR]: invoice total 250"
    monkeypatch.setattr(document_processing, "ocr_pdf", ocr)
    path = tmp_path / "scan.pdf"
    path.write_bytes(b"synthetic PDF bytes")
    backend = LocalBackend(tmp_path)
    result = pdf_reader._run_read_pdf({"source": "scan.pdf", "pages": "1"}, backend)
    assert "total 250" in result and seen[0] == (path.read_bytes(), "1", backend)
    monkeypatch.setattr(pdf_reader, "_selected_text", lambda *args: pytest.fail("explicit OCR should include image-only pages"))
    assert "OCR" in pdf_reader._run_read_pdf({"source": "scan.pdf", "ocr": True}, backend)


def test_archive_duplicate_members_are_refused(tmp_path):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("xl/workbook.xml", "first")
        with pytest.warns(UserWarning):
            archive.writestr("xl/workbook.xml", "second")
    with pytest.raises(ValueError, match="ambiguous"):
        WorkbookPackage(raw.getvalue())
