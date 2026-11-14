"""Spreadsheet tool: CSV (stdlib) + XLSX (openpyxl extra)."""
from __future__ import annotations

import json

import pytest
from maverick.tools import spreadsheet as ss

# ---- CSV (stdlib, always available) -----------------------------------------

def test_csv_write_read_info(tmp_path):
    p = tmp_path / "data.csv"
    assert ss._run({"op": "write", "path": str(p),
                    "rows": [["a", "b"], [1, 2], [3, 4]]}).startswith("wrote 3")
    rows = json.loads(ss._run({"op": "read", "path": str(p)}))
    assert rows[0] == ["a", "b"] and rows[1] == ["1", "2"]   # csv reads back as strings
    assert "rows=3" in ss._run({"op": "info", "path": str(p)})


def test_neutralize_formula_helper():
    assert ss._neutralize_formula("=1+1") == "'=1+1"
    assert ss._neutralize_formula("+x") == "'+x"
    assert ss._neutralize_formula("-x") == "'-x"
    assert ss._neutralize_formula("@x") == "'@x"
    assert ss._neutralize_formula("\tx") == "'\tx"
    assert ss._neutralize_formula("\rx") == "'\rx"
    assert ss._neutralize_formula("\nx") == "'\nx"
    assert ss._neutralize_formula("  =x") == "'  =x"
    assert ss._neutralize_formula(" \t=x") == "' \t=x"
    assert ss._neutralize_formula("safe") == "safe"
    assert ss._neutralize_formula(42) == 42       # numbers untouched
    assert ss._neutralize_formula("") == ""       # empty untouched


def test_csv_write_neutralizes_formula_injection(tmp_path):
    p = tmp_path / "evil.csv"
    rows = [["=HYPERLINK(1)", "+1", "-2", "@SUM(A1)", "safe"]]
    ss._run({"op": "write", "path": str(p), "rows": rows})
    out = json.loads(ss._run({"op": "read", "path": str(p)}))
    # Every formula-leading cell is prefixed with ' so a spreadsheet app renders
    # it as text; benign cells are unchanged.
    assert out[0] == ["'=HYPERLINK(1)", "'+1", "'-2", "'@SUM(A1)", "safe"]


def test_set_cell_rejects_csv(tmp_path):
    p = tmp_path / "data.csv"
    ss._run({"op": "write", "path": str(p), "rows": [["x"]]})
    assert "xlsx-only" in ss._run({"op": "set_cell", "path": str(p), "cell": "A1", "value": 1})


def test_set_cell_rejects_a_range_before_opening_a_new_workbook(tmp_path):
    # A new file is written in the host process, where ws["A1:XFD1048576"]
    # materialises every cell of the sheet before failing.
    p = tmp_path / "new.xlsx"
    for cell in ("A1:XFD1048576", "A:A", "XFD1048577", "A0"):
        out = ss._run({"op": "set_cell", "path": str(p), "cell": cell, "value": 1})
        assert out.startswith("ERROR") and "single A1 cell" in out, cell
    assert not p.exists()


def test_errors():
    assert ss._run({"op": "read"}).startswith("ERROR: path is required")
    assert ss._run({"op": "", "path": "x"}).startswith("ERROR: op is required")
    assert ss._run({"op": "read", "path": "/nope/missing.csv"}).startswith("ERROR: no such file")
    assert ss._run({"op": "bogus", "path": "x.csv"}).startswith("ERROR")


def test_confines_paths_to_sandbox_workspace(tmp_path):
    class _SB:
        workdir = tmp_path / "ws"

    (tmp_path / "ws").mkdir()
    secret = tmp_path / "secret.csv"
    secret.write_text("token,value\nHOST_SECRET,42\n")

    tool = ss.spreadsheet(_SB())
    assert "escapes the workspace" in tool.fn({"op": "read", "path": str(secret)})
    assert "escapes the workspace" in tool.fn({
        "op": "write", "path": "../out.csv", "rows": [["x"]],
    })
    assert not (tmp_path / "out.csv").exists()

    out = tool.fn({
        "op": "write", "path": "nested/data.csv", "rows": [["a", "b"], [1, 2]],
    })
    assert out.startswith("wrote 2")
    assert (tmp_path / "ws" / "nested" / "data.csv").exists()
    rows = json.loads(tool.fn({"op": "read", "path": "nested/data.csv"}))
    assert rows == [["a", "b"], ["1", "2"]]


def test_refuses_git_writes_and_opaque_test_reads(tmp_path, monkeypatch):
    class _SB:
        workdir = tmp_path

    (tmp_path / ".git").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("assert f(2) == 41\n")
    tool = ss.spreadsheet(_SB())
    out = tool.fn({"op": "write", "path": ".git/config",
                   "rows": [["[core]"], ["fsmonitor = echo pwned"]]})
    assert "refusing to write under .git/" in out
    assert not (tmp_path / ".git" / "config").exists()

    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    monkeypatch.delenv("MAVERICK_BENCHMARK_OPAQUE", raising=False)
    read = ss.spreadsheet_read(_SB()).fn({"op": "read", "path": "tests/test_x.py"})
    assert read.startswith("ERROR") and "41" not in read


# ---- XLSX (needs openpyxl) --------------------------------------------------

def test_xlsx_write_read_setcell_info(tmp_path):
    pytest.importorskip("openpyxl")
    p = tmp_path / "book.xlsx"
    assert ss._run({"op": "write", "path": str(p),
                    "rows": [["h1", "h2"], [10, 20]], "sheet": "Data"}).startswith("wrote 2")
    rows = json.loads(ss._run({"op": "read", "path": str(p), "sheet": "Data"}))
    assert rows[0] == ["h1", "h2"] and rows[1] == [10, 20]   # xlsx preserves int types
    assert ss._run({"op": "set_cell", "path": str(p), "cell": "A3",
                    "value": 99, "sheet": "Data"}).startswith("set A3")
    rows2 = json.loads(ss._run({"op": "read", "path": str(p), "sheet": "Data"}))
    assert rows2[2][0] == 99
    assert "xlsx sheets" in ss._run({"op": "info", "path": str(p)})


def test_set_cell_creates_missing_sheet_instead_of_renaming(tmp_path):
    # Regression: set_cell on an existing workbook used to RENAME the active
    # sheet to the requested name (silently corrupting the original sheet and
    # breaking cross-sheet formula references) instead of creating it.
    pytest.importorskip("openpyxl")
    import openpyxl
    p = tmp_path / "book.xlsx"
    ss._run({"op": "write", "path": str(p),
             "rows": [["h1"], [1]], "sheet": "Data"})
    out = ss._run({"op": "set_cell", "path": str(p), "cell": "B2",
                   "value": 42, "sheet": "Summary"})
    assert out.startswith("set B2")
    wb = openpyxl.load_workbook(p)
    assert wb.sheetnames == ["Data", "Summary"]   # Data survives, Summary created
    assert wb["Summary"]["B2"].value == 42
    assert wb["Data"]["A2"].value == 1            # original data untouched
    assert wb["Data"]["B2"].value is None         # not written into Data's grid


def test_set_cell_names_sheet_on_fresh_workbook(tmp_path):
    # Brand-new workbook: the default "Sheet" is still renamed to the request.
    pytest.importorskip("openpyxl")
    import openpyxl
    p = tmp_path / "new.xlsx"
    assert ss._run({"op": "set_cell", "path": str(p), "cell": "A1",
                    "value": 7, "sheet": "Only"}).startswith("set A1")
    wb = openpyxl.load_workbook(p)
    assert wb.sheetnames == ["Only"]
    assert wb["Only"]["A1"].value == 7


def test_xlsx_graceful_without_openpyxl(tmp_path, monkeypatch):
    # If openpyxl is unavailable, xlsx ops fail with an actionable install hint
    # rather than a raw ImportError.
    def _boom():
        raise RuntimeError("openpyxl not installed; .xlsx support needs it. "
                           "Run: pip install 'maverick-agent[spreadsheet]'")
    monkeypatch.setattr(ss, "_openpyxl", _boom)
    out = ss._run({"op": "write", "path": str(tmp_path / "x.xlsx"), "rows": [["a"]]})
    assert out.startswith("ERROR") and "maverick-agent[spreadsheet]" in out


def test_factory_shape():
    t = ss.spreadsheet()
    assert t.name == "spreadsheet" and callable(t.fn)


def test_xlsx_reads_fail_closed_when_isolated_worker_fails(tmp_path, monkeypatch):
    from maverick import parser_isolation
    path = tmp_path / "book.xlsx"
    path.write_bytes(b"untrusted")

    def fail(*args, **kwargs):
        raise RuntimeError("worker unavailable")

    monkeypatch.setattr(parser_isolation, "parse_isolated", fail)
    monkeypatch.setattr(ss, "_validate_xlsx", lambda *_: pytest.fail("parsed in parent"))
    for op in ("read", "info"):
        assert "worker unavailable" in ss._run({"op": op, "path": str(path)})


def test_xlsx_edit_worker_failure_preserves_original(tmp_path, monkeypatch):
    from maverick import parser_isolation
    path = tmp_path / "book.xlsx"
    original = b"existing workbook"
    path.write_bytes(original)

    def fail(*args, **kwargs):
        raise RuntimeError("worker unavailable")

    monkeypatch.setattr(parser_isolation, "parse_isolated", fail)
    result = ss._run({"op": "set_cell", "path": str(path), "cell": "A1", "value": 3})
    assert "worker unavailable" in result
    assert path.read_bytes() == original


def test_macro_cell_edit_does_not_create_non_macro_workbook(tmp_path, monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "get_document_tools", lambda: {"macro_cell_edits": True})
    path = tmp_path / "missing.xlsm"
    result = ss._run({"op": "set_cell", "path": str(path), "cell": "A1", "value": 3})
    assert "must already exist" in result
    assert not path.exists()


def test_xlsx_rejects_compressed_expansion_before_parser(tmp_path):
    import zipfile

    path = tmp_path / "bomb.xlsx"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/sharedStrings.xml", b"x" * (16 * 1024 * 1024 + 1))
    result = ss._run({"op": "info", "path": str(path)})
    assert result.startswith("ERROR:") and "oversized" in result


def test_xlsx_rejects_fifo_and_external_links(tmp_path):
    import os
    import zipfile

    if hasattr(os, "mkfifo"):
        pipe = tmp_path / "pipe.xlsx"
        os.mkfifo(pipe)
        assert ss._run({"op": "info", "path": str(pipe)}).startswith("ERROR:")
    path = tmp_path / "linked.xlsx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/externalLinks/externalLink1.xml", b"<link/>")
    assert "external links" in ss._run({"op": "info", "path": str(path)})


def test_xlsx_rejects_merged_cell_and_directory_amplification(tmp_path):
    import zipfile

    merged = tmp_path / "merged.xlsx"
    with zipfile.ZipFile(merged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/worksheets/sheet1.xml", (
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<mergeCells><mergeCell ref="A1:XFD1048576"/></mergeCells></worksheet>'
        ))
    for op in ("info", "read", "set_cell"):
        result = ss._run({"op": op, "path": str(merged), "cell": "A1", "value": "x"})
        assert "merged cells exceed" in result
    entries = tmp_path / "entries.xlsx"
    with zipfile.ZipFile(entries, "w") as archive:
        for index in range(2001):
            archive.writestr(f"item{index}", b"")
    assert "directory exceeds" in ss._run({"op": "info", "path": str(entries)})


def test_xlsx_bounds_noncanonical_parts_and_total_merged_area(tmp_path):
    import zipfile

    path = tmp_path / "book.xlsx"
    sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
             '<mergeCells><mergeCell ref="A1:CW500"/></mergeCells></worksheet>')
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("unusual/first.bin", sheet)
        archive.writestr("unusual/second.bin", sheet)
    assert "merged cells exceed" in ss._run({"op": "info", "path": str(path)})

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("unusual/sheet.bin", sheet.encode("utf-16"))
    assert "XML declarations" in ss._run({"op": "info", "path": str(path)})
