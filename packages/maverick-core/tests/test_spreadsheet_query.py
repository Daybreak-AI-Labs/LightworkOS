"""spreadsheet_read's read-only query compares workspace CSV files exactly.

Without the answer key in its workspace, the Finance sample specialist compared
four CSV files by eye and missed a duplicate invoice and a vendor absent from
the vendor master. A SELECT across the files finds both exactly.
"""
from __future__ import annotations

from pathlib import Path

from maverick.sandbox.local import LocalBackend
from maverick.tools.spreadsheet import spreadsheet_read


def _workspace(tmp_path: Path) -> LocalBackend:
    root = tmp_path / "ws"
    (root / "sample").mkdir(parents=True)
    (root / "sample" / "invoices.csv").write_text(
        "invoice_id,vendor,po_number,amount_usd\n"
        "INV-1,Northwind,PO-1,4800.00\nINV-2,Northwind,PO-1,4800.00\nINV-3,Sunrise,PO-2,900.00\n", encoding="utf-8")
    (root / "sample" / "vendor_master.csv").write_text("vendor\nNorthwind\n", encoding="utf-8")
    return LocalBackend(workdir=root)


def test_a_query_joins_workspace_csv_files_exactly(tmp_path):
    tool = spreadsheet_read(_workspace(tmp_path))
    paths = ["sample/invoices.csv", "sample/vendor_master.csv"]
    dupes = tool.fn({"op": "query", "paths": paths, "sql":
                     "SELECT vendor, po_number, amount_usd, COUNT(*) AS n FROM invoices "
                     "GROUP BY vendor, po_number, amount_usd HAVING n > 1"})
    assert dupes == "vendor,po_number,amount_usd,n\nNorthwind,PO-1,4800.0,2"
    unknown = tool.fn({"op": "query", "paths": paths, "sql":
                       "SELECT invoice_id FROM invoices WHERE vendor NOT IN (SELECT vendor FROM vendor_master)"})
    assert unknown == "invoice_id\nINV-3"


def test_the_query_stays_read_only_and_inside_the_workspace(tmp_path):
    tool = spreadsheet_read(_workspace(tmp_path))
    assert tool.fn({"op": "query", "paths": ["sample/invoices.csv"], "sql": "DELETE FROM invoices"}).startswith("ERROR")
    assert tool.fn({"op": "query", "paths": ["../outside.csv"], "sql": "SELECT 1"}).startswith("ERROR")
    assert tool.fn({"op": "query", "paths": [], "sql": "SELECT 1"}).startswith("ERROR")
    assert tool.fn({"op": "write", "path": "x.csv", "rows": [["a"]]}).startswith("ERROR")


def test_a_query_reads_an_excel_workbook(tmp_path):
    # Live: to total a workbook it had written, an agent tried query, got
    # "is not a CSV file", and fell back to a shell command waiting for approval.
    import pytest
    pytest.importorskip("openpyxl")
    from maverick.tools.spreadsheet import spreadsheet

    sandbox = _workspace(tmp_path)
    rows = [["Due Date", "Payment"]] + [[f"2026-{m:02d}-01", 3200] for m in range(3, 13)]
    assert spreadsheet(sandbox).fn({"op": "write", "path": "rent.xlsx", "rows": rows}).startswith("wrote")
    tool = spreadsheet_read(sandbox)
    out = tool.fn({"op": "query", "paths": ["rent.xlsx"],
                   "sql": "SELECT COUNT(*) AS n, SUM(Payment) AS total FROM rent"})
    assert out == "n,total\n10,32000.0" or out == "n,total\n10,32000", out
