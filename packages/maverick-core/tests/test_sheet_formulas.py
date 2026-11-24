"""Plain workbook formulas computed without a spreadsheet program."""
from __future__ import annotations

import json
from decimal import Decimal

import pytest
from maverick.sheet_formulas import evaluate

_GRID = {"B2": 45000, "B3": 50000, "B4": 55000, "C2": 13500, "C3": 15000, "C4": 16500,
         "D2": "=B2-C2", "D3": "=B3-C3", "D4": "=B4-C4", "E1": "15%", "F1": None,
         "B5": "=SUM(B2:B4)", "D5": "=SUM(D2:D4)", "G1": "=G2", "G2": "=G1", "H1": "text"}


def _get(ref):
    return _GRID.get(ref)


@pytest.mark.parametrize("formula, expected", [
    ("=SUM(B2:B4)", Decimal(150000)),
    ("=B2-C2-1000", Decimal(30500)),
    ("=SUM(D2:D4)", Decimal(105000)),            # formulas that use formulas
    ("=B5*15%", Decimal("22500.00")),
    ("=ROUND(B2/7, 2)", Decimal("6428.57")),
    ("=AVERAGE(B2:B4)", Decimal(50000)),
    ("=MAX(B2:B4)-MIN(B2:B4)", Decimal(10000)),
    ("=(B2+C2)*2", Decimal(117000)),
    ("=-B2+2^3", Decimal(-44992)),
    ("=SUM(B2:B4,F1,1)", Decimal(150001)),       # an empty cell counts as nothing
    ("=$B$2+B$3", Decimal(95000)),
])
def test_plain_formulas_are_computed(formula, expected):
    assert evaluate(formula, _get) == expected


@pytest.mark.parametrize("formula", [
    "=G1",                 # a circular reference
    "=H1*2",               # text in arithmetic
    "=VLOOKUP(B2,B2:C4,2)",  # a function outside the plain set
    "=Sheet2!B2",          # another sheet
    "=B2/0",
    "=SUM(B2:B4",
    "not a formula",
])
def test_anything_else_is_left_uncomputed(formula):
    assert evaluate(formula, _get) is None


def test_reading_a_written_workbook_gives_computed_totals(tmp_path):
    # Live: a follow-up read a budget workbook's total as "=SUM(B2:B13)" with
    # no value, added twelve months itself and reported $825,000, not $819,000.
    pytest.importorskip("openpyxl")
    from maverick.tools import spreadsheet as ss

    p = tmp_path / "budget.xlsx"
    months = [45000, 50000, 55000, 60000, 65000, 70000, 74000, 76000, 78000, 80000, 82000, 84000]
    rows = [["Month", "Revenue"], *[[i + 1, m] for i, m in enumerate(months)], ["Total", "=SUM(B2:B13)"]]
    assert ss._run({"op": "write", "path": str(p), "rows": rows}).startswith("wrote")
    total = json.loads(ss._run({"op": "read", "path": str(p)}))[-1][1]
    assert total == {"formula": "=SUM(B2:B13)", "cached_value": None, "value_status": "computed",
                     "computed_value": 819000, "cell": "B14"}
    assert "Total,819000" in ss.xlsx_bytes_as_csv(p.read_bytes())


def _schedule(rows: int) -> dict:
    """An amortization schedule: each balance reads the balance above twice,
    once through the month's interest and once through its principal."""
    grid = {"B1": 1199.10, "E2": 200000}
    for r in range(3, rows + 3):
        grid.update({f"C{r}": f"=E{r - 1}*0.005", f"D{r}": f"=B1-C{r}", f"E{r}": f"=E{r - 1}-D{r}"})
    return grid


def test_each_formula_cell_is_worked_out_once():
    # Review: a schedule whose balance reads the balance above twice doubled
    # the work with every row, because each reference was worked out afresh;
    # a write's read-back of 23 such rows ran for minutes in the agent's process.
    grid = _schedule(25)
    looked_up = []

    def get(ref):
        looked_up.append(ref)
        assert len(looked_up) < 5_000, "a formula cell was worked out more than once"
        return grid.get(ref)

    balance = Decimal(200000)
    for _ in range(25):
        balance -= Decimal("1199.1") - balance * Decimal("0.005")
    assert evaluate(grid["E27"], get) == balance
    # A memo carries the results across the formulas of one sheet.
    from maverick.sheet_formulas import Memo

    looked_up.clear()
    memo = Memo()
    for r in range(3, 28):
        evaluate(grid[f"E{r}"], get, memo)
    assert len(looked_up) < 200, len(looked_up)


def test_the_work_on_one_sheet_is_capped():
    # Past the cap, the sheet's remaining formulas are left uncomputed.
    from maverick.sheet_formulas import Memo

    grid = {f"A{r}": r for r in range(1, 1001)}
    memo = Memo(steps=5_000)
    results = [evaluate("=SUM(A1:A1000)", grid.get, memo) for _ in range(10)]
    assert results[0] == Decimal(500500) and results[-1] is None, results
    assert all(result is None for result in results[results.index(None):])


def test_a_range_leaves_out_text_as_excel_does():
    # Review: "1200" written as text was added into =SUM(B2:B3), but Excel
    # and LibreOffice leave text in a range out of SUM, AVERAGE, MIN, MAX and
    # COUNT, so the file's total was 0 while the read-back said 900.
    grid = {"B2": "1200", "B3": "'-300", "B4": 500, "B5": "=B4*2", "B6": None}
    assert evaluate("=SUM(B2:B3)", grid.get) == 0
    assert evaluate("=SUM(B2:B6)", grid.get) == Decimal(1500)
    assert evaluate("=AVERAGE(B2:B6)", grid.get) == Decimal(750)
    assert evaluate("=MIN(B2:B6)", grid.get) == Decimal(500)
    assert evaluate("=MAX(B2:B6)", grid.get) == Decimal(1000)
    assert evaluate("=COUNT(B2:B6)", grid.get) == Decimal(2)
    # A cell named on its own is still read as a number, as Excel does.
    assert evaluate("=B2*2", grid.get) == Decimal(2400)
    assert evaluate("=B3*2", grid.get) is None


def test_an_error_cell_in_a_range_leaves_the_formula_uncomputed(tmp_path):
    # Review: SUM over a #N/A skipped it as text and read back 2030.75 where
    # Excel and LibreOffice show #N/A; op=read called the figure computed.
    from maverick.tools import spreadsheet

    rows = [["Customer", "Balance"], ["Acme", 1200.50], ["Beta", "#N/A"], ["Gamma", 830.25], ["Total", "=SUM(B2:B4)"]]
    out = spreadsheet._run({"op": "write", "path": str(tmp_path / "aging.xlsx"), "rows": rows})
    assert "Total,2030.75" not in out and "Total,=SUM(B2:B4)" in out, out
    out = spreadsheet._run({"op": "write", "path": str(tmp_path / "m.xlsx"),
                            "rows": [["Store", "Margin"], ["A", 0.21], ["B", "#DIV/0!"], ["Avg", "=AVERAGE(B2:B3)"]]})
    assert "Avg,0.21" not in out, out


def test_count_skips_an_error_cell_as_excel_does():
    # Review: once an error cell stopped every formula, COUNT over a #N/A was
    # left uncomputed; Excel's COUNT skips it and counts the numbers.
    from maverick.sheet_formulas import evaluate

    cells = {"B2": 1200, "B3": "#N/A", "B4": 830.75, "B5": "N/A"}.get
    assert evaluate("=COUNT(B2:B5)", cells) == 2
    assert evaluate("=SUM(B2:B5)", cells) is None
    assert evaluate("=AVERAGE(B2:B4)", cells) is None
