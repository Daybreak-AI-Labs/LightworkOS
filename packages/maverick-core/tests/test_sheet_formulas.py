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
