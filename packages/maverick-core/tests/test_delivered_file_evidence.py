"""What the files on a task's page hold, as the verifier is shown them."""
from __future__ import annotations

import pytest
from maverick import task_files
from maverick.agent import _delivered_file_evidence
from maverick.world_model import WorldModel


def _evidence(tmp_path, name: str, write) -> str:
    tmp_path.mkdir(mode=0o700, exist_ok=True)
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Clean the invoices.", "", owner="alice")
    work = tmp_path / "work"
    work.mkdir()
    write(work / name)
    task_files.record(world, gid, work, work / name, delivered=True)
    return _delivered_file_evidence(world, gid)


def test_a_long_csv_says_how_many_rows_it_has_and_that_only_the_first_are_shown(tmp_path):
    # Review: a cleaned 120-row invoice CSV was shown as its header and 24
    # rows under "holds:", beside a contract asking for every row of the data
    # accounted for, so a complete file looked as if it had lost 96 rows.
    lines = ["invoice,amount"] + [f"INV-{i},{100 + i}.00" for i in range(120)]
    evidence = _evidence(tmp_path, "invoices_clean.csv", lambda p: p.write_text("\n".join(lines) + "\n"))
    assert ("invoices_clean.csv, a file on the task's page, holds 121 rows; these are the first 25 "
            "(the other 96 are in the file, not shown here):\ninvoice,amount\nINV-0,100.00\n") in evidence
    assert "INV-23,123.00\n</tool_output" in evidence and "INV-24" not in evidence
    short = _evidence(tmp_path / "short", "short.csv", lambda p: p.write_text("a,b\n1,2\n"))
    assert "short.csv, a file on the task's page, holds 2 rows:\na,b\n1,2\n</tool_output" in short


def test_a_file_cut_short_of_its_first_rows_says_so(tmp_path):
    # The frame's room ends before the rows do: the cut is marked.
    lines = ["note"] + ["x" * 400] * 30
    evidence = _evidence(tmp_path, "notes.csv", lambda p: p.write_text("\n".join(lines) + "\n"))
    assert "x\n... (the rest of the file is not shown here)\n</tool_output" in evidence


def test_each_sheet_says_how_many_rows_it_has(tmp_path):
    # Review: a Summary's total of 2,000 sat beside 24 of its 200 detail rows
    # (240), with nothing to say the other rows were in the file.
    pytest.importorskip("openpyxl")
    from maverick.tools import spreadsheet as ss

    sheets = {"Summary": [["bucket", "total"], ["all", 2000]],
              "Detail": [["invoice", "amount"]] + [[f"INV-{i}", 10] for i in range(200)]}
    evidence = _evidence(tmp_path, "aging.xlsx",
                         lambda p: ss._run({"op": "write", "path": str(p), "sheets": sheets}))
    assert ("aging.xlsx, a file on the task's page, holds:\nSheet 'Summary', 2 rows:\nbucket,total\nall,2000\n"
            "Sheet 'Detail', 201 rows; these are the first 25 (the other 176 are in the file, not shown here):\n"
            "invoice,amount\nINV-0,10\n") in evidence
    assert "INV-23,10\n</tool_output" in evidence


def test_the_verifier_is_told_rows_a_frame_does_not_show_are_not_missing():
    from maverick.verifier import EVIDENCE_CONTRACT

    assert "rows it does not show are in the file, not missing" in EVIDENCE_CONTRACT
