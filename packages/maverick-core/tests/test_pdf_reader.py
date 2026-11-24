"""Regression tests for pdf_reader._parse_pages page-range clamping."""
import time

import pytest
from maverick.tools.pdf_reader import _parse_pages


def test_huge_end_is_clamped_to_total_and_fast():
    # A spec whose upper bound dwarfs the page count must NOT build a
    # ~10^8-element range; it should be clamped to `total` and return quickly.
    start = time.perf_counter()
    result = _parse_pages("1-99999999", total=3)
    elapsed = time.perf_counter() - start
    assert result == [0, 1, 2]
    assert elapsed < 0.5, f"range was not clamped (took {elapsed:.2f}s)"


def test_huge_open_end_is_clamped():
    assert _parse_pages("1-", total=3) == [0, 1, 2]


def test_huge_start_with_open_end_is_bounded():
    # start far beyond total -> empty selection, no giant range built.
    start = time.perf_counter()
    result = _parse_pages("99999999-", total=3)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 0.5


def test_start_greater_than_clamped_end_is_empty():
    assert _parse_pages("5-2", total=3) == []


def test_non_numeric_spec_does_not_silently_expand_to_all_pages():
    with pytest.raises(ValueError, match="invalid PDF page selection"):
        _parse_pages("a-b", total=3)


def test_normal_ranges_still_work():
    assert _parse_pages("1-2", total=5) == [0, 1]
    assert _parse_pages("3", total=5) == [2]
    assert _parse_pages("1-2,4", total=5) == [0, 1, 3]
    assert _parse_pages("", total=3) == [0, 1, 2]


# ---------- read_pdf ----------

def test_read_pdf_rejects_empty_source():
    from maverick.tools.pdf_reader import read_pdf
    assert "source is required" in read_pdf().fn({"source": ""}).lower()


def test_read_pdf_missing_file():
    from maverick.tools.pdf_reader import read_pdf
    out = read_pdf().fn({"source": "/definitely/does/not/exist.pdf"})
    assert "could not read" in out.lower()


def test_pdf_parse_pages_ranges():
    from maverick.tools.pdf_reader import _parse_pages
    assert _parse_pages("", 10) == list(range(10))
    assert _parse_pages("1-3", 10) == [0, 1, 2]
    assert _parse_pages("5", 10) == [4]
    assert _parse_pages("1,3,5", 10) == [0, 2, 4]
    assert _parse_pages("8-", 10) == [7, 8, 9]


def test_all_means_every_page():
    # Live: read_attachment(pages="all") answered "PDF parse failed
    # (ValueError); check the document", and the agent decided the receipt
    # could not be read and tried OCR, images and a shell command.
    for spec in ("all", "ALL", "*", "all pages"):
        assert _parse_pages(spec, total=3) == [0, 1, 2]


def test_a_page_selection_problem_is_said_plainly():
    from maverick.markdown_pdf import pdf_from_markdown
    from maverick.tools.pdf_reader import pdf_text

    data = pdf_from_markdown("# Receipt\n\nTOTAL 315.16\n")
    if pdf_text(data, max_chars=10_000).startswith("ERROR"):
        pytest.skip("no PDF parser installed")
    assert "TOTAL 315.16" in pdf_text(data, pages="all", max_chars=10_000)
    out = pdf_text(data, pages="99", max_chars=10_000)
    assert out.startswith("ERROR: this PDF has") and "leave pages out" in out
    bad = pdf_text(data, pages="a-b", max_chars=10_000)
    assert bad.startswith("ERROR: invalid PDF page selection")


def test_a_statement_table_keeps_its_columns():
    # Live: a bank statement read as "10/03 Card-Costco 3,753.21 8,727.34" and
    # "10/05 Cashdeposit 3,459.47 12,186.81": with the columns gone, the agent
    # could not tell withdrawals from deposits and got both totals wrong.
    from maverick.markdown_pdf import pdf_from_markdown
    from maverick.tools.pdf_reader import extract_text_from_bytes

    statement = ("# Business Checking\n\nOpening balance: $12,480.55\n\n"
                 "| Date | Description | Withdrawals | Deposits | Balance |\n|---|---|---:|---:|---:|\n"
                 "| 10/03 | Card - Costco | 3,753.21 | | 8,727.34 |\n| 10/05 | Cash deposit | | 3,459.47 | 12,186.81 |\n"
                 "| 10/07 | ACH - PG&E | 4,249.27 | | 7,937.54 |\n| 10/09 | Card settlement | | 2,422.72 | 10,360.26 |\n"
                 "| 10/10 | Check | 718.81 | | 9,641.45 |\n")
    text = extract_text_from_bytes(pdf_from_markdown(statement))
    lines = {line.split()[0]: line for line in text.splitlines() if line[:3] in ("10/", "Dat")}
    withdrawal, deposit = lines["10/03"].index("3,753.21"), lines["10/05"].index("3,459.47")
    assert deposit > withdrawal + 4, text
    assert lines["Date"].index("Deposits") > lines["Date"].index("Withdrawals"), text
    assert "Cash deposit" in lines["10/05"], text
    # A page of prose reads as before.
    prose = extract_text_from_bytes(pdf_from_markdown("# Note\n\nKeep it posted by the sink. Costs are shared.\n"))
    assert "Keep it posted by the sink. Costs are shared." in prose, prose
