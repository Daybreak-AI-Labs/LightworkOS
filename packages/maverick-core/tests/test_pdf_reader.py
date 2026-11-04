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
