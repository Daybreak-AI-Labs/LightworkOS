"""memory_safe_parse: bounded parsing of untrusted JSON/CSV."""
from __future__ import annotations

import csv
import io
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick.tools.memory_safe_parse import _csv_shape, memory_safe_parse


def _run(**kw):
    return memory_safe_parse().fn({"op": "parse", **kw})


def test_ok_json_shape_summary():
    out = _run(text='{"a": 1, "b": [1, 2, 3]}', format="json")
    assert out.startswith("OK json")
    assert "dict" in out


def test_reject_oversize():
    out = _run(text="x" * 100, format="csv", max_bytes=10)
    assert out.startswith("REJECT") and "max_bytes" in out


def test_reject_too_deep():
    deep = "[" * 50 + "]" * 50
    out = _run(text=deep, format="json", max_depth=5)
    assert out.startswith("REJECT") and "max_depth" in out


def test_reject_too_many_items():
    out = _run(text="[" + ",".join("1" for _ in range(20)) + "]",
               format="json", max_items=5)
    assert out.startswith("REJECT") and "max_items" in out


def test_invalid_json_does_not_raise():
    out = _run(text="{not valid", format="json")
    assert out.startswith("REJECT") and "invalid JSON" in out


def test_csv_rows_and_header_cols():
    out = _run(text="a,b,c\n1,2,3\n4,5,6", format="csv")
    assert out.startswith("OK csv")
    assert "3 row(s)" in out and "3 column(s)" in out


def test_errors_and_contract():
    assert memory_safe_parse().fn({"op": "parse", "text": 123}).startswith("ERROR")
    assert _run(text="{}", format="xml").startswith("ERROR")
    t = memory_safe_parse()
    assert t.name == "memory_safe_parse" and t.parallel_safe is True


@pytest.mark.parametrize("text", [
    'name,note\r\n"Smith, John","two\r\nlines"\r\n',
    'name,note\n"Doubled ""quotes""","hello, world"\n',
    '\n\na,b\n\n,\n"",\n',
    'one,two\nthree\nfour,five,six\n',
    '',
    '""\n',
    'a,b\r1,2\r',
    '名字,备注\n甲,乙\n',
])
def test_csv_logical_shape_agrees_with_stdlib_and_reports_physical_lines(text):
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    expected = [row for row in reader if row]
    result = _csv_shape(text, 100)
    assert result.error is None
    assert result.records == len(expected)
    assert result.header_columns == (len(expected[0]) if expected else 0)
    assert result.physical_lines == reader.line_num
    assert result.min_columns == min(map(len, expected), default=0)
    assert result.max_columns == max(map(len, expected), default=0)


@pytest.mark.parametrize("text", ['a,b\n"unclosed,b', 'a,b\n"closed"junk,b'])
def test_csv_malformed_quoting_is_rejected_without_echoing_customer_text(text):
    result = _run(text=text, format="csv")
    assert result.startswith("REJECT: invalid CSV")
    assert "unclosed" not in result and "junk" not in result


def test_csv_bounds_logical_records_fields_and_bytes_without_global_parser_changes():
    before = csv.field_size_limit()
    multiline = 'a,b\n"first\nsecond",2\n3,4\n'
    shape = _csv_shape(multiline, 2)
    assert shape.error == "row count exceeds max_items 2"
    assert shape.records == 3 and shape.physical_lines == 4
    text = '"' + "x" * 65_537 + '"'
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: _run(text=text, format="csv"), range(8)))
    assert all(result.startswith("REJECT: CSV field exceeds") for result in results)
    assert csv.field_size_limit() == before
    assert "max_bytes" in _run(text="é" * 5, format="csv", max_bytes=6)
    assert _run(text="\ud800", format="csv").startswith("REJECT")
    assert "max_bytes" in _run(text="x" * 1_000_001, format="csv", max_bytes=10_000_000)


def test_quoted_delimiters_and_newlines_do_not_inflate_summary():
    result = _run(text='name,note\n"Smith, John","two\nlines"\n', format="csv")
    assert "2 row(s), 2 column(s) in header" in result
    assert "3 physical line(s)" in result
