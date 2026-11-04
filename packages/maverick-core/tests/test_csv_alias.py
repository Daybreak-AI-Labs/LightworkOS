"""The shared alias-headed CSV reader: the importers' two crash modes.

Ragged rows (overflow cells under DictReader's ``None`` key, missing cells
as ``None``) must contribute what they validly carry, and CSV the parser
cannot read at all (NUL bytes) must raise a clean ``ValueError`` — never
an AttributeError or a bare ``csv.Error`` that surfaces as a 500.
"""
from __future__ import annotations

import pytest
from maverick.csv_alias import MAX_FIELD_CHARS, alias_rows

_ALIASES = {
    "name": ("vendor name", "name"),
    "owner": ("owner", "business owner"),
}


def test_aliases_resolve_first_non_empty_match():
    rows = alias_rows(
        "Vendor Name,Business Owner\nAcme, Dana \n", _ALIASES, limit=10
    )
    assert rows == [{"name": "Acme", "owner": "Dana"}]


def test_ragged_rows_contribute_what_they_validly_carry():
    # Row 1 overflows (extra cells land under the None key as a list);
    # row 2 is short (missing cell filled with None). Neither crashes.
    text = "name,owner\nAcme,Dana,extra,cells\nSolo\n"
    rows = alias_rows(text, _ALIASES, limit=10)
    assert rows == [{"name": "Acme", "owner": "Dana"}, {"name": "Solo"}]


def test_unparseable_csv_raises_a_clean_value_error():
    # A cell past csv.field_size_limit() makes the parser itself fail;
    # that must surface as ValueError, never a bare csv.Error.
    huge = "x" * 200_000
    with pytest.raises(ValueError, match="not parseable"):
        alias_rows(f"name,owner\nAcme,{huge}\n", _ALIASES, limit=10)


def test_nul_bytes_never_leak_a_raw_csv_error():
    # Python 3.10's csv module raises "line contains NUL"; 3.11+ parses
    # NUL as ordinary data. Either way the importer's contract holds:
    # data flows through, or the failure is our clean ValueError -- never
    # a bare csv.Error surfacing as a 500.
    try:
        rows = alias_rows("name,owner\nAcme,\x00Dana\n", _ALIASES, limit=10)
    except ValueError as exc:
        assert "not parseable" in str(exc)
    else:
        assert rows[0]["name"] == "Acme"


def test_rows_beyond_the_limit_are_dropped():
    text = "name\n" + "\n".join(f"v{i}" for i in range(5)) + "\n"
    assert len(alias_rows(text, _ALIASES, limit=3)) == 3


def test_cells_are_stripped_and_bounded():
    huge = "x" * (MAX_FIELD_CHARS + 100)
    rows = alias_rows(f"name\n  {huge}  \n", _ALIASES, limit=10)
    assert len(rows[0]["name"]) == MAX_FIELD_CHARS
