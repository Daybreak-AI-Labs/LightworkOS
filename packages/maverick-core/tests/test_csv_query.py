"""csv_query: SQL over CSV text reads the numbers the file holds."""
from __future__ import annotations

from maverick.tools.csv_query import query_tables


def _query(text: str, sql: str) -> list[str]:
    return query_tables({"data": ("data.csv", text)}, sql).splitlines()


def test_formatted_amounts_are_numbers():
    # Live: a bank reconciliation summed a ledger whose amounts were written
    # "4,850.00". They loaded as text, CAST read "4,850.00" as 4, and the
    # agent reported both month totals wrong without any error.
    text = ('date,description,amount\n'
            '2026-10-01,DEPOSIT,"4,850.00"\n'
            '2026-10-04,CHECK 1041,"-1,245.60"\n'
            '2026-10-05,FEE,$18.00\n'
            '2026-10-06,REFUND,"($1,000.50)"\n'
            '2026-10-07,CARD,"$2,317.45"\n'
            '2026-10-08,ADJ,-$2.37\n'
            '2026-10-09,BIG,"1,234,567"\n')
    assert _query(text, "SELECT ROUND(SUM(amount), 2) AS total FROM data") == ["total", "1239503.98"]
    assert _query(text, "SELECT ROUND(SUM(CAST(amount AS REAL)), 2) AS total FROM data") == [
        "total", "1239503.98"]
    assert _query(text, "SELECT description FROM data ORDER BY amount DESC LIMIT 2") == [
        "description", "BIG", "DEPOSIT"]


def test_text_that_only_looks_numeric_stays_as_written():
    # A ZIP code or an account number keeps its leading zero, and a comma
    # that is not a thousands separator does not join two numbers.
    text = 'zip,code,pair,plain,half\n02134,007,"1,5",0,0.5\n'
    assert _query(text, "SELECT zip, code, pair, plain, half FROM data") == [
        "zip,code,pair,plain,half", "02134,007,\"1,5\",0,0.5"]
    assert _query(text, "SELECT typeof(zip), typeof(pair), typeof(plain), typeof(half) FROM data")[1] == (
        "text,text,integer,real")


def test_plain_numbers_read_as_before():
    text = "a,b,c,d,e\n1e3,+5,1.,-0.25,.5\n"
    assert _query(text, "SELECT a + b + c + d + e AS total FROM data") == ["total", "1006.25"]
