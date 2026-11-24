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


def test_clock_times_give_hours_across_midnight_and_inside_a_window():
    # Live, twice: a night crew's pay was worked out by hand and both runs
    # counted the wrong night hours (8 for a 21:00-05:00 shift, not 7).
    text = ("employee,clock_in,clock_out,break_min\n"
            "Marcus,22:00,06:30,30\nMarcus,21:00,05:00,30\nPriya,16:00,00:30,30\n"
            "Tomas,23:30,07:45,45\nTomas,06:00,14:00,30\nAda,9:15,17:45,0\n")
    rows = _query(text, "SELECT employee, hours(clock_in, clock_out) - break_min / 60.0 AS paid, "
                        "overlap(clock_in, clock_out, '22:00', '06:00') AS night FROM data")
    assert rows == ["employee,paid,night", "Marcus,8.0,8.0", "Marcus,7.5,7.0", "Priya,8.0,2.5",
                    "Tomas,7.5,6.5", "Tomas,7.5,0.0", "Ada,8.5,0.0"]
    assert _query(text, "SELECT SUM(overlap(clock_in, clock_out, '22:00', '06:00')) AS n FROM data") == [
        "n", "24.0"]
    # A value that is not a clock time gives NULL, not a guess.
    assert _query("a,b\n25:00,x\n", "SELECT hours(a, b) AS h, overlap(a, b, '1:00', '2:00') AS o FROM data") == [
        "h,o", ","]
