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


def test_a_blank_in_a_column_of_numbers_is_null_and_a_blank_in_text_stays_blank():
    # A statement splits withdrawals and deposits into two columns, each
    # blank where the other is filled: as text '', the blank outranked every
    # number in MAX and counted as 0 in AVG. A text column keeps '' so a
    # filter such as receipt = '' still finds the blanks.
    text = "date,withdrawal,deposit,receipt\n10/03,3753.21,,yes\n10/05,,3459.47,\n10/07,4249.27,,no\n"
    assert _query(text, "SELECT MAX(withdrawal) AS w, AVG(withdrawal) AS a, COUNT(deposit) AS d FROM data") == [
        "w,a,d", "4249.27,4001.24,1"]
    assert _query(text, "SELECT COUNT(*) AS n FROM data WHERE receipt = ''") == ["n", "1"]


def test_an_unknown_column_error_lists_the_columns():
    # Live: "no such column: amount" over a statement's Withdrawals and
    # Deposits; the agent gave up on the query and added figures by hand.
    out = query_tables({"data": ("s.csv", "Date,Withdrawals,Deposits\n10/03,5.00,\n")},
                       "SELECT SUM(amount) FROM data")
    assert out.startswith("ERROR") and "no such column: amount" in out
    assert "data has the columns Date, Withdrawals, Deposits" in out


def test_dates_written_month_first_or_day_first_become_iso_when_the_data_shows_the_order():
    # Live: an aging report's julianday(invoice_date) was NULL for every
    # "10/29/2026", a CASE fell through to ELSE '90+', and the summary put
    # every customer's balance in 90+ days past due.
    text = "invoice,invoice_date,due\nA,10/29/2026,11/13/2026\nB,8/4/2026,9/3/2026\nC,,\n"
    assert _query(text, "SELECT invoice, invoice_date, julianday('2026-11-24') - julianday(due) AS late "
                        "FROM data") == ["invoice,invoice_date,late", "A,2026-10-29,11.0",
                                         "B,2026-08-04,82.0", "C,,"]
    day_first = "d\n29/10/2026\n03.04.2026\n"
    assert _query(day_first, "SELECT d FROM data") == ["d", "2026-10-29", "2026-04-03"]
    assert _query("d\n2026/10/29\n2026/1/5\n", "SELECT d FROM data") == ["d", "2026-10-29", "2026-01-05"]
    # Not dates in every row, or an impossible date: left as written.
    assert _query("d\n10/29/2026\nsoon\n", "SELECT d FROM data") == ["d", "10/29/2026", "soon"]
    assert _query("d\n02/30/2026\n10/29/2026\n", "SELECT d FROM data") == ["d", "02/30/2026", "10/29/2026"]


def test_dates_whose_order_the_data_does_not_show_are_kept_and_named_when_a_date_function_runs():
    text = "d,amount\n03/04/2026,5\n05/06/2026,7\n"
    assert _query(text, "SELECT d FROM data") == ["d", "03/04/2026", "05/06/2026"]
    out = _query(text, "SELECT julianday(d) AS j FROM data")
    assert out[:3] == ["j", '""', '""']
    note = "\n".join(out[3:])
    assert "data.d" in note and "03/04/2026" in note and "day or the month" in note


def test_a_date_function_empty_in_every_row_says_why():
    out = _query("d\nOct 29 2026\nNov 2 2026\n", "SELECT date(d, '+30 days') AS due FROM data")
    assert out[:3] == ["due", '""', '""']
    assert "due is empty in every row" in "\n".join(out[3:]) and "YYYY-MM-DD" in "\n".join(out[3:])
    assert len(_query("d\n2026-10-29\n", "SELECT date(d, '+30 days') AS due FROM data")) == 2


def test_a_percent_column_used_as_a_fraction_gets_a_note():
    # Live: revenue as qty * price * (1 - discount_pct) with discount_pct 15
    # came out negative, and the answer blamed "a sign issue in the data".
    text = "sku,qty,unit_price,discount_pct\nA,2,10.00,15\nB,1,20.00,0\n"
    out = _query(text, "SELECT SUM(qty * unit_price * (1 - discount_pct)) AS revenue FROM data")
    assert out[:2] == ["revenue", "-260.0"]
    assert "discount_pct holds percents (largest 15)" in out[2] and "divide it by 100" in out[2]
    for fine in ("SELECT SUM(qty * unit_price * (1 - discount_pct / 100.0)) AS revenue FROM data",
                 "SELECT SUM(qty * unit_price * (100 - discount_pct) / 100) AS revenue FROM data",
                 "SELECT sku, discount_pct FROM data"):
        assert len(_query(text, fine)) == (2 if "SUM" in fine else 3), fine
    # A column of fractions needs no note.
    assert len(_query("tax_pct,amount\n0.0825,100\n", "SELECT amount * tax_pct AS t FROM data")) == 2


def test_hours_reads_a_shift_written_as_one_range_and_twelve_hour_times():
    text = "who,mon,start,end\nDana,7:00-15:30,7:00 AM,3:30 PM\nFemi,off,12:30 pm,12:15 AM\nHank,10:00 – 18:45,9am,5pm\n"
    assert _query(text, "SELECT who, hours(mon) AS m, hours(start, end) AS s FROM data") == [
        "who,m,s", "Dana,8.5,8.5", "Femi,,11.75", "Hank,8.75,8.0"]
    assert _query(text, "SELECT overlap(mon, '12:00', '13:00') AS lunch FROM data") == [
        "lunch", "1.0", '""', "1.0"]


def test_round_works_out_money_as_people_and_compute_do():
    # SQLite's ROUND(41.175, 2) is 41.17: the binary float is 41.17499...
    # A discounted line total came out a cent under a hand check.
    assert _query("x\n1\n", "SELECT ROUND(41.175, 2) AS a, ROUND(-2.5) AS b, ROUND(0.125, 2) AS c, "
                            "ROUND(1.005, 2) AS d, ROUND(7) AS e, ROUND(NULL, 2) AS f, ROUND(2.5, -1) AS g "
                            "FROM data") == ["a,b,c,d,e,f,g", "41.18,-3.0,0.13,1.01,7.0,,3.0"]
