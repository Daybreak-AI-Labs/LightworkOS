"""csv_query: SQL over CSV text reads the numbers the file holds."""
from __future__ import annotations

import time

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
    out = _query(text, "SELECT invoice, invoice_date, julianday('2026-11-24') - julianday(due) AS late FROM data")
    assert out[:4] == ["invoice,invoice_date,late", "A,2026-10-29,11.0", "B,2026-08-04,82.0", "C,,"]
    assert "data.invoice_date holds dates written like 10/29/2026; queries read them as 2026-10-29" in out[4]
    assert "data.due holds dates written like 11/13/2026; queries read them as 2026-11-13" in out[5]
    day_first = "d\n29/10/2026\n03.04.2026\n"
    assert _query(day_first, "SELECT d FROM data")[:3] == ["d", "2026-10-29", "2026-04-03"]
    assert _query("d\n2026/10/29\n2026/1/5\n", "SELECT d FROM data")[:3] == ["d", "2026-10-29", "2026-01-05"]
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
    note = "\n".join(out[3:])
    assert "data.d holds values such as 'Oct 29 2026'" in note and "YYYY-MM-DD" in note
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


def test_a_blank_number_used_in_arithmetic_gets_a_note():
    # A blank paid cell is NULL (so AVG and MAX are right), and so
    # amount - paid is NULL for every unpaid invoice: an aging summary's SUM
    # silently left them out and a customer owing $7,887.79 showed $0.00.
    text = "customer,amount,paid\nA,100.00,\nA,50.00,20.00\nB,70.00,\n"
    out = _query(text, "SELECT customer, SUM(amount - paid) AS open FROM data GROUP BY customer")
    assert out[:3] == ["customer,open", "A,30.0", "B,"]
    assert "paid is blank in 2 rows" in out[3] and "COALESCE(paid, 0)" in out[3]
    fine = _query(text, "SELECT customer, SUM(amount - COALESCE(paid, 0)) AS open FROM data GROUP BY customer")
    assert fine == ["customer,open", "A,130.0", "B,70.0"]
    assert len(_query(text, "SELECT AVG(paid) AS a, MAX(paid) AS m FROM data")) == 2
    assert len(_query(text, 'SELECT SUM(amount - IFNULL("paid", 0)) AS t FROM data')) == 2


def test_dates_read_as_iso_get_a_note_when_the_query_names_the_column():
    # The agent sees 10/29/2026 when it reads the file, so WHERE date =
    # '10/29/2026' and GROUP BY substr(date, 1, 2) silently matched nothing
    # or grouped on the year once the column was read as 2026-10-29.
    text = "invoice,date,amount\nA1,10/29/2026,100\nA2,10/30/2026,50\nA3,11/02/2026,75\n"
    note = ("Note: data.date holds dates written like 10/29/2026; queries read them as 2026-10-29 "
            "(YYYY-MM-DD), so compare, filter and group on that form.")
    assert _query(text, "SELECT SUM(amount) AS total FROM data WHERE date = '10/29/2026'") == [
        "total", '""', note]
    assert _query(text, 'SELECT SUM(amount) AS total FROM data WHERE "date" LIKE \'10/%\'')[2] == note
    assert _query(text, "SELECT SUM(amount) AS total FROM data WHERE date = '2026-10-29'") == [
        "total", "100", note]
    assert _query(text, "SELECT substr(d.date, 1, 7) AS month, SUM(amount) AS total FROM data d "
                        "GROUP BY month") == ["month,total", "2026-10,150", "2026-11,75", note]
    # A query that does not name the column, or only calls date(), has no note.
    assert _query(text, "SELECT SUM(amount) AS total FROM data") == ["total", "225"]
    assert _query(text, "SELECT date('2026-10-29', '+1 day') AS next FROM data LIMIT 1") == [
        "next", "2026-10-30"]
    # spreadsheet_read's op=query reads dates the same way and says so.
    from maverick.tools.spreadsheet import spreadsheet_read
    description = spreadsheet_read().description
    assert "10/29/2026" in description and "2026-10-29" in description


def test_one_columns_day_month_order_reads_the_columns_that_do_not_show_it():
    # invoices.csv shows its dates are month first (10/29/2026); payments.csv
    # holds only 10/05/2026 and 11/02/2026, which could be either. Read one
    # way and not the other, the join on date matched nothing.
    invoices = "invoice,amount,date\nA1,100,10/05/2026\nA2,200,10/29/2026\n"
    payments = "paid,date\n100,10/05/2026\n50,11/02/2026\n"
    out = query_tables({"invoices": ("invoices.csv", invoices), "payments": ("payments.csv", payments)},
                       "SELECT i.invoice, i.amount, p.paid FROM invoices i JOIN payments p ON p.date = i.date")
    assert out.splitlines()[:2] == ["invoice,amount,paid", "A1,100,100"]
    # The borrowed order is a guess, so the note says whose order it is.
    assert ("payments.date holds dates written like 10/05/2026, and none of them shows whether the day or "
            "the month comes first; this query reads them month first, as invoices.date does (10/29/2026), "
            "so 10/05/2026 is 2026-10-05 (YYYY-MM-DD). If they are written the other way, ask which it is.") in out
    # The same within one file: due shows the order, paid_on does not.
    one = "invoice,due,paid_on\nA1,10/29/2026,10/05/2026\nA2,11/15/2026,12/01/2026\n"
    assert _query(one, "SELECT invoice, paid_on FROM data WHERE paid_on > due")[:2] == [
        "invoice,paid_on", "A2,2026-12-01"]
    assert _query("a,c\n29/10/2026,03/04/2026\n", "SELECT a, c FROM data")[:2] == ["a,c", "2026-10-29,2026-04-03"]
    # Columns that disagree leave the undecided one as written.
    assert _query("a,b,c\n29/10/2026,10/29/2026,03/04/2026\n", "SELECT a, b, c FROM data")[:2] == [
        "a,b,c", "2026-10-29,2026-10-29,03/04/2026"]


def test_round_never_fails_a_query():
    # ROUND(amount, 2) on 1e30 asked Decimal for 33 digits, raised, and the
    # whole query failed where SQLite's own ROUND gave the figure back.
    assert _query("item,amount\na,12.5\nb,1e30\n", "SELECT item, ROUND(amount, 2) AS r FROM data") == [
        "item,r", "a,12.5", "b,1e+30"]
    assert _query("sample,value\na,0.5\nb,123456789012345.678\n",
                  "SELECT sample, ROUND(value, 15) AS r FROM data") == ["sample,r", "a,0.5", "b,123456789012345.67"]
    assert _query("x\n5\n", "SELECT ROUND(x, NULL) AS r, ROUND(x) AS s FROM data") == ["r,s", ",5.0"]
    assert not query_tables({"data": ("d.csv", "x\n5\n")}, "SELECT ROUND(x, 1e999) FROM data").startswith("ERROR")
    # A failure on a later row is an ERROR result, not an exception.
    out = query_tables({"data": ("d.csv", "x\n1\n-9223372036854775808\n")}, "SELECT abs(x) AS a FROM data")
    assert out.startswith("ERROR") and "integer overflow" in out


def test_a_date_note_names_only_a_column_the_date_functions_cannot_read():
    # Correct queries over YYYY-MM-DD dates were told the date functions
    # could not read them because a total over no rows, or a column the WHERE
    # made NULL, came back empty.
    text = "invoice,due,amount,paid\nA1,2026-10-01,100,\nA2,2026-11-15,50,50\n"
    assert _query(text, "SELECT SUM(amount) AS december FROM data WHERE date(due) >= '2026-12-01'") == [
        "december", '""']
    assert _query(text, "SELECT invoice, amount, paid, julianday('2026-11-24') - julianday(due) AS days "
                        "FROM data WHERE paid IS NULL") == ["invoice,amount,paid,days", "A1,100,,54.0"]
    # A column of dates whose order is unknown is named only when the query reads it.
    assert _query("d,due\n03/04/2026,2026-10-01\n", "SELECT julianday(due) AS j FROM data") == ["j", "2461314.5"]
    # A filter over dates SQLite cannot read leaves no empty column, but still gets a note.
    out = _query("d\nOct 29 2026\nNov 2 2026\n", "SELECT COUNT(*) AS n FROM data WHERE julianday(d) > 0")
    assert out[:2] == ["n", "0"] and "data.d" in out[2] and "'Oct 29 2026'" in out[2]


def test_blank_counts_are_per_table():
    # The file read as data was also loaded under its own name, and the note
    # added the two tables' blanks together: "paid is blank in 4 rows" for 2.
    text = "invoice,amount,paid\nA1,100,\nA2,50,50\nA3,70,\n"
    # Only the table the query reads gets a note: data.paid was named too,
    # though the query read only ar_aging.
    out = query_tables({"data": ("ar_aging.csv", text), "ar_aging": ("ar_aging.csv", text)},
                       "SELECT invoice, amount - paid AS open FROM ar_aging")
    assert out.count("is blank in") == 1 and "ar_aging.paid is blank in 2 rows" in out
    orders = "item,qty,price,discount_pct\nA,2,10,15\nB,1,5,\n"
    out = query_tables({"data": ("orders.csv", orders), "orders": ("orders.csv", orders)},
                       "SELECT item, qty * price * (1 - discount_pct) AS net FROM orders")
    assert out.count("holds percents") == 1 and out.count("orders.discount_pct is blank in 1 row,") == 1
    assert "data." not in out
    payments = "invoice,paid\nA1,\nA2,50\n"
    out = query_tables({"invoices": ("i.csv", text), "payments": ("p.csv", payments)},
                       "SELECT i.invoice, i.amount - i.paid - p.paid AS open FROM invoices i JOIN payments p "
                       "USING (invoice)")
    assert "invoices.paid is blank in 2 rows" in out and "payments.paid is blank in 1 row," in out
    out = query_tables({"invoices": ("i.csv", text), "payments": ("p.csv", payments)},
                       "SELECT i.invoice, i.amount - p.paid AS open FROM invoices i JOIN payments p USING (invoice)")
    assert "invoices.paid" not in out and "payments.paid is blank in 1 row," in out


def test_only_the_dates_a_query_reads_decide_their_day_month_order():
    # A US invoice file (10/29/2026) loaded beside a European bank file
    # (05/10/2026 and 03/11/2026: 5 October and 3 November) rewrote the
    # bank's dates month first in a query that read only the bank file.
    # SELECT * showed 2026-05-10 with no note, julianday(booked) lost its
    # "ask which it is", and the same query gave other dates when the
    # invoices were not passed.
    us = "invoice,date,amount\nA1,10/29/2026,100\n"
    eu = "txn,booked,amount\nT1,05/10/2026,100\nT2,03/11/2026,50\n"
    both = {"us_invoices": ("us_invoices.csv", us), "eu_bank": ("eu_bank.csv", eu)}
    for tables in (both, {"eu_bank": ("eu_bank.csv", eu)}):
        assert query_tables(tables, "SELECT * FROM eu_bank").splitlines() == [
            "txn,booked,amount", "T1,05/10/2026,100", "T2,03/11/2026,50"]
        out = query_tables(tables, "SELECT txn, julianday(booked) AS j FROM eu_bank").splitlines()
        assert out[:3] == ["txn,j", "T1,", "T2,"]
        assert "eu_bank.booked (such as '05/10/2026')" in out[3] and "Ask which it is" in out[3]
    # The same within one file: order_date shows month first, but the query reads only ship_ref.
    out = _query("order_date,ship_ref\n10/29/2026,05/06/2026\n", "SELECT julianday(ship_ref) AS j FROM data")
    assert out[:2] == ["j", '""'] and "data.ship_ref (such as '05/06/2026')" in out[2]


def test_a_date_note_is_only_for_the_column_a_date_function_reads_as_a_date():
    # A CASE condition, a modifier built from a text column, a column the
    # query itself turns into YYYY-MM-DD with substr, and a same-named column
    # of a table the query never reads were each named as dates SQLite could
    # not read, on queries whose dates were right.
    text = "invoice,status,paid_date,due\nA1,paid,2026-10-05,2026-10-01\nA2,open,,2026-11-15\n"
    assert _query(text, "SELECT invoice, date(CASE WHEN status = 'paid' THEN paid_date ELSE due END) AS settle "
                        "FROM data") == ["invoice,settle", "A1,2026-10-05", "A2,2026-11-15"]
    terms = "invoice,invoice_date,terms\nA1,2026-10-05,Net 30\nA2,2026-10-20,Net 45\n"
    assert _query(terms, "SELECT invoice, date(invoice_date, '+' || substr(terms, 5) || ' days') AS due "
                         "FROM data") == ["invoice,due", "A1,2026-11-04", "A2,2026-12-04"]
    stamped = "d,amount\n10/29/2026 10:00,5\n11/02/2026 09:00,7\n"
    assert _query(stamped, "SELECT date(substr(d,7,4)||'-'||substr(d,1,2)||'-'||substr(d,4,2)) AS day, amount "
                           "FROM data") == ["day,amount", "2026-10-29,5", "2026-11-02,7"]
    tables = {"ledger": ("ledger.csv", "entry,date\nE1,2026-10-29\n"),
              "notes": ("notes.csv", "id,date\nN1,Oct 29 2026\n")}
    assert query_tables(tables, "SELECT entry, julianday(l.date) AS j FROM ledger l") == "entry,j\nE1,2461342.5"
    assert query_tables(tables, "SELECT l.entry, julianday(l.date) AS j, n.date FROM ledger l JOIN notes n") == (
        "entry,j,date\nE1,2461342.5,Oct 29 2026")
    # The column a date function is given as its date still gets the note,
    # quoted or after a table alias.
    out = query_tables(tables, "SELECT strftime('%Y', n.\"date\") AS y FROM ledger l JOIN notes AS n")
    assert out.splitlines()[:2] == ["y", '""']
    assert "notes.date holds values such as 'Oct 29 2026'" in out and "ledger.date" not in out


def test_a_deeply_nested_query_is_refused_at_once():
    # The date-note scan ran before SQLite parsed the query and rescanned to
    # each call's closing parenthesis: 5,000 nested julianday( calls took 23
    # seconds to be refused as a parser stack overflow.
    sql = "SELECT " + "julianday(" * 5000 + "d" + ")" * 5000 + " FROM data"
    started = time.monotonic()
    out = _query("d\nOct 1 2026\n", sql)
    assert out[0].startswith("ERROR") and "parser stack overflow" in out[0]
    assert time.monotonic() - started < 3
