"""read_attachment: the agent reads its goal's uploads by id, sealed or not."""
from __future__ import annotations

from maverick import attachments as att
from maverick.tools.attachments import read_attachment_tool
from maverick.world_model import WorldModel


def _setup(tmp_path, monkeypatch, sealed):
    if sealed:
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    other = world.create_goal("other", "")
    rec = att.store(gid, "brief.txt", "text/plain", b"ship on friday", root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    img = att.store(gid, "p.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"0" * 20, root=tmp_path / "a")
    iid = world.add_attachment(gid, img.filename, img.mime, img.size_bytes, img.sha256, str(img.path))
    return world, gid, other, aid, iid


def test_reads_text_sealed_and_plain(tmp_path, monkeypatch):
    for sealed in (False, True):
        world, gid, _other, aid, _iid = _setup(tmp_path / str(sealed), monkeypatch, sealed)
        assert read_attachment_tool(world, gid).fn({"id": aid}) == "ship on friday"


def test_scoped_to_the_goal_and_text_only(tmp_path, monkeypatch):
    world, gid, other, aid, iid = _setup(tmp_path, monkeypatch, False)
    assert read_attachment_tool(world, other).fn({"id": aid}).startswith("ERROR: no attachment")
    assert "image/png" in read_attachment_tool(world, gid).fn({"id": iid})
    assert read_attachment_tool(world, gid).fn({"id": "x"}).startswith("ERROR")
    assert read_attachment_tool(world, None).fn({"id": aid}).startswith("ERROR")


def _sales(tmp_path, monkeypatch, sealed=False):
    if sealed:
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    rows = ["month,region,revenue,refunds"]
    for month in range(1, 13):
        rows += [f"2026-{month:02d},North,{1000 + month}.25,{month % 3}",
                 f"2026-{month:02d},South,{500 + month}.10,1"]
    rec = att.store(gid, "sales.csv", "text/csv", "\r\n".join(rows).encode(), root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    return world, gid, aid


def test_a_csv_attachment_answers_an_exact_select(tmp_path, monkeypatch):
    # With code off, the agent added 48 numbers in its head and got every total
    # wrong. A read-only SELECT over the task's own CSV gives exact totals.
    for sealed in (False, True):
        world, gid, aid = _sales(tmp_path / str(sealed), monkeypatch, sealed)
        out = read_attachment_tool(world, gid).fn({
            "id": aid, "sql": "SELECT region, ROUND(SUM(revenue), 2) AS revenue, SUM(refunds) AS refunds "
                              "FROM data GROUP BY region ORDER BY revenue DESC"})
        assert out.splitlines()[:3] == ["region,revenue,refunds", "North,12081.0,12", "South,6079.2,12"]


def test_the_query_cannot_change_anything_or_reach_other_files(tmp_path, monkeypatch):
    world, gid, aid = _sales(tmp_path, monkeypatch)
    tool = read_attachment_tool(world, gid)
    for sql in ("DELETE FROM data", "DROP TABLE data", "ATTACH DATABASE 'x.db' AS x",
                "SELECT * FROM data; DELETE FROM data", "PRAGMA table_info(data)",
                "SELECT load_extension('x')"):
        assert tool.fn({"id": aid, "sql": sql}).startswith("ERROR"), sql
    assert tool.fn({"id": aid, "sql": "SELECT COUNT(*) AS n FROM data"}) == "n\n24"


def test_a_query_on_a_non_table_attachment_is_refused(tmp_path, monkeypatch):
    world, gid, _other, aid, _iid = _setup(tmp_path, monkeypatch, False)
    assert read_attachment_tool(world, gid).fn({"id": aid, "sql": "SELECT 1"}).startswith("ERROR")


def test_query_results_carry_no_floating_point_noise(tmp_path, monkeypatch):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    body = b"region,revenue\nSouth,8820.87\nSouth,9542.12\nSouth,24596.34\n"
    rec = att.store(gid, "s.csv", "text/csv", body, root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    out = read_attachment_tool(world, gid).fn({"id": aid, "sql": "SELECT SUM(revenue) AS total FROM data"})
    assert out == "total\n42959.33"


def _pdf(text: str) -> bytes:
    """A one-page PDF whose page shows ``text`` (Helvetica, no compression)."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = b"%PDF-1.4\n", []
    for number, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    return out + b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)


def test_a_pdf_attachment_is_read_as_text_sealed_and_plain(tmp_path, monkeypatch):
    # A model that cannot take PDF document blocks (every provider but
    # Anthropic) has no other way to read an uploaded PDF: read_pdf is
    # confined to the workspace and attachments live outside it.
    for sealed in (False, True):
        if sealed:
            monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
        root = tmp_path / str(sealed)
        world = WorldModel(root / "w.db")
        gid = world.create_goal("g", "")
        rec = att.store(gid, "incident.pdf", "application/pdf",
                        _pdf("The belt snapped. Repair cost 1,180 USD."), root=root / "a")
        aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
        text = read_attachment_tool(world, gid).fn({"id": aid})
        assert "Repair cost 1,180 USD" in text, text
        assert "Repair cost" in read_attachment_tool(world, gid).fn({"id": aid, "pages": "1"})


def test_a_pdf_with_no_text_layer_says_so(tmp_path, monkeypatch):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    rec = att.store(gid, "scan.pdf", "application/pdf", _pdf(""), root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    assert read_attachment_tool(world, gid).fn({"id": aid}).startswith("ERROR: no text found")


def test_read_pdf_opens_its_goals_attachment_by_the_listed_path(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from maverick.tools.pdf_reader import read_pdf

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    other = world.create_goal("other", "")
    rec = att.store(gid, "incident.pdf", "application/pdf",
                    _pdf("Stopped 3 hours 20 minutes."), root=tmp_path / "a")
    world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    workspace = tmp_path / "task"
    workspace.mkdir()
    sandbox = SimpleNamespace(workdir=workspace)
    assert "3 hours 20 minutes" in read_pdf(sandbox, world=world, goal_id=gid).fn({"source": str(rec.path)})
    refused = read_pdf(sandbox, world=world, goal_id=other).fn({"source": str(rec.path)})
    assert refused.startswith("ERROR: could not read PDF")


def _long_report(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    filler = "\n".join(f"Paragraph {n}: inventory forecast supplier review." for n in range(4000))
    body = filler + "\nThe forklift battery order BAT-77341 ships from Leeds.\n" + filler
    rec = att.store(gid, "long-report.txt", "text/plain", body.encode(), root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    return read_attachment_tool(world, gid), aid, body


def test_a_long_attachment_can_be_searched_without_running_a_command(tmp_path):
    # Seen live: a 333 KB report was cut at 100,000 characters, and the only
    # way to the rest was a shell grep that waited on an approval.
    tool, aid, body = _long_report(tmp_path)
    assert len(body) > 200_000
    first = tool.fn({"id": aid})
    assert "BAT-77341" not in first
    assert "pass offset=100000 to continue" in first
    found = tool.fn({"id": aid, "search": "forklift battery"})
    assert "BAT-77341 ships from Leeds" in found
    assert found.splitlines()[0].startswith("1 line matches")
    assert "no line matches" in tool.fn({"id": aid, "search": "zeppelin"})


def test_a_long_attachment_reads_on_from_an_offset(tmp_path):
    tool, aid, body = _long_report(tmp_path)
    at = body.index("BAT-77341")
    window = tool.fn({"id": aid, "offset": at - 10})
    assert "BAT-77341" in window[:200]
    assert tool.fn({"id": aid, "offset": len(body) + 5}).startswith("ERROR: offset")
    assert tool.fn({"id": aid, "offset": "x"}).startswith("ERROR: offset")


def test_attachment_list_and_workspace_tools_point_to_reading_by_id(tmp_path, monkeypatch):
    # Live: an agent passed the stored path list_attachments printed to
    # spreadsheet_read, got "escapes the workspace", and computed payroll by
    # hand-written formulas (one wrong row) instead of one exact SQL query.
    from types import SimpleNamespace

    from maverick.tools import spreadsheet as ss
    from maverick.tools.attachments import list_attachments_tool

    world, gid, _other, aid, _iid = _setup(tmp_path, monkeypatch, False)
    listing = list_attachments_tool(world, gid).fn({})
    assert "read_attachment" in listing and "`sql`" in listing
    stored = next(a.path for a in world.list_attachments(gid) if a.id == aid)
    out = ss._run({"op": "info", "path": stored}, SimpleNamespace(workdir=str(tmp_path / "work")))
    assert "read_attachment" in out and "sql" in out


def _inventory(tmp_path, monkeypatch, sealed):
    import io

    import openpyxl

    if sealed:
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Inventory"
    for row in (["SKU", "Item", "On hand", "Reorder level", "Reorder qty", "Unit cost"],
                ["SKU-100", "Flour", 20, 10, 30, 39.75], ["SKU-101", "Sugar", 4, 20, 20, 23.21],
                ["SKU-108", "Boxes", 18, 15, 20, 33.36], ["SKU-111", "Lids", 12, 15, 20, 33.77]):
        sheet.append(row)
    raw = io.BytesIO()
    book.save(raw)
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    rec = att.store(gid, "inventory.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    raw.getvalue(), root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    return world, gid, aid


def test_an_excel_attachment_reads_as_a_table_and_answers_an_exact_select(tmp_path, monkeypatch):
    # Live: an attached inventory workbook could be read only through its
    # cell-by-cell text companion, and the agent listed Boxes (18 on hand,
    # level 15) as below its reorder level and invented the quantities.
    for sealed in (False, True):
        world, gid, aid = _inventory(tmp_path / str(sealed), monkeypatch, sealed)
        tool = read_attachment_tool(world, gid)
        table = tool.fn({"id": aid})
        assert "sheet 'Inventory' as CSV" in table and "SKU-108,Boxes,18,15,20,33.36" in table
        out = tool.fn({"id": aid, "sql": 'SELECT SKU, "Reorder qty" * "Unit cost" AS cost FROM data '
                                        'WHERE "On hand" <= "Reorder level"'})
        assert out == "SKU,cost\nSKU-101,464.2\nSKU-111,675.4", out


def test_a_workbook_names_its_sheets_and_reads_or_queries_any_of_them(tmp_path):
    # Live: a vendor-spend workbook kept its 80 transactions on a second
    # sheet, after a one-page summary; only the first sheet could be read or
    # queried, and the agent could not total the spend.
    import io

    import openpyxl

    book = openpyxl.Workbook()
    book.active.title = "Summary"
    book.active.append(["Report", "Q3 vendor spend"])
    sheet = book.create_sheet("Transactions")
    for row in (["vendor", "amount"], ["Sysco", 120.5], ["PG&E", 80.25], ["Sysco", 30]):
        sheet.append(row)
    raw = io.BytesIO()
    book.save(raw)
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    rec = att.store(gid, "spend.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    raw.getvalue(), root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    tool = read_attachment_tool(world, gid)
    first = tool.fn({"id": aid})
    assert "Summary, Transactions" in first and "Report,Q3 vendor spend" in first, first
    assert "vendor,amount" in tool.fn({"id": aid, "sheet": "Transactions"})
    out = tool.fn({"id": aid, "sheet": "Transactions",
                   "sql": "SELECT vendor, SUM(amount) AS total FROM data GROUP BY vendor ORDER BY vendor"})
    assert out == "vendor,total\nPG&E,80.25\nSysco,150.5", out
    # A query that misses on the first sheet points to the others.
    missed = tool.fn({"id": aid, "sql": "SELECT SUM(amount) FROM data"})
    assert missed.startswith("ERROR") and "Transactions" in missed and "sheet" in missed, missed
    assert tool.fn({"id": aid, "sheet": "Nope"}).startswith("ERROR: spend.xlsx has no sheet 'Nope'")
    assert "sheet" in tool.input_schema["properties"]


def _thread(world, conversation, title, **kw):
    goal_id = world.create_goal(title, "", **kw)
    world.append_turn(conversation, "user", title, goal_id=goal_id)
    return goal_id


def test_a_follow_up_reads_the_files_attached_earlier_in_its_chat(tmp_path):
    # Live: "Ben's week 2 hours were 46, not 50. Update the payroll" had no
    # attachments, so the agent guessed a $150 change; the correct one was
    # $201.72 from the timesheet attached to the first message.
    from maverick.tools.attachments import goal_attachment_bytes, list_attachments_tool

    world = WorldModel(tmp_path / "w.db")
    chat = world.get_or_create_conversation("web", "alice/1").id
    first = _thread(world, chat, "run payroll", owner="alice")
    rec = att.store(first, "payroll.csv", "text/csv", b"employee,rate\nBen,33.62\n", root=tmp_path / "a")
    aid = world.add_attachment(first, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    follow_up = _thread(world, chat, "Ben worked 46 hours", owner="alice")

    listing = list_attachments_tool(world, follow_up).fn({})
    assert f"{aid}  payroll.csv" in listing and "earlier message in this conversation" in listing
    assert read_attachment_tool(world, follow_up).fn({"id": aid, "sql": "SELECT rate FROM data"}) == "rate\n33.62"
    assert goal_attachment_bytes(world, follow_up, str(rec.path))[0].startswith(b"employee")

    # Another person's message in the thread, another chat, and a channel
    # conversation (one per person, across all their messages) do not share.
    bob = _thread(world, chat, "bob asks", owner="bob")
    other_chat = _thread(world, world.get_or_create_conversation("web", "alice/9").id, "new chat", owner="alice")
    slack = world.get_or_create_conversation("slack", "alice")
    slack_first = _thread(world, slack.id, "first", owner="alice")
    old = att.store(slack_first, "old.csv", "text/csv", b"a\n1\n", root=tmp_path / "a")
    old_id = world.add_attachment(slack_first, old.filename, old.mime, old.size_bytes, old.sha256, str(old.path))
    slack_later = _thread(world, slack.id, "later", owner="alice")
    for goal_id in (bob, other_chat, slack_later):
        for wanted in (aid, old_id):
            assert read_attachment_tool(world, goal_id).fn({"id": wanted}).startswith("ERROR: no attachment")
        assert list_attachments_tool(world, goal_id).fn({}) == "(no attachments)"


def test_a_statement_pdf_answers_an_exact_select(tmp_path):
    # Live, 4 of 5 runs: an agent typed a statement PDF's amounts into its own
    # sums and dropped some. Its table now answers one query, like a CSV.
    from maverick.markdown_pdf import pdf_from_markdown

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    statement = ("# Business Checking\n\nOpening balance: $12,480.55\n\n"
                 "| Date | Description | Withdrawals | Deposits | Balance |\n"
                 "|---|---|---:|---:|---:|\n| 10/03 | Card - Costco | 3,753.21 | | 8,727.34 |\n"
                 "| 10/05 | Cash deposit | | 3,459.47 | 12,186.81 |\n| 10/07 | ACH - PG&E | 4,249.27 | | 7,937.54 |\n"
                 "| 10/09 | Card settlement | | 2,422.72 | 10,360.26 |\n| 10/10 | Check | 718.81 | | 9,641.45 |\n"
                 "\nClosing balance: $9,641.45\n")
    rec = att.store(gid, "statement.pdf", "application/pdf", pdf_from_markdown(statement), root=tmp_path / "a")
    aid = world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))
    tool = read_attachment_tool(world, gid)
    out = tool.fn({"id": aid, "sql": "SELECT ROUND(SUM(Withdrawals), 2) AS w, ROUND(SUM(Deposits), 2) AS d, "
                                     "MAX(Withdrawals) AS largest FROM data"})
    assert out.startswith("w,d,largest\n8721.29,5882.19,4249.27"), out
    # Live: with only the table in view, an agent took the first row's balance
    # as the opening balance and said the statement did not reconcile.
    assert "Opening balance: $12,480.55" in out and "Closing balance: $9,641.45" in out, out
    assert "PDF" in tool.description and "statement" in tool.description
    # A PDF with no table says so instead of guessing.
    note = att.store(gid, "note.pdf", "application/pdf", pdf_from_markdown("# Note\n\nNo figures here.\n"),
                     root=tmp_path / "a")
    nid = world.add_attachment(gid, note.filename, note.mime, note.size_bytes, note.sha256, str(note.path))
    assert tool.fn({"id": nid, "sql": "SELECT 1 FROM data"}).startswith("ERROR: no table")


def _add(world, gid, tmp_path, name, mime, data):
    rec = att.store(gid, name, mime, data, root=tmp_path / "a")
    return world.add_attachment(gid, rec.filename, rec.mime, rec.size_bytes, rec.sha256, str(rec.path))


_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_a_query_joins_the_tasks_other_files_by_their_names(tmp_path):
    # Live: an agent wrote FROM read_attachment_158 to join October's sales
    # to a cost workbook, was told "no such table", matched SKUs to
    # categories in its head and got every category's cost wrong.
    import io

    import openpyxl

    book = openpyxl.Workbook()
    book.active.title = "Read me"
    book.active.append(["Unit costs are on the Costs sheet."])
    costs = book.create_sheet("Costs")
    for row in (["SKU", "Category", "Unit cost"], ["CB-01", "Coffee", 6.4], ["TE-01", "Tea", 3.2],
                ["CB-02", "Coffee", 7.1]):
        costs.append(row)
    raw = io.BytesIO()
    book.save(raw)
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    sales = _add(world, gid, tmp_path, "october_sales.csv", "text/csv",
                 b"sku,qty,unit_price,discount_pct\nCB-01,2,14.00,0\nTE-01,3,9.00,10\nCB-02,1,15.50,15\n")
    _add(world, gid, tmp_path, "unit_costs.xlsx", _XLSX, raw.getvalue())
    tool = read_attachment_tool(world, gid)
    sql = ("SELECT c.Category, ROUND(SUM(s.qty * s.unit_price * (100 - s.discount_pct) / 100.0), 2) AS revenue, "
           'ROUND(SUM(s.qty * c."Unit cost"), 2) AS cost FROM data s JOIN {} c ON c.SKU = s.sku '
           "GROUP BY c.Category ORDER BY c.Category")
    for table in ("unit_costs", "UNIT_COSTS", "unit_costs_costs"):
        assert tool.fn({"id": sales, "sql": sql.format(table)}) == (
            "Category,revenue,cost\nCoffee,41.18,19.9\nTea,24.3,9.6"), table
    missed = tool.fn({"id": sales, "sql": "SELECT * FROM data JOIN read_attachment_158"})
    assert missed.startswith("ERROR") and "no such table" in missed
    assert "unit_costs (unit_costs.xlsx" in missed and "data (october_sales.csv, also october_sales)" in missed, missed
    from maverick.tools.attachments import list_attachments_tool
    assert "october_sales, unit_costs" in list_attachments_tool(world, gid).fn({})


def _timesheet_docx() -> bytes:
    from maverick.markdown_word import word_answer

    return word_answer("Lunch is unpaid.\n\n| Employee | Rate | Mon | Tue |\n|---|---|---|---|\n"
                       "| Dana | $22.50 | 7:00-15:30 |  |\n| Hank | $18.25 | off | 14:00-23:00 |\n\n"
                       "Approvals:\n\n| Manager | Signed |\n|---|---|\n| Lee | yes |\n", "Timesheet")


def test_a_word_documents_table_answers_an_exact_select(tmp_path):
    # Live: a timesheet in a Word table was read one cell per line and
    # added up by hand; two of four people's hours came out wrong.
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    aid = _add(world, gid, tmp_path, "timesheet.docx", _DOCX, _timesheet_docx())
    tool = read_attachment_tool(world, gid)
    sql = ("SELECT Employee, SUM(h) AS hours, ROUND(SUM(h) * Rate, 2) AS pay FROM ("
           "SELECT Employee, Rate, COALESCE(hours(Mon), 0) + COALESCE(hours(Tue), 0) AS h FROM data) "
           "GROUP BY Employee ORDER BY Employee")
    out = tool.fn({"id": aid, "sql": sql})
    assert out.splitlines()[:3] == ["Employee,hours,pay", "Dana,8.5,191.25", "Hank,9.0,164.25"], out
    assert "2 tables" in out and "`table`" in out
    assert tool.fn({"id": aid, "table": 2, "sql": "SELECT Manager FROM data WHERE Signed = 'yes'"}) == "Manager\nLee"
    assert tool.fn({"id": aid, "table": 3, "sql": "SELECT 1"}).startswith("ERROR: timesheet.docx has 2 tables")
    plain = tool.fn({"id": aid})
    assert plain.startswith("ERROR") and ".extracted.txt" in plain and "`sql`" in plain
    assert "table" in tool.input_schema["properties"]
    # Joined from another file's query, by its name.
    rates = _add(world, gid, tmp_path, "bonus.csv", "text/csv", b"name,bonus\nDana,50\nHank,25\n")
    joined = tool.fn({"id": rates, "sql": "SELECT b.name, b.bonus + t.Rate AS x FROM data b "
                                          "JOIN timesheet t ON t.Employee = b.name ORDER BY b.name"})
    assert joined == "name,x\nDana,72.5\nHank,43.25", joined


def test_a_word_document_with_no_table_says_so(tmp_path):
    from maverick.markdown_word import word_answer

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    aid = _add(world, gid, tmp_path, "memo.docx", _DOCX, word_answer("Just a memo.", "Memo"))
    out = read_attachment_tool(world, gid).fn({"id": aid, "sql": "SELECT 1"})
    assert out.startswith("ERROR: memo.docx has no table")


def test_the_queried_file_is_also_a_table_under_its_own_name(tmp_path):
    # Live: a query over october_sales.csv wrote FROM october_sales and was
    # told there is no such table: the file being read was only `data`.
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    sales = _add(world, gid, tmp_path, "october_sales.csv", "text/csv", b"sku,qty\nA,2\nB,3\n")
    _add(world, gid, tmp_path, "costs.csv", "text/csv", b"sku,cost\nA,1.5\nB,2\n")
    tool = read_attachment_tool(world, gid)
    out = tool.fn({"id": sales, "sql": "SELECT SUM(s.qty * c.cost) AS t FROM october_sales s JOIN costs c "
                                       "ON c.sku = s.sku"})
    assert out == "t\n9.0", out


def test_sql_on_a_documents_text_companion_queries_the_document(tmp_path):
    # Live: an agent passed `sql` to timesheet.docx.extracted.txt, was told it
    # is not a CSV file, read the rows one by one and got two people's lunch
    # deductions wrong.
    from maverick.attachments import generate_companions

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    _add(world, gid, tmp_path, "timesheet.docx", _DOCX, _timesheet_docx())
    _add(world, gid, tmp_path, "notes.txt", "text/plain", b"plain")
    assert generate_companions(world, gid, root=tmp_path / "a") == 1
    companion = next(a.id for a in world.list_attachments(gid) if a.filename.endswith(".extracted.txt"))
    tool = read_attachment_tool(world, gid)
    out = tool.fn({"id": companion, "sql": "SELECT Employee, COALESCE(hours(Mon), 0) AS h FROM data ORDER BY Employee"})
    assert out.splitlines()[:3] == ["Employee,h", "Dana,8.5", "Hank,0"], out
    # A companion's plain read is unchanged, and other text still refuses sql.
    assert "| Dana | $22.50 | 7:00-15:30 |  |" in tool.fn({"id": companion})
    plain = next(a.id for a in world.list_attachments(gid) if a.filename == "notes.txt")
    assert tool.fn({"id": plain, "sql": "SELECT 1"}).startswith("ERROR: notes.txt is not a CSV file")


def test_another_file_is_loaded_only_where_the_query_uses_it_as_a_table(tmp_path):
    # A column or function sharing another file's name (receipt next to
    # receipt.docx, hours() next to Hours.docx) loaded that file, and a file
    # with no table then failed a query that never read it.
    from maverick.markdown_word import word_answer

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    expenses = _add(world, gid, tmp_path, "expenses.csv", "text/csv",
                    b"item,amount,receipt\nTaxi,12,yes\nLunch,30,no\n")
    shifts = _add(world, gid, tmp_path, "timesheet.csv", "text/csv", b"name,clock_in,clock_out\nDana,7:00,15:30\n")
    _add(world, gid, tmp_path, "receipt.docx", _DOCX, word_answer("Paid in cash.", "Receipt"))
    _add(world, gid, tmp_path, "Hours.docx", _DOCX, word_answer("Overtime starts after 40 hours.", "Hours"))
    tool = read_attachment_tool(world, gid)
    assert tool.fn({"id": expenses, "sql": "SELECT DISTINCT receipt FROM data ORDER BY receipt"}) == "receipt\nno\nyes"
    out = tool.fn({"id": shifts, "sql": "SELECT name, hours(clock_in, clock_out) AS h FROM data"})
    assert out == "name,h\nDana,8.5", out
    # Used as a table, a file that cannot be loaded says why.
    out = tool.fn({"id": expenses, "sql": "SELECT d.item FROM data d, receipt r"})
    assert out.startswith("ERROR") and "no such table: receipt" in out, out
    assert "receipt.docx has no table to query" in out and "receipt (receipt.docx" not in out, out


def test_another_workbook_parses_only_the_sheets_the_query_uses(tmp_path, monkeypatch):
    # Each sheet is parsed in its own subprocess. A column such as
    # sales_total, which only starts with the name of sales.xlsx, parsed every
    # sheet of the workbook on every query.
    import io

    import openpyxl
    from maverick import parser_isolation

    book = openpyxl.Workbook()
    book.active.title = "Read me"
    book.active.append(["Regional sales follow."])
    for title, amounts in (("North", (10, 20)), ("South", (5,)), ("West", (7,))):
        sheet = book.create_sheet(title)
        for row in (["amount"], *([a] for a in amounts)):
            sheet.append(row)
    raw = io.BytesIO()
    book.save(raw)
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    orders = _add(world, gid, tmp_path, "orders.csv", "text/csv", b"id,sales_total\n1,20\n2,15\n")
    _add(world, gid, tmp_path, "sales.xlsx", _XLSX, raw.getvalue())
    parsed = []
    real = parser_isolation.parse_isolated

    def counting(name, data, **kwargs):
        parsed.append((name, kwargs.get("sheet")))
        return real(name, data, **kwargs)

    monkeypatch.setattr(parser_isolation, "parse_isolated", counting)
    tool = read_attachment_tool(world, gid)
    assert tool.fn({"id": orders, "sql": "SELECT SUM(sales_total) AS t FROM data"}) == "t\n35"
    assert parsed == []
    assert tool.fn({"id": orders, "sql": "SELECT SUM(amount) AS t FROM sales_south"}) == "t\n5"
    assert parsed == [("spreadsheet_info", None), ("spreadsheet_read", "South")]
    parsed.clear()
    # The bare name is the first sheet holding a table; no sheet after it is parsed.
    assert tool.fn({"id": orders, "sql": "SELECT SUM(amount) AS t FROM sales"}) == "t\n30"
    assert parsed == [("spreadsheet_info", None), ("spreadsheet_read", "Read me"), ("spreadsheet_read", "North")]


def _tracked_change(docx: bytes, old: str, new: str) -> bytes:
    """``docx`` with the cell text ``old`` replaced by ``new`` as a pending
    tracked change: ``old`` deleted, ``new`` inserted, neither accepted."""
    import io
    import zipfile

    run = f'<w:r><w:t xml:space="preserve">{old}</w:t></w:r>'.encode()
    change = (f'<w:del w:id="1" w:author="A"><w:r><w:delText>{old}</w:delText></w:r></w:del>'
              f'<w:ins w:id="2" w:author="A"><w:r><w:t>{new}</w:t></w:r></w:ins>').encode()
    source, out = zipfile.ZipFile(io.BytesIO(docx)), io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist():
            raw = source.read(item)
            if item.filename == "word/document.xml":
                assert run in raw
                raw = raw.replace(run, change)
            target.writestr(item, raw)
    return out.getvalue()


def test_a_word_table_with_tracked_changes_is_refused_like_its_text(tmp_path):
    # Text extraction refuses a document with pending tracked changes, but
    # `sql` read its table anyway: Ann's unaccepted 40 -> 45 counted as 45.
    from maverick.markdown_word import word_answer

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    table = "| Name | Hours |\n|---|---|\n| Ann | 40 |\n| Bob | 20 |\n"
    aid = _add(world, gid, tmp_path, "timesheet.docx", _DOCX, _tracked_change(word_answer(table, "Hours"), "40", "45"))
    out = read_attachment_tool(world, gid).fn({"id": aid, "sql": "SELECT SUM(Hours) AS total FROM data"})
    assert out.startswith("ERROR: timesheet.docx could not be read") and "tracked changes" in out, out


def test_the_queried_file_is_loaded_once_under_the_name_the_query_uses(tmp_path):
    # Loaded as `data` and again under its own name, a file's blank cells were
    # counted twice in the note; and a filename with a comma (Sales, Q3.csv)
    # got the alias sales instead of the sales__q3 the listing showed.
    from maverick.tools.attachments import list_attachments_tool

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    invoices = _add(world, gid, tmp_path, "invoices.csv", "text/csv",
                    b"id,amount,paid\n1,100,100\n2,50,\n3,70,\n4,20,20\n")
    tool = read_attachment_tool(world, gid)
    for table in ("data", "invoices"):
        out = tool.fn({"id": invoices, "sql": f"SELECT SUM(amount - paid) AS owed FROM {table}"})
        assert out.startswith("owed\n0\nNote: paid is blank in 2 rows,"), (table, out)
    both = tool.fn({"id": invoices, "sql": "SELECT COUNT(*) AS n FROM data d JOIN invoices i ON i.id = d.id"})
    assert both == "n\n4", both
    sales = _add(world, gid, tmp_path, "Sales, Q3.csv", "text/csv", b"sku,qty\nA,2\nB,3\n")
    _add(world, gid, tmp_path, "costs.csv", "text/csv", b"sku,cost\nA,1.5\nB,2\n")
    assert "invoices, sales__q3, costs." in list_attachments_tool(world, gid).fn({})
    out = tool.fn({"id": sales, "sql": "SELECT SUM(s.qty * c.cost) AS t FROM sales__q3 s JOIN costs c "
                                       "ON c.sku = s.sku"})
    assert out == "t\n9.0", out


def test_an_empty_quoted_token_does_not_break_a_query(tmp_path):
    # Reading the query's table names, an empty string such as '' raised
    # AttributeError, so WHERE paid = '' never ran on any attachment.
    from maverick.tools.attachments import query_table

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    invoices = _add(world, gid, tmp_path, "invoices.csv", "text/csv", b"id,amount,paid\n1,100,yes\n2,50,\n3,70,no\n")
    tool = read_attachment_tool(world, gid)
    assert tool.fn({"id": invoices, "sql": "SELECT COUNT(*) AS n FROM data WHERE paid = ''"}) == "n\n1"
    out = tool.fn({"id": invoices, "sql": "SELECT SUM(amount) AS t FROM data WHERE COALESCE(paid, '') <> 'yes'"})
    assert out == "t\n120", out
    assert tool.fn({"id": invoices, "sql": 'SELECT COUNT(*) AS n FROM data WHERE paid = ""'}) == "n\n1"
    assert query_table("x.csv", "text/csv", "a,b\n1,\n", "SELECT COUNT(*) AS n FROM data WHERE b = ''") == "n\n1"


def test_a_file_named_after_in_is_loaded_as_a_table(tmp_path):
    # SQLite reads `sku IN skus` as the table skus, but only FROM and JOIN
    # loaded another file, so the query failed with no such table: skus while
    # the hint listed skus.csv among the tables it could read.
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    orders = _add(world, gid, tmp_path, "orders.csv", "text/csv", b"sku,sales_total\nA,10\nB,25\n")
    _add(world, gid, tmp_path, "skus.csv", "text/csv", b"sku\nA\n")
    tool = read_attachment_tool(world, gid)
    for where, total in (("sku IN skus", 10), ("sku IN main.skus", 10), ("sku NOT IN skus", 25),
                         ("sku IN (SELECT sku FROM skus)", 10), ("sku IN ('A', 'B')", 35)):
        out = tool.fn({"id": orders, "sql": f"SELECT SUM(sales_total) AS t FROM data WHERE {where}"})
        assert out == f"t\n{total}", (where, out)
