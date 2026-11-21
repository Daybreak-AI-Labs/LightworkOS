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
