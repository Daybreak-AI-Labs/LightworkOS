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
