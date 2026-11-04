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
