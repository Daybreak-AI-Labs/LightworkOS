from unpack import extract


def test_writes_members(tmp_path):
    extract({"a.txt": b"1", "sub/b.txt": b"2"}, tmp_path)
    assert (tmp_path / "sub" / "b.txt").read_bytes() == b"2"
