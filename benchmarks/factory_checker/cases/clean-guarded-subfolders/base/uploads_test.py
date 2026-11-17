from uploads import read_upload


def test_reads_an_upload(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"hi")
    assert read_upload(tmp_path, "a.txt") == b"hi"
