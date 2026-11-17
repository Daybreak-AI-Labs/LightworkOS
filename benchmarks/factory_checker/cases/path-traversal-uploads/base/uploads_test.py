import pytest
from uploads import read_upload


def test_reads_an_upload(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"hi")
    assert read_upload(tmp_path, "a.txt") == b"hi"


def test_refuses_an_absolute_name(tmp_path):
    with pytest.raises(ValueError):
        read_upload(tmp_path, "/etc/hostname")
