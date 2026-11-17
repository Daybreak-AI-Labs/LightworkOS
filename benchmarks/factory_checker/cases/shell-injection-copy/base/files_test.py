from files import copy_file


def test_copies(tmp_path):
    (tmp_path / "a").write_text("x")
    copy_file(str(tmp_path / "a"), str(tmp_path / "b"))
    assert (tmp_path / "b").read_text() == "x"
