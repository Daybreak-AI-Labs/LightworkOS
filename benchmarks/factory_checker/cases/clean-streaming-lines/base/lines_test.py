from lines import read_lines


def test_reads_lines(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("one\ntwo\n")
    assert list(read_lines(f)) == ["one", "two"]
