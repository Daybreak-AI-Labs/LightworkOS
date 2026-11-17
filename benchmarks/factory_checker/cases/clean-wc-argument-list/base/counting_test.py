from counting import count_lines


def test_counts_lines(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("one\ntwo\n")
    assert count_lines(str(f)) == 2
