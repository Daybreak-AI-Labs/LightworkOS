from report import to_csv


def test_header_and_rows():
    assert to_csv([{"a": 1, "b": 2}]) == "a,b\n1,2\n"
