from limits import read_limit


def test_reads_the_limit():
    assert read_limit({"LIMIT": "5"}) == 5
