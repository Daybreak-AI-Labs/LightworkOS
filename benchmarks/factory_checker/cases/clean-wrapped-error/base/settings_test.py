from settings import load


def test_loads(tmp_path):
    f = tmp_path / "s.json"
    f.write_text('{"a": 1}')
    assert load(f) == {"a": 1}
